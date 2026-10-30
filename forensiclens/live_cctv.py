"""Independent Live CCTV stream, dual YOLO inference, alerts, and evidence capture."""

from __future__ import annotations

import json
import os
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from math import hypot
from pathlib import Path
from typing import Any, Iterator

import cv2
import numpy as np

from forensiclens.forensic_events import DEFAULT_CONFIG as FORENSIC_EVENT_CONFIG
from forensiclens.ml.predict import ForensicPredictor
from forensiclens.preservation import sha256_file, utc_now
from forensiclens.threat_model import THREAT_MODEL_PATH, load_threat_model
from forensiclens.video_intelligence import DEFAULT_CONFIG as VIDEO_CONFIG, _frame_change_score, _load_model, _values

CAMERA_SOURCE: int | str = 0
CAMERA_NAME = "Live CCTV 01"
LIVE_FRAME_WIDTH = 640
INFERENCE_INTERVAL = 2
GENERAL_CONFIDENCE_THRESHOLD = 0.35
THREAT_CONFIDENCE_THRESHOLD = 0.85
THREAT_ALERT_COOLDOWN_SECONDS = 8.0
ANOMALY_COOLDOWN_SECONDS = 12.0
EVIDENCE_DIR = Path("reports/live_evidence")
JPEG_QUALITY = 80
MOVEMENT_PIXEL_THRESHOLD = float(FORENSIC_EVENT_CONFIG["movement_displacement_pixels"])
PROLONGED_PRESENCE_SECONDS = float(FORENSIC_EVENT_CONFIG["prolonged_presence_seconds"])
MULTIPLE_OBJECT_COUNT = int(FORENSIC_EVENT_CONFIG["multiple_object_count"])
FRAME_CHANGE_THRESHOLD = float(VIDEO_CONFIG["frame_change_threshold"])

GENERAL_BOX_COLOR = (56, 189, 248)
THREAT_BOX_COLOR = (56, 63, 244)
ANOMALY_BOX_COLOR = (15, 158, 245)


def _parse_camera_source(value: str | int | None = None) -> int | str:
    raw = os.environ.get("FORENSICLENS_CAMERA_SOURCE") if value is None else value
    if raw is None:
        return CAMERA_SOURCE
    text = str(raw).strip()
    if text.isdigit():
        return int(text)
    return text or 0


def _local_now() -> datetime:
    return datetime.now().astimezone()


def _local_clock() -> str:
    return _local_now().strftime("%H:%M:%S")


def _display_name(label: str) -> str:
    aliases = {
        "explosion": "Explosive",
        "explosive": "Explosive",
        "gun": "Gun",
        "knife": "Knife",
        "grenade": "Grenade",
        "pistol": "Gun",
        "handgun": "Gun",
        "rifle": "Gun",
    }
    key = label.strip().lower()
    if key in aliases:
        return aliases[key]
    return label.replace("_", " ").strip().title()


def _open_capture(source: int | str) -> cv2.VideoCapture:
    if isinstance(source, int):
        capture = cv2.VideoCapture(source, cv2.CAP_DSHOW)
        if capture.isOpened():
            return capture
        capture.release()
        return cv2.VideoCapture(source)
    return cv2.VideoCapture(source)


class LiveCCTVEngine:
    """Background webcam loop used only by the Live CCTV dashboard mode."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.running = False
        self.thread: threading.Thread | None = None
        self.capture: cv2.VideoCapture | None = None
        self.latest_jpeg: bytes | None = None
        self.fps = 0.0
        self.camera_status = "OFFLINE"
        self.camera_source = _parse_camera_source()
        self.camera_name = CAMERA_NAME
        self.frame_index = 0
        self.last_error: str | None = None
        self.general_model = None
        self.threat_model = None
        self.device: str | int = "cpu"
        self.threat_classes: list[str] = []
        self.threat_metadata: dict[str, Any] = {}
        self.general_runtime: dict[str, Any] = {}
        self.models_ready = False
        self.prepare_error: str | None = None
        self.events: deque[dict[str, Any]] = deque(maxlen=200)
        self.alerts: deque[dict[str, Any]] = deque(maxlen=50)
        self.detections: list[dict[str, Any]] = []
        self.evidence_records: list[dict[str, Any]] = []
        self.evidence_counter = 0
        self._cooldowns: dict[str, float] = {}
        self._track_history: dict[int, deque[tuple[float, float, float]]] = defaultdict(lambda: deque(maxlen=40))
        self._track_first_seen: dict[int, float] = {}
        self._predictor: ForensicPredictor | None = None
        self._predictor_loaded = False
        self._load_existing_evidence()

    def _load_existing_evidence(self) -> None:
        index_path = EVIDENCE_DIR / "index.json"
        if not index_path.is_file():
            return
        try:
            payload = json.loads(index_path.read_text(encoding="utf-8"))
            self.evidence_records = list(payload.get("records", []))
            self.evidence_counter = int(payload.get("counter", len(self.evidence_records)))
        except Exception:
            self.evidence_records = []

    def _persist_evidence_index(self) -> None:
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        payload = {"counter": self.evidence_counter, "records": self.evidence_records}
        (EVIDENCE_DIR / "index.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def prepare_models(self) -> dict[str, Any]:
        with self.lock:
            if self.models_ready and self.general_model is not None and self.threat_model is not None:
                return self.model_status()
        try:
            general_model, runtime = _load_model({"model_name": VIDEO_CONFIG["model_name"]})
            threat_model, threat_meta = load_threat_model(THREAT_MODEL_PATH)
            with self.lock:
                self.general_model = general_model
                self.threat_model = threat_model
                self.general_runtime = runtime
                self.device = runtime.get("inference_device_argument", "cpu")
                self.threat_metadata = threat_meta
                self.threat_classes = list(threat_meta.get("classes") or [])
                self.models_ready = True
                self.prepare_error = None
            return self.model_status()
        except Exception as error:
            with self.lock:
                self.prepare_error = str(error)
                self.models_ready = False
            raise

    def model_status(self) -> dict[str, Any]:
        with self.lock:
            return {
                "ready": self.models_ready,
                "error": self.prepare_error,
                "threat_model_path": str(Path(THREAT_MODEL_PATH).resolve()),
                "threat_model_exists": Path(THREAT_MODEL_PATH).is_file(),
                "threat_classes": list(self.threat_classes),
                "threat_downloaded_this_session": bool(self.threat_metadata.get("downloaded")),
                "reused_local_threat_model": bool(self.threat_metadata.get("reused_local_file")),
                "general_model": VIDEO_CONFIG["model_name"],
                "device": self.general_runtime.get("device", "cpu"),
            }

    def _ensure_predictor(self) -> ForensicPredictor | None:
        if self._predictor_loaded:
            return self._predictor
        try:
            predictor = ForensicPredictor()
            self._predictor = predictor if predictor.pipeline is not None else predictor
        except Exception:
            self._predictor = None
        self._predictor_loaded = True
        return self._predictor

    def start(self) -> dict[str, Any]:
        self.prepare_models()
        with self.lock:
            if self.running:
                return self.status()
            self.last_error = None
            self.camera_source = _parse_camera_source()
            self.running = True
            self.camera_status = "STARTING"
            self.thread = threading.Thread(target=self._run_loop, name="live-cctv", daemon=True)
            self.thread.start()
        return self.status()

    def stop(self) -> dict[str, Any]:
        with self.lock:
            self.running = False
        thread = self.thread
        if thread and thread.is_alive() and threading.current_thread() is not thread:
            thread.join(timeout=3.0)
        with self.lock:
            if self.capture is not None:
                try:
                    self.capture.release()
                except Exception:
                    pass
                self.capture = None
            self.camera_status = "OFFLINE"
            self.fps = 0.0
            self.detections = []
            self.thread = None
        return self.status()

    def clear_alerts(self) -> dict[str, Any]:
        with self.lock:
            self.alerts.clear()
            self.events.clear()
            self._cooldowns.clear()
        return self.status()

    def _cooldown_ok(self, key: str, seconds: float) -> bool:
        now = time.monotonic()
        previous = self._cooldowns.get(key, 0.0)
        if now - previous < seconds:
            return False
        self._cooldowns[key] = now
        return True

    def _append_event(self, event: dict[str, Any]) -> None:
        event.setdefault("status", "AI-assisted — investigator verification required")
        self.events.appendleft(event)
        if event.get("event_type") == "Potential Threat":
            self.alerts.appendleft(event)

    def _next_evidence_id(self, when: datetime) -> str:
        self.evidence_counter += 1
        return f"LIVE-{when.strftime('%Y%m%d-%H%M%S')}-{self.evidence_counter:03d}"

    def capture_evidence(
        self,
        *,
        event_type: str = "Manual Capture",
        object_name: str | None = None,
        confidence: float | None = None,
        track_id: int | None = None,
        severity: str = "MEDIUM",
        frame: np.ndarray | None = None,
    ) -> dict[str, Any]:
        with self.lock:
            jpeg = self.latest_jpeg
            source_frame = None if frame is None else frame.copy()
        if source_frame is None:
            if not jpeg:
                raise RuntimeError("No live frame is available to capture as evidence.")
            decoded = cv2.imdecode(np.frombuffer(jpeg, dtype=np.uint8), cv2.IMREAD_COLOR)
            if decoded is None:
                raise RuntimeError("Unable to decode the current live frame for evidence capture.")
            source_frame = decoded

        when = _local_now()
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        with self.lock:
            evidence_id = self._next_evidence_id(when)
        filename = f"{evidence_id}.jpg"
        path = EVIDENCE_DIR / filename
        ok, encoded = cv2.imencode(".jpg", source_frame, [int(cv2.IMWRITE_JPEG_QUALITY), 92])
        if not ok:
            raise RuntimeError("Unable to encode the evidence frame.")
        path.write_bytes(encoded.tobytes())
        digest = sha256_file(path)
        record = {
            "evidence_id": evidence_id,
            "event": event_type if not object_name else f"{event_type} - {object_name}",
            "event_type": event_type,
            "object": object_name,
            "confidence": round(float(confidence), 4) if confidence is not None else None,
            "track_id": track_id,
            "camera": self.camera_name,
            "camera_source": str(self.camera_source),
            "timestamp": when.strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp_utc": utc_now(),
            "severity": severity,
            "relative_path": str(path).replace("\\", "/"),
            "sha256": digest,
            "size_bytes": path.stat().st_size,
            "status": "captured",
            "disclaimer": "AI-Assisted Security Alert. Detection requires investigator verification and does not confirm a crime.",
        }
        sidecar = path.with_suffix(".json")
        sidecar.write_text(json.dumps(record, indent=2), encoding="utf-8")
        with self.lock:
            self.evidence_records.append(record)
            self._persist_evidence_index()
        return record

    def _extract_named_detections(self, result: Any, names: dict[Any, str], min_conf: float) -> list[dict[str, Any]]:
        boxes = getattr(result, "boxes", None)
        if boxes is None:
            return []
        coordinates = _values(getattr(boxes, "xyxy", None))
        confidences = _values(getattr(boxes, "conf", None))
        classes = _values(getattr(boxes, "cls", None))
        track_ids = _values(getattr(boxes, "id", None))
        detections: list[dict[str, Any]] = []
        for index, coordinate in enumerate(coordinates):
            confidence = float(confidences[index]) if index < len(confidences) else 0.0
            if confidence < min_conf:
                continue
            class_id = int(classes[index]) if index < len(classes) else -1
            label = names.get(class_id) or names.get(str(class_id)) or f"class_{class_id}"
            detections.append({
                "class": str(label),
                "display": _display_name(str(label)),
                "confidence": confidence,
                "bounding_box_xyxy": [int(float(value)) for value in coordinate],
                "track_id": int(track_ids[index]) if index < len(track_ids) and track_ids[index] is not None else None,
            })
        return detections

    def _draw(self, frame: np.ndarray, detections: list[dict[str, Any]], active_alert: dict[str, Any] | None, fps: float) -> np.ndarray:
        annotated = frame.copy()
        for detection in detections:
            x1, y1, x2, y2 = detection["bounding_box_xyxy"]
            color = THREAT_BOX_COLOR if detection.get("kind") == "threat" else GENERAL_BOX_COLOR
            cv2.rectangle(annotated, (x1, y1), (x2, y2), color, 2)
            track = f" ID {detection['track_id']}" if detection.get("track_id") is not None else ""
            label = f"{detection['display']} {detection['confidence']*100:.0f}%{track}"
            (tw, th), _ = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, 0.5, 1)
            cv2.rectangle(annotated, (x1, max(0, y1 - th - 8)), (x1 + tw + 8, y1), color, -1)
            cv2.putText(annotated, label, (x1 + 4, y1 - 4), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (15, 23, 42), 1, cv2.LINE_AA)

        status = self.camera_status
        cv2.rectangle(annotated, (8, 8), (420, 78), (15, 23, 42), -1)
        cv2.putText(annotated, "LIVE CCTV", (16, 32), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (56, 189, 248), 2, cv2.LINE_AA)
        cv2.putText(
            annotated,
            f"Camera: 01  Status: {status}  FPS: {fps:.1f}",
            (16, 58),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.5,
            (226, 232, 240),
            1,
            cv2.LINE_AA,
        )
        if active_alert:
            height, width = annotated.shape[:2]
            cv2.rectangle(annotated, (8, height - 86), (width - 8, height - 8), (30, 30, 180), -1)
            cv2.putText(annotated, "POTENTIAL THREAT DETECTED", (20, height - 56), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2, cv2.LINE_AA)
            detail = f"Object: {active_alert.get('object')}  Confidence: {active_alert.get('confidence_pct')}  {active_alert.get('timestamp')}"
            cv2.putText(annotated, detail, (20, height - 28), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1, cv2.LINE_AA)
        return annotated

    def _encode_jpeg(self, frame: np.ndarray) -> bytes:
        ok, encoded = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), JPEG_QUALITY])
        if not ok:
            return b""
        return encoded.tobytes()

    def _score_live_anomalies(self, general: list[dict[str, Any]], change_score: float | None, now_ts: float) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        persons = [item for item in general if item["class"].lower() == "person"]
        if len(persons) >= MULTIPLE_OBJECT_COUNT and self._cooldown_ok("anomaly:multiple_people", ANOMALY_COOLDOWN_SECONDS):
            anomalies.append({
                "event_type": "Multiple People",
                "object": "Person",
                "confidence": None,
                "track_id": persons[0].get("track_id"),
                "severity": "MEDIUM",
                "explanation": f"{len(persons)} people were visible at the same time. This is an activity event, not proof of a crime.",
            })
        if change_score is not None and change_score >= max(FRAME_CHANGE_THRESHOLD * 1.8, 0.22) and self._cooldown_ok("anomaly:activity", ANOMALY_COOLDOWN_SECONDS):
            anomalies.append({
                "event_type": "Unusual Activity Level",
                "object": "-",
                "confidence": None,
                "track_id": None,
                "severity": "MEDIUM",
                "explanation": f"Frame-change score {change_score:.2f} exceeded the live activity threshold. Investigator review is required.",
            })
        if len(general) >= int(FORENSIC_EVENT_CONFIG["detection_burst_count"]) and self._cooldown_ok("anomaly:burst", ANOMALY_COOLDOWN_SECONDS):
            anomalies.append({
                "event_type": "Detection Burst",
                "object": general[0]["display"] if general else "-",
                "confidence": None,
                "track_id": general[0].get("track_id") if general else None,
                "severity": "MEDIUM",
                "explanation": "A burst of detections occurred in a short window. This is an activity event, not a confirmed incident.",
            })

        predictor = self._ensure_predictor()
        for detection in general:
            track_id = detection.get("track_id")
            if track_id is None:
                continue
            box = detection["bounding_box_xyxy"]
            cx, cy = (box[0] + box[2]) / 2.0, (box[1] + box[3]) / 2.0
            history = self._track_history[track_id]
            history.append((now_ts, cx, cy))
            self._track_first_seen.setdefault(track_id, now_ts)
            duration = now_ts - self._track_first_seen[track_id]
            if duration >= PROLONGED_PRESENCE_SECONDS and self._cooldown_ok(f"anomaly:presence:{track_id}", ANOMALY_COOLDOWN_SECONDS):
                anomalies.append({
                    "event_type": "Prolonged Presence",
                    "object": detection["display"],
                    "confidence": detection["confidence"],
                    "track_id": track_id,
                    "severity": "MEDIUM",
                    "explanation": f"Local track {track_id} remained visible for {duration:.1f}s. Track IDs are temporary and are not identities.",
                })
            if len(history) >= 4:
                first = history[0]
                displacement = hypot(cx - first[1], cy - first[2])
                elapsed = max(now_ts - first[0], 0.05)
                if displacement >= MOVEMENT_PIXEL_THRESHOLD and self._cooldown_ok(f"anomaly:move:{track_id}", ANOMALY_COOLDOWN_SECONDS):
                    severity = "MEDIUM"
                    explanation = f"Unusual movement: centroid displacement {displacement:.0f}px over {elapsed:.1f}s."
                    if predictor is not None:
                        track = {
                            "class": detection["class"],
                            "duration_seconds": elapsed,
                            "mean_confidence": detection["confidence"],
                            "max_confidence": detection["confidence"],
                            "number_of_detections": len(history),
                            "bounding_box_trajectory_summary": {"displacement_pixels": displacement},
                            "parent_evidence_id": "live-cctv-01",
                            "track_id": track_id,
                        }
                        prediction = predictor.predict_track(track)
                        if prediction.get("classification") == "anomaly" or (prediction.get("anomaly_score") or 0) >= 0.65:
                            severity = "HIGH" if prediction.get("review_priority") == "high" else "MEDIUM"
                            explanation += " Isolation Forest marked this motion pattern as unusual. This does not prove a crime."
                    anomalies.append({
                        "event_type": "Unusual Movement",
                        "object": detection["display"],
                        "confidence": detection["confidence"],
                        "track_id": track_id,
                        "severity": severity,
                        "explanation": explanation,
                    })
        return anomalies

    def _run_loop(self) -> None:
        source = self.camera_source
        capture = _open_capture(source)
        if not capture.isOpened():
            with self.lock:
                self.running = False
                self.camera_status = "ERROR"
                self.last_error = f"Unable to open camera source {source}. Check that a webcam is connected, or set CAMERA_SOURCE / FORENSICLENS_CAMERA_SOURCE."
                self.capture = None
            return

        capture.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
        capture.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
        with self.lock:
            self.capture = capture
            self.camera_status = "ONLINE"
            self.frame_index = 0
            self._track_history.clear()
            self._track_first_seen.clear()

        previous_frame = None
        fps_window: deque[float] = deque(maxlen=20)
        last_detections: list[dict[str, Any]] = []
        last_alert: dict[str, Any] | None = None
        try:
            while True:
                with self.lock:
                    if not self.running:
                        break
                started = time.perf_counter()
                ok, frame = capture.read()
                if not ok or frame is None:
                    with self.lock:
                        self.camera_status = "ERROR"
                        self.last_error = "Camera stopped delivering frames."
                    time.sleep(0.05)
                    continue

                height, width = frame.shape[:2]
                if width > LIVE_FRAME_WIDTH:
                    scale = LIVE_FRAME_WIDTH / float(width)
                    frame = cv2.resize(frame, (LIVE_FRAME_WIDTH, int(height * scale)))

                self.frame_index += 1
                change_score = _frame_change_score(previous_frame, frame) if previous_frame is not None else None
                previous_frame = frame
                now_ts = time.monotonic()
                detections: list[dict[str, Any]] = last_detections

                if self.frame_index % INFERENCE_INTERVAL == 0:
                    detections = []
                    try:
                        tracked = self.general_model.track(
                            frame,
                            persist=True,
                            tracker=VIDEO_CONFIG["tracker"],
                            conf=GENERAL_CONFIDENCE_THRESHOLD,
                            verbose=False,
                            device=self.device,
                        )
                        general_names = getattr(self.general_model, "names", {}) or {}
                        general = self._extract_named_detections(tracked[0] if tracked else None, general_names, GENERAL_CONFIDENCE_THRESHOLD)
                        for item in general:
                            item["kind"] = "general"
                        detections.extend(general)
                    except Exception as error:
                        with self.lock:
                            self.last_error = f"General detection error: {error}"
                        general = []

                    threats: list[dict[str, Any]] = []
                    try:
                        threat_results = self.threat_model.predict(
                            frame,
                            conf=THREAT_CONFIDENCE_THRESHOLD,
                            verbose=False,
                            device=self.device,
                            imgsz=640,
                        )
                        threat_names = getattr(self.threat_model, "names", {}) or {}
                        threats = self._extract_named_detections(threat_results[0] if threat_results else None, threat_names, THREAT_CONFIDENCE_THRESHOLD)
                    except Exception as error:
                        with self.lock:
                            self.last_error = f"Threat detection error: {error}"

                    for threat in threats:
                        threat["kind"] = "threat"
                        detections.append(threat)
                        class_key = threat["class"].lower()
                        track_key = threat.get("track_id") if threat.get("track_id") is not None else class_key
                        cooldown_key = f"threat:{class_key}:{track_key}"
                        if not self._cooldown_ok(cooldown_key, THREAT_ALERT_COOLDOWN_SECONDS):
                            continue
                        when = _local_now()
                        event = {
                            "timestamp": when.strftime("%H:%M:%S"),
                            "timestamp_full": when.strftime("%Y-%m-%d %H:%M:%S"),
                            "_shown_at": time.monotonic(),
                            "event_type": "Potential Threat",
                            "object": threat["display"],
                            "confidence": threat["confidence"],
                            "confidence_pct": f"{threat['confidence']*100:.0f}%",
                            "track_id": threat.get("track_id"),
                            "severity": "HIGH",
                            "camera": self.camera_name,
                            "status": "AI-Assisted Security Alert — investigator verification required",
                            "title": "POTENTIAL THREAT DETECTED",
                            "explanation": f"The threat model detected {threat['display']} at {threat['confidence']*100:.0f}% confidence. This is an AI-assisted security alert, not a confirmed crime.",
                        }
                        try:
                            evidence = self.capture_evidence(
                                event_type="Potential Threat",
                                object_name=threat["display"],
                                confidence=threat["confidence"],
                                track_id=threat.get("track_id"),
                                severity="HIGH",
                                frame=frame,
                            )
                            event["evidence_id"] = evidence["evidence_id"]
                            event["sha256"] = evidence["sha256"]
                        except Exception as error:
                            event["evidence_error"] = str(error)
                        with self.lock:
                            self._append_event(event)
                            last_alert = event

                    for anomaly in self._score_live_anomalies(general, change_score, now_ts):
                        when = _local_now()
                        event = {
                            "timestamp": when.strftime("%H:%M:%S"),
                            "timestamp_full": when.strftime("%Y-%m-%d %H:%M:%S"),
                            "event_type": anomaly["event_type"],
                            "object": anomaly["object"],
                            "confidence": anomaly.get("confidence"),
                            "confidence_pct": f"{anomaly['confidence']*100:.0f}%" if anomaly.get("confidence") is not None else "-",
                            "track_id": anomaly.get("track_id"),
                            "severity": anomaly["severity"],
                            "camera": self.camera_name,
                            "status": "Anomaly/event — investigator review required",
                            "explanation": anomaly["explanation"],
                        }
                        with self.lock:
                            self._append_event(event)
                    last_detections = detections

                elapsed = time.perf_counter() - started
                fps_window.append(1.0 / elapsed if elapsed > 0 else 0.0)
                fps = sum(fps_window) / max(len(fps_window), 1)
                if last_alert and (time.monotonic() - float(last_alert.get("_shown_at", now_ts))) > 4.0:
                    last_alert = None
                annotated = self._draw(frame, detections, last_alert, fps)
                jpeg = self._encode_jpeg(annotated)
                with self.lock:
                    self.latest_jpeg = jpeg
                    self.fps = fps
                    self.detections = detections
                    self.camera_status = "ONLINE"
        finally:
            capture.release()
            with self.lock:
                self.capture = None
                if self.running:
                    self.camera_status = "ERROR"
                else:
                    self.camera_status = "OFFLINE"
                self.running = False
                self.fps = 0.0

    def mjpeg_generator(self) -> Iterator[bytes]:
        placeholder = self._placeholder_jpeg("LIVE CCTV STOPPED")
        while True:
            with self.lock:
                running = self.running
                payload = self.latest_jpeg or placeholder
            yield b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" + payload + b"\r\n"
            if not running and self.latest_jpeg is None:
                time.sleep(0.2)
            else:
                time.sleep(0.04)

    def _placeholder_jpeg(self, message: str) -> bytes:
        canvas = np.zeros((360, 640, 3), dtype=np.uint8)
        canvas[:] = (15, 23, 42)
        cv2.putText(canvas, message, (80, 180), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (56, 189, 248), 2, cv2.LINE_AA)
        cv2.putText(canvas, "Click START LIVE CCTV", (150, 220), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (148, 163, 184), 1, cv2.LINE_AA)
        return self._encode_jpeg(canvas)

    def _public_event(self, event: dict[str, Any] | None) -> dict[str, Any] | None:
        if not event:
            return None
        return {key: value for key, value in event.items() if not str(key).startswith("_")}

    def status(self) -> dict[str, Any]:
        with self.lock:
            active_alert = next((item for item in self.alerts if item.get("event_type") == "Potential Threat"), None)
            return {
                "running": self.running,
                "camera": self.camera_name,
                "camera_source": str(self.camera_source),
                "status": self.camera_status,
                "fps": round(self.fps, 1),
                "error": self.last_error,
                "detections": list(self.detections),
                "events": [self._public_event(item) for item in self.events],
                "alerts": [self._public_event(item) for item in self.alerts],
                "active_alert": self._public_event(active_alert),
                "evidence": list(reversed(self.evidence_records[-25:])),
                "models": self.model_status(),
            }


live_cctv_engine = LiveCCTVEngine()
