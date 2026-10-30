"""Pretrained, read-only video detection, tracking, and frame-change analysis."""

from __future__ import annotations

import hashlib
import importlib.metadata
import time
from pathlib import Path
from typing import Any, Callable

import cv2

from .preservation import sha256_file, verify_evidence


COCO_TARGET_CLASSES = {0: "person", 1: "bicycle", 2: "car", 3: "motorcycle", 5: "bus", 7: "truck"}
DEFAULT_CONFIG = {
    "model_name": "yolov8n.pt",
    "confidence_threshold": 0.25,
    "sampling_stride_frames": 5,
    "frame_change_threshold": 0.12,
    "tracker": "bytetrack.yaml",
}


def _audit(audit_log: list[dict[str, Any]], timestamp: str, evidence_id: str, operation: str, status: str) -> None:
    audit_log.append({
        "timestamp_utc": timestamp,
        "evidence_id": evidence_id,
        "operation": operation,
        "source": "video_intelligence",
        "status": status,
    })


def _runtime_versions() -> dict[str, str | None]:
    try:
        ultralytics_version = importlib.metadata.version("ultralytics")
    except importlib.metadata.PackageNotFoundError:
        ultralytics_version = None
    try:
        import torch
        return {"ultralytics_version": ultralytics_version, "torch_version": torch.__version__}
    except ImportError:
        return {"ultralytics_version": ultralytics_version, "torch_version": None}


def _load_model(config: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    """Load a pretrained model lazily, selecting CUDA only when available."""
    import torch
    from ultralytics import YOLO

    device: str | int = 0 if torch.cuda.is_available() else "cpu"
    model = YOLO(config["model_name"])
    weights_path = Path(getattr(model, "ckpt_path", config["model_name"]))
    weight_hash = sha256_file(weights_path) if weights_path.is_file() else None
    return model, {
        **_runtime_versions(),
        "device": "cuda:0" if device == 0 else "cpu",
        "model_weight_path": str(weights_path),
        "model_weight_sha256": weight_hash,
        "inference_device_argument": device,
    }


def _values(value: Any) -> list[Any]:
    if value is None:
        return []
    if hasattr(value, "cpu"):
        value = value.cpu()
    if hasattr(value, "tolist"):
        return value.tolist()
    return list(value)


def _extract_detections(result: Any) -> list[dict[str, Any]]:
    boxes = getattr(result, "boxes", None)
    if boxes is None:
        return []
    coordinates = _values(getattr(boxes, "xyxy", None))
    confidences = _values(getattr(boxes, "conf", None))
    classes = _values(getattr(boxes, "cls", None))
    track_ids = _values(getattr(boxes, "id", None))
    detections: list[dict[str, Any]] = []
    for index, coordinate in enumerate(coordinates):
        class_id = int(classes[index]) if index < len(classes) else -1
        if class_id not in COCO_TARGET_CLASSES:
            continue
        detections.append({
            "class": COCO_TARGET_CLASSES[class_id],
            "confidence": float(confidences[index]) if index < len(confidences) else None,
            "bounding_box_xyxy": [round(float(value), 2) for value in coordinate],
            "track_id": int(track_ids[index]) if index < len(track_ids) and track_ids[index] is not None else None,
        })
    return detections


def _frame_change_score(previous: Any, current: Any) -> float:
    previous_gray = cv2.cvtColor(previous, cv2.COLOR_BGR2GRAY)
    current_gray = cv2.cvtColor(current, cv2.COLOR_BGR2GRAY)
    if previous_gray.shape != current_gray.shape:
        current_gray = cv2.resize(current_gray, (previous_gray.shape[1], previous_gray.shape[0]))
    return float(cv2.absdiff(previous_gray, current_gray).mean() / 255.0)


def _event_id(parent_evidence_id: str, event_type: str, frame_index: int, sequence: int) -> str:
    seed = f"{parent_evidence_id}:{event_type}:{frame_index}:{sequence}".encode("utf-8")
    return f"evt-{hashlib.sha256(seed).hexdigest()[:16]}"


def _timeline_event(event: dict[str, Any], filename: str) -> dict[str, str]:
    return {
        "timestamp": f"{event['video_timestamp_seconds']:.6f}",
        "timestamp_kind": "video_relative_seconds",
        "event_type": event["event_type"],
        "evidence_file": filename,
        "parent_evidence_id": event["parent_evidence_id"],
        "description": event["description"],
        "source": event["source"],
        "availability": event["availability"],
    }


def analyze_video_intelligence(
    video_evidence: dict[str, Any],
    analysis_timestamp_utc: str,
    audit_log: list[dict[str, Any]],
    config: dict[str, Any] | None = None,
    model_loader: Callable[[dict[str, Any]], tuple[Any, dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Analyze video frames in memory and return only derived JSON findings."""
    settings = {**DEFAULT_CONFIG, **(config or {})}
    result: dict[str, Any] = {
        "status": "not_run",
        "configuration": {key: settings[key] for key in DEFAULT_CONFIG},
        "runtime": _runtime_versions(),
        "performance": {"frames_analyzed": 0, "inference_seconds": 0.0, "inference_fps": 0.0},
        "events": [],
        "timeline_events": [],
        "detections_by_class": {},
        "track_count": 0,
        "motion_change_event_count": 0,
        "errors": [],
        "derived_artifacts": [],
    }
    videos = video_evidence.get("videos", [])
    if not videos:
        result["status"] = "unavailable"
        result["errors"].append("No ingested video evidence is available for intelligence analysis.")
        return result

    try:
        model, runtime = (model_loader or _load_model)(settings)
        result["runtime"].update(runtime)
    except Exception as error:  # Model download/load failures must remain structured.
        result["status"] = "unavailable"
        result["errors"].append(f"Unable to load pretrained model: {error}")
        for video in videos:
            _audit(audit_log, analysis_timestamp_utc, video["evidence_id"], "video_intelligence_model_load", "unavailable")
        return result

    source_roots = [Path(root) for root in video_evidence.get("source_roots", [])]
    known_tracks: set[tuple[str, int]] = set()
    sequence = 0
    for video in videos:
        if not source_roots:
            result["errors"].append(f"No source root is recorded for {video['filename']}.")
            continue
        path = source_roots[0] / video["relative_path"]
        capture = cv2.VideoCapture(str(path))
        if not capture.isOpened():
            capture.release()
            result["errors"].append(f"Unable to open video for intelligence analysis: {video['relative_path']}")
            _audit(audit_log, analysis_timestamp_utc, video["evidence_id"], "video_intelligence_started", "unavailable")
            continue
        _audit(audit_log, analysis_timestamp_utc, video["evidence_id"], "video_intelligence_started", "started")
        fps = float(video.get("video_metadata", {}).get("fps") or 0.0)
        previous_frame = None
        frame_index = 0
        try:
            while True:
                success, frame = capture.read()
                if not success:
                    break
                if frame_index % settings["sampling_stride_frames"] != 0:
                    frame_index += 1
                    continue
                timestamp_seconds = frame_index / fps if fps > 0 else 0.0
                if previous_frame is not None:
                    change_score = _frame_change_score(previous_frame, frame)
                    if change_score >= settings["frame_change_threshold"]:
                        sequence += 1
                        change_event = {
                            "event_id": _event_id(video["evidence_id"], "frame_change_measured", frame_index, sequence),
                            "parent_evidence_id": video["evidence_id"],
                            "event_type": "frame_change_measured",
                            "assertion_type": "measured_frame_change",
                            "video_timestamp_seconds": timestamp_seconds,
                            "frame_reference": {"frame_index": frame_index, "video_relative_timestamp_seconds": timestamp_seconds},
                            "measurement": {"change_score": change_score, "threshold": settings["frame_change_threshold"]},
                            "description": "Frame-to-frame pixel change exceeded the configured threshold.",
                            "source": "frame_difference",
                            "availability": "available",
                        }
                        result["events"].append(change_event)
                        result["timeline_events"].append(_timeline_event(change_event, video["filename"]))
                        result["motion_change_event_count"] += 1
                previous_frame = frame

                start = time.perf_counter()
                try:
                    tracked = model.track(
                        frame, persist=True, tracker=settings["tracker"], conf=settings["confidence_threshold"],
                        classes=list(COCO_TARGET_CLASSES), verbose=False,
                        device=result["runtime"].get("inference_device_argument", "cpu"),
                    )
                    detections = _extract_detections(tracked[0] if tracked else None)
                except Exception as error:
                    sequence += 1
                    failure_event = {
                        "event_id": _event_id(video["evidence_id"], "inference_error", frame_index, sequence),
                        "parent_evidence_id": video["evidence_id"], "event_type": "inference_error",
                        "assertion_type": "analysis_error", "video_timestamp_seconds": timestamp_seconds,
                        "frame_reference": {"frame_index": frame_index, "video_relative_timestamp_seconds": timestamp_seconds},
                        "description": f"Inference failed: {error}", "source": "yolov8n", "availability": "error_recorded",
                    }
                    result["events"].append(failure_event)
                    result["timeline_events"].append(_timeline_event(failure_event, video["filename"]))
                    result["errors"].append(f"Frame {frame_index}: {error}")
                    frame_index += 1
                    continue
                result["performance"]["inference_seconds"] += time.perf_counter() - start
                result["performance"]["frames_analyzed"] += 1

                for detection in detections:
                    sequence += 1
                    detected_event = {
                        "event_id": _event_id(video["evidence_id"], "object_detected", frame_index, sequence),
                        "parent_evidence_id": video["evidence_id"], "event_type": "object_detected",
                        "assertion_type": "detected_fact", "video_timestamp_seconds": timestamp_seconds,
                        "frame_reference": {"frame_index": frame_index, "video_relative_timestamp_seconds": timestamp_seconds},
                        "object": {key: detection[key] for key in ("class", "confidence", "bounding_box_xyxy", "track_id")},
                        "description": f"Model detected {detection['class']} in sampled frame.",
                        "source": settings["model_name"], "availability": "available",
                    }
                    result["events"].append(detected_event)
                    result["timeline_events"].append(_timeline_event(detected_event, video["filename"]))
                    result["detections_by_class"][detection["class"]] = result["detections_by_class"].get(detection["class"], 0) + 1
                    if detection["track_id"] is not None:
                        track_key = (video["evidence_id"], detection["track_id"])
                        association_type = "track_started" if track_key not in known_tracks else "track_continued"
                        known_tracks.add(track_key)
                        sequence += 1
                        association_event = {
                            "event_id": _event_id(video["evidence_id"], association_type, frame_index, sequence),
                            "parent_evidence_id": video["evidence_id"], "event_type": association_type,
                            "assertion_type": "inferred_tracker_association", "video_timestamp_seconds": timestamp_seconds,
                            "frame_reference": {"frame_index": frame_index, "video_relative_timestamp_seconds": timestamp_seconds},
                            "track": {"track_id": detection["track_id"], "class": detection["class"]},
                            "description": f"ByteTrack associated a {detection['class']} with local track ID {detection['track_id']}.",
                            "source": settings["tracker"], "availability": "available",
                        }
                        result["events"].append(association_event)
                        result["timeline_events"].append(_timeline_event(association_event, video["filename"]))
                frame_index += 1
        finally:
            capture.release()
        video["post_intelligence_verification"] = verify_evidence(path, video["original_integrity"].get("sha256"))
        _audit(audit_log, analysis_timestamp_utc, video["evidence_id"], "video_post_intelligence_hash_verified", video["post_intelligence_verification"]["status"])
        _audit(audit_log, analysis_timestamp_utc, video["evidence_id"], "video_intelligence_completed", "completed")

    seconds = result["performance"]["inference_seconds"]
    result["performance"]["inference_fps"] = result["performance"]["frames_analyzed"] / seconds if seconds else 0.0
    result["track_count"] = len(known_tracks)
    result["status"] = "completed" if result["performance"]["frames_analyzed"] else "partial"
    return result
