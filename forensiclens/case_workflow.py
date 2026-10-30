"""Investigator workflow services.  All state is derived metadata; source evidence is never changed."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import cv2

from .preservation import sha256_file, verify_evidence


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class CaseWorkspace:
    """Small JSON-backed workspace for review and collaboration metadata."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, Any] = {"reviews": {}, "notes": [], "evidence_status": {}, "alerts": [], "workflow": {}}
        if path.is_file():
            try:
                self.data.update(json.loads(path.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, OSError):
                pass

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")

    def review(self, event_id: str, decision: str, reason: str, investigator: str) -> dict[str, Any]:
        record = {"event_id": event_id, "decision": decision, "reason": reason, "investigator": investigator, "timestamp_utc": now_utc()}
        self.data["reviews"][event_id] = record
        self.save()
        return record

    def add_note(self, body: str, author: str, target_id: str | None = None) -> dict[str, Any]:
        note = {"note_id": hashlib.sha256(f"{now_utc()}:{body}".encode()).hexdigest()[:12], "body": body, "author": author, "target_id": target_id, "timestamp_utc": now_utc()}
        self.data["notes"].append(note)
        self.save()
        return note


def authenticity_risk(video: dict[str, Any], source_root: Path, max_samples: int = 30) -> dict[str, Any]:
    """Conservative screening only: signals prompt review and do not establish manipulation."""
    path = source_root / video["relative_path"]
    if not path.is_file():
        return {"status": "unavailable", "signals": [], "disclaimer": "Screening could not locate video file."}

    capture = cv2.VideoCapture(str(path))
    if not capture.isOpened():
        return {"status": "unavailable", "signals": [], "disclaimer": "Screening could not open this video."}

    hashes: list[str] = []
    diffs: list[float] = []
    prior = None
    fps = 0.0

    try:
        total = int(capture.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        fps = float(capture.get(cv2.CAP_PROP_FPS) or 0)
        step = max(1, total // max_samples) if total else 1

        count = 0
        frame_idx = 0
        while capture.isOpened() and count < max_samples:
            ok = capture.grab()
            if not ok:
                break
            if frame_idx % step == 0:
                ret, frame = capture.retrieve()
                if ret and frame is not None:
                    small = cv2.resize(cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY), (64, 36))
                    hashes.append(hashlib.sha256(small.tobytes()).hexdigest())
                    if prior is not None:
                        diffs.append(float(cv2.absdiff(prior, small).mean() / 255.0))
                    prior = small
                    count += 1
            frame_idx += 1
    except Exception:
        pass
    finally:
        capture.release()

    duplicate_count = len(hashes) - len(set(hashes))
    signals: list[dict[str, Any]] = []
    if duplicate_count:
        signals.append({"kind": "repeated_sampled_frame", "severity": "medium", "detail": f"{duplicate_count} repeated low-resolution sampled frame fingerprint(s) detected."})
    if diffs and max(diffs) > 0.65:
        signals.append({"kind": "abrupt_visual_discontinuity", "severity": "low", "detail": "A large sampled frame-to-frame change was detected; a cut or scene change may explain it."})
    if not fps:
        signals.append({"kind": "missing_frame_rate", "severity": "low", "detail": "Frame rate metadata was unavailable."})
    return {"status": "review_required" if signals else "no_screening_signal", "method": "sampled perceptual frame fingerprints", "sample_count": len(hashes), "signals": signals, "disclaimer": "This is a triage screen, not proof of editing, deepfake content, or authenticity."}


def search_tracks(report: dict[str, Any], object_class: str | None, time_start: float | None, time_end: float | None) -> list[dict[str, Any]]:
    results = []
    for track in report.get("track_summary", []):
        if object_class and track.get("class") != object_class:
            continue
        start, end = track.get("first_timestamp_seconds", 0), track.get("last_timestamp_seconds", 0)
        if time_start is not None and end < time_start or time_end is not None and start > time_end:
            continue
        results.append({key: track.get(key) for key in ("parent_evidence_id", "track_id", "class", "first_timestamp_seconds", "last_timestamp_seconds", "mean_confidence", "number_of_detections")})
    return results


def build_alerts(report: dict[str, Any]) -> list[dict[str, Any]]:
    alerts = []
    for event in report.get("forensic_events", []):
        if event.get("review_priority") == "high" or event.get("event_type") in {"person_entered", "vehicle_entered", "prolonged_presence"}:
            alerts.append({"alert_id": f"alert-{event['event_id']}", "event_id": event["event_id"], "timestamp_seconds": event.get("video_timestamp_seconds", 0), "type": event.get("event_type"), "status": "new", "message": event.get("explanation"), "disclaimer": "Automated alert; investigator verification required."})
    return alerts


def create_full_frame_private_copy(video: dict[str, Any], source_root: Path, output_dir: Path) -> dict[str, Any]:
    """Create a conservative full-frame blurred derivative when no face/plate detector is available."""
    source = source_root / video["relative_path"]
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / f"redacted_{source.stem}.mp4"
    capture = cv2.VideoCapture(str(source))
    if not capture.isOpened():
        raise ValueError("Unable to open source video for derived privacy export.")
    fps = float(capture.get(cv2.CAP_PROP_FPS) or 25.0)
    width, height = int(capture.get(cv2.CAP_PROP_FRAME_WIDTH)), int(capture.get(cv2.CAP_PROP_FRAME_HEIGHT))
    writer = cv2.VideoWriter(str(destination), cv2.VideoWriter_fourcc(*"mp4v"), fps, (width, height))
    while True:
        ok, frame = capture.read()
        if not ok:
            break
        writer.write(cv2.GaussianBlur(frame, (51, 51), 0))
    capture.release(); writer.release()
    return {"kind": "privacy_preserving_derived_video", "path": str(destination), "sha256": sha256_file(destination), "source_sha256_verification": verify_evidence(source, video.get("original_integrity", {}).get("sha256")), "method": "conservative full-frame blur", "disclaimer": "Derived share-copy only. Original evidence remains unchanged; this is not face/license-plate-specific redaction."}
