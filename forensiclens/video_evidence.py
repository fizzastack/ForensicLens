"""Read-only generic video evidence ingestion and metadata analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

import cv2

from .dvr_nvr.schema import evidence_id
from .preservation import capture_integrity, verify_evidence


VIDEO_EXTENSIONS = {".avi", ".m2ts", ".mkv", ".mov", ".mp4", ".mpeg", ".mpg", ".mts", ".wmv"}


def _audit(audit_log: list[dict[str, Any]], timestamp: str, evidence_id_value: str, operation: str, status: str) -> None:
    audit_log.append({
        "timestamp_utc": timestamp,
        "evidence_id": evidence_id_value,
        "operation": operation,
        "source": "video_evidence",
        "status": status,
    })


def _container_from_header(path: Path) -> dict[str, str]:
    try:
        with path.open("rb") as evidence_file:
            header = evidence_file.read(32)
    except OSError as error:
        return {"value": None, "source": "file_header", "availability": "unavailable", "reason": str(error)}

    if len(header) >= 12 and header[4:8] == b"ftyp":
        return {"value": "ISO Base Media / MP4", "source": "file_header", "availability": "available"}
    if header.startswith(b"RIFF") and header[8:12] == b"AVI ":
        return {"value": "AVI", "source": "file_header", "availability": "available"}
    if header.startswith(b"\x1a\x45\xdf\xa3"):
        return {"value": "EBML / Matroska", "source": "file_header", "availability": "available"}
    if path.suffix.lower() in VIDEO_EXTENSIONS:
        return {
            "value": path.suffix.lstrip(".").upper(),
            "source": "filename_extension",
            "availability": "undetermined",
            "reason": "No implemented container signature matched the file header.",
        }
    return {"value": None, "source": "file_header", "availability": "unsupported", "reason": "Not a recognized video extension or container signature."}


def _fourcc_to_string(value: float) -> str | None:
    code = int(value)
    if code <= 0:
        return None
    characters = "".join(chr((code >> (8 * index)) & 0xFF) for index in range(4))
    return characters.rstrip("\x00") or None


def _number_or_none(value: float, integer: bool = False) -> int | float | None:
    if value <= 0:
        return None
    return int(round(value)) if integer else float(value)


def _probe_video(path: Path) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    capture = cv2.VideoCapture(str(path))
    try:
        if not capture.isOpened():
            return {
                "duration_seconds": None, "width": None, "height": None, "fps": None,
                "frame_count": None, "codec": {"value": None, "availability": "unavailable"},
                "availability": "unsupported",
            }, ["Video capture backend could not open this file."]

        width = _number_or_none(capture.get(cv2.CAP_PROP_FRAME_WIDTH), integer=True)
        height = _number_or_none(capture.get(cv2.CAP_PROP_FRAME_HEIGHT), integer=True)
        fps = _number_or_none(capture.get(cv2.CAP_PROP_FPS))
        frame_count = _number_or_none(capture.get(cv2.CAP_PROP_FRAME_COUNT), integer=True)
        codec = _fourcc_to_string(capture.get(cv2.CAP_PROP_FOURCC))
        duration = (frame_count / fps) if frame_count is not None and fps is not None else None
        availability = "available" if any(value is not None for value in (width, height, fps, frame_count, codec)) else "unavailable"
        if availability == "unavailable":
            errors.append("Video capture backend returned no usable metadata.")
        return {
            "duration_seconds": duration,
            "width": width,
            "height": height,
            "fps": fps,
            "frame_count": frame_count,
            "codec": {"value": codec, "availability": "available" if codec else "unavailable"},
            "availability": availability,
        }, errors
    finally:
        capture.release()


def analyze_video_file(path: Path, video_root: Path, analysis_timestamp_utc: str, audit_log: list[dict[str, Any]]) -> dict[str, Any]:
    """Ingest one video without modifying the source path."""
    original_integrity = capture_integrity(path)
    relative_path = path.relative_to(video_root).as_posix()
    record: dict[str, Any] = {
        "evidence_id": evidence_id(original_integrity["sha256"], relative_path),
        "relative_path": relative_path,
        "filename": path.name,
        "original_integrity": original_integrity,
        "errors": [],
    }
    _audit(audit_log, analysis_timestamp_utc, record["evidence_id"], "video_original_sha256_calculated", original_integrity["status"])

    record["container"] = _container_from_header(path)
    metadata, errors = _probe_video(path)
    record["video_metadata"] = metadata
    record["errors"].extend(errors)
    record["processing_status"] = "analyzed" if metadata["availability"] == "available" else "unsupported"
    _audit(audit_log, analysis_timestamp_utc, record["evidence_id"], "video_metadata_analyzed", record["processing_status"])

    record["post_processing_verification"] = verify_evidence(path, original_integrity["sha256"])
    _audit(
        audit_log, analysis_timestamp_utc, record["evidence_id"], "video_post_analysis_hash_verified",
        record["post_processing_verification"]["status"],
    )
    return record


def discover_video_evidence(video_root: Path, analysis_timestamp_utc: str, audit_log: list[dict[str, Any]]) -> dict[str, Any]:
    """Recursively discover and safely ingest candidate video files."""
    video_root = video_root.resolve()
    if not video_root.is_dir():
        return {
            "source_roots": [str(video_root)],
            "read_only_evidence_handling": {"source_evidence_write_policy": "prohibited"},
            "videos": [], "unsupported_videos": [], "derived_artifacts": [],
            "errors": [f"Video evidence directory does not exist: {video_root}"],
            "total_videos_discovered": 0, "videos_metadata_extracted": 0, "videos_with_errors": 0,
        }

    paths = sorted(path for path in video_root.rglob("*") if path.is_file() and path.suffix.lower() in VIDEO_EXTENSIONS)
    videos = [analyze_video_file(path, video_root, analysis_timestamp_utc, audit_log) for path in paths]
    unsupported = [
        {"evidence_file": video["relative_path"], "parent_evidence_id": video["evidence_id"], "reason": "; ".join(video["errors"]), "status": "unsupported"}
        for video in videos if video["processing_status"] == "unsupported"
    ]
    return {
        "source_roots": [str(video_root)],
        "read_only_evidence_handling": {"source_evidence_write_policy": "prohibited"},
        "videos": videos,
        "unsupported_videos": unsupported,
        "derived_artifacts": [],
        "errors": [],
        "total_videos_discovered": len(videos),
        "videos_metadata_extracted": sum(video["processing_status"] == "analyzed" for video in videos),
        "videos_with_errors": sum(bool(video["errors"]) for video in videos),
    }


def sample_frames(path: Path, frame_indices: Iterable[int], audit_log: list[dict[str, Any]] | None = None, evidence_id_value: str | None = None) -> list[dict[str, Any]]:
    """Read selected frames into memory only; no derived files are written."""
    capture = cv2.VideoCapture(str(path))
    if not capture.isOpened():
        capture.release()
        raise ValueError("Video capture backend could not open this file for frame sampling.")
    try:
        fps = _number_or_none(capture.get(cv2.CAP_PROP_FPS))
        samples: list[dict[str, Any]] = []
        for frame_index in sorted(set(frame_indices)):
            if frame_index < 0:
                continue
            capture.set(cv2.CAP_PROP_POS_FRAMES, frame_index)
            success, frame = capture.read()
            if not success:
                continue
            samples.append({
                "frame_index": frame_index,
                "timestamp_seconds": (frame_index / fps) if fps else None,
                "width": int(frame.shape[1]),
                "height": int(frame.shape[0]),
                "frame": frame,
            })
        if audit_log is not None and evidence_id_value is not None:
            _audit(audit_log, "in_memory", evidence_id_value, "video_frame_sampling_requested", "completed")
        return samples
    finally:
        capture.release()
