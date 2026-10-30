"""ForensicLens Machine Learning subsystem: Dataset preparation and feature extraction."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np


FEATURE_COLUMNS = [
    "duration_seconds",
    "mean_confidence",
    "max_confidence",
    "detection_count",
    "displacement_pixels",
    "mean_velocity_pixels_per_second",
    "object_count_in_window",
    "event_frequency_in_window",
    "is_person",
    "is_vehicle",
    "has_entry_edge",
    "has_exit_edge",
    "sequence_position",
]


def _safe_float(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default
    try:
        val = float(value)
        return default if np.isnan(val) or np.isinf(val) else val
    except (ValueError, TypeError):
        return default


def extract_features_from_track(track: dict[str, Any], index: int = 0) -> dict[str, float]:
    """Extract a standardized numerical feature vector from a track summary."""
    obj_class = str(track.get("class", "")).lower()
    is_person = 1.0 if obj_class == "person" else 0.0
    is_vehicle = 1.0 if obj_class in {"car", "truck", "bus", "motorcycle", "bicycle"} else 0.0

    duration = _safe_float(track.get("duration_seconds"), 0.0)
    displacement = _safe_float(
        track.get("bounding_box_trajectory_summary", {}).get("displacement_pixels")
        or track.get("displacement_pixels"),
        0.0,
    )
    velocity = displacement / duration if duration > 0 else 0.0

    entry_edge = track.get("entry_edge")
    exit_edge = track.get("exit_edge")

    return {
        "duration_seconds": duration,
        "mean_confidence": _safe_float(track.get("mean_confidence"), 0.5),
        "max_confidence": _safe_float(track.get("max_confidence"), 0.5),
        "detection_count": _safe_float(track.get("number_of_detections") or track.get("detection_count"), 1.0),
        "displacement_pixels": displacement,
        "mean_velocity_pixels_per_second": velocity,
        "object_count_in_window": _safe_float(track.get("object_count_in_window") or track.get("number_of_detections"), 1.0),
        "event_frequency_in_window": _safe_float(track.get("event_frequency_in_window"), 1.0),
        "is_person": is_person,
        "is_vehicle": is_vehicle,
        "has_entry_edge": 1.0 if entry_edge else 0.0,
        "has_exit_edge": 1.0 if exit_edge else 0.0,
        "sequence_position": float(index),
    }


def extract_features_from_event(event: dict[str, Any], index: int = 0) -> dict[str, float]:
    """Extract a standardized numerical feature vector from a forensic event."""
    event_type = event.get("event_type", "")
    is_person = 1.0 if "person" in event_type else 0.0
    is_vehicle = 1.0 if "vehicle" in event_type else 0.0

    confidence = _safe_float(event.get("confidence"), 0.5)
    refs = event.get("frame_references", [])
    ref_count = len(refs) if refs else 1.0

    # Calculate duration across frame references if available
    duration = 0.0
    if len(refs) >= 2:
        first_t = _safe_float(refs[0].get("video_relative_timestamp_seconds"))
        last_t = _safe_float(refs[-1].get("video_relative_timestamp_seconds"))
        duration = max(0.0, last_t - first_t)

    displacement = _safe_float(event.get("movement", {}).get("displacement_pixels"), 0.0)
    velocity = _safe_float(event.get("movement", {}).get("speed_pixels_per_second"), 0.0)

    return {
        "duration_seconds": duration,
        "mean_confidence": confidence,
        "max_confidence": confidence,
        "detection_count": float(ref_count),
        "displacement_pixels": displacement,
        "mean_velocity_pixels_per_second": velocity,
        "object_count_in_window": float(ref_count),
        "event_frequency_in_window": 1.0 / max(duration, 1.0),
        "is_person": is_person,
        "is_vehicle": is_vehicle,
        "has_entry_edge": 1.0 if "entered" in event_type else 0.0,
        "has_exit_edge": 1.0 if "exited" in event_type else 0.0,
        "sequence_position": float(index),
    }


def build_dataset_from_report(report_data: dict[str, Any]) -> tuple[np.ndarray, list[dict[str, Any]], list[str], str]:
    """Extract feature matrix and metadata from forensic report dictionary.

    Returns:
        (feature_matrix, metadata_records, feature_names, dataset_hash)
    """
    records: list[dict[str, Any]] = []
    matrix_rows: list[list[float]] = []

    # Process track summaries
    tracks = report_data.get("track_summary", [])
    for idx, track in enumerate(tracks):
        feats = extract_features_from_track(track, idx)
        row = [feats[col] for col in FEATURE_COLUMNS]
        matrix_rows.append(row)
        records.append({
            "record_type": "track",
            "parent_evidence_id": track.get("parent_evidence_id"),
            "track_id": track.get("track_id"),
            "event_id": None,
            "features": feats,
        })

    # Process forensic events
    events = report_data.get("forensic_events", [])
    for idx, event in enumerate(events):
        feats = extract_features_from_event(event, idx)
        row = [feats[col] for col in FEATURE_COLUMNS]
        matrix_rows.append(row)
        records.append({
            "record_type": "event",
            "parent_evidence_id": event.get("parent_evidence_id"),
            "track_id": event.get("track_id"),
            "event_id": event.get("event_id"),
            "features": feats,
        })

    if not matrix_rows:
        feature_matrix = np.empty((0, len(FEATURE_COLUMNS)), dtype=np.float32)
    else:
        feature_matrix = np.array(matrix_rows, dtype=np.float32)

    # Compute deterministic SHA-256 of the extracted dataset
    dataset_bytes = json.dumps(
        {"columns": FEATURE_COLUMNS, "records": records},
        sort_keys=True,
    ).encode("utf-8")
    dataset_hash = hashlib.sha256(dataset_bytes).hexdigest()

    return feature_matrix, records, FEATURE_COLUMNS, dataset_hash
