"""Normalized, evidence-backed forensic timeline generation."""

from __future__ import annotations

from datetime import datetime
from typing import Any


EXIF_TIMESTAMP_FIELDS = ("DateTimeOriginal", "DateTimeDigitized", "DateTime")


def _event(
    timestamp: str,
    event_type: str,
    evidence_file: str,
    description: str,
    source: str,
    availability: str,
    timestamp_kind: str,
) -> dict[str, str]:
    return {
        "timestamp": timestamp,
        "timestamp_kind": timestamp_kind,
        "event_type": event_type,
        "evidence_file": evidence_file,
        "description": description,
        "source": source,
        "availability": availability,
    }


def _utc_sort_value(timestamp: str) -> datetime | None:
    """Return a sortable UTC timestamp, or None for non-UTC/unreadable values."""
    try:
        value = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return value if value.tzinfo is not None else None


def _exif_sort_value(timestamp: str) -> datetime | None:
    """Parse the common timezone-free EXIF datetime representation without converting it."""
    try:
        return datetime.strptime(timestamp, "%Y:%m:%d %H:%M:%S")
    except (TypeError, ValueError):
        return None


def _timeline_sort_key(event: dict[str, str]) -> tuple[int, datetime, str, str]:
    if event["timestamp_kind"].endswith("_utc") or event["timestamp_kind"] == "analysis_utc":
        value = _utc_sort_value(event["timestamp"])
        if value is not None:
            return (0, value, event["evidence_file"], event["event_type"])
    if event["timestamp_kind"] == "exif_unzoned":
        value = _exif_sort_value(event["timestamp"])
        if value is not None:
            return (1, value, event["evidence_file"], event["event_type"])
    if event["timestamp_kind"] == "video_relative_seconds":
        try:
            return (2, datetime.fromtimestamp(float(event["timestamp"])), event["evidence_file"], event["event_type"])
        except (TypeError, ValueError, OverflowError):
            pass
    return (3, datetime.max, event["evidence_file"], event["event_type"])


def build_timeline(
    evidence_files: list[dict[str, Any]],
    analysis_timestamp_utc: str,
    additional_events: list[dict[str, str]] | None = None,
) -> list[dict[str, str]]:
    """Create events only for facts available in evidence records.

    UTC-source events are sorted chronologically. Timezone-free EXIF values are
    retained as reported and sorted after UTC events, never converted to UTC.
    """
    events: list[dict[str, str]] = []
    for record in evidence_files:
        evidence_file = record["relative_path"]
        events.append(_event(
            analysis_timestamp_utc, "file_discovered", evidence_file,
            "Evidence file discovered during analysis.", "analysis_process", "available", "analysis_utc",
        ))

        if record.get("created_at_utc"):
            events.append(_event(
                record["created_at_utc"], "file_created", evidence_file,
                "Filesystem creation timestamp recorded.", "filesystem_metadata", "available", "filesystem_created_utc",
            ))
        if record.get("modified_at_utc"):
            events.append(_event(
                record["modified_at_utc"], "file_modified", evidence_file,
                "Filesystem modification timestamp recorded.", "filesystem_metadata", "available", "filesystem_modified_utc",
            ))

        events.append(_event(
            analysis_timestamp_utc, "file_metadata_analyzed", evidence_file,
            "Basic filesystem metadata analyzed.", "analysis_process", "available", "analysis_utc",
        ))
        if record.get("sha256"):
            events.append(_event(
                analysis_timestamp_utc, "sha256_calculated", evidence_file,
                "SHA-256 hash calculated for the evidence file.", "analysis_process", "available", "analysis_utc",
            ))

        image_metadata = record.get("image_metadata")
        if isinstance(image_metadata, dict) and image_metadata:
            events.append(_event(
                analysis_timestamp_utc, "image_metadata_analyzed", evidence_file,
                "Available image metadata and EXIF data analyzed.", "image_metadata", "available", "analysis_utc",
            ))
            exif = image_metadata.get("exif", {})
            if isinstance(exif, dict):
                for field in EXIF_TIMESTAMP_FIELDS:
                    timestamp = exif.get(field)
                    if isinstance(timestamp, str) and timestamp:
                        availability = "available_unzoned" if _exif_sort_value(timestamp) else "available_unparsed"
                        events.append(_event(
                            timestamp, "exif_timestamp_recorded", evidence_file,
                            f"EXIF {field} timestamp recorded without a verified timezone.",
                            f"exif_metadata:{field}", availability, "exif_unzoned",
                        ))

        for error in record.get("errors", []):
            events.append(_event(
                analysis_timestamp_utc, "analysis_error", evidence_file,
                str(error), "analysis_process", "error_recorded", "analysis_utc",
            ))

    events.extend(additional_events or [])
    return sorted(events, key=_timeline_sort_key)
