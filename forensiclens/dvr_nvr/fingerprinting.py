"""Safe file-header and extension fingerprinting for DVR/NVR evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any


VIDEO_EXTENSIONS = {".avi", ".mkv", ".mov", ".mp4", ".mpeg", ".mpg", ".mts", ".m2ts", ".wmv"}
PROPRIETARY_OR_RAW_EXTENSIONS = {".264", ".dav", ".dvr", ".h264", ".hik", ".nvr", ".ps"}


def fingerprint_file(path: Path, record: dict[str, Any]) -> dict[str, Any]:
    """Identify only observable signatures; unknown formats remain unknown."""
    extension = record.get("extension", path.suffix.lower())
    header = b""
    error = None
    try:
        with path.open("rb") as evidence_file:
            header = evidence_file.read(32)
    except OSError as read_error:
        error = str(read_error)

    if header.startswith(b"\xff\xd8\xff"):
        kind, signature, availability = "image", "jpeg", "available"
    elif len(header) >= 12 and header[4:8] == b"ftyp":
        kind, signature, availability = "video", "iso_base_media", "available"
    elif header.startswith(b"RIFF") and header[8:12] == b"AVI ":
        kind, signature, availability = "video", "avi_riff", "available"
    elif header.startswith(b"\x1a\x45\xdf\xa3"):
        kind, signature, availability = "video", "ebml_container", "available"
    elif extension in PROPRIETARY_OR_RAW_EXTENSIONS:
        kind, signature, availability = "dvr_artifact", "unrecognized_proprietary_or_raw_extension", "unsupported"
    elif extension in VIDEO_EXTENSIONS:
        kind, signature, availability = "video", "extension_only", "undetermined"
    else:
        kind, signature, availability = "unknown", "unrecognized", "undetermined"

    fingerprint: dict[str, Any] = {
        "evidence_file": record["relative_path"],
        "artifact_kind": kind,
        "extension": extension,
        "signature": signature,
        "source": "file_header_and_extension",
        "availability": availability,
    }
    if error:
        fingerprint["read_error"] = error
    return fingerprint
