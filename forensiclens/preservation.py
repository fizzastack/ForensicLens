"""Read-only evidence preservation and integrity verification helpers."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HASH_CHUNK_SIZE = 1024 * 1024


def utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    """Calculate SHA-256 using a read-only file handle."""
    digest = hashlib.sha256()
    with path.open("rb") as evidence_file:
        for chunk in iter(lambda: evidence_file.read(HASH_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_file(path: Path) -> dict[str, str]:
    """Calculate SHA-256 and MD5 together from one read-only stream."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with path.open("rb") as evidence_file:
        for chunk in iter(lambda: evidence_file.read(HASH_CHUNK_SIZE), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest()}


def capture_integrity(path: Path) -> dict[str, Any]:
    """Capture a size and SHA-256 snapshot without modifying evidence."""
    snapshot: dict[str, Any] = {"size_bytes": None, "sha256": None, "status": "unavailable"}
    try:
        snapshot["size_bytes"] = path.stat().st_size
        hashes = hash_file(path)
        snapshot.update(hashes)
        snapshot["status"] = "recorded"
    except OSError as error:
        snapshot["error"] = str(error)
    return snapshot


def verify_evidence(path: Path, expected_sha256: str | None) -> dict[str, Any]:
    """Recalculate a hash and return MATCH, MISMATCH, or UNAVAILABLE."""
    observed = capture_integrity(path)
    verification: dict[str, Any] = {
        "verification_timestamp_utc": utc_now(),
        "expected_sha256": expected_sha256,
        "observed_sha256": observed["sha256"],
        "observed_size_bytes": observed["size_bytes"],
    }
    if not expected_sha256 or observed["sha256"] is None:
        verification["status"] = "UNAVAILABLE"
        if "error" in observed:
            verification["error"] = observed["error"]
    elif observed["sha256"] == expected_sha256:
        verification["status"] = "MATCH"
    else:
        verification["status"] = "MISMATCH"
    return verification


def assert_output_outside_evidence(output_path: Path, evidence_root: Path) -> None:
    """Reject output paths inside the read-only evidence root."""
    try:
        output_path.resolve().relative_to(evidence_root.resolve())
    except ValueError:
        return
    raise ValueError("Writing inside the source evidence directory is not permitted.")
