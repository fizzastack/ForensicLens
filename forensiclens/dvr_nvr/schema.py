"""Vendor-independent DVR/NVR evidence schema helpers."""

from __future__ import annotations

from typing import Any


def evidence_id(sha256: str | None, relative_path: str) -> str:
    """Return a stable ID from the original hash, with a path fallback."""
    if sha256:
        return f"ev-{sha256[:16]}"
    return f"ev-path-{relative_path.encode('utf-8').hex()[:16]}"


def derived_artifact(
    artifact_id: str,
    parent_evidence_id: str,
    operation: str,
    integrity: dict[str, Any],
    relative_path: str,
) -> dict[str, Any]:
    """Build a normalized record for a future derived artifact."""
    return {
        "artifact_id": artifact_id,
        "is_derived": True,
        "parent_evidence_id": parent_evidence_id,
        "relative_path": relative_path,
        "creation_operation": operation,
        "integrity": integrity,
    }
