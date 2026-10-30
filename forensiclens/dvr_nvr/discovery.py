"""Vendor-neutral discovery pipeline for DVR/NVR-related evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .fingerprinting import fingerprint_file
from .parsers.base import EvidenceContext
from .registry import parse_with_registry


def _audit(audit_log: list[dict[str, Any]], timestamp: str, evidence_id: str, operation: str, status: str) -> None:
    audit_log.append({
        "timestamp_utc": timestamp,
        "evidence_id": evidence_id,
        "operation": operation,
        "source": "dvr_nvr_core",
        "status": status,
    })


def analyze_dvr_nvr_evidence(
    evidence_root: Path,
    evidence_files: list[dict[str, Any]],
    analysis_timestamp_utc: str,
    audit_log: list[dict[str, Any]],
) -> dict[str, Any]:
    """Fingerprint evidence and report only implemented parser capabilities."""
    fingerprints: list[dict[str, Any]] = []
    recordings: list[dict[str, Any]] = []
    unsupported: list[dict[str, Any]] = []
    camera_observations: list[dict[str, str]] = []

    for record in evidence_files:
        path = evidence_root / record["relative_path"]
        fingerprint = fingerprint_file(path, record)
        fingerprints.append(fingerprint)
        _audit(audit_log, analysis_timestamp_utc, record["evidence_id"], "storage_format_fingerprinted", fingerprint["availability"])

        exif = record.get("image_metadata", {}).get("exif", {})
        if isinstance(exif, dict) and exif.get("Make"):
            camera_observations.append({
                "evidence_file": record["relative_path"],
                "observation": f"Image EXIF camera make: {exif['Make']}",
                "source": "image_exif",
            })

        parsed = parse_with_registry(EvidenceContext(path, record, fingerprint))
        _audit(audit_log, analysis_timestamp_utc, record["evidence_id"], "parser_registry_evaluated", parsed["result"].get("status", "available"))
        if parsed["kind"] == "recording":
            recordings.append(parsed["result"])
        elif parsed["result"]["status"] == "unsupported":
            unsupported.append(parsed["result"])

    return {
        "schema_version": "1.0",
        "read_only_evidence_handling": {
            "source_evidence_write_policy": "prohibited",
            "source_evidence_root": str(evidence_root),
        },
        "device_identification": {
            "status": "undetermined",
            "candidates": [],
            "observations": camera_observations,
            "reason": "No implemented DVR/NVR vendor signature was found in the analyzed evidence.",
        },
        "storage_fingerprints": fingerprints,
        "recordings": recordings,
        "unsupported_artifacts": unsupported,
        "derived_artifacts": [],
    }
