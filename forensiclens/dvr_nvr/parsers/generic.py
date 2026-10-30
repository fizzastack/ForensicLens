"""Generic standard-media adapter; it makes no proprietary-format claims."""

from __future__ import annotations

from typing import Any

from .base import EvidenceContext, MatchResult


class GenericMediaParser:
    name = "generic_media"

    def can_parse(self, context: EvidenceContext) -> MatchResult:
        if context.fingerprint["artifact_kind"] == "video" and context.fingerprint["availability"] == "available":
            return MatchResult(True, "high", "Recognized standard video container signature.")
        return MatchResult(False, "none", "No supported generic video container signature.")

    def parse(self, context: EvidenceContext) -> dict[str, Any]:
        return {
            "recording_id": f"rec-{context.record['evidence_id'][3:]}",
            "evidence_file": context.record["relative_path"],
            "parent_evidence_id": context.record["evidence_id"],
            "sha256": context.record.get("original_sha256"),
            "discovery_status": "discovered",
            "container": {"value": context.fingerprint["signature"], "availability": "available"},
            "video_metadata": {
                "duration_seconds": None, "width": None, "height": None, "codec": None,
                "availability": "not_available",
                "reason": "Generic stream metadata parsing is not implemented for this container.",
            },
            "parser": {"name": self.name, "status": "supported", "reason": None},
        }
