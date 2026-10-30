"""Parser selection for currently implemented adapters only."""

from __future__ import annotations

from typing import Any

from .parsers.base import EvidenceContext
from .parsers.generic import GenericMediaParser


def parse_with_registry(context: EvidenceContext) -> dict[str, Any]:
    parser = GenericMediaParser()
    match = parser.can_parse(context)
    if match.matched:
        return {"kind": "recording", "result": parser.parse(context)}
    return {
        "kind": "unsupported",
        "result": {
            "evidence_file": context.record["relative_path"],
            "parent_evidence_id": context.record["evidence_id"],
            "reason": match.reason,
            "source": "parser_registry",
            "status": "unsupported" if context.fingerprint["availability"] == "unsupported" else "not_applicable",
        },
    }
