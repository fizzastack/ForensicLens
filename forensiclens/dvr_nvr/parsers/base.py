"""Adapter contract for safe, read-only parser implementations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class EvidenceContext:
    path: Path
    record: dict[str, Any]
    fingerprint: dict[str, Any]


@dataclass(frozen=True)
class MatchResult:
    matched: bool
    confidence: str
    reason: str


class ParserAdapter(Protocol):
    name: str

    def can_parse(self, context: EvidenceContext) -> MatchResult:
        ...

    def parse(self, context: EvidenceContext) -> dict[str, Any]:
        ...
