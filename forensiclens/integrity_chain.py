"""Deterministic in-memory chain of custody and private evidence ledger."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


GENESIS_HASH = "0" * 64


def utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_hash(record: dict[str, Any]) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class ChainOfCustody:
    """Append-only hash-linked operation history held in report data."""

    def __init__(self, case_id: str) -> None:
        self.case_id = case_id
        self.entries: list[dict[str, Any]] = []

    def append(self, evidence_id: str, operation: str, evidence_sha256: str | None, actor: str, parent_evidence_id: str | None = None, timestamp_utc: str | None = None) -> dict[str, Any]:
        previous = self.entries[-1]["current_entry_hash"] if self.entries else GENESIS_HASH
        entry = {
            "chain_entry_id": f"coc-{len(self.entries) + 1:06d}", "evidence_id": evidence_id,
            "parent_evidence_id": parent_evidence_id, "case_id": self.case_id, "operation": operation,
            "timestamp_utc": timestamp_utc or utc_now(), "actor_source": actor,
            "evidence_sha256": evidence_sha256, "previous_entry_hash": previous,
        }
        entry["current_entry_hash"] = canonical_hash(entry)
        self.entries.append(entry)
        return entry.copy()

    def verify(self) -> dict[str, Any]:
        previous = GENESIS_HASH
        for entry in self.entries:
            check = {key: value for key, value in entry.items() if key != "current_entry_hash"}
            if entry.get("previous_entry_hash") != previous or entry.get("current_entry_hash") != canonical_hash(check):
                return {"status": "CHAIN_BROKEN", "broken_entry_id": entry.get("chain_entry_id")}
            previous = entry["current_entry_hash"]
        return {"status": "CHAIN_VALID", "entry_count": len(self.entries)}


class PrivateEvidenceLedger:
    """Local/private, hash-linked provenance ledger; it stores no evidence bytes."""

    def __init__(self) -> None:
        self.blocks: list[dict[str, Any]] = []

    def append_ledger_entry(self, evidence_id: str, operation: str, evidence_sha256: str | None, timestamp_utc: str | None = None) -> dict[str, Any]:
        previous = self.blocks[-1]["block_hash"] if self.blocks else GENESIS_HASH
        block = {
            "block_index": len(self.blocks), "timestamp_utc": timestamp_utc or utc_now(), "evidence_id": evidence_id,
            "operation": operation, "evidence_sha256": evidence_sha256, "previous_block_hash": previous,
        }
        block["block_hash"] = canonical_hash(block)
        self.blocks.append(block)
        return block.copy()

    def verify_ledger(self) -> dict[str, Any]:
        previous = GENESIS_HASH
        for block in self.blocks:
            check = {key: value for key, value in block.items() if key != "block_hash"}
            if block.get("previous_block_hash") != previous or block.get("block_hash") != canonical_hash(check):
                return {"status": "CHAIN_BROKEN", "broken_block_index": block.get("block_index")}
            previous = block["block_hash"]
        return {"status": "CHAIN_VALID", "block_count": len(self.blocks), "ledger_type": "local_private_hash_linked"}

    def get_evidence_history(self, evidence_id: str) -> list[dict[str, Any]]:
        return [block.copy() for block in self.blocks if block["evidence_id"] == evidence_id]


def verify_evidence_hash(path: Any, expected_hash: str | None) -> dict[str, Any]:
    from .preservation import verify_evidence
    return verify_evidence(path, expected_hash)


def verify_evidence_chain(chain: ChainOfCustody) -> dict[str, Any]:
    return chain.verify()


def detect_tampering(chain: ChainOfCustody, ledger: PrivateEvidenceLedger) -> dict[str, Any]:
    chain_result, ledger_result = chain.verify(), ledger.verify_ledger()
    return {"status": "MATCH" if chain_result["status"] == ledger_result["status"] == "CHAIN_VALID" else "MISMATCH", "chain": chain_result, "ledger": ledger_result}
