"""Normalized evidence registry, lineage, and case-integrity report sections."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .integrity_chain import ChainOfCustody, PrivateEvidenceLedger, canonical_hash, detect_tampering


def _json_integrity(value: Any) -> tuple[str, str, int]:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), hashlib.md5(payload).hexdigest(), len(payload)


def _source_record(record: dict[str, Any], case_id: str, source: str) -> dict[str, Any]:
    integrity = record.get("integrity", {}).get("pre_processing", record.get("original_integrity", {}))
    return {
        "evidence_id": record["evidence_id"], "parent_evidence_id": None, "case_id": case_id,
        "relative_path": record.get("relative_path"), "filename": record.get("filename"),
        "evidence_type": "source_video" if record.get("video_metadata") else "source_file",
        "size_bytes": integrity.get("size_bytes", record.get("size_bytes")), "sha256": integrity.get("sha256", record.get("original_sha256")),
        "md5": integrity.get("md5"), "registration_timestamp_utc": None, "source": source,
        "operation": "evidence_registered", "status": "registered", "derived_from": None,
        "integrity_status": "MATCH" if record.get("integrity", {}).get("post_processing", record.get("post_processing_verification", {})).get("status") == "MATCH" else "UNAVAILABLE",
    }


def _derived_record(case_id: str, evidence_id: str, parent: str | None, evidence_type: str, operation: str, content: Any, relative_path: str, source: str) -> dict[str, Any]:
    sha256, md5, size = _json_integrity(content)
    return {
        "evidence_id": evidence_id, "parent_evidence_id": parent, "case_id": case_id, "relative_path": relative_path,
        "filename": Path(relative_path).name, "evidence_type": evidence_type, "size_bytes": size, "sha256": sha256, "md5": md5,
        "registration_timestamp_utc": None, "source": source, "operation": operation, "status": "derived",
        "derived_from": parent, "integrity_status": "MATCH",
    }


def get_evidence_lineage(registry: list[dict[str, Any]], evidence_id: str) -> list[dict[str, Any]]:
    by_id = {record["evidence_id"]: record for record in registry}
    lineage: list[dict[str, Any]] = []
    current = by_id.get(evidence_id)
    while current:
        lineage.append(current)
        current = by_id.get(current.get("parent_evidence_id"))
    return list(reversed(lineage))


def build_case_integrity(report: dict[str, Any], case_id: str, investigation_title: str) -> dict[str, Any]:
    """Build registry, immutable-style provenance views, and professional case metadata."""
    registry: list[dict[str, Any]] = []
    seen: set[str] = set()
    for source_record in report.get("video_evidence", {}).get("videos", []) + report.get("evidence_files", []):
        record = _source_record(source_record, case_id, "source_evidence")
        if record["evidence_id"] not in seen:
            seen.add(record["evidence_id"])
            registry.append(record)

    for video in report.get("video_evidence", {}).get("videos", []):
        parent = video["evidence_id"]
        content = {key: value for key, value in report.get("video_events", {}).items() if key not in {"events", "timeline_events"}}
        registry.append(_derived_record(case_id, f"drv-analysis-{parent[3:]}", parent, "analysis_result", "evidence_analyzed", content, f"derived/analysis/{parent}.json", "video_intelligence"))
    for event in report.get("forensic_events", []):
        registry.append(_derived_record(case_id, f"drv-event-{event['event_id'][3:]}", event["parent_evidence_id"], "forensic_event_artifact", "evidence_derived", event, f"derived/events/{event['event_id']}.json", "forensic_event_aggregation"))
    if report.get("ml_intelligence"):
        ml_parent = report.get("video_evidence", {}).get("videos", [{}])[0].get("evidence_id") if report.get("video_evidence", {}).get("videos") else None
        registry.append(_derived_record(case_id, "drv-ml-intelligence", ml_parent, "ml_analysis_artifact", "ml_intelligence_evaluated", report["ml_intelligence"], "derived/ml/ml_intelligence.json", "ml_subsystem"))
    if report.get("correlations"):
        corr_parent = report.get("video_evidence", {}).get("videos", [{}])[0].get("evidence_id") if report.get("video_evidence", {}).get("videos") else None
        registry.append(_derived_record(case_id, "drv-correlations", corr_parent, "correlation_artifact", "events_correlated", report["correlations"], "derived/correlation/correlations.json", "correlation_engine"))
    if report.get("evidence_graph"):
        graph_parent = report.get("video_evidence", {}).get("videos", [{}])[0].get("evidence_id") if report.get("video_evidence", {}).get("videos") else None
        registry.append(_derived_record(case_id, "drv-evidence-graph", graph_parent, "graph_artifact", "graph_constructed", report["evidence_graph"], "derived/graph/evidence_graph.json", "graph_subsystem"))

    report_content = {"case_id": case_id, "analysis_timestamp_utc": report.get("analysis_timestamp_utc"), "source_evidence_ids": sorted(seen)}
    primary_parent = next(iter(sorted(seen)), None)
    registry.append(_derived_record(case_id, "drv-case-report", primary_parent, "forensic_report", "report_generated", report_content, "reports/forensic_case_report.json", "report_generator"))

    chain, ledger = ChainOfCustody(case_id), PrivateEvidenceLedger()
    audit_extensions: list[dict[str, Any]] = []
    for record in registry:
        operations = ["evidence_registered", "evidence_hashed"] if record["parent_evidence_id"] is None else [record["operation"]]
        if record["evidence_type"] == "source_video":
            operations.append("evidence_analyzed")
        if record["integrity_status"] == "MATCH":
            operations.append("evidence_verified")
        for operation in operations:
            entry = chain.append(record["evidence_id"], operation, record["sha256"], record["source"], record["parent_evidence_id"], report.get("analysis_timestamp_utc"))
            ledger.append_ledger_entry(record["evidence_id"], operation, record["sha256"], entry["timestamp_utc"])
            audit_extensions.append({"timestamp_utc": entry["timestamp_utc"], "evidence_id": record["evidence_id"], "operation": operation, "source": "case_integrity", "status": "completed"})

    chain_verification, ledger_verification = chain.verify(), ledger.verify_ledger()
    audit_extensions.extend([
        {"timestamp_utc": report.get("analysis_timestamp_utc"), "evidence_id": None, "operation": "chain_verification", "source": "case_integrity", "status": chain_verification["status"]},
        {"timestamp_utc": report.get("analysis_timestamp_utc"), "evidence_id": None, "operation": "ledger_verification", "source": "private_evidence_ledger", "status": ledger_verification["status"]},
    ])
    return {
        "case": {"case_id": case_id, "investigation_title": investigation_title, "report_generation_time_utc": report.get("analysis_timestamp_utc")},
        "evidence_registry": registry,
        "chain_of_custody": {"entries": chain.entries, "verification": chain_verification},
        "private_evidence_ledger": {"ledger_type": "local_private_hash_linked", "public_blockchain": False, "blocks": ledger.blocks, "verification": ledger_verification},
        "integrity_summary": {"source_evidence_count": sum(record["parent_evidence_id"] is None for record in registry), "derived_evidence_count": sum(record["parent_evidence_id"] is not None for record in registry), "tamper_status": detect_tampering(chain, ledger)["status"]},
        "audit_extensions": audit_extensions,
        "limitations": [
            "The hash-linked ledger is local/private and does not claim public-blockchain immutability or legal admissibility.",
            "Unsupported proprietary DVR/NVR formats remain unsupported.",
            "Track IDs are local to one video analysis.",
            "Video-relative timestamps are not wall-clock UTC.",
            "Inferred tracker, boundary, and correlation relationships remain strictly labeled as inferred.",
            "File-level sanitization applies solely to safe test copies; it does not replace physical drive degaussing.",
        ],
    }
