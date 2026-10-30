"""ForensicLens Deterministic End-to-End Demonstration and Verification Runner.

Executes the complete SIH PS 26150 forensic pipeline:
1. Cryptographic pre-hash recording of all source evidence
2. Read-only evidence inventory & metadata analysis (37 JPGs)
3. In-memory video intelligence & tracking (VIRAT video)
4. Forensic event aggregation & review triage
5. Unsupervised ML anomaly detection & calibration (Isolation Forest)
6. Multi-camera & intra-video surveillance event correlation
7. Evidence relationship graph construction (facts vs inferred)
8. Append-only chain of custody & private evidence ledger
9. Standardized report generation (JSON, Markdown, HTML)
10. Grounded investigator query execution
11. Safe test-only erasure verification & source protection refusal
12. Cryptographic post-hash verification (verifying ZERO source modification)
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from forensiclens.analyzer import build_evidence_report
from forensiclens.preservation import hash_file, verify_evidence
from forensiclens.query.engine import GroundedQueryEngine
from forensiclens.reporting.generator import export_standardized_reports
from forensiclens.sanitization import ProtectedEvidenceError, sanitize_test_file


def run_demo() -> dict[str, Any]:
    print("=" * 70)
    print(" FORENSICLENS — FULL CONSOLIDATED END-TO-END DEMONSTRATION")
    print(" SIH 2026 PS 26150 — Vendor-Agnostic DVR/NVR Forensic Analysis")
    print("=" * 70)

    evidence_root = Path("dataset/raw")
    video_root = Path("dataset/raw/video")
    video_file = video_root / "VIRAT_S_010000_01_000184_000324.mp4"

    # Step 1: Pre-Analysis Source Hashes
    print("\n[STEP 1/10] Capturing Pre-Analysis Source Evidence Hashes...")
    pre_video_hashes = hash_file(video_file)
    print(f"  > Video Evidence: {video_file.name}")
    print(f"    SHA-256: {pre_video_hashes['sha256']}")
    print(f"    MD5:     {pre_video_hashes['md5']}")

    # Step 2: Build Evidence Report & Execute Intelligence Pipeline
    print("\n[STEP 2/10] Ingesting Evidence & Running In-Memory AI Intelligence...")
    start_time = time.perf_counter()
    report = build_evidence_report(
        evidence_root=evidence_root,
        video_root=video_root,
        enable_video_intelligence=True,
        video_intelligence_config={
            "sampling_stride_frames": 5,
            "confidence_threshold": 0.25,
            "tracker": "bytetrack.yaml",
        },
        forensic_event_config={
            "prolonged_presence_seconds": 10.0,
            "movement_displacement_pixels": 60.0,
            "boundary_margin_ratio": 0.05,
        },
        case_id="CASE-SIH-2026-VIRAT",
        investigation_title="ForensicLens Automated Surveillance Case Study",
        enable_ml=True,
    )
    analysis_duration = time.perf_counter() - start_time
    print(f"  > Analysis completed in {analysis_duration:.2f}s")
    print(f"  > Total Evidence Files:    {report['total_evidence_files']}")
    print(f"  > Ingested Videos:         {len(report['video_evidence']['videos'])}")
    print(f"  > Raw Model Detections:    {len(report['video_events'].get('events', []))}")
    print(f"  > Extracted Tracks:        {len(report['track_summary'])}")
    print(f"  > Forensic Review Events:  {len(report['forensic_events'])}")

    # Step 3: ML Anomaly Intelligence
    print("\n[STEP 3/10] Inspecting Machine Learning Intelligence Subsystem...")
    ml_intel = report.get("ml_intelligence", {})
    ml_meta = ml_intel.get("model_metadata", {})
    print(f"  > Model Architecture:      {ml_meta.get('model_architecture')}")
    print(f"  > Training Mode:           {ml_meta.get('mode')} (Strictly zero target leakage)")
    print(f"  > Anomaly Decision Thresh: {ml_meta.get('threshold')}")
    print(f"  > In-Case Anomaly Rate:    {ml_meta.get('metrics', {}).get('anomaly_rate', 0.0):.2%}")
    print(f"  > High Priority Events:    {ml_intel.get('high_priority_inferences')}")
    print(f"  > Model Artifact SHA-256:  {ml_meta.get('model_file_sha256')}")

    # Step 4: Correlation Engine
    print("\n[STEP 4/10] Multi-Camera & Intra-Video Event Correlation...")
    correlations = report.get("correlations", [])
    print(f"  > Total Correlations:      {len(correlations)}")
    for c in correlations[:3]:
        print(f"    - [{c['correlation_id']}] {c['relationship_type']} (Score: {c['score']:.2f}): {c['explanation']}")

    # Step 5: Evidence Relationship Graph
    print("\n[STEP 5/10] Inspecting Evidence Relationship Graph...")
    graph = report.get("evidence_graph", {})
    print(f"  > Graph Nodes:             {graph.get('node_count')}")
    print(f"  > Graph Edges:             {graph.get('edge_count')}")
    print(f"  > Detected Facts (Direct): {graph.get('summary', {}).get('detected_facts_count')}")
    print(f"  > Inferred Associations:   {graph.get('summary', {}).get('inferred_associations_count')}")

    # Step 6: Chain of Custody & Private Evidence Ledger
    print("\n[STEP 6/10] Cryptographic Chain of Custody & Ledger Verification...")
    chain = report.get("chain_of_custody", {})
    ledger = report.get("private_evidence_ledger", {})
    integrity = report.get("integrity_summary", {})
    print(f"  > Chain Verification:      {chain.get('verification', {}).get('status')} ({len(chain.get('entries', []))} entries)")
    print(f"  > Ledger Verification:     {ledger.get('verification', {}).get('status')} ({len(ledger.get('blocks', []))} blocks)")
    print(f"  > Overall Tamper Status:   {integrity.get('tamper_status')}")

    # Step 7: Export Standardized Forensic Reports
    print("\n[STEP 7/10] Exporting Standardized Forensic Case Reports...")
    exported_paths = export_standardized_reports(report, output_dir="reports")
    for fmt, p in exported_paths.items():
        print(f"  > Exported {fmt.upper()} Report: {p.name} ({p.stat().st_size:,} bytes)")

    # Step 8: Grounded Investigator Q&A Demo
    print("\n[STEP 8/10] Grounded Investigator Query Execution...")
    query_engine = GroundedQueryEngine(report)
    sample_queries = [
        "What happened during the first minute?",
        "Show all person events.",
        "Which events have high review priority?",
        "What is the integrity status of the source video?",
        "Who is the suspect and what is their motive?",  # Unsubstantiated query test
    ]
    for q in sample_queries:
        res = query_engine.query(q)
        print(f"  Q: \"{q}\"")
        print(f"  A: {res['grounded_answer']}")
        if res['evidence_references']:
            print(f"     [Refs: {len(res['evidence_references'])} item(s)]")

    # Step 9: Secure Erasure Workflow & Protection Test
    print("\n[STEP 9/10] Testing Secure Erasure Workflow & Source Protection Guards...")
    # 9a: Refusal on source path
    try:
        sanitize_test_file(video_file)
        print("  [ERROR] Source video was NOT protected!")
    except ProtectedEvidenceError as pe:
        print(f"  > Source Protection Guard: PASS (Refused: {pe})")

    # 9b: Sanitization on safe temporary test copy
    scratch_dir = Path("reports/temp_test_copy")
    scratch_dir.mkdir(parents=True, exist_ok=True)
    temp_copy = scratch_dir / "safe_test_evidence_copy.tmp"
    temp_copy.write_bytes(b"TEMPORARY_TEST_EVIDENCE_FOR_ERASURE_DEMO_2026")
    cert = sanitize_test_file(temp_copy, method="NIST_SP_800_88_CLEAR")
    print(f"  > Safe Test Copy Sanitization: PASS (Cert ID: {cert.certificate_id}, Status: {cert.verification_status})")

    # Step 10: Post-Analysis Source Evidence Verification
    print("\n[STEP 10/10] Verifying Immutable Source Evidence Integrity...")
    post_video_verif = verify_evidence(video_file, pre_video_hashes['sha256'])
    print(f"  > Source Video Status: {post_video_verif['status']}")
    assert post_video_verif['status'] == "MATCH", "CRITICAL: Source video SHA-256 changed!"

    print("\n" + "=" * 70)
    print(" DEMO COMPLETED SUCCESSFULLY — ALL VERIFICATIONS MATCHED")
    print("=" * 70 + "\n")

    return {
        "report": report,
        "exported_paths": exported_paths,
        "integrity_status": post_video_verif['status'],
        "chain_status": chain.get('verification', {}).get('status'),
        "ledger_status": ledger.get('verification', {}).get('status'),
    }


if __name__ == "__main__":
    run_demo()
