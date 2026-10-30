"""Tests for ForensicLens Standardized Reporting Subsystem."""

import json
import tempfile
import unittest
from pathlib import Path

from forensiclens.reporting.generator import (
    export_standardized_reports,
    generate_html_report,
    generate_markdown_report,
)


class ReportingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report_data = {
            "analysis_timestamp_utc": "2026-08-31T12:00:00Z",
            "evidence_root": "dataset/raw",
            "case": {
                "case_id": "CASE-2026-TEST",
                "investigation_title": "Automated Test Case",
            },
            "evidence_files": [
                {
                    "evidence_id": "ev-file-01",
                    "filename": "IMG_0003.JPG",
                    "size_bytes": 840101,
                    "sha256": "1234567890abcdef" * 4,
                    "is_image": True,
                    "integrity": {"post_processing": {"status": "MATCH"}},
                }
            ],
            "video_evidence": {
                "videos": [
                    {
                        "evidence_id": "ev-vid-01",
                        "filename": "VIRAT_S_010000_01_000184_000324.mp4",
                        "original_integrity": {
                            "sha256": "11f452eba4ba48e45301d0d58f971c9edc8e0c41d8b7f214846d1602d4f175fe",
                            "md5": "d41d8cd98f00b204e9800998ecf8427e",
                            "size_bytes": 24789774,
                        },
                        "video_metadata": {
                            "width": 1920,
                            "height": 1080,
                            "fps": 30.0,
                            "frame_count": 1500,
                            "duration_seconds": 50.0,
                            "codec": {"value": "avc1"},
                        },
                        "post_processing_verification": {"status": "MATCH"},
                    }
                ]
            },
            "dvr_nvr_evidence": {
                "vendor_identification_status": "Generic MP4 / ISO Base Media",
                "active_parsers": ["Generic_MP4_H264"],
                "unsupported_files": [],
            },
            "timeline": [
                {
                    "timestamp": "2026-08-31T12:00:00Z",
                    "timestamp_kind": "analysis_utc",
                    "event_type": "file_discovered",
                    "evidence_file": "IMG_0003.JPG",
                    "description": "File discovered",
                }
            ],
            "forensic_events": [
                {
                    "event_id": "fe-vid-01-prolonged_presence-000100-0001",
                    "parent_evidence_id": "ev-vid-01",
                    "event_type": "prolonged_presence",
                    "assertion_type": "detected_fact",
                    "video_timestamp_seconds": 10.0,
                    "review_priority": "high",
                    "anomaly_score": 0.82,
                    "explanation": "Track detected for >10s.",
                }
            ],
            "track_summary": [
                {
                    "parent_evidence_id": "ev-vid-01",
                    "track_id": 1,
                    "class": "person",
                    "duration_seconds": 12.0,
                    "mean_confidence": 0.92,
                    "bounding_box_trajectory_summary": {
                        "displacement_pixels": 85.0,
                        "direction": "east",
                    },
                    "entry_edge": "left",
                    "exit_edge": "right",
                }
            ],
            "ml_intelligence": {
                "status": "available",
                "model_metadata": {
                    "model_architecture": "IsolationForest+StandardScaler",
                    "mode": "UNSUPERVISED",
                    "threshold": 0.65,
                    "metrics": {"anomaly_rate": 0.15, "inference_fps": 2500.0},
                },
            },
            "correlations": [
                {
                    "correlation_id": "corr-000001",
                    "relationship_type": "sequential_movement",
                    "score": 0.88,
                    "source_event_id": "fe-vid-01-prolonged_presence-000100-0001",
                    "target_event_id": "fe-vid-01-prolonged_presence-000100-0001",
                    "explanation": "Correlation test link",
                }
            ],
            "evidence_graph": {
                "node_count": 5,
                "edge_count": 4,
                "summary": {"detected_facts_count": 2, "inferred_associations_count": 2},
            },
            "chain_of_custody": {
                "verification": {"status": "CHAIN_VALID"},
                "entries": [
                    {
                        "chain_entry_id": "coc-000001",
                        "evidence_id": "ev-vid-01",
                        "operation": "evidence_registered",
                        "actor_source": "system",
                        "current_entry_hash": "a" * 64,
                        "timestamp_utc": "2026-08-31T12:00:00Z",
                    }
                ],
            },
            "private_evidence_ledger": {
                "ledger_type": "local_private_hash_linked",
                "verification": {"status": "CHAIN_VALID"},
                "blocks": [{"block_index": 0}],
            },
            "integrity_summary": {
                "tamper_status": "MATCH",
                "source_evidence_count": 2,
                "derived_evidence_count": 3,
            },
            "limitations": ["Test limitation notice."],
            "reproducibility_configuration": {"seed": 42},
        }

    def test_markdown_report_contains_all_18_sections(self) -> None:
        md = generate_markdown_report(self.report_data)
        for i in range(1, 19):
            self.assertIn(f"## {i}.", md)

    def test_html_report_generation(self) -> None:
        html = generate_html_report(self.report_data)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("CASE-2026-TEST", html)
        self.assertIn("<table>", html)

    def test_export_standardized_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = export_standardized_reports(self.report_data, output_dir=tmp_dir)
            self.assertTrue(paths["json"].is_file())
            self.assertTrue(paths["markdown"].is_file())
            self.assertTrue(paths["html"].is_file())

            # Validate exported JSON matches data
            with paths["json"].open("r", encoding="utf-8") as f:
                loaded = json.load(f)
            self.assertEqual(loaded["case"]["case_id"], "CASE-2026-TEST")


if __name__ == "__main__":
    unittest.main()
