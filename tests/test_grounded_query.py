"""Tests for ForensicLens Grounded Investigator Query Interface."""

import unittest

from forensiclens.query.engine import GroundedQueryEngine


class GroundedQueryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = {
            "case": {"case_id": "CASE-2026-001", "investigation_title": "Forensic Testing"},
            "evidence_files": [
                {"evidence_id": "ev-file-1", "filename": "IMG_0001.JPG", "size_bytes": 5000},
            ],
            "video_evidence": {
                "videos": [
                    {
                        "evidence_id": "ev-video-1",
                        "filename": "surveillance_feed_1.mp4",
                        "original_integrity": {"sha256": "abcdef1234567890" * 4},
                        "post_processing_verification": {"status": "MATCH"},
                    }
                ]
            },
            "forensic_events": [
                {
                    "event_id": "fe-video-1-person_entered-000010-0001",
                    "parent_evidence_id": "ev-video-1",
                    "event_type": "person_entered",
                    "assertion_type": "inferred_association",
                    "video_timestamp_seconds": 5.5,
                    "track_id": 2,
                    "review_priority": "high",
                    "anomaly_score": 0.78,
                    "explanation": "Person entered through left boundary.",
                    "frame_references": [{"frame_index": 10, "video_relative_timestamp_seconds": 5.5}],
                },
                {
                    "event_id": "fe-video-1-movement_detected-000030-0002",
                    "parent_evidence_id": "ev-video-1",
                    "event_type": "movement_detected",
                    "assertion_type": "detected_fact",
                    "video_timestamp_seconds": 12.0,
                    "track_id": 2,
                    "review_priority": "medium",
                    "anomaly_score": 0.45,
                    "explanation": "High velocity movement detected.",
                    "frame_references": [{"frame_index": 30, "video_relative_timestamp_seconds": 12.0}],
                },
            ],
            "track_summary": [
                {
                    "parent_evidence_id": "ev-video-1",
                    "track_id": 2,
                    "class": "person",
                    "duration_seconds": 8.0,
                    "mean_confidence": 0.89,
                    "review_priority": "high",
                    "bounding_box_trajectory_summary": {"displacement_pixels": 110.0},
                }
            ],
            "correlations": [
                {
                    "correlation_id": "corr-000001",
                    "relationship_type": "sequential_movement",
                    "score": 0.85,
                    "source_event_id": "fe-video-1-person_entered-000010-0001",
                    "target_event_id": "fe-video-1-movement_detected-000030-0002",
                    "explanation": "Track 2 entry followed by rapid movement.",
                    "evidence_references": [{"event_id": "fe-video-1-person_entered-000010-0001"}],
                }
            ],
            "chain_of_custody": {
                "verification": {"status": "CHAIN_VALID"},
                "entries": [
                    {
                        "chain_entry_id": "coc-000001",
                        "evidence_id": "ev-video-1",
                        "operation": "evidence_registered",
                        "timestamp_utc": "2026-08-31T00:00:00Z",
                        "actor_source": "ingestion",
                    }
                ],
            },
            "private_evidence_ledger": {
                "verification": {"status": "CHAIN_VALID"},
                "blocks": [{"block_index": 0, "operation": "evidence_registered"}],
            },
            "integrity_summary": {
                "tamper_status": "MATCH",
            },
        }
        self.engine = GroundedQueryEngine(self.report)

    def test_query_first_minute(self) -> None:
        res = self.engine.query("What happened during the first minute?")
        self.assertEqual(res["intent"], "time_window_query")
        self.assertIn("Found 2 forensic event(s)", res["grounded_answer"])
        self.assertTrue(len(res["evidence_references"]) == 2)

    def test_query_person_events(self) -> None:
        res = self.engine.query("Show all person events.")
        self.assertEqual(res["intent"], "class_query")
        self.assertIn("person", res["grounded_answer"])
        self.assertTrue(len(res["evidence_references"]) >= 1)

    def test_query_high_review_priority(self) -> None:
        res = self.engine.query("Which events have high review priority?")
        self.assertEqual(res["intent"], "priority_query")
        self.assertIn("high review priority", res["grounded_answer"])
        self.assertEqual(res["evidence_references"][0]["review_priority"], "high")

    def test_query_track_events(self) -> None:
        res = self.engine.query("Show all events linked to track 2.")
        self.assertEqual(res["intent"], "track_query")
        self.assertIn("Track 2", res["grounded_answer"])

    def test_query_correlation_support(self) -> None:
        res = self.engine.query("What evidence supports this correlation?")
        self.assertEqual(res["intent"], "correlation_query")
        self.assertIn("corr-000001", res["grounded_answer"])

    def test_query_integrity_status(self) -> None:
        res = self.engine.query("What is the integrity status of the source video?")
        self.assertEqual(res["intent"], "integrity_query")
        self.assertIn("MATCH", res["grounded_answer"])

    def test_query_custody_history(self) -> None:
        res = self.engine.query("Show the custody history of this evidence.")
        self.assertEqual(res["intent"], "custody_query")
        self.assertIn("Chain of Custody", res["grounded_answer"])

    def test_unsubstantiated_query_returns_insufficient_evidence(self) -> None:
        res = self.engine.query("Who is the suspect and what is their motive?")
        self.assertEqual(res["grounded_answer"], "Insufficient evidence in this case.")
        self.assertEqual(res["evidence_references"], [])


if __name__ == "__main__":
    unittest.main()
