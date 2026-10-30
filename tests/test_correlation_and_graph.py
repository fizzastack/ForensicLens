"""Tests for ForensicLens Correlation Engine and Evidence Relationship Graph."""

import unittest

from forensiclens.correlation.engine import CorrelationEngine
from forensiclens.correlation.graph import EvidenceGraph, build_evidence_graph
from forensiclens.correlation.topology import CameraTopology


class CorrelationAndGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.events = [
            {
                "event_id": "fe-vid1-person_entered-000001-0001",
                "parent_evidence_id": "ev-vid1",
                "event_type": "person_entered",
                "assertion_type": "inferred_association",
                "video_timestamp_seconds": 2.0,
                "track_id": 10,
                "confidence": 0.9,
                "explanation": "Person entered through left boundary.",
                "frame_references": [{"frame_index": 5, "video_relative_timestamp_seconds": 2.0}],
            },
            {
                "event_id": "fe-vid1-movement_detected-000020-0002",
                "parent_evidence_id": "ev-vid1",
                "event_type": "movement_detected",
                "assertion_type": "detected_fact",
                "video_timestamp_seconds": 6.0,
                "track_id": 10,
                "confidence": 0.92,
                "explanation": "Track moved across frame.",
                "frame_references": [{"frame_index": 15, "video_relative_timestamp_seconds": 6.0}],
            },
            {
                "event_id": "fe-vid2-person_entered-000030-0003",
                "parent_evidence_id": "ev-vid2",
                "event_type": "person_entered",
                "assertion_type": "inferred_association",
                "video_timestamp_seconds": 12.0,
                "track_id": 20,
                "confidence": 0.88,
                "explanation": "Person entered camera 2.",
                "frame_references": [{"frame_index": 30, "video_relative_timestamp_seconds": 12.0}],
            },
        ]

        self.tracks = [
            {
                "parent_evidence_id": "ev-vid1",
                "track_id": 10,
                "class": "person",
                "duration_seconds": 8.0,
                "mean_confidence": 0.91,
                "displacement_pixels": 150.0,
            },
            {
                "parent_evidence_id": "ev-vid2",
                "track_id": 20,
                "class": "person",
                "duration_seconds": 5.0,
                "mean_confidence": 0.88,
                "displacement_pixels": 70.0,
            },
        ]

    def test_intra_camera_sequential_movement_correlation(self) -> None:
        engine = CorrelationEngine(config={"temporal_proximity_window_seconds": 15.0})
        correlations = engine.correlate_events(self.events, self.tracks)

        self.assertTrue(len(correlations) >= 1)
        seq_corr = next((c for c in correlations if c["relationship_type"] == "sequential_movement"), None)
        self.assertIsNotNone(seq_corr)
        self.assertEqual(seq_corr["source_event_id"], "fe-vid1-person_entered-000001-0001")
        self.assertEqual(seq_corr["target_event_id"], "fe-vid1-movement_detected-000020-0002")
        self.assertEqual(seq_corr["assertion_type"], "inferred_association")

    def test_cross_camera_topology_correlation(self) -> None:
        topo = CameraTopology()
        topo.add_camera("ev-vid1", "Gate Area")
        topo.add_camera("ev-vid2", "Lobby")
        topo.add_transition("ev-vid1", "ev-vid2", min_seconds=2.0, max_seconds=20.0, weight=1.0)

        engine = CorrelationEngine(config={"temporal_proximity_window_seconds": 25.0}, topology=topo)
        correlations = engine.correlate_events(self.events, self.tracks)

        cross_corr = next((c for c in correlations if c["relationship_type"] == "cross_camera_related_event"), None)
        self.assertIsNotNone(cross_corr)
        self.assertEqual(cross_corr["assertion_type"], "inferred_association")
        self.assertGreater(cross_corr["score"], 0.4)

    def test_evidence_graph_distinguishes_facts_and_inferences(self) -> None:
        report_data = {
            "case": {"case_id": "CASE-100", "investigation_title": "Graph Test"},
            "evidence_files": [{"evidence_id": "ev-file1", "filename": "log.txt", "size_bytes": 100}],
            "video_evidence": {"videos": [{"evidence_id": "ev-vid1", "filename": "cam1.mp4", "original_integrity": {"sha256": "hash1"}}]},
            "track_summary": self.tracks[:1],
            "forensic_events": self.events[:2],
        }

        corrs = [
            {
                "correlation_id": "corr-000001",
                "source_event_id": "fe-vid1-person_entered-000001-0001",
                "target_event_id": "fe-vid1-movement_detected-000020-0002",
                "relationship_type": "sequential_movement",
                "score": 0.85,
                "explanation": "Progression detected",
            }
        ]

        graph_dict = build_evidence_graph(report_data, corrs)
        self.assertIn("nodes", graph_dict)
        self.assertIn("edges", graph_dict)

        # Check detected facts vs inferred associations
        facts = [e for e in graph_dict["edges"] if e["assertion_type"] == "detected_fact"]
        inferred = [e for e in graph_dict["edges"] if e["assertion_type"] == "inferred_association"]

        self.assertTrue(len(facts) > 0)
        self.assertTrue(len(inferred) > 0)
        self.assertEqual(graph_dict["summary"]["detected_facts_count"], len(facts))
        self.assertEqual(graph_dict["summary"]["inferred_associations_count"], len(inferred))


if __name__ == "__main__":
    unittest.main()
