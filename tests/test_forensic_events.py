import unittest

from forensiclens.forensic_events import aggregate_forensic_events
from forensiclens.timeline import build_timeline


def detection(frame, timestamp, track_id, box, confidence=0.9, object_class="person"):
    return {"event_type": "object_detected", "assertion_type": "detected_fact", "parent_evidence_id": "ev-video", "video_timestamp_seconds": timestamp, "frame_reference": {"frame_index": frame}, "object": {"class": object_class, "confidence": confidence, "bounding_box_xyxy": box, "track_id": track_id}}


class ForensicEventTests(unittest.TestCase):
    def test_lifecycle_events_features_and_triage_are_deterministic(self) -> None:
        events = [detection(0, 0.0, 1, [0, 10, 20, 40]), detection(10, 5.0, 1, [100, 10, 120, 40]), detection(20, 12.0, 1, [180, 10, 200, 40]), detection(10, 5.0, 2, [50, 10, 70, 40], object_class="car")]
        video_evidence = {"videos": [{"evidence_id": "ev-video", "original_integrity": {"sha256": "sourcehash"}, "video_metadata": {"width": 200, "height": 100}}]}
        result = aggregate_forensic_events({"events": events}, video_evidence, {"prolonged_presence_seconds": 10, "movement_displacement_pixels": 30, "detection_burst_count": 2})
        track = next(item for item in result["track_summary"] if item["track_id"] == 1)
        self.assertEqual(track["duration_seconds"], 12.0)
        self.assertEqual(track["entry_edge"], "left")
        event_types = {item["event_type"] for item in result["forensic_events"]}
        self.assertTrue({"prolonged_presence", "movement_detected", "multiple_objects_present", "detection_burst"}.issubset(event_types))
        self.assertTrue(all(item["source_sha256"] == "sourcehash" for item in result["forensic_events"]))
        self.assertTrue(result["forensic_features"])
        self.assertGreater(result["triage_summary"]["items"][0]["triage_score"], 0)

    def test_missing_track_ids_and_empty_detections_are_safe(self) -> None:
        result = aggregate_forensic_events({"events": [detection(0, 0.0, None, [0, 0, 2, 2])]}, {"videos": []})
        self.assertEqual(result["track_summary"], [])
        self.assertEqual(result["forensic_events"], [])

    def test_boundary_entry_exit_are_inferred_and_features_repeat_exactly(self) -> None:
        events = [
            detection(0, 0.0, 99, [30, 20, 50, 50]),
            detection(5, 2.5, 1, [0, 10, 20, 40]),
            detection(10, 5.0, 1, [180, 10, 200, 40]),
            detection(15, 7.5, 99, [30, 20, 50, 50]),
        ]
        evidence = {"videos": [{"evidence_id": "ev-video", "original_integrity": {"sha256": "sourcehash"}, "video_metadata": {"width": 200, "height": 100}}]}
        first = aggregate_forensic_events({"events": events}, evidence, {"movement_displacement_pixels": 500})
        second = aggregate_forensic_events({"events": events}, evidence, {"movement_displacement_pixels": 500})
        relevant = [event for event in first["forensic_events"] if event.get("track_id") == 1]
        self.assertEqual({event["event_type"] for event in relevant}, {"person_entered", "person_exited"})
        self.assertTrue(all(event["assertion_type"] == "inferred_association" for event in relevant))
        self.assertEqual(first["forensic_features"], second["forensic_features"])

    def test_forensic_timeline_events_keep_video_relative_order(self) -> None:
        event = {"timestamp": "12.000000", "timestamp_kind": "video_relative_seconds", "event_type": "movement_detected", "evidence_file": "video.mp4", "description": "movement", "source": "test", "availability": "available"}
        timeline = build_timeline([], "2026-01-01T00:00:00Z", [event])
        self.assertEqual(timeline[0]["timestamp_kind"], "video_relative_seconds")


if __name__ == "__main__":
    unittest.main()
