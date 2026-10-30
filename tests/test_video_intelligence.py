import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cv2
import numpy as np

from forensiclens.video_intelligence import analyze_video_intelligence


class FakeBoxes:
    xyxy = np.array([[1, 2, 10, 20]], dtype=float)
    conf = np.array([0.9], dtype=float)
    cls = np.array([0], dtype=float)
    id = np.array([7], dtype=float)


class FakeResult:
    boxes = FakeBoxes()


class FakeModel:
    def track(self, *args, **kwargs):
        return [FakeResult()]


class FakeCapture:
    def __init__(self):
        self.index = 0

    def isOpened(self):
        return True

    def read(self):
        if self.index >= 3:
            return False, None
        frame = np.full((4, 4, 3), self.index * 100, dtype=np.uint8)
        self.index += 1
        return True, frame

    def release(self):
        pass


class VideoIntelligenceTests(unittest.TestCase):
    def _video_evidence(self, directory: str):
        root = Path(directory) / "video"
        root.mkdir()
        video = root / "sample.mp4"
        video.write_bytes(b"source")
        return {
            "source_roots": [str(root)],
            "videos": [{
                "evidence_id": "ev-test", "relative_path": "sample.mp4", "filename": "sample.mp4",
                "original_integrity": {"sha256": "c4b31"},
                "video_metadata": {"fps": 10},
            }],
        }

    @patch("forensiclens.video_intelligence.cv2.VideoCapture")
    def test_detection_tracking_motion_and_reproducibility(self, capture_factory) -> None:
        capture_factory.return_value = FakeCapture()
        with tempfile.TemporaryDirectory() as temporary_directory:
            evidence = self._video_evidence(temporary_directory)
            loader = lambda config: (FakeModel(), {"device": "cpu", "model_weight_sha256": "abc", "inference_device_argument": "cpu"})
            result = analyze_video_intelligence(evidence, "2026-01-01T00:00:00Z", [], {"sampling_stride_frames": 1, "frame_change_threshold": 0.01}, loader)
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["performance"]["frames_analyzed"], 3)
            self.assertEqual(result["detections_by_class"], {"person": 3})
            self.assertEqual(result["track_count"], 1)
            self.assertGreaterEqual(result["motion_change_event_count"], 1)
            assertion_types = {event["assertion_type"] for event in result["events"]}
            self.assertIn("detected_fact", assertion_types)
            self.assertIn("inferred_tracker_association", assertion_types)
            self.assertEqual(evidence["videos"][0]["post_intelligence_verification"]["status"], "MISMATCH")

    def test_model_load_failure_is_structured(self) -> None:
        result = analyze_video_intelligence({"source_roots": [], "videos": [{"evidence_id": "ev-test"}]}, "2026-01-01T00:00:00Z", [], model_loader=lambda config: (_ for _ in ()).throw(RuntimeError("offline")))
        self.assertEqual(result["status"], "unavailable")
        self.assertIn("Unable to load pretrained model", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
