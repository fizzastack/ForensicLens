import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cv2

from forensiclens.video_evidence import discover_video_evidence, sample_frames


class FakeFrame:
    shape = (6, 8, 3)


class FakeCapture:
    def __init__(self, opened=True):
        self.opened = opened
        self.position = 0
        self.released = False

    def isOpened(self):
        return self.opened

    def get(self, property_id):
        values = {
            cv2.CAP_PROP_FRAME_WIDTH: 640,
            cv2.CAP_PROP_FRAME_HEIGHT: 480,
            cv2.CAP_PROP_FPS: 25,
            cv2.CAP_PROP_FRAME_COUNT: 100,
            cv2.CAP_PROP_FOURCC: float(ord("a") | (ord("v") << 8) | (ord("c") << 16) | (ord("1") << 24)),
        }
        return values.get(property_id, 0)

    def set(self, property_id, value):
        self.position = value

    def read(self):
        return (self.position != 99, FakeFrame())

    def release(self):
        self.released = True


class VideoEvidenceTests(unittest.TestCase):
    def _video_root(self, directory: str) -> Path:
        root = Path(directory) / "video"
        root.mkdir()
        (root / "sample.mp4").write_bytes(b"\x00\x00\x00\x18ftypisom")
        return root

    @patch("forensiclens.video_evidence.cv2.VideoCapture")
    def test_discovers_and_extracts_video_metadata(self, capture_factory) -> None:
        capture_factory.return_value = FakeCapture()
        with tempfile.TemporaryDirectory() as temporary_directory:
            report = discover_video_evidence(self._video_root(temporary_directory), "2026-01-01T00:00:00Z", [])
            video = report["videos"][0]
            self.assertEqual(report["total_videos_discovered"], 1)
            self.assertEqual(report["videos_metadata_extracted"], 1)
            self.assertEqual(video["container"]["value"], "ISO Base Media / MP4")
            self.assertEqual(video["video_metadata"]["duration_seconds"], 4.0)
            self.assertEqual(video["video_metadata"]["codec"]["value"], "avc1")
            self.assertEqual(video["post_processing_verification"]["status"], "MATCH")

    @patch("forensiclens.video_evidence.cv2.VideoCapture")
    def test_unsupported_video_does_not_crash(self, capture_factory) -> None:
        capture_factory.return_value = FakeCapture(opened=False)
        with tempfile.TemporaryDirectory() as temporary_directory:
            report = discover_video_evidence(self._video_root(temporary_directory), "2026-01-01T00:00:00Z", [])
            self.assertEqual(report["videos_with_errors"], 1)
            self.assertEqual(report["unsupported_videos"][0]["status"], "unsupported")

    @patch("forensiclens.video_evidence.cv2.VideoCapture")
    def test_frame_sampling_is_in_memory_and_skips_unreadable_frames(self, capture_factory) -> None:
        capture_factory.return_value = FakeCapture()
        samples = sample_frames(Path("placeholder.mp4"), [2, 99, 2])
        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0]["frame_index"], 2)
        self.assertEqual(samples[0]["timestamp_seconds"], 0.08)
        self.assertEqual((samples[0]["width"], samples[0]["height"]), (8, 6))


if __name__ == "__main__":
    unittest.main()
