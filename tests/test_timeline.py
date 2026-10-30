import unittest

from forensiclens.timeline import build_timeline


ANALYSIS_TIME = "2026-08-31T03:10:00Z"


class TimelineTests(unittest.TestCase):
    def test_generates_required_events_from_available_metadata(self) -> None:
        records = [{
            "relative_path": "photo.jpg",
            "created_at_utc": "2026-08-30T01:00:00Z",
            "modified_at_utc": "2026-08-30T02:00:00Z",
            "sha256": "abc123",
            "image_metadata": {"width": 10, "exif": {"DateTimeOriginal": "2026:08:29 12:30:00"}},
            "errors": ["Unable to read a supplementary tag"],
        }]

        timeline = build_timeline(records, ANALYSIS_TIME)
        event_types = {event["event_type"] for event in timeline}

        self.assertTrue({
            "file_discovered", "file_metadata_analyzed", "sha256_calculated",
            "image_metadata_analyzed", "analysis_error", "file_created", "file_modified",
            "exif_timestamp_recorded",
        }.issubset(event_types))
        exif_event = next(event for event in timeline if event["event_type"] == "exif_timestamp_recorded")
        self.assertEqual(exif_event["timestamp_kind"], "exif_unzoned")
        self.assertEqual(exif_event["availability"], "available_unzoned")

    def test_missing_timestamps_are_handled_without_timestamp_events(self) -> None:
        records = [{
            "relative_path": "note.txt",
            "sha256": None,
            "errors": [],
        }]

        timeline = build_timeline(records, ANALYSIS_TIME)

        self.assertEqual([event["event_type"] for event in timeline], ["file_discovered", "file_metadata_analyzed"])
        self.assertTrue(all(event["timestamp"] == ANALYSIS_TIME for event in timeline))

    def test_utc_events_are_chronological_and_unzoned_exif_is_not_converted(self) -> None:
        records = [{
            "relative_path": "photo.jpg",
            "created_at_utc": "2026-08-29T01:00:00Z",
            "modified_at_utc": "2026-08-30T01:00:00Z",
            "sha256": "hash",
            "image_metadata": {"exif": {"DateTime": "2026:08:31 10:00:00"}},
            "errors": [],
        }]

        timeline = build_timeline(records, ANALYSIS_TIME)
        utc_events = [event for event in timeline if event["timestamp_kind"] != "exif_unzoned"]

        self.assertEqual(utc_events[0]["event_type"], "file_created")
        self.assertEqual(utc_events[1]["event_type"], "file_modified")
        exif_event = timeline[-1]
        self.assertEqual(exif_event["timestamp"], "2026:08:31 10:00:00")
        self.assertEqual(exif_event["timestamp_kind"], "exif_unzoned")


if __name__ == "__main__":
    unittest.main()
