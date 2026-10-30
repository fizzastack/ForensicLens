import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from forensiclens.analyzer import analyze_file, build_evidence_report, write_report


class AnalyzerTests(unittest.TestCase):
    def test_analyze_image_includes_hash_and_dimensions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            image_path = root / "sample.jpg"
            Image.new("RGB", (8, 6), color="red").save(image_path)

            record = analyze_file(image_path, root)

            self.assertTrue(record["is_image"])
            self.assertEqual(record["sha256"], hashlib.sha256(image_path.read_bytes()).hexdigest())
            self.assertEqual(record["original_sha256"], record["sha256"])
            self.assertEqual(record["integrity"]["post_processing"]["status"], "MATCH")
            self.assertEqual(record["image_metadata"]["width"], 8)
            self.assertEqual(record["image_metadata"]["height"], 6)
            self.assertEqual(record["errors"], [])

    def test_corrupted_image_records_error_without_failing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            corrupted_path = root / "corrupted.jpg"
            corrupted_path.write_bytes(b"not a JPEG")

            record = analyze_file(corrupted_path, root)

            self.assertTrue(record["is_image"])
            self.assertIsNotNone(record["sha256"])
            self.assertEqual(record["image_metadata"], {})
            self.assertTrue(record["errors"])

    def test_report_scans_recursively_and_writes_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "evidence"
            nested_directory = root / "nested"
            nested_directory.mkdir(parents=True)
            (root / "note.txt").write_text("evidence", encoding="utf-8")
            (nested_directory / "item.bin").write_bytes(b"binary evidence")

            report = build_evidence_report(root)
            output_path = Path(temporary_directory) / "report.json"
            write_report(report, output_path)

            self.assertEqual(report["total_evidence_files"], 2)
            self.assertEqual(report["image_file_count"], 0)
            self.assertIn("analysis_timestamp_utc", report)
            self.assertIn("timeline", report)
            self.assertIn("dvr_nvr_evidence", report)
            self.assertTrue(report["audit_log"])
            self.assertEqual(json.loads(output_path.read_text(encoding="utf-8")), report)


if __name__ == "__main__":
    unittest.main()
