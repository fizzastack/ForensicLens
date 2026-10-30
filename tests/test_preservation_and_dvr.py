import tempfile
import unittest
from pathlib import Path

from PIL import Image

from forensiclens.analyzer import build_evidence_report, write_report
from forensiclens.preservation import sha256_file, verify_evidence


class PreservationAndDvrTests(unittest.TestCase):
    def test_verification_returns_match_then_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "evidence.bin"
            path.write_bytes(b"original evidence")
            expected = sha256_file(path)
            self.assertEqual(verify_evidence(path, expected)["status"], "MATCH")
            path.write_bytes(b"altered evidence")
            self.assertEqual(verify_evidence(path, expected)["status"], "MISMATCH")

    def test_dvr_core_marks_current_jpeg_evidence_as_non_dvr(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "evidence"
            root.mkdir()
            Image.new("RGB", (4, 4)).save(root / "photo.jpg")
            report = build_evidence_report(root)

            dvr = report["dvr_nvr_evidence"]
            self.assertEqual(dvr["device_identification"]["status"], "undetermined")
            self.assertEqual(dvr["storage_fingerprints"][0]["signature"], "jpeg")
            self.assertEqual(dvr["recordings"], [])
            self.assertEqual(report["evidence_files"][0]["integrity"]["post_processing"]["status"], "MATCH")

    def test_report_cannot_be_written_inside_evidence_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "evidence"
            root.mkdir()
            (root / "note.txt").write_text("read-only evidence", encoding="utf-8")
            report = build_evidence_report(root)
            with self.assertRaises(ValueError):
                write_report(report, root / "forbidden_report.json")


if __name__ == "__main__":
    unittest.main()
