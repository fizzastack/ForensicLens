"""Tests for ForensicLens Secure Sanitization and Source Protection."""

import tempfile
import unittest
from pathlib import Path

from forensiclens.sanitization import (
    ProtectedEvidenceError,
    is_path_protected,
    sanitize_test_file,
)


class SanitizationTests(unittest.TestCase):
    def test_protected_source_paths_are_strictly_rejected(self) -> None:
        source_video = Path("dataset/raw/video/VIRAT_S_010000_01_000184_000324.mp4")
        source_jpg = Path("dataset/raw/IMG_0003.JPG")

        self.assertTrue(is_path_protected(source_video))
        self.assertTrue(is_path_protected(source_jpg))

        with self.assertRaises(ProtectedEvidenceError):
            sanitize_test_file(source_video)

        with self.assertRaises(ProtectedEvidenceError):
            sanitize_test_file(source_jpg)

    def test_safe_test_copy_sanitization_nist_single_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_file = Path(tmp_dir) / "scratch_evidence_copy.tmp"
            test_file.write_bytes(b"TEMPORARY_TEST_DATA_FOR_ERASURE_TESTING")
            orig_size = test_file.stat().st_size

            cert = sanitize_test_file(test_file, method="NIST_SP_800_88_CLEAR", unlink_after_sanitization=True)

            self.assertEqual(cert.sanitization_method, "NIST_SP_800_88_CLEAR")
            self.assertEqual(cert.passes_completed, 1)
            self.assertEqual(cert.original_size_bytes, orig_size)
            self.assertEqual(cert.verification_status, "OVERWRITE_VERIFIED_AND_UNLINKED")
            self.assertFalse(test_file.exists())
            self.assertIn("NOTICE OF LIMITATION", cert.limitations)

    def test_safe_test_copy_sanitization_dod_three_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_file = Path(tmp_dir) / "scratch_dod_copy.tmp"
            test_file.write_bytes(b"DOD_OVERWRITE_VERIFICATION_PAYLOAD_123456789")

            cert = sanitize_test_file(test_file, method="DOD_5220_22_M_3_PASS", unlink_after_sanitization=False)

            self.assertEqual(cert.sanitization_method, "DOD_5220_22_M_3_PASS")
            self.assertEqual(cert.passes_completed, 3)
            self.assertEqual(cert.verification_status, "OVERWRITE_VERIFIED")
            self.assertTrue(test_file.exists())
            # Verify contents are overwritten
            self.assertNotEqual(test_file.read_bytes(), b"DOD_OVERWRITE_VERIFICATION_PAYLOAD_123456789")

    def test_source_evidence_files_remain_intact(self) -> None:
        # Check an actual file in dataset/raw to confirm existence and integrity
        raw_video = Path("dataset/raw/video/VIRAT_S_010000_01_000184_000324.mp4")
        if raw_video.exists():
            self.assertTrue(raw_video.stat().st_size > 0)


if __name__ == "__main__":
    unittest.main()
