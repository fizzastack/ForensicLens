"""End-to-End integration test for ForensicLens SIH PS 26150."""

import tempfile
import unittest
from pathlib import Path

from PIL import Image

from forensiclens.analyzer import build_evidence_report
from forensiclens.query.engine import GroundedQueryEngine
from forensiclens.reporting.generator import export_standardized_reports
from forensiclens.sanitization import ProtectedEvidenceError, sanitize_test_file


class EndToEndIntegrationTests(unittest.TestCase):
    def test_full_synthetic_pipeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evidence_dir = root / "evidence"
            evidence_dir.mkdir(parents=True)
            video_dir = root / "video"
            video_dir.mkdir(parents=True)
            models_dir = root / "models"
            reports_dir = root / "reports"

            # Create sample image
            img_path = evidence_dir / "test_frame.jpg"
            Image.new("RGB", (64, 64), color="blue").save(img_path)

            report = build_evidence_report(
                evidence_root=evidence_dir,
                video_root=video_dir,
                enable_video_intelligence=False,
                case_id="CASE-E2E-001",
                investigation_title="E2E Synthetic Pipeline Test",
                models_dir=models_dir,
            )

            self.assertEqual(report["case"]["case_id"], "CASE-E2E-001")
            self.assertEqual(report["total_evidence_files"], 1)
            self.assertEqual(report["chain_of_custody"]["verification"]["status"], "CHAIN_VALID")
            self.assertEqual(report["private_evidence_ledger"]["verification"]["status"], "CHAIN_VALID")
            self.assertEqual(report["integrity_summary"]["tamper_status"], "MATCH")

            # Query test
            engine = GroundedQueryEngine(report)
            ans = engine.query("What is the integrity status of the source video?")
            self.assertIn("Integrity Status", ans["grounded_answer"])

            # Reporting test
            exported = export_standardized_reports(report, output_dir=reports_dir)
            self.assertTrue(exported["json"].is_file())
            self.assertTrue(exported["markdown"].is_file())
            self.assertTrue(exported["html"].is_file())

            # Sanitization test on temporary copy
            test_copy = root / "safe_test_copy.tmp"
            test_copy.write_bytes(b"DATA_TO_ERASE")
            cert = sanitize_test_file(test_copy, method="NIST_SP_800_88_CLEAR")
            self.assertEqual(cert.verification_status, "OVERWRITE_VERIFIED_AND_UNLINKED")
            self.assertFalse(test_copy.exists())


if __name__ == "__main__":
    unittest.main()
