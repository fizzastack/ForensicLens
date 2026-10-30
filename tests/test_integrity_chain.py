import tempfile
import unittest
from pathlib import Path

from forensiclens.evidence_registry import build_case_integrity, get_evidence_lineage
from forensiclens.integrity_chain import ChainOfCustody, PrivateEvidenceLedger, detect_tampering, verify_evidence_hash


class IntegrityChainTests(unittest.TestCase):
    def test_hash_match_and_mismatch_use_a_temporary_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "copy.bin"
            path.write_bytes(b"original")
            expected = verify_evidence_hash(path, None)["observed_sha256"]
            self.assertEqual(verify_evidence_hash(path, expected)["status"], "MATCH")
            path.write_bytes(b"changed")
            self.assertEqual(verify_evidence_hash(path, expected)["status"], "MISMATCH")

    def test_chain_and_ledger_detect_tampering(self) -> None:
        chain, ledger = ChainOfCustody("CASE-1"), PrivateEvidenceLedger()
        chain.append("ev-1", "evidence_registered", "a" * 64, "test")
        ledger.append_ledger_entry("ev-1", "evidence_registered", "a" * 64)
        self.assertEqual(chain.verify()["status"], "CHAIN_VALID")
        self.assertEqual(ledger.verify_ledger()["status"], "CHAIN_VALID")
        chain.entries[0]["operation"] = "changed"
        self.assertEqual(chain.verify()["status"], "CHAIN_BROKEN")
        self.assertEqual(detect_tampering(chain, ledger)["status"], "MISMATCH")

    def test_registry_lineage_chain_and_report_sections(self) -> None:
        report = {"analysis_timestamp_utc": "2026-01-01T00:00:00Z", "evidence_files": [{"evidence_id": "ev-source", "relative_path": "source.bin", "filename": "source.bin", "size_bytes": 3, "original_sha256": "a" * 64, "integrity": {"pre_processing": {"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 3}, "post_processing": {"status": "MATCH"}}}], "video_evidence": {"videos": []}, "video_events": {}, "forensic_events": []}
        result = build_case_integrity(report, "CASE-1", "Test")
        self.assertEqual(result["chain_of_custody"]["verification"]["status"], "CHAIN_VALID")
        self.assertEqual(result["private_evidence_ledger"]["verification"]["status"], "CHAIN_VALID")
        self.assertEqual(get_evidence_lineage(result["evidence_registry"], "ev-source")[0]["evidence_id"], "ev-source")
        self.assertTrue(result["audit_extensions"])


if __name__ == "__main__":
    unittest.main()
