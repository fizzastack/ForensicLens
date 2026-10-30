"""Tests for ForensicLens Dashboard API endpoints."""

import unittest
from forensiclens.dashboard.app import create_app


class DashboardAPITests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app()
        self.client = self.app.test_client()

    def test_index_route(self) -> None:
        resp = self.client.get('/')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"FORENSICLENS", resp.data)

    def test_case_api(self) -> None:
        resp = self.client.get('/api/case')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("case", data)
        self.assertIn("chain_of_custody", data)
        self.assertIn("private_evidence_ledger", data)

    def test_grounded_query_api(self) -> None:
        resp = self.client.post('/api/query', json={"query": "Show all person events."})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("grounded_answer", data)

    def test_sanitize_refusal_api(self) -> None:
        resp = self.client.post('/api/sanitize', json={"target_path": "dataset/raw/IMG_0003.JPG"})
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertEqual(data.get("status"), "rejected_protected")

    def test_sanitize_safe_copy_api(self) -> None:
        resp = self.client.post('/api/sanitize', json={
            "target_path": "scratch_sanitization_test/test_demo.tmp",
            "create_sample_if_missing": True,
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("status"), "success")
        self.assertIn("certificate", data)

    def test_export_report_api(self) -> None:
        resp_json = self.client.get('/api/report/export/json')
        self.assertEqual(resp_json.status_code, 200)
        self.assertEqual(resp_json.mimetype, "application/json")

        resp_md = self.client.get('/api/report/export/markdown')
        self.assertEqual(resp_md.status_code, 200)
        self.assertEqual(resp_md.mimetype, "text/markdown")

        resp_html = self.client.get('/api/report/export/html')
        self.assertEqual(resp_html.status_code, 200)
        self.assertEqual(resp_html.mimetype, "text/html")


if __name__ == "__main__":
    unittest.main()
