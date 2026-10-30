"""Unit tests for ForensicLens Live USB & Removable Storage Monitor."""

import json
import tempfile
import time
import unittest
from pathlib import Path

from forensiclens.dashboard.app import create_app
from forensiclens.usb_monitor import (
    USBDevice,
    USBForensicEvent,
    USBMonitorManager,
    compute_file_sha256,
    get_local_now,
    get_utc_now,
    usb_monitor,
)


class TestUSBMonitor(unittest.TestCase):
    def setUp(self) -> None:
        self.manager = USBMonitorManager(poll_interval_seconds=0.2)

    def tearDown(self) -> None:
        self.manager.stop()

    def test_utc_and_local_now(self) -> None:
        utc_ts = get_utc_now()
        local_ts = get_local_now()
        self.assertIn("T", utc_ts)
        self.assertIsInstance(local_ts, str)
        self.assertGreater(len(local_ts), 10)

    def test_compute_file_sha256(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"FORENSIC_EVIDENCE_PAYLOAD_TEST")
            tmp_path = tf.name

        try:
            sha = compute_file_sha256(tmp_path)
            self.assertEqual(len(sha), 64)
            # Known sha256 for this exact payload
            import hashlib
            expected = hashlib.sha256(b"FORENSIC_EVIDENCE_PAYLOAD_TEST").hexdigest()
            self.assertEqual(sha, expected)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_usb_device_lifecycle(self) -> None:
        dev = USBDevice(
            drive_letter="E:\\",
            volume_label="SANDISK_USB",
            file_system="FAT32",
            serial_number="A1B2-C3D4",
            total_bytes=32000000000,
            used_bytes=1000000000,
            free_bytes=31000000000,
        )
        self.assertEqual(dev.status, "CONNECTED")
        self.assertIsNone(dev.disconnected_at_utc)

        time.sleep(0.1)
        dev.mark_disconnected()
        self.assertEqual(dev.status, "DISCONNECTED")
        self.assertIsNotNone(dev.disconnected_at_utc)
        self.assertGreaterEqual(dev.duration_seconds or 0, 0.0)

    def test_custom_watch_path_and_simulation(self) -> None:
        self.manager.start()
        res = self.manager.simulate_demo_activity()
        self.assertEqual(res.get("status"), "simulation_complete")

        status = self.manager.get_status()
        self.assertGreater(status["total_events_count"], 0)
        self.assertGreaterEqual(status["summary"]["files_created"], 1)
        self.assertGreaterEqual(status["summary"]["files_deleted"], 1)

        events = self.manager.get_events()
        self.assertGreater(len(events), 0)
        self.assertTrue(any(e["event_type"] == "FILE_CREATED" for e in events))

        # Check export formats
        json_report = self.manager.export_report_json()
        parsed = json.loads(json_report)
        self.assertEqual(parsed["report_type"], "FORENSICLENS_LIVE_USB_FORENSIC_AUDIT_LOG")

        md_report = self.manager.export_report_markdown()
        self.assertIn("# ForensicLens Live USB", md_report)

        csv_report = self.manager.export_report_csv()
        self.assertIn("Event ID,Timestamp UTC", csv_report)


class TestUSBDashboardAPI(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app()
        self.client = self.app.test_client()

    def test_get_usb_status_api(self) -> None:
        resp = self.client.get("/api/usb/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("is_monitoring", data)
        self.assertIn("summary", data)
        self.assertIn("all_devices", data)

    def test_get_usb_events_api(self) -> None:
        resp = self.client.get("/api/usb/events")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIsInstance(data["events"], list)

    def test_simulate_usb_activity_api(self) -> None:
        resp = self.client.post("/api/usb/simulate")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "simulation_complete")

    def test_toggle_usb_monitor_api(self) -> None:
        resp = self.client.post("/api/usb/monitor/toggle", json={"action": "add_custom", "custom_path": "dataset/test_usb_custom"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "success")

    def test_export_usb_reports_api(self) -> None:
        resp_json = self.client.get("/api/usb/export/json")
        self.assertEqual(resp_json.status_code, 200)
        self.assertEqual(resp_json.mimetype, "application/json")

        resp_md = self.client.get("/api/usb/export/markdown")
        self.assertEqual(resp_md.status_code, 200)
        self.assertEqual(resp_md.mimetype, "text/markdown")

        resp_csv = self.client.get("/api/usb/export/csv")
        self.assertEqual(resp_csv.status_code, 200)
        self.assertEqual(resp_csv.mimetype, "text/csv")


if __name__ == "__main__":
    unittest.main()
