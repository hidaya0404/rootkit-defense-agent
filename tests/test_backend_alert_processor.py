import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import context  # noqa: F401
from evidence_quarantine.backend_alert_processor import process_backend_ready_alerts
from evidence_quarantine.config import QuarantineConfig
from evidence_quarantine.quarantine_manager import QuarantineManager


class BackendAlertProcessorTest(unittest.TestCase):
    def test_process_backend_alert_quarantines_downloaded_artifact_and_sends_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage_root = Path(tmp) / "storage"
            downloaded = Path(tmp) / "downloaded.bin"
            downloaded.write_bytes(
                b"BENIGN BACKEND ARTIFACT\n"
                b"rootkit insmod /etc/ld.so.preload sys_call_table\n"
            )
            manager = QuarantineManager(QuarantineConfig(storage_root=storage_root))
            sent_manifests = []

            def fake_get_ready_alerts(backend_url, *, status, timeout):
                self.assertEqual(status, "ARTIFACT_READY")
                return [
                    {
                        "alert_id": "ALT-M4-READY-0001",
                        "status": "ARTIFACT_READY",
                        "risk_level": "HIGH",
                        "filename": "rk_demo.ko",
                        "details": {"path": "/tmp/rk_demo.ko"},
                        "download_url": "/api/artifacts/ALT-M4-READY-0001/download",
                    }
                ]

            def fake_download_backend_artifact(backend_url, alert_id, save_dir, *, timeout, filename, download_url):
                self.assertEqual(alert_id, "ALT-M4-READY-0001")
                target = Path(save_dir) / filename
                target.write_bytes(downloaded.read_bytes())
                return target

            def fake_post_quarantine_manifest_payload(backend_url, manifest, *, timeout):
                sent_manifests.append(manifest)
                return {"accepted": True}

            with patch(
                "evidence_quarantine.backend_alert_processor.get_ready_alerts",
                side_effect=fake_get_ready_alerts,
            ), patch(
                "evidence_quarantine.backend_alert_processor.download_backend_artifact",
                side_effect=fake_download_backend_artifact,
            ), patch(
                "evidence_quarantine.backend_alert_processor.post_quarantine_manifest_payload",
                side_effect=fake_post_quarantine_manifest_payload,
            ):
                summary = process_backend_ready_alerts(
                    manager,
                    "https://m4.example.test",
                    status="ARTIFACT_READY",
                )

            self.assertEqual(summary["processed_alerts"], 1)
            self.assertEqual(summary["sent_manifests"], 1)
            self.assertTrue(summary["results"][0]["success"])

            record = manager.get_evidence("ALT-M4-READY-0001")
            self.assertIsNotNone(record)
            self.assertEqual(record["status"], "READY_FOR_ANALYSIS")
            self.assertEqual(record["original_path"], "/tmp/rk_demo.ko")
            self.assertTrue(Path(record["backend_manifest_path"]).exists())

            manifest = sent_manifests[0]
            self.assertEqual(manifest["alert_id"], "ALT-M4-READY-0001")
            self.assertEqual(manifest["status"], "READY_FOR_ANALYSIS")
            self.assertEqual(manifest["source_alert_status"], "ARTIFACT_READY")
            self.assertEqual(manifest["original_path"], "/tmp/rk_demo.ko")
            self.assertEqual(manifest["hashes"]["sha256"], record["sha256"])

            saved_manifest = json.loads(Path(record["backend_manifest_path"]).read_text(encoding="utf-8"))
            self.assertEqual(saved_manifest["alert_id"], "ALT-M4-READY-0001")


if __name__ == "__main__":
    unittest.main()
