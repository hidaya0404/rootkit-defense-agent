import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import context  # noqa: F401
from evidence_quarantine.config import QuarantineConfig
from evidence_quarantine.lab_simulator import RootkitLabSimulator
from evidence_quarantine.quarantine_manager import QuarantineManager
from evidence_quarantine.ui_server import build_cases, load_dashboard_alerts, load_sandbox_results


class UiServerTest(unittest.TestCase):
    def test_dashboard_alerts_include_quarantined_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = QuarantineConfig(storage_root=root / "storage")
            manager = QuarantineManager(config)
            RootkitLabSimulator(root / "victim").quarantine_scenario("kernel-module", manager)

            with patch.dict(os.environ, {"ROOTRAP_PENDING_ALERTS_FILE": str(root / "missing.jsonl")}):
                alerts = load_dashboard_alerts(config)

            self.assertEqual(len(alerts), 1)
            alert = alerts[0]
            self.assertEqual(alert["alert_id"], "ALT-LAB-KMOD-0001")
            self.assertEqual(alert["status"], "READY_FOR_ANALYSIS")
            self.assertEqual(alert["severity"], "HIGH")
            self.assertEqual(alert["source_module"], "m2-quarantine")
            self.assertTrue(alert["derived_from_quarantine"])
            self.assertEqual(alert["details"]["rootkit_category"], "kernel_module_rootkit_suspect")

    def test_remote_sandbox_results_are_scoped_to_local_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = QuarantineConfig(storage_root=root / "storage")
            manager = QuarantineManager(config)
            RootkitLabSimulator(root / "victim").quarantine_scenario("kernel-module", manager)

            remote_payload = {
                "results": [
                    {
                        "artifact_id": "ART-ALT-LAB-KMOD-0001",
                        "alert_id": "ALT-LAB-KMOD-0001",
                        "execution_status": "COMPLETED",
                    },
                    {
                        "artifact_id": "ART-OLD-REMOTE-TEST",
                        "alert_id": "ALT-OLD-REMOTE-TEST",
                        "execution_status": "COMPLETED",
                    },
                ]
            }

            with patch.dict(
                os.environ,
                {
                    "ROOTRAP_PENDING_ALERTS_FILE": str(root / "missing.jsonl"),
                    "ROOTRAP_STORAGE_ROOT": str(config.storage_root),
                    "ROOTRAP_ENABLE_REMOTE_DASHBOARD_DATA": "1",
                },
            ), patch("evidence_quarantine.ui_server.load_remote_json", return_value=(remote_payload, None)):
                results = load_sandbox_results()

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["artifact_id"], "ART-ALT-LAB-KMOD-0001")

    def test_cases_show_waiting_sandbox_stage(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = QuarantineConfig(storage_root=root / "storage")
            manager = QuarantineManager(config)
            RootkitLabSimulator(root / "victim").quarantine_scenario("kernel-module", manager)

            with patch.dict(
                os.environ,
                {
                    "ROOTRAP_PENDING_ALERTS_FILE": str(root / "missing.jsonl"),
                    "ROOTRAP_STORAGE_ROOT": str(config.storage_root),
                    "ROOTRAP_ENABLE_REMOTE_DASHBOARD_DATA": "0",
                },
            ):
                cases = build_cases(config)

            self.assertEqual(len(cases), 1)
            self.assertEqual(cases[0]["status"], "IN_PROGRESS")
            self.assertEqual(cases[0]["stopped_at"], "M3 Sandbox")


if __name__ == "__main__":
    unittest.main()
