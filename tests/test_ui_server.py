import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import context  # noqa: F401
from evidence_quarantine.config import QuarantineConfig
from evidence_quarantine.lab_simulator import RootkitLabSimulator
from evidence_quarantine.quarantine_manager import QuarantineManager
from evidence_quarantine.ui_server import load_dashboard_alerts


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


if __name__ == "__main__":
    unittest.main()
