import json
import tempfile
import unittest
from pathlib import Path

from tests import context  # noqa: F401
from evidence_quarantine.config import QuarantineConfig
from evidence_quarantine.lab_simulator import RootkitLabSimulator
from evidence_quarantine.quarantine_manager import QuarantineManager


class RootkitLabSimulatorTest(unittest.TestCase):
    def test_full_scenario_creates_benign_alert_bundle(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lab_root = Path(temp_dir) / "victim"
            artifacts = RootkitLabSimulator(lab_root).create_scenario("full")

            self.assertEqual(len(artifacts), 6)
            self.assertTrue((lab_root / "alerts.json").exists())
            bundle = json.loads((lab_root / "alerts.json").read_text(encoding="utf-8"))
            self.assertEqual(len(bundle["alerts"]), 6)
            self.assertIn("Benign simulation only", bundle["safety_note"])

    def test_kernel_module_scenario_can_be_quarantined(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            simulator = RootkitLabSimulator(root / "victim")
            manager = QuarantineManager(QuarantineConfig(storage_root=root / "storage"))

            payload = simulator.quarantine_scenario("kernel-module", manager)

            self.assertEqual(payload["alerts"][0]["expected_rootkit_category"], "kernel_module_rootkit_suspect")
            self.assertTrue(payload["quarantine_results"][0]["success"])
            self.assertEqual(payload["quarantine_results"][0]["status"], "READY_FOR_ANALYSIS")


if __name__ == "__main__":
    unittest.main()

