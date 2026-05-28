import tempfile
import unittest
from pathlib import Path

from tests import context  # noqa: F401
from evidence_quarantine.config import QuarantineConfig
from evidence_quarantine.lab_detector import LabDetector
from evidence_quarantine.lab_simulator import RootkitLabSimulator
from evidence_quarantine.quarantine_manager import QuarantineManager


class LabDetectorTest(unittest.TestCase):
    def test_processes_simulated_alerts_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            lab_root = root / "victim-drop"
            RootkitLabSimulator(lab_root).create_scenario("kernel-module")

            manager = QuarantineManager(QuarantineConfig(storage_root=root / "storage"))
            payload = LabDetector(manager).process_alerts_file(lab_root / "alerts.json")

            self.assertEqual(payload["processed_alerts"], 1)
            self.assertTrue(payload["quarantine_results"][0]["success"])
            self.assertEqual(payload["quarantine_results"][0]["status"], "READY_FOR_ANALYSIS")


if __name__ == "__main__":
    unittest.main()

