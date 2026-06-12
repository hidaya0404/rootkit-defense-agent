import tempfile
import unittest
from pathlib import Path

from tests import context  # noqa: F401
from evidence_quarantine.cli import main


class CliTest(unittest.TestCase):
    def test_demo_command_runs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            exit_code = main(["--storage-root", str(Path(temp_dir) / "storage"), "demo"])
            self.assertEqual(exit_code, 0)

    def test_manifest_command_prints_backend_contract(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = Path(temp_dir) / "storage"
            main(["--storage-root", str(storage), "demo", "--alert-id", "ALT-CLI-0001"])
            exit_code = main(["--storage-root", str(storage), "manifest", "--alert-id", "ALT-CLI-0001"])
            self.assertEqual(exit_code, 0)

    def test_simulate_rootkit_quarantines_by_default(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            storage = root / "storage"
            lab_root = root / "victim"

            exit_code = main(
                [
                    "--storage-root",
                    str(storage),
                    "simulate-rootkit",
                    "--scenario",
                    "kernel-module",
                    "--lab-root",
                    str(lab_root),
                ]
            )

            self.assertEqual(exit_code, 0)
            evidence_dir = storage / "quarantine" / "ALT-LAB-KMOD-0001"
            self.assertTrue((evidence_dir / "artifact.bin").exists())
            self.assertTrue((evidence_dir / "manifest.json").exists())

    def test_simulate_rootkit_can_generate_without_quarantine_for_lab_setup(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            storage = root / "storage"
            lab_root = root / "victim"

            exit_code = main(
                [
                    "--storage-root",
                    str(storage),
                    "simulate-rootkit",
                    "--scenario",
                    "kernel-module",
                    "--lab-root",
                    str(lab_root),
                    "--no-quarantine",
                ]
            )

            self.assertEqual(exit_code, 0)
            self.assertTrue((lab_root / "alerts.json").exists())
            self.assertFalse((storage / "quarantine" / "ALT-LAB-KMOD-0001").exists())


if __name__ == "__main__":
    unittest.main()
