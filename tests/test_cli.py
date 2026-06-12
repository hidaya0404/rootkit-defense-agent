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


if __name__ == "__main__":
    unittest.main()
