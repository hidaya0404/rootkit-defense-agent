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


if __name__ == "__main__":
    unittest.main()

