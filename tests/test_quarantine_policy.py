import os
import tempfile
import unittest
from pathlib import Path

from tests import context  # noqa: F401
from evidence_quarantine.config import QuarantineConfig
from evidence_quarantine.exceptions import PolicyViolation
from evidence_quarantine.quarantine_policy import QuarantinePolicy


class QuarantinePolicyTest(unittest.TestCase):
    def test_rejects_missing_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            policy = QuarantinePolicy(QuarantineConfig(storage_root=Path(temp_dir) / "storage"))
            with self.assertRaises(PolicyViolation):
                policy.validate(Path(temp_dir) / "missing.bin")

    def test_rejects_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            policy = QuarantinePolicy(QuarantineConfig(storage_root=Path(temp_dir) / "storage"))
            with self.assertRaises(PolicyViolation):
                policy.validate(Path(temp_dir))

    def test_rejects_symlink_when_supported(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            target = temp / "target.txt"
            link = temp / "link.txt"
            target.write_text("demo", encoding="utf-8")
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("Symlink creation is not available in this environment")

            policy = QuarantinePolicy(QuarantineConfig(storage_root=temp / "storage"))
            with self.assertRaises(PolicyViolation):
                policy.validate(link)


if __name__ == "__main__":
    unittest.main()

