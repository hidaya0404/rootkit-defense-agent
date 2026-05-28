import hashlib
import tempfile
import unittest
from pathlib import Path

from tests import context  # noqa: F401
from evidence_quarantine.hash_service import HashService


class HashServiceTest(unittest.TestCase):
    def test_calculates_md5_sha1_sha256(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "sample.bin"
            payload = b"abc"
            sample.write_bytes(payload)

            hashes = HashService().calculate(sample)

            self.assertEqual(hashes.md5, hashlib.md5(payload, usedforsecurity=False).hexdigest())
            self.assertEqual(hashes.sha1, hashlib.sha1(payload).hexdigest())
            self.assertEqual(hashes.sha256, hashlib.sha256(payload).hexdigest())


if __name__ == "__main__":
    unittest.main()

