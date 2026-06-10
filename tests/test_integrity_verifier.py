import unittest

from tests import context  # noqa: F401
from evidence_quarantine.integrity_verifier import IntegrityVerifier
from evidence_quarantine.models import HashSet


class IntegrityVerifierTest(unittest.TestCase):
    def test_integrity_match(self):
        hashes = HashSet(md5="m", sha1="s1", sha256="s256")
        report = IntegrityVerifier().verify(hashes, hashes)
        self.assertTrue(report.match)

    def test_integrity_mismatch(self):
        before = HashSet(md5="m", sha1="s1", sha256="s256")
        after = HashSet(md5="m", sha1="s1", sha256="changed")
        report = IntegrityVerifier().verify(before, after)
        self.assertFalse(report.match)


if __name__ == "__main__":
    unittest.main()

