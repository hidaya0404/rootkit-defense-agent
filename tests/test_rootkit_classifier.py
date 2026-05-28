import tempfile
import unittest
from pathlib import Path

from tests import context  # noqa: F401
from evidence_quarantine.rootkit_classifier import RootkitArtifactClassifier


class RootkitArtifactClassifierTest(unittest.TestCase):
    def test_classifies_kernel_module(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "rk_demo.ko"
            sample.write_bytes(b"not a real module")

            profile = RootkitArtifactClassifier().classify(sample)

            self.assertEqual(profile.category, "kernel_module_rootkit_suspect")
            self.assertIn("kernel_module_loading", profile.suspected_techniques)
            self.assertIn("T1014 Rootkit", profile.mitre_attack_mapping)

    def test_classifies_ld_preload_hook(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "ld.so.preload"
            sample.write_text("/tmp/libhide.so\n", encoding="utf-8")

            profile = RootkitArtifactClassifier().classify(sample)

            self.assertEqual(profile.category, "userland_preload_hook_suspect")
            self.assertIn("ld_preload_hooking", profile.suspected_techniques)

    def test_classifies_shared_library_hook(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "libhide.so"
            sample.write_bytes(b"demo")

            profile = RootkitArtifactClassifier().classify(sample)

            self.assertEqual(profile.category, "shared_library_hook_suspect")
            self.assertIn("shared_library_injection", profile.suspected_techniques)


if __name__ == "__main__":
    unittest.main()

