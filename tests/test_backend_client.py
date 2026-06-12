import unittest

from tests import context  # noqa: F401
from evidence_quarantine.backend_client import build_quarantine_manifest


class BackendClientTest(unittest.TestCase):
    def test_build_quarantine_manifest_matches_m4_contract(self):
        record = {
            "artifact_id": "ART-ALT-1",
            "alert_id": "ALT-1",
            "artifact_name": "rk_demo.ko",
            "artifact_path": "/q/ALT-1/artifact.bin",
            "original_path": "/tmp/rk_demo.ko",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "metadata_path": "/q/ALT-1/metadata.json",
            "hashes_path": "/q/ALT-1/hashes.json",
            "manifest_path": "/q/ALT-1/manifest.json",
            "rootkit_category": "kernel_module_rootkit_suspect",
            "status": "READY_FOR_ANALYSIS",
            "integrity_verified": True,
            "ready_for_sandbox": True,
            "created_at": "2026-05-28T19:22:07Z",
            "source_alert_status": "ARTIFACT_READY",
        }

        manifest = build_quarantine_manifest(record, download_url="/quarantine/ALT-1/download")

        self.assertEqual(manifest["artifact_id"], "ART-ALT-1")
        self.assertEqual(manifest["timestamp"], "2026-05-28T19:22:07Z")
        self.assertEqual(manifest["filename"], "rk_demo.ko")
        self.assertEqual(manifest["quarantine_path"], "/q/ALT-1/artifact.bin")
        self.assertEqual(manifest["stored_path"], "/q/ALT-1/artifact.bin")
        self.assertEqual(manifest["md5"], "md5")
        self.assertEqual(manifest["sha1"], "sha1")
        self.assertEqual(manifest["hashes"]["sha256"], "sha256")
        self.assertEqual(manifest["source_alert_status"], "ARTIFACT_READY")
        self.assertEqual(manifest["download_url"], "/quarantine/ALT-1/download")


if __name__ == "__main__":
    unittest.main()
