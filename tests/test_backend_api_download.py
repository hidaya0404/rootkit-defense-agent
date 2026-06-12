import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import context  # noqa: F401

if importlib.util.find_spec("fastapi") is None:
    raise unittest.SkipTest("fastapi is not installed in this test environment")

from backend import api


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class BackendApiDownloadTest(unittest.TestCase):
    def test_local_artifact_must_match_manifest_sha256(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            stale = root / "stale.bin"
            stale.write_bytes(b"old fake artifact")
            expected_sha256 = sha256_bytes(b"current quarantined artifact")

            selected, actual_sha256, mismatches = api.select_downloadable_local_artifact(
                {
                    "artifact_id": "ART-1",
                    "alert_id": "ALT-1",
                    "stored_path": str(stale),
                    "sha256": expected_sha256,
                }
            )

            self.assertIsNone(selected)
            self.assertIsNone(actual_sha256)
            self.assertEqual(mismatches[0]["actual_sha256"], sha256_bytes(b"old fake artifact"))
            self.assertEqual(mismatches[0]["expected_sha256"], expected_sha256)

    def test_artifacts_dir_fallback_can_replace_stale_path_when_hash_matches(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            stale = root / "stale.bin"
            stale.write_bytes(b"old fake artifact")
            artifact_dir = root / "artifacts" / "ALT-1"
            artifact_dir.mkdir(parents=True)
            current = artifact_dir / "rk_demo.ko"
            current.write_bytes(b"current quarantined artifact")
            expected_sha256 = sha256_bytes(b"current quarantined artifact")

            with patch.object(api, "ARTIFACTS_DIR", root / "artifacts"):
                selected, actual_sha256, mismatches = api.select_downloadable_local_artifact(
                    {
                        "artifact_id": "ART-1",
                        "alert_id": "ALT-1",
                        "stored_path": str(stale),
                        "sha256": expected_sha256,
                    }
                )

            self.assertEqual(selected, current)
            self.assertEqual(actual_sha256, expected_sha256)
            self.assertEqual(mismatches[0]["actual_sha256"], sha256_bytes(b"old fake artifact"))

    def test_rootrap_quarantine_scan_announces_actual_download_hash(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            evidence_dir = root / "ALT-LAB-KMOD-0001"
            evidence_dir.mkdir()
            artifact = evidence_dir / "artifact.bin"
            artifact.write_bytes(b"fake kernel module rootkit artifact rk_demo.ko")
            (evidence_dir / "metadata.json").write_text(
                """
                {
                  "alert_id": "ALT-LAB-KMOD-0001",
                  "artifact_name": "rk_demo.ko",
                  "risk_level": "HIGH",
                  "rootkit_profile": {
                    "category": "kernel_module_rootkit_suspect"
                  }
                }
                """,
                encoding="utf-8",
            )

            records = api.rootrap_quarantine_records(root)

            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["artifact_id"], "ART-ALT-LAB-KMOD-0001")
            self.assertEqual(records[0]["filename"], "rk_demo.ko")
            self.assertEqual(
                records[0]["sha256"],
                sha256_bytes(b"fake kernel module rootkit artifact rk_demo.ko"),
            )


if __name__ == "__main__":
    unittest.main()
