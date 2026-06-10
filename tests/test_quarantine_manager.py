import json
import tempfile
import unittest
from pathlib import Path

from tests import context  # noqa: F401
from evidence_quarantine.config import QuarantineConfig
from evidence_quarantine.models import QuarantineRequest, QuarantineStatus, RiskLevel
from evidence_quarantine.quarantine_manager import QuarantineManager


class QuarantineManagerTest(unittest.TestCase):
    def test_quarantine_success_creates_complete_evidence_package(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sample = root / "suspicious_demo.sh"
            sample.write_text("#!/bin/sh\necho demo\n", encoding="utf-8", newline="\n")
            config = QuarantineConfig(storage_root=root / "storage")

            result = QuarantineManager(config).quarantine_artifact(
                QuarantineRequest(
                    alert_id="ALT-TEST-0001",
                    artifact_path=sample,
                    detection_reason="unit test suspicious executable",
                    risk_level=RiskLevel.HIGH,
                    source_module="unit-test",
                    tags=["unit-test"],
                )
            )

            self.assertTrue(result.success, result.errors)
            self.assertEqual(result.status, QuarantineStatus.READY_FOR_ANALYSIS)
            self.assertTrue(result.artifact_path.exists())
            self.assertTrue(result.metadata_path.exists())
            self.assertTrue(result.hashes_path.exists())
            self.assertTrue(result.manifest_path.exists())
            self.assertTrue(result.audit_log_path.exists())

            metadata = json.loads(result.metadata_path.read_text(encoding="utf-8"))
            hashes = json.loads(result.hashes_path.read_text(encoding="utf-8"))
            manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
            audit_log = result.audit_log_path.read_text(encoding="utf-8")

            self.assertEqual(metadata["alert_id"], "ALT-TEST-0001")
            self.assertEqual(metadata["status"], "READY_FOR_ANALYSIS")
            self.assertTrue(metadata["integrity_verified"])
            self.assertEqual(metadata["rootkit_profile"]["category"], "unknown_rootkit_artifact")
            self.assertIn("T1014 Rootkit", metadata["rootkit_profile"]["mitre_attack_mapping"])
            self.assertTrue(hashes["match"])
            self.assertTrue(manifest["ready_for_sandbox"])
            self.assertIn("INTEGRITY_VERIFIED", audit_log)
            self.assertIn("ARTIFACT_COPIED", audit_log)

    def test_invalid_path_is_rejected_and_audited(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = QuarantineConfig(storage_root=root / "storage")

            result = QuarantineManager(config).quarantine_artifact(
                QuarantineRequest(
                    alert_id="ALT-TEST-MISSING",
                    artifact_path=root / "missing.sh",
                    detection_reason="missing file test",
                )
            )

            self.assertFalse(result.success)
            self.assertEqual(result.status, QuarantineStatus.REJECTED)
            self.assertTrue(result.audit_log_path.exists())
            self.assertTrue(result.manifest_path.exists())
            self.assertIn("does not exist", result.errors[0])
            self.assertIn("POLICY_REJECTED", result.audit_log_path.read_text(encoding="utf-8"))

    def test_repository_index_contains_quarantine_summary(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sample = root / "sample.txt"
            sample.write_text("demo", encoding="utf-8")
            config = QuarantineConfig(storage_root=root / "storage")
            manager = QuarantineManager(config)

            manager.quarantine_artifact(
                QuarantineRequest(
                    alert_id="ALT-INDEX-0001",
                    artifact_path=sample,
                    detection_reason="index test",
                    risk_level=RiskLevel.MEDIUM,
                )
            )

            records = manager.list_evidence()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["alert_id"], "ALT-INDEX-0001")
            self.assertEqual(records[0]["status"], "READY_FOR_ANALYSIS")
            self.assertTrue(records[0]["ready_for_sandbox"])


if __name__ == "__main__":
    unittest.main()
