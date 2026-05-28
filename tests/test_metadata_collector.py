import tempfile
import unittest
from pathlib import Path

from tests import context  # noqa: F401
from evidence_quarantine.metadata_collector import MetadataCollector
from evidence_quarantine.models import QuarantineStatus, RiskLevel


class MetadataCollectorTest(unittest.TestCase):
    def test_collects_forensic_metadata(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "suspicious.txt"
            sample.write_text("demo", encoding="utf-8")

            metadata = MetadataCollector().collect(
                path=sample,
                alert_id="ALT-TEST-0001",
                detection_reason="unit test",
                detected_at="2026-05-28T18:30:00Z",
                risk_level=RiskLevel.HIGH,
                quarantine_path=Path(temp_dir) / "artifact.bin",
                status=QuarantineStatus.VALIDATED,
            )

            self.assertEqual(metadata.alert_id, "ALT-TEST-0001")
            self.assertEqual(metadata.artifact_name, "suspicious.txt")
            self.assertEqual(metadata.file_type, "regular_file")
            self.assertEqual(metadata.size_bytes, 4)
            self.assertEqual(metadata.risk_level, RiskLevel.HIGH)
            self.assertEqual(metadata.status, QuarantineStatus.VALIDATED)


if __name__ == "__main__":
    unittest.main()

