import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from tests import context  # noqa: F401
from agent import main as agent_main


def test_send_alert_quarantines_and_logs_once():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        suspicious = root / "rootrap_test_malware.sh"
        suspicious.write_text("#!/bin/sh\necho rootrap_test_payload\n", encoding="utf-8")

        pending_alerts = root / "pending_alerts.jsonl"
        storage_root = root / "storage"
        alert = {
            "alert_id": "ALT-TEST-AGENT-0001",
            "timestamp": "2026-06-13T12:00:00Z",
            "source_module": "file_monitor",
            "severity": "HIGH",
            "type": "EXECUTABLE_IN_SUSPICIOUS_DIR",
            "description": "test executable in suspicious dir",
            "details": {
                "path": str(suspicious),
                "needs_quarantine": True,
            },
            "status": "NEW",
        }

        agent_main._sent_alerts.clear()
        with patch.dict(
            agent_main.CONFIG,
            {
                "pending_alerts_file": str(pending_alerts),
                "backend_url": "http://127.0.0.1:9",
                "alert_endpoint": "/api/alerts",
            },
        ), patch.dict(os.environ, {"ROOTRAP_STORAGE_ROOT": str(storage_root)}), patch.object(agent_main.requests, "post") as post:
            post.side_effect = RuntimeError("backend unavailable in unit test")

            assert agent_main.send_alert(alert) is True
            assert agent_main.send_alert(dict(alert)) is False

        assert not suspicious.exists()
        evidence_dir = storage_root / "quarantine" / "ALT-TEST-AGENT-0001"
        artifact = evidence_dir / "artifact.bin"
        assert artifact.exists()
        assert (evidence_dir / "manifest.json").exists()
        assert (evidence_dir / "hashes.json").exists()
        assert (evidence_dir / "metadata.json").exists()

        lines = pending_alerts.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        logged = json.loads(lines[0])
        assert logged["alert_id"] == "ALT-TEST-AGENT-0001"
        assert logged["details"]["quarantine_path"] == str(artifact)
        assert logged["details"]["m2_status"] == "READY_FOR_ANALYSIS"
