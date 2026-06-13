import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import context  # noqa: F401
from evidence_quarantine.config import QuarantineConfig
from evidence_quarantine.lab_simulator import RootkitLabSimulator
from evidence_quarantine.quarantine_manager import QuarantineManager
from evidence_quarantine.ui_server import (
    build_cases,
    build_dashboard_report_html,
    load_dashboard_alerts,
    load_remediations,
    load_reports,
    load_sandbox_results,
    load_ui_records,
)


class UiServerTest(unittest.TestCase):
    def test_dashboard_alerts_include_quarantined_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = QuarantineConfig(storage_root=root / "storage")
            manager = QuarantineManager(config)
            RootkitLabSimulator(root / "victim").quarantine_scenario("kernel-module", manager)

            with patch.dict(os.environ, {"ROOTRAP_PENDING_ALERTS_FILE": str(root / "missing.jsonl")}):
                alerts = load_dashboard_alerts(config)

            self.assertEqual(len(alerts), 1)
            alert = alerts[0]
            self.assertEqual(alert["alert_id"], "ALT-LAB-KMOD-0001")
            self.assertEqual(alert["status"], "READY_FOR_ANALYSIS")
            self.assertEqual(alert["severity"], "HIGH")
            self.assertEqual(alert["source_module"], "m2-quarantine")
            self.assertTrue(alert["derived_from_quarantine"])
            self.assertEqual(alert["details"]["rootkit_category"], "kernel_module_rootkit_suspect")

    def test_remote_sandbox_results_are_scoped_to_local_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = QuarantineConfig(storage_root=root / "storage")
            manager = QuarantineManager(config)
            RootkitLabSimulator(root / "victim").quarantine_scenario("kernel-module", manager)

            remote_payload = {
                "results": [
                    {
                        "artifact_id": "ART-ALT-LAB-KMOD-0001",
                        "alert_id": "ALT-LAB-KMOD-0001",
                        "execution_status": "COMPLETED",
                    },
                    {
                        "artifact_id": "ART-OLD-REMOTE-TEST",
                        "alert_id": "ALT-OLD-REMOTE-TEST",
                        "execution_status": "COMPLETED",
                    },
                ]
            }

            with patch.dict(
                os.environ,
                {
                    "ROOTRAP_PENDING_ALERTS_FILE": str(root / "missing.jsonl"),
                    "ROOTRAP_STORAGE_ROOT": str(config.storage_root),
                    "ROOTRAP_ENABLE_REMOTE_DASHBOARD_DATA": "1",
                },
            ), patch("evidence_quarantine.ui_server.load_remote_json", return_value=(remote_payload, None)):
                results = load_sandbox_results()

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["artifact_id"], "ART-ALT-LAB-KMOD-0001")

    def test_cases_show_waiting_sandbox_stage(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = QuarantineConfig(storage_root=root / "storage")
            manager = QuarantineManager(config)
            RootkitLabSimulator(root / "victim").quarantine_scenario("kernel-module", manager)

            with patch.dict(
                os.environ,
                {
                    "ROOTRAP_PENDING_ALERTS_FILE": str(root / "missing.jsonl"),
                    "ROOTRAP_STORAGE_ROOT": str(config.storage_root),
                    "ROOTRAP_ENABLE_REMOTE_DASHBOARD_DATA": "0",
                },
            ):
                cases = build_cases(config)

            self.assertEqual(len(cases), 1)
            self.assertEqual(cases[0]["status"], "IN_PROGRESS")
            self.assertEqual(cases[0]["stopped_at"], "M3 Sandbox")

    def test_cases_merge_agent_alert_with_remote_sandbox_result(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = QuarantineConfig(storage_root=root / "storage")
            manager = QuarantineManager(config)
            RootkitLabSimulator(root / "victim").quarantine_scenario("kernel-module", manager)

            pending_alerts = root / "pending_alerts.jsonl"
            pending_alerts.write_text(
                json.dumps(
                    {
                        "alert_id": "ALT-LAB-KMOD-0001",
                        "timestamp": "2026-06-13T13:29:00Z",
                        "source_module": "file_monitor",
                        "severity": "HIGH",
                        "type": "EXECUTABLE_IN_SUSPICIOUS_DIR",
                        "description": "test alert",
                        "details": {"m2_artifact_id": "ART-ALT-LAB-KMOD-0001"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            def fake_remote(url, **_kwargs):
                if url.endswith("/api/sandbox/results"):
                    return (
                        {
                            "results": [
                                {
                                    "artifact_id": "ART-ALT-LAB-KMOD-0001",
                                    "alert_id": "ALT-LAB-KMOD-0001",
                                    "execution_status": "COMPLETED",
                                    "finished_at": "2026-06-13T13:31:00Z",
                                }
                            ]
                        },
                        None,
                    )
                return ({}, None)

            with patch.dict(
                os.environ,
                {
                    "ROOTRAP_PENDING_ALERTS_FILE": str(pending_alerts),
                    "ROOTRAP_STORAGE_ROOT": str(config.storage_root),
                    "ROOTRAP_ENABLE_REMOTE_DASHBOARD_DATA": "1",
                },
            ), patch("evidence_quarantine.ui_server.load_remote_json", side_effect=fake_remote):
                cases = build_cases(config)

            self.assertEqual(len(cases), 1)
            sandbox_stage = next(stage for stage in cases[0]["timeline"] if stage["id"] == "m3")
            self.assertEqual(sandbox_stage["status"], "DONE")

    def test_cases_merge_sandbox_result_when_m4_uses_different_artifact_id_but_same_hash(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = QuarantineConfig(storage_root=root / "storage")
            manager = QuarantineManager(config)
            RootkitLabSimulator(root / "victim").quarantine_scenario("kernel-module", manager)
            local_record = load_ui_records(config)[0]
            local_sha256 = local_record["sha256"]

            def fake_remote(url, **_kwargs):
                if url.endswith("/api/sandbox/results"):
                    return (
                        {
                            "results": [
                                {
                                    "artifact_id": "ART-M4-REGENERATED-ID",
                                    "alert_id": "ALT-M4-REGENERATED-ID",
                                    "execution_status": "COMPLETED",
                                    "finished_at": "2026-06-13T13:31:00Z",
                                }
                            ]
                        },
                        None,
                    )
                if url.endswith("/api/quarantine/ready"):
                    return (
                        {
                            "artifacts": [
                                {
                                    "artifact_id": "ART-M4-REGENERATED-ID",
                                    "alert_id": "ALT-M4-REGENERATED-ID",
                                    "filename": "rk_demo.ko",
                                    "sha256": local_sha256,
                                    "status": "READY_FOR_ANALYSIS",
                                    "integrity_verified": True,
                                    "ready_for_sandbox": True,
                                }
                            ]
                        },
                        None,
                    )
                return ({}, None)

            with patch.dict(
                os.environ,
                {
                    "ROOTRAP_PENDING_ALERTS_FILE": str(root / "missing.jsonl"),
                    "ROOTRAP_STORAGE_ROOT": str(config.storage_root),
                    "ROOTRAP_ENABLE_REMOTE_DASHBOARD_DATA": "1",
                },
            ), patch("evidence_quarantine.ui_server.load_remote_json", side_effect=fake_remote):
                results = load_sandbox_results()
                cases = build_cases(config)

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["artifact_sha256"], local_sha256)
            sandbox_stage = next(stage for stage in cases[0]["timeline"] if stage["id"] == "m3")
            self.assertEqual(sandbox_stage["status"], "DONE")

    def test_local_remediation_and_report_download_are_generated_from_quarantine(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = QuarantineConfig(storage_root=root / "storage")
            manager = QuarantineManager(config)
            RootkitLabSimulator(root / "victim").quarantine_scenario("kernel-module", manager)

            with patch.dict(
                os.environ,
                {
                    "ROOTRAP_PENDING_ALERTS_FILE": str(root / "missing.jsonl"),
                    "ROOTRAP_STORAGE_ROOT": str(config.storage_root),
                    "ROOTRAP_ENABLE_REMOTE_DASHBOARD_DATA": "0",
                },
            ):
                remediations = load_remediations(config)
                reports = load_reports()
                body, filename = build_dashboard_report_html("RPT-ART-ALT-LAB-KMOD-0001", config)

            self.assertEqual(len(remediations), 1)
            self.assertEqual(remediations[0]["artifact_id"], "ART-ALT-LAB-KMOD-0001")
            self.assertTrue(reports[0]["download_url"].endswith("/download"))
            self.assertIn("RootRAP Incident Report", body)
            self.assertEqual(filename, "rootrap-report-ART-ALT-LAB-KMOD-0001.html")


if __name__ == "__main__":
    unittest.main()
