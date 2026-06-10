from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evidence_quarantine.models import QuarantineRequest, RiskLevel, to_jsonable
from evidence_quarantine.quarantine_manager import QuarantineManager
from evidence_quarantine.time_utils import utc_now


@dataclass(frozen=True)
class SimulatedRootkitArtifact:
    alert_id: str
    artifact_path: Path
    detection_reason: str
    risk_level: RiskLevel
    expected_category: str
    source_module: str
    tags: list[str]

    def to_alert(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "artifact_path": str(self.artifact_path),
            "detection_reason": self.detection_reason,
            "risk_level": self.risk_level.value,
            "detected_at": utc_now(),
            "source_module": self.source_module,
            "tags": self.tags,
            "expected_rootkit_category": self.expected_category,
        }


class RootkitLabSimulator:
    """Creates benign rootkit-like artifacts for defensive lab testing only."""

    def __init__(self, lab_root: Path) -> None:
        self.lab_root = lab_root.expanduser().resolve()

    def create_scenario(self, scenario: str = "full") -> list[SimulatedRootkitArtifact]:
        self.lab_root.mkdir(parents=True, exist_ok=True)
        scenario = scenario.lower()

        builders = {
            "kernel-module": self._kernel_module,
            "ld-preload": self._ld_preload,
            "systemd": self._systemd_persistence,
            "cron": self._cron_persistence,
            "hidden-payload": self._hidden_payload,
            "binary-tamper": self._system_binary_tamper,
        }

        if scenario == "full":
            artifacts: list[SimulatedRootkitArtifact] = []
            for builder in builders.values():
                artifacts.append(builder())
            self._write_alert_bundle(artifacts)
            return artifacts

        if scenario not in builders:
            valid = ", ".join(["full", *builders.keys()])
            raise ValueError(f"Unknown scenario '{scenario}'. Valid scenarios: {valid}")

        artifacts = [builders[scenario]()]
        self._write_alert_bundle(artifacts)
        return artifacts

    def quarantine_scenario(
        self,
        scenario: str,
        manager: QuarantineManager,
    ) -> dict[str, Any]:
        artifacts = self.create_scenario(scenario)
        results = []
        for artifact in artifacts:
            result = manager.quarantine_artifact(
                QuarantineRequest(
                    alert_id=artifact.alert_id,
                    artifact_path=artifact.artifact_path,
                    detection_reason=artifact.detection_reason,
                    risk_level=artifact.risk_level,
                    source_module=artifact.source_module,
                    tags=artifact.tags,
                )
            )
            results.append(result.to_summary())
        return {
            "lab_root": self.lab_root,
            "scenario": scenario,
            "alerts": [artifact.to_alert() for artifact in artifacts],
            "quarantine_results": results,
        }

    def _kernel_module(self) -> SimulatedRootkitArtifact:
        path = self.lab_root / "tmp" / "rk_demo.ko"
        self._write_bytes(
            path,
            b"BENIGN ROOTKIT DEFENSE LAB ARTIFACT\n"
            b"Fake .ko marker. This is not a real Linux kernel module.\n"
            b"Never load suspicious modules on the host.\n",
        )
        return SimulatedRootkitArtifact(
            alert_id="ALT-LAB-KMOD-0001",
            artifact_path=path,
            detection_reason="Suspicious kernel module-like artifact discovered in temporary directory",
            risk_level=RiskLevel.HIGH,
            expected_category="kernel_module_rootkit_suspect",
            source_module="lab-rootkit-simulator",
            tags=["lab", "rootkit", "kernel-module", "benign"],
        )

    def _ld_preload(self) -> SimulatedRootkitArtifact:
        lib_path = self.lab_root / "tmp" / "libhide.so"
        preload_path = self.lab_root / "etc" / "ld.so.preload"
        self._write_bytes(
            lib_path,
            b"BENIGN FAKE SHARED LIBRARY\n"
            b"Simulates a userland rootkit preload library name only.\n",
        )
        self._write_text(
            preload_path,
            "# Benign lab file, not the real /etc/ld.so.preload\n"
            f"{lib_path.as_posix()}\n",
        )
        return SimulatedRootkitArtifact(
            alert_id="ALT-LAB-PRELOAD-0001",
            artifact_path=preload_path,
            detection_reason="ld.so.preload-like file references a suspicious shared library",
            risk_level=RiskLevel.CRITICAL,
            expected_category="userland_preload_hook_suspect",
            source_module="lab-rootkit-simulator",
            tags=["lab", "rootkit", "ld-preload", "userland-hook", "benign"],
        )

    def _systemd_persistence(self) -> SimulatedRootkitArtifact:
        path = self.lab_root / "etc" / "systemd" / "system" / "rk-update.service"
        self._write_text(
            path,
            "[Unit]\n"
            "Description=Benign Rootkit Defense Lab Marker\n\n"
            "[Service]\n"
            "Type=oneshot\n"
            "ExecStart=/bin/echo simulated-rootkit-service\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n",
        )
        return SimulatedRootkitArtifact(
            alert_id="ALT-LAB-SYSTEMD-0001",
            artifact_path=path,
            detection_reason="Suspicious systemd service-like persistence artifact",
            risk_level=RiskLevel.HIGH,
            expected_category="systemd_persistence_suspect",
            source_module="lab-rootkit-simulator",
            tags=["lab", "rootkit", "systemd", "persistence", "benign"],
        )

    def _cron_persistence(self) -> SimulatedRootkitArtifact:
        path = self.lab_root / "var" / "spool" / "cron" / "root"
        self._write_text(
            path,
            "# Benign lab cron-like persistence marker\n"
            "*/5 * * * * /bin/echo simulated-rootkit-cron\n",
        )
        return SimulatedRootkitArtifact(
            alert_id="ALT-LAB-CRON-0001",
            artifact_path=path,
            detection_reason="Suspicious cron-like persistence artifact",
            risk_level=RiskLevel.MEDIUM,
            expected_category="cron_persistence_suspect",
            source_module="lab-rootkit-simulator",
            tags=["lab", "rootkit", "cron", "persistence", "benign"],
        )

    def _hidden_payload(self) -> SimulatedRootkitArtifact:
        path = self.lab_root / "dev" / "shm" / ".rk_stage"
        self._write_bytes(
            path,
            b"BENIGN HIDDEN PAYLOAD MARKER\n"
            b"Simulates hidden staging file under dev/shm only.\n",
        )
        return SimulatedRootkitArtifact(
            alert_id="ALT-LAB-HIDDEN-0001",
            artifact_path=path,
            detection_reason="Hidden payload-like artifact in volatile runtime directory",
            risk_level=RiskLevel.HIGH,
            expected_category="hidden_payload_suspect",
            source_module="lab-rootkit-simulator",
            tags=["lab", "rootkit", "hidden-file", "staging", "benign"],
        )

    def _system_binary_tamper(self) -> SimulatedRootkitArtifact:
        path = self.lab_root / "usr" / "bin" / "ps"
        self._write_text(
            path,
            "#!/bin/sh\n"
            "# Benign lab marker simulating a replaced ps binary path.\n"
            "echo simulated-ps-marker\n",
        )
        return SimulatedRootkitArtifact(
            alert_id="ALT-LAB-BINTAMPER-0001",
            artifact_path=path,
            detection_reason="System command path resembles binary replacement used by userland rootkits",
            risk_level=RiskLevel.CRITICAL,
            expected_category="system_binary_tampering_suspect",
            source_module="lab-rootkit-simulator",
            tags=["lab", "rootkit", "binary-tampering", "benign"],
        )

    def _write_alert_bundle(self, artifacts: list[SimulatedRootkitArtifact]) -> None:
        bundle = {
            "created_at": utc_now(),
            "lab_root": str(self.lab_root),
            "safety_note": "Benign simulation only. No real rootkit behavior is implemented.",
            "alerts": [artifact.to_alert() for artifact in artifacts],
        }
        self._write_text(self.lab_root / "alerts.json", json.dumps(to_jsonable(bundle), indent=2) + "\n")

    @staticmethod
    def _write_text(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")

    @staticmethod
    def _write_bytes(path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

