from __future__ import annotations

import json
from dataclasses import dataclass, field
from hashlib import sha256
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
    indicators: list[str] = field(default_factory=list)
    mitre_attack_mapping: list[str] = field(default_factory=lambda: ["T1014 Rootkit"])

    def to_alert(self) -> dict[str, Any]:
        digest = sha256(self.artifact_path.read_bytes()).hexdigest()
        return {
            "alert_id": self.alert_id,
            "artifact_path": str(self.artifact_path),
            "detection_reason": self.detection_reason,
            "risk_level": self.risk_level.value,
            "detected_at": utc_now(),
            "source_module": self.source_module,
            "tags": self.tags,
            "expected_rootkit_category": self.expected_category,
            "details": {
                "path": str(self.artifact_path),
                "sha256": digest,
                "artifact_type": self.expected_category,
                "indicators": self.indicators,
                "mitre_attack_mapping": self.mitre_attack_mapping,
                "safe_simulation": True,
            },
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
            "modules-load": self._modules_load_persistence,
            "modprobe": self._modprobe_persistence,
            "proc-inconsistency": self._proc_inconsistency,
            "network-stealth": self._network_stealth,
            "log-tamper": self._log_tamper,
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
            extra=(
                b"strings: init_module cleanup_module sys_call_table kallsyms_lookup_name "
                b"hook_getdents64 hide_pid hide_file netfilter_hook\n"
            ),
        )
        return SimulatedRootkitArtifact(
            alert_id="ALT-LAB-KMOD-0001",
            artifact_path=path,
            detection_reason="Suspicious kernel module-like artifact discovered in temporary directory",
            risk_level=RiskLevel.HIGH,
            expected_category="kernel_module_rootkit_suspect",
            source_module="lab-rootkit-simulator",
            tags=["lab", "rootkit", "kernel-module", "benign"],
            indicators=[
                "module-like extension .ko",
                "kernel symbol strings",
                "hidden process and file hook markers",
            ],
            mitre_attack_mapping=["T1014 Rootkit", "T1547.006 Kernel Modules and Extensions"],
        )

    def _ld_preload(self) -> SimulatedRootkitArtifact:
        lib_path = self.lab_root / "tmp" / "libhide.so"
        preload_path = self.lab_root / "etc" / "ld.so.preload"
        self._write_bytes(
            lib_path,
            b"BENIGN FAKE SHARED LIBRARY\n"
            b"Simulates a userland rootkit preload library name only.\n",
            extra=b"strings: LD_PRELOAD readdir getdents64 fopen openat hide_process hide_file\n",
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
            indicators=[
                "ld.so.preload reference",
                "shared object preload marker",
                "userland hook strings",
            ],
            mitre_attack_mapping=["T1014 Rootkit", "T1574 Hijack Execution Flow"],
        )

    def _systemd_persistence(self) -> SimulatedRootkitArtifact:
        path = self.lab_root / "etc" / "systemd" / "system" / "rk-update.service"
        self._write_text(
            path,
            "[Unit]\n"
            "Description=Benign Rootkit Defense Lab Marker\n\n"
            "[Service]\n"
            "Type=oneshot\n"
            "ExecStart=/opt/.rda-lab/.rk_update --restore --hide\n"
            "Restart=always\n"
            "RestartSec=10\n\n"
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
            indicators=["systemd auto-start unit", "hidden-looking ExecStart path", "restart persistence"],
            mitre_attack_mapping=["T1014 Rootkit", "T1543.002 Systemd Service"],
        )

    def _cron_persistence(self) -> SimulatedRootkitArtifact:
        path = self.lab_root / "var" / "spool" / "cron" / "root"
        self._write_text(
            path,
            "# Benign lab cron-like persistence marker\n"
            "*/5 * * * * /opt/.rda-lab/.rk_watchdog --reinstall >/dev/null 2>&1\n",
        )
        return SimulatedRootkitArtifact(
            alert_id="ALT-LAB-CRON-0001",
            artifact_path=path,
            detection_reason="Suspicious cron-like persistence artifact",
            risk_level=RiskLevel.MEDIUM,
            expected_category="cron_persistence_suspect",
            source_module="lab-rootkit-simulator",
            tags=["lab", "rootkit", "cron", "persistence", "benign"],
            indicators=["cron persistence marker", "hidden-looking watchdog path", "stdout/stderr redirection"],
            mitre_attack_mapping=["T1014 Rootkit", "T1053.003 Cron"],
        )

    def _hidden_payload(self) -> SimulatedRootkitArtifact:
        path = self.lab_root / "dev" / "shm" / ".rk_stage"
        self._write_bytes(
            path,
            b"BENIGN HIDDEN PAYLOAD MARKER\n"
            b"Simulates hidden staging file under dev/shm only.\n",
            extra=b"strings: stage2 dropper memfd_create /dev/shm/.rk_stage hide_me\n",
        )
        return SimulatedRootkitArtifact(
            alert_id="ALT-LAB-HIDDEN-0001",
            artifact_path=path,
            detection_reason="Hidden payload-like artifact in volatile runtime directory",
            risk_level=RiskLevel.HIGH,
            expected_category="hidden_payload_suspect",
            source_module="lab-rootkit-simulator",
            tags=["lab", "rootkit", "hidden-file", "staging", "benign"],
            indicators=["hidden filename", "runtime directory staging", "dropper marker strings"],
            mitre_attack_mapping=["T1014 Rootkit", "T1036 Masquerading"],
        )

    def _system_binary_tamper(self) -> SimulatedRootkitArtifact:
        path = self.lab_root / "usr" / "bin" / "ps"
        self._write_text(
            path,
            "#!/bin/sh\n"
            "# Benign lab marker simulating a replaced ps binary path.\n"
            "echo simulated-ps-marker --hide-pid --hide-name rk\n",
        )
        return SimulatedRootkitArtifact(
            alert_id="ALT-LAB-BINTAMPER-0001",
            artifact_path=path,
            detection_reason="System command path resembles binary replacement used by userland rootkits",
            risk_level=RiskLevel.CRITICAL,
            expected_category="system_binary_tampering_suspect",
            source_module="lab-rootkit-simulator",
            tags=["lab", "rootkit", "binary-tampering", "benign"],
            indicators=["system command replacement path", "hide-pid marker", "masquerading marker"],
            mitre_attack_mapping=["T1014 Rootkit", "T1036 Masquerading"],
        )

    def _modules_load_persistence(self) -> SimulatedRootkitArtifact:
        path = self.lab_root / "etc" / "modules-load.d" / "rk-stealth.conf"
        self._write_text(
            path,
            "# Benign lab marker, not the real /etc/modules-load.d\n"
            "rk_stealth\n"
            "rk_netfilter\n",
        )
        return SimulatedRootkitArtifact(
            alert_id="ALT-LAB-MODLOAD-0001",
            artifact_path=path,
            detection_reason="Kernel module auto-load configuration-like persistence marker",
            risk_level=RiskLevel.HIGH,
            expected_category="kernel_module_persistence_suspect",
            source_module="lab-rootkit-simulator",
            tags=["lab", "rootkit", "modules-load", "persistence", "benign"],
            indicators=["modules-load.d marker", "boot-time module load names", "kernel persistence"],
            mitre_attack_mapping=["T1014 Rootkit", "T1547.006 Kernel Modules and Extensions"],
        )

    def _modprobe_persistence(self) -> SimulatedRootkitArtifact:
        path = self.lab_root / "etc" / "modprobe.d" / "rk-override.conf"
        self._write_text(
            path,
            "# Benign lab marker, not the real /etc/modprobe.d\n"
            "install rk_stealth /sbin/insmod /opt/.rda-lab/rk_stealth.ko hide_pid=1\n"
            "options rk_stealth hide_files=.rk_stage,libhide.so\n",
        )
        return SimulatedRootkitArtifact(
            alert_id="ALT-LAB-MODPROBE-0001",
            artifact_path=path,
            detection_reason="modprobe override-like kernel persistence artifact",
            risk_level=RiskLevel.HIGH,
            expected_category="kernel_module_persistence_suspect",
            source_module="lab-rootkit-simulator",
            tags=["lab", "rootkit", "modprobe", "kernel-persistence", "benign"],
            indicators=["modprobe install override", "insmod string", "hide_pid option marker"],
            mitre_attack_mapping=["T1014 Rootkit", "T1547.006 Kernel Modules and Extensions"],
        )

    def _proc_inconsistency(self) -> SimulatedRootkitArtifact:
        path = self.lab_root / "var" / "log" / "rda" / "proc_mismatch.json"
        payload = {
            "safe_simulation": True,
            "description": "Benign snapshot that simulates a hidden process detection case.",
            "procfs_pids": [1, 22, 104, 31337],
            "ps_pids": [1, 22, 104],
            "hidden_candidates": [31337],
            "suspicious_names": ["rk_worker"],
            "note": "No process is hidden. This is static lab evidence only.",
        }
        self._write_text(path, json.dumps(payload, indent=2) + "\n")
        return SimulatedRootkitArtifact(
            alert_id="ALT-LAB-PROC-0001",
            artifact_path=path,
            detection_reason="Simulated /proc versus process-list inconsistency indicating hidden process behavior",
            risk_level=RiskLevel.CRITICAL,
            expected_category="process_hiding_suspect",
            source_module="lab-rootkit-simulator",
            tags=["lab", "rootkit", "procfs", "hidden-process", "benign"],
            indicators=["procfs mismatch", "hidden pid candidate", "process hiding marker"],
            mitre_attack_mapping=["T1014 Rootkit", "T1562 Impair Defenses"],
        )

    def _network_stealth(self) -> SimulatedRootkitArtifact:
        path = self.lab_root / "var" / "log" / "rda" / "network_mismatch.json"
        payload = {
            "safe_simulation": True,
            "description": "Benign snapshot that simulates a hidden TCP connection detection case.",
            "proc_net_tcp": ["0100007F:1F90 0200000A:15B3 01", "0A00000A:115C C0A83801:0035 01"],
            "ss_output": ["127.0.0.1:8080 10.0.0.2:5555"],
            "hidden_socket_candidates": ["10.0.0.10:4444 -> 192.168.56.1:53"],
            "note": "No connection is opened. This is static lab evidence only.",
        }
        self._write_text(path, json.dumps(payload, indent=2) + "\n")
        return SimulatedRootkitArtifact(
            alert_id="ALT-LAB-NET-0001",
            artifact_path=path,
            detection_reason="Simulated network table mismatch indicating hidden connection behavior",
            risk_level=RiskLevel.HIGH,
            expected_category="hidden_network_connection_suspect",
            source_module="lab-rootkit-simulator",
            tags=["lab", "rootkit", "network", "hidden-connection", "benign"],
            indicators=["/proc/net mismatch", "ss mismatch", "hidden socket candidate"],
            mitre_attack_mapping=["T1014 Rootkit", "T1095 Non-Application Layer Protocol"],
        )

    def _log_tamper(self) -> SimulatedRootkitArtifact:
        path = self.lab_root / "var" / "log" / "auth.log.tamper-marker"
        self._write_text(
            path,
            "BENIGN LAB LOG TAMPER MARKER\n"
            "simulated_removed_lines=12\n"
            "simulated_gap_start=2026-06-11T10:10:00Z\n"
            "simulated_gap_end=2026-06-11T10:14:00Z\n"
            "strings: log_wipe unlink truncate auditd_disable journalctl --vacuum-time\n",
        )
        return SimulatedRootkitArtifact(
            alert_id="ALT-LAB-LOGTAMPER-0001",
            artifact_path=path,
            detection_reason="Simulated authentication log tampering marker",
            risk_level=RiskLevel.MEDIUM,
            expected_category="log_tampering_suspect",
            source_module="lab-rootkit-simulator",
            tags=["lab", "rootkit", "log-tampering", "anti-forensics", "benign"],
            indicators=["auth log gap marker", "truncate string", "auditd disable marker"],
            mitre_attack_mapping=["T1014 Rootkit", "T1070 Indicator Removal"],
        )

    def _write_alert_bundle(self, artifacts: list[SimulatedRootkitArtifact]) -> None:
        bundle = {
            "created_at": utc_now(),
            "lab_root": str(self.lab_root),
            "safety_note": "Benign simulation only. No real rootkit behavior is implemented.",
            "safety_controls": [
                "writes only under lab_root",
                "does not load kernel modules",
                "does not modify real /etc, /proc, /var/log, systemd, cron, or SSH configuration",
                "does not open network connections",
                "does not hide files, processes, ports, users, or logs",
            ],
            "detection_surfaces": [
                "kernel module indicators",
                "userland preload indicators",
                "boot persistence indicators",
                "scheduled task indicators",
                "hidden payload indicators",
                "binary tampering indicators",
                "process hiding snapshots",
                "network hiding snapshots",
                "anti-forensic log tampering snapshots",
            ],
            "alerts": [artifact.to_alert() for artifact in artifacts],
        }
        self._write_text(self.lab_root / "alerts.json", json.dumps(to_jsonable(bundle), indent=2) + "\n")
        self._write_text(
            self.lab_root / "simulation_manifest.json",
            json.dumps(
                to_jsonable(
                    {
                        "created_at": bundle["created_at"],
                        "profile": "rootkit-like simulator, detection-realistic, system-safe",
                        "artifact_count": len(artifacts),
                        "artifacts": [
                            {
                                "alert_id": artifact.alert_id,
                                "path": artifact.artifact_path,
                                "expected_category": artifact.expected_category,
                                "indicators": artifact.indicators,
                            }
                            for artifact in artifacts
                        ],
                    }
                ),
                indent=2,
            )
            + "\n",
        )

    @staticmethod
    def _write_text(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")

    @staticmethod
    def _write_bytes(path: Path, content: bytes, *, extra: bytes = b"") -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content + extra)
