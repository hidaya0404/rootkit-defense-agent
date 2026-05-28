from __future__ import annotations

import stat
from pathlib import Path

from evidence_quarantine.models import RootkitArtifactProfile


class RootkitArtifactClassifier:
    """Classifies Linux rootkit-related evidence without executing the artifact."""

    def classify(self, path: Path) -> RootkitArtifactProfile:
        lowered = path.as_posix().lower()
        name = path.name.lower()
        rationale: list[str] = []
        techniques: list[str] = []
        mitre: list[str] = ["T1014 Rootkit"]
        category = "unknown_rootkit_artifact"
        next_step = "Perform static analysis, YARA scan, and sandbox handoff if integrity is valid."

        executable = self._is_executable(path)

        if name.endswith(".ko") or "/lib/modules/" in lowered:
            category = "kernel_module_rootkit_suspect"
            techniques.extend(["kernel_module_loading", "kernel_space_hiding"])
            mitre.extend(["T1547.006 Kernel Modules and Extensions"])
            rationale.append("Artifact resembles a Linux kernel module or is located under module storage.")
            next_step = "Extract module metadata with modinfo/readelf in analysis environment; do not load it on host."

        elif name == "ld.so.preload" or lowered.endswith("/etc/ld.so.preload"):
            category = "userland_preload_hook_suspect"
            techniques.extend(["ld_preload_hooking", "userland_api_interception"])
            mitre.extend(["T1574 Hijack Execution Flow"])
            rationale.append("ld.so.preload can force shared libraries into processes and hide userland activity.")
            next_step = "Inspect referenced libraries and preserve every path listed in ld.so.preload."

        elif "/etc/modules-load.d/" in lowered or "/etc/modprobe.d/" in lowered:
            category = "kernel_module_persistence_suspect"
            techniques.extend(["kernel_module_persistence", "boot_time_loading"])
            mitre.extend(["T1547.006 Kernel Modules and Extensions"])
            rationale.append("Module auto-load configuration can persist kernel-level components.")
            next_step = "Collect referenced module names and related .ko files for correlation."

        elif "/systemd/" in lowered or name.endswith(".service"):
            category = "systemd_persistence_suspect"
            techniques.extend(["service_persistence", "auto_start"])
            mitre.extend(["T1543.002 Systemd Service"])
            rationale.append("Systemd unit files can persist suspicious binaries after reboot.")
            next_step = "Parse ExecStart/ExecReload entries and quarantine referenced binaries if suspicious."

        elif "/cron" in lowered or "/var/spool/cron/" in lowered:
            category = "cron_persistence_suspect"
            techniques.extend(["scheduled_task_persistence"])
            mitre.extend(["T1053.003 Cron"])
            rationale.append("Cron entries can repeatedly launch hidden payloads or restoration scripts.")
            next_step = "Extract scheduled commands and correlate them with quarantined artifacts."

        elif name.endswith(".so"):
            category = "shared_library_hook_suspect"
            techniques.extend(["shared_library_injection", "userland_hooking"])
            mitre.extend(["T1574 Hijack Execution Flow"])
            rationale.append("Shared libraries can be used by userland rootkits to intercept libc/system calls.")
            next_step = "Run strings/readelf and YARA rules for preload or hook indicators."

        elif self._is_hidden_name(name) and self._is_temp_or_runtime_path(lowered):
            category = "hidden_payload_suspect"
            techniques.extend(["hidden_file", "masquerading"])
            mitre.extend(["T1036 Masquerading"])
            rationale.append("Hidden file found in a temporary/runtime location commonly abused for stealth.")
            next_step = "Check parent directory, timestamps, and related running process command lines."

        elif executable and self._is_temp_or_runtime_path(lowered):
            category = "temporary_executable_payload_suspect"
            techniques.extend(["dropped_executable", "staging_directory_abuse"])
            rationale.append("Executable artifact in temporary/runtime location may indicate staged payload.")
            next_step = "Preserve process context and send artifact to sandbox after integrity verification."

        elif self._looks_like_system_binary_replacement(lowered):
            category = "system_binary_tampering_suspect"
            techniques.extend(["binary_replacement", "defense_evasion"])
            mitre.extend(["T1036 Masquerading"])
            rationale.append("Artifact path resembles a common Linux command targeted by userland rootkits.")
            next_step = "Compare hash with trusted package manager baseline in a clean environment."

        else:
            rationale.append("Artifact is suspicious by detection context, but no specific rootkit family pattern was inferred.")

        return RootkitArtifactProfile(
            category=category,
            suspected_techniques=techniques or ["rootkit_indicator"],
            rationale=rationale,
            recommended_next_step=next_step,
            mitre_attack_mapping=mitre,
        )

    @staticmethod
    def _is_executable(path: Path) -> bool:
        try:
            mode = path.stat().st_mode
        except OSError:
            return False
        return bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))

    @staticmethod
    def _is_temp_or_runtime_path(lowered_path: str) -> bool:
        return (
            lowered_path.startswith("/tmp/")
            or lowered_path.startswith("/var/tmp/")
            or lowered_path.startswith("/dev/shm/")
            or "/tmp/" in lowered_path
            or "/var/tmp/" in lowered_path
            or "/dev/shm/" in lowered_path
        )

    @staticmethod
    def _is_hidden_name(name: str) -> bool:
        return name.startswith(".") and name not in {".", ".."}

    @staticmethod
    def _looks_like_system_binary_replacement(lowered_path: str) -> bool:
        targets = ("/bin/ps", "/bin/ls", "/bin/netstat", "/bin/ss", "/usr/bin/ps", "/usr/bin/ls")
        return any(lowered_path.endswith(target) for target in targets)
