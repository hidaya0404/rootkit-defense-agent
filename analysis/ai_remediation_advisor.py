from __future__ import annotations

from datetime import datetime
import math
import re
from typing import Any


MODEL_INFO = {
    "name": "RDA-Remediation-AI",
    "version": "1.0",
    "type": "local_playbook_ranker",
    "external_api": False,
    "purpose": "Defensive rootkit incident remediation recommendation",
}


PLAYBOOKS = [
    {
        "id": "kernel_module_rootkit_response",
        "title": "Kernel module rootkit response",
        "priority": "CRITICAL",
        "signals": [
            "kernel",
            "module",
            "insmod",
            "rmmod",
            "modprobe",
            "lsmod",
            "/lib/modules",
            "sys_call_table",
            "init_module",
            ".ko",
        ],
        "containment": [
            "Keep the artifact in quarantine and block execution or loading on production hosts.",
            "Preserve module metadata, hashes, audit logs, and the original detection alert.",
            "Isolate the impacted Linux host if unknown kernel module loading is confirmed.",
        ],
        "investigation": [
            "Review loaded modules with lsmod and compare against the approved kernel module baseline.",
            "Inspect dmesg, journalctl -k, and kernel module load events around the detection timestamp.",
            "Check /lib/modules, /etc/modules-load.d, and /etc/modprobe.d for unauthorized persistence.",
        ],
        "remediation": [
            "Do not unload or delete blindly; validate the module identity and preserve evidence first.",
            "Remove unauthorized module load configuration after analyst approval.",
            "Rebuild or reimage the host if kernel-space compromise is confirmed.",
        ],
        "validation": [
            "Reboot in a controlled maintenance window and verify the suspicious module does not reload.",
            "Run M1 kernel monitor again and confirm no unknown module remains.",
        ],
    },
    {
        "id": "ld_preload_userland_hook_response",
        "title": "LD_PRELOAD userland hook response",
        "priority": "HIGH",
        "signals": [
            "ld.so.preload",
            "ld_preload",
            "preload",
            "readdir",
            "getdents",
            "libc",
            "hide_process",
            "hook",
        ],
        "containment": [
            "Keep the suspected preload library and /etc/ld.so.preload evidence in quarantine.",
            "Prevent interactive users from executing suspicious binaries until the preload chain is reviewed.",
        ],
        "investigation": [
            "Inspect /etc/ld.so.preload and referenced shared libraries.",
            "Check process/file hiding indicators by comparing ps, /proc, lsof, and direct filesystem reads.",
            "Search for the same library hash across other Linux hosts.",
        ],
        "remediation": [
            "Remove malicious preload entries only after evidence preservation and approval.",
            "Replace tampered userland binaries from trusted packages if integrity mismatch is confirmed.",
        ],
        "validation": [
            "Run M1 process and file monitors again after cleanup.",
            "Confirm the preload file is empty or matches the approved baseline.",
        ],
    },
    {
        "id": "persistence_mechanism_response",
        "title": "Persistence mechanism response",
        "priority": "HIGH",
        "signals": [
            "systemd",
            ".service",
            "cron",
            "crontab",
            "modules-load.d",
            "rc.local",
            "persistence",
            "startup",
        ],
        "containment": [
            "Disable the suspicious persistence entry without deleting the evidence package.",
            "Keep service files, cron entries, timestamps, and owner information in the report.",
        ],
        "investigation": [
            "Review systemctl list-unit-files, systemctl status, timers, and cron directories.",
            "Correlate created_at and modified_at timestamps with the original alert timeline.",
            "Identify the binary or script launched by the persistence mechanism.",
        ],
        "remediation": [
            "Remove unauthorized systemd or cron persistence after analyst validation.",
            "Rotate credentials if the persistence mechanism executed with privileged context.",
        ],
        "validation": [
            "Reboot the test host and verify the suspicious service or cron job does not restart.",
            "Confirm M1 file monitor no longer reports unauthorized persistence.",
        ],
    },
    {
        "id": "network_ioc_response",
        "title": "Network IOC response",
        "priority": "HIGH",
        "signals": [
            "http://",
            "https://",
            "tcp",
            "udp",
            "reverse shell",
            "4444",
            "connect",
            "network",
            "domain",
            "url",
            "ip",
        ],
        "containment": [
            "Block confirmed malicious IPs, domains, and URLs at firewall, DNS, or proxy level.",
            "Preserve connection evidence before applying destructive network changes.",
        ],
        "investigation": [
            "Correlate IOC timestamps with firewall, proxy, DNS, and endpoint logs.",
            "Check whether the same IOC appears in sandbox network events.",
            "Search for outbound connections from other hosts to the same destinations.",
        ],
        "remediation": [
            "Add temporary containment rules for confirmed malicious destinations.",
            "Open an incident ticket for any host that contacted confirmed malicious infrastructure.",
        ],
        "validation": [
            "Verify no new outbound events to the same IOC after containment.",
            "Re-run IOC extraction after updated analysis data is available.",
        ],
    },
    {
        "id": "anti_forensic_log_tamper_response",
        "title": "Anti-forensic and log tampering response",
        "priority": "CRITICAL",
        "signals": [
            "auth.log",
            "wtmp",
            "utmp",
            "journal",
            "log",
            "tamper",
            "truncate",
            "history",
            "anti-forensic",
        ],
        "containment": [
            "Preserve current logs and quarantine suspected tampering markers.",
            "Avoid log rotation or cleanup jobs until evidence is copied.",
        ],
        "investigation": [
            "Compare local logs with centralized SIEM, EDR, or remote syslog records.",
            "Check shell history, authentication logs, sudo logs, and journal gaps.",
            "Review filesystem timestamps for log truncation or unauthorized edits.",
        ],
        "remediation": [
            "Rebuild trust in logging by restarting known-good logging services after evidence capture.",
            "Treat confirmed log tampering as a high-confidence compromise indicator.",
        ],
        "validation": [
            "Confirm new authentication and system events are recorded correctly.",
            "Document any irrecoverable log gaps in the final report.",
        ],
    },
    {
        "id": "generic_suspicious_artifact_response",
        "title": "Generic suspicious Linux artifact response",
        "priority": "MEDIUM",
        "signals": [
            "rootkit",
            "suspicious",
            "artifact",
            "binary",
            "elf",
            "yara",
            "hash",
        ],
        "containment": [
            "Keep the artifact quarantined and do not execute it on the host.",
            "Preserve hashes, metadata, strings, IOC, and YARA matches.",
        ],
        "investigation": [
            "Compare the artifact hash with trusted baselines and reputation sources.",
            "Review extracted strings for paths, services, credentials, and network indicators.",
            "Send the artifact to M3 sandbox if risk is HIGH or CRITICAL.",
        ],
        "remediation": [
            "Apply manual remediation only after static and sandbox analysis are reviewed.",
            "Update detection rules if the artifact is confirmed malicious.",
        ],
        "validation": [
            "Confirm no related alerts remain open after remediation.",
            "Attach the AI recommendation and analyst decision to the incident report.",
        ],
    },
]


def build_ai_recommendation(artifact: dict[str, Any]) -> dict[str, Any]:
    analysis = artifact.get("analysis", {}) if isinstance(artifact, dict) else {}
    text = _build_signal_text(artifact, analysis)
    tokens = _tokenize(text)

    ranked = []
    for playbook in PLAYBOOKS:
        matched = _matched_signals(tokens, playbook["signals"], text)
        score = _playbook_score(playbook, matched, analysis, artifact)
        ranked.append((score, matched, playbook))

    ranked.sort(key=lambda item: item[0], reverse=True)
    best_score, matched, selected = ranked[0]
    confidence = min(0.98, max(0.35, best_score / 100))

    risk_level = str(analysis.get("risk_level") or "UNKNOWN").upper()
    priority = _priority(selected["priority"], risk_level)
    recommended_actions = _flatten_actions(selected)

    return {
        "model": MODEL_INFO,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "artifact_id": artifact.get("artifact_id"),
        "alert_id": artifact.get("alert_id"),
        "selected_playbook": {
            "id": selected["id"],
            "title": selected["title"],
            "priority": priority,
        },
        "confidence": round(confidence, 2),
        "risk_level": risk_level,
        "risk_score": analysis.get("risk_score"),
        "decision": _decision(priority, selected["title"]),
        "matched_signals": matched,
        "rationale": _rationale(selected, matched, analysis),
        "recommended_actions": recommended_actions,
        "containment_actions": selected["containment"],
        "investigation_actions": selected["investigation"],
        "remediation_actions": selected["remediation"],
        "validation_actions": selected["validation"],
        "requires_human_validation": True,
        "automatic_destructive_action_allowed": False,
    }


def flatten_ai_recommendations(ai_recommendation: dict[str, Any]) -> list[str]:
    actions = ai_recommendation.get("recommended_actions", [])
    if isinstance(actions, list) and actions:
        return [str(action) for action in actions]
    return [
        "Keep the artifact in quarantine.",
        "Preserve hashes, metadata, IOC, YARA results, and audit logs.",
        "Require analyst validation before remediation.",
    ]


def _build_signal_text(artifact: dict[str, Any], analysis: dict[str, Any]) -> str:
    parts: list[str] = []
    parts.extend(_values(artifact))
    parts.extend(_values(analysis))
    sandbox = artifact.get("sandbox_result") or analysis.get("sandbox_result")
    if isinstance(sandbox, dict):
        parts.extend(_values(sandbox))
    return " ".join(parts).lower()


def _values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        result: list[str] = []
        for key, item in value.items():
            result.append(str(key))
            result.extend(_values(item))
        return result
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(_values(item))
        return result
    return [str(value)]


def _tokenize(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9_./:-]+", text.lower()))


def _matched_signals(tokens: set[str], signals: list[str], text: str) -> list[str]:
    matched = []
    for signal in signals:
        normalized = signal.lower()
        if _signal_matches(normalized, tokens, text):
            matched.append(signal)
    return matched


def _signal_matches(signal: str, tokens: set[str], text: str) -> bool:
    if signal in tokens:
        return True

    # Paths, extensions, URLs, and phrases must be matched in the full context.
    if any(char in signal for char in "/:. "):
        return signal in text

    generic_exact_only = {
        "artifact",
        "binary",
        "domain",
        "elf",
        "hash",
        "ip",
        "log",
        "network",
        "suspicious",
        "url",
        "yara",
    }
    if signal in generic_exact_only:
        return False

    # Split technical tokens such as hook_getdents64 or artifact_id without
    # giving generic words like "artifact" or "hash" accidental substring hits.
    token_parts = set()
    for token in tokens:
        token_parts.update(part for part in re.split(r"[^a-z0-9]+", token) if part)
    if signal in token_parts:
        return True

    high_signal_prefixes = {"getdents", "preload", "connect"}
    if signal in high_signal_prefixes:
        return any(signal in token for token in tokens)

    return False


def _playbook_score(
    playbook: dict[str, Any],
    matched: list[str],
    analysis: dict[str, Any],
    artifact: dict[str, Any],
) -> float:
    score = len(matched) * 14
    risk_level = str(analysis.get("risk_level") or "").upper()
    risk_score = int(analysis.get("risk_score") or 0)
    category = str(artifact.get("rootkit_category") or "").lower()

    if risk_level == playbook["priority"]:
        score += 16
    if risk_level in {"HIGH", "CRITICAL"}:
        score += 10
    if risk_score:
        score += min(20, math.floor(risk_score / 5))
    if playbook["id"].split("_response")[0].replace("_", " ") in category:
        score += 12
    return score


def _priority(playbook_priority: str, risk_level: str) -> str:
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    risk = risk_level if risk_level in order else "MEDIUM"
    return max(playbook_priority, risk, key=order.index)


def _decision(priority: str, playbook_title: str) -> str:
    if priority == "CRITICAL":
        return f"Immediate containment required using {playbook_title}; keep evidence quarantined and escalate to analyst."
    if priority == "HIGH":
        return f"Prioritize investigation using {playbook_title}; sandbox and validate before remediation."
    if priority == "MEDIUM":
        return f"Monitor and investigate using {playbook_title}; no destructive action without validation."
    return f"Document and monitor using {playbook_title}; preserve evidence."


def _rationale(playbook: dict[str, Any], matched: list[str], analysis: dict[str, Any]) -> list[str]:
    rationale = [
        f"Selected playbook: {playbook['title']}",
        f"Matched signals: {', '.join(matched) if matched else 'generic suspicious artifact'}",
    ]
    if analysis.get("risk_level"):
        rationale.append(f"Risk level from scoring engine: {analysis.get('risk_level')}")
    if analysis.get("yara_matches"):
        rationale.append("YARA output is included in the recommendation context.")
    if analysis.get("iocs"):
        rationale.append("IOC extraction is included in the recommendation context.")
    return rationale


def _flatten_actions(playbook: dict[str, Any]) -> list[str]:
    return [
        *playbook["containment"],
        *playbook["investigation"],
        *playbook["remediation"],
        *playbook["validation"],
    ]
