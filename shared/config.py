from __future__ import annotations

import os


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


CONFIG = {
    "backend_url": os.getenv(
        "ROOTKIT_DEFENSE_M4_URL",
        "https://stopped-cet-musician-render.trycloudflare.com",
    ).rstrip("/"),
    "alert_endpoint": os.getenv("ROOTRAP_ALERT_ENDPOINT", "/api/alerts"),
    "scan_interval": _int_env("ROOTRAP_SCAN_INTERVAL", 30),
    "log_file": os.getenv("ROOTRAP_AGENT_LOG_FILE", "logs/agent.log"),
    "pending_alerts_file": os.getenv(
        "ROOTRAP_PENDING_ALERTS_FILE",
        "logs/pending_alerts.jsonl",
    ),
    "discord_webhook": os.getenv("ROOTRAP_DISCORD_WEBHOOK", ""),
    "quarantine_dir": os.getenv("ROOTRAP_AGENT_QUARANTINE_DIR", "quarantine_zone"),
    "baseline_dir": os.getenv("ROOTRAP_BASELINE_DIR", "shared"),
}
