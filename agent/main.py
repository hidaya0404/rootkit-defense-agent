import hashlib
import json
import logging
import os
import sys
import time

import requests

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.config import CONFIG
from agent.monitor_files import (
    quarantine_file,
    scan_file_integrity,
    scan_suspicious_executables,
)
from agent.monitor_kernel import scan_kernel_modules
from agent.monitor_network import scan_network
from agent.monitor_processes import scan_processes


os.makedirs(os.path.dirname(CONFIG["log_file"]) or ".", exist_ok=True)
os.makedirs(os.path.dirname(CONFIG["pending_alerts_file"]) or ".", exist_ok=True)

logging.basicConfig(
    filename=CONFIG["log_file"],
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# Déduplication : garde une signature des alertes déjà envoyées
# Format : { alert_signature: last_sent_timestamp }
_sent_alerts: dict = {}

# Délai minimum entre deux alertes identiques (en secondes)
ALERT_COOLDOWN = CONFIG.get("alert_cooldown", 300)  # 5 min par défaut


def _alert_signature(alert: dict) -> str:
    """Génère une clé unique par (type, module, détail principal)."""
    key_parts = [
        alert.get("type", ""),
        alert.get("source_module", ""),
        str(alert.get("details", {}).get("pid", "")),
        str(alert.get("details", {}).get("path", "")),
        str(alert.get("details", {}).get("module_name", "")),
    ]
    raw = "|".join(key_parts)
    return hashlib.md5(raw.encode()).hexdigest()


def is_duplicate(alert: dict) -> bool:
    sig = _alert_signature(alert)
    now = time.time()
    last_sent = _sent_alerts.get(sig)
    if last_sent and (now - last_sent) < ALERT_COOLDOWN:
        return True
    _sent_alerts[sig] = now
    return False


def send_alert(alert):
    if is_duplicate(alert):
        return  # Supprime les doublons dans la fenêtre de cooldown

    with open(CONFIG["pending_alerts_file"], "a", encoding="utf-8") as handle:
        handle.write(json.dumps(alert) + "\n")

    print(f"[ALERT] {alert['severity']} - {alert['type']} | {alert.get('description', '')}")
    logging.info("Alert: %s - %s | %s", alert["type"], alert["severity"], alert.get("description"))

    if alert.get("details", {}).get("needs_quarantine"):
        file_path = alert["details"].get("path")
        if file_path and os.path.isfile(file_path):
            quarantine_path = quarantine_file(file_path, alert["alert_id"])
            if quarantine_path:
                alert["details"]["quarantine_path"] = quarantine_path

    try:
        url = CONFIG["backend_url"] + CONFIG["alert_endpoint"]
        requests.post(url, json=alert, timeout=5)
        print("[BACKEND] sent")
    except Exception as exc:
        print(f"[BACKEND] warning: {exc}")


def run_scans():
    cycle = 0
    while True:
        cycle += 1
        print(f"\n[SCAN] Cycle {cycle} running...")

        all_alerts = []
        all_alerts += scan_processes()
        all_alerts += scan_kernel_modules()
        all_alerts += scan_suspicious_executables()
        all_alerts += scan_file_integrity()
        all_alerts += scan_network()

        sent = 0
        for alert in all_alerts:
            if not is_duplicate(alert):
                send_alert(alert)
                sent += 1

        print(f"[SCAN] Cycle {cycle} finished — {len(all_alerts)} détectées, {sent} nouvelles envoyées")
        logging.info("Cycle %s: %s detected, %s new", cycle, len(all_alerts), sent)
        time.sleep(CONFIG["scan_interval"])


if __name__ == "__main__":
    print("=== RootRAP Agent started 24/7 ===")
    logging.info("=== Agent started ===")
    run_scans()

