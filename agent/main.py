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


def send_alert(alert):
    with open(CONFIG["pending_alerts_file"], "a", encoding="utf-8") as handle:
        handle.write(json.dumps(alert) + "\n")
    print(f"[ALERT] {alert['severity']} - {alert['type']}")
    logging.info("Alert: %s - %s", alert["type"], alert["severity"])

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
        print(f"[SCAN] Cycle {cycle} running...")

        all_alerts = []
        all_alerts += scan_processes()
        all_alerts += scan_kernel_modules()
        all_alerts += scan_suspicious_executables()
        all_alerts += scan_file_integrity()
        all_alerts += scan_network()

        for alert in all_alerts:
            send_alert(alert)

        print(f"[SCAN] Cycle {cycle} finished - {len(all_alerts)} alerts")
        logging.info("Cycle %s finished: %s alerts", cycle, len(all_alerts))
        time.sleep(CONFIG["scan_interval"])


if __name__ == "__main__":
    print("=== RootRAP Agent started 24/7 ===")
    logging.info("=== Agent started ===")
    run_scans()
