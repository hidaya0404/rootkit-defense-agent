import time
import logging
import json
import os
import sys
import requests
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.config import CONFIG
from agent.monitor_processes import scan_processes
from agent.monitor_kernel import scan_kernel_modules
from agent.monitor_files import (scan_suspicious_executables,
                                  scan_file_integrity,
                                  quarantine_file)
from agent.monitor_network import scan_network

os.makedirs('/opt/roottrap/logs', exist_ok=True)

logging.basicConfig(
    filename=CONFIG["log_file"],
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

def send_alert(alert):
    # Sauvegarde locale
    with open(CONFIG["pending_alerts_file"], 'a') as f:
        f.write(json.dumps(alert) + '\n')
    print(f"[ALERTE] {alert['severity']} — {alert['type']}")
    logging.info(f"Alerte : {alert['type']} - {alert['severity']}")

    # Quarantaine du fichier original si nécessaire
    if alert.get('details', {}).get('needs_quarantine'):
        file_path = alert['details'].get('path')
        if file_path and os.path.isfile(file_path):
            quarantine_path = quarantine_file(file_path, alert['alert_id'])
            if quarantine_path:
                alert['details']['quarantine_path'] = quarantine_path

    # Envoi backend
    try:
        url = CONFIG["backend_url"] + CONFIG["alert_endpoint"]
        requests.post(url, json=alert, timeout=5)
        print(f"[BACKEND] ✅ Envoyée")
    except Exception as e:
        print(f"[BACKEND] ⚠️ {e}")

def run_scans():
    cycle = 0
    while True:
        cycle += 1
        print(f"[SCAN] Cycle {cycle} en cours...")

        all_alerts = []
        all_alerts += scan_processes()
        all_alerts += scan_kernel_modules()
        all_alerts += scan_suspicious_executables()
        all_alerts += scan_file_integrity()
        all_alerts += scan_network()

        for alert in all_alerts:
            send_alert(alert)

        print(f"[SCAN] Cycle {cycle} terminé — {len(all_alerts)} alertes")
        logging.info(f"Cycle {cycle} terminé : {len(all_alerts)} alertes")
        time.sleep(CONFIG["scan_interval"])

if __name__ == "__main__":
    print("=== RootTrap Agent démarré 24/7 ===")
    logging.info("=== Agent démarré ===")
    run_scans()
