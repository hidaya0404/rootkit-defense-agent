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
from agent.monitor_files import scan_suspicious_executables, scan_file_integrity
from agent.monitor_network import scan_network
from agent.artifact_uploader import upload_artifact

os.makedirs('/opt/rootkit-defense-agent/logs', exist_ok=True)

logging.basicConfig(
    filename=CONFIG["log_file"],
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

def send_alert(alert):
    """Envoyer alerte à M4 + sauvegarder localement"""
    # Sauvegarde locale
    with open(CONFIG["pending_alerts_file"], 'a') as f:
        f.write(json.dumps(alert) + '\n')
    print(f"[ALERTE] {alert['severity']} — {alert['type']}")

    # Envoi backend M4
    try:
        url = CONFIG["backend_url"] + CONFIG["alert_endpoint"]
        response = requests.post(url, json=alert, timeout=5)
        if response.status_code == 200:
            print(f"[BACKEND] ✅ Alerte envoyée : {alert['alert_id']}")
        else:
            print(f"[BACKEND] ⚠️ Status : {response.status_code}")
    except Exception as e:
        print(f"[BACKEND] ⚠️ Erreur : {e}")

    # Upload artefact si nécessaire
    if alert.get('details', {}).get('needs_upload'):
        file_path = alert['details'].get('path')
        sha256 = alert['details'].get('sha256') or alert['details'].get('current_sha256')
        if file_path and os.path.isfile(file_path):
            upload_artifact(
                alert_id=alert['alert_id'],
                file_path=file_path,
                sha256=sha256
            )

def run_scans():
    cycle = 0
    while True:
        cycle += 1
        print(f"[SCAN] Cycle {cycle} en cours...")
        logging.info(f"Cycle {cycle} démarré")

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
    print("=== Agent RootTrap démarré 24/7 ===")
    logging.info("=== Agent démarré ===")
    run_scans()
