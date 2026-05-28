import time
import logging
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.config import CONFIG
from agent.monitor_processes import scan_processes
from agent.monitor_kernel import scan_kernel_modules
from agent.monitor_files import scan_suspicious_executables, scan_file_integrity
from agent.monitor_network import scan_network

os.makedirs('logs', exist_ok=True)

logging.basicConfig(
    filename=CONFIG["log_file"],
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

def send_alert(alert):
    """Sauvegarder alerte localement en attendant le backend"""
    with open(CONFIG["pending_alerts_file"], 'a') as f:
        import json
        f.write(json.dumps(alert) + '\n')
    logging.info(f"Alerte : {alert['type']} - {alert['severity']}")
    print(f"[ALERTE] {alert['severity']} — {alert['type']} : {alert['description']}")

def run_scans():
    while True:
        logging.info("Démarrage cycle de scan...")
        all_alerts = []
        all_alerts += scan_processes()
        all_alerts += scan_kernel_modules()
        all_alerts += scan_suspicious_executables()
        all_alerts += scan_file_integrity()
        all_alerts += scan_network()

        for alert in all_alerts:
            send_alert(alert)

        logging.info(f"Cycle terminé : {len(all_alerts)} alertes")
        print(f"[SCAN] Cycle terminé — {len(all_alerts)} alertes")
        time.sleep(CONFIG["scan_interval"])

if __name__ == "__main__":
    logging.info("=== Agent Rootkit Defense démarré ===")
    print("=== Agent démarré — Ctrl+C pour arrêter ===")
    run_scans()
