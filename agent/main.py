import hashlib
import json
import logging
import os
import sys
import time
from pathlib import Path

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
from evidence_quarantine.config import QuarantineConfig
from evidence_quarantine.models import QuarantineRequest, RiskLevel
from evidence_quarantine.quarantine_manager import QuarantineManager


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


def _m2_storage_root() -> Path:
    return Path(
        os.getenv("ROOTRAP_STORAGE_ROOT")
        or os.getenv("ROOTKIT_DEFENSE_STORAGE")
        or "/var/lib/rootrap"
    ).expanduser()


def _risk_level(value: object) -> RiskLevel:
    try:
        return RiskLevel[str(value or "MEDIUM").upper()]
    except KeyError:
        return RiskLevel.MEDIUM


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


def _send_alert_legacy(alert):
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


def quarantine_artifact_for_alert(alert: dict) -> str | None:
    details = alert.setdefault("details", {})
    file_path = details.get("path")
    if not file_path or not os.path.isfile(file_path):
        return None

    manager = QuarantineManager(QuarantineConfig(storage_root=_m2_storage_root()))
    result = manager.quarantine_artifact(
        QuarantineRequest(
            artifact_path=Path(str(file_path)),
            detection_reason=str(alert.get("description") or alert.get("type") or "RootRAP detection"),
            alert_id=str(alert.get("alert_id") or ""),
            risk_level=_risk_level(alert.get("severity")),
            detected_at=alert.get("timestamp"),
            source_module=str(alert.get("source_module") or "agent"),
            tags=["agent", "auto-quarantine", str(alert.get("type") or "alert")],
        )
    )

    details["m2_artifact_id"] = result.artifact_id
    details["m2_evidence_dir"] = str(result.evidence_dir)
    details["m2_manifest_path"] = str(result.manifest_path) if result.manifest_path else None
    details["m2_status"] = result.status.value
    details["m2_errors"] = result.errors

    if not result.success or not result.artifact_path:
        return None

    try:
        if os.path.exists(file_path):
            os.remove(file_path)
    except OSError as exc:
        details["source_cleanup_warning"] = str(exc)

    return str(result.artifact_path)


def send_alert(alert):
    if is_duplicate(alert):
        return False

    print(f"[ALERT] {alert['severity']} - {alert['type']} | {alert.get('description', '')}")
    logging.info("Alert: %s - %s | %s", alert["type"], alert["severity"], alert.get("description"))

    if alert.get("details", {}).get("needs_quarantine"):
        file_path = alert["details"].get("path")
        if file_path and os.path.isfile(file_path):
            quarantine_path = quarantine_artifact_for_alert(alert)
            if not quarantine_path and os.path.isfile(file_path):
                quarantine_path = quarantine_file(file_path, alert["alert_id"])
            if quarantine_path:
                alert["details"]["quarantine_path"] = quarantine_path

    with open(CONFIG["pending_alerts_file"], "a", encoding="utf-8") as handle:
        handle.write(json.dumps(alert) + "\n")

    try:
        url = CONFIG["backend_url"] + CONFIG["alert_endpoint"]
        requests.post(url, json=alert, timeout=5)
        print("[BACKEND] sent")
    except Exception as exc:
        print(f"[BACKEND] warning: {exc}")
    return True


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
            if send_alert(alert):
                sent += 1

        print(f"[SCAN] Cycle {cycle} finished — {len(all_alerts)} détectées, {sent} nouvelles envoyées")
        logging.info("Cycle %s: %s detected, %s new", cycle, len(all_alerts), sent)
        time.sleep(CONFIG["scan_interval"])


if __name__ == "__main__":
    print("=== RootRAP Agent started 24/7 ===")
    logging.info("=== Agent started ===")
    run_scans()

