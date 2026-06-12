import os
import hashlib
import json
import shutil
from datetime import datetime, timezone
from agent.monitor_processes import build_alert

SENSITIVE_PATHS = [
    '/etc/passwd', '/etc/shadow', '/etc/sudoers',
    '/etc/crontab', '/bin', '/sbin', '/usr/bin'
]
SUSPICIOUS_EXEC_DIRS = ['/tmp', '/dev/shm', '/var/tmp']
BASELINE_FILE = "shared/file_baseline.json"
QUARANTINE_DIR = "/opt/roottrap/evidence_quarantine/"

def hash_file(path):
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            h.update(f.read())
        return h.hexdigest()
    except:
        return None

def quarantine_file(file_path, alert_id):
    """
    Déplacer le fichier original en quarantaine
    et bloquer toutes ses permissions
    """
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)

        # Nom sécurisé dans la quarantaine
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_name = f"{timestamp}_{alert_id}.bin"
        quarantine_path = os.path.join(QUARANTINE_DIR, safe_name)

        # Déplacer l'original (pas copier)
        shutil.move(file_path, quarantine_path)

        # Bloquer toutes les permissions
        os.chmod(quarantine_path, 0o000)

        print(f"[QUARANTINE] ✅ Fichier isolé : {file_path} → {quarantine_path}")

        return quarantine_path

    except Exception as e:
        print(f"[QUARANTINE] ⚠️ Erreur isolation : {e}")
        return None

def save_file_baseline():
    baseline = {}
    for path in SENSITIVE_PATHS:
        if os.path.isfile(path):
            baseline[path] = hash_file(path)
    with open(BASELINE_FILE, 'w') as f:
        json.dump(baseline, f, indent=2)
    return baseline

def load_file_baseline():
    if not os.path.exists(BASELINE_FILE):
        return save_file_baseline()
    with open(BASELINE_FILE, 'r') as f:
        return json.load(f)

def scan_suspicious_executables():
    alerts = []
    for directory in SUSPICIOUS_EXEC_DIRS:
        if os.path.exists(directory):
            for fname in os.listdir(directory):
                fpath = os.path.join(directory, fname)
                if os.path.isfile(fpath) and os.access(fpath, os.X_OK):
                    sha256 = hash_file(fpath)
                    alert = build_alert(
                        module="file_monitor",
                        severity="HIGH",
                        alert_type="EXECUTABLE_IN_SUSPICIOUS_DIR",
                        description=f"Exécutable suspect isolé : {fpath}",
                        details={
                            "path": fpath,
                            "sha256": sha256,
                            "needs_upload": True,
                            "needs_quarantine": True
                        }
                    )
                    alerts.append(alert)
    return alerts

def scan_file_integrity():
    alerts = []
    baseline = load_file_baseline()
    for path, original_hash in baseline.items():
        current_hash = hash_file(path)
        if current_hash and current_hash != original_hash:
            alerts.append(build_alert(
                module="file_monitor",
                severity="CRITICAL",
                alert_type="SENSITIVE_FILE_MODIFIED",
                description=f"Fichier sensible modifié : {path}",
                details={
                    "path": path,
                    "original_sha256": original_hash,
                    "current_sha256": current_hash,
                    "needs_upload": True,
                    "needs_quarantine": False  # fichier système → ne pas déplacer
                }
            ))
    return alerts
