import os
import hashlib
import json
from agent.monitor_processes import build_alert

SENSITIVE_PATHS = [
    '/etc/passwd', '/etc/shadow', '/etc/sudoers',
    '/etc/crontab', '/bin', '/sbin', '/usr/bin'
]
SUSPICIOUS_EXEC_DIRS = ['/tmp', '/dev/shm', '/var/tmp']
BASELINE_FILE = "shared/file_baseline.json"

def hash_file(path):
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            h.update(f.read())
        return h.hexdigest()
    except:
        return None

def save_file_baseline():
    baseline = {}
    for path in SENSITIVE_PATHS:
        if os.path.isfile(path):
            baseline[path] = hash_file(path)
    with open(BASELINE_FILE, 'w') as f:
        json.dump(baseline, f, indent=2)
    print(f"[BASELINE] {len(baseline)} fichiers sauvegardés")
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
                        description=f"Exécutable trouvé dans répertoire suspect : {fpath}",
                        details={
                            "path": fpath,
                            "sha256": sha256,
                            "needs_upload": True  # ← signal pour upload
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
                    "needs_upload": True
                }
            ))
    return alerts
