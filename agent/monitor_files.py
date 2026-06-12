import hashlib
import json
import os
import shutil
from datetime import datetime, timezone

from agent.monitor_processes import build_alert
from shared.config import CONFIG


SENSITIVE_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/crontab",
    "/bin",
    "/sbin",
    "/usr/bin",
]
SUSPICIOUS_EXEC_DIRS = ["/tmp", "/dev/shm", "/var/tmp"]
BASELINE_FILE = os.path.join(CONFIG["baseline_dir"], "file_baseline.json")
QUARANTINE_DIR = CONFIG["quarantine_dir"]


def hash_file(path):
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def quarantine_file(file_path, alert_id):
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_name = f"{timestamp}_{alert_id}.bin"
        quarantine_path = os.path.join(QUARANTINE_DIR, safe_name)

        shutil.move(file_path, quarantine_path)
        os.chmod(quarantine_path, 0o000)

        print(f"[QUARANTINE] isolated: {file_path} -> {quarantine_path}")
        return quarantine_path

    except Exception as exc:
        print(f"[QUARANTINE] isolation error: {exc}")
        return None


def save_file_baseline():
    os.makedirs(os.path.dirname(BASELINE_FILE) or ".", exist_ok=True)
    baseline = {}
    for path in SENSITIVE_PATHS:
        if os.path.isfile(path):
            baseline[path] = hash_file(path)
    with open(BASELINE_FILE, "w", encoding="utf-8") as handle:
        json.dump(baseline, handle, indent=2)
    return baseline


def load_file_baseline():
    if not os.path.exists(BASELINE_FILE):
        return save_file_baseline()
    with open(BASELINE_FILE, "r", encoding="utf-8") as handle:
        return json.load(handle)


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
                        description=f"Executable suspect isole : {fpath}",
                        details={
                            "path": fpath,
                            "sha256": sha256,
                            "needs_upload": True,
                            "needs_quarantine": True,
                        },
                    )
                    alerts.append(alert)
    return alerts


def scan_file_integrity():
    alerts = []
    baseline = load_file_baseline()
    for path, original_hash in baseline.items():
        current_hash = hash_file(path)
        if current_hash and current_hash != original_hash:
            alerts.append(
                build_alert(
                    module="file_monitor",
                    severity="CRITICAL",
                    alert_type="SENSITIVE_FILE_MODIFIED",
                    description=f"Fichier sensible modifie : {path}",
                    details={
                        "path": path,
                        "original_sha256": original_hash,
                        "current_sha256": current_hash,
                        "needs_upload": True,
                        "needs_quarantine": False,
                    },
                )
            )
    return alerts
