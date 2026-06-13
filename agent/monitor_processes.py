import psutil
import os
import uuid
from datetime import datetime, timezone


def build_alert(module, severity, alert_type, description, details):
    return {
        "alert_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_module": module,
        "severity": severity,
        "type": alert_type,
        "description": description,
        "details": details,
        "status": "NEW"
    }


def get_proc_pids():
    pids = set()
    for entry in os.listdir('/proc'):
        if entry.isdigit():
            pids.add(int(entry))
    return pids


def get_psutil_pids():
    return set(p.pid for p in psutil.process_iter())


def scan_processes():
    alerts = []

    # --- Processus cachés ---
    hidden = get_proc_pids() - get_psutil_pids()
    for pid in hidden:
        # Tenter de lire les infos depuis /proc directement
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().replace(b'\x00', b' ').decode(errors='replace').strip()
        except Exception:
            cmdline = "non lisible"

        alerts.append(build_alert(
            module="process_monitor",
            severity="CRITICAL",
            alert_type="HIDDEN_PROCESS",
            description=f"PID {pid} visible dans /proc mais absent de psutil — possible rootkit",
            details={
                "pid": pid,
                "cmdline": cmdline,
                "detection_method": "/proc vs psutil"
            }
        ))

    # --- Processus depuis répertoires suspects ---
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'cmdline', 'ppid', 'create_time']):
        try:
            exe = proc.info['exe'] or ''
            if any(exe.startswith(d) for d in ['/tmp', '/dev/shm', '/var/tmp']):
                # Récupérer le nom du processus parent
                try:
                    parent = psutil.Process(proc.info['ppid'])
                    parent_name = parent.name()
                except Exception:
                    parent_name = "inconnu"

                cmdline = " ".join(proc.info.get('cmdline') or []) or exe
                uptime_s = round(datetime.now(timezone.utc).timestamp() - (proc.info.get('create_time') or 0))

                alerts.append(build_alert(
                    module="process_monitor",
                    severity="HIGH",
                    alert_type="SUSPICIOUS_PROCESS_PATH",
                    description=f"Processus '{proc.info['name']}' (PID {proc.pid}) exécuté depuis {exe}",
                    details={
                        "pid": proc.pid,
                        "name": proc.info['name'],
                        "exe": exe,
                        "cmdline": cmdline,
                        "user": proc.info['username'],
                        "ppid": proc.info['ppid'],
                        "parent_name": parent_name,
                        "uptime_seconds": uptime_s,
                    }
                ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return alerts

