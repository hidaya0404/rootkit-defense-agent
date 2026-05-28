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
    hidden = get_proc_pids() - get_psutil_pids()
    for pid in hidden:
        alerts.append(build_alert(
            module="process_monitor",
            severity="CRITICAL",
            alert_type="HIDDEN_PROCESS",
            description=f"PID {pid} visible dans /proc mais absent de psutil",
            details={"pid": pid}
        ))

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
        try:
            exe = proc.info['exe'] or ''
            if any(exe.startswith(d) for d in ['/tmp', '/dev/shm', '/var/tmp']):
                alerts.append(build_alert(
                    module="process_monitor",
                    severity="HIGH",
                    alert_type="SUSPICIOUS_PROCESS_PATH",
                    description=f"Processus depuis repertoire suspect : {exe}",
                    details={
                        "pid": proc.pid,
                        "name": proc.info['name'],
                        "exe": exe,
                        "user": proc.info['username']
                    }
                ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return alerts
