import subprocess
from agent.monitor_processes import build_alert

def get_connections_from_proc():
    connections = set()
    for proto_file in ['/proc/net/tcp', '/proc/net/tcp6']:
        try:
            with open(proto_file) as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) > 3:
                        # 01 = ESTABLISHED uniquement
                        if parts[3] == '01':
                            connections.add((parts[1], parts[2]))
        except:
            pass
    return connections

def get_connections_from_ss():
    result = subprocess.run(['ss', '-tn'], capture_output=True, text=True)
    connections = set()
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            connections.add(parts[4])
    return connections

def scan_network():
    alerts = []
    proc_conns = get_connections_from_proc()
    ss_conns = get_connections_from_ss()

    if abs(len(proc_conns) - len(ss_conns)) > 2:
        alerts.append(build_alert(
            module="network_monitor",
            severity="CRITICAL",
            alert_type="HIDDEN_NETWORK_CONNECTION",
            description="Incohérence détectée entre /proc/net/tcp et ss",
            details={
                "proc_count": len(proc_conns),
                "ss_count": len(ss_conns)
            }
        ))
    return alerts
