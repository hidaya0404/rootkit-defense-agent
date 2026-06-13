import subprocess
from agent.monitor_processes import build_alert


def _hex_to_ip_port(hex_addr: str):
    """Convertit une adresse hex du format /proc/net/tcp en IP:port lisible."""
    try:
        addr, port_hex = hex_addr.split(":")
        # Little-endian byte reversal pour l'IP
        ip = ".".join(str(int(addr[i:i+2], 16)) for i in range(6, -1, -2))
        port = int(port_hex, 16)
        return f"{ip}:{port}"
    except Exception:
        return hex_addr


def get_connections_from_proc():
    connections = {}
    for proto_file in ['/proc/net/tcp', '/proc/net/tcp6']:
        try:
            with open(proto_file) as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) > 3 and parts[3] == '01':  # ESTABLISHED
                        local = _hex_to_ip_port(parts[1])
                        remote = _hex_to_ip_port(parts[2])
                        inode = parts[9] if len(parts) > 9 else "?"
                        connections[inode] = {"local": local, "remote": remote, "inode": inode}
        except Exception:
            pass
    return connections


def get_connections_from_ss():
    result = subprocess.run(['ss', '-tnp'], capture_output=True, text=True)
    connections = {}
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            # ss -tnp : State Recv-Q Send-Q Local Remote [process]
            remote = parts[4]
            process_info = parts[5] if len(parts) > 5 else ""
            connections[remote] = {"remote": remote, "process": process_info}
    return connections


def scan_network():
    alerts = []
    proc_conns = get_connections_from_proc()
    ss_conns = get_connections_from_ss()

    proc_count = len(proc_conns)
    ss_count = len(ss_conns)
    diff = abs(proc_count - ss_count)

    # Seuil adaptatif : alerte seulement si diff > 20% du total ET > 1
    threshold = max(2, int(proc_count * 0.20))

    if diff > threshold:
        # Identifier les connexions présentes dans /proc mais absentes de ss
        proc_remotes = {v["remote"] for v in proc_conns.values()}
        ss_remotes = set(ss_conns.keys())
        hidden_remotes = proc_remotes - ss_remotes

        alerts.append(build_alert(
            module="network_monitor",
            severity="CRITICAL",
            alert_type="HIDDEN_NETWORK_CONNECTION",
            description=(
                f"Incohérence réseau : {proc_count} connexions dans /proc/net/tcp "
                f"vs {ss_count} dans ss ({diff} écart, seuil={threshold})"
            ),
            details={
                "proc_count": proc_count,
                "ss_count": ss_count,
                "difference": diff,
                "threshold_used": threshold,
                "hidden_remote_addresses": list(hidden_remotes)[:20],  # max 20 pour lisibilité
                "detection_method": "/proc/net/tcp vs ss -tnp"
            }
        ))

    return alerts

