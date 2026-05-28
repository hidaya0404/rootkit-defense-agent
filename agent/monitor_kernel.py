import os
from agent.monitor_processes import build_alert

BASELINE_FILE = "shared/kernel_modules_baseline.txt"

def get_loaded_modules():
    modules = {}
    with open('/proc/modules', 'r') as f:
        for line in f:
            parts = line.split()
            modules[parts[0]] = parts[1]
    return modules

def save_baseline():
    modules = get_loaded_modules()
    with open(BASELINE_FILE, 'w') as f:
        for name in modules:
            f.write(name + "\n")
    print(f"[BASELINE] {len(modules)} modules sauvegardés")

def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        save_baseline()
        return set()
    with open(BASELINE_FILE, 'r') as f:
        return set(line.strip() for line in f)

def scan_kernel_modules():
    alerts = []
    baseline = load_baseline()
    current = set(get_loaded_modules().keys())
    new_modules = current - baseline

    for mod in new_modules:
        alerts.append(build_alert(
            module="kernel_monitor",
            severity="HIGH",
            alert_type="UNKNOWN_KERNEL_MODULE",
            description=f"Module kernel inconnu détecté : {mod}",
            details={"module_name": mod}
        ))

    return alerts
