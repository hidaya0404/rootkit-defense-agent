import os

from agent.monitor_processes import build_alert
from shared.config import CONFIG


BASELINE_FILE = os.path.join(CONFIG["baseline_dir"], "kernel_modules_baseline.txt")


def get_loaded_modules():
    modules = {}
    with open("/proc/modules", "r", encoding="utf-8") as handle:
        for line in handle:
            parts = line.split()
            modules[parts[0]] = parts[1]
    return modules


def save_baseline():
    os.makedirs(os.path.dirname(BASELINE_FILE) or ".", exist_ok=True)
    modules = get_loaded_modules()
    with open(BASELINE_FILE, "w", encoding="utf-8") as handle:
        for name in modules:
            handle.write(name + "\n")
    print(f"[BASELINE] {len(modules)} modules saved")


def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        save_baseline()
        return set()
    with open(BASELINE_FILE, "r", encoding="utf-8") as handle:
        return {line.strip() for line in handle if line.strip()}


def scan_kernel_modules():
    alerts = []
    baseline = load_baseline()
    current = set(get_loaded_modules().keys())
    new_modules = current - baseline

    for mod in new_modules:
        alerts.append(
            build_alert(
                module="kernel_monitor",
                severity="HIGH",
                alert_type="UNKNOWN_KERNEL_MODULE",
                description=f"Module kernel inconnu detecte : {mod}",
                details={"module_name": mod},
            )
        )

    return alerts
