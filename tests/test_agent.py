import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.monitor_processes import scan_processes, build_alert
from agent.monitor_kernel import scan_kernel_modules
from agent.monitor_files import scan_suspicious_executables, scan_file_integrity

def test_build_alert():
    alert = build_alert("test", "HIGH", "TEST", "desc", {})
    assert "alert_id" in alert
    assert alert["severity"] == "HIGH"
    assert alert["status"] == "NEW"

def test_scan_processes():
    alerts = scan_processes()
    assert isinstance(alerts, list)

def test_scan_kernel():
    alerts = scan_kernel_modules()
    assert isinstance(alerts, list)

def test_scan_files():
    alerts = scan_suspicious_executables()
    assert isinstance(alerts, list)

def test_scan_integrity():
    alerts = scan_file_integrity()
    assert isinstance(alerts, list)

from agent.monitor_network import scan_network

def test_scan_network():
    alerts = scan_network()
    assert isinstance(alerts, list)
