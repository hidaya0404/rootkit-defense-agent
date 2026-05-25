import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.monitor_processes import scan_processes, build_alert

def test_build_alert():
    alert = build_alert("test", "HIGH", "TEST", "desc", {})
    assert "alert_id" in alert
    assert alert["severity"] == "HIGH"
    assert alert["status"] == "NEW"
    print("✅ test_build_alert OK")

def test_scan_processes():
    alerts = scan_processes()
    assert isinstance(alerts, list)
    print(f"✅ test_scan_processes OK — {len(alerts)} alertes")

if __name__ == "__main__":
    test_build_alert()
    test_scan_processes()
    print("\n Tous les tests OK")
