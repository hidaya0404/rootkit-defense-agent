import os
from analysis.static_analyzer import analyze_file
from analysis.ioc_extractor import extract_iocs
from analysis.scoring import calculate_risk_score


def test_ioc_extraction():
    strings = [
        "connect to 192.168.1.10",
        "http://malicious.example.com/payload",
        "/etc/ld.so.preload",
        "fake.service"
    ]

    iocs = extract_iocs(strings)

    assert "192.168.1.10" in iocs["ips"]
    assert "/etc/ld.so.preload" in iocs["paths"]
    assert "fake.service" in iocs["services"]


def test_scoring_high_or_critical():
    iocs = {
        "ips": ["192.168.1.10"],
        "urls": [],
        "domains": [],
        "paths": ["/etc/ld.so.preload"],
        "services": [],
        "suspicious_files": []
    }

    yara_matches = ["Suspicious_Linux_Rootkit_Indicators"]
    strings = ["rootkit insmod /etc/ld.so.preload"]

    result = calculate_risk_score(iocs, yara_matches, strings)

    assert result["risk_score"] >= 50
    assert result["risk_level"] in ["HIGH", "CRITICAL"]


def test_static_analyzer(tmp_path):
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("rootkit insmod /etc/ld.so.preload 10.10.10.10")

    result = analyze_file(str(artifact), artifact_id="test-artifact", alert_id="test-alert")

    assert "hashes" in result
    assert "iocs" in result
    assert "risk_score" in result
    assert "risk_level" in result
    assert "timeline" in result
