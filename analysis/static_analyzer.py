import hashlib
import os
import re
import subprocess
from pathlib import Path

try:
    import yara
except ImportError:
    yara = None


def calculate_hashes(file_path):
    hashes = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256()
    }

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            for h in hashes.values():
                h.update(chunk)

    return {name: h.hexdigest() for name, h in hashes.items()}


def get_file_type(file_path):
    try:
        result = subprocess.run(
            ["file", file_path],
            capture_output=True,
            text=True
        )
        return result.stdout.strip()
    except Exception as e:
        return f"file command error: {e}"


def extract_strings(file_path, min_length=4):
    data = Path(file_path).read_bytes()

    strings = re.findall(rb"[ -~]{%d,}" % min_length, data)

    decoded = []

    for s in strings[:100]:
        try:
            decoded.append(s.decode("utf-8", errors="ignore"))
        except Exception:
            pass

    return decoded


def extract_iocs(strings):
    iocs = {
        "ips": [],
        "domains": [],
        "paths": [],
        "urls": []
    }

    ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    url_regex = r"https?://[^\s\"']+"
    domain_regex = r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    path_regex = r"\/(?:[A-Za-z0-9._-]+\/?)+"

    text = "\n".join(strings)

    iocs["ips"] = list(set(re.findall(ip_regex, text)))
    iocs["urls"] = list(set(re.findall(url_regex, text)))
    iocs["domains"] = list(set(re.findall(domain_regex, text)))
    iocs["paths"] = list(set(re.findall(path_regex, text)))

    return iocs


def run_yara(file_path):
    if yara is None:
        return ["YARA not available"]

    rule_path = "analysis/yara_rules/suspicious_linux_artifact.yar"

    if not os.path.exists(rule_path):
        return ["No YARA rule found"]

    try:
        rules = yara.compile(filepath=rule_path)
        matches = rules.match(file_path)
        return [str(match) for match in matches]
    except Exception as e:
        return [f"YARA error: {e}"]


def calculate_risk_score(iocs, yara_matches, strings):
    score = 0

    if iocs["ips"]:
        score += 20

    if iocs["urls"] or iocs["domains"]:
        score += 20

    if iocs["paths"]:
        suspicious_paths = [
            p for p in iocs["paths"]
            if p.startswith(("/etc", "/usr/bin", "/bin", "/root"))
        ]

        if suspicious_paths:
            score += 20

    if yara_matches and yara_matches != ["YARA not available"] and yara_matches != ["No YARA rule found"]:
        score += 30

    suspicious_keywords = [
        "insmod",
        "rmmod",
        "ld.so.preload",
        "hide",
        "rootkit",
        "persistence",
        "cron",
        "systemd"
    ]

    text = "\n".join(strings).lower()

    for keyword in suspicious_keywords:
        if keyword in text:
            score += 5

    score = min(score, 100)

    if score >= 70:
        level = "CRITICAL"
    elif score >= 40:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level


def generate_recommendations(risk_level):
    if risk_level == "CRITICAL":
        return [
            "Conserver l’artefact en quarantaine.",
            "Ne pas exécuter l’artefact sur la machine hôte.",
            "Analyser dans une VM sandbox isolée.",
            "Vérifier les fichiers système sensibles.",
            "Contrôler les modules kernel chargés.",
            "Préparer une remédiation manuelle contrôlée."
        ]

    if risk_level == "HIGH":
        return [
            "Maintenir l’artefact en quarantaine.",
            "Vérifier les IOC extraits.",
            "Effectuer une analyse sandbox.",
            "Surveiller les connexions réseau associées."
        ]

    if risk_level == "MEDIUM":
        return [
            "Analyser les chaînes extraites.",
            "Comparer avec une base de référence saine.",
            "Surveiller l’évolution de l’alerte."
        ]

    return [
        "Conserver l’événement dans les logs.",
        "Aucune action destructive automatique recommandée."
    ]


def analyze_file(file_path):
    hashes = calculate_hashes(file_path)
    file_type = get_file_type(file_path)
    strings = extract_strings(file_path)
    iocs = extract_iocs(strings)
    yara_matches = run_yara(file_path)
    risk_score, risk_level = calculate_risk_score(iocs, yara_matches, strings)
    recommendations = generate_recommendations(risk_level)

    return {
        "file_path": file_path,
        "file_type": file_type,
        "size_bytes": os.path.getsize(file_path),
        "hashes": hashes,
        "strings_sample": strings[:30],
        "iocs": iocs,
        "yara_matches": yara_matches,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "recommendations": recommendations
    }
