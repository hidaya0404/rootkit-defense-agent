def calculate_risk_score(iocs, yara_matches, strings, file_info=None, elf_info=None):
    score = 0
    reasons = []

    if iocs.get("ips"):
        score += 15
        reasons.append("Adresse IP détectée dans l’artefact.")

    if iocs.get("urls") or iocs.get("domains"):
        score += 15
        reasons.append("Domaine ou URL détecté dans l’artefact.")

    sensitive_paths = [
        "/etc",
        "/usr/bin",
        "/bin",
        "/root",
        "/lib/modules",
        "/etc/cron",
        "/etc/systemd"
    ]

    for path in iocs.get("paths", []):
        if any(path.startswith(sp) for sp in sensitive_paths):
            score += 20
            reasons.append(f"Chemin sensible détecté : {path}")
            break

    if yara_matches and yara_matches not in [["YARA not available"], ["No YARA rule found"]]:
        score += 30
        reasons.append("Règle YARA déclenchée.")

    suspicious_keywords = [
        "rootkit",
        "insmod",
        "rmmod",
        "ld.so.preload",
        "hide_process",
        "persistence",
        "cron",
        "systemd",
        "reverse shell"
    ]

    text = "\n".join(strings).lower()

    for keyword in suspicious_keywords:
        if keyword in text:
            score += 5
            reasons.append(f"Mot-clé suspect détecté : {keyword}")

    if file_info:
        permissions = file_info.get("permissions", "")

        if "x" in permissions:
            score += 10
            reasons.append("Artefact exécutable.")

    if elf_info:
        if elf_info.get("is_elf"):
            score += 10
            reasons.append("Fichier ELF détecté.")

        if elf_info.get("symbols"):
            score += 5
            reasons.append("Symboles ELF extraits.")

    score = min(score, 100)

    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons
    }
