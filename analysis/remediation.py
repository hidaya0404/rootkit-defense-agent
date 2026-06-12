from datetime import datetime
import uuid

from analysis.ai_remediation_advisor import build_ai_recommendation


def build_remediation_plan(artifact):
    analysis = artifact.get("analysis", {})
    risk_level = analysis.get("risk_level", "UNKNOWN")
    iocs = analysis.get("iocs", {})
    yara_matches = analysis.get("yara_matches", [])
    ai_recommendation = build_ai_recommendation(artifact)

    actions = []

    actions.append({
        "step": 1,
        "title": "Préservation des preuves",
        "action": "Conserver l’artefact dans la zone de quarantaine.",
        "command": "Aucune suppression automatique.",
        "status": "RECOMMENDED"
    })

    actions.append({
        "step": 2,
        "title": "Vérification des hash",
        "action": "Conserver les empreintes MD5, SHA1 et SHA256 dans le rapport.",
        "command": "Comparer les hash avec une base de réputation si disponible.",
        "status": "RECOMMENDED"
    })

    if yara_matches:
        actions.append({
            "step": 3,
            "title": "Investigation YARA",
            "action": "Examiner les règles YARA déclenchées.",
            "command": "yara analysis/yara_rules/suspicious_linux_artifact.yar <artefact>",
            "status": "RECOMMENDED"
        })

    if iocs.get("ips") or iocs.get("domains") or iocs.get("urls"):
        actions.append({
            "step": 4,
            "title": "Contrôle réseau",
            "action": "Vérifier les connexions sortantes liées aux IOC détectés.",
            "command": "ss -tunap ; journalctl --since '1 hour ago'",
            "status": "RECOMMENDED"
        })

    if iocs.get("paths"):
        actions.append({
            "step": 5,
            "title": "Contrôle des chemins sensibles",
            "action": "Vérifier si les chemins détectés ont été modifiés sur la machine surveillée.",
            "command": "ls -la /etc /usr/bin /bin /root 2>/dev/null",
            "status": "RECOMMENDED"
        })

    if risk_level in ["HIGH", "CRITICAL"]:
        actions.append({
            "step": 6,
            "title": "Analyse sandbox",
            "action": "Envoyer l’artefact vers la VM sandbox de M3 pour analyse comportementale.",
            "command": "GET /api/quarantine puis analyse dans VM isolée",
            "status": "RECOMMENDED"
        })

        actions.append({
            "step": 7,
            "title": "Durcissement système",
            "action": "Vérifier les mécanismes de persistance possibles.",
            "command": "systemctl list-unit-files ; crontab -l ; ls -la /etc/cron*",
            "status": "RECOMMENDED"
        })

    actions.append({
        "step": 8,
        "title": "Rapport final",
        "action": "Inclure les IOC, le score de risque et les recommandations dans le rapport.",
        "command": "GET /api/reports",
        "status": "RECOMMENDED"
    })

    step = len(actions) + 1
    for action in ai_recommendation.get("recommended_actions", [])[:8]:
        actions.append({
            "step": step,
            "title": "AI remediation advisor",
            "action": action,
            "command": "Validation humaine obligatoire avant action destructive.",
            "status": "AI_RECOMMENDED"
        })
        step += 1

    return {
        "remediation_id": str(uuid.uuid4()),
        "artifact_id": artifact.get("artifact_id"),
        "alert_id": artifact.get("alert_id"),
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "risk_level": risk_level,
        "risk_score": analysis.get("risk_score"),
        "decision": ai_recommendation.get("decision") or get_decision(risk_level),
        "ai_recommendation": ai_recommendation,
        "automatic_deletion": False,
        "requires_human_validation": True,
        "actions": actions
    }


def get_decision(risk_level):
    if risk_level == "CRITICAL":
        return "Maintenir en quarantaine, analyser en sandbox, vérifier les IOC et préparer une remédiation manuelle contrôlée."
    if risk_level == "HIGH":
        return "Maintenir en quarantaine, vérifier les IOC et demander une analyse complémentaire."
    if risk_level == "MEDIUM":
        return "Surveiller l’artefact, conserver les logs et comparer avec une base de référence."
    if risk_level == "LOW":
        return "Conserver dans les logs et surveiller sans action destructive."
    return "Analyse insuffisante, validation humaine nécessaire."
