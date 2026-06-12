import hashlib
import mimetypes
import os
import stat
import subprocess
import re
from pathlib import Path
from datetime import datetime

from analysis.ioc_extractor import extract_iocs
from analysis.scoring import calculate_risk_score
from analysis.ai_remediation_advisor import build_ai_recommendation, flatten_ai_recommendations

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


def get_file_metadata(file_path):
    st = os.stat(file_path)

    permissions = stat.filemode(st.st_mode)
    mimetype, _ = mimetypes.guess_type(file_path)

    return {
        "filename": os.path.basename(file_path),
        "path": file_path,
        "size_bytes": st.st_size,
        "permissions": permissions,
        "owner_uid": st.st_uid,
        "group_gid": st.st_gid,
        "created_at": datetime.utcfromtimestamp(st.st_ctime).isoformat() + "Z",
        "modified_at": datetime.utcfromtimestamp(st.st_mtime).isoformat() + "Z",
        "mimetype": mimetype or "unknown"
    }


def extract_strings(file_path, min_length=4):
    data = Path(file_path).read_bytes()
    strings = re.findall(rb"[ -~]{%d,}" % min_length, data)

    decoded = []

    for s in strings[:300]:
        decoded.append(s.decode("utf-8", errors="ignore"))

    return decoded


def analyze_elf(file_path):
    file_type = get_file_type(file_path)

    if "ELF" not in file_type:
        return {
            "is_elf": False,
            "sections": [],
            "symbols": [],
            "headers": []
        }

    elf_info = {
        "is_elf": True,
        "headers": [],
        "sections": [],
        "symbols": []
    }

    try:
        headers = subprocess.run(
            ["readelf", "-h", file_path],
            capture_output=True,
            text=True
        )
        elf_info["headers"] = headers.stdout.splitlines()[:50]
    except Exception as e:
        elf_info["headers"] = [f"readelf header error: {e}"]

    try:
        sections = subprocess.run(
            ["readelf", "-S", file_path],
            capture_output=True,
            text=True
        )
        elf_info["sections"] = sections.stdout.splitlines()[:80]
    except Exception as e:
        elf_info["sections"] = [f"readelf sections error: {e}"]

    try:
        symbols = subprocess.run(
            ["readelf", "-s", file_path],
            capture_output=True,
            text=True
        )
        elf_info["symbols"] = symbols.stdout.splitlines()[:80]
    except Exception as e:
        elf_info["symbols"] = [f"readelf symbols error: {e}"]

    return elf_info


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


def generate_recommendations(risk_level):
    if risk_level == "CRITICAL":
        return [
            "Maintenir l’artefact en quarantaine.",
            "Ne pas exécuter l’artefact sur la machine hôte.",
            "Envoyer l’artefact vers la sandbox M3.",
            "Vérifier les IOC réseau et les chemins sensibles.",
            "Contrôler les modules kernel et mécanismes de persistance.",
            "Effectuer une remédiation manuelle validée par l’administrateur."
        ]

    if risk_level == "HIGH":
        return [
            "Conserver l’artefact en quarantaine.",
            "Vérifier les IOC extraits.",
            "Effectuer une analyse complémentaire en sandbox.",
            "Surveiller les connexions réseau associées."
        ]

    if risk_level == "MEDIUM":
        return [
            "Conserver les logs.",
            "Comparer l’artefact avec une base de référence.",
            "Surveiller l’évolution de l’alerte."
        ]

    return [
        "Aucune action destructive recommandée.",
        "Conserver l’événement dans l’historique."
    ]


def build_timeline(artifact_id, alert_id, analysis_result):
    now = datetime.utcnow().isoformat() + "Z"

    return [
        {
            "time": now,
            "event": "Artefact reçu en quarantaine",
            "artifact_id": artifact_id,
            "alert_id": alert_id
        },
        {
            "time": now,
            "event": "Analyse statique exécutée",
            "details": "hash, strings, permissions, file type, YARA, IOC"
        },
        {
            "time": now,
            "event": "Score de risque attribué",
            "risk_score": analysis_result.get("risk_score"),
            "risk_level": analysis_result.get("risk_level")
        },
        {
            "time": now,
            "event": "Rapport généré",
            "details": "rapport HTML/PDF disponible"
        }
    ]


def analyze_file(file_path, artifact_id=None, alert_id=None):
    metadata = get_file_metadata(file_path)
    hashes = calculate_hashes(file_path)
    file_type = get_file_type(file_path)
    strings = extract_strings(file_path)
    elf_info = analyze_elf(file_path)
    iocs = extract_iocs(strings)
    yara_matches = run_yara(file_path)

    scoring = calculate_risk_score(
        iocs=iocs,
        yara_matches=yara_matches,
        strings=strings,
        file_info=metadata,
        elf_info=elf_info
    )

    result = {
        "file_path": file_path,
        "file_type": file_type,
        "metadata": metadata,
        "hashes": hashes,
        "strings_sample": strings[:50],
        "elf_analysis": elf_info,
        "iocs": iocs,
        "yara_matches": yara_matches,
        "risk_score": scoring["risk_score"],
        "risk_level": scoring["risk_level"],
        "risk_reasons": scoring["reasons"],
    }

    ai_recommendation = build_ai_recommendation(
        {
            "artifact_id": artifact_id,
            "alert_id": alert_id,
            "analysis": result,
        }
    )
    result["ai_recommendation"] = ai_recommendation
    result["recommendations"] = flatten_ai_recommendations(ai_recommendation)

    result["timeline"] = build_timeline(
        artifact_id=artifact_id,
        alert_id=alert_id,
        analysis_result=result
    )

    return result
