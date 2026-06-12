import argparse
import json
import time
import hashlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin

import requests

from sandbox_config import (
    VM_NAME,
    SNAPSHOT_NAME,
    VBOXMANAGE,
    GUEST_USER,
    GUEST_PASSWORD,
    REMOTE_WORKDIR,
    BACKEND_URL,
    SANDBOX_RESULT_ENDPOINT,
    LOCAL_RESULTS_DIR,
)


# ============================================================
# Utilitaires généraux
# ============================================================

def _format_command(command):
    """
    Affiche une commande proprement sans exposer le mot de passe.
    """
    if isinstance(command, (list, tuple)):
        parts = []
        hide_next = False

        for part in command:
            part = str(part)

            if hide_next:
                parts.append("********")
                hide_next = False
                continue

            if part == "--password":
                parts.append(part)
                hide_next = True
                continue

            if any(ch.isspace() for ch in part):
                parts.append(f'"{part}"')
            else:
                parts.append(part)

        return " ".join(parts)

    return str(command).replace(GUEST_PASSWORD, "********")


def run_cmd(command, check=True, log=True):
    if log:
        print(f"[CMD] {_format_command(command)}")

    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        text=True,
        capture_output=True,
    )

    if log and result.stdout:
        print(result.stdout)

    if log and result.stderr:
        print(result.stderr)

    if check and result.returncode != 0:
        raise RuntimeError(f"Commande echouee : {_format_command(command)}")

    return result


def sha256_file(path):
    h = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)

    return h.hexdigest()


def read_text_file(path, max_chars=5000):
    path = Path(path)

    if not path.exists():
        return ""

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        return text[:max_chars]
    except Exception:
        return ""


def get_result_file(local_result_path, filename):
    """
    Selon VBoxManage copyfrom, les fichiers peuvent être copiés directement
    dans analysis_xxx/ ou dans analysis_xxx/results/.
    Cette fonction cherche dans les deux emplacements.
    """
    local_result_path = Path(local_result_path)

    direct = local_result_path / filename
    nested = local_result_path / "results" / filename

    if direct.exists():
        return direct

    return nested


# ============================================================
# Validation du format M2
# ============================================================

def validate_artifact_for_sandbox(artifact_info):
    """
    Vérifie que l’artefact venant de M2 est prêt pour la sandbox.
    Si artifact_info est vide, on considère qu'on est en mode test local.
    """
    if not artifact_info:
        return True

    status_ok = artifact_info.get("status") == "READY_FOR_ANALYSIS"
    integrity_ok = artifact_info.get("integrity_verified") is True
    sandbox_ok = artifact_info.get("ready_for_sandbox") is True

    if not status_ok:
        raise ValueError("Artefact refuse : status doit etre READY_FOR_ANALYSIS")

    if not integrity_ok:
        raise ValueError("Artefact refuse : integrity_verified doit etre true")

    if not sandbox_ok:
        raise ValueError("Artefact refuse : ready_for_sandbox doit etre true")

    return True


def load_artifact_metadata(metadata_path):
    metadata_path = Path(metadata_path)

    if not metadata_path.exists():
        raise FileNotFoundError(f"Fichier metadata introuvable : {metadata_path}")

    with open(metadata_path, "r", encoding="utf-8") as f:
        return json.load(f)


def download_artifact_from_backend(artifact_info):
    """
    Télécharge l’artefact depuis download_url via le backend M4.
    Exemple :
    download_url = /api/quarantine/artifact_001/download
    BACKEND_URL = https://accommodations-requiring-henry-workshops.trycloudflare.com
    """
    download_url = artifact_info.get("download_url")

    if not download_url:
        raise ValueError("download_url absent dans artifact_info")

    if download_url.startswith("http://") or download_url.startswith("https://"):
        url = download_url
    else:
        url = urljoin(BACKEND_URL.rstrip("/") + "/", download_url.lstrip("/"))

    artifact_id = artifact_info.get("artifact_id", "artifact")
    filename = artifact_info.get("filename", "artifact.bin")

    download_dir = Path(LOCAL_RESULTS_DIR).resolve() / "downloaded_artifacts"
    download_dir.mkdir(parents=True, exist_ok=True)

    local_path = download_dir / f"{artifact_id}_{filename}"

    print(f"[+] Telechargement artefact depuis backend : {url}")

    response = requests.get(url, timeout=30)
    response.raise_for_status()

    with open(local_path, "wb") as f:
        f.write(response.content)

    print(f"[+] Artefact telecharge : {local_path}")
    return local_path


def resolve_artifact_path(local_artifact_path=None, artifact_info=None):
    """
    Priorité :
    1. chemin local donné manuellement
    2. quarantine_path si accessible localement
    3. download_url via backend
    4. artefact de test local
    """
    if local_artifact_path:
        path = Path(local_artifact_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Artefact introuvable : {path}")
        return path

    if artifact_info:
        quarantine_path = artifact_info.get("quarantine_path")

        if quarantine_path:
            qpath = Path(quarantine_path)

            if qpath.exists():
                print(f"[+] Artefact recupere depuis quarantine_path : {qpath}")
                return qpath.resolve()

        if artifact_info.get("download_url"):
            return download_artifact_from_backend(artifact_info)

    default_path = Path("sandbox/sample_artifacts/benign_suspicious.sh").resolve()

    if not default_path.exists():
        raise FileNotFoundError(f"Artefact de test introuvable : {default_path}")

    print("[i] Aucun artefact M2 fourni, utilisation de l’artefact de test local.")
    return default_path


def verify_artifact_hash(local_artifact_path, artifact_info, calculated_sha256):
    """
    Si M2 fournit un sha256 réel, on le compare au hash local.
    Si le champ est vide ou contient "...", on ignore la comparaison.
    """
    if not artifact_info:
        return

    expected_sha256 = artifact_info.get("sha256")

    if not expected_sha256 or expected_sha256.strip() == "...":
        return

    if calculated_sha256.lower() != expected_sha256.lower():
        raise ValueError(
            "Hash SHA256 invalide : l’artefact local ne correspond pas au hash M2"
        )


# ============================================================
# Gestion VirtualBox
# ============================================================

def restore_snapshot():
    print("[+] Restauration du snapshot propre")
    run_cmd(f'"{VBOXMANAGE}" controlvm "{VM_NAME}" poweroff', check=False)
    time.sleep(3)
    run_cmd(f'"{VBOXMANAGE}" snapshot "{VM_NAME}" restore "{SNAPSHOT_NAME}"')


def guest_run(command, check=True, timeout_ms=120000, log=True):
    return run_cmd(
        [
            VBOXMANAGE,
            "guestcontrol",
            VM_NAME,
            "run",
            "--username",
            GUEST_USER,
            "--password",
            GUEST_PASSWORD,
            "--exe",
            "/bin/bash",
            "--wait-stdout",
            "--wait-stderr",
            "--timeout",
            str(timeout_ms),
            "--",
            "-lc",
            command,
        ],
        check=check,
        log=log,
    )


def guest_copy_to(local_path, remote_path):
    run_cmd(
        [
            VBOXMANAGE,
            "guestcontrol",
            VM_NAME,
            "copyto",
            "--username",
            GUEST_USER,
            "--password",
            GUEST_PASSWORD,
            "--target-directory",
            remote_path,
            str(local_path),
        ]
    )


def guest_copy_from(remote_path, local_path):
    run_cmd(
        [
            VBOXMANAGE,
            "guestcontrol",
            VM_NAME,
            "copyfrom",
            "--recursive",
            "--username",
            GUEST_USER,
            "--password",
            GUEST_PASSWORD,
            "--target-directory",
            str(local_path),
            remote_path,
        ]
    )


def wait_for_guest_ready(timeout_seconds=240, poll_interval=5):
    print("[+] Attente disponibilite du guest")
    deadline = time.time() + timeout_seconds

    while time.time() < deadline:
        result = guest_run("true", check=False, timeout_ms=15000, log=False)

        if result.returncode == 0:
            return

        time.sleep(poll_interval)

    raise RuntimeError(
        "Le guest n'a pas ete pret a temps. "
        "Verifier Guest Additions, utilisateur invite et mot de passe."
    )


def start_vm():
    print("[+] Demarrage de la VM sandbox")
    run_cmd(f'"{VBOXMANAGE}" startvm "{VM_NAME}" --type headless')
    wait_for_guest_ready()


def stop_vm():
    print("[+] Arret de la VM sandbox")
    run_cmd(f'"{VBOXMANAGE}" controlvm "{VM_NAME}" poweroff', check=False)
    time.sleep(5)


def prepare_guest():
    print("[+] Preparation dossier sandbox dans la VM")
    guest_run(
        f"rm -rf {REMOTE_WORKDIR} && "
        f"mkdir -p {REMOTE_WORKDIR}/input {REMOTE_WORKDIR}/results"
    )


# ============================================================
# Résumé comportemental
# ============================================================

def parse_file_paths(file_content):
    paths = set()

    for line in file_content.splitlines():
        line = line.strip()
        if not line:
            continue

        # Le premier champ est le chemin du fichier.
        paths.add(line.split(" ")[0])

    return paths


def parse_new_lines(before_text, after_text, limit=50):
    before = set(line.strip() for line in before_text.splitlines() if line.strip())
    after = set(line.strip() for line in after_text.splitlines() if line.strip())

    new_items = list(after - before)
    return new_items[:limit]


def build_behavior_summary(local_result_path):
    processes_before = read_text_file(get_result_file(local_result_path, "processes_before.txt"))
    processes_after = read_text_file(get_result_file(local_result_path, "processes_after.txt"))

    network_before = read_text_file(get_result_file(local_result_path, "network_before.txt"))
    network_after = read_text_file(get_result_file(local_result_path, "network_after.txt"))

    files_before_text = read_text_file(get_result_file(local_result_path, "files_tmp_before.txt"))
    files_after_text = read_text_file(get_result_file(local_result_path, "files_tmp_after.txt"))

    stdout_text = read_text_file(get_result_file(local_result_path, "stdout.log"))
    stderr_text = read_text_file(get_result_file(local_result_path, "stderr.log"))
    strace_excerpt = read_text_file(get_result_file(local_result_path, "strace.log"), max_chars=5000)

    exit_code_text = read_text_file(get_result_file(local_result_path, "exit_code.txt")).strip()
    timestamp_start = read_text_file(get_result_file(local_result_path, "timestamp_start.txt")).strip()
    timestamp_end = read_text_file(get_result_file(local_result_path, "timestamp_end.txt")).strip()

    try:
        exit_code = int(exit_code_text)
    except Exception:
        exit_code = None

    files_before = parse_file_paths(files_before_text)
    files_after = parse_file_paths(files_after_text)

    files_created_or_modified = sorted(list(files_after - files_before))

    return {
        "execution_success": exit_code == 0,
        "exit_code": exit_code,
        "stderr_empty": len(stderr_text.strip()) == 0,
        "files_created_or_modified": len(files_created_or_modified) > 0,
        "network_activity_observed": len(parse_new_lines(network_before, network_after)) > 0,
        "started_at": timestamp_start,
        "finished_at": timestamp_end,
        "processes": parse_new_lines(processes_before, processes_after),
        "files_created": files_created_or_modified,
        "files_modified": files_created_or_modified,
        "network_connections": parse_new_lines(network_before, network_after),
        "stdout": stdout_text,
        "stderr": stderr_text,
        "strace_excerpt": strace_excerpt,
    }


# ============================================================
# Analyse sandbox
# ============================================================

def analyze_artifact(local_artifact_path=None, artifact_info=None):
    validate_artifact_for_sandbox(artifact_info)

    artifact_path = resolve_artifact_path(local_artifact_path, artifact_info)

    if not artifact_path.exists():
        raise FileNotFoundError(f"Artefact introuvable : {artifact_path}")

    analysis_id = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    local_result_path = Path(LOCAL_RESULTS_DIR).resolve() / analysis_id
    local_result_path.mkdir(parents=True, exist_ok=True)

    artifact_hash = sha256_file(artifact_path)
    verify_artifact_hash(artifact_path, artifact_info, artifact_hash)

    if artifact_path.suffix.lower() == ".ko":
        print(
            "[!] Artefact .ko detecte. "
            "Le module ne sera pas charge automatiquement dans le kernel. "
            "Analyse controlee uniquement."
        )

    try:
        restore_snapshot()
        start_vm()
        prepare_guest()

        print("[+] Copie de l'artefact vers la VM")
        remote_artifact = f"{REMOTE_WORKDIR}/input/{artifact_path.name}"
        guest_copy_to(str(artifact_path), remote_artifact)

        print("[+] Copie du runner vers la VM")
        guest_copy_to(
            str(Path("sandbox/guest_runner.sh").resolve()),
            f"{REMOTE_WORKDIR}/guest_runner.sh",
        )

        guest_run(f"chmod +x {REMOTE_WORKDIR}/guest_runner.sh")

        print("[+] Lancement analyse comportementale")
        guest_run(
            f"bash {REMOTE_WORKDIR}/guest_runner.sh "
            f"{remote_artifact} {REMOTE_WORKDIR}/results",
            check=False,
        )

        print("[+] Recuperation des resultats")
        guest_copy_from(f"{REMOTE_WORKDIR}/results", str(local_result_path))

        behavior_summary = build_behavior_summary(local_result_path)

        result_json = {
            "analysis_id": analysis_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),

            # Champs venant de M2 si disponibles
            "artifact_id": artifact_info.get("artifact_id") if artifact_info else None,
            "alert_id": artifact_info.get("alert_id") if artifact_info else None,
            "risk_level": artifact_info.get("risk_level") if artifact_info else None,
            "rootkit_category": artifact_info.get("rootkit_category") if artifact_info else None,

            # Informations artefact
            "artifact_name": artifact_info.get("filename") if artifact_info else artifact_path.name,
            "artifact_sha256": artifact_hash,
            "artifact_md5": artifact_info.get("md5") if artifact_info else None,
            "artifact_sha1": artifact_info.get("sha1") if artifact_info else None,
            "quarantine_path": artifact_info.get("quarantine_path") if artifact_info else None,
            "metadata_path": artifact_info.get("metadata_path") if artifact_info else None,
            "manifest_path": artifact_info.get("manifest_path") if artifact_info else None,

            # Informations sandbox
            "sandbox_vm": VM_NAME,
            "snapshot_used": SNAPSHOT_NAME,
            "status": "DONE",
            "sandbox_status": "COMPLETED",

            # Logs générés
            "behavior_logs": {
                "processes_before": "processes_before.txt",
                "processes_after": "processes_after.txt",
                "network_before": "network_before.txt",
                "network_after": "network_after.txt",
                "files_tmp_before": "files_tmp_before.txt",
                "files_tmp_after": "files_tmp_after.txt",
                "strace": "strace.log",
                "stdout": "stdout.log",
                "stderr": "stderr.log",
                "exit_code": "exit_code.txt",
                "timestamp_start": "timestamp_start.txt",
                "timestamp_end": "timestamp_end.txt",
            },

            # Format simple demandé par M2/M4
            "processes": behavior_summary["processes"],
            "files_created": behavior_summary["files_created"],
            "files_modified": behavior_summary["files_modified"],
            "network_connections": behavior_summary["network_connections"],
            "stdout": behavior_summary["stdout"],
            "stderr": behavior_summary["stderr"],
            "strace_log": "strace.log",
            "strace_excerpt": behavior_summary["strace_excerpt"],
            "exit_code": behavior_summary["exit_code"],
            "started_at": behavior_summary["started_at"],
            "finished_at": behavior_summary["finished_at"],

            # Résumé lisible
            "behavior_summary": behavior_summary,

            # Chemin local
            "local_result_path": str(local_result_path),
        }

        with open(local_result_path / "sandbox_result.json", "w", encoding="utf-8") as f:
            json.dump(result_json, f, indent=4, ensure_ascii=False)

        print("[+] Resultat JSON genere")
        print(json.dumps(result_json, indent=4, ensure_ascii=False))

        return result_json

    finally:
        stop_vm()
        restore_snapshot()


# ============================================================
# Backend M4
# ============================================================

def send_result_to_backend(result):
    url = BACKEND_URL.rstrip("/") + SANDBOX_RESULT_ENDPOINT
    print(f"[+] Envoi resultat vers backend : {url}")

    try:
        response = requests.post(url, json=result, timeout=10)
        print(f"[+] Status backend : {response.status_code}")
        print(response.text)
    except Exception as e:
        print(f"[!] Backend indisponible ou endpoint non pret : {e}")


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Rootkit Defense Agent - Sandbox Membre 3")

    parser.add_argument(
        "--artifact",
        help="Chemin local d'un artefact a analyser"
    )

    parser.add_argument(
        "--metadata",
        help="Chemin vers un fichier JSON metadata fourni par M2"
    )

    args = parser.parse_args()

    artifact_info = None

    if args.metadata:
        artifact_info = load_artifact_metadata(args.metadata)

    result = analyze_artifact(
        local_artifact_path=args.artifact,
        artifact_info=artifact_info,
    )

    send_result_to_backend(result)


if __name__ == "__main__":
    main()
