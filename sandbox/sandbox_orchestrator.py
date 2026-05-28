import json
import time
import hashlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path

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


def _format_command(command):
    if isinstance(command, (list, tuple)):
        parts = []
        for part in command:
            part = str(part)
            if any(ch.isspace() for ch in part):
                parts.append(f'"{part}"')
            else:
                parts.append(part)
        return " ".join(parts)
    return command


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
            local_path,
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
            local_path,
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
        "Guest Additions ou services invites indisponibles."
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


def analyze_artifact(local_artifact_path):
    artifact_path = Path(local_artifact_path).resolve()

    if not artifact_path.exists():
        raise FileNotFoundError(f"Artefact introuvable : {artifact_path}")

    analysis_id = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    local_result_path = Path(LOCAL_RESULTS_DIR).resolve() / analysis_id
    local_result_path.mkdir(parents=True, exist_ok=True)

    artifact_hash = sha256_file(artifact_path)

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

        result_json = {
            "analysis_id": analysis_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "artifact_name": artifact_path.name,
            "artifact_sha256": artifact_hash,
            "sandbox_vm": VM_NAME,
            "snapshot_used": SNAPSHOT_NAME,
            "status": "DONE",
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
            },
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


def send_result_to_backend(result):
    url = BACKEND_URL + SANDBOX_RESULT_ENDPOINT
    print(f"[+] Envoi resultat vers backend : {url}")

    try:
        response = requests.post(url, json=result, timeout=10)
        print(f"[+] Status backend : {response.status_code}")
        print(response.text)
    except Exception as e:
        print(f"[!] Backend indisponible ou endpoint non pret : {e}")


def main():
    local_artifact = "sandbox/sample_artifacts/benign_suspicious.sh"

    result = analyze_artifact(local_artifact)
    send_result_to_backend(result)


if __name__ == "__main__":
    main()
