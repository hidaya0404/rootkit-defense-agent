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
    VMRUN,
    VMX_PATH,
    VM_NAME,
    SNAPSHOT_NAME,
    SSH_HOST,
    SSH_PORT,
    SSH_USER,
    SSH_KEY_PATH,
    REMOTE_WORKDIR,
    BACKEND_URL,
    SANDBOX_RESULT_ENDPOINT,
    LOCAL_RESULTS_DIR,
)


# ============================================================
# Utils
# ============================================================

def run_cmd(command, check=True, log=True):
    if log:
        print("[CMD]", " ".join(str(x) for x in command))

    result = subprocess.run(
        command,
        text=True,
        capture_output=True,
        shell=False,
    )

    if log and result.stdout:
        print(result.stdout)

    if log and result.stderr:
        print(result.stderr)

    if check and result.returncode != 0:
        raise RuntimeError("Commande echouee : " + " ".join(str(x) for x in command))

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
        return path.read_text(encoding="utf-8", errors="replace")[:max_chars]
    except Exception:
        return ""


def get_result_file(local_result_path, filename):
    local_result_path = Path(local_result_path)

    direct = local_result_path / filename
    nested = local_result_path / "results" / filename

    if direct.exists():
        return direct

    return nested


# ============================================================
# Metadata M2
# ============================================================

def load_artifact_metadata(metadata_path):
    metadata_path = Path(metadata_path)

    if not metadata_path.exists():
        raise FileNotFoundError(f"Fichier metadata introuvable : {metadata_path}")

    with open(metadata_path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_artifact_for_sandbox(artifact_info):
    if not artifact_info:
        return True

    if artifact_info.get("status") != "READY_FOR_ANALYSIS":
        raise ValueError("Artefact refuse : status doit etre READY_FOR_ANALYSIS")

    if artifact_info.get("integrity_verified") is not True:
        raise ValueError("Artefact refuse : integrity_verified doit etre true")

    if artifact_info.get("ready_for_sandbox") is not True:
        raise ValueError("Artefact refuse : ready_for_sandbox doit etre true")

    return True


def download_artifact_from_backend(artifact_info):
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
    if local_artifact_path:
        path = Path(local_artifact_path).resolve()

        if not path.exists():
            raise FileNotFoundError(f"Artefact introuvable : {path}")

        return path

    if artifact_info:
        if artifact_info.get("download_url"):
            return download_artifact_from_backend(artifact_info)

        quarantine_path = artifact_info.get("quarantine_path")

        if quarantine_path:
            qpath = Path(quarantine_path)

            if qpath.exists():
                print(f"[+] Artefact recupere depuis quarantine_path : {qpath}")
                return qpath.resolve()

    default_path = Path("sandbox/sample_artifacts/benign_suspicious.sh").resolve()

    if not default_path.exists():
        raise FileNotFoundError(f"Artefact de test introuvable : {default_path}")

    print("[i] Aucun artefact M2 fourni, utilisation de l’artefact de test local.")

    return default_path


def verify_artifact_hash(local_artifact_path, artifact_info, calculated_sha256):
    if not artifact_info:
        return

    expected_sha256 = artifact_info.get("sha256")

    if not expected_sha256 or expected_sha256.strip() == "...":
        print("[i] SHA256 M2 absent ou non reel, verification ignoree en mode test.")
        return

    if calculated_sha256.lower() != expected_sha256.lower():
        raise ValueError("Hash SHA256 invalide : l’artefact analyse ne correspond pas au manifest M2")

    print("[+] Verification SHA256 reussie")


# ============================================================
# VMware + SSH/SCP
# ============================================================

def ssh_target():
    return f"{SSH_USER}@{SSH_HOST}"


def ssh_base_command():
    return [
        "ssh",
        "-i", SSH_KEY_PATH,
        "-p", str(SSH_PORT),
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=no",
        ssh_target(),
    ]


def scp_base_command():
    return [
        "scp",
        "-i", SSH_KEY_PATH,
        "-P", str(SSH_PORT),
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
    ]


def vmrun(args, check=True):
    return run_cmd([VMRUN] + args, check=check, log=True)


def restore_snapshot():
    print("[+] Restauration du snapshot VMware propre")

    vmrun(["stop", VMX_PATH, "hard"], check=False)
    time.sleep(3)

    vmrun(["revertToSnapshot", VMX_PATH, SNAPSHOT_NAME], check=True)
    time.sleep(3)


def start_vm():
    print("[+] Demarrage de la VM VMware sandbox")

    vmrun(["start", VMX_PATH, "nogui"], check=False)

    wait_for_ssh_ready()


def stop_vm():
    print("[+] Arret de la VM VMware sandbox")
    vmrun(["stop", VMX_PATH, "hard"], check=False)
    time.sleep(3)


def wait_for_ssh_ready(timeout_seconds=120, poll_interval=5):
    print("[+] Attente disponibilite SSH de la sandbox")

    deadline = time.time() + timeout_seconds
    last_error = ""

    while time.time() < deadline:
        result = run_cmd(
            ssh_base_command() + ["whoami && pwd"],
            check=False,
            log=False,
        )

        if result.returncode == 0:
            print("[+] SSH pret")
            print(result.stdout.strip())
            return

        last_error = (result.stderr or result.stdout or "").strip()
        time.sleep(poll_interval)

    raise RuntimeError(
        "SSH non disponible. Verifier IP, cle SSH, sshd et reseau Host-only. "
        f"Derniere erreur : {last_error or 'aucune information'}"
    )


def guest_run(command, check=True, log=True):
    return run_cmd(
        ssh_base_command() + [command],
        check=check,
        log=log,
    )


def guest_copy_to(local_path, remote_path):
    run_cmd(
        scp_base_command() + [
            str(local_path),
            f"{ssh_target()}:{remote_path}",
        ],
        check=True,
        log=True,
    )


def guest_copy_from(remote_path, local_path):
    local_path = Path(local_path)
    local_path.mkdir(parents=True, exist_ok=True)

    run_cmd(
        scp_base_command() + [
            "-r",
            f"{ssh_target()}:{remote_path}",
            str(local_path),
        ],
        check=True,
        log=True,
    )


def prepare_guest():
    print("[+] Preparation dossier sandbox dans la VM via SSH")

    guest_run(
        f"rm -rf {REMOTE_WORKDIR} && "
        f"mkdir -p {REMOTE_WORKDIR}/input {REMOTE_WORKDIR}/results && "
        f"chmod -R 755 {REMOTE_WORKDIR}"
    )


# ============================================================
# Analyse des logs
# ============================================================

def parse_file_paths(file_content):
    paths = set()

    for line in file_content.splitlines():
        line = line.strip()

        if not line:
            continue

        paths.add(line.split(" ")[0])

    return paths


def parse_new_lines(before_text, after_text, limit=50):
    before = set(line.strip() for line in before_text.splitlines() if line.strip())
    after = set(line.strip() for line in after_text.splitlines() if line.strip())

    return list(after - before)[:limit]


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

    processes = parse_new_lines(processes_before, processes_after)
    network_connections = parse_new_lines(network_before, network_after)

    return {
        "execution_success": exit_code == 0,
        "exit_code": exit_code,
        "stderr_empty": len(stderr_text.strip()) == 0,
        "files_created_or_modified": len(files_created_or_modified) > 0,
        "network_activity_observed": len(network_connections) > 0,
        "started_at": timestamp_start,
        "finished_at": timestamp_end,
        "processes": processes,
        "files_created": files_created_or_modified,
        "files_modified": files_created_or_modified,
        "network_connections": network_connections,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "strace_excerpt": strace_excerpt,
    }


def get_sandbox_status(exit_code, stderr_text="", artifact_name=""):
    if exit_code == 0:
        return "COMPLETED", None

    if exit_code == 124:
        return "TIMEOUT", "Analyse arretee par timeout"

    if "Exec format error" in stderr_text or artifact_name.endswith(".ko"):
        return (
            "COMPLETED",
            "Artefact non executable directement en user-space. "
            "Probable module kernel Linux (.ko). Analyse sandbox terminee avec observation."
        )

    return "FAILED", f"Analyse terminee avec exit_code={exit_code}"


# ============================================================
# Analyse sandbox
# ============================================================

def analyze_artifact(local_artifact_path=None, artifact_info=None, demo_fast=False):
    validate_artifact_for_sandbox(artifact_info)

    artifact_path = resolve_artifact_path(local_artifact_path, artifact_info)

    if not artifact_path.exists():
        raise FileNotFoundError(f"Artefact introuvable : {artifact_path}")

    artifact_hash = sha256_file(artifact_path)
    verify_artifact_hash(artifact_path, artifact_info, artifact_hash)

    analysis_id = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    local_result_path = Path(LOCAL_RESULTS_DIR).resolve() / analysis_id
    local_result_path.mkdir(parents=True, exist_ok=True)

    try:
        if demo_fast:
            print("[DEMO] Mode rapide : VM deja prete, pas de snapshot.")
            wait_for_ssh_ready(timeout_seconds=30)
        else:
            restore_snapshot()
            start_vm()

        prepare_guest()

        print("[+] Copie de l'artefact vers la VM")
        remote_artifact = f"{REMOTE_WORKDIR}/input/{artifact_path.name}"
        guest_copy_to(str(artifact_path), remote_artifact)

        print("[+] Copie du runner vers la VM")
        remote_runner = f"{REMOTE_WORKDIR}/guest_runner.sh"
        guest_copy_to(str(Path("sandbox/guest_runner.sh").resolve()), remote_runner)

        guest_run(f"chmod +x {remote_runner} {remote_artifact}")

        print("[+] Lancement analyse comportementale")
        guest_run(
            f"bash {remote_runner} {remote_artifact} {REMOTE_WORKDIR}/results",
            check=False,
        )

        print("[+] Recuperation des resultats")
        guest_copy_from(f"{REMOTE_WORKDIR}/results/.", str(local_result_path))

        behavior_summary = build_behavior_summary(local_result_path)
        sandbox_status, error_message = get_sandbox_status(
             behavior_summary["exit_code"],
             behavior_summary.get("stderr", ""),
             artifact_info.get("filename", artifact_path.name) if artifact_info else artifact_path.name,
      )

        result_json = {
            "analysis_id": analysis_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),

            "artifact_id": artifact_info.get("artifact_id") if artifact_info else None,
            "alert_id": artifact_info.get("alert_id") if artifact_info else None,
            "risk_level": artifact_info.get("risk_level") if artifact_info else None,
            "rootkit_category": artifact_info.get("rootkit_category") if artifact_info else None,

            "artifact_name": artifact_info.get("filename") if artifact_info else artifact_path.name,
            "artifact_sha256": artifact_hash,
            "artifact_md5": artifact_info.get("md5") if artifact_info else None,
            "artifact_sha1": artifact_info.get("sha1") if artifact_info else None,
            "quarantine_path": artifact_info.get("quarantine_path") if artifact_info else None,
            "download_url": artifact_info.get("download_url") if artifact_info else None,
            "metadata_path": artifact_info.get("metadata_path") if artifact_info else None,
            "manifest_path": artifact_info.get("manifest_path") if artifact_info else None,

            "status": "DONE",
            "sandbox_status": sandbox_status,
            "error_message": error_message,

            "sandbox_vm": VM_NAME,
            "snapshot_used": SNAPSHOT_NAME,
            "vm_name": VM_NAME,
            "snapshot_name": SNAPSHOT_NAME,

            "analysis_started_at": behavior_summary["started_at"],
            "analysis_finished_at": behavior_summary["finished_at"],

            "logs_path": str(local_result_path),
            "stdout_path": str(get_result_file(local_result_path, "stdout.log")),
            "stderr_path": str(get_result_file(local_result_path, "stderr.log")),
            "strace_path": str(get_result_file(local_result_path, "strace.log")),

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

            "observed_processes": behavior_summary["processes"],
            "file_events": {
                "created": behavior_summary["files_created"],
                "modified": behavior_summary["files_modified"],
            },
            "network_events": behavior_summary["network_connections"],

            "behavior_summary": behavior_summary,

            # Alias compatibles avec M4
            "sandbox_id": VM_NAME,
            "execution_status": sandbox_status,
            "processes_created": behavior_summary["processes"],
            "persistence_indicators": [],
            "risk_observations": [
               "Artefact identifié comme module kernel Linux (.ko), non exécutable directement en user-space."
            ] if (
               artifact_info and artifact_info.get("filename", "").endswith(".ko")
            ) or "Exec format error" in behavior_summary.get("stderr", "") else [],

            "local_result_path": str(local_result_path),
        }

        with open(local_result_path / "sandbox_result.json", "w", encoding="utf-8") as f:
            json.dump(result_json, f, indent=4, ensure_ascii=False)

        print("[+] Resultat JSON genere")
        print(json.dumps(result_json, indent=4, ensure_ascii=False))

        return result_json

    finally:
        if demo_fast:
            print("[DEMO] Mode rapide : VM laissee allumee.")
        else:
            stop_vm()
            restore_snapshot()


# ============================================================
# Backend M4
# ============================================================

def send_result_to_backend(result):
    url = BACKEND_URL.rstrip("/") + SANDBOX_RESULT_ENDPOINT
    print(f"[+] Envoi resultat vers backend : {url}")

    behavior = result.get("behavior_summary", {})
    is_kernel_module_observation = False

    if isinstance(behavior, dict):
        stderr_text = str(behavior.get("stderr", ""))
        artifact_name = str(result.get("artifact_name", ""))

        is_kernel_module_observation = (
            result.get("execution_status") == "COMPLETED"
            and (
                "Exec format error" in stderr_text
                or artifact_name.endswith(".ko")
            )
        )

        if is_kernel_module_observation:
            behavior_summary_text = (
                f"Sandbox analysis completed; "
                f"artifact_execution=not_applicable_user_space; "
                f"exit_code={behavior.get('exit_code')}; "
                f"artifact_type=kernel_module; "
                f"files_created={len(behavior.get('files_created', []))}; "
                f"files_modified={len(behavior.get('files_modified', []))}; "
                f"network_connections={len(behavior.get('network_connections', []))}; "
                f"observation=Linux kernel module not directly executable in user-space"
            )
        else:
            behavior_summary_text = (
                f"Execution success={behavior.get('execution_success')}; "
                f"exit_code={behavior.get('exit_code')}; "
                f"files_created={len(behavior.get('files_created', []))}; "
                f"files_modified={len(behavior.get('files_modified', []))}; "
                f"network_connections={len(behavior.get('network_connections', []))}; "
                f"stderr_empty={behavior.get('stderr_empty')}"
            )
    else:
        behavior_summary_text = str(behavior)

    risk_observations = result.get("risk_observations", [])

    if is_kernel_module_observation:
        observation = "Artefact identifié comme module kernel Linux (.ko), non exécutable directement en user-space."
        if observation not in risk_observations:
            risk_observations.append(observation)

    m4_payload = {
        "artifact_id": result.get("artifact_id"),
        "alert_id": result.get("alert_id"),
        "sandbox_id": result.get("sandbox_id"),
        "execution_status": result.get("execution_status"),
        "started_at": result.get("started_at"),
        "finished_at": result.get("finished_at"),

        "behavior_summary": behavior_summary_text,

        "processes_created": result.get("processes_created", []),
        "files_created": result.get("files_created", []),
        "files_modified": result.get("files_modified", []),
        "network_connections": result.get("network_connections", []),
        "persistence_indicators": result.get("persistence_indicators", []),
        "risk_observations": risk_observations,
    }

    print("[+] Payload envoye a M4 :")
    print(json.dumps(m4_payload, indent=4, ensure_ascii=False))

    try:
        response = requests.post(url, json=m4_payload, timeout=5)
        print(f"[+] Status backend : {response.status_code}")
        print(response.text)
    except Exception as e:
        print(f"[!] Backend indisponible ou endpoint non pret : {e}")


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Rootkit Defense Agent - Sandbox M3 VMware SSH"
    )

    parser.add_argument(
        "--artifact",
        help="Chemin local d'un artefact a analyser"
    )

    parser.add_argument(
        "--metadata",
        help="Chemin vers un fichier JSON metadata fourni par M2"
    )

    parser.add_argument(
        "--demo-fast",
        action="store_true",
        help="Mode demo rapide : VM deja allumee, pas de snapshot."
    )

    args = parser.parse_args()

    artifact_info = None

    if args.metadata:
        artifact_info = load_artifact_metadata(args.metadata)

    result = analyze_artifact(
        local_artifact_path=args.artifact,
        artifact_info=artifact_info,
        demo_fast=args.demo_fast,
    )

    send_result_to_backend(result)


if __name__ == "__main__":
    main()