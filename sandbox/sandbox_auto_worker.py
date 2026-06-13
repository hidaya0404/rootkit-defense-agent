import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urljoin

import requests

try:
    from sandbox_config import BACKEND_URL as CONFIG_BACKEND_URL
except ImportError:
    CONFIG_BACKEND_URL = "https://sheet-different-operation-mature.trycloudflare.com"


READY_ENDPOINT = "/api/quarantine/ready"
PROCESSED_FILE = Path("sandbox/processed_artifacts.json")
DOWNLOAD_DIR = Path("sandbox/downloaded_artifacts")
METADATA_DIR = Path("sandbox/auto_metadata")
DEFAULT_BACKEND_URL = os.getenv("ROOTKIT_DEFENSE_M4_URL", CONFIG_BACKEND_URL).rstrip("/")


def load_processed():
    if PROCESSED_FILE.exists():
        return set(json.loads(PROCESSED_FILE.read_text(encoding="utf-8")))
    return set()


def save_processed(processed):
    PROCESSED_FILE.parent.mkdir(parents=True, exist_ok=True)
    PROCESSED_FILE.write_text(
        json.dumps(sorted(processed), indent=4, ensure_ascii=False),
        encoding="utf-8"
    )


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def get_ready_artifacts(backend_url):
    url = backend_url.rstrip("/") + READY_ENDPOINT
    print(f"[+] Verification artefacts prets : {url}")

    response = requests.get(url, timeout=10)
    response.raise_for_status()

    data = response.json()
    return data.get("artifacts", [])


def download_artifact(artifact, backend_url):
    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

    artifact_id = artifact["artifact_id"]
    download_url = artifact["download_url"]

    url = download_url if download_url.startswith(("http://", "https://")) else urljoin(
        backend_url.rstrip("/") + "/",
        download_url.lstrip("/")
    )
    local_path = DOWNLOAD_DIR / f"{artifact_id}.bin"

    print(f"[+] Telechargement artefact : {artifact_id}")
    print(f"[+] URL : {url}")

    response = requests.get(url, timeout=30)
    response.raise_for_status()

    local_path.write_bytes(response.content)

    expected_sha256 = artifact.get("sha256")
    actual_sha256 = sha256_file(local_path)

    if expected_sha256 and actual_sha256.lower() != expected_sha256.lower():
        raise ValueError(
            f"SHA256 invalide pour {artifact_id}: "
            f"attendu={expected_sha256}, obtenu={actual_sha256}"
        )

    print("[+] SHA256 artefact telecharge valide")
    return local_path


def create_metadata_file(artifact):
    METADATA_DIR.mkdir(parents=True, exist_ok=True)

    artifact_id = artifact["artifact_id"]
    metadata_path = METADATA_DIR / f"{artifact_id}.json"

    metadata = {
        "artifact_id": artifact.get("artifact_id"),
        "alert_id": artifact.get("alert_id"),
        "filename": artifact.get("filename"),
        "sha256": artifact.get("sha256"),
        "download_url": artifact.get("download_url"),
        "status": artifact.get("status"),
        "integrity_verified": artifact.get("integrity_verified"),
        "ready_for_sandbox": artifact.get("ready_for_sandbox"),
        "quarantine_path": artifact.get("quarantine_path"),
        "metadata_path": artifact.get("metadata_path"),
        "hashes_path": artifact.get("hashes_path"),
        "manifest_path": artifact.get("manifest_path"),
    }

    metadata_path.write_text(
        json.dumps(metadata, indent=4, ensure_ascii=False),
        encoding="utf-8"
    )

    return metadata_path


def remote_result_exists(artifact_id, backend_url):
    url = backend_url.rstrip("/") + f"/api/sandbox/results/{artifact_id}"
    try:
        response = requests.get(url, timeout=8)
        if response.status_code == 404:
            return False
        response.raise_for_status()
        data = response.json()
    except Exception:
        return False

    if isinstance(data, dict):
        result = data.get("result") or data.get("sandbox_result") or data
        return bool(result and not result.get("error"))
    return bool(data)


def run_vmware_orchestrator(metadata_path, artifact_path, backend_url):
    cmd = [
        sys.executable,
        "sandbox/sandbox_orchestrator_vmware.py",
        "--metadata",
        str(metadata_path),
        "--artifact",
        str(artifact_path),
    ]

    print("[+] Lancement automatique analyse VMware")
    print("[CMD]", " ".join(cmd))

    env = os.environ.copy()
    env["ROOTKIT_DEFENSE_M4_URL"] = backend_url.rstrip("/")

    result = subprocess.run(cmd, env=env)
    return result.returncode


def process_once(backend_url):
    processed = load_processed()
    artifacts = get_ready_artifacts(backend_url)

    print(f"[+] Nombre artefacts prets : {len(artifacts)}")

    for artifact in artifacts:
        artifact_id = artifact.get("artifact_id")

        if not artifact_id:
            continue

        if artifact_id in processed:
            if remote_result_exists(artifact_id, backend_url):
                print(f"[-] Deja traite et confirme M4 : {artifact_id}")
                continue
            print(f"[!] {artifact_id} marque traite localement, mais absent de M4 : relance analyse")

        if not artifact.get("ready_for_sandbox"):
            print(f"[-] Non pret sandbox : {artifact_id}")
            continue

        try:
            artifact_path = download_artifact(artifact, backend_url)
            metadata_path = create_metadata_file(artifact)

            code = run_vmware_orchestrator(metadata_path, artifact_path, backend_url)

            if code == 0 and remote_result_exists(artifact_id, backend_url):
                print(f"[+] Analyse terminee pour {artifact_id}")
                processed.add(artifact_id)
                save_processed(processed)
            elif code == 0:
                print(f"[!] Analyse executee, mais resultat non visible dans M4 : {artifact_id}")
            else:
                print(f"[!] Analyse echouee pour {artifact_id}, code={code}")

        except Exception as e:
            print(f"[!] Erreur traitement {artifact_id}: {e}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--backend-url",
        default=DEFAULT_BACKEND_URL,
        help="M4 backend URL, default from ROOTKIT_DEFENSE_M4_URL or sandbox_config.py",
    )
    parser.add_argument("--once", action="store_true", help="Executer une seule verification")
    parser.add_argument("--interval", type=int, default=30, help="Intervalle polling en secondes")
    args = parser.parse_args()

    if args.once:
        process_once(args.backend_url)
        return

    print("[+] M3 Auto Worker demarre")
    print("[+] Mode automatique : GET ready -> download -> VMware -> POST M4")
    print(f"[+] Backend M4 : {args.backend_url}")

    while True:
        process_once(args.backend_url)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
