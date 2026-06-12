from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlencode, urljoin
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class BackendSyncError(RuntimeError):
    """Raised when the M2 -> backend manifest synchronization fails."""


def build_quarantine_manifest(record: dict[str, Any], *, download_url: str | None = None) -> dict[str, Any]:
    md5 = record.get("md5")
    sha1 = record.get("sha1")
    sha256 = record.get("sha256")
    manifest = {
        "artifact_id": record.get("artifact_id"),
        "alert_id": record.get("alert_id"),
        "timestamp": record.get("timestamp") or record.get("created_at"),
        "filename": record.get("filename") or record.get("artifact_name"),
        "sha256": sha256,
        "md5": md5,
        "sha1": sha1,
        "hashes": {
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
        },
        "original_path": record.get("original_path"),
        "quarantine_path": record.get("quarantine_path") or record.get("artifact_path"),
        "stored_path": record.get("stored_path") or record.get("artifact_path"),
        "metadata_path": record.get("metadata_path"),
        "hashes_path": record.get("hashes_path"),
        "manifest_path": record.get("manifest_path"),
        "backend_manifest_path": record.get("backend_manifest_path"),
        "rootkit_category": record.get("rootkit_category"),
        "status": record.get("status"),
        "source_alert_status": record.get("source_alert_status") or record.get("backend_alert_status"),
        "integrity_verified": record.get("integrity_verified"),
        "ready_for_sandbox": record.get("ready_for_sandbox"),
        "created_at": record.get("created_at"),
    }
    if download_url:
        manifest["download_url"] = download_url
    return manifest


def get_ready_alerts(
    backend_url: str,
    *,
    status: str = "ARTIFACT_READY",
    timeout: float = 10.0,
) -> list[dict[str, Any]]:
    """Fetch alerts whose artifacts are ready on M4."""

    endpoint = backend_url.rstrip("/") + "/api/alerts?" + urlencode({"status": status})
    request = Request(endpoint, headers={"Accept": "application/json"}, method="GET")
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise BackendSyncError(f"Backend rejected ready-alert request ({exc.code}): {detail}") from exc
    except URLError as exc:
        raise BackendSyncError(f"Cannot reach backend: {exc.reason}") from exc

    payload = json.loads(body) if body else []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("alerts", "items", "results", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
    raise BackendSyncError("Backend returned an invalid ready-alerts payload")


def download_url_to_file(
    url: str,
    save_dir: str | Path,
    *,
    timeout: float = 30.0,
    filename: str | None = None,
) -> Path:
    """Download one backend artifact into a controlled local directory."""

    save_dir = Path(save_dir).expanduser().resolve()
    save_dir.mkdir(parents=True, exist_ok=True)
    request = Request(url, headers={"Accept": "application/octet-stream"}, method="GET")

    try:
        with urlopen(request, timeout=timeout) as response:
            header_filename = _filename_from_content_disposition(response.headers.get("Content-Disposition"))
            target_name = _safe_filename(filename or header_filename or "artifact.bin")
            target_path = save_dir / target_name
            with target_path.open("wb") as handle:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise BackendSyncError(f"Backend artifact download failed ({exc.code}): {detail}") from exc
    except URLError as exc:
        raise BackendSyncError(f"Cannot download backend artifact: {exc.reason}") from exc

    return target_path


def download_backend_artifact(
    backend_url: str,
    alert_id: str,
    save_dir: str | Path,
    *,
    timeout: float = 30.0,
    filename: str | None = None,
    download_url: str | None = None,
) -> Path:
    """Download the artifact associated with an M4 alert."""

    if download_url:
        endpoint = download_url if download_url.startswith(("http://", "https://")) else urljoin(
            backend_url.rstrip("/") + "/",
            download_url.lstrip("/"),
        )
    else:
        endpoint = backend_url.rstrip("/") + f"/api/artifacts/{quote(alert_id, safe='')}/download"
    return download_url_to_file(endpoint, save_dir, timeout=timeout, filename=filename)


def post_quarantine_manifest(
    backend_url: str,
    record: dict[str, Any],
    *,
    timeout: float = 10.0,
    download_url: str | None = None,
) -> dict[str, Any]:
    return post_quarantine_manifest_payload(
        backend_url,
        build_quarantine_manifest(record, download_url=download_url),
        timeout=timeout,
    )


def post_quarantine_manifest_payload(
    backend_url: str,
    manifest: dict[str, Any],
    *,
    timeout: float = 10.0,
) -> dict[str, Any]:
    endpoint = backend_url.rstrip("/") + "/api/quarantine/manifest"
    payload = json.dumps(manifest).encode("utf-8")
    request = Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body else {"status": response.status}
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise BackendSyncError(f"Backend rejected manifest ({exc.code}): {detail}") from exc
    except URLError as exc:
        raise BackendSyncError(f"Cannot reach backend: {exc.reason}") from exc


def _filename_from_content_disposition(value: str | None) -> str | None:
    if not value:
        return None
    encoded = re.search(r"filename\*=(?:UTF-8'')?([^;]+)", value, flags=re.IGNORECASE)
    if encoded:
        return unquote(encoded.group(1).strip().strip('"'))
    regular = re.search(r'filename="?([^";]+)"?', value, flags=re.IGNORECASE)
    if regular:
        return regular.group(1).strip()
    return None


def _safe_filename(value: str) -> str:
    name = Path(value).name.strip() or "artifact.bin"
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    return name[:120] or "artifact.bin"
