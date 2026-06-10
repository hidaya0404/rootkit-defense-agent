from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class BackendSyncError(RuntimeError):
    """Raised when the M2 -> backend manifest synchronization fails."""


def build_quarantine_manifest(record: dict[str, Any], *, download_url: str | None = None) -> dict[str, Any]:
    manifest = {
        "artifact_id": record.get("artifact_id"),
        "alert_id": record.get("alert_id"),
        "filename": record.get("filename") or record.get("artifact_name"),
        "sha256": record.get("sha256"),
        "md5": record.get("md5"),
        "sha1": record.get("sha1"),
        "original_path": record.get("original_path"),
        "quarantine_path": record.get("quarantine_path") or record.get("artifact_path"),
        "stored_path": record.get("stored_path") or record.get("artifact_path"),
        "metadata_path": record.get("metadata_path"),
        "hashes_path": record.get("hashes_path"),
        "manifest_path": record.get("manifest_path"),
        "rootkit_category": record.get("rootkit_category"),
        "status": record.get("status"),
        "integrity_verified": record.get("integrity_verified"),
        "ready_for_sandbox": record.get("ready_for_sandbox"),
        "created_at": record.get("created_at"),
    }
    if download_url:
        manifest["download_url"] = download_url
    return manifest


def post_quarantine_manifest(
    backend_url: str,
    record: dict[str, Any],
    *,
    timeout: float = 10.0,
    download_url: str | None = None,
) -> dict[str, Any]:
    endpoint = backend_url.rstrip("/") + "/api/quarantine/manifest"
    payload = json.dumps(build_quarantine_manifest(record, download_url=download_url)).encode("utf-8")
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
