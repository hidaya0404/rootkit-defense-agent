from __future__ import annotations

from pathlib import Path
from typing import Any

from evidence_quarantine.backend_client import (
    BackendSyncError,
    build_quarantine_manifest,
    download_backend_artifact,
    get_ready_alerts,
    post_quarantine_manifest_payload,
)
from evidence_quarantine.id_generator import sanitize_alert_id
from evidence_quarantine.models import QuarantineRequest, RiskLevel, to_jsonable
from evidence_quarantine.quarantine_manager import QuarantineManager
from evidence_quarantine.storage import atomic_write_json, ensure_dir
from evidence_quarantine.time_utils import utc_now


def process_backend_ready_alerts(
    manager: QuarantineManager,
    backend_url: str,
    *,
    status: str = "ARTIFACT_READY",
    timeout: float = 10.0,
    send_manifest: bool = True,
    skip_existing: bool = True,
) -> dict[str, Any]:
    """M2 workflow: pull M4 ready alerts, quarantine artifacts, send manifest."""

    alerts = get_ready_alerts(backend_url, status=status, timeout=timeout)
    results = [
        _process_one_alert(
            manager,
            backend_url,
            alert,
            timeout=timeout,
            send_manifest=send_manifest,
            skip_existing=skip_existing,
        )
        for alert in alerts
    ]
    return to_jsonable(
        {
            "backend_url": backend_url,
            "requested_status": status,
            "received_alerts": len(alerts),
            "processed_alerts": len(results),
            "skipped_alerts": sum(1 for item in results if item.get("skipped") is True),
            "sent_manifests": sum(1 for item in results if item.get("manifest_sent") is True),
            "results": results,
        }
    )


def _process_one_alert(
    manager: QuarantineManager,
    backend_url: str,
    alert: dict[str, Any],
    *,
    timeout: float,
    send_manifest: bool,
    skip_existing: bool,
) -> dict[str, Any]:
    alert_id = str(alert.get("alert_id") or alert.get("id") or "").strip()
    if not alert_id:
        return {
            "success": False,
            "stage": "alert_validation",
            "error": "Backend alert does not contain alert_id",
            "alert": alert,
        }

    safe_alert_id = sanitize_alert_id(alert_id)
    existing = manager.get_evidence(safe_alert_id) or manager.get_evidence(alert_id)
    if skip_existing and existing and _already_ready(existing):
        response = None
        manifest_error = None
        if send_manifest and not existing.get("backend_manifest_sent"):
            try:
                response = post_quarantine_manifest_payload(
                    backend_url,
                    build_quarantine_manifest(existing, download_url=_manifest_download_url(alert_id, alert)),
                    timeout=timeout,
                )
                existing = dict(existing)
                existing["backend_manifest_sent"] = True
                existing["backend_manifest_sent_at"] = utc_now()
                existing["backend_response"] = response
                manager.repository.upsert(existing)
            except BackendSyncError as exc:
                manifest_error = str(exc)

        return to_jsonable(
            {
                "success": manifest_error is None,
                "skipped": manifest_error is None,
                "stage": "already_quarantined",
                "alert_id": existing.get("alert_id"),
                "artifact_id": existing.get("artifact_id"),
                "quarantine_status": existing.get("status"),
                "manifest_sent": response is not None,
                "backend_response": response,
                "error": manifest_error,
            }
        )

    download_dir = manager.config.storage_root / "backend-downloads" / safe_alert_id
    ensure_dir(download_dir)

    try:
        artifact_path = download_backend_artifact(
            backend_url,
            alert_id,
            download_dir,
            timeout=timeout,
            filename=_filename_from_alert(alert),
            download_url=_download_url_from_alert(alert),
        )
    except BackendSyncError as exc:
        return {
            "success": False,
            "alert_id": alert_id,
            "stage": "download",
            "error": str(exc),
        }

    quarantine_result = manager.quarantine_artifact(
        QuarantineRequest(
            alert_id=alert_id,
            artifact_path=artifact_path,
            detection_reason=_detection_reason(alert),
            risk_level=_risk_level(alert),
            source_module="m4-backend-pull",
            tags=_tags(alert),
        )
    )

    record = manager.get_evidence(quarantine_result.alert_id) or quarantine_result.to_summary()
    record = dict(record)
    source_original_path = _original_path(alert)
    if source_original_path:
        record["original_path"] = source_original_path
        record["source_original_path"] = source_original_path
    record["source_alert_status"] = alert.get("status")
    record["backend_alert_status"] = alert.get("status")
    record["backend_url"] = backend_url
    record["backend_download_path"] = str(artifact_path)

    backend_manifest_path = Path(quarantine_result.evidence_dir) / "backend_manifest.json"
    record["backend_manifest_path"] = str(backend_manifest_path)
    manifest_payload = build_quarantine_manifest(record, download_url=_manifest_download_url(alert_id, alert))
    atomic_write_json(backend_manifest_path, manifest_payload)
    manager.repository.upsert(record)

    response: dict[str, Any] | None = None
    manifest_error: str | None = None
    if send_manifest and quarantine_result.success:
        try:
            response = post_quarantine_manifest_payload(backend_url, manifest_payload, timeout=timeout)
        except BackendSyncError as exc:
            manifest_error = str(exc)

    if response is not None:
        record["backend_manifest_sent"] = True
        record["backend_manifest_sent_at"] = utc_now()
        record["backend_response"] = response
        manager.repository.upsert(record)

    return to_jsonable(
        {
            "success": quarantine_result.success and manifest_error is None,
            "alert_id": quarantine_result.alert_id,
            "artifact_id": quarantine_result.artifact_id,
            "downloaded_artifact": artifact_path,
            "quarantine_status": quarantine_result.status,
            "evidence_dir": quarantine_result.evidence_dir,
            "backend_manifest_path": backend_manifest_path,
            "manifest_sent": response is not None,
            "backend_response": response,
            "error": manifest_error,
            "quarantine_errors": quarantine_result.errors,
        }
    )


def _download_url_from_alert(alert: dict[str, Any]) -> str | None:
    value = alert.get("download_url") or alert.get("artifact_download_url")
    return str(value) if value else None


def _manifest_download_url(alert_id: str, alert: dict[str, Any]) -> str:
    return _download_url_from_alert(alert) or f"/api/artifacts/{alert_id}/download"


def _already_ready(record: dict[str, Any]) -> bool:
    return (
        record.get("status") == "READY_FOR_ANALYSIS"
        and record.get("integrity_verified") is True
        and record.get("ready_for_sandbox") is True
    )


def _filename_from_alert(alert: dict[str, Any]) -> str | None:
    value = alert.get("filename") or alert.get("artifact_name")
    details = alert.get("details") if isinstance(alert.get("details"), dict) else {}
    value = value or details.get("filename") or details.get("name")
    return str(value) if value else None


def _original_path(alert: dict[str, Any]) -> str | None:
    details = alert.get("details") if isinstance(alert.get("details"), dict) else {}
    value = alert.get("original_path") or details.get("path") or details.get("original_path")
    return str(value) if value else None


def _detection_reason(alert: dict[str, Any]) -> str:
    details = alert.get("details") if isinstance(alert.get("details"), dict) else {}
    value = (
        alert.get("detection_reason")
        or alert.get("reason")
        or alert.get("message")
        or details.get("reason")
        or details.get("description")
    )
    return str(value) if value else "M4 alert marked ARTIFACT_READY for M2 quarantine"


def _risk_level(alert: dict[str, Any]) -> RiskLevel:
    raw = alert.get("risk_level") or alert.get("risk") or alert.get("severity") or alert.get("level")
    value = str(raw or RiskLevel.MEDIUM.value).upper()
    aliases = {
        "INFO": RiskLevel.LOW,
        "WARN": RiskLevel.MEDIUM,
        "WARNING": RiskLevel.MEDIUM,
        "SEVERE": RiskLevel.HIGH,
    }
    if value in aliases:
        return aliases[value]
    try:
        return RiskLevel(value)
    except ValueError:
        return RiskLevel.MEDIUM


def _tags(alert: dict[str, Any]) -> list[str]:
    tags = ["m2-quarantine", "m4-artifact-ready", "backend-pull"]
    for key in ("rootkit_category", "category", "type"):
        value = alert.get(key)
        if value:
            tags.append(str(value))
    return tags
