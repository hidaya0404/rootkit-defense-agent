from __future__ import annotations

import json
import html
import mimetypes
import os
import subprocess
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen

from analysis.ai_remediation_advisor import build_ai_recommendation
from evidence_quarantine.backend_client import build_quarantine_manifest
from evidence_quarantine.config import QuarantineConfig
from evidence_quarantine.quarantine_manager import QuarantineManager
from evidence_quarantine.storage import read_json

DEFAULT_M4_BACKEND_URL = "https://disclose-fired-boating-findings.trycloudflare.com"


def rootrap_storage_root() -> Path | None:
    configured = os.getenv("ROOTRAP_STORAGE_ROOT") or os.getenv("ROOTKIT_DEFENSE_STORAGE")
    return Path(configured).expanduser() if configured else None


def rootrap_log_dir() -> Path | None:
    configured = os.getenv("ROOTRAP_LOG_DIR")
    return Path(configured).expanduser() if configured else None


def remote_dashboard_data_enabled() -> bool:
    value = os.getenv("ROOTRAP_ENABLE_REMOTE_DASHBOARD_DATA", "1").strip().lower()
    return value in {"1", "true", "yes", "on", "remote", "remote-first"}


def timestamp_key(item: dict[str, object]) -> str:
    for key in ("received_at", "finished_at", "analysis_finished_at", "timestamp", "created_at", "generated_at"):
        value = item.get(key)
        if value:
            return str(value)
    return ""


def merge_records(*collections: list[dict[str, object]], identity_keys: tuple[str, ...]) -> list[dict[str, object]]:
    merged: dict[str, dict[str, object]] = {}
    fallback = 0
    for collection in collections:
        for item in collection:
            key_parts = [str(item.get(key) or "") for key in identity_keys]
            key = "|".join(key_parts).strip("|")
            if not key:
                fallback += 1
                key = f"item-{fallback}"
            merged[key] = {**merged.get(key, {}), **item}
    return sorted(merged.values(), key=timestamp_key, reverse=True)


def list_from_payload(payload: dict[str, object] | list[object] | None, *keys: str) -> list[dict[str, object]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def hash_identity_values(item: dict[str, object]) -> set[str]:
    values: set[str] = set()
    for key in ("sha256", "artifact_sha256", "downloaded_sha256", "md5", "sha1"):
        value = item.get(key)
        if value:
            normalized_key = "sha256" if key in {"artifact_sha256", "downloaded_sha256"} else key
            values.add(f"{normalized_key}:{str(value).lower()}")

    hashes = item.get("hashes")
    if isinstance(hashes, dict):
        for key in ("sha256", "md5", "sha1"):
            value = hashes.get(key)
            if value:
                values.add(f"{key}:{str(value).lower()}")

    details = item.get("details")
    if isinstance(details, dict):
        values.update(hash_identity_values(details))

    analysis = item.get("analysis")
    if isinstance(analysis, dict):
        values.update(hash_identity_values(analysis))

    sandbox_result = item.get("sandbox_result")
    if isinstance(sandbox_result, dict):
        values.update(hash_identity_values(sandbox_result))

    return values


def remote_quarantine_artifacts() -> list[dict[str, object]]:
    artifacts: list[dict[str, object]] = []
    if not remote_dashboard_data_enabled():
        return artifacts

    for endpoint in ("/api/quarantine", "/api/quarantine/ready"):
        payload, _ = load_remote_json(f"{configured_m4_backend_url()}{endpoint}", timeout=4.0)
        artifacts.extend(list_from_payload(payload, "artifacts", "quarantine", "results", "items", "data"))

    return merge_records(artifacts, identity_keys=("artifact_id", "alert_id", "sha256"))


def enrich_sandbox_results_with_artifacts(
    sandbox_results: list[dict[str, object]],
    artifacts: list[dict[str, object]],
) -> list[dict[str, object]]:
    index: dict[str, dict[str, object]] = {}
    for artifact in artifacts:
        for key in identity_values(artifact):
            index.setdefault(key, artifact)

    enriched: list[dict[str, object]] = []
    for result in sandbox_results:
        item = dict(result)
        matches = [index[key] for key in identity_values(item) if key in index]
        artifact = matches[0] if matches else None
        if artifact:
            item.setdefault("m4_artifact_id", artifact.get("artifact_id"))
            item.setdefault("artifact_name", artifact.get("filename") or artifact.get("artifact_name"))
            item.setdefault("filename", artifact.get("filename") or artifact.get("artifact_name"))
            item.setdefault("artifact_sha256", artifact.get("sha256") or artifact.get("artifact_sha256"))
            item.setdefault("sha256", artifact.get("sha256") or artifact.get("artifact_sha256"))
            item.setdefault("quarantine_path", artifact.get("quarantine_path") or artifact.get("stored_path"))
            item.setdefault("download_url", artifact.get("download_url"))
        enriched.append(item)

    return enriched


def embedded_sandbox_results(scope: set[str], artifacts: list[dict[str, object]] | None = None) -> list[dict[str, object]]:
    embedded: list[dict[str, object]] = []
    if not remote_dashboard_data_enabled():
        return embedded

    for artifact in artifacts if artifacts is not None else remote_quarantine_artifacts():
        sandbox_result = artifact.get("sandbox_result")
        if not isinstance(sandbox_result, dict):
            continue
        item = dict(sandbox_result)
        item.setdefault("artifact_id", artifact.get("artifact_id"))
        item.setdefault("alert_id", artifact.get("alert_id"))
        item.setdefault("artifact_name", artifact.get("filename") or artifact.get("artifact_name"))
        item.setdefault("filename", artifact.get("filename") or artifact.get("artifact_name"))
        item.setdefault("artifact_sha256", artifact.get("sha256"))
        item.setdefault("sha256", artifact.get("sha256"))
        item.setdefault("quarantine_path", artifact.get("quarantine_path") or artifact.get("stored_path"))
        if matches_dashboard_scope(item, scope):
            embedded.append(item)
    return embedded


def runtime_config() -> QuarantineConfig:
    return QuarantineConfig(storage_root=rootrap_storage_root() or repo_root() / "runtime" / "rootrap")


def identity_values(item: dict[str, object]) -> set[str]:
    values: set[str] = set()
    for key in ("alert_id", "artifact_id"):
        value = item.get(key)
        if value:
            values.add(str(value))

    details = item.get("details")
    if isinstance(details, dict):
        for key in ("alert_id", "artifact_id", "m2_artifact_id"):
            value = details.get(key)
            if value:
                values.add(str(value))
    values.update(hash_identity_values(item))
    return values


def dashboard_scope_ids(config: QuarantineConfig | None = None) -> set[str]:
    """IDs created by this installation.

    Remote M4 is shared during demos, so the UI must not display every remote
    sandbox/report/remediation row. It only imports remote rows that match local
    alerts or local quarantine records.
    """

    scope: set[str] = set()
    for item in load_alerts():
        scope.update(identity_values(item))
    for item in load_ui_records(config or runtime_config()):
        scope.update(identity_values(item))
    return scope


def matches_dashboard_scope(item: dict[str, object], scope: set[str]) -> bool:
    return bool(scope and identity_values(item).intersection(scope))


def default_web_dir() -> Path:
    repo_web = Path(__file__).resolve().parents[1] / "web"
    if repo_web.exists():
        return repo_web
    cwd_web = Path.cwd() / "web"
    if cwd_web.exists():
        return cwd_web
    return repo_web


def load_ui_records(config: QuarantineConfig) -> list[dict[str, object]]:
    records = QuarantineManager(config).list_evidence()
    enriched: list[dict[str, object]] = []
    for record in records:
        item = dict(record)
        metadata_path = item.get("metadata_path")
        metadata = read_json(Path(str(metadata_path)), default={}) if metadata_path else {}
        if isinstance(metadata, dict):
            item.setdefault("detection_reason", metadata.get("detection_reason"))
            item.setdefault("detected_at", metadata.get("detected_at"))
            item.setdefault("risk_level", metadata.get("risk_level"))
            item.setdefault("tags", metadata.get("tags", []))
            item.setdefault("file_type", metadata.get("file_type"))
            item.setdefault("size_bytes", metadata.get("size_bytes"))
        profile = metadata.get("rootkit_profile") if isinstance(metadata, dict) else None
        if isinstance(profile, dict):
            item.setdefault("rootkit_category", profile.get("category"))
            item.setdefault("suspected_techniques", profile.get("suspected_techniques", []))
        enriched.append(item)
    return enriched


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def read_json_lines(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    records: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def load_alerts() -> list[dict[str, object]]:
    configured_alerts = os.getenv("ROOTRAP_PENDING_ALERTS_FILE")
    if configured_alerts:
        return read_json_lines(Path(configured_alerts).expanduser())

    log_dir = rootrap_log_dir()
    if log_dir:
        return read_json_lines(log_dir / "pending_alerts.jsonl")

    root = repo_root()
    candidates = [
        root / "logs" / "pending_alerts.jsonl",
        Path.cwd() / "logs" / "pending_alerts.jsonl",
    ]
    for candidate in candidates:
        alerts = read_json_lines(candidate)
        if alerts:
            return alerts
    return []


def alert_from_quarantine_record(record: dict[str, object]) -> dict[str, object]:
    category = str(record.get("rootkit_category") or "quarantined_artifact")
    risk_level = str(record.get("risk_level") or "MEDIUM")
    status = str(record.get("status") or "READY_FOR_ANALYSIS")
    filename = record.get("filename") or record.get("artifact_name") or record.get("original_filename")
    description = record.get("detection_reason") or f"Quarantined artifact ready for analysis: {filename or category}"

    return {
        "alert_id": record.get("alert_id"),
        "artifact_id": record.get("artifact_id"),
        "timestamp": record.get("detected_at") or record.get("created_at"),
        "source_module": record.get("source_module") or "m2-quarantine",
        "type": category,
        "severity": risk_level,
        "status": status,
        "description": description,
        "derived_from_quarantine": True,
        "details": {
            "artifact_id": record.get("artifact_id"),
            "filename": filename,
            "original_path": record.get("original_path"),
            "quarantine_path": record.get("quarantine_path") or record.get("artifact_path"),
            "sha256": record.get("sha256"),
            "md5": record.get("md5"),
            "sha1": record.get("sha1"),
            "rootkit_category": category,
            "suspected_techniques": record.get("suspected_techniques", []),
            "integrity_verified": record.get("integrity_verified"),
            "ready_for_sandbox": record.get("ready_for_sandbox"),
            "tags": record.get("tags", []),
        },
    }


def load_dashboard_alerts(config: QuarantineConfig) -> list[dict[str, object]]:
    alerts = load_alerts()
    seen_alert_ids = {str(alert.get("alert_id")) for alert in alerts if alert.get("alert_id")}

    for record in load_ui_records(config):
        alert_id = record.get("alert_id")
        if not alert_id or str(alert_id) in seen_alert_ids:
            continue
        alerts.append(alert_from_quarantine_record(record))
        seen_alert_ids.add(str(alert_id))

    return alerts


def load_sandbox_results() -> list[dict[str, object]]:
    root = repo_root()
    local_items: list[dict[str, object]] = []
    remote_items: list[dict[str, object]] = []
    scope = dashboard_scope_ids()

    storage_root = rootrap_storage_root()
    if storage_root:
        local_candidates = [
            storage_root / "sandbox_results.json",
            storage_root / "sandbox" / "results.json",
            storage_root / "sandbox" / "sandbox_results.json",
        ]
        for candidate in local_candidates:
            local_results = read_json(candidate, default=[])
            if isinstance(local_results, list):
                local_items.extend(item for item in local_results if isinstance(item, dict))
            if isinstance(local_results, dict):
                results = local_results.get("results")
                if isinstance(results, list):
                    local_items.extend(item for item in results if isinstance(item, dict))

        sandbox_dir = storage_root / "sandbox" / "results"
        if sandbox_dir.exists():
            for result_file in sorted(sandbox_dir.glob("*/sandbox_result.json")):
                item = read_json(result_file, default={})
                if isinstance(item, dict):
                    local_items.append(item)

    if remote_dashboard_data_enabled():
        remote_payload, _ = load_remote_json(f"{configured_m4_backend_url()}/api/sandbox/results", timeout=4.0)
        remote_items.extend(
            list_from_payload(
                remote_payload,
                "results",
                "sandbox_results",
                "sandbox",
                "items",
                "data",
            )
        )
        remote_artifacts = remote_quarantine_artifacts()
        remote_items = enrich_sandbox_results_with_artifacts(remote_items, remote_artifacts)
        remote_items.extend(embedded_sandbox_results(scope, remote_artifacts))
        remote_items = [item for item in remote_items if matches_dashboard_scope(item, scope)]

    results_file = root / "backend" / "data" / "sandbox_results.json"
    results = read_json(results_file, default=[])
    if isinstance(results, list) and results:
        local_items.extend(item for item in results if isinstance(item, dict) and matches_dashboard_scope(item, scope))

    sandbox_dir = root / "sandbox" / "results"
    if sandbox_dir.exists():
        for result_file in sorted(sandbox_dir.glob("*/sandbox_result.json")):
            item = read_json(result_file, default={})
            if isinstance(item, dict) and matches_dashboard_scope(item, scope):
                local_items.append(item)
    return merge_records(remote_items, local_items, identity_keys=("artifact_id", "started_at", "received_at"))


def load_reports() -> list[dict[str, object]]:
    root = repo_root()
    local_items: list[dict[str, object]] = []
    remote_items: list[dict[str, object]] = []
    scope = dashboard_scope_ids()

    storage_root = rootrap_storage_root()
    if storage_root:
        local_candidates = [
            storage_root / "reports.json",
            storage_root / "reports" / "reports.json",
        ]
        for candidate in local_candidates:
            local_reports = read_json(candidate, default=[])
            if isinstance(local_reports, list):
                local_items.extend(item for item in local_reports if isinstance(item, dict))
            if isinstance(local_reports, dict):
                reports = local_reports.get("reports")
                if isinstance(reports, list):
                    local_items.extend(item for item in reports if isinstance(item, dict))

        reports_dir = storage_root / "reports"
        if reports_dir.exists():
            local_items.extend(
                {"report_path": str(path), "filename": path.name, "status": "LOCAL_HTML"}
                for path in sorted(reports_dir.glob("*.html"))
            )

    if remote_dashboard_data_enabled():
        remote_payload, _ = load_remote_json(f"{configured_m4_backend_url()}/api/reports", timeout=4.0)
        remote_items.extend(list_from_payload(remote_payload, "reports", "results", "items", "data"))
        remote_items = [item for item in remote_items if matches_dashboard_scope(item, scope)]

    reports_file = root / "backend" / "data" / "reports.json"
    reports = read_json(reports_file, default=[])
    if isinstance(reports, list):
        local_items.extend(item for item in reports if isinstance(item, dict) and matches_dashboard_scope(item, scope))

    merged = merge_records(remote_items, local_items, identity_keys=("report_id", "artifact_id", "report_path"))
    if merged:
        for item in merged:
            report_id = item.get("report_id")
            if report_id and not item.get("download_url"):
                item["download_url"] = f"/api/reports/{report_id}/download"
        return merged
    return synthetic_dashboard_reports()


def risk_score_from_level(risk_level: object) -> int:
    mapping = {
        "CRITICAL": 92,
        "HIGH": 78,
        "MEDIUM": 48,
        "LOW": 20,
    }
    return mapping.get(str(risk_level or "").upper(), 50)


def synthetic_dashboard_reports() -> list[dict[str, object]]:
    quarantine_records = load_ui_records(runtime_config())

    sandbox_by_artifact = {
        item.get("artifact_id"): item
        for item in load_sandbox_results()
        if item.get("artifact_id")
    }
    reports = []
    for record in quarantine_records:
        artifact_id = record.get("artifact_id")
        report_id = f"RPT-{artifact_id}"
        risk_level = record.get("risk_level") or "MEDIUM"
        reports.append(
            {
                "report_id": report_id,
                "artifact_id": artifact_id,
                "alert_id": record.get("alert_id"),
                "timestamp": record.get("created_at") or record.get("detected_at"),
                "risk_score": risk_score_from_level(risk_level),
                "risk_level": risk_level,
                "status": "LOCAL_INCIDENT_REPORT",
                "summary": "Local incident report generated from alert, quarantine, sandbox and remediation data.",
                "report_path": None,
                "pdf_report_path": None,
                "download_url": f"/api/reports/{report_id}/download",
                "sandbox_status": sandbox_by_artifact.get(artifact_id, {}).get("execution_status"),
            }
        )
    return reports


def _artifact_candidates(config: QuarantineConfig) -> list[str]:
    candidates: list[str] = []
    for collection in (load_reports(), load_ui_records(config)):
        for item in collection:
            artifact_id = item.get("artifact_id") if isinstance(item, dict) else None
            if artifact_id and str(artifact_id) not in candidates:
                candidates.append(str(artifact_id))

    return candidates[:6]


def load_remediations(config: QuarantineConfig) -> list[dict[str, object]]:
    backend_url = configured_m4_backend_url()
    remediations: list[dict[str, object]] = []
    remediation_list_missing = False

    if remote_dashboard_data_enabled():
        remote_payload, error = load_remote_json(f"{backend_url}/api/remediation", timeout=3.0)
        remediation_list_missing = bool(error and ("404" in error or "not found" in error.lower()))
        scope = dashboard_scope_ids(config)
        if isinstance(remote_payload, dict):
            remote_results = remote_payload.get("results") or remote_payload.get("remediations")
            if isinstance(remote_results, list):
                filtered = [
                    item for item in remote_results
                    if isinstance(item, dict) and matches_dashboard_scope(item, scope)
                ]
                if filtered:
                    return filtered
        if isinstance(remote_payload, list):
            filtered = [
                item for item in remote_payload
                if isinstance(item, dict) and matches_dashboard_scope(item, scope)
            ]
            if filtered:
                return filtered

    if remote_dashboard_data_enabled() and not remediation_list_missing:
        for artifact_id in _artifact_candidates(config):
            payload, error = load_remote_json(f"{backend_url}/api/remediation/{artifact_id}", timeout=2.0)
            if error or not isinstance(payload, dict):
                continue
            remediation = payload.get("remediation") if isinstance(payload.get("remediation"), dict) else payload
            if isinstance(remediation, dict):
                item = dict(remediation)
                item.setdefault("artifact_id", artifact_id)
                remediations.append(item)

    if remediations:
        return remediations

    return synthetic_dashboard_remediations(config)


def synthetic_dashboard_remediations(config: QuarantineConfig) -> list[dict[str, object]]:
    records = load_ui_records(config)

    sandbox_by_artifact = {
        item.get("artifact_id"): item
        for item in load_sandbox_results()
        if item.get("artifact_id")
    }

    plans: list[dict[str, object]] = []
    for record in records:
        artifact_id = record.get("artifact_id")
        risk_level = str(record.get("risk_level") or "HIGH").upper()
        artifact = {
            **record,
            "analysis": {
                "risk_level": risk_level,
                "risk_score": risk_score_from_level(risk_level),
                "iocs": {
                    "paths": [record.get("original_path")] if record.get("original_path") else [],
                    "hashes": [record.get("sha256")] if record.get("sha256") else [],
                },
                "sandbox_result": sandbox_by_artifact.get(artifact_id),
            },
        }
        ai = build_ai_recommendation(artifact)
        actions = [
            {
                "step": index + 1,
                "title": "AI remediation advisor",
                "action": action,
                "command": "Validation humaine obligatoire avant action destructive.",
                "status": "AI_RECOMMENDED",
            }
            for index, action in enumerate(ai.get("recommended_actions", [])[:8])
        ]
        plans.append(
            {
                "remediation_id": f"REM-{artifact_id}",
                "artifact_id": artifact_id,
                "alert_id": record.get("alert_id"),
                "generated_at": record.get("created_at") or record.get("received_at"),
                "risk_level": ai.get("risk_level") or risk_level,
                "risk_score": ai.get("risk_score") or risk_score_from_level(risk_level),
                "decision": ai.get("decision"),
                "ai_recommendation": ai,
                "requires_human_validation": True,
                "automatic_deletion": False,
                "actions": actions,
            }
        )
    return plans


def first_match(
    items: list[dict[str, object]],
    *,
    alert_id: object = None,
    artifact_id: object = None,
    reference: dict[str, object] | None = None,
) -> dict[str, object] | None:
    expected = {str(value) for value in (alert_id, artifact_id) if value}
    if reference:
        expected.update(identity_values(reference))
    if not expected:
        return None
    for item in items:
        if identity_values(item).intersection(expected):
            return item
    return None


def stage(
    stage_id: str,
    label: str,
    status: str,
    *,
    timestamp: object = None,
    detail: object = None,
) -> dict[str, object]:
    return {
        "id": stage_id,
        "label": label,
        "status": status,
        "timestamp": timestamp,
        "detail": detail,
    }


def sandbox_stage_status(result: dict[str, object] | None) -> str:
    if not result:
        return "WAITING"
    status = str(result.get("execution_status") or result.get("sandbox_status") or "").upper()
    if status == "COMPLETED":
        return "DONE"
    if status in {"FAILED", "TIMEOUT", "ERROR"}:
        return "BLOCKED"
    return "WAITING"


def quarantine_stage(record: dict[str, object] | None) -> dict[str, object]:
    if not record:
        return stage("m2", "M2 Quarantaine", "WAITING", detail="Aucun artefact mis en quarantaine pour cette alerte.")
    status = str(record.get("status") or "UNKNOWN").upper()
    integrity_verified = record.get("integrity_verified") is True
    ready_for_sandbox = record.get("ready_for_sandbox") is True
    if status == "REJECTED":
        stage_status = "BLOCKED"
        detail = record.get("rejection_reason") or "Artefact refuse par la politique de quarantaine."
    elif not integrity_verified:
        stage_status = "BLOCKED"
        detail = "Integrite non verifiee: hash avant/apres ou SHA256 invalide."
    elif status == "READY_FOR_ANALYSIS" and ready_for_sandbox:
        stage_status = "DONE"
        detail = "Copie securisee, hashes et manifest valides."
    else:
        stage_status = "WAITING"
        detail = f"Statut actuel: {status}."
    return stage("m2", "M2 Quarantaine", stage_status, timestamp=record.get("created_at"), detail=detail)


def build_cases(config: QuarantineConfig) -> list[dict[str, object]]:
    alerts = load_dashboard_alerts(config)
    quarantine_records = load_ui_records(config)
    sandbox_results = load_sandbox_results()
    remediations = load_remediations(config)
    reports = load_reports()

    case_keys: dict[str, dict[str, object]] = {}
    for item in [*alerts, *quarantine_records]:
        alert_id = item.get("alert_id")
        artifact_id = item.get("artifact_id")
        details = item.get("details")
        if isinstance(details, dict):
            artifact_id = artifact_id or details.get("artifact_id") or details.get("m2_artifact_id")
        key = str(artifact_id or alert_id or "")
        if not key:
            continue
        case_keys.setdefault(key, {"alert_id": alert_id, "artifact_id": artifact_id})
        if alert_id:
            case_keys[key]["alert_id"] = alert_id
        if artifact_id:
            case_keys[key]["artifact_id"] = artifact_id

    cases: list[dict[str, object]] = []
    for key, identifiers in case_keys.items():
        alert_id = identifiers.get("alert_id")
        artifact_id = identifiers.get("artifact_id")
        alert = first_match(alerts, alert_id=alert_id, artifact_id=artifact_id)
        record = first_match(quarantine_records, alert_id=alert_id, artifact_id=artifact_id)
        reference = record or alert
        sandbox = first_match(sandbox_results, alert_id=alert_id, artifact_id=artifact_id, reference=reference)
        remediation = first_match(remediations, alert_id=alert_id, artifact_id=artifact_id, reference=reference or sandbox)
        report = first_match(reports, alert_id=alert_id, artifact_id=artifact_id, reference=reference or sandbox or remediation)

        m1 = stage(
            "m1",
            "M1 Alerte",
            "DONE" if alert else "WAITING",
            timestamp=alert.get("timestamp") if alert else None,
            detail=alert.get("description") if alert else "Aucune alerte visible cote agent.",
        )
        m2 = quarantine_stage(record)

        sandbox_status = sandbox_stage_status(sandbox)
        if not record:
            sandbox_status = "PENDING"
            sandbox_detail = "En attente de la quarantaine M2."
        elif m2["status"] != "DONE":
            sandbox_status = "PENDING"
            sandbox_detail = "Artefact pas encore pret pour M3."
        elif sandbox:
            sandbox_detail = sandbox.get("error_message") or sandbox.get("behavior_summary") or "Resultat sandbox recu."
        else:
            sandbox_detail = "Pret pour M3, en attente du worker sandbox."
        m3 = stage(
            "m3",
            "M3 Sandbox",
            sandbox_status,
            timestamp=(sandbox or {}).get("analysis_finished_at") or (sandbox or {}).get("finished_at"),
            detail=sandbox_detail,
        )

        if m3["status"] != "DONE":
            remediation_status = "PENDING"
            remediation_detail = "En attente du resultat sandbox M3."
        elif remediation:
            remediation_status = "DONE"
            remediation_detail = remediation.get("decision") or "Plan de remediation disponible."
        else:
            remediation_status = "WAITING"
            remediation_detail = "En attente du scoring/remediation M4."
        m4 = stage(
            "m4",
            "M4 Remediation",
            remediation_status,
            timestamp=(remediation or {}).get("generated_at") or (remediation or {}).get("created_at"),
            detail=remediation_detail,
        )

        report_status_text = str((report or {}).get("status") or "").upper()
        report_path_text = str((report or {}).get("report_path") or "")
        has_final_report = bool(
            report
            and "SYNTHETIC" not in report_status_text
            and (report.get("download_url") or not report_path_text.endswith("manifest.json"))
        )
        if has_final_report:
            report_status = "DONE"
            report_detail = report.get("report_path") or report.get("status") or "Rapport disponible."
        elif m4["status"] == "DONE":
            report_status = "WAITING"
            report_detail = "Plan pret, rapport final pas encore publie."
        else:
            report_status = "PENDING"
            report_detail = "En attente de la remediation M4."
        report_stage = stage(
            "report",
            "Rapport",
            report_status,
            timestamp=(report or {}).get("timestamp") or (report or {}).get("created_at"),
            detail=report_detail,
        )

        timeline = [m1, m2, m3, m4, report_stage]
        blocked = next((item for item in timeline if item["status"] == "BLOCKED"), None)
        waiting = next((item for item in timeline if item["status"] in {"WAITING", "PENDING"}), None)
        stopped = blocked or waiting
        if blocked:
            case_status = "BLOCKED"
        elif waiting:
            case_status = "IN_PROGRESS"
        else:
            case_status = "COMPLETED"

        timestamps = [
            str(value)
            for value in (
                (alert or {}).get("timestamp"),
                (record or {}).get("created_at"),
                (sandbox or {}).get("analysis_finished_at") or (sandbox or {}).get("finished_at"),
                (remediation or {}).get("generated_at") or (remediation or {}).get("created_at"),
                (report or {}).get("timestamp") or (report or {}).get("created_at"),
            )
            if value
        ]
        cases.append(
            {
                "case_id": f"CASE-{artifact_id or alert_id or key}",
                "alert_id": alert_id or (alert or {}).get("alert_id"),
                "artifact_id": artifact_id or (record or sandbox or remediation or report or {}).get("artifact_id"),
                "filename": (
                    (record or {}).get("filename")
                    or (record or {}).get("artifact_name")
                    or (alert or {}).get("type")
                    or "artifact"
                ),
                "risk_level": (record or {}).get("risk_level") or (alert or {}).get("severity") or (remediation or {}).get("risk_level"),
                "status": case_status,
                "stopped_at": stopped.get("label") if stopped else None,
                "blocked_reason": stopped.get("detail") if stopped else None,
                "last_update": max(timestamps) if timestamps else None,
                "timeline": timeline,
            }
        )

    return sorted(cases, key=lambda item: str(item.get("last_update") or ""), reverse=True)


def _html(value: object) -> str:
    return html.escape(str(value if value is not None else "-"))


def _report_section(title: str, content: str) -> str:
    return f"<section><h2>{_html(title)}</h2>{content}</section>"


def _kv_table(rows: list[tuple[str, object]]) -> str:
    body = "".join(
        f"<tr><th>{_html(label)}</th><td>{_html(value)}</td></tr>"
        for label, value in rows
    )
    return f"<table>{body}</table>"


def _list_block(items: object, empty: str = "Aucun element observe.") -> str:
    if not isinstance(items, list) or not items:
        return f"<p class='muted'>{_html(empty)}</p>"
    return "<ul>" + "".join(f"<li>{_html(_compact_report_value(item))}</li>" for item in items[:30]) + "</ul>"


def _compact_report_value(value: object) -> str:
    if isinstance(value, dict):
        for keys in (
            ("process", "pid", "cmdline"),
            ("protocol", "remote", "port"),
            ("path", "action", "sha256"),
            ("name", "value", "status"),
        ):
            parts = [str(value.get(key)) for key in keys if value.get(key) not in (None, "")]
            if parts:
                return " | ".join(parts)
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return ", ".join(str(item) for item in value[:8])
    return str(value)


def build_dashboard_report_html(report_id: str, config: QuarantineConfig) -> tuple[str, str]:
    artifact_id = report_id[4:] if report_id.startswith("RPT-") else report_id
    records = load_ui_records(config)
    alerts = load_dashboard_alerts(config)
    sandbox_results = load_sandbox_results()
    remediations = load_remediations(config)
    cases = build_cases(config)

    record = first_match(records, artifact_id=artifact_id)
    alert_id = (record or {}).get("alert_id")
    alert = first_match(alerts, alert_id=alert_id, artifact_id=artifact_id)
    sandbox = first_match(sandbox_results, alert_id=alert_id, artifact_id=artifact_id, reference=record or alert)
    remediation = first_match(remediations, alert_id=alert_id, artifact_id=artifact_id, reference=record or alert or sandbox)
    case = first_match(cases, alert_id=alert_id, artifact_id=artifact_id, reference=record or alert or sandbox or remediation)

    filename = (
        (record or {}).get("filename")
        or (record or {}).get("artifact_name")
        or (sandbox or {}).get("artifact_name")
        or artifact_id
    )
    status = (case or {}).get("status") or "UNKNOWN"
    timeline = (case or {}).get("timeline") if isinstance((case or {}).get("timeline"), list) else []
    timeline_html = "<ol>" + "".join(
        "<li>"
        f"<strong>{_html(step.get('label'))}</strong> "
        f"<span>{_html(step.get('status'))}</span>"
        f"<p>{_html(step.get('detail'))}</p>"
        f"<em>{_html(step.get('timestamp'))}</em>"
        "</li>"
        for step in timeline
        if isinstance(step, dict)
    ) + "</ol>"

    behavior = (sandbox or {}).get("behavior_summary")
    if isinstance(behavior, dict):
        behavior_text = json.dumps(behavior, ensure_ascii=False, indent=2)
    else:
        behavior_text = str(behavior or "Aucun resume comportemental recu.")

    actions = (remediation or {}).get("actions")
    action_items = []
    if isinstance(actions, list):
        for action in actions[:20]:
            if isinstance(action, dict):
                action_items.append(
                    f"{action.get('step', '-')}. {action.get('title', 'Action')} - "
                    f"{action.get('action') or action.get('command') or action.get('status')}"
                )

    content = "\n".join(
        [
            "<!doctype html><html lang='fr'><head><meta charset='utf-8'>",
            f"<title>RootRAP Report - {_html(artifact_id)}</title>",
            "<style>",
            "body{font-family:Arial,Helvetica,sans-serif;background:#090909;color:#f3eeee;margin:32px;line-height:1.45}",
            "h1{color:#ff3b3b}h2{border-bottom:1px solid #602020;padding-bottom:6px;color:#fff}",
            "section{border:1px solid #3a1717;background:#130b0b;margin:16px 0;padding:16px}",
            "table{width:100%;border-collapse:collapse}th,td{border:1px solid #3a1717;padding:8px;text-align:left;vertical-align:top}",
            "th{width:220px;color:#b99}.badge{display:inline-block;border:1px solid #ff3b3b;color:#55ff99;padding:4px 8px}",
            "pre{white-space:pre-wrap;background:#050505;border:1px solid #3a1717;padding:12px;overflow-wrap:anywhere}",
            "li{margin:10px 0}.muted,em{color:#ad9999}",
            "</style></head><body>",
            f"<h1>RootRAP Incident Report</h1><p><span class='badge'>{_html(status)}</span></p>",
            _report_section(
                "Resume executif",
                _kv_table(
                    [
                        ("Report ID", report_id),
                        ("Artifact ID", artifact_id),
                        ("Alert ID", alert_id or (alert or {}).get("alert_id")),
                        ("Fichier", filename),
                        ("Risque", (record or {}).get("risk_level") or (remediation or {}).get("risk_level")),
                        ("Statut case", status),
                        ("Bloque a", (case or {}).get("stopped_at") or "Flux complet"),
                    ]
                ),
            ),
            _report_section("Timeline", timeline_html or "<p class='muted'>Aucune timeline disponible.</p>"),
            _report_section(
                "Quarantaine M2",
                _kv_table(
                    [
                        ("Status", (record or {}).get("status")),
                        ("Original path", (record or {}).get("original_path")),
                        ("Quarantine path", (record or {}).get("quarantine_path") or (record or {}).get("artifact_path")),
                        ("SHA256", (record or {}).get("sha256")),
                        ("Integrity", (record or {}).get("integrity_verified")),
                        ("Profile", (record or {}).get("rootkit_category")),
                    ]
                ),
            ),
            _report_section(
                "Analyse sandbox M3",
                _kv_table(
                    [
                        ("Execution", (sandbox or {}).get("execution_status") or (sandbox or {}).get("sandbox_status")),
                        ("VM", (sandbox or {}).get("vm_name") or (sandbox or {}).get("sandbox_id")),
                        ("Snapshot", (sandbox or {}).get("snapshot_name") or (sandbox or {}).get("snapshot_used")),
                        ("Exit code", (sandbox or {}).get("exit_code")),
                        ("Started", (sandbox or {}).get("started_at") or (sandbox or {}).get("analysis_started_at")),
                        ("Finished", (sandbox or {}).get("finished_at") or (sandbox or {}).get("analysis_finished_at")),
                    ]
                )
                + f"<h3>Resume comportemental</h3><pre>{_html(behavior_text)}</pre>"
                + "<h3>Processus observes</h3>"
                + _list_block((sandbox or {}).get("observed_processes") or (sandbox or {}).get("processes_created"))
                + "<h3>Connexions reseau</h3>"
                + _list_block((sandbox or {}).get("network_events") or (sandbox or {}).get("network_connections"))
                + "<h3>Fichiers crees/modifies</h3>"
                + _list_block(((sandbox or {}).get("files_created") or []) + ((sandbox or {}).get("files_modified") or [])),
            ),
            _report_section(
                "Remediation",
                _kv_table(
                    [
                        ("Decision", (remediation or {}).get("decision")),
                        ("Risk score", (remediation or {}).get("risk_score")),
                        ("Human validation", (remediation or {}).get("requires_human_validation")),
                    ]
                )
                + _list_block(action_items, "Aucune action de remediation disponible."),
            ),
            "</body></html>",
        ]
    )

    safe_name = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(artifact_id))
    return content, f"rootrap-report-{safe_name}.html"


def configured_m4_backend_url() -> str:
    return os.getenv("ROOTKIT_DEFENSE_M4_URL", DEFAULT_M4_BACKEND_URL).rstrip("/")


def load_remote_json(url: str, *, timeout: float = 5.0) -> tuple[dict[str, object] | list[object] | None, str | None]:
    request = Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            return json.loads(body) if body else {}, None
    except Exception as exc:  # network health check must return diagnostics, not crash the UI
        return None, str(exc)


def systemd_service_status(service_name: str) -> str | None:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service_name],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return None
    return (result.stdout or result.stderr).strip() or "unknown"


def build_boot_checks(config: QuarantineConfig) -> dict[str, object]:
    root = repo_root()
    backend_url = configured_m4_backend_url()
    checks: list[dict[str, object]] = []

    agent_files = [
        root / "agent" / "main.py",
        root / "agent" / "monitor_processes.py",
        root / "agent" / "monitor_kernel.py",
        root / "agent" / "monitor_files.py",
        root / "agent" / "monitor_network.py",
    ]
    service_state = systemd_service_status("rootrap-agent.service") or systemd_service_status("rootkit-agent.service")
    missing_agent_files = [str(path.relative_to(root)) for path in agent_files if not path.exists()]
    alerts_count = len(load_dashboard_alerts(config))
    if service_state == "active":
        m1_status = "OK"
        m1_line = f"rootrap-agent.service active; {alerts_count} local alert(s) visible"
    elif not missing_agent_files:
        m1_status = "WARN"
        m1_line = "agent modules installed; systemd service not active in this runtime"
    else:
        m1_status = "FAIL"
        m1_line = "agent monitor files missing"
    checks.append(
        {
            "id": "m1",
            "label": "kernel monitor",
            "status": m1_status,
            "line": m1_line,
            "details": {
                "service_state": service_state,
                "alerts_count": alerts_count,
                "missing_files": missing_agent_files,
            },
        }
    )

    manager = QuarantineManager(config)
    m2_service_state = systemd_service_status("rootrap-m2-worker.service")
    quarantine_records = manager.list_evidence()
    quarantine_ready = [
        record for record in quarantine_records
        if record.get("status") == "READY_FOR_ANALYSIS"
        and record.get("integrity_verified") is True
        and record.get("ready_for_sandbox") is True
    ]
    if m2_service_state == "active" and config.quarantine_dir.exists():
        m2_status = "OK"
    elif config.quarantine_dir.exists():
        m2_status = "WARN"
    else:
        m2_status = "FAIL"
    checks.append(
        {
            "id": "m2",
            "label": "quarantine vault",
            "status": m2_status,
            "line": (
                f"M2 worker={m2_service_state or 'unknown'}; {len(quarantine_ready)} ready artifact(s), "
                f"{len(quarantine_records)} total record(s)"
            ),
            "details": {
                "service_state": m2_service_state,
                "storage_root": str(config.storage_root),
                "index_file": str(config.index_file),
                "ready_records": len(quarantine_ready),
                "total_records": len(quarantine_records),
            },
        }
    )

    sandbox_payload, sandbox_error = load_remote_json(f"{backend_url}/api/sandbox/results")
    local_sandbox_count = len(load_sandbox_results())
    remote_sandbox_count = 0
    if isinstance(sandbox_payload, dict):
        remote_sandbox_count = int(sandbox_payload.get("count") or len(sandbox_payload.get("results") or []))
    if sandbox_error:
        m3_status = "WARN" if local_sandbox_count else "FAIL"
        m3_line = f"sandbox endpoint unavailable; {local_sandbox_count} local result(s)"
    else:
        m3_status = "OK"
        m3_line = f"M3 sandbox bridge reachable; {remote_sandbox_count} remote result(s)"
    checks.append(
        {
            "id": "m3",
            "label": "sandbox bridge",
            "status": m3_status,
            "line": m3_line,
            "details": {
                "backend_url": backend_url,
                "remote_results": remote_sandbox_count,
                "local_results": local_sandbox_count,
                "error": sandbox_error,
            },
        }
    )

    home_payload, home_error = load_remote_json(f"{backend_url}/")
    ready_payload, ready_error = load_remote_json(f"{backend_url}/api/quarantine/ready")
    ready_count = 0
    if isinstance(ready_payload, dict):
        ready_count = int(ready_payload.get("count") or len(ready_payload.get("artifacts") or []))
    if home_error or ready_error:
        m4_status = "FAIL"
        m4_line = "M4 backend unreachable"
    else:
        m4_status = "OK"
        m4_line = f"M4 backend reachable; {ready_count} ready artifact(s)"
    checks.append(
        {
            "id": "m4",
            "label": "ioc reporting",
            "status": m4_status,
            "line": m4_line,
            "details": {
                "backend_url": backend_url,
                "home": home_payload,
                "ready_artifacts": ready_count,
                "home_error": home_error,
                "ready_error": ready_error,
            },
        }
    )

    checks.append(
        {
            "id": "ui",
            "label": "dashboard api",
            "status": "OK",
            "line": "/api/boot/checks responsive; live SOC dashboard armed",
            "details": {"web_dir": str(default_web_dir())},
        }
    )

    return {
        "status": "OK" if all(check["status"] == "OK" for check in checks) else "WARN",
        "backend_url": backend_url,
        "checks": checks,
    }


def create_handler(config: QuarantineConfig, web_dir: Path) -> type[BaseHTTPRequestHandler]:
    web_root = web_dir.resolve()

    class RootkitDefenseUIHandler(BaseHTTPRequestHandler):
        server_version = "RootkitDefenseUI/1.0"

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            parsed = urlparse(self.path)
            if parsed.path == "/api/health":
                self._json(
                    {
                        "status": "ok",
                        "service": "rootkit-defense-ui",
                        "modules": ["agent", "quarantine", "sandbox", "analyzer"],
                        "m4_backend_url": configured_m4_backend_url(),
                    }
                )
                return
            if parsed.path == "/api/boot/checks":
                self._json(build_boot_checks(config))
                return
            if parsed.path == "/api/alerts":
                self._json(load_dashboard_alerts(config))
                return
            if parsed.path == "/api/quarantine":
                self._json(load_ui_records(config))
                return
            if parsed.path == "/api/sandbox/results":
                self._json({"count": len(load_sandbox_results()), "results": load_sandbox_results()})
                return
            if parsed.path == "/api/reports":
                self._json({"count": len(load_reports()), "reports": load_reports()})
                return
            if parsed.path.startswith("/api/reports/"):
                if self._reports_api(parsed.path, config):
                    return
                self._not_found()
                return
            if parsed.path == "/api/remediation":
                remediations = load_remediations(config)
                self._json({"count": len(remediations), "remediations": remediations})
                return
            if parsed.path == "/api/cases":
                cases = build_cases(config)
                self._json({"count": len(cases), "cases": cases})
                return
            if parsed.path.startswith("/api/quarantine/"):
                if self._quarantine_api(parsed.path, config):
                    return
                self._not_found()
                return
            self._static(parsed.path)

        def log_message(self, format: str, *args: object) -> None:
            return

        def _json(self, payload: object, status: int = 200) -> None:
            body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _static(self, requested_path: str) -> None:
            safe_path = unquote(requested_path).lstrip("/") or "index.html"
            candidate = (web_root / safe_path).resolve()
            try:
                candidate.relative_to(web_root)
            except ValueError:
                self._not_found()
                return
            if not candidate.exists() or candidate.is_dir():
                self._not_found()
                return

            content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
            body = candidate.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _quarantine_api(self, path: str, config: QuarantineConfig) -> bool:
            parts = [part for part in path.split("/") if part]
            if len(parts) != 4 or parts[0] != "api" or parts[1] != "quarantine":
                return False

            alert_id = unquote(parts[2])
            action = parts[3]
            manager = QuarantineManager(config)
            record = manager.get_evidence(alert_id)
            if record is None:
                self._json({"error": "alert_id not found", "alert_id": alert_id}, status=404)
                return True

            if action == "manifest":
                self._json(
                    build_quarantine_manifest(
                        dict(record),
                        download_url=f"/api/quarantine/{alert_id}/download",
                    )
                )
                return True

            if action == "handoff":
                if not record.get("ready_for_sandbox"):
                    self._json({"error": "evidence not ready for sandbox"}, status=409)
                    return True
                self._json(
                    {
                        "alert_id": alert_id,
                        "artifact_id": record.get("artifact_id"),
                        "quarantine_path": record.get("quarantine_path") or record.get("artifact_path"),
                        "filename": record.get("filename") or record.get("artifact_name"),
                        "sha256": record.get("sha256"),
                        "download_url": f"/api/quarantine/{alert_id}/download",
                        "handoff_status": "READY_FOR_SANDBOX",
                    }
                )
                return True

            if action == "download":
                artifact_path = record.get("artifact_path") or record.get("quarantine_path")
                if not artifact_path:
                    self._json({"error": "artifact path missing"}, status=404)
                    return True
                path_obj = Path(str(artifact_path))
                if not path_obj.exists() or not path_obj.is_file():
                    self._json({"error": "artifact not found"}, status=404)
                    return True
                body = path_obj.read_bytes()
                filename = record.get("filename") or record.get("artifact_name") or "artifact.bin"
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return True

            return False

        def _reports_api(self, path: str, config: QuarantineConfig) -> bool:
            parts = [part for part in path.split("/") if part]
            if len(parts) != 4 or parts[0] != "api" or parts[1] != "reports" or parts[3] != "download":
                return False

            report_id = unquote(parts[2])
            body, filename = build_dashboard_report_html(report_id, config)
            encoded = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(encoded)
            return True

        def _not_found(self) -> None:
            body = b"Not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return RootkitDefenseUIHandler


def run_ui_server(
    config: QuarantineConfig,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    open_browser: bool = True,
    web_dir: Path | None = None,
) -> None:
    static_dir = (web_dir or default_web_dir()).resolve()
    handler = create_handler(config, static_dir)
    server = ThreadingHTTPServer((host, port), handler)
    url = f"http://{host}:{server.server_port}/"
    print(f"Rootkit Defense Agent UI: {url}")
    print(f"Storage root: {config.storage_root}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping UI server.")
    finally:
        server.server_close()
