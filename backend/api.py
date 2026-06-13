from datetime import datetime
import hashlib
import json
import os
import shutil
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from analysis.static_analyzer import analyze_file
from analysis.report_generator import generate_html_report
from analysis.remediation import build_remediation_plan

app = FastAPI(title="Rootkit Defense Agent API - M4")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB_DIR = PROJECT_ROOT / "web"
STATIC_DIR = WEB_DIR / "static"

if STATIC_DIR.exists() and not any(route.path == "/static" for route in app.routes):
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

DATA_DIR = PROJECT_ROOT / "backend" / "data"
ALERTS_FILE = os.path.join(DATA_DIR, "alerts.json")
QUARANTINE_FILE = os.path.join(DATA_DIR, "quarantine.json")
REPORTS_FILE = os.path.join(DATA_DIR, "reports.json")
UPLOAD_QUARANTINE_DIR = PROJECT_ROOT / "uploads" / "quarantine"
GENERATED_REPORTS_DIR = PROJECT_ROOT / "reports" / "generated"
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
ROOTRAP_QUARANTINE_DIR = Path(
    os.getenv("ROOTRAP_M4_QUARANTINE_DIR", "/var/lib/rootrap/quarantine")
)

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UPLOAD_QUARANTINE_DIR, exist_ok=True)
os.makedirs(GENERATED_REPORTS_DIR, exist_ok=True)
os.makedirs(ARTIFACTS_DIR, exist_ok=True)


class Alert(BaseModel):
    alert_id: Optional[str] = None
    timestamp: Optional[str] = None
    source_module: str
    severity: str
    type: str
    description: str
    details: Dict[str, Any] = {}
    status: str = "NEW"


def load_json(path):
    if not os.path.exists(path):
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def resolve_local_path(path_value):
    if not path_value:
        return None

    path = Path(path_value)
    if not path.is_absolute():
        path = PROJECT_ROOT / path

    return path


def calculate_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json_object(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return payload if isinstance(payload, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def canonical_quarantine_download_url(artifact_id: str) -> str:
    return f"/api/quarantine/{artifact_id}/download"


def source_download_url(artifact: dict[str, Any]) -> str | None:
    artifact_id = artifact.get("artifact_id")
    value = artifact.get("download_url")
    if not value:
        return None
    value = str(value)
    if artifact_id and value == canonical_quarantine_download_url(str(artifact_id)):
        return None
    return value


def rootrap_quarantine_records(root: Path | None = None) -> list[dict[str, Any]]:
    root = root or ROOTRAP_QUARANTINE_DIR
    if not root.exists():
        return []

    records_by_artifact_id: dict[str, dict[str, Any]] = {}
    for evidence_dir in sorted(root.iterdir()):
        if not evidence_dir.is_dir():
            continue

        artifact_file = evidence_dir / "artifact.bin"
        if not artifact_file.exists() or not artifact_file.is_file():
            continue

        metadata_path = evidence_dir / "metadata.json"
        hashes_path = evidence_dir / "hashes.json"
        manifest_path = evidence_dir / "manifest.json"
        metadata = read_json_object(metadata_path)
        profile = metadata.get("rootkit_profile") if isinstance(metadata.get("rootkit_profile"), dict) else {}
        alert_id = str(metadata.get("alert_id") or evidence_dir.name)
        artifact_id = str(metadata.get("artifact_id") or f"ART-{alert_id}")
        actual_sha256 = calculate_sha256(artifact_file)

        records_by_artifact_id[artifact_id] = {
            "artifact_id": artifact_id,
            "alert_id": alert_id,
            "filename": metadata.get("artifact_name") or metadata.get("filename") or artifact_file.name,
            "original_filename": metadata.get("artifact_name") or artifact_file.name,
            "sha256": actual_sha256,
            "md5": None,
            "sha1": None,
            "original_path": metadata.get("original_path"),
            "stored_path": str(artifact_file),
            "quarantine_path": str(artifact_file),
            "metadata_path": str(metadata_path) if metadata_path.exists() else None,
            "hashes_path": str(hashes_path) if hashes_path.exists() else None,
            "manifest_path": str(manifest_path) if manifest_path.exists() else None,
            "rootkit_category": profile.get("category") or metadata.get("rootkit_category"),
            "risk_level": metadata.get("risk_level"),
            "status": "READY_FOR_ANALYSIS",
            "integrity_verified": True,
            "ready_for_sandbox": True,
            "created_at": metadata.get("quarantined_at") or metadata.get("detected_at"),
            "source": "ROOTRAP_LOCAL_QUARANTINE_DIR",
            "download_integrity_status": "VERIFIED_LOCAL",
        }

    return list(records_by_artifact_id.values())


def merge_quarantine_sources(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {
        str(item.get("artifact_id")): dict(item)
        for item in artifacts
        if item.get("artifact_id")
    }

    for local_record in rootrap_quarantine_records():
        artifact_id = str(local_record.get("artifact_id"))
        existing = merged.get(artifact_id)
        if existing and source_download_url(existing):
            continue
        if existing and existing.get("sha256") and existing.get("sha256") != local_record.get("sha256"):
            local_record["manifest_sha256"] = existing.get("sha256")
        merged[artifact_id] = {**(existing or {}), **local_record}

    return list(merged.values())


def local_artifact_candidates(artifact: dict[str, Any]) -> list[Path]:
    candidates: list[Path] = []
    for key in ("stored_path", "quarantine_path"):
        path = resolve_local_path(artifact.get(key))
        if path and path.exists() and path.is_file() and path not in candidates:
            candidates.append(path)

    alert_id = artifact.get("alert_id")
    if alert_id:
        artifact_dir = ARTIFACTS_DIR / str(alert_id)
        if artifact_dir.exists():
            for candidate in sorted(artifact_dir.iterdir()):
                if candidate.is_file() and candidate not in candidates:
                    candidates.append(candidate)

    return candidates


def select_downloadable_local_artifact(artifact: dict[str, Any]) -> tuple[Path | None, str | None, list[dict[str, str]]]:
    expected_sha256 = str(artifact.get("sha256") or "").lower()
    mismatches: list[dict[str, str]] = []
    first_existing: tuple[Path, str] | None = None

    for candidate in local_artifact_candidates(artifact):
        actual_sha256 = calculate_sha256(candidate)
        if first_existing is None:
            first_existing = (candidate, actual_sha256)
        if not expected_sha256 or actual_sha256 == expected_sha256:
            return candidate, actual_sha256, mismatches
        mismatches.append(
            {
                "path": str(candidate),
                "expected_sha256": expected_sha256,
                "actual_sha256": actual_sha256,
            }
        )

    if first_existing and not expected_sha256:
        return first_existing[0], first_existing[1], mismatches

    return None, None, mismatches


def risk_score_from_level(risk_level: str | None) -> int:
    mapping = {
        "CRITICAL": 92,
        "HIGH": 78,
        "MEDIUM": 48,
        "LOW": 20,
    }
    return mapping.get(str(risk_level or "").upper(), 50)


def artifact_for_remediation(artifact: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(artifact)
    analysis = enriched.get("analysis") if isinstance(enriched.get("analysis"), dict) else {}
    if not analysis:
        risk_level = str(enriched.get("risk_level") or "MEDIUM").upper()
        analysis = {
            "risk_level": risk_level,
            "risk_score": risk_score_from_level(risk_level),
            "iocs": {
                "paths": [enriched.get("original_path")] if enriched.get("original_path") else [],
                "hashes": [enriched.get("sha256")] if enriched.get("sha256") else [],
            },
            "yara_matches": [],
        }

    if enriched.get("sandbox_result"):
        analysis.setdefault("sandbox_result", enriched.get("sandbox_result"))
    if enriched.get("rootkit_category"):
        analysis.setdefault("rootkit_category", enriched.get("rootkit_category"))

    enriched["analysis"] = analysis
    return enriched


def synthetic_report_for_artifact(artifact: dict[str, Any]) -> dict[str, Any]:
    risk_level = str(artifact.get("risk_level") or artifact.get("analysis", {}).get("risk_level") or "MEDIUM").upper()
    artifact_id = artifact.get("artifact_id")
    report_id = f"RPT-{artifact_id}"
    return {
        "report_id": report_id,
        "artifact_id": artifact_id,
        "alert_id": artifact.get("alert_id"),
        "timestamp": artifact.get("created_at") or artifact.get("received_by_backend_at") or datetime.utcnow().isoformat() + "Z",
        "risk_score": artifact.get("risk_score") or risk_score_from_level(risk_level),
        "risk_level": risk_level,
        "status": "INCIDENT_REPORT_READY",
        "summary": "Operational report generated from quarantine, sandbox and remediation data.",
        "report_path": None,
        "pdf_report_path": None,
        "download_url": f"/api/reports/{report_id}/download",
    }


def synthetic_report_summaries() -> list[dict[str, Any]]:
    artifacts = merge_quarantine_sources(load_json(QUARANTINE_FILE))
    sandbox_results = load_json(SANDBOX_RESULTS_FILE)
    sandbox_by_artifact = {
        item.get("artifact_id"): item
        for item in sandbox_results
        if isinstance(item, dict) and item.get("artifact_id")
    }

    reports = []
    for artifact in artifacts:
        artifact = dict(artifact)
        if artifact.get("artifact_id") in sandbox_by_artifact:
            artifact["sandbox_result"] = sandbox_by_artifact[artifact.get("artifact_id")]
        reports.append(synthetic_report_for_artifact(artifact_for_remediation(artifact)))
    return reports


@app.get("/")
def home():
    return {
        "project": "Rootkit Defense Agent",
        "member": "M4",
        "status": "Backend running"
    }


@app.post("/api/alerts")
def receive_alert(alert: Alert):
    alerts = load_json(ALERTS_FILE)

    alert_dict = alert.model_dump()

    if not alert_dict.get("alert_id"):
        alert_dict["alert_id"] = str(uuid.uuid4())

    if not alert_dict.get("timestamp"):
        alert_dict["timestamp"] = datetime.utcnow().isoformat() + "Z"

    alerts.append(alert_dict)
    save_json(ALERTS_FILE, alerts)

    return {
        "message": "Alert received successfully",
        "alert_id": alert_dict["alert_id"]
    }


@app.get("/api/alerts")
def get_alerts(status: Optional[str] = Query(None)):
    alerts = load_json(ALERTS_FILE)

    if status:
        alerts = [a for a in alerts if a.get("status") == status]

    return {
        "count": len(alerts),
        "alerts": alerts
    }


@app.patch("/api/alerts/{alert_id}/status")
def update_alert_status(alert_id: str, status: str):
    alerts = load_json(ALERTS_FILE)

    for alert in alerts:
        if alert.get("alert_id") == alert_id:
            alert["status"] = status
            save_json(ALERTS_FILE, alerts)
            return {
                "message": "Status updated",
                "alert_id": alert_id,
                "status": status
            }

    raise HTTPException(status_code=404, detail="Alert not found")


@app.post("/api/quarantine")
def upload_quarantined_artifact(
    alert_id: str,
    file: UploadFile = File(...)
):
    artifact_id = str(uuid.uuid4())
    filename = f"{artifact_id}_{file.filename}"
    file_path = UPLOAD_QUARANTINE_DIR / filename

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    artifacts = load_json(QUARANTINE_FILE)

    artifact = {
        "artifact_id": artifact_id,
        "alert_id": alert_id,
        "original_filename": file.filename,
        "stored_path": str(file_path),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "status": "QUARANTINED"
    }

    artifacts.append(artifact)
    save_json(QUARANTINE_FILE, artifacts)

    return {
        "message": "Artifact uploaded to quarantine",
        "artifact": artifact
    }


@app.get("/api/quarantine")
def get_quarantine():
    artifacts = merge_quarantine_sources(load_json(QUARANTINE_FILE))

    return {
        "count": len(artifacts),
        "artifacts": artifacts
    }


@app.post("/api/analyze/{artifact_id}")
def analyze_artifact(artifact_id: str):
    artifacts = load_json(QUARANTINE_FILE)

    artifact = next(
        (a for a in artifacts if a.get("artifact_id") == artifact_id),
        None
    )

    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")

    file_path = resolve_local_path(artifact.get("stored_path"))

    if not file_path or not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found on server")

    analysis_result = analyze_file(str(file_path), artifact_id=artifact_id, alert_id=artifact.get("alert_id"))
    report_path = generate_html_report(artifact, analysis_result)

    reports = load_json(REPORTS_FILE)

    report = {
        "report_id": str(uuid.uuid4()),
        "artifact_id": artifact_id,
        "alert_id": artifact["alert_id"],
        "report_path": report_path.get("html_report") if isinstance(report_path, dict) else report_path,
        "pdf_report_path": report_path.get("pdf_report") if isinstance(report_path, dict) else None,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "risk_score": analysis_result.get("risk_score"),
        "risk_level": analysis_result.get("risk_level")
    }

    reports.append(report)
    save_json(REPORTS_FILE, reports)

    artifact["status"] = "ANALYZED"
    artifact["analysis"] = analysis_result
    save_json(QUARANTINE_FILE, artifacts)

    return {
        "message": "Analysis completed",
        "artifact_id": artifact_id,
        "analysis": analysis_result,
        "report": report
    }


@app.get("/api/reports")
def get_reports():
    reports = load_json(REPORTS_FILE)
    if not reports:
        reports = synthetic_report_summaries()

    return {
        "count": len(reports),
        "reports": reports
    }


def html_escape(value: Any) -> str:
    import html

    return html.escape(str(value if value is not None else "-"))


def report_kv(rows: list[tuple[str, Any]]) -> str:
    body = "".join(
        f"<tr><th>{html_escape(label)}</th><td>{html_escape(value)}</td></tr>"
        for label, value in rows
    )
    return f"<table>{body}</table>"


def report_list(items: Any, empty: str = "Aucun element disponible.") -> str:
    if not isinstance(items, list) or not items:
        return f"<p class='muted'>{html_escape(empty)}</p>"
    return "<ul>" + "".join(f"<li>{html_escape(item)}</li>" for item in items[:30]) + "</ul>"


def report_pre(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, ensure_ascii=False, indent=2)
    return f"<pre>{html_escape(value)}</pre>"


def build_incident_report_html(report_id: str) -> tuple[str, str]:
    artifact_id = report_id[4:] if report_id.startswith("RPT-") else report_id
    artifacts = merge_quarantine_sources(load_json(QUARANTINE_FILE))
    artifact = next((item for item in artifacts if item.get("artifact_id") == artifact_id), None)
    if not artifact:
        raise HTTPException(status_code=404, detail="Report artifact not found")

    sandbox_results = [
        item for item in load_json(SANDBOX_RESULTS_FILE)
        if isinstance(item, dict) and item.get("artifact_id") == artifact_id
    ]
    sandbox = sandbox_results[-1] if sandbox_results else {}
    enriched = dict(artifact)
    if sandbox:
        enriched["sandbox_result"] = sandbox
    remediation = build_remediation_plan(artifact_for_remediation(enriched))
    behavior = sandbox.get("behavior_summary") or "Aucun resultat sandbox recu pour cet artefact."

    html_body = "\n".join(
        [
            "<!doctype html><html lang='fr'><head><meta charset='utf-8'>",
            f"<title>RootRAP Report - {html_escape(artifact_id)}</title>",
            "<style>",
            "body{font-family:Arial,Helvetica,sans-serif;background:#090909;color:#f4eeee;margin:32px;line-height:1.45}",
            "h1{color:#ff3b3b}h2{border-bottom:1px solid #5a1b1b;padding-bottom:6px;color:#fff}",
            "section{border:1px solid #3a1717;background:#130b0b;margin:16px 0;padding:16px}",
            "table{width:100%;border-collapse:collapse}th,td{border:1px solid #3a1717;padding:8px;text-align:left;vertical-align:top}",
            "th{width:230px;color:#b99}.badge{display:inline-block;border:1px solid #ff3b3b;color:#55ff99;padding:4px 8px}",
            "pre{white-space:pre-wrap;background:#050505;border:1px solid #3a1717;padding:12px;overflow-wrap:anywhere}.muted,em{color:#ad9999}",
            "</style></head><body>",
            "<h1>RootRAP Incident Report</h1>",
            f"<p><span class='badge'>{html_escape(remediation.get('risk_level'))}</span></p>",
            "<section><h2>Resume executif</h2>"
            + report_kv(
                [
                    ("Report ID", report_id),
                    ("Artifact ID", artifact_id),
                    ("Alert ID", artifact.get("alert_id")),
                    ("Fichier", artifact.get("filename") or artifact.get("artifact_name")),
                    ("Risque", remediation.get("risk_level")),
                    ("Score", remediation.get("risk_score")),
                    ("Decision", remediation.get("decision")),
                ]
            )
            + "</section>",
            "<section><h2>Quarantaine M2</h2>"
            + report_kv(
                [
                    ("Status", artifact.get("status")),
                    ("Original path", artifact.get("original_path")),
                    ("Quarantine path", artifact.get("quarantine_path") or artifact.get("stored_path")),
                    ("SHA256", artifact.get("sha256")),
                    ("Integrity", artifact.get("integrity_verified")),
                    ("Ready for sandbox", artifact.get("ready_for_sandbox")),
                ]
            )
            + "</section>",
            "<section><h2>Analyse sandbox M3</h2>"
            + report_kv(
                [
                    ("Execution", sandbox.get("execution_status") or sandbox.get("sandbox_status")),
                    ("VM", sandbox.get("vm_name") or sandbox.get("sandbox_id")),
                    ("Snapshot", sandbox.get("snapshot_name") or sandbox.get("snapshot_used")),
                    ("Exit code", sandbox.get("exit_code")),
                    ("Started", sandbox.get("started_at") or sandbox.get("analysis_started_at")),
                    ("Finished", sandbox.get("finished_at") or sandbox.get("analysis_finished_at")),
                ]
            )
            + "<h3>Resume comportemental</h3>"
            + report_pre(behavior)
            + "<h3>Processus observes</h3>"
            + report_list(sandbox.get("observed_processes") or sandbox.get("processes_created"))
            + "<h3>Connexions reseau</h3>"
            + report_list(sandbox.get("network_events") or sandbox.get("network_connections"))
            + "<h3>Fichiers crees/modifies</h3>"
            + report_list((sandbox.get("files_created") or []) + (sandbox.get("files_modified") or []))
            + "</section>",
            "<section><h2>Remediation AI</h2>"
            + report_kv(
                [
                    ("Validation humaine", remediation.get("requires_human_validation")),
                    ("Suppression automatique", remediation.get("automatic_deletion")),
                ]
            )
            + report_list(
                [
                    f"{action.get('step', '-')}. {action.get('title', 'Action')} - {action.get('action') or action.get('command')}"
                    for action in remediation.get("actions", [])
                    if isinstance(action, dict)
                ],
                "Aucune action de remediation disponible.",
            )
            + "</section>",
            "</body></html>",
        ]
    )

    safe_name = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(artifact_id))
    return html_body, f"rootrap-report-{safe_name}.html"


@app.get("/api/reports/{report_id}/download", response_class=HTMLResponse)
def download_report(report_id: str):
    reports = load_json(REPORTS_FILE)
    report = next((item for item in reports if isinstance(item, dict) and item.get("report_id") == report_id), None)
    report_path = report.get("report_path") if isinstance(report, dict) else None
    if report_path:
        path = Path(str(report_path))
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        if path.exists() and path.is_file():
            return FileResponse(str(path), media_type="text/html", filename=path.name)

    body, filename = build_incident_report_html(report_id)
    return HTMLResponse(
        content=body,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/remediation")
def list_remediation_items():
    artifacts = merge_quarantine_sources(load_json(QUARANTINE_FILE))
    sandbox_results = load_json(SANDBOX_RESULTS_FILE)
    sandbox_by_artifact = {
        item.get("artifact_id"): item
        for item in sandbox_results
        if isinstance(item, dict) and item.get("artifact_id")
    }

    remediations = []
    for artifact in artifacts:
        artifact = dict(artifact)
        if artifact.get("artifact_id") in sandbox_by_artifact:
            artifact["sandbox_result"] = sandbox_by_artifact[artifact.get("artifact_id")]
        remediations.append(build_remediation_plan(artifact_for_remediation(artifact)))

    return {
        "count": len(remediations),
        "remediations": remediations
    }


@app.get("/api/remediation/{artifact_id}")
def get_remediation_plan(artifact_id: str):
    artifacts = merge_quarantine_sources(load_json(QUARANTINE_FILE))

    artifact = next(
        (a for a in artifacts if a.get("artifact_id") == artifact_id),
        None
    )

    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")

    sandbox_results = load_json(SANDBOX_RESULTS_FILE)
    sandbox_result = next(
        (
            item for item in sandbox_results
            if isinstance(item, dict) and item.get("artifact_id") == artifact_id
        ),
        None
    )
    if sandbox_result:
        artifact = dict(artifact)
        artifact["sandbox_result"] = sandbox_result

    remediation_plan = build_remediation_plan(artifact_for_remediation(artifact))

    return {
        "message": "Remediation plan generated",
        "remediation": remediation_plan
    }


# ============================================================
# M4 Integration with M2 Quarantine Manager
# ============================================================

class QuarantineManifest(BaseModel):
    artifact_id: str
    alert_id: str
    filename: str
    sha256: str
    md5: Optional[str] = None
    sha1: Optional[str] = None
    original_path: Optional[str] = None
    quarantine_path: str
    stored_path: Optional[str] = None
    metadata_path: Optional[str] = None
    hashes_path: Optional[str] = None
    manifest_path: Optional[str] = None
    download_url: Optional[str] = None
    rootkit_category: Optional[str] = None
    status: str = "READY_FOR_ANALYSIS"
    integrity_verified: bool = True
    ready_for_sandbox: bool = True
    created_at: Optional[str] = None


@app.post("/api/quarantine/manifest")
def receive_quarantine_manifest(manifest: QuarantineManifest):
    artifacts = load_json(QUARANTINE_FILE)

    manifest_dict = manifest.model_dump()

    if not manifest_dict.get("created_at"):
        manifest_dict["created_at"] = datetime.utcnow().isoformat() + "Z"

    manifest_dict["received_by_backend_at"] = datetime.utcnow().isoformat() + "Z"
    manifest_dict["source"] = "M2_QUARANTINE_MANAGER"

    existing = next(
        (a for a in artifacts if a.get("artifact_id") == manifest.artifact_id),
        None
    )

    if existing:
        existing.update(manifest_dict)
    else:
        artifacts.append(manifest_dict)

    save_json(QUARANTINE_FILE, artifacts)

    return {
        "message": "M2 quarantine manifest received successfully",
        "artifact": manifest_dict
   }

@app.get("/api/quarantine/ready")
def get_ready_quarantine_artifacts():
    artifacts = merge_quarantine_sources(load_json(QUARANTINE_FILE))

    ready_artifacts = []

    for artifact in artifacts:
        is_ready = (
            artifact.get("status") == "READY_FOR_ANALYSIS"
            or artifact.get("ready_for_sandbox") is True
        )

        if is_ready:
            artifact_id = artifact.get("artifact_id")
            if not artifact_id:
                continue

            download_url = canonical_quarantine_download_url(str(artifact_id))
            local_file, actual_sha256, mismatches = select_downloadable_local_artifact(artifact)
            external_source = source_download_url(artifact)

            if local_file:
                exposed_sha256 = actual_sha256 or artifact.get("sha256")
                download_integrity_status = "VERIFIED_LOCAL"
            elif external_source:
                exposed_sha256 = artifact.get("sha256")
                download_integrity_status = "REDIRECT_SOURCE"
            else:
                artifact["ready_for_sandbox"] = False
                artifact["integrity_verified"] = False
                artifact["status"] = "INTEGRITY_FAILED"
                artifact["download_integrity_error"] = (
                    "No downloadable artifact matches the manifest SHA256"
                )
                artifact["download_hash_mismatches"] = mismatches
                continue

            ready_artifacts.append({
                "artifact_id": artifact.get("artifact_id"),
                "alert_id": artifact.get("alert_id"),
                "filename": artifact.get("filename") or artifact.get("original_filename"),
                "sha256": exposed_sha256,
                "download_url": download_url,
                "status": artifact.get("status", "READY_FOR_ANALYSIS"),
                "integrity_verified": artifact.get("integrity_verified", False),
                "ready_for_sandbox": artifact.get("ready_for_sandbox", False),
                "quarantine_path": artifact.get("quarantine_path") or artifact.get("stored_path"),
                "metadata_path": artifact.get("metadata_path"),
                "hashes_path": artifact.get("hashes_path"),
                "manifest_path": artifact.get("manifest_path"),
                "download_integrity_status": download_integrity_status,
            })

    save_json(QUARANTINE_FILE, artifacts)

    return {
        "count": len(ready_artifacts),
        "artifacts": ready_artifacts
    }

# ============================================================
# M4 Integration with M3 Sandbox Analysis
# ============================================================

SANDBOX_RESULTS_FILE = os.path.join(DATA_DIR, "sandbox_results.json")


class SandboxResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    artifact_id: str
    alert_id: Optional[str] = None
    sandbox_id: Optional[str] = None
    execution_status: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    analysis_id: Optional[str] = None
    analysis_started_at: Optional[str] = None
    analysis_finished_at: Optional[str] = None
    vm_name: Optional[str] = None
    snapshot_name: Optional[str] = None
    artifact_name: Optional[str] = None
    artifact_sha256: Optional[str] = None
    exit_code: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    strace_excerpt: Optional[str] = None
    logs_path: Optional[str] = None
    stdout_path: Optional[str] = None
    stderr_path: Optional[str] = None
    strace_path: Optional[str] = None
    error_message: Optional[str] = None
    file_events: dict = Field(default_factory=dict)
    network_events: list = Field(default_factory=list)
    observed_processes: list = Field(default_factory=list)
    processes_created: list = Field(default_factory=list)
    files_created: list = Field(default_factory=list)
    files_modified: list = Field(default_factory=list)
    network_connections: list = Field(default_factory=list)
    persistence_indicators: list = Field(default_factory=list)
    behavior_summary: Optional[str] = None
    risk_observations: list = Field(default_factory=list)


@app.post("/api/sandbox/results")
def receive_sandbox_results(result: SandboxResult):
    results = load_json(SANDBOX_RESULTS_FILE)

    result_dict = result.model_dump()
    result_dict["received_at"] = datetime.utcnow().isoformat() + "Z"

    results.append(result_dict)
    save_json(SANDBOX_RESULTS_FILE, results)

    artifacts = load_json(QUARANTINE_FILE)

    for artifact in artifacts:
        if artifact.get("artifact_id") == result.artifact_id:
            artifact["sandbox_status"] = "RESULT_RECEIVED"
            artifact["sandbox_result"] = result_dict

    save_json(QUARANTINE_FILE, artifacts)

    return {
        "message": "Sandbox result received successfully",
        "artifact_id": result.artifact_id,
        "sandbox_result": result_dict
    }


@app.get("/api/sandbox/results")
def get_sandbox_results():
    results = load_json(SANDBOX_RESULTS_FILE)

    return {
        "count": len(results),
        "results": results
    }


@app.get("/api/sandbox/results/{artifact_id}")
def get_sandbox_result_by_artifact(artifact_id: str):
    results = load_json(SANDBOX_RESULTS_FILE)

    artifact_results = [
        r for r in results
        if r.get("artifact_id") == artifact_id
    ]

    return {
        "count": len(artifact_results),
        "results": artifact_results
    }


# ============================================================
# Artifact download endpoint for M3 Sandbox
# ============================================================

@app.get("/api/quarantine/{artifact_id}/download")
def download_quarantined_artifact(artifact_id: str):
    artifacts = merge_quarantine_sources(load_json(QUARANTINE_FILE))

    artifact = next(
        (a for a in artifacts if a.get("artifact_id") == artifact_id),
        None
    )

    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")

    file_path, actual_sha256, mismatches = select_downloadable_local_artifact(artifact)

    if not file_path:
        external_source = source_download_url(artifact)
        if external_source:
            return RedirectResponse(url=external_source, status_code=307)

        if mismatches:
            artifact["status"] = "INTEGRITY_FAILED"
            artifact["integrity_verified"] = False
            artifact["ready_for_sandbox"] = False
            artifact["download_hash_mismatches"] = mismatches
            save_json(QUARANTINE_FILE, artifacts)
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "Artifact hash mismatch",
                    "message": "M4 refused to serve a file that does not match the manifest SHA256",
                    "mismatches": mismatches,
                },
            )

        raise HTTPException(
            status_code=404,
            detail="Artifact file not found on backend"
        )

    filename = (
        artifact.get("original_filename")
        or artifact.get("filename")
        or "artifact.bin"
    )

    artifact["downloaded_sha256"] = actual_sha256
    artifact["download_integrity_checked_at"] = datetime.utcnow().isoformat() + "Z"
    save_json(QUARANTINE_FILE, artifacts)

    return FileResponse(
        path=str(file_path),
        filename=filename,
        media_type="application/octet-stream"
    )



@app.get("/ui")
def splash_screen():
    return FileResponse(str(WEB_DIR / "splash.html"))


@app.get("/dashboard")
def dashboard():
    return FileResponse(str(WEB_DIR / "dashboard.html"))

# ============================================================
# M1 -> M4 -> M2 Compatibility Endpoints
# ============================================================

@app.post("/api/artifacts/upload")
async def upload_artifact_from_m1(
    alert_id: str = Form(...),
    sha256: str = Form(None),
    original_path: str = Form(None),
    file: UploadFile = File(...)
):
    """
    M1 uploads a suspicious artifact linked to an alert.
    The artifact is saved on M4 backend so M2 can download it.
    """
    artifact_dir = ARTIFACTS_DIR / alert_id
    os.makedirs(artifact_dir, exist_ok=True)

    file_path = artifact_dir / file.filename

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    alerts = load_json(ALERTS_FILE)

    for alert in alerts:
        if alert.get("alert_id") == alert_id:
            alert["status"] = "ARTIFACT_READY"
            alert["artifact_path"] = str(file_path)
            alert["artifact_sha256"] = sha256
            alert["original_path"] = original_path
            alert["artifact_filename"] = file.filename
            alert["artifact_uploaded_at"] = datetime.utcnow().isoformat() + "Z"

    save_json(ALERTS_FILE, alerts)

    return {
        "status": "uploaded",
        "message": "Artifact uploaded successfully",
        "alert_id": alert_id,
        "filename": file.filename,
        "artifact_path": str(file_path),
        "sha256": sha256,
        "download_url": f"/api/artifacts/{alert_id}/download"
    }


@app.get("/api/artifacts/{alert_id}/download")
def download_artifact_for_m2(alert_id: str):
    """
    M2 downloads the artifact uploaded by M1.
    """
    artifact_dir = ARTIFACTS_DIR / alert_id

    if not artifact_dir.exists():
        raise HTTPException(status_code=404, detail="Artifact directory not found")

    files = os.listdir(artifact_dir)

    if not files:
        raise HTTPException(status_code=404, detail="Artifact folder is empty")

    file_path = artifact_dir / files[0]

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Artifact file not found")

    return FileResponse(
        path=str(file_path),
        filename=files[0],
        media_type="application/octet-stream"
    )
