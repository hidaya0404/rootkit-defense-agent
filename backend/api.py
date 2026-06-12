from datetime import datetime
import hashlib
import json
import os
import shutil
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

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

    return {
        "count": len(reports),
        "reports": reports
    }

@app.get("/api/remediation/{artifact_id}")
def get_remediation_plan(artifact_id: str):
    artifacts = load_json(QUARANTINE_FILE)

    artifact = next(
        (a for a in artifacts if a.get("artifact_id") == artifact_id),
        None
    )

    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")

    if "analysis" not in artifact:
        raise HTTPException(
            status_code=400,
            detail="Artifact must be analyzed before remediation"
        )

    remediation_plan = build_remediation_plan(artifact)

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
    artifact_id: str
    alert_id: Optional[str] = None
    sandbox_id: Optional[str] = None
    execution_status: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    processes_created: list = []
    files_created: list = []
    files_modified: list = []
    network_connections: list = []
    persistence_indicators: list = []
    behavior_summary: Optional[str] = None
    risk_observations: list = []


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
