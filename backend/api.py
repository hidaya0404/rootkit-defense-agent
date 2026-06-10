from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime
import uuid
import os
import json
import shutil

from analysis.static_analyzer import analyze_file
from analysis.report_generator import generate_html_report

app = FastAPI(title="Rootkit Defense Agent API - M4")

DATA_DIR = "backend/data"
ALERTS_FILE = os.path.join(DATA_DIR, "alerts.json")
QUARANTINE_FILE = os.path.join(DATA_DIR, "quarantine.json")
REPORTS_FILE = os.path.join(DATA_DIR, "reports.json")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs("uploads/quarantine", exist_ok=True)
os.makedirs("reports/generated", exist_ok=True)


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
    file_path = os.path.join("uploads/quarantine", filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    artifacts = load_json(QUARANTINE_FILE)

    artifact = {
        "artifact_id": artifact_id,
        "alert_id": alert_id,
        "original_filename": file.filename,
        "stored_path": file_path,
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
    artifacts = load_json(QUARANTINE_FILE)

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

    file_path = artifact["stored_path"]

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found on server")

    analysis_result = analyze_file(file_path, artifact_id=artifact_id, alert_id=artifact.get("alert_id"))
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


from analysis.remediation import build_remediation_plan


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
