from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from evidence_quarantine.config import QuarantineConfig
from evidence_quarantine.models import QuarantineRequest, RiskLevel, to_jsonable
from evidence_quarantine.quarantine_manager import QuarantineManager

try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover - optional API dependency
    raise RuntimeError(
        "FastAPI API dependencies are not installed. Install with: "
        "pip install 'evidence-quarantine-manager[api]'"
    ) from exc


class QuarantineAlertIn(BaseModel):
    artifact_path: str = Field(..., examples=["/tmp/suspicious.sh"])
    detection_reason: str = Field(..., examples=["Executable file created in /tmp"])
    alert_id: str | None = Field(None, examples=["ALT-2026-000001"])
    risk_level: RiskLevel = RiskLevel.MEDIUM
    detected_at: str | None = None
    source_module: str = "detection-engine"
    tags: list[str] = Field(default_factory=list)


def _read_json_file(path: str | None) -> Any:
    if not path:
        return None
    file_path = Path(path)
    if not file_path.exists():
        return None
    with file_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def create_app(config: QuarantineConfig | None = None) -> FastAPI:
    app = FastAPI(
        title="Evidence & Quarantine Manager API",
        version="1.0.0",
        description="Defensive evidence preservation and quarantine API for Rootkit Defense Agent.",
    )
    manager = QuarantineManager(config)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "evidence-quarantine-manager"}

    @app.post("/quarantine", status_code=201)
    def quarantine(alert: QuarantineAlertIn) -> dict[str, Any]:
        result = manager.quarantine_artifact(
            QuarantineRequest(
                artifact_path=Path(alert.artifact_path),
                detection_reason=alert.detection_reason,
                alert_id=alert.alert_id,
                risk_level=alert.risk_level,
                detected_at=alert.detected_at,
                source_module=alert.source_module,
                tags=alert.tags,
            )
        )
        return to_jsonable(result.to_summary())

    @app.get("/quarantine")
    def list_quarantine() -> list[dict[str, Any]]:
        return manager.list_evidence()

    @app.get("/quarantine/{alert_id}")
    def get_quarantine(alert_id: str) -> dict[str, Any]:
        record = manager.get_evidence(alert_id)
        if record is None:
            raise HTTPException(status_code=404, detail="alert_id not found")
        return record

    @app.get("/quarantine/{alert_id}/package")
    def get_evidence_package(alert_id: str) -> dict[str, Any]:
        record = manager.get_evidence(alert_id)
        if record is None:
            raise HTTPException(status_code=404, detail="alert_id not found")
        return {
            "record": record,
            "metadata": _read_json_file(record.get("metadata_path")),
            "hashes": _read_json_file(record.get("hashes_path")),
            "manifest": _read_json_file(record.get("manifest_path")),
        }

    @app.post("/quarantine/{alert_id}/sandbox-handoff")
    def sandbox_handoff(alert_id: str) -> dict[str, Any]:
        record = manager.get_evidence(alert_id)
        if record is None:
            raise HTTPException(status_code=404, detail="alert_id not found")
        if not record.get("ready_for_sandbox"):
            raise HTTPException(status_code=409, detail="Evidence package is not ready for sandbox")
        return {
            "alert_id": alert_id,
            "artifact_path": record.get("artifact_path"),
            "sha256": record.get("sha256"),
            "manifest_path": record.get("manifest_path"),
            "handoff_status": "READY_FOR_SANDBOX",
        }

    return app


app = create_app()
