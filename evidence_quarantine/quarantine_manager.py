from __future__ import annotations

import os
import shutil
from pathlib import Path

from evidence_quarantine.audit_logger import AuditLogger
from evidence_quarantine.config import QuarantineConfig
from evidence_quarantine.exceptions import PolicyViolation
from evidence_quarantine.hash_service import HashService
from evidence_quarantine.id_generator import generate_alert_id, sanitize_alert_id
from evidence_quarantine.integrity_verifier import IntegrityVerifier
from evidence_quarantine.metadata_collector import MetadataCollector
from evidence_quarantine.models import (
    CustodyEvent,
    EvidenceManifest,
    QuarantineRequest,
    QuarantineResult,
    QuarantineStatus,
    to_jsonable,
)
from evidence_quarantine.quarantine_policy import QuarantinePolicy
from evidence_quarantine.repository import EvidenceRepository
from evidence_quarantine.storage import atomic_write_json, ensure_dir
from evidence_quarantine.time_utils import utc_now


class QuarantineManager:
    """Coordinates validation, evidence capture, quarantine, and audit."""

    def __init__(self, config: QuarantineConfig | None = None) -> None:
        self.config = config or QuarantineConfig()
        self.policy = QuarantinePolicy(self.config)
        self.hash_service = HashService(buffer_size=self.config.copy_buffer_size)
        self.integrity_verifier = IntegrityVerifier()
        self.metadata_collector = MetadataCollector()
        self.repository = EvidenceRepository(self.config.index_file)
        self.audit = AuditLogger(self.config.audit_dir / "evidence-audit.log")
        self._prepare_storage()

    def quarantine_artifact(self, request: QuarantineRequest) -> QuarantineResult:
        alert_id = sanitize_alert_id(request.alert_id or generate_alert_id())
        detected_at = request.detected_at or utc_now()
        evidence_dir = self._unique_evidence_dir(alert_id)
        ensure_dir(evidence_dir)
        package_audit_path = evidence_dir / "audit.log"
        audit = self.audit.bind_package(package_audit_path)
        custody: list[CustodyEvent] = []

        def custody_event(action: str, **details: object) -> None:
            event = CustodyEvent(action=action, actor=self.config.actor, timestamp=utc_now(), details=details)
            custody.append(event)

        audit.event(
            "ALERT_RECEIVED",
            alert_id=alert_id,
            source_module=request.source_module,
            artifact_path=request.artifact_path,
            risk_level=request.risk_level,
        )
        custody_event("ALERT_RECEIVED", source_module=request.source_module)

        try:
            decision = self.policy.validate(Path(request.artifact_path))
            source_path = decision.normalized_path
            if source_path is None:
                raise PolicyViolation("Policy accepted without a normalized path")
            audit.event("POLICY_VALIDATED", alert_id=alert_id, decision=decision.reason)
            custody_event("POLICY_VALIDATED", decision=decision.reason)
        except PolicyViolation as exc:
            return self._reject(
                alert_id=alert_id,
                evidence_dir=evidence_dir,
                audit=audit,
                package_audit_path=package_audit_path,
                request=request,
                detected_at=detected_at,
                reason=str(exc),
                custody=custody,
            )

        artifact_path = evidence_dir / "artifact.bin"
        metadata_path = evidence_dir / "metadata.json"
        hashes_path = evidence_dir / "hashes.json"
        manifest_path = evidence_dir / "manifest.json"

        try:
            metadata = self.metadata_collector.collect(
                path=source_path,
                alert_id=alert_id,
                detection_reason=request.detection_reason,
                detected_at=detected_at,
                risk_level=request.risk_level,
                quarantine_path=artifact_path,
                status=QuarantineStatus.VALIDATED,
                tags=request.tags,
            )
            audit.event(
                "METADATA_COLLECTED",
                alert_id=alert_id,
                size_bytes=metadata.size_bytes,
                permissions=metadata.permissions,
                owner_uid=metadata.owner_uid,
            )
            custody_event("METADATA_COLLECTED", size_bytes=metadata.size_bytes)

            before_hash = self.hash_service.calculate(source_path)
            metadata.status = QuarantineStatus.HASHED
            audit.event("HASH_BEFORE_COPY", alert_id=alert_id, sha256=before_hash.sha256)
            custody_event("HASH_BEFORE_COPY", sha256=before_hash.sha256)

            self._secure_copy(source_path, artifact_path)
            metadata.status = QuarantineStatus.QUARANTINED
            metadata.quarantined_at = utc_now()
            audit.event("ARTIFACT_COPIED", alert_id=alert_id, destination=artifact_path)
            custody_event("ARTIFACT_COPIED", destination=str(artifact_path))

            after_hash = self.hash_service.calculate(artifact_path)
            hashes = self.integrity_verifier.verify(before_hash, after_hash)
            audit.event("HASH_AFTER_COPY", alert_id=alert_id, sha256=after_hash.sha256)
            custody_event("HASH_AFTER_COPY", sha256=after_hash.sha256)

            if hashes.match:
                metadata.integrity_verified = True
                metadata.status = QuarantineStatus.READY_FOR_ANALYSIS
                audit.event("INTEGRITY_VERIFIED", alert_id=alert_id, result=True)
                custody_event("INTEGRITY_VERIFIED", result=True)
                success = True
                final_status = QuarantineStatus.READY_FOR_ANALYSIS
                errors: list[str] = []
            else:
                metadata.integrity_verified = False
                metadata.status = QuarantineStatus.INTEGRITY_FAILED
                error = "Hash mismatch between source and quarantined artifact"
                metadata.errors.append(error)
                audit.event("INTEGRITY_FAILED", alert_id=alert_id, level="ERROR", result=False)
                custody_event("INTEGRITY_FAILED", result=False)
                success = False
                final_status = QuarantineStatus.INTEGRITY_FAILED
                errors = [error]

            atomic_write_json(metadata_path, metadata)
            atomic_write_json(hashes_path, hashes)
            manifest = EvidenceManifest(
                evidence_package_id=f"EV-{alert_id}",
                alert_id=alert_id,
                package_version=self.config.version,
                files=["artifact.bin", "metadata.json", "hashes.json", "audit.log", "manifest.json"],
                package_created_at=utc_now(),
                chain_of_custody=custody,
                ready_for_sandbox=success,
            )
            atomic_write_json(manifest_path, manifest)
            audit.event("EVIDENCE_PACKAGE_CREATED", alert_id=alert_id, manifest=manifest_path)

            self.repository.upsert(
                {
                    "alert_id": alert_id,
                    "artifact_name": metadata.artifact_name,
                    "original_path": metadata.original_path,
                    "evidence_dir": str(evidence_dir),
                    "artifact_path": str(artifact_path),
                    "metadata_path": str(metadata_path),
                    "hashes_path": str(hashes_path),
                    "manifest_path": str(manifest_path),
                    "audit_log_path": str(package_audit_path),
                    "sha256": before_hash.sha256,
                    "rootkit_category": metadata.rootkit_profile.category if metadata.rootkit_profile else None,
                    "suspected_techniques": metadata.rootkit_profile.suspected_techniques
                    if metadata.rootkit_profile
                    else [],
                    "risk_level": request.risk_level.value,
                    "status": final_status.value,
                    "integrity_verified": metadata.integrity_verified,
                    "created_at": metadata.quarantined_at,
                    "ready_for_sandbox": success,
                    "errors": errors,
                }
            )

            return QuarantineResult(
                success=success,
                alert_id=alert_id,
                status=final_status,
                evidence_dir=evidence_dir,
                artifact_path=artifact_path,
                metadata_path=metadata_path,
                hashes_path=hashes_path,
                manifest_path=manifest_path,
                audit_log_path=package_audit_path,
                errors=errors,
            )
        except Exception as exc:
            audit.event("QUARANTINE_FAILED", alert_id=alert_id, level="ERROR", error=str(exc))
            custody_event("QUARANTINE_FAILED", error=str(exc))
            self._write_failure_manifest(evidence_dir, alert_id, request, detected_at, str(exc), custody)
            self.repository.upsert(
                {
                    "alert_id": alert_id,
                    "artifact_name": Path(request.artifact_path).name,
                    "original_path": str(request.artifact_path),
                    "evidence_dir": str(evidence_dir),
                    "artifact_path": None,
                    "metadata_path": None,
                    "hashes_path": None,
                    "manifest_path": str(evidence_dir / "manifest.json"),
                    "audit_log_path": str(package_audit_path),
                    "sha256": None,
                    "risk_level": request.risk_level.value,
                    "status": QuarantineStatus.FAILED.value,
                    "integrity_verified": False,
                    "created_at": utc_now(),
                    "ready_for_sandbox": False,
                    "errors": [str(exc)],
                }
            )
            return QuarantineResult(
                success=False,
                alert_id=alert_id,
                status=QuarantineStatus.FAILED,
                evidence_dir=evidence_dir,
                artifact_path=None,
                metadata_path=None,
                hashes_path=None,
                manifest_path=evidence_dir / "manifest.json",
                audit_log_path=package_audit_path,
                errors=[str(exc)],
            )

    def list_evidence(self) -> list[dict[str, object]]:
        return self.repository.list_records()

    def get_evidence(self, alert_id: str) -> dict[str, object] | None:
        return self.repository.get(alert_id)

    def _prepare_storage(self) -> None:
        ensure_dir(self.config.storage_root)
        ensure_dir(self.config.quarantine_dir)
        ensure_dir(self.config.audit_dir)
        ensure_dir(self.config.reports_dir)

    def _unique_evidence_dir(self, alert_id: str) -> Path:
        base = self.config.quarantine_dir / alert_id
        if not base.exists():
            return base
        suffix = 1
        while True:
            candidate = self.config.quarantine_dir / f"{alert_id}-{suffix}"
            if not candidate.exists():
                return candidate
            suffix += 1

    def _secure_copy(self, source_path: Path, artifact_path: Path) -> None:
        temp_path = artifact_path.with_suffix(".tmp")
        if temp_path.exists():
            temp_path.unlink()

        with source_path.open("rb") as source, temp_path.open("xb") as destination:
            shutil.copyfileobj(source, destination, length=self.config.copy_buffer_size)

        shutil.copystat(source_path, temp_path, follow_symlinks=False)
        if self.config.secure_permissions and os.name == "posix":
            os.chmod(temp_path, 0o400)
        os.replace(temp_path, artifact_path)

    def _reject(
        self,
        *,
        alert_id: str,
        evidence_dir: Path,
        audit: AuditLogger,
        package_audit_path: Path,
        request: QuarantineRequest,
        detected_at: str,
        reason: str,
        custody: list[CustodyEvent],
    ) -> QuarantineResult:
        audit.event("POLICY_REJECTED", alert_id=alert_id, level="WARN", reason=reason)
        custody.append(
            CustodyEvent(
                action="POLICY_REJECTED",
                actor=self.config.actor,
                timestamp=utc_now(),
                details={"reason": reason},
            )
        )
        manifest_path = evidence_dir / "manifest.json"
        atomic_write_json(
            evidence_dir / "request.json",
            {
                "alert_id": alert_id,
                "artifact_path": str(request.artifact_path),
                "detection_reason": request.detection_reason,
                "risk_level": request.risk_level.value,
                "detected_at": detected_at,
                "source_module": request.source_module,
                "tags": request.tags,
            },
        )
        manifest = EvidenceManifest(
            evidence_package_id=f"EV-{alert_id}",
            alert_id=alert_id,
            package_version=self.config.version,
            files=["request.json", "audit.log", "manifest.json"],
            package_created_at=utc_now(),
            chain_of_custody=custody,
            ready_for_sandbox=False,
        )
        atomic_write_json(manifest_path, manifest)
        self.repository.upsert(
            {
                "alert_id": alert_id,
                "artifact_name": Path(request.artifact_path).name,
                "original_path": str(request.artifact_path),
                "evidence_dir": str(evidence_dir),
                "artifact_path": None,
                "metadata_path": None,
                "hashes_path": None,
                "manifest_path": str(manifest_path),
                "audit_log_path": str(package_audit_path),
                "sha256": None,
                "risk_level": request.risk_level.value,
                "status": QuarantineStatus.REJECTED.value,
                "integrity_verified": False,
                "created_at": utc_now(),
                "ready_for_sandbox": False,
                "errors": [reason],
            }
        )
        return QuarantineResult(
            success=False,
            alert_id=alert_id,
            status=QuarantineStatus.REJECTED,
            evidence_dir=evidence_dir,
            artifact_path=None,
            metadata_path=None,
            hashes_path=None,
            manifest_path=manifest_path,
            audit_log_path=package_audit_path,
            errors=[reason],
        )

    def _write_failure_manifest(
        self,
        evidence_dir: Path,
        alert_id: str,
        request: QuarantineRequest,
        detected_at: str,
        error: str,
        custody: list[CustodyEvent],
    ) -> None:
        atomic_write_json(
            evidence_dir / "failure.json",
            {
                "alert_id": alert_id,
                "artifact_path": str(request.artifact_path),
                "detection_reason": request.detection_reason,
                "risk_level": request.risk_level.value,
                "detected_at": detected_at,
                "error": error,
            },
        )
        manifest = EvidenceManifest(
            evidence_package_id=f"EV-{alert_id}",
            alert_id=alert_id,
            package_version=self.config.version,
            files=["failure.json", "audit.log", "manifest.json"],
            package_created_at=utc_now(),
            chain_of_custody=custody,
            ready_for_sandbox=False,
        )
        atomic_write_json(evidence_dir / "manifest.json", to_jsonable(manifest))
