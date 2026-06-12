from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class QuarantineStatus(str, Enum):
    RECEIVED = "RECEIVED"
    VALIDATED = "VALIDATED"
    HASHED = "HASHED"
    QUARANTINED = "QUARANTINED"
    INTEGRITY_VERIFIED = "INTEGRITY_VERIFIED"
    READY_FOR_ANALYSIS = "READY_FOR_ANALYSIS"
    INTEGRITY_FAILED = "INTEGRITY_FAILED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class RootkitArtifactProfile:
    category: str
    suspected_techniques: list[str]
    rationale: list[str]
    recommended_next_step: str
    mitre_attack_mapping: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class QuarantineRequest:
    artifact_path: Path
    detection_reason: str
    alert_id: str | None = None
    risk_level: RiskLevel = RiskLevel.MEDIUM
    detected_at: str | None = None
    source_module: str = "detection-engine"
    tags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class HashSet:
    md5: str
    sha1: str
    sha256: str


@dataclass
class HashReport:
    before_copy: HashSet | None
    after_copy: HashSet | None
    match: bool


@dataclass
class ArtifactMetadata:
    alert_id: str
    artifact_name: str
    original_path: str
    quarantine_path: str | None
    file_type: str
    size_bytes: int
    permissions: str
    owner_uid: int | None
    owner_name: str | None
    group_gid: int | None
    group_name: str | None
    inode: int | None
    device: int | None
    created_at: str | None
    modified_at: str | None
    accessed_at: str | None
    detected_at: str
    quarantined_at: str | None
    detection_reason: str
    risk_level: RiskLevel
    status: QuarantineStatus
    integrity_verified: bool
    policy_decision: str
    rootkit_profile: RootkitArtifactProfile | None = None
    errors: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class CustodyEvent:
    action: str
    actor: str
    timestamp: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceManifest:
    evidence_package_id: str
    artifact_id: str
    alert_id: str
    package_version: str
    files: list[str]
    package_created_at: str
    chain_of_custody: list[CustodyEvent]
    ready_for_sandbox: bool


@dataclass
class QuarantineResult:
    success: bool
    artifact_id: str
    alert_id: str
    status: QuarantineStatus
    evidence_dir: Path
    artifact_path: Path | None
    metadata_path: Path | None
    hashes_path: Path | None
    manifest_path: Path | None
    audit_log_path: Path
    errors: list[str] = field(default_factory=list)

    def to_summary(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "artifact_id": self.artifact_id,
            "alert_id": self.alert_id,
            "status": self.status,
            "evidence_dir": self.evidence_dir,
            "artifact_path": self.artifact_path,
            "metadata_path": self.metadata_path,
            "hashes_path": self.hashes_path,
            "manifest_path": self.manifest_path,
            "audit_log_path": self.audit_log_path,
            "errors": self.errors,
        }


def to_jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return {k: to_jsonable(v) for k, v in asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [to_jsonable(item) for item in value]
    return value
