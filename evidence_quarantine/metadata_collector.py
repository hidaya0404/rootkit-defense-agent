from __future__ import annotations

import os
import stat
from pathlib import Path

from evidence_quarantine.models import ArtifactMetadata, QuarantineStatus, RiskLevel
from evidence_quarantine.rootkit_classifier import RootkitArtifactClassifier
from evidence_quarantine.time_utils import timestamp_to_utc


def _owner_name(uid: int | None) -> str | None:
    if uid is None or os.name != "posix":
        return None
    try:
        import pwd

        return pwd.getpwuid(uid).pw_name
    except Exception:
        return None


def _group_name(gid: int | None) -> str | None:
    if gid is None or os.name != "posix":
        return None
    try:
        import grp

        return grp.getgrgid(gid).gr_name
    except Exception:
        return None


def _file_type(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "regular_file"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode):
        return "character_device"
    if stat.S_ISBLK(mode):
        return "block_device"
    return "unknown"


class MetadataCollector:
    """Collects forensic metadata without modifying the source artifact."""

    def __init__(self, classifier: RootkitArtifactClassifier | None = None) -> None:
        self.classifier = classifier or RootkitArtifactClassifier()

    def collect(
        self,
        *,
        path: Path,
        alert_id: str,
        detection_reason: str,
        detected_at: str,
        risk_level: RiskLevel,
        quarantine_path: Path | None = None,
        status: QuarantineStatus = QuarantineStatus.VALIDATED,
        integrity_verified: bool = False,
        policy_decision: str = "accepted",
        errors: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> ArtifactMetadata:
        st = path.stat()
        mode = st.st_mode
        uid = getattr(st, "st_uid", None)
        gid = getattr(st, "st_gid", None)

        return ArtifactMetadata(
            alert_id=alert_id,
            artifact_name=path.name,
            original_path=str(path),
            quarantine_path=str(quarantine_path) if quarantine_path else None,
            file_type=_file_type(mode),
            size_bytes=st.st_size,
            permissions=f"{stat.S_IMODE(mode):04o}",
            owner_uid=uid,
            owner_name=_owner_name(uid),
            group_gid=gid,
            group_name=_group_name(gid),
            inode=getattr(st, "st_ino", None),
            device=getattr(st, "st_dev", None),
            created_at=timestamp_to_utc(getattr(st, "st_ctime", None)),
            modified_at=timestamp_to_utc(getattr(st, "st_mtime", None)),
            accessed_at=timestamp_to_utc(getattr(st, "st_atime", None)),
            detected_at=detected_at,
            quarantined_at=None,
            detection_reason=detection_reason,
            risk_level=risk_level,
            status=status,
            integrity_verified=integrity_verified,
            policy_decision=policy_decision,
            rootkit_profile=self.classifier.classify(path),
            errors=errors or [],
            tags=tags or [],
        )
