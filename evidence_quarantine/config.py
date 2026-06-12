from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def default_storage_root() -> Path:
    configured = os.getenv("ROOTRAP_STORAGE_ROOT") or os.getenv("ROOTKIT_DEFENSE_STORAGE")
    if configured:
        return Path(configured).expanduser()
    if os.name == "posix":
        return Path("/var/lib/rootrap")
    return Path.cwd() / "runtime" / "rootkit-defense"


@dataclass(frozen=True)
class QuarantineConfig:
    """Runtime configuration for evidence preservation and quarantine."""

    storage_root: Path = default_storage_root()
    allow_system_paths: bool = False
    max_artifact_size_bytes: int = 100 * 1024 * 1024
    copy_buffer_size: int = 1024 * 1024
    actor: str = "evidence-quarantine-manager"
    secure_permissions: bool = True
    version: str = "1.0"

    def __post_init__(self) -> None:
        object.__setattr__(self, "storage_root", Path(self.storage_root).expanduser().resolve())

    @property
    def quarantine_dir(self) -> Path:
        return self.storage_root / "quarantine"

    @property
    def audit_dir(self) -> Path:
        return self.storage_root / "audit"

    @property
    def reports_dir(self) -> Path:
        return self.storage_root / "reports"

    @property
    def index_file(self) -> Path:
        return self.storage_root / "index.json"

    @classmethod
    def from_root(cls, storage_root: str | Path) -> "QuarantineConfig":
        return cls(storage_root=Path(storage_root).expanduser())
