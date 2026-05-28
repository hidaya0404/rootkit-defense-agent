from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from evidence_quarantine.config import QuarantineConfig
from evidence_quarantine.exceptions import PolicyViolation


@dataclass(frozen=True)
class PolicyDecision:
    accepted: bool
    normalized_path: Path | None
    reason: str


class QuarantinePolicy:
    """Validates artifact paths before collection."""

    CRITICAL_PREFIXES = (
        Path("/bin"),
        Path("/sbin"),
        Path("/lib"),
        Path("/lib64"),
        Path("/boot"),
        Path("/proc"),
        Path("/sys"),
        Path("/dev"),
        Path("/usr/bin"),
        Path("/usr/sbin"),
        Path("/usr/lib"),
    )

    def __init__(self, config: QuarantineConfig) -> None:
        self.config = config

    def validate(self, artifact_path: Path) -> PolicyDecision:
        path = artifact_path.expanduser()
        if not path.exists():
            raise PolicyViolation("Artifact path does not exist")

        lstat = path.lstat()
        if stat.S_ISLNK(lstat.st_mode):
            raise PolicyViolation("Symbolic links are rejected to avoid evidence ambiguity")

        if not path.is_file():
            raise PolicyViolation("Only regular files can be quarantined")

        if lstat.st_size > self.config.max_artifact_size_bytes:
            raise PolicyViolation(
                f"Artifact is too large: {lstat.st_size} bytes "
                f"(limit={self.config.max_artifact_size_bytes})"
            )

        normalized = path.resolve(strict=True)
        self._validate_critical_path(normalized)

        if not os.access(normalized, os.R_OK):
            raise PolicyViolation("Artifact is not readable by the current process")

        return PolicyDecision(accepted=True, normalized_path=normalized, reason="accepted")

    def _validate_critical_path(self, path: Path) -> None:
        if self.config.allow_system_paths or os.name != "posix":
            return
        for prefix in self.CRITICAL_PREFIXES:
            try:
                path.relative_to(prefix)
            except ValueError:
                continue
            raise PolicyViolation(
                f"Critical system path rejected by default: {path}. "
                "Enable allow_system_paths only in a controlled lab."
            )

