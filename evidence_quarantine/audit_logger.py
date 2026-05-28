from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from evidence_quarantine.storage import ensure_dir
from evidence_quarantine.time_utils import utc_now


def _sanitize(value: Any) -> str:
    if isinstance(value, Enum):
        value = value.value
    text = str(value)
    return text.replace("\n", "\\n").replace("\r", "\\r").replace("|", "/")


class AuditLogger:
    """Writes append-only audit events for global and evidence-package logs."""

    def __init__(self, global_log_path: Path, package_log_path: Path | None = None) -> None:
        self.global_log_path = global_log_path
        self.package_log_path = package_log_path
        ensure_dir(global_log_path.parent)
        if package_log_path:
            ensure_dir(package_log_path.parent)

    def bind_package(self, package_log_path: Path) -> "AuditLogger":
        return AuditLogger(self.global_log_path, package_log_path)

    def event(self, action: str, *, alert_id: str, level: str = "INFO", **fields: Any) -> None:
        timestamp = utc_now()
        details = " ".join(f"{key}={_sanitize(value)}" for key, value in sorted(fields.items()))
        line = f"{timestamp} | {level} | {action} | alert_id={_sanitize(alert_id)}"
        if details:
            line = f"{line} | {details}"
        line = f"{line}\n"

        self._append(self.global_log_path, line)
        if self.package_log_path:
            self._append(self.package_log_path, line)

    @staticmethod
    def _append(path: Path, line: str) -> None:
        ensure_dir(path.parent)
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line)
