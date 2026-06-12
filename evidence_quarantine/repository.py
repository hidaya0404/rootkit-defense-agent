from __future__ import annotations

from pathlib import Path
from typing import Any

from evidence_quarantine.storage import atomic_write_json, ensure_dir, file_lock, read_json


class EvidenceRepository:
    """Small JSON repository used by the CLI, API, and web mock."""

    def __init__(self, index_file: Path) -> None:
        self.index_file = index_file
        ensure_dir(index_file.parent)

    def list_records(self) -> list[dict[str, Any]]:
        return read_json(self.index_file, default=[])

    def upsert(self, record: dict[str, Any]) -> None:
        with file_lock(self.index_file.with_suffix(self.index_file.suffix + ".lock")):
            records = self.list_records()
            records = [item for item in records if item.get("artifact_id") != record.get("artifact_id")]
            records.append(record)
            records.sort(key=lambda item: item.get("created_at", ""), reverse=True)
            atomic_write_json(self.index_file, records)

    def get(self, alert_id: str) -> dict[str, Any] | None:
        for record in self.list_records():
            if record.get("alert_id") == alert_id:
                return record
        return None
