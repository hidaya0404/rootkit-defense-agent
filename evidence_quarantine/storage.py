from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from evidence_quarantine.models import to_jsonable


def ensure_dir(path: Path, mode: int = 0o700) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path, mode)


def atomic_write_text(path: Path, content: str, mode: int = 0o600) -> None:
    ensure_dir(path.parent)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        if os.name == "posix":
            os.chmod(temp_path, mode)
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def atomic_write_json(path: Path, payload: Any, mode: int = 0o600) -> None:
    content = json.dumps(to_jsonable(payload), indent=2, sort_keys=True, ensure_ascii=False)
    atomic_write_text(path, content + "\n", mode=mode)


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)

