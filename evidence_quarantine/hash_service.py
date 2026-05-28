from __future__ import annotations

import hashlib
from pathlib import Path

from evidence_quarantine.models import HashSet


class HashService:
    """Streaming hash calculator for forensic fingerprints."""

    def __init__(self, buffer_size: int = 1024 * 1024) -> None:
        self.buffer_size = buffer_size

    def calculate(self, path: Path) -> HashSet:
        md5 = hashlib.md5(usedforsecurity=False)
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        with path.open("rb") as handle:
            while True:
                chunk = handle.read(self.buffer_size)
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        return HashSet(md5=md5.hexdigest(), sha1=sha1.hexdigest(), sha256=sha256.hexdigest())

