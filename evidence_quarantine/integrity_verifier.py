from __future__ import annotations

from evidence_quarantine.models import HashReport, HashSet


class IntegrityVerifier:
    """Compares source and quarantined artifact fingerprints."""

    def verify(self, before_copy: HashSet, after_copy: HashSet) -> HashReport:
        return HashReport(
            before_copy=before_copy,
            after_copy=after_copy,
            match=before_copy.sha256 == after_copy.sha256
            and before_copy.sha1 == after_copy.sha1
            and before_copy.md5 == after_copy.md5,
        )
