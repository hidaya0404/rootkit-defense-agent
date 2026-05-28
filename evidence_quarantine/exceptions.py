class QuarantineError(Exception):
    """Base exception for quarantine workflow failures."""


class PolicyViolation(QuarantineError):
    """Raised when an artifact does not pass quarantine policy checks."""


class EvidenceWriteError(QuarantineError):
    """Raised when an evidence package cannot be written safely."""

