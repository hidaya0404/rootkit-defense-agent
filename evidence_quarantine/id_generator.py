from __future__ import annotations

import re
import uuid

from evidence_quarantine.time_utils import utc_now


_SAFE_ID = re.compile(r"[^A-Za-z0-9_.-]+")


def generate_alert_id() -> str:
    date = utc_now().replace("-", "").replace(":", "").replace("Z", "")
    date = date.split("T")[0]
    return f"ALT-{date}-{uuid.uuid4().hex[:8].upper()}"


def sanitize_alert_id(alert_id: str) -> str:
    cleaned = _SAFE_ID.sub("-", alert_id.strip())
    cleaned = cleaned.strip(".-")
    return cleaned or generate_alert_id()

