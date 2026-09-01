"""Conservative redaction for report/ledger text; never used for verdict logic."""

from __future__ import annotations

import re
from typing import Any


_PATTERNS = [
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(basic\s+)[A-Za-z0-9+/=]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(gh[pousr]_[A-Za-z0-9_]+)"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"(?i)((?:token|password|passwd|secret|api[_-]?key|cookie)\s*[=:]\s*)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)([?&](?:token|password|secret|api[_-]?key|signature)=[^&#\s]+)"), r"[REDACTED_QUERY]") ,
]


def redact_text(value: Any) -> str:
    text = "" if value is None else str(value)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text
