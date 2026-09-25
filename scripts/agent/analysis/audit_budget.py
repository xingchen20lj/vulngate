"""Persistent wall-clock stop-loss for a host-native VulnGate round."""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional


SCHEMA_VERSION = "audit-round-budget-v1"
DEFAULT_BUDGET_SECONDS = 90 * 60
# A single audit round must remain short enough to produce a useful checkpoint
# instead of allowing configuration to turn the stop-loss into a multi-hour
# permission. Older persisted records may still contain up to 24 hours; their
# effective deadline is clamped when read below.
MAX_BUDGET_SECONDS = DEFAULT_BUDGET_SECONDS
LEGACY_MAX_PERSISTED_BUDGET_SECONDS = 24 * 60 * 60
MAX_ROUND = 1_000_000
_TARGET_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z")


def budget_path(workspace: Path, target: str, round_no: int) -> Path:
    """Return a contained S0 budget path for a simple target slug."""
    if not _TARGET_RE.fullmatch(str(target or "")):
        raise ValueError("target must be a 1-96 character path-safe slug")
    if not 1 <= int(round_no) <= MAX_ROUND:
        raise ValueError("round must be in [1, %d]" % MAX_ROUND)
    root = Path(workspace).resolve()
    path = (root / "state" / target / ("round-%02d" % int(round_no)) /
            "S0" / "execution-budget.json")
    if not path.resolve().is_relative_to(root):
        raise ValueError("audit budget path escapes the workspace")
    return path


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("%s must be an ISO-8601 timestamp" % field)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("%s must be an ISO-8601 timestamp" % field) from exc
    if parsed.tzinfo is None:
        raise ValueError("%s must include a timezone" % field)
    return parsed.astimezone(timezone.utc)


def _load(path: Path, target: str, round_no: int) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError("cannot read audit-round budget: %s" % exc) from exc
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("audit-round budget has an unsupported schema")
    if data.get("target") != target or data.get("round") != round_no:
        raise ValueError("audit-round budget identity does not match the request")
    started = _parse_timestamp(data.get("round_started_at"), "round_started_at")
    deadline = _parse_timestamp(data.get("deadline_at"), "deadline_at")
    seconds = data.get("budget_seconds")
    if (not isinstance(seconds, int)
            or not 1 <= seconds <= LEGACY_MAX_PERSISTED_BUDGET_SECONDS):
        raise ValueError("audit-round budget duration is invalid")
    if deadline <= started or (deadline - started).total_seconds() != seconds:
        raise ValueError("audit-round budget timestamps are inconsistent")
    return data


def start_round_budget(workspace: Path, target: str, round_no: int,
                       budget_seconds: int = DEFAULT_BUDGET_SECONDS) -> Dict[str, Any]:
    """Create a budget once; an existing deadline is never reset by `start`."""
    if isinstance(budget_seconds, bool) or not isinstance(budget_seconds, int):
        raise ValueError("budget_seconds must be an integer")
    seconds = budget_seconds
    path = budget_path(workspace, target, round_no)
    if path.exists():
        data = _load(path, target, round_no)
        data["start_result"] = "already-started"
        return data
    if not 1 <= seconds <= MAX_BUDGET_SECONDS:
        raise ValueError("budget_seconds must be in [1, %d]" % MAX_BUDGET_SECONDS)

    started = datetime.now(timezone.utc).replace(microsecond=0)
    deadline = started + timedelta(seconds=seconds)
    data = {
        "schema_version": SCHEMA_VERSION,
        "target": target,
        "round": int(round_no),
        "round_started_at": started.isoformat().replace("+00:00", "Z"),
        "deadline_at": deadline.isoformat().replace("+00:00", "Z"),
        "budget_seconds": seconds,
        "claim_status": "not-a-finding",
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=".%s." % path.name, suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary_name, path)
        except FileExistsError:
            # A concurrent starter won. Never replace or renew its deadline.
            data = _load(path, target, round_no)
            data["start_result"] = "already-started"
            return data
        data["start_result"] = "started"
        return data
    finally:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass


def round_budget_snapshot(data: Dict[str, Any], now: Optional[datetime] = None
                          ) -> Dict[str, Any]:
    """Summarize a persisted deadline without changing it."""
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    started = _parse_timestamp(data.get("round_started_at"), "round_started_at")
    configured_deadline = _parse_timestamp(data.get("deadline_at"), "deadline_at")
    hard_deadline = started + timedelta(seconds=MAX_BUDGET_SECONDS)
    deadline = min(configured_deadline, hard_deadline)
    effective_budget = max(1, int((deadline - started).total_seconds()))
    elapsed = max(0.0, (current - started).total_seconds())
    remaining = max(0.0, (deadline - current).total_seconds())
    effective_deadline_at = deadline.isoformat().replace("+00:00", "Z")
    return {
        "schema_version": SCHEMA_VERSION,
        "target": data["target"],
        "round": data["round"],
        "round_started_at": data["round_started_at"],
        "deadline_at": effective_deadline_at,
        "configured_deadline_at": data["deadline_at"],
        "configured_budget_seconds": data["budget_seconds"],
        "budget_seconds": effective_budget,
        "hard_cap_seconds": MAX_BUDGET_SECONDS,
        "elapsed_seconds": round(elapsed, 3),
        "remaining_seconds": round(remaining, 3),
        "expired": remaining < 1.0,
        "claim_status": "not-a-finding",
    }


def load_round_budget(workspace: Path, target: str, round_no: int
                      ) -> Dict[str, Any]:
    """Read a previously initialized budget; never create or renew one."""
    path = budget_path(workspace, target, round_no)
    if not path.is_file():
        raise ValueError("audit-round budget is not initialized: %s" % path)
    return _load(path, target, round_no)
