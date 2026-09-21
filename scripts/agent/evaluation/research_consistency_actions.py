"""Materialize bounded actions for cross-round consistency conflicts.

``research-consistency-v1`` detects that comparable observations disagree, but
the detector alone is not enough to make the next S2/S4 round reproducible.
This module turns each non-consistent row into a small experiment contract:
fixed isolation axes, paired lanes, required observation classes and explicit
falsifier codes.  The contract is scheduling metadata only.  It never stores
source prose, payloads, commands, process output, credentials or a finding
conclusion.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from .research_consistency import (
    CONSISTENCY_CLAIM_STATUS,
    normalize_research_consistency,
)
from ..tools.redaction import redact_text


ACTION_SCHEMA_VERSION = "research-consistency-action-v1"
ACTION_FILENAME = "research-consistency-actions.json"
ACTION_CLAIM_STATUS = CONSISTENCY_CLAIM_STATUS

MAX_ENTRIES = 64
MAX_CODES = 8
MAX_TEXT = 120

ACTION_STATUSES = frozenset({
    "conflicted", "unstable", "insufficient", "environment-gap",
})
ISOLATION_AXES = frozenset({
    "effect-observation", "fixture-replay", "comparison-arm",
    "state-lifecycle", "runtime-context", "environment-repair",
    "independent-repeat",
})
REQUIRED_OBSERVATIONS = frozenset({
    "same-fixture-identity", "controlled-runtime-context",
    "independent-replay", "positive-effect-or-safe-equivalent",
    "comparison-arm-status", "state-reset-observed", "environment-status",
})
FALSIFIERS = frozenset({
    "environment-gap-keeps-action-pending",
    "missing-independent-replay-keeps-action-pending",
    "signature-drift-is-not-effect",
    "state-not-reset-keeps-action-pending",
    "context-digest-mismatch-keeps-action-pending",
    "comparison-arm-mismatch-keeps-action-pending",
    "fixture-identity-mismatch-keeps-action-pending",
    "typed-effect-or-safe-equivalent-missing",
})
LANES = frozenset({"positive", "negative", "environment-gap"})


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    try:
        value = redact_text(value)
    except Exception:  # pragma: no cover - defensive redaction boundary
        value = str(value)
    return " ".join(str(value or "").replace("\x00", "").split())[:limit]


def _int(value: Any, default: int = 0, minimum: int = 0,
         maximum: int = 1000000) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _bounded(values: Any, allowed: Iterable[str], limit: int = MAX_CODES,
             item_limit: int = MAX_TEXT) -> List[str]:
    if isinstance(values, (str, bytes)):
        values = [values]
    if not isinstance(values, (list, tuple, set)):
        return []
    allowed_set = set(allowed)
    result = []
    for value in values:
        item = _text(value, item_limit).lower()
        if item in allowed_set and item not in result:
            result.append(item)
        if len(result) >= limit:
            break
    return sorted(result)


def _status(value: Any) -> str:
    value = _text(value, 32).lower()
    return value if value in ACTION_STATUSES else ""


def _derived_contract(status: str, codes: List[str],
                      next_action: str) -> Dict[str, Any]:
    """Derive all action mechanics from allowlisted status and conflict codes."""
    axes = set()
    required = set()
    falsifiers = set()

    if status == "environment-gap":
        axes.add("environment-repair")
        required.add("environment-status")
        falsifiers.add("environment-gap-keeps-action-pending")
    else:
        axes.update({"fixture-replay", "independent-repeat"})
        required.update({
            "same-fixture-identity", "controlled-runtime-context",
            "independent-replay",
        })
        falsifiers.add("missing-independent-replay-keeps-action-pending")

    if "effect-presence-drift" in codes:
        axes.add("effect-observation")
        required.add("positive-effect-or-safe-equivalent")
        falsifiers.update({
            "typed-effect-or-safe-equivalent-missing",
            "signature-drift-is-not-effect",
        })
    if "reproduction-drift" in codes:
        axes.add("fixture-replay")
        required.add("same-fixture-identity")
        falsifiers.add("fixture-identity-mismatch-keeps-action-pending")
    if "comparison-drift" in codes:
        axes.add("comparison-arm")
        required.add("comparison-arm-status")
        falsifiers.add("comparison-arm-mismatch-keeps-action-pending")
    if "state-drift" in codes:
        axes.add("state-lifecycle")
        required.add("state-reset-observed")
        falsifiers.add("state-not-reset-keeps-action-pending")
    if "context-drift" in codes:
        axes.add("runtime-context")
        required.add("controlled-runtime-context")
        falsifiers.add("context-digest-mismatch-keeps-action-pending")

    if status == "insufficient":
        axes.add("independent-repeat")
    if status == "unstable" and not codes:
        axes.add("state-lifecycle")
        required.add("state-reset-observed")
        falsifiers.add("state-not-reset-keeps-action-pending")

    paired_lanes = ["environment-gap"] if status == "environment-gap" \
        else ["positive", "negative"]
    return {
        "isolation_axes": sorted(axes)[:MAX_CODES],
        "matrix_shape": {
            "repeat_count": 2,
            "paired_lanes": paired_lanes,
            "lock_context": ["version", "safe_mode", "fixture", "runtime_context"],
            "reset_state": bool({"state-drift", "reproduction-drift"} & set(codes))
            or status in {"unstable", "insufficient"},
            "comparison_required": status != "environment-gap" and (
                "comparison-drift" in codes or
                "effect-presence-drift" in codes),
        },
        "required_observations": sorted(required)[:MAX_CODES],
        "falsifiers": sorted(falsifiers)[:MAX_CODES],
        "next_action": next_action,
    }


def _normalize_entry(raw: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, Mapping):
        return None
    research_key = _text(raw.get("research_key"), 80)
    status = _status(raw.get("status"))
    if not research_key or not status:
        return None
    codes = _bounded(raw.get("conflict_codes"), {
        "effect-presence-drift", "reproduction-drift", "comparison-drift",
        "state-drift", "context-drift",
    })
    # Status owns the scheduling action.  Do not let a copied or forged
    # `next_action` turn an environment gap into an executable replay.
    action = {
        "environment-gap": "repair-environment",
        "insufficient": "collect-independent-observation",
        "conflicted": "repeat-with-controlled-context",
        "unstable": "isolate-state",
    }[status]
    contract = _derived_contract(status, codes, action)
    return {
        "research_key": research_key,
        "candidate_id": _text(raw.get("candidate_id"), 120),
        "status": status,
        "next_action": contract["next_action"],
        "conflict_codes": codes,
        "isolation_axes": contract["isolation_axes"],
        "matrix_shape": contract["matrix_shape"],
        "required_observations": contract["required_observations"],
        "falsifiers": contract["falsifiers"],
        "claim_status": ACTION_CLAIM_STATUS,
    }


def _summary(entries: List[Mapping[str, Any]]) -> Dict[str, Any]:
    statuses = Counter(str(item.get("status")) for item in entries)
    actions = Counter(str(item.get("next_action")) for item in entries)
    axes = Counter(axis for item in entries
                   for axis in item.get("isolation_axes") or [])
    return {
        "action_count": len(entries),
        "conflicted_entries": statuses.get("conflicted", 0),
        "unstable_entries": statuses.get("unstable", 0),
        "environment_gap_entries": statuses.get("environment-gap", 0),
        "insufficient_entries": statuses.get("insufficient", 0),
        "action_counts": dict(sorted(actions.items())),
        "axis_counts": dict(sorted(axes.items())),
        "claim_status": ACTION_CLAIM_STATUS,
    }


def _empty() -> Dict[str, Any]:
    return {
        "schema_version": ACTION_SCHEMA_VERSION,
        "summary": _summary([]),
        "entries": [],
        "provenance": {
            "producer": "research-consistency-actions",
            "confidence": "bounded-controlled-recheck",
            "evidence_type": "research-metadata",
            "claim_status": ACTION_CLAIM_STATUS,
        },
        "claim_status": ACTION_CLAIM_STATUS,
    }


def normalize_research_consistency_actions(raw: Any) -> Dict[str, Any]:
    """Normalize an action artifact and recompute its bounded summary."""
    if not isinstance(raw, Mapping) or \
            raw.get("schema_version") != ACTION_SCHEMA_VERSION:
        return {}
    entries: List[Dict[str, Any]] = []
    seen = set()
    for item in raw.get("entries") or []:
        entry = _normalize_entry(item)
        if not entry or entry["research_key"] in seen:
            continue
        seen.add(entry["research_key"])
        entries.append(entry)
        if len(entries) >= MAX_ENTRIES:
            break
    entries.sort(key=lambda item: item["research_key"])
    result = _empty()
    result["entries"] = entries
    result["summary"] = _summary(entries)
    return result


def normalize_research_consistency_action(raw: Any) -> Dict[str, Any]:
    """Normalize one embedded action contract for S2/S4 consumers."""
    return _normalize_entry(raw) or {}


def build_research_consistency_actions(
        consistency: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """Build one controlled recheck contract for each non-consistent row."""
    normalized = normalize_research_consistency(consistency)
    if not normalized:
        return _empty()
    entries: List[Dict[str, Any]] = []
    for row in normalized.get("entries") or []:
        if not isinstance(row, Mapping):
            continue
        status = _status(row.get("status"))
        if not status:
            continue
        # Consistent rows have no pending action.  Keeping them out of the
        # action artifact makes the artifact directly executable by S2.
        if status not in ACTION_STATUSES:
            continue
        entry = _normalize_entry({
            "research_key": row.get("research_key"),
            "candidate_id": row.get("candidate_id"),
            "status": status,
            "next_action": row.get("next_action"),
            "conflict_codes": row.get("conflict_codes"),
        })
        if entry:
            entries.append(entry)
        if len(entries) >= MAX_ENTRIES:
            break
    entries.sort(key=lambda item: item["research_key"])
    result = _empty()
    result["entries"] = entries
    result["summary"] = _summary(entries)
    return result


def consistency_actions_path(workspace: Path, target: str) -> Path:
    return (Path(workspace).resolve() / "state" / str(target) /
            "coverage" / ACTION_FILENAME)


def write_research_consistency_actions(
        workspace: Path, target: str, actions: Mapping[str, Any]) -> Path:
    path = consistency_actions_path(workspace, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = normalize_research_consistency_actions(actions)
    if not payload:
        payload = _empty()
    temporary = path.with_name(".%s.tmp.%d" % (path.name, os.getpid()))
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                         encoding="utf-8")
    temporary.replace(path)
    return path


def load_research_consistency_actions(workspace: Path, target: str) -> Dict[str, Any]:
    path = consistency_actions_path(workspace, target)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError):
        return {}
    return normalize_research_consistency_actions(raw)


def action_for_research_key(actions: Mapping[str, Any], research_key: Any,
                            candidate_id: Any = "") -> Dict[str, Any]:
    """Return one normalized action using stable key first, id as fallback."""
    normalized = normalize_research_consistency_actions(actions)
    key = _text(research_key, 80)
    candidate = _text(candidate_id, 120)
    for entry in normalized.get("entries") or []:
        if key and entry.get("research_key") == key:
            return dict(entry)
    for entry in normalized.get("entries") or []:
        if candidate and entry.get("candidate_id") == candidate:
            return dict(entry)
    return {}
