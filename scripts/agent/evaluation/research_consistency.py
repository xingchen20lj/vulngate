"""Detect cross-round evidence inconsistency without making findings.

Research memory intentionally keeps more than the latest runtime state, but a
consumer that only follows that latest state can still miss an important expert
signal: the same mechanism behaved differently across comparable runs.  This
module turns that signal into a bounded, replayable scheduling artifact.

The result is a consistency view, not a verdict.  It stores only allowlisted
state classes, booleans, digests, and round references.  It never copies source
prose, payloads, commands, process output, credentials, or finding conclusions.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ..tools.redaction import redact_text


CONSISTENCY_SCHEMA_VERSION = "research-consistency-v1"
CONSISTENCY_FILENAME = "research-consistency.json"
CONSISTENCY_CLAIM_STATUS = "not-a-finding"

MAX_ENTRIES = 64
MAX_EVENTS_PER_ENTRY = 8
MAX_ROUNDS = 16
MAX_CODES = 8
MAX_DIGESTS = 8
MAX_TEXT = 120

STATUSES = frozenset({
    "consistent", "conflicted", "unstable", "insufficient",
    "environment-gap",
})
ACTIONS = frozenset({
    "hold-for-new-evidence",
    "repeat-with-controlled-context",
    "isolate-state",
    "collect-independent-observation",
    "repair-environment",
})
CONFLICT_CODES = frozenset({
    "effect-presence-drift",
    "reproduction-drift",
    "comparison-drift",
    "state-drift",
    "context-drift",
})
EFFECT_CLASSES = frozenset({
    "effect-observed", "no-effect-observed", "observation-only",
    "environment-gap", "unknown",
})
COMPARISON_CLASSES = frozenset({
    "difference-observed", "signature-drift", "same-observation",
    "inconclusive", "unobserved",
})
RUNTIME_STATES = frozenset({
    "stable-reproducer", "stable-observation", "environment-gap",
    "unstable-replay", "actionable-difference", "inconclusive",
})
GAP_EXECUTION_STATES = frozenset({
    "unexecuted", "run-failed", "precondition-unavailable",
    "gate-blocked", "harness-error", "inconclusive", "disabled",
})
_DIGEST_RE = re.compile(r"^[0-9a-f]{16,64}$")


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


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode(
        "utf-8", errors="replace")).hexdigest()[:24]


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


def _event_sort_key(event: Mapping[str, Any]) -> Tuple[int, str]:
    return (_int(event.get("round"), 0, 0, 1000000),
            _text(event.get("event_id"), 80))


def _meaningful_events(entry: Mapping[str, Any]) -> List[Dict[str, Any]]:
    events = []
    for raw in entry.get("events") or []:
        if not isinstance(raw, Mapping):
            continue
        state = _text(raw.get("state"), 80).lower()
        if state not in RUNTIME_STATES:
            continue
        events.append(dict(raw))
    events.sort(key=_event_sort_key)
    return events[-MAX_EVENTS_PER_ENTRY:]


def _execution_states(evidence: Mapping[str, Any]) -> List[str]:
    raw = evidence.get("execution_states") or []
    if isinstance(raw, (str, bytes)):
        raw = [raw]
    if not isinstance(raw, (list, tuple, set)):
        return []
    allowed = {
        "executed", "executed-no-effect", "executed-with-effect",
        *GAP_EXECUTION_STATES,
    }
    return sorted({
        _text(value, 48).lower() for value in raw
        if _text(value, 48).lower() in allowed
    })[:MAX_CODES]


def _variant_signal_set(evidence: Mapping[str, Any]) -> set:
    variant = evidence.get("variant_evidence")
    if not isinstance(variant, Mapping):
        return set()
    return set(_bounded(
        variant.get("observed_signals"),
        {
            "execution", "entry-behavior", "authorization",
            "negative-baseline", "capability-trace", "state-sequence",
            "typed-effect", "safe-equivalent", "environment-gap",
            "evidence-field", "runtime-error",
        }, 16, 64))


def _effect_class(evidence: Mapping[str, Any]) -> str:
    states = set(_execution_states(evidence))
    signals = _variant_signal_set(evidence)
    variant = evidence.get("variant_evidence")
    if isinstance(variant, Mapping):
        for cell in variant.get("cells") or []:
            if isinstance(cell, Mapping) and cell.get("typed_effect_observed") is True:
                return "effect-observed"
    if "executed-with-effect" in states or "typed-effect" in signals:
        return "effect-observed"
    if "executed-no-effect" in states or "safe-equivalent" in signals:
        return "no-effect-observed"
    replay_status = _text(evidence.get("replay_status"), 80).lower()
    if (replay_status in {"precondition-unavailable", "run-failed", "disabled"}
            or states & GAP_EXECUTION_STATES
            or "environment-gap" in signals):
        return "environment-gap"
    if "executed" in states or replay_status in {"stable", "completed"}:
        return "observation-only"
    return "unknown"


def _reproduction_class(evidence: Mapping[str, Any]) -> str:
    value = evidence.get("reproduces_expected")
    if value is True:
        return "true"
    if value is False:
        return "false"
    return "unknown"


def _comparison_class(evidence: Mapping[str, Any]) -> str:
    comparison = evidence.get("comparison")
    if isinstance(comparison, Mapping):
        status = _text(comparison.get("status"), 48).lower()
        if status in COMPARISON_CLASSES:
            return status
    status = _text(evidence.get("differential_status"), 100).lower()
    if status.startswith("difference"):
        return "difference-observed"
    if status == "signature-drift":
        return "signature-drift"
    if status == "same-observation":
        return "same-observation"
    if status in {"inconclusive", "environment-gap", "not-executed"}:
        return "inconclusive"
    return "unobserved"


def _context_digest(evidence: Mapping[str, Any]) -> str:
    context = evidence.get("runtime_context")
    if isinstance(context, Mapping):
        digest = _text(context.get("context_digest"), 64).lower()
        if _DIGEST_RE.fullmatch(digest):
            return digest
    digest = _text(evidence.get("configuration_digest"), 64).lower()
    return digest if _DIGEST_RE.fullmatch(digest) else ""


def _observation(event: Mapping[str, Any]) -> Dict[str, Any]:
    evidence = event.get("evidence")
    if not isinstance(evidence, Mapping):
        evidence = {}
    state = _text(event.get("state"), 80).lower()
    effect = _effect_class(evidence)
    reproduction = _reproduction_class(evidence)
    comparison = _comparison_class(evidence)
    context = _context_digest(evidence)
    signals = sorted(_variant_signal_set(evidence))
    execution = _execution_states(evidence)
    fingerprint = _digest({
        "state": state,
        "effect": effect,
        "reproduction": reproduction,
        "comparison": comparison,
        "context": context,
        "signals": signals,
        "execution": execution,
    })
    return {
        "round": _int(event.get("round"), 0, 0, 1000000),
        "state": state,
        "effect_class": effect,
        "reproduction": reproduction,
        "comparison_class": comparison,
        "context_digest": context,
        "fingerprint": fingerprint,
    }


def _conflict_codes(observations: Sequence[Mapping[str, Any]]) -> List[str]:
    comparable = [row for row in observations
                  if row.get("effect_class") != "environment-gap"]
    effects = {row.get("effect_class") for row in comparable}
    reproductions = {row.get("reproduction") for row in comparable
                     if row.get("reproduction") != "unknown"}
    comparisons = {row.get("comparison_class") for row in comparable
                   if row.get("comparison_class") not in {"unobserved", "inconclusive"}}
    states = {row.get("state") for row in comparable}
    codes: List[str] = []
    if {"effect-observed", "no-effect-observed"} <= effects:
        codes.append("effect-presence-drift")
    if {"true", "false"} <= reproductions:
        codes.append("reproduction-drift")
    if len(comparisons) > 1:
        codes.append("comparison-drift")
    if len(states) > 1:
        codes.append("state-drift")
    contexts = {row.get("context_digest") for row in comparable
                if row.get("context_digest")}
    if len(contexts) > 1:
        codes.append("context-drift")
    return codes[:MAX_CODES]


def _status_and_action(observations: Sequence[Mapping[str, Any]],
                       codes: Sequence[str]) -> Tuple[str, str]:
    comparable = [row for row in observations
                  if row.get("effect_class") != "environment-gap"]
    if not comparable:
        return "environment-gap", "repair-environment"
    if len(comparable) < 2:
        return "insufficient", "collect-independent-observation"
    if any(code in codes for code in (
            "effect-presence-drift", "reproduction-drift", "comparison-drift")):
        return "conflicted", "repeat-with-controlled-context"
    if codes:
        return "unstable", "isolate-state"
    fingerprints = {row.get("fingerprint") for row in comparable}
    if len(fingerprints) > 1:
        return "unstable", "isolate-state"
    return "consistent", "hold-for-new-evidence"


def _normalize_row(raw: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, Mapping):
        return None
    key = _text(raw.get("research_key"), 80)
    if not key:
        return None
    observations = []
    for item in raw.get("observations") or []:
        if not isinstance(item, Mapping):
            continue
        effect = _text(item.get("effect_class"), 40).lower()
        if effect not in EFFECT_CLASSES:
            effect = "unknown"
        reproduction = _text(item.get("reproduction"), 16).lower()
        if reproduction not in {"true", "false", "unknown"}:
            reproduction = "unknown"
        comparison = _text(item.get("comparison_class"), 40).lower()
        if comparison not in COMPARISON_CLASSES:
            comparison = "unobserved"
        digest = _text(item.get("context_digest"), 64).lower()
        if not _DIGEST_RE.fullmatch(digest):
            digest = ""
        fingerprint = _text(item.get("fingerprint"), 64).lower()
        if not _DIGEST_RE.fullmatch(fingerprint):
            fingerprint = ""
        state = _text(item.get("state"), 80).lower()
        if state not in RUNTIME_STATES:
            state = "inconclusive"
        observations.append({
            "round": _int(item.get("round"), 0, 0, 1000000),
            "state": state,
            "effect_class": effect,
            "reproduction": reproduction,
            "comparison_class": comparison,
            "context_digest": digest,
            "fingerprint": fingerprint,
        })
        if len(observations) >= MAX_EVENTS_PER_ENTRY:
            break
    observations.sort(key=lambda item: (item["round"], item["fingerprint"]))
    codes = _conflict_codes(observations)
    status, action = _status_and_action(observations, codes)
    rounds = sorted({item["round"] for item in observations})[:MAX_ROUNDS]
    fingerprints = sorted({item["fingerprint"] for item in observations
                           if item.get("fingerprint")})[:MAX_DIGESTS]
    contexts = sorted({item["context_digest"] for item in observations
                       if item.get("context_digest")})[:MAX_DIGESTS]
    return {
        "research_key": key,
        "candidate_id": _text(raw.get("candidate_id"), 120),
        "status": status,
        "next_action": action,
        "observation_count": len(observations),
        "comparable_count": sum(
            1 for item in observations
            if item.get("effect_class") != "environment-gap"
        ),
        "rounds": rounds,
        "observation_fingerprints": fingerprints,
        "context_digests": contexts,
        "conflict_codes": codes,
        "observed_effect_classes": sorted({
            item["effect_class"] for item in observations
        })[:MAX_CODES],
        "observed_comparison_classes": sorted({
            item["comparison_class"] for item in observations
        })[:MAX_CODES],
        "observations": observations,
        "claim_status": CONSISTENCY_CLAIM_STATUS,
    }


def _summary(rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    statuses = Counter(str(row.get("status")) for row in rows)
    actions = Counter(str(row.get("next_action")) for row in rows)
    conflicts = Counter(code for row in rows
                        for code in row.get("conflict_codes") or [])
    return {
        "entry_count": len(rows),
        "observation_count": sum(_int(row.get("observation_count"), 0)
                                  for row in rows),
        "comparable_observations": sum(_int(row.get("comparable_count"), 0)
                                       for row in rows),
        "conflicted_entries": statuses.get("conflicted", 0),
        "unstable_entries": statuses.get("unstable", 0),
        "environment_gap_entries": statuses.get("environment-gap", 0),
        "insufficient_entries": statuses.get("insufficient", 0),
        "consistent_entries": statuses.get("consistent", 0),
        "statuses": dict(sorted(statuses.items())),
        "actions": dict(sorted(actions.items())),
        "conflict_codes": dict(sorted(conflicts.items())),
        "claim_status": CONSISTENCY_CLAIM_STATUS,
    }


def _empty() -> Dict[str, Any]:
    return {
        "schema_version": CONSISTENCY_SCHEMA_VERSION,
        "summary": _summary([]),
        "entries": [],
        "provenance": {
            "producer": "research-consistency",
            "confidence": "bounded-comparison",
            "evidence_type": "research-metadata",
            "claim_status": CONSISTENCY_CLAIM_STATUS,
        },
        "claim_status": CONSISTENCY_CLAIM_STATUS,
    }


def normalize_research_consistency(raw: Any) -> Dict[str, Any]:
    """Normalize a consistency artifact and recompute its aggregate summary."""
    if not isinstance(raw, Mapping) or \
            raw.get("schema_version") != CONSISTENCY_SCHEMA_VERSION:
        return {}
    rows: List[Dict[str, Any]] = []
    seen = set()
    for item in raw.get("entries") or []:
        row = _normalize_row(item)
        if not row or row["research_key"] in seen:
            continue
        seen.add(row["research_key"])
        rows.append(row)
        if len(rows) >= MAX_ENTRIES:
            break
    rows.sort(key=lambda row: row["research_key"])
    result = _empty()
    result["entries"] = rows
    result["summary"] = _summary(rows)
    return result


def build_research_consistency(memory: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """Build a bounded consistency view from normalized research memory."""
    if not isinstance(memory, Mapping):
        return _empty()
    rows: List[Dict[str, Any]] = []
    for entry in memory.get("entries") or []:
        if not isinstance(entry, Mapping):
            continue
        key = _text(entry.get("research_key"), 80)
        if not key:
            continue
        events = _meaningful_events(entry)
        observations = [_observation(event) for event in events]
        codes = _conflict_codes(observations)
        status, action = _status_and_action(observations, codes)
        comparable = [row for row in observations
                      if row.get("effect_class") != "environment-gap"]
        rows.append({
            "research_key": key,
            "candidate_id": _text(entry.get("candidate_id"), 120),
            "status": status,
            "next_action": action,
            "observation_count": len(observations),
            "comparable_count": len(comparable),
            "rounds": sorted({row["round"] for row in observations})[:MAX_ROUNDS],
            "observation_fingerprints": sorted({
                row["fingerprint"] for row in observations
                if row.get("fingerprint")
            })[:MAX_DIGESTS],
            "context_digests": sorted({
                row["context_digest"] for row in observations
                if row.get("context_digest")
            })[:MAX_DIGESTS],
            "conflict_codes": codes,
            "observed_effect_classes": sorted({
                row["effect_class"] for row in observations
            })[:MAX_CODES],
            "observed_comparison_classes": sorted({
                row["comparison_class"] for row in observations
            })[:MAX_CODES],
            "observations": observations,
            "claim_status": CONSISTENCY_CLAIM_STATUS,
        })
        if len(rows) >= MAX_ENTRIES:
            break
    rows.sort(key=lambda row: row["research_key"])
    result = _empty()
    result["entries"] = rows
    result["summary"] = _summary(rows)
    return result


def consistency_path(workspace: Path, target: str) -> Path:
    return (Path(workspace).resolve() / "state" / str(target) /
            "coverage" / CONSISTENCY_FILENAME)


def write_research_consistency(workspace: Path, target: str,
                               consistency: Mapping[str, Any]) -> Path:
    path = consistency_path(workspace, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = normalize_research_consistency(consistency)
    if not payload:
        payload = _empty()
    temporary = path.with_name(".%s.tmp.%d" % (path.name, os.getpid()))
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                         encoding="utf-8")
    temporary.replace(path)
    return path


def load_research_consistency(workspace: Path, target: str) -> Dict[str, Any]:
    path = consistency_path(workspace, target)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError):
        return {}
    return normalize_research_consistency(raw)
