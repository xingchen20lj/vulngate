"""Verify execution of a bounded cross-round consistency recheck.

``research-consistency-action-v1`` is a scheduling contract.  This module is
the closure boundary: it consumes only normalized S4 lane evidence and
reports whether the contract was observed, partially observed, blocked by the
environment, or not executed.  It never promotes an observation into a
finding and never stores source prose, payloads, commands, process output, or
credentials.
"""

from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from .research_consistency_actions import (
    ACTION_CLAIM_STATUS,
    LANES,
    REQUIRED_OBSERVATIONS,
    normalize_research_consistency_action,
    normalize_research_consistency_actions,
    normalize_research_consistency_lane,
)
from ..tools.redaction import redact_text


RECHECK_SCHEMA_VERSION = "research-consistency-recheck-v1"
RECHECK_FILENAME = "research-consistency-rechecks.json"
RECHECK_CLAIM_STATUS = ACTION_CLAIM_STATUS

MAX_ENTRIES = 64
MAX_LANES = 8
MAX_CODES = 12
MAX_TEXT = 120

RECHECK_STATUSES = frozenset({
    "observed", "partial", "environment-gap", "not-executed",
})
_GAP_PRECONDITIONS = frozenset({
    "precondition-unavailable", "run-failed", "gate-blocked", "policy-denied",
})
_COMPARISON_GAPS = frozenset({"", "unexecuted", "inconclusive"})
_EFFECT_MARKERS = ("canary", "simulat", "shape-only", "in-memory")


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


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() not in {
        "", "false", "none", "null", "0", "no",
    }


def _bounded(values: Any, allowed: Iterable[str], limit: int = MAX_CODES,
             item_limit: int = MAX_TEXT) -> List[str]:
    if isinstance(values, (str, bytes)):
        values = [values]
    if not isinstance(values, (list, tuple, set)):
        return []
    allow = set(allowed)
    result = []
    for value in values:
        item = _text(value, item_limit).lower()
        if item in allow and item not in result:
            result.append(item)
        if len(result) >= limit:
            break
    return sorted(result)


def _observations(row: Mapping[str, Any]) -> Mapping[str, Any]:
    value = row.get("observations")
    return value if isinstance(value, Mapping) else {}


def _gap(row: Mapping[str, Any], obs: Mapping[str, Any]) -> bool:
    if _text(row.get("precondition_status"), 64).lower() in _GAP_PRECONDITIONS:
        return True
    if row.get("compile_error") or row.get("harness_error") or row.get("timed_out"):
        return True
    if _text(obs.get("ENV_ERROR"), 80):
        return True
    return (isinstance(row.get("returncode"), int)
            and not isinstance(row.get("returncode"), bool)
            and row.get("returncode") != 0)


def _signal_set(rows: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    signals = set()
    gap_count = 0
    execution_count = 0
    typed_effect = False
    safe_equivalent = False
    state_reset = False
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        obs = _observations(row)
        is_gap = _gap(row, obs)
        if is_gap:
            gap_count += 1
            signals.add("environment-status")
        else:
            execution_count += 1
            if row.get("returncode") in (None, 0, "0"):
                signals.add("execution")
        availability = _text(obs.get("AVAILABILITY"), 80).lower()
        if availability in {"true", "yes", "ok", "available", "ready",
                            "healthy"} or _bool(obs.get("ENV_READY")) \
                or _bool(obs.get("RUNTIME_READY")) \
                or _bool(obs.get("HEALTHCHECK")):
            signals.add("environment-status")
        effect_kind = _text(obs.get("EFFECT_KIND"), 80).lower()
        effect = _text(obs.get("EFFECT", obs.get("SIDE_EFFECT")), 80)
        if effect_kind and effect and not any(
                marker in effect_kind for marker in _EFFECT_MARKERS):
            typed_effect = True
            signals.add("positive-effect-or-safe-equivalent")
        if (_bool(obs.get("CANARY")) or _bool(obs.get("SAFE_EQUIVALENT"))
                or (effect_kind and any(marker in effect_kind
                                        for marker in _EFFECT_MARKERS))):
            safe_equivalent = True
            signals.add("positive-effect-or-safe-equivalent")
        if (_bool(obs.get("STATE_RESET")) or _bool(obs.get("RESET_STATE"))
                or _bool(obs.get("STATE_CLEAN"))):
            state_reset = True
            signals.add("state-reset-observed")
    return {
        "signals": sorted(signals),
        "gap_count": min(gap_count, 64),
        "execution_count": min(execution_count, 64),
        "typed_effect_observed": typed_effect,
        "safe_equivalent_observed": safe_equivalent,
        "state_reset_observed": state_reset,
    }


def _action_entries(actions: Any) -> Dict[str, Dict[str, Any]]:
    normalized = normalize_research_consistency_actions(actions)
    result: Dict[str, Dict[str, Any]] = {}
    for item in normalized.get("entries") or []:
        key = _text(item.get("research_key"), 80)
        if key:
            result[key] = dict(item)
    return result


def _fixture_action(fixture: Mapping[str, Any], expected: Mapping[str, Any]
                    ) -> Dict[str, Any]:
    action = normalize_research_consistency_action(
        fixture.get("consistency_action"))
    if action:
        return action
    candidate_id = _text(fixture.get("candidate_id"), 120)
    for item in expected.values():
        if candidate_id and _text(item.get("candidate_id"), 120) == candidate_id:
            return dict(item)
    return {}


def _lane_evidence(fixture: Mapping[str, Any]) -> Dict[str, Any]:
    raw = fixture.get("consistency_recheck")
    if not isinstance(raw, Mapping):
        return {}
    lane = normalize_research_consistency_lane(raw.get("lane"))
    if not lane:
        return {}
    signals = _bounded(raw.get("observed_observations"), REQUIRED_OBSERVATIONS,
                       MAX_CODES)
    missing = _bounded(raw.get("missing_observations"), REQUIRED_OBSERVATIONS,
                       MAX_CODES)
    status = _text(raw.get("status"), 32).lower()
    if status not in RECHECK_STATUSES:
        status = "partial"
    return {
        "lane": lane,
        "status": status,
        "fixture_id": _text(fixture.get("fixture_id"), 100),
        "template_key": _text(fixture.get("template_key"), 100),
        "context_digest": _text(fixture.get("context_digest"), 40),
        "base_version": _text(fixture.get("base_version"), 80),
        "base_safe_mode": bool(fixture.get("base_safe_mode", False)),
        "base_context_complete": bool(
            _text(fixture.get("base_version"), 80)
            and "base_safe_mode" in fixture),
        "replay_attempts": _int(raw.get("replay_attempts"), 0, 0, 8),
        "row_count": _int(raw.get("row_count"), 0, 0, 128),
        "cells_with_gap": _int(raw.get("cells_with_gap"), 0, 0, 128),
        "observed_observations": signals,
        "missing_observations": missing,
        "comparison_status": _text(raw.get("comparison_status"), 64).lower(),
        "typed_effect_observed": bool(raw.get("typed_effect_observed")),
        "safe_equivalent_observed": bool(raw.get("safe_equivalent_observed")),
        "state_reset_observed": bool(raw.get("state_reset_observed")),
        "claim_status": RECHECK_CLAIM_STATUS,
    }


def summarize_recheck_lane(action: Any, fixture: Mapping[str, Any],
                           rows: Iterable[Mapping[str, Any]],
                           replay: Mapping[str, Any],
                           differential: Mapping[str, Any],
                           comparison: Mapping[str, Any]) -> Dict[str, Any]:
    """Build one safe lane witness from raw S4 rows before they are reduced."""
    normalized = normalize_research_consistency_action(action)
    if not normalized:
        return {}
    lane = normalize_research_consistency_lane(fixture.get("consistency_lane"))
    if not lane:
        return {}
    bounded_rows = [row for row in rows if isinstance(row, Mapping)][:128]
    signal_view = _signal_set(bounded_rows)
    repeat_count = _int((normalized.get("matrix_shape") or {}).get(
        "repeat_count"), 2, 1, 8)
    attempts = _int((replay or {}).get("attempts"), 0, 0, 8)
    if attempts >= repeat_count:
        signal_view["signals"].append("independent-replay")
    required = set(_bounded(normalized.get("required_observations"),
                            REQUIRED_OBSERVATIONS, MAX_CODES))
    observed = set(signal_view["signals"])
    # These two identity/context observations are closed only at aggregate
    # time, after both paired lanes are available.
    if fixture.get("template_key"):
        observed.add("same-fixture-identity")
    if fixture.get("context_digest"):
        observed.add("controlled-runtime-context")
    comparison_status = _text(
        (comparison or {}).get("status"), 64).lower()
    comparison_required = bool((normalized.get("matrix_shape") or {}).get(
        "comparison_required"))
    if comparison_required and comparison_status not in _COMPARISON_GAPS:
        observed.add("comparison-arm-status")
    missing = sorted(required - observed)
    if not bounded_rows:
        status = "not-executed"
    elif signal_view["execution_count"] == 0 and signal_view["gap_count"]:
        status = "environment-gap"
    elif not missing:
        status = "observed"
    else:
        status = "partial"
    return {
        "schema_version": RECHECK_SCHEMA_VERSION,
        "lane": lane,
        "status": status,
        "row_count": len(bounded_rows),
        "replay_attempts": attempts,
        "cells_with_gap": signal_view["gap_count"],
        "observed_observations": sorted(observed & REQUIRED_OBSERVATIONS),
        "missing_observations": missing[:MAX_CODES],
        "comparison_status": comparison_status,
        "typed_effect_observed": bool(signal_view["typed_effect_observed"]),
        "safe_equivalent_observed": bool(
            signal_view["safe_equivalent_observed"]),
        "state_reset_observed": bool(signal_view["state_reset_observed"]),
        "claim_status": RECHECK_CLAIM_STATUS,
    }


def _entry_status(action: Mapping[str, Any], lanes: List[Dict[str, Any]],
                  runtime_status: str) -> Dict[str, Any]:
    shape = action.get("matrix_shape") or {}
    expected_lanes = [normalize_research_consistency_lane(item)
                      for item in shape.get("paired_lanes") or []]
    expected_lanes = [item for item in expected_lanes if item]
    if not expected_lanes:
        expected_lanes = ["environment-gap"] if action.get("status") == \
            "environment-gap" else ["positive", "negative"]
    by_lane: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for lane in lanes:
        by_lane[lane["lane"]].append(lane)
    selected: List[Dict[str, Any]] = []
    for lane in expected_lanes:
        selected.extend(by_lane.get(lane, []))
    missing_lanes = [lane for lane in expected_lanes if not by_lane.get(lane)]
    if not selected:
        status = "environment-gap" if runtime_status in _GAP_PRECONDITIONS \
            else "not-executed"
        return {
            "status": status,
            "expected_lanes": expected_lanes,
            "observed_lanes": [],
            "missing_lanes": missing_lanes,
            "observed_observations": [],
            "missing_observations": sorted(set(
                action.get("required_observations") or [])),
            "pending_falsifiers": sorted(set(action.get("falsifiers") or [])),
        }

    observed_lanes = sorted({lane["lane"] for lane in selected})
    all_gap = all(item.get("status") == "environment-gap" for item in selected)
    observed = set(item for lane in selected
                   for item in lane.get("observed_observations") or [])
    required = set(action.get("required_observations") or [])
    missing_observations = set(required - observed)
    templates = {lane.get("template_key") for lane in selected
                 if lane.get("template_key")}
    contexts = {lane.get("context_digest") for lane in selected
                if lane.get("context_digest")}
    if len(templates) != 1:
        missing_observations.add("same-fixture-identity")
    if len(contexts) != 1:
        missing_observations.add("controlled-runtime-context")
    base_contexts = {
        (lane.get("base_version"), bool(lane.get("base_safe_mode")))
        for lane in selected
    }
    if (len(base_contexts) != 1
            or not all(lane.get("base_context_complete") for lane in selected)):
        missing_observations.add("controlled-runtime-context")
    repeat_count = _int(shape.get("repeat_count"), 2, 1, 8)
    if any(_int(item.get("replay_attempts"), 0, 0, 8) < repeat_count
           for item in selected):
        missing_observations.add("independent-replay")
    if missing_lanes:
        missing_observations.add("same-fixture-identity")

    comparison_required = bool(shape.get("comparison_required"))
    comparison_missing = comparison_required and any(
        _text(item.get("comparison_status"), 64).lower() in _COMPARISON_GAPS
        for item in selected)
    if comparison_missing:
        missing_observations.add("comparison-arm-status")

    typed = any(item.get("typed_effect_observed") for item in selected)
    safe = any(item.get("safe_equivalent_observed") for item in selected)
    if ("positive-effect-or-safe-equivalent" in required
            and not (typed or safe)):
        missing_observations.add("positive-effect-or-safe-equivalent")

    action_falsifiers = set(action.get("falsifiers") or [])
    pending = set()
    missing_to_falsifiers = {
        "independent-replay": {
            "missing-independent-replay-keeps-action-pending",
        },
        "same-fixture-identity": {
            "fixture-identity-mismatch-keeps-action-pending",
        },
        "controlled-runtime-context": {
            "context-digest-mismatch-keeps-action-pending",
        },
        "state-reset-observed": {
            "state-not-reset-keeps-action-pending",
        },
        "comparison-arm-status": {
            "comparison-arm-mismatch-keeps-action-pending",
        },
        "positive-effect-or-safe-equivalent": {
            "typed-effect-or-safe-equivalent-missing",
            "signature-drift-is-not-effect",
        },
    }
    for observation, falsifiers in missing_to_falsifiers.items():
        if observation in missing_observations:
            pending.update(action_falsifiers & falsifiers)
    if action.get("status") == "environment-gap":
        status = "environment-gap" if all_gap else "partial"
        pending = {"environment-gap-keeps-action-pending"}
    elif all_gap:
        status = "environment-gap"
    elif missing_observations:
        status = "partial"
    else:
        status = "observed"
    return {
        "status": status,
        "expected_lanes": expected_lanes,
        "observed_lanes": observed_lanes,
        "missing_lanes": missing_lanes,
        "observed_observations": sorted(observed & REQUIRED_OBSERVATIONS),
        "missing_observations": sorted(missing_observations)[:MAX_CODES],
        "pending_falsifiers": sorted(pending)[:MAX_CODES],
    }


def _empty() -> Dict[str, Any]:
    return {
        "schema_version": RECHECK_SCHEMA_VERSION,
        "summary": {
            "entry_count": 0,
            "observed": 0,
            "partial": 0,
            "environment_gap": 0,
            "not_executed": 0,
            "claim_status": RECHECK_CLAIM_STATUS,
        },
        "entries": [],
        "provenance": {
            "producer": "research-consistency-rechecks",
            "evidence_type": "bounded-s4-closure-metadata",
            "claim_status": RECHECK_CLAIM_STATUS,
        },
        "claim_status": RECHECK_CLAIM_STATUS,
    }


def build_research_consistency_rechecks(
        runtime_lab: Optional[Mapping[str, Any]],
        actions: Optional[Mapping[str, Any]] = None
        ) -> Dict[str, Any]:
    """Aggregate S4 lane witnesses against the pending action artifact."""
    runtime = runtime_lab if isinstance(runtime_lab, Mapping) else {}
    expected = _action_entries(actions)
    grouped: Dict[str, Dict[str, Any]] = {}
    for item in runtime.get("fixtures") or []:
        if not isinstance(item, Mapping):
            continue
        fixture = item.get("fixture")
        if not isinstance(fixture, Mapping):
            fixture = item
        action = _fixture_action(fixture, expected)
        key = _text(action.get("research_key"), 80)
        if not key:
            continue
        lane_source = dict(fixture)
        lane_source["consistency_recheck"] = item.get(
            "consistency_recheck", fixture.get("consistency_recheck"))
        lane = _lane_evidence(lane_source)
        if not lane:
            continue
        entry = grouped.setdefault(key, {
            "research_key": key,
            "candidate_id": _text(action.get("candidate_id"), 120),
            "action_status": _text(action.get("status"), 32).lower(),
            "conflict_codes": _bounded(action.get("conflict_codes"),
                                         {"effect-presence-drift",
                                          "reproduction-drift",
                                          "comparison-drift", "state-drift",
                                          "context-drift"}, 8, 64),
            "action": dict(action),
            "lanes": [],
            "runtime_status": _text(runtime.get("status"), 48).lower(),
        })
        entry["lanes"].append(lane)
    # A missing fixture must still be visible as a pending execution gap.  S8
    # passes the previous action artifact so an interrupted/disabled round is
    # not silently interpreted as closure.
    for key, action in expected.items():
        if key in grouped:
            continue
        grouped[key] = {
            "research_key": key,
            "candidate_id": _text(action.get("candidate_id"), 120),
            "action_status": _text(action.get("status"), 32).lower(),
            "conflict_codes": _bounded(action.get("conflict_codes"),
                                         {"effect-presence-drift",
                                          "reproduction-drift",
                                          "comparison-drift", "state-drift",
                                          "context-drift"}, 8, 64),
            "action": dict(action),
            "lanes": [],
            "runtime_status": _text(runtime.get("status"), 48).lower(),
        }

    entries: List[Dict[str, Any]] = []
    for key in sorted(grouped):
        raw = grouped[key]
        action = normalize_research_consistency_action(raw.get("action"))
        if not action:
            continue
        lanes = raw.get("lanes") or []
        closure = _entry_status(action, lanes, raw.get("runtime_status", ""))
        entries.append({
            "research_key": key,
            "candidate_id": _text(raw.get("candidate_id"), 120),
            "action_status": _text(action.get("status"), 32).lower(),
            "status": closure["status"],
            "conflict_codes": _bounded(action.get("conflict_codes"),
                                         {"effect-presence-drift",
                                          "reproduction-drift",
                                          "comparison-drift", "state-drift",
                                          "context-drift"}, 8, 64),
            "expected_lanes": closure["expected_lanes"],
            "observed_lanes": closure["observed_lanes"],
            "missing_lanes": closure["missing_lanes"],
            "observed_observations": closure["observed_observations"],
            "missing_observations": closure["missing_observations"],
            "pending_falsifiers": closure["pending_falsifiers"],
            "lane_evidence": lanes[:MAX_LANES],
            "round_runtime_status": _text(raw.get("runtime_status"), 48),
            "claim_status": RECHECK_CLAIM_STATUS,
        })
        if len(entries) >= MAX_ENTRIES:
            break
    summary_counts = Counter(item.get("status") for item in entries)
    result = _empty()
    result["entries"] = entries
    result["summary"] = {
        "entry_count": len(entries),
        "observed": summary_counts.get("observed", 0),
        "partial": summary_counts.get("partial", 0),
        "environment_gap": summary_counts.get("environment-gap", 0),
        "not_executed": summary_counts.get("not-executed", 0),
        "claim_status": RECHECK_CLAIM_STATUS,
    }
    return result


def normalize_research_consistency_rechecks(raw: Any) -> Dict[str, Any]:
    """Normalize a closure artifact and recompute its summary."""
    if not isinstance(raw, Mapping) or \
            raw.get("schema_version") != RECHECK_SCHEMA_VERSION:
        return {}
    result = _empty()
    entries: List[Dict[str, Any]] = []
    seen = set()
    for item in raw.get("entries") or []:
        if not isinstance(item, Mapping):
            continue
        key = _text(item.get("research_key"), 80)
        status = _text(item.get("status"), 32).lower()
        if not key or key in seen or status not in RECHECK_STATUSES:
            continue
        seen.add(key)
        lanes = []
        for lane in item.get("lane_evidence") or []:
            if not isinstance(lane, Mapping):
                continue
            lane_name = normalize_research_consistency_lane(lane.get("lane"))
            if not lane_name:
                continue
            lanes.append({
                "lane": lane_name,
                "status": _text(lane.get("status"), 32).lower()
                if _text(lane.get("status"), 32).lower() in RECHECK_STATUSES
                else "partial",
                "fixture_id": _text(lane.get("fixture_id"), 100),
                "template_key": _text(lane.get("template_key"), 100),
                "context_digest": _text(lane.get("context_digest"), 40),
                "base_version": _text(lane.get("base_version"), 80),
                "base_safe_mode": bool(lane.get("base_safe_mode", False)),
                "base_context_complete": bool(
                    lane.get("base_context_complete")),
                "replay_attempts": _int(lane.get("replay_attempts"), 0, 0, 8),
                "row_count": _int(lane.get("row_count"), 0, 0, 128),
                "cells_with_gap": _int(lane.get("cells_with_gap"), 0, 0, 128),
                "observed_observations": _bounded(
                    lane.get("observed_observations"), REQUIRED_OBSERVATIONS),
                "missing_observations": _bounded(
                    lane.get("missing_observations"), REQUIRED_OBSERVATIONS),
                "comparison_status": _text(
                    lane.get("comparison_status"), 64).lower(),
                "typed_effect_observed": bool(
                    lane.get("typed_effect_observed")),
                "safe_equivalent_observed": bool(
                    lane.get("safe_equivalent_observed")),
                "state_reset_observed": bool(
                    lane.get("state_reset_observed")),
                "claim_status": RECHECK_CLAIM_STATUS,
            })
        entries.append({
            "research_key": key,
            "candidate_id": _text(item.get("candidate_id"), 120),
            "action_status": _text(item.get("action_status"), 32).lower(),
            "status": status,
            "conflict_codes": _bounded(item.get("conflict_codes"),
                                         {"effect-presence-drift",
                                          "reproduction-drift",
                                          "comparison-drift", "state-drift",
                                          "context-drift"}, 8, 64),
            "expected_lanes": _bounded(item.get("expected_lanes"), LANES, 8, 24),
            "observed_lanes": _bounded(item.get("observed_lanes"), LANES, 8, 24),
            "missing_lanes": _bounded(item.get("missing_lanes"), LANES, 8, 24),
            "observed_observations": _bounded(
                item.get("observed_observations"), REQUIRED_OBSERVATIONS),
            "missing_observations": _bounded(
                item.get("missing_observations"), REQUIRED_OBSERVATIONS),
            "pending_falsifiers": _bounded(
                item.get("pending_falsifiers"), {
                    "environment-gap-keeps-action-pending",
                    "missing-independent-replay-keeps-action-pending",
                    "signature-drift-is-not-effect",
                    "state-not-reset-keeps-action-pending",
                    "context-digest-mismatch-keeps-action-pending",
                    "comparison-arm-mismatch-keeps-action-pending",
                    "fixture-identity-mismatch-keeps-action-pending",
                    "typed-effect-or-safe-equivalent-missing",
                }),
            "lane_evidence": lanes[:MAX_LANES],
            "round_runtime_status": _text(item.get("round_runtime_status"), 48),
            "claim_status": RECHECK_CLAIM_STATUS,
        })
        if len(entries) >= MAX_ENTRIES:
            break
    counts = Counter(item.get("status") for item in entries)
    result["entries"] = sorted(entries, key=lambda item: item["research_key"])
    result["summary"] = {
        "entry_count": len(entries),
        "observed": counts.get("observed", 0),
        "partial": counts.get("partial", 0),
        "environment_gap": counts.get("environment-gap", 0),
        "not_executed": counts.get("not-executed", 0),
        "claim_status": RECHECK_CLAIM_STATUS,
    }
    return result


def rechecks_path(workspace: Path, target: str) -> Path:
    return (Path(workspace).resolve() / "state" / str(target) /
            "coverage" / RECHECK_FILENAME)


def write_research_consistency_rechecks(
        workspace: Path, target: str, rechecks: Mapping[str, Any]) -> Path:
    path = rechecks_path(workspace, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = normalize_research_consistency_rechecks(rechecks) or _empty()
    temporary = path.with_name(".%s.tmp.%d" % (path.name, os.getpid()))
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                         encoding="utf-8")
    temporary.replace(path)
    return path


def load_research_consistency_rechecks(workspace: Path, target: str) -> Dict[str, Any]:
    path = rechecks_path(workspace, target)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError):
        return {}
    return normalize_research_consistency_rechecks(raw)
