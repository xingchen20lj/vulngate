"""Calibrate research guidance from real project round replays.

This module measures the part of the research loop that synthetic benchmark
cases cannot answer: whether a guidance decision in one real round produced a
new, bounded observation in a later round.  It reads only persisted S8
guidance/feedback and S4 runtime-lab summaries.  Raw source text, payloads,
commands, process output, credentials, and finding conclusions are never
copied into the calibration artifact.

The output is a scheduling policy, not a security judgment.  A calibrated
replacement threshold may delay a low-yield experiment replacement, but it
cannot alter a candidate, G4/G5, CVSS, or a ledger result.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ..analysis.research_strategy import normalize_research_guidance
from ..tools.redaction import redact_text


CALIBRATION_SCHEMA_VERSION = "research-replay-calibration-v1"
CALIBRATION_FILENAME = "research-replay-calibration.json"
CALIBRATION_CLAIM_STATUS = "not-a-finding"

MAX_ROUNDS = 128
MAX_GUIDANCE_ITEMS = 48
MAX_FEEDBACK_ITEMS = 48
MAX_OUTCOMES = 256
MAX_RECOMMENDATIONS = 8
MAX_TEXT = 120
MAX_JSON_BYTES = 8 * 1024 * 1024
MIN_REPLAYABLE_ITEMS = 3

REPLACEMENT_ZERO_GAIN_DEFAULT = 1
REPLACEMENT_ZERO_GAIN_MAX = 2
REPLACEMENT_HIT_RATE_LOW = 0.5
UNPRODUCTIVE_REPEAT_RATE_HIGH = 0.5
FIXTURE_TRUNCATION_RATE_HIGH = 0.25
COMPARISON_GAP_RATE_HIGH = 0.5

_ROUND_RE = re.compile(r"^round-(\d+)$")
_STRATEGY_ID_RE = re.compile(r"^rs-[0-9a-f]{20}$")
_ACTIONS = frozenset({
    "repair-environment", "replay-residual-variant", "review-followup",
    "reframe-scope", "add-negative-control", "trace-capability-transition",
    "review-source-dataflow", "add-typed-effect", "replay-new-variant",
    "continue-path-closure", "hold-for-new-evidence",
})
_OBSERVATION_STATUSES = frozenset({
    "unobserved", "execution-only", "partial", "complete",
    "environment-gap", "falsifier-observed",
})
_EXECUTION_STATES = frozenset({
    "executed", "executed-no-effect", "executed-with-effect",
    "unexecuted", "run-failed", "precondition-unavailable", "gate-blocked",
    "harness-error", "inconclusive", "disabled", "environment-gap",
})
_COMPARISON_STATUSES = frozenset({
    "difference-observed", "signature-drift", "inconclusive",
    "same-observation", "unobserved",
})
_COMPARISON_GAP_STATUSES = frozenset({"inconclusive", "unobserved"})
_OUTCOME_CODES = frozenset({
    "unobserved", "new-information", "replacement-productive",
    "replacement-observed-no-new-information", "repeat-no-new-information",
    "environment-recovered", "environment-still-gap",
    "changed-without-new-information",
})
_RECOMMENDATION_CODES = frozenset({
    "collect-more-replay", "retain-zero-gain-threshold",
    "require-consecutive-zero-gain", "increase-fixture-budget-or-split-lanes",
    "prioritize-comparison-gap-recovery", "no-threshold-change",
})
_RESEARCH_SURFACES = frozenset({
    "web", "protocol", "cloud", "mobile", "native",
})


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    try:
        value = redact_text(value)
    except Exception:  # pragma: no cover - defensive redaction boundary
        value = str(value)
    return " ".join(str(value).replace("\x00", "").split())[:limit]


def _int(value: Any, default: int = 0, minimum: int = 0,
         maximum: int = 1000000) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _number(value: Any, minimum: float = 0.0,
            maximum: float = 1.0) -> Optional[float]:
    if isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(parsed):
        return None
    return round(max(minimum, min(maximum, parsed)), 4)


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    return round(float(numerator) / float(denominator), 4) if denominator else None


def _bounded(values: Any, limit: int, item_limit: int = MAX_TEXT) -> List[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes)):
        values = [values]
    if not isinstance(values, (list, tuple, set)):
        return []
    result: List[str] = []
    seen = set()
    for value in values:
        item = _text(value, item_limit)
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
        if len(result) >= limit:
            break
    return sorted(result)


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def _digest(value: Any, prefix: str = "rc") -> str:
    return prefix + "-" + hashlib.sha256(
        _canonical(value).encode("utf-8", errors="replace")).hexdigest()[:24]


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        if not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _round_no(value: Any) -> int:
    return _int(value, 0, 0, 1000000)


def _variant_digest(value: Any) -> str:
    """Digest only canonical surface-plan identities, never plan prose."""
    if not isinstance(value, Mapping):
        return ""
    if _text(value.get("schema_version"), 60) != "surface-variant-plan-v1":
        return ""
    selected = []
    for row in value.get("selected_variants") or []:
        if not isinstance(row, Mapping):
            continue
        variant_id = _text(row.get("variant_id"), 96)
        family = _text(row.get("family"), 96)
        axis = _text(row.get("axis"), 96)
        if variant_id:
            selected.append({"variant_id": variant_id,
                             "family": family, "axis": axis})
        if len(selected) >= 3:
            break
    lanes = []
    for row in value.get("lanes") or []:
        if not isinstance(row, Mapping):
            continue
        variant_id = _text(row.get("variant_id"), 96)
        lane = _text(row.get("lane"), 24)
        if variant_id and lane:
            lanes.append({"variant_id": variant_id, "lane": lane})
        if len(lanes) >= 9:
            break
    if not selected and not lanes:
        return ""
    return _digest({"selected": selected, "lanes": lanes}, "sv")


def _guidance_surface(value: Any) -> str:
    """Keep only an explicit research surface for cohort aggregation."""
    if not isinstance(value, Mapping):
        return ""
    surface = _text(value.get("research_surface", value.get("surface")), 24).lower()
    if not surface:
        plan = value.get("surface_variant_plan")
        if isinstance(plan, Mapping):
            surface = _text(plan.get("surface"), 24).lower()
    return surface if surface in _RESEARCH_SURFACES else ""


def _normal_guidance_item(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    strategy_id = _text(value.get("strategy_id"), 80)
    if not _STRATEGY_ID_RE.fullmatch(strategy_id):
        return {}
    action = _text(value.get("next_action"), 64).lower()
    if action not in _ACTIONS:
        return {}
    observation_status = _text(value.get("observation_status"), 48).lower()
    if observation_status not in _OBSERVATION_STATUSES:
        observation_status = "unobserved"
    return {
        "strategy_id": strategy_id,
        "research_key": _text(value.get("research_key"), 80),
        "candidate_id": _text(value.get("candidate_id"), 120),
        "next_action": action,
        "replacement_recommended": bool(
            value.get("replacement_recommended")),
        "observation_status": observation_status,
        "surface": _guidance_surface(value),
        "variant_digest": _variant_digest(value.get("surface_variant_plan")),
        "round": _round_no(value.get("last_round", value.get("round", 0))),
    }


def _normalize_guidance(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        return {}
    normalized = normalize_research_guidance(dict(raw))
    if not normalized:
        return {}
    items: List[Dict[str, Any]] = []
    seen = set()
    for row in normalized.get("items") or []:
        item = _normal_guidance_item(row)
        if not item or item["strategy_id"] in seen:
            continue
        seen.add(item["strategy_id"])
        items.append(item)
        if len(items) >= MAX_GUIDANCE_ITEMS:
            break
    return {
        "round": _round_no(normalized.get("round")),
        "items": items,
    }


def _normal_feedback_observation(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    status = _text(value.get("status"), 48).lower()
    if status not in _OBSERVATION_STATUSES:
        status = "unobserved"
    current_status = _text(value.get("current_status"), 48).lower()
    if current_status not in _OBSERVATION_STATUSES:
        current_status = status
    states = [state for state in _bounded(
        value.get("execution_states"), 12, 48)
              if state in _EXECUTION_STATES]
    return {
        "status": status,
        "current_status": current_status,
        "information_gain": _int(value.get("information_gain"), 0, 0, 5),
        "new_signal_count": min(16, len(_bounded(
            value.get("new_signals"), 16, 48))),
        "execution_states": states,
    }


def _normalize_feedback(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        return {}
    if _text(raw.get("schema_version"), 64) != "research-strategy-feedback-v1":
        return {}
    items: List[Dict[str, Any]] = []
    seen = set()
    for row in raw.get("items") or []:
        if not isinstance(row, Mapping):
            continue
        strategy_id = _text(row.get("strategy_id"), 80)
        if not _STRATEGY_ID_RE.fullmatch(strategy_id) or strategy_id in seen:
            continue
        observation = _normal_feedback_observation(row.get("observation"))
        if not observation:
            continue
        seen.add(strategy_id)
        items.append({
            "strategy_id": strategy_id,
            "research_key": _text(row.get("research_key"), 80),
            "candidate_id": _text(row.get("candidate_id"), 120),
            "observation": observation,
        })
        if len(items) >= MAX_FEEDBACK_ITEMS:
            break
    return {
        "round": _round_no(raw.get("round")),
        "items": items,
    }


def _runtime_view(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        return {}
    status = _text(raw.get("status"), 48).lower()
    fixture_count = _int(raw.get("fixture_count"), 0, 0, 1000000)
    fixture_budget = _int(raw.get("fixture_budget"), 0, 0, 1000000)
    has_budget = "fixture_budget" in raw
    truncated = bool(raw.get("fixture_budget_truncated"))
    comparison_fixtures = 0
    comparison_gaps = 0
    inconclusive_cells = 0
    pending_arms = 0
    for item in raw.get("fixtures") or []:
        if not isinstance(item, Mapping):
            continue
        comparison = item.get("comparison")
        if not isinstance(comparison, Mapping) or not comparison.get(
                "comparison_id"):
            continue
        comparison_fixtures += 1
        comparison_status = _text(comparison.get("status"), 48).lower()
        if comparison_status in _COMPARISON_GAP_STATUSES:
            comparison_gaps += 1
        inconclusive_cells += _int(
            comparison.get("inconclusive_count"), 0, 0, 128)
        for key in ("source_revision_observations", "sibling_observations"):
            for arm in comparison.get(key) or []:
                if isinstance(arm, Mapping) and _text(
                        arm.get("status"), 32).lower() == "not-executed":
                    pending_arms += 1
    if pending_arms:
        comparison_gaps = max(comparison_gaps, 1)
    return {
        "status": status,
        "fixture_count": fixture_count,
        "fixture_budget": fixture_budget,
        "has_budget": has_budget,
        "fixture_budget_truncated": truncated,
        "comparison_fixtures": comparison_fixtures,
        "comparison_gaps": comparison_gaps,
        "inconclusive_cells": inconclusive_cells,
        "pending_comparison_arms": min(128, pending_arms),
    }


def _normalize_round(raw: Any, fallback_round: int = 0) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        return {}
    round_no = _round_no(raw.get("round", fallback_round))
    guidance = _normalize_guidance(raw.get("guidance"))
    feedback = _normalize_feedback(raw.get("feedback"))
    runtime = _runtime_view(raw.get("runtime_lab"))
    if not (round_no or guidance or feedback or runtime):
        return {}
    if not guidance.get("round"):
        guidance["round"] = round_no
    if not feedback.get("round"):
        feedback["round"] = round_no
    return {
        "round": round_no,
        "guidance": guidance,
        "feedback": feedback,
        "runtime_lab": runtime,
    }


def load_replay_history(workspace: Path, target: str) -> List[Dict[str, Any]]:
    """Load only the known per-round research artifacts for one target."""
    base = Path(workspace).resolve() / "state" / str(target)
    if not base.is_dir():
        return []
    rows: List[Dict[str, Any]] = []
    for directory in sorted(base.glob("round-*"),
                            key=lambda path: _round_no(
                                (_ROUND_RE.match(path.name) or [0, 0])[1])):
        match = _ROUND_RE.match(directory.name)
        if not match:
            continue
        round_no = _round_no(match.group(1))
        row = _normalize_round({
            "round": round_no,
            "guidance": _read_json(directory / "S8" / "research-guidance.json"),
            "feedback": _read_json(directory / "S8" /
                                    "research-strategy-feedback.json"),
            "runtime_lab": _read_json(directory / "S4" / "runtime-lab.json"),
        }, round_no)
        if row:
            rows.append(row)
        if len(rows) >= MAX_ROUNDS:
            break
    return rows


def _identity(item: Mapping[str, Any]) -> Tuple[str, str]:
    strategy_id = _text(item.get("strategy_id"), 80)
    if strategy_id:
        return "strategy", strategy_id
    research_key = _text(item.get("research_key"), 80)
    if research_key:
        return "research", research_key
    candidate_id = _text(item.get("candidate_id"), 120)
    return ("candidate", candidate_id) if candidate_id else ("", "")


def _find_feedback(rounds: Sequence[Dict[str, Any]], index: int,
                   guidance_item: Mapping[str, Any]) -> Tuple[
                       Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    identity = _identity(guidance_item)
    if not identity[1]:
        return None, None
    for later in rounds[index + 1:]:
        feedback_items = (later.get("feedback") or {}).get("items") or []
        for item in feedback_items:
            if _identity(item) == identity:
                future_guidance = None
                for candidate in (later.get("guidance") or {}).get("items") or []:
                    if _identity(candidate) == identity:
                        future_guidance = candidate
                        break
                return item, future_guidance
    return None, None


def _outcome(current: Mapping[str, Any], feedback: Optional[Mapping[str, Any]],
             future_guidance: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    if not feedback:
        return {
            "outcome": "unobserved",
            "next_round": 0,
            "information_gain": 0,
            "action_changed": False,
            "variant_changed": False,
            "environment_recovered": False,
        }
    observation = feedback.get("observation") or {}
    information_gain = _int(observation.get("information_gain"), 0, 0, 5)
    current_action = _text(current.get("next_action"), 64)
    next_action = _text((future_guidance or {}).get("next_action"), 64)
    action_changed = bool(next_action and next_action != current_action)
    current_variant = _text(current.get("variant_digest"), 40)
    next_variant = _text((future_guidance or {}).get("variant_digest"), 40)
    variant_changed = bool(next_variant and next_variant != current_variant)
    next_status = _text(observation.get("current_status"), 48)
    states = set(observation.get("execution_states") or [])
    next_is_gap = next_status == "environment-gap" or bool(
        states & {"unexecuted", "run-failed", "precondition-unavailable",
                  "gate-blocked", "harness-error", "inconclusive",
                  "disabled", "environment-gap"})
    current_gap = (current.get("observation_status") == "environment-gap"
                   or current_action == "repair-environment")
    environment_recovered = bool(current_gap and information_gain > 0
                                  and not next_is_gap)
    if environment_recovered:
        code = "environment-recovered"
    elif current_gap and next_is_gap:
        code = "environment-still-gap"
    elif current.get("replacement_recommended"):
        if (information_gain > 0 and (action_changed or variant_changed)):
            code = "replacement-productive"
        elif action_changed or variant_changed:
            code = "replacement-observed-no-new-information"
        elif information_gain > 0:
            code = "new-information"
        else:
            code = "repeat-no-new-information"
    elif information_gain > 0:
        code = "new-information"
    elif action_changed or variant_changed:
        code = "changed-without-new-information"
    else:
        code = "repeat-no-new-information"
    return {
        "outcome": code,
        "next_round": _round_no(feedback.get("round")),
        "information_gain": information_gain,
        "action_changed": action_changed,
        "variant_changed": variant_changed,
        "environment_recovered": environment_recovered,
    }


def _round_summary(row: Mapping[str, Any]) -> Dict[str, Any]:
    runtime = row.get("runtime_lab") or {}
    comparison_count = _int(runtime.get("comparison_fixtures"), 0, 0, 1000000)
    comparison_gaps = _int(runtime.get("comparison_gaps"), 0, 0, 1000000)
    return {
        "round": _round_no(row.get("round")),
        "guidance_items": len((row.get("guidance") or {}).get("items") or []),
        "feedback_items": len((row.get("feedback") or {}).get("items") or []),
        "runtime_lab_status": _text(runtime.get("status"), 48),
        "fixture_count": _int(runtime.get("fixture_count"), 0, 0, 1000000),
        "fixture_budget": _int(runtime.get("fixture_budget"), 0, 0, 1000000),
        "fixture_budget_truncated": bool(
            runtime.get("fixture_budget_truncated")),
        "comparison_fixtures": comparison_count,
        "comparison_gaps": comparison_gaps,
        "comparison_gap_rate": _ratio(comparison_gaps, comparison_count),
        "claim_status": CALIBRATION_CLAIM_STATUS,
    }


def _recommendations(metrics: Mapping[str, Any]) -> Tuple[str, List[Dict[str, Any]], int]:
    replayable = _int(metrics.get("replayed_guidance_items"), 0, 0, 1000000)
    replacement_observed = _int(
        metrics.get("replacement_observed"), 0, 0, 1000000)
    hit_rate = metrics.get("replacement_hit_rate")
    repeat_rate = metrics.get("unproductive_repeat_rate")
    truncation_rate = metrics.get("fixture_truncation_rate")
    comparison_gap_rate = metrics.get("comparison_gap_rate")
    recommendations: List[Dict[str, Any]] = []

    def add(code: str, priority: str, metric: str, value: Any,
            threshold: Any) -> None:
        recommendations.append({
            "code": code,
            "priority": priority,
            "metric": metric,
            "value": value,
            "threshold": threshold,
            "claim_status": CALIBRATION_CLAIM_STATUS,
        })

    if replayable < MIN_REPLAYABLE_ITEMS:
        add("collect-more-replay", "high", "replayed_guidance_items",
            replayable, MIN_REPLAYABLE_ITEMS)
        return "insufficient-sample", recommendations, REPLACEMENT_ZERO_GAIN_DEFAULT

    threshold = REPLACEMENT_ZERO_GAIN_DEFAULT
    if (replacement_observed > 0 and isinstance(hit_rate, (int, float))
            and isinstance(repeat_rate, (int, float))
            and hit_rate < REPLACEMENT_HIT_RATE_LOW
            and repeat_rate >= UNPRODUCTIVE_REPEAT_RATE_HIGH):
        threshold = REPLACEMENT_ZERO_GAIN_MAX
        add("require-consecutive-zero-gain", "medium",
            "replacement_hit_rate", hit_rate, REPLACEMENT_HIT_RATE_LOW)
    elif replacement_observed > 0:
        add("retain-zero-gain-threshold", "low", "replacement_hit_rate",
            hit_rate, REPLACEMENT_HIT_RATE_LOW)

    if (isinstance(truncation_rate, (int, float))
            and truncation_rate > FIXTURE_TRUNCATION_RATE_HIGH):
        add("increase-fixture-budget-or-split-lanes", "medium",
            "fixture_truncation_rate", truncation_rate,
            FIXTURE_TRUNCATION_RATE_HIGH)
    if (isinstance(comparison_gap_rate, (int, float))
            and comparison_gap_rate > COMPARISON_GAP_RATE_HIGH):
        add("prioritize-comparison-gap-recovery", "medium",
            "comparison_gap_rate", comparison_gap_rate,
            COMPARISON_GAP_RATE_HIGH)
    if not recommendations:
        add("no-threshold-change", "low", "replayed_guidance_items",
            replayable, MIN_REPLAYABLE_ITEMS)
    return "calibrated", recommendations[:MAX_RECOMMENDATIONS], threshold


def calibrate_replay_history(history: Sequence[Mapping[str, Any]],
                             target: str = "") -> Dict[str, Any]:
    """Build a bounded calibration artifact from normalized round history."""
    rounds: List[Dict[str, Any]] = []
    for raw in history or []:
        row = _normalize_round(raw)
        if row:
            rounds.append(row)
        if len(rounds) >= MAX_ROUNDS:
            break
    rounds.sort(key=lambda row: _round_no(row.get("round")))

    outcomes: List[Dict[str, Any]] = []
    replacement_recommendations = 0
    replacement_observed = 0
    replacement_hits = 0
    unproductive_repeats = 0
    environment_repairs = 0
    environment_recoveries = 0
    for index, row in enumerate(rounds):
        for current in (row.get("guidance") or {}).get("items") or []:
            feedback, future_guidance = _find_feedback(rounds, index, current)
            outcome = _outcome(current, feedback, future_guidance)
            if current.get("replacement_recommended"):
                replacement_recommendations += 1
                if feedback:
                    replacement_observed += 1
                if outcome["outcome"] == "replacement-productive":
                    replacement_hits += 1
            if feedback and outcome["outcome"] in {
                    "repeat-no-new-information",
                    "replacement-observed-no-new-information",
                    "changed-without-new-information"}:
                unproductive_repeats += 1
            if (current.get("observation_status") == "environment-gap"
                    or current.get("next_action") == "repair-environment"):
                environment_repairs += 1
                environment_recoveries += int(
                    outcome["outcome"] == "environment-recovered")
            if len(outcomes) < MAX_OUTCOMES:
                outcomes.append({
                    "strategy_id": current.get("strategy_id", ""),
                    "research_key": current.get("research_key", ""),
                    "candidate_id": current.get("candidate_id", ""),
                    "surface": current.get("surface", ""),
                    "round": _round_no(row.get("round")),
                    "next_action": current.get("next_action", ""),
                    "replacement_recommended": bool(
                        current.get("replacement_recommended")),
                    **outcome,
                    "claim_status": CALIBRATION_CLAIM_STATUS,
                })

    replayable = sum(1 for row in outcomes if row.get("outcome") != "unobserved")
    budgets = [row.get("runtime_lab") or {} for row in rounds
               if (row.get("runtime_lab") or {}).get("has_budget")]
    truncated_rounds = sum(bool(row.get("fixture_budget_truncated"))
                           for row in budgets)
    comparison_fixtures = sum(_int((row.get("runtime_lab") or {}).get(
        "comparison_fixtures"), 0, 0, 1000000) for row in rounds)
    comparison_gaps = sum(_int((row.get("runtime_lab") or {}).get(
        "comparison_gaps"), 0, 0, 1000000) for row in rounds)
    metrics: Dict[str, Any] = {
        "round_count": len(rounds),
        "guidance_items": len(outcomes),
        "replayed_guidance_items": replayable,
        "replacement_recommendations": replacement_recommendations,
        "replacement_observed": replacement_observed,
        "replacement_hits": replacement_hits,
        "replacement_hit_rate": _ratio(replacement_hits, replacement_observed),
        "unproductive_repeats": unproductive_repeats,
        "unproductive_repeat_rate": _ratio(unproductive_repeats, replayable),
        "environment_repair_recommendations": environment_repairs,
        "environment_recoveries": environment_recoveries,
        "environment_recovery_rate": _ratio(environment_recoveries,
                                               environment_repairs),
        "fixture_budget_rounds": len(budgets),
        "fixture_truncated_rounds": truncated_rounds,
        "fixture_truncation_rate": _ratio(truncated_rounds, len(budgets)),
        "comparison_fixtures": comparison_fixtures,
        "comparison_gaps": comparison_gaps,
        "comparison_gap_rate": _ratio(comparison_gaps, comparison_fixtures),
        "claim_status": CALIBRATION_CLAIM_STATUS,
    }
    status, recommendations, threshold = _recommendations(metrics)
    policy = {
        "replacement_zero_gain_rounds": threshold,
        "source": "real-project-replay",
        "applies_only_to": "research-guidance-scheduling",
        "claim_status": CALIBRATION_CLAIM_STATUS,
    }
    digest = _digest({
        "rounds": [_round_summary(row) for row in rounds],
        "metrics": metrics,
        "policy": policy,
    })
    return {
        "schema_version": CALIBRATION_SCHEMA_VERSION,
        "target": _text(target, 120),
        "status": status,
        "history_digest": digest,
        "metrics": metrics,
        "policy": policy,
        "recommendations": recommendations,
        "rounds": [_round_summary(row) for row in rounds[:MAX_ROUNDS]],
        "outcomes": outcomes,
        "claim_status": CALIBRATION_CLAIM_STATUS,
    }


def normalize_replay_calibration(raw: Any) -> Dict[str, Any]:
    """Normalize an artifact before it can influence guidance scheduling."""
    if not isinstance(raw, Mapping) or raw.get(
            "schema_version") != CALIBRATION_SCHEMA_VERSION:
        return {}
    status = _text(raw.get("status"), 32)
    if status not in {"no-data", "insufficient-sample", "calibrated"}:
        status = "no-data"
    metrics_raw = raw.get("metrics") if isinstance(raw.get("metrics"), Mapping) else {}
    metric_names = (
        "round_count", "guidance_items", "replayed_guidance_items",
        "replacement_recommendations", "replacement_observed", "replacement_hits",
        "unproductive_repeats", "environment_repair_recommendations",
        "environment_recoveries", "fixture_budget_rounds",
        "fixture_truncated_rounds", "comparison_fixtures", "comparison_gaps",
    )
    metrics: Dict[str, Any] = {
        name: _int(metrics_raw.get(name), 0, 0, 1000000)
        for name in metric_names
    }
    for name in ("replacement_hit_rate", "unproductive_repeat_rate",
                 "environment_recovery_rate", "fixture_truncation_rate",
                 "comparison_gap_rate"):
        number = _number(metrics_raw.get(name))
        if number is not None:
            metrics[name] = number
    policy_raw = raw.get("policy") if isinstance(raw.get("policy"), Mapping) else {}
    threshold = _int(policy_raw.get("replacement_zero_gain_rounds"),
                     REPLACEMENT_ZERO_GAIN_DEFAULT, 1,
                     REPLACEMENT_ZERO_GAIN_MAX)
    policy = {
        "replacement_zero_gain_rounds": threshold,
        "source": "real-project-replay",
        "applies_only_to": "research-guidance-scheduling",
        "claim_status": CALIBRATION_CLAIM_STATUS,
    }
    recommendations = []
    for row in raw.get("recommendations") or []:
        if not isinstance(row, Mapping):
            continue
        code = _text(row.get("code"), 80)
        priority = _text(row.get("priority"), 16).lower()
        metric = _text(row.get("metric"), 80)
        if code not in _RECOMMENDATION_CODES or priority not in {
                "low", "medium", "high"} or not metric:
            continue
        value = row.get("value")
        threshold_value = row.get("threshold")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            value = round(float(value), 4)
        else:
            value = _text(value, 80)
        if isinstance(threshold_value, (int, float)) and not isinstance(
                threshold_value, bool):
            threshold_value = round(float(threshold_value), 4)
        else:
            threshold_value = _text(threshold_value, 80)
        recommendations.append({
            "code": code, "priority": priority, "metric": metric,
            "value": value, "threshold": threshold_value,
            "claim_status": CALIBRATION_CLAIM_STATUS,
        })
        if len(recommendations) >= MAX_RECOMMENDATIONS:
            break
    round_rows: List[Dict[str, Any]] = []
    for row in raw.get("rounds") or []:
        if not isinstance(row, Mapping):
            continue
        comparison_count = _int(row.get("comparison_fixtures"), 0, 0, 1000000)
        comparison_gaps = _int(row.get("comparison_gaps"), 0, 0, 1000000)
        round_rows.append({
            "round": _round_no(row.get("round")),
            "guidance_items": _int(row.get("guidance_items"), 0, 0, MAX_GUIDANCE_ITEMS),
            "feedback_items": _int(row.get("feedback_items"), 0, 0, MAX_FEEDBACK_ITEMS),
            "runtime_lab_status": _text(row.get("runtime_lab_status"), 48),
            "fixture_count": _int(row.get("fixture_count"), 0, 0, 1000000),
            "fixture_budget": _int(row.get("fixture_budget"), 0, 0, 1000000),
            "fixture_budget_truncated": bool(
                row.get("fixture_budget_truncated")),
            "comparison_fixtures": comparison_count,
            "comparison_gaps": comparison_gaps,
            "comparison_gap_rate": _ratio(comparison_gaps, comparison_count),
            "claim_status": CALIBRATION_CLAIM_STATUS,
        })
        if len(round_rows) >= MAX_ROUNDS:
            break
    outcome_rows: List[Dict[str, Any]] = []
    for row in raw.get("outcomes") or []:
        if not isinstance(row, Mapping):
            continue
        strategy_id = _text(row.get("strategy_id"), 80)
        outcome = _text(row.get("outcome"), 64)
        if (not _STRATEGY_ID_RE.fullmatch(strategy_id)
                or outcome not in _OUTCOME_CODES):
            continue
        outcome_rows.append({
            "strategy_id": strategy_id,
            "research_key": _text(row.get("research_key"), 80),
            "candidate_id": _text(row.get("candidate_id"), 120),
            "surface": (_text(row.get("surface"), 24).lower()
                        if _text(row.get("surface"), 24).lower()
                        in _RESEARCH_SURFACES else ""),
            "round": _round_no(row.get("round")),
            "next_action": _text(row.get("next_action"), 64)
            if _text(row.get("next_action"), 64) in _ACTIONS else "",
            "replacement_recommended": bool(
                row.get("replacement_recommended")),
            "outcome": outcome,
            "next_round": _round_no(row.get("next_round")),
            "information_gain": _int(row.get("information_gain"), 0, 0, 5),
            "action_changed": bool(row.get("action_changed")),
            "variant_changed": bool(row.get("variant_changed")),
            "environment_recovered": bool(row.get("environment_recovered")),
            "claim_status": CALIBRATION_CLAIM_STATUS,
        })
        if len(outcome_rows) >= MAX_OUTCOMES:
            break
    return {
        "schema_version": CALIBRATION_SCHEMA_VERSION,
        "target": _text(raw.get("target"), 120),
        "status": status,
        "history_digest": _text(raw.get("history_digest"), 40),
        "metrics": metrics,
        "policy": policy,
        "recommendations": recommendations,
        "rounds": round_rows,
        "outcomes": outcome_rows,
        "claim_status": CALIBRATION_CLAIM_STATUS,
    }


def calibration_path(workspace: Path, target: str) -> Path:
    return (Path(workspace).resolve() / "state" / str(target) /
            "coverage" / CALIBRATION_FILENAME)


def write_replay_calibration(workspace: Path, target: str,
                             calibration: Mapping[str, Any]) -> Path:
    path = calibration_path(workspace, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = normalize_replay_calibration(calibration)
    if not payload:
        payload = calibrate_replay_history([], target)
    temporary = path.with_name(".%s.tmp.%d" % (path.name, os.getpid()))
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                         encoding="utf-8")
    temporary.replace(path)
    return path


def load_replay_calibration(workspace: Path, target: str) -> Dict[str, Any]:
    path = calibration_path(workspace, target)
    return normalize_replay_calibration(_read_json(path))


def build_replay_calibration(workspace: Path, target: str) -> Dict[str, Any]:
    return calibrate_replay_history(load_replay_history(workspace, target),
                                    target=target)
