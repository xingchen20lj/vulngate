"""Bounded project-level research portfolio for the VulnGate loop.

Research memory is mechanism-shaped: it answers what happened to one stable
research key.  A portfolio is project-shaped: it answers which surfaces,
variants and precondition classes have actually been exercised, where the
uncertainty is concentrated, and which bounded probe should be scheduled next.

This artifact is intentionally separate from the finding ledger.  It contains
only normalized research metadata and state counts.  It never copies source
prose, reviewer notes, payloads, commands, process output, credentials, CVSS
values or a vulnerability conclusion.
"""

from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..evaluation.benchmark import normalize_benchmark_feedback
from ..evaluation.research_consistency import (
    build_research_consistency,
    normalize_research_consistency,
)
from ..evaluation.research_consistency_actions import (
    ACTION_SCHEMA_VERSION,
    build_research_consistency_actions,
    normalize_research_consistency_actions,
)
from ..tools.redaction import redact_text
from .research import (
    MEMORY_CLAIM_STATUS,
    REVIEW_STATUSES,
    STATE_ACTIONABLE_DIFFERENCE,
    STATE_DECISION_RECORDED,
    STATE_ENVIRONMENT_GAP,
    STATE_INCONCLUSIVE,
    STATE_PENDING_RESIDUAL,
    STATE_RESIDUAL_FALSIFIED,
    STATE_REVIEW_ACCEPTED,
    STATE_REVIEW_NEEDS_EVIDENCE,
    STATE_REVIEW_REJECTED,
    STATE_REVIEW_SCOPE_CORRECTED,
    STATE_STABLE_OBSERVATION,
    STATE_STABLE_REPRODUCER,
    STATE_UNSTABLE_REPLAY,
)
from .surface_coverage import (
    build_surface_lane_coverage,
    empty_surface_lane_coverage,
    normalize_surface_lane_coverage,
)


PORTFOLIO_SCHEMA_VERSION = "research-portfolio-v1"
PORTFOLIO_FILENAME = "research-portfolio.json"
PORTFOLIO_CLAIM_STATUS = MEMORY_CLAIM_STATUS

MAX_DIMENSION_VALUES = 48
MAX_VARIANT_VALUES = 64
MAX_NEXT_PROBES = 24
MAX_HINTS = 4
MAX_TEXT = 160
MAX_KEY = 80

RESEARCH_SURFACES = frozenset({"web", "protocol", "cloud", "mobile", "native"})
TARGET_TYPES = frozenset({
    "library", "web-app", "middleware", "logging", "expression",
    "message-rpc", "cloud-service", "mobile-app", "native-app",
})
TARGET_TYPE_TO_SURFACE = {
    "web-app": "web",
    "middleware": "protocol",
    "message-rpc": "protocol",
    "cloud-service": "cloud",
    "mobile-app": "mobile",
    "native-app": "native",
}

KNOWN_STATES = frozenset({
    STATE_STABLE_REPRODUCER, STATE_ACTIONABLE_DIFFERENCE,
    STATE_ENVIRONMENT_GAP, STATE_UNSTABLE_REPLAY,
    STATE_STABLE_OBSERVATION, STATE_INCONCLUSIVE,
    STATE_DECISION_RECORDED, STATE_REVIEW_ACCEPTED,
    STATE_REVIEW_REJECTED, STATE_REVIEW_NEEDS_EVIDENCE,
    STATE_REVIEW_SCOPE_CORRECTED,
    STATE_PENDING_RESIDUAL,
})
STABLE_STATES = frozenset({STATE_STABLE_REPRODUCER, STATE_STABLE_OBSERVATION})
UNRESOLVED_STATES = frozenset({
    STATE_ENVIRONMENT_GAP, STATE_UNSTABLE_REPLAY,
    STATE_INCONCLUSIVE, STATE_REVIEW_NEEDS_EVIDENCE,
    STATE_DECISION_RECORDED,
    STATE_PENDING_RESIDUAL,
})
FOLLOWUP_STATES = frozenset({
    STATE_ACTIONABLE_DIFFERENCE, STATE_REVIEW_ACCEPTED,
    STATE_REVIEW_SCOPE_CORRECTED,
})

DIMENSIONS = (
    "research_surface", "target_type", "attack_class",
    "variant", "precondition_class",
)


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    if value is None:
        return ""
    try:
        value = redact_text(value)
    except Exception:  # pragma: no cover - redaction is defensive
        value = str(value)
    return " ".join(str(value).replace("\x00", "").split())[:limit]


def _safe_int(value: Any, default: int = 0, minimum: int = 0,
              maximum: int = 1000000) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _bounded_strings(values: Any, limit: int = MAX_HINTS,
                     item_limit: int = MAX_TEXT) -> List[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes)):
        values = [values]
    if not isinstance(values, (list, tuple, set)):
        return []
    out: List[str] = []
    seen = set()
    for value in values:
        item = _text(value, item_limit)
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
        if len(out) >= limit:
            break
    return sorted(out)


def _event_sort_key(event: Dict[str, Any]) -> Tuple[int, str]:
    return (_safe_int(event.get("round"), 0), _text(event.get("event_id"), 80))


def _known_state(value: Any) -> str:
    state = _text(value, 80)
    return state if state in KNOWN_STATES else ""


def _latest_event(events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    items = [event for event in events
             if isinstance(event, dict) and _known_state(event.get("state"))]
    meaningful = [event for event in items
                  if _known_state(event.get("state")) != STATE_DECISION_RECORDED]
    return max(meaningful or items, key=_event_sort_key) if (meaningful or items) else {}


def _dimension_values(entry: Dict[str, Any], dimension: str) -> List[str]:
    if dimension == "research_surface":
        value = _text(entry.get("research_surface"), 32).lower()
        if value in RESEARCH_SURFACES:
            return [value]
        target_type = _text(entry.get("target_type"), 60).lower()
        mapped = TARGET_TYPE_TO_SURFACE.get(target_type)
        return [mapped or "unclassified"]
    if dimension == "target_type":
        value = _text(entry.get("target_type"), 60).lower()
        return [value if value in TARGET_TYPES else "unclassified"]
    if dimension == "attack_class":
        values = _bounded_strings(
            entry.get("attack_classes") or [entry.get("attack_class")], 8, 80)
        return [value.lower() for value in values] or ["unclassified"]
    if dimension == "precondition_class":
        values = _bounded_strings(
            entry.get("precondition_classes")
            or [entry.get("precondition_class")], 8, 60)
        normalized = ["default" if value.lower() == "0" else value.lower()
                      for value in values]
        return sorted(set(normalized)) or ["unclassified"]
    values = _bounded_strings(
        entry.get("variants") or [entry.get("variant")]
        + list(entry.get("fix_variants") or []), 12, 100)
    return sorted(set(values)) or ["unclassified"]


def _review_index(review_feedback: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    latest: Dict[str, Dict[str, Any]] = {}
    if not isinstance(review_feedback, dict):
        return latest
    for raw in review_feedback.get("entries") or []:
        if not isinstance(raw, dict):
            continue
        key = _text(raw.get("research_key"), MAX_KEY)
        status = _text(raw.get("status"), 40).lower()
        if not key or status not in REVIEW_STATUSES:
            continue
        item = {
            "status": status,
            "reason_code": _text(raw.get("reason_code"), 60).lower(),
            "round": _safe_int(raw.get("round"), 0),
            "next_probe_hints": _bounded_strings(
                raw.get("next_probe_hints"), MAX_HINTS, 220),
            "feedback_id": _text(raw.get("feedback_id"), 80),
        }
        previous = latest.get(key)
        if previous is None or (_safe_int(item.get("round")), item["feedback_id"]) >= \
                (_safe_int(previous.get("round")), previous.get("feedback_id", "")):
            latest[key] = item
    return latest


def _surface_lane_probe_hints(row: Dict[str, Any]) -> List[str]:
    """Explain the smallest bounded follow-up for one unresolved lane."""
    status = _text(row.get("status"), 32).lower()
    missing = set(row.get("missing_observations") or [])
    if status == "environment-gap":
        return ["先修复该研究面 lane 的 runtime/harness 缺口；缺口不等于安全"]
    hints: List[str] = []
    if "state-sequence" in missing:
        hints.append("补齐有序 STEP/STATE 观测，不把声明当成已执行")
    if "typed-effect" in missing:
        hints.append("补 typed-effect 或 safe-equivalent 观测，区分中间轨迹与真实影响")
    if "negative-baseline" in missing or "safe-equivalent" in missing:
        hints.append("补对应 lane 的负向/安全等价基线，避免只跑正向路径")
    if not hints:
        hints.append("补齐该研究面 lane 的必需观测，避免把部分覆盖当成完整")
    return _bounded_strings(hints, MAX_HINTS, 220)


def _consistency_probe_hints(row: Dict[str, Any]) -> List[str]:
    """Turn an observation conflict into a bounded controlled replay action."""
    status = _text(row.get("status"), 32).lower()
    codes = set(row.get("conflict_codes") or [])
    if status == "environment-gap":
        return ["先修复 runtime/harness 缺口；环境缺口不是负向证据"]
    if "context-drift" in codes:
        return ["固定版本、SafeMode、fixture 和服务配置后重放，避免上下文漂移"]
    if "effect-presence-drift" in codes:
        return ["在同一受控上下文重复正/负向对照，区分 typed effect 与安全等价结果"]
    if "reproduction-drift" in codes:
        return ["固定输入和状态生命周期做独立重复，记录可复现性而非采用最新一次"]
    if "comparison-drift" in codes:
        return ["固定版本对照和历史构建，再复核 comparison 差异的语义影响"]
    if status == "insufficient":
        return ["补一次独立可比观测；单次运行不足以校准该机制"]
    return ["隔离状态、配置和 fixture 后重放，保留每次结果的差异摘要"]


def _empty_portfolio() -> Dict[str, Any]:
    return {
        "schema_version": PORTFOLIO_SCHEMA_VERSION,
        "round": 0,
        "summary": {
            "mechanism_count": 0,
            "event_count": 0,
            "unresolved_mechanisms": 0,
            "stable_mechanisms": 0,
            "actionable_differences": 0,
            "reviewed_mechanisms": 0,
            "pending_residuals": 0,
            "resolved_residuals": 0,
            "consistency_conflicted": 0,
            "consistency_unstable": 0,
            "consistency_environment_gaps": 0,
            "consistency_insufficient": 0,
            "states": {},
            "review_statuses": {},
        },
        "dimensions": {dimension: [] for dimension in DIMENSIONS},
        "variant_coverage": [],
        "surface_lane_coverage": empty_surface_lane_coverage(),
        "consistency": build_research_consistency({}),
        "consistency_actions": build_research_consistency_actions({}),
        "next_probes": [],
        "benchmark": {},
        "claim_status": PORTFOLIO_CLAIM_STATUS,
    }


def _benchmark_view(value: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    feedback = normalize_benchmark_feedback(value or {})
    if not feedback:
        return {}
    trend = feedback.get("trend") or {}
    surface_guidance = []
    for item in feedback.get("surface_guidance") or []:
        if not isinstance(item, dict):
            continue
        surface = _text(item.get("surface"), 32).lower()
        if surface not in RESEARCH_SURFACES:
            continue
        snapshot = item.get("metric_snapshot")
        metrics = sorted(_text(key, 80) for key in snapshot) \
            if isinstance(snapshot, dict) else []
        surface_guidance.append({
            "surface": surface,
            "priority_delta": _safe_int(item.get("priority_delta"), 0, 0, 6),
            "metrics": metrics[:8],
        })
    return {
        "benchmark_id": _text(feedback.get("benchmark_id"), 120),
        "alert_codes": sorted({
            _text(item.get("code"), 80)
            for item in feedback.get("alerts") or []
            if isinstance(item, dict) and item.get("code")
        })[:12],
        "trend": {
            "status": _text(trend.get("status"), 24),
            "baseline_benchmark_id": _text(
                trend.get("baseline_benchmark_id"), 120),
            "current_benchmark_id": _text(
                trend.get("current_benchmark_id"), 120),
            "regressed_metrics": sorted({
                _text(item.get("metric"), 80)
                for item in trend.get("regressions") or []
                if isinstance(item, dict) and item.get("metric")
            })[:16],
            "regressed_surfaces": sorted({
                _text(item.get("surface"), 32).lower()
                for item in trend.get("surface_regressions") or []
                if isinstance(item, dict)
                and _text(item.get("surface"), 32).lower() in RESEARCH_SURFACES
            })[:len(RESEARCH_SURFACES)],
        },
        "surface_guidance": sorted(
            surface_guidance, key=lambda item: str(item.get("surface")))[:8],
        "claim_status": PORTFOLIO_CLAIM_STATUS,
    }


def build_research_portfolio(
        memory: Optional[Dict[str, Any]],
        review_feedback: Optional[Dict[str, Any]] = None,
        benchmark_feedback: Optional[Dict[str, Any]] = None,
        consistency: Optional[Dict[str, Any]] = None,
        consistency_actions: Optional[Dict[str, Any]] = None,
        ) -> Dict[str, Any]:
    """Build a deterministic, bounded project view from research artifacts."""
    if not isinstance(memory, dict):
        memory = _empty_portfolio()
    entries = [entry for entry in memory.get("entries") or []
               if isinstance(entry, dict) and _text(entry.get("research_key"), MAX_KEY)]
    if consistency is None:
        consistency = build_research_consistency(memory)
    consistency = normalize_research_consistency(consistency)
    if not consistency:
        consistency = build_research_consistency(memory)
    if consistency_actions is None:
        consistency_actions = build_research_consistency_actions(consistency)
    consistency_actions = normalize_research_consistency_actions(
        consistency_actions)
    if not consistency_actions:
        consistency_actions = build_research_consistency_actions(consistency)
    reviews = _review_index(review_feedback)
    states = Counter()
    latest_states = Counter()
    review_statuses = Counter()
    dimensions: Dict[str, Dict[str, Dict[str, Any]]] = {
        dimension: defaultdict(lambda: {
            "entry_keys": set(), "event_count": 0,
            "state_counts": Counter(), "unresolved_keys": set(),
            "stable_keys": set(),
        }) for dimension in DIMENSIONS
    }
    next_candidates: List[Dict[str, Any]] = []
    stable_count = 0
    unresolved_count = 0
    difference_count = 0
    pending_residual_count = 0
    resolved_residual_count = 0

    for entry in entries:
        key = _text(entry.get("research_key"), MAX_KEY)
        events = [event for event in entry.get("events") or []
                  if isinstance(event, dict) and _known_state(event.get("state"))]
        latest = _latest_event(events)
        state = _known_state(latest.get("state")) or STATE_DECISION_RECORDED
        latest_states[state] += 1
        review = reviews.get(key, {})
        review_status = _text(review.get("status"), 40).lower()
        if review_status:
            review_statuses[review_status] += 1
        for event in events:
            event_state = _known_state(event.get("state"))
            if event_state:
                states[event_state] += 1

        if state in STABLE_STATES:
            stable_count += 1
        if state in UNRESOLVED_STATES:
            unresolved_count += 1
        if state == STATE_ACTIONABLE_DIFFERENCE:
            difference_count += 1
        residuals = [item for item in entry.get("residuals") or []
                     if isinstance(item, dict) and item.get("residual_id")]
        pending_residuals = [item for item in residuals
                             if item.get("state") != STATE_RESIDUAL_FALSIFIED]
        pending_residual_count += len(pending_residuals)
        resolved_residual_count += len(residuals) - len(pending_residuals)
        if pending_residuals and state not in UNRESOLVED_STATES:
            # A stable primary replay does not close an S3 residual variant.
            unresolved_count += 1

        for dimension in DIMENSIONS:
            for value in _dimension_values(entry, dimension):
                bucket = dimensions[dimension][value]
                bucket["entry_keys"].add(key)
                bucket["event_count"] += len(events)
                for event in events:
                    event_state = _known_state(event.get("state"))
                    if event_state:
                        bucket["state_counts"][event_state] += 1
                if state in UNRESOLVED_STATES or pending_residuals:
                    bucket["unresolved_keys"].add(key)
                if state in STABLE_STATES:
                    bucket["stable_keys"].add(key)

        hints = _bounded_strings(latest.get("next_probe_hints"), MAX_HINTS, 220)
        for hint in review.get("next_probe_hints") or []:
            if hint not in hints:
                hints.append(hint)
        if state == STATE_DECISION_RECORDED and not hints:
            hints = ["补齐至少一个可执行 cell 或明确前置条件，再决定下一轮探针"]
        if state in UNRESOLVED_STATES or state in FOLLOWUP_STATES or review_status == "needs-evidence":
            if state in (STATE_ENVIRONMENT_GAP, STATE_REVIEW_NEEDS_EVIDENCE) or \
                    review_status == "needs-evidence":
                priority = 5
            elif state == STATE_ACTIONABLE_DIFFERENCE:
                priority = 4
            elif state in (STATE_UNSTABLE_REPLAY, STATE_INCONCLUSIVE):
                priority = 3
            else:
                priority = 2
            next_candidates.append({
                "research_key": key,
                "candidate_id": _text(entry.get("candidate_id"), 120),
                "residual_id": "",
                "residual_kind": "",
                "residual_reason_code": "",
                "research_surface": _dimension_values(
                    entry, "research_surface")[0],
                "target_type": _dimension_values(entry, "target_type")[0],
                "attack_class": _dimension_values(entry, "attack_class")[0],
                "variant": _dimension_values(entry, "variant")[:4],
                "precondition_class": _dimension_values(
                    entry, "precondition_class")[0],
                "state": state,
                "round": _safe_int(latest.get("round", entry.get("round")), 0),
                "priority": priority,
                "review_status": review_status,
                "reason_code": _text(review.get("reason_code"), 60).lower(),
                "next_probe_hints": hints[:MAX_HINTS],
                "claim_status": PORTFOLIO_CLAIM_STATUS,
            })

        # S3 residuals are owed research even when the latest runtime replay
        # was stable.  Keep one bounded probe per residual so a later round
        # cannot mistake "the primary case replayed" for "all variants closed".
        for residual in pending_residuals:
            residual_id = _text(residual.get("residual_id"), 80)
            residual_kind = _text(residual.get("kind"), 48).lower()
            has_plan = bool(residual.get("has_probe_plan"))
            hint = ("执行已声明的有界 residual probe，并记录明确 falsifier"
                    if has_plan else
                    "为 residual 补充有界 probe_plan 与明确 falsifier")
            next_candidates.append({
                "research_key": key,
                "candidate_id": _text(entry.get("candidate_id"), 120),
                "residual_id": residual_id,
                "residual_kind": residual_kind,
                "residual_reason_code": _text(
                    residual.get("reason_code"), 48).lower(),
                "research_surface": _dimension_values(
                    entry, "research_surface")[0],
                "target_type": _dimension_values(entry, "target_type")[0],
                "attack_class": _dimension_values(entry, "attack_class")[0],
                "variant": _dimension_values(entry, "variant")[:4],
                "precondition_class": _dimension_values(
                    entry, "precondition_class")[0],
                "state": STATE_PENDING_RESIDUAL,
                "round": _safe_int(entry.get("round"), 0),
                "priority": 4,
                "review_status": review_status,
                "reason_code": "s3-residual",
                "next_probe_hints": [
                    "S3 residual=%s：%s" % (residual_kind or "unclassified", hint)
                ],
                "claim_status": PORTFOLIO_CLAIM_STATUS,
            })

    surface_lane_coverage = build_surface_lane_coverage(memory)
    lane_probe_keys = set()
    for lane_row in surface_lane_coverage.get("lanes") or []:
        if not isinstance(lane_row, dict):
            continue
        lane_status = _text(lane_row.get("status"), 32).lower()
        if lane_status == "observed":
            continue
        if lane_status == "environment-gap":
            lane_state = STATE_ENVIRONMENT_GAP
            priority = 5
        elif lane_status == "partial":
            lane_state = STATE_INCONCLUSIVE
            priority = 4
        else:
            lane_state = STATE_INCONCLUSIVE
            priority = 3
        hints = _surface_lane_probe_hints(lane_row)
        for ref in lane_row.get("entry_refs") or []:
            if not isinstance(ref, dict):
                continue
            research_key = _text(ref.get("research_key"), MAX_KEY)
            if not research_key:
                continue
            probe_key = (research_key, lane_row.get("variant_id"),
                         lane_row.get("lane"))
            if probe_key in lane_probe_keys:
                continue
            lane_probe_keys.add(probe_key)
            next_candidates.append({
                "research_key": research_key,
                "candidate_id": _text(ref.get("candidate_id"), 120),
                "residual_id": "",
                "residual_kind": "",
                "residual_reason_code": "",
                "research_surface": _text(lane_row.get("surface"), 32),
                "target_type": "",
                "attack_class": "",
                "variant": [_text(lane_row.get("variant_id"), 100)],
                "precondition_class": "",
                "state": lane_state,
                "round": _safe_int(lane_row.get("latest_round"), 0),
                "priority": priority,
                "review_status": "",
                "reason_code": "surface-lane-witness",
                "surface_variant_id": _text(
                    lane_row.get("variant_id"), 100),
                "surface_lane": _text(lane_row.get("lane"), 24),
                "lane_status": lane_status,
                "next_probe_hints": hints,
                "claim_status": PORTFOLIO_CLAIM_STATUS,
            })

    consistency_entries = [row for row in consistency.get("entries") or []
                           if isinstance(row, dict)]
    action_entries = {
        _text(row.get("research_key"), MAX_KEY): row
        for row in consistency_actions.get("entries") or []
        if isinstance(row, dict) and _text(row.get("research_key"), MAX_KEY)
    }
    consistency_probe_keys = set()
    for row in consistency_entries:
        key = _text(row.get("research_key"), MAX_KEY)
        status = _text(row.get("status"), 32).lower()
        if not key or status in {"consistent", ""}:
            continue
        if key in consistency_probe_keys:
            continue
        consistency_probe_keys.add(key)
        entry = next((item for item in entries
                      if _text(item.get("research_key"), MAX_KEY) == key), {})
        if status == "environment-gap":
            state = STATE_ENVIRONMENT_GAP
            priority = 5
        elif status == "conflicted":
            state = STATE_UNSTABLE_REPLAY
            priority = 5
        elif status == "unstable":
            state = STATE_UNSTABLE_REPLAY
            priority = 4
        else:
            state = STATE_INCONCLUSIVE
            priority = 3
        next_candidates.append({
            "research_key": key,
            "candidate_id": _text(entry.get("candidate_id"), 120),
            "residual_id": "",
            "residual_kind": "",
            "residual_reason_code": "",
            "research_surface": _dimension_values(
                entry, "research_surface")[0] if entry else "",
            "target_type": _dimension_values(
                entry, "target_type")[0] if entry else "",
            "attack_class": _dimension_values(
                entry, "attack_class")[0] if entry else "",
            "variant": _dimension_values(entry, "variant")[:4] if entry else [],
            "precondition_class": _dimension_values(
                entry, "precondition_class")[0] if entry else "",
            "state": state,
            "round": _safe_int((row.get("rounds") or [0])[-1], 0),
            "priority": priority,
            "review_status": "",
            "reason_code": "evidence-consistency",
            "consistency_status": status,
            "conflict_codes": _bounded_strings(
                row.get("conflict_codes"), 8, 64),
            "consistency_observation_count": _safe_int(
                row.get("observation_count"), 0, 0, 8),
            "consistency_action": dict(
                action_entries.get(key) or {}),
            "next_probe_hints": _consistency_probe_hints(row),
            "claim_status": PORTFOLIO_CLAIM_STATUS,
        })

    def dimension_rows(dimension: str) -> List[Dict[str, Any]]:
        rows = []
        for value, bucket in dimensions[dimension].items():
            rows.append({
                "value": _text(value, 100),
                "entry_count": len(bucket["entry_keys"]),
                "event_count": int(bucket["event_count"]),
                "state_counts": dict(sorted(bucket["state_counts"].items())),
                "unresolved_entries": len(bucket["unresolved_keys"]),
                "stable_entries": len(bucket["stable_keys"]),
                "claim_status": PORTFOLIO_CLAIM_STATUS,
            })
        rows.sort(key=lambda item: str(item.get("value", "")))
        return rows[:MAX_DIMENSION_VALUES]

    dimension_output = {
        dimension: dimension_rows(dimension) for dimension in DIMENSIONS
    }
    variants = dimension_output["variant"][:MAX_VARIANT_VALUES]
    variant_coverage = []
    for row in variants:
        unresolved = int(row.get("unresolved_entries", 0) or 0)
        stable = int(row.get("stable_entries", 0) or 0)
        status = "gap" if unresolved else ("stable-observed" if stable else "observed")
        variant_coverage.append({
            "variant": row.get("value"),
            "entry_count": row.get("entry_count", 0),
            "observed_states": sorted((row.get("state_counts") or {}).keys()),
            "unresolved_entries": unresolved,
            "status": status,
            "claim_status": PORTFOLIO_CLAIM_STATUS,
        })

    next_candidates.sort(key=lambda item: (
        -int(item.get("priority", 0) or 0),
        -int(item.get("round", 0) or 0),
        str(item.get("research_key", "")),
        str(item.get("residual_id", "")),
    ))
    benchmark = _benchmark_view(benchmark_feedback)
    consistency_summary = consistency.get("summary") or {}
    return {
        "schema_version": PORTFOLIO_SCHEMA_VERSION,
        "round": _safe_int(memory.get("round"), 0),
        "summary": {
            "mechanism_count": len(entries),
            "event_count": sum(len(entry.get("events") or []) for entry in entries),
            "unresolved_mechanisms": unresolved_count,
            "stable_mechanisms": stable_count,
            "actionable_differences": difference_count,
            "reviewed_mechanisms": sum(1 for key in reviews if any(
                _text(entry.get("research_key"), MAX_KEY) == key for entry in entries)),
            "pending_residuals": pending_residual_count,
            "resolved_residuals": resolved_residual_count,
            "consistency_conflicted": _safe_int(
                consistency_summary.get("conflicted_entries"), 0, 0, 1000000),
            "consistency_unstable": _safe_int(
                consistency_summary.get("unstable_entries"), 0, 0, 1000000),
            "consistency_environment_gaps": _safe_int(
                consistency_summary.get("environment_gap_entries"), 0, 0, 1000000),
            "consistency_insufficient": _safe_int(
                consistency_summary.get("insufficient_entries"), 0, 0, 1000000),
            "states": dict(sorted(states.items())),
            "latest_states": dict(sorted(latest_states.items())),
            "review_statuses": dict(sorted(review_statuses.items())),
            "benchmark_regressed": bool(
                (benchmark.get("trend") or {}).get("status") == "regressed"),
        },
        "dimensions": dimension_output,
        "variant_coverage": variant_coverage,
        "surface_lane_coverage": surface_lane_coverage,
        "consistency": consistency,
        "consistency_actions": consistency_actions,
        "next_probes": next_candidates[:MAX_NEXT_PROBES],
        "benchmark": benchmark,
        "claim_status": PORTFOLIO_CLAIM_STATUS,
    }


def normalize_research_portfolio(raw: Any) -> Dict[str, Any]:
    """Load only the bounded fields safe for a future scheduling prompt."""
    if not isinstance(raw, dict) or raw.get("schema_version") != PORTFOLIO_SCHEMA_VERSION:
        return {}
    result = _empty_portfolio()
    result["round"] = _safe_int(raw.get("round"), 0)
    summary = raw.get("summary") if isinstance(raw.get("summary"), dict) else {}
    for key in (
        "mechanism_count", "event_count", "unresolved_mechanisms",
        "stable_mechanisms", "actionable_differences", "reviewed_mechanisms",
        "pending_residuals", "resolved_residuals",
        "consistency_conflicted", "consistency_unstable",
        "consistency_environment_gaps", "consistency_insufficient",
    ):
        result["summary"][key] = _safe_int(summary.get(key), 0, 0, 1000000)
    for key in ("states", "latest_states", "review_statuses"):
        values = summary.get(key) if isinstance(summary.get(key), dict) else {}
        result["summary"][key] = {
            _text(name, 80): _safe_int(count, 0, 0, 1000000)
            for name, count in sorted(values.items(), key=lambda item: str(item[0]))
            if _text(name, 80)
        }
    result["summary"]["benchmark_regressed"] = bool(
        summary.get("benchmark_regressed"))
    consistency = normalize_research_consistency(raw.get("consistency"))
    if consistency:
        result["consistency"] = consistency
    consistency_actions = normalize_research_consistency_actions(
        raw.get("consistency_actions"))
    if consistency_actions:
        result["consistency_actions"] = consistency_actions
    for dimension in DIMENSIONS:
        rows = []
        for raw_row in (raw.get("dimensions") or {}).get(dimension, []) \
                if isinstance(raw.get("dimensions"), dict) else []:
            if not isinstance(raw_row, dict):
                continue
            row = {
                "value": _text(raw_row.get("value"), 100),
                "entry_count": _safe_int(raw_row.get("entry_count"), 0, 0, 1000000),
                "event_count": _safe_int(raw_row.get("event_count"), 0, 0, 1000000),
                "state_counts": {
                    _text(name, 80): _safe_int(count, 0, 0, 1000000)
                    for name, count in sorted(
                        (raw_row.get("state_counts") or {}).items(),
                        key=lambda item: str(item[0]))
                    if _known_state(name)
                },
                "unresolved_entries": _safe_int(
                    raw_row.get("unresolved_entries"), 0, 0, 1000000),
                "stable_entries": _safe_int(
                    raw_row.get("stable_entries"), 0, 0, 1000000),
                "claim_status": PORTFOLIO_CLAIM_STATUS,
            }
            if row["value"]:
                rows.append(row)
        result["dimensions"][dimension] = rows[:MAX_DIMENSION_VALUES]
    lane_coverage = normalize_surface_lane_coverage(
        raw.get("surface_lane_coverage"))
    if lane_coverage:
        result["surface_lane_coverage"] = lane_coverage
    result["variant_coverage"] = [
        {
            "variant": _text(row.get("variant"), 100),
            "entry_count": _safe_int(row.get("entry_count"), 0, 0, 1000000),
            "observed_states": [state for state in _bounded_strings(
                row.get("observed_states"), 16, 80) if state in KNOWN_STATES],
            "unresolved_entries": _safe_int(
                row.get("unresolved_entries"), 0, 0, 1000000),
            "status": _text(row.get("status"), 32),
            "claim_status": PORTFOLIO_CLAIM_STATUS,
        }
        for row in (raw.get("variant_coverage") or [])
        if isinstance(row, dict) and _text(row.get("variant"), 100)
    ][:MAX_VARIANT_VALUES]
    probes = []
    for raw_probe in raw.get("next_probes") or []:
        if not isinstance(raw_probe, dict):
            continue
        probe = {
            "research_key": _text(raw_probe.get("research_key"), MAX_KEY),
            "candidate_id": _text(raw_probe.get("candidate_id"), 120),
            "residual_id": _text(raw_probe.get("residual_id"), 80),
            "residual_kind": _text(raw_probe.get("residual_kind"), 48).lower(),
            "residual_reason_code": _text(
                raw_probe.get("residual_reason_code"), 48).lower(),
            "research_surface": _text(raw_probe.get("research_surface"), 32),
            "target_type": _text(raw_probe.get("target_type"), 60),
            "attack_class": _text(raw_probe.get("attack_class"), 80),
            "variant": _bounded_strings(raw_probe.get("variant"), 4, 100),
            "precondition_class": _text(raw_probe.get("precondition_class"), 60),
            "state": _known_state(raw_probe.get("state")),
            "round": _safe_int(raw_probe.get("round"), 0),
            "priority": _safe_int(raw_probe.get("priority"), 0, 0, 5),
            "review_status": _text(raw_probe.get("review_status"), 40),
            "reason_code": _text(raw_probe.get("reason_code"), 60),
            "next_probe_hints": _bounded_strings(
                raw_probe.get("next_probe_hints"), MAX_HINTS, 220),
            "claim_status": PORTFOLIO_CLAIM_STATUS,
        }
        surface_variant_id = _text(raw_probe.get("surface_variant_id"), 100)
        surface_lane = _text(raw_probe.get("surface_lane"), 24)
        lane_status = _text(raw_probe.get("lane_status"), 32)
        if surface_variant_id or surface_lane or lane_status:
            probe.update({
                "surface_variant_id": surface_variant_id,
                "surface_lane": surface_lane,
                "lane_status": lane_status,
            })
        consistency_status = _text(raw_probe.get("consistency_status"), 32).lower()
        if consistency_status in {"conflicted", "unstable", "insufficient",
                                  "environment-gap"}:
            probe["consistency_status"] = consistency_status
            probe["conflict_codes"] = _bounded_strings(
                raw_probe.get("conflict_codes"), 8, 64)
            probe["consistency_observation_count"] = _safe_int(
                raw_probe.get("consistency_observation_count"), 0, 0, 8)
            action = normalize_research_consistency_actions({
                "schema_version": ACTION_SCHEMA_VERSION,
                "entries": [raw_probe.get("consistency_action")],
            })
            if action.get("entries"):
                probe["consistency_action"] = action["entries"][0]
        if probe["research_key"] and probe["state"]:
            probes.append(probe)
    result["next_probes"] = probes[:MAX_NEXT_PROBES]
    benchmark = raw.get("benchmark") if isinstance(raw.get("benchmark"), dict) else {}
    if benchmark:
        trend = benchmark.get("trend") if isinstance(benchmark.get("trend"), dict) else {}
        result["benchmark"] = {
            "benchmark_id": _text(benchmark.get("benchmark_id"), 120),
            "alert_codes": _bounded_strings(benchmark.get("alert_codes"), 12, 80),
            "trend": {
                "status": _text(trend.get("status"), 24),
                "baseline_benchmark_id": _text(
                    trend.get("baseline_benchmark_id"), 120),
                "current_benchmark_id": _text(
                    trend.get("current_benchmark_id"), 120),
                "regressed_metrics": _bounded_strings(
                    trend.get("regressed_metrics"), 16, 80),
                "regressed_surfaces": [surface for surface in
                    _bounded_strings(trend.get("regressed_surfaces"), 8, 32)
                    if surface in RESEARCH_SURFACES],
            },
            "surface_guidance": [
                {
                    "surface": _text(item.get("surface"), 32),
                    "priority_delta": _safe_int(
                        item.get("priority_delta"), 0, 0, 6),
                    "metrics": _bounded_strings(item.get("metrics"), 8, 80),
                }
                for item in benchmark.get("surface_guidance") or []
                if isinstance(item, dict)
                and _text(item.get("surface"), 32) in RESEARCH_SURFACES
            ][:8],
            "claim_status": PORTFOLIO_CLAIM_STATUS,
        }
    result["claim_status"] = PORTFOLIO_CLAIM_STATUS
    return result


def portfolio_path(workspace: Path, target: str) -> Path:
    return Path(workspace).resolve() / "state" / str(target) / PORTFOLIO_FILENAME


def write_research_portfolio(workspace: Path, target: str,
                             portfolio: Dict[str, Any]) -> Path:
    path = portfolio_path(workspace, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = normalize_research_portfolio(portfolio) or _empty_portfolio()
    tmp = path.with_name(".%s.tmp.%d" % (path.name, os.getpid()))
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    tmp.replace(path)
    return path


def load_research_portfolio(workspace: Path, target: str) -> Dict[str, Any]:
    path = portfolio_path(workspace, target)
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    return normalize_research_portfolio(raw)
