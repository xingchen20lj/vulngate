"""Build a bounded active research agenda from the current strategy.

The strategy explains *what* remains open.  A senior researcher also needs a
small, explicit work queue that decides which hypotheses should consume the
next finite round budget, while preserving surface diversity and expected
information gain.  This module provides that queue without changing a
candidate conclusion: it consumes normalized strategy/portfolio metadata and
emits only scheduling metadata with ``claim_status=not-a-finding``.

No source prose, payloads, commands, process output, credentials, CVSS or
finding conclusion is copied into the agenda.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from ..memory.portfolio import normalize_research_portfolio
from ..tools.redaction import redact_text
from .research_strategy import (
    STRATEGY_GUIDANCE_ACTIONS,
    STRATEGY_KINDS,
    STRATEGY_OBSERVATION_STATUSES,
    normalize_research_strategy,
)


AGENDA_SCHEMA_VERSION = "research-agenda-v1"
AGENDA_FILENAME = "research-agenda.json"
AGENDA_CLAIM_STATUS = "not-a-finding"

MAX_ENTRIES = 64
MAX_TEXT = 120
MAX_IDS = 8
MAX_REASON_CODES = 8
MAX_OBSERVATIONS = 8
MAX_FALSIFIERS = 6
MAX_SLOTS = 16
MAX_PER_SURFACE = 8
DEFAULT_SLOTS = 8
DEFAULT_MAX_PER_SURFACE = 3

AGENDA_STATUSES = frozenset({"selected", "deferred", "hold"})
RESEARCH_SURFACES = frozenset({"web", "protocol", "cloud", "mobile", "native"})
TARGET_TYPES = frozenset({
    "library", "web-app", "middleware", "logging", "expression",
    "message-rpc", "cloud-service", "mobile-app", "native-app",
})
OBSERVATION_STATUSES = frozenset(STRATEGY_OBSERVATION_STATUSES)
KINDS = frozenset(STRATEGY_KINDS)
ACTIONS = frozenset(STRATEGY_GUIDANCE_ACTIONS)

AGENDA_REASON_CODES = frozenset({
    "priority",
    "evidence-debt",
    "expected-information-gain",
    "environment-repair",
    "replacement",
    "review-followup",
    "residual-closure",
    "surface-diversity",
    "budget-deferred",
    "evidence-satisfied",
    "outcome-recovery",
    "outcome-no-new-information",
    "outcome-not-executed",
    "outcome-falsifier",
    "outcome-new-information",
})
PREREQUISITES = frozenset({
    "environment-ready",
    "source-scope-available",
    "source-path-mapped",
    "runtime-execution",
    "fixture-locked",
    "independent-repeat",
    "negative-control",
    "residual-contract",
    "surface-variant-plan",
    "review-scope-confirmed",
})

_AGENDA_ID_RE = re.compile(r"^ra-[0-9a-f]{24}$")
_TARGET_TO_SURFACE = {
    "web-app": "web",
    "middleware": "protocol",
    "message-rpc": "protocol",
    "cloud-service": "cloud",
    "mobile-app": "mobile",
    "native-app": "native",
}


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


def _bounded(values: Any, allowed: Optional[Iterable[str]] = None,
             limit: int = MAX_IDS, item_limit: int = MAX_TEXT) -> List[str]:
    if isinstance(values, (str, bytes)):
        values = [values]
    if not isinstance(values, (list, tuple, set)):
        return []
    allow = set(allowed) if allowed is not None else None
    result: List[str] = []
    for value in values:
        item = _text(value, item_limit)
        if not item or (allow is not None and item not in allow):
            continue
        if item in result:
            continue
        result.append(item)
        if len(result) >= limit:
            break
    return sorted(result)


def _code(value: Any, allowed: Iterable[str], fallback: str = "") -> str:
    item = _text(value, 80).lower()
    return item if item in set(allowed) else fallback


def _surface(value: Any, target_type: Any = "") -> str:
    item = _text(value, 32).lower()
    if item in RESEARCH_SURFACES:
        return item
    target = _text(target_type, 48).lower()
    return _TARGET_TO_SURFACE.get(target, "")


def _stable_id(*parts: Any) -> str:
    material = "\x1f".join(_text(part, 240) for part in parts)
    return "ra-" + hashlib.sha256(
        material.encode("utf-8", errors="replace")).hexdigest()[:24]


def _default_action(item: Mapping[str, Any]) -> str:
    state = _text(item.get("state"), 48)
    kind = _code(item.get("kind"), KINDS, "portfolio-followup")
    if state == "pending-environment" or kind == "environment-recovery":
        return "repair-environment"
    if state == "pending-residual" or kind == "residual-closure":
        return "replay-residual-variant"
    if state == "pending-capability" or kind == "capability-closure":
        return "trace-capability-transition"
    if kind in {"reachability-closure", "coverage-closure"}:
        return "review-source-dataflow"
    if kind == "control-closure":
        return "add-negative-control"
    return "continue-path-closure"


def _observation(item: Mapping[str, Any]) -> Dict[str, Any]:
    value = item.get("observation")
    return value if isinstance(value, Mapping) else {}


def _observation_status(item: Mapping[str, Any]) -> str:
    return _code(_observation(item).get("status"), OBSERVATION_STATUSES,
                 "unobserved")


def _action(item: Mapping[str, Any]) -> str:
    guidance = item.get("guidance")
    guidance = guidance if isinstance(guidance, Mapping) else {}
    return _code(guidance.get("next_action"), ACTIONS,
                 _default_action(item))


def _missing(item: Mapping[str, Any]) -> List[str]:
    return _bounded((_observation(item).get("missing_observations") or []),
                    limit=MAX_OBSERVATIONS, item_limit=96)


def _expected_information_gain(status: str, action: str,
                               missing: Sequence[str],
                               recheck_status: str = "") -> int:
    base = {
        "unobserved": 4,
        "execution-only": 4,
        "partial": 3,
        "environment-gap": 3,
        "complete": 1,
        "falsifier-observed": 1,
    }.get(status, 3)
    if missing:
        base += 1
    if action == "repair-environment":
        base = max(base, 4)
    if action == "hold-for-new-evidence":
        base = 0
    if recheck_status in {"partial", "environment-gap", "not-executed"}:
        base = min(5, base + 1)
    return max(0, min(5, base))


def _estimated_cost(action: str, missing: Sequence[str]) -> int:
    cost = {
        "repair-environment": 1,
        "review-followup": 2,
        "reframe-scope": 1,
        "review-source-dataflow": 2,
        "add-negative-control": 3,
        "add-typed-effect": 3,
        "replay-residual-variant": 3,
        "replay-new-variant": 3,
        "repeat-with-controlled-context": 3,
        "trace-capability-transition": 4,
        "continue-path-closure": 3,
        "hold-for-new-evidence": 0,
    }.get(action, 3)
    return max(1 if action != "hold-for-new-evidence" else 0,
               min(5, cost + (1 if len(missing) >= 4 else 0)))


def _prerequisites(action: str, missing: Sequence[str]) -> List[str]:
    if action == "repair-environment":
        return ["environment-ready"]
    if action == "review-source-dataflow":
        return ["source-scope-available"]
    if action == "trace-capability-transition":
        return ["fixture-locked", "source-path-mapped"]
    if action == "add-typed-effect":
        return ["fixture-locked", "runtime-execution"]
    if action == "add-negative-control":
        return ["fixture-locked", "negative-control"]
    if action == "replay-residual-variant":
        return ["fixture-locked", "residual-contract"]
    if action == "replay-new-variant":
        return ["fixture-locked", "surface-variant-plan"]
    if action == "repeat-with-controlled-context":
        return ["fixture-locked", "independent-repeat"]
    if action == "review-followup":
        return ["review-scope-confirmed"]
    if missing:
        return ["fixture-locked"]
    return []


def _priority_score(item: Mapping[str, Any], expected_gain: int,
                    estimated_cost: int, recheck_status: str = "",
                    outcome_code: str = "") -> int:
    priority = _int(item.get("priority"), 1, 1, 5)
    guidance = item.get("guidance")
    guidance = guidance if isinstance(guidance, Mapping) else {}
    delta = _int(guidance.get("priority_delta"), 0, 0, 3)
    score = priority * 16 + expected_gain * 8 + delta * 5
    action = _action(item)
    status = _observation_status(item)
    if action == "repair-environment":
        score += 12
    if action == "review-followup":
        score += 8
    if action == "replay-residual-variant":
        score += 8
    if bool(guidance.get("replacement_recommended")):
        score += 6
    if status in {"unobserved", "environment-gap"}:
        score += 4
    if recheck_status in {"partial", "environment-gap", "not-executed"}:
        score += 6
    if outcome_code == "environment-gap":
        score += 8
    elif outcome_code == "not-executed":
        score += 6
    elif outcome_code == "no-new-information":
        score += 3
    if expected_gain == 0:
        score -= 12
    score -= max(0, estimated_cost - 3) * 2
    return max(0, min(100, score))


def _agenda_item(item: Mapping[str, Any], recheck_status: str = "",
                 outcome: Optional[Mapping[str, Any]] = None
                 ) -> Dict[str, Any]:
    strategy_id = _text(item.get("strategy_id"), 80)
    identity = (item.get("research_key") or item.get("candidate_id") or
                item.get("residual_id") or item.get("path_id") or strategy_id)
    action = _action(item)
    status = _observation_status(item)
    missing = _missing(item)
    outcome = outcome if isinstance(outcome, Mapping) else {}
    outcome_code = _code(
        outcome.get("outcome_code"),
        {"new-information", "falsifier-observed", "no-new-information",
         "environment-gap", "not-executed", "not-selected"}, "")
    expected_gain = _expected_information_gain(
        status, action, missing, recheck_status)
    estimated_cost = _estimated_cost(action, missing)
    score = _priority_score(item, expected_gain, estimated_cost,
                            recheck_status, outcome_code)
    guidance = item.get("guidance")
    guidance = guidance if isinstance(guidance, Mapping) else {}
    surface = _surface(item.get("research_surface"), item.get("target_type"))
    selection_status = (
        "hold" if action == "hold-for-new-evidence"
        or (status in {"complete", "falsifier-observed"} and not missing
             and not guidance.get("replacement_recommended"))
        else "deferred")
    reasons: List[str] = []
    if _int(item.get("priority"), 1, 1, 5) >= 4:
        reasons.append("priority")
    if missing or recheck_status in {"partial", "environment-gap", "not-executed"}:
        reasons.append("evidence-debt")
    if expected_gain >= 3:
        reasons.append("expected-information-gain")
    if action == "repair-environment":
        reasons.append("environment-repair")
    if action == "review-followup":
        reasons.append("review-followup")
    if action == "replay-residual-variant":
        reasons.append("residual-closure")
    if guidance.get("replacement_recommended"):
        reasons.append("replacement")
    if outcome_code == "environment-gap":
        reasons.append("outcome-recovery")
    elif outcome_code == "no-new-information":
        reasons.append("outcome-no-new-information")
    elif outcome_code == "not-executed":
        reasons.append("outcome-not-executed")
    elif outcome_code == "falsifier-observed":
        reasons.append("outcome-falsifier")
    elif outcome_code == "new-information":
        reasons.append("outcome-new-information")
    if selection_status == "hold":
        reasons = ["evidence-satisfied"]
    return {
        "agenda_id": _stable_id(strategy_id, identity),
        "strategy_id": strategy_id,
        "research_key": _text(item.get("research_key"), 80),
        "candidate_id": _text(item.get("candidate_id"), 120),
        "kind": _code(item.get("kind"), KINDS, "portfolio-followup"),
        "state": _text(item.get("state"), 48),
        "surface": surface,
        "target_type": _code(item.get("target_type"), TARGET_TYPES, ""),
        "attack_class": _text(item.get("attack_class"), 80).lower(),
        "variant": _bounded(item.get("variant"), limit=4, item_limit=100),
        "action": action,
        "observation_status": status,
        "missing_observations": missing,
        "required_observations": _bounded(
            item.get("required_observations"), limit=MAX_OBSERVATIONS,
            item_limit=96),
        "falsifiers": _bounded(item.get("falsifiers"), limit=MAX_FALSIFIERS,
                                item_limit=180),
        "prerequisites": _prerequisites(action, missing),
        "expected_information_gain": expected_gain,
        "estimated_cost": estimated_cost,
        "priority_score": score,
        "selection_status": selection_status,
        "selection_reason_codes": sorted(set(reasons))[:MAX_REASON_CODES],
        "rank": 0,
        "recheck_status": _code(
            recheck_status, {"observed", "partial", "environment-gap",
                             "not-executed"}, ""),
        "last_outcome": outcome_code,
        "outcome_round": _int(outcome.get("round"), 0, 0, 1000000),
        "outcome_information_gain": _int(
            outcome.get("information_gain"), 0, 0, 5),
        "outcome_observed_signals": _bounded(
            outcome.get("observed_signals"), limit=8, item_limit=48),
        "outcome_consecutive_no_information": _int(
            outcome.get("consecutive_no_information"), 0, 0, 32),
        "claim_status": AGENDA_CLAIM_STATUS,
    }


def _empty(target: str = "", round_no: int = 0, slots: int = DEFAULT_SLOTS,
           max_per_surface: int = DEFAULT_MAX_PER_SURFACE) -> Dict[str, Any]:
    return {
        "schema_version": AGENDA_SCHEMA_VERSION,
        "target": _text(target, 120),
        "round": _int(round_no, 0, 0, 1000000),
        "policy": {
            "slots": _int(slots, DEFAULT_SLOTS, 0, MAX_SLOTS),
            "max_per_surface": _int(max_per_surface,
                                      DEFAULT_MAX_PER_SURFACE, 1,
                                      MAX_PER_SURFACE),
            "algorithm": "priority-information-gain-diversity-v1",
            "claim_status": AGENDA_CLAIM_STATUS,
        },
        "summary": {
            "entry_count": 0,
            "selected_count": 0,
            "deferred_count": 0,
            "hold_count": 0,
            "selected_cost": 0,
            "selected_expected_information_gain": 0,
            "status_counts": {},
            "surface_counts": {},
            "action_counts": {},
            "last_outcome_counts": {},
            "claim_status": AGENDA_CLAIM_STATUS,
        },
        "items": [],
        "provenance": {
            "producer": "research-agenda",
            "evidence_type": "bounded-research-scheduling",
            "claim_status": AGENDA_CLAIM_STATUS,
        },
        "claim_status": AGENDA_CLAIM_STATUS,
    }


def _recheck_statuses(portfolio: Mapping[str, Any]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    rechecks = portfolio.get("consistency_rechecks")
    if not isinstance(rechecks, Mapping):
        return result
    for row in rechecks.get("entries") or []:
        if not isinstance(row, Mapping):
            continue
        key = _text(row.get("research_key"), 80)
        status = _code(row.get("status"),
                       {"observed", "partial", "environment-gap",
                        "not-executed"}, "")
        if key and status:
            result[key] = status
    return result


def _summary(items: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    statuses = Counter(_text(item.get("selection_status"), 32)
                       for item in items)
    surfaces = Counter(_text(item.get("surface"), 24) or "unknown"
                       for item in items
                       if item.get("selection_status") == "selected")
    actions = Counter(_text(item.get("action"), 64) for item in items
                      if item.get("selection_status") == "selected")
    outcomes = Counter(_text(item.get("last_outcome"), 40) for item in items
                       if _text(item.get("last_outcome"), 40))
    return {
        "entry_count": len(items),
        "selected_count": statuses.get("selected", 0),
        "deferred_count": statuses.get("deferred", 0),
        "hold_count": statuses.get("hold", 0),
        "selected_cost": sum(_int(item.get("estimated_cost"), 0, 0, 5)
                              for item in items
                              if item.get("selection_status") == "selected"),
        "selected_expected_information_gain": sum(
            _int(item.get("expected_information_gain"), 0, 0, 5)
            for item in items if item.get("selection_status") == "selected"),
        "status_counts": dict(sorted(statuses.items())),
        "surface_counts": dict(sorted(surfaces.items())),
        "action_counts": dict(sorted(actions.items())),
        "last_outcome_counts": dict(sorted(outcomes.items())),
        "claim_status": AGENDA_CLAIM_STATUS,
    }


def build_research_agenda(
        strategy: Optional[Mapping[str, Any]],
        portfolio: Optional[Mapping[str, Any]] = None,
        target: str = "",
        round_no: int = 0,
        slots: int = DEFAULT_SLOTS,
        max_per_surface: int = DEFAULT_MAX_PER_SURFACE,
        outcomes: Optional[Mapping[str, Any]] = None,
        ) -> Dict[str, Any]:
    """Select a diverse, information-seeking queue from normalized strategy."""
    normalized = normalize_research_strategy(strategy or {})
    normalized_portfolio = normalize_research_portfolio(portfolio or {})
    slots = _int(slots, DEFAULT_SLOTS, 0, MAX_SLOTS)
    max_per_surface = _int(max_per_surface, DEFAULT_MAX_PER_SURFACE, 1,
                           MAX_PER_SURFACE)
    rechecks = _recheck_statuses(normalized_portfolio)
    outcome_index: Dict[str, Mapping[str, Any]] = {}
    if isinstance(outcomes, Mapping):
        rows = list(outcomes.get("entries") or [])
        rows += list(outcomes.get("history") or [])
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            for key in (_text(row.get("agenda_id"), 80),
                        _text(row.get("strategy_id"), 80),
                        _text(row.get("research_key"), 80),
                        _text(row.get("candidate_id"), 120)):
                if key:
                    previous = outcome_index.get(key)
                    if previous is None or _int(row.get("round"), 0) >= _int(
                            previous.get("round"), 0):
                        outcome_index[key] = row
    candidates: List[Dict[str, Any]] = []
    seen_identity = set()
    for raw in normalized.get("items") or []:
        if not isinstance(raw, Mapping):
            continue
        identity = (_text(raw.get("research_key"), 80)
                    or _text(raw.get("candidate_id"), 120)
                    or _text(raw.get("residual_id"), 80)
                    or _text(raw.get("path_id"), 120)
                    or _text(raw.get("strategy_id"), 80))
        if not identity or identity in seen_identity:
            continue
        seen_identity.add(identity)
        outcome = None
        for key in (_stable_id(_text(raw.get("strategy_id"), 80), identity),
                    _text(raw.get("strategy_id"), 80),
                    _text(raw.get("research_key"), 80),
                    _text(raw.get("candidate_id"), 120)):
            if key and key in outcome_index:
                outcome = outcome_index[key]
                break
        row = _agenda_item(raw, rechecks.get(identity, ""), outcome)
        candidates.append(row)

    candidates.sort(key=lambda item: (
        -_int(item.get("priority_score"), 0, 0, 100),
        _text(item.get("surface"), 24) or "unknown",
        _text(item.get("attack_class"), 80),
        _text(item.get("agenda_id"), 80),
    ))
    for index, item in enumerate(candidates, 1):
        item["rank"] = index

    eligible = [item for item in candidates
                if item.get("selection_status") != "hold"]
    selected: List[Dict[str, Any]] = []
    surface_counts: Counter = Counter()
    diversity_buckets = set()

    def choose(item: Dict[str, Any], diverse: bool) -> bool:
        if len(selected) >= slots:
            return False
        surface = _text(item.get("surface"), 24) or "unknown"
        if surface_counts[surface] >= max_per_surface:
            return False
        bucket = (surface, _text(item.get("attack_class"), 80)
                  or _text(item.get("kind"), 48))
        if diverse and bucket in diversity_buckets:
            return False
        item["selection_status"] = "selected"
        reasons = set(item.get("selection_reason_codes") or [])
        if diverse:
            reasons.add("surface-diversity")
        item["selection_reason_codes"] = sorted(
            reasons & AGENDA_REASON_CODES)[:MAX_REASON_CODES]
        selected.append(item)
        surface_counts[surface] += 1
        diversity_buckets.add(bucket)
        return True

    # First pass spreads the finite budget across different research surfaces
    # and attack classes.  The second pass exploits the remaining highest
    # information-gain items without violating the per-surface cap.
    for item in eligible:
        if len(selected) >= slots:
            break
        choose(item, True)
    for item in eligible:
        if len(selected) >= slots:
            break
        if item not in selected:
            choose(item, False)

    selected_ids = {id(item) for item in selected}
    for item in candidates:
        if id(item) in selected_ids:
            continue
        if item.get("selection_status") == "hold":
            item["selection_reason_codes"] = ["evidence-satisfied"]
        else:
            item["selection_status"] = "deferred"
            item["selection_reason_codes"] = sorted(
                set(item.get("selection_reason_codes") or [])
                | {"budget-deferred"})[:MAX_REASON_CODES]

    result = _empty(target, round_no, slots, max_per_surface)
    result["items"] = sorted(candidates, key=lambda item: (
        0 if item.get("selection_status") == "selected" else
        (2 if item.get("selection_status") == "hold" else 1),
        _int(item.get("rank"), 0, 0, MAX_ENTRIES),
        _text(item.get("agenda_id"), 80),
    ))[:MAX_ENTRIES]
    result["summary"] = _summary(result["items"])
    return result


def _normalize_item(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        return {}
    agenda_id = _text(raw.get("agenda_id"), 80)
    if not _AGENDA_ID_RE.fullmatch(agenda_id):
        return {}
    status = _code(raw.get("selection_status"), AGENDA_STATUSES, "")
    if not status:
        return {}
    action = _code(raw.get("action"), ACTIONS, "continue-path-closure")
    observation_status = _code(
        raw.get("observation_status"), OBSERVATION_STATUSES, "unobserved")
    return {
        "agenda_id": agenda_id,
        "strategy_id": _text(raw.get("strategy_id"), 80),
        "research_key": _text(raw.get("research_key"), 80),
        "candidate_id": _text(raw.get("candidate_id"), 120),
        "kind": _code(raw.get("kind"), KINDS, "portfolio-followup"),
        "state": _text(raw.get("state"), 48),
        "surface": _surface(raw.get("surface"), raw.get("target_type")),
        "target_type": _code(raw.get("target_type"), TARGET_TYPES, ""),
        "attack_class": _text(raw.get("attack_class"), 80).lower(),
        "variant": _bounded(raw.get("variant"), limit=4, item_limit=100),
        "action": action,
        "observation_status": observation_status,
        "missing_observations": _bounded(
            raw.get("missing_observations"), limit=MAX_OBSERVATIONS,
            item_limit=96),
        "required_observations": _bounded(
            raw.get("required_observations"), limit=MAX_OBSERVATIONS,
            item_limit=96),
        "falsifiers": _bounded(raw.get("falsifiers"), limit=MAX_FALSIFIERS,
                                item_limit=180),
        "prerequisites": _bounded(raw.get("prerequisites"), PREREQUISITES,
                                   limit=MAX_IDS, item_limit=64),
        "expected_information_gain": _int(
            raw.get("expected_information_gain"), 0, 0, 5),
        "estimated_cost": _int(raw.get("estimated_cost"), 0, 0, 5),
        "priority_score": _int(raw.get("priority_score"), 0, 0, 100),
        "selection_status": status,
        "selection_reason_codes": _bounded(
            raw.get("selection_reason_codes"), AGENDA_REASON_CODES,
            MAX_REASON_CODES, 64),
        "rank": _int(raw.get("rank"), 0, 0, MAX_ENTRIES),
        "recheck_status": _code(
            raw.get("recheck_status"),
            {"observed", "partial", "environment-gap", "not-executed"}, ""),
        "last_outcome": _code(
            raw.get("last_outcome"),
            {"new-information", "falsifier-observed", "no-new-information",
             "environment-gap", "not-executed", "not-selected"}, ""),
        "outcome_round": _int(raw.get("outcome_round"), 0, 0, 1000000),
        "outcome_information_gain": _int(
            raw.get("outcome_information_gain"), 0, 0, 5),
        "outcome_observed_signals": _bounded(
            raw.get("outcome_observed_signals"), limit=8, item_limit=48),
        "outcome_consecutive_no_information": _int(
            raw.get("outcome_consecutive_no_information"), 0, 0, 32),
        "claim_status": AGENDA_CLAIM_STATUS,
    }


def normalize_research_agenda(raw: Any) -> Dict[str, Any]:
    """Normalize an agenda and recompute its summary from allowlisted fields."""
    if not isinstance(raw, Mapping) or \
            raw.get("schema_version") != AGENDA_SCHEMA_VERSION:
        return {}
    policy = raw.get("policy") if isinstance(raw.get("policy"), Mapping) else {}
    target = _text(raw.get("target"), 120)
    round_no = _int(raw.get("round"), 0, 0, 1000000)
    slots = _int(policy.get("slots"), DEFAULT_SLOTS, 0, MAX_SLOTS)
    max_per_surface = _int(
        policy.get("max_per_surface"), DEFAULT_MAX_PER_SURFACE, 1,
        MAX_PER_SURFACE)
    result = _empty(target, round_no, slots, max_per_surface)
    items: List[Dict[str, Any]] = []
    seen = set()
    for row in raw.get("items") or []:
        item = _normalize_item(row)
        if not item or item["agenda_id"] in seen:
            continue
        seen.add(item["agenda_id"])
        items.append(item)
        if len(items) >= MAX_ENTRIES:
            break
    items.sort(key=lambda item: (
        0 if item.get("selection_status") == "selected" else
        (2 if item.get("selection_status") == "hold" else 1),
        _int(item.get("rank"), 0, 0, MAX_ENTRIES),
        item["agenda_id"],
    ))
    result["items"] = items
    result["summary"] = _summary(items)
    return result


def agenda_path(workspace: Path, target: str) -> Path:
    return (Path(workspace).resolve() / "state" / str(target) /
            "coverage" / AGENDA_FILENAME)


def write_research_agenda(workspace: Path, target: str,
                          agenda: Mapping[str, Any]) -> Path:
    path = agenda_path(workspace, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = normalize_research_agenda(agenda) or _empty(target)
    temporary = path.with_name(".%s.tmp.%d" % (path.name, os.getpid()))
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                         encoding="utf-8")
    temporary.replace(path)
    return path


def load_research_agenda(workspace: Path, target: str) -> Dict[str, Any]:
    path = agenda_path(workspace, target)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError):
        return {}
    return normalize_research_agenda(raw)
