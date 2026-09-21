"""Allocate bounded research budget from observed agenda outcomes.

An active agenda becomes expert-like only when its finite budget changes for a
reason that can be replayed.  This module aggregates the previous agenda and
its normalized outcomes by research surface, cost and information gain.  It
produces a small, allowlisted policy consumed by the next agenda round:

* environment gaps receive recovery priority;
* repeated no-information work is cooled down without deleting the hypothesis;
* productive surfaces receive a bounded exploitation nudge; and
* surfaces without evidence retain an exploration opportunity.

The policy is scheduling metadata only.  It never changes candidate status,
CVSS, G4/G5, or any finding conclusion, and it never stores source prose,
payloads, commands, process output, credentials, or reviewer notes.
"""

from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from ..tools.redaction import redact_text
from .research_agenda import normalize_research_agenda
from .research_agenda_outcomes import normalize_research_agenda_outcomes


BUDGET_SCHEMA_VERSION = "research-budget-v1"
BUDGET_FILENAME = "research-budget.json"
BUDGET_CLAIM_STATUS = "not-a-finding"

MAX_SURFACES = 5
MAX_HISTORY = 64
MAX_RESEARCH_KEYS = 128
MAX_TEXT = 120
MAX_ROUNDS = 1_000_000
MAX_SLOTS = 16
MAX_COST = 5
MAX_DELTA = 8

RESEARCH_SURFACES = frozenset({"web", "protocol", "cloud", "mobile", "native"})
RECOMMENDATIONS = frozenset({
    "recover-environment",
    "cooldown-low-yield",
    "exploit-high-yield",
    "explore-undercovered",
    "continue-balanced",
})
OUTCOME_CODES = frozenset({
    "new-information", "falsifier-observed", "no-new-information",
    "environment-gap", "not-executed", "not-selected",
})

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
         maximum: int = MAX_ROUNDS) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _signed(value: Any, default: int = 0, minimum: int = -MAX_DELTA,
            maximum: int = MAX_DELTA) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _float(value: Any, default: float = 0.0, minimum: float = 0.0,
           maximum: float = 5.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    if parsed != parsed:  # NaN
        parsed = default
    return round(max(minimum, min(maximum, parsed)), 4)


def _code(value: Any, allowed: Iterable[str], fallback: str = "") -> str:
    item = _text(value, 80).lower()
    return item if item in set(allowed) else fallback


def _surface(value: Any, target_type: Any = "") -> str:
    item = _text(value, 32).lower()
    if item in RESEARCH_SURFACES:
        return item
    return _TARGET_TO_SURFACE.get(_text(target_type, 48).lower(), "")


def _empty(target: str = "", round_no: int = 0, slots: int = 8
           ) -> Dict[str, Any]:
    return {
        "schema_version": BUDGET_SCHEMA_VERSION,
        "target": _text(target, 120),
        "round": _int(round_no, 0, 0, MAX_ROUNDS),
        "policy": {
            "algorithm": "outcome-cost-adaptive-v1",
            "slots": _int(slots, 8, 0, MAX_SLOTS),
            "exploration_floor": 1,
            "claim_status": BUDGET_CLAIM_STATUS,
        },
        "surfaces": [],
        "research_keys": [],
        "history": [],
        "summary": {
            "surface_count": 0,
            "observed_surface_count": 0,
            "selected_count": 0,
            "productive_count": 0,
            "information_gain": 0,
            "estimated_cost": 0,
            "environment_gap_count": 0,
            "no_information_count": 0,
            "productive_rate": 0.0,
            "yield_per_cost": 0.0,
            "recommendation_counts": {},
            "claim_status": BUDGET_CLAIM_STATUS,
        },
        "provenance": {
            "producer": "research-budget",
            "evidence_type": "bounded-outcome-cost-scheduling",
            "claim_status": BUDGET_CLAIM_STATUS,
        },
        "claim_status": BUDGET_CLAIM_STATUS,
    }


def _agenda_index(agenda: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    result: Dict[str, Mapping[str, Any]] = {}
    for item in agenda.get("items") or []:
        if not isinstance(item, Mapping):
            continue
        for key in (
                _text(item.get("agenda_id"), 80),
                _text(item.get("strategy_id"), 80),
                _text(item.get("research_key"), 80),
                _text(item.get("candidate_id"), 120)):
            if key:
                result.setdefault(key, item)
    return result


def _outcome_index(outcomes: Mapping[str, Any]
                   ) -> Dict[str, Mapping[str, Any]]:
    result: Dict[str, Mapping[str, Any]] = {}
    rows = list(outcomes.get("entries") or [])
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        for key in (
                _text(row.get("agenda_id"), 80),
                _text(row.get("strategy_id"), 80),
                _text(row.get("research_key"), 80),
                _text(row.get("candidate_id"), 120)):
            if key:
                previous = result.get(key)
                if previous is None or _int(row.get("round"), 0) >= _int(
                        previous.get("round"), 0):
                    result[key] = row
    return result


def _surface_stats() -> Dict[str, Any]:
    return {
        "selected_count": 0,
        "productive_count": 0,
        "information_gain": 0,
        "estimated_cost": 0,
        "environment_gap_count": 0,
        "no_information_count": 0,
        "not_executed_count": 0,
    }


def _current_round_stats(agenda: Mapping[str, Any],
                         outcomes: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Join selected outcome rows to their exact prior agenda metadata."""
    agenda_index = _agenda_index(agenda)
    stats: Dict[str, Dict[str, Any]] = defaultdict(_surface_stats)
    for raw in outcomes.get("entries") or []:
        if not isinstance(raw, Mapping):
            continue
        if _text(raw.get("selection_status"), 24) != "selected":
            continue
        item = None
        for key in (
                _text(raw.get("agenda_id"), 80),
                _text(raw.get("strategy_id"), 80),
                _text(raw.get("research_key"), 80),
                _text(raw.get("candidate_id"), 120)):
            if key and key in agenda_index:
                item = agenda_index[key]
                break
        if not item:
            continue
        surface = _surface(item.get("surface"), item.get("target_type"))
        if not surface:
            continue
        row = stats[surface]
        code = _code(raw.get("outcome_code"), OUTCOME_CODES,
                     "not-executed")
        row["selected_count"] += 1
        row["productive_count"] += int(code in {
            "new-information", "falsifier-observed"})
        row["information_gain"] += _int(raw.get("information_gain"), 0, 0, 5)
        row["estimated_cost"] += _int(item.get("estimated_cost"), 1, 1,
                                      MAX_COST)
        row["environment_gap_count"] += int(code == "environment-gap")
        row["no_information_count"] += int(code == "no-new-information")
        row["not_executed_count"] += int(code == "not-executed")
    return dict(stats)


def _normalize_history_row(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        return {}
    surface = _surface(raw.get("surface"))
    if not surface:
        return {}
    selected = _int(raw.get("selected_count"), 0, 0, MAX_SLOTS)
    return {
        "round": _int(raw.get("round"), 0, 0, MAX_ROUNDS),
        "surface": surface,
        "selected_count": selected,
        "productive_count": _int(raw.get("productive_count"), 0, 0, MAX_SLOTS),
        "information_gain": _int(raw.get("information_gain"), 0, 0,
                                  MAX_SLOTS * 5),
        "estimated_cost": _int(raw.get("estimated_cost"), 0, 0,
                                MAX_SLOTS * MAX_COST),
        "environment_gap_count": _int(
            raw.get("environment_gap_count"), 0, 0, MAX_SLOTS),
        "no_information_count": _int(
            raw.get("no_information_count"), 0, 0, MAX_SLOTS),
        "not_executed_count": _int(
            raw.get("not_executed_count"), 0, 0, MAX_SLOTS),
        "claim_status": BUDGET_CLAIM_STATUS,
    }


def _normalize_surface_row(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        return {}
    surface = _surface(raw.get("surface"))
    if not surface:
        return {}
    return {
        "surface": surface,
        "rounds_observed": _int(raw.get("rounds_observed"), 0, 0,
                                MAX_HISTORY),
        "selected_count": _int(raw.get("selected_count"), 0, 0,
                                MAX_HISTORY * MAX_SLOTS),
        "productive_count": _int(raw.get("productive_count"), 0, 0,
                                  MAX_HISTORY * MAX_SLOTS),
        "information_gain": _int(raw.get("information_gain"), 0, 0,
                                  MAX_HISTORY * MAX_SLOTS * 5),
        "estimated_cost": _int(raw.get("estimated_cost"), 0, 0,
                                MAX_HISTORY * MAX_SLOTS * MAX_COST),
        "environment_gap_count": _int(
            raw.get("environment_gap_count"), 0, 0,
            MAX_HISTORY * MAX_SLOTS),
        "no_information_count": _int(
            raw.get("no_information_count"), 0, 0,
            MAX_HISTORY * MAX_SLOTS),
        "not_executed_count": _int(
            raw.get("not_executed_count"), 0, 0,
            MAX_HISTORY * MAX_SLOTS),
        "yield_per_cost": _float(raw.get("yield_per_cost"), 0.0, 0.0, 5.0),
        "productive_rate": _float(raw.get("productive_rate"), 0.0, 0.0, 1.0),
        "environment_gap_rate": _float(
            raw.get("environment_gap_rate"), 0.0, 0.0, 1.0),
        "no_information_rate": _float(
            raw.get("no_information_rate"), 0.0, 0.0, 1.0),
        "recommendation": _code(raw.get("recommendation"), RECOMMENDATIONS,
                                 "continue-balanced"),
        "priority_delta": _signed(raw.get("priority_delta"), 0, -MAX_DELTA,
                                  MAX_DELTA),
        "cap_hint": _int(raw.get("cap_hint"), 2, 1, MAX_SLOTS),
        "last_round": _int(raw.get("last_round"), 0, 0, MAX_ROUNDS),
        "claim_status": BUDGET_CLAIM_STATUS,
    }


def _normalize_key_row(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        return {}
    key = _text(raw.get("research_key"), 80)
    if not key:
        return {}
    return {
        "research_key": key,
        "surface": _surface(raw.get("surface")),
        "last_outcome": _code(raw.get("last_outcome"), OUTCOME_CODES, ""),
        "consecutive_no_information": _int(
            raw.get("consecutive_no_information"), 0, 0, 32),
        "round": _int(raw.get("round"), 0, 0, MAX_ROUNDS),
        "recommendation": _code(raw.get("recommendation"), RECOMMENDATIONS,
                                 "continue-balanced"),
        "claim_status": BUDGET_CLAIM_STATUS,
    }


def _summary(surfaces: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    observed = [row for row in surfaces if row.get("selected_count", 0)]
    selected = sum(_int(row.get("selected_count"), 0, 0) for row in surfaces)
    productive = sum(_int(row.get("productive_count"), 0, 0)
                     for row in surfaces)
    gain = sum(_int(row.get("information_gain"), 0, 0) for row in surfaces)
    cost = sum(_int(row.get("estimated_cost"), 0, 0) for row in surfaces)
    env = sum(_int(row.get("environment_gap_count"), 0, 0)
              for row in surfaces)
    no_info = sum(_int(row.get("no_information_count"), 0, 0)
                  for row in surfaces)
    recommendations = Counter(_text(row.get("recommendation"), 48)
                              for row in surfaces
                              if _text(row.get("recommendation"), 48))
    return {
        "surface_count": len(surfaces),
        "observed_surface_count": len(observed),
        "selected_count": selected,
        "productive_count": productive,
        "information_gain": gain,
        "estimated_cost": cost,
        "environment_gap_count": env,
        "no_information_count": no_info,
        "productive_rate": round(float(productive) / selected, 4)
        if selected else 0.0,
        "yield_per_cost": _float(float(gain) / cost if cost else 0.0),
        "recommendation_counts": dict(sorted(recommendations.items())),
        "claim_status": BUDGET_CLAIM_STATUS,
    }


def _recommendation(stats: Mapping[str, Any], observed_rounds: int
                    ) -> tuple[str, int, int]:
    selected = _int(stats.get("selected_count"), 0, 0)
    env = _int(stats.get("environment_gap_count"), 0, 0)
    no_info = _int(stats.get("no_information_count"), 0, 0)
    productive = _int(stats.get("productive_count"), 0, 0)
    env_rate = float(env) / selected if selected else 0.0
    no_info_rate = float(no_info) / selected if selected else 0.0
    productive_rate = float(productive) / selected if selected else 0.0
    gain = _int(stats.get("information_gain"), 0, 0)
    cost = _int(stats.get("estimated_cost"), 0, 0)
    yield_per_cost = float(gain) / cost if cost else 0.0
    if env and (env_rate >= 0.5 or observed_rounds <= 1):
        return "recover-environment", 8, 2
    if selected >= 2 and no_info_rate >= 0.6 and productive_rate < 0.5:
        return "cooldown-low-yield", -6, 1
    if selected and productive_rate >= 0.5 and yield_per_cost >= 0.25:
        return "exploit-high-yield", 4, 4
    if not selected or not observed_rounds:
        return "explore-undercovered", 1, 1
    return "continue-balanced", 0, 2


def build_research_budget(
        agenda: Optional[Mapping[str, Any]],
        outcomes: Optional[Mapping[str, Any]],
        prior_budget: Optional[Mapping[str, Any]] = None,
        target: str = "",
        round_no: int = 0,
        slots: int = 8,
        ) -> Dict[str, Any]:
    """Build an idempotent, bounded outcome-to-budget policy."""
    normalized_agenda = normalize_research_agenda(agenda or {})
    normalized_outcomes = normalize_research_agenda_outcomes(outcomes or {})
    prior = normalize_research_budget(prior_budget or {})
    round_no = _int(round_no or normalized_outcomes.get("round") or
                    normalized_agenda.get("round"), 0, 0, MAX_ROUNDS)
    slots = _int(slots or (normalized_agenda.get("policy") or {}).get("slots"),
                 8, 0, MAX_SLOTS)

    current = _current_round_stats(normalized_agenda, normalized_outcomes)
    surfaces = set(current)
    for item in normalized_agenda.get("items") or []:
        surface = _surface(item.get("surface"), item.get("target_type"))
        if surface:
            surfaces.add(surface)
    for row in prior.get("surfaces") or []:
        if isinstance(row, Mapping) and _surface(row.get("surface")):
            surfaces.add(_surface(row.get("surface")))
    for row in prior.get("history") or []:
        if isinstance(row, Mapping) and _surface(row.get("surface")):
            surfaces.add(_surface(row.get("surface")))
    surfaces = set(sorted(surfaces))

    prior_history: List[Dict[str, Any]] = []
    for raw in prior.get("history") or []:
        row = _normalize_history_row(raw)
        if row and row.get("round") != round_no:
            prior_history.append(row)
    for surface in sorted(current):
        row = dict(current[surface])
        row.update({"round": round_no, "surface": surface,
                    "claim_status": BUDGET_CLAIM_STATUS})
        prior_history.append(_normalize_history_row(row))
    prior_history = [row for row in prior_history if row]
    prior_history.sort(key=lambda row: (_int(row.get("round"), 0),
                                        _text(row.get("surface"), 24)))
    prior_history = prior_history[-MAX_HISTORY:]

    surface_rows: List[Dict[str, Any]] = []
    for surface in sorted(surfaces):
        aggregate = _surface_stats()
        rounds = set()
        for row in prior_history:
            if row.get("surface") != surface:
                continue
            rounds.add(_int(row.get("round"), 0))
            for key in aggregate:
                aggregate[key] += _int(row.get(key), 0, 0)
        current_row = current.get(surface)
        if current_row:
            rounds.add(round_no)
        recommendation, delta, cap_hint = _recommendation(
            aggregate, len(rounds))
        selected = aggregate["selected_count"]
        cost = aggregate["estimated_cost"]
        productive = aggregate["productive_count"]
        env = aggregate["environment_gap_count"]
        no_info = aggregate["no_information_count"]
        row = {
            "surface": surface,
            "rounds_observed": len(rounds),
            **aggregate,
            "yield_per_cost": _float(
                float(aggregate["information_gain"]) / cost if cost else 0.0),
            "productive_rate": _float(
                float(productive) / selected if selected else 0.0, 0.0, 0.0, 1.0),
            "environment_gap_rate": _float(
                float(env) / selected if selected else 0.0, 0.0, 0.0, 1.0),
            "no_information_rate": _float(
                float(no_info) / selected if selected else 0.0, 0.0, 0.0, 1.0),
            "recommendation": recommendation,
            "priority_delta": delta,
            "cap_hint": cap_hint,
            "last_round": max((_int(item.get("round"), 0)
                                for item in prior_history
                                if item.get("surface") == surface), default=0),
            "claim_status": BUDGET_CLAIM_STATUS,
        }
        surface_rows.append(row)

    surface_rows.sort(key=lambda row: (
        -_signed(row.get("priority_delta"), 0, -MAX_DELTA, MAX_DELTA),
        -_float(row.get("yield_per_cost"), 0.0),
        _text(row.get("surface"), 24),
    ))

    outcome_index = _outcome_index(normalized_outcomes)
    key_rows: List[Dict[str, Any]] = []
    seen_keys = set()
    for item in normalized_agenda.get("items") or []:
        key = _text(item.get("research_key"), 80)
        if not key or key in seen_keys:
            continue
        seen_keys.add(key)
        row = None
        for candidate_key in (
                _text(item.get("agenda_id"), 80),
                _text(item.get("strategy_id"), 80), key,
                _text(item.get("candidate_id"), 120)):
            if candidate_key and candidate_key in outcome_index:
                row = outcome_index[candidate_key]
                break
        if not row:
            continue
        code = _code(row.get("outcome_code"), OUTCOME_CODES, "")
        streak = _int(row.get("consecutive_no_information"), 0, 0, 32)
        recommendation = ("cooldown-low-yield" if streak >= 2 else
                          "continue-balanced")
        key_rows.append({
            "research_key": key,
            "surface": _surface(item.get("surface"), item.get("target_type")),
            "last_outcome": code,
            "consecutive_no_information": streak,
            "round": _int(row.get("round"), round_no, 0, MAX_ROUNDS),
            "recommendation": recommendation,
            "claim_status": BUDGET_CLAIM_STATUS,
        })
        if len(key_rows) >= MAX_RESEARCH_KEYS:
            break

    result = _empty(target or normalized_agenda.get("target", ""),
                    round_no, slots)
    result["surfaces"] = surface_rows[:MAX_SURFACES]
    result["research_keys"] = key_rows
    result["history"] = prior_history
    result["summary"] = _summary(result["surfaces"])
    result["provenance"].update({
        "agenda_present": bool(normalized_agenda),
        "outcomes_present": bool(normalized_outcomes),
        "prior_budget_present": bool(prior),
    })
    return result


def normalize_research_budget(raw: Any) -> Dict[str, Any]:
    """Normalize a budget policy and discard untrusted/raw fields."""
    if not isinstance(raw, Mapping) or \
            raw.get("schema_version") != BUDGET_SCHEMA_VERSION:
        return {}
    result = _empty(raw.get("target", ""),
                    _int(raw.get("round"), 0, 0, MAX_ROUNDS),
                    _int((raw.get("policy") or {}).get("slots"), 8, 0,
                         MAX_SLOTS))
    surfaces: List[Dict[str, Any]] = []
    seen = set()
    for raw_row in raw.get("surfaces") or []:
        row = _normalize_surface_row(raw_row)
        if not row or row["surface"] in seen:
            continue
        seen.add(row["surface"])
        surfaces.append(row)
        if len(surfaces) >= MAX_SURFACES:
            break
    surfaces.sort(key=lambda row: (
        -_signed(row.get("priority_delta"), 0, -MAX_DELTA, MAX_DELTA),
        -_float(row.get("yield_per_cost"), 0.0), row["surface"]))
    keys: List[Dict[str, Any]] = []
    seen_keys = set()
    for raw_row in raw.get("research_keys") or []:
        row = _normalize_key_row(raw_row)
        if not row or row["research_key"] in seen_keys:
            continue
        seen_keys.add(row["research_key"])
        keys.append(row)
        if len(keys) >= MAX_RESEARCH_KEYS:
            break
    history: List[Dict[str, Any]] = []
    seen_history = set()
    for raw_row in raw.get("history") or []:
        row = _normalize_history_row(raw_row)
        if not row:
            continue
        identity = (row["round"], row["surface"])
        if identity in seen_history:
            continue
        seen_history.add(identity)
        history.append(row)
        if len(history) >= MAX_HISTORY:
            break
    history.sort(key=lambda row: (_int(row.get("round"), 0),
                                 _text(row.get("surface"), 24)))
    result["surfaces"] = surfaces
    result["research_keys"] = keys
    result["history"] = history[-MAX_HISTORY:]
    result["summary"] = _summary(surfaces)
    policy = raw.get("policy")
    policy = policy if isinstance(policy, Mapping) else {}
    result["policy"].update({
        "algorithm": _text(policy.get("algorithm"), 80) or
        "outcome-cost-adaptive-v1",
        "exploration_floor": _int(policy.get("exploration_floor"), 1, 0,
                                   MAX_SLOTS),
    })
    provenance = raw.get("provenance")
    provenance = provenance if isinstance(provenance, Mapping) else {}
    result["provenance"].update({
        key: bool(provenance.get(key))
        for key in ("agenda_present", "outcomes_present",
                    "prior_budget_present")
        if key in provenance
    })
    return result


def budget_path(workspace: Path, target: str) -> Path:
    return (Path(workspace).resolve() / "state" / str(target) /
            "coverage" / BUDGET_FILENAME)


def write_research_budget(workspace: Path, target: str,
                          budget: Mapping[str, Any]) -> Path:
    path = budget_path(workspace, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = normalize_research_budget(budget) or _empty(target)
    temporary = path.with_name(".%s.tmp.%d" % (path.name, os.getpid()))
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                         encoding="utf-8")
    temporary.replace(path)
    return path


def load_research_budget(workspace: Path, target: str) -> Dict[str, Any]:
    path = budget_path(workspace, target)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError):
        return {}
    return normalize_research_budget(raw)


def budget_view(budget: Mapping[str, Any]) -> Dict[str, Any]:
    """Return the small allowlisted view embedded in the next agenda."""
    normalized = normalize_research_budget(budget or {})
    if not normalized:
        return {}
    return {
        "schema_version": BUDGET_SCHEMA_VERSION,
        "round": normalized.get("round", 0),
        "algorithm": (normalized.get("policy") or {}).get(
            "algorithm", "outcome-cost-adaptive-v1"),
        "surface_order": [row.get("surface")
                           for row in normalized.get("surfaces") or []],
        "surfaces": [
            {
                "surface": row.get("surface"),
                "recommendation": row.get("recommendation"),
                "priority_delta": row.get("priority_delta", 0),
                "cap_hint": row.get("cap_hint", 2),
            }
            for row in (normalized.get("surfaces") or [])[:MAX_SURFACES]
        ],
        "claim_status": BUDGET_CLAIM_STATUS,
    }
