"""Measure bounded outcomes of an active research agenda.

An active queue is only expert-like when the next round can distinguish a
selected experiment that produced new information from one that was never
scheduled, hit an environment gap, or repeated the same observation.  This
module joins the previous agenda with the persisted schedule and S4/S8
summaries.  It stores only allowlisted outcome metadata and remains
``claim_status=not-a-finding``: an outcome is research feedback, never a
vulnerability conclusion.

No source prose, payloads, commands, process output, credentials, CVSS or
finding conclusion is copied into the artifact.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set

from ..tools.redaction import redact_text
from .research_agenda import (
    AGENDA_CLAIM_STATUS,
    AGENDA_SCHEMA_VERSION,
    normalize_research_agenda,
)


OUTCOME_SCHEMA_VERSION = "research-agenda-outcome-v1"
OUTCOME_FILENAME = "research-agenda-outcomes.json"
OUTCOME_CLAIM_STATUS = "not-a-finding"

MAX_ENTRIES = 64
MAX_HISTORY = 256
MAX_CODES = 8
MAX_SIGNALS = 12
MAX_ROUNDS = 1000000
MAX_TEXT = 120

OUTCOME_CODES = frozenset({
    "new-information",
    "falsifier-observed",
    "no-new-information",
    "environment-gap",
    "not-executed",
    "not-selected",
})
SCHEDULE_STATUSES = frozenset({"selected", "deferred", "unknown"})
EXECUTION_STATES = frozenset({
    "executed", "executed-no-effect", "executed-with-effect",
    "unexecuted", "run-failed", "precondition-unavailable", "gate-blocked",
    "harness-error", "inconclusive", "disabled", "environment-gap",
})
OBSERVATION_STATUSES = frozenset({
    "unobserved", "execution-only", "partial", "complete",
    "environment-gap", "falsifier-observed",
})
OBSERVATION_SIGNALS = frozenset({
    "execution", "entry-behavior", "authorization", "negative-baseline",
    "capability-trace", "state-sequence", "typed-effect", "safe-equivalent",
    "residual-contract", "explicit-falsifier", "residual-safe",
    "evidence-field", "environment-gap", "runtime-error",
})
REASON_CODES = frozenset({
    "agenda-selected", "agenda-deferred", "schedule-missing",
    "candidate-not-scheduled", "candidate-not-found", "s4-executed",
    "strategy-feedback", "new-observation", "falsifier-observed",
    "no-information-gain", "environment-gap", "not-executed",
    "verification-summary", "runtime-lab-summary",
})
GAP_STATES = frozenset({
    "unexecuted", "run-failed", "precondition-unavailable", "gate-blocked",
    "harness-error", "inconclusive", "disabled", "environment-gap",
})
LAB_GAP_STATUSES = frozenset({
    "run-failed", "precondition-unavailable", "policy-denied",
    "environment-gap", "degraded", "disabled", "no-fixtures", "not-executed",
})

_OUTCOME_ID_RE = re.compile(r"^rao-[0-9a-f]{24}$")


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    try:
        value = redact_text(value)
    except Exception:  # pragma: no cover - defensive boundary
        value = str(value)
    return " ".join(str(value or "").replace("\x00", "").split())[:limit]


def _int(value: Any, default: int = 0, minimum: int = 0,
         maximum: int = MAX_ROUNDS) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _bounded(values: Any, allowed: Optional[Iterable[str]] = None,
             limit: int = MAX_CODES, item_limit: int = MAX_TEXT) -> List[str]:
    if isinstance(values, (str, bytes)):
        values = [values]
    if not isinstance(values, (list, tuple, set)):
        return []
    allow = set(allowed) if allowed is not None else None
    result: List[str] = []
    for value in values:
        item = _text(value, item_limit).lower()
        if not item or (allow is not None and item not in allow):
            continue
        if item not in result:
            result.append(item)
        if len(result) >= limit:
            break
    return sorted(result)


def _code(value: Any, allowed: Iterable[str], fallback: str = "") -> str:
    item = _text(value, 80).lower()
    return item if item in set(allowed) else fallback


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def _stable_id(*parts: Any) -> str:
    material = "\x1f".join(_text(part, 240) for part in parts)
    return "rao-" + hashlib.sha256(
        material.encode("utf-8", errors="replace")).hexdigest()[:24]


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _candidate_status(verification: Mapping[str, Any],
                     candidate_id: str) -> Mapping[str, Any]:
    row = verification.get(candidate_id)
    return row if isinstance(row, Mapping) else {}


def _lab_status(runtime_lab: Mapping[str, Any], candidate_id: str
                ) -> Mapping[str, Any]:
    rows = runtime_lab.get("candidate_status")
    if not isinstance(rows, Mapping):
        return {}
    row = rows.get(candidate_id)
    return row if isinstance(row, Mapping) else {}


def _feedback_index(strategy_feedback: Mapping[str, Any]
                    ) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for raw in strategy_feedback.get("items") or []:
        if not isinstance(raw, Mapping):
            continue
        observation = raw.get("observation")
        observation = observation if isinstance(observation, Mapping) else {}
        item = {
            "strategy_id": _text(raw.get("strategy_id"), 80),
            "research_key": _text(raw.get("research_key"), 80),
            "candidate_id": _text(raw.get("candidate_id"), 120),
            "observation_status": _code(
                observation.get("status"), OBSERVATION_STATUSES, "unobserved"),
            "information_gain": _int(observation.get("information_gain"), 0, 0, 5),
            "new_signals": _bounded(
                observation.get("new_signals"), OBSERVATION_SIGNALS,
                MAX_SIGNALS, 48),
            "observed_signals": _bounded(
                observation.get("current_signals") or
                observation.get("observed_signals"), OBSERVATION_SIGNALS,
                MAX_SIGNALS, 48),
            "missing_observations": _bounded(
                observation.get("missing_observations"), limit=MAX_CODES,
                item_limit=96),
            "falsifier_codes": _bounded(
                observation.get("falsifier_codes"), limit=MAX_CODES,
                item_limit=64),
            "execution_states": _bounded(
                observation.get("execution_states"), EXECUTION_STATES,
                MAX_CODES, 64),
        }
        for key in (item["strategy_id"], item["research_key"],
                    item["candidate_id"]):
            if key:
                result[key] = item
    return result


def _feedback_for(item: Mapping[str, Any],
                  index: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
    for key in (
            _text(item.get("strategy_id"), 80),
            _text(item.get("research_key"), 80),
            _text(item.get("candidate_id"), 120)):
        if key and key in index:
            return dict(index[key])
    return {}


def _schedule_index(schedule: Mapping[str, Any]) -> Dict[str, Any]:
    if not schedule:
        return {"available": False, "by_key": {}, "by_candidate": {}}
    by_key: Dict[str, str] = {}
    by_candidate: Dict[str, str] = {}
    selected_ids = {
        _text(value, 120) for value in schedule.get("selected_ids") or []
        if _text(value, 120)
    }
    deferred_ids = {
        _text(value, 120) for value in schedule.get("deferred_ids") or []
        if _text(value, 120)
    }
    rows: List[Mapping[str, Any]] = []
    for status, field in (("selected", "selected"), ("deferred", "deferred")):
        for raw in schedule.get(field) or []:
            if isinstance(raw, Mapping):
                row = dict(raw)
                row["_schedule_status"] = status
                rows.append(row)
    for candidate_id in selected_ids:
        by_candidate[candidate_id] = "selected"
    for candidate_id in deferred_ids:
        by_candidate.setdefault(candidate_id, "deferred")
    for row in rows:
        status = _code(row.get("_schedule_status"),
                       {"selected", "deferred"}, "unknown")
        candidate_id = _text(row.get("candidate_id"), 120)
        if candidate_id:
            by_candidate[candidate_id] = status
        evidence = row.get("evidence")
        evidence = evidence if isinstance(evidence, Mapping) else {}
        agenda = evidence.get("research_agenda")
        agenda = agenda if isinstance(agenda, Mapping) else {}
        for key in (_text(agenda.get("agenda_id"), 80),
                    _text(agenda.get("strategy_id"), 80),
                    _text(agenda.get("research_key"), 80)):
            if key:
                by_key[key] = status
    return {"available": True, "by_key": by_key, "by_candidate": by_candidate}


def _schedule_for(item: Mapping[str, Any], index: Mapping[str, Any]) -> str:
    for key in (
            _text(item.get("agenda_id"), 80),
            _text(item.get("strategy_id"), 80),
            _text(item.get("research_key"), 80)):
        if key and key in index.get("by_key", {}):
            return index["by_key"][key]
    candidate_id = _text(item.get("candidate_id"), 120)
    if candidate_id:
        return index.get("by_candidate", {}).get(candidate_id, "unknown")
    return "unknown"


def _execution_view(candidate_id: str, verification: Mapping[str, Any],
                    runtime_lab: Mapping[str, Any]) -> Dict[str, Any]:
    summary = _candidate_status(verification, candidate_id)
    lab = _lab_status(runtime_lab, candidate_id)
    execution_state = _code(summary.get("execution_state"), EXECUTION_STATES,
                            "")
    cells_ran = _int(summary.get("cells_ran"), 0, 0, 128)
    fixture_count = _int(lab.get("fixture_count"), 0, 0, 128)
    replay_statuses = _bounded(lab.get("replay_statuses"), limit=MAX_CODES,
                               item_limit=64)
    differential_statuses = _bounded(
        lab.get("differential_statuses"), limit=MAX_CODES, item_limit=64)
    gap = execution_state in GAP_STATES
    gap = gap or any(status in GAP_STATES for status in replay_statuses)
    gap = gap or any(status in GAP_STATES for status in differential_statuses)
    lab_status = _code(runtime_lab.get("status"), LAB_GAP_STATUSES, "")
    if lab_status in LAB_GAP_STATUSES and not fixture_count and not cells_ran:
        gap = True
    safe = bool(summary.get("safe_equivalent"))
    effect = bool(summary.get("effect_evidence") or summary.get("http_evidence")
                  or summary.get("leaked") or summary.get("instantiated"))
    executed = bool(cells_ran or fixture_count or execution_state in {
        "executed", "executed-no-effect", "executed-with-effect"})
    return {
        "candidate_id": candidate_id,
        "execution_state": execution_state,
        "cells_ran": cells_ran,
        "fixture_count": fixture_count,
        "replay_statuses": replay_statuses,
        "differential_statuses": differential_statuses,
        "environment_gap": bool(gap),
        "executed": bool(executed),
        "safe_equivalent_observed": safe,
        "effect_observed": effect,
    }


def _fallback_observation(item: Mapping[str, Any], execution: Mapping[str, Any]
                          ) -> Dict[str, Any]:
    if execution.get("environment_gap"):
        return {
            "outcome_code": "environment-gap",
            "information_gain": 0,
            "observed_signals": ["environment-gap"],
            "missing_observations": [],
            "falsifier_codes": [],
            "reason_codes": ["environment-gap", "runtime-lab-summary"],
        }
    if not execution.get("executed"):
        return {
            "outcome_code": "not-executed",
            "information_gain": 0,
            "observed_signals": [],
            "missing_observations": [],
            "falsifier_codes": [],
            "reason_codes": ["not-executed"],
        }
    if execution.get("safe_equivalent_observed"):
        return {
            "outcome_code": "falsifier-observed",
            "information_gain": 1,
            "observed_signals": ["safe-equivalent"],
            "missing_observations": [],
            "falsifier_codes": ["negative-or-safe-observation"],
            "reason_codes": ["falsifier-observed", "verification-summary"],
        }
    if execution.get("effect_observed"):
        return {
            "outcome_code": "new-information",
            "information_gain": 1,
            "observed_signals": ["execution"],
            "missing_observations": [],
            "falsifier_codes": [],
            "reason_codes": ["new-observation", "verification-summary"],
        }
    return {
        "outcome_code": "no-new-information",
        "information_gain": 0,
        "observed_signals": ["execution"],
        "missing_observations": [],
        "falsifier_codes": [],
        "reason_codes": ["no-information-gain", "verification-summary"],
    }


def _feedback_observation(feedback: Mapping[str, Any]) -> Dict[str, Any]:
    status = _code(feedback.get("observation_status"), OBSERVATION_STATUSES,
                   "unobserved")
    gain = _int(feedback.get("information_gain"), 0, 0, 5)
    signals = _bounded(feedback.get("new_signals") or
                       feedback.get("observed_signals"),
                       OBSERVATION_SIGNALS, MAX_SIGNALS, 48)
    falsifiers = _bounded(feedback.get("falsifier_codes"), limit=MAX_CODES,
                          item_limit=64)
    reasons = ["strategy-feedback"]
    if status == "environment-gap":
        outcome = "environment-gap"
        reasons.append("environment-gap")
        if "environment-gap" not in signals:
            signals.append("environment-gap")
    elif status == "falsifier-observed" or falsifiers:
        outcome = "falsifier-observed"
        reasons.append("falsifier-observed")
    elif gain or signals:
        outcome = "new-information"
        reasons.append("new-observation")
    else:
        outcome = "no-new-information"
        reasons.append("no-information-gain")
    return {
        "outcome_code": outcome,
        "information_gain": gain,
        "observed_signals": sorted(set(signals))[:MAX_SIGNALS],
        "missing_observations": _bounded(
            feedback.get("missing_observations"), limit=MAX_CODES,
            item_limit=96),
        "falsifier_codes": falsifiers,
        "reason_codes": sorted(set(reasons)),
        "observation_status": status,
        "execution_states": _bounded(feedback.get("execution_states"),
                                      EXECUTION_STATES, MAX_CODES, 64),
    }


def _summary(entries: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    counts = Counter(_text(item.get("outcome_code"), 40) for item in entries)
    selected = [item for item in entries
                if item.get("selection_status") == "selected"]
    productive = [item for item in selected if item.get("outcome_code") in {
        "new-information", "falsifier-observed"}]
    return {
        "entry_count": len(entries),
        "selected_count": len(selected),
        "scheduled_count": sum(bool(item.get("scheduled")) for item in entries),
        "executed_count": sum(bool(item.get("executed")) for item in entries),
        "new_information_count": counts.get("new-information", 0),
        "falsifier_observed_count": counts.get("falsifier-observed", 0),
        "no_new_information_count": counts.get("no-new-information", 0),
        "environment_gap_count": counts.get("environment-gap", 0),
        "not_executed_count": counts.get("not-executed", 0),
        "not_selected_count": counts.get("not-selected", 0),
        "productive_selected_count": len(productive),
        "selected_yield": (round(float(len(productive)) / len(selected), 4)
                            if selected else None),
        "outcome_counts": dict(sorted(counts.items())),
        "claim_status": OUTCOME_CLAIM_STATUS,
    }


def _normalize_history_row(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        return {}
    outcome_id = _text(raw.get("outcome_id"), 80)
    if not _OUTCOME_ID_RE.fullmatch(outcome_id):
        return {}
    outcome_code = _code(raw.get("outcome_code"), OUTCOME_CODES, "")
    if not outcome_code:
        return {}
    return {
        "outcome_id": outcome_id,
        "round": _int(raw.get("round"), 0, 0, MAX_ROUNDS),
        "agenda_id": _text(raw.get("agenda_id"), 80),
        "strategy_id": _text(raw.get("strategy_id"), 80),
        "research_key": _text(raw.get("research_key"), 80),
        "candidate_id": _text(raw.get("candidate_id"), 120),
        "outcome_code": outcome_code,
        "information_gain": _int(raw.get("information_gain"), 0, 0, 5),
        "observed_signals": _bounded(raw.get("observed_signals"),
                                      OBSERVATION_SIGNALS, MAX_SIGNALS, 48),
        "claim_status": OUTCOME_CLAIM_STATUS,
    }


def _normalize_entry(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        return {}
    outcome_id = _text(raw.get("outcome_id"), 80)
    if not _OUTCOME_ID_RE.fullmatch(outcome_id):
        return {}
    outcome_code = _code(raw.get("outcome_code"), OUTCOME_CODES, "")
    schedule_status = _code(raw.get("schedule_status"), SCHEDULE_STATUSES,
                            "unknown")
    if not outcome_code:
        return {}
    return {
        "outcome_id": outcome_id,
        "round": _int(raw.get("round"), 0, 0, MAX_ROUNDS),
        "agenda_id": _text(raw.get("agenda_id"), 80),
        "strategy_id": _text(raw.get("strategy_id"), 80),
        "research_key": _text(raw.get("research_key"), 80),
        "candidate_id": _text(raw.get("candidate_id"), 120),
        "selection_status": _code(raw.get("selection_status"),
                                   {"selected", "deferred", "hold"},
                                   "deferred"),
        "schedule_status": schedule_status,
        "scheduled": bool(raw.get("scheduled")),
        "executed": bool(raw.get("executed")),
        "environment_gap": bool(raw.get("environment_gap")),
        "outcome_code": outcome_code,
        "information_gain": _int(raw.get("information_gain"), 0, 0, 5),
        "observed_signals": _bounded(raw.get("observed_signals"),
                                      OBSERVATION_SIGNALS, MAX_SIGNALS, 48),
        "missing_observations": _bounded(
            raw.get("missing_observations"), limit=MAX_CODES, item_limit=96),
        "falsifier_codes": _bounded(
            raw.get("falsifier_codes"), limit=MAX_CODES, item_limit=64),
        "reason_codes": _bounded(raw.get("reason_codes"), REASON_CODES,
                                  MAX_CODES, 64),
        "execution_state": _code(raw.get("execution_state"), EXECUTION_STATES,
                                  ""),
        "cells_ran": _int(raw.get("cells_ran"), 0, 0, 128),
        "fixture_count": _int(raw.get("fixture_count"), 0, 0, 128),
        "prior_outcome_code": _code(raw.get("prior_outcome_code"),
                                     OUTCOME_CODES, ""),
        "consecutive_no_information": _int(
            raw.get("consecutive_no_information"), 0, 0, 32),
        "claim_status": OUTCOME_CLAIM_STATUS,
    }


def _empty(target: str = "", round_no: int = 0) -> Dict[str, Any]:
    return {
        "schema_version": OUTCOME_SCHEMA_VERSION,
        "agenda_schema_version": AGENDA_SCHEMA_VERSION,
        "target": _text(target, 120),
        "round": _int(round_no, 0, 0, MAX_ROUNDS),
        "schedule_available": False,
        "summary": _summary([]),
        "entries": [],
        "history": [],
        "provenance": {
            "producer": "research-agenda-outcomes",
            "evidence_type": "bounded-agenda-execution-feedback",
            "claim_status": OUTCOME_CLAIM_STATUS,
        },
        "claim_status": OUTCOME_CLAIM_STATUS,
    }


def build_research_agenda_outcomes(
        agenda: Optional[Mapping[str, Any]],
        schedule: Optional[Mapping[str, Any]] = None,
        verification: Optional[Mapping[str, Any]] = None,
        runtime_lab: Optional[Mapping[str, Any]] = None,
        strategy_feedback: Optional[Mapping[str, Any]] = None,
        prior_outcomes: Optional[Mapping[str, Any]] = None,
        target: str = "",
        round_no: int = 0,
        ) -> Dict[str, Any]:
    """Join one agenda with schedule and actual bounded execution feedback."""
    normalized_agenda = normalize_research_agenda(agenda or {})
    if not normalized_agenda:
        return _empty(target, round_no)
    schedule_value = _mapping(schedule)
    verification_value = _mapping(verification)
    runtime_value = _mapping(runtime_lab)
    feedback_index = _feedback_index(_mapping(strategy_feedback))
    schedule_index = _schedule_index(schedule_value)
    prior = normalize_research_agenda_outcomes(prior_outcomes or {})
    prior_by_key: Dict[str, Mapping[str, Any]] = {}
    for row in (prior.get("entries") or []) + (prior.get("history") or []):
        if not isinstance(row, Mapping):
            continue
        for key in (_text(row.get("agenda_id"), 80),
                    _text(row.get("strategy_id"), 80),
                    _text(row.get("research_key"), 80),
                    _text(row.get("candidate_id"), 120)):
            if key:
                previous = prior_by_key.get(key)
                if previous is None or _int(row.get("round"), 0) >= _int(
                        previous.get("round"), 0):
                    prior_by_key[key] = row

    entries: List[Dict[str, Any]] = []
    for raw_item in normalized_agenda.get("items") or []:
        if not isinstance(raw_item, Mapping):
            continue
        item = dict(raw_item)
        selection_status = _code(item.get("selection_status"),
                                 {"selected", "deferred", "hold"},
                                 "deferred")
        schedule_status = _schedule_for(item, schedule_index)
        previous = None
        for key in (_text(item.get("agenda_id"), 80),
                    _text(item.get("strategy_id"), 80),
                    _text(item.get("research_key"), 80),
                    _text(item.get("candidate_id"), 120)):
            if key and key in prior_by_key:
                previous = prior_by_key[key]
                break
        prior_code = _code((previous or {}).get("outcome_code"),
                           OUTCOME_CODES, "")
        consecutive_no_info = _int(
            (previous or {}).get("consecutive_no_information"), 0, 0, 32)
        if selection_status != "selected":
            observation = {
                "outcome_code": "not-selected",
                "information_gain": 0,
                "observed_signals": [],
                "missing_observations": [],
                "falsifier_codes": [],
                "reason_codes": ["agenda-deferred"],
            }
            if selection_status == "hold":
                observation["reason_codes"] = ["agenda-deferred"]
        elif not schedule_index.get("available"):
            observation = {
                "outcome_code": "not-executed",
                "information_gain": 0,
                "observed_signals": [],
                "missing_observations": [],
                "falsifier_codes": [],
                "reason_codes": ["schedule-missing", "not-executed"],
            }
        elif schedule_status != "selected":
            observation = {
                "outcome_code": "not-executed",
                "information_gain": 0,
                "observed_signals": [],
                "missing_observations": [],
                "falsifier_codes": [],
                "reason_codes": ["candidate-not-scheduled", "not-executed"],
            }
        else:
            feedback = _feedback_for(item, feedback_index)
            if feedback:
                observation = _feedback_observation(feedback)
            else:
                execution = _execution_view(
                    _text(item.get("candidate_id"), 120),
                    verification_value, runtime_value)
                observation = _fallback_observation(item, execution)
                observation.update({
                    "execution_state": execution.get("execution_state", ""),
                    "cells_ran": execution.get("cells_ran", 0),
                    "fixture_count": execution.get("fixture_count", 0),
                    "environment_gap": execution.get("environment_gap", False),
                })
        outcome_code = _code(observation.get("outcome_code"), OUTCOME_CODES,
                             "not-executed")
        if outcome_code == "no-new-information":
            consecutive_no_info = min(32, consecutive_no_info + 1)
        else:
            consecutive_no_info = 0
        outcome_id = _stable_id(
            normalized_agenda.get("target"), round_no,
            item.get("agenda_id"), item.get("strategy_id"),
            item.get("research_key"))
        entry = {
            "outcome_id": outcome_id,
            "round": _int(round_no, 0, 0, MAX_ROUNDS),
            "agenda_id": _text(item.get("agenda_id"), 80),
            "strategy_id": _text(item.get("strategy_id"), 80),
            "research_key": _text(item.get("research_key"), 80),
            "candidate_id": _text(item.get("candidate_id"), 120),
            "selection_status": selection_status,
            "schedule_status": schedule_status,
            "scheduled": schedule_status == "selected",
            "executed": bool(observation.get("outcome_code") in {
                "new-information", "falsifier-observed",
                "no-new-information", "environment-gap",
            }),
            "environment_gap": bool(observation.get("environment_gap")
                                     or outcome_code == "environment-gap"),
            "outcome_code": outcome_code,
            "information_gain": _int(observation.get("information_gain"), 0, 0, 5),
            "observed_signals": _bounded(
                observation.get("observed_signals"), OBSERVATION_SIGNALS,
                MAX_SIGNALS, 48),
            "missing_observations": _bounded(
                observation.get("missing_observations"), limit=MAX_CODES,
                item_limit=96),
            "falsifier_codes": _bounded(
                observation.get("falsifier_codes"), limit=MAX_CODES,
                item_limit=64),
            "reason_codes": _bounded(
                observation.get("reason_codes"), REASON_CODES, MAX_CODES, 64),
            "execution_state": _code(
                observation.get("execution_state"), EXECUTION_STATES, ""),
            "cells_ran": _int(observation.get("cells_ran"), 0, 0, 128),
            "fixture_count": _int(observation.get("fixture_count"), 0, 0, 128),
            "prior_outcome_code": prior_code,
            "consecutive_no_information": consecutive_no_info,
            "claim_status": OUTCOME_CLAIM_STATUS,
        }
        entries.append(entry)
        if len(entries) >= MAX_ENTRIES:
            break

    entries.sort(key=lambda row: (
        0 if row.get("selection_status") == "selected" else 1,
        _int(row.get("round"), 0),
        _text(row.get("agenda_id"), 80),
    ))
    current_history = [
        {
            "outcome_id": row["outcome_id"],
            "round": row["round"],
            "agenda_id": row["agenda_id"],
            "strategy_id": row["strategy_id"],
            "research_key": row["research_key"],
            "candidate_id": row["candidate_id"],
            "outcome_code": row["outcome_code"],
            "information_gain": row["information_gain"],
            "observed_signals": row["observed_signals"],
            "claim_status": OUTCOME_CLAIM_STATUS,
        }
        for row in entries
    ]
    prior_history = []
    if isinstance(prior.get("history"), list):
        prior_history = [
            _normalize_history_row(row) for row in prior.get("history")
        ]
        prior_history = [row for row in prior_history if row]
    history_by_id = {row["outcome_id"]: row for row in prior_history}
    for row in current_history:
        history_by_id[row["outcome_id"]] = row
    history = sorted(history_by_id.values(), key=lambda row: (
        _int(row.get("round"), 0), _text(row.get("outcome_id"), 80)))
    history = history[-MAX_HISTORY:]
    result = _empty(
        target or normalized_agenda.get("target", ""),
        round_no or normalized_agenda.get("round", 0))
    result["schedule_available"] = bool(schedule_index.get("available"))
    result["entries"] = entries
    result["history"] = history
    result["summary"] = _summary(entries)
    result["provenance"].update({
        "agenda_present": True,
        "schedule_present": bool(schedule_value),
        "verification_present": bool(verification_value),
        "runtime_lab_present": bool(runtime_value),
        "strategy_feedback_present": bool(_mapping(strategy_feedback)),
    })
    return result


def normalize_research_agenda_outcomes(raw: Any) -> Dict[str, Any]:
    """Normalize outcomes and recompute summary/history from allowlists."""
    if not isinstance(raw, Mapping) or \
            raw.get("schema_version") != OUTCOME_SCHEMA_VERSION:
        return {}
    result = _empty(
        raw.get("target", ""),
        _int(raw.get("round"), 0, 0, MAX_ROUNDS))
    result["schedule_available"] = bool(raw.get("schedule_available"))
    entries: List[Dict[str, Any]] = []
    seen = set()
    for row in raw.get("entries") or []:
        item = _normalize_entry(row)
        if not item or item["outcome_id"] in seen:
            continue
        seen.add(item["outcome_id"])
        entries.append(item)
        if len(entries) >= MAX_ENTRIES:
            break
    entries.sort(key=lambda row: (
        0 if row.get("selection_status") == "selected" else 1,
        _int(row.get("round"), 0), _text(row.get("agenda_id"), 80)))
    history: List[Dict[str, Any]] = []
    seen_history = set()
    for row in raw.get("history") or []:
        item = _normalize_history_row(row)
        if not item or item["outcome_id"] in seen_history:
            continue
        seen_history.add(item["outcome_id"])
        history.append(item)
        if len(history) >= MAX_HISTORY:
            break
    history.sort(key=lambda row: (_int(row.get("round"), 0), row["outcome_id"]))
    result["entries"] = entries
    result["history"] = history[-MAX_HISTORY:]
    result["summary"] = _summary(entries)
    provenance = raw.get("provenance")
    provenance = provenance if isinstance(provenance, Mapping) else {}
    result["provenance"].update({
        key: bool(provenance.get(key))
        for key in ("agenda_present", "schedule_present",
                    "verification_present", "runtime_lab_present",
                    "strategy_feedback_present")
        if key in provenance
    })
    return result


def outcomes_path(workspace: Path, target: str) -> Path:
    return (Path(workspace).resolve() / "state" / str(target) /
            "coverage" / OUTCOME_FILENAME)


def write_research_agenda_outcomes(workspace: Path, target: str,
                                   outcomes: Mapping[str, Any]) -> Path:
    path = outcomes_path(workspace, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = normalize_research_agenda_outcomes(outcomes) or _empty(target)
    temporary = path.with_name(".%s.tmp.%d" % (path.name, os.getpid()))
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                         encoding="utf-8")
    temporary.replace(path)
    return path


def load_research_agenda_outcomes(workspace: Path, target: str
                                  ) -> Dict[str, Any]:
    path = outcomes_path(workspace, target)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError):
        return {}
    return normalize_research_agenda_outcomes(raw)


def load_schedule_snapshot(workspace: Path, target: str, round_no: int = 0
                           ) -> Dict[str, Any]:
    """Load the target-level scheduler snapshot used by either pipeline."""
    base = Path(workspace).resolve() / "state" / str(target) / "coverage"
    name = ("schedule-round-%02d.json" % int(round_no)
            if int(round_no or 0) > 0 else "schedule-latest.json")
    try:
        raw = json.loads((base / name).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def load_round_artifact(workspace: Path, target: str, round_no: int,
                        stage: str, name: str) -> Dict[str, Any]:
    path = (Path(workspace).resolve() / "state" / str(target) /
            ("round-%02d" % int(round_no)) / str(stage) / str(name))
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError):
        return {}
    return raw if isinstance(raw, dict) else {}
