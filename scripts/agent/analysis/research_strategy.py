"""Bounded, evidence-driven research strategy synthesis.

The coverage inventory, attacker-path model, research memory, and project
portfolio each answer a different expert question.  This module joins their
safe metadata into one replayable research agenda:

* which attack path or residual should be closed next;
* which observations are still required; and
* what observation would falsify the current hypothesis.

It is deliberately a strategy artifact, not a finding artifact.  It never
copies source prose, payloads, commands, process output, credentials, CVSS or
runtime conclusions.  Every item remains ``claim_status=not-a-finding``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from ..evaluation.benchmark import normalize_benchmark_feedback
from ..tools.redaction import redact_text
from ..memory.portfolio import normalize_research_portfolio
from .threat_model import normalize_threat_model


STRATEGY_SCHEMA_VERSION = "research-strategy-v1"
STRATEGY_FILENAME = "research-strategy.json"
STRATEGY_CLAIM_STATUS = "not-a-finding"

MAX_STRATEGY_ITEMS = 48
MAX_REASON_CODES = 6
MAX_IDS = 16
MAX_TEXT = 160

STRATEGY_KINDS = frozenset({
    "path-closure",
    "control-closure",
    "capability-closure",
    "reachability-closure",
    "coverage-closure",
    "residual-closure",
    "environment-recovery",
    "portfolio-followup",
})
STRATEGY_STATES = frozenset({
    "pending-static-review",
    "pending-runtime",
    "pending-capability",
    "pending-reachability",
    "pending-coverage",
    "pending-residual",
    "pending-environment",
})
STRATEGY_REASON_CODES = frozenset({
    "threat-path",
    "control-gap",
    "missing-capability",
    "reachability-gap",
    "unmapped-entry",
    "unmapped-sink",
    "s3-residual",
    "environment-gap",
    "actionable-difference",
    "unstable-replay",
    "inconclusive",
    "review-needs-evidence",
    "portfolio-followup",
})
RESIDUAL_KINDS = frozenset({
    "fix-completeness", "variant", "control-gap", "authz", "validation",
    "typed-effect", "capability-chain", "environment-gap", "source-sink",
    "differential", "state", "race", "availability", "parser", "default",
    "unclassified",
})
RESIDUAL_REASON_CODES = frozenset({
    "unverified", "missing-effect", "missing-transition", "fix-gap",
    "control-gap", "environment-gap", "inconclusive", "requires-runtime",
    "needs-source-review", "pending", "unclassified",
})
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

_STRATEGY_ID = re.compile(r"^rs-[0-9a-f]{20}$")

_OBJECTIVES = {
    "path-closure": "close the attacker path with independent source-to-sink and typed runtime evidence",
    "control-closure": "verify control ordering, subject/object binding, and the negative authorization baseline",
    "capability-closure": "verify each capability transition independently and observe the typed terminal effect",
    "reachability-closure": "resolve entry exposure, dynamic dispatch, registration, and default-configuration reachability",
    "coverage-closure": "turn the unmapped entry or sink into a citable, falsifiable research cell",
    "residual-closure": "close the S3 residual with its declared bounded probe and an explicit falsifier",
    "environment-recovery": "repair the environment gap and repeat the blocked comparison without treating it as negative evidence",
    "portfolio-followup": "retest the pending project-level research probe with independent evidence",
}

_OBSERVATIONS = {
    "path-closure": [
        "default-config-exposure",
        "typed-source-sink-flow",
        "control-ordering-and-binding",
        "typed-effect-or-safe-equivalent",
    ],
    "control-closure": [
        "default-config-exposure",
        "control-ordering-and-binding",
        "negative-unauthorized-baseline",
        "typed-effect-or-safe-equivalent",
    ],
    "capability-closure": [
        "default-config-exposure",
        "capability-transition",
        "typed-effect-or-safe-equivalent",
        "negative-baseline",
    ],
    "reachability-closure": [
        "dynamic-dispatch-or-registration",
        "default-config-exposure",
        "typed-source-sink-flow",
        "negative-unreachable-control",
    ],
    "coverage-closure": [
        "entry-or-sink-mapping",
        "default-config-exposure",
        "typed-source-sink-flow",
        "explicit-negative-observation",
    ],
    "residual-closure": [
        "declared-residual-probe",
        "explicit-falsifier",
        "negative-or-safe-observation",
    ],
    "environment-recovery": [
        "runtime-availability",
        "replay-after-remediation",
        "negative-or-safe-observation",
    ],
    "portfolio-followup": [
        "independent-reproduction",
        "required-evidence-fields",
        "explicit-falsifier",
    ],
}

_FALSIFIERS = {
    "path-closure": [
        "default configuration does not expose the entry",
        "independent source-to-sink review disproves the path",
        "the declared typed effect is not observed in a bounded cell",
    ],
    "control-closure": [
        "the control executes before the sink and binds the correct subject/object",
        "the unauthorized negative baseline is rejected without the claimed effect",
        "the static path is not present under the target default configuration",
    ],
    "capability-closure": [
        "a required capability transition cannot be observed",
        "the terminal typed effect is absent or safe-equivalent",
        "the input cannot reach the capability chain under the declared preconditions",
    ],
    "reachability-closure": [
        "registration or dynamic dispatch cannot be reached from the authorized input",
        "default configuration disables the entry or sink path",
        "the source-to-sink relation is disproved by source review",
    ],
    "coverage-closure": [
        "the region is outside the authorized source or runtime scope",
        "the mapping cannot be reproduced from the persisted index",
        "the required negative observation is recorded without the claimed effect",
    ],
    "residual-closure": [
        "the declared residual probe produces a bounded safe or negative observation",
        "the residual precondition is unavailable and remains explicitly pending",
        "the source review disproves the residual variant",
    ],
    "environment-recovery": [
        "the required runtime or harness remains unavailable",
        "the remediated replay is still non-comparable",
        "a comparable replay records a bounded negative or safe observation",
    ],
    "portfolio-followup": [
        "the independent reproduction does not satisfy the required observation",
        "the explicit falsifier is observed",
        "the environment gap persists and is retained as pending",
    ],
}


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    if value is None:
        return ""
    try:
        value = redact_text(value)
    except Exception:  # pragma: no cover - defensive redaction boundary
        value = str(value)
    return " ".join(str(value).replace("\x00", "").split())[:limit]


def _int(value: Any, default: int = 0, minimum: int = 0,
         maximum: int = 5) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _bounded(values: Any, limit: int = MAX_IDS,
             item_limit: int = MAX_TEXT) -> List[str]:
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


def _code(value: Any, allowed: Iterable[str], fallback: str) -> str:
    text = _text(value, 80).lower()
    allowed = set(allowed)
    return text if text in allowed else fallback


def _stable_id(*parts: Any) -> str:
    material = "\x1f".join(_text(part, 240) for part in parts)
    return "rs-" + hashlib.sha1(material.encode("utf-8", errors="replace")).hexdigest()[:20]


def _surface(target_type: Any) -> str:
    value = _text(target_type, 80).lower()
    return TARGET_TYPE_TO_SURFACE.get(value, value if value in RESEARCH_SURFACES else "")


def _safe_state_for_kind(kind: str) -> str:
    return {
        "path-closure": "pending-runtime",
        "control-closure": "pending-runtime",
        "capability-closure": "pending-capability",
        "reachability-closure": "pending-reachability",
        "coverage-closure": "pending-coverage",
        "residual-closure": "pending-residual",
        "environment-recovery": "pending-environment",
        "portfolio-followup": "pending-runtime",
    }.get(kind, "pending-runtime")


def _item_template(kind: str, identity: Any, target: str,
                   priority: Any = 1) -> Dict[str, Any]:
    kind = _code(kind, STRATEGY_KINDS, "portfolio-followup")
    return {
        "strategy_id": _stable_id(target, kind, identity),
        "kind": kind,
        "state": _safe_state_for_kind(kind),
        "priority": _int(priority, 1),
        "objective": _OBJECTIVES[kind],
        "required_observations": list(_OBSERVATIONS[kind]),
        "falsifiers": list(_FALSIFIERS[kind]),
        "reason_codes": [],
        "claim_status": STRATEGY_CLAIM_STATUS,
    }


def _path_kind(path: Mapping[str, Any]) -> str:
    if _text(path.get("coverage_gap"), 80):
        return "reachability-closure"
    hypotheses = [item for item in path.get("capability_hypotheses") or []
                  if isinstance(item, Mapping)]
    if any(item.get("missing_capabilities") for item in hypotheses):
        return "capability-closure"
    if _text(path.get("control_posture"), 32) in {
            "partial", "uncontrolled", "unmapped"}:
        return "control-closure"
    return "path-closure"


def _path_priority(path: Mapping[str, Any]) -> int:
    priority = _int(path.get("research_priority"), 1)
    if _text(path.get("coverage_gap"), 80):
        priority += 1
    if _text(path.get("control_posture"), 32) in {
            "partial", "uncontrolled", "unmapped"}:
        priority += 1
    if any(isinstance(item, Mapping) and item.get("missing_capabilities")
           for item in path.get("capability_hypotheses") or []):
        priority += 1
    return min(5, max(1, priority))


def _add_path_item(items: List[Dict[str, Any]], path: Mapping[str, Any],
                   target: str, target_type: str) -> None:
    path_id = _text(path.get("path_id"), 160)
    flow_id = _text(path.get("flow_id"), 160)
    entry_id = _text(path.get("entry_id"), 160)
    sink_id = _text(path.get("sink_id"), 160)
    identity = path_id or "|".join((flow_id, entry_id, sink_id))
    if not identity:
        return
    kind = _path_kind(path)
    item = _item_template(kind, identity, target, _path_priority(path))
    item.update({
        "path_id": path_id,
        "flow_id": flow_id,
        "entry_id": entry_id,
        "sink_id": sink_id,
        "boundary_id": _text(path.get("boundary_id"), 160),
        "sink_category": _text(path.get("sink_category"), 64),
        "control_posture": _code(
            path.get("control_posture"),
            {"guarded", "partial", "uncontrolled", "not-applicable", "unmapped"},
            "unmapped"),
        "target_type": _code(target_type, TARGET_TYPES, ""),
        "research_surface": _surface(target_type),
        "capability_candidate_ids": sorted({
            _text(hypothesis.get("candidate_id"), 160)
            for hypothesis in path.get("capability_hypotheses") or []
            if isinstance(hypothesis, Mapping) and hypothesis.get("candidate_id")
        })[:8],
    })
    reasons = ["threat-path"]
    if _text(path.get("coverage_gap"), 80):
        reasons.append("reachability-gap")
    if item["control_posture"] in {"partial", "uncontrolled", "unmapped"}:
        reasons.append("control-gap")
    if item["capability_candidate_ids"] and any(
            isinstance(hypothesis, Mapping) and hypothesis.get("missing_capabilities")
            for hypothesis in path.get("capability_hypotheses") or []):
        reasons.append("missing-capability")
    item["reason_codes"] = reasons[:MAX_REASON_CODES]
    observations = list(_OBSERVATIONS[kind])
    if item["capability_candidate_ids"] and any(
            isinstance(hypothesis, Mapping) and hypothesis.get("missing_capabilities")
            for hypothesis in path.get("capability_hypotheses") or []):
        observations.append("capability-transition")
    if item["control_posture"] in {"partial", "uncontrolled", "unmapped"}:
        observations.append("control-ordering-and-binding")
    if _text(path.get("coverage_gap"), 80):
        observations.append("dynamic-dispatch-or-registration")
    item["required_observations"] = list(dict.fromkeys(observations))[:6]
    items.append(item)


def _add_coverage_item(items: List[Dict[str, Any]], row: Mapping[str, Any],
                       target: str, target_type: str, kind: str,
                       reason: str) -> None:
    ref = _text(row.get("entry_id") or row.get("sink_id"), 160)
    if not ref:
        return
    item = _item_template(kind, "%s:%s" % (reason, ref), target, 4)
    item.update({
        "entry_id": _text(row.get("entry_id"), 160),
        "sink_id": _text(row.get("sink_id"), 160),
        "target_type": _code(target_type, TARGET_TYPES, ""),
        "research_surface": _surface(target_type),
        "reason_codes": [reason],
    })
    items.append(item)


def _add_portfolio_item(items: List[Dict[str, Any]], probe: Mapping[str, Any],
                        target: str) -> None:
    state = _text(probe.get("state"), 64)
    if state == "pending-residual":
        kind = "residual-closure"
        reason_codes = ["s3-residual"]
        priority = max(4, _int(probe.get("priority"), 4))
    elif state in {"environment-gap", "pending-environment"}:
        kind = "environment-recovery"
        reason_codes = ["environment-gap"]
        priority = max(4, _int(probe.get("priority"), 4))
    else:
        kind = "portfolio-followup"
        raw_reason = _code(
            probe.get("reason_code"),
            {"actionable-difference", "unstable-replay", "inconclusive",
             "review-needs-evidence"}, "portfolio-followup")
        reason_codes = [raw_reason]
        priority = _int(probe.get("priority"), 2)
    key = _text(probe.get("research_key"), 80)
    residual_id = _text(probe.get("residual_id"), 80)
    identity = residual_id or key or _text(probe.get("candidate_id"), 120)
    if not identity:
        return
    item = _item_template(kind, identity, target, priority)
    item.update({
        "research_key": key,
        "candidate_id": _text(probe.get("candidate_id"), 120),
        "residual_id": residual_id,
        "residual_kind": _code(probe.get("residual_kind"),
                                RESIDUAL_KINDS, "unclassified"),
        "residual_reason_code": _code(
            probe.get("residual_reason_code"), RESIDUAL_REASON_CODES,
            "unclassified"),
        "research_surface": _surface(probe.get("research_surface")),
        "target_type": _code(probe.get("target_type"), TARGET_TYPES, ""),
        "attack_class": _text(probe.get("attack_class"), 80).lower(),
        "variant": _bounded(probe.get("variant"), 4, 100),
        "precondition_class": _text(probe.get("precondition_class"), 60).lower(),
        "reason_codes": reason_codes,
    })
    items.append(item)


def _latest_memory_state(entry: Mapping[str, Any]) -> str:
    events = [event for event in entry.get("events") or []
              if isinstance(event, Mapping) and event.get("state")]
    if not events:
        return ""
    events.sort(key=lambda event: (
        _int(event.get("round"), 0, 0, 1000000),
        _text(event.get("event_id"), 80),
    ))
    return _text(events[-1].get("state"), 64)


def _add_memory_fallback(items: List[Dict[str, Any]], entry: Mapping[str, Any],
                         target: str) -> None:
    state = _latest_memory_state(entry)
    key = _text(entry.get("research_key"), 80)
    if not key or state not in {
            "environment-gap", "unstable-replay", "inconclusive",
            "actionable-difference", "review-needs-evidence"}:
        return
    if state == "environment-gap":
        kind = "environment-recovery"
        reason = "environment-gap"
        priority = 4
    else:
        kind = "portfolio-followup"
        reason = {
            "actionable-difference": "actionable-difference",
            "unstable-replay": "unstable-replay",
            "inconclusive": "inconclusive",
            "review-needs-evidence": "review-needs-evidence",
        }.get(state, "portfolio-followup")
        priority = 4 if state in {"actionable-difference", "review-needs-evidence"} else 3
    item = _item_template(kind, key, target, priority)
    item.update({
        "research_key": key,
        "candidate_id": _text(entry.get("candidate_id"), 120),
        "research_surface": _surface(entry.get("research_surface")),
        "target_type": _code(entry.get("target_type"), TARGET_TYPES, ""),
        "attack_class": _text(entry.get("attack_class"), 80).lower(),
        "variant": _bounded(entry.get("variants") or [entry.get("variant")], 4, 100),
        "precondition_class": _text(entry.get("precondition_class"), 60).lower(),
        "reason_codes": [reason],
    })
    items.append(item)


def _benchmark_context(portfolio: Mapping[str, Any],
                       benchmark_feedback: Optional[Dict[str, Any]] = None
                       ) -> Dict[str, Any]:
    feedback = normalize_benchmark_feedback(benchmark_feedback or {})
    if feedback:
        trend = feedback.get("trend") if isinstance(
            feedback.get("trend"), Mapping) else {}
        return {
            "benchmark_id": _text(feedback.get("benchmark_id"), 120),
            "alert_codes": sorted({
                _text(item.get("code"), 80)
                for item in feedback.get("alerts") or []
                if isinstance(item, Mapping) and item.get("code")
            })[:12],
            "trend_status": _text(trend.get("status"), 24),
            "regressed_surfaces": [surface for surface in _bounded(
                trend.get("regressed_surfaces"), 8, 32)
                if surface in RESEARCH_SURFACES],
            "claim_status": STRATEGY_CLAIM_STATUS,
        }
    benchmark = portfolio.get("benchmark")
    if not isinstance(benchmark, Mapping) or not benchmark:
        return {}
    trend = benchmark.get("trend") if isinstance(benchmark.get("trend"), Mapping) else {}
    return {
        "benchmark_id": _text(benchmark.get("benchmark_id"), 120),
        "alert_codes": _bounded(benchmark.get("alert_codes"), 12, 80),
        "trend_status": _text(trend.get("status"), 24),
        "regressed_surfaces": [surface for surface in _bounded(
            trend.get("regressed_surfaces"), 8, 32)
            if surface in RESEARCH_SURFACES],
        "claim_status": STRATEGY_CLAIM_STATUS,
    }


def _summary(items: Sequence[Mapping[str, Any]], path_count: int,
             unresolved_count: int) -> Dict[str, Any]:
    kinds = Counter(_text(item.get("kind"), 64) for item in items)
    states = Counter(_text(item.get("state"), 64) for item in items)
    return {
        "item_count": len(items),
        "path_count": path_count,
        "unresolved_count": unresolved_count,
        "pending_residuals": sum(
            1 for item in items if item.get("kind") == "residual-closure"),
        "environment_recovery": sum(
            1 for item in items if item.get("kind") == "environment-recovery"),
        "by_kind": dict(sorted(kinds.items())),
        "by_state": dict(sorted(states.items())),
        "claim_status": STRATEGY_CLAIM_STATUS,
    }


def build_research_strategy(
        threat_model: Optional[Dict[str, Any]] = None,
        research_portfolio: Optional[Dict[str, Any]] = None,
        research_memory: Optional[Sequence[Dict[str, Any]]] = None,
        benchmark_feedback: Optional[Dict[str, Any]] = None,
        target: str = "",
        target_type: str = "",
        round_no: int = 0,
        ) -> Dict[str, Any]:
    """Join bounded research artifacts into a deterministic agenda."""
    model = normalize_threat_model(threat_model or {})
    portfolio = normalize_research_portfolio(research_portfolio or {})
    target = _text(target, 120)
    target_type = _code(
        target_type or model.get("target_type"), TARGET_TYPES, "")
    items: List[Dict[str, Any]] = []
    paths = [row for row in model.get("attack_paths") or []
             if isinstance(row, Mapping)]
    paths.sort(key=lambda row: (
        -_int(row.get("research_priority"), 1),
        _text(row.get("path_id"), 160),
    ))
    for path in paths[:MAX_STRATEGY_ITEMS]:
        _add_path_item(items, path, target, target_type)

    unresolved = model.get("unresolved") if isinstance(model.get("unresolved"), Mapping) else {}
    unresolved_entries = [row for row in unresolved.get("unmapped_entries") or []
                          if isinstance(row, Mapping)]
    unresolved_sinks = [row for row in unresolved.get("unmapped_sinks") or []
                        if isinstance(row, Mapping)]
    for row in unresolved_entries[:MAX_STRATEGY_ITEMS]:
        _add_coverage_item(items, row, target, target_type,
                           "reachability-closure", "unmapped-entry")
    for row in unresolved_sinks[:MAX_STRATEGY_ITEMS]:
        _add_coverage_item(items, row, target, target_type,
                           "coverage-closure", "unmapped-sink")

    portfolio_probes = [row for row in portfolio.get("next_probes") or []
                        if isinstance(row, Mapping)]
    for probe in portfolio_probes:
        _add_portfolio_item(items, probe, target)

    portfolio_keys = {
        _text(item.get("research_key"), 80)
        for item in items if item.get("research_key")
    }
    memory_entries = [entry for entry in (research_memory or [])
                      if isinstance(entry, Mapping)]
    for entry in memory_entries:
        key = _text(entry.get("research_key"), 80)
        if key and key not in portfolio_keys:
            _add_memory_fallback(items, entry, target)

    # Residuals are allowed to survive even if portfolio data was truncated or
    # an older portfolio artifact was loaded.  Add only the missing residual
    # identities; normal portfolio output normally makes this a no-op.
    known_residuals = {
        _text(item.get("residual_id"), 80)
        for item in items if item.get("residual_id")
    }
    for entry in memory_entries:
        for residual in entry.get("residuals") or []:
            if not isinstance(residual, Mapping):
                continue
            residual_id = _text(residual.get("residual_id"), 80)
            if not residual_id or residual_id in known_residuals:
                continue
            _add_portfolio_item(items, {
                "state": "pending-residual",
                "research_key": entry.get("research_key"),
                "candidate_id": entry.get("candidate_id"),
                "residual_id": residual_id,
                "residual_kind": residual.get("kind"),
                "residual_reason_code": residual.get("reason_code"),
                "research_surface": entry.get("research_surface"),
                "target_type": entry.get("target_type"),
                "attack_class": entry.get("attack_class"),
                "variant": entry.get("variants") or [entry.get("variant")],
                "precondition_class": entry.get("precondition_class"),
                "priority": 4,
            }, target)
            known_residuals.add(residual_id)

    # Normalize and deduplicate by strategy identity before applying the final
    # bound.  Priority sorting keeps the most useful work when a large target
    # has more paths than the prompt budget.
    normalized_items = []
    seen = set()
    for item in items:
        normalized = _normalize_item(item)
        strategy_id = normalized.get("strategy_id")
        if not strategy_id or strategy_id in seen:
            continue
        seen.add(strategy_id)
        normalized_items.append(normalized)
    normalized_items.sort(key=lambda item: (
        -_int(item.get("priority"), 1),
        _text(item.get("kind"), 64),
        _text(item.get("strategy_id"), 80),
    ))
    normalized_items = normalized_items[:MAX_STRATEGY_ITEMS]
    return {
        "schema_version": STRATEGY_SCHEMA_VERSION,
        "target": target,
        "target_type": target_type,
        "round": max(0, _int(round_no, 0, 0, 1000000)),
        "summary": _summary(
            normalized_items, len(paths),
            len(unresolved_entries) + len(unresolved_sinks)),
        "benchmark_context": _benchmark_context(portfolio, benchmark_feedback),
        "items": normalized_items,
        "provenance": {
            "producer": "research-strategy",
            "confidence": "bounded-synthesis",
            "evidence_type": "research-plan",
            "claim_status": STRATEGY_CLAIM_STATUS,
        },
        "claim_status": STRATEGY_CLAIM_STATUS,
    }


def _normalize_item(raw: Mapping[str, Any]) -> Dict[str, Any]:
    kind = _code(raw.get("kind"), STRATEGY_KINDS, "portfolio-followup")
    state = _code(raw.get("state"), STRATEGY_STATES,
                  _safe_state_for_kind(kind))
    identity = (raw.get("path_id") or raw.get("residual_id") or
                raw.get("research_key") or raw.get("candidate_id") or
                raw.get("entry_id") or raw.get("sink_id") or kind)
    strategy_id = _text(raw.get("strategy_id"), 80)
    if not _STRATEGY_ID.fullmatch(strategy_id):
        strategy_id = _stable_id(kind, identity)
    reason_codes = []
    for value in raw.get("reason_codes") or []:
        code = _code(value, STRATEGY_REASON_CODES, "")
        if code and code not in reason_codes:
            reason_codes.append(code)
    if not reason_codes:
        reason_codes = ["portfolio-followup"]
    out = {
        "strategy_id": strategy_id,
        "kind": kind,
        "state": state,
        "priority": _int(raw.get("priority"), 1),
        "objective": _OBJECTIVES[kind],
        "required_observations": list(_OBSERVATIONS[kind]),
        "falsifiers": list(_FALSIFIERS[kind]),
        "reason_codes": reason_codes[:MAX_REASON_CODES],
        "path_id": _text(raw.get("path_id"), 160),
        "flow_id": _text(raw.get("flow_id"), 160),
        "entry_id": _text(raw.get("entry_id"), 160),
        "sink_id": _text(raw.get("sink_id"), 160),
        "boundary_id": _text(raw.get("boundary_id"), 160),
        "research_key": _text(raw.get("research_key"), 80),
        "candidate_id": _text(raw.get("candidate_id"), 120),
        "residual_id": _text(raw.get("residual_id"), 80),
        "residual_kind": _code(raw.get("residual_kind"),
                                RESIDUAL_KINDS, "unclassified"),
        "residual_reason_code": _code(
            raw.get("residual_reason_code"), RESIDUAL_REASON_CODES,
            "unclassified"),
        "research_surface": _surface(raw.get("research_surface")),
        "target_type": _code(raw.get("target_type"), TARGET_TYPES, ""),
        "attack_class": _text(raw.get("attack_class"), 80).lower(),
        "variant": _bounded(raw.get("variant"), 4, 100),
        "precondition_class": _text(raw.get("precondition_class"), 60).lower(),
        "sink_category": _text(raw.get("sink_category"), 64),
        "control_posture": _code(
            raw.get("control_posture"),
            {"guarded", "partial", "uncontrolled", "not-applicable", "unmapped"},
            "unmapped"),
        "capability_candidate_ids": _bounded(
            raw.get("capability_candidate_ids"), 8, 160),
        "claim_status": STRATEGY_CLAIM_STATUS,
    }
    if out["residual_id"] and not re.fullmatch(
            r"rr-[0-9a-f]{20}", out["residual_id"]):
        out["residual_id"] = ""
    # Omit empty optional values so a normalized round-trip stays compact and
    # callers can distinguish a path item from a portfolio item by fields.
    return {key: value for key, value in out.items()
            if value not in ("", [], None) or key in {
                "strategy_id", "kind", "state", "priority", "objective",
                "required_observations", "falsifiers", "reason_codes",
                "claim_status"}}


def normalize_research_strategy(raw: Any) -> Dict[str, Any]:
    """Strip untrusted fields and force a replayable strategy contract."""
    if not isinstance(raw, Mapping) or raw.get("schema_version") != STRATEGY_SCHEMA_VERSION:
        return {}
    items = []
    seen = set()
    for row in raw.get("items") or []:
        if not isinstance(row, Mapping):
            continue
        item = _normalize_item(row)
        if item["strategy_id"] in seen:
            continue
        seen.add(item["strategy_id"])
        items.append(item)
        if len(items) >= MAX_STRATEGY_ITEMS:
            break
    items.sort(key=lambda item: (
        -_int(item.get("priority"), 1),
        _text(item.get("kind"), 64),
        _text(item.get("strategy_id"), 80),
    ))
    target_type = _code(raw.get("target_type"), TARGET_TYPES, "")
    benchmark = raw.get("benchmark_context")
    if not isinstance(benchmark, Mapping):
        benchmark = {}
    benchmark_context = {}
    if benchmark:
        benchmark_context = {
            "benchmark_id": _text(benchmark.get("benchmark_id"), 120),
            "alert_codes": _bounded(benchmark.get("alert_codes"), 12, 80),
            "trend_status": _text(benchmark.get("trend_status"), 24),
            "regressed_surfaces": [surface for surface in _bounded(
                benchmark.get("regressed_surfaces"), 8, 32)
                if surface in RESEARCH_SURFACES],
            "claim_status": STRATEGY_CLAIM_STATUS,
        }
    return {
        "schema_version": STRATEGY_SCHEMA_VERSION,
        "target": _text(raw.get("target"), 120),
        "target_type": target_type,
        "round": _int(raw.get("round"), 0, 0, 1000000),
        "summary": _summary(
            items,
            _int((raw.get("summary") or {}).get("path_count"), 0, 0, 1000000)
            if isinstance(raw.get("summary"), Mapping) else 0,
            _int((raw.get("summary") or {}).get("unresolved_count"), 0, 0, 1000000)
            if isinstance(raw.get("summary"), Mapping) else 0,
        ),
        "benchmark_context": benchmark_context,
        "items": items,
        "provenance": {
            "producer": "research-strategy",
            "confidence": "bounded-synthesis",
            "evidence_type": "research-plan",
            "claim_status": STRATEGY_CLAIM_STATUS,
        },
        "claim_status": STRATEGY_CLAIM_STATUS,
    }


def strategy_path(workspace: Path, target: str) -> Path:
    return Path(workspace).resolve() / "state" / str(target) / "coverage" / STRATEGY_FILENAME


def write_research_strategy(workspace: Path, target: str,
                            strategy: Mapping[str, Any]) -> Path:
    path = strategy_path(workspace, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = normalize_research_strategy(strategy)
    tmp = path.with_name(".%s.tmp.%d" % (path.name, os.getpid()))
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    tmp.replace(path)
    return path


def load_research_strategy(workspace: Path, target: str) -> Dict[str, Any]:
    path = strategy_path(workspace, target)
    if not path.exists():
        return {}
    try:
        return normalize_research_strategy(
            json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {}
