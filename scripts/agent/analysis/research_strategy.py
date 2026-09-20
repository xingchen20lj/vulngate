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
from ..memory.research import research_key, residual_meta
from ..tools.surface_variants import (build_surface_variant_plan,
                                      normalize_surface_variant_plan)
from .threat_model import normalize_threat_model


STRATEGY_SCHEMA_VERSION = "research-strategy-v1"
STRATEGY_FILENAME = "research-strategy.json"
STRATEGY_CLAIM_STATUS = "not-a-finding"
STRATEGY_FEEDBACK_SCHEMA_VERSION = "research-strategy-feedback-v1"
STRATEGY_GUIDANCE_SCHEMA_VERSION = "research-strategy-guidance-v1"
STRATEGY_GUIDANCE_FILENAME = "research-guidance.json"

MAX_STRATEGY_ITEMS = 48
MAX_REASON_CODES = 6
MAX_IDS = 16
MAX_TEXT = 160
MAX_OBSERVATION_SIGNALS = 16
MAX_OBSERVATION_STATES = 8
MAX_OBSERVATION_CANDIDATES = 8
MAX_GUIDANCE_REASON_CODES = 6
MAX_GUIDANCE_VARIANT_GAPS = 8
MAX_GUIDANCE_SOURCES = 4
MAX_ZERO_GAIN_STREAK = 8
DEFAULT_REPLACEMENT_ZERO_GAIN_ROUNDS = 1

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
STRATEGY_OBSERVATION_STATUSES = frozenset({
    "unobserved",
    "execution-only",
    "partial",
    "complete",
    "environment-gap",
    "falsifier-observed",
})
STRATEGY_GUIDANCE_ACTIONS = frozenset({
    "repair-environment",
    "replay-residual-variant",
    "review-followup",
    "reframe-scope",
    "add-negative-control",
    "trace-capability-transition",
    "review-source-dataflow",
    "add-typed-effect",
    "replay-new-variant",
    "continue-path-closure",
    "hold-for-new-evidence",
})
STRATEGY_GUIDANCE_SOURCES = frozenset({
    "strategy-observation",
    "human-review",
    "variant-coverage",
    "project-portfolio",
})
STRATEGY_GUIDANCE_REASON_CODES = frozenset({
    "environment-gap",
    "pending-residual",
    "review-needs-evidence",
    "review-accepted",
    "review-rejected",
    "review-scope-corrected",
    "missing-negative-baseline",
    "missing-typed-effect",
    "missing-capability-transition",
    "missing-source-observation",
    "variant-gap",
    "zero-information-gain",
    "unobserved",
    "partial-observation",
    "complete-observation",
    "falsifier-observed",
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

_OBSERVATION_SIGNALS = frozenset({
    "execution",
    "entry-behavior",
    "authorization",
    "negative-baseline",
    "capability-trace",
    "state-sequence",
    "typed-effect",
    "safe-equivalent",
    "residual-contract",
    "explicit-falsifier",
    "residual-safe",
    "evidence-field",
    "environment-gap",
    "runtime-error",
})

# These are intentionally conservative aliases.  S4 may establish that an
# observation was made, but a missing alias remains missing; absence is never
# promoted into a negative result.
_REQUIRED_SIGNAL_ALIASES = {
    "default-config-exposure": ("entry-behavior",),
    "typed-source-sink-flow": (),
    "control-ordering-and-binding": ("authorization",),
    "negative-unauthorized-baseline": ("negative-baseline",),
    "typed-effect-or-safe-equivalent": ("typed-effect", "safe-equivalent"),
    "capability-transition": ("capability-trace",),
    "negative-baseline": ("negative-baseline", "safe-equivalent"),
    "dynamic-dispatch-or-registration": (),
    "negative-unreachable-control": ("negative-baseline",),
    "entry-or-sink-mapping": (),
    "explicit-negative-observation": ("negative-baseline", "safe-equivalent"),
    "declared-residual-probe": ("residual-contract",),
    "explicit-falsifier": ("explicit-falsifier",),
    "negative-or-safe-observation": (
        "negative-baseline", "safe-equivalent", "residual-safe"),
    "runtime-availability": ("execution",),
    "replay-after-remediation": ("execution",),
    "independent-reproduction": ("execution",),
    "required-evidence-fields": ("evidence-field",),
}

_EXECUTION_GAP_STATES = frozenset({
    "unexecuted", "run-failed", "precondition-unavailable", "gate-blocked",
    "harness-error", "inconclusive", "disabled",
})
_EXECUTION_STATES = frozenset({
    "executed", "executed-no-effect", "executed-with-effect",
    *_EXECUTION_GAP_STATES,
})

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


def _safe_execution_state(value: Any) -> str:
    text = _text(value, 64).lower()
    return text if text in _EXECUTION_STATES else ""


def _normalize_observation(value: Any) -> Dict[str, Any]:
    """Normalize one S4-derived strategy observation without raw evidence."""
    if not isinstance(value, Mapping):
        return {}
    status = _code(value.get("status"), STRATEGY_OBSERVATION_STATUSES,
                   "unobserved")
    current_status = _code(value.get("current_status"),
                           STRATEGY_OBSERVATION_STATUSES, status)
    history_status = _code(value.get("history_status"),
                           STRATEGY_OBSERVATION_STATUSES, status)
    states = [_safe_execution_state(item)
              for item in _bounded(value.get("execution_states"),
                                   MAX_OBSERVATION_STATES, 64)]
    states = [item for item in states if item]
    signals = [item for item in _bounded(value.get("observed_signals"),
                                         MAX_OBSERVATION_SIGNALS, 48)
               if item in _OBSERVATION_SIGNALS]
    current_signals = [item for item in _bounded(
        value.get("current_signals"), MAX_OBSERVATION_SIGNALS, 48)
        if item in _OBSERVATION_SIGNALS]
    new_signals = [item for item in _bounded(
        value.get("new_signals"), MAX_OBSERVATION_SIGNALS, 48)
        if item in _OBSERVATION_SIGNALS]
    missing = _bounded(value.get("missing_observations"), 8, 96)
    falsifiers = _bounded(value.get("falsifier_codes"), 8, 64)
    candidates = _bounded(value.get("matched_candidate_ids"),
                          MAX_OBSERVATION_CANDIDATES, 120)
    try:
        last_round = int(value.get("last_round", 0) or 0)
    except (TypeError, ValueError):
        last_round = 0
    last_round = max(0, min(1000000, last_round))
    information_gain = _int(value.get("information_gain"), 0, 0, 5)
    cumulative_gain = _int(value.get("cumulative_information_gain"),
                            information_gain, 0, 32)
    zero_gain_streak = _int(
        value.get("zero_gain_streak"),
        1 if information_gain == 0 else 0,
        0, MAX_ZERO_GAIN_STREAK)
    digest = _text(value.get("evidence_digest"), 40).lower()
    if digest and not re.fullmatch(r"sg-[0-9a-f]{24}", digest):
        digest = ""
    return {
        "status": status,
        "current_status": current_status,
        "history_status": history_status,
        "last_round": last_round,
        "matched_candidate_ids": candidates,
        "execution_states": states,
        "observed_signals": signals,
        "current_signals": current_signals,
        "new_signals": new_signals,
        "missing_observations": missing,
        "falsifier_codes": falsifiers,
        "information_gain": information_gain,
        "cumulative_information_gain": cumulative_gain,
        "zero_gain_streak": zero_gain_streak,
        "evidence_digest": digest,
        "claim_status": STRATEGY_CLAIM_STATUS,
    }


def _normalize_guidance(value: Any) -> Dict[str, Any]:
    """Normalize one bounded next-action recommendation.

    Guidance is deliberately narrower than the strategy itself.  It may tell
    the scheduler which *class* of experiment should replace a low-yield
    repeat, but it cannot carry reviewer prose, payloads, commands, runtime
    output, or a finding verdict.
    """
    if not isinstance(value, Mapping):
        return {}
    action = _code(value.get("next_action"), STRATEGY_GUIDANCE_ACTIONS,
                   "continue-path-closure")
    reasons = [item for item in _bounded(
        value.get("reason_codes"), MAX_GUIDANCE_REASON_CODES, 64)
               if item in STRATEGY_GUIDANCE_REASON_CODES]
    sources = [item for item in _bounded(
        value.get("sources"), MAX_GUIDANCE_SOURCES, 64)
               if item in STRATEGY_GUIDANCE_SOURCES]
    gaps = _bounded(value.get("variant_gaps"), MAX_GUIDANCE_VARIANT_GAPS, 100)
    missing = _bounded(value.get("missing_observations"), 8, 96)
    review_status = _code(
        value.get("review_status"),
        {"accepted", "rejected", "needs-evidence", "scope-corrected"}, "")
    observation_status = _code(
        value.get("observation_status"), STRATEGY_OBSERVATION_STATUSES, "")
    replacement_rounds = _int(
        value.get("replacement_zero_gain_rounds"),
        DEFAULT_REPLACEMENT_ZERO_GAIN_ROUNDS, 1, 2)
    surface_variant_plan = normalize_surface_variant_plan(
        value.get("surface_variant_plan"))
    return {
        "next_action": action,
        "priority_delta": _int(value.get("priority_delta"), 0, 0, 3),
        "replacement_recommended": bool(
            value.get("replacement_recommended")),
        "reason_codes": reasons,
        "sources": sources,
        "variant_gaps": gaps,
        "missing_observations": missing,
        "review_status": review_status,
        "observation_status": observation_status,
        "replacement_zero_gain_rounds": replacement_rounds,
        "last_round": _int(value.get("last_round"), 0, 0, 1000000),
        "surface_variant_plan": surface_variant_plan,
        "claim_status": STRATEGY_CLAIM_STATUS,
    }


def _review_guidance_index(value: Any) -> Dict[str, Dict[str, Any]]:
    """Return only the latest safe review state for each research key."""
    latest: Dict[str, Dict[str, Any]] = {}
    if not isinstance(value, Mapping):
        return latest
    statuses = {"accepted", "rejected", "needs-evidence", "scope-corrected"}
    for raw in value.get("entries") or []:
        if not isinstance(raw, Mapping):
            continue
        key = _text(raw.get("research_key"), 80)
        status = _text(raw.get("status"), 32).lower()
        if not key or status not in statuses:
            continue
        item = {
            "status": status,
            "round": _int(raw.get("round"), 0, 0, 1000000),
            "feedback_id": _text(raw.get("feedback_id"), 80),
        }
        previous = latest.get(key)
        if previous is None or (
                item["round"], item["feedback_id"]
        ) >= (
                previous["round"], previous.get("feedback_id", "")
        ):
            latest[key] = item
    return latest


def _variant_guidance_rows(item: Mapping[str, Any],
                           portfolio: Mapping[str, Any]
                           ) -> Dict[str, Any]:
    """Match explicit item variants to portfolio coverage without inference."""
    variants = {
        _text(value, 100).lower()
        for value in item.get("variant") or []
        if _text(value, 100)
    }
    research_key_value = _text(item.get("research_key"), 80)
    residual_id = _text(item.get("residual_id"), 80)
    for probe in portfolio.get("next_probes") or []:
        if not isinstance(probe, Mapping):
            continue
        if ((research_key_value and _text(probe.get("research_key"), 80)
             == research_key_value) or
                (residual_id and _text(probe.get("residual_id"), 80)
                 == residual_id)):
            variants.update(
                _text(value, 100).lower()
                for value in probe.get("variant") or []
                if _text(value, 100))
    if not variants:
        return {"values": [], "gaps": [], "statuses": {}}
    rows = {
        _text(row.get("variant"), 100).lower(): row
        for row in portfolio.get("variant_coverage") or []
        if isinstance(row, Mapping) and _text(row.get("variant"), 100)
    }
    statuses: Dict[str, str] = {}
    gaps: List[str] = []
    for variant in sorted(variants):
        row = rows.get(variant)
        status = _text(row.get("status"), 32).lower() if row else "unobserved"
        statuses[variant] = status
        if status not in {"stable-observed", "observed"}:
            gaps.append(variant)
    return {
        "values": sorted(variants)[:MAX_GUIDANCE_VARIANT_GAPS],
        "gaps": gaps[:MAX_GUIDANCE_VARIANT_GAPS],
        "statuses": statuses,
    }


def _missing_guidance_action(missing: Sequence[str]) -> tuple:
    """Map missing observation labels to a bounded experiment class."""
    labels = set(missing)
    negative = {
        "negative-unauthorized-baseline", "negative-baseline",
        "negative-unreachable-control", "explicit-negative-observation",
        "negative-or-safe-observation",
    }
    capability = {"capability-transition"}
    typed = {"typed-effect-or-safe-equivalent"}
    source = {
        "default-config-exposure", "typed-source-sink-flow",
        "dynamic-dispatch-or-registration", "entry-or-sink-mapping",
    }
    if labels & negative:
        return "add-negative-control", "missing-negative-baseline"
    if labels & capability:
        return "trace-capability-transition", "missing-capability-transition"
    if labels & typed:
        return "add-typed-effect", "missing-typed-effect"
    if labels & source:
        return "review-source-dataflow", "missing-source-observation"
    return "continue-path-closure", "partial-observation"


def _item_guidance(item: Mapping[str, Any], portfolio: Mapping[str, Any],
                   reviews: Mapping[str, Mapping[str, Any]],
                   round_no: int,
                   replacement_zero_gain_rounds: int =
                   DEFAULT_REPLACEMENT_ZERO_GAIN_ROUNDS) -> Dict[str, Any]:
    """Fuse observation, review, and variant metadata into one next action."""
    observation = item.get("observation")
    observation = observation if isinstance(observation, Mapping) else {}
    status = _code(observation.get("status"), STRATEGY_OBSERVATION_STATUSES,
                   "unobserved")
    current_status = _code(
        observation.get("current_status"), STRATEGY_OBSERVATION_STATUSES,
        status)
    missing = _bounded(observation.get("missing_observations"), 8, 96)
    try:
        information_gain = int(observation.get("information_gain") or 0)
    except (TypeError, ValueError):
        information_gain = 0
    information_gain = max(0, min(5, information_gain))
    zero_gain_streak = _int(
        observation.get("zero_gain_streak"),
        1 if information_gain == 0 else 0,
        0, MAX_ZERO_GAIN_STREAK)
    replacement_zero_gain_rounds = _int(
        replacement_zero_gain_rounds,
        DEFAULT_REPLACEMENT_ZERO_GAIN_ROUNDS, 1, 2)
    review = reviews.get(_text(item.get("research_key"), 80), {})
    review_status = _text(review.get("status"), 32).lower()
    variant = _variant_guidance_rows(item, portfolio)
    variant_gaps = list(variant.get("gaps") or [])
    reasons: List[str] = []
    sources: List[str] = []

    def add_reason(value: str) -> None:
        if value in STRATEGY_GUIDANCE_REASON_CODES and value not in reasons:
            reasons.append(value)

    def add_source(value: str) -> None:
        if value in STRATEGY_GUIDANCE_SOURCES and value not in sources:
            sources.append(value)

    action = "continue-path-closure"
    priority_delta = 0

    if status == "environment-gap" or item.get("kind") == "environment-recovery":
        action = "repair-environment"
        priority_delta = 3
        add_reason("environment-gap")
        add_source("strategy-observation")
    elif item.get("kind") == "residual-closure" or item.get("residual_id"):
        action = "replay-residual-variant"
        priority_delta = 2
        add_reason("pending-residual")
        add_source("project-portfolio")
    elif review_status == "needs-evidence":
        action = "review-followup"
        priority_delta = 3
        add_reason("review-needs-evidence")
        add_source("human-review")
    elif review_status in {"rejected", "scope-corrected"}:
        action = "reframe-scope"
        add_reason("review-%s" % review_status)
        add_source("human-review")
    elif variant_gaps:
        action = "replay-new-variant"
        priority_delta = 2
        add_reason("variant-gap")
        add_source("variant-coverage")
    elif missing:
        action, reason = _missing_guidance_action(missing)
        priority_delta = 2 if status in {"partial", "execution-only"} else 1
        add_reason(reason)
        add_source("strategy-observation")
    elif status in {"complete", "falsifier-observed"} and information_gain == 0:
        action = "hold-for-new-evidence"
        add_reason("complete-observation" if status == "complete"
                   else "falsifier-observed")
        add_source("strategy-observation")
    elif status == "unobserved":
        add_reason("unobserved")
        add_source("strategy-observation")
        priority_delta = 1
    else:
        add_reason("partial-observation")
        add_source("strategy-observation")
        priority_delta = 1

    replacement = bool(
        information_gain == 0 and
        zero_gain_streak >= replacement_zero_gain_rounds and
        current_status not in {"unobserved", "environment-gap"} and
        action != "repair-environment")
    if replacement:
        add_reason("zero-information-gain")
    if review_status:
        add_source("human-review")
    if variant_gaps and "variant-coverage" not in sources:
        add_source("variant-coverage")

    surface_variant_plan = build_surface_variant_plan(
        item.get("research_surface"), item.get("target_type"), action,
        item.get("attack_class"), item.get("variant"))

    return {
        "next_action": action,
        "priority_delta": priority_delta,
        "replacement_recommended": replacement,
        "replacement_zero_gain_rounds": replacement_zero_gain_rounds,
        "reason_codes": reasons[:MAX_GUIDANCE_REASON_CODES],
        "sources": sources[:MAX_GUIDANCE_SOURCES],
        "variant_gaps": variant_gaps[:MAX_GUIDANCE_VARIANT_GAPS],
        "missing_observations": missing[:8],
        "review_status": review_status,
        "observation_status": status,
        "last_round": _int(round_no, 0, 0, 1000000),
        "surface_variant_plan": surface_variant_plan,
        "claim_status": STRATEGY_CLAIM_STATUS,
    }


def _required_observations(signals: Iterable[str], required: Any
                           ) -> List[str]:
    """Return required labels still missing from the bounded signal set."""
    observed = set(signals)
    missing = []
    for label in _bounded(required, 8, 96):
        aliases = _REQUIRED_SIGNAL_ALIASES.get(label, ())
        if aliases and not any(alias in observed for alias in aliases):
            missing.append(label)
        elif not aliases:
            # Static/source obligations intentionally remain open until their
            # own artifact has evidence; S4 runtime execution cannot satisfy
            # them by implication.
            missing.append(label)
    return missing


def _classify_observation(signals: Iterable[str], required: Any,
                          execution_states: Iterable[str]) -> str:
    observed = set(signals)
    states = set(execution_states)
    has_execution = "execution" in observed
    has_gap = "environment-gap" in observed
    if "explicit-falsifier" in observed:
        return "falsifier-observed"
    if not has_execution and has_gap:
        return "environment-gap"
    if not has_execution:
        return "unobserved"
    missing = _required_observations(observed, required)
    if not missing:
        return "complete"
    if any(signal != "execution" for signal in observed):
        return "partial"
    if states:
        return "execution-only"
    return "unobserved"


def _summary_observation(summary: Any) -> Dict[str, Any]:
    """Extract a safe observation taxonomy from one S4 candidate summary."""
    if not isinstance(summary, Mapping):
        return {"signals": [], "execution_states": [], "falsifiers": []}
    signals = set()
    states = set()
    falsifiers = set()
    state = _safe_execution_state(summary.get("execution_state"))
    if state:
        states.add(state)
        if state.startswith("executed-"):
            signals.add("execution")
        elif state in _EXECUTION_GAP_STATES:
            signals.add("environment-gap")
    try:
        if (int(summary.get("cells_ran", 0) or 0) > 0 and
                state not in _EXECUTION_GAP_STATES):
            signals.add("execution")
    except (TypeError, ValueError):
        pass
    if summary.get("harness_error") or summary.get("compile_error"):
        signals.add("environment-gap")
        states.add("harness-error" if summary.get("harness_error")
                   else "run-failed")
    if summary.get("errors") or summary.get("env_errors"):
        signals.add("runtime-error")

    runtime_lab = summary.get("runtime_lab")
    if isinstance(runtime_lab, Mapping):
        for signal in runtime_lab.get("variant_observed_signals") or []:
            signal = str(signal).strip().lower()
            if signal in {
                    "execution", "entry-behavior", "authorization",
                    "negative-baseline", "capability-trace", "state-sequence",
                    "typed-effect", "safe-equivalent", "environment-gap",
                    "evidence-field", "runtime-error"}:
                signals.add(signal)
        variant_statuses = {
            str(value).strip().lower()
            for value in runtime_lab.get("variant_evidence_statuses") or []
        }
        if "environment-gap" in variant_statuses:
            signals.add("environment-gap")

    if (summary.get("instantiated") or summary.get("parsed") or
            summary.get("http_evidence")):
        signals.add("entry-behavior")
        signals.add("evidence-field")

    authz_rows = [row for row in summary.get("authz_results") or []
                  if isinstance(row, Mapping)]
    if authz_rows:
        signals.update({"authorization", "evidence-field"})
        for row in authz_rows:
            expected = row.get("authz") or row.get("expected") or {}
            deny_expected = expected.get("expected_authz") == "deny"
            if not deny_expected:
                deny_expected = any(
                    code in {401, 403}
                    for code in expected.get("expected_http_codes") or [])
            if deny_expected and row.get("status") == "passed" \
                    and not row.get("boundary_violation"):
                signals.add("negative-baseline")
                falsifiers.add("negative-baseline-observed")

    capability_rows = [row for row in summary.get("capability_evidence") or []
                       if isinstance(row, Mapping)]
    if capability_rows:
        signals.update({"capability-trace", "evidence-field"})

    experiment_rows = [row for row in summary.get("experiment_evidence") or []
                       if isinstance(row, Mapping)]
    if experiment_rows:
        signals.update({"state-sequence", "evidence-field"})

    if (summary.get("effect_evidence") or summary.get("network_side_effects")
            or summary.get("leaked")):
        signals.update({"typed-effect", "evidence-field"})
    if summary.get("safe_equivalent"):
        signals.update({"safe-equivalent", "evidence-field"})
        falsifiers.add("safe-equivalent-observed")

    residual_rows = [row for row in summary.get("residual_falsifiers") or []
                     if isinstance(row, Mapping)]
    if residual_rows:
        signals.update({"residual-contract", "evidence-field"})
        for row in residual_rows:
            row_state = _safe_execution_state(row.get("execution_state"))
            if row_state:
                states.add(row_state)
            if (str(row.get("status") or "").lower() == "falsified" and
                    row_state in {"executed", "executed-no-effect"}):
                if not row.get("effect_observed"):
                    signals.update({"explicit-falsifier", "residual-safe"})
                    falsifiers.add("explicit-residual-falsifier")
                else:
                    signals.add("typed-effect")

    return {
        "signals": sorted(signals),
        "execution_states": sorted(states),
        "falsifiers": sorted(falsifiers),
    }


def _candidate_residual_ids(candidate: Mapping[str, Any]) -> set:
    ids = {str(row.get("residual_id")) for row in residual_meta(dict(candidate))
           if row.get("residual_id")}
    plan = candidate.get("experiment_plan")
    if isinstance(plan, Mapping):
        for row in plan.get("residual_contracts") or []:
            if isinstance(row, Mapping) and row.get("residual_id"):
                ids.add(str(row.get("residual_id")))
    return ids


def _item_matches_candidate(item: Mapping[str, Any],
                            candidate: Mapping[str, Any]) -> bool:
    candidate_id = _text(candidate.get("candidate_id"), 120)
    if candidate_id and candidate_id == _text(item.get("candidate_id"), 120):
        return True
    try:
        candidate_key = research_key(dict(candidate))
    except Exception:  # pragma: no cover - defensive identity boundary
        candidate_key = ""
    if candidate_key and candidate_key == _text(item.get("research_key"), 80):
        return True
    residual_id = _text(item.get("residual_id"), 80)
    if residual_id and residual_id in _candidate_residual_ids(candidate):
        return True
    for field in ("path_id", "flow_id", "entry_id", "sink_id"):
        item_value = _text(item.get(field), 160)
        candidate_value = _text(candidate.get(field), 160)
        if item_value and item_value == candidate_value:
            return True
    return False


def _item_observation(item: Mapping[str, Any], matches: Sequence[Mapping[str, Any]],
                      round_no: int) -> Dict[str, Any]:
    previous = _normalize_observation(item.get("observation"))
    current_signals = set()
    current_states = set()
    current_falsifiers = set()
    for summary in matches:
        view = _summary_observation(summary)
        current_signals.update(view["signals"])
        current_states.update(view["execution_states"])
        current_falsifiers.update(view["falsifiers"])
    prior_signals = set(previous.get("observed_signals") or [])
    prior_states = set(previous.get("execution_states") or [])
    all_signals = prior_signals | current_signals
    all_states = prior_states | current_states
    all_falsifiers = set(previous.get("falsifier_codes") or []) | current_falsifiers
    current_status = _classify_observation(
        current_signals, item.get("required_observations") or [], current_states)
    history_status = _classify_observation(
        all_signals, item.get("required_observations") or [], all_states)
    new_signals = current_signals - prior_signals
    new_states = current_states - prior_states
    information_gain = min(5, len(new_signals) + len(new_states))
    if previous and information_gain == 0 and current_status != previous.get("current_status"):
        information_gain = 1
    previous_zero_gain_streak = _int(
        previous.get("zero_gain_streak"), 0, 0, MAX_ZERO_GAIN_STREAK)
    zero_gain_streak = (
        min(MAX_ZERO_GAIN_STREAK, previous_zero_gain_streak + 1)
        if information_gain == 0 else 0
    )
    matched_ids = set(previous.get("matched_candidate_ids") or [])
    matched_ids.update(_text(summary.get("candidate_id"), 120)
                       for summary in matches if summary.get("candidate_id"))
    digest_material = {
        "strategy_id": item.get("strategy_id"),
        "round": _int(round_no, 0, 0, 1000000),
        "signals": sorted(current_signals),
        "states": sorted(current_states),
        "falsifiers": sorted(current_falsifiers),
    }
    digest = "sg-" + hashlib.sha256(json.dumps(
        digest_material, sort_keys=True, ensure_ascii=False,
        separators=(",", ":")).encode("utf-8")).hexdigest()[:24]
    return {
        "status": history_status,
        "current_status": current_status,
        "history_status": history_status,
        "last_round": _int(round_no, 0, 0, 1000000),
        "matched_candidate_ids": sorted(matched_ids)[:MAX_OBSERVATION_CANDIDATES],
        "execution_states": sorted(all_states)[:MAX_OBSERVATION_STATES],
        "observed_signals": sorted(all_signals)[:MAX_OBSERVATION_SIGNALS],
        "current_signals": sorted(current_signals)[:MAX_OBSERVATION_SIGNALS],
        "new_signals": sorted(new_signals)[:MAX_OBSERVATION_SIGNALS],
        "missing_observations": _required_observations(
            all_signals, item.get("required_observations") or []),
        "falsifier_codes": sorted(all_falsifiers)[:8],
        "information_gain": information_gain,
        "cumulative_information_gain": min(
            32, _int(previous.get("cumulative_information_gain"), 0, 0, 32)
            + information_gain),
        "zero_gain_streak": zero_gain_streak,
        "evidence_digest": digest,
        "claim_status": STRATEGY_CLAIM_STATUS,
    }


def _carry_strategy_observations(items: List[Dict[str, Any]],
                                 prior_strategy: Any) -> None:
    prior = normalize_research_strategy(prior_strategy or {})
    by_id = {
        str(item.get("strategy_id")): item
        for item in prior.get("items") or []
        if isinstance(item, Mapping)
    }
    for item in items:
        previous = by_id.get(item.get("strategy_id"), {})
        observation = _normalize_observation(previous.get("observation"))
        if observation:
            item["observation"] = observation
        guidance = _normalize_guidance(previous.get("guidance"))
        if guidance:
            item["guidance"] = guidance


def apply_strategy_observations(
        strategy: Mapping[str, Any], candidates: Sequence[Mapping[str, Any]],
        summaries: Optional[Mapping[str, Any]], round_no: int = 0
        ) -> tuple:
    """Back-write bounded S4 observations and per-round information gain.

    Matching is explicit (candidate id, stable research key, residual id, or
    persisted path identifiers).  The result is a research status update only;
    it never writes a finding status or changes G4/G5 inputs.
    """
    normalized = normalize_research_strategy(strategy)
    if not normalized:
        return {}, {
            "schema_version": STRATEGY_FEEDBACK_SCHEMA_VERSION,
            "round": _int(round_no, 0, 0, 1000000),
            "summary": {"item_count": 0, "matched_items": 0,
                         "information_gain": 0,
                         "claim_status": STRATEGY_CLAIM_STATUS},
            "items": [], "claim_status": STRATEGY_CLAIM_STATUS,
        }
    summaries = summaries if isinstance(summaries, Mapping) else {}
    candidate_list = [candidate for candidate in candidates or []
                      if isinstance(candidate, Mapping)]
    feedback_items = []
    for item in normalized.get("items") or []:
        matched = []
        for candidate in candidate_list:
            if not _item_matches_candidate(item, candidate):
                continue
            cid = _text(candidate.get("candidate_id"), 120)
            summary = summaries.get(cid, {}) if cid else {}
            if isinstance(summary, Mapping):
                row = dict(summary)
                row["candidate_id"] = cid
                matched.append(row)
        if not matched:
            continue
        observation = _item_observation(item, matched, round_no)
        item["observation"] = observation
        feedback_items.append({
            "strategy_id": item.get("strategy_id"),
            "kind": item.get("kind"),
            "candidate_id": item.get("candidate_id", ""),
            "research_key": item.get("research_key", ""),
            "residual_id": item.get("residual_id", ""),
            "observation": observation,
            "claim_status": STRATEGY_CLAIM_STATUS,
        })
    normalized["summary"] = _summary(
        normalized.get("items") or [],
        _int((normalized.get("summary") or {}).get("path_count"), 0,
             0, 1000000),
        _int((normalized.get("summary") or {}).get("unresolved_count"), 0,
             0, 1000000),
    )
    feedback_summary = {
        "item_count": len(feedback_items),
        "matched_items": len(feedback_items),
        "information_gain": sum(
            _int(item.get("observation", {}).get("information_gain"), 0, 0, 5)
            for item in feedback_items),
        "new_information_items": sum(
            1 for item in feedback_items
            if item.get("observation", {}).get("information_gain", 0)),
        "falsifier_observed": sum(
            1 for item in feedback_items
            if item.get("observation", {}).get("status") == "falsifier-observed"),
        "environment_gaps": sum(
            1 for item in feedback_items
            if item.get("observation", {}).get("status") == "environment-gap"),
        "claim_status": STRATEGY_CLAIM_STATUS,
    }
    feedback = {
        "schema_version": STRATEGY_FEEDBACK_SCHEMA_VERSION,
        "strategy_schema_version": STRATEGY_SCHEMA_VERSION,
        "round": _int(round_no, 0, 0, 1000000),
        "summary": feedback_summary,
        "items": feedback_items[:MAX_STRATEGY_ITEMS],
        "claim_status": STRATEGY_CLAIM_STATUS,
    }
    return normalized, feedback


def apply_research_guidance(
        strategy: Mapping[str, Any],
        research_portfolio: Optional[Mapping[str, Any]] = None,
        review_feedback: Optional[Mapping[str, Any]] = None,
        round_no: int = 0,
        replay_calibration: Optional[Mapping[str, Any]] = None,
        ) -> tuple:
    """Attach a bounded next-action layer to a research strategy.

    This joins three *research* signals only: S4-derived strategy
    observations, the project portfolio's explicit variant coverage, and the
    latest human review state.  The returned artifact is scheduling guidance,
    never a finding or a replacement for G4/G5 evidence.
    """
    normalized = normalize_research_strategy(strategy)
    round_value = _int(round_no, 0, 0, 1000000)
    replacement_zero_gain_rounds = DEFAULT_REPLACEMENT_ZERO_GAIN_ROUNDS
    if isinstance(replay_calibration, Mapping) and \
            replay_calibration.get("schema_version") == \
            "research-replay-calibration-v1" and \
            replay_calibration.get("status") == "calibrated":
        calibration_metrics = replay_calibration.get("metrics")
        if not isinstance(calibration_metrics, Mapping):
            calibration_metrics = {}
        policy = replay_calibration.get("policy")
        replayable = _int(
            calibration_metrics.get("replayed_guidance_items"), 0, 0, 1000000)
        if replayable >= 3 and isinstance(policy, Mapping):
            replacement_zero_gain_rounds = _int(
                policy.get("replacement_zero_gain_rounds"),
                DEFAULT_REPLACEMENT_ZERO_GAIN_ROUNDS, 1, 2)
    empty = {
        "schema_version": STRATEGY_GUIDANCE_SCHEMA_VERSION,
        "strategy_schema_version": STRATEGY_SCHEMA_VERSION,
        "round": round_value,
        "summary": {
            "item_count": 0,
            "actionable_items": 0,
            "replacement_recommendations": 0,
            "environment_repairs": 0,
            "review_followups": 0,
            "variant_gaps": 0,
            "replacement_zero_gain_rounds": replacement_zero_gain_rounds,
            "action_counts": {},
            "claim_status": STRATEGY_CLAIM_STATUS,
        },
        "items": [],
        "claim_status": STRATEGY_CLAIM_STATUS,
    }
    if not normalized:
        return {}, empty
    portfolio = normalize_research_portfolio(dict(research_portfolio or {}))
    reviews = _review_guidance_index(review_feedback or {})
    guidance_items = []
    action_counts = Counter()
    replacement_count = 0
    environment_count = 0
    review_count = 0
    variant_gap_count = 0
    for item in normalized.get("items") or []:
        guidance = _item_guidance(
            item, portfolio, reviews, round_value,
            replacement_zero_gain_rounds=replacement_zero_gain_rounds)
        item["guidance"] = guidance
        action = guidance.get("next_action", "continue-path-closure")
        action_counts[action] += 1
        replacement_count += int(bool(guidance.get(
            "replacement_recommended")))
        environment_count += int(action == "repair-environment")
        review_count += int(action in {"review-followup", "reframe-scope"})
        variant_gap_count += int(bool(guidance.get("variant_gaps")))
        guidance_items.append({
            "strategy_id": item.get("strategy_id", ""),
            "research_key": item.get("research_key", ""),
            "candidate_id": item.get("candidate_id", ""),
            "residual_id": item.get("residual_id", ""),
            "next_action": action,
            "priority_delta": guidance.get("priority_delta", 0),
            "replacement_recommended": bool(
                guidance.get("replacement_recommended")),
            "replacement_zero_gain_rounds": guidance.get(
                "replacement_zero_gain_rounds", replacement_zero_gain_rounds),
            "reason_codes": list(guidance.get("reason_codes") or [])[
                :MAX_GUIDANCE_REASON_CODES],
            "sources": list(guidance.get("sources") or [])[
                :MAX_GUIDANCE_SOURCES],
            "variant_gaps": list(guidance.get("variant_gaps") or [])[
                :MAX_GUIDANCE_VARIANT_GAPS],
            "missing_observations": list(
                guidance.get("missing_observations") or [])[:8],
            "review_status": guidance.get("review_status", ""),
            "observation_status": guidance.get("observation_status", ""),
            "last_round": guidance.get("last_round", round_value),
            "surface_variant_plan": normalize_surface_variant_plan(
                guidance.get("surface_variant_plan")),
            "claim_status": STRATEGY_CLAIM_STATUS,
        })
    normalized["summary"] = _summary(
        normalized.get("items") or [],
        _int((normalized.get("summary") or {}).get("path_count"), 0,
             0, 1000000),
        _int((normalized.get("summary") or {}).get("unresolved_count"), 0,
             0, 1000000),
    )
    guidance = {
        "schema_version": STRATEGY_GUIDANCE_SCHEMA_VERSION,
        "strategy_schema_version": STRATEGY_SCHEMA_VERSION,
        "round": round_value,
        "summary": {
            "item_count": len(guidance_items),
            "actionable_items": sum(
                1 for item in guidance_items
                if item.get("priority_delta", 0) or item.get(
                    "replacement_recommended")),
            "replacement_recommendations": replacement_count,
            "environment_repairs": environment_count,
            "review_followups": review_count,
            "variant_gaps": variant_gap_count,
            "replacement_zero_gain_rounds": replacement_zero_gain_rounds,
            "action_counts": dict(sorted(action_counts.items())),
            "claim_status": STRATEGY_CLAIM_STATUS,
        },
        "items": guidance_items[:MAX_STRATEGY_ITEMS],
        "claim_status": STRATEGY_CLAIM_STATUS,
    }
    return normalized, guidance


def strategy_guidance_for_candidate(strategy: Mapping[str, Any],
                                    candidate: Mapping[str, Any]
                                    ) -> Dict[str, Any]:
    """Return guidance for an exact candidate/research-key match.

    S2 planners use this bridge to carry the same surface-specific plan into
    the candidate's experiment artifact.  It intentionally refuses fuzzy
    prose matching; an unmatched candidate receives the planner's generic
    surface plan instead.
    """
    normalized = normalize_research_strategy(strategy)
    if not normalized or not isinstance(candidate, Mapping):
        return {}
    candidate_id = _text(candidate.get("candidate_id"), 120)
    try:
        candidate_key = research_key(dict(candidate))
    except Exception:  # pragma: no cover - defensive identity boundary
        candidate_key = ""
    residual_ids = _candidate_residual_ids(dict(candidate))
    for item in normalized.get("items") or []:
        if not isinstance(item, Mapping):
            continue
        if (candidate_id and candidate_id == _text(item.get("candidate_id"), 120)):
            return _normalize_guidance(item.get("guidance"))
        if (candidate_key and candidate_key == _text(
                item.get("research_key"), 80)):
            return _normalize_guidance(item.get("guidance"))
        if _text(item.get("residual_id"), 80) in residual_ids:
            return _normalize_guidance(item.get("guidance"))
    return {}


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
    observations = [item.get("observation") for item in items
                    if isinstance(item.get("observation"), Mapping)]
    observation_states = Counter(
        _text(item.get("status"), 48) for item in observations
        if item.get("status"))
    return {
        "item_count": len(items),
        "path_count": path_count,
        "unresolved_count": unresolved_count,
        "pending_residuals": sum(
            1 for item in items if item.get("kind") == "residual-closure"),
        "environment_recovery": sum(
            1 for item in items if item.get("kind") == "environment-recovery"),
        "observed_items": len(observations),
        "information_gain": sum(
            _int(item.get("information_gain"), 0, 0, 5)
            for item in observations),
        "falsifier_observed": sum(
            1 for item in observations if item.get("status") == "falsifier-observed"),
        "observation_statuses": dict(sorted(observation_states.items())),
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
        prior_strategy: Optional[Dict[str, Any]] = None,
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
            residual_state = _text(residual.get("state"), 64)
            if residual_state and residual_state != "pending-residual":
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
    _carry_strategy_observations(normalized_items, prior_strategy)
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
    observation = _normalize_observation(raw.get("observation"))
    if observation:
        out["observation"] = observation
    guidance = _normalize_guidance(raw.get("guidance"))
    if guidance:
        out["guidance"] = guidance
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


def normalize_research_guidance(raw: Any) -> Dict[str, Any]:
    """Strip untrusted fields from a standalone guidance snapshot."""
    if not isinstance(raw, Mapping) or raw.get(
            "schema_version") != STRATEGY_GUIDANCE_SCHEMA_VERSION:
        return {}
    items = []
    seen = set()
    for row in raw.get("items") or []:
        if not isinstance(row, Mapping):
            continue
        strategy_id = _text(row.get("strategy_id"), 80)
        if not _STRATEGY_ID.fullmatch(strategy_id) or strategy_id in seen:
            continue
        seen.add(strategy_id)
        guidance = _normalize_guidance({
            "next_action": row.get("next_action"),
            "priority_delta": row.get("priority_delta"),
            "replacement_recommended": row.get(
                "replacement_recommended"),
            "reason_codes": row.get("reason_codes"),
            "sources": row.get("sources"),
            "variant_gaps": row.get("variant_gaps"),
            "missing_observations": row.get("missing_observations"),
            "review_status": row.get("review_status"),
            "observation_status": row.get("observation_status"),
            "replacement_zero_gain_rounds": row.get(
                "replacement_zero_gain_rounds"),
            "last_round": row.get("last_round"),
            "surface_variant_plan": row.get("surface_variant_plan"),
        })
        items.append({
            "strategy_id": strategy_id,
            "research_key": _text(row.get("research_key"), 80),
            "candidate_id": _text(row.get("candidate_id"), 120),
            "residual_id": _text(row.get("residual_id"), 80),
            **guidance,
        })
        if len(items) >= MAX_STRATEGY_ITEMS:
            break
    items.sort(key=lambda row: str(row.get("strategy_id", "")))
    summary = raw.get("summary") if isinstance(raw.get("summary"), Mapping) else {}
    actions = {
        _code(name, STRATEGY_GUIDANCE_ACTIONS, "continue-path-closure"):
        _int(count, 0, 0, MAX_STRATEGY_ITEMS)
        for name, count in sorted(
            (summary.get("action_counts") or {}).items(),
            key=lambda item: str(item[0]))
    }
    return {
        "schema_version": STRATEGY_GUIDANCE_SCHEMA_VERSION,
        "strategy_schema_version": STRATEGY_SCHEMA_VERSION,
        "round": _int(raw.get("round"), 0, 0, 1000000),
        "summary": {
            "item_count": len(items),
            "actionable_items": _int(summary.get("actionable_items"), 0,
                                      0, MAX_STRATEGY_ITEMS),
            "replacement_recommendations": _int(
                summary.get("replacement_recommendations"), 0, 0,
                MAX_STRATEGY_ITEMS),
            "environment_repairs": _int(summary.get("environment_repairs"),
                                         0, 0, MAX_STRATEGY_ITEMS),
            "review_followups": _int(summary.get("review_followups"), 0, 0,
                                      MAX_STRATEGY_ITEMS),
            "variant_gaps": _int(summary.get("variant_gaps"), 0, 0,
                                  MAX_STRATEGY_ITEMS),
            "replacement_zero_gain_rounds": _int(
                summary.get("replacement_zero_gain_rounds"),
                DEFAULT_REPLACEMENT_ZERO_GAIN_ROUNDS, 1, 2),
            "action_counts": actions,
            "claim_status": STRATEGY_CLAIM_STATUS,
        },
        "items": items,
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


def guidance_path(workspace: Path, target: str) -> Path:
    return (Path(workspace).resolve() / "state" / str(target) /
            "coverage" / STRATEGY_GUIDANCE_FILENAME)


def write_research_guidance(workspace: Path, target: str,
                            guidance: Mapping[str, Any]) -> Path:
    path = guidance_path(workspace, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = normalize_research_guidance(guidance) or {
        "schema_version": STRATEGY_GUIDANCE_SCHEMA_VERSION,
        "strategy_schema_version": STRATEGY_SCHEMA_VERSION,
        "round": 0,
        "summary": {
            "item_count": 0, "actionable_items": 0,
            "replacement_recommendations": 0, "environment_repairs": 0,
            "review_followups": 0, "variant_gaps": 0,
            "action_counts": {}, "claim_status": STRATEGY_CLAIM_STATUS,
        },
        "items": [], "claim_status": STRATEGY_CLAIM_STATUS,
    }
    tmp = path.with_name(".%s.tmp.%d" % (path.name, os.getpid()))
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    tmp.replace(path)
    return path


def load_research_guidance(workspace: Path, target: str) -> Dict[str, Any]:
    path = guidance_path(workspace, target)
    if not path.exists():
        return {}
    try:
        return normalize_research_guidance(
            json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {}
