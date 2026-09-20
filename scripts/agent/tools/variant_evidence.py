"""Validate actual S4 observations against a surface-variant lane.

``surface-variant-fixture-v1`` is a planning/execution context, not proof.  A
PoC can receive the lane and state-step identifiers and still emit no useful
observation.  This module compares the machine-readable row emitted by the
existing matrix runner with the allowlisted lane contract and persists only a
small taxonomy of signals, counts, and trace identities.  It never copies
payloads, command output, effect details, or credentials.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Set

from .experiment import sequence_trace_status
from .redaction import redact_text
from .surface_variants import normalize_variant_fixture_context


VARIANT_EVIDENCE_SCHEMA_VERSION = "surface-variant-evidence-v1"
CLAIM_STATUS = "not-a-finding"
MAX_CELLS = 16
MAX_SIGNALS = 12
MAX_TRACE_IDS = 16
MAX_SEQUENCE_STATUSES = 8

_SIGNALS = frozenset({
    "execution", "entry-behavior", "authorization", "negative-baseline",
    "capability-trace", "state-sequence", "typed-effect",
    "safe-equivalent", "environment-gap", "evidence-field", "runtime-error",
})
_STATUSES = frozenset({"observed", "partial", "environment-gap", "not-executed"})
_SEQUENCE_STATUSES = frozenset({
    "not-declared", "no-trace", "partial", "out-of-order", "unexpected-step",
    "complete",
})
_GAP_PRECONDITIONS = frozenset({
    "precondition-unavailable", "run-failed", "gate-blocked", "policy-denied",
})
_SAFE_EFFECT_MARKERS = ("canary", "simulat", "shape-only", "in-memory")


def _text(value: Any, limit: int = 120) -> str:
    return redact_text(value).replace("\x00", "").strip()[:limit]


def _trace(value: Any) -> List[str]:
    if isinstance(value, list):
        return [_text(item, 120) for item in value[:32] if _text(item, 120)]
    item = _text(value, 120)
    return [item] if item else []


def _observations(row: Mapping[str, Any]) -> Mapping[str, Any]:
    value = row.get("observations")
    return value if isinstance(value, Mapping) else {}


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() not in {
        "", "false", "none", "null", "0", "no",
    }


def _is_gap(row: Mapping[str, Any], obs: Mapping[str, Any]) -> bool:
    if _text(row.get("precondition_status"), 64).lower() in _GAP_PRECONDITIONS:
        return True
    if row.get("harness_error") or row.get("compile_error") \
            or bool(row.get("timed_out")):
        return True
    if _text(obs.get("ENV_ERROR"), 80):
        return True
    return (isinstance(row.get("returncode"), int)
            and row.get("returncode") != 0
            and not isinstance(row.get("returncode"), bool))


def _known_trace_ids(values: Iterable[Any], allowed: Set[str]) -> List[str]:
    result: List[str] = []
    for value in _trace(list(values) if isinstance(values, list) else values):
        if value in allowed and value not in result:
            result.append(value)
        if len(result) >= MAX_TRACE_IDS:
            break
    return result


def _cell_evidence(context: Mapping[str, Any], row: Mapping[str, Any]) -> Dict[str, Any]:
    obs = _observations(row)
    gap = _is_gap(row, obs)
    signals: Set[str] = set()
    if gap:
        signals.add("environment-gap")
    else:
        if (isinstance(row.get("returncode"), int)
                and not isinstance(row.get("returncode"), bool)
                and row.get("returncode") == 0):
            signals.add("execution")

    error = _text(obs.get("ERROR"), 80) or _text(obs.get("ENV_ERROR"), 80)
    if error:
        signals.add("runtime-error")

    entry_keys = ("PARSED", "INSTANTIATED", "HTTP_CODE", "RESP_MATCH",
                  "OBJECT_MUTATED", "AUTHZ_RESULT", "EVIDENCE", "LEAKED",
                  "NETWORK", "EFFECT_KIND")
    entry_observed = any(
        (str(obs.get(key, "")).strip().isdigit() if key == "HTTP_CODE"
         else _truthy(obs.get(key)))
        for key in entry_keys)
    if entry_observed:
        signals.update({"entry-behavior", "evidence-field"})

    authz = _text(obs.get("AUTHZ_RESULT"), 40).lower()
    assertion = row.get("authz_assertion")
    if authz or (isinstance(assertion, Mapping)
                 and _text(assertion.get("status"), 40)):
        signals.update({"authorization", "evidence-field"})
    code = _text(obs.get("HTTP_CODE"), 8)
    if authz in {"deny", "denied", "reject", "rejected"} or code in {"401", "403"}:
        signals.add("negative-baseline")

    declared = _trace(row.get("sequence"))
    experiment = row.get("experiment")
    if isinstance(experiment, Mapping):
        declared = _trace(experiment.get("sequence")) or declared
    declared = declared or _trace(context.get("state_steps"))
    allowed_steps = set(declared) | set(_trace(context.get("state_steps")))
    step_trace = _trace(obs.get("STEP_TRACE"))
    state_trace = _trace(obs.get("STATE_TRACE"))
    observed_steps = _known_trace_ids(step_trace, allowed_steps)
    observed_states = _known_trace_ids(
        state_trace, set(_trace(context.get("state_steps"))) | allowed_steps)
    sequence_status = sequence_trace_status(declared, step_trace) \
        if declared else "not-declared"
    if sequence_status == "complete":
        signals.add("state-sequence")
    elif step_trace or state_trace:
        signals.add("evidence-field")

    capability_trace = _trace(obs.get("CAPABILITY_TRACE"))
    if capability_trace:
        signals.update({"capability-trace", "evidence-field"})

    effect_kind = _text(obs.get("EFFECT_KIND"), 80).lower()
    effect = _text(obs.get("EFFECT", obs.get("SIDE_EFFECT")), 80)
    safe_effect = any(marker in effect_kind for marker in _SAFE_EFFECT_MARKERS)
    if effect_kind and effect and not safe_effect:
        signals.update({"typed-effect", "evidence-field"})
    if (_truthy(obs.get("CANARY"))
            or (effect_kind and safe_effect)):
        signals.update({"safe-equivalent", "evidence-field"})

    status = "environment-gap" if gap else "observed"
    return {
        "version": _text(row.get("version"), 80),
        "safe_mode": bool(row.get("safe_mode", False)),
        "status": status,
        "signals": sorted(signals)[:MAX_SIGNALS],
        "sequence_status": sequence_status
        if sequence_status in _SEQUENCE_STATUSES else "no-trace",
        "observed_steps": observed_steps,
        "observed_states": observed_states,
        "typed_effect_observed": "typed-effect" in signals,
        "claim_status": CLAIM_STATUS,
    }


def _missing_falsifiers(context: Mapping[str, Any], missing: Iterable[str]) -> List[str]:
    planned = set(_trace(context.get("falsifiers")))
    mapping = {
        "typed-effect": "typed-effect-missing",
        "state-sequence": "transition-not-observed",
        "negative-baseline": "negative-baseline-missing",
        "safe-equivalent": "safe-equivalent-missing",
        "authorization": "subject-object-binding-missing",
        "capability-trace": "transition-not-observed",
    }
    return sorted({mapping[item] for item in missing
                   if item in mapping and mapping[item] in planned})


def summarize_variant_evidence(context: Any,
                               rows: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    """Classify bounded actual rows against one normalized variant lane."""
    normalized = normalize_variant_fixture_context(context)
    if not normalized:
        return {}
    cells = [_cell_evidence(normalized, row)
             for row in rows if isinstance(row, Mapping)]
    required = sorted({item for item in normalized.get("required_observations", [])
                       if item in _SIGNALS})
    observed = sorted({signal for cell in cells for signal in cell["signals"]
                       if signal in _SIGNALS})
    missing = [signal for signal in required if signal not in observed]
    gap_count = sum(1 for cell in cells if cell["status"] == "environment-gap")
    executed_count = len(cells) - gap_count
    if not cells:
        status = "not-executed"
    elif executed_count == 0 and gap_count:
        status = "environment-gap"
    elif not missing:
        status = "observed"
    else:
        status = "partial"
    sequence_statuses = sorted({cell["sequence_status"] for cell in cells})
    return {
        "schema_version": VARIANT_EVIDENCE_SCHEMA_VERSION,
        "fixture_key": _text(normalized.get("fixture_key"), 80),
        "surface": _text(normalized.get("surface"), 32),
        "variant_id": _text(normalized.get("variant_id"), 96),
        "lane": _text(normalized.get("lane"), 24),
        "expected_observation": _text(normalized.get("expected_observation"), 40),
        "required_observations": required,
        "observed_signals": observed,
        "missing_observations": missing,
        "falsifier_signals": _missing_falsifiers(normalized, missing),
        "sequence_statuses": sequence_statuses[:MAX_SEQUENCE_STATUSES],
        "cells_observed": len(cells),
        "cells_with_gap": gap_count,
        "status": status if status in _STATUSES else "partial",
        "cells": cells[:MAX_CELLS],
        "claim_status": CLAIM_STATUS,
    }
