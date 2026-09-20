"""Bounded stateful/concurrency experiment metadata for S4 cells.

The PoC still owns the actual requests and state transitions.  This module
only normalizes the experiment declaration that the runner exposes to that
PoC and persists with each cell.  Keeping the contract small prevents an LLM
candidate from smuggling arbitrary commands, secrets, or unbounded fan-out
through matrix metadata.
"""

from __future__ import annotations

import re
from typing import Any, List, Tuple

from .redaction import redact_text


MAX_SEQUENCE_STEPS = 16
MAX_STEP_ID_LENGTH = 64
MAX_CONCURRENCY = 64
MAX_CAPABILITIES = 16
MAX_TRANSITION_RULES = 16
MAX_CAPABILITY_GOAL_LENGTH = 160

_STEP_ID = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,%d}$" % (MAX_STEP_ID_LENGTH - 1))
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off", ""}


def _normalize_bool(value: Any, field: str, warnings: List[str]) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _TRUE:
            return True
        if lowered in _FALSE:
            return False
    warnings.append("%s must be boolean; defaulted to false" % field)
    return False


def normalize_experiment(sequence: Any = None, concurrency: Any = 1,
                         availability_probe: Any = False
                         ) -> Tuple[List[str], int, bool, List[str]]:
    """Normalize a cell experiment declaration and return warnings.

    Sequence entries are identifiers only.  They are intentionally not shell
    fragments, URLs, or request bodies.  The PoC may use the identifiers to
    select its own local steps, while the runner records the declaration and
    the emitted ``STEP``/``STEP_EVIDENCE`` observations.
    """
    warnings: List[str] = []
    if sequence is None:
        raw_steps = []
    elif isinstance(sequence, (list, tuple)):
        raw_steps = list(sequence)
    else:
        raw_steps = []
        warnings.append("sequence must be an array of step identifiers")

    steps: List[str] = []
    for raw in raw_steps:
        step = str(raw).strip()
        if not step or not _STEP_ID.fullmatch(step):
            warnings.append("invalid sequence step omitted")
            continue
        steps.append(step)
    if len(steps) > MAX_SEQUENCE_STEPS:
        warnings.append("sequence truncated to %d steps" % MAX_SEQUENCE_STEPS)
        steps = steps[:MAX_SEQUENCE_STEPS]

    try:
        if isinstance(concurrency, bool):
            raise ValueError
        workers = int(concurrency)
    except (TypeError, ValueError):
        workers = 1
        warnings.append("concurrency must be an integer; defaulted to 1")
    if workers < 1:
        warnings.append("concurrency below 1; defaulted to 1")
        workers = 1
    elif workers > MAX_CONCURRENCY:
        warnings.append("concurrency capped at %d" % MAX_CONCURRENCY)
        workers = MAX_CONCURRENCY

    probe = _normalize_bool(availability_probe, "availability_probe", warnings)
    if probe and workers < 2:
        warnings.append("availability_probe requires declared concurrency >= 2")

    return steps, workers, probe, warnings


def _bounded_identifiers(value: Any, limit: int) -> List[str]:
    """Keep capability names identifier-shaped and bounded.

    Capability contracts are metadata supplied by static analysis or an LLM
    candidate.  They must never become a second command/configuration channel.
    """
    if not isinstance(value, (list, tuple)):
        return []
    out: List[str] = []
    for raw in value:
        item = str(raw).strip()
        if not item or not _STEP_ID.fullmatch(item) or item in out:
            continue
        out.append(item)
        if len(out) >= limit:
            break
    return out


def normalize_capability_contract(value: Any) -> dict:
    """Normalize a bounded capability-chain contract for one S4 cell.

    The contract describes what a PoC should attempt to observe; it does not
    assert that any primitive or transition exists.  Only identifier-shaped
    capability names and ``from``/``to`` pairs survive normalization.
    """
    if not isinstance(value, dict):
        return {}
    required = _bounded_identifiers(
        value.get("required_capabilities") or value.get("required"),
        MAX_CAPABILITIES)
    observed = _bounded_identifiers(
        value.get("observed_capabilities") or value.get("observed"),
        MAX_CAPABILITIES)
    missing = _bounded_identifiers(
        value.get("missing_capabilities") or value.get("missing"),
        MAX_CAPABILITIES)
    rules: List[dict] = []
    raw_rules = value.get("transition_rules") or value.get("transitions")
    if isinstance(raw_rules, (list, tuple)):
        for raw in raw_rules:
            if not isinstance(raw, dict):
                continue
            left = str(raw.get("from", "")).strip()
            right = str(raw.get("to", "")).strip()
            if not _STEP_ID.fullmatch(left) or not _STEP_ID.fullmatch(right):
                continue
            row = {"from": left, "to": right}
            if isinstance(raw.get("declared"), bool):
                row["declared"] = raw["declared"]
            rules.append(row)
            if len(rules) >= MAX_TRANSITION_RULES:
                break
    goal = redact_text(value.get("goal", "")).replace("\x00", "").strip()
    return {
        "required_capabilities": required,
        "observed_capabilities": observed,
        "missing_capabilities": missing,
        "transition_rules": rules,
        "goal": goal[:MAX_CAPABILITY_GOAL_LENGTH],
        "typed_effect_required": bool(value.get("typed_effect_required", False)),
    }


def capability_contract_from_candidate(candidate: Any) -> dict:
    """Derive a cell contract from a static capability candidate or plan."""
    if not isinstance(candidate, dict):
        return {}
    nested = candidate.get("capability_contract")
    if not isinstance(nested, dict):
        plan = candidate.get("experiment_plan")
        if isinstance(plan, dict):
            nested = plan.get("capability_contract")
    if isinstance(nested, dict):
        return normalize_capability_contract(nested)
    return normalize_capability_contract({
        "required_capabilities": candidate.get("required_capabilities"),
        "observed_capabilities": candidate.get("observed_capabilities"),
        "missing_capabilities": candidate.get("missing_capabilities"),
        "transition_rules": candidate.get("transition_rules"),
        "goal": candidate.get("goal"),
        "typed_effect_required": candidate.get(
            "typed_effect_required", candidate.get("runtime_required", False)),
    })


def experiment_metadata(cell: Any) -> dict:
    """Return the stable JSON shape persisted for one matrix cell."""
    return {
        "sequence": list(getattr(cell, "sequence", []) or []),
        "concurrency": int(getattr(cell, "concurrency", 1) or 1),
        "availability_probe": bool(getattr(cell, "availability_probe", False)),
        "warnings": list(getattr(cell, "experiment_warnings", []) or []),
        "capability_contract": normalize_capability_contract(
            getattr(cell, "capability_contract", {})),
    }


def sequence_trace_status(declared: List[str], observed: List[str]) -> str:
    """Classify whether an observed step trace follows the declaration."""
    if not declared:
        return "not-declared"
    if not observed:
        return "no-trace"
    expected_index = 0
    unexpected = False
    out_of_order = False
    for raw in observed:
        step = str(raw)
        if step not in declared:
            unexpected = True
            continue
        try:
            index = declared.index(step, expected_index)
        except ValueError:
            out_of_order = True
            continue
        expected_index = index + 1
    if out_of_order:
        return "out-of-order"
    if unexpected:
        return "unexpected-step"
    if expected_index == len(declared):
        return "complete"
    return "partial"
