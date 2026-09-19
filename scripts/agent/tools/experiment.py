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


MAX_SEQUENCE_STEPS = 16
MAX_STEP_ID_LENGTH = 64
MAX_CONCURRENCY = 64

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


def experiment_metadata(cell: Any) -> dict:
    """Return the stable JSON shape persisted for one matrix cell."""
    return {
        "sequence": list(getattr(cell, "sequence", []) or []),
        "concurrency": int(getattr(cell, "concurrency", 1) or 1),
        "availability_probe": bool(getattr(cell, "availability_probe", False)),
        "warnings": list(getattr(cell, "experiment_warnings", []) or []),
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
