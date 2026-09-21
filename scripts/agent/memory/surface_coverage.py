"""Cross-round coverage for actual surface-variant lane witnesses.

``surface-variant-evidence-v1`` is cell-shaped.  This module turns those
bounded witnesses from research memory into a project-shaped view without
turning a partial lane into a negative result.  The output is deliberately
separate from the finding ledger: it answers which lane observations are
closed, incomplete, or blocked, and which exact research key should receive
the next probe.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from .research import _normalize_variant_evidence
from ..tools.redaction import redact_text


SURFACE_LANE_COVERAGE_SCHEMA_VERSION = "surface-variant-coverage-v1"
CLAIM_STATUS = "not-a-finding"
MAX_LANES = 64
MAX_ENTRY_REFS = 16
MAX_SIGNALS = 11
MAX_SEQUENCE_STATUSES = 8
MAX_STATUS_COUNTS = 8
MAX_TEXT = 120

SURFACES = frozenset({"web", "protocol", "cloud", "mobile", "native"})
LANES = frozenset({"positive", "negative", "environment-gap"})
STATUSES = frozenset({
    "observed", "partial", "environment-gap", "not-executed",
})
SIGNALS = frozenset({
    "execution", "entry-behavior", "authorization", "negative-baseline",
    "capability-trace", "state-sequence", "typed-effect",
    "safe-equivalent", "environment-gap", "evidence-field", "runtime-error",
})
SEQUENCE_STATUSES = frozenset({
    "not-declared", "no-trace", "partial", "out-of-order",
    "unexpected-step", "complete",
})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,95}$")


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    try:
        value = redact_text(value)
    except Exception:  # pragma: no cover - defensive artifact boundary
        value = str(value)
    return " ".join(str(value or "").replace("\x00", "").split())[:limit]


def _safe_int(value: Any, default: int = 0,
              minimum: int = 0, maximum: int = 1000000) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _bounded(values: Any, allowed: Set[str], limit: int) -> List[str]:
    if not isinstance(values, (list, tuple, set)):
        return []
    return sorted({str(item).strip().lower() for item in values
                   if str(item).strip().lower() in allowed})[:limit]


def _bounded_refs(values: Any) -> List[Dict[str, str]]:
    if not isinstance(values, (list, tuple, set)):
        return []
    refs: Dict[str, Dict[str, str]] = {}
    for raw in values:
        if not isinstance(raw, Mapping):
            continue
        key = _text(raw.get("research_key"), 80)
        if not key:
            continue
        refs[key] = {
            "research_key": key,
            "candidate_id": _text(raw.get("candidate_id"), 120),
        }
        if len(refs) >= MAX_ENTRY_REFS:
            break
    return [refs[key] for key in sorted(refs)]


def _empty() -> Dict[str, Any]:
    return {
        "schema_version": SURFACE_LANE_COVERAGE_SCHEMA_VERSION,
        "summary": {
            "lane_count": 0,
            "observed_lanes": 0,
            "partial_lanes": 0,
            "environment_gap_lanes": 0,
            "not_executed_lanes": 0,
            "cells_observed": 0,
            "cells_with_gap": 0,
        },
        "lanes": [],
        "claim_status": CLAIM_STATUS,
    }


def empty_surface_lane_coverage() -> Dict[str, Any]:
    """Return an empty, schema-correct coverage view."""
    return _empty()


def _aggregate_status(statuses: Iterable[str]) -> str:
    values = {value for value in statuses if value in STATUSES}
    if not values:
        return "not-executed"
    if values == {"observed"}:
        return "observed"
    if values == {"environment-gap"}:
        return "environment-gap"
    if values == {"not-executed"}:
        return "not-executed"
    return "partial"


def _normalize_lane_row(raw: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, Mapping):
        return None
    surface = _text(raw.get("surface"), 32).lower()
    variant_id = _text(raw.get("variant_id"), 96)
    lane = _text(raw.get("lane"), 24).lower()
    if surface not in SURFACES or lane not in LANES \
            or not _IDENTIFIER.fullmatch(variant_id):
        return None
    status = _text(raw.get("status"), 32).lower()
    if status not in STATUSES:
        status = "partial"
    raw_counts = raw.get("status_counts")
    status_counts = {
        _text(key, 32).lower(): _safe_int(value, 0, 0, 1000000)
        for key, value in (raw_counts.items() if isinstance(raw_counts, Mapping)
                           else [])
        if _text(key, 32).lower() in STATUSES
    }
    latest_counts = raw.get("latest_status_counts")
    latest_status_counts = {
        _text(key, 32).lower(): _safe_int(value, 0, 0, 1000000)
        for key, value in (latest_counts.items()
                           if isinstance(latest_counts, Mapping) else [])
        if _text(key, 32).lower() in STATUSES
    }
    return {
        "surface": surface,
        "variant_id": variant_id,
        "lane": lane,
        "entry_count": _safe_int(raw.get("entry_count"), 0, 0, 1000000),
        "event_count": _safe_int(raw.get("event_count"), 0, 0, 1000000),
        "cells_observed": _safe_int(raw.get("cells_observed"), 0, 0, 4096),
        "cells_with_gap": _safe_int(raw.get("cells_with_gap"), 0, 0, 4096),
        "status_counts": dict(list(sorted(status_counts.items()))[
            :MAX_STATUS_COUNTS]),
        "latest_status_counts": dict(list(sorted(latest_status_counts.items()))[
            :MAX_STATUS_COUNTS]),
        "status": status,
        "latest_round": _safe_int(raw.get("latest_round"), 0, 0, 1000000),
        "required_observations": _bounded(
            raw.get("required_observations"), set(SIGNALS), MAX_SIGNALS),
        "observed_signals": _bounded(
            raw.get("observed_signals"), set(SIGNALS), MAX_SIGNALS),
        "latest_observed_signals": _bounded(
            raw.get("latest_observed_signals"), set(SIGNALS), MAX_SIGNALS),
        "missing_observations": _bounded(
            raw.get("missing_observations"), set(SIGNALS), MAX_SIGNALS),
        "sequence_statuses": _bounded(
            raw.get("sequence_statuses"), set(SEQUENCE_STATUSES),
            MAX_SEQUENCE_STATUSES),
        "latest_sequence_statuses": _bounded(
            raw.get("latest_sequence_statuses"), set(SEQUENCE_STATUSES),
            MAX_SEQUENCE_STATUSES),
        "entry_refs": _bounded_refs(raw.get("entry_refs")),
        "claim_status": CLAIM_STATUS,
    }


def normalize_surface_lane_coverage(raw: Any) -> Dict[str, Any]:
    """Normalize a persisted surface-lane view and discard unknown fields."""
    if not isinstance(raw, Mapping) or raw.get("schema_version") \
            != SURFACE_LANE_COVERAGE_SCHEMA_VERSION:
        return {}
    lanes = []
    for item in raw.get("lanes") or []:
        row = _normalize_lane_row(item)
        if row:
            lanes.append(row)
        if len(lanes) >= MAX_LANES:
            break
    lanes.sort(key=lambda row: (
        row["surface"], row["variant_id"], row["lane"]))
    result = _empty()
    result["lanes"] = lanes
    summary = Counter(row["status"] for row in lanes)
    result["summary"] = {
        "lane_count": len(lanes),
        "observed_lanes": summary.get("observed", 0),
        "partial_lanes": summary.get("partial", 0),
        "environment_gap_lanes": summary.get("environment-gap", 0),
        "not_executed_lanes": summary.get("not-executed", 0),
        "cells_observed": min(4096, sum(row["cells_observed"]
                                        for row in lanes)),
        "cells_with_gap": min(4096, sum(row["cells_with_gap"]
                                         for row in lanes)),
    }
    return result


def build_surface_lane_coverage(memory: Any) -> Dict[str, Any]:
    """Aggregate normalized lane witnesses across all memory rounds."""
    if not isinstance(memory, Mapping):
        return _empty()
    buckets: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for entry in memory.get("entries") or []:
        if not isinstance(entry, Mapping):
            continue
        research_key = _text(entry.get("research_key"), 80)
        if not research_key:
            continue
        candidate_id = _text(entry.get("candidate_id"), 120)
        for event in entry.get("events") or []:
            if not isinstance(event, Mapping):
                continue
            evidence = event.get("evidence")
            if not isinstance(evidence, Mapping):
                continue
            witness = _normalize_variant_evidence(
                evidence.get("variant_evidence"))
            if not witness:
                continue
            surface = _text(witness.get("surface"), 32).lower()
            variant_id = _text(witness.get("variant_id"), 96)
            lane = _text(witness.get("lane"), 24).lower()
            if surface not in SURFACES or lane not in LANES \
                    or not _IDENTIFIER.fullmatch(variant_id):
                continue
            key = (surface, variant_id, lane)
            bucket = buckets.setdefault(key, {
                "entry_refs": {},
                "event_count": 0,
                "cells_observed": 0,
                "cells_with_gap": 0,
                "status_counts": Counter(),
                "required_observations": set(),
                "observed_signals": set(),
                "sequence_statuses": set(),
                "latest_by_entry": {},
            })
            bucket["entry_refs"][research_key] = {
                "research_key": research_key,
                "candidate_id": candidate_id,
            }
            bucket["event_count"] = min(1000000, bucket["event_count"] + 1)
            bucket["cells_observed"] = min(
                4096, bucket["cells_observed"] + _safe_int(
                    witness.get("cells_observed"), 0, 0, 64))
            bucket["cells_with_gap"] = min(
                4096, bucket["cells_with_gap"] + _safe_int(
                    witness.get("cells_with_gap"), 0, 0, 64))
            status = _text(witness.get("status"), 32).lower()
            if status not in STATUSES:
                status = "partial"
            bucket["status_counts"][status] += 1
            bucket["required_observations"].update(
                _bounded(witness.get("required_observations"),
                         set(SIGNALS), MAX_SIGNALS))
            bucket["observed_signals"].update(
                _bounded(witness.get("observed_signals"),
                         set(SIGNALS), MAX_SIGNALS))
            bucket["sequence_statuses"].update(
                _bounded(witness.get("sequence_statuses"),
                         set(SEQUENCE_STATUSES), MAX_SEQUENCE_STATUSES))
            event_round = _safe_int(event.get("round"), 0, 0, 1000000)
            event_id = _text(event.get("event_id"), 80)
            latest = bucket["latest_by_entry"].get(research_key)
            latest_key = (event_round, event_id)
            if latest is None or latest_key >= latest["sort_key"]:
                bucket["latest_by_entry"][research_key] = {
                    "sort_key": latest_key,
                    "round": event_round,
                    "status": status,
                    "required_observations": _bounded(
                        witness.get("required_observations"),
                        set(SIGNALS), MAX_SIGNALS),
                    "observed_signals": _bounded(
                        witness.get("observed_signals"),
                        set(SIGNALS), MAX_SIGNALS),
                    "missing_observations": _bounded(
                        witness.get("missing_observations"),
                        set(SIGNALS), MAX_SIGNALS),
                    "sequence_statuses": _bounded(
                        witness.get("sequence_statuses"),
                        set(SEQUENCE_STATUSES), MAX_SEQUENCE_STATUSES),
                }

    rows: List[Dict[str, Any]] = []
    for (surface, variant_id, lane), bucket in sorted(buckets.items()):
        latest_rows = list(bucket["latest_by_entry"].values())
        status = _aggregate_status(row["status"] for row in latest_rows)
        required = sorted({item for row in latest_rows
                           for item in row["required_observations"]})[:MAX_SIGNALS]
        latest_observed = sorted({item for row in latest_rows
                                  for item in row["observed_signals"]})[:MAX_SIGNALS]
        missing = sorted({item for row in latest_rows
                          for item in row["missing_observations"]})[:MAX_SIGNALS]
        latest_sequences = sorted({item for row in latest_rows
                                   for item in row["sequence_statuses"]})[
                                       :MAX_SEQUENCE_STATUSES]
        latest_status_counts = Counter(row["status"] for row in latest_rows)
        rows.append({
            "surface": surface,
            "variant_id": variant_id,
            "lane": lane,
            "entry_count": len(bucket["entry_refs"]),
            "event_count": bucket["event_count"],
            "cells_observed": bucket["cells_observed"],
            "cells_with_gap": bucket["cells_with_gap"],
            "status_counts": dict(sorted(bucket["status_counts"].items())),
            "latest_status_counts": dict(sorted(latest_status_counts.items())),
            "status": status,
            "latest_round": max((row["round"] for row in latest_rows),
                                 default=0),
            "required_observations": required,
            "observed_signals": sorted(bucket["observed_signals"])[:MAX_SIGNALS],
            "latest_observed_signals": latest_observed,
            "missing_observations": missing,
            "sequence_statuses": sorted(bucket["sequence_statuses"])[
                :MAX_SEQUENCE_STATUSES],
            "latest_sequence_statuses": latest_sequences,
            "entry_refs": [bucket["entry_refs"][key]
                           for key in sorted(bucket["entry_refs"])
                           ][:MAX_ENTRY_REFS],
            "claim_status": CLAIM_STATUS,
        })
        if len(rows) >= MAX_LANES:
            break
    return normalize_surface_lane_coverage({
        "schema_version": SURFACE_LANE_COVERAGE_SCHEMA_VERSION,
        "lanes": rows,
    })
