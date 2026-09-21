"""Aggregate bounded replay calibration across independent projects.

Per-target replay calibration answers whether a guidance action paid off for
one project.  A senior researcher also needs to know whether that signal is
project-specific or repeats across projects.  This module consumes only the
already-normalized ``research-replay-calibration-v1`` artifacts and derives a
small cohort policy for research scheduling.

The cohort is deliberately not a finding or a benchmark truth source.  It
never copies source text, payloads, commands, process output, credentials, or
candidate conclusions.  It can only select the existing one- or two-round
zero-information replacement threshold, and only after enough *distinct*
project replays are present.  An explicitly configured cohort may be used as a
fallback when a target has too little local history; target-local calibration
always takes precedence when it is sufficient.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ..tools.redaction import redact_text
from .replay_calibration import (
    CALIBRATION_SCHEMA_VERSION,
    normalize_replay_calibration,
)


COHORT_SCHEMA_VERSION = "research-replay-cohort-v1"
COHORT_FILENAME = "research-replay-cohort.json"
COHORT_CLAIM_STATUS = "not-a-finding"

MAX_PROJECTS = 32
MAX_SURFACES = 5
MAX_RECOMMENDATIONS = 8
MAX_TEXT = 120
MAX_JSON_BYTES = 8 * 1024 * 1024
MIN_PROJECT_REPLAYS = 3
MIN_COHORT_PROJECTS = 3

RESEARCH_SURFACES = frozenset({
    "web", "protocol", "cloud", "mobile", "native",
})

_PROJECT_ID_RE = re.compile(r"^project-[0-9a-f]{16,32}$")
_OUTCOME_UNPRODUCTIVE = frozenset({
    "repeat-no-new-information",
    "replacement-observed-no-new-information",
    "changed-without-new-information",
})
def _text(value: Any, limit: int = MAX_TEXT) -> str:
    try:
        value = redact_text(value)
    except Exception:  # pragma: no cover - defensive redaction boundary
        value = str(value)
    return " ".join(str(value).replace("\x00", "").split())[:limit]


def _int(value: Any, default: int = 0, minimum: int = 0,
         maximum: int = 1000000) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    return round(float(numerator) / float(denominator), 4) if denominator else None


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def _digest(value: Any, prefix: str = "cohort") -> str:
    return prefix + "-" + hashlib.sha256(
        _canonical(value).encode("utf-8", errors="replace")).hexdigest()[:24]


def _surface(value: Any) -> str:
    value = _text(value, 24).lower()
    return value if value in RESEARCH_SURFACES else ""


def _rate_fields(row: Dict[str, Any]) -> Dict[str, Any]:
    row["replacement_hit_rate"] = _ratio(
        row.get("replacement_hits", 0), row.get("replacement_observed", 0))
    row["unproductive_repeat_rate"] = _ratio(
        row.get("unproductive_repeats", 0), row.get("replayed_guidance_items", 0))
    row["environment_recovery_rate"] = _ratio(
        row.get("environment_recoveries", 0),
        row.get("environment_repair_recommendations", 0))
    return row


def _empty_surface(surface: str) -> Dict[str, Any]:
    return {
        "surface": surface,
        "project_count": 0,
        "sufficient_project_count": 0,
        "guidance_items": 0,
        "replayed_guidance_items": 0,
        "replacement_recommendations": 0,
        "replacement_observed": 0,
        "replacement_hits": 0,
        "unproductive_repeats": 0,
        "environment_repair_recommendations": 0,
        "environment_recoveries": 0,
        "replacement_hit_rate": None,
        "unproductive_repeat_rate": None,
        "environment_recovery_rate": None,
        "sample_sufficient": False,
        "status": "insufficient-sample",
        "claim_status": COHORT_CLAIM_STATUS,
    }


def _surface_metrics_from_outcomes(outcomes: Any) -> List[Dict[str, Any]]:
    counters: Dict[str, Dict[str, Any]] = {}
    project_surfaces = set()
    if not isinstance(outcomes, (list, tuple)):
        return []
    for raw in outcomes:
        if not isinstance(raw, Mapping):
            continue
        surface = _surface(raw.get("surface"))
        if not surface:
            continue
        row = counters.setdefault(surface, _empty_surface(surface))
        project_surfaces.add(surface)
        row["guidance_items"] += 1
        outcome = _text(raw.get("outcome"), 64)
        replayed = outcome != "unobserved"
        row["replayed_guidance_items"] += int(replayed)
        replacement = bool(raw.get("replacement_recommended"))
        row["replacement_recommendations"] += int(replacement)
        row["replacement_observed"] += int(replacement and replayed)
        row["replacement_hits"] += int(
            replacement and outcome == "replacement-productive")
        row["unproductive_repeats"] += int(
            replayed and outcome in _OUTCOME_UNPRODUCTIVE)
        repair = _text(raw.get("next_action"), 64) == "repair-environment"
        row["environment_repair_recommendations"] += int(repair)
        row["environment_recoveries"] += int(
            repair and bool(raw.get("environment_recovered")))
    result = []
    for name in sorted(project_surfaces)[:MAX_SURFACES]:
        row = counters[name]
        _rate_fields(row)
        row["status"] = (
            "sufficient" if row["replayed_guidance_items"] >= MIN_PROJECT_REPLAYS
            else "insufficient-sample")
        row["sample_sufficient"] = bool(
            row["replayed_guidance_items"] >= MIN_PROJECT_REPLAYS)
        row["claim_status"] = COHORT_CLAIM_STATUS
        result.append(row)
    return result


def _normalize_surface_row(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        return {}
    surface = _surface(raw.get("surface"))
    if not surface:
        return {}
    row = _empty_surface(surface)
    for key in (
        "project_count", "sufficient_project_count", "guidance_items",
        "replayed_guidance_items",
        "replacement_recommendations", "replacement_observed",
        "replacement_hits", "unproductive_repeats",
        "environment_repair_recommendations", "environment_recoveries",
    ):
        row[key] = _int(raw.get(key), 0, 0, 1000000)
    _rate_fields(row)
    row["status"] = (
        "sufficient" if row.get("project_count", 0) >= MIN_COHORT_PROJECTS
        and row.get("sufficient_project_count", 0) >= MIN_COHORT_PROJECTS
        else "insufficient-sample")
    row["sample_sufficient"] = bool(
        row["replayed_guidance_items"] >= MIN_PROJECT_REPLAYS)
    return row


def _project_id(label: str, target: str, history_digest: str,
                index: int = 0) -> str:
    seed = label or target or history_digest or "project-%d" % index
    # The persisted identifier is opaque; paths and target labels are never
    # copied into the cohort artifact.
    return "project-" + hashlib.sha256(
        (seed + "\x00" + history_digest).encode("utf-8", errors="replace")
    ).hexdigest()[:24]


def _project_from_calibration(raw: Any, label: str = "",
                              index: int = 0) -> Dict[str, Any]:
    calibration = normalize_replay_calibration(raw)
    if not calibration:
        return {}
    metrics = calibration.get("metrics") or {}
    status = _text(calibration.get("status"), 32)
    replayed = _int(metrics.get("replayed_guidance_items"), 0, 0, 1000000)
    project = {
        "project_id": _project_id(
            _text(label, 96), _text(calibration.get("target"), 96),
            _text(calibration.get("history_digest"), 48), index),
        "calibration_status": status,
        "eligible": bool(status == "calibrated" and
                          replayed >= MIN_PROJECT_REPLAYS),
        "replayed_guidance_items": replayed,
        "replacement_recommendations": _int(
            metrics.get("replacement_recommendations"), 0, 0, 1000000),
        "replacement_observed": _int(
            metrics.get("replacement_observed"), 0, 0, 1000000),
        "replacement_hits": _int(
            metrics.get("replacement_hits"), 0, 0, 1000000),
        "unproductive_repeats": _int(
            metrics.get("unproductive_repeats"), 0, 0, 1000000),
        "environment_repair_recommendations": _int(
            metrics.get("environment_repair_recommendations"), 0, 0, 1000000),
        "environment_recoveries": _int(
            metrics.get("environment_recoveries"), 0, 0, 1000000),
        "fixture_budget_rounds": _int(
            metrics.get("fixture_budget_rounds"), 0, 0, 1000000),
        "fixture_truncated_rounds": _int(
            metrics.get("fixture_truncated_rounds"), 0, 0, 1000000),
        "comparison_fixtures": _int(
            metrics.get("comparison_fixtures"), 0, 0, 1000000),
        "comparison_gaps": _int(
            metrics.get("comparison_gaps"), 0, 0, 1000000),
        "surface_metrics": _surface_metrics_from_outcomes(
            calibration.get("outcomes")),
        "claim_status": COHORT_CLAIM_STATUS,
    }
    _rate_fields(project)
    return project


def _normalize_project(raw: Any, index: int = 0) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        return {}
    project_id = _text(raw.get("project_id"), 64)
    if not _PROJECT_ID_RE.fullmatch(project_id):
        project_id = _project_id("", "", _text(raw.get("history_digest"), 48), index)
    status = _text(raw.get("calibration_status"), 32)
    if status not in {"no-data", "insufficient-sample", "calibrated"}:
        status = "no-data"
    project: Dict[str, Any] = {
        "project_id": project_id,
        "calibration_status": status,
        "replayed_guidance_items": _int(
            raw.get("replayed_guidance_items"), 0, 0, 1000000),
        "replacement_recommendations": _int(
            raw.get("replacement_recommendations"), 0, 0, 1000000),
        "replacement_observed": _int(
            raw.get("replacement_observed"), 0, 0, 1000000),
        "replacement_hits": _int(raw.get("replacement_hits"), 0, 0, 1000000),
        "unproductive_repeats": _int(
            raw.get("unproductive_repeats"), 0, 0, 1000000),
        "environment_repair_recommendations": _int(
            raw.get("environment_repair_recommendations"), 0, 0, 1000000),
        "environment_recoveries": _int(
            raw.get("environment_recoveries"), 0, 0, 1000000),
        "fixture_budget_rounds": _int(
            raw.get("fixture_budget_rounds"), 0, 0, 1000000),
        "fixture_truncated_rounds": _int(
            raw.get("fixture_truncated_rounds"), 0, 0, 1000000),
        "comparison_fixtures": _int(
            raw.get("comparison_fixtures"), 0, 0, 1000000),
        "comparison_gaps": _int(
            raw.get("comparison_gaps"), 0, 0, 1000000),
        "surface_metrics": [],
        "claim_status": COHORT_CLAIM_STATUS,
    }
    project["eligible"] = bool(
        status == "calibrated" and
        project["replayed_guidance_items"] >= MIN_PROJECT_REPLAYS)
    seen = set()
    for item in raw.get("surface_metrics") or []:
        row = _normalize_surface_row(item)
        if not row or row["surface"] in seen:
            continue
        seen.add(row["surface"])
        project["surface_metrics"].append(row)
        if len(project["surface_metrics"]) >= MAX_SURFACES:
            break
    _rate_fields(project)
    return project


def _aggregate_surfaces(projects: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    totals: Dict[str, Dict[str, Any]] = {}
    project_sets: Dict[str, set] = defaultdict(set)
    sufficient_project_sets: Dict[str, set] = defaultdict(set)
    for project in projects:
        project_id = _text(project.get("project_id"), 64)
        for raw in project.get("surface_metrics") or []:
            row = _normalize_surface_row(raw)
            if not row:
                continue
            surface = row["surface"]
            total = totals.setdefault(surface, _empty_surface(surface))
            project_sets[surface].add(project_id)
            if row.get("sample_sufficient"):
                sufficient_project_sets[surface].add(project_id)
            for key in (
                "guidance_items", "replayed_guidance_items",
                "replacement_recommendations", "replacement_observed",
                "replacement_hits", "unproductive_repeats",
                "environment_repair_recommendations", "environment_recoveries",
            ):
                total[key] += row.get(key, 0)
    result = []
    for surface in sorted(totals)[:MAX_SURFACES]:
        row = totals[surface]
        row["project_count"] = len(project_sets[surface])
        row["sufficient_project_count"] = len(
            sufficient_project_sets[surface])
        _rate_fields(row)
        row["status"] = (
            "sufficient" if row["project_count"] >= MIN_COHORT_PROJECTS
            and row["sufficient_project_count"] >= MIN_COHORT_PROJECTS
            else "insufficient-sample")
        row["sample_sufficient"] = bool(row["status"] == "sufficient")
        row["claim_status"] = COHORT_CLAIM_STATUS
        result.append(row)
    return result


def _sum(projects: Sequence[Mapping[str, Any]], key: str,
         eligible_only: bool = False) -> int:
    return sum(_int(row.get(key), 0, 0, 1000000) for row in projects
               if not eligible_only or row.get("eligible"))


def _build_cohort(projects: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for index, raw in enumerate(projects):
        row = _normalize_project(raw, index)
        if not row or row["project_id"] in seen:
            continue
        seen.add(row["project_id"])
        deduped.append(row)
        if len(deduped) >= MAX_PROJECTS:
            break
    eligible = [row for row in deduped if row.get("eligible")]
    replayed = _sum(deduped, "replayed_guidance_items")
    eligible_replayed = _sum(eligible, "replayed_guidance_items")
    metrics: Dict[str, Any] = {
        "project_count": len(deduped),
        "calibrated_projects": sum(
            row.get("calibration_status") == "calibrated" for row in deduped),
        "eligible_projects": len(eligible),
        "insufficient_sample_projects": len(deduped) - len(eligible),
        "replayed_guidance_items": replayed,
        "eligible_replayed_guidance_items": eligible_replayed,
        "replacement_recommendations": _sum(eligible, "replacement_recommendations"),
        "replacement_observed": _sum(eligible, "replacement_observed"),
        "replacement_hits": _sum(eligible, "replacement_hits"),
        "unproductive_repeats": _sum(eligible, "unproductive_repeats"),
        "environment_repair_recommendations": _sum(
            eligible, "environment_repair_recommendations"),
        "environment_recoveries": _sum(eligible, "environment_recoveries"),
        "fixture_budget_rounds": _sum(eligible, "fixture_budget_rounds"),
        "fixture_truncated_rounds": _sum(eligible, "fixture_truncated_rounds"),
        "comparison_fixtures": _sum(eligible, "comparison_fixtures"),
        "comparison_gaps": _sum(eligible, "comparison_gaps"),
        "claim_status": COHORT_CLAIM_STATUS,
    }
    _rate_fields(metrics)

    evaluable = [row for row in eligible
                 if row.get("replacement_observed", 0) > 0]
    low_yield = [row for row in evaluable
                 if isinstance(row.get("replacement_hit_rate"), (int, float))
                 and row["replacement_hit_rate"] < 0.5
                 and isinstance(row.get("unproductive_repeat_rate"), (int, float))
                 and row["unproductive_repeat_rate"] >= 0.5]
    threshold = 1
    policy_basis = "insufficient-cohort"
    if len(eligible) >= MIN_COHORT_PROJECTS:
        policy_basis = "cohort-default"
        if len(evaluable) >= MIN_COHORT_PROJECTS and \
                len(low_yield) * 2 >= len(evaluable):
            threshold = 2
            policy_basis = "majority-low-yield-projects"
    metrics["replacement_evaluable_projects"] = len(evaluable)
    metrics["low_yield_projects"] = len(low_yield)

    if not deduped:
        status = "no-data"
    elif len(eligible) < MIN_COHORT_PROJECTS:
        status = "insufficient-cohort"
    else:
        status = "calibrated"

    recommendations: List[Dict[str, Any]] = []

    def add(code: str, priority: str, metric: str, value: Any,
            limit: Any) -> None:
        recommendations.append({
            "code": code,
            "priority": priority,
            "metric": metric,
            "value": value,
            "threshold": limit,
            "claim_status": COHORT_CLAIM_STATUS,
        })

    if len(eligible) < MIN_COHORT_PROJECTS:
        add("collect-more-projects", "high", "eligible_projects",
            len(eligible), MIN_COHORT_PROJECTS)
    elif threshold == 2:
        add("activate-cohort-policy", "medium", "low_yield_projects",
            len(low_yield), len(evaluable))
    else:
        add("retain-cohort-default", "low", "eligible_projects",
            len(eligible), MIN_COHORT_PROJECTS)

    surfaces = _aggregate_surfaces(deduped)
    for row in surfaces:
        if row.get("sufficient_project_count", 0) < MIN_COHORT_PROJECTS:
            add("collect-more-surface-replay", "medium",
                "%s.sufficient_project_count" % row.get("surface"),
                row.get("sufficient_project_count", 0),
                MIN_COHORT_PROJECTS)
            if len(recommendations) >= MAX_RECOMMENDATIONS:
                break
    if not recommendations:
        add("no-cohort-policy-change", "low", "eligible_projects",
            len(eligible), MIN_COHORT_PROJECTS)

    policy = {
        "replacement_zero_gain_rounds": threshold,
        "source": "cross-project-replay",
        "applies_only_to": "research-guidance-scheduling",
        "minimum_projects": MIN_COHORT_PROJECTS,
        "eligible_projects": len(eligible),
        "decision_basis": policy_basis,
        "claim_status": COHORT_CLAIM_STATUS,
    }
    digest = _digest({
        "projects": deduped,
        "metrics": metrics,
        "policy": policy,
    })
    return {
        "schema_version": COHORT_SCHEMA_VERSION,
        "status": status,
        "cohort_digest": digest,
        "metrics": metrics,
        "policy": policy,
        "projects": deduped,
        "surfaces": surfaces,
        "recommendations": recommendations[:MAX_RECOMMENDATIONS],
        "claim_status": COHORT_CLAIM_STATUS,
    }


def calibrate_replay_cohort(
        artifacts: Sequence[Any],
        project_ids: Optional[Sequence[str]] = None,
        ) -> Dict[str, Any]:
    """Build a cohort artifact from normalized calibration JSON values.

    ``artifacts`` may contain calibration dictionaries directly or wrappers of
    the form ``{"calibration": <artifact>, "project_id": "label"}``.
    Explicit labels are used only to derive opaque project IDs.
    """
    rows: List[Dict[str, Any]] = []
    labels = list(project_ids or [])
    for index, item in enumerate(artifacts or []):
        label = labels[index] if index < len(labels) else ""
        raw = item
        if isinstance(item, Mapping) and "calibration" in item:
            raw = item.get("calibration")
            label = _text(item.get("project_id"), 96) or label
        row = _project_from_calibration(raw, label=label, index=index)
        if row:
            rows.append(row)
        if len(rows) >= MAX_PROJECTS:
            break
    return _build_cohort(rows)


def normalize_replay_cohort(raw: Any) -> Dict[str, Any]:
    """Normalize an artifact and recompute policy from its project rows."""
    if not isinstance(raw, Mapping) or raw.get(
            "schema_version") != COHORT_SCHEMA_VERSION:
        return {}
    projects: List[Dict[str, Any]] = []
    for index, item in enumerate(raw.get("projects") or []):
        row = _normalize_project(item, index)
        if row:
            projects.append(row)
        if len(projects) >= MAX_PROJECTS:
            break
    return _build_cohort(projects)


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        if not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def load_replay_cohort_file(path: Path) -> Dict[str, Any]:
    raw = _read_json(Path(path))
    if isinstance(raw.get("cohort"), Mapping):
        raw = raw["cohort"]
    return normalize_replay_cohort(raw)


def cohort_path(workspace: Path) -> Path:
    return Path(workspace).resolve() / "state" / "coverage" / COHORT_FILENAME


def write_replay_cohort(workspace: Path,
                        cohort: Mapping[str, Any]) -> Path:
    path = cohort_path(workspace)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = normalize_replay_cohort(cohort)
    if not payload:
        payload = _build_cohort([])
    temporary = path.with_name(".%s.tmp.%d" % (path.name, os.getpid()))
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                         encoding="utf-8")
    temporary.replace(path)
    return path


def load_replay_cohort(workspace: Path) -> Dict[str, Any]:
    return load_replay_cohort_file(cohort_path(workspace))


def select_effective_replay_calibration(
        local_calibration: Optional[Mapping[str, Any]],
        cohort: Optional[Mapping[str, Any]],
        ) -> Dict[str, Any]:
    """Select a scheduling policy without letting a cohort override local data.

    The returned value intentionally uses the existing per-target calibration
    shape because ``apply_research_guidance`` already accepts that bounded
    policy.  It is an in-memory adapter, not a replacement for the cohort
    artifact and is never written as if it were target-local evidence.
    """
    local = normalize_replay_calibration(dict(local_calibration or {}))
    local_metrics = local.get("metrics") or {}
    if (local.get("status") == "calibrated" and
            _int(local_metrics.get("replayed_guidance_items"), 0) >=
            MIN_PROJECT_REPLAYS):
        return local
    normalized = normalize_replay_cohort(dict(cohort or {}))
    metrics = normalized.get("metrics") or {}
    policy = normalized.get("policy") or {}
    if (normalized.get("status") != "calibrated" or
            _int(metrics.get("eligible_projects"), 0) < MIN_COHORT_PROJECTS):
        return local
    return {
        "schema_version": CALIBRATION_SCHEMA_VERSION,
        "status": "calibrated",
        "history_digest": _text(normalized.get("cohort_digest"), 48),
        "metrics": {
            "replayed_guidance_items": max(
                MIN_PROJECT_REPLAYS,
                _int(metrics.get("eligible_replayed_guidance_items"), 0)),
        },
        "policy": {
            "replacement_zero_gain_rounds": _int(
                policy.get("replacement_zero_gain_rounds"), 1, 1, 2),
            "source": "cross-project-replay",
            "applies_only_to": "research-guidance-scheduling",
            "cohort_projects": _int(metrics.get("eligible_projects"), 0),
            "claim_status": COHORT_CLAIM_STATUS,
        },
        "provenance": {
            "source_schema": COHORT_SCHEMA_VERSION,
            "cohort_digest": _text(normalized.get("cohort_digest"), 48),
            "claim_status": COHORT_CLAIM_STATUS,
        },
        "claim_status": COHORT_CLAIM_STATUS,
    }
