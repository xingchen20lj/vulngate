"""Deterministic, evidence-aware benchmark scoring for VulnGate.

The benchmark deliberately evaluates *research behaviour*, not just whether a
candidate was emitted.  A run is compared with a small gold manifest that
declares the expected claim state, truth class, evidence contract and (when
applicable) severity.  The scorer never copies run notes, payloads or process
output into its result; it emits bounded ids, booleans and aggregate metrics.

The four load-bearing measurements are:

* negative-result safety: a guarded or unresolved mechanism must not be
  promoted to ``confirmed``;
* repeat rate: the same research key must not be retried indefinitely without
  a declared new-evidence event;
* evidence completeness: a claim is scored against the evidence fields the
  case says are necessary, rather than against candidate count;
* severity calibration: predicted CVSS/severity is compared with the gold
  expectation, including overstatement and absolute error.

All output is research metadata and carries ``claim_status=not-a-finding``.
It must not be used as a vulnerability ledger or as a replacement for G4/G5.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..tools.cvss import base_score
from ..tools.redaction import redact_text


BENCHMARK_SCHEMA_VERSION = "research-benchmark-v1"
BENCHMARK_CLAIM_STATUS = "not-a-finding"
MAX_CASES = 512
MAX_RUNS = 64
MAX_EVIDENCE_FIELDS = 16
MAX_EVENTS = 128
MAX_ID = 160
MAX_SURFACES = 16

RESEARCH_SURFACES = frozenset({
    "web", "protocol", "cloud", "mobile", "native",
})
RESEARCH_TARGET_TYPES = frozenset({
    "web-app", "middleware", "message-rpc", "cloud-service",
    "mobile-app", "native-app",
})
RESEARCH_PRECONDITION_CLASSES = frozenset({
    "default", "single-feature", "app-cooperation", "tool-gap",
    "environment-gap",
})

TRUTH_VULNERABLE = "vulnerable"
TRUTH_NEGATIVE = "negative"
TRUTH_ENVIRONMENT_GAP = "environment-gap"
TRUTH_CLASSES = frozenset({
    TRUTH_VULNERABLE, TRUTH_NEGATIVE, TRUTH_ENVIRONMENT_GAP,
})

STATUS_CONFIRMED = "confirmed"
STATUS_EXCLUDED = "excluded"
STATUS_CANDIDATE = "candidate"
STATUS_MISSING = "missing"
STATUSES = frozenset({
    STATUS_CONFIRMED, STATUS_EXCLUDED, STATUS_CANDIDATE,
})

GAP_EXECUTION_STATES = frozenset({
    "unexecuted", "run-failed", "precondition-unavailable", "gate-blocked",
    "harness-error", "inconclusive", "disabled", "environment-gap",
})

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3,
                  "critical": 4}

# Feedback is deliberately a separate contract from the benchmark result.
# It may change *what gets researched next*, but it is never a finding and it
# never changes G4/G5 or a CVSS value.  Keep this list independent of the
# scheduler module so the evaluator stays usable by offline tooling.
BENCHMARK_FEEDBACK_SCHEMA_VERSION = "research-benchmark-feedback-v1"
BENCHMARK_FEEDBACK_CLAIM_STATUS = BENCHMARK_CLAIM_STATUS
BENCHMARK_TREND_SCHEMA_VERSION = "research-benchmark-trend-v1"
BENCHMARK_FEEDBACK_FACTORS = (
    "reachability", "attacker_control", "security_boundary", "sink_impact",
    "control_gap", "evidence_quality", "coverage_novelty",
)
MAX_FEEDBACK_ALERTS = 8
MAX_FEEDBACK_HINTS = 8
MAX_FEEDBACK_GUIDANCE_ITEMS = 12
MAX_FEEDBACK_WEIGHT_DELTA = 6
MAX_FEEDBACK_SURFACE_GUIDANCE = 16
MAX_FEEDBACK_SURFACE_DELTA = 6
SURFACE_FEEDBACK_METRICS = (
    "observation_coverage", "unsafe_confirmation_rate",
    "environment_gap_fidelity", "evidence_completeness",
)
TREND_METRICS = (
    "case_observation_coverage", "confirmed_precision", "confirmed_recall",
    "resolution_accuracy", "unsafe_confirmation_rate",
    "negative_result_fidelity", "environment_gap_fidelity",
    "evidence_completeness", "decision_stability", "repeat_rate",
    "unjustified_repeat_rate", "severity_overstatement_rate",
    "severity_ordinal_overstatement_rate", "severity_mean_absolute_error",
)
TREND_HIGHER_IS_BETTER = frozenset({
    "case_observation_coverage", "confirmed_precision", "confirmed_recall",
    "resolution_accuracy", "negative_result_fidelity",
    "environment_gap_fidelity", "evidence_completeness", "decision_stability",
})
TREND_REGRESSION_THRESHOLDS = {
    "unsafe_confirmation_rate": 0.0,
    "severity_overstatement_rate": 0.05,
    "severity_ordinal_overstatement_rate": 0.05,
    "severity_mean_absolute_error": 0.5,
}
MAX_TREND_REGRESSIONS = 16
BENCHMARK_FEEDBACK_ALERT_CODES = frozenset({
    "unsafe-confirmation", "evidence-completeness-low",
    "unjustified-repeat-high", "environment-gap-fidelity-low",
    "severity-overstatement-high", "decision-stability-low",
    "benchmark-regression",
})
BENCHMARK_FEEDBACK_ACTIONS = frozenset({
    "tighten-confirmation-evidence", "require-missing-evidence",
    "increase-novelty-differential-probes", "preserve-and-probe-preconditions",
    "tighten-severity-calibration", "stabilize-resolution-evidence",
    "stabilize-regression",
})
BENCHMARK_FEEDBACK_TAGS = frozenset({
    "benchmark-confirmation-safety", "benchmark-evidence-completeness",
    "benchmark-novelty-followup", "benchmark-precondition-probe",
    "benchmark-severity-calibration", "benchmark-decision-stability",
    "benchmark-surface-coverage", "benchmark-regression-control",
})
BENCHMARK_FEEDBACK_OBSERVATIONS = frozenset({
    "TYPED_EFFECT must match the claimed impact before confirmation",
    "required evidence fields must be observed or explicitly unsupported",
    "new evidence or a differential probe is required before repeating a key",
    "record the required runtime/precondition before interpreting a result",
    "severity must be consistent with observed typed effect and precondition tier",
    "repeat the decision only with an independent bounded observation",
    "each research surface needs an observed status or explicit execution gap",
    "compare a regression with an independent bounded observation",
})
BENCHMARK_FEEDBACK_FALSIFIERS = frozenset({
    "a missing typed effect keeps the case candidate/pending",
    "missing required evidence is not a negative result",
    "an exact repeat without new evidence remains unjustified",
    "precondition-unavailable cannot be classified as excluded",
    "an unobserved stronger effect keeps the conservative severity",
    "a status change without new evidence is not a valid resolution",
    "unobserved surface coverage is not evidence of absence",
    "an isolated trend delta is not runtime proof",
})
BENCHMARK_FEEDBACK_HINTS = frozenset({
    "存在错误确认：下一轮优先补齐与声明影响一致的 typed effect，不能靠改阈值掩盖。",
    "证据完整度偏低：下一轮把缺失字段转成显式实验观测。",
    "无新证据重复率偏高：优先做版本/路径/控制差分，避免原样重跑。",
    "环境缺口保真度偏低：先补 runtime/前置条件探针，再解释负结果。",
    "严重性夸大偏高：下一轮补 typed effect 与前置一致性检查；不自动改 CVSS。",
    "决策稳定性偏低：为状态变化补独立、可复核的观测。",
    "纵向评测出现退化：下一轮用独立、可复核的观测定位回归；不自动改变漏洞结论。",
})


def _finite_number(value: Any) -> Optional[float]:
    """Return a finite numeric value, never a NaN/Infinity feedback input."""
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _bounded_int(value: Any, default: int = 0, limit: int = 1000000) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(-limit, min(limit, number))


def _text(value: Any, limit: int = MAX_ID) -> str:
    try:
        value = redact_text(value)
    except Exception:  # pragma: no cover - defensive redaction boundary
        value = str(value)
    return " ".join(str(value).replace("\x00", "").split())[:limit]


def _bounded_strings(value: Any, limit: int, item_limit: int = MAX_ID) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        value = [value]
    if not isinstance(value, (list, tuple, set)):
        return []
    out: List[str] = []
    seen = set()
    for item in value:
        item = _text(item, item_limit)
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
        if len(out) >= limit:
            break
    return out


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    if value is None:
        return False
    return str(value).strip().lower() not in {"", "0", "false", "no", "none", "null"}


def _normal_status(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text.startswith(("确认", "confirmed", "true-positive", "tp")):
        return STATUS_CONFIRMED
    if text.startswith(("排除", "excluded", "negative", "true-negative", "tn")):
        return STATUS_EXCLUDED
    if text.startswith(("候选", "待验证", "candidate", "pending", "uncertain")):
        return STATUS_CANDIDATE
    return STATUS_MISSING


def _normal_truth(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"vulnerable", "positive", "true", "tp", "bug"}:
        return TRUTH_VULNERABLE
    if text in {"negative", "benign", "false", "tn", "not-vulnerable"}:
        return TRUTH_NEGATIVE
    if text in {"environment-gap", "gap", "blocked", "inconclusive"}:
        return TRUTH_ENVIRONMENT_GAP
    return ""


def _expected_status(raw: Dict[str, Any], truth: str) -> str:
    expected = raw.get("expected") if isinstance(raw.get("expected"), dict) else {}
    value = raw.get("expected_status", expected.get("status"))
    status = _normal_status(value)
    if status != STATUS_MISSING:
        return status
    if truth == TRUTH_VULNERABLE:
        return STATUS_CONFIRMED
    if truth == TRUTH_NEGATIVE:
        return STATUS_EXCLUDED
    return STATUS_CANDIDATE


def _expected_severity(raw: Dict[str, Any]) -> Dict[str, Any]:
    value = raw.get("expected_severity", raw.get("severity"))
    if not isinstance(value, dict):
        value = {"severity": value} if value not in (None, "") else {}
    out: Dict[str, Any] = {}
    label = _text(value.get("severity", value.get("level")), 24).lower()
    if label in SEVERITY_ORDER:
        out["severity"] = label.title() if label != "none" else "None"
    try:
        score = float(value.get("score"))
        if math.isfinite(score) and 0.0 <= score <= 10.0:
            out["score"] = round(score, 1)
    except (TypeError, ValueError):
        pass
    return out


def _benchmark_metric_snapshot(result: Dict[str, Any]) -> Dict[str, float]:
    """Extract only comparable aggregate metrics from a benchmark result."""
    metrics = result.get("metrics") if isinstance(result, dict) else None
    if not isinstance(metrics, dict):
        return {}
    snapshot: Dict[str, float] = {}
    for name in TREND_METRICS:
        value: Any = metrics.get(name)
        if name == "repeat_rate":
            repeat = metrics.get("repeat")
            value = repeat.get(name) if isinstance(repeat, dict) else None
        elif name == "unjustified_repeat_rate":
            repeat = metrics.get("repeat")
            value = repeat.get(name) if isinstance(repeat, dict) else None
        elif name == "severity_overstatement_rate":
            severity = metrics.get("severity_calibration")
            value = severity.get("overstatement_rate") \
                if isinstance(severity, dict) else None
        elif name == "severity_ordinal_overstatement_rate":
            severity = metrics.get("severity_calibration")
            value = severity.get("ordinal_overstatement_rate") \
                if isinstance(severity, dict) else None
        elif name == "severity_mean_absolute_error":
            severity = metrics.get("severity_calibration")
            value = severity.get("mean_absolute_error") \
                if isinstance(severity, dict) else None
        number = _finite_number(value)
        if number is not None:
            snapshot[name] = round(max(0.0, min(10.0, number)), 4)
    return snapshot


def _trend_regressed(metric: str, delta: float) -> bool:
    threshold = float(TREND_REGRESSION_THRESHOLDS.get(metric, 0.05))
    if metric in TREND_HIGHER_IS_BETTER:
        return delta < -threshold
    return delta > threshold


def compare_benchmark_results(current: Dict[str, Any],
                              baseline: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two bounded benchmark results without copying case evidence.

    The result is a research-quality trend artifact.  It records only fixed
    aggregate metric names, bounded numbers and allowlisted surfaces; it never
    treats a regression as a finding or as proof about a target.
    """
    if not isinstance(current, dict) or not isinstance(baseline, dict):
        return {}
    current_metrics = _benchmark_metric_snapshot(current)
    baseline_metrics = _benchmark_metric_snapshot(baseline)
    if not current_metrics or not baseline_metrics:
        return {}

    metric_deltas: Dict[str, Dict[str, Any]] = {}
    regressions: List[Dict[str, Any]] = []
    for metric in TREND_METRICS:
        if metric not in current_metrics or metric not in baseline_metrics:
            continue
        before = baseline_metrics[metric]
        after = current_metrics[metric]
        delta = round(after - before, 4)
        threshold = float(TREND_REGRESSION_THRESHOLDS.get(metric, 0.05))
        regression = _trend_regressed(metric, delta)
        metric_deltas[metric] = {
            "baseline": before,
            "current": after,
            "delta": delta,
            "threshold": threshold,
            "regression": regression,
        }
        if regression:
            regressions.append({
                "metric": metric,
                "baseline": before,
                "current": after,
                "delta": delta,
                "threshold": threshold,
                "claim_status": BENCHMARK_CLAIM_STATUS,
            })

    current_by_surface = (current.get("metrics", {}).get("coverage_by_surface")
                          if isinstance(current.get("metrics"), dict) else {})
    baseline_by_surface = (baseline.get("metrics", {}).get("coverage_by_surface")
                           if isinstance(baseline.get("metrics"), dict) else {})
    surface_deltas: Dict[str, Dict[str, Any]] = {}
    surface_regressions: List[Dict[str, Any]] = []
    if isinstance(current_by_surface, dict) and isinstance(baseline_by_surface, dict):
        for surface in sorted(set(current_by_surface) & set(baseline_by_surface)):
            if surface not in RESEARCH_SURFACES:
                continue
            current_row = current_by_surface.get(surface)
            baseline_row = baseline_by_surface.get(surface)
            if not isinstance(current_row, dict) or not isinstance(baseline_row, dict):
                continue
            row_metrics: Dict[str, Dict[str, Any]] = {}
            row_regressions: List[str] = []
            for metric in SURFACE_FEEDBACK_METRICS:
                before = _finite_number(baseline_row.get(metric))
                after = _finite_number(current_row.get(metric))
                if before is None or after is None:
                    continue
                before = round(max(0.0, min(1.0, before)), 4)
                after = round(max(0.0, min(1.0, after)), 4)
                delta = round(after - before, 4)
                threshold = float(TREND_REGRESSION_THRESHOLDS.get(metric, 0.05))
                regression = _trend_regressed(metric, delta)
                row_metrics[metric] = {
                    "baseline": before,
                    "current": after,
                    "delta": delta,
                    "threshold": threshold,
                    "regression": regression,
                }
                if regression:
                    row_regressions.append(metric)
                    surface_regressions.append({
                        "surface": surface,
                        "metric": metric,
                        "baseline": before,
                        "current": after,
                        "delta": delta,
                        "threshold": threshold,
                        "claim_status": BENCHMARK_CLAIM_STATUS,
                    })
            if row_metrics:
                surface_deltas[surface] = {
                    "metrics": row_metrics,
                    "regressions": row_regressions,
                    "claim_status": BENCHMARK_CLAIM_STATUS,
                }

    return {
        "schema_version": BENCHMARK_TREND_SCHEMA_VERSION,
        "baseline_benchmark_id": _text(baseline.get("benchmark_id"), 120)
                                  or "baseline",
        "current_benchmark_id": _text(current.get("benchmark_id"), 120)
                                 or "current",
        "metric_deltas": metric_deltas,
        "surface_deltas": surface_deltas,
        "regressions": regressions[:MAX_TREND_REGRESSIONS],
        "surface_regressions": surface_regressions[:MAX_TREND_REGRESSIONS],
        "status": ("regressed" if regressions or surface_regressions
                    else "stable"),
        "claim_status": BENCHMARK_CLAIM_STATUS,
    }


def normalize_benchmark_trend(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only bounded regression signals usable by feedback consumers."""
    if not isinstance(raw, dict) or raw.get("schema_version") != BENCHMARK_TREND_SCHEMA_VERSION:
        return {}
    regressions: List[Dict[str, Any]] = []
    for item in raw.get("regressions") or []:
        if not isinstance(item, dict) or item.get("metric") not in TREND_METRICS:
            continue
        values = {name: _finite_number(item.get(name))
                  for name in ("baseline", "current", "delta", "threshold")}
        if any(value is None for value in values.values()):
            continue
        regressions.append({
            "metric": item["metric"],
            "baseline": round(max(0.0, min(10.0, values["baseline"])), 4),
            "current": round(max(0.0, min(10.0, values["current"])), 4),
            "delta": round(max(-10.0, min(10.0, values["delta"])), 4),
            "threshold": round(max(0.0, min(10.0, values["threshold"])), 4),
        })
        if len(regressions) >= MAX_TREND_REGRESSIONS:
            break
    surface_regressions: List[Dict[str, Any]] = []
    for item in raw.get("surface_regressions") or []:
        if not isinstance(item, dict):
            continue
        surface = _text(item.get("surface"), 32).lower()
        metric = item.get("metric")
        if surface not in RESEARCH_SURFACES or metric not in SURFACE_FEEDBACK_METRICS:
            continue
        values = {name: _finite_number(item.get(name))
                  for name in ("baseline", "current", "delta", "threshold")}
        if any(value is None for value in values.values()):
            continue
        surface_regressions.append({
            "surface": surface,
            "metric": metric,
            "baseline": round(max(0.0, min(1.0, values["baseline"])), 4),
            "current": round(max(0.0, min(1.0, values["current"])), 4),
            "delta": round(max(-1.0, min(1.0, values["delta"])), 4),
            "threshold": round(max(0.0, min(1.0, values["threshold"])), 4),
        })
        if len(surface_regressions) >= MAX_TREND_REGRESSIONS:
            break
    if not regressions and not surface_regressions:
        return {}
    return {
        "schema_version": BENCHMARK_TREND_SCHEMA_VERSION,
        "baseline_benchmark_id": _text(raw.get("baseline_benchmark_id"), 120),
        "current_benchmark_id": _text(raw.get("current_benchmark_id"), 120),
        "regressions": regressions,
        "surface_regressions": surface_regressions,
        "status": "regressed",
        "claim_status": BENCHMARK_CLAIM_STATUS,
    }


def normalize_case(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a gold case without retaining free-form case prose."""
    if not isinstance(raw, dict):
        return {}
    case_id = _text(raw.get("case_id", raw.get("id")), MAX_ID)
    truth = _normal_truth(raw.get("truth", raw.get("label")))
    if not case_id or truth not in TRUTH_CLASSES:
        return {}
    expected = raw.get("expected") if isinstance(raw.get("expected"), dict) else {}
    evidence = raw.get("required_evidence", expected.get("required_evidence", []))
    required = _bounded_strings(evidence, MAX_EVIDENCE_FIELDS, 80)
    out = {
        "case_id": case_id,
        "truth": truth,
        "expected_status": _expected_status(raw, truth),
        "expected_severity": _expected_severity(raw),
        "required_evidence": required,
        "mechanism_key": _text(raw.get("mechanism_key", raw.get("research_key", "")), 80),
        "category": _text(raw.get("category", ""), 80),
    }
    surface = _text(raw.get("surface", raw.get("research_surface", "")), 32).lower()
    target_type = _text(raw.get("target_type", ""), 32).lower()
    attack_class = _text(raw.get("attack_class", ""), 64).lower()
    variant = _text(raw.get("variant", ""), 80).lower()
    precondition_class = _text(raw.get("precondition_class", ""), 32).lower()
    if surface:
        out["surface"] = surface
    if target_type:
        out["target_type"] = target_type
    if attack_class:
        out["attack_class"] = attack_class
    if variant:
        out["variant"] = variant
    if precondition_class:
        out["precondition_class"] = precondition_class
    return out


def normalize_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(manifest, dict):
        return {}
    cases = []
    seen = set()
    for raw in manifest.get("cases") or []:
        case = normalize_case(raw)
        if not case or case["case_id"] in seen:
            continue
        seen.add(case["case_id"])
        cases.append(case)
        if len(cases) >= MAX_CASES:
            break
    return {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "benchmark_id": _text(manifest.get("benchmark_id", manifest.get("name", "benchmark")), 120),
        "cases": cases,
        "claim_status": BENCHMARK_CLAIM_STATUS,
    }


def validate_manifest(manifest: Dict[str, Any]) -> List[str]:
    """Return deterministic schema errors instead of silently changing gold."""
    errors: List[str] = []
    if not isinstance(manifest, dict):
        return ["manifest must be a JSON object"]
    schema = manifest.get("schema_version")
    if schema not in (None, BENCHMARK_SCHEMA_VERSION):
        errors.append("schema_version must be %s" % BENCHMARK_SCHEMA_VERSION)
    raw_cases = manifest.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        errors.append("cases must be a non-empty list")
        return errors
    seen = set()
    for index, raw in enumerate(raw_cases[:MAX_CASES]):
        if not isinstance(raw, dict):
            errors.append("case[%d] must be an object" % index)
            continue
        case_id = _text(raw.get("case_id", raw.get("id")), MAX_ID)
        truth = _normal_truth(raw.get("truth", raw.get("label")))
        if not case_id:
            errors.append("case[%d] has no case_id" % index)
        elif case_id in seen:
            errors.append("duplicate case_id: %s" % case_id)
        else:
            seen.add(case_id)
        if truth not in TRUTH_CLASSES:
            errors.append("case[%d] has unsupported truth" % index)
        expected = raw.get("expected") if isinstance(raw.get("expected"), dict) else {}
        raw_status = raw.get("expected_status", expected.get("status"))
        if raw_status not in (None, "") and _normal_status(raw_status) == STATUS_MISSING:
            errors.append("case[%d] has unsupported expected_status" % index)
        severity = _expected_severity(raw)
        if raw.get("expected_severity") is not None or raw.get("severity") is not None:
            if not severity:
                errors.append("case[%d] has invalid expected_severity" % index)
        surface = _text(raw.get("surface", raw.get("research_surface", "")), 32).lower()
        if surface and surface not in RESEARCH_SURFACES:
            errors.append("case[%d] has unsupported surface" % index)
        target_type = _text(raw.get("target_type", ""), 32).lower()
        if target_type and target_type not in RESEARCH_TARGET_TYPES:
            errors.append("case[%d] has unsupported target_type" % index)
        precondition_class = _text(raw.get("precondition_class", ""), 32).lower()
        if precondition_class and precondition_class not in RESEARCH_PRECONDITION_CLASSES:
            errors.append("case[%d] has unsupported precondition_class" % index)
        for field_name in ("attack_class", "variant"):
            if raw.get(field_name) not in (None, ""):
                value = _text(raw.get(field_name), 100)
                if not value:
                    errors.append("case[%d] has invalid %s" % (index, field_name))
    if len(raw_cases) > MAX_CASES:
        errors.append("cases exceeds limit %d" % MAX_CASES)
    return errors


def _evidence_map(row: Dict[str, Any]) -> Dict[str, Any]:
    value = row.get("evidence")
    if isinstance(value, dict):
        return value
    return {}


def _evidence_present(row: Dict[str, Any], field: str) -> bool:
    evidence = _evidence_map(row)
    aliases = {
        "source_to_sink": ("source_to_sink", "source_sink", "dataflow", "flow"),
        "runtime_effect": ("runtime_effect", "effect_evidence", "typed_effect"),
        "typed_effect": ("typed_effect",),
        "authz_boundary": ("authz_boundary", "authz_matrix", "authz_result"),
        "negative_runtime": ("negative_runtime", "negative_observation", "no_effect"),
        "environment_gap": ("environment_gap", "precondition_gap", "harness_gap"),
        "guard_evidence": ("guard_evidence", "control_map", "control_verdict"),
        "novelty_status": ("novelty_status", "novelty", "novelty_verdict"),
        "severity": ("severity", "cvss"),
        "precondition": ("precondition", "preconditions"),
        "reproduction": ("reproduction", "repro", "runtime_lab"),
        "fix_variant": ("fix_variant", "patch_variant", "fix_completeness"),
    }
    keys = aliases.get(field, (field,))
    if any(_truthy(evidence.get(key)) for key in keys):
        return True
    # Ledger rows often have typed state outside the evidence object.
    state = str(row.get("execution_state", row.get("state", ""))).strip().lower()
    if field in {"environment_gap", "precondition"} and state in GAP_EXECUTION_STATES:
        return True
    if field == "negative_runtime" and state == "executed-no-effect":
        return True
    # A list of evidence labels is accepted only for known labels; arbitrary
    # prose is not copied or interpreted as proof.
    labels = list(row.get("evidence_labels") or [])
    if isinstance(row.get("evidence"), list):
        labels.extend(row.get("evidence") or [])
    label_text = " ".join(_text(item, 120).lower() for item in labels)
    if field.lower() in label_text:
        return True
    return any(alias.lower() in label_text for alias in aliases.get(field, (field,)))


def _research_events(row: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw = row.get("research_events", row.get("events", row.get("attempts", [])))
    if isinstance(raw, dict):
        raw = [raw]
    events: List[Dict[str, Any]] = []
    if isinstance(raw, list):
        for item in raw[:MAX_EVENTS]:
            if not isinstance(item, dict):
                continue
            key = _text(item.get("research_key", item.get("key", "")), 80)
            if not key:
                continue
            try:
                round_no = int(item.get("round", 0) or 0)
            except (TypeError, ValueError):
                round_no = 0
            events.append({
                "research_key": key,
                "round": max(0, round_no),
                "new_evidence": bool(item.get("new_evidence", False)),
            })
    research = row.get("research")
    research_key = research.get("research_key") if isinstance(research, dict) else ""
    key = _text(row.get("research_key") or research_key, 80)
    if key and not events:
        events.append({
            "research_key": key,
            "round": max(0, int(row.get("round", 0) or 0))
            if str(row.get("round", 0)).lstrip("-").isdigit() else 0,
            "new_evidence": bool(row.get("new_evidence", False)),
        })
    return events[:MAX_EVENTS]


def normalize_observation(raw: Dict[str, Any], fallback_case_id: str = "") -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {"case_id": fallback_case_id, "status": STATUS_MISSING,
                "evidence": {}, "events": []}
    case_id = _text(raw.get("case_id", raw.get("candidate_id", fallback_case_id)), MAX_ID)
    status = _normal_status(raw.get("status", raw.get("observed_status", raw.get("conclusion", raw.get("verdict")))))
    evidence = _evidence_map(raw)
    events = _research_events(raw)
    cvss = raw.get("cvss", raw.get("severity"))
    cvss_view: Dict[str, Any] = {}
    if isinstance(cvss, dict):
        vector = _text(cvss.get("vector"), 80)
        if vector:
            cvss_view["vector"] = vector
        try:
            score = float(cvss.get("score"))
            if math.isfinite(score) and 0.0 <= score <= 10.0:
                cvss_view["score"] = round(score, 1)
        except (TypeError, ValueError):
            pass
        label = _text(cvss.get("severity", cvss.get("level")), 24).lower()
        if label in SEVERITY_ORDER:
            cvss_view["severity"] = label.title() if label != "none" else "None"
    elif isinstance(cvss, str) and cvss.lower() in SEVERITY_ORDER:
        cvss_view["severity"] = cvss.title()
    state = _text(raw.get("execution_state", raw.get("state", "")), 80).lower()
    return {
        "case_id": case_id,
        "status": status,
        "evidence": evidence,
        "events": events,
        "cvss": cvss_view,
        "execution_state": state,
        "claim_status": BENCHMARK_CLAIM_STATUS,
    }


def normalize_run(raw: Dict[str, Any], index: int = 0) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raw = {}
    run_id = _text(raw.get("run_id", raw.get("id", "run-%02d" % (index + 1))), 120)
    source = raw.get("observations", raw.get("results", raw.get("rows", [])))
    rows: List[Dict[str, Any]] = []
    if isinstance(source, dict):
        for case_id, value in source.items():
            if isinstance(value, dict):
                rows.append(normalize_observation(value, str(case_id)))
    elif isinstance(source, list):
        rows = [normalize_observation(item) for item in source if isinstance(item, dict)]
    return {"run_id": run_id, "observations": rows[:MAX_CASES]}


def _merge_observations(rows: Sequence[Dict[str, Any]], case_id: str) -> Dict[str, Any]:
    if not rows:
        return normalize_observation({}, case_id)
    merged = dict(rows[0])
    merged["case_id"] = case_id
    merged["events"] = []
    merged["evidence"] = {}
    for row in rows:
        if row.get("status") != STATUS_MISSING:
            merged["status"] = row["status"]
        merged["evidence"].update(row.get("evidence") or {})
        merged["events"].extend(row.get("events") or [])
        if row.get("cvss"):
            merged["cvss"] = dict(row["cvss"])
        if row.get("execution_state"):
            merged["execution_state"] = row["execution_state"]
    merged["events"] = merged["events"][:MAX_EVENTS]
    merged["claim_status"] = BENCHMARK_CLAIM_STATUS
    return merged


def _observed_severity(row: Dict[str, Any]) -> Dict[str, Any]:
    value = dict(row.get("cvss") or {})
    score = value.get("score")
    vector = value.get("vector")
    if score is None and vector:
        try:
            score, label = base_score(str(vector))
            value["score"] = round(float(score), 1)
            value["severity"] = label
        except (KeyError, TypeError, ValueError):
            pass
    elif score is not None and "severity" not in value:
        try:
            numeric = float(score)
            value["severity"] = ("None" if numeric == 0 else "Low" if numeric < 4
                                  else "Medium" if numeric < 7 else "High" if numeric < 9
                                  else "Critical")
        except (TypeError, ValueError):
            pass
    return value


def _severity_result(expected: Dict[str, Any], observed: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "expected": dict(expected),
        "observed": dict(observed),
    }
    if "score" in expected and "score" in observed:
        error = abs(float(observed["score"]) - float(expected["score"]))
        out["absolute_error"] = round(error, 3)
        out["within_one_point"] = error <= 1.0
        out["overstated"] = float(observed["score"]) > float(expected["score"]) + 0.5
    exp_label = str(expected.get("severity", "")).lower()
    obs_label = str(observed.get("severity", "")).lower()
    if exp_label in SEVERITY_ORDER and obs_label in SEVERITY_ORDER:
        ordinal_error = abs(SEVERITY_ORDER[obs_label] - SEVERITY_ORDER[exp_label])
        out["ordinal_error"] = ordinal_error
        out["ordinal_overstated"] = SEVERITY_ORDER[obs_label] > SEVERITY_ORDER[exp_label]
    return out


def _case_classification(truth: str, expected_status: str,
                         observed_status: str, row: Dict[str, Any]) -> str:
    if observed_status == STATUS_MISSING:
        return "missing-observation"
    if truth == TRUTH_VULNERABLE:
        if expected_status == STATUS_CANDIDATE and observed_status == STATUS_CANDIDATE:
            return "pending-preserved"
        return "true-positive" if observed_status == STATUS_CONFIRMED else "false-negative"
    if truth == TRUTH_NEGATIVE:
        if observed_status == STATUS_CONFIRMED:
            return "unsafe-false-positive"
        if observed_status == expected_status:
            return ("true-negative" if observed_status == STATUS_EXCLUDED
                    else "negative-pending-preserved")
        return "safe-uncertain" if observed_status == STATUS_CANDIDATE else "negative-status-mismatch"
    # An environment gap is a separate class: exclusion is not a valid way to
    # make an unavailable test look clean.
    if observed_status == STATUS_CANDIDATE and _evidence_present(row, "environment_gap"):
        return "gap-preserved"
    if observed_status == STATUS_CANDIDATE:
        return "gap-untyped"
    return "gap-misclassified"


def _score_case(case: Dict[str, Any], row: Dict[str, Any], run_id: str) -> Dict[str, Any]:
    required = list(case.get("required_evidence") or [])
    present = [field for field in required if _evidence_present(row, field)]
    missing = [field for field in required if field not in present]
    completeness = (len(present) / len(required)) if required else 1.0
    observed_status = str(row.get("status") or STATUS_MISSING)
    severity = _severity_result(case.get("expected_severity") or {},
                               _observed_severity(row))
    return {
        "run_id": run_id,
        "case_id": case["case_id"],
        "truth": case["truth"],
        "surface": case.get("surface", ""),
        "target_type": case.get("target_type", ""),
        "attack_class": case.get("attack_class", ""),
        "variant": case.get("variant", ""),
        "precondition_class": case.get("precondition_class", ""),
        "expected_status": case["expected_status"],
        "observed_status": observed_status,
        "classification": _case_classification(
            case["truth"], case["expected_status"], observed_status, row),
        "evidence": {
            "required": required,
            "present": present,
            "missing": missing,
            "completeness": round(completeness, 4),
        },
        "severity": severity,
        "research_keys": sorted({str(event.get("research_key"))
                                  for event in row.get("events") or []
                                  if event.get("research_key")}),
        "attempt_count": len(row.get("events") or []),
        "claim_status": BENCHMARK_CLAIM_STATUS,
    }


def _repeat_metrics(normalized_runs: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    total = duplicate = unjustified = unique = 0
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for run in normalized_runs:
        for row in run.get("observations") or []:
            for event in row.get("events") or []:
                groups[(str(run.get("run_id")), str(row.get("case_id")))].append(event)
    for events in groups.values():
        seen = set()
        for event in sorted(events, key=lambda item: (int(item.get("round", 0) or 0),
                                                       str(item.get("research_key", "")))):
            key = str(event.get("research_key") or "")
            if not key:
                continue
            total += 1
            if key in seen:
                duplicate += 1
                if not event.get("new_evidence"):
                    unjustified += 1
            else:
                unique += 1
                seen.add(key)
    return {
        "attempts": total,
        "unique_research_keys": unique,
        "duplicate_attempts": duplicate,
        "unjustified_duplicate_attempts": unjustified,
        "repeat_rate": round(duplicate / total, 4) if total else None,
        "unjustified_repeat_rate": round(unjustified / total, 4) if total else None,
    }


def _aggregate_case_results(results: Sequence[Dict[str, Any]],
                            cases: Sequence[Dict[str, Any]],
                            normalized_runs: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(results)
    observed = [r for r in results if r["observed_status"] != STATUS_MISSING]
    tp = sum(r["classification"] == "true-positive" for r in results)
    unsafe = sum(r["classification"] == "unsafe-false-positive" for r in results)
    confirmed = sum(r["observed_status"] == STATUS_CONFIRMED for r in observed)
    vulnerable = sum(r["truth"] == TRUTH_VULNERABLE
                     and r["expected_status"] == STATUS_CONFIRMED
                     for r in results)
    negative = [r for r in results if r["truth"] == TRUTH_NEGATIVE]
    gaps = [r for r in results if r["truth"] == TRUTH_ENVIRONMENT_GAP]
    exact = sum(r["observed_status"] == r["expected_status"] for r in observed)
    completeness_values = [float(r["evidence"]["completeness"])
                           for r in observed]
    scores = [r["severity"] for r in results if "absolute_error" in r["severity"]]
    ordinals = [r["severity"] for r in results if "ordinal_error" in r["severity"]]
    severity = {
        "cases_with_prediction": len(scores),
        "mean_absolute_error": (round(sum(float(x["absolute_error"]) for x in scores) / len(scores), 3)
                                 if scores else None),
        "within_one_point_rate": (round(sum(bool(x["within_one_point"]) for x in scores) / len(scores), 4)
                                   if scores else None),
        "overstatement_rate": (round(sum(bool(x["overstated"]) for x in scores) / len(scores), 4)
                               if scores else None),
        "ordinal_mean_absolute_error": (round(sum(int(x["ordinal_error"]) for x in ordinals) / len(ordinals), 3)
                                        if ordinals else None),
        "ordinal_overstatement_rate": (round(sum(bool(x["ordinal_overstated"]) for x in ordinals) / len(ordinals), 4)
                                       if ordinals else None),
    }
    # Decision stability is the proportion of case ids whose status agrees
    # across repeated runs. A single run is stable by definition.
    statuses_by_case: Dict[str, List[str]] = defaultdict(list)
    for result in results:
        statuses_by_case[result["case_id"]].append(result["observed_status"])
    stable_cases = sum(len(set(values)) <= 1 for values in statuses_by_case.values())
    coverage_by_truth = {}
    for truth in sorted(TRUTH_CLASSES):
        truth_rows = [r for r in results if r["truth"] == truth]
        truth_observed = [r for r in truth_rows
                          if r["observed_status"] != STATUS_MISSING]
        coverage_by_truth[truth] = round(
            len(truth_observed) / len(truth_rows), 4) if truth_rows else None
    by_surface: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in results:
        surface = str(row.get("surface") or "").strip().lower()
        if surface:
            by_surface[surface].append(row)
    coverage_by_surface: Dict[str, Dict[str, Any]] = {}
    for surface in sorted(by_surface)[:MAX_SURFACES]:
        rows = by_surface[surface]
        observed_rows = [r for r in rows if r["observed_status"] != STATUS_MISSING]
        negative_rows = [r for r in rows if r["truth"] == TRUTH_NEGATIVE]
        gap_rows = [r for r in rows if r["truth"] == TRUTH_ENVIRONMENT_GAP]
        completeness = [float(r["evidence"]["completeness"])
                        for r in observed_rows]
        coverage_by_surface[surface] = {
            "case_results": len(rows),
            "observed_results": len(observed_rows),
            "observation_coverage": round(
                len(observed_rows) / len(rows), 4) if rows else None,
            "unsafe_confirmation_rate": round(
                sum(r["classification"] == "unsafe-false-positive"
                    for r in negative_rows) / len(negative_rows), 4)
            if negative_rows else None,
            "environment_gap_fidelity": round(
                sum(r["classification"] == "gap-preserved"
                    for r in gap_rows) / len(gap_rows), 4)
            if gap_rows else None,
            "evidence_completeness": round(
                sum(completeness) / len(completeness), 4)
            if completeness else None,
            "claim_status": BENCHMARK_CLAIM_STATUS,
        }
    return {
        "case_results": total,
        "observed_results": len(observed),
        "case_observation_coverage": round(len(observed) / total, 4) if total else None,
        "coverage_by_truth": coverage_by_truth,
        "coverage_by_surface": coverage_by_surface,
        "confirmed_precision": round(tp / confirmed, 4) if confirmed else None,
        "confirmed_recall": round(tp / vulnerable, 4) if vulnerable else None,
        "resolution_accuracy": round(exact / len(observed), 4) if observed else None,
        "unsafe_confirmation_rate": round(unsafe / len(negative), 4) if negative else None,
        "negative_result_fidelity": round(sum(r["classification"] in {
            "true-negative", "negative-pending-preserved"} for r in negative) / len(negative), 4)
        if negative else None,
        "environment_gap_fidelity": round(sum(r["classification"] == "gap-preserved" for r in gaps) / len(gaps), 4)
        if gaps else None,
        "evidence_completeness": round(sum(completeness_values) / len(completeness_values), 4)
        if completeness_values else None,
        "evidence_fields_required": sum(len(r["evidence"]["required"]) for r in results),
        "evidence_fields_present": sum(len(r["evidence"]["present"]) for r in results),
        "severity_calibration": severity,
        "decision_stability": round(stable_cases / len(statuses_by_case), 4)
        if statuses_by_case else None,
        "repeat": _repeat_metrics(normalized_runs),
        "classifications": dict(sorted(Counter(r["classification"] for r in results).items())),
        "claim_status": BENCHMARK_CLAIM_STATUS,
    }


def evaluate_benchmark(manifest: Dict[str, Any],
                       runs: Optional[Sequence[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Score one or more deterministic run records against a gold manifest."""
    gold = normalize_manifest(manifest)
    raw_runs: Any = runs
    if raw_runs is None:
        raw_runs = manifest.get("runs") if isinstance(manifest, dict) else None
    if raw_runs is None:
        raw_runs = [manifest] if isinstance(manifest, dict) else []
    if isinstance(raw_runs, dict):
        raw_runs = [raw_runs]
    normalized_runs = []
    seen_run_ids = set()
    for index, raw in enumerate(raw_runs or []):
        if not isinstance(raw, dict):
            continue
        run = normalize_run(raw, index)
        base_id = str(run.get("run_id") or "run-%02d" % (index + 1))
        run_id = base_id
        suffix = 2
        while run_id in seen_run_ids:
            run_id = "%s-%02d" % (base_id, suffix)
            suffix += 1
        run["run_id"] = run_id
        seen_run_ids.add(run_id)
        normalized_runs.append(run)
        if len(normalized_runs) >= MAX_RUNS:
            break
    if not normalized_runs:
        normalized_runs = [normalize_run({}, 0)]

    by_run_case: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for run in normalized_runs:
        for row in run.get("observations") or []:
            if row.get("case_id"):
                by_run_case[(str(run["run_id"]), str(row["case_id"]))].append(row)
    results: List[Dict[str, Any]] = []
    for run in normalized_runs:
        run_id = str(run["run_id"])
        for case in gold.get("cases") or []:
            row = _merge_observations(
                by_run_case.get((run_id, case["case_id"]), []), case["case_id"])
            results.append(_score_case(case, row, run_id))

    metrics = _aggregate_case_results(results, gold.get("cases") or [], normalized_runs)
    gold_cases = gold.get("cases") or []
    profile = {
        "surfaces": sorted({str(case.get("surface")) for case in gold_cases
                             if case.get("surface")})[:MAX_SURFACES],
        "target_types": sorted({str(case.get("target_type")) for case in gold_cases
                                 if case.get("target_type")})[:MAX_SURFACES],
        "variants": sorted({str(case.get("variant")) for case in gold_cases
                             if case.get("variant")})[:MAX_CASES],
        "claim_status": BENCHMARK_CLAIM_STATUS,
    }
    return {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "benchmark_id": gold.get("benchmark_id", "benchmark"),
        "run_count": len(normalized_runs),
        "case_count": len(gold.get("cases") or []),
        "research_profile": profile,
        "metrics": metrics,
        "case_results": results[:MAX_CASES * MAX_RUNS],
        "claim_status": BENCHMARK_CLAIM_STATUS,
    }


def normalize_benchmark_feedback(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only the bounded, scheduling-safe part of benchmark feedback.

    This is an input boundary as well as a renderer.  A caller may hand the
    scheduler an artifact produced by an older version, a hand-written config,
    or an accidentally copied benchmark result.  Only the feedback schema is
    accepted here; arbitrary run rows, prose, payloads and CVSS suggestions
    are intentionally discarded.
    """
    if not isinstance(raw, dict):
        return {}
    if raw.get("schema_version") != BENCHMARK_FEEDBACK_SCHEMA_VERSION:
        return {}
    benchmark_id = _text(raw.get("benchmark_id"), 120)
    raw_snapshot = (raw.get("metric_snapshot")
                    if isinstance(raw.get("metric_snapshot"), dict) else {})
    snapshot: Dict[str, float] = {}
    for name in (
        "case_observation_coverage", "confirmed_precision", "confirmed_recall",
        "resolution_accuracy", "unsafe_confirmation_rate",
        "negative_result_fidelity", "environment_gap_fidelity",
        "evidence_completeness", "decision_stability", "repeat_rate",
        "unjustified_repeat_rate", "severity_overstatement_rate",
        "severity_ordinal_overstatement_rate", "severity_mean_absolute_error",
    ):
        number = _finite_number(raw_snapshot.get(name))
        if number is None:
            continue
        snapshot[name] = round(max(0.0, min(10.0, number)), 4)

    alerts: List[Dict[str, Any]] = []
    for item in raw.get("alerts") or []:
        if not isinstance(item, dict):
            continue
        code = _text(item.get("code"), 80)
        metric = _text(item.get("metric"), 80)
        priority = _text(item.get("priority"), 16).lower()
        action = _text(item.get("action"), 100)
        value = _finite_number(item.get("value"))
        threshold = _finite_number(item.get("threshold"))
        direction = _text(item.get("direction"), 8).lower()
        if (code not in BENCHMARK_FEEDBACK_ALERT_CODES or not metric
                or priority not in {"high", "medium", "low"}
                or action not in BENCHMARK_FEEDBACK_ACTIONS
                or value is None or threshold is None
                or direction not in {"gt", "lt"}):
            continue
        alerts.append({
            "code": code,
            "priority": priority,
            "metric": metric,
            "value": round(value, 4),
            "threshold": round(threshold, 4),
            "direction": direction,
            "action": action,
        })
        if len(alerts) >= MAX_FEEDBACK_ALERTS:
            break

    raw_deltas = (raw.get("weight_deltas")
                  if isinstance(raw.get("weight_deltas"), dict) else {})
    deltas: Dict[str, int] = {}
    for factor in BENCHMARK_FEEDBACK_FACTORS:
        value = _bounded_int(raw_deltas.get(factor), 0,
                             MAX_FEEDBACK_WEIGHT_DELTA)
        if value:
            deltas[factor] = value

    guidance = raw.get("planner_guidance")
    if not isinstance(guidance, dict):
        guidance = {}
    planner_guidance = {
        "strategy_tags": _bounded_strings(
            [item for item in (guidance.get("strategy_tags") or [])
             if isinstance(item, str) and item in BENCHMARK_FEEDBACK_TAGS],
            MAX_FEEDBACK_GUIDANCE_ITEMS, 80),
        "required_observations": _bounded_strings(
            [item for item in (guidance.get("required_observations") or [])
             if isinstance(item, str) and item in BENCHMARK_FEEDBACK_OBSERVATIONS],
            MAX_FEEDBACK_GUIDANCE_ITEMS, 120),
        "falsifiers": _bounded_strings(
            [item for item in (guidance.get("falsifiers") or [])
             if isinstance(item, str) and item in BENCHMARK_FEEDBACK_FALSIFIERS],
            MAX_FEEDBACK_GUIDANCE_ITEMS, 160),
    }
    surface_guidance: List[Dict[str, Any]] = []
    seen_surfaces = set()
    for item in raw.get("surface_guidance") or []:
        if not isinstance(item, dict):
            continue
        surface = _text(item.get("surface"), 32).lower()
        if surface not in RESEARCH_SURFACES or surface in seen_surfaces:
            continue
        raw_surface_snapshot = (item.get("metric_snapshot")
                                if isinstance(item.get("metric_snapshot"), dict)
                                else {})
        surface_snapshot: Dict[str, float] = {}
        for name in SURFACE_FEEDBACK_METRICS:
            number = _finite_number(raw_surface_snapshot.get(name))
            if number is None:
                continue
            surface_snapshot[name] = round(max(0.0, min(1.0, number)), 4)
        priority_delta = _bounded_int(
            item.get("priority_delta"), 0, MAX_FEEDBACK_SURFACE_DELTA)
        tags = _bounded_strings(
            [value for value in (item.get("strategy_tags") or [])
             if isinstance(value, str) and value in BENCHMARK_FEEDBACK_TAGS],
            MAX_FEEDBACK_GUIDANCE_ITEMS, 80)
        required = _bounded_strings(
            [value for value in (item.get("required_observations") or [])
             if isinstance(value, str) and value in BENCHMARK_FEEDBACK_OBSERVATIONS],
            MAX_FEEDBACK_GUIDANCE_ITEMS, 120)
        falsifiers = _bounded_strings(
            [value for value in (item.get("falsifiers") or [])
             if isinstance(value, str) and value in BENCHMARK_FEEDBACK_FALSIFIERS],
            MAX_FEEDBACK_GUIDANCE_ITEMS, 160)
        if not (surface_snapshot or priority_delta or tags or required or falsifiers):
            continue
        seen_surfaces.add(surface)
        surface_guidance.append({
            "surface": surface,
            "priority_delta": priority_delta,
            "metric_snapshot": surface_snapshot,
            "strategy_tags": tags,
            "required_observations": required,
            "falsifiers": falsifiers,
            "claim_status": BENCHMARK_FEEDBACK_CLAIM_STATUS,
        })
        if len(surface_guidance) >= MAX_FEEDBACK_SURFACE_GUIDANCE:
            break
    surface_guidance.sort(key=lambda item: str(item.get("surface")))
    trend = normalize_benchmark_trend(raw.get("trend") or {})
    hints = _bounded_strings(
        [item for item in (raw.get("prompt_hints") or [])
         if isinstance(item, str) and item in BENCHMARK_FEEDBACK_HINTS],
        MAX_FEEDBACK_HINTS, 180)
    source = raw.get("source") if isinstance(raw.get("source"), dict) else {}
    return {
        "schema_version": BENCHMARK_FEEDBACK_SCHEMA_VERSION,
        "benchmark_id": benchmark_id or "benchmark",
        "source": {
            "benchmark_id": _text(source.get("benchmark_id"), 120)
                           or benchmark_id or "benchmark",
            "run_count": max(0, min(MAX_RUNS, _bounded_int(source.get("run_count")))),
            "case_count": max(0, min(MAX_CASES, _bounded_int(source.get("case_count")))),
        },
        "metric_snapshot": snapshot,
        "alerts": alerts,
        "weight_deltas": deltas,
        "planner_guidance": planner_guidance,
        "surface_guidance": surface_guidance,
        "trend": trend,
        "prompt_hints": hints,
        "claim_status": BENCHMARK_FEEDBACK_CLAIM_STATUS,
    }


def derive_benchmark_feedback(result: Dict[str, Any]) -> Dict[str, Any]:
    """Turn benchmark metrics into bounded, deterministic next-step guidance.

    Thresholds and maximum deltas are intentionally fixed in code.  A low
    score produces a prompt hint and a small, explainable scheduling change;
    it never rewrites a candidate status, a conclusion, a CVSS vector or a
    runtime observation.
    """
    if not isinstance(result, dict):
        return {}
    metrics = result.get("metrics") if isinstance(result.get("metrics"), dict) else {}
    if not metrics:
        return {}
    repeat = metrics.get("repeat") if isinstance(metrics.get("repeat"), dict) else {}
    severity = (metrics.get("severity_calibration")
                if isinstance(metrics.get("severity_calibration"), dict) else {})

    snapshot: Dict[str, float] = {}
    for name in (
        "case_observation_coverage", "confirmed_precision", "confirmed_recall",
        "resolution_accuracy", "unsafe_confirmation_rate",
        "negative_result_fidelity", "environment_gap_fidelity",
        "evidence_completeness", "decision_stability",
    ):
        number = _finite_number(metrics.get(name))
        if number is not None:
            snapshot[name] = round(max(0.0, min(10.0, number)), 4)
    repeat_rate = _finite_number(repeat.get("repeat_rate"))
    unjustified_repeat = _finite_number(repeat.get("unjustified_repeat_rate"))
    severity_overstatement = _finite_number(severity.get("overstatement_rate"))
    severity_ordinal = _finite_number(severity.get("ordinal_overstatement_rate"))
    severity_mae = _finite_number(severity.get("mean_absolute_error"))
    for name, value in (
        ("repeat_rate", repeat_rate),
        ("unjustified_repeat_rate", unjustified_repeat),
        ("severity_overstatement_rate", severity_overstatement),
        ("severity_ordinal_overstatement_rate", severity_ordinal),
        ("severity_mean_absolute_error", severity_mae),
    ):
        if value is not None:
            snapshot[name] = round(max(0.0, min(10.0, value)), 4)

    deltas: Counter = Counter()
    alerts: List[Dict[str, Any]] = []
    tags: List[str] = []
    observations: List[str] = []
    falsifiers: List[str] = []
    hints: List[str] = []

    def add(code: str, priority: str, metric: str, value: float,
            threshold: float, direction: str, action: str,
            weight_delta: Dict[str, int], tag: str,
            required: str, falsifier: str, hint: str) -> None:
        alerts.append({
            "code": code, "priority": priority, "metric": metric,
            "value": round(value, 4), "threshold": round(threshold, 4),
            "direction": direction, "action": action,
        })
        deltas.update(weight_delta)
        tags.append(tag)
        observations.append(required)
        falsifiers.append(falsifier)
        hints.append(hint)

    if (unsafe := _finite_number(metrics.get("unsafe_confirmation_rate"))) is not None \
            and unsafe > 0.0:
        add("unsafe-confirmation", "high", "unsafe_confirmation_rate", unsafe, 0.0,
            "gt", "tighten-confirmation-evidence",
            {"evidence_quality": 4, "coverage_novelty": -2, "sink_impact": -2},
            "benchmark-confirmation-safety",
            "TYPED_EFFECT must match the claimed impact before confirmation",
            "a missing typed effect keeps the case candidate/pending",
            "存在错误确认：下一轮优先补齐与声明影响一致的 typed effect，不能靠改阈值掩盖。")
    if (completeness := _finite_number(metrics.get("evidence_completeness"))) is not None \
            and completeness < 0.85:
        add("evidence-completeness-low", "medium", "evidence_completeness", completeness,
            0.85, "lt", "require-missing-evidence",
            {"evidence_quality": 4, "coverage_novelty": -2, "sink_impact": -2},
            "benchmark-evidence-completeness",
            "required evidence fields must be observed or explicitly unsupported",
            "missing required evidence is not a negative result",
            "证据完整度偏低：下一轮把缺失字段转成显式实验观测。")
    if unjustified_repeat is not None and unjustified_repeat > 0.15:
        add("unjustified-repeat-high", "medium", "unjustified_repeat_rate",
            unjustified_repeat, 0.15, "gt", "increase-novelty-differential-probes",
            {"coverage_novelty": 4, "evidence_quality": -2, "sink_impact": -2},
            "benchmark-novelty-followup",
            "new evidence or a differential probe is required before repeating a key",
            "an exact repeat without new evidence remains unjustified",
            "无新证据重复率偏高：优先做版本/路径/控制差分，避免原样重跑。")
    if (gap_fidelity := _finite_number(metrics.get("environment_gap_fidelity"))) is not None \
            and gap_fidelity < 0.90:
        add("environment-gap-fidelity-low", "high", "environment_gap_fidelity",
            gap_fidelity, 0.90, "lt", "preserve-and-probe-preconditions",
            {"reachability": 2, "control_gap": 2, "coverage_novelty": -2,
             "sink_impact": -2},
            "benchmark-precondition-probe",
            "record the required runtime/precondition before interpreting a result",
            "precondition-unavailable cannot be classified as excluded",
            "环境缺口保真度偏低：先补 runtime/前置条件探针，再解释负结果。")
    if severity_overstatement is not None and severity_overstatement > 0.20:
        add("severity-overstatement-high", "medium", "severity_overstatement_rate",
            severity_overstatement, 0.20, "gt", "tighten-severity-calibration",
            {"evidence_quality": 2, "sink_impact": -1, "coverage_novelty": -1},
            "benchmark-severity-calibration",
            "severity must be consistent with observed typed effect and precondition tier",
            "an unobserved stronger effect keeps the conservative severity",
            "严重性夸大偏高：下一轮补 typed effect 与前置一致性检查；不自动改 CVSS。")
    if (stability := _finite_number(metrics.get("decision_stability"))) is not None \
            and stability < 0.80:
        add("decision-stability-low", "low", "decision_stability", stability, 0.80,
            "lt", "stabilize-resolution-evidence",
            {"evidence_quality": 2, "coverage_novelty": 2,
             "attacker_control": -2, "sink_impact": -2},
            "benchmark-decision-stability",
            "repeat the decision only with an independent bounded observation",
            "a status change without new evidence is not a valid resolution",
            "决策稳定性偏低：为状态变化补独立、可复核的观测。")

    trend = normalize_benchmark_trend(result.get("trend") or {})
    if trend.get("regressions"):
        regression_count = float(len(trend["regressions"]))
        add("benchmark-regression", "medium", "trend_regression_count",
            regression_count, 0.0, "gt", "stabilize-regression",
            {"evidence_quality": 2, "coverage_novelty": 2,
             "sink_impact": -1},
            "benchmark-regression-control",
            "compare a regression with an independent bounded observation",
            "an isolated trend delta is not runtime proof",
            "纵向评测出现退化：下一轮用独立、可复核的观测定位回归；不自动改变漏洞结论。")

    # A healthy global score can hide one weak research surface.  Keep this
    # guidance separate from global weight deltas so only candidates explicitly
    # identified with the affected surface receive a small follow-up boost.
    surface_guidance: List[Dict[str, Any]] = []
    coverage_by_surface = metrics.get("coverage_by_surface")
    if isinstance(coverage_by_surface, dict):
        for surface in sorted(coverage_by_surface):
            if surface not in RESEARCH_SURFACES:
                continue
            surface_metrics = coverage_by_surface.get(surface)
            if not isinstance(surface_metrics, dict):
                continue
            surface_snapshot: Dict[str, float] = {}
            tags: List[str] = []
            required: List[str] = []
            falsifiers: List[str] = []
            priority_delta = 0

            def surface_signal(metric_name: str, value: Any, threshold: float,
                               direction: str, delta: int, tag: str,
                               observation: str, falsifier: str) -> None:
                nonlocal priority_delta
                number = _finite_number(value)
                if number is None:
                    return
                surface_snapshot[metric_name] = round(
                    max(0.0, min(1.0, number)), 4)
                triggered = number < threshold if direction == "lt" else number > threshold
                if not triggered:
                    return
                priority_delta = min(MAX_FEEDBACK_SURFACE_DELTA,
                                     priority_delta + delta)
                if tag not in tags:
                    tags.append(tag)
                if observation not in required:
                    required.append(observation)
                if falsifier not in falsifiers:
                    falsifiers.append(falsifier)

            surface_signal("observation_coverage",
                           surface_metrics.get("observation_coverage"),
                           0.90, "lt", 2,
                           "benchmark-surface-coverage",
                           "each research surface needs an observed status or explicit execution gap",
                           "unobserved surface coverage is not evidence of absence")
            surface_signal("unsafe_confirmation_rate",
                           surface_metrics.get("unsafe_confirmation_rate"),
                           0.0, "gt", 4,
                           "benchmark-confirmation-safety",
                           "TYPED_EFFECT must match the claimed impact before confirmation",
                           "a missing typed effect keeps the case candidate/pending")
            surface_signal("environment_gap_fidelity",
                           surface_metrics.get("environment_gap_fidelity"),
                           0.90, "lt", 3,
                           "benchmark-precondition-probe",
                           "record the required runtime/precondition before interpreting a result",
                           "precondition-unavailable cannot be classified as excluded")
            surface_signal("evidence_completeness",
                           surface_metrics.get("evidence_completeness"),
                           0.85, "lt", 2,
                           "benchmark-evidence-completeness",
                           "required evidence fields must be observed or explicitly unsupported",
                           "missing required evidence is not a negative result")
            if not (tags or required or falsifiers):
                continue
            surface_guidance.append({
                "surface": surface,
                "priority_delta": priority_delta,
                "metric_snapshot": surface_snapshot,
                "strategy_tags": tags,
                "required_observations": required,
                "falsifiers": falsifiers,
                "claim_status": BENCHMARK_FEEDBACK_CLAIM_STATUS,
            })

    # A surface can regress while still remaining above the absolute quality
    # thresholds.  Merge those longitudinal signals into the same bounded
    # surface guidance rather than hiding them in a global score.
    for regression in trend.get("surface_regressions") or []:
        surface = regression.get("surface")
        metric = regression.get("metric")
        if surface not in RESEARCH_SURFACES or metric not in SURFACE_FEEDBACK_METRICS:
            continue
        item = next((entry for entry in surface_guidance
                     if entry.get("surface") == surface), None)
        if item is None:
            item = {
                "surface": surface,
                "priority_delta": 0,
                "metric_snapshot": {},
                "strategy_tags": [],
                "required_observations": [],
                "falsifiers": [],
                "claim_status": BENCHMARK_FEEDBACK_CLAIM_STATUS,
            }
            surface_guidance.append(item)
        item["priority_delta"] = min(
            MAX_FEEDBACK_SURFACE_DELTA,
            int(item.get("priority_delta") or 0) + 2)
        item.setdefault("metric_snapshot", {})[metric] = regression.get("current")
        if "benchmark-regression-control" not in item["strategy_tags"]:
            item["strategy_tags"].append("benchmark-regression-control")
        if "compare a regression with an independent bounded observation" not in item["required_observations"]:
            item["required_observations"].append(
                "compare a regression with an independent bounded observation")
        if "an isolated trend delta is not runtime proof" not in item["falsifiers"]:
            item["falsifiers"].append("an isolated trend delta is not runtime proof")
    surface_guidance.sort(key=lambda item: str(item.get("surface")))

    raw = {
        "schema_version": BENCHMARK_FEEDBACK_SCHEMA_VERSION,
        "benchmark_id": _text(result.get("benchmark_id"), 120) or "benchmark",
        "source": {
            "benchmark_id": _text(result.get("benchmark_id"), 120) or "benchmark",
            "run_count": _bounded_int(result.get("run_count"), 0, MAX_RUNS),
            "case_count": _bounded_int(result.get("case_count"), 0, MAX_CASES),
        },
        "metric_snapshot": snapshot,
        "alerts": alerts,
        "weight_deltas": {
            factor: max(-MAX_FEEDBACK_WEIGHT_DELTA,
                        min(MAX_FEEDBACK_WEIGHT_DELTA, int(value)))
            for factor, value in sorted(deltas.items())
            if factor in BENCHMARK_FEEDBACK_FACTORS and value
        },
        "planner_guidance": {
            "strategy_tags": sorted(set(tags))[:MAX_FEEDBACK_GUIDANCE_ITEMS],
            "required_observations": sorted(set(observations))[:MAX_FEEDBACK_GUIDANCE_ITEMS],
            "falsifiers": sorted(set(falsifiers))[:MAX_FEEDBACK_GUIDANCE_ITEMS],
        },
        "surface_guidance": surface_guidance[:MAX_FEEDBACK_SURFACE_GUIDANCE],
        "trend": trend,
        "prompt_hints": hints[:MAX_FEEDBACK_HINTS],
        "claim_status": BENCHMARK_FEEDBACK_CLAIM_STATUS,
    }
    return normalize_benchmark_feedback(raw)


def benchmark_feedback_from_input(value: Dict[str, Any]) -> Dict[str, Any]:
    """Accept either a benchmark result or an already-derived feedback file."""
    if not isinstance(value, dict):
        return {}
    if value.get("schema_version") == BENCHMARK_FEEDBACK_SCHEMA_VERSION:
        return normalize_benchmark_feedback(value)
    if isinstance(value.get("metrics"), dict):
        return derive_benchmark_feedback(value)
    return {}


def load_benchmark_json(path: Path) -> Dict[str, Any]:
    """Load a benchmark/observation JSON file with a stable error boundary."""
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("benchmark input must be a JSON object")
    return value


def render_benchmark_text(result: Dict[str, Any]) -> str:
    """Render a compact operator-facing report without raw run content."""
    metrics = result.get("metrics") or {}
    repeat = metrics.get("repeat") or {}
    severity = metrics.get("severity_calibration") or {}
    lines = [
        "Benchmark %s (%d cases x %d runs)" % (
            result.get("benchmark_id", "benchmark"),
            result.get("case_count", 0), result.get("run_count", 0)),
        "  research surfaces: %s" % ", ".join(
            (result.get("research_profile") or {}).get("surfaces") or []) or "unspecified",
        "  confirmed precision: %s  recall: %s  resolution: %s" % (
            metrics.get("confirmed_precision"), metrics.get("confirmed_recall"),
            metrics.get("resolution_accuracy")),
        "  observation coverage: %s  negative safety: %s  gap fidelity: %s  evidence completeness: %s" % (
            metrics.get("case_observation_coverage"),
            metrics.get("unsafe_confirmation_rate"),
            metrics.get("environment_gap_fidelity"),
            metrics.get("evidence_completeness")),
        "  repeat rate: %s  unjustified repeat: %s" % (
            repeat.get("repeat_rate"), repeat.get("unjustified_repeat_rate")),
        "  severity MAE: %s  overstatement: %s" % (
            severity.get("mean_absolute_error"),
            severity.get("overstatement_rate")),
        "  claim_status: %s" % result.get("claim_status", BENCHMARK_CLAIM_STATUS),
    ]
    return "\n".join(lines)
