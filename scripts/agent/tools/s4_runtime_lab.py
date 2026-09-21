"""Bounded runtime-lab adapter for ordinary S4 PoC cells.

The directed-fuzz path has its own fixture format because its payload is a
byte string.  Ordinary Java and shell S4 PoCs need a different adapter: their
fixture is the complete bounded execution context (arguments, precondition,
authorization metadata, state declaration and capability contract).  This
module keeps that context stable without copying raw arguments or process
output into the research artifact.

The adapter deliberately reuses the existing isolated matrix runners.  It
records replay/differential evidence only; it never changes a candidate's
conclusion or claim status.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlparse

from .authz import authz_fixture_id, normalize_authz_case, normalize_authz_cases
from ..evaluation.research_consistency_actions import (
    normalize_research_consistency_action,
    normalize_research_consistency_lane,
)
from ..evaluation.research_consistency_rechecks import summarize_recheck_lane
from .build import (JavaMatrixRunner, MatrixCell, POCSpec, ShellMatrixRunner,
                    ShellPOCSpec)
from .redaction import redact_text
from .runtime_lab import (LAB_SCHEMA_VERSION, MAX_CELLS,
                          summarize_replay, summarize_version_differential)
from .service_lifecycle import ServiceLifecycle
from .surface_variants import (normalize_variant_fixture_context,
                               normalize_variant_fixture_plan)
from .source_revisions import (source_revision_index,
                               source_revision_paths,
                               source_revision_snapshot)
from .variant_evidence import summarize_variant_evidence
from .variant_comparisons import (build_comparison_contract,
                                  normalize_comparison_contract,
                                  summarize_comparison_observations)


MAX_S4_FIXTURES = 16
MAX_S4_REPLAY_RUNS = 5
MAX_S4_SAFE_MODES = 4
MAX_FIELD_LENGTH = 160
MAX_CONTEXT_AUTHZ_FIXTURES = 128
CONTEXT_SCHEMA_VERSION = "runtime-context-v1"


def _text(value: Any, limit: int = MAX_FIELD_LENGTH) -> str:
    return " ".join(redact_text(value).replace("\x00", "").split())[:limit]


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _truthy(value: Any) -> bool:
    if isinstance(value, (list, tuple, set)):
        return any(_truthy(item) for item in value)
    return str(value or "").strip().lower() not in {
        "", "false", "none", "null", "0", "no",
    }


def _first_marker(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return _text(value[0], 120) if value else ""
    return _text(value, 120)


def _safe_cell_context(cell: MatrixCell) -> Dict[str, Any]:
    """Return the bounded, non-secret part of a cell's identity."""
    # Arguments are intentionally represented only by count + digest.  A PoC
    # argument may contain a fixture path or an operator-supplied value that
    # should not be copied into a cross-round artifact.
    return {
        "precondition": _text(cell.precondition, 120),
        "features": [_text(item, 80) for item in cell.features[:16]],
        "args_count": len(cell.args),
        "args_digest": _digest(cell.args),
        "jvm": {
            _text(key, 40): _text(value, 80)
            for key, value in sorted(cell.jvm.items())[:16]
        },
        "authz": normalize_authz_case(cell.authz),
        "authz_fixture_id": authz_fixture_id(cell.authz),
        "required_runtime": _text(cell.required_runtime, 80),
        "java_bin": _text(cell.java_bin, 160),
        "java_home": _text(cell.java_home, 160),
        "sequence_count": len(cell.sequence),
        "sequence_digest": _digest(cell.sequence),
        "concurrency": int(cell.concurrency),
        "availability_probe": bool(cell.availability_probe),
        "capability_digest": _digest(cell.capability_contract),
        "variant_fixture_key": normalize_variant_fixture_context(
            cell.variant_context).get("fixture_key", ""),
        "consistency_action_digest": _digest(
            normalize_research_consistency_action(cell.consistency_action)),
    }


def _template_key(cell: MatrixCell) -> str:
    # Version and SafeMode are deliberately excluded: one template can be
    # compared across both dimensions while retaining all other preconditions.
    return _digest(_safe_cell_context(cell))


def _spec_identity(spec: Any, kind: str) -> Dict[str, str]:
    if kind == "java":
        return {
            "poc": _text(getattr(spec, "class_name", ""), 120),
            "source": _text(getattr(spec, "src", ""), 160),
        }
    return {
        "poc": _text(getattr(spec, "script", ""), 160),
        "source": _text(getattr(spec, "script", ""), 160),
    }


def build_s4_fixture(candidate: Dict[str, Any], spec: Any, cell: MatrixCell,
                     kind: str, spec_index: int,
                     template_key: Optional[str] = None,
                     variant_context: Optional[Dict[str, Any]] = None,
                     comparison_contract: Optional[Dict[str, Any]] = None,
                     consistency_action: Optional[Dict[str, Any]] = None
                     ) -> Dict[str, Any]:
    """Build a stable ordinary-S4 fixture without persisting raw arguments."""
    candidate_id = str(candidate.get("candidate_id", ""))
    spec_info = _spec_identity(spec, kind)
    context = _safe_cell_context(cell)
    variant = normalize_variant_fixture_context(
        variant_context if variant_context is not None else cell.variant_context)
    comparison = normalize_comparison_contract(comparison_contract)
    recheck = normalize_research_consistency_action(
        consistency_action if consistency_action is not None
        else cell.consistency_action)
    identity = {
        "kind": kind,
        "candidate_id": candidate_id,
        "spec_index": int(spec_index),
        "poc": spec_info["poc"],
        "source": spec_info["source"],
        "entry": str(getattr(spec, "entry", "") or candidate.get("entry", "")),
        "input_shape": str(getattr(spec, "input_shape", "") or
                            candidate.get("input_shape", "")),
        "cell_context": context,
        "comparison_id": comparison.get("comparison_id", ""),
        "consistency_action": recheck,
        "consistency_lane": normalize_research_consistency_lane(
            cell.consistency_lane),
    }
    digest = _digest(identity)
    fixture = {
        "schema_version": LAB_SCHEMA_VERSION,
        "fixture_id": "s4fx-" + digest[:16],
        "digest": digest,
        "fixture_kind": kind,
        "candidate_id": _text(candidate_id, 120),
        "spec_index": int(spec_index),
        "poc": spec_info["poc"],
        "source": spec_info["source"],
        "entry": _text(identity["entry"], 160),
        "input_shape": _text(identity["input_shape"], 120),
        "template_key": template_key or _template_key(cell),
        "base_version": _text(cell.version, 80),
        "base_safe_mode": bool(cell.safe_mode),
        "precondition": _text(cell.precondition, 120),
        "features": context["features"],
        "args_count": context["args_count"],
        "args_digest": context["args_digest"],
        "authz": context["authz"],
        "authz_fixture_id": context["authz_fixture_id"],
        "sequence_count": context["sequence_count"],
        "sequence_digest": context["sequence_digest"],
        "concurrency": context["concurrency"],
        "availability_probe": context["availability_probe"],
        "variant_context": variant,
        "comparison_contract": comparison,
        "consistency_action": recheck,
        "consistency_lane": normalize_research_consistency_lane(
            cell.consistency_lane),
        "context_digest": _digest(context)[:24],
        "claim_status": "not-a-finding",
    }
    return fixture


def _options(config: Any) -> Dict[str, Any]:
    if isinstance(config, dict):
        raw = config.get("runtime_lab", {})
    else:
        raw = getattr(config, "runtime_lab", {}) if config is not None else {}
    if raw is True:
        raw = {}
    if raw is False or raw is None:
        raw = {"enabled": False} if raw is False else {}
    if not isinstance(raw, dict):
        raw = {}
    try:
        max_fixtures = max(1, min(int(raw.get("max_fixtures", 8)),
                                  MAX_S4_FIXTURES))
    except (TypeError, ValueError):
        max_fixtures = 8
    try:
        replay_runs = max(1, min(int(raw.get("replay_runs", 3)),
                                  MAX_S4_REPLAY_RUNS))
    except (TypeError, ValueError):
        replay_runs = 3
    safe_modes: List[bool] = []
    configured_modes = raw.get("safe_modes", [False, True])
    if isinstance(configured_modes, (list, tuple)):
        for item in configured_modes[:MAX_S4_SAFE_MODES]:
            value = bool(item) if isinstance(item, bool) else str(item).lower() in {
                "true", "1", "yes", "on",
            }
            if value not in safe_modes:
                safe_modes.append(value)
    if not safe_modes:
        safe_modes = [False, True]
    candidate_ids = raw.get("candidate_ids", [])
    if not isinstance(candidate_ids, list):
        candidate_ids = []
    return {
        "enabled": raw.get("enabled", True) is not False,
        "max_fixtures": max_fixtures,
        "replay_runs": replay_runs,
        "safe_modes": safe_modes,
        "candidate_ids": {str(item) for item in candidate_ids if str(item)},
        "include_java": raw.get("include_java", True) is not False,
        "include_shell": raw.get("include_shell", True) is not False,
    }


def _config_value(config: Any, key: str, default: Any = None) -> Any:
    if isinstance(config, dict):
        return config.get(key, default)
    return getattr(config, key, default) if config is not None else default


def _version_set(jars_by_version: Dict[str, List[Any]],
                 version_universe: Optional[Sequence[str]]) -> List[str]:
    versions = sorted({str(item) for item in (version_universe or []) if str(item)})
    if not versions:
        versions = sorted({str(item) for item in jars_by_version if str(item)})
    return versions


def _safe_url_snapshot(value: Any) -> Dict[str, Any]:
    """Describe a target URL without persisting query values or credentials."""
    raw = _text(value, 500)
    if not raw:
        return {"configured": False}
    try:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return {"configured": True, "valid": False,
                "url_digest": _digest(raw)[:20]}
    return {
        "configured": True,
        "valid": bool(parsed.scheme in {"http", "https"} and host
                       and not parsed.username and not parsed.password),
        "scheme": _text(parsed.scheme, 16),
        "host_digest": _digest(host.lower())[:20] if host else "",
        "port": port or (443 if parsed.scheme == "https" else 80),
        "path_digest": _digest(parsed.path or "/")[:20],
        "url_digest": _digest(raw)[:20],
    }


def _safe_authz_fixture(case: Any, candidate_id: str) -> Dict[str, Any]:
    normalized = normalize_authz_case(case)
    return {
        "candidate_id": _text(candidate_id, 120),
        "fixture_id": authz_fixture_id(normalized),
        "case_id": _text(normalized.get("case_id", ""), 80),
        "principal": _text(normalized.get("principal", ""), 80),
        "role": _text(normalized.get("role", ""), 80),
        "tenant_id": _text(normalized.get("tenant_id", ""), 80),
        "object_id": _text(normalized.get("object_id", ""), 80),
        "object_tenant_id": _text(normalized.get("object_tenant_id", ""), 80),
        "expected_authz": normalized.get("expected_authz", ""),
        "expected_http_codes": list(normalized.get("expected_http_codes", [])),
        "expected_object_mutated": normalized.get("expected_object_mutated"),
    }


def build_runtime_context_snapshot(
        config: Any, versions: Sequence[str], candidates: Sequence[Dict[str, Any]],
        options: Dict[str, Any], service_info: Optional[Dict[str, Any]] = None
        ) -> Dict[str, Any]:
    """Build a deterministic, credential-free snapshot of an S4 run context."""
    target_urls = _config_value(config, "target_urls", {})
    if not isinstance(target_urls, dict):
        target_urls = {}
    authz_fixtures: List[Dict[str, Any]] = []
    seen = set()
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        cid = str(candidate.get("candidate_id", ""))
        for case in normalize_authz_cases(candidate.get("authz_cases")):
            fixture = _safe_authz_fixture(case, cid)
            key = (fixture["candidate_id"], fixture["fixture_id"])
            if key not in seen:
                seen.add(key)
                authz_fixtures.append(fixture)
            if len(authz_fixtures) >= MAX_CONTEXT_AUTHZ_FIXTURES:
                break
        if len(authz_fixtures) >= MAX_CONTEXT_AUTHZ_FIXTURES:
            break
    service = service_info or {
        "schema_version": "service-lifecycle-v1",
        "configured": False,
        "enabled": False,
        "claim_status": "not-a-finding",
    }
    return {
        "schema_version": CONTEXT_SCHEMA_VERSION,
        "target_type": _text(_config_value(config, "target_type", "library"), 40),
        "versions": sorted({str(item) for item in versions if str(item)}),
        "target_urls": {
            _text(version, 80): _safe_url_snapshot(url)
            for version, url in sorted(target_urls.items(), key=lambda item: str(item[0]))
            if str(version)
        },
        "runtime_lab": {
            "enabled": bool(options.get("enabled")),
            "max_fixtures": int(options.get("max_fixtures", 0) or 0),
            "replay_runs": int(options.get("replay_runs", 0) or 0),
            "safe_modes": list(options.get("safe_modes", [])),
            "include_java": bool(options.get("include_java")),
            "include_shell": bool(options.get("include_shell")),
            "candidate_ids": sorted(str(item) for item in options.get("candidate_ids", set())),
        },
        "authz_fixtures": authz_fixtures,
        "service_lifecycle": service,
        "claim_status": "not-a-finding",
    }


def _clone_cell(cell: MatrixCell, version: str, safe_mode: bool,
                *, features: Optional[List[str]] = None,
                sequence: Optional[List[str]] = None,
                variant_context: Optional[Dict[str, Any]] = None,
                consistency_lane: Optional[str] = None
                ) -> MatrixCell:
    return MatrixCell(
        version=version,
        safe_mode=safe_mode,
        features=list(cell.features if features is None else features),
        precondition=cell.precondition,
        args=list(cell.args),
        jvm=dict(cell.jvm),
        timeout=cell.timeout,
        authz=dict(cell.authz),
        required_runtime=cell.required_runtime,
        java_bin=cell.java_bin,
        java_home=cell.java_home,
        sequence=list(cell.sequence if sequence is None else sequence),
        concurrency=cell.concurrency,
        availability_probe=cell.availability_probe,
        capability_contract=dict(cell.capability_contract),
        residual_contracts=list(cell.residual_contracts),
        variant_context=(dict(cell.variant_context)
                         if variant_context is None else variant_context),
        consistency_action=dict(cell.consistency_action),
        consistency_lane=(cell.consistency_lane
                          if consistency_lane is None else consistency_lane),
    )


def _cell_groups(cells: Iterable[MatrixCell]) -> Dict[str, List[MatrixCell]]:
    grouped: Dict[str, List[MatrixCell]] = defaultdict(list)
    for cell in cells:
        grouped[_template_key(cell)].append(cell)
    return grouped


def _variant_contexts(candidate: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Resolve the candidate's trusted S2 plan into bounded S4 contexts."""
    plan = candidate.get("experiment_plan")
    if not isinstance(plan, dict):
        return []
    fixture_plan = normalize_variant_fixture_plan(
        plan.get("variant_fixture_plan"),
        plan.get("surface_variant_plan"), candidate.get("candidate_id", ""))
    rows = []
    for row in fixture_plan.get("fixtures") or []:
        context = normalize_variant_fixture_context(row)
        if context:
            rows.append(context)
    return rows


def _consistency_lanes(candidate: Dict[str, Any]) -> List[str]:
    """Materialize the paired lanes required by a pending recheck action."""
    plan = candidate.get("experiment_plan")
    action = normalize_research_consistency_action(
        plan.get("consistency_action") if isinstance(plan, dict) else None)
    if not action:
        return []
    lanes = [normalize_research_consistency_lane(item) for item in
             (action.get("matrix_shape") or {}).get("paired_lanes") or []]
    return [item for item in lanes if item]


def _comparison_contract(candidate: Dict[str, Any],
                         versions: Sequence[str]) -> Dict[str, Any]:
    """Prefer the S2 contract, with a deterministic old-candidate fallback."""
    plan = candidate.get("experiment_plan")
    raw = plan.get("comparison_contract") if isinstance(plan, dict) else None
    normalized = normalize_comparison_contract(raw)
    return normalized or build_comparison_contract(candidate, versions)


def _merge_state_steps(base: Sequence[str], variant: Sequence[str]) -> List[str]:
    result: List[str] = []
    for value in list(base) + list(variant):
        item = _text(value, 80)
        if item and item not in result:
            result.append(item)
        if len(result) >= 16:
            break
    return result


def _variant_cell(base: MatrixCell,
                  context: Dict[str, Any]) -> MatrixCell:
    """Make a lane-specific cell while preserving the base preconditions."""
    variant = normalize_variant_fixture_context(context)
    if not variant:
        return _clone_cell(base, base.version, bool(base.safe_mode))
    features = list(base.features)
    for marker in (
            "surface=" + variant["surface"],
            "variant=" + variant["variant_id"],
            "lane=" + variant["lane"]):
        if marker not in features:
            features.append(marker)
    return _clone_cell(
        base, base.version, bool(base.safe_mode),
        features=features[:16],
        sequence=_merge_state_steps(base.sequence, variant["state_steps"]),
        variant_context=variant,
    )


def _choose_base(cells: List[MatrixCell], primary_version: str) -> MatrixCell:
    return sorted(
        cells,
        key=lambda cell: (
            0 if cell.version == primary_version else 1,
            0 if not cell.safe_mode else 1,
            str(cell.version),
            str(cell.precondition),
        ),
    )[0]


def _templates(candidates: Sequence[Dict[str, Any]],
               java_specs: Sequence[POCSpec],
               shell_specs: Sequence[ShellPOCSpec],
               primary_version: str, options: Dict[str, Any]
               ) -> List[Tuple[Dict[str, Any], Any, str, int, MatrixCell, str]]:
    by_id = {str(item.get("candidate_id")): item for item in candidates}
    out: List[Tuple[Dict[str, Any], Any, str, int, MatrixCell, str]] = []

    def collect(specs: Sequence[Any], kind: str, enabled: bool) -> None:
        if not enabled:
            return
        for spec_index, spec in enumerate(specs):
            cid = str(getattr(spec, "candidate_id", ""))
            candidate = by_id.get(cid)
            if not candidate or not getattr(spec, "cells", None):
                continue
            candidate_lab = candidate.get("runtime_lab")
            if candidate_lab is False or (
                    isinstance(candidate_lab, dict)
                    and candidate_lab.get("enabled") is False):
                continue
            if options["candidate_ids"] and cid not in options["candidate_ids"]:
                continue
            for key, cells in sorted(_cell_groups(spec.cells).items()):
                base = _choose_base(cells, primary_version)
                out.append((candidate, spec, kind, spec_index, base, key))

    collect(java_specs, "java", options["include_java"])
    collect(shell_specs, "shell", options["include_shell"])
    return sorted(out, key=lambda item: (
        str(item[0].get("candidate_id", "")), item[2], item[3], item[5]))


def _row_observations(row: Dict[str, Any]) -> Dict[str, Any]:
    value = row.get("observations") or {}
    return value if isinstance(value, dict) else {}


def _matrix_bucket(row: Dict[str, Any]) -> str:
    explicit = _text(row.get("bucket", ""), 60).lower()
    if explicit:
        return explicit
    if row.get("precondition_status") == "precondition-unavailable":
        return "precondition-unavailable"
    if row.get("compile_error") or row.get("harness_error"):
        return "harness-error"
    obs = _row_observations(row)
    gate = _first_marker(obs.get("GATE_BLOCKED"))
    if gate.lower() == "precondition-unavailable":
        return "precondition-unavailable"
    if _truthy(gate):
        return "gate-blocked"
    if row.get("timed_out"):
        return "hang"
    if row.get("returncode") not in (None, 0, "0") and not _truthy(obs.get("ERROR")):
        return "run-failed"
    if _truthy(obs.get("AUTHZ_RESULT")) or _truthy(obs.get("OBJECT_MUTATED")):
        assertion = row.get("authz_assertion") or {}
        if isinstance(assertion, dict) and assertion.get("boundary_violation"):
            return "authz-boundary"
    if _truthy(obs.get("ERROR")) or _truthy(obs.get("ENV_ERROR")):
        return "error"
    if _truthy(obs.get("EFFECT_KIND")) and _truthy(
            obs.get("EFFECT", obs.get("SIDE_EFFECT", ""))):
        return "typed-effect"
    if _truthy(obs.get("LEAKED")):
        return "leaked"
    if _truthy(obs.get("NETWORK")):
        return "network"
    if (_truthy(obs.get("HTTP_CODE")) or _truthy(obs.get("RESP_MATCH"))
            or _truthy(obs.get("EVIDENCE"))):
        return "http-evidence"
    if _truthy(obs.get("INSTANTIATED")):
        return "instantiated"
    if _truthy(obs.get("PARSED")):
        return "parsed"
    return "empty"


def _matrix_signature(row: Dict[str, Any]) -> str:
    explicit = _text(row.get("signature", row.get("observed_signature", "")),
                     240)
    if explicit:
        return explicit
    obs = _row_observations(row)
    parts: List[str] = []
    value_keys = ("ERROR", "ENV_ERROR", "GATE_BLOCKED", "EFFECT_KIND",
                  "HTTP_CODE", "AUTHZ_RESULT", "OBJECT_MUTATED",
                  "INSTANTIATED")
    for key in value_keys:
        value = _first_marker(obs.get(key))
        if value and value.lower() not in {"true", "yes", "ok", "false"}:
            parts.append("%s=%s" % (key, value))
    for key in ("LEAKED", "NETWORK", "RESP_MATCH", "EVIDENCE", "EFFECT",
                "SIDE_EFFECT", "PARSED"):
        if _truthy(obs.get(key)):
            parts.append(key + "=<present>")
    return "|".join(parts)[:240]


def normalize_matrix_record(row: Dict[str, Any], fixture_id: str = "",
                            lab_kind: str = "",
                            variant_context: Optional[Dict[str, Any]] = None
                            ) -> Dict[str, Any]:
    """Reduce one ordinary S4 cell to bounded lab evidence."""
    result = {
        "version": _text(row.get("version", ""), 80),
        "safe_mode": bool(row.get("safe_mode", False)),
        "precondition": _text(row.get("precondition", "none"), 120),
        "bucket": _matrix_bucket(row),
        "signature": _matrix_signature(row),
        "returncode": row.get("returncode"),
        "timed_out": bool(row.get("timed_out", False)),
        "precondition_status": _text(row.get("precondition_status", ""), 80),
        "harness_error": _text(row.get("harness_error", ""), 240),
        "compile_error": _text(row.get("compile_error", ""), 240),
        "claim_status": "not-a-finding",
    }
    if fixture_id:
        result["fixture_id"] = fixture_id
    if lab_kind:
        result["lab_kind"] = lab_kind
    lane = normalize_research_consistency_lane(
        row.get("consistency_lane") or
        (row.get("experiment") or {}).get("consistency_lane"))
    if lane:
        result["consistency_lane"] = lane
    action = normalize_research_consistency_action(row.get("consistency_action"))
    if action:
        result["consistency_action"] = action
    context = normalize_variant_fixture_context(
        variant_context if variant_context is not None
        else row.get("variant_context"))
    if context:
        result["variant_context"] = context
    return result


def _baseline_row(rows: Iterable[Dict[str, Any]], spec: Any,
                  kind: str, cell: MatrixCell) -> Optional[Dict[str, Any]]:
    for row in rows:
        if not isinstance(row, dict):
            continue
        if (str(row.get("version", "")) != str(cell.version)
                or bool(row.get("safe_mode", False)) != bool(cell.safe_mode)
                or str(row.get("precondition", "none")) != str(cell.precondition)):
            continue
        if kind == "java" and row.get("poc_class") not in (None, spec.class_name):
            continue
        if kind == "shell" and row.get("poc_script") not in (None, spec.script):
            continue
        return row
    return None


def _clone_spec(spec: Any, kind: str, candidate_id: str,
                cells: List[MatrixCell]) -> Any:
    if kind == "java":
        return POCSpec(
            candidate_id=candidate_id,
            class_name=spec.class_name,
            src=spec.src,
            cells=cells,
            extra_srcs=list(spec.extra_srcs),
            safe_mode_jvm_prop=spec.safe_mode_jvm_prop,
            module_opts=list(spec.module_opts),
            module_run_opts=list(spec.module_run_opts),
            jvm_default=dict(spec.jvm_default),
            entry=spec.entry,
            input_shape=spec.input_shape,
            logic=spec.logic,
            notes=spec.notes,
        )
    return ShellPOCSpec(
        candidate_id=candidate_id,
        script=spec.script,
        cells=cells,
        env=dict(spec.env),
        urls=dict(spec.urls),
        entry=spec.entry,
        input_shape=spec.input_shape,
        logic=spec.logic,
        notes=spec.notes,
    )


def _run_manifest(kind: str, runner: Any, spec: Any,
                  jars_by_version: Dict[str, List[Any]]) -> List[Dict[str, Any]]:
    if kind == "java":
        return runner.run_manifest([spec], jars_by_version).get(
            spec.candidate_id, [])
    return runner.run_manifest([spec]).get(spec.candidate_id, [])


def _decorate(rows: Iterable[Dict[str, Any]], fixture_id: str,
              lab_kind: str,
              variant_context: Optional[Dict[str, Any]] = None
              ) -> List[Dict[str, Any]]:
    context = normalize_variant_fixture_context(variant_context)
    decorated = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        normalized = normalize_matrix_record(row, fixture_id, lab_kind)
        if context:
            normalized["variant_context"] = context
        decorated.append(normalized)
    return decorated


def _failure(version: str, safe_mode: bool, fixture_id: str,
             lab_kind: str, error: Exception,
             variant_context: Optional[Dict[str, Any]] = None
             ) -> List[Dict[str, Any]]:
    return [normalize_matrix_record({
        "version": version,
        "safe_mode": safe_mode,
        "precondition": "none",
        "harness_error": "%s: %s" % (type(error).__name__, str(error)[:200]),
    }, fixture_id, lab_kind, variant_context=variant_context)]


def _unique_comparison_contracts(rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Keep one bounded comparison contract per comparison id."""
    result: List[Dict[str, Any]] = []
    seen = set()
    for row in rows:
        fixture = row.get("fixture") if isinstance(row, dict) else {}
        contract = normalize_comparison_contract(
            fixture.get("comparison_contract") if isinstance(fixture, dict)
            else None)
        comparison_id = contract.get("comparison_id")
        if not comparison_id or comparison_id in seen:
            continue
        seen.add(comparison_id)
        result.append(contract)
        if len(result) >= 16:
            break
    return result


def _source_revision_execution_plan(
        contract: Mapping[str, Any], resolved: Any, base: MatrixCell,
        safe_modes: Sequence[bool], kind: str
        ) -> Tuple[List[MatrixCell], Dict[str, Dict[str, str]],
                   List[Dict[str, Any]]]:
    """Create source-arm cells only for validated operator artifacts."""
    index = source_revision_index(resolved)
    cells: List[MatrixCell] = []
    aliases: Dict[str, Dict[str, str]] = {}
    gaps: List[Dict[str, Any]] = []
    for arm in contract.get("source_revision") or []:
        role = str(arm.get("role") or "")
        ref = str(arm.get("ref") or "")
        entry = index.get((role, ref))
        if entry is None:
            continue
        if entry.get("status") != "available":
            gaps.append({
                "source_revision": {"role": role, "ref": ref},
                "status": "precondition-unavailable",
                "reason_code": "source-revision-artifact-unavailable",
                "claim_status": "not-a-finding",
            })
            continue
        if kind != "java":
            gaps.append({
                "source_revision": {"role": role, "ref": ref},
                "status": "precondition-unavailable",
                "reason_code": "source-revision-java-adapter-only",
                "claim_status": "not-a-finding",
            })
            continue
        paths = source_revision_paths(entry)
        if not paths:
            gaps.append({
                "source_revision": {"role": role, "ref": ref},
                "status": "precondition-unavailable",
                "reason_code": "source-revision-artifact-unavailable",
                "claim_status": "not-a-finding",
            })
            continue
        alias = "source-" + role
        aliases[alias] = {"role": role, "ref": ref}
        for safe_mode in safe_modes:
            cells.append(_clone_cell(base, alias, bool(safe_mode)))
    return cells, aliases, gaps


def _annotate_source_revision_rows(rows: Iterable[Dict[str, Any]],
                                   aliases: Mapping[str, Mapping[str, str]]) \
        -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        alias = str(row.get("version") or "")
        marker = aliases.get(alias)
        if marker:
            row = dict(row)
            row["source_revision"] = {
                "role": str(marker.get("role") or ""),
                "ref": str(marker.get("ref") or ""),
            }
        result.append(row)
    return result


def _run_s4_runtime_lab_core(
        workspace: Any, target: str, round_no: int, config: Any,
        candidates: Sequence[Dict[str, Any]],
        java_specs: Sequence[POCSpec], shell_specs: Sequence[ShellPOCSpec],
        jars_by_version: Dict[str, List[Any]],
        baseline_results: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        approval: Any = None,
        version_universe: Optional[Sequence[str]] = None,
        source_revision_artifacts: Optional[Dict[str, Any]] = None
        ) -> Dict[str, Any]:
    """Run bounded replay/differential experiments for ordinary S4 specs."""
    source_revision_artifacts = source_revision_artifacts or {}
    source_revision_artifact_view = source_revision_snapshot(
        source_revision_artifacts)
    options = _options(config)
    if not options["enabled"]:
        return {
            "schema_version": LAB_SCHEMA_VERSION,
            "scope": "ordinary-s4",
            "status": "disabled",
            "source_revision_artifacts": source_revision_artifact_view,
            "fixtures": [],
            "claim_status": "not-a-finding",
        }

    versions = sorted({str(item) for item in (version_universe or []) if str(item)})
    if not versions:
        versions = sorted({str(item) for item in jars_by_version if str(item)})
    primary_version = versions[-1] if versions else ""
    templates = _templates(candidates, java_specs, shell_specs,
                           primary_version, options)
    work_items = []
    for item in templates:
        candidate = item[0]
        contexts = _variant_contexts(candidate) or [{}]
        consistency_lanes = _consistency_lanes(candidate) or [""]
        for context in contexts:
            for consistency_lane in consistency_lanes:
                work_items.append((*item, context, consistency_lane))
    work_item_count = len(work_items)
    work_items = work_items[:options["max_fixtures"]]
    if not work_items:
        return {
            "schema_version": LAB_SCHEMA_VERSION,
            "scope": "ordinary-s4",
            "status": "no-fixtures",
            "replay_runs": options["replay_runs"],
            "version_count": len(versions),
            "fixture_count": 0,
            "fixture_budget": options["max_fixtures"],
            "fixture_budget_truncated": False,
            "comparison_contracts": [],
            "source_revision_artifacts": source_revision_artifact_view,
            "fixtures": [],
            "claim_status": "not-a-finding",
    }

    java_runner = (JavaMatrixRunner(workspace, target, round_no, approval=approval)
                   if any(item[2] == "java" for item in work_items) else None)
    shell_runner = (ShellMatrixRunner(workspace, target, round_no, approval=approval)
                    if any(item[2] == "shell" for item in work_items) else None)
    source_revision_entries = source_revision_index(source_revision_artifacts)
    baseline_results = baseline_results or {}
    rows: List[Dict[str, Any]] = []
    for (candidate, spec, kind, spec_index, base, template_key,
         variant_context, consistency_lane) in work_items:
        variant_base = (_variant_cell(base, variant_context)
                        if variant_context else base)
        if consistency_lane:
            variant_base = _clone_cell(
                variant_base, variant_base.version,
                bool(variant_base.safe_mode),
                consistency_lane=consistency_lane)
        comparison_contract = _comparison_contract(candidate, versions)
        fixture = build_s4_fixture(
            candidate, spec, variant_base, kind, spec_index, template_key,
            variant_context=variant_context,
            comparison_contract=comparison_contract,
            consistency_action=(candidate.get("experiment_plan") or {}).get(
                "consistency_action", {}))
        fixture_id = fixture["fixture_id"]
        candidate_id = str(candidate.get("candidate_id", ""))
        selected_versions = versions or [str(base.version)]
        primary = (str(variant_base.version)
                   if str(variant_base.version) in selected_versions
                   else selected_versions[-1])
        replay_cells = [
            _clone_cell(variant_base, primary, bool(variant_base.safe_mode))
            for _ in range(options["replay_runs"])
        ]
        differential_cells = [
            _clone_cell(variant_base, version, safe)
            for version in selected_versions for safe in options["safe_modes"]
        ]
        replay_id = "LAB-S4-REPLAY-" + fixture_id
        diff_id = "LAB-S4-DIFF-" + fixture_id
        raw_replay_records: List[Dict[str, Any]] = []
        raw_differential_records: List[Dict[str, Any]] = []
        replay_records: List[Dict[str, Any]] = []
        differential_records: List[Dict[str, Any]] = []
        try:
            replay_spec = _clone_spec(spec, kind, replay_id, replay_cells)
            runner = java_runner if kind == "java" else shell_runner
            if runner is None:
                raise RuntimeError("runtime lab runner unavailable")
            raw_replay_records = _run_manifest(
                kind, runner, replay_spec, jars_by_version)
            replay_records = _decorate(
                raw_replay_records,
                fixture_id, "replay", variant_context)
            diff_spec = _clone_spec(spec, kind, diff_id, differential_cells)
            raw_differential_records = _run_manifest(
                kind, runner, diff_spec, jars_by_version)
            differential_records = _decorate(
                raw_differential_records,
                fixture_id, "differential", variant_context)
        except Exception as exc:  # preserve a typed lab gap, keep S4 usable
            raw_replay_records = []
            raw_differential_records = []
            replay_records = _failure(
                primary, bool(variant_base.safe_mode), fixture_id,
                "replay", exc, variant_context)
            differential_records = _failure(
                primary, bool(variant_base.safe_mode), fixture_id,
                "differential", exc, variant_context)

        source_revision_records: List[Dict[str, Any]] = []
        source_revision_gaps: List[Dict[str, Any]] = []
        source_cells, source_aliases, source_revision_gaps = (
            _source_revision_execution_plan(
                comparison_contract, source_revision_artifacts, variant_base,
                options["safe_modes"], kind))
        if source_cells:
            try:
                source_spec = _clone_spec(
                    spec, kind, "LAB-S4-SOURCE-" + fixture_id, source_cells)
                source_jars = dict(jars_by_version)
                for alias, marker in source_aliases.items():
                    entry = source_revision_entries.get(
                        (marker["role"], marker["ref"]), {})
                    source_jars[alias] = source_revision_paths(entry)
                source_revision_records = _annotate_source_revision_rows(
                    _decorate(
                        _run_manifest(kind, java_runner, source_spec,
                                      source_jars),
                        fixture_id, "source-revision", variant_context),
                    source_aliases)
            except Exception as exc:  # preserve source-arm execution gaps
                for marker in source_aliases.values():
                    source_revision_gaps.append({
                        "source_revision": {
                            "role": marker["role"], "ref": marker["ref"],
                        },
                        "status": "run-failed",
                        "reason_code": "source-revision-run-failed",
                        "harness_error": type(exc).__name__,
                        "claim_status": "not-a-finding",
                    })

        variant_evidence = summarize_variant_evidence(
            variant_context,
            raw_replay_records + raw_differential_records
            or replay_records + differential_records)
        replay = summarize_replay(replay_records)
        differential = summarize_version_differential(
            differential_records, primary)
        comparison = summarize_comparison_observations(
            comparison_contract, differential_records, primary,
            source_revision_records=source_revision_records
            + source_revision_gaps)
        consistency_recheck = summarize_recheck_lane(
            fixture.get("consistency_action"), fixture,
            raw_replay_records + raw_differential_records
            or replay_records + differential_records,
            replay, differential, comparison)
        baseline = _baseline_row(baseline_results.get(candidate_id, []),
                                 spec, kind, variant_base)
        expected = (normalize_matrix_record(baseline)
                    if baseline is not None else {
                        "status": "unavailable",
                        "claim_status": "not-a-finding",
                    })
        representative = replay.get("representative", {})
        expected_outcome = expected.get("bucket", "")
        expected_signature = expected.get("signature", "")
        reproduces = None if baseline is None else bool(
            replay.get("status") == "stable"
            and representative.get("outcome") == expected_outcome
            and representative.get("signature") == expected_signature)
        rows.append({
            "fixture": fixture,
            "expected": expected,
            "replay": replay,
            "reproduces_expected": reproduces,
            "replay_records": replay_records[:MAX_CELLS],
            "differential": differential,
            "comparison": comparison,
            "differential_records": differential_records[:MAX_CELLS],
            "source_revision_records": source_revision_records[:MAX_CELLS],
            "variant_evidence": variant_evidence,
            "consistency_recheck": consistency_recheck,
            "claim_status": "not-a-finding",
        })

    candidate_status: Dict[str, Dict[str, Any]] = {}
    for item in rows:
        cid = str(item["fixture"].get("candidate_id", ""))
        status = candidate_status.setdefault(cid, {
            "fixture_count": 0,
            "replay_statuses": [],
            "differential_statuses": [],
            "claim_status": "not-a-finding",
        })
        status["fixture_count"] += 1
        status["replay_statuses"].append(item["replay"].get("status"))
        status["differential_statuses"].append(
            item["differential"].get("status"))
        comparison = item.get("comparison") or {}
        if comparison:
            status.setdefault("comparison_statuses", []).append(
                comparison.get("status", "unobserved"))
            status.setdefault("comparison_ids", []).append(
                comparison.get("comparison_id", ""))
        lane = (item["fixture"].get("variant_context") or {}).get("lane")
        if lane:
            lane_counts = status.setdefault("variant_lane_counts", {})
            lane_counts[lane] = int(lane_counts.get(lane, 0)) + 1
        variant_evidence = item.get("variant_evidence") or {}
        if isinstance(variant_evidence, dict) and variant_evidence.get("status"):
            status.setdefault("variant_evidence_statuses", []).append(
                variant_evidence.get("status"))
            if variant_evidence.get("status") in {"partial", "not-executed"}:
                status["variant_incomplete_count"] = int(
                    status.get("variant_incomplete_count", 0)) + 1
            observed_signals = status.setdefault("variant_observed_signals", [])
            for signal in variant_evidence.get("observed_signals") or []:
                if signal not in observed_signals and len(observed_signals) < 12:
                    observed_signals.append(signal)
        recheck = item.get("consistency_recheck") or {}
        if isinstance(recheck, dict) and recheck.get("status"):
            status.setdefault("consistency_recheck_statuses", []).append(
                recheck.get("status"))
            lane = recheck.get("lane")
            if lane:
                lane_counts = status.setdefault("consistency_lane_counts", {})
                lane_counts[lane] = int(lane_counts.get(lane, 0)) + 1
    return {
        "schema_version": LAB_SCHEMA_VERSION,
        "scope": "ordinary-s4",
        "status": "completed",
        "replay_runs": options["replay_runs"],
        "safe_modes": options["safe_modes"],
        "version_count": len(versions),
        "fixture_count": len(rows),
        "fixture_budget": options["max_fixtures"],
        "fixture_budget_truncated": work_item_count > len(work_items),
        "source_revision_artifacts": source_revision_artifact_view,
        "comparison_contracts": _unique_comparison_contracts(rows),
        "candidate_status": candidate_status,
        "fixtures": rows,
        "claim_status": "not-a-finding",
    }


def _runtime_lab_gap(status: str, options: Dict[str, Any],
                     versions: Sequence[str], reason: str,
                     service_info: Dict[str, Any], config: Any,
                     candidates: Sequence[Dict[str, Any]],
                     source_revision_artifacts: Optional[Dict[str, Any]] = None
                     ) -> Dict[str, Any]:
    service_record = dict(service_info)
    artifact = {
        "schema_version": LAB_SCHEMA_VERSION,
        "scope": "ordinary-s4",
        "status": status,
        "reason": _text(reason, 240),
        "replay_runs": options["replay_runs"],
        "safe_modes": options["safe_modes"],
        "version_count": len(versions),
        "fixture_count": 0,
        "fixture_budget": options["max_fixtures"],
        "fixture_budget_truncated": False,
        "candidate_status": {},
        "source_revision_artifacts": source_revision_snapshot(
            source_revision_artifacts or {}),
        "fixtures": [],
        "comparison_contracts": [
            contract for contract in (
                build_comparison_contract(candidate, versions)
                for candidate in candidates if isinstance(candidate, dict)
            ) if contract
        ][:16],
        "service_lifecycle": service_record,
        "claim_status": "not-a-finding",
    }
    artifact["configuration"] = build_runtime_context_snapshot(
        config, versions, candidates, options, service_record)
    return artifact


def run_s4_runtime_lab(
        workspace: Any, target: str, round_no: int, config: Any,
        candidates: Sequence[Dict[str, Any]],
        java_specs: Sequence[POCSpec], shell_specs: Sequence[ShellPOCSpec],
        jars_by_version: Dict[str, List[Any]],
        baseline_results: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        approval: Any = None,
        version_universe: Optional[Sequence[str]] = None,
        service_lifecycle: Optional[ServiceLifecycle] = None,
        source_revision_artifacts: Optional[Dict[str, Any]] = None
        ) -> Dict[str, Any]:
    """Run ordinary S4 lab experiments with a bounded service context."""
    if source_revision_artifacts is None:
        from .source_revisions import resolve_source_revision_artifacts

        source_revision_artifacts = resolve_source_revision_artifacts(
            workspace, config)
    options = _options(config)
    versions = _version_set(jars_by_version, version_universe)
    owns_lifecycle = service_lifecycle is None
    lifecycle = service_lifecycle or ServiceLifecycle(
        workspace, target, round_no, config, approval=approval)
    service_info = (lifecycle.snapshot() if owns_lifecycle
                    else lifecycle.result())

    # Do not start a target service when the configured candidates do not have
    # any repeatable fixture.  The core function still owns the exact
    # disabled/no-fixture artifact shape.
    primary_version = versions[-1] if versions else ""
    templates = _templates(candidates, java_specs, shell_specs,
                           primary_version, options)[:options["max_fixtures"]]
    if options["enabled"] and templates and lifecycle.configured and lifecycle.enabled:
        try:
            if "ready" not in service_info:
                service_info = lifecycle.ensure_ready()
        except Exception as exc:
            stop_info = (lifecycle.stop() if owns_lifecycle else {
                "status": "managed-by-caller", "stopped": False,
                "claim_status": "not-a-finding",
            })
            service_info = lifecycle.snapshot()
            service_info.update({
                "status": "run-failed", "ready": False,
                "reason": "%s: %s" % (type(exc).__name__, str(exc)[:180]),
                "stop": stop_info,
            })
            return _runtime_lab_gap(
                "run-failed", options, versions, service_info["reason"],
                service_info, config, candidates, source_revision_artifacts)
        if not service_info.get("ready"):
            stop_info = (lifecycle.stop() if owns_lifecycle else {
                "status": "managed-by-caller", "stopped": False,
                "claim_status": "not-a-finding",
            })
            service_info = dict(service_info)
            service_info["stop"] = stop_info
            return _runtime_lab_gap(
                "precondition-unavailable" if service_info.get("status") != "policy-denied"
                else "policy-denied",
                options, versions,
                service_info.get("reason", "service healthcheck did not become ready"),
                service_info, config, candidates, source_revision_artifacts)

    try:
        artifact = _run_s4_runtime_lab_core(
            workspace, target, round_no, config, candidates, java_specs,
            shell_specs, jars_by_version, baseline_results=baseline_results,
            approval=approval, version_universe=version_universe,
            source_revision_artifacts=source_revision_artifacts)
    finally:
        # An external-ready service is deliberately not owned by this run;
        # a process started above is always stopped in the same turn. When a
        # caller owns the lifecycle, it holds the service lock across the
        # baseline and lab so autonomous workers cannot race one service.
        stop_info = (lifecycle.stop() if owns_lifecycle else {
            "status": "managed-by-caller", "stopped": False,
            "claim_status": "not-a-finding",
        })

    service_record = dict(service_info)
    service_record["stop"] = stop_info
    artifact["service_lifecycle"] = service_record
    artifact["configuration"] = build_runtime_context_snapshot(
        config, versions, candidates, options, service_record)
    artifact["source_revision_artifacts"] = source_revision_snapshot(
        source_revision_artifacts)
    return artifact


def merge_runtime_lab_artifacts(artifacts: Iterable[Dict[str, Any]],
                                scope: str = "ordinary-s4") -> Dict[str, Any]:
    """Merge per-worker autonomous lab artifacts without losing gaps."""
    items = [item for item in artifacts if isinstance(item, dict)]
    fixtures: List[Dict[str, Any]] = []
    candidate_status: Dict[str, Dict[str, Any]] = {}
    replay_runs = 0
    versions = 0
    statuses = []
    configurations = []
    service_lifecycles = []
    comparison_contracts: Dict[str, Dict[str, Any]] = {}
    source_revision_view: Dict[str, Any] = {}
    fixture_budget = 0
    fixture_budget_truncated = False
    for item in items:
        fixtures.extend(item.get("fixtures", []) or [])
        try:
            replay_runs = max(replay_runs, int(item.get("replay_runs", 0) or 0))
        except (TypeError, ValueError):
            pass
        try:
            fixture_budget = max(fixture_budget,
                                 int(item.get("fixture_budget", 0) or 0))
        except (TypeError, ValueError):
            pass
        fixture_budget_truncated = (fixture_budget_truncated
                                    or bool(item.get("fixture_budget_truncated")))
        try:
            versions = max(versions, int(item.get("version_count", 0) or 0))
        except (TypeError, ValueError):
            pass
        statuses.append(item.get("status"))
        if isinstance(item.get("configuration"), dict):
            configurations.append(item["configuration"])
        if isinstance(item.get("service_lifecycle"), dict):
            service_lifecycles.append(item["service_lifecycle"])
        if not source_revision_view and isinstance(
                item.get("source_revision_artifacts"), dict):
            source_revision_view = source_revision_snapshot(
                item["source_revision_artifacts"])
        for contract in item.get("comparison_contracts") or []:
            normalized = normalize_comparison_contract(contract)
            if normalized:
                comparison_contracts[normalized["comparison_id"]] = normalized
        for cid, status in (item.get("candidate_status") or {}).items():
            candidate_status[str(cid)] = status
    if not items:
        status = "no-fixtures"
    elif any(value in {"run-failed", "precondition-unavailable", "policy-denied"}
             for value in statuses):
        status = "completed-with-gaps"
    elif fixtures:
        status = "completed"
    else:
        status = statuses[0] if statuses else "no-fixtures"
    return {
        "schema_version": LAB_SCHEMA_VERSION,
        "scope": scope,
        "status": status,
        "replay_runs": replay_runs,
        "version_count": versions,
        "fixture_count": len(fixtures),
        "fixture_budget": fixture_budget,
        "fixture_budget_truncated": fixture_budget_truncated,
        "source_revision_artifacts": source_revision_view,
        "comparison_contracts": list(comparison_contracts.values())[:16],
        "candidate_status": candidate_status,
        "fixtures": fixtures,
        "configuration": configurations[0] if configurations else {},
        "service_lifecycle": service_lifecycles[0] if service_lifecycles else {},
        "claim_status": "not-a-finding",
    }
