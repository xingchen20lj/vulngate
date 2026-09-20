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
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .authz import normalize_authz_case
from .build import (JavaMatrixRunner, MatrixCell, POCSpec, ShellMatrixRunner,
                    ShellPOCSpec)
from .redaction import redact_text
from .runtime_lab import (LAB_SCHEMA_VERSION, MAX_CELLS,
                          summarize_replay, summarize_version_differential)


MAX_S4_FIXTURES = 16
MAX_S4_REPLAY_RUNS = 5
MAX_S4_SAFE_MODES = 4
MAX_FIELD_LENGTH = 160


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
        "required_runtime": _text(cell.required_runtime, 80),
        "java_bin": _text(cell.java_bin, 160),
        "java_home": _text(cell.java_home, 160),
        "sequence_count": len(cell.sequence),
        "sequence_digest": _digest(cell.sequence),
        "concurrency": int(cell.concurrency),
        "availability_probe": bool(cell.availability_probe),
        "capability_digest": _digest(cell.capability_contract),
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
                     template_key: Optional[str] = None) -> Dict[str, Any]:
    """Build a stable ordinary-S4 fixture without persisting raw arguments."""
    candidate_id = str(candidate.get("candidate_id", ""))
    spec_info = _spec_identity(spec, kind)
    context = _safe_cell_context(cell)
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
        "sequence_count": context["sequence_count"],
        "sequence_digest": context["sequence_digest"],
        "concurrency": context["concurrency"],
        "availability_probe": context["availability_probe"],
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


def _clone_cell(cell: MatrixCell, version: str, safe_mode: bool) -> MatrixCell:
    return MatrixCell(
        version=version,
        safe_mode=safe_mode,
        features=list(cell.features),
        precondition=cell.precondition,
        args=list(cell.args),
        jvm=dict(cell.jvm),
        timeout=cell.timeout,
        authz=dict(cell.authz),
        required_runtime=cell.required_runtime,
        java_bin=cell.java_bin,
        java_home=cell.java_home,
        sequence=list(cell.sequence),
        concurrency=cell.concurrency,
        availability_probe=cell.availability_probe,
        capability_contract=dict(cell.capability_contract),
    )


def _cell_groups(cells: Iterable[MatrixCell]) -> Dict[str, List[MatrixCell]]:
    grouped: Dict[str, List[MatrixCell]] = defaultdict(list)
    for cell in cells:
        grouped[_template_key(cell)].append(cell)
    return grouped


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
                            lab_kind: str = "") -> Dict[str, Any]:
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
              lab_kind: str) -> List[Dict[str, Any]]:
    return [normalize_matrix_record(row, fixture_id, lab_kind)
            for row in rows if isinstance(row, dict)]


def _failure(version: str, safe_mode: bool, fixture_id: str,
             lab_kind: str, error: Exception) -> List[Dict[str, Any]]:
    return [normalize_matrix_record({
        "version": version,
        "safe_mode": safe_mode,
        "precondition": "none",
        "harness_error": "%s: %s" % (type(error).__name__, str(error)[:200]),
    }, fixture_id, lab_kind)]


def run_s4_runtime_lab(
        workspace: Any, target: str, round_no: int, config: Any,
        candidates: Sequence[Dict[str, Any]],
        java_specs: Sequence[POCSpec], shell_specs: Sequence[ShellPOCSpec],
        jars_by_version: Dict[str, List[Any]],
        baseline_results: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        approval: Any = None,
        version_universe: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """Run bounded replay/differential experiments for ordinary S4 specs."""
    options = _options(config)
    if not options["enabled"]:
        return {
            "schema_version": LAB_SCHEMA_VERSION,
            "scope": "ordinary-s4",
            "status": "disabled",
            "fixtures": [],
            "claim_status": "not-a-finding",
        }

    versions = sorted({str(item) for item in (version_universe or []) if str(item)})
    if not versions:
        versions = sorted({str(item) for item in jars_by_version if str(item)})
    primary_version = versions[-1] if versions else ""
    templates = _templates(candidates, java_specs, shell_specs,
                           primary_version, options)
    templates = templates[:options["max_fixtures"]]
    if not templates:
        return {
            "schema_version": LAB_SCHEMA_VERSION,
            "scope": "ordinary-s4",
            "status": "no-fixtures",
            "replay_runs": options["replay_runs"],
            "version_count": len(versions),
            "fixture_count": 0,
            "fixtures": [],
            "claim_status": "not-a-finding",
        }

    java_runner = (JavaMatrixRunner(workspace, target, round_no, approval=approval)
                   if any(item[2] == "java" for item in templates) else None)
    shell_runner = (ShellMatrixRunner(workspace, target, round_no, approval=approval)
                    if any(item[2] == "shell" for item in templates) else None)
    baseline_results = baseline_results or {}
    rows: List[Dict[str, Any]] = []
    for candidate, spec, kind, spec_index, base, template_key in templates:
        fixture = build_s4_fixture(candidate, spec, base, kind, spec_index,
                                    template_key)
        fixture_id = fixture["fixture_id"]
        candidate_id = str(candidate.get("candidate_id", ""))
        selected_versions = versions or [str(base.version)]
        primary = (str(base.version) if str(base.version) in selected_versions
                   else selected_versions[-1])
        replay_cells = [
            _clone_cell(base, primary, bool(base.safe_mode))
            for _ in range(options["replay_runs"])
        ]
        differential_cells = [
            _clone_cell(base, version, safe)
            for version in selected_versions for safe in options["safe_modes"]
        ]
        replay_id = "LAB-S4-REPLAY-" + fixture_id
        diff_id = "LAB-S4-DIFF-" + fixture_id
        replay_records: List[Dict[str, Any]] = []
        differential_records: List[Dict[str, Any]] = []
        try:
            replay_spec = _clone_spec(spec, kind, replay_id, replay_cells)
            runner = java_runner if kind == "java" else shell_runner
            if runner is None:
                raise RuntimeError("runtime lab runner unavailable")
            replay_records = _decorate(
                _run_manifest(kind, runner, replay_spec, jars_by_version),
                fixture_id, "replay")
            diff_spec = _clone_spec(spec, kind, diff_id, differential_cells)
            differential_records = _decorate(
                _run_manifest(kind, runner, diff_spec, jars_by_version),
                fixture_id, "differential")
        except Exception as exc:  # preserve a typed lab gap, keep S4 usable
            replay_records = _failure(primary, bool(base.safe_mode), fixture_id,
                                      "replay", exc)
            differential_records = _failure(primary, bool(base.safe_mode),
                                            fixture_id, "differential", exc)

        replay = summarize_replay(replay_records)
        differential = summarize_version_differential(
            differential_records, primary)
        baseline = _baseline_row(baseline_results.get(candidate_id, []),
                                 spec, kind, base)
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
            "differential_records": differential_records[:MAX_CELLS],
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
    return {
        "schema_version": LAB_SCHEMA_VERSION,
        "scope": "ordinary-s4",
        "status": "completed",
        "replay_runs": options["replay_runs"],
        "safe_modes": options["safe_modes"],
        "version_count": len(versions),
        "fixture_count": len(rows),
        "candidate_status": candidate_status,
        "fixtures": rows,
        "claim_status": "not-a-finding",
    }


def merge_runtime_lab_artifacts(artifacts: Iterable[Dict[str, Any]],
                                scope: str = "ordinary-s4") -> Dict[str, Any]:
    """Merge per-worker autonomous lab artifacts without losing gaps."""
    items = [item for item in artifacts if isinstance(item, dict)]
    fixtures: List[Dict[str, Any]] = []
    candidate_status: Dict[str, Dict[str, Any]] = {}
    replay_runs = 0
    versions = 0
    statuses = []
    for item in items:
        fixtures.extend(item.get("fixtures", []) or [])
        try:
            replay_runs = max(replay_runs, int(item.get("replay_runs", 0) or 0))
        except (TypeError, ValueError):
            pass
        try:
            versions = max(versions, int(item.get("version_count", 0) or 0))
        except (TypeError, ValueError):
            pass
        statuses.append(item.get("status"))
        for cid, status in (item.get("candidate_status") or {}).items():
            candidate_status[str(cid)] = status
    if not items:
        status = "no-fixtures"
    elif any(value in {"run-failed", "precondition-unavailable"}
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
        "candidate_status": candidate_status,
        "fixtures": fixtures,
        "claim_status": "not-a-finding",
    }
