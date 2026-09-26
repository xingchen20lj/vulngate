"""S1->S8 stage implementations (deterministic machinery + LLM judgment seams)."""

from __future__ import annotations

import json
import dataclasses
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...memory.ledger import render_finding_md, write_round_artifacts
from ...memory.research import (build_residual_closure_report,
                                build_round_memory, load_research_memory,
                                load_review_feedback, merge_research_memory,
                                research_key, write_research_memory)
from ...memory.portfolio import (build_research_portfolio,
                                write_research_portfolio)
from ...evaluation.research_consistency import (
    build_research_consistency,
    write_research_consistency,
)
from ...evaluation.research_consistency_actions import (
    action_for_research_key,
    build_research_consistency_actions,
    load_research_consistency_actions,
    write_research_consistency_actions,
)
from ...evaluation.research_consistency_rechecks import (
    build_research_consistency_rechecks,
    write_research_consistency_rechecks,
)
from ...analysis.research_strategy import (apply_strategy_observations,
                                           apply_research_guidance,
                                           load_research_strategy,
                                           strategy_guidance_for_candidate,
                                           write_research_guidance,
                                           write_research_strategy)
from ...analysis.research_agenda import (build_research_agenda,
                                        load_research_agenda,
                                        selected_candidate_ids,
                                        write_research_agenda)
from ...analysis.research_agenda_outcomes import (
    build_research_agenda_outcomes,
    load_research_agenda_outcomes,
    load_schedule_snapshot,
    write_research_agenda_outcomes,
)
from ...analysis.research_budget import (
    build_research_budget,
    load_research_budget,
    write_research_budget,
)
from ...memory.state import CheckpointStore
from ...analysis.languages import (ALL_SUFFIXES, SOURCE_INVENTORY_POLICY_VERSION,
                                  SourceFilter, SourceScanTimeout,
                                  resolve_source_dirs)
from ...sandbox.approval import ApprovalGate
from ...sandbox.runner import CommandRunner
from ..work_budget import WorkBudget
from ...tools import search as srch
from ...tools.build import (JavaMatrixRunner, MatrixCell, POCSpec,
                           ShellMatrixRunner, ShellPOCSpec, summarize_candidate,
                           converge_s4_cells, S4_EVIDENCE_POLICY_VERSION,
                           S4ExecutionBudget)
from ...tools.authz import (assert_authz_observations, authz_fixture_id,
                           normalize_authz_case, normalize_authz_cases)
from ...tools.conclusion import conclusion_status, derive_conclusion, is_confirmed_conclusion
from ...tools.cvss import base_score, check_impact_consistency
from ...tools.source_evidence import (build_source_sink_graph,
                                     match_source_sink_paths)
from ...tools.patch_variants import analyze_patch_history, fix_completeness_candidate
from ...tools.project_profile import build_project_profile
from ...tools.experiment_planner import plan_candidate_experiments
from ...tools.experiment import capability_contract_from_candidate
from ...tools.research_strategies import composite_chain_candidates
from ...tools.s4_runtime_lab import run_s4_runtime_lab
from ...tools.service_lifecycle import ServiceLifecycle
from ...tools.target_rules import composite_chain_hints, scan_s1_source_rules
from ...tools.novelty import (Disclosure, NoveltyChecker, UpstreamRef,
                             mechanism_audit_llm,
                             upstream_ref_from_search_hit)
from ...tools.public_scan import (NOVELTY_QUERY_POLICY_VERSION, scan_all)
from ..config import TargetConfig
from ..gates import (GateResult, g0_dead_code, g1_reachable, g1b_gate_blocks,
                    g3_novelty, g4_runtime, g5_cvss, g5_record_valid)


class StageContext:
    def __init__(self, workspace: Path, target: str, round_no: int,
                 config: TargetConfig, offline: bool = False,
                 llm: Optional[Any] = None):
        self.workspace = workspace
        self.target = target
        self.round_no = round_no
        self.config = config
        self.offline = offline
        self.llm = llm
        self.store = CheckpointStore(workspace, target, round_no)
        self.approval = ApprovalGate(log_path=self.store.approval_log())
        self.runner = CommandRunner(workspace, self.approval)
        self.checked_at = datetime.now().isoformat(timespec="seconds")
        self._public_scan_cache: Optional[Dict[str, Any]] = None
        self._benchmark_feedback_cache: Optional[Dict[str, Any]] = None
        self._replay_cohort_cache: Optional[Dict[str, Any]] = None

    def public_disclosures(self) -> Dict[str, Any]:
        if self._public_scan_cache is None:
            self._public_scan_cache = scan_all(
                self.config, offline=self.offline,
                cache_dir=self.workspace / "agent" / "regression" / "cache" / "api")
        return self._public_scan_cache

    def fixture_dir(self) -> Optional[Path]:
        d = self.workspace / "agent" / "regression" / "fixtures"
        return d if d.exists() else None

    def benchmark_feedback(self) -> Dict[str, Any]:
        """Load only explicitly configured benchmark feedback for this target."""
        if self._benchmark_feedback_cache is not None:
            return dict(self._benchmark_feedback_cache)
        from ...evaluation.benchmark import benchmark_feedback_from_input

        value: Any = getattr(self.config, "benchmark_feedback", {}) or {}
        configured_path = getattr(self.config, "benchmark_feedback_path", None)
        if configured_path:
            path = Path(configured_path)
            if not path.is_absolute():
                path = self.workspace / path
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                value = {}
        self._benchmark_feedback_cache = benchmark_feedback_from_input(value)
        return dict(self._benchmark_feedback_cache)

    def replay_cohort_calibration(self) -> Dict[str, Any]:
        """Load only explicitly configured cross-project replay metadata."""
        if self._replay_cohort_cache is not None:
            return dict(self._replay_cohort_cache)
        configured_path = getattr(
            self.config, "replay_cohort_calibration_path", None)
        value: Dict[str, Any] = {}
        if configured_path:
            from ...evaluation.replay_cohort import load_replay_cohort_file

            path = Path(configured_path)
            if not path.is_absolute():
                path = self.workspace / path
            value = load_replay_cohort_file(path)
        self._replay_cohort_cache = value
        return dict(value)


def _coverage_scope_incomplete(summary: Any) -> bool:
    """Whether a coverage artifact is unsafe to use as a current universe."""
    if not isinstance(summary, dict) or not summary:
        return True
    if summary.get("status") in {"incomplete", "failed"}:
        return True
    scope = summary.get("scope")
    if not isinstance(scope, dict):
        return True
    if scope.get("valid") is not True:
        return True
    if scope.get("status") != "matched":
        return True
    audit_status = summary.get("audit_status")
    return (isinstance(audit_status, dict)
            and audit_status.get("scope_valid") is False)


def _effective_source_dirs(ctx: StageContext) -> List[str]:
    """Canonical source roots shared by S1 evidence and coverage indexing.

    ``build_inventory`` records invalid configured roots as a scope gap instead
    of widening to the workspace.  S1's direct grep helpers must use that same
    decision; otherwise the coverage artifact and the source-evidence artifact
    could honestly describe two different universes.
    """
    _bases, source_dirs, _invalid = resolve_source_dirs(
        ctx.workspace, ctx.config.source_dirs)
    return source_dirs


def _gate_scan(ctx: StageContext) -> List[Dict[str, Any]]:
    keywords = ["SafeMode", "SupportAutoType", "checkAutoType", "maxLevel",
                "readLength", "deny", "registerIfAbsent", "getObjectReader("]
    hits = []
    for src in _effective_source_dirs(ctx):
        d = ctx.workspace / src
        if not d.exists():
            continue
        for kw in keywords:
            # [vulngate-macos-universal] 去掉 *.java 硬编码：
            # globs=None 时 srch.rg 扫全部文件，
            # 让 source-evidence 的白名单成为唯一口径。
            lines = srch.rg(kw, d, max_count=6)
            if lines:
                hits.append({"keyword": kw, "source": src, "lines": lines})
    return hits


def _fix_history(ctx: StageContext) -> List[Dict[str, Any]]:
    """The S1 patch-history artifact, or ``[]`` when S1 did not produce one.

    Optional input to the PR4 sibling diff (spec §18 Phase 4 "patch sibling
    diff"): with no history the differential simply has no patch-evidence
    findings.  Read defensively because this runs at the end of S1, where a
    patch-analysis failure must not take the coverage index down with it.
    """
    try:
        return list(ctx.store.read_artifact("S1", "security-fix-history.json") or [])
    except Exception:  # pragma: no cover - artifact store is best-effort here
        return []


def _build_coverage_index(ctx: StageContext) -> Dict[str, Any]:
    """S1 -> Inventory / Coverage Index (spec §21.3).

    The inventory is built once and then *refreshed*: rebuilding the whole
    source universe on every round would be wasted work, while re-deriving the
    review state from the round ledgers is cheap and is what actually changes
    between rounds.  The index is target-scoped (``state/<target>/coverage/``),
    not round-scoped, because coverage accumulates.

    A store built by an earlier phase is rebuilt rather than trusted: the PR2
    indices (symbol index, call graph, flow index) are a strict superset of the
    PR1 indices, and ``source-inventory.json`` existing is not evidence that
    they do.  Without this check an upgraded checkout silently keeps scoring
    flows it never computed.

    PR4's control map, differential index and semantic path/guard/call/control-flow/AST/transform evidence join that
    required set for the same reason: a store built by an earlier phase has
    flows but no complete path evidence, and a scheduler that silently scored
    without it would look identical to one that had it.
    """
    from ...analysis import controls as ctl
    from ...analysis import capability_graph as capability
    from ...analysis import coverage as cov
    from ...analysis import differential as diff
    from ...analysis import semantic_guards as semantic_guard
    from ...analysis import semantic_calls as semantic_call
    from ...analysis import semantic_controlflow as semantic_controlflow
    from ...analysis import semantic_ast as semantic_ast
    from ...analysis import semantic_transforms as semantic_transform
    from ...analysis import semantic_bindings as semantic_binding
    from ...analysis import evidence_provenance as evidence_provenance_analysis
    from ...analysis import semantic_paths as semantic
    from ...analysis import threat_model as threat_model_analysis
    from ...analysis.inventory import (CoverageStore, build_inventory,
                                      coverage_scope_status, persist_inventory)

    store = CoverageStore(ctx.workspace, ctx.target)
    scan_filter = SourceFilter(scan_timeout_seconds=int(
        getattr(ctx.config, "coverage_scan_timeout_seconds", 600) or 0))
    required = ("source-inventory", "flow-index", "symbol-index",
                ctl.CONTROL_MAP_INDEX, diff.DIFFERENTIAL_INDEX,
                capability.CAPABILITY_GRAPH_INDEX,
                semantic.SEMANTIC_PATH_INDEX,
                semantic_guard.SEMANTIC_GUARD_INDEX,
                semantic_call.SEMANTIC_CALL_INDEX,
                semantic_controlflow.SEMANTIC_CONTROLFLOW_INDEX,
                semantic_ast.SEMANTIC_AST_INDEX,
                semantic_transform.SEMANTIC_TRANSFORM_INDEX,
                semantic_binding.SEMANTIC_BINDING_INDEX,
                evidence_provenance_analysis.EVIDENCE_PROVENANCE_INDEX,
                threat_model_analysis.THREAT_MODEL_INDEX)
    missing = [name for name in required if not store.path(name).exists()]
    scope_before = coverage_scope_status(
        store, ctx.workspace, ctx.config.source_dirs,
        source_filter=scan_filter, target_type=ctx.config.target_type)
    # ``invalid`` is a meaningful persisted result: rebuilding the same typo
    # every round adds cost without repairing the audit universe.  Missing,
    # legacy, and mismatched contracts on the other hand are unsafe to reuse.
    scope_requires_rebuild = scope_before["status"] in {
        "missing", "legacy", "mismatch", "incomplete", "running", "failed",
    }
    built = False
    if missing or scope_requires_rebuild:
        store.write("coverage-build-status", {
            "status": "running", "started_at": datetime.now().isoformat(timespec="seconds"),
            "timeout_seconds": scan_filter.scan_timeout_seconds,
            "source_dirs": list(ctx.config.source_dirs or ["."]),
        })
        ctx.store.write_artifact("S1", "coverage-progress.json", {
            "status": "running", "started_at": datetime.now().isoformat(timespec="seconds"),
            "timeout_seconds": scan_filter.scan_timeout_seconds,
            "source_dirs": list(ctx.config.source_dirs or ["."]),
        })

        def report_progress(progress: Dict[str, Any]) -> None:
            ctx.store.write_artifact("S1", "coverage-progress.json", {
                "status": "running", "timeout_seconds": scan_filter.scan_timeout_seconds,
                **progress,
            })

        result = build_inventory(ctx.workspace, ctx.config.source_dirs,
                                 target=ctx.target,
                                 target_type=ctx.config.target_type,
                                 fix_history=_fix_history(ctx),
                                 source_filter=scan_filter,
                                 progress_callback=report_progress)
        persist_inventory(store, result, target_type=ctx.config.target_type)
        store.write("coverage-build-status", {
            "status": "complete", "completed_at": datetime.now().isoformat(timespec="seconds"),
            "scope_id": result.scope.get("scope_id", ""),
            "source_files": len(result.files), "elapsed_ms": result.elapsed_ms,
        })
        ctx.store.write_artifact("S1", "coverage-progress.json", {
            "status": "complete", "elapsed_ms": result.elapsed_ms,
            "files_seen": result.scanned_files,
            "source_files": len(result.files),
        })
        built = True
    info = cov.refresh_candidate_coverage(store, ctx.workspace, ctx.target)
    info["rebuilt"] = built
    info["missing_indices"] = missing
    scope_after = coverage_scope_status(
        store, ctx.workspace, ctx.config.source_dirs,
        source_filter=scan_filter, target_type=ctx.config.target_type)
    scope_actual = scope_after.get("actual") or {}
    info["scope"] = {
        "before": scope_before["status"],
        "status": scope_after["status"],
        "scope_id": scope_actual.get("scope_id", ""),
        "valid": bool(scope_actual.get("valid", False)),
        "analysis_gaps": list(scope_actual.get("analysis_gaps") or []),
        "mismatches": scope_after.get("mismatches", []),
        "claim_status": "not-a-finding",
    }
    summary = store.read("call-graph-summary") or {}
    flow_summary = store.read("flow-summary") or {}
    control_summary = (store.read(ctl.CONTROL_MAP_INDEX) or {}).get("summary") or {}
    differential_summary = (store.read(diff.DIFFERENTIAL_INDEX) or {}).get("summary") or {}
    capability_summary = (store.read(capability.CAPABILITY_GRAPH_INDEX) or {}).get("summary") or {}
    semantic_summary = (store.read(semantic.SEMANTIC_PATH_INDEX) or {}).get("summary") or {}
    semantic_guard_summary = (store.read(
        semantic_guard.SEMANTIC_GUARD_INDEX) or {}).get("summary") or {}
    semantic_call_summary = (store.read(
        semantic_call.SEMANTIC_CALL_INDEX) or {}).get("summary") or {}
    semantic_controlflow_summary = (store.read(
        semantic_controlflow.SEMANTIC_CONTROLFLOW_INDEX) or {}).get("summary") or {}
    semantic_ast_summary = (store.read(
        semantic_ast.SEMANTIC_AST_INDEX) or {}).get("summary") or {}
    semantic_transform_summary = (store.read(
        semantic_transform.SEMANTIC_TRANSFORM_INDEX) or {}).get("summary") or {}
    semantic_binding_summary = (store.read(
        semantic_binding.SEMANTIC_BINDING_INDEX) or {}).get("summary") or {}
    provenance_summary = (store.read(
        evidence_provenance_analysis.EVIDENCE_PROVENANCE_INDEX) or {}).get("summary") or {}
    threat_model_summary = (store.read(
        threat_model_analysis.THREAT_MODEL_INDEX) or {}).get("summary") or {}
    if control_summary:
        info["control_map"] = {
            "flows": control_summary.get("flows"),
            "verdicts": control_summary.get("verdicts"),
            "missing_controls": control_summary.get("missing_controls"),
            "auth_bypass_paths": control_summary.get("auth_bypass_paths"),
            "validation_gap_paths": control_summary.get("validation_gap_paths"),
        }
    if differential_summary:
        info["differential"] = {
            "members": differential_summary.get("members"),
            "groups": differential_summary.get("groups"),
            "findings": differential_summary.get("findings"),
            "findings_by_kind": differential_summary.get("findings_by_kind"),
            "findings_by_risk": differential_summary.get("findings_by_risk"),
        }
    if capability_summary:
        info["capability_graph"] = {
            "nodes": capability_summary.get("nodes"),
            "edges": capability_summary.get("edges"),
            "flows_considered": capability_summary.get("flows_considered"),
            "observed_capabilities": capability_summary.get("observed_capabilities"),
            "paths": capability_summary.get("paths"),
            "complete_hypotheses": capability_summary.get("complete_hypotheses"),
            "partial_hypotheses": capability_summary.get("partial_hypotheses"),
            "truncated": capability_summary.get("truncated"),
        }
    if semantic_summary:
        info["semantic_paths"] = {
            "flows": semantic_summary.get("flows"),
            "same_symbol_flows": semantic_summary.get("same_symbol_flows"),
            "taint_status": semantic_summary.get("taint_status"),
            "semantic_verdicts": semantic_summary.get("semantic_verdicts"),
            "order_gap_flows": semantic_summary.get("order_gap_flows"),
            "dataflow_gap_flows": semantic_summary.get("dataflow_gap_flows"),
            "candidates": semantic_summary.get("candidates"),
            "claim_status": semantic_summary.get("claim_status", "not-a-finding"),
        }
    if semantic_guard_summary:
        info["semantic_guards"] = {
            "flows": semantic_guard_summary.get("flows"),
            "flows_with_branch_gaps": semantic_guard_summary.get(
                "flows_with_branch_gaps"),
            "flows_with_subject_binding_gaps": semantic_guard_summary.get(
                "flows_with_subject_binding_gaps"),
            "branch_postures": semantic_guard_summary.get("branch_postures"),
            "subject_binding": semantic_guard_summary.get("subject_binding"),
            "candidates": semantic_guard_summary.get("candidates"),
            "claim_status": semantic_guard_summary.get(
                "claim_status", "not-a-finding"),
        }
    if semantic_call_summary:
        info["semantic_calls"] = {
            "flows": semantic_call_summary.get("flows"),
            "cross_symbol_flows": semantic_call_summary.get("cross_symbol_flows"),
            "call_steps": semantic_call_summary.get("call_steps"),
            "callsite_status": semantic_call_summary.get("callsite_status"),
            "parameter_bindings": semantic_call_summary.get("parameter_bindings"),
            "return_bindings": semantic_call_summary.get("return_bindings"),
            "sink_binding": semantic_call_summary.get("sink_binding"),
            "candidates": semantic_call_summary.get("candidates"),
            "claim_status": semantic_call_summary.get(
                "claim_status", "not-a-finding"),
        }
    if semantic_controlflow_summary:
        info["semantic_controlflow"] = {
            "flows": semantic_controlflow_summary.get("flows"),
            "controls": semantic_controlflow_summary.get("controls"),
            "flows_with_alternate_paths": semantic_controlflow_summary.get(
                "flows_with_alternate_paths"),
            "flows_with_dominance_likely": semantic_controlflow_summary.get(
                "flows_with_dominance_likely"),
            "relations": semantic_controlflow_summary.get("relations"),
            "candidates": semantic_controlflow_summary.get("candidates"),
            "claim_status": semantic_controlflow_summary.get(
                "claim_status", "not-a-finding"),
        }
    if semantic_ast_summary:
        info["semantic_ast"] = {
            "flows": semantic_ast_summary.get("flows"),
            "controls": semantic_ast_summary.get("controls"),
            "files": semantic_ast_summary.get("files"),
            "parsed_files": semantic_ast_summary.get("parsed_files"),
            "parser_status": semantic_ast_summary.get("parser_status"),
            "relations": semantic_ast_summary.get("relations"),
            "candidates": semantic_ast_summary.get("candidates"),
            "claim_status": semantic_ast_summary.get(
                "claim_status", "not-a-finding"),
        }
    if semantic_transform_summary:
        info["semantic_transforms"] = {
            "flows": semantic_transform_summary.get("flows"),
            "controls": semantic_transform_summary.get("controls"),
            "flows_with_binding_gaps": semantic_transform_summary.get(
                "flows_with_binding_gaps"),
            "relations": semantic_transform_summary.get("relation_counts"),
            "verdicts": semantic_transform_summary.get("verdicts"),
            "candidates": semantic_transform_summary.get("candidates"),
            "claim_status": semantic_transform_summary.get(
                "claim_status", "not-a-finding"),
        }
    if semantic_binding_summary:
        info["semantic_bindings"] = {
            "flows": semantic_binding_summary.get("flows"),
            "controls": semantic_binding_summary.get("controls"),
            "files": semantic_binding_summary.get("files"),
            "parsed_files": semantic_binding_summary.get("parsed_files"),
            "parser_status": semantic_binding_summary.get("parser_status"),
            "relations": semantic_binding_summary.get("relations"),
            "candidates": semantic_binding_summary.get("candidates"),
            "claim_status": semantic_binding_summary.get(
                "claim_status", "not-a-finding"),
        }
    if provenance_summary:
        info["evidence_provenance"] = {
            "records": provenance_summary.get("records"),
            "raw_source_facts": provenance_summary.get("raw_source_facts"),
            "derived_evidence": provenance_summary.get("derived_evidence"),
            "candidate_evidence": provenance_summary.get("candidate_evidence"),
            "independence_groups": provenance_summary.get("independence_groups"),
            "correlated_groups": provenance_summary.get("correlated_groups"),
            "correlated_candidates": provenance_summary.get("correlated_candidates"),
            "claim_status": provenance_summary.get(
                "claim_status", "not-a-finding"),
        }
    if threat_model_summary:
        info["threat_model"] = {
            "boundaries": threat_model_summary.get("boundaries"),
            "attack_paths": threat_model_summary.get("attack_paths"),
            "high_priority_paths": threat_model_summary.get("high_priority_paths"),
            "capability_linked_paths": threat_model_summary.get(
                "capability_linked_paths"),
            "unmapped_entries": threat_model_summary.get("unmapped_entries"),
            "unmapped_sinks": threat_model_summary.get("unmapped_sinks"),
            "truncated": threat_model_summary.get("truncated"),
            "claim_status": threat_model_summary.get(
                "claim_status", "not-a-finding"),
        }
    if summary:
        info["call_graph"] = {
            "nodes": summary.get("nodes"), "edges": summary.get("edges"),
            "propagation": summary.get("propagation"),
            "unresolved_calls": summary.get("unresolved_calls"),
            "ambiguous_names": summary.get("ambiguous_names"),
        }
    if flow_summary:
        info["flows"] = {
            "total": flow_summary.get("flows"),
            "by_priority": flow_summary.get("flows_by_priority"),
            "sinks_forward_seen": flow_summary.get("sinks_forward_seen"),
            "sinks_backward_seen": flow_summary.get("sinks_backward_seen"),
            "coverage_gaps": flow_summary.get("coverage_gaps"),
            "truncated": flow_summary.get("truncated"),
        }
    return info



def _merge_static_candidates(ctx: StageContext, pool: List[Dict[str, Any]]
                             ) -> "tuple[List[Dict[str, Any]], List[str]]":
    """Add the PR4 index-derived candidates to a round's pool, never raising.

    Returns ``(pool, added_ids)``.  A missing or unreadable coverage store means
    "no static candidates this round" and the reason is returned as an empty
    list rather than an exception: losing an ordering aid must not cost the
    round its audit (same contract as :func:`_schedule_round`).  ``added_ids`` is
    surfaced into the S2 result so a pool that grew says so.
    """
    from ...analysis import controls as ctl
    from ...analysis.inventory import CoverageStore

    if not bool(getattr(ctx.config, "static_candidates", True)):
        return pool, []
    try:
        store = CoverageStore(ctx.workspace, ctx.target)
        merged, added = ctl.merge_static_candidates(store, pool)
    except Exception:  # pragma: no cover - defensive, mirrors _schedule_round
        return pool, []
    if added:
        print("[S2] +%d index-derived candidates (%s)"
              % (len(added), ", ".join(added[:6]) + ("..." if len(added) > 6 else "")))
    return merged, added


def _candidate_budget(ctx: StageContext) -> int:
    """Resolve a finite per-round budget, including legacy ``0`` configs."""
    from ...analysis import scheduler as sched

    try:
        configured = int(getattr(ctx.config, "max_candidates", 0) or 0)
    except (TypeError, ValueError):
        configured = 0
    return configured if configured > 0 else sched.DEFAULT_SLOTS


def _schedule_round(ctx: StageContext,
                    pool: List[Dict[str, Any]], slots: Optional[int] = None,
                    priority_ids: Optional[List[str]] = None
                    ) -> "tuple[List[Dict[str, Any]], Any, str]":
    """Run the coverage-aware scheduler for one round, never raising.

    S1 already refreshed the coverage index, so the sweep is not repeated here
    (``refresh=False``) -- re-running it before this round's ledger exists would
    double the work and change nothing.  A scheduler failure degrades to the
    pre-PR3 behaviour and returns the reason, because losing the ordering must
    not cost the round its audit.

    The slot count is always finite.  A legacy/unset ``max_candidates=0`` maps
    to the scheduler default rather than expanding into the entire static
    candidate pool.  Candidates outside the active intake window remain in
    their source artifacts with an explicit queued count.
    """
    from ...analysis import scheduler as sched
    slots = int(slots if slots is not None else _candidate_budget(ctx))
    try:
        return sched.round_selection(
            ctx.workspace, ctx.target, pool, slots,
            round_no=ctx.round_no, refresh=False,
            priority_ids=priority_ids or (),
            benchmark_feedback=ctx.benchmark_feedback())
    except Exception as exc:  # pragma: no cover - defensive by design
        return pool[:slots], None, (
            "scheduler unavailable (%s: %s); fell back to proposal order"
            % (type(exc).__name__, exc))



def _poc_specs(ctx: StageContext) -> List[POCSpec]:
    specs = []
    for cand in ctx.config.candidates:
        candidate_cases = normalize_authz_cases(cand.get("authz_cases"))
        for poc in cand.get("pocs", []):
            if "script" in poc:
                continue  # shell PoCs are collected separately
            poc_sequence = poc.get("sequence", cand.get("sequence", []))
            poc_concurrency = poc.get("concurrency", cand.get("concurrency", 1))
            poc_probe = poc.get("availability_probe", cand.get("availability_probe", False))
            cells = [MatrixCell(
                version=c["version"], safe_mode=c["safe_mode"],
                features=c.get("features", []), precondition=c.get("precondition", "none"),
                args=c.get("args", []), jvm=c.get("jvm", {}),
                timeout=c.get("timeout"),
                sequence=c.get("sequence", poc_sequence),
                concurrency=c.get("concurrency", poc_concurrency),
                availability_probe=c.get("availability_probe", poc_probe),
                required_runtime=str(c.get("required_runtime", c.get("requested_runtime", ""))),
                java_bin=str(c.get("java_bin", "")), java_home=str(c.get("java_home", "")),
                authz=normalize_authz_case(c.get("authz") or
                                           (candidate_cases[0] if len(candidate_cases) == 1 else {})),
                capability_contract=capability_contract_from_candidate(
                    {**cand, **poc, **c}),
                residual_contracts=(c.get("residual_contracts")
                                    or poc.get("residual_contracts")
                                    or (cand.get("experiment_plan") or {}).get(
                                        "residual_contracts", [])),
                consistency_action=(cand.get("experiment_plan") or {}).get(
                    "consistency_action", {}),
            ) for c in poc.get("cells", [])]
            specs.append(POCSpec(
                candidate_id=cand["candidate_id"],
                class_name=poc["class_name"],
                src=poc["src"],
                cells=cells,
                safe_mode_jvm_prop=poc.get("safe_mode_jvm_prop", ""),
                module_opts=poc.get("module_opts", []),
                module_run_opts=poc.get("module_run_opts", poc.get("module_opts", [])),
                jvm_default=poc.get("jvm_default", {}),
                entry=cand.get("entry", ""),
                input_shape=cand.get("input_shape", ""),
                logic=cand.get("logic", ""),
            ))
    return specs


def _shell_poc_specs(ctx: StageContext) -> List[ShellPOCSpec]:
    specs = []
    for cand in ctx.config.candidates:
        candidate_cases = normalize_authz_cases(cand.get("authz_cases"))
        for poc in cand.get("pocs", []):
            if "script" not in poc:
                continue
            poc_sequence = poc.get("sequence", cand.get("sequence", []))
            poc_concurrency = poc.get("concurrency", cand.get("concurrency", 1))
            poc_probe = poc.get("availability_probe", cand.get("availability_probe", False))
            cells = [MatrixCell(
                version=c["version"], safe_mode=c["safe_mode"],
                features=c.get("features", []), precondition=c.get("precondition", "none"),
                args=c.get("args", []), jvm=c.get("jvm", {}),
                timeout=c.get("timeout"),
                sequence=c.get("sequence", poc_sequence),
                concurrency=c.get("concurrency", poc_concurrency),
                availability_probe=c.get("availability_probe", poc_probe),
                required_runtime=str(c.get("required_runtime", c.get("requested_runtime", ""))),
                java_bin=str(c.get("java_bin", "")), java_home=str(c.get("java_home", "")),
                authz=normalize_authz_case(c.get("authz") or
                                           (candidate_cases[0] if len(candidate_cases) == 1 else {})),
                capability_contract=capability_contract_from_candidate(
                    {**cand, **poc, **c}),
                residual_contracts=(c.get("residual_contracts")
                                    or poc.get("residual_contracts")
                                    or (cand.get("experiment_plan") or {}).get(
                                        "residual_contracts", [])),
                consistency_action=(cand.get("experiment_plan") or {}).get(
                    "consistency_action", {}),
            ) for c in poc.get("cells", [])]
            specs.append(ShellPOCSpec(
                candidate_id=cand["candidate_id"],
                script=poc["script"],
                cells=cells,
                env=dict(poc.get("env", {})),
                urls=dict(poc.get("urls", ctx.config.target_urls)),
                entry=cand.get("entry", ""),
                input_shape=cand.get("input_shape", ""),
                logic=cand.get("logic", ""),
            ))
    return specs


def _stage_pocs(ctx: StageContext) -> None:
    """Copy PoC sources from config.poc_src_dir into the round src dir (idempotent)."""
    src_round = ctx.workspace / "poc" / ctx.target / ("round-%02d" % ctx.round_no) / "src"
    src_round.mkdir(parents=True, exist_ok=True)
    if not ctx.config.poc_src_dir:
        return
    poc_dir = ctx.workspace / ctx.config.poc_src_dir
    if not poc_dir.exists():
        return
    for f in sorted(poc_dir.glob("*.java")) + sorted(poc_dir.glob("*.sh")):
        target = src_round / f.name
        if not target.exists():
            target.write_text(f.read_text(encoding="utf-8"), encoding="utf-8")


def _service_gap_row(spec: Any, cell: MatrixCell,
                     service_info: Dict[str, Any], kind: str) -> Dict[str, Any]:
    """Represent a missing target service as a typed S4 precondition gap."""
    name = getattr(spec, "class_name", "") if kind == "java" else getattr(spec, "script", "")
    result = {
        "candidate_id": str(getattr(spec, "candidate_id", "")),
        "poc_class" if kind == "java" else "poc_script": name,
        "version": cell.version,
        "safe_mode": cell.safe_mode,
        "features": list(cell.features),
        "precondition": cell.precondition,
        "required_runtime": cell.required_runtime,
        "authz": normalize_authz_case(cell.authz),
        "authz_fixture_id": authz_fixture_id(cell.authz),
        "returncode": None,
        "timed_out": False,
        "precondition_status": "precondition-unavailable",
        "observations": {"GATE_BLOCKED": "precondition-unavailable"},
        "authz_assertion": assert_authz_observations(cell.authz, {}),
        "harness_error": "service precondition unavailable: %s" % (
            service_info.get("reason") or service_info.get("status") or "unknown"),
        "lang": kind,
        "claim_status": "not-a-finding",
    }
    return result



def _evidence_from_summary(summary: Dict[str, Any], candidate: Dict[str, Any]) -> List[str]:
    ev = []
    if summary.get("harness_error"):
        ev.append("HARNESS_ERROR=" + str(summary["harness_error"]))
    if summary.get("compile_error"):
        ev.append("COMPILE_ERROR=" + str(summary["compile_error"]))
    if summary.get("execution_state"):
        ev.append("S4_EXECUTION_STATE=" + str(summary["execution_state"]))
    if summary.get("s4_result_sources"):
        ev.append("S4_RESULT_SOURCES=" + ",".join(summary["s4_result_sources"]))
    for claim in summary.get("poc_claims", [])[:4]:
        ev.append("POC_CLAIM_UNTRUSTED=%s" % json.dumps(
            claim.get("fields", {}), ensure_ascii=False, separators=(",", ":"))[:360])
    for i in summary.get("instantiated", [])[:4]:
        ev.append("%s SafeMode=%s %s -> INSTANTIATED %s" % (
            i["version"], i["safe"], i["precondition"], i["class"]))
    for e in summary.get("errors", [])[:6]:
        ev.append("%s SafeMode=%s %s -> ERROR %s" % (
            e["version"], e["safe"], e["precondition"], e["error"]))
    for g in summary.get("gate_blocked", [])[:4]:
        ev.append("%s SafeMode=%s %s -> GATE_BLOCKED %s" % (
            g["version"], g["safe"], g["precondition"], g["class"]))
    for n in summary.get("network_side_effects", [])[:2]:
        ev.append("NETWORK %s" % n)
    for lk in summary.get("leaked", [])[:3]:
        ev.append("%s SafeMode=%s %s -> LEAKED %s" % (
            lk["version"], lk["safe"], lk["precondition"], lk["leaked"][:120]))
    for c in summary.get("safe_equivalent", [])[:4]:
        ev.append("%s SafeMode=%s %s -> SAFE_EQUIVALENT %s %s" % (
            c["version"], c["safe"], c["precondition"], c["kind"], c.get("detail", "")))
    for e in summary.get("effect_evidence", [])[:4]:
        ev.append("%s SafeMode=%s %s -> EFFECT_KIND=%s EFFECT=%s" % (
            e["version"], e["safe"], e["precondition"], e["kind"], e.get("detail", "")))
    for a in summary.get("availability_proof", [])[:2]:
        ev.append("%s SafeMode=%s %s -> AVAILABILITY_PROOF=concurrency:%s service_unavailable:%s" % (
            a["version"], a["safe"], a["precondition"], a["concurrency"], a["service_unavailable"]))
    for x in summary.get("experiment_evidence", [])[:4]:
        ev.append("%s SafeMode=%s %s -> EXPERIMENT sequence=%s sequence_status=%s "
                  "declared_concurrency=%s probe=%s STEP=%s STATE=%s STEP_EVIDENCE=%s" % (
                      x.get("version"), x.get("safe"), x.get("precondition"),
                      ",".join(str(s) for s in x.get("declared_sequence", [])) or "-",
                      x.get("sequence_status", "unknown"),
                      x.get("declared_concurrency", 1),
                      x.get("declared_availability_probe", False),
                      "|".join(str(s) for s in x.get("step_trace", [])[:8]) or "-",
                      "|".join(str(s) for s in x.get("state_trace", [])[:8]) or "-",
                      "|".join(str(s) for s in x.get("step_evidence", [])[:4]) or "-"))
    for a in summary.get("authz_results", [])[:8]:
        az = a.get("authz", {})
        ev.append("%s SafeMode=%s %s -> AUTHZ_CASE=%s principal=%s role=%s tenant=%s object=%s assertion=%s boundary_violation=%s" % (
            a.get("version"), a.get("safe"), a.get("precondition"),
            az.get("case_id", "?"), az.get("principal", "?"), az.get("role", "?"),
            az.get("tenant_id", "?"), az.get("object_id", "?"),
            a.get("status"), a.get("boundary_violation")))
    for issue in summary.get("validation_issues", [])[:4]:
        ev.append("VALIDATION_ISSUE=" + str(issue))
    ev.append("cells_ran=%d" % summary.get("cells_ran", 0))
    return ev



def _precondition_distribution(rows: List[Dict[str, Any]]) -> str:
    from collections import Counter
    c = Counter(r.get("precondition_tier", "?") for r in rows
                if is_confirmed_conclusion(r.get("conclusion")))
    return ", ".join("%s=%d" % (k, v) for k, v in sorted(c.items()))


