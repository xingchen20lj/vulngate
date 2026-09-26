"""Independent Sx stage implementation.

Stage-specific logic is kept in this module; shared audit context and bounded
helpers live in the common module.
"""

from __future__ import annotations

from .common import (
    ALL_SUFFIXES,
    Any,
    ApprovalGate,
    CheckpointStore,
    CommandRunner,
    Dict,
    Disclosure,
    GateResult,
    JavaMatrixRunner,
    List,
    MatrixCell,
    NOVELTY_QUERY_POLICY_VERSION,
    NoveltyChecker,
    Optional,
    POCSpec,
    Path,
    S4ExecutionBudget,
    S4_EVIDENCE_POLICY_VERSION,
    SOURCE_INVENTORY_POLICY_VERSION,
    ServiceLifecycle,
    ShellMatrixRunner,
    ShellPOCSpec,
    SourceFilter,
    SourceScanTimeout,
    StageContext,
    TargetConfig,
    UpstreamRef,
    WorkBudget,
    action_for_research_key,
    analyze_patch_history,
    apply_research_guidance,
    apply_strategy_observations,
    assert_authz_observations,
    authz_fixture_id,
    base_score,
    build_project_profile,
    build_research_agenda,
    build_research_agenda_outcomes,
    build_research_budget,
    build_research_consistency,
    build_research_consistency_actions,
    build_research_consistency_rechecks,
    build_research_portfolio,
    build_residual_closure_report,
    build_round_memory,
    build_source_sink_graph,
    capability_contract_from_candidate,
    check_impact_consistency,
    composite_chain_candidates,
    composite_chain_hints,
    conclusion_status,
    converge_s4_cells,
    dataclasses,
    datetime,
    derive_conclusion,
    fix_completeness_candidate,
    g0_dead_code,
    g1_reachable,
    g1b_gate_blocks,
    g3_novelty,
    g4_runtime,
    g5_cvss,
    g5_record_valid,
    is_confirmed_conclusion,
    json,
    load_research_agenda,
    load_research_agenda_outcomes,
    load_research_budget,
    load_research_consistency_actions,
    load_research_memory,
    load_research_strategy,
    load_review_feedback,
    load_schedule_snapshot,
    match_source_sink_paths,
    mechanism_audit_llm,
    merge_research_memory,
    normalize_authz_case,
    normalize_authz_cases,
    plan_candidate_experiments,
    re,
    render_finding_md,
    research_key,
    resolve_source_dirs,
    run_s4_runtime_lab,
    scan_all,
    scan_s1_source_rules,
    selected_candidate_ids,
    srch,
    strategy_guidance_for_candidate,
    summarize_candidate,
    upstream_ref_from_search_hit,
    write_research_agenda,
    write_research_agenda_outcomes,
    write_research_budget,
    write_research_consistency,
    write_research_consistency_actions,
    write_research_consistency_rechecks,
    write_research_guidance,
    write_research_memory,
    write_research_portfolio,
    write_research_strategy,
    write_round_artifacts,
)

from .common import (
    _candidate_budget,
    _merge_static_candidates,
    _schedule_round,
    _poc_specs,
    _shell_poc_specs,
    _stage_pocs,
    _service_gap_row,
    _evidence_from_summary,
    _precondition_distribution,
    _coverage_scope_incomplete,
    _effective_source_dirs,
    _gate_scan,
    _fix_history,
    _build_coverage_index,
)

def run_s4(ctx: StageContext) -> Dict[str, Any]:
    """Minimal PoC + verification matrix: version x safe-mode x precondition."""
    parent_budget = getattr(ctx, "work_budget", None)
    s4_budget = (parent_budget.child(
        "s4", wall_seconds=getattr(ctx.config, "s4_timeout_seconds", 5400),
        candidate_slots=_candidate_budget(ctx))
                  if parent_budget is not None else None)
    execution_budget = S4ExecutionBudget(
        getattr(ctx.config, "s4_timeout_seconds", 5400),
        getattr(ctx.config, "s4_candidate_timeout_seconds", 900),
        work_budget=s4_budget)
    _stage_pocs(ctx)
    jars_by_version = ctx.config.resolve_jars(ctx.workspace)
    source_revision_artifacts = ctx.config.resolve_source_revision_artifacts(
        ctx.workspace)
    results = {}
    java_specs = _poc_specs(ctx)
    shell_specs = _shell_poc_specs(ctx)
    service = ServiceLifecycle(ctx.workspace, ctx.target, ctx.round_no,
                               ctx.config, approval=ctx.approval,
                               execution_budget=execution_budget)
    service_info = service.snapshot()
    try:
        if service.configured and service.enabled and (java_specs or shell_specs):
            service_info = service.ensure_ready()
        service_unavailable = (
            service.configured and service.enabled
            and not service_info.get("ready", False))

        if java_specs:
            matrix_runner = JavaMatrixRunner(
                ctx.workspace, ctx.target, ctx.round_no, ctx.approval,
                execution_budget=execution_budget)
            if service_unavailable:
                for spec in java_specs:
                    cells = [_service_gap_row(spec, cell, service_info, "java")
                             for cell in spec.cells]
                    matrix_runner._write_cells(spec.candidate_id, cells)
                    results.setdefault(spec.candidate_id, []).extend(cells)
            else:
                for cid, cells in matrix_runner.run_manifest(java_specs, jars_by_version).items():
                    results.setdefault(cid, []).extend(cells)
        if shell_specs:
            shell_runner = ShellMatrixRunner(
                ctx.workspace, ctx.target, ctx.round_no, ctx.approval,
                execution_budget=execution_budget)
            if service_unavailable:
                for spec in shell_specs:
                    cells = [_service_gap_row(spec, cell, service_info, "shell")
                             for cell in spec.cells]
                    shell_runner._write_cells(spec.candidate_id, cells)
                    results.setdefault(spec.candidate_id, []).extend(cells)
            else:
                for cid, cells in shell_runner.run_manifest(shell_specs).items():
                    results.setdefault(cid, []).extend(cells)
        try:
            runtime_lab = run_s4_runtime_lab(
                ctx.workspace, ctx.target, ctx.round_no, ctx.config,
                ctx.config.candidates, java_specs, shell_specs, jars_by_version,
                baseline_results=results, approval=ctx.approval,
                version_universe=sorted(set(jars_by_version)
                                        | set(ctx.config.target_urls)),
                service_lifecycle=service,
                source_revision_artifacts=source_revision_artifacts,
                execution_budget=execution_budget)
        except Exception as exc:  # keep ordinary S4 usable while preserving gap
            runtime_lab = {
                "schema_version": "runtime-lab-v1",
                "scope": "ordinary-s4",
                "status": "run-failed",
                "reason": "%s: %s" % (type(exc).__name__, str(exc)[:240]),
                "fixtures": [],
                "claim_status": "not-a-finding",
            }
    finally:
        service.stop()
    runtime_lab_ref = "state/%s/round-%02d/S4/runtime-lab.json" % (
        ctx.target, ctx.round_no)
    ctx.store.write_artifact("S4", "runtime-lab.json", runtime_lab)
    summaries = {}
    authz_matrix = []
    for cand in ctx.config.candidates:
        cid = cand["candidate_id"]
        cells, convergence = converge_s4_cells(
            ctx.workspace, ctx.target, ctx.round_no, cid, results.get(cid, []))
        summaries[cid] = summarize_candidate(cells)
        summaries[cid]["s4_result_sources"] = convergence["sources"]
        summaries[cid]["s4_persisted_matrix"] = convergence["persisted_matrix"]
        candidate_lab = (runtime_lab.get("candidate_status") or {}).get(str(cid))
        if candidate_lab:
            summaries[cid]["runtime_lab"] = {
                "artifact_ref": runtime_lab_ref,
                "fixture_count": candidate_lab.get("fixture_count", 0),
                "replay_statuses": candidate_lab.get("replay_statuses", []),
                "differential_statuses": candidate_lab.get(
                    "differential_statuses", []),
                "variant_evidence_statuses": candidate_lab.get(
                    "variant_evidence_statuses", []),
                "variant_incomplete_count": candidate_lab.get(
                    "variant_incomplete_count", 0),
                "variant_observed_signals": candidate_lab.get(
                    "variant_observed_signals", []),
                "claim_status": "not-a-finding",
            }
        for cell in cells:
            assertion = cell.get("authz_assertion")
            if assertion and assertion.get("status") != "not_applicable":
                authz_matrix.append({
                    "candidate_id": cid,
                    "version": cell.get("version"),
                    "safe_mode": cell.get("safe_mode"),
                    "precondition": cell.get("precondition"),
                    "authz": normalize_authz_case(cell.get("authz", {})),
                    "assertion": assertion,
                })
    ctx.store.write_artifact("S4", "verification-matrix.json", summaries)
    ctx.store.write_artifact(
        "S4", "residual-closure.json",
        build_residual_closure_report(ctx.config.candidates, summaries,
                                      ctx.round_no))
    ctx.store.write_artifact("S4", "execution-status.json", {
        cid: {
            key: value for key, value in summary.items()
            if key.endswith("_count") or key in ("execution_state", "cells_ran",
                                                   "cells_attempted", "s4_result_sources",
                                                   "evidence_policy_version")
        }
        for cid, summary in summaries.items()
    })
    ctx.store.write_artifact("S4", "execution-budget.json",
                             execution_budget.snapshot())
    ctx.store.write_artifact("S4", "authz-matrix.json", authz_matrix)
    return {"summaries": summaries, "runtime_lab": runtime_lab,
            "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION,
            "execution_budget": execution_budget.snapshot()}




