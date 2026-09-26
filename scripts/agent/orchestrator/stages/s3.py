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

def run_s3(ctx: StageContext) -> Dict[str, Any]:
    """Static audit per candidate: gates, dead code, default reachability."""
    gate_scan = ctx.store.read_artifact("S1", "gate-scan.json") or []
    source_sink_graph = ctx.store.read_artifact("S1", "source-sink-graph.json") or []
    experiment_plan_rows = ctx.store.read_artifact(
        "S2", "experiment-plans.json") or []
    experiment_plans = {
        str(row.get("candidate_id")): row
        for row in experiment_plan_rows if isinstance(row, dict)
    }
    notes = []
    for cand in ctx.config.candidates:
        audit = cand.get("audit_notes", {})
        g1b = g1b_gate_blocks(audit)
        source_to_sink = cand.get("source_to_sink") or match_source_sink_paths(
            source_sink_graph, cand)
        if source_to_sink:
            cand["source_to_sink"] = source_to_sink
        experiment_plan = experiment_plans.get(str(cand["candidate_id"])) \
            or cand.get("experiment_plan") or {}
        notes.append({
            "candidate_id": cand["candidate_id"],
            "surface": cand["surface"],
            "audit_notes": audit,
            "g1b": g1b.__dict__,
            "code_location": cand.get("code_location", []),
            "source_to_sink": source_to_sink,
            "experiment_plan": experiment_plan,
        })
    residuals = []
    for cand in ctx.config.candidates:
        for residual in (cand.get("residuals") or []):
            if isinstance(residual, dict):
                item = dict(residual)
                item.setdefault("candidate_id", cand["candidate_id"])
                residuals.append(item)
    ctx.store.write_artifact("S3", "residuals.json", residuals)
    ctx.store.write_artifact("S3", "audit-notes.json", notes)
    return {"notes": notes, "gate_scan": gate_scan}





