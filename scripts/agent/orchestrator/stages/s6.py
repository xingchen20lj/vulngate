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

def run_s6(ctx: StageContext, summaries: Dict[str, Any], conclusions: Dict[str, str]) -> Dict[str, Any]:
    """Severity calibration: defensible CVSS + precondition consistency (G5)."""
    out = {}
    for cand in ctx.config.candidates:
        cid = cand["candidate_id"]
        if not is_confirmed_conclusion(conclusions.get(cid)):
            continue
        vector = cand.get("cvss_vector", "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N")
        tier = cand.get("precondition_tier_hint", "single-feature")
        try:
            score, severity = base_score(vector)
            g5 = g5_cvss(tier, vector, cand.get("implicit_default_on", False))
            impact_ok, impact_reason = check_impact_consistency(
                cand, summaries.get(cid, {}), vector)
        except ValueError as exc:
            out[cid] = {
                "vector": vector,
                "blocked": True,
                "g5": {"passed": False, "verdict": "invalid-cvss-vector",
                       "evidence": [str(exc)]},
            }
            continue
        if not impact_ok:
            g5.passed = False
            g5.evidence = (g5.evidence or []) + [impact_reason]
            g5.verdict = "impact evidence insufficient"
        out[cid] = {
            "vector": vector,
            "score": round(score, 1),
            "severity": severity,
            "tier": tier,
            "implicit_default_on": bool(cand.get("implicit_default_on", False)),
            "g5": g5.__dict__,
            "impact": cand.get("impact", []),
            "attack_class": cand.get("attack_class", ""),
            "surface": cand.get("surface", ""),
            "logic": cand.get("logic", ""),
            "hypothesis": cand.get("hypothesis", ""),
            "availability_proof": summaries.get(cid, {}).get(
                "availability_proof", []),
            "boundary": cand.get("boundary", ""),
        }
        if not g5.passed:
            out[cid]["blocked"] = True
    ctx.store.write_artifact("S6", "severity.json", out)
    return {"severity": out,
            "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION}





