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

def run_s2(ctx: StageContext) -> Dict[str, Any]:
    """Attack-surface matrix: entry x input shape x logic -> candidate cells.

    The candidate pool is *scheduled* rather than taken wholesale (spec §13):
    S1 has just refreshed coverage, so the scheduler ranks a finite,
    category-rotating intake window and returns the round's `max_candidates`
    slots, quota-stratified.  The complete static pool remains in its
    target-scoped producer artifacts; intake-deferred leads are recorded as
    queued, never silently deleted or marked reviewed.

    PR4 adds the index-derived candidates (spec §11/§12 and semantic path
    evidence) to that same pool: an unguarded path, a sibling control
    differential, or a source-local order/data-flow gap is a deterministic
    artifact with a citable ``file:line``, and the spec asks for them to be
    promoted automatically rather than left in a JSON file nobody reads.
    """
    coverage = ctx.store.read_artifact("S1", "coverage-summary.json") or {}
    partial_coverage = _coverage_scope_incomplete(coverage)
    # The pipeline controls whether this partial mode is allowed to proceed;
    # stage callers still need fail-safe candidate/index handling either way.
    partial_round = partial_coverage
    patch_history = ([] if partial_round else
                     ctx.store.read_artifact("S1", "security-fix-history.json") or [])
    existing_ids = {str(c.get("candidate_id")) for c in ctx.config.candidates}
    generated = []
    for fix in patch_history:
        candidate = fix_completeness_candidate(fix)
        if candidate["candidate_id"] not in existing_ids:
            ctx.config.candidates.append(candidate)
            existing_ids.add(candidate["candidate_id"])
            generated.append(candidate)
    # Composite paths used to be written only as an S1 prompt hint.  Promote
    # them into the ordinary S2 pool so the scheduler, S3 source audit and S4
    # authz/effect matrix can test whether the observed authorization still
    # protects the transformed object at the sink.
    chain_candidates = []
    if not partial_round and bool(getattr(ctx.config, "static_candidates", True)):
        chain_candidates = ctx.store.read_artifact(
            "S1", "composite-chain-candidates.json") or []
    generated_chain = []
    for candidate in chain_candidates:
        cid = str(candidate.get("candidate_id", ""))
        if not cid or cid in existing_ids:
            continue
        ctx.config.candidates.append(candidate)
        existing_ids.add(cid)
        generated_chain.append(candidate)
    if partial_round:
        # Incomplete inventory can leave target-scoped files from an earlier
        # successful run. Do not let their candidates or review state steer
        # this partial audit.
        pool, static_added = list(ctx.config.candidates), []
    else:
        pool, static_added = _merge_static_candidates(ctx, list(ctx.config.candidates))
    from ...analysis import scheduler as sched
    slots = _candidate_budget(ctx)
    from ...analysis.research_agenda import normalize_candidate_ids
    agenda_priority_ids = ([] if partial_round else selected_candidate_ids(
        load_research_agenda(ctx.workspace, ctx.target),
        current_round=ctx.round_no))
    configured_priority_ids = normalize_candidate_ids(
        getattr(ctx.config, "priority_candidate_ids", []))
    priority_ids = normalize_candidate_ids(
        configured_priority_ids + agenda_priority_ids)
    active_pool, candidate_intake = sched.bounded_candidate_intake(
        pool, slots=slots, round_no=ctx.round_no,
        priority_ids=priority_ids)
    ctx.store.write_artifact("S2", "candidate-intake.json", candidate_intake)
    if partial_round:
        selected, plan = active_pool[:slots], None
        schedule_note = ("partial coverage: configured candidates only; "
                         "coverage-aware scheduling bypassed")
    else:
        selected, plan, schedule_note = _schedule_round(
            ctx, active_pool, slots, priority_ids=configured_priority_ids)
    if candidate_intake["deferred_intake_candidates"]:
        intake_note = ("candidate intake %d/%d active; %d queued for rotation"
                       % (candidate_intake["active_candidates"],
                          candidate_intake["pool_candidates"],
                          candidate_intake["deferred_intake_candidates"]))
        schedule_note = "; ".join(
            item for item in (schedule_note, intake_note) if item)
    selected_ids = {str(c.get("candidate_id")) for c in selected}
    versions = sorted({str(j.get("version")) for j in ctx.config.jars
                       if j.get("version")})
    benchmark_feedback = ctx.benchmark_feedback()
    if benchmark_feedback:
        ctx.store.write_artifact("S2", "benchmark-feedback.json",
                                 benchmark_feedback)
    experiment_plans = []
    scheduled_strategy = plan.research_strategy if plan is not None else {}
    consistency_actions = load_research_consistency_actions(
        ctx.workspace, ctx.target)
    for cand in selected:
        candidate_action = action_for_research_key(
            consistency_actions, research_key(cand), cand.get("candidate_id"))
        research_plan = plan_candidate_experiments(
            cand, versions, benchmark_feedback=benchmark_feedback,
            research_guidance=strategy_guidance_for_candidate(
                scheduled_strategy, cand),
            consistency_action=candidate_action,
            target_type=ctx.config.target_type)
        cand["experiment_plan"] = research_plan
        plan_row = dict(research_plan)
        plan_row["scheduled"] = str(cand.get("candidate_id")) in selected_ids
        experiment_plans.append(plan_row)
    ctx.store.write_artifact("S2", "experiment-plans.json", experiment_plans)
    matrix = []
    for cand in selected:
        research_plan = cand.get("experiment_plan") or {}
        matrix.append({
            "candidate_id": cand["candidate_id"],
            "surface": cand["surface"],
            "entry": cand.get("entry", ""),
            "input_shape": cand.get("input_shape", ""),
            "logic": cand.get("logic", ""),
            "authz_cases": normalize_authz_cases(cand.get("authz_cases")),
            "sequence": cand.get("sequence", []),
            "concurrency": cand.get("concurrency", 1),
            "availability_probe": cand.get("availability_probe", False),
            "capability_contract": research_plan.get(
                "capability_contract") or capability_contract_from_candidate(cand),
            "status": "candidate",
            "fix_completeness": bool(cand.get("fix_completeness")),
            "patch_commit": cand.get("patch_commit", ""),
            "patch_variants": cand.get("patch_variants", []),
            "chain_components": cand.get("chain_components", []),
            "experiment_plan_ids": [p.get("plan_id") for p in
                                    research_plan.get("plans", [])],
            "surface_variant_plan": research_plan.get(
                "surface_variant_plan", {}),
            "variant_fixture_plan": research_plan.get(
                "variant_fixture_plan", {}),
            "comparison_contract": research_plan.get(
                "comparison_contract", {}),
            "consistency_action": research_plan.get(
                "consistency_action", {}),
            "research_strategy": research_plan.get("strategy_tags", []),
        })
    ctx.store.write_artifact("S2", "candidate-matrix.json", matrix)
    if plan is not None:
        ctx.store.write_artifact("S2", "candidate-schedule.json", plan.as_dict())
        ctx.store.write_artifact("S2", "research-strategy.json",
                                 plan.research_strategy)
    result = {"candidate_count": len(matrix), "matrix": matrix,
              "generated_fix_candidates": [c["candidate_id"] for c in generated],
              "generated_chain_candidates": [c["candidate_id"]
                                              for c in generated_chain],
              "static_candidates": static_added,
              "candidates": selected,
              "pool_size": len(pool),
              "active_pool_size": len(active_pool),
              "candidate_intake": candidate_intake,
              "schedule_note": schedule_note,
              "coverage_scope": {
                  "state": "scope-incomplete" if partial_round else
                           ("incomplete" if partial_coverage else "current"),
                  "candidate_source": "configured-only" if partial_round else
                                      "configured-and-derived",
                  "coverage_claims_allowed": not partial_coverage,
                  "claim_status": "not-a-finding",
              },
              "benchmark_feedback": {
                  "benchmark_id": benchmark_feedback.get("benchmark_id", ""),
                  "alerts": [item.get("code") for item in
                             benchmark_feedback.get("alerts", [])
                             if isinstance(item, dict)],
                  "claim_status": "not-a-finding",
              } if benchmark_feedback else {},
              "experiment_plan_count": len(experiment_plans),
              "scheduled_experiment_plan_count": sum(
                  1 for item in experiment_plans if item.get("scheduled"))}
    if plan is not None:
        result["schedule"] = {
            "round": plan.round_no,
            "deferred": [s.candidate_id for s in plan.deferred],
            "quota": plan.filled_quota,
            "relocated": {k: v for k, v in plan.relocated_quota.items() if v},
            "high_risk_uncovered": plan.residual.get("high_risk_uncovered"),
        }
        result["research_strategy"] = {
            "artifact": "S2/research-strategy.json",
            "item_count": (plan.research_strategy.get("summary", {})
                           .get("item_count", 0)),
            "claim_status": "not-a-finding",
        }
    # Keep direct stage callers aligned with the full pipeline: S3-S8 must
    # consume exactly the scheduled work order, never the broad discovery
    # pool that S2 used to form its intake window.  The full pool remains
    # represented by the static producer artifacts and candidate-intake.json.
    ctx.config.candidates = selected
    return result





