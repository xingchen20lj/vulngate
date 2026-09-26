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

def run_s8(ctx: StageContext, summaries: Dict[str, Any], conclusions: Dict[str, str],
           novelties: Dict[str, Any], severities: Dict[str, Any]) -> Dict[str, Any]:
    """Round close: ledger + exclusions + summary + next-round candidates."""
    rows = []
    excluded = []
    final_evidence_rows = []
    for cand in ctx.config.candidates:
        cid = cand["candidate_id"]
        summary = summaries.get(cid, {})
        requested_conclusion = conclusions.get(cid, "候选（待验证）")
        conclusion = requested_conclusion
        novelty_record = novelties.get(cid, {})
        novelty_record = novelty_record if isinstance(novelty_record, dict) else {}
        g3_record = novelty_record.get("g3")
        g3_record = g3_record if isinstance(g3_record, dict) else {}
        checks = []
        # S8 is a final integrity boundary as well as a renderer. Pipeline
        # callers normally derive this earlier, but a hand-written/resumed S8
        # invocation must not turn static evidence into a finding by passing a
        # string such as "确认". Keep G4 and G3 independently visible.
        if is_confirmed_conclusion(conclusion):
            g4 = g4_runtime(summary, "确认", cand)
            checks.append({"gate": "G4", "passed": g4.passed,
                           "verdict": g4.verdict})
            if not g4.passed:
                conclusion = "候选（待验证）"
            elif not g3_record.get("passed", False):
                checks.append({"gate": "G3", "passed": False,
                               "verdict": str(g3_record.get(
                                   "verdict", "novelty-evidence-missing"))})
                conclusion = "候选（待验证）"
            else:
                checks.append({"gate": "G3", "passed": True,
                               "verdict": str(g3_record.get("verdict", ""))})
        row = {
            "candidate_id": cid,
            "surface": cand["surface"],
            "conclusion": conclusion,
            "status": conclusion_status(conclusion),
            "evidence": _evidence_from_summary(summary, cand),
            "precondition_tier": cand.get("precondition_tier_hint", ""),
            "code_location": cand.get("code_location", []),
            "authorization_matrix": summary.get("authz_results", []),
        }
        nv = novelty_record.get("novelty")
        if nv:
            row["novelty"] = {"verdict": nv["verdict"], "reason": nv["reason"],
                              "increments": nv.get("increments", [])}
            if nv.get("verdict") == "candidate-0day":
                # Absence of a public record is a novelty research result, not
                # a vulnerability claim. A static/pending row must render that
                # distinction explicitly rather than looking like an 0day.
                claimable = bool(is_confirmed_conclusion(conclusion)
                                 and g3_record.get("passed", False))
                row["novelty"]["claimable"] = claimable
                if not claimable:
                    row["novelty"]["presentation"] = (
                        "unconfirmed-novelty-hypothesis")
                    row["evidence"].append(
                        "S8_NOVELTY_UNCONFIRMED=not-a-finding")
        severity = severities.get(cid)
        if is_confirmed_conclusion(row["conclusion"]):
            if not g5_record_valid(severity):
                row["conclusion"] = "候选（待验证）"
                evidence = ((severity or {}).get("g5") or {}).get("evidence", [])
                label = "G5_BLOCKED=" if severity else "G5_MISSING="
                row["evidence"].append(label + "; ".join(evidence or [
                    "S6 severity record missing or invalid"]))
                checks.append({"gate": "G5", "passed": False,
                               "verdict": "cvss-record-missing-or-invalid"})
            else:
                row["cvss"] = {"vector": severity["vector"], "score": severity["score"]}
                checks.append({"gate": "G5", "passed": True,
                               "verdict": "cvss-attached"})
        elif severity:
            row["evidence"].append("S8_CVSS_WITHHELD=unconfirmed-not-a-finding")
        row["status"] = conclusion_status(row.get("conclusion"))
        rows.append(row)
        final_evidence_rows.append({
            "candidate_id": cid,
            "requested_conclusion": requested_conclusion,
            "effective_conclusion": row["conclusion"],
            "checks": checks,
            "static_claim": "not-a-finding",
        })
        if conclusion_status(row.get("conclusion")) == "excluded":
            excluded.append({
                "surface": cand["surface"],
                "conclusion": "排除（%s）" % cand.get("exclusion_reason", "门控/受控异常"),
                "evidence": row["evidence"],
            })
    final_evidence = {
        "schema_version": "final-evidence-consistency-v1",
        "stage": "S8",
        "rows": final_evidence_rows,
        "summary": {
            "candidate_count": len(final_evidence_rows),
            "demoted_count": sum(
                row["requested_conclusion"] != row["effective_conclusion"]
                for row in final_evidence_rows),
            "claim_status": "not-a-finding",
        },
        "claim_status": "not-a-finding",
    }
    ctx.store.write_artifact("S8", "final-evidence-consistency.json",
                             final_evidence)
    confirmed_rows = [r for r in rows if is_confirmed_conclusion(r.get("conclusion"))]
    novelty_misses = len([
        r for r in confirmed_rows
        if (r.get("novelty") or {}).get("verdict") == "candidate-0day"
        and any(k in (r.get("novelty") or {}).get("reason", "") for k in ("upstream", "disclosure"))
    ])
    metrics = {
        "候选数": len(ctx.config.candidates),
        "确认数": len(confirmed_rows),
        "排除数": len([r for r in rows if conclusion_status(r.get("conclusion")) == "excluded"]),
        "候选->PoC 转化率": "%d/%d" % (len(confirmed_rows), len(ctx.config.candidates)),
        "Novelty 漏检数（必须=0）": novelty_misses,
        "前置分布": _precondition_distribution(rows),
    }
    next_round = [c.get("next_round_hint", "") for c in ctx.config.candidates
                  if c.get("next_round_hint")]
    summary = {
        "header_note": ctx.config.notes,
        "metrics": metrics,
        "final_evidence_consistency": {
            "artifact": "state/%s/round-%02d/S8/final-evidence-consistency.json"
                        % (ctx.target, ctx.round_no),
            **final_evidence["summary"],
        },
        "next_round": next_round or ["复测 2.0.65（#7753 发布后）", "扩展模块轮（HTTP/Redis/JSONB 集成面）"],
    }
    # S8 closes the round's durable research loop.  This is deliberately
    # separate from the finding ledger: a stable replay or a version
    # difference is useful feedback, but neither is a vulnerability verdict.
    runtime_lab = ctx.store.read_artifact("S4", "runtime-lab.json") or {}
    prior_consistency_actions = load_research_consistency_actions(
        ctx.workspace, ctx.target)
    research_consistency_rechecks = build_research_consistency_rechecks(
        runtime_lab, prior_consistency_actions)
    research_consistency_rechecks_file = write_research_consistency_rechecks(
        ctx.workspace, ctx.target, research_consistency_rechecks)
    from ...evaluation.replay_calibration import (
        build_replay_calibration, load_replay_calibration,
        write_replay_calibration,
    )
    from ...evaluation.replay_cohort import (
        select_effective_replay_calibration,
    )
    from ...evaluation.replay_pack import (
        build_replay_pack, write_replay_pack,
    )
    prior_replay_calibration = load_replay_calibration(
        ctx.workspace, ctx.target)
    replay_cohort = ctx.replay_cohort_calibration()
    effective_replay_calibration = select_effective_replay_calibration(
        prior_replay_calibration, replay_cohort)
    memory_delta = build_round_memory(
        ctx.config.candidates, summaries,
        {r["candidate_id"]: r.get("conclusion", "") for r in rows},
        runtime_lab, ctx.round_no, target_type=ctx.config.target_type)
    memory = merge_research_memory(
        load_research_memory(ctx.workspace, ctx.target), memory_delta)
    memory_file = write_research_memory(ctx.workspace, ctx.target, memory)
    review_feedback = load_review_feedback(ctx.workspace, ctx.target)
    research_consistency = build_research_consistency(memory)
    research_consistency_file = write_research_consistency(
        ctx.workspace, ctx.target, research_consistency)
    research_consistency_actions = build_research_consistency_actions(
        research_consistency)
    research_consistency_actions_file = write_research_consistency_actions(
        ctx.workspace, ctx.target, research_consistency_actions)
    portfolio = build_research_portfolio(
        memory, review_feedback, ctx.benchmark_feedback(),
        research_consistency, research_consistency_actions,
        research_consistency_rechecks)
    portfolio_file = write_research_portfolio(
        ctx.workspace, ctx.target, portfolio)
    strategy = load_research_strategy(ctx.workspace, ctx.target)
    if not strategy:
        strategy = ctx.store.read_artifact("S2", "research-strategy.json") or {}
    strategy_feedback = {}
    research_guidance = {}
    strategy_file = None
    guidance_file = None
    if strategy:
        strategy, strategy_feedback = apply_strategy_observations(
            strategy, ctx.config.candidates, summaries, ctx.round_no)
        strategy, research_guidance = apply_research_guidance(
            strategy, portfolio, review_feedback, ctx.round_no,
            replay_calibration=effective_replay_calibration)
        if strategy:
            strategy_file = write_research_strategy(
                ctx.workspace, ctx.target, strategy)
            guidance_file = write_research_guidance(
                ctx.workspace, ctx.target, research_guidance)
            ctx.store.write_artifact("S8", "research-strategy.json", strategy)
            ctx.store.write_artifact(
                "S8", "research-strategy-feedback.json", strategy_feedback)
            ctx.store.write_artifact(
                "S8", "research-guidance.json", research_guidance)
    # Close the previous round's active queue before replacing it with the
    # next one.  The outcome join is scheduling feedback only: it cannot
    # change a candidate conclusion, CVSS, G4 or G5.
    prior_research_agenda = load_research_agenda(ctx.workspace, ctx.target)
    prior_agenda_outcomes = load_research_agenda_outcomes(
        ctx.workspace, ctx.target)
    prior_research_budget = load_research_budget(ctx.workspace, ctx.target)
    schedule_snapshot = ctx.store.read_artifact(
        "S2", "candidate-schedule.json") or load_schedule_snapshot(
            ctx.workspace, ctx.target, ctx.round_no)
    verification_matrix = ctx.store.read_artifact(
        "S4", "verification-matrix.json") or {}
    research_agenda_outcomes = build_research_agenda_outcomes(
        prior_research_agenda, schedule_snapshot, verification_matrix,
        runtime_lab, strategy_feedback,
        prior_outcomes=prior_agenda_outcomes,
        target=ctx.target, round_no=ctx.round_no)
    research_agenda_outcomes_file = write_research_agenda_outcomes(
        ctx.workspace, ctx.target, research_agenda_outcomes)
    ctx.store.write_artifact(
        "S8", "research-agenda-outcomes.json", research_agenda_outcomes)
    research_budget = build_research_budget(
        prior_research_agenda, research_agenda_outcomes,
        prior_budget=prior_research_budget, target=ctx.target,
        round_no=ctx.round_no,
        slots=((prior_research_agenda.get("policy") or {}).get(
            "slots", 0) if prior_research_agenda else 0) or 8)
    research_budget_file = write_research_budget(
        ctx.workspace, ctx.target, research_budget)
    ctx.store.write_artifact("S8", "research-budget.json", research_budget)
    research_agenda = build_research_agenda(
        strategy, portfolio, target=ctx.target, round_no=ctx.round_no,
        outcomes=research_agenda_outcomes, budget_policy=research_budget)
    research_agenda_file = write_research_agenda(
        ctx.workspace, ctx.target, research_agenda)
    ctx.store.write_artifact("S8", "research-agenda.json", research_agenda)
    replay_calibration = build_replay_calibration(
        ctx.workspace, ctx.target)
    replay_calibration_file = write_replay_calibration(
        ctx.workspace, ctx.target, replay_calibration)
    ctx.store.write_artifact(
        "S8", "research-replay-calibration.json", replay_calibration)
    if replay_cohort:
        ctx.store.write_artifact(
            "S8", "research-replay-cohort.json", replay_cohort)
    ctx.store.write_artifact("S8", "research-memory.json", memory_delta)
    ctx.store.write_artifact("S8", "research-memory-summary.json", memory["summary"])
    ctx.store.write_artifact("S8", "review-feedback.json", review_feedback)
    ctx.store.write_artifact(
        "S8", "research-consistency.json", research_consistency)
    ctx.store.write_artifact(
        "S8", "research-consistency-actions.json",
        research_consistency_actions)
    ctx.store.write_artifact(
        "S8", "research-consistency-rechecks.json",
        research_consistency_rechecks)
    ctx.store.write_artifact("S8", "research-portfolio.json", portfolio)
    replay_pack = build_replay_pack(ctx.workspace, ctx.target)
    replay_pack_file = write_replay_pack(
        ctx.workspace, ctx.target, replay_pack)
    ctx.store.write_artifact("S8", "research-replay-pack.json", replay_pack)
    by_candidate_memory = {
        str(entry.get("candidate_id")): entry for entry in memory_delta.get("entries", [])
    }
    for row in rows:
        entry = by_candidate_memory.get(str(row.get("candidate_id")))
        if not entry:
            continue
        row["research"] = {
            "research_key": entry.get("research_key", ""),
            "states": sorted({str(event.get("state")) for event in
                               entry.get("events", []) if event.get("state")}),
            "claim_status": "not-a-finding",
        }
    summary["research_memory"] = {
        "artifact": str(memory_file.relative_to(ctx.workspace.resolve())),
        "round_entries": len(memory_delta.get("entries", [])),
        "total_entries": len(memory.get("entries", [])),
        "states": memory.get("summary", {}).get("states", {}),
        "claim_status": "not-a-finding",
    }
    summary["review_feedback"] = {
        "artifact": "state/%s/review-feedback.json" % ctx.target,
        "count": review_feedback.get("summary", {}).get("feedback_count", 0),
        "statuses": review_feedback.get("summary", {}).get("statuses", {}),
        "claim_status": "not-a-finding",
    }
    summary["research_portfolio"] = {
        "artifact": str(portfolio_file.relative_to(ctx.workspace.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-portfolio.json"
                          % (ctx.target, ctx.round_no),
        "mechanism_count": portfolio.get("summary", {}).get("mechanism_count", 0),
        "unresolved_mechanisms": portfolio.get("summary", {}).get(
            "unresolved_mechanisms", 0),
        "next_probe_count": len(portfolio.get("next_probes") or []),
        "surface_lane_coverage": (portfolio.get("surface_lane_coverage") or {}
                                  ).get("summary", {}),
        "claim_status": "not-a-finding",
    }
    summary["research_consistency"] = {
        "artifact": str(research_consistency_file.relative_to(
            ctx.workspace.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-consistency.json"
                          % (ctx.target, ctx.round_no),
        "status_counts": (research_consistency.get("summary") or {}
                           ).get("statuses", {}),
        "conflicted_entries": (research_consistency.get("summary") or {}
                               ).get("conflicted_entries", 0),
        "unstable_entries": (research_consistency.get("summary") or {}
                             ).get("unstable_entries", 0),
        "claim_status": "not-a-finding",
    }
    summary["research_consistency_actions"] = {
        "artifact": str(research_consistency_actions_file.relative_to(
            ctx.workspace.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-consistency-actions.json"
                          % (ctx.target, ctx.round_no),
        "action_count": (research_consistency_actions.get("summary") or {}
                          ).get("action_count", 0),
        "action_counts": (research_consistency_actions.get("summary") or {}
                           ).get("action_counts", {}),
        "claim_status": "not-a-finding",
    }
    summary["research_consistency_rechecks"] = {
        "artifact": str(research_consistency_rechecks_file.relative_to(
            ctx.workspace.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-consistency-rechecks.json"
                          % (ctx.target, ctx.round_no),
        "status_counts": {
            key: value for key, value in
            (research_consistency_rechecks.get("summary") or {}).items()
            if key in {"observed", "partial", "environment_gap",
                       "not_executed"}
        },
        "claim_status": "not-a-finding",
    }
    summary["research_agenda"] = {
        "artifact": str(research_agenda_file.relative_to(
            ctx.workspace.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-agenda.json"
                          % (ctx.target, ctx.round_no),
        "selected_count": (research_agenda.get("summary") or {}).get(
            "selected_count", 0),
        "deferred_count": (research_agenda.get("summary") or {}).get(
            "deferred_count", 0),
        "surface_counts": (research_agenda.get("summary") or {}).get(
            "surface_counts", {}),
        "claim_status": "not-a-finding",
    }
    summary["research_agenda_outcomes"] = {
        "artifact": str(research_agenda_outcomes_file.relative_to(
            ctx.workspace.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-agenda-outcomes.json"
                          % (ctx.target, ctx.round_no),
        "selected_count": (research_agenda_outcomes.get("summary") or {}
                            ).get("selected_count", 0),
        "productive_selected_count": (research_agenda_outcomes.get(
            "summary") or {}).get("productive_selected_count", 0),
        "selected_yield": (research_agenda_outcomes.get("summary") or {}
                           ).get("selected_yield"),
        "outcome_counts": (research_agenda_outcomes.get("summary") or {}
                            ).get("outcome_counts", {}),
        "claim_status": "not-a-finding",
    }
    summary["research_budget"] = {
        "artifact": str(research_budget_file.relative_to(
            ctx.workspace.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-budget.json"
                          % (ctx.target, ctx.round_no),
        "surface_count": (research_budget.get("summary") or {}).get(
            "surface_count", 0),
        "recommendation_counts": (research_budget.get("summary") or {}
                                   ).get("recommendation_counts", {}),
        "claim_status": "not-a-finding",
    }
    if strategy_file:
        summary["research_strategy"] = {
            "artifact": str(strategy_file.relative_to(ctx.workspace.resolve())),
            "round_artifact": "state/%s/round-%02d/S8/research-strategy.json"
                              % (ctx.target, ctx.round_no),
            "feedback_artifact": "state/%s/round-%02d/S8/research-strategy-feedback.json"
                                % (ctx.target, ctx.round_no),
            "guidance_artifact": (str(guidance_file.relative_to(
                ctx.workspace.resolve())) if guidance_file else
                "state/%s/coverage/research-guidance.json" % ctx.target),
            "guidance_round_artifact": "state/%s/round-%02d/S8/research-guidance.json"
                                      % (ctx.target, ctx.round_no),
            "observed_items": strategy.get("summary", {}).get(
                "observed_items", 0),
            "information_gain": strategy_feedback.get("summary", {}).get(
                "information_gain", 0),
            "next_actions": research_guidance.get("summary", {}).get(
                "action_counts", {}),
            "replacement_recommendations": research_guidance.get(
                "summary", {}).get("replacement_recommendations", 0),
            "claim_status": "not-a-finding",
        }
    summary["research_replay_calibration"] = {
        "artifact": str(replay_calibration_file.relative_to(
            ctx.workspace.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-replay-calibration.json"
                          % (ctx.target, ctx.round_no),
        "status": replay_calibration.get("status", "no-data"),
        "replayed_guidance_items": replay_calibration.get(
            "metrics", {}).get("replayed_guidance_items", 0),
        "replacement_hit_rate": replay_calibration.get(
            "metrics", {}).get("replacement_hit_rate"),
        "claim_status": "not-a-finding",
    }
    summary["research_replay_pack"] = {
        "artifact": str(replay_pack_file.relative_to(
            ctx.workspace.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-replay-pack.json"
                          % (ctx.target, ctx.round_no),
        "status": (replay_pack.get("provenance") or {}).get(
            "status", "not-executed"),
        "valid_for_cohort": (replay_pack.get("provenance") or {}).get(
            "valid_for_cohort", False),
        "pack_digest": replay_pack.get("pack_digest", ""),
        "claim_status": "not-a-finding",
    }
    if replay_cohort:
        summary["research_replay_cohort"] = {
            "artifact": "configured:replay_cohort_calibration_path",
            "schema_version": replay_cohort.get("schema_version", ""),
            "status": replay_cohort.get("status", "no-data"),
            "eligible_projects": replay_cohort.get("metrics", {}).get(
                "eligible_projects", 0),
            "policy_threshold": replay_cohort.get("policy", {}).get(
                "replacement_zero_gain_rounds", 1),
            "claim_status": "not-a-finding",
        }
    # A ledger is durable only after this call, but the rows above are already
    # the exact current-round decisions.  Overlay them so S8's closure record
    # cannot accidentally describe the previous round's coverage.  This is a
    # coverage state machine, not a finding gate: it neither promotes a static
    # lead nor relaxes the S4/G4 runtime requirement for confirmation.
    s1_coverage = ctx.store.read_artifact("S1", "coverage-summary.json") or {}
    partial_coverage = _coverage_scope_incomplete(s1_coverage)
    try:
        from ...analysis import coverage as cov
        from ...analysis.inventory import CoverageStore

        coverage_store = CoverageStore(ctx.workspace, ctx.target)
        coverage_summary = coverage_store.read("coverage-summary") or {}
        if not isinstance(coverage_summary, dict):
            coverage_summary = {}
        if partial_coverage:
            # Do not mark rows against an older inventory. The current round's
            # candidate evidence remains in the ledger; global coverage needs
            # a complete, current source universe before it can be refreshed.
            coverage_refresh = {}
        else:
            coverage_refresh = cov.refresh_candidate_coverage(
                coverage_store, ctx.workspace, ctx.target,
                round_no=ctx.round_no, extra_rows=rows)
            coverage_summary = coverage_store.read("coverage-summary") or {}
        coverage_closure = {
            "artifact": "state/%s/coverage/coverage-summary.json" % ctx.target,
            "state": (coverage_summary.get("audit_status") or {}).get(
                "state", "coverage-unknown"),
            "scope_id": (coverage_summary.get("audit_status") or {}).get(
                "scope_id", ""),
            "scope_valid": (coverage_summary.get("audit_status") or {}).get(
                "scope_valid", False),
            "blockers": list((coverage_summary.get("audit_status") or {}).get(
                "blockers") or []),
            "high_risk_uncovered": coverage_refresh.get(
                "high_risk_uncovered", 0),
            "stop_condition_met": bool(coverage_refresh.get(
                "stop_condition_met", False)),
            "claim_status": "not-a-finding",
        }
        if partial_coverage:
            # Invalidate any old target-level coverage summary too, so later
            # readers cannot mistake its denominator for this round's scope.
            previous_counts = coverage_summary.get("counts")
            previous_scope = coverage_summary.get("scope")
            previous_uncovered = coverage_store.read_records(
                "uncovered-regions")
            coverage_summary["previous_inventory_counts"] = previous_counts
            if previous_scope is not None:
                coverage_summary["previous_inventory_scope"] = previous_scope
            if previous_uncovered:
                coverage_store.write_records(
                    "previous-uncovered-regions", previous_uncovered)
            coverage_store.write_records("uncovered-regions", [])
            coverage_summary["scope"] = {
                "status": "incomplete", "scope_id": "", "valid": False,
                "claim_status": "not-a-finding",
            }
            coverage_summary["counts"] = {}
            coverage_summary["metrics"] = {
                key: None for key in (coverage_summary.get("metrics") or {})}
            coverage_summary["acceptance"] = {
                key: {"target": (row or {}).get("target"),
                      "actual": None, "met": False}
                for key, row in (coverage_summary.get("acceptance") or {}).items()
            }
            coverage_summary["uncovered_regions"] = []
            coverage_summary["high_risk_uncovered"] = None
            coverage_summary["stop_condition_met"] = False
            coverage_summary["coverage_inventory_current"] = False
            coverage_summary["audit_status"] = {
                "state": "scope-incomplete",
                "scope_id": "",
                "scope_valid": False,
                "scope_present": True,
                "blockers": ["coverage-inventory-incomplete"],
                "claim_status": "not-a-finding",
            }
            coverage_summary["status"] = "incomplete"
            coverage_store.write("coverage-summary", coverage_summary)
            coverage_closure.update({
                "state": "scope-incomplete",
                "scope_id": "",
                "scope_valid": False,
                "blockers": ["coverage-inventory-incomplete"],
                "high_risk_uncovered": None,
                "stop_condition_met": False,
                "claim_status": "not-a-finding",
            })
    except Exception as exc:  # pragma: no cover - preserve a completed ledger
        coverage_closure = {
            "artifact": "state/%s/coverage/coverage-summary.json" % ctx.target,
            "state": "coverage-refresh-error",
            "scope_id": "",
            "scope_valid": False,
            "blockers": ["coverage-refresh-error:%s" % type(exc).__name__],
            "high_risk_uncovered": None,
            "stop_condition_met": False,
            "claim_status": "not-a-finding",
        }
    if partial_coverage:
        coverage_closure.update({
            "state": "scope-incomplete",
            "scope_id": "",
            "scope_valid": False,
            "blockers": ["coverage-inventory-incomplete"],
            "high_risk_uncovered": None,
            "stop_condition_met": False,
            "claim_status": "not-a-finding",
        })
    metrics["覆盖状态"] = coverage_closure["state"]
    metrics["高风险未覆盖数"] = coverage_closure["high_risk_uncovered"]
    summary["coverage_closure"] = coverage_closure
    ctx.store.write_artifact("S8", "coverage-closure.json", coverage_closure)
    out_dir = write_round_artifacts(ctx.workspace, ctx.target, ctx.round_no, rows, excluded,
                                    summary, lang=ctx.config.output_lang)
    return {"ledger_dir": str(out_dir.relative_to(ctx.workspace)), "rows": len(rows),
            "excluded": len(excluded), "metrics": metrics,
            "research_memory": summary["research_memory"],
            "research_consistency": summary["research_consistency"],
            "research_consistency_actions": summary[
                "research_consistency_actions"],
            "research_consistency_rechecks": summary[
                "research_consistency_rechecks"],
            "research_agenda": summary["research_agenda"],
            "research_agenda_outcomes": summary[
                "research_agenda_outcomes"],
            "research_budget": summary["research_budget"],
            "research_portfolio": summary["research_portfolio"],
            "research_replay_calibration": summary[
            "research_replay_calibration"],
            "research_replay_pack": summary["research_replay_pack"],
            "final_evidence_consistency": final_evidence["summary"],
            "coverage": coverage_closure,
            "research_replay_cohort": summary.get(
                "research_replay_cohort", {
                    "claim_status": "not-a-finding"}),
            "research_strategy": summary.get("research_strategy", {
                "claim_status": "not-a-finding"}),
            "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION}





