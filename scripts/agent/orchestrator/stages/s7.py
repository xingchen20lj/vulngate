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

def run_s7(ctx: StageContext, rows: List[Dict[str, Any]], summaries: Dict[str, Any],
           severities: Dict[str, Any]) -> Dict[str, Any]:
    """Coordination/disclosure prep: self-contained finding docs + timeline."""
    reports_dir = ctx.workspace / "reports" / ctx.target / ("round-%02d" % ctx.round_no)
    reports_dir.mkdir(parents=True, exist_ok=True)
    written = []
    withheld = []
    prior_stage = ctx.store.load_stage("S7") or {}
    prior_docs = set(prior_stage.get("finding_docs", []))
    idx = 0
    for cand in ctx.config.candidates:
        cid = cand["candidate_id"]
        if conclusion_status(cand.get("conclusion_override", "确认")) != "confirmed":
            continue
        row = next((r for r in rows if r.get("candidate_id") == cid), {})
        if not is_confirmed_conclusion(row.get("conclusion")):
            continue
        if not g5_record_valid(severities.get(cid)):
            withheld.append({"candidate_id": cid,
                             "reason": "G5 severity record missing or invalid"})
            continue
        idx += 1
        sev = severities[cid]
        novelty_record = (ctx.store.read_artifact("S5", "novelty.json") or {}).get(cid, {})
        affected_versions = cand.get("affected_versions") or [
            str(j.get("version")) for j in ctx.config.jars if j.get("version")]
        negative_results = list(cand.get("negative_results") or [])
        negative_results += ["%s" % issue for issue in
                             (ctx.store.read_artifact("S4", "verification-matrix.json") or {}
                              ).get(cid, {}).get("validation_issues", [])]
        finding = {
            "title": row.get("surface", cid),
            "date": ctx.config.discovery_date,
            "status": "确认（机制级，受控验证）",
            "summary": cand.get("finding_summary", row.get("surface", "")),
            "entrypoint": cand.get("entry", ""),
            "affected_versions": affected_versions,
            "fixed_versions": cand.get("fixed_versions", []),
            "source_to_sink": cand.get("source_to_sink", []),
            "code_location": cand.get("code_location", []),
            "scope": ctx.config.scope_constraints,
            "repro": cand.get("repro", ""),
            "evidence": "\n".join(row.get("evidence", [])) or "见 matrix-runs 输出",
            "preconditions": cand.get("preconditions", []),
            "authorization_matrix": row.get("authorization_matrix", []),
            "negative_results": negative_results,
            "novelty": novelty_record.get("novelty", novelty_record),
            "cvss": sev,
            "impact": sev.get("impact", []),
            "boundary": sev.get("boundary", cand.get("boundary", "")),
            "timeline": cand.get("timeline", [{"date": ctx.config.discovery_date, "event": "发现并完成验证矩阵"}]),
        }
        fname = ("finding-%02d-%s.md" % (idx, cid) if ctx.config.output_lang == "en"
                 else "挖洞-发现-%02d-%s.md" % (idx, cid))
        (reports_dir / fname).write_text(
            render_finding_md(finding, lang=ctx.config.output_lang), encoding="utf-8")
        written.append(fname)
    stale_docs = sorted(prior_docs - set(written))
    stale_marker = ("> 状态更新：该报告来自旧版 S4 证据策略，当前轮次已无法用其材料确认此发现。"
                    "请以本轮 S8 Ledger 为准。\n\n")
    for name in stale_docs:
        path = reports_dir / name
        if path.is_file():
            old = path.read_text(encoding="utf-8", errors="replace")
            if stale_marker not in old:
                path.write_text(stale_marker + old, encoding="utf-8")
    if stale_docs:
        ctx.store.write_artifact("S7", "superseded-finding-docs.json", {
            "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION,
            "files": stale_docs,
            "reason": "G4/G5 did not revalidate the prior confirmation",
        })
    return {"finding_docs": written, "withheld": withheld,
            "superseded_docs": stale_docs,
            "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION,
            "dir": str(reports_dir.relative_to(ctx.workspace))}





