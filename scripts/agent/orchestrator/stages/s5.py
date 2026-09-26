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

def _derive_conclusion(candidate: Dict[str, Any], summary: Dict[str, Any],
                       cells: Optional[List[Dict[str, Any]]] = None) -> str:
    """Data-driven conclusion, delegating to the shared rules module
    (baseline fix #10: one implementation across config/autonomous/benchmark)."""
    return derive_conclusion(summary, candidate, cells)


def run_s5(ctx: StageContext) -> Dict[str, Any]:
    """Novelty gate: upstream open PR/issue + public disclosure + timeline."""
    cache_dir = ctx.workspace / "agent" / "regression" / "cache" / "api"
    checker = NoveltyChecker(fixtures_dir=ctx.fixture_dir(), offline=ctx.offline,
                             cache_dir=cache_dir)
    pub = ctx.public_disclosures()
    results = {}
    coverage = {
        "offline": ctx.offline,
        "public_scan_channels": pub.get("channels", {}),
        "public_scan_channel_status": pub.get("channel_status", {}),
        "public_scan_errors": pub.get("errors", []),
        "public_disclosure_count": len(pub.get("disclosures", [])),
        "configured_public_channels": bool(
            (ctx.config.public_scan or {}).get("maven_package")
            or (ctx.config.public_scan or {}).get("nvd_keywords")
            or (ctx.config.public_scan or {}).get("advisories_repo")
            or ctx.config.upstream_repo),
        "candidates": [],
    }
    for cand in ctx.config.candidates:
        if cand.get("skip_novelty"):
            results[cand["candidate_id"]] = {
                "novelty": {"verdict": "not-applicable", "reason": "排除项候选不主张 0day，跳过 Novelty 判定"},
                "g3": {"gate_id": "G3", "passed": True, "verdict": "not-applicable", "evidence": []},
            }
            continue
        refs = []
        query_attempts_before = len(checker.query_attempts)
        query_errors_before = set(checker.query_errors)
        for r in cand.get("upstream_refs", []):
            refs.append(UpstreamRef(**r))
        # Live scan: refresh config refs via API and search by keywords.
        repo = ctx.config.upstream_repo or ""
        keyword_limit = max(1, int(cand.get("novelty_max_keywords", 12)))
        result_limit = max(1, int(cand.get("novelty_max_results", 20)))
        coverage["candidates"].append({
            "candidate_id": cand["candidate_id"],
            "repo": repo,
            "keywords": list(cand.get("novelty_keywords", []))[:keyword_limit],
            "keyword_limit": keyword_limit,
            "result_limit": result_limit,
        })
        if repo and not ctx.offline:
            for r in list(refs):
                num = "".join(ch for ch in r.ref if ch.isdigit())
                if num:
                    live = checker.fetch_ref(
                        repo, int(num), "pulls" if r.kind == "pull_request" else "issues")
                    if live is not None:
                        live.coverage_note = r.coverage_note
                        refs[refs.index(r)] = live
            for kw in cand.get("novelty_keywords", [])[:keyword_limit]:
                for item in checker.search(repo, kw)[:result_limit]:
                    ref = upstream_ref_from_search_hit(
                        repo, item, "GitHub search API/fixture")
                    if ref is None:
                        checker.query_errors.append("search:malformed-hit")
                        continue
                    if (ref.kind, ref.ref) not in {(x.kind, x.ref) for x in refs}:
                        refs.append(ref)
        disclosures = []
        for d in cand.get("disclosures", []):
            disclosures.append(Disclosure(**d))
        disclosures += pub["disclosures"]
        # Baseline #7: when any public-info channel failed (or the run is
        # offline / rate-limited), absence of a record is NOT a 0day claim.
        query_metadata = checker.query_metadata()
        github_query_attempted = len(checker.query_attempts) > query_attempts_before
        candidate_query_errors = set(checker.query_errors) - query_errors_before
        successful_public_channels = bool(pub.get("channel_status")) and all(
            status in ("success-with-hits", "success-empty")
            for status in pub.get("channel_status", {}).values())
        query_failed = (bool(pub.get("errors")) or checker.last_rate_limit is not None
                        or bool(candidate_query_errors) or ctx.offline
                        or not (github_query_attempted or successful_public_channels))
        nv = checker.evaluate(refs, disclosures, ctx.config.discovery_date,
                              increments_hint=cand.get("increments_hint", []),
                              query_failed=query_failed)
        g3 = g3_novelty(nv.__dict__)
        nv_dict = dataclasses.asdict(nv)
        results[cand["candidate_id"]] = {
            "novelty": nv_dict, "g3": g3.__dict__,
            "query_metadata": query_metadata,
        }
        if getattr(ctx.config, "llm_audit", False) and ctx.llm is not None:
            audit = mechanism_audit_llm(
                ctx.llm, "你是资深安全研究员，判断上游记录与候选是否同一漏洞机制。",
                cand, refs, checker, ctx.config.discovery_date,
                ctx.config.upstream_repo or "", offline=ctx.offline)
            if audit:
                same = [a for a in audit if a.get("same_mechanism")]
                if same:
                    # Mechanism audit found an upstream body for the same bug:
                    # downgrade the verdict and recompute G3 (previously the
                    # gate was computed only before the audit).
                    nv_dict["verdict"] = "known-family-with-increment"
                    nv_dict["reason"] += " | upstream body confirms same mechanism: %s" % ", ".join(
                        str(a.get("ref")) for a in same)
                nv_dict["increments"] = list(nv_dict.get("increments", [])) + [
                    "mechanism audit (pipeline): %d reviewed, %d same"
                    % (len(audit), len(same))]
                g3 = g3_novelty(nv_dict)
                results[cand["candidate_id"]] = {
                    "novelty": nv_dict, "g3": g3.__dict__,
                    "mechanism_audit": audit,
                    "query_metadata": checker.query_metadata(),
                }
    if checker.last_rate_limit:
        results["api_rate_limit"] = checker.last_rate_limit
    if checker.query_errors:
        results["api_query_errors"] = sorted(set(checker.query_errors))
    results["public_scan"] = {
        "channels": pub["channels"],
        "channel_status": pub.get("channel_status", {}),
        "errors": pub["errors"],
        "disclosure_ids": [d.id for d in pub["disclosures"]],
    }
    results["github_query"] = checker.query_metadata()
    coverage["github_query_errors"] = sorted(set(checker.query_errors))
    coverage["github_query"] = checker.query_metadata()
    coverage["authoritative"] = bool(coverage["configured_public_channels"])
    coverage["authoritative"] = (coverage["authoritative"]
                                  and not bool(pub.get("errors"))
                                  and not checker.query_errors
                                  and checker.last_rate_limit is None
                                  and not ctx.offline)
    ctx.store.write_artifact("S5", "novelty-coverage.json", coverage)
    ctx.store.write_artifact("S5", "novelty.json", results)
    return {"novelty": results,
            "query_policy_version": NOVELTY_QUERY_POLICY_VERSION}





