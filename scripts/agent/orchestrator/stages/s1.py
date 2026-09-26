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

def run_s1(ctx: StageContext) -> Dict[str, Any]:
    """Module topology + entry inventory + default-feature inventory.

    Baseline #1/#2 additions: jar version diff (added/removed classes between
    versions) and a danger call-site map (danger patterns x file x line), with
    per-entry danger-hit counts as reachability clues.
    """
    source_dirs = _effective_source_dirs(ctx)
    inventory_timeout = getattr(ctx.config, "coverage_scan_timeout_seconds", 600)
    if (isinstance(inventory_timeout, bool)
            or not isinstance(inventory_timeout, int) or inventory_timeout < 0):
        raise ValueError("coverage_scan_timeout_seconds must be a nonnegative integer")
    jars_info = []
    class_sets = {}
    for j in ctx.config.jars:
        p = ctx.workspace / j["path"]
        classes = srch.jar_classes(p)
        class_sets[j["version"]] = set(
            c for c in classes if c.endswith(".class") and "module-info" not in c)
        jars_info.append({
            "version": j["version"],
            # [vulngate-macos-universal] TargetConfig.resolve_jars 允许
            # jar 位于 workspace 之外（绝对路径），但这一行假设了
            # 包含关系，relative_to 会抛 ValueError 让 S1 整体崩。
            # macOS 应用的 jar 天然在 /Applications 下，故需容忍。
            "path": (str(p.relative_to(ctx.workspace))
                     if ctx.workspace.resolve() in p.resolve().parents else str(p)),
            "sha256": srch.sha256(p),
            "size_bytes": p.stat().st_size,
            "class_count": len([c for c in classes if c.endswith(".class")]),
            "module_map": srch.module_map(classes),
        })
    # Version diff: classes added/removed between the oldest and newest jar.
    version_diff = []
    if len(class_sets) >= 2:
        versions = sorted(class_sets.keys())
        base = class_sets[versions[0]]
        head = class_sets[versions[-1]]
        version_diff = {
            "from": versions[0],
            "to": versions[-1],
            "added": sorted(head - base)[:200],
            "removed": sorted(base - head)[:200],
        }
    # Danger call-site map (source dirs only; jar scan is name-level).
    try:
        danger_sites, target_rule_hits = scan_s1_source_rules(
            ctx.config.target_type, source_dirs, ctx.workspace,
            danger_limit=8, target_limit=8, timeout=inventory_timeout)
        source_rule_status = {"status": "complete",
                              "timeout_seconds": inventory_timeout,
                              "claim_status": "not-a-finding"}
    except SourceScanTimeout as exc:
        danger_sites, target_rule_hits = [], []
        source_rule_status = {
            "status": "incomplete", "timeout_seconds": inventory_timeout,
            "error": str(exc), "progress": exc.progress,
            "claim_status": "not-a-finding",
        }
    per_file_hits: Dict[str, int] = {}
    for hit in danger_sites:
        fl = str(hit["file"])
        per_file_hits[fl] = per_file_hits.get(fl, 0) + 1
    entries = []
    # ``count_references`` shells out to ripgrep per entry.  With the entry
    # inventory no longer capped (spec §6.1) that would be one rg per entry;
    # entries share a small set of API names, so memoizing by name collapses it
    # to a handful of scans without changing the result.
    refs_cache: Dict[str, int] = {}
    targets_dir = ctx.workspace / "targets"
    for ep in ctx.config.entry_points:
        api = str(ep.get("api", ""))
        if targets_dir.exists():
            if api not in refs_cache:
                refs_cache[api] = srch.count_references(targets_dir, api)
            refs = refs_cache[api]
        else:
            refs = 0
        entry = dict(ep)
        entry["g0"] = g0_dead_code(ep, refs).__dict__
        entry["g1"] = g1_reachable(ep).__dict__
        fl = ep.get("file_line") or ep.get("file") or ""
        # [vulngate-macos-universal] 原为 t.endswith(".java")，导致 .h/.swift/
        # .py/.ts 入口的 danger_hits 恒为 0。后缀集现在来自
        # agent.analysis.languages（spec §6.3），不再各处硬编码。
        _src_exts = tuple(ALL_SUFFIXES)
        fname_tokens = [t for t in re.split(r"[^\w./]+", str(fl))
                        if t.endswith(_src_exts)]

        def _match(d: Dict[str, object]) -> bool:
            dfile = str(d["file"])
            return any(t in dfile for t in fname_tokens) or (fl and fl in dfile)

        entry["danger_hits"] = sum(1 for d in danger_sites if _match(d))
        entry["reachability_clues"] = [
            {"label": d["label"], "file": d["file"], "line": d["line"]}
            for d in danger_sites if _match(d)
        ][:10]
        entries.append(entry)
    gate_scan = _gate_scan(ctx)
    patch_history = analyze_patch_history(ctx.workspace, max_count=30)
    graph_timeout = min(inventory_timeout, 120) if inventory_timeout else 0
    graph_filter = SourceFilter(scan_timeout_seconds=graph_timeout)
    try:
        source_sink_graph = build_source_sink_graph(
            source_dirs, ctx.workspace, source_filter=graph_filter)
        source_sink_status = {
            "status": "complete", "path_count": len(source_sink_graph),
            "timeout_seconds": graph_timeout,
            "claim_status": "not-a-finding",
        }
    except SourceScanTimeout as exc:
        source_sink_graph = []
        source_sink_status = {
            "status": "incomplete", "error": str(exc),
            "progress": exc.progress,
            "timeout_seconds": graph_timeout,
            "claim_status": "not-a-finding",
        }
    chain_hints = composite_chain_hints(source_sink_graph)
    chain_candidates = composite_chain_candidates(chain_hints)
    project_profile = build_project_profile(
        ctx.config, ctx.workspace, danger_site_count=len(danger_sites),
        source_sink_path_count=len(source_sink_graph),
        security_fix_count=len(patch_history))
    ctx.store.write_artifact("S1", "jars.json", jars_info)
    ctx.store.write_artifact("S1", "entry-inventory.json", entries)
    ctx.store.write_artifact("S1", "gate-scan.json", gate_scan)
    ctx.store.write_artifact("S1", "version-diff.json", version_diff)
    ctx.store.write_artifact("S1", "danger-call-sites.json", danger_sites)
    ctx.store.write_artifact("S1", "source-rule-scan-status.json",
                             source_rule_status)
    ctx.store.write_artifact("S1", "security-fix-history.json", patch_history)
    ctx.store.write_artifact("S1", "patch-variants.json", [
        {k: fix[k] for k in ("short_commit", "commit", "parent", "subject",
                             "affected_paths", "variant_hints", "probe_plan")}
        for fix in patch_history
    ])
    ctx.store.write_artifact("S1", "source-sink-graph.json", source_sink_graph)
    ctx.store.write_artifact("S1", "source-sink-graph-status.json",
                             source_sink_status)
    ctx.store.write_artifact("S1", "project-profile.json", project_profile)
    ctx.store.write_artifact("S1", "target-rules.json", {
        "target_type": ctx.config.target_type,
        "hits": target_rule_hits,
    })
    ctx.store.write_artifact("S1", "composite-chain-hints.json", chain_hints)
    ctx.store.write_artifact("S1", "composite-chain-candidates.json",
                             chain_candidates)
    # S1 -> Inventory / Coverage Index (spec §21.3).  Best-effort: a coverage
    # failure must not abort an audit round, but the reason is recorded so the
    # gap is visible rather than silent.
    try:
        coverage_index = _build_coverage_index(ctx)
    except SourceScanTimeout as exc:
        from ...analysis.inventory import CoverageStore

        coverage_index = {
            "status": "incomplete", "scope_complete": False,
            "error": str(exc), "progress": exc.progress,
            "claim_status": "not-a-finding",
        }
        ctx.store.write_artifact("S1", "coverage-progress.json", {
            "status": "timed-out", **exc.progress, "error": str(exc),
        })
        CoverageStore(ctx.workspace, ctx.target).write("coverage-build-status", {
            "status": "incomplete", "failed_at": datetime.now().isoformat(timespec="seconds"),
            "error": str(exc), "progress": exc.progress,
        })
    except Exception as exc:  # pragma: no cover - defensive
        from ...analysis.inventory import CoverageStore

        coverage_index = {
            "status": "incomplete", "scope_complete": False,
            "error": "%s: %s" % (type(exc).__name__, exc),
            "claim_status": "not-a-finding",
        }
        CoverageStore(ctx.workspace, ctx.target).write("coverage-build-status", {
            "status": "failed", "failed_at": datetime.now().isoformat(timespec="seconds"),
            "error": coverage_index["error"],
        })
    coverage_incomplete = _coverage_scope_incomplete(coverage_index)
    if coverage_incomplete:
        coverage_index["status"] = "incomplete"
        coverage_index["scope_complete"] = False
    ctx.store.write_artifact("S1", "coverage-summary.json", coverage_index)
    if coverage_incomplete:
        return {
            "jars": jars_info, "entries": entries,
            "gate_scan_count": len(gate_scan), "version_diff": version_diff,
            "danger_site_count": len(danger_sites),
            "security_fix_count": len(patch_history),
            "source_sink_path_count": len(source_sink_graph),
            "target_rule_hit_count": len(target_rule_hits),
            "composite_chain_hint_count": len(chain_hints),
            "composite_chain_candidate_count": len(chain_candidates),
            "source_dirs": source_dirs, "coverage": coverage_index,
            "project_profile": project_profile,
            "coverage_policy_version": SOURCE_INVENTORY_POLICY_VERSION,
        }
    # Keep the graph and its candidates visible in the round checkpoint as
    # well as in the target-scoped coverage store.  This makes S1 evidence
    # auditable without duplicating the graph-building logic.
    try:
        from ...analysis import capability_graph as capability
        from ...analysis import semantic_guards as semantic_guard
        from ...analysis import semantic_calls as semantic_call
        from ...analysis import semantic_controlflow as semantic_controlflow
        from ...analysis import semantic_ast as semantic_ast
        from ...analysis import semantic_transforms as semantic_transform
        from ...analysis import semantic_bindings as semantic_binding
        from ...analysis import semantic_paths as semantic
        from ...analysis import evidence_provenance as evidence_provenance_analysis
        from ...analysis import threat_model as threat_model_analysis
        from ...analysis.inventory import CoverageStore
        coverage_store = CoverageStore(ctx.workspace, ctx.target)
        ctx.store.write_artifact(
            "S1", "capability-graph.json",
            capability.load_capability_graph(coverage_store))
        ctx.store.write_artifact(
            "S1", "capability-candidates.json",
            capability.load_capability_candidates(coverage_store))
        ctx.store.write_artifact(
            "S1", "threat-model.json",
            threat_model_analysis.load_threat_model(ctx.workspace, ctx.target))
        ctx.store.write_artifact(
            "S1", "semantic-path-evidence.json",
            semantic.load_semantic_evidence(coverage_store))
        ctx.store.write_artifact(
            "S1", "semantic-path-candidates.json",
            semantic.load_semantic_candidates(coverage_store))
        ctx.store.write_artifact(
            "S1", "semantic-guard-evidence.json",
            semantic_guard.load_semantic_guards(coverage_store))
        ctx.store.write_artifact(
            "S1", "semantic-guard-candidates.json",
            semantic_guard.load_semantic_guard_candidates(coverage_store))
        ctx.store.write_artifact(
            "S1", "semantic-call-evidence.json",
            semantic_call.load_semantic_call_evidence(coverage_store))
        ctx.store.write_artifact(
            "S1", "semantic-call-candidates.json",
            semantic_call.load_semantic_call_candidates(coverage_store))
        ctx.store.write_artifact(
            "S1", "semantic-controlflow-evidence.json",
            semantic_controlflow.load_semantic_controlflow(coverage_store))
        ctx.store.write_artifact(
            "S1", "semantic-controlflow-candidates.json",
            semantic_controlflow.load_semantic_controlflow_candidates(coverage_store))
        ctx.store.write_artifact(
            "S1", "semantic-ast-evidence.json",
            semantic_ast.load_semantic_ast(coverage_store))
        ctx.store.write_artifact(
            "S1", "semantic-ast-candidates.json",
            semantic_ast.load_semantic_ast_candidates(coverage_store))
        ctx.store.write_artifact(
            "S1", "semantic-transform-evidence.json",
            semantic_transform.load_semantic_transform_evidence(coverage_store))
        ctx.store.write_artifact(
            "S1", "semantic-transform-candidates.json",
            semantic_transform.load_semantic_transform_candidates(coverage_store))
        ctx.store.write_artifact(
            "S1", "semantic-python-binding-evidence.json",
            semantic_binding.load_semantic_binding_evidence(coverage_store))
        ctx.store.write_artifact(
            "S1", "semantic-python-binding-candidates.json",
            semantic_binding.load_semantic_binding_candidates(coverage_store))
        ctx.store.write_artifact(
            "S1", "evidence-provenance.json",
            evidence_provenance_analysis.load_evidence_provenance(coverage_store))
    except Exception as exc:  # pragma: no cover - evidence mirror is best-effort
        ctx.store.write_artifact("S1", "capability-graph-error.json", {
            "error": "%s: %s" % (type(exc).__name__, exc)})
    return {"jars": jars_info, "entries": entries, "gate_scan_count": len(gate_scan),
            "version_diff": version_diff, "danger_site_count": len(danger_sites),
            "security_fix_count": len(patch_history),
            "source_sink_path_count": len(source_sink_graph),
            "target_rule_hit_count": len(target_rule_hits),
            "composite_chain_hint_count": len(chain_hints),
            "composite_chain_candidate_count": len(chain_candidates),
            "source_dirs": source_dirs,
            "coverage": coverage_index,
            "project_profile": project_profile,
            "coverage_policy_version": SOURCE_INVENTORY_POLICY_VERSION}





