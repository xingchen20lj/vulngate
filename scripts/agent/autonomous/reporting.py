"""Autonomous round orchestration, reporting, and CLI entrypoint."""

from __future__ import annotations

# The phase modules share a deliberately centralized policy/context namespace.
# Keep this import surface stable while the public facade preserves legacy callers.
# ruff: noqa: F403,F405
from .common import *
from .common import (_scope_block, _sec_prompt, _target_source_scope)
from .preparation import (
    _ensure_capability_inventory,
    prepare_target,
)
from .scheduling import (
    _attach_experiment_plans,
    learn_api_hint,
    propose_candidates,
    schedule_candidates,
    static_candidates,
)
from .execution import (
    _fuzz_audit,
    audit_candidate,
    cvss_for_tier,
    novelty_check,
    verify_candidate,
)

def run_round(ctx: AutoCtx, round_no: int) -> Dict[str, Any]:
    """Full S2->S8 round with per-stage checkpoints (baseline fix #10:
    autonomous state semantics aligned with the config pipeline) and the G5
    CVSS-precondition consistency gate (previously missing in this driver)."""
    from ..memory.state import CheckpointStore
    from ..tools.cvss import check_precondition_consistency
    from ..analysis.audit_budget import (
        DEFAULT_BUDGET_SECONDS, round_budget_snapshot, start_round_budget,
    )
    from ..analysis.audit_guard import register_active_audit

    store = CheckpointStore(ctx.root, ctx.cfg.name, round_no)
    budget_seconds = getattr(
        ctx.cfg, "audit_round_timeout_seconds", DEFAULT_BUDGET_SECONDS)
    if budget_seconds is None:
        budget_seconds = DEFAULT_BUDGET_SECONDS
    try:
        ctx._round_budget_record = start_round_budget(
            ctx.root, ctx.cfg.name, round_no, budget_seconds)
    except (OSError, TypeError, ValueError) as exc:
        error = {"status": "invalid-round-budget", "error": str(exc),
                 "claim_status": "not-a-finding"}
        ctx.write_artifact(round_no, "S0", "execution-budget-status.json", error)
        print("[round-%02d] refusing invalid round budget: %s" % (round_no, exc))
        return {"next_candidates": [], **error}
    remaining_seconds = max(
        0.001, float(round_budget_snapshot(ctx._round_budget_record).get(
            "remaining_seconds", budget_seconds)))
    ctx.work_budget = WorkBudget(
        name="autonomous-round", wall_seconds=remaining_seconds,
        scan_files=500_000, scan_bytes=4 * 1024 * 1024 * 1024,
        process_slots=128, candidate_slots=max(1, int(ctx.max_candidates)),
        llm_calls=max(1, int(getattr(ctx.llm, "max_calls", 40))))
    set_work_budget = getattr(ctx.llm, "set_work_budget", None)
    if callable(set_work_budget):
        set_work_budget(ctx.work_budget)

    def timebox_report(last_completed: Optional[str], next_stage: str
                       ) -> Optional[Dict[str, Any]]:
        snapshot = round_budget_snapshot(ctx._round_budget_record)
        if not snapshot["expired"]:
            return None
        report = {
            "status": "stopped-at-round-deadline",
            "last_completed_stage": last_completed,
            "next_stage": next_stage,
            "completed_stages": store.completed_stages(),
            "audit_budget": snapshot,
            "claim_status": "not-a-finding",
        }
        ctx.write_artifact(round_no, "S0", "execution-budget-status.json", snapshot)
        ctx.write_artifact(round_no, "S0", "round-timebox-report.json", report)
        store.save_stage("S0", report)
        print("[round-%02d] round deadline expired; preserving progress and stopping" %
              round_no)
        return report

    report = timebox_report(None, "S1")
    if report:
        return {"next_candidates": [], **report}

    try:
        source_root, _source_dirs = _target_source_scope(ctx)
        register_active_audit(
            source_root, ctx.root, ctx.cfg.name, round_no,
            str(round_budget_snapshot(ctx._round_budget_record)["deadline_at"]))
    except (OSError, TypeError, ValueError) as exc:
        error = {"status": "invalid-round-guard", "error": str(exc),
                 "claim_status": "not-a-finding"}
        ctx.write_artifact(round_no, "S0", "execution-budget-status.json", error)
        print("[round-%02d] refusing round without active-audit guard: %s" % (
            round_no, exc))
        return {"next_candidates": [], **error}
    ctx._active_audit_guard_registered = True
    bind_deadline = getattr(ctx.llm, "set_timeout_provider", None)
    if callable(bind_deadline):
        bind_deadline(ctx.round_budget_remaining)

    ctx._candidate_source_hit_cache = {}
    ctx._candidate_source_snippet_cache.reset_round(
        round_no, ctx.root / "state" / ctx.cfg.name /
        ("round-%02d" % round_no) / "S0" / "source-cache-metrics.json")

    def bounded_scan_timeout(configured: int) -> int:
        remaining = int(round_budget_snapshot(
            ctx._round_budget_record)["remaining_seconds"])
        if remaining < 1:
            return 1
        return min(configured, remaining) if configured > 0 else remaining

    def record_capability_state(state: Dict[str, Any]) -> None:
        ctx._coverage_inventory_round = round_no
        ctx._coverage_inventory_state = state
        scope = state.get("scope")
        ctx.write_artifact(round_no, "S1", "capability-inventory-status.json", {
            "status": state.get("status") or (
                "complete" if isinstance(scope, dict) and scope.get("usable")
                else "incomplete"),
            "rebuilt": bool(state.get("rebuilt")),
            "deferred": bool(state.get("deferred")),
            "error": state.get("error"),
            "scope": state.get("scope") or {},
            "claim_status": "not-a-finding",
        })
        ctx.write_artifact(round_no, "S1", "capability-graph.json",
                           state.get("graph") or {})
        ctx.write_artifact(round_no, "S1", "capability-candidates.json",
                           state.get("candidates") or [])
        ctx.write_artifact(round_no, "S1", "threat-model.json",
                           state.get("threat_model") or {})
        ctx.write_artifact(round_no, "S1", "semantic-guard-evidence.json",
                           state.get("semantic_guards") or {})
        ctx.write_artifact(round_no, "S1", "semantic-guard-candidates.json",
                           state.get("semantic_guard_candidates") or [])
        ctx.write_artifact(round_no, "S1", "semantic-call-evidence.json",
                           state.get("semantic_calls") or {})
        ctx.write_artifact(round_no, "S1", "semantic-call-candidates.json",
                           state.get("semantic_call_candidates") or [])
        ctx.write_artifact(round_no, "S1", "semantic-controlflow-evidence.json",
                           state.get("semantic_controlflow") or {})
        ctx.write_artifact(round_no, "S1", "semantic-controlflow-candidates.json",
                           state.get("semantic_controlflow_candidates") or [])
        ctx.write_artifact(round_no, "S1", "semantic-ast-evidence.json",
                           state.get("semantic_ast") or {})
        ctx.write_artifact(round_no, "S1", "semantic-ast-candidates.json",
                           state.get("semantic_ast_candidates") or [])
        ctx.write_artifact(round_no, "S1", "semantic-transform-evidence.json",
                           state.get("semantic_transforms") or {})
        ctx.write_artifact(round_no, "S1", "semantic-transform-candidates.json",
                           state.get("semantic_transform_candidates") or [])
        ctx.write_artifact(round_no, "S1", "semantic-python-binding-evidence.json",
                           state.get("semantic_bindings") or {})
        ctx.write_artifact(round_no, "S1", "semantic-python-binding-candidates.json",
                           state.get("semantic_binding_candidates") or [])
        ctx.write_artifact(round_no, "S1", "evidence-provenance.json",
                           state.get("evidence_provenance") or {})
        if state.get("error"):
            ctx.write_artifact(round_no, "S1", "capability-graph-error.json", {
                "error": state["error"]})

    def try_deferred_inventory(stage: str) -> List[Dict[str, Any]]:
        state = getattr(ctx, "_coverage_inventory_state", None)
        if not isinstance(state, dict) or not state.get("deferred"):
            return []
        remaining = int(round_budget_snapshot(
            ctx._round_budget_record)["remaining_seconds"])
        # Reserve at least 15 minutes for S3/S4 (or S5-S8 after S4). A single
        # optional inventory attempt is capped at five minutes and can never
        # hold a scheduled candidate waiting for its next falsifier.
        reserve_seconds = 900
        if remaining <= reserve_seconds:
            ctx.write_artifact(round_no, stage, "capability-inventory-followup.json", {
                "status": "deferred", "reason": "insufficient-round-budget",
                "remaining_seconds": remaining, "claim_status": "not-a-finding",
            })
            return []
        rebuild_budget = min(300, remaining - reserve_seconds)
        rebuilt = _ensure_capability_inventory(
            ctx, allow_rebuild=True, rebuild_budget_seconds=rebuild_budget)
        ctx._coverage_inventory_round = round_no
        ctx._coverage_inventory_state = rebuilt
        scope = rebuilt.get("scope")
        ctx.write_artifact(round_no, stage, "capability-inventory-followup.json", {
            "status": rebuilt.get("status") or (
                "complete" if isinstance(scope, dict) and scope.get("usable")
                else "incomplete"),
            "rebuilt": bool(rebuilt.get("rebuilt")),
            "error": rebuilt.get("error"), "scope": rebuilt.get("scope") or {},
            "remaining_seconds": int(round_budget_snapshot(
                ctx._round_budget_record)["remaining_seconds"]),
            "claim_status": "not-a-finding",
        })
        leads, _ids = static_candidates(ctx, round_no)
        if leads:
            ctx.write_artifact(round_no, stage,
                               "deferred-capability-candidates.json", leads)
        return leads

    report = timebox_report(None, "S1")
    if report:
        return {**report, "next_candidates": []}

    if not ctx.cfg.api_hint:
        learn_api_hint(ctx, round_no)
        report = timebox_report("S1.5", "S1")
        if report:
            return {**report, "next_candidates": []}

    # Candidate prompt anchors are reused in-memory for this round. Extracted
    # snippets use a separate bounded content-digest cache: file bytes are
    # hashed on first access each round, so source edits invalidate old text.
    deferred_index_candidates: List[Dict[str, Any]] = []
    force = getattr(ctx, "force", False)
    source_root, source_dirs = _target_source_scope(ctx)
    inventory_timeout = getattr(ctx.cfg, "coverage_scan_timeout_seconds", 600)
    if (isinstance(inventory_timeout, bool)
            or not isinstance(inventory_timeout, int) or inventory_timeout < 0):
        raise ValueError("coverage_scan_timeout_seconds must be a nonnegative integer")
    from ..analysis.languages import SourceScanTimeout
    inventory_timeout = bounded_scan_timeout(inventory_timeout)

    # ---- S1 artifacts: attack surface (deterministic, refreshed cheaply) --
    # Baseline #1/#2: danger call-site map + entry danger-hit counts feed the
    # LLM prompts (via source_evidence) and the G0/G1 reachability notes.
    try:
        _danger_hits, target_rule_hits = scan_s1_source_rules(
            ctx.cfg.target_type, source_dirs, source_root,
            danger_limit=6, target_limit=8, timeout=inventory_timeout)
        source_rule_status = {"status": "complete",
                              "timeout_seconds": inventory_timeout,
                              "claim_status": "not-a-finding"}
    except SourceScanTimeout as exc:
        _danger_hits, target_rule_hits = [], []
        source_rule_status = {
            "status": "incomplete", "timeout_seconds": inventory_timeout,
            "error": str(exc), "progress": exc.progress,
            "claim_status": "not-a-finding",
        }
    _danger = [{"label": _h["label"], "file": _h["file"],
                "line": _h["line"], "text": _h["text"]}
               for _h in _danger_hits]
    ctx.write_artifact(round_no, "S1", "attack-surface.json", {
        "entries": ctx.cfg.entry_points,
        "danger_sites": _danger,
        "danger_site_count": len(_danger),
        "source_root": str(source_root),
        "source_dirs": source_dirs,
        "claim_status": "not-a-finding",
    })
    ctx.write_artifact(round_no, "S1", "source-rule-scan-status.json",
                       source_rule_status)
    patch_history = analyze_patch_history(ctx.root, max_count=30)
    report = timebox_report("S1-source-rules", "S1-source-sink-graph")
    if report:
        return {**report, "next_candidates": []}
    from ..analysis.languages import SourceFilter
    graph_timeout = bounded_scan_timeout(
        min(inventory_timeout, 120) if inventory_timeout else 0)
    graph_filter = SourceFilter(
        scan_timeout_seconds=min(inventory_timeout, 120) if inventory_timeout else 0,
        runtime_deadline_override_seconds=round_budget_snapshot(
            ctx._round_budget_record)["remaining_seconds"])
    try:
        ctx._source_sink_graph = build_source_sink_graph(
            source_dirs, source_root, source_filter=graph_filter)
        source_sink_status = {
            "status": "complete", "path_count": len(ctx._source_sink_graph),
            "timeout_seconds": graph_timeout,
            "claim_status": "not-a-finding",
        }
    except SourceScanTimeout as exc:
        ctx._source_sink_graph = []
        source_sink_status = {
            "status": "incomplete", "error": str(exc),
            "progress": exc.progress,
            "timeout_seconds": graph_timeout,
            "claim_status": "not-a-finding",
        }
    ctx.write_artifact(round_no, "S1", "source-sink-graph-status.json",
                       source_sink_status)
    profile_cfg = dataclasses.replace(ctx.cfg, source_dirs=source_dirs)
    ctx._project_profile = build_project_profile(
        profile_cfg, source_root, danger_site_count=len(_danger),
        source_sink_path_count=len(ctx._source_sink_graph),
        security_fix_count=len(patch_history))
    chain_hints = composite_chain_hints(ctx._source_sink_graph)
    chain_candidates = composite_chain_candidates(chain_hints)
    ctx.write_artifact(round_no, "S1", "security-fix-history.json", patch_history)
    ctx.write_artifact(round_no, "S1", "patch-variants.json", [
        {k: fix[k] for k in ("short_commit", "commit", "parent", "subject",
                             "affected_paths", "variant_hints", "probe_plan")}
        for fix in patch_history
    ])
    ctx.write_artifact(round_no, "S1", "source-sink-graph.json", ctx._source_sink_graph)
    ctx.write_artifact(round_no, "S1", "project-profile.json", ctx._project_profile)
    ctx.write_artifact(round_no, "S1", "target-rules.json", {
        "target_type": ctx.cfg.target_type, "hits": target_rule_hits,
    })
    ctx.write_artifact(round_no, "S1", "composite-chain-hints.json", chain_hints)
    ctx.write_artifact(round_no, "S1", "composite-chain-candidates.json",
                       chain_candidates)
    report = timebox_report("S1-source-sink-graph", "S1-capability-inventory")
    if report:
        return {**report, "next_candidates": []}
    capability_state = _ensure_capability_inventory(ctx, allow_rebuild=False)
    record_capability_state(capability_state)
    report = timebox_report("S1-capability-inventory", "S2")
    if report:
        return {**report, "next_candidates": []}

    # ---- S2: candidates (resumable) -----------------------------------
    s2 = store.load_stage("S2")
    if s2 and not force:
        candidates = s2["candidates"]
        print("[round-%02d] S2 resume: %d candidates loaded" % (round_no, len(candidates)))
        experiment_plans = _attach_experiment_plans(ctx, round_no, candidates)
        store.save_stage("S2", {"candidates": candidates})
    else:
        fuzz_cands: List[Dict[str, Any]] = []
        if ctx.fuzz_budget > 0:
            print("[round-%02d] S2: fuzz discovery (budget=%d, seed=%s)..."
                  % (round_no, ctx.fuzz_budget, ctx.fuzz_seed or 20260808))
            fuzz_cands = run_fuzz_for_pipeline(
                ctx.root, ctx.cfg, round_no, budget=ctx.fuzz_budget,
                seed=ctx.fuzz_seed or 20260808, force=ctx.fuzz_force,
                skip_minimize=ctx.fuzz_skip_minimize)
        llm_slots = max(0, ctx.max_candidates - len(fuzz_cands))
        if llm_slots > 0:
            print("[round-%02d] S2: proposing candidates (LLM)..." % round_no)
            llm_cands = propose_candidates(ctx, round_no,
                                           carryover=ctx.carryover)[:llm_slots]
        else:
            print("[round-%02d] fuzz candidates fill budget; skipping LLM proposal" % round_no)
            llm_cands = []
        seen_ids = set()
        merged = []
        # Index-derived candidates first: on an exact score tie the candidate
        # with a citable file:line and a named missing control should win over
        # one that has neither.  The scheduler re-ranks everything after this,
        # so position is only a tiebreaker.
        derived, derived_ids = static_candidates(ctx, round_no)
        if derived_ids:
            print("[round-%02d] S2: +%d index-derived candidates (spec §11/§12)"
                  % (round_no, len(derived_ids)))
        for c in derived + fuzz_cands + llm_cands:
            cid = c.get("candidate_id")
            if cid in seen_ids:
                continue
            seen_ids.add(cid)
            merged.append(c)
        # Spec §13: the scheduler decides *which* N, not the merge order.  Fuzz
        # candidates are pinned: they carry runtime evidence (a reproducer and
        # its observations) that no static factor can see, so a static ranking
        # must never be able to displace one in favour of a nicer-looking
        # candidate that has not been executed.
        pinned = [str(c.get("candidate_id")) for c in fuzz_cands
                  if c.get("candidate_id")]
        candidates, schedule_note = schedule_candidates(ctx, round_no, merged,
                                                        pinned=pinned)
        if not candidates:
            late_candidates = try_deferred_inventory("S2")
            if late_candidates:
                merged.extend(late_candidates)
                candidates, late_note = schedule_candidates(
                    ctx, round_no, merged, pinned=pinned)
                schedule_note = "; ".join(
                    item for item in (schedule_note, late_note) if item)
        if not candidates:
            print("[round-%02d] no candidates; stopping" % round_no)
            return {"next_candidates": []}
        experiment_plans = _attach_experiment_plans(ctx, round_no, candidates)
        ctx.write_artifact(round_no, "S2", "candidate-matrix.json",
                           {"candidate_count": len(candidates),
                            "schedule_note": schedule_note,
                            "pool_size": len(merged),
                            "pinned": pinned,
                            "experiment_plan_count": len(experiment_plans),
                            "matrix": [
                                dict(
                                    [(k, c.get(k)) for k in (
                                        "candidate_id", "surface", "entry",
                                        "input_shape", "logic", "authz_cases",
                                        "experiment_plan")]
                                    + [("capability_contract",
                                       (c.get("experiment_plan") or {}).get(
                                           "capability_contract") or
                                       capability_contract_from_candidate(c)),
                                       ("variant_fixture_plan",
                                        (c.get("experiment_plan") or {}).get(
                                            "variant_fixture_plan", {})),
                                       ("comparison_contract",
                                        (c.get("experiment_plan") or {}).get(
                                            "comparison_contract", {})),
                                       ("consistency_action",
                                        (c.get("experiment_plan") or {}).get(
                                            "consistency_action", {}))]
                                )
                                for c in candidates
                            ]})
        store.save_stage("S2", {"candidates": candidates})

    report = timebox_report("S2", "S3")
    if report:
        return {**report, "next_candidates": []}

    # ---- S3: static audit (resumable) ---------------------------------
    s3 = store.load_stage("S3")
    if s3 and not force:
        audits = s3["audits"]
        print("[round-%02d] S3 resume: %d audit notes loaded" % (round_no, len(audits)))
    else:
        print("[round-%02d] S3: auditing %d candidates (LLM)..." % (round_no, len(candidates)))
        audits = {}
        for candidate in candidates:
            report = timebox_report("S3", "S3-candidate:%s" %
                                    candidate.get("candidate_id", "unknown"))
            if report:
                ctx.write_artifact(round_no, "S3", "audit-notes.partial.json", audits)
                return {**report, "next_candidates": []}
            audits[candidate["candidate_id"]] = (
                _fuzz_audit(candidate) if candidate.get("fuzz_spec")
                else audit_candidate(ctx, candidate))
        ctx.write_artifact(round_no, "S3", "audit-notes.json", audits)
        store.save_stage("S3", {"audits": audits})
    for candidate in candidates:
        audit = audits.get(candidate["candidate_id"], {})
        if not candidate.get("source_to_sink"):
            candidate["source_to_sink"] = audit.get("source_to_sink") or match_source_sink_paths(
                getattr(ctx, "_source_sink_graph", []), candidate)
    ctx.write_artifact(round_no, "S3", "residuals.json", [
        dict(residual, candidate_id=candidate["candidate_id"])
        for candidate in candidates for residual in (candidate.get("residuals") or [])
        if isinstance(residual, dict)
    ])
    report = timebox_report("S3", "S4")
    if report:
        return {**report, "next_candidates": []}

    # ---- S4: PoC + matrix (resumable, rows serialized w/o spec) -------
    s4 = store.load_stage("S4")
    s4_fresh = bool(
        s4 and s4.get("evidence_policy_version") == S4_EVIDENCE_POLICY_VERSION)
    invalidate_after_s4 = force or not s4_fresh
    if s4 and not s4_fresh:
        print("[round-%02d] S4 checkpoint predates %s; recomputing S4-S8" % (
            round_no, S4_EVIDENCE_POLICY_VERSION))
    report = timebox_report("S3", "S4")
    if report:
        return {**report, "next_candidates": []}
    if s4 and s4_fresh and not force:
        rows = s4["rows"]
        excluded = s4["excluded"]
        print("[round-%02d] S4 resume: %d confirmed / %d excluded"
              % (round_no, len(rows), len(excluded)))
    else:
        # Baseline fix #1 (spawn-like parallelism): candidates are verified in
        # independent workers (each candidate has its own PoC dir, matrix dir
        # and approval log). LLM usage accounting stays approximate under
        # concurrency (call/token counters may lag by a race window).
        from concurrent.futures import ThreadPoolExecutor, as_completed
        print("[round-%02d] S4: generating PoCs and running matrix "
              "(parallel workers)..." % round_no)
        round_remaining = max(1, int(round_budget_snapshot(
            ctx._round_budget_record)["remaining_seconds"]))
        s4_work_budget = (ctx.work_budget.child(
            "autonomous-s4", wall_seconds=min(
                getattr(ctx.cfg, "s4_timeout_seconds", 5400), round_remaining),
            candidate_slots=max(1, int(ctx.max_candidates)))
                          if ctx.work_budget is not None else None)
        ctx.s4_execution_budget = S4ExecutionBudget(
            min(getattr(ctx.cfg, "s4_timeout_seconds", 5400), round_remaining),
            min(getattr(ctx.cfg, "s4_candidate_timeout_seconds", 900),
                round_remaining), work_budget=s4_work_budget)
        rows = []
        excluded = []
        max_workers = min(4, max(1, len(candidates)))
        futures = {}
        processed_ids = set()

        def record_candidate_row(cand: Dict[str, Any], row: Dict[str, Any]) -> None:
            processed_ids.add(str(cand["candidate_id"]))
            if is_confirmed_conclusion(row.get("conclusion")):
                rows.append(row)
            else:
                excluded.append({
                    "candidate_id": cand["candidate_id"],
                    "surface": cand.get("surface"),
                    "conclusion": row.get("conclusion", "待验证"),
                    "evidence": row.get("summary", {}),
                    "runtime_lab": row.get("runtime_lab"),
                })
            print("  %s -> %s" % (
                cand["candidate_id"], row.get("conclusion", "待验证")))

        try:
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {
                    pool.submit(verify_candidate, ctx, round_no, cand,
                                audits[cand["candidate_id"]]): cand
                    for cand in candidates
                }
                for fut in as_completed(futures):
                    cand = futures[fut]
                    try:
                        row = fut.result()
                    except BudgetExceeded:
                        for pending in futures:
                            if pending is not fut:
                                pending.cancel()
                        stop_requests = getattr(ctx.llm, "set_timeout_provider", None)
                        if callable(stop_requests):
                            stop_requests(lambda: 0.0)
                        raise
                    except Exception as exc:
                        persisted_cells, convergence = converge_s4_cells(
                            ctx.root, ctx.cfg.name, round_no,
                            cand["candidate_id"], [])
                        failed_summary = summarize_candidate(persisted_cells)
                        failed_summary["harness_error"] = "%s: %s" % (
                            type(exc).__name__, exc)
                        failed_summary["s4_result_sources"] = convergence["sources"]
                        row = {"candidate": cand,
                               "audit": audits[cand["candidate_id"]],
                               "summary": failed_summary,
                               "conclusion": "候选（待验证）"}
                    record_candidate_row(cand, row)
        except BudgetExceeded as exc:
            # The executor has now joined already-running workers. Preserve
            # their finished results before the outer loop records the stop.
            for fut, cand in futures.items():
                cid = str(cand.get("candidate_id", ""))
                if cid in processed_ids or fut.cancelled() or not fut.done():
                    continue
                try:
                    record_candidate_row(cand, fut.result())
                except Exception:
                    continue
            partial_rows = []
            for row in rows:
                saved = dict(row)
                saved.pop("spec", None)
                partial_rows.append(saved)
            partial = {
                "status": "partial-llm-budget-exhausted",
                "reason": str(exc),
                "completed_candidate_ids": sorted(processed_ids),
                "pending_candidate_ids": sorted(
                    str(c.get("candidate_id")) for c in candidates
                    if str(c.get("candidate_id")) not in processed_ids),
                "rows": partial_rows, "excluded": excluded,
                "execution_budget": ctx.s4_execution_budget.snapshot(),
                "claim_status": "not-a-finding",
            }
            ctx.write_artifact(round_no, "S4", "partial-results.json", partial)
            ctx.write_artifact(round_no, "S4", "execution-budget.json",
                               partial["execution_budget"])
            raise
        serializable = []
        for r in rows:
            rr = dict(r)
            rr.pop("spec", None)   # POCSpec is not JSON-serializable
            serializable.append(rr)
        execution_budget = ctx.s4_execution_budget.snapshot()
        store.save_stage("S4", {
            "rows": serializable,
            "excluded": excluded,
            "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION,
            "execution_budget": execution_budget,
        })
        ctx.write_artifact(round_no, "S4", "execution-budget.json",
                           execution_budget)
        ctx.write_artifact(round_no, "S4", "authz-matrix.json", [
            {
                "candidate_id": r["candidate"]["candidate_id"],
                "authz_results": (r.get("summary") or {}).get("authz_results", []),
            }
            for r in rows if (r.get("summary") or {}).get("authz_results")
        ])
    lab_artifacts = [
        row.get("runtime_lab") for row in rows + excluded
        if isinstance(row.get("runtime_lab"), dict)
    ]
    ctx.write_artifact(
        round_no, "S4", "runtime-lab.json",
        merge_runtime_lab_artifacts(lab_artifacts, scope="autonomous-s4"))
    s4_summaries = {
        str(row.get("candidate", {}).get("candidate_id")): row.get("summary", {})
        for row in rows if isinstance(row, dict)
        and isinstance(row.get("candidate"), dict)
    }
    for item in excluded:
        cid = str(item.get("candidate_id", ""))
        if cid:
            s4_summaries.setdefault(cid, item.get("evidence", {}))
    ctx.write_artifact(
        round_no, "S4", "residual-closure.json",
        build_residual_closure_report(candidates, s4_summaries, round_no))

    budget_snapshot = (
        ctx.s4_execution_budget.snapshot()
        if getattr(ctx, "s4_execution_budget", None)
        else (s4.get("execution_budget", {}) if isinstance(s4, dict) else {}))
    if budget_snapshot:
        ctx.write_artifact(round_no, "S4", "execution-budget.json",
                           budget_snapshot)
    if budget_snapshot.get("round_exhausted"):
        progress = {
            "status": "stopped-at-s4-timebox",
            "execution_budget": budget_snapshot,
            "completed_candidates": [
                {"candidate_id": row.get("candidate", {}).get("candidate_id"),
                 "conclusion": row.get("conclusion"),
                 "execution_state": (row.get("summary") or {}).get(
                     "execution_state"),
                 "cells_ran": (row.get("summary") or {}).get("cells_ran", 0)}
                for row in rows
            ],
            "pending_candidates": [
                {"candidate_id": row.get("candidate_id"),
                 "conclusion": row.get("conclusion"),
                 "execution_state": (row.get("evidence") or {}).get(
                     "execution_state"),
                 "cells_ran": (row.get("evidence") or {}).get("cells_ran", 0)}
                for row in excluded
            ],
            "claim_status": "not-a-finding",
        }
        ctx.write_artifact(round_no, "S4", "round-timebox-report.json", progress)
        print("[round-%02d] S4 wall-clock limit reached; preserving artifacts and ending round" % round_no)
        return {"next_candidates": [], "status": "s4-timebox-exhausted",
                "execution_budget": budget_snapshot}

    report = timebox_report("S4", "S5")
    if report:
        return {**report, "next_candidates": []}
    deferred_index_candidates = try_deferred_inventory("S4")
    current_candidate_ids = {str(candidate.get("candidate_id"))
                             for candidate in candidates}
    deferred_index_candidates = [candidate for candidate in deferred_index_candidates
                                 if str(candidate.get("candidate_id"))
                                 not in current_candidate_ids]

    # ---- S5: Novelty (resumable) --------------------------------------
    s5 = store.load_stage("S5")
    if s5 and not force and not invalidate_after_s4:
        novelties = s5["novelty"]
        print("[round-%02d] S5 resume: %d novelty records loaded" % (round_no, len(novelties)))
    else:
        print("[round-%02d] S5: Novelty live scan + judgment..." % round_no)
        for row in rows:
            row["novelty_check"] = novelty_check(ctx, row)
        novelties = {r["candidate"]["candidate_id"]: r["novelty_check"] for r in rows}
        store.save_stage("S5", {"novelty": novelties})
    ctx.write_artifact(round_no, "S5", "novelty.json", novelties)
    report = timebox_report("S5", "S6")
    if report:
        return {**report, "next_candidates": []}

    # ---- S6: CVSS + G5 consistency gate (resumable) -------------------
    s6 = store.load_stage("S6")
    if s6 and not force and not invalidate_after_s4:
        print("[round-%02d] S6 resume: severity records loaded" % round_no)
    else:
        print("[round-%02d] S6: CVSS + severity..." % round_no)
        blocked_rows = []
        for row in rows:
            tier = row["candidate"].get("precondition_tier_hint", "single-feature")
            vector = row["candidate"].get("cvss_vector") or cvss_for_tier(tier)
            score, severity = base_score(vector)
            g5_ok, g5_reason = check_precondition_consistency(tier, vector)
            impact_ok, impact_reason = check_impact_consistency(
                row["candidate"], row.get("summary", {}), vector)
            if not impact_ok:
                g5_ok = False
                g5_reason = g5_reason + "; " + impact_reason
            row["cvss"] = {"vector": vector, "score": score,
                           "severity": severity, "tier": tier,
                           "g5": {"passed": g5_ok, "reason": g5_reason}}
            if not g5_ok:
                # Hard discipline: an inconsistent CVSS-precondition pairing
                # cannot confirm; withhold the verdict for human calibration.
                row["conclusion"] = "候选（待验证）"
                row["g5_blocked"] = True
                blocked_rows.append(row)
                excluded.append({
                    "candidate_id": row["candidate"]["candidate_id"],
                    "surface": row["candidate"].get("surface"),
                    "conclusion": "候选（待验证）G5: " + g5_reason,
                    "evidence": row.get("summary", {}),
                })
        if blocked_rows:
            rows = [r for r in rows if r not in blocked_rows]
        store.save_stage("S6", {"severity": {
            r["candidate"]["candidate_id"]: r["cvss"] for r in rows}})
    ctx.write_artifact(round_no, "S6", "severity.json",
                       {r["candidate"]["candidate_id"]: r["cvss"] for r in rows})
    report = timebox_report("S6", "S7")
    if report:
        return {**report, "next_candidates": []}

    # ---- S7: finding docs (resumable) ---------------------------------
    s7 = store.load_stage("S7")
    if s7 and not force and not invalidate_after_s4:
        print("[round-%02d] S7 resume: finding docs already written" % round_no)
    else:
        print("[round-%02d] S7: finding documents (local only)..." % round_no)
        reports_dir = ctx.root / "reports" / ctx.cfg.name / ("round-%02d" % round_no)
        reports_dir.mkdir(parents=True, exist_ok=True)
        prior_s7 = s7 if isinstance(s7, dict) else {}
        prior_docs = {str(name) for name in prior_s7.get("finding_docs", [])
                      if isinstance(name, str) and Path(name).name == name}
        written = []
        idx = 0
        for row in rows:
            if not is_confirmed_conclusion(row.get("conclusion")):
                continue
            idx += 1
            cand = row["candidate"]
            summary = row.get("summary") or {}
            finding = {
                "title": cand.get("surface", cand["candidate_id"]),
                "date": ctx.cfg.discovery_date,
                "status": "确认（机制级，受控验证）",
                "summary": cand.get("hypothesis", ""),
                "entrypoint": cand.get("entry", ""),
                "affected_versions": cand.get("affected_versions") or [
                    str(j.get("version")) for j in ctx.cfg.jars if j.get("version")],
                "fixed_versions": cand.get("fixed_versions", []),
                "source_to_sink": cand.get("source_to_sink", []),
                "code_location": cand.get("code_location", []),
                "scope": ctx.cfg.scope_constraints,
                "repro": _repro_text(row),
                "evidence": _evidence_text(row),
                "preconditions": cand.get("preconditions") or ["无"],
                "authorization_matrix": (row.get("summary") or {}).get("authz_results", []),
                "negative_results": cand.get("negative_results") or summary.get("validation_issues", []),
                "novelty": (row.get("novelty_check") or {}).get("novelty", {}),
                "cvss": row.get("cvss", {}),
                "impact": [
                    {"tier": "机制", "impact": cand.get("logic", "")},
                    {"tier": "端到端（条件部分）", "impact": "受控 harness 验证；未做武器化。"},
                ],
                "boundary": "回环/受控 JVM；PoC 由 LLM 生成后经编译与实跑验证。",
                "timeline": [
                    {"date": ctx.cfg.discovery_date, "event": "自治轮次验证（修复公开前不披露）"},
                ],
            }
            fname = ("finding-%02d-%s.md" % (idx, cand["candidate_id"])
                     if ctx.cfg.output_lang == "en"
                     else "挖洞-发现-%02d-%s.md" % (idx, cand["candidate_id"]))
            (reports_dir / fname).write_text(
                render_finding_md(finding, lang=ctx.cfg.output_lang), encoding="utf-8")
            written.append(fname)
        stale_docs = sorted(prior_docs - set(written))
        stale_marker = ("> 状态更新：该报告来自旧版 S4 证据策略，本轮未能重新确认。"
                        "请以本轮 S8 Ledger 为准。\n\n")
        for name in stale_docs:
            path = reports_dir / name
            if path.is_file():
                old = path.read_text(encoding="utf-8", errors="replace")
                if stale_marker not in old:
                    path.write_text(stale_marker + old, encoding="utf-8")
        if stale_docs:
            ctx.write_artifact(round_no, "S7", "superseded-finding-docs.json", {
                "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION,
                "files": stale_docs,
                "reason": "S4-S8 checkpoints were recomputed after the evidence-policy change",
            })
        store.save_stage("S7", {
            "finding_docs": written,
            "superseded_docs": stale_docs,
            "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION,
        })

    report = timebox_report("S7", "S8")
    if report:
        return {**report, "next_candidates": []}

    # ---- S8: ledger (resumable) ---------------------------------------
    # Build the research-memory delta before the resumable ledger branch.  On
    # resume this remains idempotent, while an interrupted S8 still leaves the
    # runtime feedback available to the next scheduling round.
    runtime_lab = {}
    runtime_lab_path = (ctx.root / "state" / ctx.cfg.name
                        / ("round-%02d" % round_no) / "S4" / "runtime-lab.json")
    if runtime_lab_path.exists():
        try:
            loaded_lab = json.loads(runtime_lab_path.read_text(encoding="utf-8"))
            if isinstance(loaded_lab, dict):
                runtime_lab = loaded_lab
        except (OSError, ValueError, TypeError):
            runtime_lab = {}
    prior_consistency_actions = load_research_consistency_actions(
        ctx.root, ctx.cfg.name)
    research_consistency_rechecks = build_research_consistency_rechecks(
        runtime_lab, prior_consistency_actions)
    research_consistency_rechecks_file = write_research_consistency_rechecks(
        ctx.root, ctx.cfg.name, research_consistency_rechecks)
    memory_summaries = {
        str(row.get("candidate", {}).get("candidate_id")): row.get("summary", {})
        for row in rows if isinstance(row, dict) and isinstance(row.get("candidate"), dict)
    }
    memory_conclusions = {
        str(row.get("candidate", {}).get("candidate_id")): row.get("conclusion", "")
        for row in rows if isinstance(row, dict) and isinstance(row.get("candidate"), dict)
    }
    for item in excluded:
        cid = str(item.get("candidate_id", ""))
        if cid:
            memory_summaries.setdefault(cid, item.get("evidence", {}))
            memory_conclusions.setdefault(cid, item.get("conclusion", ""))
    from ..evaluation.replay_calibration import (
        build_replay_calibration, load_replay_calibration,
        write_replay_calibration,
    )
    from ..evaluation.replay_cohort import (
        select_effective_replay_calibration,
    )
    from ..evaluation.replay_pack import (
        build_replay_pack, write_replay_pack,
    )
    prior_replay_calibration = load_replay_calibration(
        ctx.root, ctx.cfg.name)
    replay_cohort = ctx.replay_cohort_calibration()
    effective_replay_calibration = select_effective_replay_calibration(
        prior_replay_calibration, replay_cohort)
    memory_delta = build_round_memory(
        candidates, memory_summaries, memory_conclusions, runtime_lab, round_no,
        target_type=ctx.cfg.target_type)
    memory = merge_research_memory(
        load_research_memory(ctx.root, ctx.cfg.name), memory_delta)
    memory_file = write_research_memory(ctx.root, ctx.cfg.name, memory)
    review_feedback = load_review_feedback(ctx.root, ctx.cfg.name)
    research_consistency = build_research_consistency(memory)
    research_consistency_file = write_research_consistency(
        ctx.root, ctx.cfg.name, research_consistency)
    research_consistency_actions = build_research_consistency_actions(
        research_consistency)
    research_consistency_actions_file = write_research_consistency_actions(
        ctx.root, ctx.cfg.name, research_consistency_actions)
    portfolio = build_research_portfolio(
        memory, review_feedback, ctx.benchmark_feedback(),
        research_consistency, research_consistency_actions,
        research_consistency_rechecks)
    portfolio_file = write_research_portfolio(ctx.root, ctx.cfg.name, portfolio)
    strategy = load_research_strategy(ctx.root, ctx.cfg.name)
    if not strategy:
        s2_strategy_path = (ctx.root / "state" / ctx.cfg.name
                            / ("round-%02d" % round_no) / "S2"
                            / "research-strategy.json")
        try:
            loaded_strategy = json.loads(
                s2_strategy_path.read_text(encoding="utf-8"))
            strategy = loaded_strategy if isinstance(loaded_strategy, dict) else {}
        except (OSError, ValueError, TypeError):
            strategy = {}
    strategy_feedback = {}
    research_guidance = {}
    strategy_file = None
    guidance_file = None
    if strategy:
        strategy, strategy_feedback = apply_strategy_observations(
            strategy, candidates, memory_summaries, round_no)
        strategy, research_guidance = apply_research_guidance(
            strategy, portfolio, review_feedback, round_no,
            replay_calibration=effective_replay_calibration)
        if strategy:
            strategy_file = write_research_strategy(
                ctx.root, ctx.cfg.name, strategy)
            guidance_file = write_research_guidance(
                ctx.root, ctx.cfg.name, research_guidance)
            ctx.write_artifact(round_no, "S8", "research-strategy.json", strategy)
            ctx.write_artifact(
                round_no, "S8", "research-strategy-feedback.json",
                strategy_feedback)
            ctx.write_artifact(
                round_no, "S8", "research-guidance.json", research_guidance)
    # Measure the agenda that drove this round before replacing it with the
    # next queue.  This is bounded scheduling feedback, not a security verdict.
    prior_research_agenda = load_research_agenda(ctx.root, ctx.cfg.name)
    prior_agenda_outcomes = load_research_agenda_outcomes(
        ctx.root, ctx.cfg.name)
    prior_research_budget = load_research_budget(ctx.root, ctx.cfg.name)
    schedule_snapshot = load_schedule_snapshot(
        ctx.root, ctx.cfg.name, round_no)
    verification_matrix = {}
    verification_path = (ctx.root / "state" / ctx.cfg.name
                         / ("round-%02d" % round_no) / "S4"
                         / "verification-matrix.json")
    try:
        loaded_verification = json.loads(
            verification_path.read_text(encoding="utf-8"))
        verification_matrix = (loaded_verification
                               if isinstance(loaded_verification, dict) else {})
    except (OSError, ValueError, TypeError):
        verification_matrix = {}
    research_agenda_outcomes = build_research_agenda_outcomes(
        prior_research_agenda, schedule_snapshot, verification_matrix,
        runtime_lab, strategy_feedback,
        prior_outcomes=prior_agenda_outcomes,
        target=ctx.cfg.name, round_no=round_no)
    research_agenda_outcomes_file = write_research_agenda_outcomes(
        ctx.root, ctx.cfg.name, research_agenda_outcomes)
    ctx.write_artifact(round_no, "S8", "research-agenda-outcomes.json",
                       research_agenda_outcomes)
    research_budget = build_research_budget(
        prior_research_agenda, research_agenda_outcomes,
        prior_budget=prior_research_budget, target=ctx.cfg.name,
        round_no=round_no,
        slots=((prior_research_agenda.get("policy") or {}).get(
            "slots", 0) if prior_research_agenda else 0) or 8)
    research_budget_file = write_research_budget(
        ctx.root, ctx.cfg.name, research_budget)
    ctx.write_artifact(round_no, "S8", "research-budget.json", research_budget)
    research_agenda = build_research_agenda(
        strategy, portfolio, target=ctx.cfg.name, round_no=round_no,
        outcomes=research_agenda_outcomes, budget_policy=research_budget)
    research_agenda_file = write_research_agenda(
        ctx.root, ctx.cfg.name, research_agenda)
    ctx.write_artifact(round_no, "S8", "research-agenda.json", research_agenda)
    replay_calibration = build_replay_calibration(ctx.root, ctx.cfg.name)
    replay_calibration_file = write_replay_calibration(
        ctx.root, ctx.cfg.name, replay_calibration)
    ctx.write_artifact(round_no, "S8", "research-replay-calibration.json",
                       replay_calibration)
    if replay_cohort:
        ctx.write_artifact(round_no, "S8", "research-replay-cohort.json",
                           replay_cohort)
    ctx.write_artifact(round_no, "S8", "research-memory.json", memory_delta)
    ctx.write_artifact(round_no, "S8", "research-memory-summary.json", memory["summary"])
    ctx.write_artifact(round_no, "S8", "review-feedback.json", review_feedback)
    ctx.write_artifact(
        round_no, "S8", "research-consistency.json", research_consistency)
    ctx.write_artifact(
        round_no, "S8", "research-consistency-actions.json",
        research_consistency_actions)
    ctx.write_artifact(
        round_no, "S8", "research-consistency-rechecks.json",
        research_consistency_rechecks)
    ctx.write_artifact(round_no, "S8", "research-portfolio.json", portfolio)
    replay_pack = build_replay_pack(ctx.root, ctx.cfg.name)
    replay_pack_file = write_replay_pack(
        ctx.root, ctx.cfg.name, replay_pack)
    ctx.write_artifact(round_no, "S8", "research-replay-pack.json", replay_pack)
    research_memory_info = {
        "artifact": str(memory_file.relative_to(ctx.root.resolve())),
        "round_entries": len(memory_delta.get("entries", [])),
        "total_entries": len(memory.get("entries", [])),
        "states": memory.get("summary", {}).get("states", {}),
        "claim_status": "not-a-finding",
    }
    review_feedback_info = {
        "artifact": "state/%s/review-feedback.json" % ctx.cfg.name,
        "count": review_feedback.get("summary", {}).get("feedback_count", 0),
        "statuses": review_feedback.get("summary", {}).get("statuses", {}),
        "claim_status": "not-a-finding",
    }
    research_portfolio_info = {
        "artifact": str(portfolio_file.relative_to(ctx.root.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-portfolio.json"
                          % (ctx.cfg.name, round_no),
        "mechanism_count": portfolio.get("summary", {}).get("mechanism_count", 0),
        "unresolved_mechanisms": portfolio.get("summary", {}).get(
            "unresolved_mechanisms", 0),
        "next_probe_count": len(portfolio.get("next_probes") or []),
        "surface_lane_coverage": (portfolio.get("surface_lane_coverage") or {}
                                  ).get("summary", {}),
        "claim_status": "not-a-finding",
    }
    research_consistency_info = {
        "artifact": str(research_consistency_file.relative_to(ctx.root.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-consistency.json"
                          % (ctx.cfg.name, round_no),
        "status_counts": (research_consistency.get("summary") or {}
                           ).get("statuses", {}),
        "conflicted_entries": (research_consistency.get("summary") or {}
                               ).get("conflicted_entries", 0),
        "unstable_entries": (research_consistency.get("summary") or {}
                             ).get("unstable_entries", 0),
        "claim_status": "not-a-finding",
    }
    research_consistency_actions_info = {
        "artifact": str(research_consistency_actions_file.relative_to(
            ctx.root.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-consistency-actions.json"
                          % (ctx.cfg.name, round_no),
        "action_count": (research_consistency_actions.get("summary") or {}
                          ).get("action_count", 0),
        "action_counts": (research_consistency_actions.get("summary") or {}
                           ).get("action_counts", {}),
        "claim_status": "not-a-finding",
    }
    research_consistency_rechecks_info = {
        "artifact": str(research_consistency_rechecks_file.relative_to(
            ctx.root.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-consistency-rechecks.json"
                          % (ctx.cfg.name, round_no),
        "status_counts": {
            key: value for key, value in
            (research_consistency_rechecks.get("summary") or {}).items()
            if key in {"observed", "partial", "environment_gap",
                       "not_executed"}
        },
        "claim_status": "not-a-finding",
    }
    research_agenda_info = {
        "artifact": str(research_agenda_file.relative_to(
            ctx.root.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-agenda.json"
                          % (ctx.cfg.name, round_no),
        "selected_count": (research_agenda.get("summary") or {}).get(
            "selected_count", 0),
        "deferred_count": (research_agenda.get("summary") or {}).get(
            "deferred_count", 0),
        "surface_counts": (research_agenda.get("summary") or {}).get(
            "surface_counts", {}),
        "claim_status": "not-a-finding",
    }
    research_agenda_outcomes_info = {
        "artifact": str(research_agenda_outcomes_file.relative_to(
            ctx.root.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-agenda-outcomes.json"
                          % (ctx.cfg.name, round_no),
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
    research_budget_info = {
        "artifact": str(research_budget_file.relative_to(
            ctx.root.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-budget.json"
                          % (ctx.cfg.name, round_no),
        "surface_count": (research_budget.get("summary") or {}).get(
            "surface_count", 0),
        "recommendation_counts": (research_budget.get("summary") or {}
                                   ).get("recommendation_counts", {}),
        "claim_status": "not-a-finding",
    }
    research_replay_calibration_info = {
        "artifact": str(replay_calibration_file.relative_to(ctx.root.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-replay-calibration.json"
                          % (ctx.cfg.name, round_no),
        "status": replay_calibration.get("status", "no-data"),
        "replayed_guidance_items": replay_calibration.get(
            "metrics", {}).get("replayed_guidance_items", 0),
        "replacement_hit_rate": replay_calibration.get(
            "metrics", {}).get("replacement_hit_rate"),
        "claim_status": "not-a-finding",
    }
    research_replay_pack_info = {
        "artifact": str(replay_pack_file.relative_to(ctx.root.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-replay-pack.json"
                          % (ctx.cfg.name, round_no),
        "status": (replay_pack.get("provenance") or {}).get(
            "status", "not-executed"),
        "valid_for_cohort": (replay_pack.get("provenance") or {}).get(
            "valid_for_cohort", False),
        "pack_digest": replay_pack.get("pack_digest", ""),
        "claim_status": "not-a-finding",
    }
    research_replay_cohort_info = {
        "claim_status": "not-a-finding",
    }
    if replay_cohort:
        research_replay_cohort_info = {
            "artifact": "configured:replay_cohort_calibration_path",
            "round_artifact": "state/%s/round-%02d/S8/research-replay-cohort.json"
                              % (ctx.cfg.name, round_no),
            "status": replay_cohort.get("status", "no-data"),
            "eligible_projects": replay_cohort.get("metrics", {}).get(
                "eligible_projects", 0),
            "policy_threshold": replay_cohort.get("policy", {}).get(
                "replacement_zero_gain_rounds", 1),
            "claim_status": "not-a-finding",
        }
    research_strategy_info = {
        "claim_status": "not-a-finding",
    }
    if strategy_file:
        research_strategy_info = {
            "artifact": str(strategy_file.relative_to(ctx.root.resolve())),
            "round_artifact": "state/%s/round-%02d/S8/research-strategy.json"
                              % (ctx.cfg.name, round_no),
            "feedback_artifact": "state/%s/round-%02d/S8/research-strategy-feedback.json"
                                % (ctx.cfg.name, round_no),
            "guidance_artifact": (str(guidance_file.relative_to(
                ctx.root.resolve())) if guidance_file else
                "state/%s/coverage/research-guidance.json" % ctx.cfg.name),
            "guidance_round_artifact": "state/%s/round-%02d/S8/research-guidance.json"
                                      % (ctx.cfg.name, round_no),
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
    s8 = store.load_stage("S8")
    if s8 and not force and not invalidate_after_s4:
        print("[round-%02d] S8 resume: ledger already written" % round_no)
    else:
        print("[round-%02d] S8: ledger..." % round_no)
        ledger_rows = [{
            "candidate_id": r["candidate"]["candidate_id"],
            "surface": r["candidate"].get("surface"),
            "conclusion": r.get("conclusion", "确认"),
            "status": conclusion_status(r.get("conclusion", "确认")),
            "evidence": _evidence_lines(r),
            "precondition_tier": r["candidate"].get("precondition_tier_hint"),
            "code_location": r.get("audit", {}).get("code_location", []),
            "novelty": r.get("novelty_check", {}).get("novelty", {}),
            "cvss": r.get("cvss", {}),
        } for r in rows]
        summary = {
            "header_note": "自治轮次：候选/PoC/审计由 LLM 生成，矩阵与结论由运行时观测推导",
            "metrics": {
                "候选数": len(candidates),
                "确认数": len(rows),
                "排除数": len(excluded),
                "LLM 调用": ctx.llm.usage.calls,
                "LLM tokens": ctx.llm.usage.total_tokens,
            },
            "next_round": [],
            "research_memory": research_memory_info,
            "research_consistency": research_consistency_info,
            "research_consistency_actions": research_consistency_actions_info,
            "research_consistency_rechecks": research_consistency_rechecks_info,
            "research_agenda": research_agenda_info,
            "research_agenda_outcomes": research_agenda_outcomes_info,
            "research_budget": research_budget_info,
            "review_feedback": review_feedback_info,
            "research_portfolio": research_portfolio_info,
            "research_replay_calibration": research_replay_calibration_info,
            "research_replay_pack": research_replay_pack_info,
            "research_replay_cohort": research_replay_cohort_info,
            "research_strategy": research_strategy_info,
        }
        by_candidate_memory = {
            str(entry.get("candidate_id")): entry
            for entry in memory_delta.get("entries", [])
        }
        for row in ledger_rows:
            entry = by_candidate_memory.get(str(row.get("candidate_id")))
            if entry:
                row["research"] = {
                    "research_key": entry.get("research_key", ""),
                    "states": sorted({str(event.get("state")) for event in
                                       entry.get("events", []) if event.get("state")}),
                    "claim_status": "not-a-finding",
                }
        write_round_artifacts(ctx.root, ctx.cfg.name, round_no, ledger_rows, excluded,
                              summary, lang=ctx.cfg.output_lang)
        ctx.write_artifact(round_no, "S8", "llm-usage.json", ctx.llm.usage.to_dict())
        store.save_stage("S8", {"ledger_rows": len(ledger_rows), "excluded": len(excluded),
                                "research_memory": research_memory_info,
                                "research_consistency": research_consistency_info,
                                "research_consistency_actions":
                                research_consistency_actions_info,
                                "research_consistency_rechecks":
                                research_consistency_rechecks_info,
                                "research_agenda": research_agenda_info,
                                "research_agenda_outcomes":
                                research_agenda_outcomes_info,
                                "research_budget": research_budget_info,
                                "review_feedback": review_feedback_info,
                                "research_portfolio": research_portfolio_info,
                                "research_replay_calibration":
                                research_replay_calibration_info,
                                "research_replay_pack":
                                research_replay_pack_info,
                                "research_replay_cohort":
                                research_replay_cohort_info,
                                "research_strategy": research_strategy_info})
    print("[round-%02d] done: 确认=%d 排除=%d" % (round_no, len(rows), len(excluded)))
    report = timebox_report("S8", "next-round-candidate-generation")
    if report:
        return {**report, "next_candidates": []}
    final_budget = round_budget_snapshot(ctx._round_budget_record)
    ctx.write_artifact(round_no, "S0", "execution-budget-status.json", final_budget)
    next_candidates = (
        _propose_next(ctx, candidates, rows)
        if final_budget["remaining_seconds"] >= 120 else [])
    next_ids = {str(candidate.get("candidate_id")) for candidate in next_candidates}
    for candidate in deferred_index_candidates:
        candidate_id = str(candidate.get("candidate_id", ""))
        if candidate_id and candidate_id not in next_ids:
            next_candidates.append(candidate)
            next_ids.add(candidate_id)
    if deferred_index_candidates:
        ctx.write_artifact(round_no, "S4", "deferred-candidates-for-next-round.json",
                           deferred_index_candidates)
    return {"next_candidates": next_candidates,
            "audit_budget": final_budget,
            "deferred_index_candidate_count": len(deferred_index_candidates),
            "research_memory": research_memory_info,
            "research_consistency": research_consistency_info,
            "research_consistency_actions": research_consistency_actions_info,
            "research_consistency_rechecks": research_consistency_rechecks_info,
            "research_agenda": research_agenda_info,
            "research_agenda_outcomes": research_agenda_outcomes_info,
            "research_budget": research_budget_info,
            "review_feedback": review_feedback_info,
            "research_portfolio": research_portfolio_info,
            "research_replay_calibration": research_replay_calibration_info,
            "research_replay_pack": research_replay_pack_info,
            "research_replay_cohort": research_replay_cohort_info,
            "research_strategy": research_strategy_info}


def _repro_text(row: Dict[str, Any]) -> str:
    cand = row["candidate"]
    spec = row.get("spec")
    if spec is None:
        return "PoC 源码见 poc/%s/round-NN/src/；复现命令见 cells.json" % cand["candidate_id"]
    return "javac -cp <jar> %s.java && java -cp <jar>:out %s" % (
        spec.class_name, spec.class_name)


def _evidence_text(row: Dict[str, Any]) -> str:
    lines = _evidence_lines(row)
    return "\n".join(lines) if lines else "cells.json 见 state/<target>/round-NN/S4/matrix-runs/"


def _evidence_lines(row: Dict[str, Any]) -> List[str]:
    s = row.get("summary", {})
    lines = []
    if s.get("harness_error"):
        lines.append("HARNESS_ERROR=" + str(s["harness_error"]))
    if s.get("compile_error"):
        lines.append("COMPILE_ERROR=" + str(s["compile_error"]))
    if s.get("execution_state"):
        lines.append("S4_EXECUTION_STATE=" + str(s["execution_state"]))
    if s.get("s4_result_sources"):
        lines.append("S4_RESULT_SOURCES=" + ",".join(s["s4_result_sources"]))
    for e in s.get("errors", []):
        lines.append("%s SafeMode=%s %s -> ERROR %s"
                     % (e.get("version"), e.get("safe"), e.get("precondition"), e.get("error")))
    for g in s.get("gate_blocked", []):
        lines.append("%s SafeMode=%s %s -> GATE_BLOCKED %s"
                     % (g.get("version"), g.get("safe"), g.get("precondition"), g.get("class")))
    for n in s.get("network_side_effects", []):
        lines.append("NETWORK %s" % n)
    for lk in s.get("leaked", []):
        lines.append("%s SafeMode=%s %s -> LEAKED %s"
                     % (lk.get("version"), lk.get("safe"), lk.get("precondition"),
                        str(lk.get("leaked"))[:120]))
    for c in s.get("safe_equivalent", []):
        lines.append("%s SafeMode=%s %s -> SAFE_EQUIVALENT %s %s" % (
            c.get("version"), c.get("safe"), c.get("precondition"),
            c.get("kind"), c.get("detail", "")))
    for e in s.get("effect_evidence", []):
        lines.append("%s SafeMode=%s %s -> EFFECT_KIND=%s EFFECT=%s" % (
            e.get("version"), e.get("safe"), e.get("precondition"),
            e.get("kind"), e.get("detail", "")))
    for a in s.get("availability_proof", []):
        lines.append("%s SafeMode=%s %s -> AVAILABILITY_PROOF=concurrency:%s service_unavailable:%s" % (
            a.get("version"), a.get("safe"), a.get("precondition"),
            a.get("concurrency"), a.get("service_unavailable")))
    for x in s.get("experiment_evidence", [])[:4]:
        lines.append("%s SafeMode=%s %s -> EXPERIMENT sequence=%s sequence_status=%s "
                     "declared_concurrency=%s probe=%s STEP=%s STATE=%s STEP_EVIDENCE=%s" % (
                         x.get("version"), x.get("safe"), x.get("precondition"),
                         ",".join(str(step) for step in x.get("declared_sequence", [])) or "-",
                         x.get("sequence_status", "unknown"),
                         x.get("declared_concurrency", 1),
                         x.get("declared_availability_probe", False),
                         "|".join(str(step) for step in x.get("step_trace", [])[:8]) or "-",
                         "|".join(str(state) for state in x.get("state_trace", [])[:8]) or "-",
                         "|".join(str(ev) for ev in x.get("step_evidence", [])[:4]) or "-"))
    for a in s.get("authz_results", [])[:8]:
        az = a.get("authz", {})
        lines.append("%s SafeMode=%s %s -> AUTHZ_CASE=%s principal=%s role=%s tenant=%s object=%s assertion=%s boundary_violation=%s" % (
            a.get("version"), a.get("safe"), a.get("precondition"),
            az.get("case_id", "?"), az.get("principal", "?"), az.get("role", "?"),
            az.get("tenant_id", "?"), az.get("object_id", "?"),
            a.get("status", "?"), a.get("boundary_violation", False)))
    for residual in s.get("residual_falsifiers", [])[:8]:
        lines.append("RESIDUAL=%s status=%s falsifier=%s execution=%s effect=%s" % (
            residual.get("residual_id", "?"), residual.get("status", ""),
            residual.get("falsifier_code", ""),
            residual.get("execution_state", ""),
            residual.get("effect_observed", False)))
    for issue in s.get("validation_issues", []):
        lines.append("VALIDATION_ISSUE=" + str(issue))
    if s.get("cells_ran") is not None:
        lines.append("cells_ran=%d" % s["cells_ran"])
    return lines


def _propose_next(ctx: AutoCtx, candidates: List[Dict[str, Any]],
                  rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Iteration: LLM proposes next-round candidates from runtime observations."""
    if not rows:
        return []
    prev = ", ".join(c["candidate_id"] for c in candidates)
    observations = "\n".join(line for r in rows for line in _evidence_lines(r)) or "无运行时观测"
    user = (
        "上一轮候选：%s\n运行时观测：\n%s\n\n"
        "基于这些观测，提出下一轮值得验证的新候选（必须不同于上一轮，且更有攻击价值）。"
        "无新候选则返回 {\"candidates\": []}。字段同上轮。"
        % (prev, observations)
    )
    try:
        data = ctx.llm.ask_json(_sec_prompt(ctx), user, max_tokens=3000)
        return (data.get("candidates") or [])[: ctx.max_candidates]
    except BudgetExceeded:
        return []
    except ValueError:
        return []


def run_loop(ctx: AutoCtx, start_round: int) -> List[Dict[str, Any]]:
    from ..analysis.languages import SourceScanTimeout

    rounds_done = []
    for r in range(start_round, start_round + ctx.max_rounds):
        ctx._active_audit_guard_registered = False
        if ctx.stop_file.exists():
            print("STOP flag found; stopping")
            break
        round_status = "failed"
        try:
            result = run_round(ctx, r)
            round_status = str(result.get("status") or "completed")
        except BudgetExceeded as exc:
            round_status = "budget-exhausted"
            record = getattr(ctx, "_round_budget_record", None)
            budget_status: Dict[str, Any] = {}
            if isinstance(record, dict):
                try:
                    from ..analysis.audit_budget import round_budget_snapshot
                    budget_status = round_budget_snapshot(record)
                    ctx.write_artifact(
                        r, "S0", "execution-budget-status.json", budget_status)
                except (OSError, TypeError, ValueError) as status_exc:
                    budget_status = {"status": "unavailable",
                                     "error": str(status_exc)}
            try:
                from ..memory.state import CheckpointStore
                completed_stages = CheckpointStore(
                    ctx.root, ctx.cfg.name, r).completed_stages()
            except (OSError, TypeError, ValueError):
                completed_stages = []
            usage = ctx.llm.usage.to_dict()
            status = ("stopped-at-round-deadline"
                      if budget_status.get("expired")
                      else "stopped-llm-budget-exhausted")
            progress = {
                "status": status, "error": str(exc),
                "completed_stages": completed_stages,
                "audit_budget": budget_status,
                "llm_usage": usage,
                "claim_status": "not-a-finding",
            }
            ctx.write_artifact(r, "S0", "round-stop-report.json", progress)
            ctx.write_artifact(r, "S0", "llm-usage.json", usage)
            print("budget exhausted; saved S0 progress for round %02d (%s)" % (
                r, status))
            rounds_done.append({"round": r, **progress})
            break
        except SourceScanTimeout as exc:
            round_status = "source-scan-incomplete"
            progress = {
                "status": "stopped-source-scan-incomplete",
                "error": str(exc), "progress": exc.progress,
                "claim_status": "not-a-finding",
            }
            ctx.write_artifact(r, "S0", "source-scan-timeout.json", progress)
            print("source scan timed out; saved progress and stopped this round")
            rounds_done.append({"round": r, **progress})
            break
        except Exception as exc:
            round_status = "failed"
            record = getattr(ctx, "_round_budget_record", None)
            budget_status: Dict[str, Any] = {}
            if isinstance(record, dict):
                try:
                    from ..analysis.audit_budget import round_budget_snapshot
                    budget_status = round_budget_snapshot(record)
                    ctx.write_artifact(
                        r, "S0", "execution-budget-status.json", budget_status)
                except Exception as status_exc:
                    budget_status = {"status": "unavailable",
                                     "error": str(status_exc)[:1000]}
            try:
                from ..memory.state import CheckpointStore
                completed_stages = CheckpointStore(
                    ctx.root, ctx.cfg.name, r).completed_stages()
            except Exception:
                completed_stages = []
            try:
                usage = ctx.llm.usage.to_dict()
            except Exception:
                usage = {}
            progress = {
                "status": "failed-unhandled-error",
                "error_type": type(exc).__name__, "error": str(exc)[:2000],
                "completed_stages": completed_stages,
                "last_completed_stage": (completed_stages[-1]
                                          if completed_stages else None),
                "audit_budget": budget_status,
                "llm_usage": usage,
                "claim_status": "not-a-finding",
            }
            try:
                ctx.write_artifact(r, "S0", "round-error-report.json", progress)
                if usage:
                    ctx.write_artifact(r, "S0", "llm-usage.json", usage)
            except Exception as write_exc:
                print("could not persist round failure report: %s" % write_exc)
            print("round %02d failed with %s: %s" % (
                r, type(exc).__name__, str(exc)[:1000]))
            rounds_done.append({"round": r, **progress})
            break
        finally:
            ctx._candidate_source_snippet_cache.finish_round(round_status, r)
            if getattr(ctx, "_active_audit_guard_registered", False):
                try:
                    from ..analysis.audit_budget import round_budget_snapshot
                    from ..analysis.audit_guard import release_active_audit
                    record = getattr(ctx, "_round_budget_record", None)
                    if record is None:
                        raise ValueError("round budget record is unavailable")
                    if round_budget_snapshot(record)["expired"]:
                        print("[round-%02d] expired source root remains guarded; "
                              "release it after writing the progress report" % r)
                    else:
                        source_root, _source_dirs = _target_source_scope(ctx)
                        release_active_audit(
                            ctx.root, ctx.cfg.name, r, root=source_root)
                except (OSError, TypeError, ValueError) as exc:
                    print("[round-%02d] could not release active-audit guard: %s" % (
                        r, exc))
        rounds_done.append(result)
        if not result.get("next_candidates"):
            print("no new candidates; loop stops")
            break
        # Baseline #9: hand the next-round candidates to the following S2.
        ctx.carryover = result["next_candidates"]
    return rounds_done


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Autonomous 0day-hunting agent")
    ap.add_argument("--name", required=True, help="target name (dir under targets/)")
    ap.add_argument("--round", type=int, default=1)
    ap.add_argument("--target-dir", help="new target source/jar dir (auto-prepare)")
    ap.add_argument("--config", help="existing config path (relative to workspace)")
    ap.add_argument("--max-calls", type=int, default=40, help="LLM call budget")
    ap.add_argument("--max-tokens", type=int, default=300_000)
    ap.add_argument("--max-candidates", type=int, default=4)
    ap.add_argument("--max-rounds", type=int, default=3)
    ap.add_argument("--model", default=None)
    ap.add_argument("--reasoning-effort", default=None,
                    help="LLM reasoning effort (low/medium/high)")
    ap.add_argument("--lang", default=None, choices=["zh", "en"],
                    help="ledger/finding output language (default: config output_lang)")
    ap.add_argument("--offline", action="store_true", help="disable live GitHub API")
    ap.add_argument("--force", action="store_true",
                    help="rebuild stage checkpoints and retry a failed coverage scope once")
    ap.add_argument("--fuzz-budget", type=int, default=0,
                    help="directed fuzz inputs per round, merged into S2 candidates (plan 2.1)")
    ap.add_argument("--fuzz-seed", type=int, default=None)
    ap.add_argument("--fuzz-force", action="store_true",
                    help="re-run fuzz discovery even if a report exists")
    ap.add_argument("--fuzz-skip-minimize", action="store_true")
    args = ap.parse_args(argv)

    if args.config:
        cfg = TargetConfig.load(ROOT / args.config)
    elif args.target_dir:
        from ..analysis.audit_budget import (
            DEFAULT_BUDGET_SECONDS, budget_path, start_round_budget,
        )
        try:
            prep_budget = start_round_budget(
                ROOT, args.name, args.round, DEFAULT_BUDGET_SECONDS)
        except (OSError, TypeError, ValueError) as exc:
            print("refusing target preparation without a valid round budget: %s" % exc)
            return 2
        try:
            cfg = prepare_target(
                ROOT, args.name, Path(args.target_dir), prep_budget)
        except TargetPreparationTimeout as exc:
            status = {
                "status": "target-preparation-incomplete",
                "error": str(exc), "progress": exc.progress,
                "claim_status": "not-a-finding",
            }
            status_path = (budget_path(ROOT, args.name, args.round).parent /
                           "target-preparation-status.json")
            status_path.parent.mkdir(parents=True, exist_ok=True)
            status_path.write_text(
                json.dumps(status, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8")
            print("target preparation timed out; saved progress to %s" % status_path)
            return 2
    else:
        ap.error("need --config or --target-dir")

    llm = LLMClient(model=args.model, max_calls=args.max_calls,
                    max_tokens_total=args.max_tokens,
                    reasoning_effort=args.reasoning_effort)
    if args.lang:
        cfg.output_lang = args.lang
    needs_api_hint = not cfg.api_hint
    ctx = AutoCtx(ROOT, cfg, llm, offline=args.offline,
                  max_candidates=args.max_candidates, max_rounds=args.max_rounds,
                  fuzz_budget=args.fuzz_budget, fuzz_seed=args.fuzz_seed,
                  fuzz_force=args.fuzz_force,
                  fuzz_skip_minimize=args.fuzz_skip_minimize,
                  force=args.force)
    rounds_done = run_loop(ctx, args.round)
    if needs_api_hint and cfg.api_hint and args.config:
        cfg_path = ROOT / args.config
        if cfg_path.exists():
            try:
                d = json.loads(cfg_path.read_text(encoding="utf-8"))
                d["api_hint"] = cfg.api_hint
                cfg_path.write_text(json.dumps(d, indent=2, ensure_ascii=False),
                                    encoding="utf-8")
            except (OSError, UnicodeError, ValueError, TypeError) as exc:
                print("[S1.5] could not persist learned api_hint: %s" % exc)
    print("\n==== autonomous round summary ====")
    print("rounds done: %d" % len(rounds_done))
    print("llm usage: %s" % json.dumps(llm.usage.to_dict(), ensure_ascii=False))
    incomplete_statuses = {
        "invalid-round-budget", "invalid-round-guard",
        "stopped-at-round-deadline", "stopped-llm-budget-exhausted",
        "stopped-source-scan-incomplete", "s4-timebox-exhausted",
        "failed-unhandled-error",
    }
    incomplete = any(str(result.get("status") or "") in incomplete_statuses
                     for result in rounds_done)
    if incomplete:
        print("audit ended incomplete; see the round S0/S4 stop report")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

