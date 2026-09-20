"""S1->S8 stage implementations (deterministic machinery + LLM judgment seams)."""

from __future__ import annotations

import json
import dataclasses
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..memory.ledger import render_finding_md, write_round_artifacts
from ..memory.state import CheckpointStore
from ..analysis.languages import ALL_SUFFIXES
from ..sandbox.approval import ApprovalGate
from ..sandbox.runner import CommandRunner
from ..tools import search as srch
from ..tools.build import (JavaMatrixRunner, MatrixCell, POCSpec,
                           ShellMatrixRunner, ShellPOCSpec, summarize_candidate,
                           converge_s4_cells)
from ..tools.authz import normalize_authz_case, normalize_authz_cases
from ..tools.conclusion import conclusion_status, derive_conclusion, is_confirmed_conclusion
from ..tools.cvss import base_score, check_impact_consistency
from ..tools.source_evidence import (DANGER_PATTERNS, build_source_sink_graph,
                                     grep_hits, match_source_sink_paths)
from ..tools.patch_variants import analyze_patch_history, fix_completeness_candidate
from ..tools.project_profile import build_project_profile
from ..tools.experiment_planner import plan_candidate_experiments
from ..tools.research_strategies import composite_chain_candidates
from ..tools.target_rules import collect_target_rule_hits, composite_chain_hints
from ..tools.novelty import (Disclosure, NoveltyChecker, UpstreamRef,
                             mechanism_audit_llm)
from ..tools.public_scan import scan_all
from .config import TargetConfig
from .gates import (GateResult, g0_dead_code, g1_reachable, g1b_gate_blocks,
                    g3_novelty, g4_runtime, g5_cvss)


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

    def public_disclosures(self) -> Dict[str, Any]:
        if self._public_scan_cache is None:
            self._public_scan_cache = scan_all(
                self.config, offline=self.offline,
                cache_dir=self.workspace / "agent" / "regression" / "cache" / "api")
        return self._public_scan_cache

    def fixture_dir(self) -> Optional[Path]:
        d = self.workspace / "agent" / "regression" / "fixtures"
        return d if d.exists() else None


def _gate_scan(ctx: StageContext) -> List[Dict[str, Any]]:
    keywords = ["SafeMode", "SupportAutoType", "checkAutoType", "maxLevel",
                "readLength", "deny", "registerIfAbsent", "getObjectReader("]
    hits = []
    for src in ctx.config.source_dirs:
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

    PR4's control map and differential index join that required set for the same
    reason: a store built by PR3 has flows but no control verdicts, and a
    scheduler that silently scored without them would look identical to one that
    had them.
    """
    from ..analysis import controls as ctl
    from ..analysis import capability_graph as capability
    from ..analysis import coverage as cov
    from ..analysis import differential as diff
    from ..analysis.inventory import CoverageStore, build_inventory, persist_inventory

    store = CoverageStore(ctx.workspace, ctx.target)
    required = ("source-inventory", "flow-index", "symbol-index",
                ctl.CONTROL_MAP_INDEX, diff.DIFFERENTIAL_INDEX,
                capability.CAPABILITY_GRAPH_INDEX)
    missing = [name for name in required if not store.path(name).exists()]
    built = False
    if missing:
        result = build_inventory(ctx.workspace, ctx.config.source_dirs,
                                 target=ctx.target,
                                 target_type=ctx.config.target_type,
                                 fix_history=_fix_history(ctx))
        persist_inventory(store, result, target_type=ctx.config.target_type)
        built = True
    info = cov.refresh_candidate_coverage(store, ctx.workspace, ctx.target)
    info["rebuilt"] = built
    info["missing_indices"] = missing
    summary = store.read("call-graph-summary") or {}
    flow_summary = store.read("flow-summary") or {}
    control_summary = (store.read(ctl.CONTROL_MAP_INDEX) or {}).get("summary") or {}
    differential_summary = (store.read(diff.DIFFERENTIAL_INDEX) or {}).get("summary") or {}
    capability_summary = (store.read(capability.CAPABILITY_GRAPH_INDEX) or {}).get("summary") or {}
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


def run_s1(ctx: StageContext) -> Dict[str, Any]:
    """Module topology + entry inventory + default-feature inventory.

    Baseline #1/#2 additions: jar version diff (added/removed classes between
    versions) and a danger call-site map (danger patterns x file x line), with
    per-entry danger-hit counts as reachability clues.
    """
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
    danger_sites = []
    per_file_hits: Dict[str, int] = {}
    for pat, label in DANGER_PATTERNS:
        for h in grep_hits(pat, ctx.config.source_dirs, ctx.workspace, max_lines=8):
            fl = str(h["file"])
            per_file_hits[fl] = per_file_hits.get(fl, 0) + 1
            danger_sites.append({
                "label": label, "pattern": pat,
                "file": fl, "line": h["line"], "text": h["text"],
            })
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
    source_sink_graph = build_source_sink_graph(ctx.config.source_dirs, ctx.workspace)
    target_rule_hits = collect_target_rule_hits(
        ctx.config.target_type, ctx.config.source_dirs, ctx.workspace)
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
    ctx.store.write_artifact("S1", "security-fix-history.json", patch_history)
    ctx.store.write_artifact("S1", "patch-variants.json", [
        {k: fix[k] for k in ("short_commit", "commit", "parent", "subject",
                             "affected_paths", "variant_hints", "probe_plan")}
        for fix in patch_history
    ])
    ctx.store.write_artifact("S1", "source-sink-graph.json", source_sink_graph)
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
    except Exception as exc:  # pragma: no cover - defensive
        coverage_index = {"error": "%s: %s" % (type(exc).__name__, exc)}
    ctx.store.write_artifact("S1", "coverage-summary.json", coverage_index)
    # Keep the graph and its candidates visible in the round checkpoint as
    # well as in the target-scoped coverage store.  This makes S1 evidence
    # auditable without duplicating the graph-building logic.
    try:
        from ..analysis import capability_graph as capability
        from ..analysis.inventory import CoverageStore
        coverage_store = CoverageStore(ctx.workspace, ctx.target)
        ctx.store.write_artifact(
            "S1", "capability-graph.json",
            capability.load_capability_graph(coverage_store))
        ctx.store.write_artifact(
            "S1", "capability-candidates.json",
            capability.load_capability_candidates(coverage_store))
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
            "coverage": coverage_index,
            "project_profile": project_profile}


def run_s2(ctx: StageContext) -> Dict[str, Any]:
    """Attack-surface matrix: entry x input shape x logic -> candidate cells.

    The candidate pool is *scheduled* rather than taken wholesale (spec §13):
    S1 has just refreshed coverage, so the scheduler ranks the pool against it
    and returns the round's `max_candidates` slots, quota-stratified.  The full
    pool is left on ``ctx.config.candidates`` -- truncating it would delete the
    fix-completeness candidates this stage just generated, and the next round
    re-schedules the same pool against coverage that has since moved.

    PR4 adds the index-derived candidates (spec §11/§12) to that same pool: an
    unguarded path and a sibling control differential are deterministic
    artifacts with a citable ``file:line``, and the spec asks for them to be
    promoted automatically rather than left in a JSON file nobody reads.
    """
    patch_history = ctx.store.read_artifact("S1", "security-fix-history.json") or []
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
    if bool(getattr(ctx.config, "static_candidates", True)):
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
    pool, static_added = _merge_static_candidates(ctx, list(ctx.config.candidates))
    selected, plan, schedule_note = _schedule_round(ctx, pool)
    selected_ids = {str(c.get("candidate_id")) for c in selected}
    versions = sorted({str(j.get("version")) for j in ctx.config.jars
                       if j.get("version")})
    experiment_plans = []
    for cand in pool:
        research_plan = plan_candidate_experiments(cand, versions)
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
            "status": "candidate",
            "fix_completeness": bool(cand.get("fix_completeness")),
            "patch_commit": cand.get("patch_commit", ""),
            "patch_variants": cand.get("patch_variants", []),
            "chain_components": cand.get("chain_components", []),
            "experiment_plan_ids": [p.get("plan_id") for p in
                                    research_plan.get("plans", [])],
            "research_strategy": research_plan.get("strategy_tags", []),
        })
    ctx.store.write_artifact("S2", "candidate-matrix.json", matrix)
    if plan is not None:
        ctx.store.write_artifact("S2", "candidate-schedule.json", plan.as_dict())
    result = {"candidate_count": len(matrix), "matrix": matrix,
              "generated_fix_candidates": [c["candidate_id"] for c in generated],
              "generated_chain_candidates": [c["candidate_id"]
                                              for c in generated_chain],
              "static_candidates": static_added,
              "candidates": selected,
              "pool_size": len(pool),
              "schedule_note": schedule_note,
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
    return result


def _merge_static_candidates(ctx: StageContext, pool: List[Dict[str, Any]]
                             ) -> "tuple[List[Dict[str, Any]], List[str]]":
    """Add the PR4 index-derived candidates to a round's pool, never raising.

    Returns ``(pool, added_ids)``.  A missing or unreadable coverage store means
    "no static candidates this round" and the reason is returned as an empty
    list rather than an exception: losing an ordering aid must not cost the
    round its audit (same contract as :func:`_schedule_round`).  ``added_ids`` is
    surfaced into the S2 result so a pool that grew says so.
    """
    from ..analysis import controls as ctl
    from ..analysis.inventory import CoverageStore

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


def _schedule_round(ctx: StageContext,
                    pool: List[Dict[str, Any]]
                    ) -> "tuple[List[Dict[str, Any]], Any, str]":
    """Run the coverage-aware scheduler for one round, never raising.

    S1 already refreshed the coverage index, so the sweep is not repeated here
    (``refresh=False``) -- re-running it before this round's ledger exists would
    double the work and change nothing.  A scheduler failure degrades to the
    pre-PR3 behaviour and returns the reason, because losing the ordering must
    not cost the round its audit.

    The slot count is ``config.max_candidates``, or the whole pool when unset:
    this stage's budget has always been "however many candidates the operator
    configured", and inventing a cap here would silently drop configured work.
    """
    from ..analysis import scheduler as sched
    slots = int(getattr(ctx.config, "max_candidates", 0) or 0) or len(pool)
    try:
        return sched.round_selection(
            ctx.workspace, ctx.target, pool, slots,
            round_no=ctx.round_no, refresh=False)
    except Exception as exc:  # pragma: no cover - defensive by design
        return pool[:slots], None, (
            "scheduler unavailable (%s: %s); fell back to proposal order"
            % (type(exc).__name__, exc))


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
            ) for c in poc.get("cells", [])]
            specs.append(ShellPOCSpec(
                candidate_id=cand["candidate_id"],
                script=poc["script"],
                cells=cells,
                env=dict(poc.get("env", {})),
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


def run_s4(ctx: StageContext) -> Dict[str, Any]:
    """Minimal PoC + verification matrix: version x safe-mode x precondition."""
    _stage_pocs(ctx)
    jars_by_version = ctx.config.resolve_jars(ctx.workspace)
    results = {}
    java_specs = _poc_specs(ctx)
    if java_specs:
        matrix_runner = JavaMatrixRunner(ctx.workspace, ctx.target, ctx.round_no, ctx.approval)
        for cid, cells in matrix_runner.run_manifest(java_specs, jars_by_version).items():
            results.setdefault(cid, []).extend(cells)
    shell_specs = _shell_poc_specs(ctx)
    if shell_specs:
        shell_runner = ShellMatrixRunner(ctx.workspace, ctx.target, ctx.round_no, ctx.approval)
        for cid, cells in shell_runner.run_manifest(shell_specs).items():
            results.setdefault(cid, []).extend(cells)
    summaries = {}
    authz_matrix = []
    for cand in ctx.config.candidates:
        cid = cand["candidate_id"]
        cells, convergence = converge_s4_cells(
            ctx.workspace, ctx.target, ctx.round_no, cid, results.get(cid, []))
        summaries[cid] = summarize_candidate(cells)
        summaries[cid]["s4_result_sources"] = convergence["sources"]
        summaries[cid]["s4_persisted_matrix"] = convergence["persisted_matrix"]
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
    ctx.store.write_artifact("S4", "execution-status.json", {
        cid: {
            key: value for key, value in summary.items()
            if key.endswith("_count") or key in ("execution_state", "cells_ran", "s4_result_sources")
        }
        for cid, summary in summaries.items()
    })
    ctx.store.write_artifact("S4", "authz-matrix.json", authz_matrix)
    return {"summaries": summaries}


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
                    number = item.get("number")
                    ref = UpstreamRef(
                        ref=("#%d" % number) if number else item.get("title", "")[:24],
                        kind="pull_request" if item.get("pull_request") else "issue",
                        title=item.get("title", ""),
                        state=item.get("state", ""),
                        created_at=item.get("created_at", ""),
                        url=item.get("html_url", ""),
                        evidence_source="live GitHub search",
                    )
                    if ref.ref not in {x.ref for x in refs}:
                        refs.append(ref)
        disclosures = []
        for d in cand.get("disclosures", []):
            disclosures.append(Disclosure(**d))
        disclosures += pub["disclosures"]
        # Baseline #7: when any public-info channel failed (or the run is
        # offline / rate-limited), absence of a record is NOT a 0day claim.
        query_metadata = checker.query_metadata()
        query_failed = bool(pub.get("errors")) or checker.last_rate_limit is not None \
            or bool(checker.query_errors) or ctx.offline or bool(query_metadata.get("query_failed"))
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
        "channels": pub["channels"], "errors": pub["errors"],
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
    return {"novelty": results}


def run_s6(ctx: StageContext, summaries: Dict[str, Any], conclusions: Dict[str, str]) -> Dict[str, Any]:
    """Severity calibration: defensible CVSS + precondition consistency (G5)."""
    out = {}
    for cand in ctx.config.candidates:
        cid = cand["candidate_id"]
        if conclusions.get(cid) != "确认":
            continue
        vector = cand.get("cvss_vector", "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N")
        tier = cand.get("precondition_tier_hint", "single-feature")
        score, severity = base_score(vector)
        g5 = g5_cvss(tier, vector, cand.get("implicit_default_on", False))
        impact_ok, impact_reason = check_impact_consistency(cand, summaries.get(cid, {}), vector)
        if not impact_ok:
            g5.passed = False
            g5.evidence = (g5.evidence or []) + [impact_reason]
            g5.verdict = "impact evidence insufficient"
        out[cid] = {
            "vector": vector,
            "score": round(score, 1),
            "severity": severity,
            "tier": tier,
            "g5": g5.__dict__,
            "impact": cand.get("impact", []),
            "boundary": cand.get("boundary", ""),
        }
        if not g5.passed:
            out[cid]["blocked"] = True
    ctx.store.write_artifact("S6", "severity.json", out)
    return {"severity": out}


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


def run_s7(ctx: StageContext, rows: List[Dict[str, Any]], summaries: Dict[str, Any],
           severities: Dict[str, Any]) -> Dict[str, Any]:
    """Coordination/disclosure prep: self-contained finding docs + timeline."""
    reports_dir = ctx.workspace / "reports" / ctx.target / ("round-%02d" % ctx.round_no)
    reports_dir.mkdir(parents=True, exist_ok=True)
    written = []
    idx = 0
    for cand in ctx.config.candidates:
        cid = cand["candidate_id"]
        if conclusion_status(cand.get("conclusion_override", "确认")) != "confirmed":
            continue
        row = next((r for r in rows if r.get("candidate_id") == cid), {})
        if not is_confirmed_conclusion(row.get("conclusion")):
            continue
        idx += 1
        sev = severities.get(cid, {})
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
    return {"finding_docs": written, "dir": str(reports_dir.relative_to(ctx.workspace))}


def run_s8(ctx: StageContext, summaries: Dict[str, Any], conclusions: Dict[str, str],
           novelties: Dict[str, Any], severities: Dict[str, Any]) -> Dict[str, Any]:
    """Round close: ledger + exclusions + summary + next-round candidates."""
    rows = []
    excluded = []
    for cand in ctx.config.candidates:
        cid = cand["candidate_id"]
        summary = summaries.get(cid, {})
        conclusion = conclusions.get(cid, "候选（待验证）")
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
        nv = novelties.get(cid, {}).get("novelty")
        if nv:
            row["novelty"] = {"verdict": nv["verdict"], "reason": nv["reason"],
                              "increments": nv.get("increments", [])}
        if cid in severities:
            row["cvss"] = {"vector": severities[cid]["vector"], "score": severities[cid]["score"]}
            if severities[cid].get("blocked"):
                row["conclusion"] = "候选（待验证）"
                row["evidence"].append(
                    "G5_BLOCKED=" + "; ".join(severities[cid].get("g5", {}).get("evidence", [])))
        row["status"] = conclusion_status(row.get("conclusion"))
        rows.append(row)
        if conclusion_status(conclusion) == "excluded":
            excluded.append({
                "surface": cand["surface"],
                "conclusion": "排除（%s）" % cand.get("exclusion_reason", "门控/受控异常"),
                "evidence": row["evidence"],
            })
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
        "next_round": next_round or ["复测 2.0.65（#7753 发布后）", "扩展模块轮（HTTP/Redis/JSONB 集成面）"],
    }
    out_dir = write_round_artifacts(ctx.workspace, ctx.target, ctx.round_no, rows, excluded,
                                    summary, lang=ctx.config.output_lang)
    return {"ledger_dir": str(out_dir.relative_to(ctx.workspace)), "rows": len(rows),
            "excluded": len(excluded), "metrics": metrics}


def _precondition_distribution(rows: List[Dict[str, Any]]) -> str:
    from collections import Counter
    c = Counter(r.get("precondition_tier", "?") for r in rows
                if is_confirmed_conclusion(r.get("conclusion")))
    return ", ".join("%s=%d" % (k, v) for k, v in sorted(c.items()))
