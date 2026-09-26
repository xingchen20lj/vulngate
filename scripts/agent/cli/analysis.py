"""Coverage and semantic-analysis CLI handlers."""

import argparse
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.tools.cvss import base_score, check_precondition_consistency
from agent.tools.github_auth import github_token_source
from agent.tools.novelty import (
    Disclosure,
    NoveltyChecker,
    UpstreamRef,
    upstream_ref_from_search_hit,
)
from agent.tools import source_evidence as se


def _out(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def cmd_coverage(args: argparse.Namespace) -> int:
    """Security audit coverage report (spec §16).

    Reads ``state/<target>/coverage/*``.  ``--rebuild`` (or a missing index)
    re-runs the full source/entry/sink/control inventory first; review state is
    then re-derived from the round ledgers, which are the durable record of what
    was decided.  Nothing here consults an LLM (spec §21.1).
    """
    from agent.analysis import coverage as cov
    from agent.analysis.inventory import (CoverageStore, build_inventory,
                                          coverage_scope_status,
                                          persist_inventory)
    from agent.analysis.languages import SourceFilter

    workspace = Path(args.workspace).resolve()
    target = args.target
    store = CoverageStore(workspace, target)
    payload: Dict[str, Any] = {"target": target, "workspace": str(workspace)}
    scan_filter = SourceFilter(scan_timeout_seconds=int(
        getattr(args, "scan_timeout_seconds", 600) or 0))

    missing_indices = [
        name for name in (
            "source-inventory", "symbol-index", "flow-index",
            "semantic-path-evidence", "semantic-guard-evidence",
            "semantic-call-evidence", "semantic-controlflow-evidence",
            "semantic-ast-evidence", "semantic-transform-evidence",
            "semantic-python-binding-evidence", "evidence-provenance",
        ) if not store.path(name).exists()
    ]
    build_status = store.read("coverage-build-status") or {}
    build_incomplete = (isinstance(build_status, dict)
                        and build_status.get("status") in {
                            "running", "incomplete", "failed"})
    need_build = args.rebuild or bool(missing_indices) or build_incomplete

    # A caller that supplies a source root, source dir, or target type is
    # asking for a particular audit universe.  Never silently render a prior
    # broad/narrow inventory in response.  When no root is supplied, prefer
    # the root persisted with the current scope over guessing ``targets/<id>``.
    scope_requested = bool(args.root or args.source_dir or args.target_type is not None)
    prior_inventory = store.read("inventory-summary") or {}
    prior_scope = (prior_inventory.get("scope")
                   if isinstance(prior_inventory, dict) else None)
    root_text = (args.root or
                 (prior_scope.get("root") if isinstance(prior_scope, dict) else None)
                 or str(workspace / "targets" / target))
    root = Path(root_text).resolve()
    scope_check = None
    if scope_requested and store.path("inventory-summary").exists():
        if not root.exists():
            _out({"error": "target source root not found", "root": str(root),
                  "hint": "pass --root <src root> with the requested scope"})
            return 2
        scope_check = coverage_scope_status(
            store, root, list(args.source_dir or []) or None,
            source_filter=scan_filter, target_type=args.target_type)
        payload["scope_check"] = {
            "status": scope_check["status"],
            "usable": scope_check["usable"],
            "mismatches": scope_check["mismatches"],
        }
        need_build = need_build or not scope_check["usable"]

    if need_build:
        # Keep the original "target root missing" behaviour for a first build,
        # while also making a scope mismatch a normal, visible rebuild reason.
        if not root.exists():
            _out({"error": "target source root not found",
                  "root": str(root),
                  "hint": "pass --root <src root> (with --rebuild) or run S1 first, "
                          "which writes state/<target>/coverage/"})
            return 2
        source_dirs = list(args.source_dir or [])
        def report_progress(progress: Dict[str, Any]) -> None:
            print("[coverage] %.1fs: %d source files, %d files seen, %d dirs; %s" % (
                progress.get("elapsed_seconds", 0), progress.get("source_files", 0),
                progress.get("files_seen", 0), progress.get("directories_seen", 0),
                progress.get("current_path", "")), file=sys.stderr, flush=True)

        store.write("coverage-build-status", {
            "status": "running", "timeout_seconds": scan_filter.scan_timeout_seconds,
            "source_dirs": source_dirs or ["."],
        })
        try:
            result = build_inventory(root, source_dirs or None, target=target,
                                     target_type=args.target_type,
                                     source_filter=scan_filter,
                                     progress_callback=report_progress)
        except Exception as exc:
            from agent.analysis.languages import SourceScanTimeout
            store.write("coverage-build-status", {
                "status": "incomplete" if isinstance(exc, SourceScanTimeout) else "failed",
                "error": str(exc),
                "progress": getattr(exc, "progress", {}),
            })
            raise
        persist_inventory(store, result, target_type=args.target_type)
        store.write("coverage-build-status", {
            "status": "complete", "scope_id": result.scope.get("scope_id", ""),
            "source_files": len(result.files), "elapsed_ms": result.elapsed_ms,
        })
        payload["rebuilt"] = {
            "root": str(root), "source_dirs": source_dirs,
            "counts": result.counts(), "missing_indices": missing_indices,
            "reason": ("explicit-rebuild" if args.rebuild else
                       "scope-contract" if scope_check is not None else
                       "missing-index"),
        }
        payload["scope"] = result.scope

    if not args.no_refresh:
        payload["refresh"] = cov.refresh_candidate_coverage(store, workspace, target)

    summary = store.read("coverage-summary") or {}
    if "scope" not in payload:
        current_inventory = store.read("inventory-summary") or {}
        if isinstance(current_inventory, dict) and isinstance(current_inventory.get("scope"), dict):
            payload["scope"] = current_inventory["scope"]
    regions = _filter_regions(summary.get("uncovered_regions") or [], args)

    if args.json:
        out = dict(summary)
        out.update(payload)
        out["uncovered_regions"] = regions
        _out(out)
        return 0

    print(cov.render_coverage_text(summary, args.lang, gap_limit=1))
    callgraph_summary = store.read("call-graph-summary") or {}
    flow_summary = store.read("flow-summary") or {}
    semantic_summary = (store.read("semantic-path-evidence") or {}).get("summary") or {}
    semantic_guard_summary = (store.read("semantic-guard-evidence") or {}).get(
        "summary") or {}
    semantic_call_summary = (store.read("semantic-call-evidence") or {}).get(
        "summary") or {}
    semantic_controlflow_summary = (store.read(
        "semantic-controlflow-evidence") or {}).get("summary") or {}
    semantic_ast_summary = (store.read(
        "semantic-ast-evidence") or {}).get("summary") or {}
    semantic_transform_summary = (store.read(
        "semantic-transform-evidence") or {}).get("summary") or {}
    semantic_binding_summary = (store.read(
        "semantic-python-binding-evidence") or {}).get("summary") or {}
    provenance_summary = (store.read("evidence-provenance") or {}).get(
        "summary") or {}
    if callgraph_summary or flow_summary:
        print("\n%s" % ("跨过程分析" if args.lang == "zh" else "Cross-procedural analysis"))
        print("─" * 46)
        if callgraph_summary:
            print("  symbols %s  edges %s  unresolved %s  ambiguous %s"
                  % (callgraph_summary.get("nodes", 0),
                     callgraph_summary.get("edges", 0),
                     callgraph_summary.get("unresolved_calls", 0),
                     callgraph_summary.get("ambiguous_names", 0)))
        if flow_summary:
            by_priority = flow_summary.get("flows_by_priority") or {}
            print("  flows %s (high %s / medium %s / low %s)"
                  % (flow_summary.get("flows", 0), by_priority.get("high", 0),
                     by_priority.get("medium", 0), by_priority.get("low", 0)))
            print("  sinks forward-seen %s  backward-seen %s  gaps %s"
                  % (flow_summary.get("sinks_forward_seen", 0),
                     flow_summary.get("sinks_backward_seen", 0),
                     flow_summary.get("coverage_gaps") or {}))
            if flow_summary.get("truncated"):
                print("  !! flow index truncated: %s flows dropped (--max-flows)"
                      % flow_summary.get("dropped_flows", 0))
    if semantic_summary:
        print("\n%s" % ("语义路径证据" if args.lang == "zh"
                        else "Semantic path evidence"))
        print("─" * 46)
        print("  flows %s  same-symbol %s  candidates %s"
              % (semantic_summary.get("flows", 0),
                 semantic_summary.get("same_symbol_flows", 0),
                 semantic_summary.get("candidates", 0)))
        print("  taint %s  verdicts %s"
              % (semantic_summary.get("taint_status") or {},
                 semantic_summary.get("semantic_verdicts") or {}))
    if semantic_guard_summary:
        print("\n%s" % ("语义守卫证据" if args.lang == "zh"
                        else "Semantic guard evidence"))
        print("─" * 46)
        print("  flows %s  branch gaps %s  subject gaps %s  candidates %s"
              % (semantic_guard_summary.get("flows", 0),
                 semantic_guard_summary.get("flows_with_branch_gaps", 0),
                 semantic_guard_summary.get("flows_with_subject_binding_gaps", 0),
                 semantic_guard_summary.get("candidates", 0)))
        print("  postures %s  binding %s"
              % (semantic_guard_summary.get("branch_postures") or {},
                 semantic_guard_summary.get("subject_binding") or {}))
    if semantic_call_summary:
        print("\n%s" % ("语义调用证据" if args.lang == "zh"
                        else "Semantic call evidence"))
        print("─" * 46)
        print("  flows %s  cross-symbol %s  steps %s  candidates %s"
              % (semantic_call_summary.get("flows", 0),
                 semantic_call_summary.get("cross_symbol_flows", 0),
                 semantic_call_summary.get("call_steps", 0),
                 semantic_call_summary.get("candidates", 0)))
        print("  callsites %s  sink binding %s"
              % (semantic_call_summary.get("callsite_status") or {},
                 semantic_call_summary.get("sink_binding") or {}))
    if semantic_controlflow_summary:
        print("\n%s" % ("语义控制流证据" if args.lang == "zh"
                        else "Semantic control-flow evidence"))
        print("─" * 46)
        print("  flows %s  controls %s  alternate %s  dominance-likely %s  candidates %s"
              % (semantic_controlflow_summary.get("flows", 0),
                 semantic_controlflow_summary.get("controls", 0),
                 semantic_controlflow_summary.get("flows_with_alternate_paths", 0),
                 semantic_controlflow_summary.get("flows_with_dominance_likely", 0),
                 semantic_controlflow_summary.get("candidates", 0)))
        print("  relations %s"
              % (semantic_controlflow_summary.get("relations") or {}))
    if semantic_ast_summary:
        print("\n%s" % ("语法 AST 结构证据" if args.lang == "zh"
                        else "Syntax AST structural evidence"))
        print("─" * 46)
        print("  flows %s  controls %s  parsed files %s/%s  candidates %s"
              % (semantic_ast_summary.get("flows", 0),
                 semantic_ast_summary.get("controls", 0),
                 semantic_ast_summary.get("parsed_files", 0),
                 semantic_ast_summary.get("files", 0),
                 semantic_ast_summary.get("candidates", 0)))
        print("  relations %s"
              % (semantic_ast_summary.get("relations") or {}))
    if semantic_transform_summary:
        print("\n%s" % ("语义变换绑定证据" if args.lang == "zh"
                        else "Semantic transform binding evidence"))
        print("─" * 46)
        print("  flows %s  controls %s  binding gaps %s  candidates %s"
              % (semantic_transform_summary.get("flows", 0),
                 semantic_transform_summary.get("controls", 0),
                 semantic_transform_summary.get("flows_with_binding_gaps", 0),
                 semantic_transform_summary.get("candidates", 0)))
        print("  relations %s  verdicts %s"
              % (semantic_transform_summary.get("relation_counts") or {},
                 semantic_transform_summary.get("verdicts") or {}))
    if semantic_binding_summary:
        print("\n%s" % ("语言感知值绑定证据" if args.lang == "zh"
                        else "Language-aware value binding evidence"))
        print("─" * 46)
        print("  flows %s  controls %s  parsed files %s/%s  candidates %s"
              % (semantic_binding_summary.get("flows", 0),
                 semantic_binding_summary.get("controls", 0),
                 semantic_binding_summary.get("parsed_files", 0),
                 semantic_binding_summary.get("files", 0),
                 semantic_binding_summary.get("candidates", 0)))
        print("  relations %s"
              % (semantic_binding_summary.get("relations") or {}))
    if provenance_summary:
        print("\n%s" % ("证据溯源" if args.lang == "zh"
                        else "Evidence provenance"))
        print("─" * 46)
        print("  records %s  groups %s  correlated candidates %s"
              % (provenance_summary.get("records", 0),
                 provenance_summary.get("independence_groups", 0),
                 provenance_summary.get("correlated_candidates", 0)))
    if args.schedule:
        from agent.analysis import scheduler as sched
        plan_payload = sched.load_schedule(store)
        print("\n%s" % ("候选调度（最近一轮）" if args.lang == "zh"
                        else "Candidate schedule (latest round)"))
        print("─" * 46)
        if not plan_payload:
            print("  （无：尚未运行 schedule / 尚未执行任何一轮）" if args.lang == "zh"
                  else "  (none: `agent_cli schedule` has not been run)")
        else:
            for item in plan_payload.get("selected") or []:
                print("  %-10s %-9s %6.2f %-7s %s" % (
                    item.get("candidate_id"), item.get("category"),
                    item.get("score", 0.0), item.get("band"),
                    ",".join(item.get("code_locations") or []) or "-"))
            quota = plan_payload.get("quota") or {}
            print("  quota  filled %s" % (quota.get("filled") or {}))
            moved = quota.get("relocated") or {}
            if moved:
                print("  quota  relocated %s" % moved)
            deferred = plan_payload.get("deferred_ids") or []
            print("  deferred %d" % len(deferred))
            pinned = plan_payload.get("pinned") or []
            if pinned:
                print("  pinned   %s" % ", ".join(pinned))
            residual = plan_payload.get("residual") or {}
            if not residual.get("measured", True):
                print("  residual not measured this round")
            elif residual:
                print("  high-risk uncovered %s  stop condition %s"
                      % (residual.get("high_risk_uncovered"),
                         "met" if residual.get("stop_condition_met") else "not met"))
    if payload.get("rebuilt"):
        counts = payload["rebuilt"]["counts"]
        print("\n[index rebuilt from %s]" % payload["rebuilt"]["root"])
        print("  excluded dirs: %d (%d files not descended into)"
              % (counts.get("excluded_dirs", 0),
                 counts.get("excluded_dir_file_count", 0)))
    if args.show_uncovered:
        print("\n%s（%d）" % ("未审计区域" if args.lang == "zh" else "Uncovered regions",
                             len(regions)))
        print("─" * 46)
        if not regions:
            print("  （无）" if args.lang == "zh" else "  (none)")
        for region in regions[:args.limit]:
            location = ("%s:%d" % (region.get("file"), region.get("line"))
                        if region.get("file") else region.get("ref", ""))
            print("  [%s] %-26s %s" % (str(region.get("risk", "")).upper()[:6],
                                       region.get("kind", ""), location))
            print("        %s" % region.get("reason", ""))
        if len(regions) > args.limit:
            print("  ... %d more (use --limit)" % (len(regions) - args.limit))
    return 0


def _load_candidate_pool(args: argparse.Namespace) -> "tuple[List[Dict[str, Any]], int, str, List[str]]":
    """Read the candidate pool for ``schedule`` from a file or a target config.

    Accepts the three shapes the pipeline already emits -- a bare list, a
    ``{"candidates": [...]}`` envelope, and an S2 ``candidate-matrix.json``
    (a list of cells) -- so an operator can re-schedule a round from exactly the
    artifacts it produced instead of re-typing the pool.
    """
    import json as _json

    if args.candidates:
        path = Path(args.candidates)
        if not path.exists():
            return [], 0, "candidate file not found: %s" % path, []
        try:
            data = _json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            return [], 0, "candidate file is not JSON: %s" % exc, []
        if isinstance(data, dict):
            data = data.get("candidates") or data.get("matrix") or []
        if not isinstance(data, list):
            return [], 0, "candidate file must hold a list or {\"candidates\": [...]}", []
        return [c for c in data if isinstance(c, dict)], 0, "", []

    if args.config:
        from agent.orchestrator.config import TargetConfig
        from agent.analysis.research_agenda import normalize_candidate_ids
        path = Path(args.config)
        if not path.exists():
            return [], 0, "config not found: %s" % path, []
        cfg = TargetConfig.load(path)
        return (list(cfg.candidates), int(cfg.max_candidates or 0), "",
                normalize_candidate_ids(cfg.priority_candidate_ids))

    return [], 0, "no candidate pool: pass --candidates <file> or --config <file>", []


def _filter_regions(regions: List[Dict[str, Any]],
                    args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Apply ``--risk`` / ``--category`` / ``--module`` to the gap list."""
    out = list(regions)
    if args.risk:
        out = [r for r in out if str(r.get("risk")) == args.risk]
    if args.category:
        needle = args.category.lower()

        def matches(region: Dict[str, Any]) -> bool:
            detail = region.get("detail") or {}
            haystack = [str(region.get("kind", "")), str(region.get("reason", ""))]
            haystack += [str(v) for v in detail.values()]
            return any(needle in item.lower() for item in haystack)

        out = [r for r in out if matches(r)]
    if args.module:
        prefix = args.module.strip("/")
        out = [r for r in out if str(r.get("file", "")).startswith(prefix)
               or ("/" + prefix) in str(r.get("file", ""))]
    return out


def cmd_schedule(args: argparse.Namespace) -> int:
    """Coverage-aware candidate schedule (spec §13/§14/§15).

    Scores a candidate pool against the persisted coverage index, applies the
    category quota, writes ``state/<target>/coverage/schedule-*.json`` and
    prints the plan.  ``--prompt`` additionally prints the structured block S2
    feeds the model.  Deterministic and offline (spec §21.1).
    """
    from agent.analysis import scheduler as sched
    from agent.analysis.inventory import CoverageStore
    from agent.evaluation.benchmark import (benchmark_feedback_from_input,
                                             load_benchmark_json)

    workspace = Path(args.workspace).resolve()
    store = CoverageStore(workspace, args.target)
    pool, config_slots, error, config_priority_ids = _load_candidate_pool(args)
    if error:
        _out({"error": error})
        return 2
    if not pool:
        _out({"error": "candidate pool is empty", "target": args.target})
        return 2
    slots = args.slots or config_slots or sched.DEFAULT_SLOTS
    try:
        slots = int(slots)
    except (TypeError, ValueError):
        slots = sched.DEFAULT_SLOTS
    if slots <= 0:
        slots = sched.DEFAULT_SLOTS
    if args.limit_pool:
        pool = pool[:args.limit_pool]
    from agent.analysis.research_agenda import (
        load_research_agenda, normalize_candidate_ids,
        selected_candidate_ids,
    )
    agenda_priority_ids = selected_candidate_ids(
        load_research_agenda(workspace, args.target),
        current_round=args.round)
    priority_ids = normalize_candidate_ids(
        list(getattr(args, "priority_candidate", []) or [])
        + config_priority_ids + agenda_priority_ids)
    explicit_priority_ids = normalize_candidate_ids(
        list(getattr(args, "priority_candidate", []) or [])
        + config_priority_ids)
    active_pool, candidate_intake = sched.bounded_candidate_intake(
        pool, slots=slots, round_no=args.round,
        priority_ids=priority_ids)

    benchmark_feedback = {}
    if args.benchmark_result:
        try:
            benchmark_input = load_benchmark_json(Path(args.benchmark_result))
            benchmark_feedback = benchmark_feedback_from_input(benchmark_input)
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            _out({"error": "benchmark result is not valid JSON: %s" % exc})
            return 2
        if not benchmark_feedback:
            _out({"error": "benchmark result has no supported metrics/feedback",
                  "path": str(Path(args.benchmark_result).resolve())})
            return 2

    selected, plan, note = sched.round_selection(
        workspace, args.target, active_pool, slots, round_no=args.round,
        refresh=not args.no_refresh, priority_ids=explicit_priority_ids,
        benchmark_feedback=benchmark_feedback)
    if plan is None:
        _out({"error": note, "target": args.target,
              "hint": "run S1 or `agent_cli coverage --rebuild` first"})
        return 2

    if args.json:
        payload = plan.as_dict()
        payload["note"] = note
        payload["pool_size"] = len(pool)
        payload["active_pool_size"] = len(active_pool)
        payload["candidate_intake"] = candidate_intake
        payload["scheduled_candidates"] = [
            {k: c.get(k) for k in ("candidate_id", "surface", "entry",
                                   "input_shape", "logic")} for c in selected]
        _out(payload)
        return 0

    print(sched.render_schedule_text(plan, args.lang))
    print("")
    print(("候选池 %d → 本轮 %d（延后 %d）" if args.lang == "zh"
           else "pool %d -> round %d (deferred %d)")
          % (len(pool), len(selected), len(plan.deferred)))
    if candidate_intake["deferred_intake_candidates"]:
        print(("候选准入窗口 %d/%d；其余 %d 个待后续轮次" if args.lang == "zh"
               else "candidate intake window %d/%d; %d remain queued")
              % (candidate_intake["active_candidates"],
                 candidate_intake["pool_candidates"],
                 candidate_intake["deferred_intake_candidates"]))
    if plan.pinned:
        print(("钉住（运行时证据）：" if args.lang == "zh" else "pinned (runtime evidence): ")
              + ", ".join(plan.pinned))
    if note:
        print(("!! %s" if args.lang == "zh" else "!! %s") % note)
    if args.prompt:
        context = sched.ScheduleContext.from_store(
            store, benchmark_feedback=benchmark_feedback)
        print("")
        print(sched.prompt_coverage_block(context, plan=plan))
    return 0


def _read_fix_history(path: Optional[str]) -> "tuple[List[Dict[str, Any]], str]":
    """Patch history for the PR4 sibling diff: explicit file, else the newest S1 one.

    Returns ``(history, note)``; an empty history is normal (no patch evidence),
    and the note says which of the two ways produced it so an operator can tell
    "no file" apart from "file has no records".
    """
    import json as _json

    if path:
        target = Path(path)
        if not target.exists():
            return [], "fix history not found: %s" % target
        try:
            data = _json.loads(target.read_text(encoding="utf-8"))
        except ValueError as exc:
            return [], "fix history is not JSON: %s" % exc
        if isinstance(data, dict):
            data = data.get("fixes") or data.get("rows") or []
        return [d for d in data if isinstance(d, dict)], ""
    return [], ""


def _newest_fix_history(workspace: Path, target: str) -> List[Dict[str, Any]]:
    """Newest ``state/<target>/round-NN/S1/security-fix-history.json``, if any."""
    import json as _json

    base = Path(workspace) / "state" / target
    if not base.exists():
        return []
    candidates = sorted(base.glob("round-*/S1/security-fix-history.json"))
    for path in reversed(candidates):
        try:
            data = _json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
    return []


def _ensure_coverage_analysis(args: argparse.Namespace,
                              required: "tuple[str, ...]",
                              with_fix_history: bool = False):
    """Make sure the requested PR4 index exists, rebuilding the inventory if not.

    Returns ``(workspace, store, rebuilt, history_note)``.  Raises nothing: the
    caller reports an unbuildable target as a normal error result, the way
    ``cmd_coverage`` does.
    """
    from agent.analysis.inventory import (CoverageStore, build_inventory,
                                          coverage_scope_status,
                                          persist_inventory)
    from agent.analysis.languages import SourceFilter

    workspace = Path(args.workspace).resolve()
    store = CoverageStore(workspace, args.target)
    scan_filter = SourceFilter(scan_timeout_seconds=int(
        getattr(args, "scan_timeout_seconds", 600) or 0))
    missing = [name for name in required if not store.path(name).exists()]
    scope_requested = bool(getattr(args, "root", None)
                           or getattr(args, "source_dir", [])
                           or getattr(args, "target_type", None) is not None)
    prior_inventory = store.read("inventory-summary") or {}
    prior_scope = (prior_inventory.get("scope")
                   if isinstance(prior_inventory, dict) else None)
    root_text = (getattr(args, "root", None) or
                 (prior_scope.get("root") if isinstance(prior_scope, dict) else None)
                 or str(workspace / "targets" / args.target))
    root = Path(root_text).resolve()
    scope_check = None
    if scope_requested and store.path("inventory-summary").exists():
        if not root.exists():
            raise FileNotFoundError(root)
        scope_check = coverage_scope_status(
            store, root, list(getattr(args, "source_dir", []) or []) or None,
            source_filter=scan_filter,
            target_type=getattr(args, "target_type", None))

    build_status = store.read("coverage-build-status") or {}
    build_incomplete = (isinstance(build_status, dict)
                        and build_status.get("status") in {
                            "running", "incomplete", "failed"})
    needs_rebuild = (getattr(args, "rebuild", False) or bool(missing)
                     or build_incomplete
                     or (scope_check is not None and not scope_check["usable"]))
    if not needs_rebuild:
        return workspace, store, None, ""

    if not root.exists():
        raise FileNotFoundError(root)

    fix_history: List[Dict[str, Any]] = []
    note = ""
    if with_fix_history:
        fix_history, note = _read_fix_history(getattr(args, "fix_history", None))
        if not fix_history and not note and not getattr(args, "fix_history", None):
            fix_history = _newest_fix_history(workspace, args.target)
            note = ("fix history: %d record(s) from the newest S1 artifact"
                    % len(fix_history))
    source_dirs = list(getattr(args, "source_dir", []) or [])
    def report_progress(progress: Dict[str, Any]) -> None:
        print("[coverage] %.1fs: %d source files, %d files seen, %d dirs; %s" % (
            progress.get("elapsed_seconds", 0), progress.get("source_files", 0),
            progress.get("files_seen", 0), progress.get("directories_seen", 0),
            progress.get("current_path", "")), file=sys.stderr, flush=True)

    store.write("coverage-build-status", {
        "status": "running", "timeout_seconds": scan_filter.scan_timeout_seconds,
        "source_dirs": source_dirs or ["."],
    })
    try:
        result = build_inventory(root, source_dirs or None, target=args.target,
                                 target_type=getattr(args, "target_type", None),
                                 fix_history=fix_history,
                                 source_filter=scan_filter,
                                 progress_callback=report_progress)
    except Exception as exc:
        from agent.analysis.languages import SourceScanTimeout
        store.write("coverage-build-status", {
            "status": "incomplete" if isinstance(exc, SourceScanTimeout) else "failed",
            "error": str(exc), "progress": getattr(exc, "progress", {}),
        })
        raise
    persist_inventory(store, result, target_type=getattr(args, "target_type", None))
    store.write("coverage-build-status", {
        "status": "complete", "scope_id": result.scope.get("scope_id", ""),
        "source_files": len(result.files), "elapsed_ms": result.elapsed_ms,
    })
    rebuilt = {"root": str(root), "source_dirs": source_dirs,
               "counts": result.counts(), "missing_indices": missing,
               "reason": ("explicit-rebuild" if getattr(args, "rebuild", False) else
                          "scope-contract" if scope_check is not None else
                          "missing-index"),
               "scope": result.scope}
    return workspace, store, rebuilt, note


def cmd_controls(args: argparse.Namespace) -> int:
    """Security control map (spec §11): Entry -> Sink path verdicts.

    Prints how many paths are guarded, partially guarded or uncontrolled, which
    control classes are missing, and the highest-signal unguarded paths.
    ``--show-candidates`` also prints the deterministic candidates the map
    generates (``possible-auth-bypass`` / ``possible-control-bypass``).  Nothing
    here consults an LLM (spec §21.1).
    """
    from agent.analysis import controls as ctl

    try:
        workspace, store, rebuilt, _ = _ensure_coverage_analysis(
            args, (ctl.CONTROL_MAP_INDEX,))
    except FileNotFoundError as exc:
        _out({"error": "target source root not found", "root": str(exc),
              "hint": "pass --root <src root> (with --rebuild) or run S1 first"})
        return 2

    cmap = ctl.load_control_map(store)
    candidates = ctl.control_candidates(cmap, limit_per_kind=args.limit_candidates)
    payload: Dict[str, Any] = {
        "target": args.target, "workspace": str(workspace),
        "summary": cmap.summary(),
        "candidates": candidates,
    }
    if rebuilt is not None:
        payload["rebuilt"] = rebuilt
    if args.json:
        entries = cmap.entries
        if args.limit:
            entries = cmap.unguarded("authz")[:args.limit]
        payload["entries"] = [e.as_dict() for e in entries]
        _out(payload)
        return 0

    print(ctl.render_control_map_text(cmap, args.lang, limit=args.limit,
                                      candidates=candidates
                                      if args.show_candidates else None))
    if rebuilt is not None:
        print("\n[index rebuilt from %s]" % rebuilt["root"])
    return 0


def cmd_capability(args: argparse.Namespace) -> int:
    """Capability primitives and bounded attack-path hypotheses.

    The graph is deterministic and static.  It reports observed/missing
    primitives and the next verification sequence; it never promotes a
    composed path to a vulnerability finding or a runtime impact claim.
    """
    from agent.analysis import capability_graph as capability

    try:
        workspace, store, rebuilt, _ = _ensure_coverage_analysis(
            args, (capability.CAPABILITY_GRAPH_INDEX,))
    except FileNotFoundError as exc:
        _out({"error": "target source root not found", "root": str(exc),
              "hint": "pass --root <src root> (with --rebuild) or run S1 first"})
        return 2

    graph = capability.load_capability_graph(store)
    candidates = capability.load_capability_candidates(store)
    if args.limit_candidates:
        candidates = candidates[:args.limit_candidates]
    summary = graph.get("summary") or {}
    payload: Dict[str, Any] = {
        "target": args.target,
        "workspace": str(workspace),
        "summary": summary,
        "candidates": candidates,
    }
    if rebuilt is not None:
        payload["rebuilt"] = rebuilt
    if args.json:
        payload["nodes"] = (graph.get("nodes") or [])[:max(0, args.limit)]
        payload["edges"] = (graph.get("edges") or [])[:max(0, args.limit)]
        _out(payload)
        return 0

    label = "能力原语图" if args.lang == "zh" else "Capability primitive graph"
    print("\n%s" % label)
    print("─" * 46)
    print("  nodes %s  edges %s  flows %s  paths %s" % (
        summary.get("nodes", 0), summary.get("edges", 0),
        summary.get("flows_considered", 0), summary.get("paths", 0)))
    print("  observed %s" % (summary.get("observed_capabilities") or {}))
    print("  complete %s  partial %s  truncated %s" % (
        summary.get("complete_hypotheses", 0),
        summary.get("partial_hypotheses", 0),
        summary.get("truncated", False)))
    if args.show_candidates:
        title = "待验证攻击链（不是漏洞结论）" if args.lang == "zh" \
            else "Verification candidates (not findings)"
        print("\n%s" % title)
        for candidate in candidates[:max(0, args.limit)]:
            missing = ",".join(candidate.get("missing_capabilities") or []) or "none"
            print("  %-16s %-42s missing=%s" % (
                candidate.get("candidate_id", ""),
                candidate.get("chain_equation", ""), missing))
    if rebuilt is not None:
        print("\n[index rebuilt from %s]" % rebuilt["root"])
    return 0


def cmd_semantic_paths(args: argparse.Namespace) -> int:
    """Show source-local path order and bounded same-symbol data-flow leads."""
    from agent.analysis import semantic_paths as semantic

    try:
        workspace, store, rebuilt, _ = _ensure_coverage_analysis(
            args, (semantic.SEMANTIC_PATH_INDEX,))
    except FileNotFoundError as exc:
        _out({"error": "target source root not found", "root": str(exc),
              "hint": "pass --root <src root> (with --rebuild) or run S1 first"})
        return 2

    evidence = semantic.load_semantic_evidence(store)
    candidates = semantic.load_semantic_candidates(store)
    if args.limit_candidates:
        candidates = candidates[:args.limit_candidates]
    payload: Dict[str, Any] = {
        "target": args.target,
        "workspace": str(workspace),
        "summary": evidence.get("summary") or {},
        "candidates": candidates,
        "claim_status": evidence.get("claim_status", "not-a-finding"),
        "limitations": evidence.get("limitations") or [],
    }
    if rebuilt is not None:
        payload["rebuilt"] = rebuilt
    if args.json:
        payload["flows"] = (evidence.get("flows") or [])[:max(0, args.limit)]
        _out(payload)
        return 0

    print(semantic.render_semantic_paths_text(evidence, args.lang, limit=args.limit))
    if args.show_candidates and not args.json:
        print("\n%s" % ("待验证线索详情" if args.lang == "zh"
                        else "Verification lead details"))
        print("─" * 52)
        for candidate in candidates[:max(0, args.limit)]:
            print("  %-22s %s" % (candidate.get("candidate_id", ""),
                                  candidate.get("hypothesis", "")))
    if rebuilt is not None:
        print("\n[index rebuilt from %s]" % rebuilt["root"])
    return 0


def cmd_semantic_guards(args: argparse.Namespace) -> int:
    """Show bounded branch-posture and subject-binding evidence.

    These rows help an expert choose the next trace, but do not prove branch
    dominance, object identity, an authorization bypass, or any finding.
    """
    from agent.analysis import semantic_guards as semantic_guard

    try:
        workspace, store, rebuilt, _ = _ensure_coverage_analysis(
            args, (semantic_guard.SEMANTIC_GUARD_INDEX,))
    except FileNotFoundError as exc:
        _out({"error": "target source root not found", "root": str(exc),
              "hint": "pass --root <src root> (with --rebuild) or run S1 first"})
        return 2

    evidence = semantic_guard.load_semantic_guards(store)
    candidates = semantic_guard.load_semantic_guard_candidates(store)
    if args.limit_candidates:
        candidates = candidates[:args.limit_candidates]
    payload: Dict[str, Any] = {
        "target": args.target,
        "workspace": str(workspace),
        "summary": evidence.get("summary") or {},
        "candidates": candidates,
        "claim_status": evidence.get("claim_status", "not-a-finding"),
        "limitations": evidence.get("limitations") or [],
    }
    if rebuilt is not None:
        payload["rebuilt"] = rebuilt
    if args.json:
        payload["flows"] = (evidence.get("flows") or [])[:max(0, args.limit)]
        _out(payload)
        return 0

    print(semantic_guard.render_semantic_guards_text(
        evidence, args.lang, limit=args.limit))
    if args.show_candidates:
        print("\n%s" % ("待验证线索详情" if args.lang == "zh"
                        else "Verification lead details"))
        print("─" * 52)
        for candidate in candidates[:max(0, args.limit)]:
            print("  %-22s %s" % (candidate.get("candidate_id", ""),
                                  candidate.get("hypothesis", "")))
    if rebuilt is not None:
        print("\n[index rebuilt from %s]" % rebuilt["root"])
    return 0


def cmd_semantic_calls(args: argparse.Namespace) -> int:
    """Show bounded one-hop interprocedural argument/return evidence."""
    from agent.analysis import semantic_calls as semantic_call

    try:
        workspace, store, rebuilt, _ = _ensure_coverage_analysis(
            args, (semantic_call.SEMANTIC_CALL_INDEX,))
    except FileNotFoundError as exc:
        _out({"error": "target source root not found", "root": str(exc),
              "hint": "pass --root <src root> (with --rebuild) or run S1 first"})
        return 2

    evidence = semantic_call.load_semantic_call_evidence(store)
    candidates = semantic_call.load_semantic_call_candidates(store)
    if args.limit_candidates:
        candidates = candidates[:args.limit_candidates]
    payload: Dict[str, Any] = {
        "target": args.target,
        "workspace": str(workspace),
        "summary": evidence.get("summary") or {},
        "candidates": candidates,
        "claim_status": evidence.get("claim_status", "not-a-finding"),
        "limitations": evidence.get("limitations") or [],
    }
    if rebuilt is not None:
        payload["rebuilt"] = rebuilt
    if args.json:
        payload["flows"] = (evidence.get("flows") or [])[:max(0, args.limit)]
        _out(payload)
        return 0

    print(semantic_call.render_semantic_calls_text(
        evidence, args.lang, limit=args.limit))
    if args.show_candidates:
        print("\n%s" % ("待验证线索详情" if args.lang == "zh"
                        else "Verification lead details"))
        print("─" * 52)
        for candidate in candidates[:max(0, args.limit)]:
            print("  %-22s %s" % (candidate.get("candidate_id", ""),
                                  candidate.get("hypothesis", "")))
    if rebuilt is not None:
        print("\n[index rebuilt from %s]" % rebuilt["root"])
    return 0


def cmd_semantic_controlflow(args: argparse.Namespace) -> int:
    """Show bounded branch-dominance and alternate-path evidence."""
    from agent.analysis import semantic_controlflow as semantic_cf

    try:
        workspace, store, rebuilt, _ = _ensure_coverage_analysis(
            args, (semantic_cf.SEMANTIC_CONTROLFLOW_INDEX,))
    except FileNotFoundError as exc:
        _out({"error": "target source root not found", "root": str(exc),
              "hint": "pass --root <src root> (with --rebuild) or run S1 first"})
        return 2

    evidence = semantic_cf.load_semantic_controlflow(store)
    candidates = semantic_cf.load_semantic_controlflow_candidates(store)
    if args.limit_candidates:
        candidates = candidates[:args.limit_candidates]
    payload: Dict[str, Any] = {
        "target": args.target,
        "workspace": str(workspace),
        "summary": evidence.get("summary") or {},
        "candidates": candidates,
        "claim_status": evidence.get("claim_status", "not-a-finding"),
        "limitations": evidence.get("limitations") or [],
    }
    if rebuilt is not None:
        payload["rebuilt"] = rebuilt
    if args.json:
        payload["flows"] = (evidence.get("flows") or [])[:max(0, args.limit)]
        _out(payload)
        return 0

    print(semantic_cf.render_semantic_controlflow_text(
        evidence, args.lang, limit=args.limit))
    if args.show_candidates:
        print("\n%s" % ("待验证线索详情" if args.lang == "zh"
                        else "Verification lead details"))
        print("─" * 52)
        for candidate in candidates[:max(0, args.limit)]:
            print("  %-22s %s" % (candidate.get("candidate_id", ""),
                                  candidate.get("hypothesis", "")))
    if rebuilt is not None:
        print("\n[index rebuilt from %s]" % rebuilt["root"])
    return 0


def cmd_semantic_ast(args: argparse.Namespace) -> int:
    """Show bounded Python-AST branch and scope evidence."""
    from agent.analysis import semantic_ast as semantic_ast_analysis

    try:
        workspace, store, rebuilt, _ = _ensure_coverage_analysis(
            args, (semantic_ast_analysis.SEMANTIC_AST_INDEX,))
    except FileNotFoundError as exc:
        _out({"error": "target source root not found", "root": str(exc),
              "hint": "pass --root <src root> (with --rebuild) or run S1 first"})
        return 2

    evidence = semantic_ast_analysis.load_semantic_ast(store)
    candidates = semantic_ast_analysis.load_semantic_ast_candidates(store)
    if args.limit_candidates:
        candidates = candidates[:args.limit_candidates]
    payload: Dict[str, Any] = {
        "target": args.target,
        "workspace": str(workspace),
        "summary": evidence.get("summary") or {},
        "candidates": candidates,
        "claim_status": evidence.get("claim_status", "not-a-finding"),
        "limitations": evidence.get("limitations") or [],
    }
    if rebuilt is not None:
        payload["rebuilt"] = rebuilt
    if args.json:
        payload["flows"] = (evidence.get("flows") or [])[:max(0, args.limit)]
        _out(payload)
        return 0

    print(semantic_ast_analysis.render_semantic_ast_text(
        evidence, args.lang, limit=args.limit))
    if args.show_candidates:
        print("\n%s" % ("待验证线索详情" if args.lang == "zh"
                        else "Verification lead details"))
        print("─" * 52)
        for candidate in candidates[:max(0, args.limit)]:
            print("  %-22s %s" % (candidate.get("candidate_id", ""),
                                  candidate.get("hypothesis", "")))
    if rebuilt is not None:
        print("\n[index rebuilt from %s]" % rebuilt["root"])
    return 0


def cmd_semantic_transforms(args: argparse.Namespace) -> int:
    """Show bounded validation/sanitization result-binding evidence."""
    from agent.analysis import semantic_transforms as semantic_transform

    try:
        workspace, store, rebuilt, _ = _ensure_coverage_analysis(
            args, (semantic_transform.SEMANTIC_TRANSFORM_INDEX,))
    except FileNotFoundError as exc:
        _out({"error": "target source root not found", "root": str(exc),
              "hint": "pass --root <src root> (with --rebuild) or run S1 first"})
        return 2

    evidence = semantic_transform.load_semantic_transform_evidence(store)
    candidates = semantic_transform.load_semantic_transform_candidates(store)
    if args.limit_candidates:
        candidates = candidates[:args.limit_candidates]
    payload: Dict[str, Any] = {
        "target": args.target,
        "workspace": str(workspace),
        "summary": evidence.get("summary") or {},
        "candidates": candidates,
        "claim_status": evidence.get("claim_status", "not-a-finding"),
        "limitations": evidence.get("limitations") or [],
    }
    if rebuilt is not None:
        payload["rebuilt"] = rebuilt
    if args.json:
        payload["flows"] = (evidence.get("flows") or [])[:max(0, args.limit)]
        _out(payload)
        return 0

    print(semantic_transform.render_semantic_transforms_text(
        evidence, args.lang, limit=args.limit))
    if args.show_candidates:
        print("\n%s" % ("待验证线索详情" if args.lang == "zh"
                        else "Verification lead details"))
        print("─" * 52)
        for candidate in candidates[:max(0, args.limit)]:
            print("  %-22s %s" % (candidate.get("candidate_id", ""),
                                  candidate.get("hypothesis", "")))
    if rebuilt is not None:
        print("\n[index rebuilt from %s]" % rebuilt["root"])
    return 0


def cmd_semantic_bindings(args: argparse.Namespace) -> int:
    """Show syntax-aware Python value-binding evidence and adapter gaps."""
    from agent.analysis import semantic_bindings as semantic_binding

    try:
        workspace, store, rebuilt, _ = _ensure_coverage_analysis(
            args, (semantic_binding.SEMANTIC_BINDING_INDEX,))
    except FileNotFoundError as exc:
        _out({"error": "target source root not found", "root": str(exc),
              "hint": "pass --root <src root> (with --rebuild) or run S1 first"})
        return 2

    evidence = semantic_binding.load_semantic_binding_evidence(store)
    candidates = semantic_binding.load_semantic_binding_candidates(store)
    if args.limit_candidates:
        candidates = candidates[:args.limit_candidates]
    payload: Dict[str, Any] = {
        "target": args.target,
        "workspace": str(workspace),
        "summary": evidence.get("summary") or {},
        "candidates": candidates,
        "claim_status": evidence.get("claim_status", "not-a-finding"),
        "limitations": evidence.get("limitations") or [],
    }
    if rebuilt is not None:
        payload["rebuilt"] = rebuilt
    if args.json:
        payload["flows"] = (evidence.get("flows") or [])[:max(0, args.limit)]
        _out(payload)
        return 0

    print(semantic_binding.render_semantic_bindings_text(
        evidence, args.lang, limit=args.limit))
    if args.show_candidates:
        print("\n%s" % ("待验证线索详情" if args.lang == "zh"
                        else "Verification lead details"))
        print("─" * 52)
        for candidate in candidates[:max(0, args.limit)]:
            print("  %-22s %s" % (candidate.get("candidate_id", ""),
                                  candidate.get("hypothesis", "")))
    if rebuilt is not None:
        print("\n[index rebuilt from %s]" % rebuilt["root"])
    return 0


def cmd_evidence_provenance(args: argparse.Namespace) -> int:
    """Show raw/derived static evidence lineage and candidate correlation."""
    from agent.analysis import evidence_provenance as provenance_analysis

    try:
        workspace, store, rebuilt, _ = _ensure_coverage_analysis(
            args, (provenance_analysis.EVIDENCE_PROVENANCE_INDEX,))
    except FileNotFoundError as exc:
        _out({"error": "target source root not found", "root": str(exc),
              "hint": "pass --root <src root> (with --rebuild) or run S1 first"})
        return 2

    provenance = provenance_analysis.load_evidence_provenance(store)
    correlations = list(provenance.get("candidate_correlations") or [])
    if args.limit_candidates:
        correlations = correlations[:args.limit_candidates]
    payload: Dict[str, Any] = {
        "schema_version": provenance.get("schema_version"),
        "target": args.target,
        "workspace": str(workspace),
        "summary": provenance.get("summary") or {},
        "candidate_correlations": correlations,
        "claim_status": provenance.get("claim_status", "not-a-finding"),
        "limitations": provenance.get("limitations") or [],
    }
    if rebuilt is not None:
        payload["rebuilt"] = rebuilt
    if args.json:
        payload["records"] = (provenance.get("records") or [])[:max(0, args.limit)]
        _out(payload)
        return 0

    print(provenance_analysis.render_evidence_provenance_text(
        provenance, args.lang))
    if args.show_candidates:
        print("\n%s" % ("相关候选组" if args.lang == "zh"
                        else "Correlated candidate groups"))
        print("─" * 52)
        for row in correlations[:max(0, args.limit)]:
            print("  %-24s %s" % (
                row.get("independence_group", ""),
                ", ".join(row.get("candidate_ids") or [])))
    if rebuilt is not None:
        print("\n[index rebuilt from %s]" % rebuilt["root"])
    return 0


def cmd_threat_model(args: argparse.Namespace) -> int:
    """Show the bounded attacker-path threat model; paths are not findings."""
    from agent.analysis import threat_model as threat_model_analysis

    try:
        workspace, store, rebuilt, _ = _ensure_coverage_analysis(
            args, (threat_model_analysis.THREAT_MODEL_INDEX,))
    except FileNotFoundError as exc:
        _out({"error": "target source root not found", "root": str(exc),
              "hint": "pass --root <src root> (with --rebuild) or run S1 first"})
        return 2

    model = threat_model_analysis.load_threat_model(workspace, args.target)
    if not model:
        _out({"error": "threat model not found",
              "hint": "run S1 or `agent_cli.py threat-model --rebuild`"})
        return 2
    paths = list(model.get("attack_paths") or [])
    if args.limit:
        paths = paths[:max(0, args.limit)]
    payload: Dict[str, Any] = {
        "target": args.target,
        "workspace": str(workspace),
        "schema_version": model.get("schema_version", ""),
        "summary": model.get("summary") or {},
        "boundaries": (model.get("boundaries") or [])[:max(0, args.limit)],
        "attack_paths": paths,
        "unresolved": model.get("unresolved") or {},
        "claim_status": model.get("claim_status", "not-a-finding"),
    }
    if rebuilt is not None:
        payload["rebuilt"] = rebuilt
    if args.json:
        _out(payload)
        return 0

    label = "攻击路径威胁模型" if args.lang == "zh" \
        else "Attacker-path threat model"
    print("\n%s" % label)
    print("─" * 46)
    summary = payload["summary"]
    print("  boundaries %s  paths %s  high-priority %s" % (
        summary.get("boundaries", 0), summary.get("attack_paths", 0),
        summary.get("high_priority_paths", 0)))
    print("  control postures %s" %
          (summary.get("attack_paths_by_control_posture") or {}))
    print("  unresolved entries %s  sinks %s" % (
        summary.get("unmapped_entries", 0), summary.get("unmapped_sinks", 0)))
    for path in paths:
        print("  [P%s] %s %s -> %s posture=%s state=%s" % (
            path.get("research_priority", 0), path.get("path_id", ""),
            path.get("entry_id", ""), path.get("sink_id", ""),
            path.get("control_posture", "unmapped"),
            path.get("research_state", "")))
    print("  claim_status=%s" % payload["claim_status"])
    if rebuilt is not None:
        print("\n[index rebuilt from %s]" % rebuilt["root"])
    return 0


def cmd_research_strategy(args: argparse.Namespace) -> int:
    """Show or rebuild the bounded cross-artifact research strategy."""
    from agent.analysis import research_strategy as strategy_analysis
    from agent.analysis import threat_model as threat_model_analysis
    from agent.memory.portfolio import load_research_portfolio
    from agent.memory.research import load_research_memory

    workspace = Path(args.workspace).resolve()
    if args.rebuild:
        try:
            workspace, _store, _rebuilt, _note = _ensure_coverage_analysis(
                args, (threat_model_analysis.THREAT_MODEL_INDEX,))
        except FileNotFoundError as exc:
            _out({"error": "target source root not found", "root": str(exc),
                  "hint": "pass --root <src root> or run S1 first"})
            return 2
    model = threat_model_analysis.load_threat_model(workspace, args.target)
    portfolio = load_research_portfolio(workspace, args.target)
    memory = load_research_memory(workspace, args.target)
    benchmark_feedback: Dict[str, Any] = {}
    if args.benchmark_feedback:
        try:
            feedback_path = Path(args.benchmark_feedback)
            if not feedback_path.is_absolute():
                feedback_path = workspace / feedback_path
            benchmark_feedback = json.loads(
                feedback_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            _out({"error": "%s: %s" % (type(exc).__name__, exc)})
            return 2
    strategy = strategy_analysis.load_research_strategy(workspace, args.target)
    if args.rebuild or not strategy:
        if not model and not portfolio and not memory.get("entries"):
            _out({"error": "research strategy inputs not found",
                  "hint": "run S1/S8 or pass --rebuild"})
            return 2
        strategy = strategy_analysis.build_research_strategy(
            threat_model=model, research_portfolio=portfolio,
            research_memory=memory.get("entries") or [],
            benchmark_feedback=benchmark_feedback,
            target=args.target,
            target_type=args.target_type or model.get("target_type", ""),
            round_no=memory.get("round", 0),
        )
        strategy_analysis.write_research_strategy(
            workspace, args.target, strategy)
    if not strategy:
        _out({"error": "research strategy not found",
              "artifact": str(strategy_analysis.strategy_path(
                  workspace, args.target))})
        return 2
    payload = {
        "target": args.target,
        "workspace": str(workspace),
        "artifact": str(strategy_analysis.strategy_path(
            workspace, args.target).relative_to(workspace)),
        "strategy": strategy,
    }
    if args.json:
        _out(payload)
        return 0
    summary = strategy.get("summary", {})
    print("research strategy: %s" % payload["artifact"])
    print("  items=%s paths=%s residuals=%s environments=%s claim_status=%s" % (
        summary.get("item_count", 0), summary.get("path_count", 0),
        summary.get("pending_residuals", 0),
        summary.get("environment_recovery", 0),
        strategy.get("claim_status", "not-a-finding")))
    for item in (strategy.get("items") or [])[:max(0, args.limit)]:
        print("  [P%s] %s kind=%s state=%s objective=%s" % (
            item.get("priority", 0), item.get("strategy_id", ""),
            item.get("kind", ""), item.get("state", ""),
            item.get("objective", "")))
    return 0
