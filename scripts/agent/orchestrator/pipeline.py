"""Pipeline CLI: single main agent drives S1->S8 with breakpoint resume.

Usage:
    python3 -m agent.orchestrator.pipeline --target <target> --round 1 \
        --config agent/regression/configs/<target>.json [--stage S4] [--offline] [--force]

Stages run in order; completed stage checkpoints are skipped unless --force.
Hard gates are enforced between stages:
  G3 (novelty) and G4 (runtime evidence) abort downstream claims when violated;
  G5 (CVSS consistency) is applied during S6.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from .config import TargetConfig
from .gates import g4_runtime, g5_cvss, g5_record_valid
from ..analysis.languages import SOURCE_INVENTORY_POLICY_VERSION
from ..tools.conclusion import conclusion_status
from ..tools.build import S4_EVIDENCE_POLICY_VERSION
from ..tools.public_scan import NOVELTY_QUERY_POLICY_VERSION
from .stages import (StageContext, run_s1, run_s2, run_s3, run_s4, run_s5,
                     run_s6, run_s7, run_s8, _coverage_scope_incomplete,
                     _derive_conclusion)
from .work_budget import WorkBudget


WORKSPACE = Path(__file__).resolve().parents[2]
STAGES = ("S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8")


def _checkpoint_scope_matches(data: Dict[str, Any], partial: bool) -> bool:
    """Legacy complete checkpoints cannot stand in for a partial audit, or vice versa."""
    marker = data.get("coverage_scope")
    marker = marker if isinstance(marker, dict) else {}
    if partial:
        return (marker.get("state") == "scope-incomplete"
                and marker.get("partial_audit") is True)
    return (marker.get("state") != "scope-incomplete"
            and not marker.get("partial_audit"))


def _pending_stage_invalidations(ctx: StageContext) -> Dict[str, Any]:
    data = ctx.store.read_artifact("S0", "stage-resume-invalidations.json")
    if not isinstance(data, dict):
        return {"pending_stages": [], "sources": []}
    pending = [stage for stage in data.get("pending_stages", [])
               if stage in STAGES]
    sources = [stage for stage in data.get("sources", [])
               if stage in STAGES]
    return {"pending_stages": pending, "sources": sources}


def _conclusions(ctx: StageContext, summaries: Dict[str, Any]) -> Dict[str, str]:
    """Per-candidate conclusion derived from runtime data + audit intent."""
    out: Dict[str, str] = {}
    for cand in ctx.config.candidates:
        cid = cand["candidate_id"]
        summary = summaries.get(cid, {})
        intended = cand.get("intended_conclusion", "确认")
        # Shared conclusion rules need the raw cells for FQCN / OOM / env-error
        # checks; load them from the S4 checkpoint (baseline fix #10).
        cells = ctx.store.read_artifact(
            "S4", "matrix-runs/%s/cells.json" % cid) or []
        derived = _derive_conclusion(cand, summary, cells)
        if derived == "确认":
            g4 = g4_runtime(summary, "确认", cand)
            out[cid] = "确认" if g4.passed else "候选（待验证）"
        elif intended == "排除":
            # Intent is an experiment target, not evidence that disproves the
            # candidate. Failed, blocked, and incomplete runs stay pending.
            out[cid] = derived if derived == "排除" else "候选（待验证）"
        else:
            out[cid] = derived
    return out


def run_round(ctx: StageContext, force: bool = False, only: Optional[str] = None) -> None:
    stages = list(STAGES)
    if only:
        if only not in STAGES:
            raise ValueError("unknown stage %s" % only)
        stages = [only]
    from ..analysis.audit_budget import (
        DEFAULT_BUDGET_SECONDS, round_budget_snapshot, start_round_budget,
    )
    from ..analysis.audit_guard import (
        register_active_audit,
        workspace_target_root,
    )
    budget_seconds = getattr(
        ctx.config, "audit_round_timeout_seconds", DEFAULT_BUDGET_SECONDS)
    if budget_seconds is None:
        budget_seconds = DEFAULT_BUDGET_SECONDS
    try:
        round_budget = start_round_budget(
            ctx.workspace, ctx.target, ctx.round_no, budget_seconds)
    except (OSError, TypeError, ValueError) as exc:
        error = {"status": "invalid-round-budget", "error": str(exc),
                 "claim_status": "not-a-finding"}
        # execution-budget.json is the create-once canonical deadline. An
        # invalid retry must never overwrite the previously valid budget.
        ctx.store.write_artifact("S0", "execution-budget-status.json", error)
        print("[pipeline] refusing round: %s" % exc)
        return
    ctx._round_budget_record = round_budget
    remaining_seconds = max(
        0.001, float(round_budget_snapshot(round_budget).get(
            "remaining_seconds", budget_seconds)))
    configured_slots = getattr(ctx.config, "max_candidates", 8) or 8
    try:
        candidate_slots = max(1, int(configured_slots))
    except (TypeError, ValueError):
        candidate_slots = 8
    ctx.work_budget = WorkBudget(
        name="audit-round", wall_seconds=remaining_seconds,
        scan_files=500_000, scan_bytes=4 * 1024 * 1024 * 1024,
        process_slots=128, candidate_slots=candidate_slots,
        llm_calls=(getattr(ctx.llm, "max_calls", None)
                   if ctx.llm is not None else None))
    if ctx.llm is not None and hasattr(ctx.llm, "set_work_budget"):
        ctx.llm.set_work_budget(ctx.work_budget)
    try:
        source_root = workspace_target_root(ctx.workspace, ctx.target)
        register_active_audit(
            source_root, ctx.workspace, ctx.target, ctx.round_no,
            str(round_budget_snapshot(round_budget)["deadline_at"]))
    except (OSError, TypeError, ValueError) as exc:
        error = {"status": "invalid-round-guard", "error": str(exc),
                 "claim_status": "not-a-finding"}
        ctx.store.write_artifact("S0", "execution-budget-status.json", error)
        print("[pipeline] refusing round without active-audit guard: %s" % exc)
        return
    ctx._active_audit_guard_registered = True

    def stop_at_deadline(last_completed: Optional[str], next_stage: Optional[str],
                         snapshot: Dict[str, Any]) -> None:
        report = {
            "status": "stopped-at-round-deadline",
            "last_completed_stage": last_completed,
            "next_stage": next_stage,
            "completed_stages": [s for s in ctx.store.completed_stages()
                                 if s in STAGES],
            "audit_budget": snapshot,
            "candidate_count": len(ctx.config.candidates),
            "coverage": ctx.store.read_artifact(
                "S1", "coverage-summary.json") or {},
            "claim_status": "not-a-finding",
        }
        ctx.store.write_artifact("S0", "execution-budget-status.json", snapshot)
        ctx.store.write_artifact("S0", "round-timebox-report.json", report)
        ctx.store.save_stage("S0", report)
        print("[pipeline] round deadline expired; preserved artifacts and stopped")

    state: Dict[str, Any] = {}
    invalidate_following = False
    policy_fields = {
        "S1": ("coverage_policy_version", SOURCE_INVENTORY_POLICY_VERSION),
        "S4": ("evidence_policy_version", S4_EVIDENCE_POLICY_VERSION),
        "S5": ("query_policy_version", NOVELTY_QUERY_POLICY_VERSION),
        "S6": ("evidence_policy_version", S4_EVIDENCE_POLICY_VERSION),
        "S7": ("evidence_policy_version", S4_EVIDENCE_POLICY_VERSION),
        "S8": ("evidence_policy_version", S4_EVIDENCE_POLICY_VERSION),
    }
    pending_invalidations = _pending_stage_invalidations(ctx)
    invalidated_stages = set(pending_invalidations["pending_stages"])
    if only:
        prerequisites = STAGES[:STAGES.index(only)]
        issues = []
        s1_coverage = ctx.store.read_artifact(
            "S1", "coverage-summary.json") or {}
        partial_scope = (_coverage_scope_incomplete(s1_coverage)
                         if prerequisites else False)
        if (partial_scope and not bool(getattr(
                ctx.config, "allow_partial_coverage", False))):
            issues.append("S1 coverage is incomplete and partial rounds are disabled")
        if only in invalidated_stages:
            # This is the stage that was marked stale, so it may be rebuilt
            # alone if all of its prerequisites are current.
            invalidated_stages.discard(only)
        for previous in prerequisites:
            saved = ctx.store.load_stage(previous)
            if saved is None:
                issues.append("missing %s checkpoint" % previous)
                continue
            if previous in invalidated_stages:
                issues.append("%s checkpoint is pending recomputation" % previous)
            if not _checkpoint_scope_matches(saved, partial_scope):
                issues.append("%s checkpoint has incompatible coverage scope" % previous)
            if previous in policy_fields:
                field, current = policy_fields[previous]
                if saved.get(field) != current:
                    issues.append("%s checkpoint has stale %s" % (previous, field))
        if "S1" in prerequisites and not ctx.store.artifact_path(
                "S1", "coverage-summary.json").is_file():
            issues.append("missing S1 coverage-summary.json")
        if "S2" in prerequisites:
            s2 = ctx.store.load_stage("S2") or {}
            if not isinstance(s2.get("candidates"), list):
                issues.append("S2 checkpoint has no scheduled candidate selection")
        required_artifacts = {
            "S5": (("S4", "verification-matrix.json"),),
            "S6": (("S4", "verification-matrix.json"),
                   ("S5", "novelty.json")),
            "S7": (("S4", "verification-matrix.json"),
                   ("S5", "novelty.json"), ("S6", "severity.json")),
            "S8": (("S4", "verification-matrix.json"),
                   ("S5", "novelty.json"), ("S6", "severity.json")),
        }
        for source, name in required_artifacts.get(only, ()):
            if not ctx.store.artifact_path(source, name).is_file():
                issues.append("missing %s/%s" % (source, name))
        if issues:
            report = {
                "status": "incompatible-stage-resume",
                "requested_stage": only,
                "issues": issues,
                "next_action": "resume the full pipeline from the earliest stale stage",
                "claim_status": "not-a-finding",
            }
            ctx.store.write_artifact("S0", "resume-prerequisite-report.json", report)
            print("[pipeline] stopping before %s: %s" % (only, "; ".join(issues)))
            return
        # A stage-only resume must use the exact scheduled selection. Restore
        # S3's enriched copy when present, otherwise fall back to S2's selection.
        if STAGES.index(only) > STAGES.index("S2"):
            candidates = None
            for previous in reversed(prerequisites):
                saved = ctx.store.load_stage(previous) or {}
                if isinstance(saved.get("candidate_state"), list):
                    candidates = saved["candidate_state"]
                    break
            if candidates is None:
                candidates = (ctx.store.load_stage("S2") or {}).get("candidates")
            if isinstance(candidates, list):
                ctx.config.candidates = candidates
    for stage_index, stage in enumerate(stages):
        budget_snapshot = round_budget_snapshot(round_budget)
        ctx.store.write_artifact("S0", "execution-budget-status.json", budget_snapshot)
        if budget_snapshot["expired"]:
            completed = [s for s in ctx.store.completed_stages() if s in STAGES]
            stop_at_deadline(completed[-1] if completed else None,
                             stage, budget_snapshot)
            return
        incomplete_scope = False
        if stage != "S1":
            s1_coverage = ctx.store.read_artifact(
                "S1", "coverage-summary.json") or {}
            incomplete_scope = _coverage_scope_incomplete(s1_coverage)
            if (incomplete_scope
                    and not bool(getattr(ctx.config,
                                         "allow_partial_coverage", False))):
                print("[pipeline] stopping before %s: S1 coverage is incomplete; "
                      "set allow_partial_coverage=true for configured-candidate "
                      "validation" % stage)
                return
            if only:
                # A stage-only invocation reads earlier artifacts directly.
                # Rebuilding S1 alone must not make old partial artifacts
                # eligible for a complete S6/S8 closure (or the reverse).
                mismatched = [
                    previous for previous in STAGES[1:STAGES.index(stage)]
                    if (prior := ctx.store.load_stage(previous)) is not None
                    and not _checkpoint_scope_matches(prior, incomplete_scope)
                ]
                if mismatched:
                    ctx.store.write_artifact("S0", "resume-scope-report.json", {
                        "status": "incompatible-checkpoint-scope",
                        "requested_stage": stage,
                        "rerun_from_stage": mismatched[0],
                        "incompatible_stages": mismatched,
                        "claim_status": "not-a-finding",
                    })
                    print("[pipeline] stopping before %s: %s checkpoints belong "
                          "to a different coverage mode; resume the full pipeline "
                          "to recompute them" % (stage, ", ".join(mismatched)))
                    return
        cached = (ctx.store.load_stage(stage)
                  if (not force and not invalidate_following
                      and stage not in invalidated_stages) else None)
        if cached is None and not force and stage != only:
            invalidate_following = True
        if cached is not None and stage in policy_fields:
            field, current = policy_fields[stage]
            if cached.get(field) != current:
                print("[pipeline] %s checkpoint predates %s=%s; recomputing" % (
                    stage, field, current))
                cached = None
                invalidate_following = True
        if (cached is not None and stage != "S1"
                and not _checkpoint_scope_matches(cached, incomplete_scope)):
            print("[pipeline] %s checkpoint belongs to a different coverage mode; "
                  "recomputing downstream stages" % stage)
            cached = None
            invalidate_following = True
        if not force and cached and stage != only:
            if stage == "S2" and cached and "candidates" in cached:
                # S2 may have materialized fix-completeness candidates from
                # S1 git history; restore them before S3-S8 resume.
                ctx.config.candidates = cached["candidates"]
            elif stage == "S3" and isinstance(cached.get("candidate_state"), list):
                ctx.config.candidates = cached["candidate_state"]
            print("[pipeline] %s already complete (resume) - skipping" % stage)
            continue
        print("[pipeline] running %s ..." % stage)
        if stage == "S1":
            data = run_s1(ctx)
        elif stage == "S2":
            data = run_s2(ctx)
            # S3-S8 consume the scheduled selection, including generated
            # control/differential candidates; deferred candidates stay in
            # the config on disk for a later round.
            ctx.config.candidates = data["candidates"]
        elif stage == "S3":
            data = run_s3(ctx)
            data["candidate_state"] = ctx.config.candidates
        elif stage == "S4":
            # Scope/checkpoint I/O may have consumed time since the stage
            # boundary check. Allocate from a fresh snapshot immediately
            # before dispatch, and do not permanently shrink the user's config.
            budget_snapshot = round_budget_snapshot(round_budget)
            if budget_snapshot["expired"]:
                completed = [s for s in ctx.store.completed_stages() if s in STAGES]
                stop_at_deadline(completed[-1] if completed else None,
                                 stage, budget_snapshot)
                return
            remaining = max(1, int(budget_snapshot["remaining_seconds"]))
            original_round = ctx.config.s4_timeout_seconds
            original_candidate = ctx.config.s4_candidate_timeout_seconds
            try:
                ctx.config.s4_timeout_seconds = min(
                    max(1, int(original_round)), remaining)
                ctx.config.s4_candidate_timeout_seconds = min(
                    max(1, int(original_candidate)), remaining)
                data = run_s4(ctx)
            finally:
                ctx.config.s4_timeout_seconds = original_round
                ctx.config.s4_candidate_timeout_seconds = original_candidate
            state["summaries"] = data["summaries"]
        elif stage == "S5":
            data = run_s5(ctx)
            state["novelties"] = data["novelty"]
        elif stage == "S6":
            summaries = state.get("summaries") or (ctx.store.read_artifact("S4", "verification-matrix.json") or {})
            conclusions = _conclusions(ctx, summaries)
            state["conclusions"] = conclusions
            data = run_s6(ctx, summaries, conclusions)
            state["severities"] = data["severity"]
        elif stage == "S7":
            summaries = state.get("summaries") or (ctx.store.read_artifact("S4", "verification-matrix.json") or {})
            conclusions = state.get("conclusions") or _conclusions(ctx, summaries)
            severities = state.get("severities") or (ctx.store.read_artifact("S6", "severity.json") or {})
            rows = _ledger_rows(ctx, summaries, conclusions, severities)
            data = run_s7(ctx, rows, summaries, severities)
        elif stage == "S8":
            summaries = state.get("summaries") or (ctx.store.read_artifact("S4", "verification-matrix.json") or {})
            conclusions = state.get("conclusions") or _conclusions(ctx, summaries)
            novelties = state.get("novelties") or (ctx.store.read_artifact("S5", "novelty.json") or {})
            severities = state.get("severities") or (ctx.store.read_artifact("S6", "severity.json") or {})
            data = run_s8(ctx, summaries, conclusions, novelties, severities)
        else:
            raise ValueError("unknown stage %s" % stage)
        if (stage == "S1" and isinstance(data, dict)
                and _coverage_scope_incomplete(data.get("coverage"))):
            if not bool(getattr(ctx.config, "allow_partial_coverage", False)):
                print("[pipeline] stopping after S1: coverage inventory is incomplete; "
                      "set allow_partial_coverage=true for a configured-candidate "
                      "partial round, or narrow source_dirs and rerun")
                ctx.store.save_stage(stage, data)
                return
            print("[pipeline] S1 coverage is incomplete; continuing configured-candidate "
                  "partial audit (coverage claims disabled)")
        round_partial = incomplete_scope
        if stage == "S1" and isinstance(data, dict):
            round_partial = _coverage_scope_incomplete(data.get("coverage"))
        if round_partial and isinstance(data, dict):
            marker = data.get("coverage_scope")
            marker = dict(marker) if isinstance(marker, dict) else {}
            marker.update({
                "state": "scope-incomplete",
                "partial_audit": True,
                "claim_status": "not-a-finding",
            })
            data["coverage_scope"] = marker
        ctx.store.save_stage(stage, data)
        print("[pipeline] %s done" % stage)
        if only and stage == only:
            descendants = list(STAGES[STAGES.index(stage) + 1:])
            pending = list(dict.fromkeys(
                [item for item in pending_invalidations["pending_stages"]
                 if item != stage] + descendants))
            sources = list(dict.fromkeys(
                pending_invalidations["sources"] + [stage]))
            ctx.store.write_artifact("S0", "stage-resume-invalidations.json", {
                "status": "downstream-stages-pending",
                "source_stage": stage,
                "pending_stages": pending,
                "sources": sources,
                "claim_status": "not-a-finding",
            })
        budget_snapshot = round_budget_snapshot(round_budget)
        ctx.store.write_artifact("S0", "execution-budget-status.json", budget_snapshot)
        if budget_snapshot["expired"]:
            next_stage = (stages[stage_index + 1]
                          if stage_index + 1 < len(stages) else None)
            stop_at_deadline(stage, next_stage, budget_snapshot)
            return
        if (stage == "S4" and isinstance(data, dict)
                and (data.get("execution_budget") or {}).get("round_exhausted")):
            summaries = data.get("summaries") or {}
            ctx.store.write_artifact("S4", "round-timebox-report.json", {
                "status": "stopped-at-s4-timebox",
                "round_timeout": data.get("execution_budget", {}),
                "candidates": {
                    cid: {
                        key: summary.get(key)
                        for key in ("execution_state", "cells_ran",
                                    "cells_attempted", "stop_loss_cell_count",
                                    "evidence_gap", "validation_issues")
                        if key in summary
                    }
                    for cid, summary in summaries.items()
                },
                "claim_status": "not-a-finding",
            })
            print("[pipeline] stopping after S4 timebox; preserved completed cells and gaps")
            return
    s8 = ctx.store.load_stage("S8") or {}
    closure = s8.get("coverage") if isinstance(s8, dict) else None
    if isinstance(closure, dict):
        print("[pipeline] round evidence recorded; coverage=%s high-risk-uncovered=%s"
              % (closure.get("state", "coverage-unknown"),
                 closure.get("high_risk_uncovered", "?")))
    else:
        print("[pipeline] round evidence recorded; coverage closure unavailable")
    if not only:
        ctx.store.write_artifact("S0", "stage-resume-invalidations.json", {
            "status": "clear", "pending_stages": [], "sources": [],
            "claim_status": "not-a-finding",
        })


def _ledger_rows(ctx: StageContext, summaries: Dict[str, Any],
                 conclusions: Dict[str, str], severities: Dict[str, Any]) -> list:
    rows = []
    for cand in ctx.config.candidates:
        cid = cand["candidate_id"]
        summary = summaries.get(cid, {})
        row = {
            "candidate_id": cid,
            "surface": cand["surface"],
            "conclusion": conclusions.get(cid, "候选（待验证）"),
            "evidence": _evidence_lines(summary),
            "precondition_tier": cand.get("precondition_tier_hint", ""),
            "code_location": cand.get("code_location", []),
            "status": conclusion_status(conclusions.get(cid, "候选（待验证）")),
        }
        if g5_record_valid(severities.get(cid)):
            row["cvss"] = {"vector": severities[cid]["vector"], "score": severities[cid]["score"]}
            if severities[cid].get("blocked"):
                row["conclusion"] = "候选（待验证）"
                row.setdefault("evidence", []).append(
                    "G5_BLOCKED=" + "; ".join(severities[cid].get("g5", {}).get("evidence", [])))
                row["status"] = conclusion_status(row["conclusion"])
        rows.append(row)
    return rows


def _evidence_lines(summary: Dict[str, Any]) -> list:
    lines = []
    if summary.get("harness_error"):
        lines.append("HARNESS_ERROR=" + str(summary["harness_error"]))
    if summary.get("compile_error"):
        lines.append("COMPILE_ERROR=" + str(summary["compile_error"]))
    if summary.get("execution_state"):
        lines.append("S4_EXECUTION_STATE=" + str(summary["execution_state"]))
    if summary.get("s4_result_sources"):
        lines.append("S4_RESULT_SOURCES=" + ",".join(summary["s4_result_sources"]))
    for claim in summary.get("poc_claims", [])[:4]:
        lines.append("POC_CLAIM_UNTRUSTED=%s" % json.dumps(
            claim.get("fields", {}), ensure_ascii=False, separators=(",", ":"))[:360])
    for i in summary.get("instantiated", [])[:4]:
        lines.append("%s Safe=%s %s -> INSTANTIATED %s" % (i["version"], i["safe"], i["precondition"], i["class"]))
    for e in summary.get("errors", [])[:6]:
        lines.append("%s Safe=%s %s -> ERROR %s" % (e["version"], e["safe"], e["precondition"], e["error"]))
    for g in summary.get("gate_blocked", [])[:4]:
        lines.append("%s Safe=%s %s -> GATE_BLOCKED %s" % (g["version"], g["safe"], g["precondition"], g["class"]))
    for c in summary.get("safe_equivalent", [])[:4]:
        lines.append("%s Safe=%s %s -> SAFE_EQUIVALENT %s %s" % (
            c["version"], c["safe"], c["precondition"], c["kind"], c.get("detail", "")))
    for e in summary.get("effect_evidence", [])[:4]:
        lines.append("%s Safe=%s %s -> EFFECT_KIND=%s EFFECT=%s" % (
            e["version"], e["safe"], e["precondition"], e["kind"], e.get("detail", "")))
    for a in summary.get("availability_proof", [])[:2]:
        lines.append("%s Safe=%s %s -> AVAILABILITY_PROOF concurrency=%s service_unavailable=%s" % (
            a["version"], a["safe"], a["precondition"], a["concurrency"], a["service_unavailable"]))
    for a in summary.get("authz_results", [])[:8]:
        az = a.get("authz", {})
        lines.append("%s Safe=%s %s -> AUTHZ_CASE=%s principal=%s role=%s tenant=%s object=%s assertion=%s boundary_violation=%s" % (
            a.get("version"), a.get("safe"), a.get("precondition"),
            az.get("case_id", "?"), az.get("principal", "?"), az.get("role", "?"),
            az.get("tenant_id", "?"), az.get("object_id", "?"),
            a.get("status", "?"), a.get("boundary_violation", False)))
    for residual in summary.get("residual_falsifiers", [])[:8]:
        lines.append("RESIDUAL=%s status=%s falsifier=%s execution=%s effect=%s" % (
            residual.get("residual_id", "?"), residual.get("status", ""),
            residual.get("falsifier_code", ""),
            residual.get("execution_state", ""),
            residual.get("effect_observed", False)))
    for issue in summary.get("validation_issues", [])[:4]:
        lines.append("VALIDATION_ISSUE=%s" % issue)
    lines.append("cells_ran=%d" % summary.get("cells_ran", 0))
    return lines


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="VulnGate pipeline")
    ap.add_argument("--target", required=True)
    ap.add_argument("--round", type=int, required=True)
    ap.add_argument("--config", required=True, help="path to target JSON config (regression config)")
    ap.add_argument("--stage", choices=["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8"])
    ap.add_argument("--offline", action="store_true", help="do not hit GitHub API; fixtures only")
    ap.add_argument("--force", action="store_true", help="re-run stages even if checkpoint exists")
    ap.add_argument("--llm-audit", action="store_true",
                    help="enable S5b mechanism audit (LLM; requires DEEPSEEK_API_KEY)")
    ap.add_argument("--workspace", default=None,
                    help="override the workspace root (default: <repo>/scripts). "
                         "Use a separate audit directory to isolate checkpoints "
                         "and keep evidence outside the installed plugin cache.")
    args = ap.parse_args(argv)

    config = TargetConfig.load(Path(args.config))
    llm = None
    if args.llm_audit:
        from ..llm.adapter import LLMClient
        llm = LLMClient(max_calls=8, max_tokens_total=20_000, reasoning_effort="low")
        config.llm_audit = True
    workspace = Path(args.workspace).expanduser().resolve() if args.workspace else WORKSPACE
    ctx = StageContext(workspace, args.target, args.round, config,
                       offline=args.offline, llm=llm)
    from ..analysis.audit_budget import round_budget_snapshot
    from ..analysis.audit_guard import release_active_audit
    ctx._active_audit_guard_registered = False
    workspace_root = Path(workspace).expanduser().resolve(strict=False)
    target_root = workspace_root / "targets" / str(args.target)
    source_root = (target_root.resolve(strict=False) if target_root.is_dir()
                   else workspace_root)
    try:
        run_round(ctx, force=args.force, only=args.stage)
    finally:
        if getattr(ctx, "_active_audit_guard_registered", False):
            try:
                budget_record = getattr(ctx, "_round_budget_record", None)
                if budget_record is None:
                    raise ValueError("round budget record is unavailable")
                if round_budget_snapshot(budget_record)["expired"]:
                    print("[pipeline] expired source root remains guarded; "
                          "release it after writing the progress report")
                else:
                    # Exact-root match prevents releasing another scope that
                    # happens to reuse this target/round identity.
                    release_active_audit(
                        workspace, args.target, args.round, root=source_root)
            except (OSError, TypeError, ValueError) as exc:
                print("[pipeline] could not release active-audit guard: %s" % exc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
