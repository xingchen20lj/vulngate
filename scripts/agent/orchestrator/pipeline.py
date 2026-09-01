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
from .gates import g4_runtime, g5_cvss
from .stages import (StageContext, run_s1, run_s2, run_s3, run_s4, run_s5,
                     run_s6, run_s7, run_s8, _derive_conclusion)


WORKSPACE = Path(__file__).resolve().parents[2]


def _conclusions(ctx: StageContext, summaries: Dict[str, Any]) -> Dict[str, str]:
    """Per-candidate conclusion derived from runtime data + audit intent."""
    out: Dict[str, str] = {}
    for cand in ctx.config.candidates:
        cid = cand["candidate_id"]
        summary = summaries.get(cid, {})
        intended = cand.get("intended_conclusion", "确认")
        if intended == "排除" and not summary.get("cells_ran"):
            out[cid] = "候选（待验证）"
            continue
        # Shared conclusion rules need the raw cells for FQCN / OOM / env-error
        # checks; load them from the S4 checkpoint (baseline fix #10).
        cells = ctx.store.read_artifact(
            "S4", "matrix-runs/%s/cells.json" % cid) or []
        derived = _derive_conclusion(cand, summary, cells)
        g4 = g4_runtime(summary, intended, cand)
        if intended == "确认" and not g4.passed and derived != "确认":
            out[cid] = "候选（待验证）"  # hard G4: never claim without runtime
        elif intended == "排除":
            out[cid] = derived if derived in ("排除",) else "排除"
        else:
            out[cid] = derived if derived != "候选（待验证）" else intended
        if intended == "确认" and out[cid] == "确认" and not g4.passed:
            raise SystemExit(
                "G4 VIOLATION: candidate %s claimed confirmed without runtime evidence" % cid)
    return out


def run_round(ctx: StageContext, force: bool = False, only: Optional[str] = None) -> None:
    stages = ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8"]
    if only:
        stages = [only]
    state: Dict[str, Any] = {}
    for stage in stages:
        if not force and ctx.store.load_stage(stage) and stage != only:
            print("[pipeline] %s already complete (resume) - skipping" % stage)
            continue
        print("[pipeline] running %s ..." % stage)
        if stage == "S1":
            data = run_s1(ctx)
        elif stage == "S2":
            data = run_s2(ctx)
        elif stage == "S3":
            data = run_s3(ctx)
        elif stage == "S4":
            data = run_s4(ctx)
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
        ctx.store.save_stage(stage, data)
        print("[pipeline] %s done" % stage)
    print("[pipeline] round complete")


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
        }
        if cid in severities:
            row["cvss"] = {"vector": severities[cid]["vector"], "score": severities[cid]["score"]}
            if severities[cid].get("blocked"):
                row["conclusion"] = "候选（待验证）"
                row.setdefault("evidence", []).append(
                    "G5_BLOCKED=" + "; ".join(severities[cid].get("g5", {}).get("evidence", [])))
        rows.append(row)
    return rows


def _evidence_lines(summary: Dict[str, Any]) -> list:
    lines = []
    if summary.get("harness_error"):
        lines.append("HARNESS_ERROR=" + str(summary["harness_error"]))
    if summary.get("compile_error"):
        lines.append("COMPILE_ERROR=" + str(summary["compile_error"]))
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
    args = ap.parse_args(argv)

    config = TargetConfig.load(Path(args.config))
    llm = None
    if args.llm_audit:
        from ..llm.adapter import LLMClient
        llm = LLMClient(max_calls=8, max_tokens_total=20_000, reasoning_effort="low")
        config.llm_audit = True
    ctx = StageContext(WORKSPACE, args.target, args.round, config,
                       offline=args.offline, llm=llm)
    run_round(ctx, force=args.force, only=args.stage)
    return 0


if __name__ == "__main__":
    sys.exit(main())
