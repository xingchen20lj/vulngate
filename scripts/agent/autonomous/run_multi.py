"""Multi-target driver (plan 2.2): --targets a,b,c serial/parallel scheduling
with a unified ledger aggregating confirmations/exclusions/costs per target.

Usage:
    python3 -m agent.autonomous.run_multi --targets jackson,kryo,xstream \
        --round 1 --max-calls 40 --max-candidates 4 --max-rounds 3 \
        --reasoning-effort low --lang zh [--parallel]

Each target gets its own LLMClient (independent call budget) and its own
state/<target>/ ledger; a unified summary is written to
ledger/multi-<targets>/<timestamp>-summary.md + summary.json.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..llm.adapter import BudgetExceeded, LLMClient
from ..orchestrator.config import TargetConfig
from .run_agent import AutoCtx, ROOT, run_loop


def _find_config(root: Path, name: str) -> Path:
    candidates = [
        root / "agent" / "regression" / "configs" / (name + "-auto.json"),
        root / "agent" / "regression" / "configs" / (name + ".json"),
    ]
    for p in candidates:
        if p.exists():
            return p
    raise FileNotFoundError(
        "no config for target '%s': expected %s or %s"
        % (name, candidates[0], candidates[1]))


def run_one(args: argparse.Namespace, name: str) -> Dict[str, Any]:
    """Run one target's autonomous loop; returns aggregated summary dict."""
    cfg = TargetConfig.load(_find_config(ROOT, name))
    round_no = _next_round(ROOT, name, args)
    llm = LLMClient(model=args.model, max_calls=args.max_calls,
                    max_tokens_total=args.max_tokens,
                    reasoning_effort=args.reasoning_effort)
    if args.lang:
        cfg.output_lang = args.lang
    ctx = AutoCtx(ROOT, cfg, llm, offline=args.offline,
                  max_candidates=args.max_candidates, max_rounds=args.max_rounds,
                  fuzz_budget=args.fuzz_budget, fuzz_seed=args.fuzz_seed,
                  fuzz_force=args.fuzz_force,
                  fuzz_skip_minimize=args.fuzz_skip_minimize)
    t0 = time.time()
    rounds_done = run_loop(ctx, round_no)
    elapsed = time.time() - t0
    usage = llm.usage.to_dict()
    return {
        "target": name,
        "rounds_done": len(rounds_done),
        "rounds": [r for r in rounds_done if r.get("next_candidates")],
        "round_start": round_no,
        "round_end": round_no + len(rounds_done),  # exclusive
        "llm_usage": usage,
        "elapsed_s": round(elapsed, 1),
    }


def _next_round(root: Path, name: str, args: argparse.Namespace) -> int:
    """Avoid clobbering existing rounds: auto-advance unless --overwrite."""
    state_dir = root / "state" / name
    existing = []
    if state_dir.exists():
        for d in state_dir.glob("round-*"):
            m = re.fullmatch(r"round-(\d+)", d.name)
            if m:
                existing.append(int(m.group(1)))
    if not existing:
        return args.round
    if args.round in existing and not args.overwrite:
        nxt = max(existing) + 1
        print("[multi] %s: round %d already exists; auto-advancing to round %d "
              "(use --overwrite to force)" % (name, args.round, nxt))
        return nxt
    return args.round


def _summarize(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Read per-target ledger.json (round-<start>..round-<start+n>) for stats."""
    out = []
    for r in rows:
        target = r["target"]
        # ledger/<target>/round-*/ledger.json has per-round metrics
        rounds_dir = ROOT / "ledger" / target
        confirmed = excluded = candidates = 0
        for rd in sorted(rounds_dir.glob("round-*")):
            try:
                rno = int(rd.name.split("-")[1])
            except (IndexError, ValueError):
                continue
            if not (r["round_start"] <= rno < r["round_end"]):
                continue
            ledger_p = rd / "ledger.json"
            if not ledger_p.exists():
                continue
            try:
                d = json.loads(ledger_p.read_text(encoding="utf-8"))
            except Exception:
                continue
            m = (d.get("summary") or {}).get("metrics") or {}
            candidates += int(m.get("候选数", 0))
            confirmed += int(m.get("确认数", 0))
            excluded += int(m.get("排除数", 0))
        u = r["llm_usage"]
        real = u.get("prompt_tokens", 0) * 0.14 / 1e6 + u.get("completion_tokens", 0) * 0.28 / 1e6
        out.append({
            "target": target,
            "rounds": r["rounds_done"],
            "candidates": candidates,
            "confirmed": confirmed,
            "excluded": excluded,
            "llm_calls": u.get("calls", 0),
            "tokens": u.get("total_tokens", 0),
            "estimated_usd": round(u.get("estimated_usd", 0.0), 4),
            "real_usd_flash": round(real, 4),
            "elapsed_s": r["elapsed_s"],
        })
    return out


def _render_md(stats: List[Dict[str, Any]]) -> str:
    lines = [
        "# 多目标并行汇总（2.2 · %s）" % datetime.now().strftime("%Y-%m-%d %H:%M"),
        "",
        "| 目标 | 轮次 | 候选 | 确认 | 排除 | LLM 调用 | token | 估算$ | 真实$(flash) | 耗时s |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    tc = tx = tk = te = tr = 0
    for s in stats:
        lines.append("| %s | %d | %d | %d | %d | %d | %d | %.4f | %.4f | %.1f |" % (
            s["target"], s["rounds"], s["candidates"], s["confirmed"], s["excluded"],
            s["llm_calls"], s["tokens"], s["estimated_usd"], s["real_usd_flash"],
            s["elapsed_s"]))
        tc += s["candidates"]; tx += s["excluded"]; tk += s["tokens"]
        te += s["estimated_usd"]; tr += s["real_usd_flash"]
    lines.append("| **合计** | **%d** | **%d** | **%d** | **%d** | **%d** | **%d** | **%.4f** | **%.4f** | — |" % (
        sum(s["rounds"] for s in stats), tc,
        sum(s["confirmed"] for s in stats), tx,
        sum(s["llm_calls"] for s in stats), tk, te, tr))
    lines += ["", "> 注：确认数来自各目标 S8 ledger（自治判定，未经人工复核）；",
              "> 新库结论须对照 reports/<target>/round-*/人工对照*.md。"]
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Multi-target autonomous scheduling (plan 2.2)")
    ap.add_argument("--targets", required=True,
                    help="comma-separated target names, e.g. jackson,kryo,xstream")
    ap.add_argument("--round", type=int, default=1)
    ap.add_argument("--max-calls", type=int, default=40)
    ap.add_argument("--max-tokens", type=int, default=300_000)
    ap.add_argument("--max-candidates", type=int, default=4)
    ap.add_argument("--max-rounds", type=int, default=3)
    ap.add_argument("--model", default=None)
    ap.add_argument("--reasoning-effort", default=None)
    ap.add_argument("--lang", default=None, choices=["zh", "en"])
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--parallel", action="store_true",
                    help="run targets concurrently (ThreadPoolExecutor); default serial")
    ap.add_argument("--fuzz-budget", type=int, default=0)
    ap.add_argument("--fuzz-seed", type=int, default=None)
    ap.add_argument("--fuzz-force", action="store_true")
    ap.add_argument("--fuzz-skip-minimize", action="store_true")
    ap.add_argument("--overwrite", action="store_true",
                    help="allow overwriting existing round dirs (default: auto-advance)")
    args = ap.parse_args(argv)

    names = [n.strip() for n in args.targets.split(",") if n.strip()]
    if not names:
        ap.error("--targets must list at least one target")

    rows: List[Dict[str, Any]] = []
    if args.parallel:
        print("[multi] parallel mode: %s" % ", ".join(names))
        with ThreadPoolExecutor(max_workers=len(names)) as pool:
            futures = {pool.submit(run_one, args, n): n for n in names}
            for fut in as_completed(futures):
                n = futures[fut]
                try:
                    rows.append(fut.result())
                    print("[multi] %s done" % n)
                except Exception as exc:
                    print("[multi] %s FAILED: %s" % (n, exc))
    else:
        print("[multi] serial mode: %s" % ", ".join(names))
        for n in names:
            try:
                rows.append(run_one(args, n))
                print("[multi] %s done" % n)
            except Exception as exc:
                print("[multi] %s FAILED: %s" % (n, exc))

    if not rows:
        print("[multi] no target completed")
        return 1

    stats = _summarize(rows)
    md = _render_md(stats)
    out_dir = ROOT / "ledger" / ("multi-%s" % "-".join(names))
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    (out_dir / ("%s-summary.md" % stamp)).write_text(md, encoding="utf-8")
    (out_dir / ("%s-summary.json" % stamp)).write_text(
        json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8")

    print("\n==== multi-target summary ====")
    print(md)
    print("\nledger: %s/" % out_dir)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
