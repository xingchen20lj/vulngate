#!/usr/bin/env python3
"""VulnGate plugin CLI — deterministic helpers for the host Codex agent.

The host agent owns reasoning (S2/S3/S5 judgment). This CLI only executes
deterministic work: source mapping, PoC matrix runs, novelty evaluation,
CVSS computation, and ledger rendering.

Usage:
  agent_cli.py doctor
  agent_cli.py source-map --root <dir> [--pattern <regex>]
  agent_cli.py source-evidence --root <dir> --file <rel> [--line N|--class-header]
  agent_cli.py matrix --workspace <dir> --target <name> --round <N> [--manifest <json>]
                           [--authorized-staging --staging-host <host>]
  agent_cli.py audit-budget start|status <target> --workspace <dir> --round <N>
  agent_cli.py audit-exec <target> --workspace <dir> --root <source-root> \
                           --round <N> [--cwd <relative-dir>] [--timeout <seconds>] -- <argv...>
  agent_cli.py novelty --query <json> [--fixtures <dir>] [--offline] [--cache <dir>]
  agent_cli.py novelty --evidence <json>
  agent_cli.py cvss --vector <CVSS:3.1/...> [--tier <tier>] [--implicit-default-on]
  agent_cli.py ledger --workspace <dir> --target <name> --round <N> --entries <json>
  agent_cli.py deps --target <dir> [--out <report.md>] [--offline] [--cache <dir>]
  agent_cli.py benchmark --manifest <gold.json> [--run <run.json>] [--out <result.json>]
                           [--feedback-out <feedback.json>] [--json]
  agent_cli.py replay-calibrate <target> --workspace <dir> [--out <result.json>] [--json]
  agent_cli.py replay-pack <target> --workspace <dir> [--round <N> ...]
                           [--out <result.json>] [--json]
  agent_cli.py replay-cohort-calibrate --artifact <calibration.json> \
                           [--artifact <calibration.json> ...] \
                           [--pack <replay-pack.json> ...] \
                           [--project-id <label> ...] [--out <result.json>] [--json]
  agent_cli.py review <target> --workspace <dir> (--research-key <rk>|--candidate-id <id>)
                           --status <accepted|rejected|needs-evidence|scope-corrected>
                           [--reason-code <code>] [--note <text>] [--evidence-ref <ref>]
                           [--next-probe <hint>] [--round <N>] [--json]
  agent_cli.py portfolio <target> --workspace <dir> [--rebuild]
                              [--benchmark-feedback <json>] [--json]
  agent_cli.py research-consistency <target> --workspace <dir> [--rebuild] [--json]
  agent_cli.py research-consistency-actions <target> --workspace <dir> [--rebuild] [--json]
  agent_cli.py research-consistency-rechecks <target> --workspace <dir> [--rebuild] [--json]
  agent_cli.py research-agenda <target> --workspace <dir> [--rebuild] [--json]
  agent_cli.py research-agenda-outcomes <target> --workspace <dir> [--round N]
                           [--rebuild] [--json]
  agent_cli.py research-strategy <target> --workspace <dir> [--rebuild]
                               [--benchmark-feedback <json>] [--json]
  agent_cli.py coverage <target> [--workspace <dir>] [--rebuild] [--show-uncovered]
                           [--json] [--risk high|medium|low] [--category authz]
                           [--module <prefix>] [--lang zh|en]
  agent_cli.py capability <target> [--workspace <dir>] [--rebuild]
                             [--show-candidates] [--json]
  agent_cli.py semantic-paths <target> [--workspace <dir>] [--rebuild]
                               [--show-candidates] [--json]
  agent_cli.py semantic-guards <target> [--workspace <dir>] [--rebuild]
                                [--show-candidates] [--json]
  agent_cli.py semantic-calls <target> [--workspace <dir>] [--rebuild]
                                [--show-candidates] [--json]
  agent_cli.py semantic-controlflow <target> [--workspace <dir>] [--rebuild]
                                [--show-candidates] [--json]
  agent_cli.py semantic-ast <target> [--workspace <dir>] [--rebuild]
                          [--show-candidates] [--json]
  agent_cli.py semantic-transforms <target> [--workspace <dir>] [--rebuild]
                                [--show-candidates] [--json]
  agent_cli.py semantic-bindings <target> [--workspace <dir>] [--rebuild]
                                [--show-candidates] [--json]
  agent_cli.py evidence-provenance <target> [--workspace <dir>] [--rebuild]
                                [--show-candidates] [--json]
  agent_cli.py threat-model <target> [--workspace <dir>] [--rebuild]
                                [--json]
  agent_cli.py spawn-probe --workspace <dir> --target <name> --round <N>
                           (--prepare | --status ok|degraded) [--reply <agent-reply>]
  agent_cli.py parallel-receipt --workspace <dir> --target <name> --round <N>
                           --candidate <id> (--prepare | --status <state> | --verify)
  agent_cli.py staging-exec --authorized-staging --host <ECS> --user <user> ...
  agent_cli.py staging-copy --authorized-staging --host <ECS> --source <file> ...
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# The bundled framework lives at <plugin>/scripts/agent/. Allow running from the
# repo root as well (when the plugin is checked out next to the project).
_PLUGIN_SCRIPTS = Path(__file__).resolve().parent
for _candidate in (_PLUGIN_SCRIPTS, _PLUGIN_SCRIPTS.parent.parent):
    if (_candidate / "agent").is_dir() and str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

from agent.tools import source_evidence as se  # noqa: E402
from agent.cli.audit import normalize_audit_exec_argv  # noqa: E402


def _out(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


from agent.cli.runtime import (
    cmd_cleanup,
    cmd_doctor,
    cmd_matrix,
    cmd_service_approval,
    cmd_source_evidence,
    cmd_source_map,
    cmd_staging_copy,
    cmd_staging_exec,
)

from agent.cli.research import (
    cmd_benchmark,
    cmd_cvss,
    cmd_deps,
    cmd_ledger,
    cmd_novelty,
    cmd_portfolio,
    cmd_replay_calibrate,
    cmd_replay_cohort_calibrate,
    cmd_replay_pack,
    cmd_research_agenda,
    cmd_research_agenda_outcomes,
    cmd_research_budget,
    cmd_research_consistency,
    cmd_research_consistency_actions,
    cmd_research_consistency_rechecks,
    cmd_review,
)

def cmd_audit_budget(args: argparse.Namespace) -> int:
    """Start or inspect an immutable host-native round deadline."""
    from agent.analysis.audit_budget import (
        DEFAULT_BUDGET_SECONDS,
        budget_path,
        load_round_budget,
        round_budget_snapshot,
        start_round_budget,
    )
    from agent.analysis.audit_guard import (
        register_active_audit,
        release_active_audit,
    )

    workspace = Path(args.workspace).resolve()
    try:
        source_root = None
        if args.root:
            source_root = Path(args.root).expanduser().resolve(
                strict=args.action != "release")
            if args.action != "release" and not source_root.is_dir():
                raise ValueError("source root must be a directory")
        if args.action == "start" and source_root is None:
            raise ValueError("--root is required to register the active-audit shell guard")
        if args.action == "release":
            if source_root is None:
                raise ValueError("--root is required to release the matching audit guard")
            released = release_active_audit(
                workspace, args.target, args.round, root=source_root)
            payload = {
                "target": args.target,
                "round": args.round,
                "source_root": str(source_root),
                "guard_released": released,
                "claim_status": "not-a-finding",
            }
            if args.json:
                _out(payload)
            else:
                print("audit command guard: %s" % (
                    "released" if released else "no active registration"))
            return 0
        if args.action == "start":
            record = start_round_budget(
                workspace, args.target, args.round,
                args.budget_seconds or DEFAULT_BUDGET_SECONDS)
        else:
            record = load_round_budget(workspace, args.target, args.round)
        payload = round_budget_snapshot(record)
        payload["artifact"] = str(budget_path(
            workspace, args.target, args.round).relative_to(workspace))
        if source_root is not None:
            if payload["expired"]:
                payload["command_guard"] = "expired-blocked-until-release"
            else:
                register_active_audit(
                    source_root, workspace, args.target, args.round,
                    str(payload["deadline_at"]))
                payload["command_guard"] = "registered"
        else:
            payload["command_guard"] = "root-not-specified"
        if args.action == "start":
            payload["start_result"] = record.get("start_result", "started")
    except (OSError, ValueError, TypeError) as exc:
        _out({"error": str(exc), "target": args.target, "round": args.round})
        return 2

    if args.json:
        _out(payload)
    else:
        print("audit-round budget: %s" % payload["artifact"])
        print("  elapsed=%ss remaining=%ss expired=%s" % (
            payload["elapsed_seconds"], payload["remaining_seconds"],
            payload["expired"]))
        print("  command_guard=%s" % payload.get("command_guard", "unknown"))
        if "start_result" in payload:
            print("  start=%s" % payload["start_result"])
    return 3 if payload["expired"] else 0


from agent.cli.audit_exec import cmd_audit_exec

from agent.cli.analysis import (
    cmd_capability,
    cmd_controls,
    cmd_coverage,
    cmd_schedule,
    cmd_semantic_ast,
    cmd_semantic_bindings,
    cmd_semantic_calls,
    cmd_semantic_controlflow,
    cmd_semantic_guards,
    cmd_semantic_paths,
    cmd_semantic_transforms,
    cmd_evidence_provenance,
    cmd_research_strategy,
    cmd_threat_model,
)

from agent.cli.evidence import (
    cmd_differential,
    cmd_parallel_receipt,
    cmd_spawn_probe,
)

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Zero-Day Agent plugin CLI (deterministic helpers)")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor", help="environment check")
    d.add_argument("--json", action="store_true",
                   help="accepted for consistency; doctor output is always JSON")
    d.set_defaults(fn=cmd_doctor)

    cl = sub.add_parser("cleanup", help="clean target-scoped local audit artifacts")
    cl.add_argument("--workspace", required=True)
    cl.add_argument("--target", required=True)
    cl.add_argument("--older-than-days", type=int, default=30)
    cl.add_argument("--all", action="store_true",
                    help="include all target-scoped artifacts, regardless of age")
    cl.add_argument("--apply", action="store_true",
                    help="perform removal; without this flag only a dry-run is printed")
    cl.set_defaults(fn=cmd_cleanup)

    sa = sub.add_parser("service-approval", help="authorize one isolated service start")
    sa.add_argument("--workspace", required=True)
    sa.add_argument("--target", required=True)
    sa.add_argument("--round", type=int, required=True)
    sa.add_argument("--run-id", required=True)
    sa.add_argument("--config-digest", required=True)
    sa.add_argument("--ttl-seconds", type=int, default=300)
    sa.set_defaults(fn=cmd_service_approval)

    sm = sub.add_parser("source-map", help="build entry inventory via rg")
    sm.add_argument("--root", required=True)
    sm.add_argument("--pattern", default=None)
    sm.add_argument("--preset", default=None, choices=sorted(se.SOURCE_MAP_PRESETS))
    sm.add_argument("--max-hits", type=int, default=200)
    sm.add_argument("--source-dir", action="append", default=[],
                    help="explicit source subdirectory to scan (repeatable)")
    sm.add_argument("--globs", default="all", choices=["all", "java"],
                    help="'all' scans Java+Clojure+Python+Go+JS/etc.; 'java' restricts to *.java")
    sm.set_defaults(fn=cmd_source_map)

    se_ = sub.add_parser("source-evidence", help="extract method/class snippet")
    se_.add_argument("--root", required=True)
    se_.add_argument("--file", required=True)
    se_.add_argument("--line", type=int, default=None)
    se_.add_argument("--class-header", action="store_true")
    se_.add_argument("--max-chars", type=int, default=4000)
    se_.set_defaults(fn=cmd_source_evidence)

    mx = sub.add_parser("matrix", help="run PoC matrix from a manifest")
    mx.add_argument("--workspace", required=True)
    mx.add_argument("--target", required=True)
    mx.add_argument("--round", type=int, required=True)
    mx.add_argument("--manifest", default=None)
    mx.add_argument("--lang", default="java", choices=["java", "shell"],
                    help="'java' compiles/runs Java PoCs; 'shell' runs bash PoCs "
                         "(web apps/services) with HTTP_CODE/RESP_MATCH/EVIDENCE contract")
    mx.add_argument("--authorized-staging", action="store_true",
                    help="explicitly allow remote staging targets listed by --staging-host")
    mx.add_argument("--staging-host", action="append", default=[],
                    help="allowlisted ECS/staging hostname or IP; repeat for multiple hosts")
    mx.set_defaults(fn=cmd_matrix)

    common_staging = argparse.ArgumentParser(add_help=False)
    common_staging.add_argument("--workspace", required=True)
    common_staging.add_argument("--target", required=True)
    common_staging.add_argument("--round", type=int, required=True)
    common_staging.add_argument("--authorized-staging", action="store_true")
    common_staging.add_argument("--host", required=True)
    common_staging.add_argument("--user", required=True)
    common_staging.add_argument("--port", type=int, default=22)
    common_staging.add_argument("--timeout", type=int, default=180)

    sx = sub.add_parser("staging-exec", parents=[common_staging],
                        help="run one explicitly authorized SSH staging command")
    sx.add_argument("--command", nargs=argparse.REMAINDER, required=True,
                    help="remote command argv; use -- before the command")
    sx.set_defaults(fn=cmd_staging_exec)

    sc = sub.add_parser("staging-copy", parents=[common_staging],
                        help="copy one workspace file to an authorized staging host")
    sc.add_argument("--source", required=True)
    sc.add_argument("--destination", required=True)
    sc.set_defaults(fn=cmd_staging_copy)

    nv = sub.add_parser("novelty", help="novelty evaluation (live or from evidence)")
    nv.add_argument("--query", default=None)
    nv.add_argument("--evidence", default=None)
    nv.add_argument("--fixtures", default=None)
    nv.add_argument("--offline", action="store_true")
    nv.add_argument("--cache", default=None)
    nv.set_defaults(fn=cmd_novelty)

    cv = sub.add_parser("cvss", help="CVSS score + G5 consistency")
    cv.add_argument("--vector", required=True)
    cv.add_argument("--tier", default=None,
                    choices=["0", "single-feature", "app-cooperation", "extra-primitive"])
    cv.add_argument("--implicit-default-on", action="store_true")
    cv.set_defaults(fn=cmd_cvss)

    lg = sub.add_parser("ledger", help="write round ledger artifacts")
    lg.add_argument("--workspace", required=True)
    lg.add_argument("--target", required=True)
    lg.add_argument("--round", type=int, required=True)
    lg.add_argument("--entries", required=True)
    lg.set_defaults(fn=cmd_ledger)

    dp = sub.add_parser("deps", help="dependency CVE scan (OSV) + fix suggestions")
    dp.add_argument("--target", required=True)
    dp.add_argument("--out", default=None)
    dp.add_argument("--offline", action="store_true")
    dp.add_argument("--cache", default=None)
    dp.set_defaults(fn=cmd_deps)

    bm = sub.add_parser(
        "benchmark",
        help="score research behaviour against a deterministic gold manifest",
    )
    bm.add_argument("--manifest", required=True,
                    help="benchmark JSON with cases and optional embedded runs")
    bm.add_argument("--run", action="append", default=[],
                    help="run JSON; repeat for independent runs")
    bm.add_argument("--out", default=None,
                    help="write the bounded result JSON to this path")
    bm.add_argument("--feedback-out", default=None,
                     help="write deterministic scheduler/planner feedback JSON")
    bm.add_argument("--baseline", default=None,
                    help="previous bounded benchmark result for trend comparison")
    bm.add_argument("--json", action="store_true",
                    help="machine-readable output")
    bm.set_defaults(fn=cmd_benchmark)

    rc = sub.add_parser(
        "replay-calibrate",
        help="calibrate research guidance from bounded real-project round replays",
    )
    rc.add_argument("target", help="target name (state/<target>/...)")
    rc.add_argument("--workspace", required=True,
                    help="workspace root containing state/<target>/")
    rc.add_argument("--out", default=None,
                    help="optional extra copy of the calibration artifact")
    rc.add_argument("--json", action="store_true",
                    help="machine-readable output")
    rc.set_defaults(fn=cmd_replay_calibrate)

    rp = sub.add_parser(
        "replay-pack",
        help="build a provenance-carrying bounded replay pack",
    )
    rp.add_argument("target", help="target name (state/<target>/...)")
    rp.add_argument("--workspace", required=True,
                    help="workspace root containing state/<target>/")
    rp.add_argument("--round", type=int, action="append", default=[],
                    help="optional round number; repeat to build a filtered pack")
    rp.add_argument("--out", default=None,
                    help="optional extra copy of the replay pack")
    rp.add_argument("--json", action="store_true",
                    help="machine-readable output")
    rp.set_defaults(fn=cmd_replay_pack)

    rcc = sub.add_parser(
        "replay-cohort-calibrate",
        help="aggregate bounded replay calibration across independent projects",
    )
    rcc.add_argument("--artifact", action="append", default=[],
                     help="legacy per-target research-replay-calibration-v1 JSON; repeatable")
    rcc.add_argument("--pack", action="append", default=[],
                     help="provenance-carrying research-replay-pack-v1 JSON; repeatable")
    rcc.add_argument("--project-id", action="append", default=[],
                     help="optional opaque label, repeated once per artifact")
    rcc.add_argument("--out", default=None,
                     help="write the cohort artifact to this path")
    rcc.add_argument("--json", action="store_true",
                     help="machine-readable output")
    rcc.set_defaults(fn=cmd_replay_cohort_calibrate)

    rv = sub.add_parser(
        "review",
        help="record bounded human review feedback for a research mechanism",
    )
    rv.add_argument("target", help="target name (state/<target>/...)")
    rv.add_argument("--workspace", required=True,
                    help="workspace root containing state/<target>/")
    identity = rv.add_mutually_exclusive_group(required=True)
    identity.add_argument("--research-key", default=None,
                          help="stable rk-... mechanism key")
    identity.add_argument("--candidate-id", default=None,
                          help="candidate id resolved through research memory")
    rv.add_argument("--status", required=True,
                    choices=["accepted", "rejected", "needs-evidence", "scope-corrected"])
    rv.add_argument("--reason-code", default="needs-source-review",
                    choices=["false-positive", "confirmed-mechanism",
                             "missing-typed-effect", "environment-gap",
                             "scope-correction", "duplicate",
                             "needs-source-review"])
    rv.add_argument("--note", default="", help="bounded reviewer note")
    rv.add_argument("--evidence-ref", action="append", default=[],
                    help="artifact/code reference; repeatable")
    rv.add_argument("--next-probe", action="append", default=[],
                    help="bounded next-probe hint; repeatable")
    rv.add_argument("--round", type=int, default=0,
                    help="review round (default: latest memory round + 1)")
    rv.add_argument("--json", action="store_true",
                    help="machine-readable output")
    rv.set_defaults(fn=cmd_review)

    po = sub.add_parser(
        "portfolio",
        help="show the bounded project research portfolio and next probes",
    )
    po.add_argument("target", help="target name (state/<target>/...)")
    po.add_argument("--workspace", required=True,
                    help="workspace root containing state/<target>/")
    po.add_argument("--rebuild", action="store_true",
                    help="rebuild from current research memory/review feedback")
    po.add_argument("--benchmark-feedback", default=None,
                    help="optional bounded benchmark result/feedback JSON for --rebuild")
    po.add_argument("--json", action="store_true",
                    help="machine-readable output")
    po.set_defaults(fn=cmd_portfolio)

    rc = sub.add_parser(
        "research-consistency",
        help="show or rebuild bounded cross-round evidence consistency metadata",
    )
    rc.add_argument("target", help="target name (state/<target>/...)")
    rc.add_argument("--workspace", required=True,
                    help="workspace root containing state/<target>/")
    rc.add_argument("--rebuild", action="store_true",
                    help="rebuild from current research memory")
    rc.add_argument("--json", action="store_true",
                    help="machine-readable output")
    rc.set_defaults(fn=cmd_research_consistency)

    rca = sub.add_parser(
        "research-consistency-actions",
        help="show or rebuild bounded controlled consistency recheck contracts",
    )
    rca.add_argument("target", help="target name (state/<target>/...)")
    rca.add_argument("--workspace", required=True,
                     help="workspace root containing state/<target>/")
    rca.add_argument("--rebuild", action="store_true",
                     help="rebuild consistency and controlled recheck actions")
    rca.add_argument("--json", action="store_true",
                     help="machine-readable output")
    rca.set_defaults(fn=cmd_research_consistency_actions)

    rcr = sub.add_parser(
        "research-consistency-rechecks",
        help="show or rebuild bounded S4 closure for consistency rechecks",
    )
    rcr.add_argument("target", help="target name (state/<target>/...)")
    rcr.add_argument("--workspace", required=True,
                     help="workspace root containing state/<target>/")
    rcr.add_argument("--round", type=int, default=0,
                     help="specific round to rebuild; default: newest runtime-lab")
    rcr.add_argument("--rebuild", action="store_true",
                     help="rebuild from a bounded runtime-lab artifact")
    rcr.add_argument("--json", action="store_true",
                     help="machine-readable output")
    rcr.set_defaults(fn=cmd_research_consistency_rechecks)

    ra = sub.add_parser(
        "research-agenda",
        help="show or rebuild the bounded active research agenda",
    )
    ra.add_argument("target", help="target name (state/<target>/...)")
    ra.add_argument("--workspace", required=True,
                    help="workspace root containing state/<target>/")
    ra.add_argument("--round", type=int, default=0,
                    help="agenda round; default: strategy round")
    ra.add_argument("--slots", type=int, default=8,
                    help="max selected work items (default: 8)")
    ra.add_argument("--max-per-surface", type=int, default=3,
                    help="max selected items per surface (default: 3)")
    ra.add_argument("--rebuild", action="store_true",
                    help="rebuild from the normalized strategy and portfolio")
    ra.add_argument("--json", action="store_true",
                    help="machine-readable output")
    ra.set_defaults(fn=cmd_research_agenda)

    rao = sub.add_parser(
        "research-agenda-outcomes",
        help="show or rebuild bounded execution feedback for the active agenda",
    )
    rao.add_argument("target", help="target name (state/<target>/...)")
    rao.add_argument("--workspace", required=True,
                     help="workspace root containing state/<target>/")
    rao.add_argument("--round", type=int, default=0,
                     help="round to measure; default: agenda round")
    rao.add_argument("--rebuild", action="store_true",
                     help="rebuild from the agenda, schedule and S4/S8 summaries")
    rao.add_argument("--json", action="store_true",
                     help="machine-readable output")
    rao.set_defaults(fn=cmd_research_agenda_outcomes)

    rb = sub.add_parser(
        "research-budget",
        help="show or rebuild bounded outcome-adaptive research budget policy",
    )
    rb.add_argument("target", help="target name (state/<target>/...)")
    rb.add_argument("--workspace", required=True,
                    help="workspace root containing state/<target>/")
    rb.add_argument("--round", type=int, default=0,
                    help="budget round; default: newest agenda outcome")
    rb.add_argument("--slots", type=int, default=8,
                    help="finite research slots (default: 8)")
    rb.add_argument("--rebuild", action="store_true",
                    help="rebuild from agenda outcomes and prior policy")
    rb.add_argument("--json", action="store_true",
                    help="machine-readable output")
    rb.set_defaults(fn=cmd_research_budget)

    ab = sub.add_parser(
        "audit-budget",
        help="start, inspect, or release the persistent audit deadline and shell guard",
    )
    ab.add_argument("action", choices=["start", "status", "release"],
                    help="start once, inspect, or release an audit round")
    ab.add_argument("target", help="target name (state/<target>/...)")
    ab.add_argument("--workspace", required=True,
                    help="workspace root containing state/<target>/")
    ab.add_argument("--round", type=int, required=True,
                    help="one-based audit round number")
    ab.add_argument("--root", default=None,
                    help="source root to register with the Codex Bash guard")
    ab.add_argument("--budget-seconds", type=int, default=0,
                    help="start duration; maximum 5400 seconds (90 minutes)")
    ab.add_argument("--json", action="store_true",
                    help="machine-readable output")
    ab.set_defaults(fn=cmd_audit_budget)

    ae = sub.add_parser(
        "audit-exec",
        help="run one host-side audit command under the round deadline",
    )
    ae.add_argument("target", help="target name (state/<target>/...)")
    ae.add_argument("--workspace", required=True,
                    help="audit workspace containing the active round deadline")
    ae.add_argument("--root", required=True,
                    help="authorized source root used to check the command cwd")
    ae.add_argument("--round", type=int, required=True,
                    help="one-based audit round with an initialized deadline")
    ae.add_argument("--cwd", default=None,
                    help="working directory under --root; default: --root")
    ae.add_argument("--timeout", type=int, default=600,
                    help="requested timeout; capped by 15 minutes and round time remaining")
    ae.add_argument("--max-output-chars", type=int, default=200000,
                    help="stdout/stderr capture bound (1000-200000)")
    ae.add_argument("--env", action="append", default=[], metavar="KEY=VALUE",
                    help="explicit non-secret environment value; ambient credentials are omitted")
    ae.add_argument("--retry-reason", default="",
                    help="explain why an identical failed/timed-out command is safe to retry")
    ae.add_argument("command", nargs=argparse.REMAINDER,
                    help="command argv; place -- before the executable")
    ae.set_defaults(fn=cmd_audit_exec)

    rs = sub.add_parser(
        "research-strategy",
        help="show or rebuild the bounded cross-artifact research strategy",
    )
    rs.add_argument("target", help="target name (state/<target>/...)")
    rs.add_argument("--workspace", required=True,
                    help="workspace root containing state/<target>/")
    rs.add_argument("--root", default=None,
                    help="target source root; needed by --rebuild when S1 is absent")
    rs.add_argument("--source-dir", action="append", default=[],
                    help="restrict an inventory rebuild (repeatable)")
    rs.add_argument("--target-type", default=None,
                    choices=["library", "web-app", "middleware", "logging",
                             "expression", "message-rpc", "native-app"],
                    help="target type used when rebuilding the strategy")
    rs.add_argument("--rebuild", action="store_true",
                    help="rebuild from threat model, memory and portfolio")
    rs.add_argument("--benchmark-feedback", default=None,
                    help="optional bounded benchmark result/feedback JSON")
    rs.add_argument("--limit", type=int, default=20,
                    help="max strategy items to print (default: 20)")
    rs.add_argument("--json", action="store_true",
                    help="machine-readable output")
    rs.set_defaults(fn=cmd_research_strategy)

    cvr = sub.add_parser(
        "coverage",
        help="security audit coverage report: source/entry/sink/flow ratios + "
             "uncovered high-risk regions",
    )
    cvr.add_argument("target", help="target name (state/<target>/coverage/)")
    cvr.add_argument("--workspace", default=".", help="workspace root (default: cwd)")
    cvr.add_argument("--root", default=None,
                     help="target source root; needed when --rebuild has no index yet")
    cvr.add_argument("--source-dir", action="append", default=[],
                     help="restrict the scan to this source dir (repeatable)")
    cvr.add_argument("--target-type", default=None,
                     choices=["library", "web-app", "middleware", "logging",
                              "expression", "message-rpc", "native-app"],
                     help="adds target-type rule patterns to the entry index")
    cvr.add_argument("--rebuild", action="store_true",
                     help="re-run the full source/entry/sink/control inventory first")
    cvr.add_argument("--scan-timeout-seconds", type=int, default=600,
                     help="stop source enumeration after this many seconds; 0 disables the limit")
    cvr.add_argument("--no-refresh", action="store_true",
                     help="skip re-deriving review state from the round ledgers")
    cvr.add_argument("--json", action="store_true", help="machine-readable output")
    cvr.add_argument("--show-uncovered", action="store_true",
                     help="list uncovered regions (respects --risk/--category/--module)")
    cvr.add_argument("--risk", default=None, choices=["high", "medium", "low"])
    cvr.add_argument("--category", default=None,
                     help="filter uncovered regions by sink/entry/control category")
    cvr.add_argument("--module", default=None,
                     help="filter uncovered regions by file path prefix")
    cvr.add_argument("--limit", type=int, default=40)
    cvr.add_argument("--lang", default="zh", choices=["zh", "en"])
    cvr.add_argument("--schedule", action="store_true",
                     help="also print the latest candidate schedule (spec §13)")
    cvr.set_defaults(fn=cmd_coverage)

    sch = sub.add_parser(
        "schedule",
        help="coverage-aware candidate schedule: weighted score + category quota "
             "+ deferred carry-over (spec §13/§14/§15)",
    )
    sch.add_argument("target", help="target name (state/<target>/coverage/)")
    sch.add_argument("--workspace", default=".", help="workspace root (default: cwd)")
    sch.add_argument("--candidates", default=None,
                     help="candidate pool JSON (bare list, {\"candidates\": [...]}, "
                          "or an S2 candidate-matrix.json)")
    sch.add_argument("--config", default=None,
                     help="target config JSON; its candidates/max_candidates are used")
    sch.add_argument("--slots", type=int, default=0,
                     help="candidate budget for the round (default: config value "
                          "or %d)" % 8)
    sch.add_argument("--priority-candidate", action="append", default=[],
                     help="select this candidate within the round slot budget, "
                          "after runtime pins and before category quotas; repeatable")
    sch.add_argument("--round", type=int, default=0,
                     help="round number, recorded on the plan and in its filename")
    sch.add_argument("--limit-pool", type=int, default=0,
                     help="score only the first N pool entries (debug aid)")
    sch.add_argument("--no-refresh", action="store_true",
                     help="skip the residual sweep before scoring (spec §14)")
    sch.add_argument("--benchmark-result", default=None,
                     help="benchmark result/feedback JSON; affects only bounded "
                          "S2 weights and prompt guidance")
    sch.add_argument("--prompt", action="store_true",
                     help="also print the spec §15 structured prompt block")
    sch.add_argument("--json", action="store_true", help="machine-readable output")
    sch.add_argument("--lang", default="zh", choices=["zh", "en"])
    sch.set_defaults(fn=cmd_schedule)

    def _add_analysis_args(parser: argparse.ArgumentParser) -> None:
        """Options shared by the two PR4 index reports."""
        parser.add_argument("target", help="target name (state/<target>/coverage/)")
        parser.add_argument("--workspace", default=".",
                            help="workspace root (default: cwd)")
        parser.add_argument("--root", default=None,
                            help="target source root; needed when --rebuild has no index yet")
        parser.add_argument("--source-dir", action="append", default=[],
                            help="restrict the scan to this source dir (repeatable)")
        parser.add_argument("--target-type", default=None,
                            choices=["library", "web-app", "middleware", "logging",
                                     "expression", "message-rpc", "native-app"],
                            help="adds target-type rule patterns to the entry index")
        parser.add_argument("--rebuild", action="store_true",
                            help="re-run the full inventory (and this analysis) first")
        parser.add_argument("--json", action="store_true",
                            help="machine-readable output")
        parser.add_argument("--show-candidates", action="store_true",
                            help="also print the generated candidates")
        parser.add_argument("--limit", type=int, default=20,
                            help="max items to list (default: 20)")
        parser.add_argument("--limit-candidates", type=int, default=0,
                            help="cap generated candidates per kind (0 = unlimited)")
        parser.add_argument("--lang", default="zh", choices=["zh", "en"])

    ctlm = sub.add_parser(
        "controls",
        help="security control map (spec §11): Entry -> Sink path verdicts + "
             "possible-auth-bypass / possible-control-bypass candidates",
    )
    _add_analysis_args(ctlm)
    ctlm.set_defaults(fn=cmd_controls)

    dfs = sub.add_parser(
        "differential",
        help="sibling / differential analysis (spec §12): where sibling handlers "
             "disagree about a security control",
    )
    _add_analysis_args(dfs)
    dfs.add_argument("--fix-history", default=None,
                     help="patch-history JSON for the patch sibling diff; "
                          "default: newest state/<target>/round-*/S1/"
                          "security-fix-history.json")
    dfs.set_defaults(fn=cmd_differential)

    cap = sub.add_parser(
        "capability",
        help="capability primitives and bounded attack-path hypotheses; "
             "paths are not findings",
    )
    _add_analysis_args(cap)
    cap.set_defaults(fn=cmd_capability)

    sem = sub.add_parser(
        "semantic-paths",
        help="source-local control-order and same-symbol data-flow evidence; "
             "all outputs are research leads, not findings",
    )
    _add_analysis_args(sem)
    sem.set_defaults(fn=cmd_semantic_paths)

    sg = sub.add_parser(
        "semantic-guards",
        help="bounded branch-posture and subject/object binding evidence; "
             "all outputs are research leads, not findings",
    )
    _add_analysis_args(sg)
    sg.set_defaults(fn=cmd_semantic_guards)

    sc = sub.add_parser(
        "semantic-calls",
        help="bounded one-hop interprocedural argument/return binding evidence; "
             "all outputs are research leads, not findings",
    )
    _add_analysis_args(sc)
    sc.set_defaults(fn=cmd_semantic_calls)

    scf = sub.add_parser(
        "semantic-controlflow",
        help="bounded branch-dominance and alternate-path evidence; "
             "all outputs are research leads, not findings",
    )
    _add_analysis_args(scf)
    scf.set_defaults(fn=cmd_semantic_controlflow)

    sas = sub.add_parser(
        "semantic-ast",
        help="bounded Python-AST branch and scope evidence; all outputs are "
             "research leads, not findings",
    )
    _add_analysis_args(sas)
    sas.set_defaults(fn=cmd_semantic_ast)

    st = sub.add_parser(
        "semantic-transforms",
        help="bounded validation/sanitization result-binding evidence; all "
             "outputs are research leads, not findings",
    )
    _add_analysis_args(st)
    st.set_defaults(fn=cmd_semantic_transforms)

    sb = sub.add_parser(
        "semantic-bindings",
        help="bounded language-aware Python value-binding evidence; all "
             "outputs are research leads, not findings",
    )
    _add_analysis_args(sb)
    sb.set_defaults(fn=cmd_semantic_bindings)

    ep = sub.add_parser(
        "evidence-provenance",
        help="raw/derived static evidence lineage and independence correlation; "
             "all outputs are research metadata, not findings",
    )
    _add_analysis_args(ep)
    ep.set_defaults(fn=cmd_evidence_provenance)

    tm = sub.add_parser(
        "threat-model",
        help="bounded attacker-path threat model; paths are research hypotheses, "
             "not findings",
    )
    _add_analysis_args(tm)
    tm.set_defaults(fn=cmd_threat_model)

    sp = sub.add_parser(
        "spawn-probe",
        help="prepare or verify a challenge-bound S4 spawn preflight probe",
    )
    sp.add_argument("--workspace", required=True)
    sp.add_argument("--target", required=True)
    sp.add_argument("--round", type=int, required=True)
    sp.add_argument("--prepare", action="store_true",
                    help="create a fresh nonce-bound heartbeat/reply challenge")
    sp.add_argument("--token", default="",
                    help="optional URL-safe probe token for --prepare")
    sp.add_argument("--status", choices=["ok", "degraded"], default=None)
    sp.add_argument("--reply", default="", help="observed sub-agent reply (raw)")
    sp.add_argument(
        "--symptom",
        choices=[
            "ok",
            "no-heartbeat-greeting-only",
            "no-heartbeat-timeout",
            "followup-retried-failed",
            "challenge-missing",
            "probe-contract-invalid",
        ],
        default=None,
        help="degraded-mode symptom classification (0.2.13+)",
    )
    sp.add_argument(
        "--followup-retried",
        action="store_true",
        help="a single followup re-delivery was attempted before degrading (0.2.13+)",
    )
    sp.add_argument("--wait-seconds", type=int, default=90,
                    help="probe wait budget in seconds (default 90)")
    sp.set_defaults(fn=cmd_spawn_probe)

    pr = sub.add_parser(
        "parallel-receipt",
        help="prepare, record, or verify a challenge-bound S4 candidate receipt",
    )
    pr.add_argument("--workspace", required=True)
    pr.add_argument("--target", required=True)
    pr.add_argument("--round", type=int, required=True)
    pr.add_argument("--candidate", required=True)
    pr.add_argument("--prepare", action="store_true")
    pr.add_argument("--verify", action="store_true")
    pr.add_argument("--inspect", action="store_true",
                    help="show bounded liveness metadata for the current receipt")
    pr.add_argument("--token", default="")
    pr.add_argument("--status", choices=["received", "progress", "completed", "partial"],
                    default=None)
    pr.add_argument("--progress-step", default="",
                    help="short evidence-producing task step for --status progress")
    pr.add_argument("--artifact", action="append", default=[],
                    help="S4/matrix-runs/<candidate>/ artifact produced by this worker")
    pr.set_defaults(fn=cmd_parallel_receipt)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    # Audit evidence, credentials-free approval logs and local reports are
    # sensitive even when they are ignored by Git.
    os.umask(0o077)
    args = build_parser().parse_args(normalize_audit_exec_argv(argv))
    try:
        return int(args.fn(args) or 0)
    except Exception as exc:  # pragma: no cover - surface harness errors as JSON
        from agent.analysis.languages import SourceScanTimeout
        if isinstance(exc, SourceScanTimeout):
            _out({"status": "incomplete", "scope_complete": False,
                  "error": str(exc), "progress": exc.progress,
                  "claim_status": "not-a-finding"})
            return 2
        _out({"error": "%s: %s" % (type(exc).__name__, exc)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
