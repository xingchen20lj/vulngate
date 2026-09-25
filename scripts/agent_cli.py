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
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# The bundled framework lives at <plugin>/scripts/agent/. Allow running from the
# repo root as well (when the plugin is checked out next to the project).
_PLUGIN_SCRIPTS = Path(__file__).resolve().parent
for _candidate in (_PLUGIN_SCRIPTS, _PLUGIN_SCRIPTS.parent.parent):
    if (_candidate / "agent").is_dir() and str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

from agent.tools.build import (  # noqa: E402
    JavaMatrixRunner,
    MatrixCell,
    POCSpec,
    ShellMatrixRunner,
    ShellPOCSpec,
    summarize_candidate,
)
from agent.tools.cvss import base_score, check_precondition_consistency  # noqa: E402
from agent.tools.novelty import (  # noqa: E402
    Disclosure,
    NoveltyChecker,
    UpstreamRef,
    upstream_ref_from_search_hit,
)
from agent.tools.github_auth import github_token_source  # noqa: E402
from agent.tools import source_evidence as se  # noqa: E402


def _out(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def cmd_doctor(_args: argparse.Namespace) -> int:
    github_source = github_token_source()
    checks = {
        "python3": shutil.which("python3") is not None,
        "java": shutil.which("java") is not None,
        "javac": shutil.which("javac") is not None,
        "rg": shutil.which("rg") is not None,
        "jar": shutil.which("jar") is not None,
        "GITHUB_TOKEN|GH_TOKEN": github_source != "missing",
    }
    if checks["java"]:
        try:
            ver = subprocess.run(["java", "-version"], capture_output=True,
                                 text=True, timeout=10).stderr.splitlines()
            checks["java_version"] = ver[0] if ver else "unknown"
        except Exception as exc:  # pragma: no cover
            checks["java_version"] = "error: %s" % exc
    missing = [k for k, v in checks.items() if v is False]
    _out({"checks": checks, "github_token_source": github_source, "missing": missing,
          "status": "ok" if not missing else "missing-tools"})
    return 0 if not missing else 2


def cmd_source_map(args: argparse.Namespace) -> int:
    from agent.analysis.languages import resolve_source_dirs

    root = Path(args.root).resolve()
    if args.preset and args.preset not in se.SOURCE_MAP_PRESETS:
        _out({"error": "unknown preset %r; choose from %s"
              % (args.preset, ", ".join(sorted(se.SOURCE_MAP_PRESETS)))})
        return 2
    pattern = args.pattern or se.SOURCE_MAP_PRESETS.get(args.preset, se.SOURCE_MAP_PRESETS["parsers"])
    globs = None if args.globs == "all" else ["*.java"]
    # A root may be a multi-module project: choosing ``src`` merely because it
    # exists silently omits sibling Java modules.  The source map is a bounded
    # *display* scan, but its scope still needs one explicit contract.  With no
    # user-provided source dir, scan the declared root; invalid explicit paths
    # produce no fallback scan and are visible in the response.
    _bases, source_dirs, invalid_source_dirs = resolve_source_dirs(
        root, list(args.source_dir or []) or None)
    hits = se.grep_hits(pattern, source_dirs, root, max_lines=args.max_hits, globs=globs)
    entries = []
    for h in hits:
        text = h["text"]
        m = re.search(r"([A-Za-z_@][\w.@/:]*)\s*\(?", text)
        api = m.group(1).rsplit(".", 1)[-1] if m else text.strip()[:40]
        entries.append({"file": h["file"], "line": h["line"], "text": h["text"], "api": api})
    _out({"root": str(root), "pattern": pattern, "count": len(entries),
          "entries": entries[:args.max_hits],
          "globs": globs or se.DEFAULT_SOURCE_GLOBS,
          "source_dirs": source_dirs,
          "invalid_source_dirs": invalid_source_dirs,
          "claim_status": "not-a-finding"})
    return 0


def cmd_source_evidence(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    path = (root / args.file).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        _out({"error": "file is outside the authorized root",
              "file": args.file, "root": str(root)})
        return 2
    if not path.is_file():
        _out({"error": "file not found", "file": args.file, "root": str(root)})
        return 2
    if args.class_header:
        body = se.extract_class_header(path)
    else:
        body = se.extract_method(path, args.line or 1)
    if not body:
        body = path.read_text(encoding="utf-8", errors="replace")[:args.max_chars]
    _out({"file": args.file, "line": args.line, "body": body})
    return 0


def _matrix_cell(c: Dict[str, Any]) -> MatrixCell:
    return MatrixCell(
        version=str(c["version"]),
        safe_mode=bool(c.get("safe_mode", False)),
        features=list(c.get("features", [])),
        precondition=str(c.get("precondition", "none")),
        args=list(c.get("args", [])),
        jvm=dict(c.get("jvm", {})),
        timeout=c.get("timeout"),
        authz=dict(c.get("authz", {})),
        sequence=list(c.get("sequence", [])) if isinstance(c.get("sequence", []), list)
        else c.get("sequence", []),
        concurrency=c.get("concurrency", 1),
        availability_probe=c.get("availability_probe", False),
        capability_contract=c.get("capability_contract", {}),
        residual_contracts=list(c.get("residual_contracts", [])),
        variant_context=dict(c.get("variant_context", {})),
        consistency_action=c.get("consistency_action", {}),
        consistency_lane=str(c.get("consistency_lane", "")),
        required_runtime=str(c.get("required_runtime", c.get("requested_runtime", ""))),
        java_bin=str(c.get("java_bin", "")),
        java_home=str(c.get("java_home", "")),
    )


def _poc_spec(s: Dict[str, Any]) -> POCSpec:
    return POCSpec(
        candidate_id=str(s["candidate_id"]),
        class_name=str(s["class_name"]),
        src=str(s["src"]),
        cells=[_matrix_cell(c) for c in s.get("cells", [])],
        extra_srcs=list(s.get("extra_srcs", [])),
        safe_mode_jvm_prop=str(s.get("safe_mode_jvm_prop", "")),
        module_opts=list(s.get("module_opts", [])),
        module_run_opts=list(s.get("module_run_opts", [])),
        jvm_default=dict(s.get("jvm_default", {})),
        entry=str(s.get("entry", "")),
        input_shape=str(s.get("input_shape", "")),
        logic=str(s.get("logic", "")),
        notes=str(s.get("notes", "")),
    )


def _shell_poc_spec(s: Dict[str, Any]) -> ShellPOCSpec:
    return ShellPOCSpec(
        candidate_id=str(s["candidate_id"]),
        script=str(s["script"]),
        cells=[_matrix_cell(c) for c in s.get("cells", [])],
        env=dict(s.get("env", {})),
        urls=dict(s.get("urls", {})),
        entry=str(s.get("entry", "")),
        input_shape=str(s.get("input_shape", "")),
        logic=str(s.get("logic", "")),
        notes=str(s.get("notes", "")),
    )


def cmd_matrix(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    from agent.analysis.audit_budget import (
        budget_path as audit_budget_path,
        load_round_budget,
        round_budget_snapshot,
    )
    from agent.tools.build import S4ExecutionBudget

    round_execution_budget = None
    try:
        deadline_path = audit_budget_path(workspace, args.target, args.round)
    except ValueError as exc:
        _out({"error": "invalid audit-round identity", "detail": str(exc)})
        return 2
    if deadline_path.exists():
        try:
            persisted_budget = load_round_budget(workspace, args.target, args.round)
            deadline = round_budget_snapshot(persisted_budget)
        except (OSError, ValueError, TypeError) as exc:
            _out({"error": "invalid audit-round deadline; refusing matrix run",
                  "detail": str(exc), "path": str(deadline_path)})
            return 2
        remaining = int(deadline["remaining_seconds"])
        if deadline["expired"] or remaining < 1:
            _out({"error": "audit-round deadline expired; refusing matrix run",
                  "audit_budget": deadline})
            return 3
        # Direct host-native matrix runs share the round deadline and a
        # 45-minute S4 envelope. The usual per-candidate limit remains 15m.
        round_execution_budget = S4ExecutionBudget(
            round_timeout_seconds=min(45 * 60, remaining),
            candidate_timeout_seconds=min(15 * 60, remaining),
        )
    staging_hosts = [str(h).strip().lower().rstrip(".") for h in (args.staging_host or []) if str(h).strip()]
    if args.authorized_staging and not staging_hosts:
        _out({"error": "--authorized-staging requires at least one --staging-host allowlist entry"})
        return 2
    manifest_path = Path(args.manifest).resolve() if args.manifest else \
        workspace / "state" / args.target / ("round-%02d" % args.round) / "S4" / "manifest.json"
    if not manifest_path.exists():
        _out({"error": "manifest not found", "path": str(manifest_path),
              "hint": "provide --manifest with {specs:[...], jars:{version:[paths]}} "
                      "(shell PoCs: --lang shell with {specs:[{candidate_id,script,cells}]})"})
        return 2
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw_specs = manifest.get("specs", [])
    if not raw_specs:
        _out({"error": "manifest has no specs"})
        return 2
    if args.lang == "shell":
        specs = [_shell_poc_spec(s) for s in raw_specs]
        runner = ShellMatrixRunner(
            workspace, args.target, args.round,
            authorized_staging=args.authorized_staging, staging_hosts=staging_hosts,
            execution_budget=round_execution_budget)
        results = runner.run_manifest(specs)
    else:
        specs = [_poc_spec(s) for s in raw_specs]
        jars = {v: [Path(p) for p in ps] for v, ps in manifest.get("jars", {}).items()}
        runner = JavaMatrixRunner(
            workspace, args.target, args.round,
            authorized_staging=args.authorized_staging, staging_hosts=staging_hosts,
            execution_budget=round_execution_budget)
        results = runner.run_manifest(specs, jars)
    summary = {cid: summarize_candidate(cells) for cid, cells in results.items()}
    _out({"target": args.target, "round": args.round,
          "lang": args.lang, "candidates": summary,
          "cells_written_to": str(runner.matrix_dir),
          "s4_execution_budget": runner.execution_budget.snapshot()})
    return 0


def _staging_runner(args: argparse.Namespace):
    from agent.sandbox.approval import ApprovalGate
    from agent.sandbox.runner import CommandRunner
    workspace = Path(args.workspace).resolve()
    log = workspace / "state" / args.target / ("round-%02d" % args.round) / "approval-log.jsonl"
    approval = ApprovalGate(log_path=log)
    return CommandRunner(workspace, approval, authorized_staging=True,
                         staging_hosts=[args.host])


def cmd_staging_exec(args: argparse.Namespace) -> int:
    """Run one explicitly authorized SSH staging command.

    This is environment preparation only; its output is never vulnerability
    evidence. The host and command are recorded by CommandRunner.
    """
    if not args.authorized_staging or not args.command:
        _out({"error": "staging-exec requires --authorized-staging and --command"})
        return 2
    runner = _staging_runner(args)
    user_host = "%s@%s" % (args.user, args.host)
    cmd = ["ssh", "-p", str(args.port), user_host] + list(args.command)
    try:
        result = runner.run(cmd, timeout=args.timeout,
                            operation_detail="authorized staging SSH %s" % args.host)
    except PermissionError as exc:
        _out({"error": str(exc), "host": args.host})
        return 2
    _out({"host": args.host, "returncode": result.returncode,
          "stdout": result.stdout, "stderr": result.stderr,
          "duration_ms": result.duration_ms, "timed_out": result.timed_out,
          "timeout_seconds": result.timeout_seconds,
          "timeout_capped": result.timeout_capped,
          "evidence_role": "environment-preparation-only"})
    return result.returncode if result.returncode >= 0 else 2


def cmd_staging_copy(args: argparse.Namespace) -> int:
    """Copy one workspace file to an explicitly authorized staging host."""
    if not args.authorized_staging:
        _out({"error": "staging-copy requires --authorized-staging"})
        return 2
    runner = _staging_runner(args)
    source = Path(args.source).resolve()
    workspace = Path(args.workspace).resolve()
    if not (str(source) == str(workspace) or str(source).startswith(str(workspace) + os.sep)):
        _out({"error": "source must stay under workspace", "source": str(source)})
        return 2
    cmd = ["scp", "-P", str(args.port), str(source),
           "%s@%s:%s" % (args.user, args.host, args.destination)]
    try:
        result = runner.run(cmd, timeout=args.timeout,
                            operation_detail="authorized staging copy %s" % args.host)
    except PermissionError as exc:
        _out({"error": str(exc), "host": args.host})
        return 2
    _out({"host": args.host, "source": str(source), "destination": args.destination,
          "returncode": result.returncode, "stdout": result.stdout,
          "stderr": result.stderr, "duration_ms": result.duration_ms,
          "timed_out": result.timed_out,
          "timeout_seconds": result.timeout_seconds,
          "timeout_capped": result.timeout_capped,
          "evidence_role": "environment-preparation-only"})
    return result.returncode if result.returncode >= 0 else 2


def cmd_novelty(args: argparse.Namespace) -> int:
    if args.evidence:
        data = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
        refs = [UpstreamRef(ref=r["ref"], kind=r.get("kind", "issue"), title=r.get("title", ""),
                            state=r.get("state", "open"), created_at=r["created_at"],
                            url=r.get("url", ""), coverage_note=r.get("coverage_note", ""),
                            evidence_source=r.get("evidence_source", ""),
                            repo=r.get("repo", ""))
                for r in data.get("refs", [])]
        disclosures = [Disclosure(id=d["id"], source=d.get("source", "advisory"),
                                  title=d.get("title", ""), date=d["date"],
                                  url=d.get("url", ""), coverage_note=d.get("coverage_note", ""))
                       for d in data.get("disclosures", [])]
        checker = NoveltyChecker(offline=True)
        result = checker.evaluate(refs, disclosures, data.get("discovery_date", "2026-01-01"),
                                  increments_hint=data.get("increments"),
                                  query_failed=bool(data.get("query_failed", False)))
        _out({"verdict": result.verdict, "reason": result.reason,
              "increments": result.increments,
              "refs": [{"ref": r.ref, "kind": r.kind, "title": r.title,
                        "state": r.state, "created_at": r.created_at,
                        "url": r.url, "evidence_source": r.evidence_source}
                       for r in result.refs],
              "disclosures": [d.id for d in result.disclosures],
              "checked_at": result.checked_at,
              "query_failed": bool(data.get("query_failed", False)),
              "query_metadata": result.query_metadata})
        return 0

    data = json.loads(Path(args.query).read_text(encoding="utf-8"))
    repo = data.get("repo", "")
    fixtures = Path(args.fixtures).resolve() if args.fixtures else None
    checker = NoveltyChecker(fixtures_dir=fixtures, offline=args.offline,
                             cache_dir=Path(args.cache).resolve() if args.cache else None)
    refs: List[UpstreamRef] = []
    query_failed = bool(args.offline)
    for num in data.get("issue_numbers", []):
        r = checker.fetch_ref(repo, num, "issues")
        if r:
            refs.append(r)
        else:
            query_failed = True
    for num in data.get("pr_numbers", []):
        r = checker.fetch_ref(repo, num, "pulls")
        if r:
            refs.append(r)
        else:
            query_failed = True
    queries = list(data.get("queries", []))
    if not repo or not queries and not data.get("issue_numbers") and not data.get("pr_numbers"):
        query_failed = True
    for q in queries:
        hits = checker.search(repo, q)
        if hits is None:
            query_failed = True
            continue
        for item in hits:
            ref = upstream_ref_from_search_hit(
                repo, item,
                "offline fixture search" if args.offline else "live GitHub search")
            if ref and ref.ref not in {existing.ref for existing in refs}:
                refs.append(ref)
    query_metadata = checker.query_metadata()
    if query_metadata.get("attempts", 0) == 0 and not refs:
        query_failed = True
    result = checker.evaluate(refs, [], data.get("discovery_date", "2026-01-01"),
                              increments_hint=data.get("increments"),
                              query_failed=query_failed)
    _out({"verdict": result.verdict, "reason": result.reason,
          "increments": result.increments,
          "refs": [{"ref": r.ref, "kind": r.kind, "title": r.title,
                    "state": r.state, "created_at": r.created_at,
                    "url": r.url, "evidence_source": r.evidence_source}
                   for r in result.refs],
          "checked_at": result.checked_at,
          "rate_limit": checker.last_rate_limit,
          "query_failed": bool(query_failed or checker.query_errors or checker.last_rate_limit),
          "query_metadata": checker.query_metadata()})
    return 0


def cmd_cvss(args: argparse.Namespace) -> int:
    try:
        score, severity = base_score(args.vector)
    except (KeyError, TypeError, ValueError) as exc:
        _out({"error": "invalid CVSS vector: %s" % exc, "vector": args.vector})
        return 2
    payload: Dict[str, Any] = {
        "vector": args.vector, "score": round(score, 1), "severity": severity,
    }
    if args.tier:
        ok, msg = check_precondition_consistency(args.tier, args.vector,
                                                 implicit_default_on=args.implicit_default_on)
        payload["g5"] = {"consistent": ok, "message": msg, "tier": args.tier}
    _out(payload)
    return 0


def cmd_ledger(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    entries = json.loads(Path(args.entries).read_text(encoding="utf-8"))
    # Evidence hard rule (Metabase lesson, 2026-08-10): C4 was excluded with an
    # EMPTY basis column. Every ledger row and every exclusion must carry
    # non-empty evidence (runtime output, source refs, or test results).
    def _evidence_text(r: Dict[str, Any]) -> str:
        ev = r.get("evidence") or r.get("reason") or r.get("basis")
        if isinstance(ev, list):
            ev = " ".join(str(e) for e in ev)
        return str(ev or "").strip()

    missing = []
    for r in list(entries.get("rows", [])) + list(entries.get("excluded", [])):
        cid = r.get("candidate_id") or r.get("surface") or "?"
        if not _evidence_text(r):
            missing.append(cid)
    if missing:
        _out({"error": "entries missing evidence",
              "candidates": missing,
              "hint": "every ledger row and exclusion must carry non-empty "
                      "evidence (runtime output, source refs, or test results)"})
        return 2

    # Evidence-fidelity hard rule: a capability-only canary must never be
    # persisted as confirmed RCE. This catches stale/hand-written ledgers even
    # when the shared conclusion helper was bypassed.
    rce_bad = []
    dos_bad = []
    for r in entries.get("rows", []):
        status = str(r.get("conclusion", "")).lower()
        hay = " ".join(str(r.get(k, "")) for k in ("surface", "logic", "hypothesis")).lower()
        evidence = _evidence_text(r)
        is_rce = any(k in hay for k in ("rce", "remote code execution", "命令执行", "代码执行"))
        has_effect = bool(re.search(
            r"EFFECT(?:_KIND)?\s*=\s*(?:command-executed|command-marker|process-started|"
            r"code-execution|file-marker)", evidence, re.IGNORECASE))
        if is_rce and ("safe-equivalent" in status or "safe_equivalent" in status or
                        "SAFE_EQUIVALENT" in evidence) and not has_effect:
            rce_bad.append(r.get("candidate_id") or r.get("surface") or "?")
        vector = r.get("cvss") if isinstance(r.get("cvss"), dict) else {}
        is_dos = any(k in hay for k in ("dos", "denial of service", "拒绝服务", "资源耗尽"))
        if is_dos and str(vector.get("vector", "")).find("/A:H") >= 0 and \
                "AVAILABILITY_PROOF=" not in evidence:
            dos_bad.append(r.get("candidate_id") or r.get("surface") or "?")
    if rce_bad or dos_bad:
        _out({"error": "evidence-fidelity gate rejected ledger",
              "rce_safe_equivalent": rce_bad,
              "dos_without_full_outage_proof": dos_bad,
              "hint": "RCE requires a real EFFECT_KIND marker; A:H requires "
                      "CONCURRENCY>=2 plus SERVICE_UNAVAILABLE evidence"})
        return 2
    # Fix-completeness runtime-evidence hard rule (0.2.15, blocked-client UAF /
    # pro-model-static-audit lesson, 2026-08-20): an EXCLUDED fix-completeness
    # candidate may NOT be closed on static reasoning alone. It must either
    # carry machine-readable runtime observation lines from its S4 cell, or be
    # explicitly justified as G1-unreachable with source references.
    _RUNTIME_RE = re.compile(
        r"(OBSERVATION\s*=|ERROR\s*=|GATE_BLOCKED|EXIT_CODE|SIGNAL\s*=|"
        r"RESULT\s*=|INSTANTIATED\s*=|NETWORK\s*=|PARSED\s*=|HTTP_CODE\s*=|"
        r"RESP_MATCH\s*=|EVIDENCE\s*=|ASAN|heap-use-after-free|out of memory|"
        r"SIGABRT|SIGSEGV|abort\s*\(|exit code\s*\d+)",
        re.IGNORECASE,
    )

    # Fix-verification surfaces that were not explicitly tagged
    # "fix-completeness" still read as fix-completeness when they cite a fix /
    # issue / CVE (Redis 0.2.13 round: "handleClientsBlockedOnKey UAF (#15594 /
    # CVE-2026-23479)" with static-only evidence slipped through).
    _FIX_FAMILY_RE = re.compile(
        r"(fix-completeness|fix_completeness|修复完整性|uaf|use.after.free|"
        r"use-after-free|overflow|out.of.bounds|\boob\b|bypass|race|crash|"
        r"cve-\d|#\d{3,}|deserial|rce|memory|越界|溢出|崩溃|竞态)",
        re.IGNORECASE,
    )

    def _is_fix_completeness(r: Dict[str, Any]) -> bool:
        hay = " ".join(
            str(r.get(k, "")) for k in
            ("surface", "candidate_id", "id", "class", "type", "kind")
        ).lower()
        if ("fix-completeness" in hay or "fix_completeness" in hay or
                str(r.get("fix_completeness", "")).lower() in ("true", "yes", "1")):
            return True
        # Untagged but clearly fix-verification shaped (fix keyword + issue/CVE
        # reference, or a fix keyword with a static-only evidence note).
        surface = str(r.get("surface", ""))
        return bool(_FIX_FAMILY_RE.search(surface))

    def _g1_unreachable(r: Dict[str, Any]) -> bool:
        basis = " ".join(str(r.get(k, "")) for k in
                         ("surface", "exclusion_basis", "basis", "gate", "reason")).lower()
        return any(k in basis for k in
                   ("g1", "unreachable", "untrusted", "不可达", "不受信",
                    "无不可信输入", "不可信输入无关", "管理员", "admin-only",
                    "trusted input"))

    static_only = []
    for r in entries.get("excluded", []):
        cid = r.get("candidate_id") or r.get("surface") or "?"
        if not _is_fix_completeness(r) or _g1_unreachable(r):
            continue
        if not _RUNTIME_RE.search(_evidence_text(r)):
            static_only.append(cid)
    if static_only:
        _out({"error": "fix-completeness exclusions require runtime cell evidence",
              "candidates": static_only,
              "hint": "add a runtime observation line (OBSERVATION= / ERROR= / "
                      "GATE_BLOCKED= / EXIT_CODE= / SIGNAL= / ASAN ...) from the "
                      "S4 cell, or mark exclusion_basis=g1-unreachable with "
                      "source references if the fix point is not reachable from "
                      "untrusted input"})
        return 2
    from agent.memory.ledger import write_round_artifacts
    out = write_round_artifacts(
        workspace, args.target, args.round,
        rows=entries.get("rows", []),
        excluded=entries.get("excluded", []),
        summary=entries.get("summary", {}),
        lang=entries.get("lang", "zh"),
    )
    _out({"written_to": str(out)})
    return 0


def cmd_deps(args: argparse.Namespace) -> int:
    from agent.tools.deps import (collect_dependencies, render_markdown,
                                  scan_dependencies)
    root = Path(args.target)
    if not root.is_dir():
        _out({"error": "target dir not found: %s" % root})
        return 2
    cache = Path(args.cache) if args.cache else None
    deps = collect_dependencies(root)
    findings, notes = scan_dependencies(deps, cache_dir=cache,
                                        offline=args.offline)
    md = render_markdown(findings, notes, str(root))
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(md, encoding="utf-8")
    _out({
        "target": str(root),
        "manifests_scanned": len({d.manifest for d in deps}),
        "deps_scanned": len(deps),
        "vulns_found": len(findings),
        "query_notes": notes,
        "report": args.out or None,
        "top": [{"dep": f.dependency.name,
                 "version": f.dependency.version,
                 "vuln": f.vuln_id,
                 "severity": f.severity,
                 "fixed_version": f.fixed_version} for f in findings[:30]],
    })
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    """Score a deterministic research run against a gold benchmark manifest."""
    from agent.evaluation.benchmark import (evaluate_benchmark,
                                             compare_benchmark_results,
                                             derive_benchmark_feedback,
                                             load_benchmark_json,
                                             normalize_manifest,
                                             render_benchmark_text,
                                             validate_manifest)

    try:
        manifest = load_benchmark_json(Path(args.manifest))
        errors = validate_manifest(manifest)
        if errors:
            _out({"error": "invalid benchmark manifest", "errors": errors[:20],
                  "manifest": str(Path(args.manifest).resolve())})
            return 2
        if not normalize_manifest(manifest).get("cases"):
            _out({"error": "benchmark manifest has no valid cases",
                  "manifest": str(Path(args.manifest).resolve())})
            return 2
        runs = []
        for filename in args.run or []:
            loaded = load_benchmark_json(Path(filename))
            if isinstance(loaded.get("runs"), list) and "observations" not in loaded:
                runs.extend(loaded["runs"])
            else:
                runs.append(loaded)
        result = evaluate_benchmark(manifest, runs if runs else None)
        if args.baseline:
            baseline = load_benchmark_json(Path(args.baseline))
            trend = compare_benchmark_results(result, baseline)
            if trend:
                result["trend"] = trend
        feedback = derive_benchmark_feedback(result)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        _out({"error": "%s: %s" % (type(exc).__name__, exc)})
        return 2

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False),
                            encoding="utf-8")
    if args.feedback_out:
        feedback_path = Path(args.feedback_out)
        feedback_path.parent.mkdir(parents=True, exist_ok=True)
        feedback_path.write_text(json.dumps(feedback, indent=2, ensure_ascii=False),
                                 encoding="utf-8")
    if args.json:
        payload = dict(result)
        payload["feedback"] = feedback
        if args.out:
            payload["written_to"] = str(Path(args.out).resolve())
        if args.feedback_out:
            payload["feedback_written_to"] = str(Path(args.feedback_out).resolve())
        _out(payload)
    else:
        print(render_benchmark_text(result))
        if args.out:
            print("  written_to: %s" % Path(args.out).resolve())
        if args.feedback_out:
            print("  feedback_written_to: %s" % Path(args.feedback_out).resolve())
    return 0


def cmd_replay_calibrate(args: argparse.Namespace) -> int:
    """Calibrate guidance from bounded real-project round replays."""
    from agent.evaluation.replay_calibration import (
        build_replay_calibration, write_replay_calibration,
    )

    workspace = Path(args.workspace).resolve()
    calibration = build_replay_calibration(workspace, args.target)
    target_path = write_replay_calibration(
        workspace, args.target, calibration)
    payload = {
        "target": args.target,
        "workspace": str(workspace),
        "artifact": str(target_path.relative_to(workspace)),
        "calibration": calibration,
        "claim_status": "not-a-finding",
    }
    if args.out:
        out_path = Path(args.out)
        if not out_path.is_absolute():
            out_path = workspace / out_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(calibration, indent=2,
                                       ensure_ascii=False), encoding="utf-8")
        payload["written_to"] = str(out_path.resolve())
    if args.json:
        _out(payload)
    else:
        metrics = calibration.get("metrics", {})
        print("replay calibration: %s" % payload["artifact"])
        print("  status=%s rounds=%s replayed=%s replacement_hit_rate=%s claim_status=%s"
              % (calibration.get("status", "no-data"),
                 metrics.get("round_count", 0),
                 metrics.get("replayed_guidance_items", 0),
                 metrics.get("replacement_hit_rate"),
                 calibration.get("claim_status", "not-a-finding")))
        if args.out:
            print("  written_to: %s" % payload["written_to"])
    return 0


def cmd_replay_pack(args: argparse.Namespace) -> int:
    """Build a provenance-carrying pack from local replay artifacts."""
    from agent.evaluation.replay_pack import (
        build_replay_pack, write_replay_pack,
    )

    workspace = Path(args.workspace).resolve()
    pack = build_replay_pack(workspace, args.target, args.round or None)
    if not pack:
        _out({"error": "replay pack could not be built",
              "target": args.target, "workspace": str(workspace)})
        return 2
    target_path = write_replay_pack(workspace, args.target, pack)
    payload = {
        "target": args.target,
        "workspace": str(workspace),
        "artifact": str(target_path.relative_to(workspace)),
        "pack": pack,
        "claim_status": "not-a-finding",
    }
    if args.out:
        out_path = Path(args.out)
        if not out_path.is_absolute():
            out_path = workspace / out_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(pack, indent=2, ensure_ascii=False),
                            encoding="utf-8")
        payload["written_to"] = str(out_path.resolve())
    if args.json:
        _out(payload)
    else:
        provenance = pack.get("provenance", {})
        print("replay pack: %s" % payload["artifact"])
        print("  status=%s rounds=%s artifacts=%s valid_for_cohort=%s "
              "claim_status=%s" % (
                  provenance.get("status", "not-executed"),
                  provenance.get("round_count", 0),
                  provenance.get("round_artifact_count", 0),
                  provenance.get("valid_for_cohort", False),
                  pack.get("claim_status", "not-a-finding")))
        if args.out:
            print("  written_to: %s" % payload["written_to"])
    return 0


def cmd_replay_cohort_calibrate(args: argparse.Namespace) -> int:
    """Aggregate bounded replay calibration from independent projects."""
    from agent.evaluation.replay_cohort import calibrate_replay_cohort
    from agent.evaluation.replay_pack import load_replay_pack_file

    artifact_paths = [Path(value).resolve() for value in args.artifact or []]
    pack_paths = [Path(value).resolve() for value in args.pack or []]
    project_ids = [str(value).strip() for value in args.project_id or []]
    input_count = len(artifact_paths) + len(pack_paths)
    if project_ids and len(project_ids) != input_count:
        _out({"error": "--project-id must be repeated once per --artifact/--pack",
              "inputs": input_count,
              "project_ids": len(project_ids)})
        return 2
    inputs = []
    invalid = []
    for index, path in enumerate(artifact_paths):
        try:
            if not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
                invalid.append(str(path))
                continue
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            invalid.append(str(path))
            continue
        if isinstance(raw, dict) and isinstance(raw.get("calibration"), dict):
            raw = raw["calibration"]
        inputs.append({
            "calibration": raw,
            "project_id": project_ids[index] if project_ids else "",
        })
    for offset, path in enumerate(pack_paths):
        pack = load_replay_pack_file(path)
        provenance = pack.get("provenance") if pack else {}
        if not pack or not provenance.get("valid_for_cohort"):
            invalid.append(str(path))
            continue
        index = len(artifact_paths) + offset
        inputs.append({
            "pack": pack,
            "project_id": project_ids[index] if project_ids else "",
        })
    if invalid:
        _out({"error": "invalid or provenance-incomplete replay input",
              "paths": invalid[:8]})
        return 2
    if not inputs:
        _out({"error": "at least one --artifact or --pack is required"})
        return 2
    cohort = calibrate_replay_cohort(inputs)
    payload = {
        "cohort": cohort,
        "artifact_count": len(inputs),
        "input_kind_counts": cohort.get("metrics", {}).get(
            "input_kind_counts", {}),
        "claim_status": "not-a-finding",
    }
    if args.out:
        out_path = Path(args.out).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(cohort, indent=2, ensure_ascii=False),
                            encoding="utf-8")
        payload["written_to"] = str(out_path)
    if args.json:
        _out(payload)
    else:
        metrics = cohort.get("metrics", {})
        print("replay cohort calibration: status=%s projects=%s eligible=%s "
              "replayed=%s threshold=%s claim_status=%s" % (
                  cohort.get("status", "no-data"),
                  metrics.get("project_count", 0),
                  metrics.get("eligible_projects", 0),
                  metrics.get("eligible_replayed_guidance_items", 0),
                  (cohort.get("policy") or {}).get(
                      "replacement_zero_gain_rounds", 1),
                  cohort.get("claim_status", "not-a-finding")))
        if args.out:
            print("  written_to: %s" % payload["written_to"])
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    """Record bounded human review feedback for one research mechanism."""
    from agent.memory.research import (REVIEW_REASON_CODES, REVIEW_STATUSES,
                                       load_research_memory,
                                       record_review_feedback,
                                       review_feedback_path)

    workspace = Path(args.workspace).resolve()
    memory = load_research_memory(workspace, args.target)
    research_key = str(args.research_key or "").strip()
    candidate_id = str(args.candidate_id or "").strip()
    if not research_key and candidate_id:
        matches = [entry for entry in memory.get("entries", [])
                   if str(entry.get("candidate_id") or "") == candidate_id]
        keys = sorted({str(entry.get("research_key")) for entry in matches
                       if entry.get("research_key")})
        if len(keys) != 1:
            _out({"error": "candidate id does not resolve to one research key",
                  "candidate_id": candidate_id, "matches": keys,
                  "hint": "pass --research-key explicitly when the candidate was renamed"})
            return 2
        research_key = keys[0]
    if not research_key:
        _out({"error": "--research-key or --candidate-id is required"})
        return 2
    if args.status not in REVIEW_STATUSES or args.reason_code not in REVIEW_REASON_CODES:
        _out({"error": "unsupported review status or reason code",
              "statuses": sorted(REVIEW_STATUSES),
              "reason_codes": sorted(REVIEW_REASON_CODES)})
        return 2
    round_no = int(args.round or 0)
    if round_no <= 0:
        try:
            round_no = max(1, int(memory.get("round", 0) or 0) + 1)
        except (TypeError, ValueError):
            round_no = 1
    try:
        feedback = record_review_feedback(
            workspace, args.target, research_key, args.status,
            reason_code=args.reason_code, candidate_id=candidate_id,
            reviewer_note=args.note, evidence_refs=args.evidence_ref,
            next_probe_hints=args.next_probe, round_no=round_no)
    except ValueError as exc:
        _out({"error": str(exc)})
        return 2
    payload = {
        "target": args.target,
        "workspace": str(workspace),
        "feedback": feedback,
        "feedback_file": str(review_feedback_path(workspace, args.target)
                               .relative_to(workspace)),
        "claim_status": "not-a-finding",
    }
    if args.json:
        _out(payload)
    else:
        print("review feedback recorded: %s %s (%s) -> %s" % (
            feedback["status"], feedback["research_key"],
            feedback["reason_code"], payload["feedback_file"]))
    return 0


def cmd_portfolio(args: argparse.Namespace) -> int:
    """Show the bounded project research portfolio (or rebuild it explicitly)."""
    from agent.memory.portfolio import (build_research_portfolio,
                                        load_research_portfolio,
                                        portfolio_path,
                                        write_research_portfolio)
    from agent.memory.research import (load_review_feedback,
                                       load_research_memory)

    workspace = Path(args.workspace).resolve()
    portfolio = load_research_portfolio(workspace, args.target)
    if args.rebuild:
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
        portfolio = build_research_portfolio(
            load_research_memory(workspace, args.target),
            load_review_feedback(workspace, args.target),
            benchmark_feedback)
        write_research_portfolio(workspace, args.target, portfolio)
    if not portfolio:
        _out({"error": "research portfolio not found",
              "hint": "run an S8 round or pass --rebuild",
              "artifact": str(portfolio_path(workspace, args.target))})
        return 2
    payload = {
        "target": args.target,
        "workspace": str(workspace),
        "artifact": str(portfolio_path(workspace, args.target).relative_to(workspace)),
        "portfolio": portfolio,
    }
    if args.json:
        _out(payload)
    else:
        summary = portfolio.get("summary", {})
        print("portfolio: %s" % payload["artifact"])
        print("  mechanisms=%s unresolved=%s next_probes=%d claim_status=%s" % (
            summary.get("mechanism_count", 0),
            summary.get("unresolved_mechanisms", 0),
            len(portfolio.get("next_probes") or []),
            portfolio.get("claim_status", "not-a-finding")))
        lane_coverage = portfolio.get("surface_lane_coverage") or {}
        lane_summary = lane_coverage.get("summary") or {}
        print("  lanes=%s observed=%s partial=%s environment_gap=%s "
              "not_executed=%s" % (
                  lane_summary.get("lane_count", 0),
                  lane_summary.get("observed_lanes", 0),
                  lane_summary.get("partial_lanes", 0),
                  lane_summary.get("environment_gap_lanes", 0),
                  lane_summary.get("not_executed_lanes", 0)))
        for lane in lane_coverage.get("lanes") or []:
            if not isinstance(lane, dict) or lane.get("status") == "observed":
                continue
            print("  lane: %s/%s/%s [%s] missing=%s" % (
                lane.get("surface"), lane.get("variant_id"),
                lane.get("lane"), lane.get("status"),
                ",".join(lane.get("missing_observations") or []) or "-"))
        for probe in portfolio.get("next_probes") or []:
            print("  next: %s [%s] %s" % (
                probe.get("candidate_id") or probe.get("research_key"),
                probe.get("state"),
                "; ".join(probe.get("next_probe_hints") or []) or "-"))
    return 0


def cmd_research_consistency(args: argparse.Namespace) -> int:
    """Show or rebuild bounded cross-round evidence consistency metadata."""
    from agent.evaluation.research_consistency import (
        build_research_consistency,
        consistency_path,
        load_research_consistency,
        write_research_consistency,
    )
    from agent.memory.research import load_research_memory

    workspace = Path(args.workspace).resolve()
    consistency = load_research_consistency(workspace, args.target)
    if args.rebuild or not consistency:
        consistency = build_research_consistency(
            load_research_memory(workspace, args.target))
        write_research_consistency(workspace, args.target, consistency)
    if not consistency:
        _out({"error": "research consistency artifact not found",
              "hint": "run an S8 round or pass --rebuild",
              "artifact": str(consistency_path(workspace, args.target))})
        return 2
    payload = {
        "target": args.target,
        "workspace": str(workspace),
        "artifact": str(consistency_path(
            workspace, args.target).relative_to(workspace)),
        "consistency": consistency,
    }
    if args.json:
        _out(payload)
    else:
        summary = consistency.get("summary", {})
        print("research consistency: %s" % payload["artifact"])
        print("  entries=%s conflicted=%s unstable=%s environment_gap=%s "
              "insufficient=%s claim_status=%s" % (
                  summary.get("entry_count", 0),
                  summary.get("conflicted_entries", 0),
                  summary.get("unstable_entries", 0),
                  summary.get("environment_gap_entries", 0),
                  summary.get("insufficient_entries", 0),
                  consistency.get("claim_status", "not-a-finding")))
        for row in consistency.get("entries") or []:
            if not isinstance(row, dict) or row.get("status") == "consistent":
                continue
            print("  next: %s [%s] action=%s codes=%s" % (
                row.get("candidate_id") or row.get("research_key"),
                row.get("status"), row.get("next_action"),
                ",".join(row.get("conflict_codes") or []) or "-"))
    return 0


def cmd_research_consistency_actions(args: argparse.Namespace) -> int:
    """Show or rebuild bounded controlled recheck contracts."""
    from agent.evaluation.research_consistency import (
        build_research_consistency,
        load_research_consistency,
        write_research_consistency,
    )
    from agent.evaluation.research_consistency_actions import (
        build_research_consistency_actions,
        consistency_actions_path,
        load_research_consistency_actions,
        write_research_consistency_actions,
    )
    from agent.memory.research import load_research_memory

    workspace = Path(args.workspace).resolve()
    consistency = load_research_consistency(workspace, args.target)
    if args.rebuild or not consistency:
        consistency = build_research_consistency(
            load_research_memory(workspace, args.target))
        write_research_consistency(workspace, args.target, consistency)
    actions = load_research_consistency_actions(workspace, args.target)
    if args.rebuild or not actions:
        actions = build_research_consistency_actions(consistency)
        write_research_consistency_actions(workspace, args.target, actions)
    if not actions:
        _out({"error": "research consistency actions artifact not found",
              "hint": "run an S8 round or pass --rebuild",
              "artifact": str(consistency_actions_path(
                  workspace, args.target))})
        return 2
    payload = {
        "target": args.target,
        "workspace": str(workspace),
        "artifact": str(consistency_actions_path(
            workspace, args.target).relative_to(workspace)),
        "actions": actions,
    }
    if args.json:
        _out(payload)
    else:
        summary = actions.get("summary", {})
        print("research consistency actions: %s" % payload["artifact"])
        print("  actions=%s conflicted=%s unstable=%s environment_gap=%s "
              "insufficient=%s claim_status=%s" % (
                  summary.get("action_count", 0),
                  summary.get("conflicted_entries", 0),
                  summary.get("unstable_entries", 0),
                  summary.get("environment_gap_entries", 0),
                  summary.get("insufficient_entries", 0),
                  actions.get("claim_status", "not-a-finding")))
        for row in actions.get("entries") or []:
            if not isinstance(row, dict):
                continue
            print("  action: %s [%s] next=%s axes=%s" % (
                row.get("candidate_id") or row.get("research_key"),
                row.get("status"), row.get("next_action"),
                ",".join(row.get("isolation_axes") or []) or "-"))
    return 0


def cmd_research_consistency_rechecks(args: argparse.Namespace) -> int:
    """Show or rebuild bounded S4 execution closure for consistency actions."""
    from agent.evaluation.research_consistency_actions import (
        load_research_consistency_actions,
    )
    from agent.evaluation.research_consistency_rechecks import (
        build_research_consistency_rechecks,
        load_research_consistency_rechecks,
        rechecks_path,
        write_research_consistency_rechecks,
    )
    from agent.tools.s4_runtime_lab import LAB_SCHEMA_VERSION

    workspace = Path(args.workspace).resolve()
    rechecks = load_research_consistency_rechecks(workspace, args.target)
    if args.rebuild or not rechecks:
        runtime_path = (workspace / "state" / args.target /
                        ("round-%02d" % args.round) / "S4" /
                        "runtime-lab.json") if args.round else None
        runtime = {}
        if runtime_path is not None:
            try:
                runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, ValueError, TypeError):
                runtime = {}
        else:
            # Rebuild from the newest bounded runtime-lab artifact only.  The
            # command never scans matrix-runs or reads raw process output.
            rounds = sorted((workspace / "state" / args.target).glob(
                "round-*/S4/runtime-lab.json"))
            if rounds:
                try:
                    runtime = json.loads(rounds[-1].read_text(encoding="utf-8"))
                except (OSError, UnicodeError, ValueError, TypeError):
                    runtime = {}
        if not isinstance(runtime, dict):
            runtime = {"schema_version": LAB_SCHEMA_VERSION,
                       "status": "not-executed", "fixtures": []}
        rechecks = build_research_consistency_rechecks(
            runtime, load_research_consistency_actions(workspace, args.target))
        write_research_consistency_rechecks(workspace, args.target, rechecks)
    if not rechecks:
        _out({"error": "research consistency rechecks artifact not found",
              "hint": "run an S8 round or pass --rebuild",
              "artifact": str(rechecks_path(
                  workspace, args.target))})
        return 2
    payload = {
        "target": args.target,
        "workspace": str(workspace),
        "artifact": str(rechecks_path(
            workspace, args.target).relative_to(workspace)),
        "rechecks": rechecks,
    }
    if args.json:
        _out(payload)
    else:
        summary = rechecks.get("summary", {})
        print("research consistency rechecks: %s" % payload["artifact"])
        print("  entries=%s observed=%s partial=%s environment_gap=%s "
              "not_executed=%s claim_status=%s" % (
                  summary.get("entry_count", 0), summary.get("observed", 0),
                  summary.get("partial", 0), summary.get("environment_gap", 0),
                  summary.get("not_executed", 0),
                  rechecks.get("claim_status", "not-a-finding")))
        for row in rechecks.get("entries") or []:
            if not isinstance(row, dict):
                continue
            print("  recheck: %s [%s] lanes=%s missing=%s" % (
                row.get("candidate_id") or row.get("research_key"),
                row.get("status"),
                ",".join(row.get("observed_lanes") or []) or "-",
                ",".join(row.get("missing_observations") or []) or "-"))
    return 0


def cmd_research_agenda(args: argparse.Namespace) -> int:
    """Show or rebuild the bounded active research agenda."""
    from agent.analysis.research_agenda import (
        agenda_path,
        build_research_agenda,
        load_research_agenda,
        write_research_agenda,
    )
    from agent.analysis.research_strategy import load_research_strategy
    from agent.memory.portfolio import load_research_portfolio

    workspace = Path(args.workspace).resolve()
    agenda = load_research_agenda(workspace, args.target)
    if args.rebuild or not agenda:
        strategy = load_research_strategy(workspace, args.target)
        portfolio = load_research_portfolio(workspace, args.target)
        round_no = args.round or int((strategy or {}).get("round", 0) or 0)
        agenda = build_research_agenda(
            strategy, portfolio, target=args.target, round_no=round_no,
            slots=args.slots, max_per_surface=args.max_per_surface)
        write_research_agenda(workspace, args.target, agenda)
    if not agenda:
        _out({"error": "research agenda artifact not found",
              "hint": "run an S8 round or pass --rebuild",
              "artifact": str(agenda_path(workspace, args.target))})
        return 2
    payload = {
        "target": args.target,
        "workspace": str(workspace),
        "artifact": str(agenda_path(
            workspace, args.target).relative_to(workspace)),
        "agenda": agenda,
    }
    if args.json:
        _out(payload)
    else:
        summary = agenda.get("summary", {})
        print("research agenda: %s" % payload["artifact"])
        print("  entries=%s selected=%s deferred=%s hold=%s cost=%s gain=%s "
              "claim_status=%s" % (
                  summary.get("entry_count", 0),
                  summary.get("selected_count", 0),
                  summary.get("deferred_count", 0),
                  summary.get("hold_count", 0),
                  summary.get("selected_cost", 0),
                  summary.get("selected_expected_information_gain", 0),
                  agenda.get("claim_status", "not-a-finding")))
        for row in agenda.get("items") or []:
            if not isinstance(row, dict) or row.get("selection_status") != "selected":
                continue
            print("  selected: %s [%s] action=%s surface=%s score=%s gain=%s"
                  % (row.get("candidate_id") or row.get("research_key"),
                     row.get("agenda_id"), row.get("action"),
                     row.get("surface") or "unknown",
                     row.get("priority_score", 0),
                     row.get("expected_information_gain", 0)))
    return 0


def cmd_research_agenda_outcomes(args: argparse.Namespace) -> int:
    """Show or rebuild bounded execution feedback for an active agenda."""
    from agent.analysis.research_agenda import load_research_agenda
    from agent.analysis.research_agenda_outcomes import (
        build_research_agenda_outcomes,
        load_research_agenda_outcomes,
        load_round_artifact,
        load_schedule_snapshot,
        outcomes_path,
        write_research_agenda_outcomes,
    )

    workspace = Path(args.workspace).resolve()
    outcomes = load_research_agenda_outcomes(workspace, args.target)
    if args.rebuild or not outcomes:
        agenda = load_research_agenda(workspace, args.target)
        round_no = args.round or int(
            (agenda or {}).get("round", 0) or
            (outcomes or {}).get("round", 0) or 0)
        schedule = load_schedule_snapshot(workspace, args.target, round_no)
        verification = load_round_artifact(
            workspace, args.target, round_no, "S4", "verification-matrix.json")
        runtime_lab = load_round_artifact(
            workspace, args.target, round_no, "S4", "runtime-lab.json")
        feedback = load_round_artifact(
            workspace, args.target, round_no, "S8",
            "research-strategy-feedback.json")
        outcomes = build_research_agenda_outcomes(
            agenda, schedule, verification, runtime_lab, feedback,
            prior_outcomes=outcomes, target=args.target, round_no=round_no)
        write_research_agenda_outcomes(workspace, args.target, outcomes)
    if not outcomes:
        _out({"error": "research agenda outcomes artifact not found",
              "hint": "run an S8 round or pass --rebuild",
              "artifact": str(outcomes_path(workspace, args.target))})
        return 2
    payload = {
        "target": args.target,
        "workspace": str(workspace),
        "artifact": str(outcomes_path(
            workspace, args.target).relative_to(workspace)),
        "outcomes": outcomes,
    }
    if args.json:
        _out(payload)
    else:
        summary = outcomes.get("summary", {})
        print("research agenda outcomes: %s" % payload["artifact"])
        print("  round=%s entries=%s selected=%s scheduled=%s executed=%s "
              "productive=%s yield=%s claim_status=%s" % (
                  outcomes.get("round", 0), summary.get("entry_count", 0),
                  summary.get("selected_count", 0),
                  summary.get("scheduled_count", 0),
                  summary.get("executed_count", 0),
                  summary.get("productive_selected_count", 0),
                  summary.get("selected_yield"),
                  outcomes.get("claim_status", "not-a-finding")))
        for row in outcomes.get("entries") or []:
            if not isinstance(row, dict) or row.get("selection_status") != "selected":
                continue
            print("  outcome: %s [%s] gain=%s scheduled=%s executed=%s" % (
                row.get("candidate_id") or row.get("research_key"),
                row.get("outcome_code"), row.get("information_gain", 0),
                row.get("scheduled", False), row.get("executed", False)))
    return 0


def cmd_research_budget(args: argparse.Namespace) -> int:
    """Show or rebuild the bounded outcome-to-budget policy."""
    from agent.analysis.research_agenda import load_research_agenda
    from agent.analysis.research_agenda_outcomes import (
        load_research_agenda_outcomes,
    )
    from agent.analysis.research_budget import (
        budget_path,
        build_research_budget,
        load_research_budget,
        write_research_budget,
    )

    workspace = Path(args.workspace).resolve()
    budget = load_research_budget(workspace, args.target)
    if args.rebuild or not budget:
        agenda = load_research_agenda(workspace, args.target)
        outcomes = load_research_agenda_outcomes(workspace, args.target)
        prior = budget
        round_no = args.round or int(
            (outcomes or {}).get("round", 0) or
            (agenda or {}).get("round", 0) or
            (budget or {}).get("round", 0) or 0)
        budget = build_research_budget(
            agenda, outcomes, prior_budget=prior, target=args.target,
            round_no=round_no, slots=args.slots)
        write_research_budget(workspace, args.target, budget)
    if not budget:
        _out({"error": "research budget artifact not found",
              "hint": "run an S8 round or pass --rebuild",
              "artifact": str(budget_path(workspace, args.target))})
        return 2
    payload = {
        "target": args.target,
        "workspace": str(workspace),
        "artifact": str(budget_path(
            workspace, args.target).relative_to(workspace)),
        "budget": budget,
    }
    if args.json:
        _out(payload)
    else:
        summary = budget.get("summary", {})
        print("research budget: %s" % payload["artifact"])
        print("  surfaces=%s observed=%s selected=%s productive=%s gain=%s "
              "cost=%s claim_status=%s" % (
                  summary.get("surface_count", 0),
                  summary.get("observed_surface_count", 0),
                  summary.get("selected_count", 0),
                  summary.get("productive_count", 0),
                  summary.get("information_gain", 0),
                  summary.get("estimated_cost", 0),
                  budget.get("claim_status", "not-a-finding")))
        for row in budget.get("surfaces") or []:
            if not isinstance(row, dict):
                continue
            print("  surface: %s [%s] delta=%s cap=%s yield=%s" % (
                row.get("surface"), row.get("recommendation"),
                row.get("priority_delta", 0), row.get("cap_hint", 0),
                row.get("yield_per_cost", 0)))
    return 0


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


def cmd_audit_exec(args: argparse.Namespace) -> int:
    """Run one bounded host-side audit command under the active round deadline."""
    import fcntl
    import time
    from datetime import datetime, timezone
    from agent.analysis.audit_budget import (
        load_round_budget,
        round_budget_snapshot,
    )
    from agent.sandbox.approval import ApprovalGate
    from agent.sandbox.runner import (
        AUDIT_COMMAND_ENV_POLICY_VERSION,
        MAX_COMMAND_WALL_TIMEOUT_SECONDS,
        CommandRunner,
    )

    workspace = Path(args.workspace).resolve()
    try:
        source_root = Path(args.root).resolve(strict=True)
        if not source_root.is_dir():
            raise ValueError("source root must be a directory")
        command = list(args.command or [])
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            raise ValueError("audit-exec requires a command after --")
        shell_names = {"sh", "bash", "zsh", "fish", "csh", "tcsh"}
        executable_name = Path(command[0]).name.lower()
        inspected_command = command
        git_subcommand = ""
        # `env bash -c ...` is still a shell wrapper. Unwrap the common env
        # forms so the simple bypass does not evade the command contract.
        if executable_name == "env":
            index = 1
            while index < len(command):
                token = command[index]
                if token == "--":
                    index += 1
                    break
                if token in {"-u", "--unset", "-C", "--chdir"}:
                    index += 2
                    continue
                if token in {"-S", "--split-string"}:
                    if index + 1 >= len(command):
                        break
                    try:
                        inspected_command = (shlex.split(command[index + 1])
                                             + command[index + 2:])
                    except ValueError:
                        inspected_command = []
                    break
                if token.startswith("--unset=") or token.startswith("--chdir="):
                    index += 1
                    continue
                if token.startswith("--split-string="):
                    try:
                        inspected_command = (
                            shlex.split(token.split("=", 1)[1])
                            + command[index + 1:])
                    except ValueError:
                        inspected_command = []
                    break
                if token.startswith("-") or re.fullmatch(
                        r"[A-Za-z_][A-Za-z0-9_]*=.*", token):
                    index += 1
                    continue
                break
            else:
                index = len(command)
            if inspected_command is command:
                inspected_command = command[index:]
            executable_name = (Path(inspected_command[0]).name.lower()
                               if inspected_command else "")
        if (executable_name in shell_names and any(
                token.startswith("-") and "c" in token[1:]
                or token == "--command" or token.startswith("--command=")
                for token in inspected_command[1:])):
            raise ValueError("audit-exec rejects shell -c commands; pass argv directly")
        network_tools = {
            "curl", "wget", "nc", "ncat", "socat", "ssh", "scp", "sftp",
            "rsync", "telnet", "rlogin", "ftp", "mosh",
        }
        if executable_name in network_tools:
            raise ValueError(
                "audit-exec is for local audit commands; use the approved network adapter")
        if executable_name == "git":
            git_index = 1
            while git_index < len(inspected_command):
                token = inspected_command[git_index]
                if token in {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}:
                    git_index += 2
                    continue
                if token.startswith("-"):
                    git_index += 1
                    continue
                git_subcommand = token.lower()
                break
            if git_subcommand in {
                    "clone", "fetch", "pull", "push", "remote", "submodule",
                    "ls-remote", "fetch-pack", "send-pack", "receive-pack",
                    "upload-pack"}:
                raise ValueError(
                    "audit-exec blocks Git remote operations; use approved source/network workflows")
        if isinstance(args.timeout, bool) or int(args.timeout) < 1:
            raise ValueError("timeout must be a positive number of seconds")
        if not 1000 <= int(args.max_output_chars) <= 200_000:
            raise ValueError("max-output-chars must be between 1000 and 200000")
        retry_reason = str(args.retry_reason or "").strip()[:400]

        env_extra: Dict[str, str] = {}
        for assignment in args.env or []:
            key, separator, value = str(assignment).partition("=")
            if (not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
                    or any(secret_word in key.upper() for secret_word in
                           ("TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH",
                            "PROXY", "API_KEY", "ACCESS_KEY"))):
                raise ValueError("--env requires a non-secret KEY=VALUE assignment")
            env_extra[key] = value

        if args.cwd:
            requested_cwd = Path(args.cwd)
            cwd = (requested_cwd if requested_cwd.is_absolute()
                   else source_root / requested_cwd).resolve(strict=True)
        else:
            cwd = source_root
        if not cwd.is_dir() or not (
                str(cwd) == str(source_root)
                or str(cwd).startswith(str(source_root) + os.sep)):
            raise ValueError("cwd must be a directory under --root")

        command_digest = hashlib.sha256(json.dumps(
            command, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")).hexdigest()
        cwd_relative = ("." if cwd == source_root else
                        cwd.relative_to(source_root).as_posix())
        run_log = (workspace / "state" / args.target
                   / ("round-%02d" % args.round) / "S0"
                   / "host-command-runs.jsonl")

        def write_run_record(record: Dict[str, Any], check_duplicate: bool = False
                             ) -> Optional[Dict[str, Any]]:
            run_log.parent.mkdir(parents=True, exist_ok=True)
            with run_log.open("a+b") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                prior_rows = []
                handle.seek(0, os.SEEK_END)
                log_size = handle.tell()
                tail_start = max(0, log_size - 16 * 1024 * 1024)
                handle.seek(tail_start)
                tail = handle.read()
                if tail_start:
                    tail = tail.partition(b"\n")[2]
                for line in tail.splitlines()[-4096:]:
                    try:
                        row = json.loads(line.decode("utf-8", "replace"))
                    except (TypeError, ValueError):
                        continue
                    if isinstance(row, dict):
                        prior_rows.append(row)
                if check_duplicate:
                    for previous in reversed(prior_rows):
                        if (previous.get("source_root") == str(source_root)
                                and previous.get("cwd") == cwd_relative
                                and previous.get("command_digest") == command_digest
                                and previous.get("status") in {
                                    "running", "timed-out", "cleanup-incomplete",
                                    "command-failed", "command-error"}):
                            if not retry_reason:
                                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                                return previous
                            break
                handle.seek(0, os.SEEK_END)
                handle.write((json.dumps(
                    record, ensure_ascii=False, separators=(",", ":"))
                    + "\n").encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            return None

        budget_record = load_round_budget(workspace, args.target, args.round)
        budget_before = round_budget_snapshot(budget_record)
        remaining = float(budget_before["remaining_seconds"])
        if budget_before["expired"] or remaining < 1.0:
            _out({"error": "audit round deadline expired; command not started",
                  "audit_budget": budget_before,
                  "claim_status": "not-a-finding"})
            return 3

        requested_timeout = int(args.timeout)
        inspection_executables = {
            "rg", "grep", "egrep", "fgrep", "ack", "ag", "find", "fd",
            "du",
        }
        bounded_git_inspections = {"grep", "status", "diff", "ls-files"}
        inline_code_flags = {
            "perl": {"-e", "-p", "-n"},
            "ruby": {"-e"},
            "node": {"-e", "--eval", "-p", "--print", "-"},
            "osascript": {"-e"},
        }
        python_interpreter = bool(re.fullmatch(
            r"(?:python|pypy)(?:\d+(?:\.\d+)*)?", executable_name))
        inline_flags = inline_code_flags.get(executable_name, set())
        inline_code_command = any(
            (python_interpreter and (token in {"-", "-c", "--command"}
             or token.startswith("-") and "c" in token[1:]))
            or token in inline_flags
            for token in inspected_command[1:])
        is_bounded_inspection = (
            executable_name in inspection_executables
            or (executable_name == "git"
                and git_subcommand in bounded_git_inspections)
            or inline_code_command)
        inspection_timeout_cap = 120
        command_timeout_cap = min(
            MAX_COMMAND_WALL_TIMEOUT_SECONDS,
            inspection_timeout_cap if is_bounded_inspection
            else MAX_COMMAND_WALL_TIMEOUT_SECONDS)
        timeout_cap_reason = (
            "inline-code" if inline_code_command else
            "recursive-search-or-inspection" if executable_name in inspection_executables else
            "git-metadata-inspection" if executable_name == "git"
            and git_subcommand in bounded_git_inspections else "")
        timeout_policy = (
            "audit-host-command-timeout-v3-inspection-120s"
            if is_bounded_inspection else "audit-host-command-timeout-v1")
        effective_timeout = min(
            requested_timeout, command_timeout_cap, max(1, int(remaining)))
        attempt_id = secrets.token_hex(8)
        executable = Path(command[0]).name
        started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        initial_record = {
            "schema_version": "audit-host-command-v1",
            "attempt_id": attempt_id,
            "target": args.target,
            "round": args.round,
            "source_root": str(source_root),
            "cwd": cwd_relative,
            "command_executable": executable,
            "command_digest": command_digest,
            "status": "running",
            "started_at": started_at,
            "requested_timeout_seconds": requested_timeout,
            "applied_timeout_seconds": effective_timeout,
            "timeout_policy": timeout_policy,
            "timeout_cap_seconds": command_timeout_cap,
            "timeout_cap_reason": timeout_cap_reason,
            "retry_reason": retry_reason,
            "claim_status": "not-a-finding",
        }
        duplicate = write_run_record(initial_record, check_duplicate=True)
        if duplicate:
            _out({
                "error": "same command previously timed out, failed, or remained running; inspect its process/output, then use --retry-reason only if the scope or environment changed",
                "previous_attempt": duplicate,
                "command_digest": command_digest,
                "claim_status": "not-a-finding",
            })
            return 2

        approval_path = (workspace / "state" / args.target
                         / ("round-%02d" % args.round) / "approval-log.jsonl")
        runner = CommandRunner(
            source_root,
            approval=ApprovalGate(log_path=approval_path),
            default_timeout=effective_timeout,
            max_output_chars=int(args.max_output_chars))
        command_started = time.monotonic()
        try:
            result = runner.run(
                command, cwd=cwd, timeout=effective_timeout,
                env_extra=env_extra, audit_command_env=True)
        except Exception as exc:
            write_run_record({
                **initial_record,
                "status": "command-error",
                "finished_at": datetime.now(timezone.utc).isoformat(
                    timespec="seconds"),
                "duration_ms": int((time.monotonic() - command_started) * 1000),
                "error_type": type(exc).__name__,
                "error": str(exc)[:300],
            })
            raise
        budget_after = round_budget_snapshot(budget_record)
        cleanup_status = str(
            (result.process_tree_cleanup or {}).get("status") or "unknown")
        run_status = (
            "timed-out" if result.timed_out else
            "cleanup-incomplete" if cleanup_status in {"incomplete", "unverified"} else
            "completed" if result.returncode == 0 else "command-failed")
        write_run_record({
            **initial_record,
            "status": run_status,
            "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_ms": result.duration_ms,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "process_tree_cleanup": result.process_tree_cleanup,
            "stdout_chars": len(result.stdout),
            "stdout_sha256": hashlib.sha256(
                result.stdout.encode("utf-8", "replace")).hexdigest(),
            "stderr_chars": len(result.stderr),
            "stderr_sha256": hashlib.sha256(
                result.stderr.encode("utf-8", "replace")).hexdigest(),
        })
        _out({
            "attempt_id": attempt_id,
            "run_log": str(run_log.relative_to(workspace)),
            "target": args.target,
            "round": args.round,
            "source_root": str(source_root),
            "cwd": cwd_relative,
            "command_executable": Path(command[0]).name,
            "command_digest": command_digest,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "duration_ms": result.duration_ms,
            "requested_timeout_seconds": requested_timeout,
            "applied_timeout_seconds": result.timeout_seconds,
            "timeout_policy": timeout_policy,
            "timeout_cap_seconds": command_timeout_cap,
            "timeout_cap_reason": timeout_cap_reason,
            "timeout_capped": (requested_timeout > effective_timeout
                               or result.timeout_capped),
            "audit_budget_before": budget_before,
            "audit_budget_after": budget_after,
            "environment_policy": AUDIT_COMMAND_ENV_POLICY_VERSION,
            "explicit_env_keys": sorted(env_extra),
            "process_tree_cleanup": result.process_tree_cleanup,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "network_isolation": "not-applied-to-host-audit-commands",
            "filesystem_isolation": "cwd-checked-only; no OS sandbox",
            "evidence_role": "host-command-output-not-finding",
            "claim_status": "not-a-finding",
        })
        if result.timed_out:
            return 124
        if cleanup_status in {"incomplete", "unverified"}:
            return 2
        return result.returncode if result.returncode >= 0 else 2
    except (OSError, PermissionError, ValueError, TypeError) as exc:
        _out({"error": str(exc), "target": args.target,
              "round": args.round, "claim_status": "not-a-finding"})
        return 2


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


def cmd_differential(args: argparse.Namespace) -> int:
    """Sibling / differential analysis (spec §12): where siblings disagree.

    Prints the sibling groups' basis, the control differentials found in them
    and the candidates they generate.  Patch evidence from S1's
    ``security-fix-history.json`` is folded in by default (spec §18 Phase 4
    "patch sibling diff"); ``--fix-history`` overrides it.  Offline and
    deterministic (spec §21.1).
    """
    from agent.analysis import differential as diff

    try:
        workspace, store, rebuilt, note = _ensure_coverage_analysis(
            args, (diff.DIFFERENTIAL_INDEX,), with_fix_history=True)
    except FileNotFoundError as exc:
        _out({"error": "target source root not found", "root": str(exc),
              "hint": "pass --root <src root> (with --rebuild) or run S1 first"})
        return 2

    index = diff.load_differential(store)
    candidates = diff.differential_candidates(index.findings, limit=args.limit_candidates)
    payload: Dict[str, Any] = {
        "target": args.target, "workspace": str(workspace),
        "summary": index.summary(),
        "findings": [f.as_dict() for f in index.findings[:max(0, args.limit)]],
        "candidates": candidates,
    }
    if note:
        payload["fix_history_note"] = note
    if rebuilt is not None:
        payload["rebuilt"] = rebuilt
    if args.json:
        _out(payload)
        return 0

    print(diff.render_differential_text(index, args.lang, limit=args.limit,
                                        candidates=candidates
                                        if args.show_candidates else None))
    if note:
        print("\n[%s]" % note)
    if rebuilt is not None:
        print("[index rebuilt from %s]" % rebuilt["root"])
    return 0


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


def cmd_spawn_probe(args: argparse.Namespace) -> int:
    """Prepare or verify a challenge-bound S4 spawn preflight probe.

    A host-created heartbeat file or a generic greeting cannot establish that
    a spawned agent received the task.  ``--prepare`` therefore creates a
    fresh, nonce-named heartbeat target and an exact reply challenge.  A later
    ``--status ok`` succeeds only when both artifacts carry that nonce; an
    invalid success request is downgraded to sequential mode and exits nonzero.
    """
    from datetime import datetime
    from agent.memory.state import CheckpointStore

    store = CheckpointStore(Path(args.workspace), args.target, args.round)
    if getattr(args, "prepare", False):
        token = str(getattr(args, "token", "") or secrets.token_urlsafe(18))
        token = re.sub(r"[^A-Za-z0-9_-]", "", token)[:96]
        if len(token) < 12:
            _out({"error": "probe token must contain at least 12 URL-safe characters"})
            return 2
        heartbeat = store.base / "S4" / ("spawn-probe-%s.heartbeat" % token)
        payload = {
            "schema_version": "spawn-probe-challenge-v1",
            "stage": "S4",
            "probe": "spawn-preflight",
            "token": token,
            "heartbeat_file": str(heartbeat),
            "expected_heartbeat": "PROBE %s" % token,
            "expected_reply": "PROBE-DONE %s" % token,
            "issued_at": datetime.now().isoformat(timespec="seconds"),
            "claim_status": "not-a-finding",
        }
        out = store.write_artifact("S4", "spawn-probe-challenge.json", payload)
        _out({"written_to": str(out), "heartbeat_file": str(heartbeat),
              "token": token, "expected_reply": payload["expected_reply"],
              "claim_status": "not-a-finding"})
        return 0

    if not getattr(args, "status", None):
        _out({"error": "--status is required unless --prepare is used"})
        return 2
    challenge = store.read_artifact("S4", "spawn-probe-challenge.json")
    challenge = challenge if isinstance(challenge, dict) else {}
    token = str(challenge.get("token") or "")
    heartbeat = Path(str(challenge.get("heartbeat_file") or
                         (store.base / "S4" / "spawn-probe.heartbeat")))
    expected_heartbeat = str(challenge.get("expected_heartbeat") or "")
    expected_reply = str(challenge.get("expected_reply") or "")
    heartbeat_lines: List[str] = []
    try:
        if heartbeat.is_file():
            heartbeat_lines = heartbeat.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        heartbeat_lines = []
    heartbeat_valid = bool(expected_heartbeat and
                           expected_heartbeat in [line.strip() for line in heartbeat_lines])
    reply = str(args.reply or "")
    reply_valid = bool(expected_reply and reply.strip() == expected_reply)
    challenge_valid = bool(token and expected_heartbeat and expected_reply)
    requested_ok = args.status == "ok"
    verified = bool(challenge_valid and heartbeat_valid and reply_valid)
    ok = bool(requested_ok and verified)
    requested_symptom = getattr(args, "symptom", None)
    if ok:
        symptom = "ok"
    elif requested_ok and not challenge_valid:
        symptom = "challenge-missing"
    elif requested_ok:
        symptom = "probe-contract-invalid"
    else:
        symptom = requested_symptom or "no-heartbeat-timeout"
    payload = {
        "schema_version": "spawn-probe-v2",
        "stage": "S4",
        "probe": "spawn-preflight",
        "status": "ok" if ok else "degraded",
        "symptom": symptom,
        "observed": {
            "heartbeat_file": str(heartbeat),
            "heartbeat_seen": heartbeat.exists(),
            "heartbeat_line_count": len(heartbeat_lines),
            "heartbeat_token_valid": heartbeat_valid,
            "reply_token_valid": reply_valid,
            "challenge_present": bool(challenge),
            "challenge_valid": challenge_valid,
            "challenge_token": token,
            "wait_seconds": args.wait_seconds,
            "agent_reply": reply,
            "followup_retried": bool(getattr(args, "followup_retried", False)),
        },
        "decision": "parallel-per-candidate" if ok else "host-sequential-whole-round",
        "recorded_at": datetime.now().isoformat(timespec="seconds"),
        "claim_status": "not-a-finding",
    }
    out = store.write_artifact("S4", "spawn-probe.json", payload)
    _out({"written_to": str(out), "decision": payload["decision"],
          "status": payload["status"], "symptom": symptom,
          "verified": verified, "claim_status": "not-a-finding"})
    return 0 if not requested_ok or ok else 2


def _parallel_candidate_id(value: Any) -> str:
    """Return a path-safe bounded candidate identifier, or an empty string."""
    candidate = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", candidate):
        return ""
    return candidate


def _parallel_artifact(store: Any, candidate: str,
                       value: Any) -> Optional[Dict[str, Any]]:
    """Validate one declared S4 matrix artifact without retaining its content."""
    raw = str(value or "").replace("\\", "/").lstrip("/")
    expected_prefix = "S4/matrix-runs/%s/" % candidate
    if not raw.startswith(expected_prefix):
        return None
    try:
        path = (store.base / raw).resolve()
        path.relative_to(store.base.resolve())
    except (OSError, ValueError):
        return None
    if not path.is_file():
        return None
    try:
        size = path.stat().st_size
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None
    if size <= 0:
        return None
    return {"path": raw, "sha256": digest, "size": size}


def cmd_parallel_receipt(args: argparse.Namespace) -> int:
    """Challenge-bind each spawned S4 candidate to a durable matrix receipt.

    Preflight proves task delivery once. This narrower per-candidate contract
    prevents a later generic reply from being mistaken for completed runtime
    work: completion is valid only when a fresh challenge and matrix digest
    agree. It records evidence metadata only, never a vulnerability result.
    """
    from datetime import datetime
    from agent.memory.state import CheckpointStore

    candidate = _parallel_candidate_id(getattr(args, "candidate", ""))
    if not candidate:
        _out({"error": "candidate must be a path-safe id (1-80 chars)"})
        return 2
    store = CheckpointStore(Path(args.workspace), args.target, args.round)
    receipt_name = "parallel-receipt-%s.json" % candidate
    challenge_name = "parallel-receipt-%s.challenge.json" % candidate
    expected_artifact = "S4/matrix-runs/%s/cells.json" % candidate

    if getattr(args, "prepare", False):
        token = str(getattr(args, "token", "") or secrets.token_urlsafe(18))
        token = re.sub(r"[^A-Za-z0-9_-]", "", token)[:96]
        if len(token) < 12:
            _out({"error": "receipt token must contain at least 12 URL-safe characters"})
            return 2
        payload = {
            "schema_version": "parallel-receipt-challenge-v1",
            "stage": "S4",
            "candidate_id": candidate,
            "token": token,
            "expected_artifact": expected_artifact,
            "issued_at": datetime.now().isoformat(timespec="seconds"),
            "claim_status": "not-a-finding",
        }
        out = store.write_artifact("S4", challenge_name, payload)
        _out({"written_to": str(out), "candidate_id": candidate,
              "token": token, "expected_artifact": expected_artifact,
              "claim_status": "not-a-finding"})
        return 0

    challenge = store.read_artifact("S4", challenge_name)
    challenge = challenge if isinstance(challenge, dict) else {}
    challenge_valid = bool(
        challenge.get("schema_version") == "parallel-receipt-challenge-v1"
        and challenge.get("candidate_id") == candidate
        and isinstance(challenge.get("token"), str)
        and len(challenge.get("token")) >= 12
        and challenge.get("expected_artifact") == expected_artifact)

    receipt = store.read_artifact("S4", receipt_name)
    receipt = receipt if isinstance(receipt, dict) else {}
    receipt_matches = bool(
        receipt.get("schema_version") == "parallel-receipt-v1"
        and receipt.get("candidate_id") == candidate
        and receipt.get("token") == challenge.get("token"))

    if getattr(args, "inspect", False):
        if not receipt_matches:
            _out({"candidate_id": candidate, "status": "missing",
                  "progress_count": 0, "last_progress": None,
                  "artifact_count": 0, "claim_status": "not-a-finding"})
            return 0
        events = receipt.get("events") if isinstance(receipt.get("events"), list) else []
        last_progress = next((event for event in reversed(events)
                              if isinstance(event, dict)
                              and event.get("kind") == "progress"), None)
        artifacts = receipt.get("artifacts") if isinstance(
            receipt.get("artifacts"), list) else []
        _out({
            "candidate_id": candidate,
            "status": receipt.get("status", "unknown"),
            "started_at": receipt.get("started_at"),
            "updated_at": receipt.get("updated_at"),
            "progress_count": int(receipt.get("progress_count") or 0),
            "last_progress": last_progress,
            "artifact_count": len(artifacts),
            "claim_status": "not-a-finding",
        })
        return 0

    if getattr(args, "verify", False):
        artifacts = receipt.get("artifacts") if isinstance(
            receipt.get("artifacts"), list) else []
        valid_artifacts = []
        for item in artifacts[:8]:
            if not isinstance(item, dict):
                continue
            checked = _parallel_artifact(store, candidate, item.get("path"))
            if checked and checked == {key: item.get(key) for key in checked}:
                valid_artifacts.append(checked)
        expected_present = any(row["path"] == expected_artifact
                               for row in valid_artifacts)
        verified = bool(
            challenge_valid
            and receipt.get("schema_version") == "parallel-receipt-v1"
            and receipt.get("candidate_id") == candidate
            and receipt.get("token") == challenge.get("token")
            and receipt.get("status") == "completed"
            and expected_present)
        _out({
            "candidate_id": candidate,
            "verified": verified,
            "decision": ("accept-runtime-artifacts" if verified else
                         "preserve-partial-and-run-host-sequentially"),
            "challenge_valid": challenge_valid,
            "receipt_status": receipt.get("status", "missing"),
            "expected_artifact_present": expected_present,
            "valid_artifact_count": len(valid_artifacts),
            "claim_status": "not-a-finding",
        })
        return 0 if verified else 2

    status = str(getattr(args, "status", "") or "").lower()
    if status not in {"received", "progress", "completed", "partial"}:
        _out({"error": "--status received|progress|completed|partial is required unless --prepare/--verify"})
        return 2
    supplied_token = str(getattr(args, "token", "") or "")
    artifact_rows = []
    for value in (getattr(args, "artifact", None) or [])[:8]:
        checked = _parallel_artifact(store, candidate, value)
        if checked and checked not in artifact_rows:
            artifact_rows.append(checked)
    if not challenge_valid or supplied_token != challenge.get("token"):
        _out({"error": "receipt challenge missing or token mismatch",
              "candidate_id": candidate})
        return 2
    prior_artifacts = []
    if receipt_matches:
        for item in (receipt.get("artifacts") or [])[:8]:
            if not isinstance(item, dict):
                continue
            checked = _parallel_artifact(store, candidate, item.get("path"))
            if checked and checked == {key: item.get(key) for key in checked}:
                prior_artifacts.append(checked)
    all_artifacts = list(prior_artifacts)
    for row in artifact_rows:
        if row not in all_artifacts:
            all_artifacts.append(row)
    all_artifacts = all_artifacts[:8]
    expected_present = any(row["path"] == expected_artifact
                           for row in all_artifacts)
    if status == "progress":
        step = " ".join(str(getattr(args, "progress_step", "") or "").split())
        step = "".join(ch for ch in step if ch.isprintable())[:120]
        if not step:
            _out({"error": "--status progress requires a concise --progress-step",
                  "candidate_id": candidate, "claim_status": "not-a-finding"})
            return 2
    else:
        step = {"received": "task-accepted", "partial": "partial-result",
                "completed": "matrix-complete"}[status]
    if status == "completed" and not expected_present:
        _out({"error": "completed receipt requires %s" % expected_artifact,
              "candidate_id": candidate, "claim_status": "not-a-finding"})
        return 2
    now = datetime.now().isoformat(timespec="seconds")
    events = list(receipt.get("events") or []) if receipt_matches else []
    events = [event for event in events if isinstance(event, dict)][-15:]
    event = {"kind": "progress" if status == "progress" else status,
             "step": step, "recorded_at": now}
    if artifact_rows:
        event["artifacts"] = [row["path"] for row in artifact_rows]
    events.append(event)
    progress_count = int(receipt.get("progress_count") or 0) if receipt_matches else 0
    if status == "progress":
        progress_count += 1
    payload = {
        "schema_version": "parallel-receipt-v1",
        "stage": "S4",
        "candidate_id": candidate,
        "token": supplied_token,
        "status": ("running" if status in {"received", "progress"} else status),
        "artifacts": all_artifacts,
        "started_at": receipt.get("started_at") if receipt_matches else now,
        "updated_at": now,
        "progress_count": progress_count,
        "events": events[-16:],
        "claim_status": "not-a-finding",
    }
    out = store.write_artifact("S4", receipt_name, payload)
    _out({"written_to": str(out), "candidate_id": candidate, "status": status,
          "progress_count": progress_count,
          "artifact_count": len(all_artifacts), "claim_status": "not-a-finding"})
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Zero-Day Agent plugin CLI (deterministic helpers)")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor", help="environment check")
    d.add_argument("--json", action="store_true",
                   help="accepted for consistency; doctor output is always JSON")
    d.set_defaults(fn=cmd_doctor)

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
    args = build_parser().parse_args(argv)
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
