#!/usr/bin/env python3
"""Zero-Day Agent plugin CLI — deterministic helpers for the host Codex agent.

The host agent owns reasoning (S2/S3/S5 judgment). This CLI only executes
deterministic work: source mapping, PoC matrix runs, novelty evaluation,
CVSS computation, and ledger rendering.

Usage:
  agent_cli.py doctor
  agent_cli.py source-map --root <dir> [--pattern <regex>]
  agent_cli.py source-evidence --root <dir> --file <rel> [--line N|--class-header]
  agent_cli.py matrix --workspace <dir> --target <name> --round <N> [--manifest <json>]
                           [--authorized-staging --staging-host <host>]
  agent_cli.py novelty --query <json> [--fixtures <dir>] [--offline] [--cache <dir>]
  agent_cli.py novelty --evidence <json>
  agent_cli.py cvss --vector <CVSS:3.1/...> [--tier <tier>] [--implicit-default-on]
  agent_cli.py ledger --workspace <dir> --target <name> --round <N> --entries <json>
  agent_cli.py deps --target <dir> [--out <report.md>] [--offline] [--cache <dir>]
  agent_cli.py spawn-probe --workspace <dir> --target <name> --round <N>
                           --status ok|degraded [--reply <agent-reply>]
  agent_cli.py staging-exec --authorized-staging --host <ECS> --user <user> ...
  agent_cli.py staging-copy --authorized-staging --host <ECS> --source <file> ...
"""

from __future__ import annotations

import argparse
import json
import os
import re
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
    root = Path(args.root).resolve()
    if args.preset and args.preset not in se.SOURCE_MAP_PRESETS:
        _out({"error": "unknown preset %r; choose from %s"
              % (args.preset, ", ".join(sorted(se.SOURCE_MAP_PRESETS)))})
        return 2
    pattern = args.pattern or se.SOURCE_MAP_PRESETS.get(args.preset, se.SOURCE_MAP_PRESETS["parsers"])
    globs = None if args.globs == "all" else ["*.java"]
    source_dirs = [d for d in ("src", "src/main/java") if (root / d).exists()] or ["."]
    hits = se.grep_hits(pattern, source_dirs, root, max_lines=args.max_hits, globs=globs)
    entries = []
    for h in hits:
        text = h["text"]
        m = re.search(r"([A-Za-z_@][\w.@/:]*)\s*\(?", text)
        api = m.group(1).rsplit(".", 1)[-1] if m else text.strip()[:40]
        entries.append({"file": h["file"], "line": h["line"], "text": h["text"], "api": api})
    _out({"root": str(root), "pattern": pattern, "count": len(entries),
          "entries": entries[:args.max_hits],
          "globs": globs or se.DEFAULT_SOURCE_GLOBS})
    return 0


def cmd_source_evidence(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    path = root / args.file
    if not path.exists():
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
        entry=str(s.get("entry", "")),
        input_shape=str(s.get("input_shape", "")),
        logic=str(s.get("logic", "")),
        notes=str(s.get("notes", "")),
    )


def cmd_matrix(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
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
            authorized_staging=args.authorized_staging, staging_hosts=staging_hosts)
        results = runner.run_manifest(specs)
    else:
        specs = [_poc_spec(s) for s in raw_specs]
        jars = {v: [Path(p) for p in ps] for v, ps in manifest.get("jars", {}).items()}
        runner = JavaMatrixRunner(
            workspace, args.target, args.round,
            authorized_staging=args.authorized_staging, staging_hosts=staging_hosts)
        results = runner.run_manifest(specs, jars)
    summary = {cid: summarize_candidate(cells) for cid, cells in results.items()}
    _out({"target": args.target, "round": args.round,
          "lang": args.lang, "candidates": summary,
          "cells_written_to": str(runner.matrix_dir)})
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
          "timed_out": result.timed_out, "evidence_role": "environment-preparation-only"})
    return result.returncode if result.returncode >= 0 else 2


def cmd_novelty(args: argparse.Namespace) -> int:
    if args.evidence:
        data = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
        refs = [UpstreamRef(ref=r["ref"], kind=r.get("kind", "issue"), title=r.get("title", ""),
                            state=r.get("state", "open"), created_at=r["created_at"],
                            url=r.get("url", ""), coverage_note=r.get("coverage_note", ""))
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
              "refs": [r.ref for r in result.refs],
              "disclosures": [d.id for d in result.disclosures],
              "checked_at": result.checked_at})
        return 0

    data = json.loads(Path(args.query).read_text(encoding="utf-8"))
    repo = data.get("repo", "")
    fixtures = Path(args.fixtures).resolve() if args.fixtures else None
    checker = NoveltyChecker(fixtures_dir=fixtures, offline=args.offline,
                             cache_dir=Path(args.cache).resolve() if args.cache else None)
    refs: List[UpstreamRef] = []
    query_failed = False
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
    for q in data.get("queries", []):
        hits = checker.search(repo, q)
        if hits is None:
            query_failed = True
    result = checker.evaluate(refs, [], data.get("discovery_date", "2026-01-01"),
                              increments_hint=data.get("increments"),
                              query_failed=query_failed)
    _out({"verdict": result.verdict, "reason": result.reason,
          "increments": result.increments,
          "refs": [r.ref for r in result.refs],
          "checked_at": result.checked_at,
          "rate_limit": checker.last_rate_limit})
    return 0


def cmd_cvss(args: argparse.Namespace) -> int:
    try:
        score, severity = base_score(args.vector)
    except KeyError as exc:
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


def cmd_spawn_probe(args: argparse.Namespace) -> int:
    """Record the S4 spawn preflight probe result (deterministic bookkeeping).

    The host decides ok/degraded from observed heartbeat/reply; this command
    only persists the decision in a uniform schema so round summaries and
    degradation records are consistent across hosts.

    0.2.13+: symptom classification makes the degraded record diagnosable:
      - no-heartbeat-greeting-only : sub-agent woke up but replied a generic
        greeting ("ready to help", "waiting for task") -> spawn message
        delivery failure (environment-level), NOT a probe protocol problem;
      - no-heartbeat-timeout       : no heartbeat, no useful reply at all;
      - followup-retried-failed    : one followup re-delivery was attempted
        and still no heartbeat.
    """
    from datetime import datetime
    from agent.memory.state import CheckpointStore

    store = CheckpointStore(Path(args.workspace), args.target, args.round)
    ok = args.status == "ok"
    heartbeat = store.base / "S4" / "spawn-probe.heartbeat"
    symptom = getattr(args, "symptom", None) or ("ok" if ok else "no-heartbeat-timeout")
    payload = {
        "stage": "S4",
        "probe": "spawn-preflight",
        "status": args.status,
        "symptom": symptom,
        "observed": {
            "heartbeat_file": str(heartbeat),
            "heartbeat_seen": heartbeat.exists(),
            "wait_seconds": args.wait_seconds,
            "agent_reply": args.reply or "",
            "followup_retried": bool(getattr(args, "followup_retried", False)),
        },
        "decision": "parallel-per-candidate" if ok else "host-sequential-whole-round",
        "recorded_at": datetime.now().isoformat(timespec="seconds"),
    }
    out = store.write_artifact("S4", "spawn-probe.json", payload)
    _out({"written_to": str(out), "decision": payload["decision"]})
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Zero-Day Agent plugin CLI (deterministic helpers)")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor", help="environment check")
    d.set_defaults(fn=cmd_doctor)

    sm = sub.add_parser("source-map", help="build entry inventory via rg")
    sm.add_argument("--root", required=True)
    sm.add_argument("--pattern", default=None)
    sm.add_argument("--preset", default=None, choices=sorted(se.SOURCE_MAP_PRESETS))
    sm.add_argument("--max-hits", type=int, default=200)
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

    sp = sub.add_parser(
        "spawn-probe",
        help="record S4 spawn preflight probe result (ok | degraded)",
    )
    sp.add_argument("--workspace", required=True)
    sp.add_argument("--target", required=True)
    sp.add_argument("--round", type=int, required=True)
    sp.add_argument("--status", choices=["ok", "degraded"], required=True)
    sp.add_argument("--reply", default="", help="observed sub-agent reply (raw)")
    sp.add_argument(
        "--symptom",
        choices=[
            "ok",
            "no-heartbeat-greeting-only",
            "no-heartbeat-timeout",
            "followup-retried-failed",
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
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.fn(args) or 0)
    except Exception as exc:  # pragma: no cover - surface harness errors as JSON
        _out({"error": "%s: %s" % (type(exc).__name__, exc)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
