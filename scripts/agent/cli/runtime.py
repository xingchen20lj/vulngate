"""Runtime-oriented CLI handlers.

This module keeps environment inspection, bounded cleanup, matrix execution,
and explicitly authorized staging operations out of the CLI parser module.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List

from agent.tools.build import (
    JavaMatrixRunner,
    MatrixCell,
    POCSpec,
    ShellMatrixRunner,
    ShellPOCSpec,
    summarize_candidate,
)
from agent.tools.github_auth import github_token_source
from agent.tools import source_evidence as se


def _out(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def cmd_doctor(_args: argparse.Namespace) -> int:
    from agent.sandbox.isolation import capability_matrix

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
    checks["capabilities"] = capability_matrix()
    _out({"checks": checks, "github_token_source": github_source, "missing": missing,
          "status": "ok" if not missing else "missing-tools"})
    return 0 if not missing else 2


def cmd_cleanup(args: argparse.Namespace) -> int:
    """Remove only this workspace's bounded, target-scoped local artifacts."""
    workspace = Path(args.workspace).resolve()
    target = str(args.target or "").strip()
    if not target or target in {".", ".."} or "/" in target or "\\" in target:
        _out({"error": "target must be a single workspace-local component"})
        return 2
    if not workspace.is_dir():
        _out({"error": "workspace does not exist", "workspace": str(workspace)})
        return 2
    roots = [workspace / name / target for name in ("state", "ledger", "reports", "poc")]
    cutoff = time.time() - max(0, int(args.older_than_days)) * 86400
    candidates: List[Path] = []
    for root in roots:
        if not root.exists() or not (root == workspace or str(root).startswith(str(workspace) + os.sep)):
            continue
        if args.all:
            candidates.append(root)
            continue
        for path in root.rglob("*"):
            try:
                if path.is_symlink() or (path.is_file() and path.stat().st_mtime <= cutoff):
                    candidates.append(path)
            except OSError:
                continue
    if not args.apply:
        _out({"status": "dry-run", "workspace": str(workspace),
              "target": target, "candidates": [str(p) for p in candidates],
              "claim_status": "not-a-finding"})
        return 0
    removed: List[str] = []
    for path in sorted(candidates, key=lambda item: len(item.parts), reverse=True):
        if not (path == workspace or str(path).startswith(str(workspace) + os.sep)):
            continue
        try:
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink()
            removed.append(str(path))
        except OSError as exc:
            _out({"error": "cleanup failed", "path": str(path),
                  "detail": type(exc).__name__, "removed": removed})
            return 1
    _out({"status": "removed", "workspace": str(workspace), "target": target,
          "removed": removed, "claim_status": "not-a-finding"})
    return 0


def cmd_service_approval(args: argparse.Namespace) -> int:
    """Create a short-lived, run/config-bound service-start approval."""
    from agent.sandbox.approval import ApprovalGate

    workspace = Path(args.workspace).resolve()
    if not workspace.is_dir() or not args.run_id or not args.config_digest:
        _out({"error": "workspace, run_id and config_digest are required"})
        return 2
    if not re.fullmatch(r"[0-9a-fA-F]{16,128}", args.config_digest):
        _out({"error": "config_digest must be a hexadecimal digest"})
        return 2
    if "/" in args.target or "\\" in args.target or args.target in {"", ".", ".."}:
        _out({"error": "target must be a single component"})
        return 2
    ttl = max(1, min(int(args.ttl_seconds), 900))
    log = workspace / "state" / args.target / ("round-%02d" % int(args.round)) / "approval-log.jsonl"
    gate = ApprovalGate(log_path=log)
    approval_id = gate.record_authorized(
        "service_lifecycle",
        "operator-approved isolated target service start",
        constraint="one-time run/config-bound approval",
        run_id=args.run_id,
        config_digest=args.config_digest,
        expires_at=time.time() + ttl,
    )
    _out({"status": "authorized", "approval_id": approval_id,
          "run_id": args.run_id, "config_digest": args.config_digest,
          "expires_in_seconds": ttl, "approval_log": str(log),
          "claim_status": "not-a-finding"})
    return 0


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
        effect_observers=dict(s.get("effect_observers", s.get("effects", {})) or {}),
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
        effect_observers=dict(s.get("effect_observers", s.get("effects", {})) or {}),
        https_tls_certfile=str(s.get("https_tls_certfile", "")),
        https_tls_keyfile=str(s.get("https_tls_keyfile", "")),
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



