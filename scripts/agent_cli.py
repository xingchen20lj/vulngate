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
  agent_cli.py novelty --query <json> [--fixtures <dir>] [--offline] [--cache <dir>]
  agent_cli.py novelty --evidence <json>
  agent_cli.py cvss --vector <CVSS:3.1/...> [--tier <tier>] [--implicit-default-on]
  agent_cli.py ledger --workspace <dir> --target <name> --round <N> --entries <json>
"""

from __future__ import annotations

import argparse
import json
import os
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
    summarize_candidate,
)
from agent.tools.cvss import base_score, check_precondition_consistency  # noqa: E402
from agent.tools.novelty import (  # noqa: E402
    Disclosure,
    NoveltyChecker,
    UpstreamRef,
)
from agent.tools import source_evidence as se  # noqa: E402


def _out(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def cmd_doctor(_args: argparse.Namespace) -> int:
    checks = {
        "python3": shutil.which("python3") is not None,
        "java": shutil.which("java") is not None,
        "javac": shutil.which("javac") is not None,
        "rg": shutil.which("rg") is not None,
        "jar": shutil.which("jar") is not None,
        "GITHUB_TOKEN|GH_TOKEN": bool(os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")),
    }
    if checks["java"]:
        try:
            ver = subprocess.run(["java", "-version"], capture_output=True,
                                 text=True, timeout=10).stderr.splitlines()
            checks["java_version"] = ver[0] if ver else "unknown"
        except Exception as exc:  # pragma: no cover
            checks["java_version"] = "error: %s" % exc
    missing = [k for k, v in checks.items() if v is False]
    _out({"checks": checks, "missing": missing,
          "status": "ok" if not missing else "missing-tools"})
    return 0 if not missing else 2


def cmd_source_map(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    pattern = args.pattern or r"(parse\w*|read\w*|deserialize\w*|convert\w*|load\w*|decode\w*)\s*\("
    source_dirs = [d for d in ("src", "src/main/java") if (root / d).exists()] or ["."]
    hits = se.grep_hits(pattern, source_dirs, root, max_lines=args.max_hits)
    entries = []
    for h in hits:
        api = h["text"].split("(")[0].strip().split()[-1]
        entries.append({"file": h["file"], "line": h["line"], "text": h["text"], "api": api})
    _out({"root": str(root), "pattern": pattern, "count": len(entries),
          "entries": entries[:args.max_hits]})
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


def cmd_matrix(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    manifest_path = Path(args.manifest).resolve() if args.manifest else \
        workspace / "state" / args.target / ("round-%02d" % args.round) / "S4" / "manifest.json"
    if not manifest_path.exists():
        _out({"error": "manifest not found", "path": str(manifest_path),
              "hint": "provide --manifest with {specs:[...], jars:{version:[paths]}}"})
        return 2
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    specs = [_poc_spec(s) for s in manifest.get("specs", [])]
    jars = {v: [Path(p) for p in ps] for v, ps in manifest.get("jars", {}).items()}
    if not specs:
        _out({"error": "manifest has no specs"})
        return 2
    runner = JavaMatrixRunner(workspace, args.target, args.round)
    results = runner.run_manifest(specs, jars)
    summary = {cid: summarize_candidate(cells) for cid, cells in results.items()}
    _out({"target": args.target, "round": args.round,
          "candidates": summary, "cells_written_to": str(runner.matrix_dir)})
    return 0


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
        r = checker.fetch_ref(repo, num, "pull_request")
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="VulnGate plugin CLI (deterministic helpers)")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor", help="environment check")
    d.set_defaults(fn=cmd_doctor)

    sm = sub.add_parser("source-map", help="build entry inventory via rg")
    sm.add_argument("--root", required=True)
    sm.add_argument("--pattern", default=None)
    sm.add_argument("--max-hits", type=int, default=200)
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
    mx.set_defaults(fn=cmd_matrix)

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
