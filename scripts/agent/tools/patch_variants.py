"""Read-only git patch analysis for fix-completeness candidates.

This module does not check out revisions or build arbitrary historical code.
It records enough bounded, source-grounded metadata for S2/S3 to plan the
version and sibling-path probes without treating the presence of a fix as proof
that all variants are fixed.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


SECURITY_FIX_RE = re.compile(
    r"\b(?:security|vuln|cve|ghsa|rce|remote.?code|deserial|overflow|"
    r"out.?of.?bounds|oob|uaf|use.?after.?free|bypass|race|crash|dos|"
    r"denial.?of.?service|injection|xxe|ssrf|auth(?:entication|orization)?)\b",
    re.I,
)
FIX_SIGNAL_RE = re.compile(
    r"\b(?:fix(?:ed|es|ing)?|patch(?:ed|es|ing)?|bug|harden(?:ed|ing)?|"
    r"mitigat(?:e|ed|ion)|remediat(?:e|ed|ion)|CVE-\d{4}-\d+|GHSA-[\w-]+)\b",
    re.I,
)
PATCH_LINE_RE = re.compile(
    r"(?:check|valid|bound|limit|length|depth|size|auth|permission|allow|deny|"
    r"sanitize|escape|decode|encode|deserialize|classloader|jndi|parser|"
    r"overflow|race|lock|close|free|release|ownership|tenant)", re.I)
HUNK_RE = re.compile(r"^@@ .*? @@(?:\s+(.*))?$")


def _run(root: Path, args: List[str], timeout: int = 20) -> str:
    try:
        proc = subprocess.run(["git", "-C", str(root)] + args,
                              capture_output=True, text=True,
                              errors="replace", timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout or ""


def _parent(root: Path, commit: str) -> Optional[str]:
    value = _run(root, ["rev-parse", "%s^" % commit]).strip()
    return value or None


def _changed_files(root: Path, commit: str) -> List[Dict[str, str]]:
    rows = []
    for line in _run(root, ["diff-tree", "--no-commit-id", "--name-status",
                            "-r", "-M", commit]).splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            rows.append({"status": parts[0], "path": parts[-1]})
    return rows[:80]


def _patch_summary(root: Path, commit: str, parent: Optional[str]) -> Dict[str, Any]:
    if not parent:
        return {"hunks": [], "security_lines": [], "variant_hints": []}
    text = _run(root, ["diff", "--no-ext-diff", "--unified=0", parent, commit], timeout=30)
    hunks: List[Dict[str, Any]] = []
    security_lines: List[str] = []
    current_file = ""
    current_hunk: Optional[Dict[str, Any]] = None
    for line in text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("@@"):
            match = HUNK_RE.match(line)
            current_hunk = {"file": current_file, "header": line,
                            "symbol": (match.group(1) or "").strip() if match else ""}
            hunks.append(current_hunk)
        elif (line.startswith("+") or line.startswith("-")) and not line.startswith(("+++", "---")):
            body = line[1:].strip()
            if PATCH_LINE_RE.search(body) and len(security_lines) < 80:
                security_lines.append(("%s:%s" % (current_file, line[:240])))
    hints = []
    files = {h.get("file", "") for h in hunks}
    if len(files) > 1:
        hints.append("multi-file: inspect sibling callers and adapters")
    if any("test" not in f.lower() and f for f in files):
        hints.append("production-path: validate the changed production path")
    if any(re.search(r"(encode|decode|read|write|parse|deserialize|serialize)", f, re.I)
           for f in files):
        hints.append("alternate-codec: inspect sibling encode/decode branches")
    if any(re.search(r"(auth|permission|tenant|owner|access)", f, re.I) for f in files):
        hints.append("boundary-variant: inspect role/tenant/object ownership paths")
    return {"hunks": hunks[:80], "security_lines": security_lines,
            "variant_hints": sorted(set(hints))}


def analyze_patch_history(root: Path, max_count: int = 30) -> List[Dict[str, Any]]:
    """Return bounded security-fix history and patch-variant hints."""
    root = root.resolve()
    rows = []
    log = _run(root, ["log", "--all", "-n", str(max_count),
                      "--date=iso-strict", "--format=%H%x09%ad%x09%s"])
    for line in log.splitlines():
        parts = line.split("\t", 2)
        if (len(parts) != 3 or not SECURITY_FIX_RE.search(parts[2])
                or not FIX_SIGNAL_RE.search(parts[2])):
            continue
        commit, date, subject = parts
        parent = _parent(root, commit)
        files = _changed_files(root, commit)
        summary = _patch_summary(root, commit, parent)
        rows.append({
            "commit": commit,
            "short_commit": commit[:12],
            "parent": parent,
            "date": date,
            "subject": subject[:240],
            "changed_files": files,
            "affected_paths": [f["path"] for f in files],
            "hunks": summary["hunks"],
            "security_lines": summary["security_lines"],
            "variant_hints": summary["variant_hints"],
            "probe_plan": [
                "build the parent revision and the fixed revision when the target supports it",
                "re-run the triggering input through every changed sibling/adapter path",
                "record fixed and residual behavior as separate matrix cells",
            ],
        })
    return rows


def fix_completeness_candidate(fix: Dict[str, Any]) -> Dict[str, Any]:
    """Convert one patch record into a conservative S2 candidate descriptor."""
    locations = ["%s (commit %s)" % (p, fix["short_commit"])
                 for p in fix.get("affected_paths", [])[:12]]
    return {
        "candidate_id": "FIX-%s" % fix["short_commit"],
        "surface": "fix-completeness: %s" % fix.get("subject", "security fix"),
        "entry": "git:%s" % fix["commit"],
        "input_shape": "patch-variant",
        "logic": "修复完整性反查；变更路径：%s；变体提示：%s" % (
            ", ".join(locations) or "unknown",
            "; ".join(fix.get("variant_hints", [])) or "inspect sibling paths"),
        "hypothesis": "修复可能只覆盖一个入口、编码分支或对象状态，需用修复前后对照 cell 验证。",
        "precondition_tier_hint": "single-feature",
        "preconditions": ["存在可构建的 parent/fixed revision；若不可构建则保持待验证"],
        "code_location": locations,
        "patch_commit": fix.get("commit"),
        "patch_parent": fix.get("parent"),
        "patch_variants": fix.get("variant_hints", []),
        "probe_plan": fix.get("probe_plan", []),
        "fix_completeness": True,
        "pocs": [],
    }
