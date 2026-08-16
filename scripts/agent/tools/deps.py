"""Dependency vulnerability scan (developer self-audit mode).

Discovers dependency manifests in a target, resolves each dependency+version
against OSV (api.osv.dev), and emits findings with the first fixed version
as the remediation suggestion. Designed for individual developers/tests who
want a quick "is my supply chain known-vulnerable" answer before release.

Usage (via agent_cli):  python3 scripts/agent_cli.py deps --target <dir>
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .public_scan import _cache_key, _http_json, _read_cache, _write_cache

MANIFESTS = {
    "pom.xml": "Maven",
    "requirements.txt": "PyPI",
    "requirements-dev.txt": "PyPI",
    "pyproject.toml": "PyPI",
    "package.json": "npm",
    "go.mod": "Go",
    "Gemfile": "RubyGems",
    "Cargo.toml": "crates.io",
    "composer.json": "Packagist",
    "build.gradle": "Maven",
    "build.gradle.kts": "Maven",
}


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str
    manifest: str
    raw_version: str = ""


@dataclass
class DepFinding:
    dependency: Dependency
    vuln_id: str
    summary: str
    severity: str
    fixed_version: Optional[str]
    url: str


def discover_manifests(root: Path) -> List[Path]:
    out: List[Path] = []
    for name in MANIFESTS:
        for p in root.rglob(name):
            if any(seg.startswith(".") or seg in ("node_modules", "vendor")
                   for seg in p.parts):
                continue
            if p.stat().st_size > 4 * 1024 * 1024:  # skip giant lock files
                continue
            out.append(p)
    return out


def _parse_pom(text: str) -> List[Tuple[str, str]]:
    deps: List[Tuple[str, str]] = []
    for m in re.finditer(
            r"<dependency>\s*<groupId>([^<]+)</groupId>\s*"
            r"<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>",
            text, re.S):
        deps.append(("%s:%s" % (m.group(1), m.group(2)), m.group(3).strip()))
    return deps


def _parse_reqs(text: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*(?:==|>=|~=|!=)\s*([0-9][^\s,;]*)?", line)
        if m:
            out.append((m.group(1), m.group(2) or "latest"))
    return out


def _parse_pyproject(text: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for line in text.splitlines():
        s = line.strip().strip('",')
        m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*(?:==|>=|~=|!=)\s*([0-9][^\s,;]*)?", s)
        if m:
            out.append((m.group(1), m.group(2) or "latest"))
    return out


def _parse_package_json(text: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return out
    for section in ("dependencies", "devDependencies"):
        for name, ver in (data.get(section) or {}).items():
            m = re.search(r"[0-9][0-9A-Za-z.\-]*", str(ver))
            out.append((name, m.group(0) if m else "latest"))
    return out


def _parse_go_mod(text: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for line in text.splitlines():
        m = re.match(r"^\s*([a-z0-9._\-/]+)\s+(v[0-9][^\s]*)", line)
        if m and not m.group(1).startswith("go"):
            out.append((m.group(1), m.group(2).lstrip("v")))
    return out


def _parse_gemfile(text: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for m in re.finditer(r"gem\s+['\"]([^'\"]+)['\"]\s*(?:,\s*['\"]([~><=]+\s*[0-9][^'\"]*)['\"])?",
                         text):
        ver = m.group(2) or ""
        vm = re.search(r"[0-9][0-9A-Za-z.\-]*", ver)
        out.append((m.group(1), vm.group(0) if vm else "latest"))
    return out


_PARSERS = {
    "pom.xml": _parse_pom,
    "requirements.txt": _parse_reqs,
    "requirements-dev.txt": _parse_reqs,
    "pyproject.toml": _parse_pyproject,
    "package.json": _parse_package_json,
    "go.mod": _parse_go_mod,
    "Gemfile": _parse_gemfile,
    "Cargo.toml": _parse_reqs,
    "composer.json": _parse_package_json,
    "build.gradle": _parse_reqs,
    "build.gradle.kts": _parse_reqs,
}


def collect_dependencies(root: Path) -> List[Dependency]:
    deps: List[Dependency] = []
    for manifest in discover_manifests(root):
        name = manifest.name
        parser = _PARSERS.get(name)
        if parser is None:
            continue
        try:
            text = manifest.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for pkg, ver in parser(text):
            raw = ver
            if ver in ("latest", "") or ver.startswith("${"):
                raw = ver
                ver = ""
            deps.append(Dependency(
                name=pkg, version=ver, ecosystem=MANIFESTS[name],
                manifest=name, raw_version=raw))
    # dedupe by (ecosystem, name, version)
    seen = set()
    out = []
    for d in deps:
        key = (d.ecosystem, d.name, d.version)
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out


def _severity_of(vuln: Dict[str, Any]) -> str:
    db = vuln.get("database_specific") or {}
    sev = db.get("severity") or ""
    if sev:
        return str(sev)
    for a in vuln.get("affected") or []:
        db = a.get("database_specific") or {}
        sev = db.get("severity") or ""
        if sev:
            return str(sev)
    return "unknown"


def _fixed_version(vuln: Dict[str, Any]) -> Optional[str]:
    fixed: List[str] = []
    for a in vuln.get("affected") or []:
        for rng in a.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    fixed.append(str(ev["fixed"]))
    if not fixed:
        return None
    # prefer semver-looking tags over commit hashes (PyPI advisories mix both)
    semvers = [f for f in fixed if re.match(r"^\d+\.\d+", f)]
    return max(semvers) if semvers else fixed[-1]


def scan_dependencies(deps: List[Dependency],
                      cache_dir: Optional[Path] = None,
                      offline: bool = False) -> Tuple[List[DepFinding], List[str]]:
    findings: List[DepFinding] = []
    notes: List[str] = []
    for dep in deps:
        if not dep.version or dep.version == "latest":
            continue
        key = _cache_key("osv-dep", "%s:%s@%s" % (dep.ecosystem, dep.name, dep.version))
        cached = _read_cache(cache_dir, key)
        if cached is not None:
            data = cached
        elif offline:
            continue
        else:
            try:
                data = _http_json(
                    "https://api.osv.dev/v1/query", method="POST",
                    body={"version": dep.version,
                          "package": {"ecosystem": dep.ecosystem,
                                      "name": dep.name}})
                _write_cache(cache_dir, key, data)
            except Exception as exc:  # noqa: BLE001
                notes.append("%s@%s: OSV query failed (%s)"
                             % (dep.name, dep.version, type(exc).__name__))
                continue
        for vuln in data.get("vulns") or []:
            vid = vuln.get("id") or ""
            if not vid:
                continue
            findings.append(DepFinding(
                dependency=dep,
                vuln_id=vid,
                summary=(vuln.get("summary") or vuln.get("details") or "")[:200],
                severity=_severity_of(vuln),
                fixed_version=_fixed_version(vuln),
                url="https://osv.dev/vulnerability/%s" % vid,
            ))
    return findings, notes


def render_markdown(findings: List[DepFinding],
                    notes: List[str], target: str) -> str:
    lines = [
        "# 依赖漏洞体检报告（OSV）",
        "",
        "目标：`%s`  |  发现 %d 条已知漏洞" % (target, len(findings)),
        "",
        "| 依赖 | 版本 | 漏洞 | 严重级 | 修复版本 |",
        "|---|---|---|---|---|",
    ]
    if not findings:
        lines.append("| （无命中） | | | | |")
    for f in sorted(findings, key=lambda x: x.severity, reverse=True):
        lines.append("| %s | %s | [%s](%s) | %s | `%s` |" % (
            f.dependency.name, f.dependency.version, f.vuln_id, f.url,
            f.severity, f.fixed_version or "待确认"))
    if notes:
        lines += ["", "## 查询异常（未计入）", ""] + ["- " + n for n in notes]
    return "\n".join(lines)
