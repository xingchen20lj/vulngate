"""S1->S8 stage implementations (deterministic machinery + LLM judgment seams)."""

from __future__ import annotations

import json
import dataclasses
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..memory.ledger import render_finding_md, write_round_artifacts
from ..memory.state import CheckpointStore
from ..sandbox.approval import ApprovalGate
from ..sandbox.runner import CommandRunner
from ..tools import search as srch
from ..tools.build import (JavaMatrixRunner, MatrixCell, POCSpec,
                           ShellMatrixRunner, ShellPOCSpec, summarize_candidate)
from ..tools.authz import normalize_authz_case, normalize_authz_cases
from ..tools.conclusion import derive_conclusion
from ..tools.cvss import base_score, check_impact_consistency
from ..tools.source_evidence import (DANGER_PATTERNS, build_source_sink_graph,
                                     grep_hits, match_source_sink_paths)
from ..tools.patch_variants import analyze_patch_history, fix_completeness_candidate
from ..tools.project_profile import build_project_profile
from ..tools.target_rules import collect_target_rule_hits, composite_chain_hints
from ..tools.novelty import (Disclosure, NoveltyChecker, UpstreamRef,
                             mechanism_audit_llm)
from ..tools.public_scan import scan_all
from .config import TargetConfig
from .gates import (GateResult, g0_dead_code, g1_reachable, g1b_gate_blocks,
                    g3_novelty, g4_runtime, g5_cvss)


class StageContext:
    def __init__(self, workspace: Path, target: str, round_no: int,
                 config: TargetConfig, offline: bool = False,
                 llm: Optional[Any] = None):
        self.workspace = workspace
        self.target = target
        self.round_no = round_no
        self.config = config
        self.offline = offline
        self.llm = llm
        self.store = CheckpointStore(workspace, target, round_no)
        self.approval = ApprovalGate(log_path=self.store.approval_log())
        self.runner = CommandRunner(workspace, self.approval)
        self.checked_at = datetime.now().isoformat(timespec="seconds")
        self._public_scan_cache: Optional[Dict[str, Any]] = None

    def public_disclosures(self) -> Dict[str, Any]:
        if self._public_scan_cache is None:
            self._public_scan_cache = scan_all(
                self.config, offline=self.offline,
                cache_dir=self.workspace / "agent" / "regression" / "cache" / "api")
        return self._public_scan_cache

    def fixture_dir(self) -> Optional[Path]:
        d = self.workspace / "agent" / "regression" / "fixtures"
        return d if d.exists() else None


def _gate_scan(ctx: StageContext) -> List[Dict[str, Any]]:
    keywords = ["SafeMode", "SupportAutoType", "checkAutoType", "maxLevel",
                "readLength", "deny", "registerIfAbsent", "getObjectReader("]
    hits = []
    for src in ctx.config.source_dirs:
        d = ctx.workspace / src
        if not d.exists():
            continue
        for kw in keywords:
            lines = srch.rg(kw, d, globs=["*.java"], max_count=6)
            if lines:
                hits.append({"keyword": kw, "source": src, "lines": lines})
    return hits


def run_s1(ctx: StageContext) -> Dict[str, Any]:
    """Module topology + entry inventory + default-feature inventory.

    Baseline #1/#2 additions: jar version diff (added/removed classes between
    versions) and a danger call-site map (danger patterns x file x line), with
    per-entry danger-hit counts as reachability clues.
    """
    jars_info = []
    class_sets = {}
    for j in ctx.config.jars:
        p = ctx.workspace / j["path"]
        classes = srch.jar_classes(p)
        class_sets[j["version"]] = set(
            c for c in classes if c.endswith(".class") and "module-info" not in c)
        jars_info.append({
            "version": j["version"],
            "path": str(p.relative_to(ctx.workspace)),
            "sha256": srch.sha256(p),
            "size_bytes": p.stat().st_size,
            "class_count": len([c for c in classes if c.endswith(".class")]),
            "module_map": srch.module_map(classes),
        })
    # Version diff: classes added/removed between the oldest and newest jar.
    version_diff = []
    if len(class_sets) >= 2:
        versions = sorted(class_sets.keys())
        base = class_sets[versions[0]]
        head = class_sets[versions[-1]]
        version_diff = {
            "from": versions[0],
            "to": versions[-1],
            "added": sorted(head - base)[:200],
            "removed": sorted(base - head)[:200],
        }
    # Danger call-site map (source dirs only; jar scan is name-level).
    danger_sites = []
    per_file_hits: Dict[str, int] = {}
    for pat, label in DANGER_PATTERNS:
        for h in grep_hits(pat, ctx.config.source_dirs, ctx.workspace, max_lines=8):
            fl = str(h["file"])
            per_file_hits[fl] = per_file_hits.get(fl, 0) + 1
            danger_sites.append({
                "label": label, "pattern": pat,
                "file": fl, "line": h["line"], "text": h["text"],
            })
    entries = []
    for ep in ctx.config.entry_points:
        refs = srch.count_references(ctx.workspace / "targets", ep.get("api", "")) if (ctx.workspace / "targets").exists() else 0
        entry = dict(ep)
        entry["g0"] = g0_dead_code(ep, refs).__dict__
        entry["g1"] = g1_reachable(ep).__dict__
        fl = ep.get("file_line") or ep.get("file") or ""
        fname_tokens = [t for t in re.split(r"[^\w./]+", str(fl)) if t.endswith(".java")]

        def _match(d: Dict[str, object]) -> bool:
            dfile = str(d["file"])
            return any(t in dfile for t in fname_tokens) or (fl and fl in dfile)

        entry["danger_hits"] = sum(1 for d in danger_sites if _match(d))
        entry["reachability_clues"] = [
            {"label": d["label"], "file": d["file"], "line": d["line"]}
            for d in danger_sites if _match(d)
        ][:10]
        entries.append(entry)
    gate_scan = _gate_scan(ctx)
    patch_history = analyze_patch_history(ctx.workspace, max_count=30)
    source_sink_graph = build_source_sink_graph(ctx.config.source_dirs, ctx.workspace)
    target_rule_hits = collect_target_rule_hits(
        ctx.config.target_type, ctx.config.source_dirs, ctx.workspace)
    chain_hints = composite_chain_hints(source_sink_graph)
    project_profile = build_project_profile(
        ctx.config, ctx.workspace, danger_site_count=len(danger_sites),
        source_sink_path_count=len(source_sink_graph),
        security_fix_count=len(patch_history))
    ctx.store.write_artifact("S1", "jars.json", jars_info)
    ctx.store.write_artifact("S1", "entry-inventory.json", entries)
    ctx.store.write_artifact("S1", "gate-scan.json", gate_scan)
    ctx.store.write_artifact("S1", "version-diff.json", version_diff)
    ctx.store.write_artifact("S1", "danger-call-sites.json", danger_sites)
    ctx.store.write_artifact("S1", "security-fix-history.json", patch_history)
    ctx.store.write_artifact("S1", "patch-variants.json", [
        {k: fix[k] for k in ("short_commit", "commit", "parent", "subject",
                             "affected_paths", "variant_hints", "probe_plan")}
        for fix in patch_history
    ])
    ctx.store.write_artifact("S1", "source-sink-graph.json", source_sink_graph)
    ctx.store.write_artifact("S1", "project-profile.json", project_profile)
    ctx.store.write_artifact("S1", "target-rules.json", {
        "target_type": ctx.config.target_type,
        "hits": target_rule_hits,
    })
    ctx.store.write_artifact("S1", "composite-chain-hints.json", chain_hints)
    return {"jars": jars_info, "entries": entries, "gate_scan_count": len(gate_scan),
            "version_diff": version_diff, "danger_site_count": len(danger_sites),
            "security_fix_count": len(patch_history),
            "source_sink_path_count": len(source_sink_graph),
            "target_rule_hit_count": len(target_rule_hits),
            "composite_chain_hint_count": len(chain_hints),
            "project_profile": project_profile}


def run_s2(ctx: StageContext) -> Dict[str, Any]:
    """Attack-surface matrix: entry x input shape x logic -> candidate cells."""
    patch_history = ctx.store.read_artifact("S1", "security-fix-history.json") or []
    existing_ids = {str(c.get("candidate_id")) for c in ctx.config.candidates}
    generated = []
    for fix in patch_history:
        candidate = fix_completeness_candidate(fix)
        if candidate["candidate_id"] not in existing_ids:
            ctx.config.candidates.append(candidate)
            existing_ids.add(candidate["candidate_id"])
            generated.append(candidate)
    matrix = []
    for cand in ctx.config.candidates:
        matrix.append({
            "candidate_id": cand["candidate_id"],
            "surface": cand["surface"],
            "entry": cand.get("entry", ""),
            "input_shape": cand.get("input_shape", ""),
            "logic": cand.get("logic", ""),
            "authz_cases": normalize_authz_cases(cand.get("authz_cases")),
            "status": "candidate",
            "fix_completeness": bool(cand.get("fix_completeness")),
            "patch_commit": cand.get("patch_commit", ""),
            "patch_variants": cand.get("patch_variants", []),
            "chain_components": cand.get("chain_components", []),
        })
    ctx.store.write_artifact("S2", "candidate-matrix.json", matrix)
    return {"candidate_count": len(matrix), "matrix": matrix,
            "generated_fix_candidates": [c["candidate_id"] for c in generated],
            "candidates": ctx.config.candidates}


def run_s3(ctx: StageContext) -> Dict[str, Any]:
    """Static audit per candidate: gates, dead code, default reachability."""
    gate_scan = ctx.store.read_artifact("S1", "gate-scan.json") or []
    source_sink_graph = ctx.store.read_artifact("S1", "source-sink-graph.json") or []
    notes = []
    for cand in ctx.config.candidates:
        audit = cand.get("audit_notes", {})
        g1b = g1b_gate_blocks(audit)
        source_to_sink = cand.get("source_to_sink") or match_source_sink_paths(
            source_sink_graph, cand)
        if source_to_sink:
            cand["source_to_sink"] = source_to_sink
        notes.append({
            "candidate_id": cand["candidate_id"],
            "surface": cand["surface"],
            "audit_notes": audit,
            "g1b": g1b.__dict__,
            "code_location": cand.get("code_location", []),
            "source_to_sink": source_to_sink,
        })
    residuals = []
    for cand in ctx.config.candidates:
        for residual in (cand.get("residuals") or []):
            if isinstance(residual, dict):
                item = dict(residual)
                item.setdefault("candidate_id", cand["candidate_id"])
                residuals.append(item)
    ctx.store.write_artifact("S3", "residuals.json", residuals)
    ctx.store.write_artifact("S3", "audit-notes.json", notes)
    return {"notes": notes, "gate_scan": gate_scan}


def _poc_specs(ctx: StageContext) -> List[POCSpec]:
    specs = []
    for cand in ctx.config.candidates:
        candidate_cases = normalize_authz_cases(cand.get("authz_cases"))
        for poc in cand.get("pocs", []):
            if "script" in poc:
                continue  # shell PoCs are collected separately
            cells = [MatrixCell(
                version=c["version"], safe_mode=c["safe_mode"],
                features=c.get("features", []), precondition=c.get("precondition", "none"),
                args=c.get("args", []), jvm=c.get("jvm", {}),
                authz=normalize_authz_case(c.get("authz") or
                                           (candidate_cases[0] if len(candidate_cases) == 1 else {})),
            ) for c in poc.get("cells", [])]
            specs.append(POCSpec(
                candidate_id=cand["candidate_id"],
                class_name=poc["class_name"],
                src=poc["src"],
                cells=cells,
                safe_mode_jvm_prop=poc.get("safe_mode_jvm_prop", ""),
                module_opts=poc.get("module_opts", []),
                module_run_opts=poc.get("module_run_opts", poc.get("module_opts", [])),
                jvm_default=poc.get("jvm_default", {}),
                entry=cand.get("entry", ""),
                input_shape=cand.get("input_shape", ""),
                logic=cand.get("logic", ""),
            ))
    return specs


def _shell_poc_specs(ctx: StageContext) -> List[ShellPOCSpec]:
    specs = []
    for cand in ctx.config.candidates:
        candidate_cases = normalize_authz_cases(cand.get("authz_cases"))
        for poc in cand.get("pocs", []):
            if "script" not in poc:
                continue
            cells = [MatrixCell(
                version=c["version"], safe_mode=c["safe_mode"],
                features=c.get("features", []), precondition=c.get("precondition", "none"),
                args=c.get("args", []), jvm=c.get("jvm", {}),
                timeout=c.get("timeout"),
                authz=normalize_authz_case(c.get("authz") or
                                           (candidate_cases[0] if len(candidate_cases) == 1 else {})),
            ) for c in poc.get("cells", [])]
            specs.append(ShellPOCSpec(
                candidate_id=cand["candidate_id"],
                script=poc["script"],
                cells=cells,
                env=dict(poc.get("env", {})),
                entry=cand.get("entry", ""),
                input_shape=cand.get("input_shape", ""),
                logic=cand.get("logic", ""),
            ))
    return specs


def _stage_pocs(ctx: StageContext) -> None:
    """Copy PoC sources from config.poc_src_dir into the round src dir (idempotent)."""
    src_round = ctx.workspace / "poc" / ctx.target / ("round-%02d" % ctx.round_no) / "src"
    src_round.mkdir(parents=True, exist_ok=True)
    if not ctx.config.poc_src_dir:
        return
    poc_dir = ctx.workspace / ctx.config.poc_src_dir
    if not poc_dir.exists():
        return
    for f in sorted(poc_dir.glob("*.java")) + sorted(poc_dir.glob("*.sh")):
        target = src_round / f.name
        if not target.exists():
            target.write_text(f.read_text(encoding="utf-8"), encoding="utf-8")


def run_s4(ctx: StageContext) -> Dict[str, Any]:
    """Minimal PoC + verification matrix: version x safe-mode x precondition."""
    _stage_pocs(ctx)
    jars_by_version = ctx.config.resolve_jars(ctx.workspace)
    results = {}
    java_specs = _poc_specs(ctx)
    if java_specs:
        matrix_runner = JavaMatrixRunner(ctx.workspace, ctx.target, ctx.round_no, ctx.approval)
        results.update(matrix_runner.run_manifest(java_specs, jars_by_version))
    shell_specs = _shell_poc_specs(ctx)
    if shell_specs:
        shell_runner = ShellMatrixRunner(ctx.workspace, ctx.target, ctx.round_no, ctx.approval)
        results.update(shell_runner.run_manifest(shell_specs))
    summaries = {}
    authz_matrix = []
    for cand in ctx.config.candidates:
        cid = cand["candidate_id"]
        cells = results.get(cid, [])
        summaries[cid] = summarize_candidate(cells)
        summaries[cid]["cells_ran"] = len(cells)
        for cell in cells:
            assertion = cell.get("authz_assertion")
            if assertion and assertion.get("status") != "not_applicable":
                authz_matrix.append({
                    "candidate_id": cid,
                    "version": cell.get("version"),
                    "safe_mode": cell.get("safe_mode"),
                    "precondition": cell.get("precondition"),
                    "authz": normalize_authz_case(cell.get("authz", {})),
                    "assertion": assertion,
                })
    ctx.store.write_artifact("S4", "verification-matrix.json", summaries)
    ctx.store.write_artifact("S4", "authz-matrix.json", authz_matrix)
    return {"summaries": summaries}


def _derive_conclusion(candidate: Dict[str, Any], summary: Dict[str, Any],
                       cells: Optional[List[Dict[str, Any]]] = None) -> str:
    """Data-driven conclusion, delegating to the shared rules module
    (baseline fix #10: one implementation across config/autonomous/benchmark)."""
    return derive_conclusion(summary, candidate, cells)


def run_s5(ctx: StageContext) -> Dict[str, Any]:
    """Novelty gate: upstream open PR/issue + public disclosure + timeline."""
    cache_dir = ctx.workspace / "agent" / "regression" / "cache" / "api"
    checker = NoveltyChecker(fixtures_dir=ctx.fixture_dir(), offline=ctx.offline,
                             cache_dir=cache_dir)
    pub = ctx.public_disclosures()
    results = {}
    coverage = {
        "offline": ctx.offline,
        "public_scan_channels": pub.get("channels", {}),
        "public_scan_errors": pub.get("errors", []),
        "public_disclosure_count": len(pub.get("disclosures", [])),
        "candidates": [],
    }
    for cand in ctx.config.candidates:
        if cand.get("skip_novelty"):
            results[cand["candidate_id"]] = {
                "novelty": {"verdict": "not-applicable", "reason": "排除项候选不主张 0day，跳过 Novelty 判定"},
                "g3": {"gate_id": "G3", "passed": True, "verdict": "not-applicable", "evidence": []},
            }
            continue
        refs = []
        for r in cand.get("upstream_refs", []):
            refs.append(UpstreamRef(**r))
        # Live scan: refresh config refs via API and search by keywords.
        repo = ctx.config.upstream_repo or ""
        keyword_limit = max(1, int(cand.get("novelty_max_keywords", 12)))
        result_limit = max(1, int(cand.get("novelty_max_results", 20)))
        coverage["candidates"].append({
            "candidate_id": cand["candidate_id"],
            "repo": repo,
            "keywords": list(cand.get("novelty_keywords", []))[:keyword_limit],
            "keyword_limit": keyword_limit,
            "result_limit": result_limit,
        })
        if repo and not ctx.offline:
            for r in list(refs):
                num = "".join(ch for ch in r.ref if ch.isdigit())
                if num:
                    live = checker.fetch_ref(
                        repo, int(num), "pulls" if r.kind == "pull_request" else "issues")
                    if live is not None:
                        live.coverage_note = r.coverage_note
                        refs[refs.index(r)] = live
            for kw in cand.get("novelty_keywords", [])[:keyword_limit]:
                for item in checker.search(repo, kw)[:result_limit]:
                    number = item.get("number")
                    ref = UpstreamRef(
                        ref=("#%d" % number) if number else item.get("title", "")[:24],
                        kind="pull_request" if item.get("pull_request") else "issue",
                        title=item.get("title", ""),
                        state=item.get("state", ""),
                        created_at=item.get("created_at", ""),
                        url=item.get("html_url", ""),
                        evidence_source="live GitHub search",
                    )
                    if ref.ref not in {x.ref for x in refs}:
                        refs.append(ref)
        disclosures = []
        for d in cand.get("disclosures", []):
            disclosures.append(Disclosure(**d))
        disclosures += pub["disclosures"]
        # Baseline #7: when any public-info channel failed (or the run is
        # offline / rate-limited), absence of a record is NOT a 0day claim.
        query_failed = bool(pub.get("errors")) or checker.last_rate_limit is not None \
            or ctx.offline
        nv = checker.evaluate(refs, disclosures, ctx.config.discovery_date,
                              increments_hint=cand.get("increments_hint", []),
                              query_failed=query_failed)
        g3 = g3_novelty(nv.__dict__)
        nv_dict = dataclasses.asdict(nv)
        results[cand["candidate_id"]] = {"novelty": nv_dict, "g3": g3.__dict__}
        if getattr(ctx.config, "llm_audit", False) and ctx.llm is not None:
            audit = mechanism_audit_llm(
                ctx.llm, "你是资深安全研究员，判断上游记录与候选是否同一漏洞机制。",
                cand, refs, checker, ctx.config.discovery_date,
                ctx.config.upstream_repo or "", offline=ctx.offline)
            if audit:
                same = [a for a in audit if a.get("same_mechanism")]
                if same:
                    # Mechanism audit found an upstream body for the same bug:
                    # downgrade the verdict and recompute G3 (previously the
                    # gate was computed only before the audit).
                    nv_dict["verdict"] = "known-family-with-increment"
                    nv_dict["reason"] += " | upstream body confirms same mechanism: %s" % ", ".join(
                        str(a.get("ref")) for a in same)
                nv_dict["increments"] = list(nv_dict.get("increments", [])) + [
                    "mechanism audit (pipeline): %d reviewed, %d same"
                    % (len(audit), len(same))]
                g3 = g3_novelty(nv_dict)
                results[cand["candidate_id"]] = {
                    "novelty": nv_dict, "g3": g3.__dict__,
                    "mechanism_audit": audit,
                }
    if checker.last_rate_limit:
        results["api_rate_limit"] = checker.last_rate_limit
    results["public_scan"] = {
        "channels": pub["channels"], "errors": pub["errors"],
        "disclosure_ids": [d.id for d in pub["disclosures"]],
    }
    coverage["authoritative"] = not bool(pub.get("errors")) and not ctx.offline
    ctx.store.write_artifact("S5", "novelty-coverage.json", coverage)
    ctx.store.write_artifact("S5", "novelty.json", results)
    return {"novelty": results}


def run_s6(ctx: StageContext, summaries: Dict[str, Any], conclusions: Dict[str, str]) -> Dict[str, Any]:
    """Severity calibration: defensible CVSS + precondition consistency (G5)."""
    out = {}
    for cand in ctx.config.candidates:
        cid = cand["candidate_id"]
        if conclusions.get(cid) != "确认":
            continue
        vector = cand.get("cvss_vector", "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N")
        tier = cand.get("precondition_tier_hint", "single-feature")
        score, severity = base_score(vector)
        g5 = g5_cvss(tier, vector, cand.get("implicit_default_on", False))
        impact_ok, impact_reason = check_impact_consistency(cand, summaries.get(cid, {}), vector)
        if not impact_ok:
            g5.passed = False
            g5.evidence = (g5.evidence or []) + [impact_reason]
            g5.verdict = "impact evidence insufficient"
        out[cid] = {
            "vector": vector,
            "score": round(score, 1),
            "severity": severity,
            "tier": tier,
            "g5": g5.__dict__,
            "impact": cand.get("impact", []),
            "boundary": cand.get("boundary", ""),
        }
        if not g5.passed:
            out[cid]["blocked"] = True
    ctx.store.write_artifact("S6", "severity.json", out)
    return {"severity": out}


def _evidence_from_summary(summary: Dict[str, Any], candidate: Dict[str, Any]) -> List[str]:
    ev = []
    if summary.get("harness_error"):
        ev.append("HARNESS_ERROR=" + str(summary["harness_error"]))
    if summary.get("compile_error"):
        ev.append("COMPILE_ERROR=" + str(summary["compile_error"]))
    for i in summary.get("instantiated", [])[:4]:
        ev.append("%s SafeMode=%s %s -> INSTANTIATED %s" % (
            i["version"], i["safe"], i["precondition"], i["class"]))
    for e in summary.get("errors", [])[:6]:
        ev.append("%s SafeMode=%s %s -> ERROR %s" % (
            e["version"], e["safe"], e["precondition"], e["error"]))
    for g in summary.get("gate_blocked", [])[:4]:
        ev.append("%s SafeMode=%s %s -> GATE_BLOCKED %s" % (
            g["version"], g["safe"], g["precondition"], g["class"]))
    for n in summary.get("network_side_effects", [])[:2]:
        ev.append("NETWORK %s" % n)
    for lk in summary.get("leaked", [])[:3]:
        ev.append("%s SafeMode=%s %s -> LEAKED %s" % (
            lk["version"], lk["safe"], lk["precondition"], lk["leaked"][:120]))
    for c in summary.get("safe_equivalent", [])[:4]:
        ev.append("%s SafeMode=%s %s -> SAFE_EQUIVALENT %s %s" % (
            c["version"], c["safe"], c["precondition"], c["kind"], c.get("detail", "")))
    for e in summary.get("effect_evidence", [])[:4]:
        ev.append("%s SafeMode=%s %s -> EFFECT_KIND=%s EFFECT=%s" % (
            e["version"], e["safe"], e["precondition"], e["kind"], e.get("detail", "")))
    for a in summary.get("availability_proof", [])[:2]:
        ev.append("%s SafeMode=%s %s -> AVAILABILITY_PROOF=concurrency:%s service_unavailable:%s" % (
            a["version"], a["safe"], a["precondition"], a["concurrency"], a["service_unavailable"]))
    for a in summary.get("authz_results", [])[:8]:
        az = a.get("authz", {})
        ev.append("%s SafeMode=%s %s -> AUTHZ_CASE=%s principal=%s role=%s tenant=%s object=%s assertion=%s boundary_violation=%s" % (
            a.get("version"), a.get("safe"), a.get("precondition"),
            az.get("case_id", "?"), az.get("principal", "?"), az.get("role", "?"),
            az.get("tenant_id", "?"), az.get("object_id", "?"),
            a.get("status"), a.get("boundary_violation")))
    for issue in summary.get("validation_issues", [])[:4]:
        ev.append("VALIDATION_ISSUE=" + str(issue))
    ev.append("cells_ran=%d" % summary.get("cells_ran", 0))
    return ev


def run_s7(ctx: StageContext, rows: List[Dict[str, Any]], summaries: Dict[str, Any],
           severities: Dict[str, Any]) -> Dict[str, Any]:
    """Coordination/disclosure prep: self-contained finding docs + timeline."""
    reports_dir = ctx.workspace / "reports" / ctx.target / ("round-%02d" % ctx.round_no)
    reports_dir.mkdir(parents=True, exist_ok=True)
    written = []
    idx = 0
    for cand in ctx.config.candidates:
        cid = cand["candidate_id"]
        if cand.get("conclusion_override", "确认") != "确认":
            continue
        row = next((r for r in rows if r.get("candidate_id") == cid), {})
        if row.get("conclusion") != "确认":
            continue
        idx += 1
        sev = severities.get(cid, {})
        novelty_record = (ctx.store.read_artifact("S5", "novelty.json") or {}).get(cid, {})
        affected_versions = cand.get("affected_versions") or [
            str(j.get("version")) for j in ctx.config.jars if j.get("version")]
        negative_results = list(cand.get("negative_results") or [])
        negative_results += ["%s" % issue for issue in
                             (ctx.store.read_artifact("S4", "verification-matrix.json") or {}
                              ).get(cid, {}).get("validation_issues", [])]
        finding = {
            "title": row.get("surface", cid),
            "date": ctx.config.discovery_date,
            "status": "确认（机制级，受控验证）",
            "summary": cand.get("finding_summary", row.get("surface", "")),
            "entrypoint": cand.get("entry", ""),
            "affected_versions": affected_versions,
            "fixed_versions": cand.get("fixed_versions", []),
            "source_to_sink": cand.get("source_to_sink", []),
            "code_location": cand.get("code_location", []),
            "scope": ctx.config.scope_constraints,
            "repro": cand.get("repro", ""),
            "evidence": "\n".join(row.get("evidence", [])) or "见 matrix-runs 输出",
            "preconditions": cand.get("preconditions", []),
            "authorization_matrix": row.get("authorization_matrix", []),
            "negative_results": negative_results,
            "novelty": novelty_record.get("novelty", novelty_record),
            "cvss": sev,
            "impact": sev.get("impact", []),
            "boundary": sev.get("boundary", cand.get("boundary", "")),
            "timeline": cand.get("timeline", [{"date": ctx.config.discovery_date, "event": "发现并完成验证矩阵"}]),
        }
        fname = ("finding-%02d-%s.md" % (idx, cid) if ctx.config.output_lang == "en"
                 else "挖洞-发现-%02d-%s.md" % (idx, cid))
        (reports_dir / fname).write_text(
            render_finding_md(finding, lang=ctx.config.output_lang), encoding="utf-8")
        written.append(fname)
    return {"finding_docs": written, "dir": str(reports_dir.relative_to(ctx.workspace))}


def run_s8(ctx: StageContext, summaries: Dict[str, Any], conclusions: Dict[str, str],
           novelties: Dict[str, Any], severities: Dict[str, Any]) -> Dict[str, Any]:
    """Round close: ledger + exclusions + summary + next-round candidates."""
    rows = []
    excluded = []
    for cand in ctx.config.candidates:
        cid = cand["candidate_id"]
        summary = summaries.get(cid, {})
        conclusion = conclusions.get(cid, "候选（待验证）")
        row = {
            "candidate_id": cid,
            "surface": cand["surface"],
            "conclusion": conclusion,
            "evidence": _evidence_from_summary(summary, cand),
            "precondition_tier": cand.get("precondition_tier_hint", ""),
            "code_location": cand.get("code_location", []),
            "authorization_matrix": summary.get("authz_results", []),
        }
        nv = novelties.get(cid, {}).get("novelty")
        if nv:
            row["novelty"] = {"verdict": nv["verdict"], "reason": nv["reason"],
                              "increments": nv.get("increments", [])}
        if cid in severities:
            row["cvss"] = {"vector": severities[cid]["vector"], "score": severities[cid]["score"]}
            if severities[cid].get("blocked"):
                row["conclusion"] = "候选（待验证）"
                row["evidence"].append(
                    "G5_BLOCKED=" + "; ".join(severities[cid].get("g5", {}).get("evidence", [])))
        rows.append(row)
        if conclusion == "排除":
            excluded.append({
                "surface": cand["surface"],
                "conclusion": "排除（%s）" % cand.get("exclusion_reason", "门控/受控异常"),
                "evidence": row["evidence"],
            })
    confirmed_rows = [r for r in rows if r["conclusion"] == "确认"]
    novelty_misses = len([
        r for r in confirmed_rows
        if (r.get("novelty") or {}).get("verdict") == "candidate-0day"
        and any(k in (r.get("novelty") or {}).get("reason", "") for k in ("upstream", "disclosure"))
    ])
    metrics = {
        "候选数": len(ctx.config.candidates),
        "确认数": len(confirmed_rows),
        "排除数": len([r for r in rows if r["conclusion"] == "排除"]),
        "候选->PoC 转化率": "%d/%d" % (len(confirmed_rows), len(ctx.config.candidates)),
        "Novelty 漏检数（必须=0）": novelty_misses,
        "前置分布": _precondition_distribution(rows),
    }
    next_round = [c.get("next_round_hint", "") for c in ctx.config.candidates
                  if c.get("next_round_hint")]
    summary = {
        "header_note": ctx.config.notes,
        "metrics": metrics,
        "next_round": next_round or ["复测 2.0.65（#7753 发布后）", "扩展模块轮（HTTP/Redis/JSONB 集成面）"],
    }
    out_dir = write_round_artifacts(ctx.workspace, ctx.target, ctx.round_no, rows, excluded,
                                    summary, lang=ctx.config.output_lang)
    return {"ledger_dir": str(out_dir.relative_to(ctx.workspace)), "rows": len(rows),
            "excluded": len(excluded), "metrics": metrics}


def _precondition_distribution(rows: List[Dict[str, Any]]) -> str:
    from collections import Counter
    c = Counter(r.get("precondition_tier", "?") for r in rows if r["conclusion"] == "确认")
    return ", ".join("%s=%d" % (k, v) for k, v in sorted(c.items()))
