"""Research, novelty, scoring, replay, and review CLI handlers."""

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
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.tools.cvss import base_score, check_precondition_consistency
from agent.tools.github_auth import github_token_source
from agent.tools.novelty import (
    Disclosure,
    NoveltyChecker,
    UpstreamRef,
    upstream_ref_from_search_hit,
)
from agent.tools import source_evidence as se


def _out(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


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



