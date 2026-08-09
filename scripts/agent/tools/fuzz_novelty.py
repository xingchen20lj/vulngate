"""Live novelty triage for fuzz-generated candidates (plan 2.1 follow-up).

Loads state/<target>/round-NN/FUZZ/fuzz-candidates.json and runs the same
Novelty machinery as S5 (upstream issue/PR search + evaluate) against each
candidate, including the crash-family ones that stay "待验证" in the round
(they never reach S5 because S5 only claims confirmed findings).

Outputs:
  state/<target>/round-NN/FUZZ/novelty-triage.json  (machine-readable)
  state/<target>/round-NN/FUZZ/novelty-triage.md    (human summary)

The same-mechanism check is a conservative body-overlap heuristic (distinctive
tokens of the candidate's surface/error vs upstream title+body); a hint is not
a claim -- humans decide. API responses are disk-cached by NoveltyChecker
(6h TTL + ETag), so re-runs are cheap.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..llm.adapter import BudgetExceeded, LLMClient
from ..orchestrator.config import TargetConfig
from ..tools.novelty import NoveltyChecker, UpstreamRef

ROOT = Path(__file__).resolve().parents[2]

STOP_TOKENS = {
    "jsonb", "parse", "crash", "fuzz", "input", "length", "lengths",
    "null", "error", "errors", "range", "index", "array", "object",
    "string", "value", "entry", "java", "lang", "com", "alibaba",
}


def _tokens(text: str) -> List[str]:
    return [t for t in re.split(r"[^A-Za-z0-9]+", text) if len(t) >= 4]


def _distinctive_tokens(cand: Dict[str, Any]) -> List[str]:
    """Tokens that identify the mechanism (exception type, class names,
    byte-code-ish names, bucket)."""
    fz = cand.get("fuzz_spec") or {}
    src = " ".join([
        cand.get("surface", ""),
        cand.get("logic", ""),
        fz.get("bucket", ""),
        fz.get("signature", ""),
    ])
    tokens = []
    for t in _tokens(src):
        low = t.lower()
        if low in STOP_TOKENS:
            continue
        if t not in tokens:
            tokens.append(t)
    # keep the strongest candidates at the front (exception name / class name)
    exc_names = [t for t in tokens if t.endswith("Exception") or t.endswith("Error")]
    return (exc_names + [t for t in tokens if t not in exc_names])[:10]


def _body_overlap(cand: Dict[str, Any], refs: List[UpstreamRef]) -> List[Dict[str, Any]]:
    tokens = _distinctive_tokens(cand)
    hits = []
    for r in refs:
        hay = "%s %s %s" % (r.title, r.body, r.coverage_note)
        hay_l = hay.lower()
        matched = [t for t in tokens if t.lower() in hay_l]
        if matched:
            hits.append({
                "ref": r.ref,
                "title": r.title,
                "matched_tokens": matched[:6],
                "url": r.url,
            })
    return hits


def _search_queries(cand: Dict[str, Any]) -> List[str]:
    """Specific queries instead of the broad candidate keywords: exception
    class name + distinctive token + bucket, so unrelated JSONB issues do not
    drown the signal."""
    fz = cand.get("fuzz_spec") or {}
    sig = fz.get("signature", "")
    exc = ""
    m = re.search(r"([A-Za-z0-9]+(?:Exception|Error))", sig)
    if m:
        exc = m.group(1)
    tokens = _distinctive_tokens(cand)
    queries = []
    if exc:
        queries.append("%s JSONB" % exc)
        if tokens:
            queries.append("%s %s" % (exc, tokens[0]))
    if tokens:
        queries.append("JSONB %s" % tokens[0])
    queries.append("%s JSONB" % fz.get("bucket", ""))
    return [q for q in dict.fromkeys(queries) if q.strip()][:4]


def _llm_mechanism_audit(cand: Dict[str, Any], refs: List[UpstreamRef],
                         llm: Optional[LLMClient]) -> List[Dict[str, Any]]:
    if llm is None or not refs:
        return []
    numbered = []
    for r in refs:
        m = re.search(r"#(\d+)", str(r.ref))
        if m and r.body:
            numbered.append(r)
    numbered = numbered[:3]
    if not numbered:
        return []
    bodies = [{
        "ref": r.ref, "title": r.title,
        "body": (r.body or "(body unavailable)")[:1500],
    } for r in numbered]
    user = (
        "候选：%s\n逻辑：%s\n\n上游记录（issue/PR 标题+正文）：\n%s\n\n"
        "逐条判断是否与候选是同一漏洞机制（同一触发点/同一 gadget 类/同一修复对象）。"
        "只输出 JSON：{\"results\":[{\"ref\":\"#N\",\"same_mechanism\":true|false,"
        "\"evidence\":\"一句话依据\"}]}"
        % (cand.get("surface", ""), cand.get("logic", ""),
           json.dumps(bodies, ensure_ascii=False)[:6000])
    )
    try:
        data = llm.ask_json(
            "你是资深 Java 安全研究员。输出严格 JSON，不要 Markdown 围栏。",
            user, max_tokens=1200)
        results = data.get("results") or []
        return [{"ref": str(b.get("ref")), "same_mechanism": bool(b.get("same_mechanism")),
                 "evidence": str(b.get("evidence", ""))[:300]} for b in results][:5]
    except (ValueError, BudgetExceeded):
        return []


def triage(workspace: Path, cfg: TargetConfig, round_no: int,
           max_candidates: Optional[int] = None,
           offline: bool = False, use_llm: bool = False) -> Dict[str, Any]:
    fuzz_dir = workspace / "state" / cfg.name / ("round-%02d" % round_no) / "FUZZ"
    cand_file = fuzz_dir / "fuzz-candidates.json"
    if not cand_file.exists():
        raise FileNotFoundError("fuzz candidates missing: %s (run fuzzer first)" % cand_file)
    cands = json.loads(cand_file.read_text(encoding="utf-8"))
    if max_candidates:
        cands = cands[:max_candidates]

    checker = NoveltyChecker(
        fixtures_dir=workspace / "agent" / "regression" / "fixtures"
        if (workspace / "agent" / "regression" / "fixtures").exists() else None,
        offline=offline,
        cache_dir=workspace / "agent" / "regression" / "cache" / "api")
    repo = cfg.upstream_repo or ""
    discovery_date = cfg.discovery_date or date.today().isoformat()
    llm = LLMClient(max_calls=40, max_tokens_total=120_000) if use_llm else None

    rows: List[Dict[str, Any]] = []
    for cand in cands:
        cid = cand["candidate_id"]
        refs: List[UpstreamRef] = []
        for r in cand.get("upstream_refs", []):
            refs.append(UpstreamRef(**r))
        search_hits = []
        if repo and not offline:
            for kw in _search_queries(cand):
                for item in checker.search(repo, kw)[:8]:
                    number = item.get("number")
                    ref = UpstreamRef(
                        ref=("#%d" % number) if number else item.get("title", "")[:24],
                        kind="pull_request" if item.get("pull_request") else "issue",
                        title=item.get("title", ""),
                        state=item.get("state", ""),
                        created_at=item.get("created_at", ""),
                        url=item.get("html_url", ""),
                        evidence_source="live GitHub search (fuzz triage)",
                    )
                    if ref.ref not in {x.ref for x in refs}:
                        refs.append(ref)
                    search_hits.append(ref.ref)

        # fetch bodies for predating refs (same-mechanism heuristic)
        predating = [r for r in refs if r.predates(discovery_date)][:5]
        for r in predating:
            num = "".join(ch for ch in r.ref if ch.isdigit())
            if num and not r.body and repo:
                live = checker.fetch_ref(repo, int(num),
                                         "pulls" if r.kind == "pull_request" else "issues")
                if live is not None:
                    live.coverage_note = r.coverage_note
                    refs[refs.index(r)] = live

        predating_ids = {r.ref for r in predating}
        predating_live = [r for r in refs if r.ref in predating_ids]
        overlap = _body_overlap(cand, predating_live)
        audit = _llm_mechanism_audit(cand, predating_live, llm)
        same_mechanism = [a for a in audit if a.get("same_mechanism")]
        nv = checker.evaluate(refs, [], discovery_date,
                              increments_hint=cand.get("increments_hint", []))
        if same_mechanism:
            nv.increments.append(
                "LLM mechanism audit: same mechanism in %s"
                % ", ".join(str(a.get("ref")) for a in same_mechanism))
        elif predating and audit:
            nv.increments.append(
                "LLM mechanism audit: %d upstream bodies reviewed, none same mechanism"
                % len(audit))
        rows.append({
            "candidate_id": cid,
            "surface": cand.get("surface", ""),
            "bucket": (cand.get("fuzz_spec") or {}).get("bucket", ""),
            "verdict": nv.verdict,
            "reason": nv.reason,
            "increments": nv.increments,
            "search_hits": sorted(set(search_hits)),
            "refs": [dataclass_dict(r) for r in refs],
            "body_overlap": overlap,
            "mechanism_audit": audit,
            "distinctive_tokens": _distinctive_tokens(cand),
        })
        print("[triage] %s %-8s %-28s hits=%d overlap=%d same=%d" % (
            cid, nv.verdict, cand.get("surface", "")[:28],
            len(search_hits), len(overlap), len(same_mechanism)))

    out = {
        "target": cfg.name,
        "round": round_no,
        "repo": repo,
        "discovery_date": discovery_date,
        "checked_at": __import__("datetime").datetime.now().isoformat(timespec="seconds"),
        "rate_limited": checker.last_rate_limit is not None,
        "rows": rows,
    }
    fuzz_dir.mkdir(parents=True, exist_ok=True)
    (fuzz_dir / "novelty-triage.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    _write_md(fuzz_dir, out)
    return out


def dataclass_dict(obj: Any) -> Dict[str, Any]:
    if hasattr(obj, "__dataclass_fields__"):
        return {k: getattr(obj, k) for k in obj.__dataclass_fields__}
    return dict(obj)


def _write_md(fuzz_dir: Path, out: Dict[str, Any]) -> None:
    lines = [
        "# Fuzz 候选 Novelty 实时分诊（round %02d · %s）" % (out["round"], out["target"]),
        "",
        "> 上游：%s ｜ 发现日期：%s ｜ 限流：%s" % (
            out["repo"], out["discovery_date"], out["rate_limited"]),
        "> 判定由 NoveltyChecker.evaluate 产出；正文重叠为保守启发式（非主张）。",
        "",
        "| 候选 | bucket | verdict | 上游命中 | 同机制(LLM) |",
        "|---|---|---|---|---|",
    ]
    for r in out["rows"]:
        hits = ", ".join(r["search_hits"][:5]) or "-"
        same = ", ".join("%s(%s)" % (a["ref"], a["evidence"][:40])
                         for a in r.get("mechanism_audit", [])
                         if a.get("same_mechanism")) or "-"
        lines.append("| %s | %s | %s | %s | %s |" % (
            r["candidate_id"], r["bucket"], r["verdict"], hits, same))
    lines += ["", "## 待人工核查（无同机制上游记录）", ""]
    pending = [r for r in out["rows"]
               if r["verdict"] in ("candidate-0day", "known-family-with-increment")
               and not any(a.get("same_mechanism") for a in r.get("mechanism_audit", []))]
    if not pending:
        lines.append("- 无")
    for r in pending:
        lines.append("- %s %s｜tokens: %s｜hits: %s" % (
            r["candidate_id"], r["surface"],
            ", ".join(r["distinctive_tokens"][:5]),
            ", ".join(r["search_hits"][:5]) or "-"))
    (fuzz_dir / "novelty-triage.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Fuzz candidate live novelty triage")
    ap.add_argument("--target", required=True)
    ap.add_argument("--round", type=int, required=True)
    ap.add_argument("--config", default=None)
    ap.add_argument("--max-candidates", type=int, default=None)
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--llm", action="store_true",
                    help="LLM mechanism audit for predating upstream refs")
    args = ap.parse_args(argv)
    cfg_path = Path(args.config) if args.config else (
        ROOT / "agent" / "regression" / "configs" / (args.target + ".json"))
    cfg = TargetConfig.load(cfg_path)
    triage(ROOT, cfg, args.round, max_candidates=args.max_candidates,
           offline=args.offline, use_llm=args.llm)
    return 0


if __name__ == "__main__":
    sys.exit(main())
