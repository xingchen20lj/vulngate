"""Append-only ledger rendering (bilingual zh/en) + JSON output.

Language is chosen per target via config `output_lang` ("zh" default, "en"
available); filenames follow the language (挖洞-* for zh, ledger-*/finding-*
for en). Format mirrors the methodology samples.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


L10N = {
    "zh": {
        "ledger_title": "# 挖洞候选账本 %02d（%s 轮次）",
        "ledger_fmt": "格式：`{候选面, 结论, 证据, 前置条件分级, 代码位置}`。先收集后整理，轮次末出汇总。",
        "ledger_cols": ["候选面", "结论", "证据", "前置条件", "代码位置"],
        "novelty_section": "## Novelty 与定级",
        "novelty_cols": ["候选", "Novelty 判定", "理由", "增量清单", "CVSS"],
        "excl_title": "# 挖洞候选排除清单（%s 轮次 · %s）",
        "excl_intro": "记录本轮已排查并排除（或降级为低优先）的候选攻击面，供后续答辩/说明使用。",
        "excl_cols": ["候选面", "结论", "依据"],
        "sum_title": "# 挖洞轮次汇总 %02d（%s）",
        "confirmed": "## 确认",
        "excluded": "## 排除",
        "none": "- 无",
        "metrics": "## 指标",
        "next_round": "## 下一轮候选",
        "finding_title": "# 挖洞发现：%s",
        "date": "日期：%s",
        "status": "状态：%s",
        "summary": "## 摘要",
        "repro": "## 复现（自包含，无外链）",
        "evidence": "## 实测证据（运行输出）",
        "preconditions": "## 前置条件清单",
        "impact": "## 影响分级",
        "boundary": "## 边界声明",
        "timeline": "## 披露时间线",
        "date_col": "日期",
        "event_col": "事件",
        "ledger_file": "挖洞-候选账本-%02d.md",
        "excl_file": "挖洞-已排除清单-%02d.md",
        "sum_file": "挖洞-轮次汇总-%02d.md",
        "finding_file": "挖洞-发现-%02d-%s.md",
    },
    "en": {
        "ledger_title": "# Candidate Ledger %02d (%s round)",
        "ledger_fmt": "Format: `{surface, conclusion, evidence, precondition tier, code location}`. Collected first, summarized at round end.",
        "ledger_cols": ["Surface", "Conclusion", "Evidence", "Precondition", "Code Location"],
        "novelty_section": "## Novelty & Severity",
        "novelty_cols": ["Candidate", "Novelty Verdict", "Reason", "Increments", "CVSS"],
        "excl_title": "# Excluded Candidates (%s round · %s)",
        "excl_intro": "Candidates reviewed and excluded (or downgraded) this round, kept for later defense/discussion.",
        "excl_cols": ["Surface", "Conclusion", "Basis"],
        "sum_title": "# Round Summary %02d (%s)",
        "confirmed": "## Confirmed",
        "excluded": "## Excluded",
        "none": "- none",
        "metrics": "## Metrics",
        "next_round": "## Next-round Candidates",
        "finding_title": "# Finding: %s",
        "date": "Date: %s",
        "status": "Status: %s",
        "summary": "## Summary",
        "repro": "## Reproduction (self-contained, no external links)",
        "evidence": "## Runtime Evidence (run output)",
        "preconditions": "## Preconditions",
        "impact": "## Impact",
        "boundary": "## Boundary Statement",
        "timeline": "## Disclosure Timeline",
        "date_col": "Date",
        "event_col": "Event",
        "ledger_file": "ledger-%02d.md",
        "excl_file": "excluded-%02d.md",
        "sum_file": "round-summary-%02d.md",
        "finding_file": "finding-%02d-%s.md",
    },
}


def _t(lang: str) -> Dict[str, str]:
    return L10N.get(lang, L10N["zh"])


def _fmt_evidence(row: Dict) -> str:
    ev = row.get("evidence", [])
    if isinstance(ev, list):
        return "<br>".join(str(e) for e in ev)
    return str(ev)


def render_ledger_md(rows: List[Dict], round_no: int, target: str,
                     header_note: str = "", lang: str = "zh") -> str:
    t = _t(lang)
    lines = [
        t["ledger_title"] % (round_no, target),
        "",
        t["ledger_fmt"],
        "",
    ]
    if header_note:
        lines += ["> %s" % header_note, ""]
    cols = t["ledger_cols"]
    lines += ["| %s |" % " | ".join(cols), "|" + "---|" * len(cols)]
    for r in rows:
        code = r.get("code_location", "")
        if isinstance(code, list):
            code = "<br>".join(str(c) for c in code)
        lines.append("| %s | %s | %s | %s | %s |" % (
            r.get("surface", r.get("candidate_surface", "")),
            r.get("conclusion", ""),
            _fmt_evidence(r),
            r.get("precondition_tier", ""),
            code,
        ))
    lines += ["", t["novelty_section"], ""]
    ncols = t["novelty_cols"]
    lines += ["| %s |" % " | ".join(ncols), "|" + "---|" * len(ncols)]
    for r in rows:
        if r.get("novelty") or r.get("cvss"):
            nv_raw = r.get("novelty")
            cv_raw = r.get("cvss")
            nv = nv_raw if isinstance(nv_raw, dict) else {
                "verdict": str(nv_raw or "-"), "reason": "", "increments": []}
            cv = cv_raw if isinstance(cv_raw, dict) else {
                "vector": "-", "score": str(cv_raw or "-")}
            lines.append("| %s | %s | %s | %s | %s |" % (
                r.get("candidate_id", ""),
                nv.get("verdict", "-"),
                nv.get("reason", "-"),
                "<br>".join(nv.get("increments", [])) or "-",
                "%s (%s)" % (cv.get("vector", "-"), cv.get("score", "-")) if cv else "-",
            ))
    return "\n".join(lines) + "\n"


def render_exclusions_md(excluded: List[Dict], round_no: int, target: str,
                         lang: str = "zh") -> str:
    t = _t(lang)
    lines = [
        t["excl_title"] % (round_no, target),
        "",
        t["excl_intro"],
        "",
    ]
    cols = t["excl_cols"]
    lines += ["| %s |" % " | ".join(cols), "|" + "---|" * len(cols)]
    for r in excluded:
        lines.append("| %s | %s | %s |" % (
            r.get("surface", ""), r.get("conclusion", ""),
            _fmt_evidence(r),
        ))
    return "\n".join(lines) + "\n"


def render_round_summary_md(round_no: int, target: str, confirmed: List[Dict],
                            excluded: List[Dict], metrics: Dict[str, Any],
                            next_round: List[str], lang: str = "zh") -> str:
    t = _t(lang)
    lines = [t["sum_title"] % (round_no, target), "", t["confirmed"], ""]
    if confirmed:
        for r in confirmed:
            lines.append("- %s：%s（前置=%s，Novelty=%s）" % (
                r.get("candidate_id", "?"),
                r.get("surface", ""),
                r.get("precondition_tier", ""),
                (r.get("novelty") or {}).get("verdict", "?"),
            ))
    else:
        lines.append(t["none"])
    lines += ["", t["excluded"], ""]
    for r in excluded:
        lines.append("- %s：%s" % (r.get("surface", "?"), r.get("conclusion", "")))
    lines += ["", t["metrics"], ""]
    for k, v in metrics.items():
        lines.append("- %s：%s" % (k, v))
    lines += ["", t["next_round"], ""]
    for c in next_round:
        lines.append("- %s" % c)
    return "\n".join(lines) + "\n"


def render_finding_md(finding: Dict, lang: str = "zh") -> str:
    """Self-contained submission body (no external links) + boundary + timeline."""
    t = _t(lang)
    lines = [
        t["finding_title"] % finding.get("title", ""),
        "",
        t["date"] % finding.get("date", ""),
        t["status"] % finding.get("status", ""),
        "",
        t["summary"],
        "",
        finding.get("summary", ""),
        "",
        t["repro"],
        "",
        "```",
        finding.get("repro", ""),
        "```",
        "",
        t["evidence"],
        "",
        "```",
        finding.get("evidence", ""),
        "```",
        "",
        t["preconditions"],
        "",
    ]
    for p in finding.get("preconditions", []):
        lines.append("1. %s" % p)
    lines += ["", t["impact"], ""]
    for row in finding.get("impact", []):
        lines.append("- %s：%s" % (row.get("tier", "?"), row.get("impact", "")))
    lines += ["", t["boundary"], "", finding.get("boundary", ""), "",
              t["timeline"], "", "| %s | %s |" % (t["date_col"], t["event_col"]), "|---|---|"]
    for tm in finding.get("timeline", []):
        lines.append("| %s | %s |" % (tm.get("date", ""), tm.get("event", "")))
    return "\n".join(lines) + "\n"


def write_round_artifacts(workspace: Path, target: str, round_no: int,
                          rows: List[Dict], excluded: List[Dict],
                          summary: Dict[str, Any], lang: str = "zh") -> Path:
    out = workspace / "ledger" / target / ("round-%02d" % round_no)
    out.mkdir(parents=True, exist_ok=True)
    t = _t(lang)
    md = render_ledger_md(rows, round_no, target, summary.get("header_note", ""), lang)
    (out / (t["ledger_file"] % round_no)).write_text(md, encoding="utf-8")
    (out / (t["excl_file"] % round_no)).write_text(
        render_exclusions_md(excluded, round_no, target, lang), encoding="utf-8")
    (out / (t["sum_file"] % round_no)).write_text(
        render_round_summary_md(round_no, target,
                                [r for r in rows if r.get("conclusion") == "确认"],
                                excluded, summary.get("metrics", {}),
                                summary.get("next_round", []), lang),
        encoding="utf-8")
    (out / "ledger.json").write_text(
        json.dumps({"round": round_no, "target": target, "rows": rows,
                    "excluded": excluded, "summary": summary},
                   indent=2, ensure_ascii=False), encoding="utf-8")
    return out
