"""Schedule persistence, carryover, round selection, and rendering."""

from __future__ import annotations

# Shared scheduler state is centralized in common.py; this keeps phase imports
# explicit at the package boundary while retaining a small compatibility API.
# ruff: noqa: F403,F405
from .common import *
from .intake import *
from .intake import _threat_model_snapshot
from .intake import _research_strategy_snapshot
from .scoring import *
from .quota import *

def load_schedule(store: CoverageStore, round_no: Optional[int] = None
                  ) -> Dict[str, Any]:
    """Read back a persisted schedule (latest when ``round_no`` is omitted)."""
    name = ("schedule-round-%02d" % round_no) if round_no else "schedule-latest"
    return store.read(name) or {}


def deferred_carryover(plan: SchedulePlan,
                       candidates: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Re-attach deferral reasons to the candidate dicts for the next round.

    The pipeline carries candidates forward as plain dicts, so the scheduler's
    verdict is written onto the candidate rather than kept in a side table --
    otherwise the reason would be lost the moment the round ends.
    """
    by_id = {str(c.get("candidate_id")): c for c in candidates}
    carried: List[Dict[str, Any]] = []
    for score in plan.deferred:
        candidate = by_id.get(score.candidate_id)
        if candidate is None:
            continue
        candidate["schedule"] = {
            "score": round(score.total, 2),
            "band": score.band,
            "category": score.category,
            "deferred": True,
            "reason": "not selected in round %d (score %.2f, band %s)"
                      % (plan.round_no, score.total, score.band),
        }
        carried.append(candidate)
    for score in plan.selected:
        candidate = by_id.get(score.candidate_id)
        if candidate is None:
            continue
        candidate["schedule"] = {
            "score": round(score.total, 2),
            "band": score.band,
            "category": score.category,
            "deferred": False,
            "factors": {k: round(v, 4) for k, v in score.factors.items()},
            "reasons": dict(score.reasons),
        }
    return carried


def apply_schedule_order(plan: SchedulePlan,
                         candidates: Sequence[Dict[str, Any]]
                         ) -> List[Dict[str, Any]]:
    """Reorder ``candidates`` so the scheduled ones come first, by score.

    Pure ordering: every candidate is returned exactly once, so no stage can
    lose one to the scheduler.  Deferred candidates keep their relative order by
    score, which keeps the carry-over deterministic.
    """
    by_id = {str(c.get("candidate_id")): c for c in candidates}
    ordered: List[Dict[str, Any]] = []
    for score in plan.selected + plan.deferred:
        candidate = by_id.pop(score.candidate_id, None)
        if candidate is not None:
            ordered.append(candidate)
    for candidate in candidates:  # ids the scheduler never saw (defensive)
        if str(candidate.get("candidate_id")) in by_id:
            ordered.append(candidate)
    return ordered


def selected_candidates(plan: SchedulePlan,
                        candidates: Sequence[Dict[str, Any]]
                        ) -> List[Dict[str, Any]]:
    """Just the candidates this round selected, in the plan's (score) order.

    This is the budget-honouring counterpart to :func:`apply_schedule_order`:
    a round of ``slots`` candidates must run ``slots`` audits, not the whole
    pool.  The deferred ones are not lost -- they stay in the pool and their
    verdict is on the plan, so the next round re-scores them against coverage
    that has since moved.
    """
    by_id = {str(c.get("candidate_id")): c for c in candidates}
    out: List[Dict[str, Any]] = []
    for score in plan.selected:
        candidate = by_id.get(score.candidate_id)
        if candidate is not None:
            out.append(candidate)
    return out


def _coverage_scope_blocker(store: CoverageStore,
                            check_coverage_summary: bool = True) -> str:
    """Explain why persisted indices cannot support a coverage-aware schedule."""
    build_status = store.read("coverage-build-status") or {}
    if isinstance(build_status, dict) and build_status.get("status") in {
            "running", "incomplete", "failed"}:
        return "coverage build %s" % build_status.get("status")

    inventory = store.read("inventory-summary") or {}
    scope = inventory.get("scope") if isinstance(inventory, dict) else None
    if not isinstance(scope, dict):
        return "inventory scope metadata missing"
    if scope.get("schema_version") != COVERAGE_SCOPE_VERSION:
        return "inventory scope schema is missing or outdated"
    if scope.get("valid") is not True:
        gaps = [str(value) for value in scope.get("analysis_gaps") or [] if value]
        return "inventory scope invalid%s" % (
            ": " + ", ".join(gaps[:4]) if gaps else "")
    try:
        source_count = int(scope.get("source_file_count") or 0)
    except (TypeError, ValueError):
        source_count = 0
    if source_count <= 0:
        return "source universe is empty"

    required_indices = {
        "source-inventory", "entry-index", "sink-index",
        "security-control-index", "symbol-index", "flow-index",
    }
    missing = sorted(required_indices - set(store.existing_indices()))
    if missing:
        return "required indices missing: %s" % ", ".join(missing)

    if check_coverage_summary:
        coverage = store.read("coverage-summary") or {}
        audit_status = (coverage.get("audit_status")
                        if isinstance(coverage, dict) else None)
        if isinstance(audit_status, dict) and (
                audit_status.get("scope_present") is False
                or audit_status.get("scope_valid") is False):
            return "coverage summary reports an invalid scope"
    return ""


def round_selection(workspace, target: str,
                    candidates: Sequence[Dict[str, Any]], slots: int,
                    round_no: int = 0,
                    quota: Optional[Dict[str, int]] = None,
                    weights: Optional[Dict[str, int]] = None,
                    pinned: Sequence[str] = (),
                    refresh: bool = True,
                    benchmark_feedback: Optional[Dict[str, Any]] = None,
                    priority_ids: Sequence[str] = ()
                    ) -> Tuple[List[Dict[str, Any]], Optional[SchedulePlan], str]:
    """Pick this round's candidates, degrading to proposal order on failure.

    Returns ``(selected, plan, note)``.  ``plan`` is ``None`` and ``note`` is
    non-empty when the coverage index could not be read; the caller then gets
    the pre-PR3 behaviour -- the first ``slots`` candidates as proposed -- and a
    reason to record.  Degrading rather than raising is deliberate: an
    unavailable scheduler must cost a round its *ordering*, never its audit.
    The note is what keeps that degradation from being silent.
    """
    pool = [c for c in candidates if isinstance(c, dict)]
    slots = max(0, int(slots))
    if not pool:
        return [], None, "empty candidate pool"
    try:
        plan = build_schedule(workspace, target, pool, slots=slots, quota=quota,
                              weights=weights, round_no=round_no,
                              refresh=refresh, pinned=pinned,
                              priority_ids=priority_ids,
                              benchmark_feedback=benchmark_feedback)
    except CoverageScopeUnavailable as exc:
        return pool[:slots], None, (
            "coverage-aware scheduling unavailable (%s); returned the bounded "
            "candidate order without coverage ranking" % exc)
    except Exception as exc:  # pragma: no cover - defensive by design
        return pool[:slots], None, (
            "scheduler unavailable (%s: %s); fell back to proposal order"
            % (type(exc).__name__, exc))
    selected = selected_candidates(plan, pool)
    note = ""
    if len(selected) < len(plan.selected):
        note = ("%d scheduled candidate(s) are not in the pool"
                % (len(plan.selected) - len(selected)))
    return selected, plan, note


def render_schedule_text(plan: SchedulePlan, lang: str = "zh") -> str:
    """Human-readable plan, for the CLI and round logs."""
    zh = lang == "zh"
    lines: List[str] = []
    lines.append("安全审计候选调度" if zh else "Candidate Schedule")
    lines.append("─" * 52)
    lines.append(("%-10s %-8s %-7s %s" % ("候选", "类别", "分数", "档位")) if zh
                 else ("%-10s %-8s %-7s %s" % ("id", "category", "score", "band")))
    for score in plan.selected:
        lines.append("%-10s %-8s %-7.2f %s%s" % (
            score.candidate_id, score.category, score.total, score.band,
            "  (dup of %s)" % score.duplicate_of if score.duplicate_of else ""))
    lines.append("")
    quota_line = ", ".join("%s %d/%d" % (k, plan.filled_quota.get(k, 0), v)
                           for k, v in plan.requested_quota.items())
    lines.append(("配额：" if zh else "quota: ") + (quota_line or "—"))
    moved = {k: v for k, v in plan.relocated_quota.items() if v}
    if moved:
        lines.append(("配额转移：" if zh else "relocated: ")
                     + ", ".join("%s-%d" % (k, v) for k, v in sorted(moved.items())))
    lines.append(("类别分布：" if zh else "categories: ")
                 + (", ".join("%s=%d" % (k, v)
                              for k, v in plan.category_counts.items()) or "—"))
    if plan.deferred:
        lines.append(("延后 %d 个：" if zh else "%d deferred: ") % len(plan.deferred)
                     + ", ".join("%s(%.1f)" % (s.candidate_id, s.total)
                                 for s in plan.deferred[:8]))
    residual = plan.residual or {}
    if residual:
        if not residual.get("measured", True):
            lines.append(("高风险未审计：" if zh else "HIGH-risk uncovered: ")
                         + ("未测量（本轮未刷新覆盖）" if zh
                            else "not measured this round"))
            return "\n".join(lines)
        lines.append(("高风险未审计：" if zh else "HIGH-risk uncovered: ")
                     + str(residual.get("high_risk_uncovered") or "n/a"))
        met = bool(residual.get("stop_condition_met"))
        lines.append(("停止条件满足：" if zh else "stop condition met: ")
                     + (("是" if met else "否") if zh else ("yes" if met else "no")))
    return "\n".join(lines)


def _linked_from_score(score: CandidateScore,
                       ctx: ScheduleContext) -> LinkedRegions:
    """Re-link a persisted score from its own locations (no candidate dict)."""
    return linked_regions(
        {"code_location": ["%s:%d" % (f, n) for f, n in score.locations]}, ctx)


def prompt_coverage_block(ctx: ScheduleContext, plan: Optional[SchedulePlan] = None,
                          limit_regions: int = 15, limit_flows: int = 12,
                          limit_selected: int = 12, limit_candidates: int = 12) -> str:
    """The structured prompt input spec §15 requires.

    The section names and their order follow the spec's list literally --
    coverage summary, gaps, high-risk unreviewed regions, selected entries,
    selected sinks, security controls, candidate-relevant flows, prior
    candidates, rejected candidates, novelty requirement -- so the block can be
    diffed against the spec by eye.

    "Selected" means *selected by this round's plan*.  When ``plan`` is omitted
    there is no selection to report, and the two sections say so and fall back
    to an index snapshot rather than silently presenting everything as chosen.
    """
    indices = {
        "source-inventory": list(ctx.sources.values()),
        "entry-index": list(ctx.entries.values()),
        "sink-index": list(ctx.sinks.values()),
        "security-control-index": list(ctx.controls.values()),
        "flow-index": list(ctx.flows),
    }
    summary = cov.compute_coverage(indices, uncovered_probe=True)
    regions = summary.get("uncovered_regions") or []

    def top(regions_list, predicate, count):
        return [r for r in regions_list if predicate(r)][:count]

    lines: List[str] = []
    lines.append("## 覆盖率摘要 / Project Coverage Summary")
    counts = summary.get("counts", {})
    lines.append(json.dumps({
        "production_source_files": counts.get("production_source_files"),
        "indexed_source_files": counts.get("indexed_source_files"),
        "entries": counts.get("entries"),
        "entries_reviewed": counts.get("entries_reviewed"),
        "sinks": counts.get("sinks"),
        "sinks_reachability_analyzed": counts.get("sinks_reachability_analyzed"),
        "flows": counts.get("flows_total"),
        "flows_reviewed": counts.get("flows_reviewed"),
        "high_risk_uncovered": summary.get("high_risk_uncovered"),
    }, ensure_ascii=False))
    lines.append("## 验收指标 / Acceptance")
    for name, item in sorted((summary.get("acceptance") or {}).items()):
        actual = item.get("actual")
        lines.append("  %-32s %s (target >= %s)" % (
            name, "n/a" if actual is None else "%.1f%%" % (actual * 100),
            item.get("target")))
    lines.append("## 覆盖缺口 / Coverage Gaps")
    lines.append("  " + json.dumps({
        "high": counts.get("uncovered_high", 0),
        "medium": counts.get("uncovered_medium", 0),
        "low": counts.get("uncovered_low", 0),
    }, ensure_ascii=False))
    lines.append("## 高风险未审计区域 / High-risk Unreviewed Regions")
    for region in top(regions, lambda r: r.get("risk") == "high", limit_regions):
        location = ("%s:%s" % (region.get("file"), region.get("line"))
                    if region.get("file") else region.get("ref", ""))
        lines.append("  [%s] %s %s" % (region.get("kind"), location,
                                       region.get("reason", "")))

    selected_links = [_linked_from_score(s, ctx) for s in (plan.selected if plan else [])]
    lines.append("## 已选入口 / Selected Entries")
    if plan is None:
        lines.append("  （本轮无调度计划，以下为索引快照 / no round plan: index snapshot）")
        for entry in sorted(ctx.entries.values(),
                            key=lambda e: str(e.get("entry_id")))[:limit_selected]:
            lines.append("  %s (%s, %s:%s)" % (
                entry.get("entry_id"), entry.get("kind"),
                entry.get("file"), entry.get("line")))
    else:
        chosen: Dict[str, Dict[str, Any]] = {}
        for link in selected_links:
            for entry in link.entries:
                chosen.setdefault(str(entry.get("entry_id")), entry)
        for key in sorted(chosen)[:limit_selected]:
            entry = chosen[key]
            lines.append("  %s (%s, %s:%s)" % (
                entry.get("entry_id"), entry.get("kind"),
                entry.get("file"), entry.get("line")))

    lines.append("## 已选 Sink / Selected Sinks")
    if plan is None:
        lines.append("  （同上 / no round plan: index snapshot）")
        sink_pool = [s for s in ctx.sinks.values()
                     if str(s.get("severity_hint")) == "high"]
    else:
        sink_pool = []
        seen_sink: Dict[str, Dict[str, Any]] = {}
        for link in selected_links:
            for sink in link.sinks:
                seen_sink.setdefault(str(sink.get("sink_id")), sink)
        sink_pool = [seen_sink[k] for k in sorted(seen_sink)]
    for sink in sorted(sink_pool, key=lambda s: str(s.get("sink_id")))[:limit_selected]:
        lines.append("  %s (%s, %s:%s)" % (sink.get("sink_id"), sink.get("category"),
                                           sink.get("file"), sink.get("line")))

    lines.append("## 安全控制 / Security Controls")
    control_kinds = Counter(str(c.get("category")) for c in ctx.controls.values())
    lines.append("  " + json.dumps(dict(sorted(control_kinds.items())),
                                   ensure_ascii=False))

    lines.append("## 候选相关数据流 / Candidate-relevant Flows")
    if plan is None:
        flow_pool = list(ctx.flows)
    else:
        seen_flow: Dict[str, Dict[str, Any]] = {}
        for link in selected_links:
            for flow in link.flows_reaching + link.flows_on_path:
                seen_flow.setdefault(str(flow.get("flow_id")), flow)
        flow_pool = [seen_flow[k] for k in sorted(seen_flow)]
    for flow in sorted(flow_pool, key=lambda f: str(f.get("flow_id")))[:limit_flows]:
        lines.append("  %s %s -> %s | %s" % (
            flow.get("flow_id"), flow.get("entry_id"), flow.get("sink_id"),
            " -> ".join(flow.get("path") or [])))

    reviewed_records = [r for r in ctx.prior_coverage
                        if str(r.get("status") or "") == "confirmed"]
    lines.append("## 已审候选 / Prior Candidates")
    for record in sorted(reviewed_records,
                         key=lambda r: str(r.get("candidate_id")))[:limit_candidates]:
        lines.append("  %s [%s] %s" % (record.get("candidate_id"),
                                       record.get("status"),
                                       record.get("conclusion", "")))

    rejected_records = [r for r in ctx.prior_coverage
                        if str(r.get("status") or "") == "excluded"]
    lines.append("## 已否决候选 / Rejected Candidates")
    for record in sorted(rejected_records,
                         key=lambda r: str(r.get("candidate_id")))[:limit_candidates]:
        lines.append("  %s [%s] %s" % (record.get("candidate_id"),
                                       record.get("status"),
                                       record.get("conclusion", "")))

    lines.append("## 跨轮研究记忆 / Cross-round Research Memory")
    memory_rows = memory_prompt_rows(ctx.research_memory, limit_candidates)
    if not memory_rows:
        lines.append("  （暂无可复用的运行时记忆 / no reusable runtime memory）")
    for row in memory_rows:
        hints = "; ".join(row.get("next_probe_hints") or []) or "-"
        review = row.get("review_status")
        review_text = (" review=%s/%s" % (
            review, row.get("reason_code") or "-") if review else "")
        variants = "; ".join(row.get("fix_variants") or [])
        variant_text = (" fix_variants=%s" % variants) if variants else ""
        residuals = "; ".join(
            "%s/%s/%s" % (
                item.get("residual_id") or "-",
                item.get("kind") or "unclassified",
                "plan" if item.get("has_probe_plan") else "no-plan",
            )
            for item in row.get("pending_residuals") or []
            if isinstance(item, dict)
        ) or "-"
        lines.append("  %s [%s, round=%s]%s next=%s residuals=%s "
                     "claim_status=%s" % (
            row.get("candidate_id") or row.get("research_key"),
            row.get("state"), row.get("round", 0), review_text + variant_text, hints,
            residuals, row.get("claim_status", "not-a-finding")))

    lines.append("## 项目级研究组合 / Project Research Portfolio")
    if not ctx.research_portfolio:
        lines.append("  （暂无项目级组合视图 / no project portfolio yet）")
    else:
        portfolio = ctx.research_portfolio
        lines.append("  " + json.dumps({
            "round": portfolio.get("round", 0),
            "summary": portfolio.get("summary", {}),
            "variant_coverage": list(
                portfolio.get("variant_coverage") or [])[:12],
            "surface_lane_coverage": {
                "summary": (portfolio.get("surface_lane_coverage") or {}
                            ).get("summary", {}),
                "lanes": list((portfolio.get("surface_lane_coverage") or {}
                               ).get("lanes") or [])[:12],
                "claim_status": ((portfolio.get("surface_lane_coverage") or {}
                                  ).get("claim_status", "not-a-finding")),
            },
            "next_probes": list(portfolio.get("next_probes") or [])[:8],
            "benchmark": portfolio.get("benchmark", {}),
            "claim_status": portfolio.get("claim_status", "not-a-finding"),
        }, ensure_ascii=False))

    lines.append("## 主动研究议程 / Active Research Agenda")
    if not ctx.research_agenda:
        lines.append("  （暂无有界研究议程 / no bounded research agenda yet）")
    else:
        agenda = ctx.research_agenda
        lines.append("  " + json.dumps({
            "policy": agenda.get("policy", {}),
            "summary": agenda.get("summary", {}),
            "selected": [
                {
                    "agenda_id": item.get("agenda_id"),
                    "research_key": item.get("research_key"),
                    "candidate_id": item.get("candidate_id"),
                    "surface": item.get("surface"),
                    "action": item.get("action"),
                    "priority_score": item.get("priority_score"),
                    "expected_information_gain": item.get(
                        "expected_information_gain"),
                    "last_outcome": item.get("last_outcome", ""),
                    "outcome_information_gain": item.get(
                        "outcome_information_gain", 0),
                    "outcome_observed_signals": item.get(
                        "outcome_observed_signals", []),
                    "outcome_consecutive_no_information": item.get(
                        "outcome_consecutive_no_information", 0),
                    "budget_recommendation": item.get(
                        "budget_recommendation", ""),
                    "budget_priority_delta": _safe_delta(item.get(
                        "budget_priority_delta", 0)),
                    "budget_cap_hint": item.get("budget_cap_hint", 0),
                    "prerequisites": item.get("prerequisites", []),
                    "claim_status": item.get("claim_status", "not-a-finding"),
                }
                for item in agenda.get("items", [])
                if isinstance(item, dict)
                and item.get("selection_status") == "selected"
            ][:8],
            "claim_status": agenda.get("claim_status", "not-a-finding"),
        }, ensure_ascii=False))

    lines.append("## 攻击路径威胁模型 / Attacker-Path Threat Model")
    if not ctx.threat_model:
        lines.append("  （暂无威胁模型 / no threat model yet）")
    else:
        model = _threat_model_snapshot(ctx.threat_model, path_limit=limit_flows,
                                       boundary_limit=limit_selected)
        lines.append("  " + json.dumps({
            "summary": model.get("summary", {}),
            "boundaries": model.get("boundaries", []),
            "unresolved": model.get("unresolved", {}),
            "claim_status": model.get("claim_status", "not-a-finding"),
        }, ensure_ascii=False))
        for path in model.get("attack_paths", []):
            capability_ids = ",".join(
                str(item.get("candidate_id"))
                for item in (path.get("capability_hypotheses") or [])
                if item.get("candidate_id")) or "-"
            lines.append("  [priority=%s] %s %s -> %s posture=%s state=%s "
                         "capability_hypotheses=%s questions=%s claim_status=%s" % (
                             path.get("research_priority", 0),
                             path.get("path_id"), path.get("entry_id"),
                             path.get("sink_id"), path.get("control_posture"),
                             path.get("research_state"),
                             capability_ids,
                             "; ".join(path.get("research_questions") or [])[:420],
                             path.get("claim_status", "not-a-finding")))

    lines.append("## 研究策略 / Research Strategy")
    if not ctx.research_strategy:
        lines.append("  （暂无研究策略 / no synthesized research strategy yet）")
    else:
        strategy = _research_strategy_snapshot(
            ctx.research_strategy, item_limit=max(8, limit_flows * 2))
        lines.append("  " + json.dumps({
            "summary": strategy.get("summary", {}),
            "benchmark_context": strategy.get("benchmark_context", {}),
            "claim_status": strategy.get("claim_status", "not-a-finding"),
        }, ensure_ascii=False))
        for item in strategy.get("items", []):
            observation = item.get("observation") or {}
            guidance = item.get("guidance") or {}
            variant_plan = guidance.get("surface_variant_plan") or {}
            variant_ids = ",".join(
                str(value) for value in variant_plan.get(
                    "selected_variants") or []) or "-"
            lane_names = ",".join(sorted({
                str(row.get("lane")) for row in variant_plan.get("lanes") or []
                if isinstance(row, dict) and row.get("lane")
            })) or "-"
            lines.append("  [priority=%s] %s kind=%s state=%s "
                         "path=%s residual=%s objective=%s observe=%s "
                         "falsify=%s observation=%s gain=%s missing=%s "
                         "next_action=%s replace=%s action_reasons=%s "
                         "surface_variants=%s lanes=%s "
                         "claim_status=%s" % (
                             item.get("priority", 0),
                             item.get("strategy_id"), item.get("kind"),
                             item.get("state"), item.get("path_id") or "-",
                             item.get("residual_id") or "-",
                             item.get("objective"),
                             ";".join(item.get("required_observations") or []),
                             ";".join(item.get("falsifiers") or [])[:360],
                             observation.get("status", "unobserved"),
                             observation.get("information_gain", 0),
                             ";".join(observation.get(
                                 "missing_observations") or []) or "-",
                             guidance.get("next_action", "continue-path-closure"),
                             "yes" if guidance.get(
                                 "replacement_recommended") else "no",
                             ";".join(guidance.get("reason_codes") or []) or "-",
                             variant_ids, lane_names,
                             item.get("claim_status", "not-a-finding")))

    lines.append("## 评测反馈 / Benchmark Feedback")
    if not ctx.benchmark_feedback:
        lines.append("  （暂无：本轮未提供 research-benchmark feedback / none supplied）")
    else:
        feedback = ctx.benchmark_feedback
        lines.append("  " + json.dumps({
            "benchmark_id": feedback.get("benchmark_id"),
            "alerts": [item.get("code") for item in feedback.get("alerts", [])
                       if isinstance(item, dict)],
            "weight_adjustments": ctx.weight_adjustments,
            "surface_guidance": list(feedback.get("surface_guidance") or [])[:8],
            "trend": feedback.get("trend") or {},
            "prompt_hints": list(feedback.get("prompt_hints") or [])[:8],
            "claim_status": feedback.get("claim_status", "not-a-finding"),
        }, ensure_ascii=False))

    lines.append("## 覆盖新颖性要求 / Coverage Novelty Requirement")
    lines.append("  优先生成来自未覆盖区域的候选；禁止重复已排除的机制，"
                 "除非存在新的数据流、安全控制差分或版本差分证据。稳定重放"
                 "只能减少重复实验，不能证明不存在漏洞；环境缺口必须修复后重试；"
                 "可行动版本差异应优先转化为最小复现和 source→sink 证据。")
    return "\n".join(lines)
