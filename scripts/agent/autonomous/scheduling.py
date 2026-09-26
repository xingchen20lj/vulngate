"""Coverage-aware autonomous candidate scheduling and proposal intake."""

from __future__ import annotations

# The phase modules share a deliberately centralized policy/context namespace.
# Keep this import surface stable while the public facade preserves legacy callers.
# ruff: noqa: F403,F405
from .common import *
from .common import (_fmt_entries, _scope_block, _sec_prompt,
                     _target_source_scope)
from .preparation import _ensure_capability_inventory

def learn_api_hint(ctx: AutoCtx, round_no: int = 1) -> str:
    """S1.5: LLM reads the target's entry classes and writes an API hint
    (package names, entry signatures, default security switches) so later
    PoC generation does not mix up library versions (e.g. Jackson 2 vs 3)."""
    if ctx.cfg.api_hint:
        return ctx.cfg.api_hint
    if ctx._api_hint_attempted:
        return ""
    ctx._api_hint_attempted = True
    source_root, source_dirs = _target_source_scope(ctx)
    srcs = ", ".join(source_dirs)
    src_block = surface_block(ctx.cfg.entry_points, source_dirs,
                              source_root, max_chars=5000,
                              snippet_cache=ctx._candidate_source_snippet_cache,
                              timeout=ctx.source_scan_timeout())
    if ctx.cfg.target_type == "web-app":
        user = (
            "目标应用：%s\n源码目录：%s\nHTTP 入口清单：\n%s\n\n"
            "以下为路由/处理器源码片段与危险模式命中摘要（真实源码证据，文件+行号）：\n%s\n\n"
            "请基于上述源码输出 api_hint：一句话说明 Web 框架与路由形态（如 Compojure/Ring）、"
            "鉴权中间件、默认安全开关（如 +auth 挂载范围、CSRF、限流），"
            "并列出值得优先审计的未认证端点前缀。只输出 JSON：{\"api_hint\": \"...\"}"
            "%s"
            % (ctx.cfg.name, srcs, _fmt_entries(ctx.cfg.entry_points),
               src_block or "（无源码片段）", _scope_block(ctx, 2500))
        )
    else:
        user = (
            "目标库：%s\n源码目录：%s\n入口清单：\n%s\n\n"
            "以下是入口类源码片段与危险模式命中摘要（真实源码证据，文件+行号）：\n%s\n\n"
            "请基于上述源码阅读入口类（如 ObjectMapper/JsonMapper/解析器），输出 api_hint："
            '一句话说明正确包名、反序列化入口 API 签名、默认安全开关'
            '（如多态类型默认关闭、深度/长度约束），并警告易混的旧版本 API。'
            "只输出 JSON：{\"api_hint\": \"...\"}"
            % (ctx.cfg.name, srcs, _fmt_entries(ctx.cfg.entry_points), src_block or "（无源码片段）")
        )
    try:
        data = ctx.llm.ask_json(_sec_prompt(ctx), user, max_tokens=1000)
        hint = (data.get("api_hint") or "").strip()
    except ValueError as exc:
        print("[S1.5] api_hint learning failed: %s" % exc)
        return ""
    if hint:
        ctx.cfg.api_hint = hint
        ctx.write_artifact(round_no, "S1", "api-hint.json", {"api_hint": hint})
    return hint


def _coverage_prompt_block(ctx: AutoCtx, round_no: int) -> str:
    """The spec §15 structured coverage block, or ``""`` when unavailable.

    S2's prompt previously carried only the danger-pattern snippets, which is
    the "few most dangerous snippets and let the model improvise" input the
    spec replaces.  A missing coverage index degrades to no block rather than
    aborting the round; the caller records why.
    """
    try:
        from ..analysis import scheduler as sched
        from ..analysis.inventory import CoverageStore
        from ..memory.research import load_research_memory
        store = CoverageStore(ctx.root, ctx.cfg.name)
        scope = _current_coverage_scope(ctx)
        if not scope.get("usable"):
            return ""
        memory = load_research_memory(ctx.root, ctx.cfg.name)
        benchmark_feedback = ctx.benchmark_feedback()
        sctx = sched.ScheduleContext.from_store(
            store, research_memory=memory.get("entries") or [],
            benchmark_feedback=benchmark_feedback)
        if not sctx.entries and not sctx.sinks:
            return ""
        plan = sched.load_schedule(store, round_no)
        return sched.prompt_coverage_block(sctx, plan=plan) if plan else \
            sched.prompt_coverage_block(sctx)
    except Exception:  # pragma: no cover - coverage is best-effort here
        return ""


def _current_coverage_scope(ctx: AutoCtx) -> Dict[str, Any]:
    """Return whether persisted coverage belongs to the configured source scope."""
    from ..analysis.inventory import CoverageStore, coverage_scope_status
    from ..analysis.languages import SourceFilter

    timeout = getattr(ctx.cfg, "coverage_scan_timeout_seconds", 600)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout < 0:
        return {"status": "invalid-config", "usable": False}
    target_root, _effective_source_dirs = _target_source_scope(ctx)
    return coverage_scope_status(
        CoverageStore(ctx.root, ctx.cfg.name), target_root,
        list(ctx.cfg.source_dirs or []) or None,
        source_filter=SourceFilter(scan_timeout_seconds=timeout),
        target_type=ctx.cfg.target_type)


def schedule_candidates(ctx: AutoCtx, round_no: int,
                        candidates: List[Dict[str, Any]],
                        pinned: Optional[List[str]] = None
                        ) -> Tuple[List[Dict[str, Any]], str]:
    """Replace "first N as proposed" with this round's coverage-aware schedule.

    Returns ``(selected, note)``.  ``note`` is empty on success and explains the
    fallback otherwise, so a round that ran unscheduled says so in its own log
    instead of looking scheduled.
    """
    from ..analysis import scheduler as sched
    from ..analysis.research_agenda import normalize_candidate_ids
    agenda_priority_ids = selected_candidate_ids(
        load_research_agenda(ctx.root, ctx.cfg.name),
        current_round=round_no)
    configured_priority_ids = normalize_candidate_ids(
        getattr(ctx.cfg, "priority_candidate_ids", []))
    priority_ids = normalize_candidate_ids(
        configured_priority_ids + agenda_priority_ids)
    active_candidates, candidate_intake = sched.bounded_candidate_intake(
        candidates, slots=ctx.max_candidates, round_no=round_no,
        pinned=pinned or (), priority_ids=priority_ids)
    ctx.write_artifact(round_no, "S2", "candidate-intake.json", candidate_intake)
    inventory_state = (
        ctx._coverage_inventory_state
        if (getattr(ctx, "_coverage_inventory_round", None) == round_no
            and isinstance(getattr(ctx, "_coverage_inventory_state", None), dict))
        else {})
    if inventory_state.get("deferred"):
        selected = active_candidates[:ctx.max_candidates]
        return selected, ("coverage-aware scheduling deferred until after the first "
                          "candidate wave; using bounded candidates")
    scope = _current_coverage_scope(ctx)
    if not scope.get("usable"):
        selected = active_candidates[:ctx.max_candidates]
        return selected, ("coverage-aware scheduling withheld: scope %s; "
                          "using bounded configured candidates only" %
                          scope.get("status", "unknown"))
    selected, plan, note = sched.round_selection(
        ctx.root, ctx.cfg.name, active_candidates, ctx.max_candidates,
        round_no=round_no, pinned=pinned or (),
        priority_ids=configured_priority_ids,
        benchmark_feedback=ctx.benchmark_feedback())
    if candidate_intake["deferred_intake_candidates"]:
        intake_note = ("candidate intake %d/%d active; %d queued for rotation"
                       % (candidate_intake["active_candidates"],
                          candidate_intake["pool_candidates"],
                          candidate_intake["deferred_intake_candidates"]))
        note = "; ".join(item for item in (note, intake_note) if item)
    if plan is not None:
        ctx.write_artifact(round_no, "S2", "research-strategy.json",
                           plan.research_strategy)
        print("[round-%02d] schedule: %d/%d selected, %s"
              % (round_no, len(selected), len(candidates),
                 ", ".join("%s=%d" % (k, v)
                           for k, v in plan.category_counts.items()) or "no category"))
    if note:
        print("[round-%02d] schedule note: %s" % (round_no, note))
    return selected, note


def _attach_experiment_plans(ctx: AutoCtx, round_no: int,
                             candidates: List[Dict[str, Any]],
                             pool: Optional[List[Dict[str, Any]]] = None
                             ) -> List[Dict[str, Any]]:
    """Attach and persist bounded, falsifiable research plans for S2 candidates.

    Production rounds pass only the scheduled selection: generating detailed
    experiment plans for every queued static lead defeats the candidate budget.
    ``pool`` remains an explicit compatibility/testing override for callers
    that intentionally need a full planning preview.
    """
    versions = sorted({str(j.get("version")) for j in ctx.cfg.jars
                       if j.get("version")})
    selected_ids = {str(c.get("candidate_id")) for c in candidates}
    plan_candidates = pool if pool is not None else candidates
    benchmark_feedback = ctx.benchmark_feedback()
    strategy = load_research_strategy(ctx.root, ctx.cfg.name)
    consistency_actions = load_research_consistency_actions(
        ctx.root, ctx.cfg.name)
    if benchmark_feedback:
        ctx.write_artifact(round_no, "S2", "benchmark-feedback.json",
                           benchmark_feedback)
    plans = []
    for candidate in plan_candidates:
        candidate_action = action_for_research_key(
            consistency_actions, research_key(candidate),
            candidate.get("candidate_id"))
        research_plan = plan_candidate_experiments(
            candidate, versions, benchmark_feedback=benchmark_feedback,
            research_guidance=strategy_guidance_for_candidate(
                strategy, candidate),
            consistency_action=candidate_action,
            target_type=ctx.cfg.target_type)
        candidate["experiment_plan"] = research_plan
        plan_row = dict(research_plan)
        plan_row["scheduled"] = (str(candidate.get("candidate_id")) in selected_ids
                                  if pool is not None else True)
        plans.append(plan_row)
    ctx.write_artifact(round_no, "S2", "experiment-plans.json", plans)
    return plans


def static_candidates(ctx: AutoCtx, round_no: Optional[int] = None
                      ) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Index-derived candidates from the persisted coverage store (spec §11/§12).

    Returns ``(candidates, added_ids)``.  Best-effort by contract: a missing or
    partial coverage store means "none this round", never a failed round --
    these are leads the static layer already produced, not a precondition for
    the LLM proposal.  S1 composite-chain candidates are merged here as well
    so the autonomous and config-driven pipelines schedule the same research
    strategies.
    """
    if not bool(getattr(ctx.cfg, "static_candidates", True)):
        return [], []
    try:
        from ..analysis import controls as ctl
        from ..analysis.inventory import CoverageStore
        inventory_state = (
            ctx._coverage_inventory_state
            if (round_no is not None
                and getattr(ctx, "_coverage_inventory_round", None) == round_no
                and isinstance(ctx._coverage_inventory_state, dict))
            else _ensure_capability_inventory(ctx))
        scope = inventory_state.get("scope") or {}
        if (inventory_state.get("error")
                or (isinstance(scope, dict)
                    and scope.get("usable") is False)):
            print("[S2] static candidates withheld: %s" %
                  inventory_state.get("error", "coverage scope unusable"))
            candidates = []
        else:
            store = CoverageStore(ctx.root, ctx.cfg.name)
            candidates = ctl.static_candidates(store)
    except Exception as exc:  # pragma: no cover - defensive
        print("[S2] static candidates unavailable: %s: %s" % (type(exc).__name__, exc))
        candidates = []
    if round_no is not None:
        path = (ctx.root / "state" / ctx.cfg.name /
                ("round-%02d" % round_no) / "S1" /
                "composite-chain-candidates.json")
        try:
            chain_candidates = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            chain_candidates = []
        seen = {str(c.get("candidate_id")) for c in candidates
                if c.get("candidate_id")}
        for candidate in (chain_candidates if isinstance(chain_candidates, list)
                          else []):
            cid = str(candidate.get("candidate_id", ""))
            if cid and cid not in seen:
                candidates.append(candidate)
                seen.add(cid)
    ids = [str(c.get("candidate_id")) for c in candidates if c.get("candidate_id")]
    return candidates, ids


def propose_candidates(ctx: AutoCtx, round_no: int,
                       carryover: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """S2: LLM proposes attack candidates from the entry inventory.

    carryover: candidates proposed at the end of the previous round (with
    runtime observations). They are injected as context and de-duplicated, so
    a resumed round continues the investigation instead of restarting from
    zero (baseline #9).

    The operator-supplied pool is *scheduled* rather than truncated: spec §13
    replaces "top-K by declaration order" with the coverage-aware ranking, so
    the same pool rotates across rounds as coverage moves instead of the same
    first N candidates being re-audited every round.
    """
    if ctx.cfg.candidates:
        selected, _ = schedule_candidates(ctx, round_no, list(ctx.cfg.candidates))
        return selected
    versions = ", ".join(sorted({j.get("version") for j in ctx.cfg.jars}))
    source_root, source_dirs = _target_source_scope(ctx)
    src_block = surface_block(ctx.cfg.entry_points, source_dirs,
                              source_root, max_chars=8000,
                              snippet_cache=ctx._candidate_source_snippet_cache,
                              timeout=ctx.source_scan_timeout())
    coverage_block = _coverage_prompt_block(ctx, round_no)
    carry_text = ""
    if carryover:
        carry_text = "\n".join(
            "- %s: %s (观测: %s)" % (
                c.get("candidate_id", "?"), c.get("surface", ""),
                "; ".join(str(x) for x in (c.get("observations") or [])[:3]) or "无")
            for c in carryover[:8])
    if ctx.cfg.target_type == "web-app":
        guidance = (
            "Web 应用攻击面：路由鉴权绕过 / SQL 注入 / SSRF / 模板注入 / "
            "命令注入 / 信息泄露 / 业务逻辑。"
            "前置分级必须引用路由与中间件的默认鉴权/校验：入口有 +auth 或权限中间件时，"
            'precondition_tier_hint 不得为 "0"，preconditions 必须写明所需调用方配置。'
            "涉及授权边界时必须给出 authz_cases：匿名/普通用户/管理员、跨租户和非归属对象，"
            "并声明 expected_http_codes、expected_object_mutated 或 expected_authz。"
        )
        input_shape_hint = 'input_shape("json"|"query"|"path"|"body"|"multipart")'
    else:
        guidance = (
            "反序列化/解析边界/类型分发/DoS。"
            "前置分级必须引用 API 提示中的默认安全开关："
            '提示声明默认拦截（如 registrationRequired=true / 默认黑名单 / autoType 关闭）时，'
            'precondition_tier_hint 不得为 "0"，preconditions 必须写明所需的调用方配置。'
        )
        input_shape_hint = "input_shape(text/json|binary/jsonb|path)"
    user = (
        "目标库：%s（版本 %s）\n"
        "API 提示（必须作为默认配置可达性的唯一依据，禁止凭模型记忆推断）：\n%s\n\n"
        "入口清单：\n%s\n\n"
        "真实源码证据（危险模式命中 + 入口类片段，供提出候选时引用文件/行号）：\n%s\n\n"
        "%s"
        "%s"
        "上一轮已提出/验证的候选（新候选必须与它们不同——不同攻击面、不同触发点、"
        "不同输入形态；严禁重复）：\n%s\n\n"
        "请提出最多 %d 个最值得验证的攻击候选（%s）。\n"
        "每个候选的 logic 必须引用源码证据中的文件/行号（如 "
        "`src/metabase/session/api.clj:229 schema 未封闭`），"
        "禁止只写入口 API 名而无代码依据。\n"
        "每个候选字段："
        'candidate_id(如 A1), surface(一句话), entry(入口API), input_shape(%s), '
        'logic(攻击逻辑), hypothesis, precondition_tier_hint("0"|"single-feature"|"application-type"|"extra-primitive"), '
        'preconditions(数组,如 ["无"] 或 ["调用方开启 SupportAutoType"]), '
        'entry_feature(默认开关名或 ""), poc_class(Java 类名; Web 候选填 ""), jvm(对象,如 {"Xmx":"256m"}), '
        'required_runtime(可选,如 jdk8), java_bin/java_home(可选,按 cell 选择实际 JDK), '
        'target_classes(数组，预期实例化的目标类全限定名，如 ["com.example.Exploit"]；'
        '类型混淆/DoS 类候选可为 []), '
        'authz_cases(可选数组；每项仅含 case_id、principal、role、tenant_id、object_id、object_tenant_id、'
        'expected_http_codes、expected_object_mutated、expected_authz；禁止放 token/cookie/password), '
        'sequence(可选数组，仅填有界步骤标识如 ["seed","mutate","probe"]), '
        'concurrency(可选 1..64 的整数；并发声明不等于已证明并发效果), '
        'availability_probe(可选布尔；只有真实观测 SERVICE_UNAVAILABLE 时才支持 A:H), '
        'chain_components(可选数组；例如 ["request-body", "parser", "authorization", "file-write"]), '
        'novelty_keywords(数组,上游检索关键词), cvss_vector(可选)。\n'
        "只输出 JSON：{\"candidates\":[...]}"
        % (ctx.cfg.name, versions, ctx.cfg.api_hint or "（无）",
           _fmt_entries(ctx.cfg.entry_points), src_block or "（无源码片段）",
           _scope_block(ctx),
           coverage_block + "\n\n" if coverage_block else "",
           carry_text or "（无，首轮）",
           ctx.max_candidates, guidance, input_shape_hint)
    )
    try:
        data = ctx.llm.ask_json(_sec_prompt(ctx), user, max_tokens=4000)
    except ValueError as exc:
        print("[S2] LLM proposal failed: %s" % exc)
        return []
    cands = data.get("candidates") or []
    if carryover:
        seen = {c.get("candidate_id") for c in carryover}
        seen_surfaces = {str(c.get("surface", "")).strip() for c in carryover}
        dedup = []
        for c in cands:
            cid = c.get("candidate_id")
            surf = str(c.get("surface", "")).strip()
            if cid in seen or surf in seen_surfaces:
                continue
            dedup.append(c)
        cands = dedup
    for i, c in enumerate(cands):
        c.setdefault("candidate_id", "A%d" % (i + 1))
        c.setdefault("precondition_tier_hint", "single-feature")
        c.setdefault("preconditions", [])
        c.setdefault("poc_class", c["candidate_id"])
        c.setdefault("jvm", {})
        c.setdefault("target_classes", [])
        c.setdefault("novelty_keywords", [])
        c.setdefault("sequence", [])
        c.setdefault("concurrency", 1)
        c.setdefault("availability_probe", False)
        c["authz_cases"] = normalize_authz_cases(c.get("authz_cases"))
    # Rank the proposal by evidence instead of trusting its order: the model's
    # listing order is not a priority, and trimming to the budget should drop
    # the least-evidenced candidate, not the last one written.
    selected, _ = schedule_candidates(ctx, round_no, cands)
    ctx.write_artifact(round_no, "S2", "candidate-matrix.json",
                       {"candidate_count": len(selected), "matrix": selected})
    return selected


