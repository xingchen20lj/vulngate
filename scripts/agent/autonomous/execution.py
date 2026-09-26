"""Autonomous static audit, PoC verification, novelty, and severity phases."""

from __future__ import annotations

# The phase modules share a deliberately centralized policy/context namespace.
# Keep this import surface stable while the public facade preserves legacy callers.
# ruff: noqa: F403,F405
from .common import *
from .common import (_poc_prompt, _scope_block, _sec_prompt,
                     _target_source_scope)

def audit_candidate(ctx: AutoCtx, cand: Dict[str, Any]) -> Dict[str, Any]:
    """S3: LLM static audit for one candidate."""
    source_root, source_dirs = _target_source_scope(ctx)
    srcs = ", ".join(source_dirs)
    src_block = candidate_block(cand, ctx.cfg.entry_points, source_dirs,
                                source_root, max_chars=8000,
                                timeout=ctx.source_scan_timeout(),
                                hit_cache=ctx._candidate_source_hit_cache,
                                snippet_cache=ctx._candidate_source_snippet_cache)
    flow_hints = match_source_sink_paths(
        getattr(ctx, "_source_sink_graph", []), cand)
    experiment_plan = json.dumps(
        cand.get("experiment_plan") or {}, ensure_ascii=False, indent=2)[:6000]
    user = (
        "候选：%s\n入口：%s\n逻辑：%s\n\n"
        "源码目录：%s\n\n"
        "候选相关源码片段（真实源码证据，文件+行号；以这些为准，不得臆测）：\n%s\n\n"
        "确定性 Source→Sink 路径提示（仅启发式，必须逐行复核）：\n%s\n\n"
        "确定性实验计划（仅验证清单，不是漏洞结论；必须用真实运行观测逐项证伪/支持）：\n%s\n\n"
        "%s"
        "请静态审计并输出："
        '{"gate_status":是否被安全门控阻断, "gate_kind":如 feature-gate/cache-lookup/missing-bound-check, '
        '"gate_location":代码位置, "default_config_reachable":true|false, '
        '"code_location":[行内引用], "audit_notes":审计笔记}'
        % (cand["candidate_id"], cand.get("entry"), cand.get("logic"), srcs,
           src_block or "（未定位到源码片段，请在审计笔记中注明）",
           json.dumps(flow_hints, ensure_ascii=False)[:6000] or "（无启发式路径）",
           experiment_plan or "（无实验计划）",
           _scope_block(ctx, 2500))
    )
    try:
        result = ctx.llm.ask_json(_sec_prompt(ctx), user, max_tokens=2000)
        result.setdefault("source_to_sink", flow_hints)
        return result
    except ValueError as exc:
        print("[S3] LLM audit failed for %s: %s" % (cand.get("candidate_id"), exc))
        return {"gate_status": "unknown", "gate_kind": "unknown",
                "gate_location": "", "default_config_reachable": None,
                "code_location": [], "source_to_sink": flow_hints,
                "audit_notes": "LLM audit failed; see stderr"}


def generate_poc(ctx: AutoCtx, cand: Dict[str, Any]) -> str:
    """S4a: LLM writes a minimal single-file Java PoC."""
    class_name = cand.get("poc_class") or cand["candidate_id"]
    versions = ", ".join(sorted({j.get("version") for j in ctx.cfg.jars}))
    pre = "; ".join(cand.get("preconditions") or ["无"])
    source_root, source_dirs = _target_source_scope(ctx)
    src_block = candidate_block(cand, ctx.cfg.entry_points, source_dirs,
                                source_root, max_chars=6000,
                                timeout=ctx.source_scan_timeout(),
                                hit_cache=ctx._candidate_source_hit_cache,
                                snippet_cache=ctx._candidate_source_snippet_cache)
    experiment_plan = json.dumps(
        cand.get("experiment_plan") or {}, ensure_ascii=False, indent=2)[:6000]
    user = (
        "候选：%s\n攻击面：%s\n入口：%s\n逻辑：%s\n前置条件：%s\n"
        "目标 jar 版本：%s\n\n"
        "确定性实验计划（仅验证清单，不是漏洞结论；按真实可执行步骤实现）：\n%s\n\n"
        "目标库 API 提示：%s\n\n"
        "候选相关源码片段（真实源码证据，写 PoC 时按真实 API 签名，禁止凭记忆猜 API）：\n%s\n\n"
        "请输出单个 Java 文件（类名 %s，public static void main），最小可编译，"
        "只使用目标库 %s 的公共 API（入口参考：%s）与 JDK 类，"
        "确保 `javac -cp <jar> 文件.java` 可直接编译通过（import 只写用到的，无 IDE 依赖）。"
        "不要为 PoC 增加 stdout/stderr marker 或伪造证据；这些输出不会被当作目标观测。"
        "运行器会独立记录退出状态和受支持的 harness 观测；没有对应观测能力时应保留缺口，"
        "不能靠打印字段填补。\n"
        "禁止真实外联网络（只能尝试 127.0.0.1）。只输出 Java 源码，无 Markdown 围栏。"
        "输出不超过 200 行，只允许 ASCII 字符（禁止全角中文标点），禁止解释性文本。"
        "若候选是 DoS/资源耗尽类（OOM/栈溢出/CPU），矩阵会自动用小堆（-Xmx256m），"
        "按候选逻辑触发边界行为；不要吞掉目标异常或用 stdout marker 代替运行器状态。"
        "若候选声明 sequence/concurrency，请读取 VULNGATE_SEQUENCE、"
        "VULNGATE_CONCURRENCY、VULNGATE_AVAILABILITY_PROBE 并按有界计划执行；"
        "这些声明字段不是执行结果。"
        "若环境提供 VULNGATE_VARIANT_SURFACE、VULNGATE_VARIANT_ID、"
        "VULNGATE_VARIANT_LANE、VULNGATE_VARIANT_STATE_STEPS，必须把它们当作"
        "当前 fixture 的实验选择器；positive/negative/environment-gap 不等于结果，"
        "按选定 lane 执行真实状态步骤，不需要打印 STEP/STATE/EFFECT marker。"
        "若候选包含 capability_contract，请读取 VULNGATE_CAPABILITY_CONTRACT、"
        "VULNGATE_CAPABILITIES、VULNGATE_TRANSITIONS 并按契约执行探测；不能把声明值"
        "当作观测结果，也不需要打印 CAPABILITY/TRANSITION/EFFECT marker。"
        % (cand["candidate_id"], cand.get("surface"), cand.get("entry"),
           cand.get("logic"), pre, versions,
           experiment_plan or "（无实验计划）",
           ctx.cfg.api_hint or "见入口清单",
           src_block or "（无源码片段）", class_name, ctx.cfg.name,
           cand.get("entry") or _fmt_entries(ctx.cfg.entry_points)[:200])
    )
    if ctx.cfg.safe_mode_switch == "stream-constraints":
        user += (
            "\n\n矩阵会传 -Dtarget.safeMode=true/false：safe=true 保持默认"
            "StreamReadConstraints（深度500/数字长度1000）；safe=false 可用"
            "StreamReadConstraints.builder().maxNestingDepth(100000).maxNumberLength(1000000).build()"
            " 放宽约束。请在代码中读取该属性并让两态行为可区分。")
    if not getattr(ctx, "_seeds_loaded", False):
        ctx._seeds = load_seeds(ctx.root)
        ctx._seeds_loaded = True
    user += seed_reference_block(getattr(ctx, "_seeds", {}), ctx.cfg.name, cand)
    # Write-code tasks stay on Chat Completions: A/B 2026-08-09 showed
    # Responses API prepends prose to generated code (0/2 compile) while
    # Chat Completions produces code-only output (2/2 compile). JSON tasks
    # (S2/S3/S5) use Responses via ask_json.
    text = ctx.llm.ask(SYSTEM_POC, user, max_tokens=8000, reasoning_effort="low")
    return extract_java_code(text)


def repair_poc(ctx: AutoCtx, cand: Dict[str, Any], src_text: str, compile_error: str) -> str:
    """S4b: one LLM repair pass with the actual javac error."""
    class_name = cand.get("poc_class") or cand["candidate_id"]
    user = (
        "你上次为候选 %s 生成的 PoC 遇到具体编译/API/运行错误，"
        "反馈如下：\n\n%s\n\n"
        "候选攻击面（必须针对这个攻击面重写 PoC，不要另起炉灶）：\n%s\n"
        "攻击逻辑：%s\n"
        "目标库 API 提示（必须严格遵守）：\n%s\n\n"
        "若反馈是'程序包不存在/找不到符号'，说明你使用了错误的外部库"
        "（如 javax.json / org.json），必须改用目标库 %s 的公共 API；"
        "入口参考：%s。\n"
        "请只输出修正后的完整 Java 文件（类名 %s），只修复反馈明确指出的编译、API "
        "或调用错误，不要为缺少 stdout marker 或独立观测而重写 PoC；"
        "stdout/stderr marker 都是未验证声明，不能补成证据。按候选的 sequence、"
        "capability_contract、residual_contracts 执行实际探测，不必打印对应 marker。"
        "只使用公共 API 与 JDK 类，确保可编译。输出不超过 200 行，"
        "只允许 ASCII 字符（禁止全角中文标点），无 Markdown 围栏。"
        % (cand["candidate_id"], compile_error[-3000:],
           cand.get("surface", ""), cand.get("logic", ""),
           ctx.cfg.api_hint or "（无）", ctx.cfg.name,
           cand.get("entry") or "见 API 提示", class_name)
    )
    text = ctx.llm.ask(SYSTEM_POC, user, max_tokens=8000, reasoning_effort="low")
    return extract_java_code(text)


def extract_java_code(text: str) -> str:
    """Extract Java source from an LLM reply the way the host lands code files:
    1) prefer a ```java / ``` fenced block anywhere in the reply;
    2) otherwise take the segment starting at the first import / class line.
    Reasoning models (effort=high) often prepend a task restatement before the
    actual code; compiling the whole reply fails while extracting the code
    segment works (verified 2026-08-09: high + extract = 3/3 compile OK)."""
    text = text.strip()
    m = re.search(r"```(?:java)?\s*(.*?)```", text, re.S)
    if m:
        return m.group(1).strip()
    m2 = re.search(
        r"(?:(?:import\s+[^;]+;\s*)+|(?:public\s+)?(?:final\s+)?(?:abstract\s+)?class\s+)",
        text)
    if m2:
        return text[m2.start():].strip()
    return text


def extract_shell_code(text: str) -> str:
    """Extract bash source from an LLM reply (fence or leading code block)."""
    text = text.strip()
    for fence in ("```bash", "```sh", "```shell"):
        m = re.search(re.escape(fence) + r"\s*(.*?)```", text, re.S)
        if m:
            return m.group(1).strip()
    m = re.search(r"```\s*(.*?)```", text, re.S)
    if m:
        return m.group(1).strip()
    start = re.search(r"(?:#!/bin/(?:ba)?sh|#!/usr/bin/env bash|set -[a-z])", text)
    if start:
        return text[start.start():].strip()
    return text


def generate_shell_poc(ctx: AutoCtx, cand: Dict[str, Any]) -> str:
    """S4a-web: LLM writes a minimal bash HTTP PoC for harness observation."""
    versions = ", ".join(sorted({v for v in ctx.cfg.target_urls}))
    pre = "; ".join(cand.get("preconditions") or ["无"])
    source_root, source_dirs = _target_source_scope(ctx)
    src_block = candidate_block(cand, ctx.cfg.entry_points, source_dirs,
                                source_root, max_chars=6000,
                                timeout=ctx.source_scan_timeout(),
                                hit_cache=ctx._candidate_source_hit_cache,
                                snippet_cache=ctx._candidate_source_snippet_cache)
    user = (
        "候选：%s\n攻击面：%s\n入口：%s\n逻辑：%s\n前置条件：%s\n"
        "可用目标版本(base URL 来自 env.md)：%s\n\n"
        "候选相关源码片段（真实源码证据，按真实端点与参数写 PoC，禁止凭记忆猜 API）：\n%s\n\n"
        "请输出单个 bash 脚本（HTTP PoC），最小可运行：\n"
        "- base URL 从环境变量 VULNGATE_TARGET_URL 读取（脚本内拼接路径）；\n"
        "- 按候选逻辑构造最小请求（curl 或 python3 urllib），真实发送并在脚本内按需检查响应；\n"
        "- HTTP 状态由 harness 独立记录；stdout/stderr marker 是未验证声明，不要为满足格式打印；\n"
        "- 只输出脚本本身，不回显响应正文、token/cookie/password 或其他敏感数据；\n"
        "- 权限矩阵上下文由 VULNGATE_AUTHZ_* 环境变量提供；\n"
        "- 有状态/竞态候选可读取 VULNGATE_SEQUENCE、VULNGATE_CONCURRENCY、"
        "VULNGATE_AVAILABILITY_PROBE 并按有界计划执行，不能把声明值当作结果；\n"
        "- 若存在 VULNGATE_VARIANT_SURFACE/VULNGATE_VARIANT_ID/"
        "VULNGATE_VARIANT_LANE/VULNGATE_VARIANT_STATE_STEPS，按当前 lane 选择"
        "fixture 状态机；lane、required observation 和 falsifier 都不是结果；\n"
        "- 能力链可读取 VULNGATE_CAPABILITY_CONTRACT、VULNGATE_CAPABILITIES、"
        "VULNGATE_TRANSITIONS 并按契约执行探测，不能把声明值当成观测；\n"
        "- 只允许访问 VULNGATE_TARGET_URL 指向的主机（回环 127.0.0.1）；禁止外联；\n"
        "- 禁止解释性输出，只输出脚本本身。"
        % (cand["candidate_id"], cand.get("surface"), cand.get("entry"),
           cand.get("logic"), pre, versions or "（未配置，需 env.md 提供 target_url）",
           src_block or "（未定位到源码片段）")
    )
    text = ctx.llm.ask(_poc_prompt(ctx), user, max_tokens=8000, reasoning_effort="low")
    return extract_shell_code(text)


def repair_shell_poc(ctx: AutoCtx, cand: Dict[str, Any], script_text: str,
                     feedback: str) -> str:
    """S4b-web: one LLM repair pass with the actual shell cell output."""
    user = (
        "你上次为候选 %s 生成的 Web PoC 遇到具体脚本或请求错误，反馈如下：\n\n%s\n\n"
        "候选攻击面（必须针对这个攻击面重写，不要另起炉灶）：\n%s\n"
        "攻击逻辑：%s\n"
        "请只输出修正后的完整 bash 脚本：base URL 从 VULNGATE_TARGET_URL 读取，"
        "只修复反馈明确指出的 shell 语法、API 用法或请求构造错误；"
        "不要为了缺少 stdout marker 或响应观测而改写脚本。HTTP 观测由 harness 采集，"
        "PoC marker 不能作为证据。权限上下文从 VULNGATE_AUTHZ_* 环境变量读取，"
        "禁止写入或输出 token/cookie/password；"
        "只允许访问 127.0.0.1/localhost，无解释性文本。"
        % (cand["candidate_id"], feedback[-3000:],
           cand.get("surface", ""), cand.get("logic", ""))
    )
    text = ctx.llm.ask(_poc_prompt(ctx), user, max_tokens=8000, reasoning_effort="low")
    return extract_shell_code(text)


def _verify_web_candidate(ctx: AutoCtx, round_no: int, cand: Dict[str, Any],
                          audit: Dict[str, Any]) -> Dict[str, Any]:
    """S4-web: shell PoC matrix against running target URLs (ShellMatrixRunner)."""
    cid = cand["candidate_id"]
    urls = dict(ctx.cfg.target_urls)
    if not urls:
        return {"candidate": cand, "audit": audit,
                "summary": {"harness_error":
                            "web-app 需要 env.md 提供 target_url（如 "
                            "`target_url: http://127.0.0.1:8080` 或按版本 "
                            "`target_url.<version>: ...`）"},
                "conclusion": "待验证", "spec": None}
    src_dir = ctx.root / "poc" / ctx.cfg.name / ("round-%02d" % round_no) / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    script_name = "Poc%s.sh" % (re.sub(r"[^A-Za-z0-9]", "", cid) or "X")
    script_text = generate_shell_poc(ctx, cand)
    if not script_text.strip():
        return {"candidate": cand, "audit": audit,
                "summary": {"harness_error": "LLM returned empty shell PoC"},
                "conclusion": "待验证", "spec": None}
    script_file = src_dir / script_name
    script_file.write_text(script_text, encoding="utf-8")
    authz_cases = normalize_authz_cases(cand.get("authz_cases")) or [{}]
    cells = [MatrixCell(version=v, safe_mode=False, precondition="none", authz=case,
                        sequence=cand.get("sequence", []),
                        concurrency=cand.get("concurrency", 1),
                        availability_probe=cand.get("availability_probe", False),
                        capability_contract=capability_contract_from_candidate(cand),
                        residual_contracts=(cand.get("experiment_plan") or {}).get(
                            "residual_contracts", []),
                        consistency_action=(cand.get("experiment_plan") or {}).get(
                            "consistency_action", {}))
             for v in sorted(urls) for case in authz_cases]
    spec = ShellPOCSpec(candidate_id=cid, script=script_name, cells=cells,
                        urls=urls, entry=cand.get("entry", ""),
                        input_shape=cand.get("input_shape", ""),
                        logic=cand.get("logic", ""),
                        effect_observers=dict(cand.get("effect_observers",
                                                       cand.get("effects", {})) or {}))
    approval = ApprovalGate(
        log_path=ctx.root / "state" / ctx.cfg.name
        / ("round-%02d" % round_no) / "approval-log.jsonl")
    budget = ctx.s4_execution_budget
    runner = ShellMatrixRunner(ctx.root, ctx.cfg.name, round_no,
                               approval=approval, execution_budget=budget)
    results: Dict[str, List[Dict[str, Any]]] = {}
    try:
        results = runner.run_manifest([spec])
        cells, convergence = converge_s4_cells(
            ctx.root, ctx.cfg.name, round_no, cid, results.get(cid, []))
        summary = summarize_candidate(cells)
        summary["s4_result_sources"] = convergence["sources"]
        for _repair_round in range(1):
            if budget.exhausted(cid):
                break
            if summary.get("evidence_gap") == "needs-harness-observer":
                # Rewriting a PoC cannot provide an unsupported observer.
                print("  %s: needs-harness-observer; keeping PoC claims and skipping repair" % cid)
                break
            # A missing response can mean the harness refused to launch the
            # cell (unsupported observer, isolation failure, unavailable
            # precondition, or stop-loss), not that the PoC needs rewriting.
            # Repair only after at least one actual, non-blocked execution.
            repairable_statuses = {
                "needs-harness-observer", "needs-network-isolation", "blocked",
                "precondition-unavailable", "stop-loss", "resource-limit-exceeded",
                "aborted",
            }
            executed_cell = any(
                c.get("returncode") is not None
                and not c.get("harness_error")
                and not c.get("timed_out")
                and c.get("policy_status") not in repairable_statuses
                for c in cells
            )
            if not executed_cell:
                print("  %s: no runnable S4 cell; skipping PoC repair" % cid)
                break
            concrete_script_failure = any(
                c.get("returncode") not in (None, 0)
                and not c.get("harness_error")
                and not c.get("timed_out")
                and c.get("policy_status") not in repairable_statuses
                for c in cells
            )
            if (summary.get("evidence_gap") == "no-independent-http-response"
                    and not concrete_script_failure):
                print("  %s: no independent HTTP response; keeping candidate pending" % cid)
                break
            needs_repair = (concrete_script_failure
                            and not summary.get("http_evidence")
                            and not summary.get("gate_blocked")
                            and not summary.get("errors"))
            if not needs_repair:
                break
            print("  %s: no evidence, asking LLM to repair (round %d)..." % (
                cid, _repair_round + 1))
            feedback = "\n".join(
                "cell %s exit=%s stderr=%s" % (
                    c.get("version"), c.get("returncode"),
                    (c.get("stderr") or "")[-800:])
                for c in cells[:2]) or "no output"
            fixed = repair_shell_poc(ctx, cand, script_text, feedback)
            if not fixed.strip():
                break
            script_file.write_text(fixed, encoding="utf-8")
            results = runner.run_manifest([spec])
            cells, convergence = converge_s4_cells(
                ctx.root, ctx.cfg.name, round_no, cid, results.get(cid, []))
            summary = summarize_candidate(cells)
            summary["s4_result_sources"] = convergence["sources"]
    except Exception as exc:
        cells, convergence = converge_s4_cells(
            ctx.root, ctx.cfg.name, round_no, cid, [])
        summary = summarize_candidate(cells)
        summary["harness_error"] = "%s: %s" % (type(exc).__name__, exc)
        summary["s4_result_sources"] = convergence["sources"]
    try:
        runtime_lab = run_s4_runtime_lab(
            ctx.root, ctx.cfg.name, round_no, ctx.cfg, [cand], [], [spec], {},
            baseline_results=results, approval=approval,
            version_universe=sorted(ctx.cfg.target_urls),
            source_revision_artifacts=ctx.cfg.resolve_source_revision_artifacts(
                ctx.root),
            execution_budget=budget)
    except Exception as exc:
        runtime_lab = {
            "schema_version": "runtime-lab-v1", "scope": "ordinary-s4",
            "status": "run-failed",
            "reason": "%s: %s" % (type(exc).__name__, str(exc)[:240]),
            "fixtures": [], "claim_status": "not-a-finding",
        }
    conclusion = _derive(summary, cand, cells)
    return {"candidate": cand, "audit": audit, "summary": summary,
            "conclusion": conclusion, "spec": spec,
            "runtime_lab": runtime_lab}


def poc_consistency(cand: Dict[str, Any], src_text: str) -> List[str]:
    """Reject vacuous LLM PoCs that ignore the candidate's declared attack:
    a PoC that declares target_classes must reference that class and
    must reflect a declared entry feature (e.g. activateDefaultTyping).
    """
    issues: List[str] = []
    targets = [str(t) for t in (cand.get("target_classes") or [])]
    if targets and not any(t in src_text or t.split(".")[-1] in src_text for t in targets):
        issues.append("PoC 源码未引用声明的目标类 %s" % targets)
    feat = cand.get("entry_feature") or ""
    if feat and feat not in src_text:
        issues.append("PoC 源码未体现声明的入口 Feature %s" % feat)
    return issues


def build_cells(ctx: AutoCtx, cand: Dict[str, Any]) -> List[MatrixCell]:
    versions = sorted({j.get("version") for j in ctx.cfg.jars})
    # cell_preconditions = matrix variants (e.g. cache-clean/cache-polluted);
    # preconditions = human checklist for the finding doc. Autonomous matrix
    # defaults to a single "none" cell unless cell_preconditions is set.
    preconditions = cand.get("cell_preconditions") or ["none"]
    authz_cases = normalize_authz_cases(cand.get("authz_cases")) or [{}]
    cells = []
    features = ["SupportAutoType"] if cand.get("entry_feature") == "SupportAutoType" else []
    jvm = dict(cand.get("jvm") or {})
    required_runtime = str(cand.get("required_runtime", cand.get("requested_runtime", "")))
    java_bin = str(cand.get("java_bin", ""))
    java_home = str(cand.get("java_home", ""))
    sequence = cand.get("sequence", [])
    concurrency = cand.get("concurrency", 1)
    availability_probe = cand.get("availability_probe", False)
    # DoS/resource-exhaustion candidates need a small heap or the OOM path
    # is never exercised under the matrix default JVM. If the LLM did not
    # declare Xmx, inject a 256m heap when the surface/logic hints at it.
    if "Xmx" not in jvm:
        blob = " ".join(str(x) for x in (
            cand.get("surface", ""), cand.get("logic", ""),
            cand.get("hypothesis", "")))
        if any(k in blob for k in (
                "OOM", "OutOfMemory", "内存", "堆", "耗尽", "DoS", "拒绝服务",
                "无界分配", "分配", "崩溃", "StackOverflow", "栈溢出", "CPU")):
            jvm["Xmx"] = "256m"
    for v in versions:
        for safe in (True, False):
            for pre in preconditions:
                for authz in authz_cases:
                    cells.append(MatrixCell(version=v, safe_mode=safe, features=features,
                                        precondition=pre, jvm=jvm, authz=authz,
                                        sequence=sequence, concurrency=concurrency,
                                        availability_probe=availability_probe,
                                        capability_contract=capability_contract_from_candidate(cand),
                                        residual_contracts=(cand.get("experiment_plan") or {}).get(
                                            "residual_contracts", []),
                                        consistency_action=(cand.get("experiment_plan") or {}).get(
                                            "consistency_action", {}),
                                        required_runtime=required_runtime,
                                        java_bin=java_bin, java_home=java_home))
    return cells


def verify_candidate(ctx: AutoCtx, round_no: int, cand: Dict[str, Any],
                     audit: Dict[str, Any]) -> Dict[str, Any]:
    """S4: write PoC, run the matrix, derive conclusion from observations."""
    cid = cand["candidate_id"]
    budget = getattr(ctx, "s4_execution_budget", None)
    if budget is None:
        budget = S4ExecutionBudget(
            getattr(ctx.cfg, "s4_timeout_seconds", 5400),
            getattr(ctx.cfg, "s4_candidate_timeout_seconds", 900))
        ctx.s4_execution_budget = budget
    budget.deadline_for(cid)
    fz = cand.get("fuzz_spec")
    if fz:
        return _verify_fuzz_candidate(ctx, round_no, cand, audit, fz)
    if ctx.cfg.target_type == "web-app":
        return _verify_web_candidate(ctx, round_no, cand, audit)
    src_dir = ctx.root / "poc" / ctx.cfg.name / ("round-%02d" % round_no) / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    spec_extra: List[str] = []
    seed_dir = cand.get("poc_seed_dir")
    is_seed = bool(seed_dir)
    if seed_dir:
        # Regression mode: use a previously verified PoC as seed (multi-file ok).
        seed_root = ctx.root / seed_dir
        if not seed_root.exists():
            return {"candidate": cand, "audit": audit,
                    "summary": {"harness_error": "poc_seed_dir missing: %s" % seed_dir},
                    "conclusion": "待验证", "spec": None}
        main_rel = cand.get("poc_class_seed") or "Probe.java"
        for f in sorted(seed_root.rglob("*.java")):
            rel = f.relative_to(seed_root)
            dest = src_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
            if rel.as_posix() != main_rel:
                spec_extra.append(rel.as_posix())
        class_name = Path(main_rel).stem
        src_file = src_dir / main_rel
        src_text = src_file.read_text(encoding="utf-8")
    else:
        # Force a collision-free, single-file class name (LLM may otherwise pick
        # library class names (e.g. the target's own entry class) -> broken harness).
        import re as _re
        class_name = "Poc" + (_re.sub(r"[^A-Za-z0-9]", "", str(cid)) or "X")
        cand["poc_class"] = class_name
        src_text = generate_poc(ctx, cand)
        if not src_text.strip():
            return {"candidate": cand, "audit": audit,
                    "summary": {"harness_error": "LLM returned empty PoC"},
                    "conclusion": "待验证", "spec": None}
        consistency = poc_consistency(cand, src_text)
        if consistency:
            return {"candidate": cand, "audit": audit,
                    "summary": {"harness_error": "PoC 与候选声明不一致: %s" % "; ".join(consistency)},
                    "conclusion": "待验证", "spec": None}
        src_file = src_dir / (class_name + ".java")
    src_file.write_text(src_text, encoding="utf-8")
    module_opts: List[str] = []
    module_run_opts: List[str] = []
    for ex in ctx.cfg.add_exports:
        module_opts += ["--add-exports", ex]
    for op in ctx.cfg.add_opens:
        module_run_opts += ["--add-opens", op]
    spec = POCSpec(
        candidate_id=cid, class_name=class_name,
        src=src_file.name, extra_srcs=spec_extra, cells=build_cells(ctx, cand),
        safe_mode_jvm_prop=ctx.cfg.safe_mode_jvm_prop,
        module_opts=module_opts,
        module_run_opts=module_run_opts,
        entry=cand.get("entry", ""), input_shape=cand.get("input_shape", ""),
        logic=cand.get("logic", ""),
    )
    approval = ApprovalGate(
        log_path=ctx.root / "state" / ctx.cfg.name
        / ("round-%02d" % round_no) / "approval-log.jsonl")
    budget = ctx.s4_execution_budget
    runner = JavaMatrixRunner(ctx.root, ctx.cfg.name, round_no,
                              approval=approval, execution_budget=budget)
    cells: List[Dict[str, Any]] = []
    results: Dict[str, List[Dict[str, Any]]] = {}
    try:
        results = runner.run_manifest([spec], ctx.jars_by_version())
        cells, convergence = converge_s4_cells(
            ctx.root, ctx.cfg.name, round_no, cid, results.get(cid, []))
        summary = summarize_candidate(cells)
        summary["s4_result_sources"] = convergence["sources"]
        for _repair_round in range(2):
            if budget.exhausted(cid):
                break
            inst_fqcn = ""
            if summary.get("instantiated"):
                inst_fqcn = str(summary["instantiated"][0])
            targets = [str(t) for t in (cand.get("target_classes") or [])]
            jvm = dict(cand.get("jvm") or {})
            if "Xmx" not in jvm:
                jvm["Xmx"] = "256m"  # mirrors build_cells injection
            err_text = " ".join(str(e.get("error", ""))
                                for e in summary.get("errors", []))
            is_dos = "Xmx" in jvm and not targets
            dos_miss = is_dos and bool(inst_fqcn) and not any(
                k in err_text for k in ("OutOfMemory", "StackOverflow"))
            mismatch_inst = bool(targets) and bool(inst_fqcn) and (
                inst_fqcn not in targets)
            needs_repair = (
                not is_seed
                and (summary.get("compile_error")
                     or (summary.get("errors")
                         and not summary.get("instantiated")
                         and not summary.get("leaked"))
                     or mismatch_inst or dos_miss))
            if not needs_repair:
                break
            # Repair both compile failures AND runtime anomalies with no
            # evidence (e.g. wrong JSONB API -> register_method_not_found):
            # a bare LLM PoC must be able to confirm a real finding without
            # relying on pre-existing seeds.
            print("  %s: no evidence, asking LLM to repair (round %d)..." % (
                cid, _repair_round + 1))
            feedback = summary.get("compile_error") or "; ".join(
                str(e.get("error", "")) for e in summary.get("errors", [])[:2])
            fixed = repair_poc(ctx, cand, src_text, feedback)
            if not fixed.strip():
                break
            src_file.write_text(fixed, encoding="utf-8")
            results = runner.run_manifest([spec], ctx.jars_by_version())
            cells, convergence = converge_s4_cells(
                ctx.root, ctx.cfg.name, round_no, cid, results.get(cid, []))
            summary = summarize_candidate(cells)
            summary["s4_result_sources"] = convergence["sources"]
    except BudgetExceeded:
        raise
    except Exception as exc:  # compile failure / harness error -> honest 待验证
        cells, convergence = converge_s4_cells(
            ctx.root, ctx.cfg.name, round_no, cid, cells)
        summary = summarize_candidate(cells)
        summary["harness_error"] = "%s: %s" % (type(exc).__name__, exc)
        summary["s4_result_sources"] = convergence["sources"]
    try:
        runtime_lab = run_s4_runtime_lab(
            ctx.root, ctx.cfg.name, round_no, ctx.cfg, [cand], [spec], [],
            ctx.jars_by_version(), baseline_results=results, approval=approval,
            version_universe=sorted(ctx.jars_by_version()),
            source_revision_artifacts=ctx.cfg.resolve_source_revision_artifacts(
                ctx.root),
            execution_budget=budget)
    except Exception as exc:
        runtime_lab = {
            "schema_version": "runtime-lab-v1", "scope": "ordinary-s4",
            "status": "run-failed",
            "reason": "%s: %s" % (type(exc).__name__, str(exc)[:240]),
            "fixtures": [], "claim_status": "not-a-finding",
        }
    conclusion = _derive(summary, cand, cells)
    return {"candidate": cand, "audit": audit, "summary": summary,
            "conclusion": conclusion, "spec": spec,
            "runtime_lab": runtime_lab}


def _verify_fuzz_candidate(ctx: AutoCtx, round_no: int, cand: Dict[str, Any],
                           audit: Dict[str, Any], fz: Dict[str, Any]) -> Dict[str, Any]:
    """S4 for fuzz-generated candidates: re-verify the minimized input through
    the standard {version x SafeMode} matrix with the shared FuzzProbe."""
    cid = cand["candidate_id"]
    probe = ctx.root / fz.get("probe_src", "")
    if not probe.exists():
        return {"candidate": cand, "audit": audit,
                "summary": {"harness_error": "fuzz probe missing: %s" % fz.get("probe_src")},
                "conclusion": "待验证", "spec": None}
    src_dir = ctx.root / "poc" / ctx.cfg.name / ("round-%02d" % round_no) / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    src_file = src_dir / "FuzzProbe.java"
    if not src_file.exists():
        src_file.write_text(probe.read_text(encoding="utf-8"), encoding="utf-8")
    class_name = "FuzzProbe"
    versions = sorted({j.get("version") for j in ctx.cfg.jars})
    jvm = fz.get("jvm") or cand.get("jvm") or {}
    cells = [MatrixCell(
        version=v, safe_mode=s, features=[], precondition="none",
        args=["--entry", fz["entry"], "--hex", fz["hex"]], jvm=jvm,
        sequence=cand.get("sequence", []),
        concurrency=cand.get("concurrency", 1),
        availability_probe=cand.get("availability_probe", False),
        capability_contract=capability_contract_from_candidate(cand),
        residual_contracts=(cand.get("experiment_plan") or {}).get(
            "residual_contracts", []),
        consistency_action=(cand.get("experiment_plan") or {}).get(
            "consistency_action", {}))
        for v in versions for s in (True, False)]
    spec = POCSpec(
        candidate_id=cid, class_name=class_name, src="FuzzProbe.java",
        cells=cells, safe_mode_jvm_prop=ctx.cfg.safe_mode_jvm_prop,
        module_opts=[], module_run_opts=[],
        entry=cand.get("entry", ""), input_shape=cand.get("input_shape", ""),
        logic=cand.get("logic", ""),
    )
    runner = JavaMatrixRunner(
        ctx.root, ctx.cfg.name, round_no,
        approval=ApprovalGate(log_path=ctx.root / "state" / ctx.cfg.name
                              / ("round-%02d" % round_no) / "approval-log.jsonl"),
        execution_budget=ctx.s4_execution_budget)
    try:
        results = runner.run_manifest([spec], ctx.jars_by_version())
        cells, convergence = converge_s4_cells(
            ctx.root, ctx.cfg.name, round_no, cid, results.get(cid, []))
        summary = summarize_candidate(cells)
        summary["s4_result_sources"] = convergence["sources"]
    except Exception as exc:
        persisted_cells, convergence = converge_s4_cells(
            ctx.root, ctx.cfg.name, round_no, cid, [])
        cells = persisted_cells
        summary = summarize_candidate(cells)
        summary["harness_error"] = "%s: %s" % (type(exc).__name__, exc)
        summary["s4_result_sources"] = convergence["sources"]
    if fz.get("bucket") == "crash":
        # Runtime anomaly observed in discovery, but mechanism-level
        # confirmation (exact code path / exploitability) is still pending.
        conclusion = "候选（待验证）"
    else:
        conclusion = _derive(summary, cand, cells)
        if conclusion == "确认" and fz.get("bucket") in ("oom", "soe", "hang"):
            # Precondition tier is decided by the full matrix: if any
            # default-config cell (SafeMode off) reproduces, it is tier "0".
            default_hit = any(
                e.get("safe") is False for e in summary.get("errors", []))
            if default_hit:
                cand["precondition_tier_hint"] = "0"
                cand["preconditions"] = ["无（默认配置触发）"]
                if not str(cand.get("cvss_vector", "")).startswith("AV:N/AC:L"):
                    cand["cvss_vector"] = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    return {"candidate": cand, "audit": audit, "summary": summary,
            "conclusion": conclusion, "spec": spec}


def _fuzz_audit(cand: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic audit note for fuzz-generated candidates (no LLM call)."""
    fz = cand.get("fuzz_spec") or {}
    return {
        "gate_status": "fuzz-generated runtime anomaly (bucket=%s)" % fz.get("bucket"),
        "gate_kind": "fuzz-observation",
        "gate_location": cand.get("entry", ""),
        "default_config_reachable": cand.get("precondition_tier_hint") == "0",
        "code_location": ["fuzzer discovery: state/<target>/round-NN/FUZZ/fuzz-report.json",
                          "minimized input: fuzz_spec.hex"],
        "audit_notes": "由定向模糊引擎生成；静态代码定位需后续人工/LLM 审计。",
    }


# Back-compat alias: the benchmark runner and callers historically imported
# `_derive` from this module. The implementation now lives in the shared
# agent/tools/conclusion.py (baseline fix #10).
_derive = derive_conclusion


def novelty_check(ctx: AutoCtx, row: Dict[str, Any]) -> Dict[str, Any]:
    """S5: live GitHub search + config refs -> evaluate -> G3."""
    cand = row["candidate"]
    fixtures = ctx.root / "agent" / "regression" / "fixtures"
    checker = NoveltyChecker(
        fixtures_dir=fixtures if fixtures.exists() else None,
        offline=ctx.offline,
        cache_dir=ctx.root / "agent" / "regression" / "cache" / "api")
    repo = getattr(ctx.cfg, "upstream_repo", None) or ""
    refs: List[UpstreamRef] = []
    for r in cand.get("upstream_refs", []):
        refs.append(UpstreamRef(**r))
    if repo and not ctx.offline:
        for kw in cand.get("novelty_keywords", [])[:4]:
            for item in checker.search(repo, kw)[:8]:
                number = item.get("number")
                ref = UpstreamRef(
                    ref=("#%d" % number) if number else item.get("title", "")[:24],
                    kind="pull_request" if item.get("pull_request") else "issue",
                    title=item.get("title", ""),
                    state=item.get("state", ""),
                    created_at=item.get("created_at", ""),
                    url=item.get("html_url", ""),
                    evidence_source="live GitHub search (autonomous)",
                )
                if ref.ref not in {x.ref for x in refs}:
                    refs.append(ref)
    disclosures = [Disclosure(**d) for d in cand.get("disclosures", [])]
    pub = ctx.public_disclosures()
    disclosures += pub["disclosures"]
    # Baseline #7: query failure/offline must not silently become "0day".
    query_metadata = checker.query_metadata()
    query_failed = bool(pub.get("errors")) or checker.last_rate_limit is not None \
        or bool(checker.query_errors) or ctx.offline \
        or bool(query_metadata.get("query_failed"))
    nv = checker.evaluate(refs, disclosures, ctx.cfg.discovery_date,
                          increments_hint=cand.get("increments_hint", []),
                          query_failed=query_failed)
    audit = mechanism_audit(ctx, cand, refs, checker)
    if audit:
        same = [a for a in audit if a.get("same_mechanism")]
        if same:
            nv.verdict = "known-family-with-increment"
            nv.reason += " | upstream body confirms same mechanism: %s" % ", ".join(
                str(a.get("ref")) for a in same)
        nv.increments.append(
            "mechanism audit: %d upstream bodies reviewed, %d same mechanism"
            % (len(audit), len(same)))
    g3 = g3_novelty(dataclasses.asdict(nv))
    def _jsonable(obj: Any) -> Any:
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            return dataclasses.asdict(obj)
        if isinstance(obj, list):
            return [_jsonable(x) for x in obj]
        if isinstance(obj, dict):
            return {k: _jsonable(v) for k, v in obj.items()}
        return obj

    return {"novelty": dataclasses.asdict(nv), "g3": g3.__dict__,
            "refs": [dataclasses.asdict(r) for r in refs],
            "disclosures": [dataclasses.asdict(d) for d in disclosures],
            "public_scan": _jsonable(pub),
            "mechanism_audit": audit,
            "query_metadata": checker.query_metadata()}


def mechanism_audit(ctx: AutoCtx, cand: Dict[str, Any], refs: List[UpstreamRef],
                    checker: NoveltyChecker) -> List[Dict[str, Any]]:
    """S5b: fetch issue/PR bodies for predating hits and have the LLM judge
    whether the upstream record is the SAME vulnerability mechanism as the
    candidate (e.g. same gadget class, same code path, same fix target).
    One bounded LLM call; failures degrade to an empty audit, never a crash.
    """
    repo = getattr(ctx.cfg, "upstream_repo", None) or ""
    return mechanism_audit_llm(
        ctx.llm, _sec_prompt(ctx), cand, refs, checker,
        ctx.cfg.discovery_date, repo, offline=ctx.offline)


def cvss_for_tier(tier: str) -> str:
    if tier == "0":
        return "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    return "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"


