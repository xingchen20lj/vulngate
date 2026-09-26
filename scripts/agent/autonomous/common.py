"""Shared context and policy for the autonomous audit phases."""

import argparse
import dataclasses
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..llm.adapter import BudgetExceeded, LLMClient
from ..memory.ledger import render_finding_md, write_round_artifacts
from ..memory.research import (build_residual_closure_report,
                                build_round_memory, load_research_memory,
                                load_review_feedback, merge_research_memory,
                                research_key, write_research_memory)
from ..memory.portfolio import (build_research_portfolio,
                                write_research_portfolio)
from ..evaluation.research_consistency import (
    build_research_consistency,
    write_research_consistency,
)
from ..evaluation.research_consistency_actions import (
    action_for_research_key,
    build_research_consistency_actions,
    load_research_consistency_actions,
    write_research_consistency_actions,
)
from ..evaluation.research_consistency_rechecks import (
    build_research_consistency_rechecks,
    write_research_consistency_rechecks,
)
from ..analysis.research_strategy import (apply_strategy_observations,
                                           apply_research_guidance,
                                           load_research_strategy,
                                           strategy_guidance_for_candidate,
                                           write_research_guidance,
                                           write_research_strategy)
from ..analysis.research_agenda import (build_research_agenda,
                                        load_research_agenda,
                                        selected_candidate_ids,
                                        write_research_agenda)
from ..analysis.research_agenda_outcomes import (
    build_research_agenda_outcomes,
    load_research_agenda_outcomes,
    load_schedule_snapshot,
    write_research_agenda_outcomes,
)
from ..analysis.research_budget import (
    build_research_budget,
    load_research_budget,
    write_research_budget,
)
from ..orchestrator.config import TargetConfig
from ..orchestrator.gates import g3_novelty
from ..orchestrator.work_budget import WorkBudget
from ..sandbox.approval import ApprovalGate
from ..tools.build import (JavaMatrixRunner, MatrixCell, POCSpec,
                           ShellMatrixRunner, ShellPOCSpec, summarize_candidate,
                           converge_s4_cells, S4ExecutionBudget,
                           S4_EVIDENCE_POLICY_VERSION)
from ..tools.authz import normalize_authz_case, normalize_authz_cases
from ..tools.conclusion import (DENY_CLASS_HINTS, conclusion_status,
                                derive_conclusion, is_confirmed_conclusion,
                                validate_confirmation)
from ..tools.cvss import base_score, check_impact_consistency
from ..tools.fuzzer import run_fuzz_for_pipeline
from ..tools.novelty import (Disclosure, NoveltyChecker, UpstreamRef,
                             mechanism_audit_llm)
from ..tools.patch_variants import analyze_patch_history
from ..tools.project_profile import build_project_profile
from ..tools.experiment_planner import plan_candidate_experiments
from ..tools.experiment import capability_contract_from_candidate
from ..tools.research_strategies import composite_chain_candidates
from ..tools.s4_runtime_lab import (merge_runtime_lab_artifacts,
                                    run_s4_runtime_lab)
from ..tools.target_rules import composite_chain_hints, scan_s1_source_rules
from ..tools.public_scan import scan_all
from ..tools.seeds import load_seeds, seed_reference_block
from ..tools import source_evidence as se
from ..tools.source_evidence import (DANGER_PATTERNS, SOURCE_MAP_PRESETS,
                                     build_source_sink_graph, candidate_block,
                                     match_source_sink_paths,
                                     summarize_hits, surface_block)

ROOT = Path(__file__).resolve().parents[2]
TARGET_PREPARATION_MAX_SECONDS = 15 * 60

SYSTEM_SECURITY = (
    "你是资深 Java 安全研究员，擅长反序列化/解析库的 0day 挖掘。"
    "所有结论必须基于可运行时验证的假设；严禁声称未经验证的 0day。"
    "只能审计当前 target 目录；禁止切换产品、使用远程主机、SSH/SCP/远程 rsync、云 CLI、"
    "公网监听或向第三方发送验证流量。无法本地回环复现的条件标记为待验证。"
    "输出严格 JSON，不要 Markdown 围栏。"
)

SYSTEM_POC = (
    "你是资深 Java 安全 PoC 作者。直接输出最终 Java 源码，"
    "不要输出思考过程，不要解释，无 Markdown 围栏，不要 package 声明（单文件默认包）。"
    "让 PoC 以最小输入真实调用目标 API，并由运行器收集退出状态及支持的独立观测。"
    "不要为了满足输出格式打印机器可读 marker；stdout/stderr 都是 PoC 自报声明，"
    "不能证明目标效果，输出诊断也不是必需的。"
    "若存在 surface variant fixture 上下文，读取 VULNGATE_VARIANT_SURFACE、"
    "VULNGATE_VARIANT_ID、VULNGATE_VARIANT_LANE、VULNGATE_VARIANT_STATE_STEPS；"
    "按当前 fixture 状态执行对应输入；positive/negative/environment-gap 只是实验选择，"
    "不能当成结果。"
)

SYSTEM_SECURITY_WEB = (
    "你是资深 Web 应用安全研究员，擅长 Web 框架的路由/鉴权、SQL 注入、SSRF、"
    "模板注入、命令注入、信息泄露与业务逻辑漏洞挖掘。"
    "所有结论必须基于可运行时验证的假设；严禁声称未经验证的 0day。"
    "只能审计当前 target 目录；禁止切换产品、使用远程主机、SSH/SCP/远程 rsync、云 CLI、"
    "公网监听或向第三方发送验证流量。无法本地回环复现的条件标记为待验证。"
    "输出严格 JSON，不要 Markdown 围栏。"
)

SYSTEM_POC_WEB = (
    "你是资深 Web 安全 PoC 作者。直接输出最终 bash 脚本（HTTP PoC），"
    "不要输出思考过程，不要解释，无 Markdown 围栏。"
    "用最小请求真实触发候选路径；不要为了满足输出格式打印机器可读 marker。"
    "stdout/stderr 是 PoC 自报声明，不能证明服务端响应或副作用；响应元数据只以"
    "运行器独立捕获的结果为准。不要输出响应中的凭据或其他敏感内容。"
    "若存在 surface variant fixture，读取 VULNGATE_VARIANT_SURFACE、"
    "VULNGATE_VARIANT_ID、VULNGATE_VARIANT_LANE、"
    "VULNGATE_VARIANT_STATE_STEPS，并按当前 fixture 状态选择请求；这些字段不是结果。"
    "目标 base URL 必须从环境变量 VULNGATE_TARGET_URL 读取（脚本内使用该变量拼接路径，"
    "禁止硬编码其他主机；网络目标只允许 127.0.0.1/localhost）。"
    "允许使用 curl 与 python3，但只能访问明确的回环 URL；禁止 SSH/SCP/远程 rsync、云 CLI、"
    "公网监听和部署。禁止输出解释性文本。"
)


class TargetPreparationTimeout(RuntimeError):
    """Raised when bounded new-target preparation exhausts its wall budget."""

    def __init__(self, progress: Dict[str, Any]):
        self.progress = dict(progress)
        super().__init__(
            "target preparation timed out in %s at %s" % (
                str(progress.get("stage") or "unknown"),
                str(progress.get("current_path") or "unknown")))


def _sec_prompt(ctx: "AutoCtx") -> str:
    return SYSTEM_SECURITY_WEB if ctx.cfg.target_type == "web-app" else SYSTEM_SECURITY


def _poc_prompt(ctx: "AutoCtx") -> str:
    return SYSTEM_POC_WEB if ctx.cfg.target_type == "web-app" else SYSTEM_POC


class AutoCtx:
    def __init__(self, root: Path, cfg: TargetConfig, llm: LLMClient,
                 offline: bool, max_candidates: int, max_rounds: int,
                 fuzz_budget: int = 0, fuzz_seed: Optional[int] = None,
                 fuzz_force: bool = False, fuzz_skip_minimize: bool = False,
                 force: bool = False):
        self.root = root
        self.cfg = cfg
        self.llm = llm
        self.offline = offline
        try:
            candidate_budget = int(max_candidates)
        except (TypeError, ValueError):
            candidate_budget = 0
        # Autonomous mode historically accepts this CLI value directly.  Keep
        # a finite fallback instead of letting ``0`` erase the work budget or
        # become an implicit unbounded pool.
        self.max_candidates = candidate_budget if candidate_budget > 0 else 4
        self.max_rounds = max_rounds
        self.fuzz_budget = fuzz_budget
        self.fuzz_seed = fuzz_seed
        self.fuzz_force = fuzz_force
        self.fuzz_skip_minimize = fuzz_skip_minimize
        self.force = bool(force)
        # Baseline #9: candidates carried from the previous round, passed into
        # the next S2 so the research loop is continuous, not from-zero.
        self.carryover: List[Dict[str, Any]] = []
        self.stop_file = root / "state" / cfg.name / "STOP"
        self._public_scan_cache: Optional[Dict[str, Any]] = None
        self._benchmark_feedback_cache: Optional[Dict[str, Any]] = None
        self._replay_cohort_cache: Optional[Dict[str, Any]] = None
        self.s4_execution_budget: Optional[S4ExecutionBudget] = None
        self._coverage_inventory_round: Optional[int] = None
        self._coverage_inventory_state: Optional[Dict[str, Any]] = None
        self._candidate_source_hit_cache: Dict[Any, Any] = {}
        self._candidate_source_snippet_cache = se.CandidateSourceSnippetCache(
            root / "state" / cfg.name / "cache" /
            "candidate-source-snippets-v1.json")
        self._api_hint_attempted = False
        self._round_budget_record: Optional[Dict[str, Any]] = None
        self.work_budget: Optional[WorkBudget] = None

    def round_budget_remaining(self) -> Optional[float]:
        """Read the current round's persistent deadline, if one is active."""
        if not isinstance(self._round_budget_record, dict):
            return None
        from ..analysis.audit_budget import round_budget_snapshot

        return float(round_budget_snapshot(self._round_budget_record)
                     ["remaining_seconds"])

    def source_scan_timeout(self) -> int:
        """Clamp prompt-source scans to both config and active round budget."""
        configured = getattr(self.cfg, "coverage_scan_timeout_seconds", 600)
        if (isinstance(configured, bool) or not isinstance(configured, int)
                or configured < 0):
            raise ValueError(
                "coverage_scan_timeout_seconds must be a nonnegative integer")
        remaining = self.round_budget_remaining()
        if remaining is None:
            return configured
        available = max(1, int(remaining))
        return min(configured, available) if configured > 0 else available

    def public_disclosures(self) -> Dict[str, Any]:
        """Memoized internet disclosure scan (plan 2.7); [] when offline."""
        if self._public_scan_cache is None:
            self._public_scan_cache = scan_all(
                self.cfg, offline=self.offline,
                cache_dir=self.root / "agent" / "regression" / "cache" / "api")
        return self._public_scan_cache

    def write_artifact(self, round_no: int, stage: str, name: str, data: Any) -> Path:
        d = self.root / "state" / self.cfg.name / ("round-%02d" % round_no) / stage
        d.mkdir(parents=True, exist_ok=True)
        p = d / name
        if isinstance(data, str):
            p.write_text(data, encoding="utf-8")
        else:
            p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return p

    def jars_by_version(self) -> Dict[str, List[Path]]:
        return self.cfg.resolve_jars(self.root)

    def benchmark_feedback(self) -> Dict[str, Any]:
        """Load only explicitly configured benchmark feedback for this target."""
        if self._benchmark_feedback_cache is not None:
            return dict(self._benchmark_feedback_cache)
        from ..evaluation.benchmark import benchmark_feedback_from_input

        value: Any = getattr(self.cfg, "benchmark_feedback", {}) or {}
        configured_path = getattr(self.cfg, "benchmark_feedback_path", None)
        if configured_path:
            path = Path(configured_path)
            if not path.is_absolute():
                path = self.root / path
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                value = {}
        self._benchmark_feedback_cache = benchmark_feedback_from_input(value)
        return dict(self._benchmark_feedback_cache)

    def replay_cohort_calibration(self) -> Dict[str, Any]:
        """Load only explicitly configured cross-project replay metadata."""
        if self._replay_cohort_cache is not None:
            return dict(self._replay_cohort_cache)
        configured_path = getattr(
            self.cfg, "replay_cohort_calibration_path", None)
        value: Dict[str, Any] = {}
        if configured_path:
            from ..evaluation.replay_cohort import load_replay_cohort_file

            path = Path(configured_path)
            if not path.is_absolute():
                path = self.root / path
            value = load_replay_cohort_file(path)
        self._replay_cohort_cache = value
        return dict(value)


def _target_source_scope(ctx: "AutoCtx") -> Tuple[Path, List[str]]:
    """Resolve the autonomous target's source universe once, without widening.

    Prepared targets live below ``targets/<name>`` while older configurations
    may intentionally use the workspace as their root.  In both forms,
    explicit invalid source dirs yield an empty direct-scan scope and are
    recorded by the inventory contract; they never fall back to scanning the
    plugin workspace.
    """
    from ..analysis.languages import resolve_source_dirs

    target_root = ctx.root / "targets" / ctx.cfg.name
    if not target_root.exists():
        target_root = ctx.root
    _bases, source_dirs, _invalid = resolve_source_dirs(
        target_root, ctx.cfg.source_dirs)
    return target_root, source_dirs


def _fmt_entries(entries: List[Dict[str, Any]]) -> str:
    return "\n".join(
        "- %s (%s, %s, untrusted=%s)"
        % (e.get("api"), e.get("input_shape"), e.get("file_line"), e.get("untrusted"))
        for e in entries[:20])


def _scope_block(ctx: "AutoCtx", limit: int = 4000) -> str:
    """Inject the target project's authoritative security-boundary rules
    (e.g. SECURITY.md) so candidate generation/audit respects its scope."""
    text = (ctx.cfg.scope_constraints or "").strip()
    if not text:
        return ""
    return ("\n\n[目标项目安全边界 —— 官方 SECURITY 文档/范围规则，"
            "必须作为候选筛选与审计的硬约束]\n%s" % text[:limit])





