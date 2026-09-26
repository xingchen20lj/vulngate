"""Autonomous 0day-hunting agent (LLM in the loop).

Unlike the config-driven S1-S8 pipeline, this driver *owns* the loop:

  prepare target -> LLM proposes candidates -> LLM audits -> LLM writes PoC
  -> deterministic {version x safeMode x precondition} matrix -> observations
  derive conclusions -> live Novelty scan + LLM judgment -> CVSS -> local
  reports + ledger -> LLM proposes next-round candidates -> iterate until
  budget exhausted / no new candidates / STOP flag.

The deterministic gates (G0-G5), approval log, checkpointing and ledger
rendering are reused from agent/orchestrator, agent/tools and agent/memory.

Usage:
  python3 -m agent.autonomous.run_agent \
    --name <target> --round 3 \
    --config agent/regression/configs/<target>-auto.json \
    --max-calls 24 --max-candidates 1 --max-rounds 1 \
    --model deepseek-v4-flash

  or for a brand-new target:
  python3 -m agent.autonomous.run_agent \
    --name jackson --target-dir /path/to/jackson --round 1 --max-rounds 3
"""

from __future__ import annotations

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


def _is_web_target(target_dir: Path, timeout: float = 30) -> bool:
    """Heuristic target-type detection (observable facts only)."""
    markers = ("compojure", "ring/ring", "javax.servlet", "jakarta.servlet",
               "spring-boot", "SpringBootApplication", "flask", "django",
               "express", "dispatcher", "defroutes", "defendpoint")
    env_md = target_dir / "env.md"
    if env_md.exists():
        text = env_md.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if line.strip().lower().startswith("target_type:"):
                tt = line.split(":", 1)[1].strip().lower()
                return tt in ("web-app", "webapp", "web", "application")
    try:
        hits = subprocess.run(
            ["rg", "-l", "-m", "1", "|".join(markers), str(target_dir)],
            capture_output=True, text=True, timeout=timeout).stdout
        return bool(hits.strip())
    except subprocess.TimeoutExpired as exc:
        raise TargetPreparationTimeout({
            "stage": "target-type-detection", "current_path": str(target_dir),
            "error": "target-type scan timed out", "claim_status": "not-a-finding",
        }) from exc
    except Exception:
        return False


def scan_all_http_entries(source_dirs: List[Path], timeout: float = 600
                          ) -> List[Dict[str, Any]]:
    """Web-app entry inventory: **every** route/controller declaration found.

    Split from :func:`scan_http_entries` per spec §6.1 -- this half is uncapped
    and is what the coverage index is built from; the other half exists only to
    keep a prompt/report bounded.
    """
    pat = SOURCE_MAP_PRESETS.get("http", r"defendpoint|defroutes|doGet|doPost")
    entries: List[Dict[str, Any]] = []
    seen = set()
    deadline = time.monotonic() + max(0.0, float(timeout))
    for sd in source_dirs:
        if not sd.exists():
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TargetPreparationTimeout({
                "stage": "http-entry-scan", "current_path": str(sd),
                "error": "shared HTTP entry scan deadline exhausted",
                "claim_status": "not-a-finding",
            })
        try:
            hits = se.scan_all_hits(pat, [sd.as_posix()], sd.parent,
                                    timeout=remaining)
        except se.SourceScanTimeout as exc:
            raise TargetPreparationTimeout({
                "stage": "http-entry-scan", "current_path": str(sd),
                "error": str(exc), "scan_progress": exc.progress,
                "claim_status": "not-a-finding",
            }) from exc
        for hit in hits:
            if time.monotonic() >= deadline:
                raise TargetPreparationTimeout({
                    "stage": "http-entry-scan", "current_path": str(hit["file"]),
                    "error": "HTTP entry classification exceeded its shared deadline",
                    "claim_status": "not-a-finding",
                })
            key = (hit["file"], hit["line"])
            if key in seen:
                continue
            seen.add(key)
            entries.append({
                "api": "http-route",
                "input_shape": "http-request",
                "file_line": "%s:%d" % (hit["file"], hit["line"]),
                "untrusted": True,
                "text": hit["text"],
                "entry_kind": "http",
                "module": str(hit["file"]).split("/")[0],
            })
    entries.sort(key=lambda e: str(e["file_line"]))
    if time.monotonic() >= deadline:
        raise TargetPreparationTimeout({
            "stage": "http-entry-scan",
            "current_path": str(source_dirs[-1] if source_dirs else Path(".")),
            "error": "HTTP entry inventory sorting exceeded its shared deadline",
            "claim_status": "not-a-finding",
        })
    return entries


def scan_http_entries(source_dirs: List[Path],
                      max_items: int = 200) -> List[Dict[str, Any]]:
    """Bounded web entry digest for configs/prompts.  **Not** an index."""
    return summarize_hits(scan_all_http_entries(source_dirs), max_items)


def _sec_prompt(ctx: "AutoCtx") -> str:
    return SYSTEM_SECURITY_WEB if ctx.cfg.target_type == "web-app" else SYSTEM_SECURITY


def _poc_prompt(ctx: "AutoCtx") -> str:
    return SYSTEM_POC_WEB if ctx.cfg.target_type == "web-app" else SYSTEM_POC

ENTRY_API_PATTERNS = [
    (r"\breadValue\s*\(", "json deserialization entry (ObjectMapper)"),
    (r"\breadTree\s*\(", "json tree parse entry"),
    (r"\bparseObject\s*\(", "text/json, typed object parse"),
    (r"\bfromJson\s*\(", "json parse"),
    (r"\bfromXml\s*\(", "text/xml object parse"),
    (r"\bfromXML\s*\(", "text/xml object parse"),
    (r"\bunmarshal\s*\(", "stream/xml unmarshal"),
    (r"\bdecodeObject\s*\(", "binary object parse"),
    (r"\breadObject\s*\(", "stream object parse"),
    (r"\bparse\s*\(", "text/json parse (generic)"),
]

#: Combined danger-pattern regex, used to score an entry file's danger density.
#: Counting from the file text once (rather than one ``rg -c`` per file) keeps
#: the now-uncapped entry scan affordable.
_DANGER_COMBINED = re.compile("|".join("(?:%s)" % p for p, _ in DANGER_PATTERNS))


def _danger_hit_count(path: Path, cache: Dict[str, int]) -> int:
    key = path.as_posix()
    if key in cache:
        return cache[key]
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        count = len(_DANGER_COMBINED.findall(text))
    except OSError:
        count = 0
    cache[key] = count
    return count


def scan_all_entries(source_dirs: List[Path], timeout: float = 600
                     ) -> List[Dict[str, Any]]:
    """**Full** entry inventory: every hit of every entry-API pattern.

    The previous implementation stopped at ``per_pattern=5`` and
    ``len(entries) >= 20``, so a target with 400 parse call sites reported 20
    entries and the remaining 380 never entered any audit state (spec §6.1).
    The caps now live only in :func:`scan_entries`. All API patterns are
    classified from one combined ripgrep pass so preparation has one shared
    scan deadline instead of rescanning the full tree once per API.
    """
    entries: List[Dict[str, Any]] = []
    seen = set()
    danger_cache: Dict[str, int] = {}
    scan_roots = [(Path(os.path.abspath(src)), Path(os.path.abspath(src)).resolve())
                  for src in source_dirs if src.exists()]
    if not scan_roots:
        return entries
    deadline = time.monotonic() + max(0.0, float(timeout))
    scan_root = Path(os.path.commonpath([str(src) for src, _resolved in scan_roots]))
    source_relpaths = [Path(os.path.relpath(src, scan_root)).as_posix()
                       for src, _resolved in scan_roots]
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise se.SourceScanTimeout({
            "elapsed_seconds": 0.0, "files_seen": 0, "source_files": 0,
            "directories_seen": 0, "hits_seen": 0, "current_path": str(scan_root),
            "scan": "entry-classification",
        })
    for hit in se.scan_all_labeled_hits(
            ENTRY_API_PATTERNS, source_relpaths, scan_root,
            max_per_pattern=None, timeout=remaining):
        if time.monotonic() >= deadline:
            raise se.SourceScanTimeout({
                "elapsed_seconds": round(float(timeout), 3),
                "files_seen": 0, "source_files": 0,
                "directories_seen": len(scan_roots), "hits_seen": len(entries),
                "current_path": str(hit.get("file") or scan_root),
                "scan": "entry-classification",
            })
        pattern = str(hit["pattern"])
        api = pattern.strip("\\b().*")
        abs_file = scan_root.resolve() / str(hit["file"])
        for src, resolved_src in scan_roots:
            try:
                abs_file.relative_to(resolved_src)
                rel = abs_file.relative_to(src.parent.resolve()).as_posix()
            except ValueError:
                continue
            key = (api, rel, hit["line"])
            if key in seen:
                continue
            seen.add(key)
            danger_hits = _danger_hit_count(abs_file, danger_cache)
            if time.monotonic() >= deadline:
                raise se.SourceScanTimeout({
                    "elapsed_seconds": round(float(timeout), 3),
                    "files_seen": 0, "source_files": 0,
                    "directories_seen": len(scan_roots), "hits_seen": len(entries),
                    "current_path": str(abs_file), "scan": "entry-classification",
                })
            entries.append({
                "api": api,
                "input_shape": hit["label"],
                "file_line": "%s:%d" % (rel, hit["line"]),
                "default_features": "[]",
                "untrusted": True,
                "danger_hits": danger_hits,
                "module": rel.split("/")[0],
                "entry_kind": "library-api",
                "text": hit["text"],
            })
    entries.sort(key=lambda e: (str(e.get("file_line")), str(e.get("api"))))
    if time.monotonic() >= deadline:
        raise se.SourceScanTimeout({
            "elapsed_seconds": round(float(timeout), 3),
            "files_seen": 0, "source_files": 0,
            "directories_seen": len(scan_roots), "hits_seen": len(entries),
            "current_path": str(scan_root), "scan": "entry-classification-sort",
        })
    return entries


def scan_entries(source_dirs: List[Path],
                 max_items: int = 20) -> List[Dict[str, Any]]:
    """Bounded entry digest for configs/prompts.  **Not** an index."""
    return summarize_hits(scan_all_entries(source_dirs), max_items)


def prepare_target(root: Path, name: str, target_dir: Path,
                   round_budget: Optional[Dict[str, Any]] = None) -> TargetConfig:
    """Copy a new target and inventory it within the persisted round budget."""
    from ..analysis.audit_budget import budget_path, round_budget_snapshot

    target_dir = target_dir.resolve()
    dest = root / "targets" / name
    prep_started = time.monotonic()
    if round_budget:
        budget_snapshot = round_budget_snapshot(round_budget)
        remaining_round = float(budget_snapshot["remaining_seconds"])
        # The S0 setup window is tied to the original round start, so retrying
        # preparation cannot renew its 15-minute slice.
        prep_window_remaining = max(
            0.0, TARGET_PREPARATION_MAX_SECONDS -
            float(budget_snapshot["elapsed_seconds"]))
        remaining = min(remaining_round, prep_window_remaining)
    else:
        remaining = min(600.0, TARGET_PREPARATION_MAX_SECONDS)
    deadline = prep_started + remaining

    def check_budget(stage: str, current_path: Path) -> float:
        left = deadline - time.monotonic()
        if left < 1:
            raise TargetPreparationTimeout({
                "stage": stage, "current_path": str(current_path),
                "elapsed_seconds": round(time.monotonic() - prep_started, 3),
                "claim_status": "not-a-finding",
            })
        return left

    def write_status(stage: str, current_path: Path,
                     status: str = "in-progress") -> None:
        if not round_budget:
            return
        status_path = budget_path(
            root, name, int(round_budget["round"])).parent / \
            "target-preparation-status.json"
        status_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "status": status, "stage": stage,
            "current_path": str(current_path),
            "elapsed_seconds": round(time.monotonic() - prep_started, 3),
            "remaining_seconds": round(max(0.0, deadline - time.monotonic()), 3),
            "round_remaining_seconds": (
                round(float(round_budget_snapshot(round_budget)["remaining_seconds"]), 3)
                if round_budget else None),
            "claim_status": "not-a-finding",
        }
        status_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")
        print("[S0 prepare] %s path=%s elapsed=%.1fs remaining=%.1fs" % (
            stage, current_path, payload["elapsed_seconds"],
            payload["remaining_seconds"]))

    write_status("target-type-detection", target_dir)
    is_web = _is_web_target(
        target_dir, timeout=min(30.0, check_budget("target-type-detection", target_dir)))
    if not dest.exists():
        dest.mkdir(parents=True)
        try:
            write_status("target-copy", target_dir)
            subprocess.run(
                ["rsync", "-a", "--exclude", ".git", "--exclude", "target",
                 "--exclude", "build", "--exclude", ".gradle",
                 str(target_dir) + "/", str(dest) + "/"],
                check=True, timeout=min(600.0, check_budget("target-copy", target_dir)))
        except subprocess.TimeoutExpired as exc:
            shutil.rmtree(dest, ignore_errors=True)
            raise TargetPreparationTimeout({
                "stage": "target-copy", "current_path": str(target_dir),
                "error": "rsync exceeded the remaining audit budget",
                "claim_status": "not-a-finding",
            }) from exc
        except Exception:
            shutil.rmtree(dest, ignore_errors=True)
            raise
    # Auto-copy built jars from the source tree (rsync excludes target/, so a
    # freshly built jar would otherwise never be seen by the jar scan).
    jar_srcs: List[Path] = []
    for pat in ("target/*.jar", "*/target/*.jar", "lib/*.jar", "*.jar"):
        check_budget("jar-import", target_dir)
        jar_srcs += [p for p in target_dir.glob(pat)
                     if "sources" not in p.name and "javadoc" not in p.name]
    if jar_srcs:
        lib = dest / "lib"
        lib.mkdir(parents=True, exist_ok=True)
        for jar_source in jar_srcs:
            check_budget("jar-import", jar_source)
            shutil.copy2(jar_source, lib / jar_source.name)
    if is_web:
        # Web-app layouts vary (Clojure src/, Maven src/main/java, ...):
        # prefer a top-level src/ dir, else the copy root.
        web_dirs = [d for d in dest.iterdir() if d.is_dir() and d.name == "src"]
        source_dirs = [d.relative_to(dest).as_posix() for d in web_dirs] or ["."]
        write_status("http-entry-scan", dest)
        entries = scan_all_http_entries(
            [dest / d for d in source_dirs],
            timeout=min(600.0, check_budget("http-entry-scan", dest)))
    else:
        source_dirs = sorted(
            d.relative_to(dest).as_posix()
            for d in dest.iterdir() if (d / "src" / "main" / "java").exists())
        write_status("library-entry-scan", dest)
        try:
            entries = scan_all_entries(
                [dest / d for d in source_dirs],
                timeout=min(600.0, check_budget("library-entry-scan", dest)))
        except se.SourceScanTimeout as exc:
            raise TargetPreparationTimeout({
                "stage": "library-entry-scan", "current_path": str(dest),
                "error": str(exc), "scan_progress": exc.progress,
                "claim_status": "not-a-finding",
            }) from exc
    write_status("jar-discovery", dest)
    jars: List[str] = []
    jar_dirs = [dest]
    while jar_dirs:
        current = jar_dirs.pop()
        check_budget("jar-discovery", current)
        try:
            with os.scandir(current) as children:
                for child in children:
                    check_budget("jar-discovery", Path(child.path))
                    try:
                        if child.is_dir(follow_symlinks=False):
                            jar_dirs.append(Path(child.path))
                        elif (child.name.endswith(".jar")
                              and "sources" not in child.name
                              and "javadoc" not in child.name
                              and child.is_file(follow_symlinks=True)):
                            jars.append(Path(child.path).as_posix())
                    except OSError:
                        continue
        except OSError:
            continue
    jars.sort()
    if not jars and not is_web:
        raise SystemExit(
            "no jars found under %s: build first (mvn package / ./mvnw -DskipTests package),\n"
            "then re-run; jars under target/ or lib/ are auto-copied into lib/" % dest)
    target_urls: Dict[str, str] = {}
    env_md = target_dir / "env.md"
    if env_md.exists():
        check_budget("target-metadata", env_md)
        for line in env_md.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.lower().startswith("target_url:"):
                target_urls["local"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("target_url."):
                ver, _, url = line[11:].partition(":")
                if url.strip():
                    target_urls[ver.strip()] = url.strip()
    scope_constraints = ""
    for scope_name in ("scope.md", "SECURITY-SCOPE.md", "SECURITY.md"):
        scope_file = target_dir / scope_name
        if scope_file.exists():
            check_budget("scope-metadata", scope_file)
            scope_constraints = scope_file.read_text(
                encoding="utf-8", errors="replace").strip()
            break
    cfg = {
        "name": name,
        "discovery_date": date.today().isoformat(),
        "target_type": "web-app" if is_web else "library",
        "target_urls": target_urls,
        "scope_constraints": scope_constraints,
        "upstream_repo": "",
        "runtime_lab": {},
        "jars": [{"version": "local", "path": jars[0]}] if jars else [],
        "deps": [],
        "source_dirs": source_dirs,
        "entry_points": entries,
        "candidates": [],
        "notes": "auto-generated by autonomous driver",
    }
    check_budget("config-write", dest)
    cfg_path = root / "agent" / "regression" / "configs" / (name + "-auto.json")
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    write_status("complete", dest, status="complete")
    return TargetConfig.load(cfg_path)


def _ensure_capability_inventory(ctx: "AutoCtx", *, allow_rebuild: bool = True,
                                rebuild_budget_seconds: Optional[int] = None
                                ) -> Dict[str, Any]:
    """Load valid path indices or build them after candidate-first work.

    Candidate-first rounds call with ``allow_rebuild=False`` before S2, so a
    missing or legacy inventory is reported as deferred without blocking
    configured or model-proposed candidates. After the first candidate wave,
    the caller may allow one bounded rebuild. A failed scope never falls back
    to stale rows.
    """
    from ..analysis import capability_graph as capability
    from ..analysis import coverage as cov
    from ..analysis import semantic_calls as semantic_call
    from ..analysis import semantic_controlflow as semantic_controlflow
    from ..analysis import semantic_ast as semantic_ast
    from ..analysis import semantic_transforms as semantic_transform
    from ..analysis import semantic_bindings as semantic_binding
    from ..analysis import semantic_guards as semantic_guard
    from ..analysis import semantic_paths as semantic
    from ..analysis import evidence_provenance as evidence_provenance_analysis
    from ..analysis import threat_model as threat_model_analysis
    from ..analysis.inventory import (CoverageStore, build_inventory,
                                      coverage_scope_status, persist_inventory)
    from ..analysis.languages import SourceFilter, SourceScanTimeout

    store = CoverageStore(ctx.root, ctx.cfg.name)
    target_root, _effective_source_dirs = _target_source_scope(ctx)
    # Keep the configured (rather than normalized) spellings for the persisted
    # contract so a missing/outside path remains a visible scope gap.
    source_dirs = list(ctx.cfg.source_dirs or [])
    scan_timeout = getattr(ctx.cfg, "coverage_scan_timeout_seconds", 600)
    if (isinstance(scan_timeout, bool)
            or not isinstance(scan_timeout, int) or scan_timeout < 0):
        return {"rebuilt": False,
                "error": "coverage_scan_timeout_seconds must be a nonnegative integer",
                "scope": {"status": "invalid-config", "usable": False},
                "graph": {}, "candidates": []}
    source_filter = SourceFilter(scan_timeout_seconds=scan_timeout)
    budget_reader = getattr(ctx, "round_budget_remaining", None)
    round_remaining = budget_reader() if callable(budget_reader) else None
    runtime_budget = round_remaining
    if rebuild_budget_seconds is not None:
        rebuild_budget = int(rebuild_budget_seconds)
        if rebuild_budget < 1:
            return {"rebuilt": False, "deferred": True,
                    "status": "deferred", "error": "no round budget remains",
                    "scope": {"status": "deferred", "usable": False},
                    "graph": {}, "candidates": []}
        runtime_budget = (min(runtime_budget, rebuild_budget)
                          if runtime_budget is not None else rebuild_budget)
    if runtime_budget is not None:
        source_filter.runtime_deadline_override_seconds = runtime_budget
    scope_status = coverage_scope_status(
        store, target_root, source_dirs or None,
        source_filter=source_filter, target_type=ctx.cfg.target_type)
    required_ready = (store.path(capability.CAPABILITY_GRAPH_INDEX).exists()
            and store.path(threat_model_analysis.THREAT_MODEL_INDEX).exists()
            and store.path(semantic.SEMANTIC_PATH_INDEX).exists()
            and store.path(semantic_guard.SEMANTIC_GUARD_INDEX).exists()
            and store.path(semantic_call.SEMANTIC_CALL_INDEX).exists()
            and store.path(semantic_controlflow.SEMANTIC_CONTROLFLOW_INDEX).exists()
            and store.path(semantic_ast.SEMANTIC_AST_INDEX).exists()
            and store.path(semantic_transform.SEMANTIC_TRANSFORM_INDEX).exists()
            and store.path(semantic_binding.SEMANTIC_BINDING_INDEX).exists()
            and store.path(evidence_provenance_analysis.EVIDENCE_PROVENANCE_INDEX).exists())
    # An incomplete/failed scan must never make old derived artifacts look
    # current. Permit a retry only after an explicit --force or a changed scope/
    # timeout; an unchanged failed scan would otherwise repeat every round.
    build_status = scope_status.get("build_status") or {}
    expected_scope = scope_status.get("expected") or {}
    actual_scope = scope_status.get("actual") or {}
    scope_fields = ("root", "source_dirs", "requested_source_dirs",
                    "invalid_source_dirs", "filter", "target_type")
    # Compare against this attempt, never the last successful inventory. A
    # failed rebuild after widening the scope leaves that old inventory intact.
    # Comparing to it would automatically repeat the same failed work forever.
    attempted_scope = build_status.get("attempt_scope")
    if isinstance(attempted_scope, dict):
        contract_changed = any(expected_scope.get(field) != attempted_scope.get(field)
                               for field in scope_fields)
    elif build_status.get("status") in {"running", "incomplete", "failed"}:
        # Legacy failures did not retain their contract. An unknown attempt is
        # not evidence of a changed scope; --force migrates it explicitly.
        contract_changed = False
    else:
        contract_changed = any(expected_scope.get(field) != actual_scope.get(field)
                               for field in scope_fields)
    retry_scope_changed = (contract_changed
        or ("source_dirs" in build_status and
            build_status["source_dirs"] != source_dirs)
        or ("timeout_seconds" in build_status and
            build_status["timeout_seconds"] != scan_timeout))
    attempt_key = (expected_scope.get("scope_id", ""), scan_timeout)
    attempted = getattr(ctx, "_coverage_attempted_contracts", set())
    retry_requested = bool(getattr(ctx, "force", False)) and attempt_key not in attempted
    blocked_scope = scope_status["status"] in {
        "running", "incomplete", "failed", "invalid",
    }
    if blocked_scope and not (retry_requested or retry_scope_changed):
        return {"rebuilt": False,
                "error": "coverage scope is %s; refusing stale derived indices" %
                         scope_status["status"],
                "coverage": {"state": "scope-incomplete",
                             "claim_status": "not-a-finding"},
                "scope": scope_status, "graph": {}, "candidates": []}
    scope_requires_rebuild = scope_status["status"] in {
        "missing", "legacy", "mismatch", "running", "incomplete",
        "failed", "invalid",
    }
    if required_ready and not scope_requires_rebuild:
        refresh = cov.refresh_candidate_coverage(store, ctx.root, ctx.cfg.name)
        return {"rebuilt": False, "coverage": refresh,
                "scope": scope_status,
                "graph": capability.load_capability_graph(store),
                "candidates": capability.load_capability_candidates(store),
                "semantic": semantic.load_semantic_evidence(store),
                "semantic_guards": semantic_guard.load_semantic_guards(store),
                "semantic_guard_candidates": semantic_guard.load_semantic_guard_candidates(store),
                "semantic_calls": semantic_call.load_semantic_call_evidence(store),
                "semantic_call_candidates": semantic_call.load_semantic_call_candidates(store),
                "semantic_controlflow": semantic_controlflow.load_semantic_controlflow(store),
                "semantic_controlflow_candidates": semantic_controlflow.load_semantic_controlflow_candidates(store),
                "semantic_ast": semantic_ast.load_semantic_ast(store),
                "semantic_ast_candidates": semantic_ast.load_semantic_ast_candidates(store),
                "semantic_transforms": semantic_transform.load_semantic_transform_evidence(store),
                "semantic_transform_candidates": semantic_transform.load_semantic_transform_candidates(store),
                "semantic_bindings": semantic_binding.load_semantic_binding_evidence(store),
                "semantic_binding_candidates": semantic_binding.load_semantic_binding_candidates(store),
                "evidence_provenance": evidence_provenance_analysis.load_evidence_provenance(store),
                "threat_model": threat_model_analysis.load_threat_model(
                    ctx.root, ctx.cfg.name)}

    # Autonomous S2 must be able to validate an initial candidate before a
    # potentially repository-wide rebuild. Reuse complete, matching indices
    # above, but defer new/missing/stale inventory work until there is no
    # candidate waiting for a falsifier.
    if not allow_rebuild:
        deferred_scope = dict(scope_status)
        deferred_scope["status"] = "deferred"
        deferred_scope["usable"] = False
        deferred_scope["mismatches"] = list(
            deferred_scope.get("mismatches") or []) + ["capability-index-not-ready"]
        return {"rebuilt": False, "deferred": True, "status": "deferred",
                "error": "capability inventory deferred until candidate-first work completes",
                "scope": deferred_scope, "graph": {}, "candidates": [],
                "semantic": {}, "semantic_guards": {},
                "semantic_guard_candidates": [], "semantic_calls": {},
                "semantic_call_candidates": [], "semantic_controlflow": {},
                "semantic_controlflow_candidates": [], "semantic_ast": {},
                "semantic_ast_candidates": [], "semantic_transforms": {},
                "semantic_transform_candidates": [], "semantic_bindings": {},
                "semantic_binding_candidates": [], "evidence_provenance": {},
                "threat_model": {}}

    try:
        attempted.add(attempt_key)
        ctx._coverage_attempted_contracts = attempted
        build_record = {
            "status": "running",
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "timeout_seconds": source_filter.scan_timeout_seconds,
            "runtime_budget_seconds": runtime_budget,
            "source_dirs": source_dirs,
            "attempt_scope": expected_scope,
        }
        store.write("coverage-build-status", build_record)

        def report_progress(progress: Dict[str, Any]) -> None:
            store.write("coverage-build-status", {
                **build_record, **progress, "status": "running",
            })

        result = build_inventory(target_root, source_dirs or None,
                                 source_filter=source_filter,
                                 target=ctx.cfg.name,
                                 target_type=ctx.cfg.target_type,
                                 progress_callback=report_progress)
        persist_inventory(store, result, target_type=ctx.cfg.target_type)
        store.write("coverage-build-status", {
            **build_record,
            "status": "complete",
            "completed_at": datetime.now().isoformat(timespec="seconds"),
            "scope_id": result.scope.get("scope_id", ""),
            "source_files": len(result.files),
            "elapsed_ms": result.elapsed_ms,
        })
        refreshed_scope = coverage_scope_status(
            store, target_root, source_dirs or None,
            source_filter=source_filter, target_type=ctx.cfg.target_type)
        if not refreshed_scope.get("usable"):
            return {"rebuilt": True,
                    "error": "rebuilt coverage scope is %s; refusing derived indices" %
                             refreshed_scope.get("status", "unknown"),
                    "coverage": {"state": "scope-incomplete",
                                 "claim_status": "not-a-finding"},
                    "scope": refreshed_scope, "graph": {}, "candidates": []}
        refresh = cov.refresh_candidate_coverage(store, ctx.root, ctx.cfg.name)
        return {"rebuilt": True, "coverage": refresh,
                "scope": refreshed_scope,
                "graph": capability.load_capability_graph(store),
                "candidates": capability.load_capability_candidates(store),
                "semantic": semantic.load_semantic_evidence(store),
                "semantic_guards": semantic_guard.load_semantic_guards(store),
                "semantic_guard_candidates": semantic_guard.load_semantic_guard_candidates(store),
                "semantic_calls": semantic_call.load_semantic_call_evidence(store),
                "semantic_call_candidates": semantic_call.load_semantic_call_candidates(store),
                "semantic_controlflow": semantic_controlflow.load_semantic_controlflow(store),
                "semantic_controlflow_candidates": semantic_controlflow.load_semantic_controlflow_candidates(store),
                "semantic_ast": semantic_ast.load_semantic_ast(store),
                "semantic_ast_candidates": semantic_ast.load_semantic_ast_candidates(store),
                "semantic_transforms": semantic_transform.load_semantic_transform_evidence(store),
                "semantic_transform_candidates": semantic_transform.load_semantic_transform_candidates(store),
                "semantic_bindings": semantic_binding.load_semantic_binding_evidence(store),
                "semantic_binding_candidates": semantic_binding.load_semantic_binding_candidates(store),
                "evidence_provenance": evidence_provenance_analysis.load_evidence_provenance(store),
                "threat_model": threat_model_analysis.load_threat_model(
                    ctx.root, ctx.cfg.name),
                "root": str(target_root)}
    except SourceScanTimeout as exc:
        store.write("coverage-build-status", {
            **build_record,
            "status": "incomplete",
            "failed_at": datetime.now().isoformat(timespec="seconds"),
            "error": str(exc), "progress": exc.progress,
        })
        return {"rebuilt": False, "error": str(exc),
                "status": "incomplete", "progress": exc.progress,
                "scope": {"status": "incomplete", "usable": False},
                "graph": {}, "candidates": [],
                "claim_status": "not-a-finding"}
    except Exception as exc:  # pragma: no cover - autonomous is best-effort
        store.write("coverage-build-status", {
            **build_record,
            "status": "failed",
            "failed_at": datetime.now().isoformat(timespec="seconds"),
            "error": "%s: %s" % (type(exc).__name__, exc),
        })
        return {"rebuilt": False,
                "error": "%s: %s" % (type(exc).__name__, exc),
                "status": "failed",
                "scope": {"status": "failed", "usable": False},
                "graph": {}, "candidates": [], "semantic": {},
                "semantic_guards": {},
                "semantic_guard_candidates": [],
                "semantic_calls": {},
                "semantic_call_candidates": [],
                "semantic_controlflow": {},
                "semantic_controlflow_candidates": [],
                "semantic_ast": {},
                "semantic_ast_candidates": [],
                "semantic_transforms": {},
                "semantic_transform_candidates": [],
                "semantic_bindings": {},
                "semantic_binding_candidates": [],
                "evidence_provenance": {},
                "threat_model": {}}


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
                        logic=cand.get("logic", ""))
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


def run_round(ctx: AutoCtx, round_no: int) -> Dict[str, Any]:
    """Full S2->S8 round with per-stage checkpoints (baseline fix #10:
    autonomous state semantics aligned with the config pipeline) and the G5
    CVSS-precondition consistency gate (previously missing in this driver)."""
    from ..memory.state import CheckpointStore
    from ..tools.cvss import check_precondition_consistency
    from ..analysis.audit_budget import (
        DEFAULT_BUDGET_SECONDS, round_budget_snapshot, start_round_budget,
    )
    from ..analysis.audit_guard import register_active_audit

    store = CheckpointStore(ctx.root, ctx.cfg.name, round_no)
    budget_seconds = getattr(
        ctx.cfg, "audit_round_timeout_seconds", DEFAULT_BUDGET_SECONDS)
    if budget_seconds is None:
        budget_seconds = DEFAULT_BUDGET_SECONDS
    try:
        ctx._round_budget_record = start_round_budget(
            ctx.root, ctx.cfg.name, round_no, budget_seconds)
    except (OSError, TypeError, ValueError) as exc:
        error = {"status": "invalid-round-budget", "error": str(exc),
                 "claim_status": "not-a-finding"}
        ctx.write_artifact(round_no, "S0", "execution-budget-status.json", error)
        print("[round-%02d] refusing invalid round budget: %s" % (round_no, exc))
        return {"next_candidates": [], **error}

    def timebox_report(last_completed: Optional[str], next_stage: str
                       ) -> Optional[Dict[str, Any]]:
        snapshot = round_budget_snapshot(ctx._round_budget_record)
        if not snapshot["expired"]:
            return None
        report = {
            "status": "stopped-at-round-deadline",
            "last_completed_stage": last_completed,
            "next_stage": next_stage,
            "completed_stages": store.completed_stages(),
            "audit_budget": snapshot,
            "claim_status": "not-a-finding",
        }
        ctx.write_artifact(round_no, "S0", "execution-budget-status.json", snapshot)
        ctx.write_artifact(round_no, "S0", "round-timebox-report.json", report)
        store.save_stage("S0", report)
        print("[round-%02d] round deadline expired; preserving progress and stopping" %
              round_no)
        return report

    report = timebox_report(None, "S1")
    if report:
        return {"next_candidates": [], **report}

    try:
        source_root, _source_dirs = _target_source_scope(ctx)
        register_active_audit(
            source_root, ctx.root, ctx.cfg.name, round_no,
            str(round_budget_snapshot(ctx._round_budget_record)["deadline_at"]))
    except (OSError, TypeError, ValueError) as exc:
        error = {"status": "invalid-round-guard", "error": str(exc),
                 "claim_status": "not-a-finding"}
        ctx.write_artifact(round_no, "S0", "execution-budget-status.json", error)
        print("[round-%02d] refusing round without active-audit guard: %s" % (
            round_no, exc))
        return {"next_candidates": [], **error}
    ctx._active_audit_guard_registered = True
    bind_deadline = getattr(ctx.llm, "set_timeout_provider", None)
    if callable(bind_deadline):
        bind_deadline(ctx.round_budget_remaining)

    ctx._candidate_source_hit_cache = {}
    ctx._candidate_source_snippet_cache.reset_round(
        round_no, ctx.root / "state" / ctx.cfg.name /
        ("round-%02d" % round_no) / "S0" / "source-cache-metrics.json")

    def bounded_scan_timeout(configured: int) -> int:
        remaining = int(round_budget_snapshot(
            ctx._round_budget_record)["remaining_seconds"])
        if remaining < 1:
            return 1
        return min(configured, remaining) if configured > 0 else remaining

    def record_capability_state(state: Dict[str, Any]) -> None:
        ctx._coverage_inventory_round = round_no
        ctx._coverage_inventory_state = state
        scope = state.get("scope")
        ctx.write_artifact(round_no, "S1", "capability-inventory-status.json", {
            "status": state.get("status") or (
                "complete" if isinstance(scope, dict) and scope.get("usable")
                else "incomplete"),
            "rebuilt": bool(state.get("rebuilt")),
            "deferred": bool(state.get("deferred")),
            "error": state.get("error"),
            "scope": state.get("scope") or {},
            "claim_status": "not-a-finding",
        })
        ctx.write_artifact(round_no, "S1", "capability-graph.json",
                           state.get("graph") or {})
        ctx.write_artifact(round_no, "S1", "capability-candidates.json",
                           state.get("candidates") or [])
        ctx.write_artifact(round_no, "S1", "threat-model.json",
                           state.get("threat_model") or {})
        ctx.write_artifact(round_no, "S1", "semantic-guard-evidence.json",
                           state.get("semantic_guards") or {})
        ctx.write_artifact(round_no, "S1", "semantic-guard-candidates.json",
                           state.get("semantic_guard_candidates") or [])
        ctx.write_artifact(round_no, "S1", "semantic-call-evidence.json",
                           state.get("semantic_calls") or {})
        ctx.write_artifact(round_no, "S1", "semantic-call-candidates.json",
                           state.get("semantic_call_candidates") or [])
        ctx.write_artifact(round_no, "S1", "semantic-controlflow-evidence.json",
                           state.get("semantic_controlflow") or {})
        ctx.write_artifact(round_no, "S1", "semantic-controlflow-candidates.json",
                           state.get("semantic_controlflow_candidates") or [])
        ctx.write_artifact(round_no, "S1", "semantic-ast-evidence.json",
                           state.get("semantic_ast") or {})
        ctx.write_artifact(round_no, "S1", "semantic-ast-candidates.json",
                           state.get("semantic_ast_candidates") or [])
        ctx.write_artifact(round_no, "S1", "semantic-transform-evidence.json",
                           state.get("semantic_transforms") or {})
        ctx.write_artifact(round_no, "S1", "semantic-transform-candidates.json",
                           state.get("semantic_transform_candidates") or [])
        ctx.write_artifact(round_no, "S1", "semantic-python-binding-evidence.json",
                           state.get("semantic_bindings") or {})
        ctx.write_artifact(round_no, "S1", "semantic-python-binding-candidates.json",
                           state.get("semantic_binding_candidates") or [])
        ctx.write_artifact(round_no, "S1", "evidence-provenance.json",
                           state.get("evidence_provenance") or {})
        if state.get("error"):
            ctx.write_artifact(round_no, "S1", "capability-graph-error.json", {
                "error": state["error"]})

    def try_deferred_inventory(stage: str) -> List[Dict[str, Any]]:
        state = getattr(ctx, "_coverage_inventory_state", None)
        if not isinstance(state, dict) or not state.get("deferred"):
            return []
        remaining = int(round_budget_snapshot(
            ctx._round_budget_record)["remaining_seconds"])
        # Reserve at least 15 minutes for S3/S4 (or S5-S8 after S4). A single
        # optional inventory attempt is capped at five minutes and can never
        # hold a scheduled candidate waiting for its next falsifier.
        reserve_seconds = 900
        if remaining <= reserve_seconds:
            ctx.write_artifact(round_no, stage, "capability-inventory-followup.json", {
                "status": "deferred", "reason": "insufficient-round-budget",
                "remaining_seconds": remaining, "claim_status": "not-a-finding",
            })
            return []
        rebuild_budget = min(300, remaining - reserve_seconds)
        rebuilt = _ensure_capability_inventory(
            ctx, allow_rebuild=True, rebuild_budget_seconds=rebuild_budget)
        ctx._coverage_inventory_round = round_no
        ctx._coverage_inventory_state = rebuilt
        scope = rebuilt.get("scope")
        ctx.write_artifact(round_no, stage, "capability-inventory-followup.json", {
            "status": rebuilt.get("status") or (
                "complete" if isinstance(scope, dict) and scope.get("usable")
                else "incomplete"),
            "rebuilt": bool(rebuilt.get("rebuilt")),
            "error": rebuilt.get("error"), "scope": rebuilt.get("scope") or {},
            "remaining_seconds": int(round_budget_snapshot(
                ctx._round_budget_record)["remaining_seconds"]),
            "claim_status": "not-a-finding",
        })
        leads, _ids = static_candidates(ctx, round_no)
        if leads:
            ctx.write_artifact(round_no, stage,
                               "deferred-capability-candidates.json", leads)
        return leads

    report = timebox_report(None, "S1")
    if report:
        return {**report, "next_candidates": []}

    if not ctx.cfg.api_hint:
        learn_api_hint(ctx, round_no)
        report = timebox_report("S1.5", "S1")
        if report:
            return {**report, "next_candidates": []}

    # Candidate prompt anchors are reused in-memory for this round. Extracted
    # snippets use a separate bounded content-digest cache: file bytes are
    # hashed on first access each round, so source edits invalidate old text.
    deferred_index_candidates: List[Dict[str, Any]] = []
    force = getattr(ctx, "force", False)
    source_root, source_dirs = _target_source_scope(ctx)
    inventory_timeout = getattr(ctx.cfg, "coverage_scan_timeout_seconds", 600)
    if (isinstance(inventory_timeout, bool)
            or not isinstance(inventory_timeout, int) or inventory_timeout < 0):
        raise ValueError("coverage_scan_timeout_seconds must be a nonnegative integer")
    from ..analysis.languages import SourceScanTimeout
    inventory_timeout = bounded_scan_timeout(inventory_timeout)

    # ---- S1 artifacts: attack surface (deterministic, refreshed cheaply) --
    # Baseline #1/#2: danger call-site map + entry danger-hit counts feed the
    # LLM prompts (via source_evidence) and the G0/G1 reachability notes.
    try:
        _danger_hits, target_rule_hits = scan_s1_source_rules(
            ctx.cfg.target_type, source_dirs, source_root,
            danger_limit=6, target_limit=8, timeout=inventory_timeout)
        source_rule_status = {"status": "complete",
                              "timeout_seconds": inventory_timeout,
                              "claim_status": "not-a-finding"}
    except SourceScanTimeout as exc:
        _danger_hits, target_rule_hits = [], []
        source_rule_status = {
            "status": "incomplete", "timeout_seconds": inventory_timeout,
            "error": str(exc), "progress": exc.progress,
            "claim_status": "not-a-finding",
        }
    _danger = [{"label": _h["label"], "file": _h["file"],
                "line": _h["line"], "text": _h["text"]}
               for _h in _danger_hits]
    ctx.write_artifact(round_no, "S1", "attack-surface.json", {
        "entries": ctx.cfg.entry_points,
        "danger_sites": _danger,
        "danger_site_count": len(_danger),
        "source_root": str(source_root),
        "source_dirs": source_dirs,
        "claim_status": "not-a-finding",
    })
    ctx.write_artifact(round_no, "S1", "source-rule-scan-status.json",
                       source_rule_status)
    patch_history = analyze_patch_history(ctx.root, max_count=30)
    report = timebox_report("S1-source-rules", "S1-source-sink-graph")
    if report:
        return {**report, "next_candidates": []}
    from ..analysis.languages import SourceFilter
    graph_timeout = bounded_scan_timeout(
        min(inventory_timeout, 120) if inventory_timeout else 0)
    graph_filter = SourceFilter(
        scan_timeout_seconds=min(inventory_timeout, 120) if inventory_timeout else 0,
        runtime_deadline_override_seconds=round_budget_snapshot(
            ctx._round_budget_record)["remaining_seconds"])
    try:
        ctx._source_sink_graph = build_source_sink_graph(
            source_dirs, source_root, source_filter=graph_filter)
        source_sink_status = {
            "status": "complete", "path_count": len(ctx._source_sink_graph),
            "timeout_seconds": graph_timeout,
            "claim_status": "not-a-finding",
        }
    except SourceScanTimeout as exc:
        ctx._source_sink_graph = []
        source_sink_status = {
            "status": "incomplete", "error": str(exc),
            "progress": exc.progress,
            "timeout_seconds": graph_timeout,
            "claim_status": "not-a-finding",
        }
    ctx.write_artifact(round_no, "S1", "source-sink-graph-status.json",
                       source_sink_status)
    profile_cfg = dataclasses.replace(ctx.cfg, source_dirs=source_dirs)
    ctx._project_profile = build_project_profile(
        profile_cfg, source_root, danger_site_count=len(_danger),
        source_sink_path_count=len(ctx._source_sink_graph),
        security_fix_count=len(patch_history))
    chain_hints = composite_chain_hints(ctx._source_sink_graph)
    chain_candidates = composite_chain_candidates(chain_hints)
    ctx.write_artifact(round_no, "S1", "security-fix-history.json", patch_history)
    ctx.write_artifact(round_no, "S1", "patch-variants.json", [
        {k: fix[k] for k in ("short_commit", "commit", "parent", "subject",
                             "affected_paths", "variant_hints", "probe_plan")}
        for fix in patch_history
    ])
    ctx.write_artifact(round_no, "S1", "source-sink-graph.json", ctx._source_sink_graph)
    ctx.write_artifact(round_no, "S1", "project-profile.json", ctx._project_profile)
    ctx.write_artifact(round_no, "S1", "target-rules.json", {
        "target_type": ctx.cfg.target_type, "hits": target_rule_hits,
    })
    ctx.write_artifact(round_no, "S1", "composite-chain-hints.json", chain_hints)
    ctx.write_artifact(round_no, "S1", "composite-chain-candidates.json",
                       chain_candidates)
    report = timebox_report("S1-source-sink-graph", "S1-capability-inventory")
    if report:
        return {**report, "next_candidates": []}
    capability_state = _ensure_capability_inventory(ctx, allow_rebuild=False)
    record_capability_state(capability_state)
    report = timebox_report("S1-capability-inventory", "S2")
    if report:
        return {**report, "next_candidates": []}

    # ---- S2: candidates (resumable) -----------------------------------
    s2 = store.load_stage("S2")
    if s2 and not force:
        candidates = s2["candidates"]
        print("[round-%02d] S2 resume: %d candidates loaded" % (round_no, len(candidates)))
        experiment_plans = _attach_experiment_plans(ctx, round_no, candidates)
        store.save_stage("S2", {"candidates": candidates})
    else:
        fuzz_cands: List[Dict[str, Any]] = []
        if ctx.fuzz_budget > 0:
            print("[round-%02d] S2: fuzz discovery (budget=%d, seed=%s)..."
                  % (round_no, ctx.fuzz_budget, ctx.fuzz_seed or 20260808))
            fuzz_cands = run_fuzz_for_pipeline(
                ctx.root, ctx.cfg, round_no, budget=ctx.fuzz_budget,
                seed=ctx.fuzz_seed or 20260808, force=ctx.fuzz_force,
                skip_minimize=ctx.fuzz_skip_minimize)
        llm_slots = max(0, ctx.max_candidates - len(fuzz_cands))
        if llm_slots > 0:
            print("[round-%02d] S2: proposing candidates (LLM)..." % round_no)
            llm_cands = propose_candidates(ctx, round_no,
                                           carryover=ctx.carryover)[:llm_slots]
        else:
            print("[round-%02d] fuzz candidates fill budget; skipping LLM proposal" % round_no)
            llm_cands = []
        seen_ids = set()
        merged = []
        # Index-derived candidates first: on an exact score tie the candidate
        # with a citable file:line and a named missing control should win over
        # one that has neither.  The scheduler re-ranks everything after this,
        # so position is only a tiebreaker.
        derived, derived_ids = static_candidates(ctx, round_no)
        if derived_ids:
            print("[round-%02d] S2: +%d index-derived candidates (spec §11/§12)"
                  % (round_no, len(derived_ids)))
        for c in derived + fuzz_cands + llm_cands:
            cid = c.get("candidate_id")
            if cid in seen_ids:
                continue
            seen_ids.add(cid)
            merged.append(c)
        # Spec §13: the scheduler decides *which* N, not the merge order.  Fuzz
        # candidates are pinned: they carry runtime evidence (a reproducer and
        # its observations) that no static factor can see, so a static ranking
        # must never be able to displace one in favour of a nicer-looking
        # candidate that has not been executed.
        pinned = [str(c.get("candidate_id")) for c in fuzz_cands
                  if c.get("candidate_id")]
        candidates, schedule_note = schedule_candidates(ctx, round_no, merged,
                                                        pinned=pinned)
        if not candidates:
            late_candidates = try_deferred_inventory("S2")
            if late_candidates:
                merged.extend(late_candidates)
                candidates, late_note = schedule_candidates(
                    ctx, round_no, merged, pinned=pinned)
                schedule_note = "; ".join(
                    item for item in (schedule_note, late_note) if item)
        if not candidates:
            print("[round-%02d] no candidates; stopping" % round_no)
            return {"next_candidates": []}
        experiment_plans = _attach_experiment_plans(ctx, round_no, candidates)
        ctx.write_artifact(round_no, "S2", "candidate-matrix.json",
                           {"candidate_count": len(candidates),
                            "schedule_note": schedule_note,
                            "pool_size": len(merged),
                            "pinned": pinned,
                            "experiment_plan_count": len(experiment_plans),
                            "matrix": [
                                dict(
                                    [(k, c.get(k)) for k in (
                                        "candidate_id", "surface", "entry",
                                        "input_shape", "logic", "authz_cases",
                                        "experiment_plan")]
                                    + [("capability_contract",
                                       (c.get("experiment_plan") or {}).get(
                                           "capability_contract") or
                                       capability_contract_from_candidate(c)),
                                       ("variant_fixture_plan",
                                        (c.get("experiment_plan") or {}).get(
                                            "variant_fixture_plan", {})),
                                       ("comparison_contract",
                                        (c.get("experiment_plan") or {}).get(
                                            "comparison_contract", {})),
                                       ("consistency_action",
                                        (c.get("experiment_plan") or {}).get(
                                            "consistency_action", {}))]
                                )
                                for c in candidates
                            ]})
        store.save_stage("S2", {"candidates": candidates})

    report = timebox_report("S2", "S3")
    if report:
        return {**report, "next_candidates": []}

    # ---- S3: static audit (resumable) ---------------------------------
    s3 = store.load_stage("S3")
    if s3 and not force:
        audits = s3["audits"]
        print("[round-%02d] S3 resume: %d audit notes loaded" % (round_no, len(audits)))
    else:
        print("[round-%02d] S3: auditing %d candidates (LLM)..." % (round_no, len(candidates)))
        audits = {}
        for candidate in candidates:
            report = timebox_report("S3", "S3-candidate:%s" %
                                    candidate.get("candidate_id", "unknown"))
            if report:
                ctx.write_artifact(round_no, "S3", "audit-notes.partial.json", audits)
                return {**report, "next_candidates": []}
            audits[candidate["candidate_id"]] = (
                _fuzz_audit(candidate) if candidate.get("fuzz_spec")
                else audit_candidate(ctx, candidate))
        ctx.write_artifact(round_no, "S3", "audit-notes.json", audits)
        store.save_stage("S3", {"audits": audits})
    for candidate in candidates:
        audit = audits.get(candidate["candidate_id"], {})
        if not candidate.get("source_to_sink"):
            candidate["source_to_sink"] = audit.get("source_to_sink") or match_source_sink_paths(
                getattr(ctx, "_source_sink_graph", []), candidate)
    ctx.write_artifact(round_no, "S3", "residuals.json", [
        dict(residual, candidate_id=candidate["candidate_id"])
        for candidate in candidates for residual in (candidate.get("residuals") or [])
        if isinstance(residual, dict)
    ])
    report = timebox_report("S3", "S4")
    if report:
        return {**report, "next_candidates": []}

    # ---- S4: PoC + matrix (resumable, rows serialized w/o spec) -------
    s4 = store.load_stage("S4")
    s4_fresh = bool(
        s4 and s4.get("evidence_policy_version") == S4_EVIDENCE_POLICY_VERSION)
    invalidate_after_s4 = force or not s4_fresh
    if s4 and not s4_fresh:
        print("[round-%02d] S4 checkpoint predates %s; recomputing S4-S8" % (
            round_no, S4_EVIDENCE_POLICY_VERSION))
    report = timebox_report("S3", "S4")
    if report:
        return {**report, "next_candidates": []}
    if s4 and s4_fresh and not force:
        rows = s4["rows"]
        excluded = s4["excluded"]
        print("[round-%02d] S4 resume: %d confirmed / %d excluded"
              % (round_no, len(rows), len(excluded)))
    else:
        # Baseline fix #1 (spawn-like parallelism): candidates are verified in
        # independent workers (each candidate has its own PoC dir, matrix dir
        # and approval log). LLM usage accounting stays approximate under
        # concurrency (call/token counters may lag by a race window).
        from concurrent.futures import ThreadPoolExecutor, as_completed
        print("[round-%02d] S4: generating PoCs and running matrix "
              "(parallel workers)..." % round_no)
        round_remaining = max(1, int(round_budget_snapshot(
            ctx._round_budget_record)["remaining_seconds"]))
        ctx.s4_execution_budget = S4ExecutionBudget(
            min(getattr(ctx.cfg, "s4_timeout_seconds", 5400), round_remaining),
            min(getattr(ctx.cfg, "s4_candidate_timeout_seconds", 900),
                round_remaining))
        rows = []
        excluded = []
        max_workers = min(4, max(1, len(candidates)))
        futures = {}
        processed_ids = set()

        def record_candidate_row(cand: Dict[str, Any], row: Dict[str, Any]) -> None:
            processed_ids.add(str(cand["candidate_id"]))
            if is_confirmed_conclusion(row.get("conclusion")):
                rows.append(row)
            else:
                excluded.append({
                    "candidate_id": cand["candidate_id"],
                    "surface": cand.get("surface"),
                    "conclusion": row.get("conclusion", "待验证"),
                    "evidence": row.get("summary", {}),
                    "runtime_lab": row.get("runtime_lab"),
                })
            print("  %s -> %s" % (
                cand["candidate_id"], row.get("conclusion", "待验证")))

        try:
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {
                    pool.submit(verify_candidate, ctx, round_no, cand,
                                audits[cand["candidate_id"]]): cand
                    for cand in candidates
                }
                for fut in as_completed(futures):
                    cand = futures[fut]
                    try:
                        row = fut.result()
                    except BudgetExceeded:
                        for pending in futures:
                            if pending is not fut:
                                pending.cancel()
                        stop_requests = getattr(ctx.llm, "set_timeout_provider", None)
                        if callable(stop_requests):
                            stop_requests(lambda: 0.0)
                        raise
                    except Exception as exc:
                        persisted_cells, convergence = converge_s4_cells(
                            ctx.root, ctx.cfg.name, round_no,
                            cand["candidate_id"], [])
                        failed_summary = summarize_candidate(persisted_cells)
                        failed_summary["harness_error"] = "%s: %s" % (
                            type(exc).__name__, exc)
                        failed_summary["s4_result_sources"] = convergence["sources"]
                        row = {"candidate": cand,
                               "audit": audits[cand["candidate_id"]],
                               "summary": failed_summary,
                               "conclusion": "候选（待验证）"}
                    record_candidate_row(cand, row)
        except BudgetExceeded as exc:
            # The executor has now joined already-running workers. Preserve
            # their finished results before the outer loop records the stop.
            for fut, cand in futures.items():
                cid = str(cand.get("candidate_id", ""))
                if cid in processed_ids or fut.cancelled() or not fut.done():
                    continue
                try:
                    record_candidate_row(cand, fut.result())
                except Exception:
                    continue
            partial_rows = []
            for row in rows:
                saved = dict(row)
                saved.pop("spec", None)
                partial_rows.append(saved)
            partial = {
                "status": "partial-llm-budget-exhausted",
                "reason": str(exc),
                "completed_candidate_ids": sorted(processed_ids),
                "pending_candidate_ids": sorted(
                    str(c.get("candidate_id")) for c in candidates
                    if str(c.get("candidate_id")) not in processed_ids),
                "rows": partial_rows, "excluded": excluded,
                "execution_budget": ctx.s4_execution_budget.snapshot(),
                "claim_status": "not-a-finding",
            }
            ctx.write_artifact(round_no, "S4", "partial-results.json", partial)
            ctx.write_artifact(round_no, "S4", "execution-budget.json",
                               partial["execution_budget"])
            raise
        serializable = []
        for r in rows:
            rr = dict(r)
            rr.pop("spec", None)   # POCSpec is not JSON-serializable
            serializable.append(rr)
        execution_budget = ctx.s4_execution_budget.snapshot()
        store.save_stage("S4", {
            "rows": serializable,
            "excluded": excluded,
            "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION,
            "execution_budget": execution_budget,
        })
        ctx.write_artifact(round_no, "S4", "execution-budget.json",
                           execution_budget)
        ctx.write_artifact(round_no, "S4", "authz-matrix.json", [
            {
                "candidate_id": r["candidate"]["candidate_id"],
                "authz_results": (r.get("summary") or {}).get("authz_results", []),
            }
            for r in rows if (r.get("summary") or {}).get("authz_results")
        ])
    lab_artifacts = [
        row.get("runtime_lab") for row in rows + excluded
        if isinstance(row.get("runtime_lab"), dict)
    ]
    ctx.write_artifact(
        round_no, "S4", "runtime-lab.json",
        merge_runtime_lab_artifacts(lab_artifacts, scope="autonomous-s4"))
    s4_summaries = {
        str(row.get("candidate", {}).get("candidate_id")): row.get("summary", {})
        for row in rows if isinstance(row, dict)
        and isinstance(row.get("candidate"), dict)
    }
    for item in excluded:
        cid = str(item.get("candidate_id", ""))
        if cid:
            s4_summaries.setdefault(cid, item.get("evidence", {}))
    ctx.write_artifact(
        round_no, "S4", "residual-closure.json",
        build_residual_closure_report(candidates, s4_summaries, round_no))

    budget_snapshot = (
        ctx.s4_execution_budget.snapshot()
        if getattr(ctx, "s4_execution_budget", None)
        else (s4.get("execution_budget", {}) if isinstance(s4, dict) else {}))
    if budget_snapshot:
        ctx.write_artifact(round_no, "S4", "execution-budget.json",
                           budget_snapshot)
    if budget_snapshot.get("round_exhausted"):
        progress = {
            "status": "stopped-at-s4-timebox",
            "execution_budget": budget_snapshot,
            "completed_candidates": [
                {"candidate_id": row.get("candidate", {}).get("candidate_id"),
                 "conclusion": row.get("conclusion"),
                 "execution_state": (row.get("summary") or {}).get(
                     "execution_state"),
                 "cells_ran": (row.get("summary") or {}).get("cells_ran", 0)}
                for row in rows
            ],
            "pending_candidates": [
                {"candidate_id": row.get("candidate_id"),
                 "conclusion": row.get("conclusion"),
                 "execution_state": (row.get("evidence") or {}).get(
                     "execution_state"),
                 "cells_ran": (row.get("evidence") or {}).get("cells_ran", 0)}
                for row in excluded
            ],
            "claim_status": "not-a-finding",
        }
        ctx.write_artifact(round_no, "S4", "round-timebox-report.json", progress)
        print("[round-%02d] S4 wall-clock limit reached; preserving artifacts and ending round" % round_no)
        return {"next_candidates": [], "status": "s4-timebox-exhausted",
                "execution_budget": budget_snapshot}

    report = timebox_report("S4", "S5")
    if report:
        return {**report, "next_candidates": []}
    deferred_index_candidates = try_deferred_inventory("S4")
    current_candidate_ids = {str(candidate.get("candidate_id"))
                             for candidate in candidates}
    deferred_index_candidates = [candidate for candidate in deferred_index_candidates
                                 if str(candidate.get("candidate_id"))
                                 not in current_candidate_ids]

    # ---- S5: Novelty (resumable) --------------------------------------
    s5 = store.load_stage("S5")
    if s5 and not force and not invalidate_after_s4:
        novelties = s5["novelty"]
        print("[round-%02d] S5 resume: %d novelty records loaded" % (round_no, len(novelties)))
    else:
        print("[round-%02d] S5: Novelty live scan + judgment..." % round_no)
        for row in rows:
            row["novelty_check"] = novelty_check(ctx, row)
        novelties = {r["candidate"]["candidate_id"]: r["novelty_check"] for r in rows}
        store.save_stage("S5", {"novelty": novelties})
    ctx.write_artifact(round_no, "S5", "novelty.json", novelties)
    report = timebox_report("S5", "S6")
    if report:
        return {**report, "next_candidates": []}

    # ---- S6: CVSS + G5 consistency gate (resumable) -------------------
    s6 = store.load_stage("S6")
    if s6 and not force and not invalidate_after_s4:
        print("[round-%02d] S6 resume: severity records loaded" % round_no)
    else:
        print("[round-%02d] S6: CVSS + severity..." % round_no)
        blocked_rows = []
        for row in rows:
            tier = row["candidate"].get("precondition_tier_hint", "single-feature")
            vector = row["candidate"].get("cvss_vector") or cvss_for_tier(tier)
            score, severity = base_score(vector)
            g5_ok, g5_reason = check_precondition_consistency(tier, vector)
            impact_ok, impact_reason = check_impact_consistency(
                row["candidate"], row.get("summary", {}), vector)
            if not impact_ok:
                g5_ok = False
                g5_reason = g5_reason + "; " + impact_reason
            row["cvss"] = {"vector": vector, "score": score,
                           "severity": severity, "tier": tier,
                           "g5": {"passed": g5_ok, "reason": g5_reason}}
            if not g5_ok:
                # Hard discipline: an inconsistent CVSS-precondition pairing
                # cannot confirm; withhold the verdict for human calibration.
                row["conclusion"] = "候选（待验证）"
                row["g5_blocked"] = True
                blocked_rows.append(row)
                excluded.append({
                    "candidate_id": row["candidate"]["candidate_id"],
                    "surface": row["candidate"].get("surface"),
                    "conclusion": "候选（待验证）G5: " + g5_reason,
                    "evidence": row.get("summary", {}),
                })
        if blocked_rows:
            rows = [r for r in rows if r not in blocked_rows]
        store.save_stage("S6", {"severity": {
            r["candidate"]["candidate_id"]: r["cvss"] for r in rows}})
    ctx.write_artifact(round_no, "S6", "severity.json",
                       {r["candidate"]["candidate_id"]: r["cvss"] for r in rows})
    report = timebox_report("S6", "S7")
    if report:
        return {**report, "next_candidates": []}

    # ---- S7: finding docs (resumable) ---------------------------------
    s7 = store.load_stage("S7")
    if s7 and not force and not invalidate_after_s4:
        print("[round-%02d] S7 resume: finding docs already written" % round_no)
    else:
        print("[round-%02d] S7: finding documents (local only)..." % round_no)
        reports_dir = ctx.root / "reports" / ctx.cfg.name / ("round-%02d" % round_no)
        reports_dir.mkdir(parents=True, exist_ok=True)
        prior_s7 = s7 if isinstance(s7, dict) else {}
        prior_docs = {str(name) for name in prior_s7.get("finding_docs", [])
                      if isinstance(name, str) and Path(name).name == name}
        written = []
        idx = 0
        for row in rows:
            if not is_confirmed_conclusion(row.get("conclusion")):
                continue
            idx += 1
            cand = row["candidate"]
            summary = row.get("summary") or {}
            finding = {
                "title": cand.get("surface", cand["candidate_id"]),
                "date": ctx.cfg.discovery_date,
                "status": "确认（机制级，受控验证）",
                "summary": cand.get("hypothesis", ""),
                "entrypoint": cand.get("entry", ""),
                "affected_versions": cand.get("affected_versions") or [
                    str(j.get("version")) for j in ctx.cfg.jars if j.get("version")],
                "fixed_versions": cand.get("fixed_versions", []),
                "source_to_sink": cand.get("source_to_sink", []),
                "code_location": cand.get("code_location", []),
                "scope": ctx.cfg.scope_constraints,
                "repro": _repro_text(row),
                "evidence": _evidence_text(row),
                "preconditions": cand.get("preconditions") or ["无"],
                "authorization_matrix": (row.get("summary") or {}).get("authz_results", []),
                "negative_results": cand.get("negative_results") or summary.get("validation_issues", []),
                "novelty": (row.get("novelty_check") or {}).get("novelty", {}),
                "cvss": row.get("cvss", {}),
                "impact": [
                    {"tier": "机制", "impact": cand.get("logic", "")},
                    {"tier": "端到端（条件部分）", "impact": "受控 harness 验证；未做武器化。"},
                ],
                "boundary": "回环/受控 JVM；PoC 由 LLM 生成后经编译与实跑验证。",
                "timeline": [
                    {"date": ctx.cfg.discovery_date, "event": "自治轮次验证（修复公开前不披露）"},
                ],
            }
            fname = ("finding-%02d-%s.md" % (idx, cand["candidate_id"])
                     if ctx.cfg.output_lang == "en"
                     else "挖洞-发现-%02d-%s.md" % (idx, cand["candidate_id"]))
            (reports_dir / fname).write_text(
                render_finding_md(finding, lang=ctx.cfg.output_lang), encoding="utf-8")
            written.append(fname)
        stale_docs = sorted(prior_docs - set(written))
        stale_marker = ("> 状态更新：该报告来自旧版 S4 证据策略，本轮未能重新确认。"
                        "请以本轮 S8 Ledger 为准。\n\n")
        for name in stale_docs:
            path = reports_dir / name
            if path.is_file():
                old = path.read_text(encoding="utf-8", errors="replace")
                if stale_marker not in old:
                    path.write_text(stale_marker + old, encoding="utf-8")
        if stale_docs:
            ctx.write_artifact(round_no, "S7", "superseded-finding-docs.json", {
                "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION,
                "files": stale_docs,
                "reason": "S4-S8 checkpoints were recomputed after the evidence-policy change",
            })
        store.save_stage("S7", {
            "finding_docs": written,
            "superseded_docs": stale_docs,
            "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION,
        })

    report = timebox_report("S7", "S8")
    if report:
        return {**report, "next_candidates": []}

    # ---- S8: ledger (resumable) ---------------------------------------
    # Build the research-memory delta before the resumable ledger branch.  On
    # resume this remains idempotent, while an interrupted S8 still leaves the
    # runtime feedback available to the next scheduling round.
    runtime_lab = {}
    runtime_lab_path = (ctx.root / "state" / ctx.cfg.name
                        / ("round-%02d" % round_no) / "S4" / "runtime-lab.json")
    if runtime_lab_path.exists():
        try:
            loaded_lab = json.loads(runtime_lab_path.read_text(encoding="utf-8"))
            if isinstance(loaded_lab, dict):
                runtime_lab = loaded_lab
        except (OSError, ValueError, TypeError):
            runtime_lab = {}
    prior_consistency_actions = load_research_consistency_actions(
        ctx.root, ctx.cfg.name)
    research_consistency_rechecks = build_research_consistency_rechecks(
        runtime_lab, prior_consistency_actions)
    research_consistency_rechecks_file = write_research_consistency_rechecks(
        ctx.root, ctx.cfg.name, research_consistency_rechecks)
    memory_summaries = {
        str(row.get("candidate", {}).get("candidate_id")): row.get("summary", {})
        for row in rows if isinstance(row, dict) and isinstance(row.get("candidate"), dict)
    }
    memory_conclusions = {
        str(row.get("candidate", {}).get("candidate_id")): row.get("conclusion", "")
        for row in rows if isinstance(row, dict) and isinstance(row.get("candidate"), dict)
    }
    for item in excluded:
        cid = str(item.get("candidate_id", ""))
        if cid:
            memory_summaries.setdefault(cid, item.get("evidence", {}))
            memory_conclusions.setdefault(cid, item.get("conclusion", ""))
    from ..evaluation.replay_calibration import (
        build_replay_calibration, load_replay_calibration,
        write_replay_calibration,
    )
    from ..evaluation.replay_cohort import (
        select_effective_replay_calibration,
    )
    from ..evaluation.replay_pack import (
        build_replay_pack, write_replay_pack,
    )
    prior_replay_calibration = load_replay_calibration(
        ctx.root, ctx.cfg.name)
    replay_cohort = ctx.replay_cohort_calibration()
    effective_replay_calibration = select_effective_replay_calibration(
        prior_replay_calibration, replay_cohort)
    memory_delta = build_round_memory(
        candidates, memory_summaries, memory_conclusions, runtime_lab, round_no,
        target_type=ctx.cfg.target_type)
    memory = merge_research_memory(
        load_research_memory(ctx.root, ctx.cfg.name), memory_delta)
    memory_file = write_research_memory(ctx.root, ctx.cfg.name, memory)
    review_feedback = load_review_feedback(ctx.root, ctx.cfg.name)
    research_consistency = build_research_consistency(memory)
    research_consistency_file = write_research_consistency(
        ctx.root, ctx.cfg.name, research_consistency)
    research_consistency_actions = build_research_consistency_actions(
        research_consistency)
    research_consistency_actions_file = write_research_consistency_actions(
        ctx.root, ctx.cfg.name, research_consistency_actions)
    portfolio = build_research_portfolio(
        memory, review_feedback, ctx.benchmark_feedback(),
        research_consistency, research_consistency_actions,
        research_consistency_rechecks)
    portfolio_file = write_research_portfolio(ctx.root, ctx.cfg.name, portfolio)
    strategy = load_research_strategy(ctx.root, ctx.cfg.name)
    if not strategy:
        s2_strategy_path = (ctx.root / "state" / ctx.cfg.name
                            / ("round-%02d" % round_no) / "S2"
                            / "research-strategy.json")
        try:
            loaded_strategy = json.loads(
                s2_strategy_path.read_text(encoding="utf-8"))
            strategy = loaded_strategy if isinstance(loaded_strategy, dict) else {}
        except (OSError, ValueError, TypeError):
            strategy = {}
    strategy_feedback = {}
    research_guidance = {}
    strategy_file = None
    guidance_file = None
    if strategy:
        strategy, strategy_feedback = apply_strategy_observations(
            strategy, candidates, memory_summaries, round_no)
        strategy, research_guidance = apply_research_guidance(
            strategy, portfolio, review_feedback, round_no,
            replay_calibration=effective_replay_calibration)
        if strategy:
            strategy_file = write_research_strategy(
                ctx.root, ctx.cfg.name, strategy)
            guidance_file = write_research_guidance(
                ctx.root, ctx.cfg.name, research_guidance)
            ctx.write_artifact(round_no, "S8", "research-strategy.json", strategy)
            ctx.write_artifact(
                round_no, "S8", "research-strategy-feedback.json",
                strategy_feedback)
            ctx.write_artifact(
                round_no, "S8", "research-guidance.json", research_guidance)
    # Measure the agenda that drove this round before replacing it with the
    # next queue.  This is bounded scheduling feedback, not a security verdict.
    prior_research_agenda = load_research_agenda(ctx.root, ctx.cfg.name)
    prior_agenda_outcomes = load_research_agenda_outcomes(
        ctx.root, ctx.cfg.name)
    prior_research_budget = load_research_budget(ctx.root, ctx.cfg.name)
    schedule_snapshot = load_schedule_snapshot(
        ctx.root, ctx.cfg.name, round_no)
    verification_matrix = {}
    verification_path = (ctx.root / "state" / ctx.cfg.name
                         / ("round-%02d" % round_no) / "S4"
                         / "verification-matrix.json")
    try:
        loaded_verification = json.loads(
            verification_path.read_text(encoding="utf-8"))
        verification_matrix = (loaded_verification
                               if isinstance(loaded_verification, dict) else {})
    except (OSError, ValueError, TypeError):
        verification_matrix = {}
    research_agenda_outcomes = build_research_agenda_outcomes(
        prior_research_agenda, schedule_snapshot, verification_matrix,
        runtime_lab, strategy_feedback,
        prior_outcomes=prior_agenda_outcomes,
        target=ctx.cfg.name, round_no=round_no)
    research_agenda_outcomes_file = write_research_agenda_outcomes(
        ctx.root, ctx.cfg.name, research_agenda_outcomes)
    ctx.write_artifact(round_no, "S8", "research-agenda-outcomes.json",
                       research_agenda_outcomes)
    research_budget = build_research_budget(
        prior_research_agenda, research_agenda_outcomes,
        prior_budget=prior_research_budget, target=ctx.cfg.name,
        round_no=round_no,
        slots=((prior_research_agenda.get("policy") or {}).get(
            "slots", 0) if prior_research_agenda else 0) or 8)
    research_budget_file = write_research_budget(
        ctx.root, ctx.cfg.name, research_budget)
    ctx.write_artifact(round_no, "S8", "research-budget.json", research_budget)
    research_agenda = build_research_agenda(
        strategy, portfolio, target=ctx.cfg.name, round_no=round_no,
        outcomes=research_agenda_outcomes, budget_policy=research_budget)
    research_agenda_file = write_research_agenda(
        ctx.root, ctx.cfg.name, research_agenda)
    ctx.write_artifact(round_no, "S8", "research-agenda.json", research_agenda)
    replay_calibration = build_replay_calibration(ctx.root, ctx.cfg.name)
    replay_calibration_file = write_replay_calibration(
        ctx.root, ctx.cfg.name, replay_calibration)
    ctx.write_artifact(round_no, "S8", "research-replay-calibration.json",
                       replay_calibration)
    if replay_cohort:
        ctx.write_artifact(round_no, "S8", "research-replay-cohort.json",
                           replay_cohort)
    ctx.write_artifact(round_no, "S8", "research-memory.json", memory_delta)
    ctx.write_artifact(round_no, "S8", "research-memory-summary.json", memory["summary"])
    ctx.write_artifact(round_no, "S8", "review-feedback.json", review_feedback)
    ctx.write_artifact(
        round_no, "S8", "research-consistency.json", research_consistency)
    ctx.write_artifact(
        round_no, "S8", "research-consistency-actions.json",
        research_consistency_actions)
    ctx.write_artifact(
        round_no, "S8", "research-consistency-rechecks.json",
        research_consistency_rechecks)
    ctx.write_artifact(round_no, "S8", "research-portfolio.json", portfolio)
    replay_pack = build_replay_pack(ctx.root, ctx.cfg.name)
    replay_pack_file = write_replay_pack(
        ctx.root, ctx.cfg.name, replay_pack)
    ctx.write_artifact(round_no, "S8", "research-replay-pack.json", replay_pack)
    research_memory_info = {
        "artifact": str(memory_file.relative_to(ctx.root.resolve())),
        "round_entries": len(memory_delta.get("entries", [])),
        "total_entries": len(memory.get("entries", [])),
        "states": memory.get("summary", {}).get("states", {}),
        "claim_status": "not-a-finding",
    }
    review_feedback_info = {
        "artifact": "state/%s/review-feedback.json" % ctx.cfg.name,
        "count": review_feedback.get("summary", {}).get("feedback_count", 0),
        "statuses": review_feedback.get("summary", {}).get("statuses", {}),
        "claim_status": "not-a-finding",
    }
    research_portfolio_info = {
        "artifact": str(portfolio_file.relative_to(ctx.root.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-portfolio.json"
                          % (ctx.cfg.name, round_no),
        "mechanism_count": portfolio.get("summary", {}).get("mechanism_count", 0),
        "unresolved_mechanisms": portfolio.get("summary", {}).get(
            "unresolved_mechanisms", 0),
        "next_probe_count": len(portfolio.get("next_probes") or []),
        "surface_lane_coverage": (portfolio.get("surface_lane_coverage") or {}
                                  ).get("summary", {}),
        "claim_status": "not-a-finding",
    }
    research_consistency_info = {
        "artifact": str(research_consistency_file.relative_to(ctx.root.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-consistency.json"
                          % (ctx.cfg.name, round_no),
        "status_counts": (research_consistency.get("summary") or {}
                           ).get("statuses", {}),
        "conflicted_entries": (research_consistency.get("summary") or {}
                               ).get("conflicted_entries", 0),
        "unstable_entries": (research_consistency.get("summary") or {}
                             ).get("unstable_entries", 0),
        "claim_status": "not-a-finding",
    }
    research_consistency_actions_info = {
        "artifact": str(research_consistency_actions_file.relative_to(
            ctx.root.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-consistency-actions.json"
                          % (ctx.cfg.name, round_no),
        "action_count": (research_consistency_actions.get("summary") or {}
                          ).get("action_count", 0),
        "action_counts": (research_consistency_actions.get("summary") or {}
                           ).get("action_counts", {}),
        "claim_status": "not-a-finding",
    }
    research_consistency_rechecks_info = {
        "artifact": str(research_consistency_rechecks_file.relative_to(
            ctx.root.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-consistency-rechecks.json"
                          % (ctx.cfg.name, round_no),
        "status_counts": {
            key: value for key, value in
            (research_consistency_rechecks.get("summary") or {}).items()
            if key in {"observed", "partial", "environment_gap",
                       "not_executed"}
        },
        "claim_status": "not-a-finding",
    }
    research_agenda_info = {
        "artifact": str(research_agenda_file.relative_to(
            ctx.root.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-agenda.json"
                          % (ctx.cfg.name, round_no),
        "selected_count": (research_agenda.get("summary") or {}).get(
            "selected_count", 0),
        "deferred_count": (research_agenda.get("summary") or {}).get(
            "deferred_count", 0),
        "surface_counts": (research_agenda.get("summary") or {}).get(
            "surface_counts", {}),
        "claim_status": "not-a-finding",
    }
    research_agenda_outcomes_info = {
        "artifact": str(research_agenda_outcomes_file.relative_to(
            ctx.root.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-agenda-outcomes.json"
                          % (ctx.cfg.name, round_no),
        "selected_count": (research_agenda_outcomes.get("summary") or {}
                            ).get("selected_count", 0),
        "productive_selected_count": (research_agenda_outcomes.get(
            "summary") or {}).get("productive_selected_count", 0),
        "selected_yield": (research_agenda_outcomes.get("summary") or {}
                           ).get("selected_yield"),
        "outcome_counts": (research_agenda_outcomes.get("summary") or {}
                            ).get("outcome_counts", {}),
        "claim_status": "not-a-finding",
    }
    research_budget_info = {
        "artifact": str(research_budget_file.relative_to(
            ctx.root.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-budget.json"
                          % (ctx.cfg.name, round_no),
        "surface_count": (research_budget.get("summary") or {}).get(
            "surface_count", 0),
        "recommendation_counts": (research_budget.get("summary") or {}
                                   ).get("recommendation_counts", {}),
        "claim_status": "not-a-finding",
    }
    research_replay_calibration_info = {
        "artifact": str(replay_calibration_file.relative_to(ctx.root.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-replay-calibration.json"
                          % (ctx.cfg.name, round_no),
        "status": replay_calibration.get("status", "no-data"),
        "replayed_guidance_items": replay_calibration.get(
            "metrics", {}).get("replayed_guidance_items", 0),
        "replacement_hit_rate": replay_calibration.get(
            "metrics", {}).get("replacement_hit_rate"),
        "claim_status": "not-a-finding",
    }
    research_replay_pack_info = {
        "artifact": str(replay_pack_file.relative_to(ctx.root.resolve())),
        "round_artifact": "state/%s/round-%02d/S8/research-replay-pack.json"
                          % (ctx.cfg.name, round_no),
        "status": (replay_pack.get("provenance") or {}).get(
            "status", "not-executed"),
        "valid_for_cohort": (replay_pack.get("provenance") or {}).get(
            "valid_for_cohort", False),
        "pack_digest": replay_pack.get("pack_digest", ""),
        "claim_status": "not-a-finding",
    }
    research_replay_cohort_info = {
        "claim_status": "not-a-finding",
    }
    if replay_cohort:
        research_replay_cohort_info = {
            "artifact": "configured:replay_cohort_calibration_path",
            "round_artifact": "state/%s/round-%02d/S8/research-replay-cohort.json"
                              % (ctx.cfg.name, round_no),
            "status": replay_cohort.get("status", "no-data"),
            "eligible_projects": replay_cohort.get("metrics", {}).get(
                "eligible_projects", 0),
            "policy_threshold": replay_cohort.get("policy", {}).get(
                "replacement_zero_gain_rounds", 1),
            "claim_status": "not-a-finding",
        }
    research_strategy_info = {
        "claim_status": "not-a-finding",
    }
    if strategy_file:
        research_strategy_info = {
            "artifact": str(strategy_file.relative_to(ctx.root.resolve())),
            "round_artifact": "state/%s/round-%02d/S8/research-strategy.json"
                              % (ctx.cfg.name, round_no),
            "feedback_artifact": "state/%s/round-%02d/S8/research-strategy-feedback.json"
                                % (ctx.cfg.name, round_no),
            "guidance_artifact": (str(guidance_file.relative_to(
                ctx.root.resolve())) if guidance_file else
                "state/%s/coverage/research-guidance.json" % ctx.cfg.name),
            "guidance_round_artifact": "state/%s/round-%02d/S8/research-guidance.json"
                                      % (ctx.cfg.name, round_no),
            "observed_items": strategy.get("summary", {}).get(
                "observed_items", 0),
            "information_gain": strategy_feedback.get("summary", {}).get(
                "information_gain", 0),
            "next_actions": research_guidance.get("summary", {}).get(
                "action_counts", {}),
            "replacement_recommendations": research_guidance.get(
                "summary", {}).get("replacement_recommendations", 0),
            "claim_status": "not-a-finding",
        }
    s8 = store.load_stage("S8")
    if s8 and not force and not invalidate_after_s4:
        print("[round-%02d] S8 resume: ledger already written" % round_no)
    else:
        print("[round-%02d] S8: ledger..." % round_no)
        ledger_rows = [{
            "candidate_id": r["candidate"]["candidate_id"],
            "surface": r["candidate"].get("surface"),
            "conclusion": r.get("conclusion", "确认"),
            "status": conclusion_status(r.get("conclusion", "确认")),
            "evidence": _evidence_lines(r),
            "precondition_tier": r["candidate"].get("precondition_tier_hint"),
            "code_location": r.get("audit", {}).get("code_location", []),
            "novelty": r.get("novelty_check", {}).get("novelty", {}),
            "cvss": r.get("cvss", {}),
        } for r in rows]
        summary = {
            "header_note": "自治轮次：候选/PoC/审计由 LLM 生成，矩阵与结论由运行时观测推导",
            "metrics": {
                "候选数": len(candidates),
                "确认数": len(rows),
                "排除数": len(excluded),
                "LLM 调用": ctx.llm.usage.calls,
                "LLM tokens": ctx.llm.usage.total_tokens,
            },
            "next_round": [],
            "research_memory": research_memory_info,
            "research_consistency": research_consistency_info,
            "research_consistency_actions": research_consistency_actions_info,
            "research_consistency_rechecks": research_consistency_rechecks_info,
            "research_agenda": research_agenda_info,
            "research_agenda_outcomes": research_agenda_outcomes_info,
            "research_budget": research_budget_info,
            "review_feedback": review_feedback_info,
            "research_portfolio": research_portfolio_info,
            "research_replay_calibration": research_replay_calibration_info,
            "research_replay_pack": research_replay_pack_info,
            "research_replay_cohort": research_replay_cohort_info,
            "research_strategy": research_strategy_info,
        }
        by_candidate_memory = {
            str(entry.get("candidate_id")): entry
            for entry in memory_delta.get("entries", [])
        }
        for row in ledger_rows:
            entry = by_candidate_memory.get(str(row.get("candidate_id")))
            if entry:
                row["research"] = {
                    "research_key": entry.get("research_key", ""),
                    "states": sorted({str(event.get("state")) for event in
                                       entry.get("events", []) if event.get("state")}),
                    "claim_status": "not-a-finding",
                }
        write_round_artifacts(ctx.root, ctx.cfg.name, round_no, ledger_rows, excluded,
                              summary, lang=ctx.cfg.output_lang)
        ctx.write_artifact(round_no, "S8", "llm-usage.json", ctx.llm.usage.to_dict())
        store.save_stage("S8", {"ledger_rows": len(ledger_rows), "excluded": len(excluded),
                                "research_memory": research_memory_info,
                                "research_consistency": research_consistency_info,
                                "research_consistency_actions":
                                research_consistency_actions_info,
                                "research_consistency_rechecks":
                                research_consistency_rechecks_info,
                                "research_agenda": research_agenda_info,
                                "research_agenda_outcomes":
                                research_agenda_outcomes_info,
                                "research_budget": research_budget_info,
                                "review_feedback": review_feedback_info,
                                "research_portfolio": research_portfolio_info,
                                "research_replay_calibration":
                                research_replay_calibration_info,
                                "research_replay_pack":
                                research_replay_pack_info,
                                "research_replay_cohort":
                                research_replay_cohort_info,
                                "research_strategy": research_strategy_info})
    print("[round-%02d] done: 确认=%d 排除=%d" % (round_no, len(rows), len(excluded)))
    report = timebox_report("S8", "next-round-candidate-generation")
    if report:
        return {**report, "next_candidates": []}
    final_budget = round_budget_snapshot(ctx._round_budget_record)
    ctx.write_artifact(round_no, "S0", "execution-budget-status.json", final_budget)
    next_candidates = (
        _propose_next(ctx, candidates, rows)
        if final_budget["remaining_seconds"] >= 120 else [])
    next_ids = {str(candidate.get("candidate_id")) for candidate in next_candidates}
    for candidate in deferred_index_candidates:
        candidate_id = str(candidate.get("candidate_id", ""))
        if candidate_id and candidate_id not in next_ids:
            next_candidates.append(candidate)
            next_ids.add(candidate_id)
    if deferred_index_candidates:
        ctx.write_artifact(round_no, "S4", "deferred-candidates-for-next-round.json",
                           deferred_index_candidates)
    return {"next_candidates": next_candidates,
            "audit_budget": final_budget,
            "deferred_index_candidate_count": len(deferred_index_candidates),
            "research_memory": research_memory_info,
            "research_consistency": research_consistency_info,
            "research_consistency_actions": research_consistency_actions_info,
            "research_consistency_rechecks": research_consistency_rechecks_info,
            "research_agenda": research_agenda_info,
            "research_agenda_outcomes": research_agenda_outcomes_info,
            "research_budget": research_budget_info,
            "review_feedback": review_feedback_info,
            "research_portfolio": research_portfolio_info,
            "research_replay_calibration": research_replay_calibration_info,
            "research_replay_pack": research_replay_pack_info,
            "research_replay_cohort": research_replay_cohort_info,
            "research_strategy": research_strategy_info}


def _repro_text(row: Dict[str, Any]) -> str:
    cand = row["candidate"]
    spec = row.get("spec")
    if spec is None:
        return "PoC 源码见 poc/%s/round-NN/src/；复现命令见 cells.json" % cand["candidate_id"]
    return "javac -cp <jar> %s.java && java -cp <jar>:out %s" % (
        spec.class_name, spec.class_name)


def _evidence_text(row: Dict[str, Any]) -> str:
    lines = _evidence_lines(row)
    return "\n".join(lines) if lines else "cells.json 见 state/<target>/round-NN/S4/matrix-runs/"


def _evidence_lines(row: Dict[str, Any]) -> List[str]:
    s = row.get("summary", {})
    lines = []
    if s.get("harness_error"):
        lines.append("HARNESS_ERROR=" + str(s["harness_error"]))
    if s.get("compile_error"):
        lines.append("COMPILE_ERROR=" + str(s["compile_error"]))
    if s.get("execution_state"):
        lines.append("S4_EXECUTION_STATE=" + str(s["execution_state"]))
    if s.get("s4_result_sources"):
        lines.append("S4_RESULT_SOURCES=" + ",".join(s["s4_result_sources"]))
    for e in s.get("errors", []):
        lines.append("%s SafeMode=%s %s -> ERROR %s"
                     % (e.get("version"), e.get("safe"), e.get("precondition"), e.get("error")))
    for g in s.get("gate_blocked", []):
        lines.append("%s SafeMode=%s %s -> GATE_BLOCKED %s"
                     % (g.get("version"), g.get("safe"), g.get("precondition"), g.get("class")))
    for n in s.get("network_side_effects", []):
        lines.append("NETWORK %s" % n)
    for lk in s.get("leaked", []):
        lines.append("%s SafeMode=%s %s -> LEAKED %s"
                     % (lk.get("version"), lk.get("safe"), lk.get("precondition"),
                        str(lk.get("leaked"))[:120]))
    for c in s.get("safe_equivalent", []):
        lines.append("%s SafeMode=%s %s -> SAFE_EQUIVALENT %s %s" % (
            c.get("version"), c.get("safe"), c.get("precondition"),
            c.get("kind"), c.get("detail", "")))
    for e in s.get("effect_evidence", []):
        lines.append("%s SafeMode=%s %s -> EFFECT_KIND=%s EFFECT=%s" % (
            e.get("version"), e.get("safe"), e.get("precondition"),
            e.get("kind"), e.get("detail", "")))
    for a in s.get("availability_proof", []):
        lines.append("%s SafeMode=%s %s -> AVAILABILITY_PROOF=concurrency:%s service_unavailable:%s" % (
            a.get("version"), a.get("safe"), a.get("precondition"),
            a.get("concurrency"), a.get("service_unavailable")))
    for x in s.get("experiment_evidence", [])[:4]:
        lines.append("%s SafeMode=%s %s -> EXPERIMENT sequence=%s sequence_status=%s "
                     "declared_concurrency=%s probe=%s STEP=%s STATE=%s STEP_EVIDENCE=%s" % (
                         x.get("version"), x.get("safe"), x.get("precondition"),
                         ",".join(str(step) for step in x.get("declared_sequence", [])) or "-",
                         x.get("sequence_status", "unknown"),
                         x.get("declared_concurrency", 1),
                         x.get("declared_availability_probe", False),
                         "|".join(str(step) for step in x.get("step_trace", [])[:8]) or "-",
                         "|".join(str(state) for state in x.get("state_trace", [])[:8]) or "-",
                         "|".join(str(ev) for ev in x.get("step_evidence", [])[:4]) or "-"))
    for a in s.get("authz_results", [])[:8]:
        az = a.get("authz", {})
        lines.append("%s SafeMode=%s %s -> AUTHZ_CASE=%s principal=%s role=%s tenant=%s object=%s assertion=%s boundary_violation=%s" % (
            a.get("version"), a.get("safe"), a.get("precondition"),
            az.get("case_id", "?"), az.get("principal", "?"), az.get("role", "?"),
            az.get("tenant_id", "?"), az.get("object_id", "?"),
            a.get("status", "?"), a.get("boundary_violation", False)))
    for residual in s.get("residual_falsifiers", [])[:8]:
        lines.append("RESIDUAL=%s status=%s falsifier=%s execution=%s effect=%s" % (
            residual.get("residual_id", "?"), residual.get("status", ""),
            residual.get("falsifier_code", ""),
            residual.get("execution_state", ""),
            residual.get("effect_observed", False)))
    for issue in s.get("validation_issues", []):
        lines.append("VALIDATION_ISSUE=" + str(issue))
    if s.get("cells_ran") is not None:
        lines.append("cells_ran=%d" % s["cells_ran"])
    return lines


def _propose_next(ctx: AutoCtx, candidates: List[Dict[str, Any]],
                  rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Iteration: LLM proposes next-round candidates from runtime observations."""
    if not rows:
        return []
    prev = ", ".join(c["candidate_id"] for c in candidates)
    observations = "\n".join(line for r in rows for line in _evidence_lines(r)) or "无运行时观测"
    user = (
        "上一轮候选：%s\n运行时观测：\n%s\n\n"
        "基于这些观测，提出下一轮值得验证的新候选（必须不同于上一轮，且更有攻击价值）。"
        "无新候选则返回 {\"candidates\": []}。字段同上轮。"
        % (prev, observations)
    )
    try:
        data = ctx.llm.ask_json(_sec_prompt(ctx), user, max_tokens=3000)
        return (data.get("candidates") or [])[: ctx.max_candidates]
    except BudgetExceeded:
        return []
    except ValueError:
        return []


def run_loop(ctx: AutoCtx, start_round: int) -> List[Dict[str, Any]]:
    from ..analysis.languages import SourceScanTimeout

    rounds_done = []
    for r in range(start_round, start_round + ctx.max_rounds):
        ctx._active_audit_guard_registered = False
        if ctx.stop_file.exists():
            print("STOP flag found; stopping")
            break
        round_status = "failed"
        try:
            result = run_round(ctx, r)
            round_status = str(result.get("status") or "completed")
        except BudgetExceeded as exc:
            round_status = "budget-exhausted"
            record = getattr(ctx, "_round_budget_record", None)
            budget_status: Dict[str, Any] = {}
            if isinstance(record, dict):
                try:
                    from ..analysis.audit_budget import round_budget_snapshot
                    budget_status = round_budget_snapshot(record)
                    ctx.write_artifact(
                        r, "S0", "execution-budget-status.json", budget_status)
                except (OSError, TypeError, ValueError) as status_exc:
                    budget_status = {"status": "unavailable",
                                     "error": str(status_exc)}
            try:
                from ..memory.state import CheckpointStore
                completed_stages = CheckpointStore(
                    ctx.root, ctx.cfg.name, r).completed_stages()
            except (OSError, TypeError, ValueError):
                completed_stages = []
            usage = ctx.llm.usage.to_dict()
            status = ("stopped-at-round-deadline"
                      if budget_status.get("expired")
                      else "stopped-llm-budget-exhausted")
            progress = {
                "status": status, "error": str(exc),
                "completed_stages": completed_stages,
                "audit_budget": budget_status,
                "llm_usage": usage,
                "claim_status": "not-a-finding",
            }
            ctx.write_artifact(r, "S0", "round-stop-report.json", progress)
            ctx.write_artifact(r, "S0", "llm-usage.json", usage)
            print("budget exhausted; saved S0 progress for round %02d (%s)" % (
                r, status))
            rounds_done.append({"round": r, **progress})
            break
        except SourceScanTimeout as exc:
            round_status = "source-scan-incomplete"
            progress = {
                "status": "stopped-source-scan-incomplete",
                "error": str(exc), "progress": exc.progress,
                "claim_status": "not-a-finding",
            }
            ctx.write_artifact(r, "S0", "source-scan-timeout.json", progress)
            print("source scan timed out; saved progress and stopped this round")
            rounds_done.append({"round": r, **progress})
            break
        except Exception as exc:
            round_status = "failed"
            record = getattr(ctx, "_round_budget_record", None)
            budget_status: Dict[str, Any] = {}
            if isinstance(record, dict):
                try:
                    from ..analysis.audit_budget import round_budget_snapshot
                    budget_status = round_budget_snapshot(record)
                    ctx.write_artifact(
                        r, "S0", "execution-budget-status.json", budget_status)
                except Exception as status_exc:
                    budget_status = {"status": "unavailable",
                                     "error": str(status_exc)[:1000]}
            try:
                from ..memory.state import CheckpointStore
                completed_stages = CheckpointStore(
                    ctx.root, ctx.cfg.name, r).completed_stages()
            except Exception:
                completed_stages = []
            try:
                usage = ctx.llm.usage.to_dict()
            except Exception:
                usage = {}
            progress = {
                "status": "failed-unhandled-error",
                "error_type": type(exc).__name__, "error": str(exc)[:2000],
                "completed_stages": completed_stages,
                "last_completed_stage": (completed_stages[-1]
                                          if completed_stages else None),
                "audit_budget": budget_status,
                "llm_usage": usage,
                "claim_status": "not-a-finding",
            }
            try:
                ctx.write_artifact(r, "S0", "round-error-report.json", progress)
                if usage:
                    ctx.write_artifact(r, "S0", "llm-usage.json", usage)
            except Exception as write_exc:
                print("could not persist round failure report: %s" % write_exc)
            print("round %02d failed with %s: %s" % (
                r, type(exc).__name__, str(exc)[:1000]))
            rounds_done.append({"round": r, **progress})
            break
        finally:
            ctx._candidate_source_snippet_cache.finish_round(round_status, r)
            if getattr(ctx, "_active_audit_guard_registered", False):
                try:
                    from ..analysis.audit_budget import round_budget_snapshot
                    from ..analysis.audit_guard import release_active_audit
                    record = getattr(ctx, "_round_budget_record", None)
                    if record is None:
                        raise ValueError("round budget record is unavailable")
                    if round_budget_snapshot(record)["expired"]:
                        print("[round-%02d] expired source root remains guarded; "
                              "release it after writing the progress report" % r)
                    else:
                        source_root, _source_dirs = _target_source_scope(ctx)
                        release_active_audit(
                            ctx.root, ctx.cfg.name, r, root=source_root)
                except (OSError, TypeError, ValueError) as exc:
                    print("[round-%02d] could not release active-audit guard: %s" % (
                        r, exc))
        rounds_done.append(result)
        if not result.get("next_candidates"):
            print("no new candidates; loop stops")
            break
        # Baseline #9: hand the next-round candidates to the following S2.
        ctx.carryover = result["next_candidates"]
    return rounds_done


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Autonomous 0day-hunting agent")
    ap.add_argument("--name", required=True, help="target name (dir under targets/)")
    ap.add_argument("--round", type=int, default=1)
    ap.add_argument("--target-dir", help="new target source/jar dir (auto-prepare)")
    ap.add_argument("--config", help="existing config path (relative to workspace)")
    ap.add_argument("--max-calls", type=int, default=40, help="LLM call budget")
    ap.add_argument("--max-tokens", type=int, default=300_000)
    ap.add_argument("--max-candidates", type=int, default=4)
    ap.add_argument("--max-rounds", type=int, default=3)
    ap.add_argument("--model", default=None)
    ap.add_argument("--reasoning-effort", default=None,
                    help="LLM reasoning effort (low/medium/high)")
    ap.add_argument("--lang", default=None, choices=["zh", "en"],
                    help="ledger/finding output language (default: config output_lang)")
    ap.add_argument("--offline", action="store_true", help="disable live GitHub API")
    ap.add_argument("--force", action="store_true",
                    help="rebuild stage checkpoints and retry a failed coverage scope once")
    ap.add_argument("--fuzz-budget", type=int, default=0,
                    help="directed fuzz inputs per round, merged into S2 candidates (plan 2.1)")
    ap.add_argument("--fuzz-seed", type=int, default=None)
    ap.add_argument("--fuzz-force", action="store_true",
                    help="re-run fuzz discovery even if a report exists")
    ap.add_argument("--fuzz-skip-minimize", action="store_true")
    args = ap.parse_args(argv)

    if args.config:
        cfg = TargetConfig.load(ROOT / args.config)
    elif args.target_dir:
        from ..analysis.audit_budget import (
            DEFAULT_BUDGET_SECONDS, budget_path, start_round_budget,
        )
        try:
            prep_budget = start_round_budget(
                ROOT, args.name, args.round, DEFAULT_BUDGET_SECONDS)
        except (OSError, TypeError, ValueError) as exc:
            print("refusing target preparation without a valid round budget: %s" % exc)
            return 2
        try:
            cfg = prepare_target(
                ROOT, args.name, Path(args.target_dir), prep_budget)
        except TargetPreparationTimeout as exc:
            status = {
                "status": "target-preparation-incomplete",
                "error": str(exc), "progress": exc.progress,
                "claim_status": "not-a-finding",
            }
            status_path = (budget_path(ROOT, args.name, args.round).parent /
                           "target-preparation-status.json")
            status_path.parent.mkdir(parents=True, exist_ok=True)
            status_path.write_text(
                json.dumps(status, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8")
            print("target preparation timed out; saved progress to %s" % status_path)
            return 2
    else:
        ap.error("need --config or --target-dir")

    llm = LLMClient(model=args.model, max_calls=args.max_calls,
                    max_tokens_total=args.max_tokens,
                    reasoning_effort=args.reasoning_effort)
    if args.lang:
        cfg.output_lang = args.lang
    needs_api_hint = not cfg.api_hint
    ctx = AutoCtx(ROOT, cfg, llm, offline=args.offline,
                  max_candidates=args.max_candidates, max_rounds=args.max_rounds,
                  fuzz_budget=args.fuzz_budget, fuzz_seed=args.fuzz_seed,
                  fuzz_force=args.fuzz_force,
                  fuzz_skip_minimize=args.fuzz_skip_minimize,
                  force=args.force)
    rounds_done = run_loop(ctx, args.round)
    if needs_api_hint and cfg.api_hint and args.config:
        cfg_path = ROOT / args.config
        if cfg_path.exists():
            try:
                d = json.loads(cfg_path.read_text(encoding="utf-8"))
                d["api_hint"] = cfg.api_hint
                cfg_path.write_text(json.dumps(d, indent=2, ensure_ascii=False),
                                    encoding="utf-8")
            except (OSError, UnicodeError, ValueError, TypeError) as exc:
                print("[S1.5] could not persist learned api_hint: %s" % exc)
    print("\n==== autonomous round summary ====")
    print("rounds done: %d" % len(rounds_done))
    print("llm usage: %s" % json.dumps(llm.usage.to_dict(), ensure_ascii=False))
    incomplete_statuses = {
        "invalid-round-budget", "invalid-round-guard",
        "stopped-at-round-deadline", "stopped-llm-budget-exhausted",
        "stopped-source-scan-incomplete", "s4-timebox-exhausted",
        "failed-unhandled-error",
    }
    incomplete = any(str(result.get("status") or "") in incomplete_statuses
                     for result in rounds_done)
    if incomplete:
        print("audit ended incomplete; see the round S0/S4 stop report")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
