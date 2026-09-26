"""Unified conclusion rules (baseline fix #10).

One `derive_conclusion` implementation shared by the config-driven pipeline
(stages.py), the autonomous driver (run_agent.py) and the benchmark runner,
so the same runtime observations always yield the same verdict. The stricter
rules (FQCN-exact instantiation, NETWORK side-effect proof, OOM amplification
via INPUT_BYTES) are the single source of truth.

Observation model (from build.py):
  GATE_BLOCKED / INSTANTIATED / ERROR / NETWORK / LEAKED / PARSED /
  INPUT_BYTES / ENV_ERROR / compile_error / harness_error

Conclusion states:
  确认 / 排除 / 候选（待验证）
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .evidence_policy import S4_EVIDENCE_POLICY_VERSION


DENY_CLASS_HINTS = (
    "JdbcRowSetImpl", "JdbcRowSet", "TemplatesImpl", "GroovyShell",
    "ScriptEngineManager", "ClassPathXmlApplicationContext",
    "SpringPropertyAccessorFactory", "JndiObjectFactoryBean", "HikariConfig",
)


def conclusion_status(value: object) -> str:
    """Normalize human-readable conclusion strings to a stable status.

    Ledger producers may append severity, novelty or review notes after the
    state (for example ``确认；High；已知机制增量；非 RCE``).  Exact equality
    with ``确认`` would silently drop such a row from summaries.
    """
    text = str(value or "").strip()
    if text.startswith("确认"):
        return "confirmed"
    if text.startswith("排除"):
        return "excluded"
    if text.startswith("候选") or text.startswith("待验证"):
        return "candidate"
    return "unknown"


def is_confirmed_conclusion(value: object) -> bool:
    return conclusion_status(value) == "confirmed"


def _requires_real_effect(cand: Dict[str, Any]) -> bool:
    """Whether a candidate claims code/command execution rather than parsing.

    Instantiation, a JNDI lookup error, or an in-memory canary proves a chain
    stage only. It is not RCE until the claimed execution effect is observed.
    """
    text = " ".join(str(cand.get(k, "")) for k in
                    ("attack_class", "surface", "logic", "hypothesis", "impact")).lower()
    return any(marker in text for marker in (
        "rce", "remote code execution", "code execution", "command execution",
        "命令执行", "远程代码执行", "processbuilder", "runtime.exec", "代码执行",
    ))


def _has_real_effect(summary: Dict[str, Any], cand: Optional[Dict[str, Any]] = None) -> bool:
    effects = summary.get("independent_effect_evidence") or []
    if not _requires_real_effect(cand or {}):
        return bool(effects)
    # A successful loopback connection, parser canary, authorization change or
    # fixture mutation is not code execution. RCE requires an independently
    # observed process lifecycle or filesystem effect; PoC labels remain
    # claims even when their EFFECT_KIND sounds convincing.
    allowed = {"process-effect", "filesystem-diff", "jvm-effect"}
    return any(str(e.get("kind", "")).lower() in allowed for e in effects)


def _is_runtime_evidence(error: str) -> bool:
    """Runtime evidence that justifies 确认 (data-driven, wrapper-aware).

    - JVM-level crashes: error starts with OutOfMemoryError / StackOverflowError
      (or java.lang. prefix). These are real DoS evidence.
    - JNDI chain: SQLException (JdbcRowSetImpl lookup failure) is a side-effect
      trace of the instantiation chain. Wrapped forms count too (e.g.
      SerializationException: ... nested exception is java.sql.SQLException:
      JdbcRowSet (连接) JNDI 无法连接) -- the rowset lookup itself ran.
    - Library-wrapped crashes (e.g. KryoException: java.lang.StackOverflowError)
      are the library's own guard converting an Error to an exception; the
      process survives (rc=0), so they are NOT standalone DoS evidence.
    """
    e = str(error).strip()
    if e.startswith(("OutOfMemoryError", "StackOverflowError",
                     "java.lang.OutOfMemoryError", "java.lang.StackOverflowError")):
        return True
    if e.startswith("java.sql.SQLException"):
        return True
    if "SQLException" in e and ("JNDI" in e or "JdbcRowSet" in e):
        # framework wrapper (Spring serializer / generic wrapper) embedding the
        # JNDI rowset-lookup failure; the dangerous chain did run.
        return True
    return False


def validate_confirmation(cand: Dict[str, Any], cells: List[Dict[str, Any]]) -> List[str]:
    """Evidence-fidelity checks against LLM PoCs that hardcode evidence lines.

    * INSTANTIATED must be a *clean* FQCN (exact match) in the candidate's
      declared target_classes or a known dangerous class. An exception message
      pasted into INSTANTIATED (e.g. "JSONException:autoType is not support.
      com.sun.rowset.JdbcRowSetImpl") is NOT instantiation evidence and must
      not confirm a finding (fixed after 0-config trial round-01 A2 false
      positive, 2026-08-09).
    * NETWORK claims must be backed by a JVM-side connection error
      (SQLException/JNDI) in the same cell.
    """
    issues: List[str] = []
    inst = [c for c in cells
            if "." in str(c.get("observations", {}).get("INSTANTIATED", ""))]
    targets = [str(t) for t in (cand.get("target_classes") or [])]
    deny = set(DENY_CLASS_HINTS)

    def _clean_fqcn(s: str) -> bool:
        return bool(re.fullmatch(r"[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*", s.strip()))

    dangerous = [
        c for c in inst
        if _clean_fqcn(v := str(c["observations"]["INSTANTIATED"]).strip())
        and (v in deny or v in targets)]
    if inst and not dangerous:
        issues.append(
            "instantiated class not in deny/target set: %s"
            % sorted({str(c["observations"]["INSTANTIATED"]) for c in inst}))
    for c in cells:
        obs = c.get("observations", {})
        net = str(obs.get("NETWORK", ""))
        err = str(obs.get("ERROR", ""))
        if "://" in net and "SQLException" not in err and "JNDI" not in err:
            issues.append(
                "NETWORK claim without JVM-side connection error "
                "(possible hardcoded): %s" % net)
        lk = str(obs.get("LEAKED", "")).strip()
        if lk and lk.lower() in ("true", "yes", "ok", "none", "null", "0", "parsed"):
            issues.append("LEAKED placeholder value, not real leaked content: %s" % lk)
        elif lk and not re.search(r"[\s:/\=\;\{\}]", lk):
            # Real leaked content (file line, response body, key material) almost
            # always contains separators; a bare identifier (class name / word)
            # is an LLM-hardcoded placeholder, not leakage evidence.
            issues.append("LEAKED value lacks content separators (hardcoded?): %s" % lk)
    return issues


def derive_conclusion(summary: Dict[str, Any],
                      cand: Optional[Dict[str, Any]] = None,
                      cells: Optional[List[Dict[str, Any]]] = None) -> str:
    """Data-driven conclusion from runtime observations (single source of truth).

    Returns one of: 确认 / 排除 / 候选（待验证）
    """
    if cells is None:
        summary.setdefault("validation_issues", []).append(
            "runtime conclusion withheld: raw S4 cells are missing; "
            "summary fields alone are not evidence")
        return "候选（待验证）"

    # Rebuild security-relevant facts from the cells instead of allowing a
    # caller-supplied or persisted summary to promote its own claims.
    from .build import _trusted_observations, summarize_candidate
    prior_issues = summary.get("validation_issues", [])
    if not isinstance(prior_issues, list):
        prior_issues = [str(prior_issues)] if prior_issues else []
    verified = summarize_candidate(cells)
    summary.update(verified)
    summary["validation_issues"] = list(dict.fromkeys(
        [str(issue) for issue in prior_issues]
        + [str(issue) for issue in verified.get("validation_issues", [])]))
    trusted_cells = []
    for cell in cells:
        if not isinstance(cell, dict):
            continue
        trusted = dict(cell)
        trusted["observations"] = _trusted_observations(cell)
        trusted_cells.append(trusted)

    if (summary.get("evidence_policy_version") != S4_EVIDENCE_POLICY_VERSION
            or summary.get("harness_error") or summary.get("compile_error")):
        return "候选（待验证）"
    execution_state = summary.get("execution_state")
    if execution_state not in ("executed-with-effect", "executed-no-effect"):
        summary.setdefault("validation_issues", []).append(
            "runtime conclusion withheld: S4 matrix is incomplete or did not execute cleanly "
            "(execution_state=%s)" % (execution_state or "unknown"))
        return "候选（待验证）"
    errs = [e.get("error", "") for e in summary.get("errors", [])]
    env_errs = summary.get("env_errors") or []

    strong = bool(summary.get("instantiated") or summary.get("leaked")
                  or any(_is_runtime_evidence(e) for e in errs))
    if env_errs and not strong:
        # Baseline #6: environment errors (missing class/linkage/JDK mismatch)
        # are not library behavior; cannot exclude nor confirm from them.
        summary.setdefault("validation_issues", [])
        summary["validation_issues"].append(
            "env-error cells present (%d); verdict withheld: %s"
            % (len(env_errs), "; ".join(str(e.get("error", "")) for e in env_errs[:2])))
        return "候选（待验证）"

    if _requires_real_effect(cand or {}) and not _has_real_effect(summary, cand):
        summary.setdefault("validation_issues", []).append(
            "RCE/code-execution claim has no labelled real side-effect evidence; "
            "instantiation/JNDI trace/memory canary is capability-only")
        return "候选（待验证）"

    if summary.get("instantiated"):
        issues = validate_confirmation(cand or {}, trusted_cells)
        if issues:
            summary["validation_issues"] = issues
            return "候选（待验证）"
        return "确认"
    if summary.get("leaked"):
        issues = validate_confirmation(cand or {}, trusted_cells)
        if issues:
            summary["validation_issues"] = issues
            return "候选（待验证）"
        return "确认"
    if summary.get("http_evidence"):
        # The current observer captures status and body digests, not response
        # content or target state. Transport metadata cannot prove impact.
        summary.setdefault("validation_issues", []).append(
            "independent HTTP transport was observed, but response content or "
            "target-state impact was not independently verified")
    if any(_is_runtime_evidence(e) for e in errs):
        # OOM must be input amplification: a huge input that OOMs by itself
        # (e.g. a 200MB JSON array) is trivial large-input DoS, not a library
        # vulnerability. Require INPUT_BYTES on the OOM cell: small input
        # (<1MB) confirms amplification; missing INPUT_BYTES downgrades to
        # 待验证 (honest, no false confirmation); >=1MB is trivial.
        oom_cells = [
            c for c in trusted_cells
            if "OutOfMemory" in str(c.get("observations", {}).get("ERROR", ""))]
        if oom_cells:
            sizes = []
            for c in oom_cells:
                ib = str(c.get("observations", {}).get("INPUT_BYTES", "")).strip()
                if ib.isdigit():
                    sizes.append(int(ib))
            if sizes and all(s >= 1_048_576 for s in sizes):
                summary["validation_issues"] = [
                    "trivial large-input OOM: INPUT_BYTES>=1MB, no amplification"]
                return "候选（待验证）"
            if not sizes:
                summary["validation_issues"] = [
                    "OOM without INPUT_BYTES evidence (amplification not established)"]
                return "候选（待验证）"
        soe_cells = [
            c for c in trusted_cells
            if "StackOverflow" in str(c.get("observations", {}).get("ERROR", ""))]
        if soe_cells:
            sizes = []
            for c in soe_cells:
                ib = str(c.get("observations", {}).get("INPUT_BYTES", "")).strip()
                if ib.isdigit():
                    sizes.append(int(ib))
            if not sizes:
                summary["validation_issues"] = [
                    "StackOverflowError without INPUT_BYTES evidence (small-input impact not established)"]
                return "候选（待验证）"
        return "确认"
    if summary.get("gate_blocked") or errs:
        summary.setdefault("validation_issues", []).append(
            "runtime error or policy gate does not disprove the candidate")
    return "候选（待验证）"
