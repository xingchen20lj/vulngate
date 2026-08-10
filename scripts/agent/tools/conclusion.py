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


DENY_CLASS_HINTS = (
    "JdbcRowSetImpl", "JdbcRowSet", "TemplatesImpl", "GroovyShell",
    "ScriptEngineManager", "ClassPathXmlApplicationContext",
    "SpringPropertyAccessorFactory", "JndiObjectFactoryBean", "HikariConfig",
)


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
    if summary.get("harness_error") or summary.get("compile_error"):
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

    if summary.get("instantiated"):
        issues = validate_confirmation(cand or {}, cells or [])
        if issues:
            summary["validation_issues"] = issues
            return "排除"
        return "确认"
    if summary.get("leaked"):
        issues = validate_confirmation(cand or {}, cells or [])
        if issues:
            summary["validation_issues"] = issues
            return "排除"
        return "确认"
    if summary.get("http_evidence"):
        # Web-app evidence (ShellMatrixRunner): a cell with a concrete
        # RESP_MATCH / EVIDENCE marker proves the HTTP side-effect (e.g.
        # session takeover -> /api/user/current 200 with admin identity).
        strong_http = [r for r in summary["http_evidence"]
                       if r.get("resp_match") or r.get("evidence")]
        if strong_http:
            bad = []
            for r in strong_http:
                val = str(r.get("resp_match") or r.get("evidence") or "")
                if not re.search(r"[\s:/\=\;\{\}\@\.\-\u4e00-\u9fff]", val):
                    bad.append(val)
            if bad:
                summary["validation_issues"] = [
                    "HTTP evidence value lacks content separators (hardcoded?): %s"
                    % "; ".join(bad[:2])]
                return "排除"
            return "确认"
    if any(_is_runtime_evidence(e) for e in errs):
        # OOM must be input amplification: a huge input that OOMs by itself
        # (e.g. a 200MB JSON array) is trivial large-input DoS, not a library
        # vulnerability. Require INPUT_BYTES on the OOM cell: small input
        # (<1MB) confirms amplification; missing INPUT_BYTES downgrades to
        # 待验证 (honest, no false confirmation); >=1MB is trivial.
        oom_cells = [
            c for c in (cells or [])
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
                return "排除"
            if not sizes:
                summary["validation_issues"] = [
                    "OOM without INPUT_BYTES evidence (amplification not established)"]
                return "候选（待验证）"
        return "确认"
    if summary.get("gate_blocked") or errs:
        return "排除"
    return "候选（待验证）"
