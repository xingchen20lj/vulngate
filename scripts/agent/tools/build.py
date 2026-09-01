"""Java PoC build + verification-matrix runner.

Runs `{version} x {safe-mode on/off} x {precondition}` cells for a candidate,
captures stdout/stderr per cell, and extracts machine-readable observations
(GATE_BLOCKED / INSTANTIATED / ERROR / NETWORK / PARSED lines) that the G4
runtime gate consumes.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ..sandbox.approval import ApprovalGate
from ..sandbox.runner import CommandRunner, RunResult


RUNNER_POLICY_VERSION = "loopback-only-v2"


LOOPBACK_OK = {"127.0.0.1", "localhost", "0.0.0.0", "[::1]", "::1"}

_URL_SCHEME = re.compile(
    r"\b(?:jar|http|https|ftp|ldap|ldaps|rmi|dns|file|tcp|udp|jdbc|nhttp|"
    r"dnslog|gopher)://([^/\"'\s:]+)", re.I)
_IP_LITERAL = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_REMOTE_TOOL = re.compile(
    r"\b(?:ssh|scp|sftp|telnet|rlogin|rsync|kubectl|docker|podman|aliyun|aws|gcloud)\b",
    re.I,
)
_WILDCARD_BIND = re.compile(
    r"\b(?:bind|listen)\s*\([^)]*[\"'](?:0\.0\.0\.0|::)[\"']", re.I | re.S)


def scan_source_egress(src_text: str, src_path: str = "",
                       allowed_hosts: Optional[set] = None) -> List[str]:
    """Static loopback-enforcement scan (baseline fix #4).

    Finds non-loopback network targets in PoC source before compilation.
    Loopback (127.0.0.1 / localhost / 0.0.0.0) is allowed; anything else is
    reported so the runner can refuse to build the PoC. This turns the
    "loopback only" prompt-level constraint into a compile-time hard gate.
    """
    bad: List[str] = []
    if _REMOTE_TOOL.search(src_text):
        bad.append("remote/cloud execution primitive (line ~%d)" % (
            src_text.count("\n", 0, _REMOTE_TOOL.search(src_text).start()) + 1))
    if _WILDCARD_BIND.search(src_text):
        bad.append("public wildcard listener 0.0.0.0/::")
    url_hosts = set()
    for m in _URL_SCHEME.finditer(src_text):
        host = m.group(1).strip().lower().rstrip(".")
        url_hosts.add(host)
        if host and host not in LOOPBACK_OK and host not in (allowed_hosts or set()) and host not in bad:
            bad.append("%s://%s (line ~%d)" % (m.group(0).split("://")[0], host,
                                               src_text.count("\n", 0, m.start()) + 1))
    for m in _IP_LITERAL.finditer(src_text):
        ip = m.group(1)
        if ip in url_hosts:
            continue  # already reported as a URL host
        if ip not in LOOPBACK_OK and ip not in (allowed_hosts or set()) and ip not in bad:
            bad.append("IP %s (line ~%d)" % (ip, src_text.count("\n", 0, m.start()) + 1))
    return sorted(set(bad))


@dataclass
class MatrixCell:
    version: str
    safe_mode: bool
    features: List[str] = field(default_factory=list)
    precondition: str = "none"
    args: List[str] = field(default_factory=list)
    jvm: Dict[str, str] = field(default_factory=dict)   # e.g. {"Xmx": "128m"}
    timeout: Optional[int] = None                        # seconds; None = runner default


@dataclass
class POCSpec:
    candidate_id: str
    class_name: str
    src: str                      # relative path under poc/<target>/round-N/src/
    cells: List[MatrixCell]
    extra_srcs: List[str] = field(default_factory=list)   # extra .java (subdirs ok)
    safe_mode_jvm_prop: str = ""  # if set, emit -D<prop>=true/false
    module_opts: List[str] = field(default_factory=list)          # javac: --add-exports only
    module_run_opts: List[str] = field(default_factory=list)      # java: --add-opens/--add-exports
    jvm_default: Dict[str, str] = field(default_factory=dict)
    entry: str = ""
    input_shape: str = ""
    logic: str = ""
    notes: str = ""


ENV_ERROR_PATTERN = re.compile(
    r"(NoClassDefFoundError|ClassNotFoundException|NoSuchMethodError|"
    r"UnsupportedClassVersionError|LinkageError|ExceptionInInitializerError|"
    r"NoSuchFieldError|NoSuchMethodException)")


def parse_observations(stdout: str, stderr: str = "") -> Dict[str, str]:
    obs: Dict[str, str] = {}
    combined = stdout + "\n" + stderr
    for line in combined.splitlines():
        for key in ("GATE_BLOCKED", "INSTANTIATED", "ERROR", "NETWORK", "LEAKED",
                    "SHORTNAME", "PARSED", "INPUT_BYTES", "CELL_START",
                    "DEFAULT_READER_FEATURES", "SUPPORTS_AUTOTYPE",
                    "CACHE_POLLUTED", "TYPED_ARRAY", "PRE_POLLUTION_GATE",
                    "ENV_ERROR", "HTTP_CODE", "RESP_MATCH", "EVIDENCE",
                    "EFFECT_KIND", "EFFECT", "SIDE_EFFECT", "CANARY",
                    "PROCESS_START_CALLS", "COMMAND_EXECUTIONS",
                    "NETWORK_ATTEMPTS", "NETWORK_SUCCESS", "CONCURRENCY",
                    "SERVICE_UNAVAILABLE", "AVAILABILITY"):
            if line.startswith(key + "="):
                obs[key] = line[len(key) + 1:]
    if "ERROR" not in obs:
        m = re.search(r"(OutOfMemoryError|StackOverflowError|SQLException|JSONException"
                      r"|ArrayIndexOutOfBoundsException|DateTimeException|"
                      r"NegativeArraySizeException|NumberFormatException|IllegalArgument\w*)",
                      combined)
        if m:
            obs["ERROR"] = m.group(1)
    if "ENV_ERROR" not in obs:
        m = ENV_ERROR_PATTERN.search(combined)
        if m:
            obs["ENV_ERROR"] = m.group(1)
    return obs


class JavaMatrixRunner:
    def __init__(self, workspace: Path, target: str, round_no: int,
                 approval: Optional[ApprovalGate] = None,
                 authorized_staging: bool = False,
                 staging_hosts: Optional[List[str]] = None):
        self.workspace = workspace.resolve()
        self.target = target
        self.round_no = round_no
        self.approval = approval or ApprovalGate()
        self.authorized_staging = authorized_staging
        self.staging_hosts = {str(h).strip().lower().rstrip(".") for h in (staging_hosts or [])}
        self.runner = CommandRunner(workspace, approval, authorized_staging=authorized_staging,
                                    staging_hosts=list(self.staging_hosts))
        self.src_dir = workspace / "poc" / target / ("round-%02d" % round_no) / "src"
        self.out_dir = workspace / "poc" / target / ("round-%02d" % round_no) / "out"
        self.matrix_dir = workspace / "state" / target / ("round-%02d" % round_no) / "S4" / "matrix-runs"

    # ------------------------------------------------------------------
    def compile(self, spec: POCSpec, version: str, jars: List[Path]) -> RunResult:
        out = self.out_dir / version
        out.mkdir(parents=True, exist_ok=True)
        src_file = self.src_dir / spec.src
        if not src_file.exists():
            raise FileNotFoundError(
                "PoC source missing: %s (stage PoCs into %s first)" % (src_file, self.src_dir))
        cp = ":".join(str(j) for j in jars)
        files = [str(src_file)] + [str(self.src_dir / s) for s in spec.extra_srcs]
        # Baseline fix #4: loopback-only hard gate before javac. Any non-loopback
        # URL/IP literal in PoC source blocks the build and is recorded.
        egress = []
        for f in files:
            try:
                text = Path(f).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            egress += scan_source_egress(text, f, self.staging_hosts if self.authorized_staging else None)
        if egress:
            detail = "PoC 源码含非回环网络目标: %s" % "; ".join(sorted(set(egress))[:6])
            self.approval.request("external_egress", detail)
            return RunResult(cmd=[], returncode=-2, stdout="",
                             stderr="EGRESS_DENIED " + detail, duration_ms=0)
        cmd = ["javac"] + spec.module_opts + ["-cp", cp, "-d", str(out)] + files
        return self.runner.run(cmd, cwd=self.src_dir)

    def run_cell(self, spec: POCSpec, cell: MatrixCell, jars: List[Path]) -> Dict:
        out = self.out_dir / cell.version
        cp = ":".join([str(j) for j in jars] + [str(out)])
        jvm = dict(spec.jvm_default)
        jvm.update(cell.jvm)
        xmx = jvm.get("Xmx")
        java_cmd = ["java"]
        if xmx:
            java_cmd.append("-Xmx" + xmx)
        if spec.safe_mode_jvm_prop:
            java_cmd += ["-D%s=%s" % (spec.safe_mode_jvm_prop, "true" if cell.safe_mode else "false")]
        # target-generic safe-mode property (target PoCs may read
        # -Dtarget.safeMode to implement two states)
        java_cmd += ["-Dtarget.safeMode=%s" % ("true" if cell.safe_mode else "false")]
        java_cmd += spec.module_run_opts
        java_cmd += ["-cp", cp, spec.class_name] + list(cell.args)
        try:
            result = self.runner.run(
                java_cmd,
                cwd=out,
                operation="loopback_connect",
                operation_detail="mechanism-level PoC %s (JNDI/HTTP limited to 127.0.0.1)" % spec.class_name,
                timeout=cell.timeout,
            )
        except PermissionError as exc:
            return {
                "candidate_id": spec.candidate_id, "poc_class": spec.class_name,
                "version": cell.version, "safe_mode": cell.safe_mode,
                "features": cell.features, "precondition": cell.precondition,
                "returncode": -3, "timed_out": False, "duration_ms": 0,
                "observations": {"GATE_BLOCKED": "policy-denied"},
                "harness_error": "policy_denied: %s" % exc,
                "stderr": str(exc), "cmd": " ".join(java_cmd),
                "runner_policy": RUNNER_POLICY_VERSION,
            }
        obs = parse_observations(result.stdout, result.stderr)
        return {
            "candidate_id": spec.candidate_id,
            "poc_class": spec.class_name,
            "version": cell.version,
            "safe_mode": cell.safe_mode,
            "features": cell.features,
            "precondition": cell.precondition,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "duration_ms": result.duration_ms,
            "observations": obs,
            "stdout": result.stdout,
            "stderr": result.stderr[-4000:],
            "cmd": " ".join(java_cmd),
            "runner_policy": RUNNER_POLICY_VERSION,
        }

    def run_manifest(self, specs: List[POCSpec], jars_by_version: Dict[str, List[Path]]) -> Dict[str, List[Dict]]:
        """Run every cell of every spec; return {candidate_id: [cell results]}."""
        all_results: Dict[str, List[Dict]] = {}
        for spec in specs:
            results = []
            versions = sorted({c.version for c in spec.cells})
            for version in versions:
                jars = jars_by_version.get(version, [])
                compiled = self.compile(spec, version, jars)
                if compiled.returncode != 0:
                    # compile failure is a harness issue, not a runtime verdict
                    results.append({
                        "candidate_id": spec.candidate_id,
                        "poc_class": spec.class_name,
                        "version": version,
                        "compile_error": (compiled.stderr or compiled.stdout)[-2000:],
                        "observations": {},
                        "cmd": " ".join(compiled.cmd),
                    })
                    continue
                for cell in [c for c in spec.cells if c.version == version]:
                    results.append(self.run_cell(spec, cell, jars))
            all_results[spec.candidate_id] = results
            self._write_cells(spec.candidate_id, results)
        return all_results

    def _write_cells(self, candidate_id: str, cells: List[Dict]) -> None:
        d = self.matrix_dir / candidate_id
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / ("cells.json.tmp.%d" % os.getpid())
        tmp.write_text(json.dumps(cells, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(d / "cells.json")


@dataclass
class ShellPOCSpec:
    candidate_id: str
    script: str                      # relative path under poc/<target>/round-N/src/
    cells: List[MatrixCell]
    env: Dict[str, str] = field(default_factory=dict)
    urls: Dict[str, str] = field(default_factory=dict)  # version -> base URL (web-app matrix)
    entry: str = ""
    input_shape: str = ""
    logic: str = ""
    notes: str = ""


class ShellMatrixRunner:
    """Shell/HTTP PoC matrix runner for web apps, services and protocol tests.

    Produces the same cells.json schema as JavaMatrixRunner so G4 sees one
    observation contract. PoC scripts (bash) must print machine-readable lines:

      HTTP_CODE=<status>        observed HTTP status code
      RESP_MATCH=<marker>       expected marker found in response body/headers
      EVIDENCE=<text>           side-effect proof (marker file / DB row / log line)
      GATE_BLOCKED=<reason>     config/precondition blocked the path
      ERROR=<exception>         runtime error observed

    Loopback-only egress is enforced by the same static source scan used for
    Java PoCs; any non-loopback URL/IP in the script is refused before run.
    Cells receive VULNGATE_VERSION / VULNGATE_SAFE_MODE / VULNGATE_PRECONDITION
    / VULNGATE_FEATURES via environment.
    """

    def __init__(self, workspace: Path, target: str, round_no: int,
                 approval: Optional[ApprovalGate] = None,
                 authorized_staging: bool = False,
                 staging_hosts: Optional[List[str]] = None):
        self.workspace = workspace.resolve()
        self.target = target
        self.round_no = round_no
        self.approval = approval or ApprovalGate()
        self.authorized_staging = authorized_staging
        self.staging_hosts = {str(h).strip().lower().rstrip(".") for h in (staging_hosts or [])}
        self.runner = CommandRunner(workspace, approval, authorized_staging=authorized_staging,
                                    staging_hosts=list(self.staging_hosts))
        self.src_dir = workspace / "poc" / target / ("round-%02d" % round_no) / "src"
        self.matrix_dir = workspace / "state" / target / ("round-%02d" % round_no) / "S4" / "matrix-runs"

    def run_manifest(self, specs: List[ShellPOCSpec]) -> Dict[str, List[Dict]]:
        all_results: Dict[str, List[Dict]] = {}
        for spec in specs:
            results = [self.run_cell(spec, cell) for cell in spec.cells]
            all_results[spec.candidate_id] = results
            self._write_cells(spec.candidate_id, results)
        return all_results

    def run_cell(self, spec: ShellPOCSpec, cell: MatrixCell) -> Dict:
        script = self.src_dir / spec.script
        if not script.exists():
            return {
                "candidate_id": spec.candidate_id,
                "poc_script": spec.script,
                "version": cell.version,
                "safe_mode": cell.safe_mode,
                "precondition": cell.precondition,
                "harness_error": "script missing: %s (stage .sh PoCs into %s)" % (script, self.src_dir),
                "observations": {},
                "lang": "shell",
            }
        egress = scan_source_egress(
            script.read_text(encoding="utf-8", errors="replace"), str(script),
            self.staging_hosts if self.authorized_staging else None)
        if egress:
            detail = "PoC 脚本含非回环网络目标: %s" % "; ".join(sorted(set(egress))[:6])
            self.approval.request("external_egress", detail)
            return {
                "candidate_id": spec.candidate_id,
                "poc_script": spec.script,
                "version": cell.version,
                "safe_mode": cell.safe_mode,
                "precondition": cell.precondition,
                "observations": {"GATE_BLOCKED": "egress-denied"},
                "stderr": "EGRESS_DENIED " + detail,
                "lang": "shell",
            }
        env_extra = {
            "VULNGATE_VERSION": cell.version,
            "VULNGATE_SAFE_MODE": "true" if cell.safe_mode else "false",
            "VULNGATE_PRECONDITION": cell.precondition,
            "VULNGATE_FEATURES": ",".join(cell.features),
            "VULNGATE_TARGET_URL": spec.urls.get(cell.version, spec.env.get("VULNGATE_TARGET_URL", "")),
        }
        env_extra.update(spec.env)
        cmd = ["bash", str(script)] + list(cell.args)
        try:
            result = self.runner.run(
                cmd,
                cwd=self.src_dir,
                env_extra=env_extra,
                operation="loopback_connect",
                operation_detail="shell/HTTP PoC %s (targets limited to 127.0.0.1)" % spec.candidate_id,
                timeout=cell.timeout,
            )
        except PermissionError as exc:
            return {
                "candidate_id": spec.candidate_id, "poc_script": spec.script,
                "version": cell.version, "safe_mode": cell.safe_mode,
                "features": cell.features, "precondition": cell.precondition,
                "returncode": -3, "timed_out": False, "duration_ms": 0,
                "observations": {"GATE_BLOCKED": "policy-denied"},
                "harness_error": "policy_denied: %s" % exc,
                "stderr": str(exc), "cmd": " ".join(cmd), "lang": "shell",
                "runner_policy": RUNNER_POLICY_VERSION,
            }
        obs = parse_observations(result.stdout, result.stderr)
        return {
            "candidate_id": spec.candidate_id,
            "poc_script": spec.script,
            "version": cell.version,
            "safe_mode": cell.safe_mode,
            "features": cell.features,
            "precondition": cell.precondition,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "duration_ms": result.duration_ms,
            "observations": obs,
            "stdout": result.stdout,
            "stderr": result.stderr[-4000:],
            "cmd": " ".join(cmd),
            "lang": "shell",
            "runner_policy": RUNNER_POLICY_VERSION,
        }

    def _write_cells(self, candidate_id: str, cells: List[Dict]) -> None:
        d = self.matrix_dir / candidate_id
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / ("cells.json.tmp.%d" % os.getpid())
        tmp.write_text(json.dumps(cells, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(d / "cells.json")


_FALSY_MARKERS = ("", "true", "yes", "ok", "none", "null", "0", "false")


def summarize_candidate(cells: List[Dict]) -> Dict:
    """Derive runtime facts from a candidate's cell results (data-driven, no hard-coding)."""
    harness_errors = [c.get("harness_error", "") for c in cells if c.get("harness_error")]
    if harness_errors:
        return {"harness_error": harness_errors[0], "cells_ran": len(cells)}
    compile_errors = [c.get("compile_error", "") for c in cells if c.get("compile_error")]
    if compile_errors:
        return {"compile_error": compile_errors[0], "cells_ran": len(cells)}
    instantiated = []
    errors = []
    gate_blocked = []
    network = []
    parsed = []
    leaked = []
    env_errors = []
    http_evidence = []
    safe_equivalent = []
    effect_evidence = []
    availability_proof = []

    def truthy(v: str) -> bool:
        # LLM-authored PoCs may emit INSTANTIATED=false / GATE_BLOCKED=none /
        # NETWORK=null; those are "not observed", never evidence.
        return str(v).strip().lower() not in ("", "false", "none", "null", "0")

    for c in cells:
        obs = c.get("observations", {})
        # Evidence contract: INSTANTIATED must be an FQCN (e.g.
        # a fully-qualified class name). A bare "true"/"yes" from an LLM PoC
        # ("parse returned non-null") is NOT evidence of target instantiation.
        if truthy(obs.get("INSTANTIATED")) and "." in str(obs.get("INSTANTIATED")):
            instantiated.append({"version": c["version"], "safe": c["safe_mode"],
                                 "precondition": c["precondition"], "class": obs["INSTANTIATED"]})
        if obs.get("ERROR"):
            errors.append({"version": c["version"], "safe": c["safe_mode"],
                           "precondition": c["precondition"], "error": obs["ERROR"]})
        if truthy(obs.get("GATE_BLOCKED")):
            gate_blocked.append({"version": c["version"], "safe": c["safe_mode"],
                                 "precondition": c["precondition"], "class": obs["GATE_BLOCKED"]})
        if truthy(obs.get("NETWORK")) and "://" in str(obs.get("NETWORK")):
            network.append(obs["NETWORK"])
        if truthy(obs.get("PARSED")):
            parsed.append(obs["PARSED"])
        # Content-leakage evidence (XXE/SSRF/file-read style): LEAKED must be a
        # concrete leaked artifact/string, not a generic "parse ok" placeholder.
        lk = str(obs.get("LEAKED", "")).strip()
        if lk and lk.lower() not in ("true", "yes", "ok", "none", "null", "0"):
            leaked.append({"version": c["version"], "safe": c["safe_mode"],
                           "precondition": c["precondition"], "leaked": lk[:200]})
        if obs.get("ENV_ERROR"):
            env_errors.append({"version": c["version"], "safe": c["safe_mode"],
                               "precondition": c["precondition"],
                               "error": obs["ENV_ERROR"]})
        effect_kind = str(obs.get("EFFECT_KIND", "")).strip().lower()
        effect = str(obs.get("EFFECT", obs.get("SIDE_EFFECT", ""))).strip()
        canary = str(obs.get("CANARY", "")).strip()
        if canary or any(marker in effect_kind for marker in
                         ("canary", "simulat", "shape-only", "in-memory")):
            safe_equivalent.append({
                "version": c["version"], "safe": c["safe_mode"],
                "precondition": c["precondition"],
                "kind": effect_kind or "memory-canary-only",
                "detail": (canary or effect)[:200],
            })
        # A side effect is evidence only when the PoC labels its effect kind.
        # This prevents a free-form EVIDENCE/Canary line from becoming RCE.
        if effect and effect_kind and not any(marker in effect_kind for marker in
                                             ("canary", "simulat", "shape-only", "in-memory")):
            effect_evidence.append({
                "version": c["version"], "safe": c["safe_mode"],
                "precondition": c["precondition"], "kind": effect_kind,
                "detail": effect[:200],
            })
        conc = str(obs.get("CONCURRENCY", "")).strip()
        unavailable = str(obs.get("SERVICE_UNAVAILABLE", obs.get("AVAILABILITY", ""))).strip().lower()
        if unavailable in ("true", "yes", "full-outage", "unavailable") and conc.isdigit() and int(conc) >= 2:
            availability_proof.append({
                "version": c["version"], "safe": c["safe_mode"],
                "precondition": c["precondition"], "concurrency": int(conc),
                "service_unavailable": unavailable,
            })
        # HTTP-layer evidence (web apps): HTTP_CODE with a digit status, and/or
        # RESP_MATCH / EVIDENCE with a concrete marker (not a placeholder).
        code = str(obs.get("HTTP_CODE", "")).strip()
        match = str(obs.get("RESP_MATCH", "")).strip()
        ev = str(obs.get("EVIDENCE", "")).strip()
        if code.isdigit() or (match and match.lower() not in _FALSY_MARKERS) or \
                (ev and ev.lower() not in _FALSY_MARKERS):
            rec = {"version": c["version"], "safe": c["safe_mode"],
                   "precondition": c["precondition"]}
            if code.isdigit():
                rec["http_code"] = int(code)
            if match and match.lower() not in _FALSY_MARKERS:
                rec["resp_match"] = match[:200]
            if ev and ev.lower() not in _FALSY_MARKERS:
                rec["evidence"] = ev[:200]
            http_evidence.append(rec)
    return {
        "instantiated": instantiated,
        "errors": errors,
        "gate_blocked": gate_blocked,
        "network_side_effects": network,
        "parsed": parsed,
        "leaked": leaked,
        "env_errors": env_errors,
        "http_evidence": http_evidence,
        "safe_equivalent": safe_equivalent,
        "effect_evidence": effect_evidence,
        "availability_proof": availability_proof,
    }
