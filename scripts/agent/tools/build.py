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
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ..sandbox.approval import ApprovalGate
from ..sandbox.runner import CommandRunner, RunResult, minimal_poc_env
from .authz import assert_authz_observations, authz_env, authz_jvm_props, normalize_authz_case


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
    authz: Dict[str, object] = field(default_factory=dict)
    # Runtime selection is per cell.  A requested JDK must never be silently
    # replaced by the agent's default Java installation.
    required_runtime: str = ""                           # e.g. jdk8 / java21
    java_bin: str = ""                                   # explicit .../bin/java
    java_home: str = ""                                  # explicit JDK home


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

RUNTIME_UNAVAILABLE = "precondition-unavailable"


def _resolve_executable(value: str, fallback_name: str) -> Optional[Path]:
    value = str(value or "").strip()
    if value:
        if os.sep in value or Path(value).is_absolute():
            path = Path(value).expanduser()
        else:
            found = shutil.which(value)
            path = Path(found) if found else Path(value)
    else:
        found = shutil.which(fallback_name)
        path = Path(found) if found else Path(fallback_name)
    try:
        path = path.resolve()
    except OSError:
        return None
    return path if path.exists() and os.access(str(path), os.X_OK) else None


def _runtime_major(version: str) -> str:
    text = str(version or "").strip()
    if text.startswith("1."):
        return text.split(".", 2)[1]
    return text.split(".", 1)[0]


def _required_runtime_matches(required: str, version: str) -> bool:
    req = str(required or "").strip().lower().replace("_", ".")
    if not req:
        return True
    major = _runtime_major(version)
    if re.search(r"(?:jdk|java)[^0-9]*1\.8", req):
        return major == "8"
    m = re.search(r"(?:jdk|java)[^0-9]*(\d+)", req)
    if m:
        return major == m.group(1)
    m = re.search(r"(?:^|[^0-9])([0-9]+)(?:\.[0-9]+)?(?:$|[^0-9])", req)
    return not m or major == m.group(1)


def _probe_java(java_bin: Path) -> Dict[str, str]:
    """Read the version of the exact executable selected for one cell."""
    try:
        proc = subprocess.run(
            [str(java_bin), "-version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=10,
            env=minimal_poc_env(),
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"version": "", "version_line": "", "error": type(exc).__name__}
    raw = ((proc.stderr or "") + "\n" + (proc.stdout or "")).strip()
    line = raw.splitlines()[0] if raw else ""
    match = re.search(r'version\s+["\']([^"\']+)', raw, re.I)
    version = match.group(1) if match else ""
    if not version:
        match = re.search(r"\b(\d+(?:\.\d+){0,2}(?:_[\w.-]+)?)\b", raw)
        version = match.group(1) if match else ""
    return {"version": version, "version_line": line[:240],
            "error": "" if proc.returncode == 0 else "exit-%d" % proc.returncode}


def resolve_java_runtime(cell: MatrixCell) -> Dict[str, str]:
    """Resolve and verify the Java toolchain required by ``cell``.

    The returned paths are the actual executables passed to javac/java.  When
    a JDK precondition is declared, an unavailable or mismatched runtime is a
    structured ``precondition-unavailable`` result, never a fallback to the
    host default.
    """
    required = str(cell.required_runtime or "")
    if not required and re.search(r"(?:jdk|java)[-_ ]?(?:version[-_ ]?)?(?:8|11|17|21)",
                                 str(cell.precondition or ""), re.I):
        required = str(cell.precondition)
    if cell.java_home:
        home = Path(cell.java_home).expanduser().resolve()
        java_bin = home / "bin" / "java"
        javac_bin = home / "bin" / "javac"
    elif cell.java_bin:
        java_bin = _resolve_executable(cell.java_bin, "java")
        if java_bin is None:
            return {"available": "false", "status": RUNTIME_UNAVAILABLE,
                    "reason": "java_bin unavailable: %s" % cell.java_bin,
                    "required_runtime": required}
        javac_bin = java_bin.parent / "javac"
        home = java_bin.parent.parent if java_bin.parent.name == "bin" else Path("")
    else:
        java_bin = _resolve_executable("", "java")
        javac_bin = _resolve_executable("", "javac")
        home = java_bin.parent.parent if java_bin and java_bin.parent.name == "bin" else Path("")

    if java_bin is None or not java_bin.exists() or not os.access(str(java_bin), os.X_OK):
        return {"available": "false", "status": RUNTIME_UNAVAILABLE,
                "reason": "java runtime unavailable", "required_runtime": required}
    if javac_bin is None or not javac_bin.exists() or not os.access(str(javac_bin), os.X_OK):
        return {"available": "false", "status": RUNTIME_UNAVAILABLE,
                "reason": "matching javac unavailable: %s" % javac_bin,
                "required_runtime": required}

    probe = _probe_java(java_bin)
    version = probe.get("version", "")
    if probe.get("error"):
        return {"available": "false", "status": RUNTIME_UNAVAILABLE,
                "reason": "cannot execute selected java: %s" % probe.get("error"),
                "required_runtime": required, "java_bin": str(java_bin),
                "javac_bin": str(javac_bin), "java_home": str(home),
                "java_version": version, "java_version_line": probe.get("version_line", "")}
    if required and not _required_runtime_matches(required, version):
        return {"available": "false", "status": RUNTIME_UNAVAILABLE,
                "reason": "requested %s but selected runtime is %s" % (required, version or "unknown"),
                "required_runtime": required, "java_bin": str(java_bin),
                "javac_bin": str(javac_bin), "java_home": str(home),
                "java_version": version, "java_version_line": probe.get("version_line", "")}
    return {"available": "true", "status": "available",
            "required_runtime": required, "java_bin": str(java_bin),
            "javac_bin": str(javac_bin), "java_home": str(home),
            "java_version": version, "java_version_line": probe.get("version_line", "")}


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
                    "SERVICE_UNAVAILABLE", "AVAILABILITY", "OBJECT_MUTATED",
                    "AUTHZ_RESULT", "AUTHZ_NOTE", "JAVA_VERSION",
                    "JDK8_RUNTIME_ACTIVE"):
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
    def compile(self, spec: POCSpec, version: str, jars: List[Path],
                runtime: Optional[Dict[str, str]] = None) -> RunResult:
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
        runtime = runtime or resolve_java_runtime(MatrixCell(version=version, safe_mode=False))
        if runtime.get("available") != "true":
            return RunResult(
                cmd=[runtime.get("javac_bin", "javac")], returncode=-4, stdout="",
                stderr="PRECONDITION_UNAVAILABLE " + runtime.get("reason", "java runtime unavailable"),
                duration_ms=0)
        cmd = [runtime["javac_bin"]] + spec.module_opts + ["-cp", cp, "-d", str(out)] + files
        return self.runner.run(cmd, cwd=self.src_dir, minimal_env=True)

    @staticmethod
    def _runtime_fields(runtime: Dict[str, str]) -> Dict[str, str]:
        return {
            "runtime_status": runtime.get("status", "unknown"),
            "java_bin": runtime.get("java_bin", ""),
            "java_home": runtime.get("java_home", ""),
            "java_version": runtime.get("java_version", ""),
            "java_version_line": runtime.get("java_version_line", ""),
            "requested_runtime": runtime.get("required_runtime", ""),
        }

    def _unavailable_cell(self, spec: POCSpec, cell: MatrixCell,
                          runtime: Dict[str, str]) -> Dict:
        result = {
            "candidate_id": spec.candidate_id, "poc_class": spec.class_name,
            "version": cell.version, "safe_mode": cell.safe_mode,
            "features": cell.features, "precondition": cell.precondition,
            "required_runtime": cell.required_runtime,
            "authz": normalize_authz_case(cell.authz),
            "returncode": -4, "timed_out": False, "duration_ms": 0,
            "observations": {"GATE_BLOCKED": "precondition-unavailable"},
            "harness_error": runtime.get("reason", "java runtime unavailable"),
            "precondition_status": RUNTIME_UNAVAILABLE,
            "stderr": runtime.get("reason", "java runtime unavailable"),
            "cmd": "",
            "runner_policy": RUNNER_POLICY_VERSION,
        }
        result.update(self._runtime_fields(runtime))
        return result

    def run_cell(self, spec: POCSpec, cell: MatrixCell, jars: List[Path],
                 runtime: Optional[Dict[str, str]] = None) -> Dict:
        runtime = runtime or resolve_java_runtime(cell)
        if runtime.get("available") != "true":
            return self._unavailable_cell(spec, cell, runtime)
        out = self.out_dir / cell.version
        cp = ":".join([str(j) for j in jars] + [str(out)])
        jvm = dict(spec.jvm_default)
        jvm.update(cell.jvm)
        xmx = jvm.get("Xmx")
        java_cmd = [runtime["java_bin"]]
        if xmx:
            java_cmd.append("-Xmx" + xmx)
        if spec.safe_mode_jvm_prop:
            java_cmd += ["-D%s=%s" % (spec.safe_mode_jvm_prop, "true" if cell.safe_mode else "false")]
        # target-generic safe-mode property (target PoCs may read
        # -Dtarget.safeMode to implement two states)
        java_cmd += ["-Dtarget.safeMode=%s" % ("true" if cell.safe_mode else "false")]
        java_cmd += authz_jvm_props(cell.authz)
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
            denied = {
                "candidate_id": spec.candidate_id, "poc_class": spec.class_name,
                "version": cell.version, "safe_mode": cell.safe_mode,
                "features": cell.features, "precondition": cell.precondition,
                "required_runtime": cell.required_runtime,
                "authz": normalize_authz_case(cell.authz),
                "returncode": -3, "timed_out": False, "duration_ms": 0,
                "observations": {"GATE_BLOCKED": "policy-denied"},
                "harness_error": "policy_denied: %s" % exc,
                "stderr": str(exc), "cmd": " ".join(java_cmd),
                "runner_policy": RUNNER_POLICY_VERSION,
            }
            denied.update(self._runtime_fields(runtime))
            return denied
        obs = parse_observations(result.stdout, result.stderr)
        authz_assertion = assert_authz_observations(cell.authz, obs)
        result_payload = {
            "candidate_id": spec.candidate_id,
            "poc_class": spec.class_name,
            "version": cell.version,
            "safe_mode": cell.safe_mode,
            "features": cell.features,
            "precondition": cell.precondition,
            "required_runtime": cell.required_runtime,
            "authz": normalize_authz_case(cell.authz),
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "duration_ms": result.duration_ms,
            "observations": obs,
            "authz_assertion": authz_assertion,
            "stdout": result.stdout,
            "stderr": result.stderr[-4000:],
            "cmd": " ".join(java_cmd),
            "runner_policy": RUNNER_POLICY_VERSION,
        }
        result_payload.update(self._runtime_fields(runtime))
        return result_payload

    def run_manifest(self, specs: List[POCSpec], jars_by_version: Dict[str, List[Path]]) -> Dict[str, List[Dict]]:
        """Run every cell of every spec; return {candidate_id: [cell results]}."""
        all_results: Dict[str, List[Dict]] = {}
        for spec in specs:
            results = []
            # Compile separately for different requested runtimes.  This keeps
            # a JDK8 cell from accidentally running bytecode/tools selected by
            # another cell or by the host agent default.
            groups: Dict[tuple, List[MatrixCell]] = {}
            for cell in spec.cells:
                key = (cell.version, cell.java_home, cell.java_bin,
                       cell.required_runtime or cell.precondition)
                groups.setdefault(key, []).append(cell)
            for (version, _java_home, _java_bin, _required), group in groups.items():
                jars = jars_by_version.get(version, [])
                runtime = resolve_java_runtime(group[0])
                if runtime.get("available") != "true":
                    results.extend(self._unavailable_cell(spec, cell, runtime) for cell in group)
                    continue
                compiled = self.compile(spec, version, jars, runtime)
                if compiled.returncode != 0:
                    # Keep one result per declared cell so matrix coverage is
                    # honest even when compilation fails for a whole group.
                    for cell in group:
                        item = {
                        "candidate_id": spec.candidate_id,
                        "poc_class": spec.class_name,
                        "version": version,
                        "safe_mode": cell.safe_mode,
                        "features": cell.features,
                        "precondition": cell.precondition,
                        "required_runtime": cell.required_runtime,
                        "authz": normalize_authz_case(next(
                            (c.authz for c in group if c is cell), {})),
                        "compile_error": (compiled.stderr or compiled.stdout)[-2000:],
                        "observations": {},
                        "cmd": " ".join(compiled.cmd),
                        }
                        item.update(self._runtime_fields(runtime))
                        results.append(item)
                    continue
                for cell in group:
                    results.append(self.run_cell(spec, cell, jars, runtime))
            all_results.setdefault(spec.candidate_id, []).extend(results)
        for candidate_id, cells in all_results.items():
            self._write_cells(candidate_id, cells)
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
            all_results.setdefault(spec.candidate_id, []).extend(results)
        for candidate_id, cells in all_results.items():
            self._write_cells(candidate_id, cells)
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
                "authz_assertion": assert_authz_observations(cell.authz, {}),
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
        # Structured authorization context wins over free-form PoC env values;
        # credentials are never part of this contract.
        env_extra.update(authz_env(cell.authz))
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
                "authz": normalize_authz_case(cell.authz),
                "returncode": -3, "timed_out": False, "duration_ms": 0,
                "observations": {"GATE_BLOCKED": "policy-denied"},
                "harness_error": "policy_denied: %s" % exc,
                "stderr": str(exc), "cmd": " ".join(cmd), "lang": "shell",
                "runner_policy": RUNNER_POLICY_VERSION,
            }
        obs = parse_observations(result.stdout, result.stderr)
        authz_assertion = assert_authz_observations(cell.authz, obs)
        return {
            "candidate_id": spec.candidate_id,
            "poc_script": spec.script,
            "version": cell.version,
            "safe_mode": cell.safe_mode,
            "features": cell.features,
            "precondition": cell.precondition,
            "authz": normalize_authz_case(cell.authz),
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "duration_ms": result.duration_ms,
            "observations": obs,
            "authz_assertion": authz_assertion,
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


def classify_s4_execution(cells: List[Dict]) -> Dict[str, object]:
    """Classify what S4 actually established, independently of host control flow.

    A proxy/agent timeout is not a matrix result.  Persisted cells, including
    fallback cells, are authoritative for this classification.
    """
    if not cells:
        return {"execution_state": "unexecuted", "declared_cell_count": 0,
                "executed_cell_count": 0, "failed_cell_count": 0,
                "gate_blocked_cell_count": 0, "precondition_unavailable_count": 0,
                "effect_cell_count": 0}

    def _truthy(value: object) -> bool:
        return str(value or "").strip().lower() not in _FALSY_MARKERS

    def _ran(cell: Dict) -> bool:
        return (cell.get("returncode") is not None
                and not cell.get("compile_error")
                and not cell.get("harness_error")
                and not cell.get("timed_out")
                and isinstance(cell.get("returncode"), int)
                and cell.get("returncode") == 0)

    def _has_effect(cell: Dict) -> bool:
        obs = cell.get("observations") or {}
        effect_kind = str(obs.get("EFFECT_KIND", "")).strip().lower()
        effect = str(obs.get("EFFECT", obs.get("SIDE_EFFECT", ""))).strip()
        if effect_kind and effect and not any(x in effect_kind for x in
                                             ("canary", "simulat", "shape-only", "in-memory")):
            return True
        leaked = str(obs.get("LEAKED", "")).strip().lower()
        if leaked and leaked not in _FALSY_MARKERS:
            return True
        network = str(obs.get("NETWORK", "")).strip()
        if network and "://" in network:
            return True
        return bool(str(obs.get("RESP_MATCH", "")).strip()
                    or str(obs.get("EVIDENCE", "")).strip())

    precondition_unavailable = [c for c in cells
                                if c.get("precondition_status") == RUNTIME_UNAVAILABLE]
    blocked = [c for c in cells
               if _truthy((c.get("observations") or {}).get("GATE_BLOCKED"))
               and c.get("precondition_status") != RUNTIME_UNAVAILABLE]
    executed = [c for c in cells if _ran(c)]
    failed = [c for c in cells if c not in executed and c not in blocked
              and c not in precondition_unavailable]
    effected = [c for c in executed if _has_effect(c)]

    if not executed and precondition_unavailable and not failed and not blocked:
        state = "precondition-unavailable"
    elif not executed and blocked and not failed and not precondition_unavailable:
        state = "gate-blocked"
    elif not executed and failed:
        state = "run-failed"
    elif effected:
        state = "executed-with-effect"
    elif executed:
        state = "executed-no-effect"
    elif blocked:
        state = "gate-blocked"
    else:
        state = "unexecuted"
    return {
        "execution_state": state,
        "declared_cell_count": len(cells),
        "executed_cell_count": len(executed),
        "failed_cell_count": len(failed),
        "gate_blocked_cell_count": len(blocked),
        "precondition_unavailable_count": len(precondition_unavailable),
        "effect_cell_count": len(effected),
    }


def _extract_s4_cells(payload: object, candidate_id: str) -> List[Dict]:
    """Accept the small set of persisted host-fallback result shapes."""
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("cells", "fallback_cells", "matrix_cells"):
        if isinstance(payload.get(key), list):
            return [x for x in payload[key] if isinstance(x, dict)]
    results = payload.get("results")
    if isinstance(results, dict) and isinstance(results.get(candidate_id), list):
        return [x for x in results[candidate_id] if isinstance(x, dict)]
    if isinstance(payload.get(candidate_id), list):
        return [x for x in payload[candidate_id] if isinstance(x, dict)]
    return []


def converge_s4_cells(workspace: Path, target: str, round_no: int,
                      candidate_id: str,
                      runner_cells: Optional[List[Dict]] = None) -> tuple:
    """Converge runner, persisted and host-fallback cells for one candidate.

    The matrix artifact is the source of truth.  A timeout from the host
    proxy/spawn channel is metadata about control flow, not evidence that S4
    did not execute.  Fallback files are intentionally additive and are
    deduplicated by their serialized cell content.
    """
    s4_dir = Path(workspace) / "state" / target / ("round-%02d" % round_no) / "S4"
    matrix_file = s4_dir / "matrix-runs" / candidate_id / "cells.json"
    candidates = []
    if runner_cells:
        candidates.append(("runner", runner_cells))
    if matrix_file.exists():
        try:
            candidates.append(("persisted", _extract_s4_cells(
                json.loads(matrix_file.read_text(encoding="utf-8")), candidate_id)))
        except (OSError, ValueError):
            pass
    if s4_dir.exists():
        for path in sorted(s4_dir.rglob("*.json")):
            name = path.name.lower()
            if "fallback" not in name and "sequential" not in name:
                continue
            try:
                cells = _extract_s4_cells(json.loads(path.read_text(encoding="utf-8")), candidate_id)
            except (OSError, ValueError):
                cells = []
            if cells:
                candidates.append(("fallback:%s" % path.name, cells))

    merged: List[Dict] = []
    seen = set()
    sources = []
    for source, cells in candidates:
        if not cells:
            continue
        sources.append(source)
        for cell in cells:
            try:
                key = json.dumps(cell, sort_keys=True, ensure_ascii=False)
            except (TypeError, ValueError):
                key = repr(cell)
            if key not in seen:
                seen.add(key)
                merged.append(cell)
    return merged, {"sources": sources, "persisted_matrix": str(matrix_file),
                    "proxy_timeout_does_not_override": True}


def summarize_candidate(cells: List[Dict]) -> Dict:
    """Derive runtime facts from a candidate's cell results (data-driven, no hard-coding)."""
    harness_errors = [c.get("harness_error", "") for c in cells if c.get("harness_error")]
    compile_errors = [c.get("compile_error", "") for c in cells if c.get("compile_error")]
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
    authz_results = []
    authz_boundary_violations = []

    def truthy(v: str) -> bool:
        # LLM-authored PoCs may emit INSTANTIATED=false / GATE_BLOCKED=none /
        # NETWORK=null; those are "not observed", never evidence.
        return str(v).strip().lower() not in ("", "false", "none", "null", "0")

    for c in cells:
        obs = c.get("observations", {})
        assertion = c.get("authz_assertion")
        if assertion is None and c.get("authz"):
            assertion = assert_authz_observations(c.get("authz"), obs)
        if assertion and assertion.get("status") != "not_applicable":
            item = {
                "version": c.get("version"), "safe": c.get("safe_mode"),
                "precondition": c.get("precondition"),
                "authz": normalize_authz_case(c.get("authz", {})),
                "status": assertion.get("status"),
                "boundary_violation": bool(assertion.get("boundary_violation")),
                "checks": assertion.get("checks", []),
                "missing": assertion.get("missing", []),
                "mismatch": assertion.get("mismatch", []),
            }
            authz_results.append(item)
            if item["boundary_violation"]:
                authz_boundary_violations.append(item)
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
    summary = {
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
        "authz_results": authz_results,
        "authz_boundary_violations": authz_boundary_violations,
        "cells_ran": len(cells),
    }
    if harness_errors:
        summary["harness_error"] = harness_errors[0]
    if compile_errors:
        summary["compile_error"] = compile_errors[0]
    summary.update(classify_s4_execution(cells))
    return summary
