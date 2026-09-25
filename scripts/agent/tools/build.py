"""Java PoC build + verification-matrix runner.

Runs `{version} x {safe-mode on/off} x {precondition}` cells for a candidate,
captures stdout/stderr per cell, and stores marker lines as untrusted PoC
claims. G4 consumes only harness-owned structured observations; a PoC cannot
confirm its own reported HTTP result, side effect, or target state.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from ..sandbox.approval import ApprovalGate
from ..sandbox.http_observer import LoopbackHTTPObserver, OBSERVER_VERSION
from ..sandbox.network_sandbox import (SEATBELT_DENY_ALL_POLICY,
                                       SEATBELT_POC_FILESYSTEM_POLICY,
                                       SEATBELT_PROXY_POLICY,
                                       verify_network_sandbox,
                                       wrap_network_command)
from ..sandbox.runner import (CommandRunner, RunResult, minimal_poc_env,
                              POC_RESOURCE_POLICY_VERSION,
                              POC_MAX_FILE_BYTES, POC_MAX_OPEN_FILES,
                              POC_MAX_PROCESS_SPAWN_DELTA,
                              POC_MAX_ADDRESS_SPACE_BYTES,
                              POC_MIN_ADDRESS_SPACE_BYTES,
                              POC_PROCESS_TREE_RSS_POLICY_VERSION,
                              POC_MAX_PROCESS_TREE_RSS_BYTES,
                              POC_PROCESS_TREE_SAMPLE_INTERVAL_SECONDS,
                              POC_SCRATCH_LIMIT_POLICY_VERSION,
                              POC_MAX_SCRATCH_BYTES,
                              POC_MAX_SCRATCH_ENTRIES,
                              POC_SCRATCH_SAMPLE_INTERVAL_SECONDS)
from ..evaluation.research_consistency_actions import (
    normalize_research_consistency_action,
    normalize_research_consistency_lane,
)
from .authz import (assert_authz_observations, authz_env, authz_fixture_id,
                    authz_jvm_props, normalize_authz_case)
from .evidence_policy import S4_EVIDENCE_POLICY_VERSION
from .experiment import (experiment_metadata, normalize_capability_contract,
                         normalize_experiment, normalize_residual_contracts,
                         sequence_trace_status)
from .surface_variants import normalize_variant_fixture_context


RUNNER_POLICY_VERSION = "static-egress-screen-v19-seatbelt-fs-read-allowlist-safe-path-explicit-java-home-process-tree-rss-watchdog-rlimit-as-scratch-watchdog-observer-direct-session-call-guard-timeout-cap-post-exit-group-reap-service-budget-abort"
JAVA_RUNNER_POLICY_VERSION = "static-egress-screen-v18-seatbelt-fs-read-allowlist-safe-path-explicit-java-home-process-tree-rss-watchdog-rlimit-as-scratch-watchdog-deny-all-direct-session-call-guard-timeout-cap-post-exit-group-reap-service-budget-abort"
POC_CLAIMS_SCHEMA = "poc-claims-v1"
HARNESS_OBSERVATIONS_SCHEMA = "harness-observations-v1"
MAX_S4_ROUND_TIMEOUT_SECONDS = 90 * 60
MAX_S4_CANDIDATE_TIMEOUT_SECONDS = 15 * 60


class S4ExecutionBudget:
    """Shared wall-clock budgets for one S4 round and each candidate."""

    def __init__(self, round_timeout_seconds: int = 5400,
                 candidate_timeout_seconds: int = 900):
        self.requested_round_timeout_seconds = max(1, int(round_timeout_seconds))
        self.requested_candidate_timeout_seconds = max(
            1, int(candidate_timeout_seconds))
        self.round_timeout_seconds = min(
            self.requested_round_timeout_seconds,
            MAX_S4_ROUND_TIMEOUT_SECONDS)
        self.candidate_timeout_seconds = min(
            self.requested_candidate_timeout_seconds,
            MAX_S4_CANDIDATE_TIMEOUT_SECONDS)
        self.started_at = time.monotonic()
        self.round_deadline = self.started_at + self.round_timeout_seconds
        self._candidate_deadlines: Dict[str, float] = {}
        self._abort_event = threading.Event()
        self.abort_reason = ""

    @property
    def abort_event(self) -> threading.Event:
        return self._abort_event

    def abort(self, reason: str) -> None:
        if self._abort_event.is_set():
            return
        self.abort_reason = str(reason or "s4-aborted")[:160]
        self._abort_event.set()

    def deadline_for(self, candidate_id: str) -> float:
        key = str(candidate_id)
        if key not in self._candidate_deadlines:
            self._candidate_deadlines[key] = min(
                self.round_deadline,
                time.monotonic() + self.candidate_timeout_seconds)
        return self._candidate_deadlines[key]

    def remaining(self, candidate_id: str) -> float:
        if self._abort_event.is_set():
            return 0.0
        return max(0.0, min(self.round_deadline,
                            self.deadline_for(candidate_id)) - time.monotonic())

    def round_remaining(self) -> float:
        if self._abort_event.is_set():
            return 0.0
        return max(0.0, self.round_deadline - time.monotonic())

    def exhausted(self, candidate_id: str) -> bool:
        return self.remaining(candidate_id) < 1.0

    def stop_reason(self, candidate_id: str) -> str:
        if self._abort_event.is_set():
            return self.abort_reason or "s4-aborted"
        if self.round_remaining() < 1.0:
            return "s4-round-timebox-exhausted"
        return "candidate-timebox-exhausted:%s" % candidate_id

    def snapshot(self) -> Dict[str, Any]:
        now = time.monotonic()
        round_remaining = self.round_remaining()
        expired = sorted(key for key, deadline in self._candidate_deadlines.items()
                         if deadline - now < 1.0)
        return {
            "requested_round_timeout_seconds": self.requested_round_timeout_seconds,
            "requested_candidate_timeout_seconds": self.requested_candidate_timeout_seconds,
            "round_timeout_seconds": self.round_timeout_seconds,
            "candidate_timeout_seconds": self.candidate_timeout_seconds,
            "round_timeout_capped": (
                self.requested_round_timeout_seconds > self.round_timeout_seconds),
            "candidate_timeout_capped": (
                self.requested_candidate_timeout_seconds > self.candidate_timeout_seconds),
            "elapsed_seconds": round(now - self.started_at, 3),
            "round_remaining_seconds": round(round_remaining, 3),
            "round_exhausted": round_remaining < 1.0,
            "aborted": self._abort_event.is_set(),
            "abort_reason": self.abort_reason,
            "candidates_started": len(self._candidate_deadlines),
            "candidate_timeboxes_exhausted": expired,
        }


def _bounded_timeout(budget: Optional[S4ExecutionBudget], candidate_id: str,
                     requested: Optional[int], default: int) -> Optional[int]:
    if budget is None:
        return requested
    remaining = budget.remaining(candidate_id)
    if remaining < 1.0:
        return None
    requested_seconds = max(1, int(requested or default))
    return max(1, min(requested_seconds, int(remaining)))


def _budget_key(spec: Any) -> str:
    return str(getattr(spec, "budget_key", "") or
               getattr(spec, "candidate_id", ""))


LOOPBACK_OK = {"127.0.0.1", "localhost", "[::1]", "::1"}

_URL_SCHEME = re.compile(
    r"\b(?:jar|http|https|ftp|ldap|ldaps|rmi|dns|file|tcp|udp|jdbc|nhttp|"
    r"dnslog|gopher)://(\[[0-9a-f:.]+\]|[^/\"'\s:]+)", re.I)
_IP_LITERAL = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_REMOTE_TOOL = re.compile(
    r"\b(?:ssh|scp|sftp|telnet|rlogin|rsync|kubectl|docker|podman|aliyun|aws|gcloud)\b",
    re.I,
)
_WILDCARD_BIND = re.compile(
    r"\b(?:bind|listen)\s*\(\s*(?:\(\s*)?[\"'](?:[\"']|0\.0\.0\.0|::)[\"']",
    re.I | re.S)
_ANY_ADDRESS = re.compile(r"\b(?:INADDR_ANY|in6addr_any)\b", re.I)
_NETWORK_PRIMITIVE = re.compile(
    r"\b(?:ServerSocket|DatagramSocket|Socket|SocketChannel|HttpClient|"
    r"HttpURLConnection|URLConnection|InitialContext|NamingContext|"
    r"InetAddress|openConnection|openStream|create_connection|socket|requests|"
    r"urllib|httpx|aiohttp|curl|wget|socat|ncat)\b", re.I)
_SAFE_PATH_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


def _safe_component(value: Any, label: str) -> str:
    text = str(value or "")
    if not _SAFE_PATH_COMPONENT.fullmatch(text):
        raise ValueError("%s must be a path-safe identifier" % label)
    return text


def _contained_path(root: Path, relative: Any, label: str,
                    allow_absolute: bool = False) -> Path:
    """Resolve a manifest path under its authorized root, including symlinks."""
    raw = str(relative or "")
    candidate_rel = Path(raw)
    if (not raw or (candidate_rel.is_absolute() and not allow_absolute)
            or "\\" in raw
            or ".." in candidate_rel.parts):
        raise ValueError("%s must be a relative path without traversal" % label)
    resolved_root = Path(root).resolve()
    resolved = (candidate_rel if candidate_rel.is_absolute()
                else resolved_root / candidate_rel).resolve()
    if not resolved.is_relative_to(resolved_root):
        raise ValueError("%s escapes its authorized root" % label)
    return resolved


def scan_source_egress(src_text: str, src_path: str = "",
                       allowed_hosts: Optional[set] = None,
                       declared_targets: Optional[List[str]] = None) -> List[str]:
    """Static source screening for known network and remote-exec targets.

    Finds literal non-loopback network targets and obvious wildcard listeners
    before compilation. This is a source check, not an OS network sandbox;
    dynamic or indirect system calls still require a supported isolation layer.
    """
    bad: List[str] = []
    if _REMOTE_TOOL.search(src_text):
        bad.append("remote/cloud execution primitive (line ~%d)" % (
            src_text.count("\n", 0, _REMOTE_TOOL.search(src_text).start()) + 1))
    if _WILDCARD_BIND.search(src_text):
        bad.append("wildcard or empty-address listener (0.0.0.0/::/empty host)")
    if _ANY_ADDRESS.search(src_text):
        bad.append("wildcard listener address INADDR_ANY/in6addr_any")
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
    target_text = "\n".join([src_text] + [str(item) for item in
                                          (declared_targets or [])])
    target_hosts = set()
    for match in _URL_SCHEME.finditer(target_text):
        target_hosts.add(match.group(1).strip().lower().rstrip("."))
    target_hosts.update(_IP_LITERAL.findall(target_text))
    if re.search(r"\blocalhost\b", target_text, re.I):
        target_hosts.add("localhost")
    explicit_target = False
    for host in target_hosts:
        if host in (allowed_hosts or set()):
            explicit_target = True
            break
        try:
            explicit_target = ipaddress.ip_address(host.strip("[]")).is_loopback
        except ValueError:
            explicit_target = host in {"localhost", "localhost.localdomain"}
        if explicit_target:
            break
    if _NETWORK_PRIMITIVE.search(src_text) and not explicit_target:
        bad.append("network-capable code has no explicit loopback or allowlisted target")
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
    # Bounded stateful/race experiment declaration.  The PoC owns the actual
    # local requests and transitions; the runner exposes only these identifiers
    # and persists the declaration with the observed cell evidence.
    sequence: List[str] = field(default_factory=list)
    concurrency: int = 1
    availability_probe: bool = False
    # Bounded capability-chain contract.  This is an observation checklist,
    # never proof that a primitive or transition exists.
    capability_contract: Dict[str, Any] = field(default_factory=dict)
    # S3 residual closure checklist; also never proof that a residual exists.
    residual_contracts: List[Dict[str, Any]] = field(default_factory=list)
    # Surface-specific fixture/state-machine context.  This is a bounded
    # experiment identity, never a payload or a runtime observation.
    variant_context: Dict[str, Any] = field(default_factory=dict)
    # Cross-round contradiction recheck contract.  This is scheduling
    # metadata only; it is not an observation or a finding.
    consistency_action: Dict[str, Any] = field(default_factory=dict)
    # The runtime lab materializes the action's paired lane here.  The label
    # is only an execution selector; the PoC must still emit observations.
    consistency_lane: str = ""
    experiment_warnings: List[str] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        (self.sequence, self.concurrency, self.availability_probe,
         self.experiment_warnings) = normalize_experiment(
            self.sequence, self.concurrency, self.availability_probe)
        self.capability_contract = normalize_capability_contract(
            self.capability_contract)
        self.residual_contracts = normalize_residual_contracts(
            self.residual_contracts)
        self.variant_context = normalize_variant_fixture_context(
            self.variant_context)
        self.consistency_action = normalize_research_consistency_action(
            self.consistency_action)
        self.consistency_lane = normalize_research_consistency_lane(
            self.consistency_lane)


def _cell_experiment_env(cell: MatrixCell) -> Dict[str, str]:
    """Expose only bounded experiment metadata to a PoC process."""
    contract = normalize_capability_contract(cell.capability_contract)
    env = {
        "VULNGATE_SEQUENCE": json.dumps(cell.sequence, ensure_ascii=False),
        "VULNGATE_CONCURRENCY": str(cell.concurrency),
        "VULNGATE_AVAILABILITY_PROBE": (
            "true" if cell.availability_probe else "false"),
        "VULNGATE_CAPABILITY_CONTRACT": json.dumps(
            contract, ensure_ascii=False, separators=(",", ":")),
        "VULNGATE_CAPABILITIES": json.dumps(
            contract.get("required_capabilities", []), ensure_ascii=False),
        "VULNGATE_OBSERVED_CAPABILITIES": json.dumps(
            contract.get("observed_capabilities", []), ensure_ascii=False),
        "VULNGATE_MISSING_CAPABILITIES": json.dumps(
            contract.get("missing_capabilities", []), ensure_ascii=False),
        "VULNGATE_TRANSITIONS": json.dumps(
            contract.get("transition_rules", []), ensure_ascii=False),
        "VULNGATE_RESIDUAL_CONTRACT": json.dumps(
            normalize_residual_contracts(cell.residual_contracts),
            ensure_ascii=False, separators=(",", ":")),
        "VULNGATE_RESIDUAL_IDS": json.dumps([
            row["residual_id"] for row in
            normalize_residual_contracts(cell.residual_contracts)
        ], ensure_ascii=False),
        "VULNGATE_CONSISTENCY_ACTION": json.dumps(
            normalize_research_consistency_action(cell.consistency_action),
            ensure_ascii=False, separators=(",", ":")),
        "VULNGATE_CONSISTENCY_LANE": cell.consistency_lane,
    }
    variant = normalize_variant_fixture_context(cell.variant_context)
    if variant:
        env.update({
            "VULNGATE_VARIANT_SURFACE": variant["surface"],
            "VULNGATE_VARIANT_ID": variant["variant_id"],
            "VULNGATE_VARIANT_LANE": variant["lane"],
            "VULNGATE_VARIANT_FIXTURE": variant["fixture_key"],
            "VULNGATE_VARIANT_FAMILY": variant["family"],
            "VULNGATE_VARIANT_STATE_STEPS": json.dumps(
                variant["state_steps"], ensure_ascii=False),
            "VULNGATE_VARIANT_OBSERVATIONS": json.dumps(
                variant["required_observations"], ensure_ascii=False),
            "VULNGATE_VARIANT_FALSIFIERS": json.dumps(
                variant["falsifiers"], ensure_ascii=False),
        })
    return env


def _cell_metadata(cell: MatrixCell) -> Dict[str, Any]:
    """Common persisted metadata for Java and Shell cells."""
    meta = experiment_metadata(cell)
    return {
        "sequence": meta["sequence"],
        "concurrency": meta["concurrency"],
        "availability_probe": meta["availability_probe"],
        "authz_fixture_id": authz_fixture_id(cell.authz),
        "capability_contract": meta["capability_contract"],
        "residual_contracts": meta["residual_contracts"],
        "variant_context": normalize_variant_fixture_context(
            cell.variant_context),
        "consistency_action": normalize_research_consistency_action(
            cell.consistency_action),
        "consistency_lane": normalize_research_consistency_lane(
            cell.consistency_lane),
        "experiment": meta,
    }


def _stoploss_cell(candidate_id: str, cell: MatrixCell,
                   budget: S4ExecutionBudget, lang: str,
                   budget_key: Optional[str] = None) -> Dict[str, Any]:
    """Persist an unexecuted matrix cell when its bounded S4 budget expires."""
    result = {
        "candidate_id": candidate_id,
        "version": cell.version,
        "safe_mode": cell.safe_mode,
        "features": list(cell.features),
        "precondition": cell.precondition,
        "returncode": None,
        "timed_out": False,
        "duration_ms": 0,
        "observations": {},
        "poc_claims": {},
        "policy_status": "stop-loss",
        "stop_reason": budget.stop_reason(budget_key or candidate_id),
        "lang": lang,
        "claim_status": "not-a-finding",
    }
    result.update(_cell_metadata(cell))
    return result


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
    budget_key: str = ""


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


def parse_poc_claims(stdout: str, stderr: str = "") -> Dict[str, Any]:
    """Parse PoC output as claims, never as independent runtime observations.

    A PoC controls its own stdout/stderr, so even well-formed marker lines are
    not evidence that an HTTP response, side effect, or target state was
    observed. Preserve them for analyst review while keeping them out of the
    observation contract consumed by G4.
    """
    fields: Dict[str, List[str]] = {}
    combined = stdout + "\n" + stderr

    def add(key: str, value: str) -> None:
        values = fields.setdefault(key, [])
        if len(values) < 32:
            values.append(value[:240])

    for line in combined.splitlines():
        for source_key, trace_key in (
                ("STEP", "STEP_TRACE"),
                ("STEP_EVIDENCE", "STEP_EVIDENCE"),
                ("STATE", "STATE_TRACE"),
                ("CAPABILITY", "CAPABILITY_TRACE"),
                ("CAPABILITY_EVIDENCE", "CAPABILITY_EVIDENCE"),
                ("TRANSITION", "TRANSITION_TRACE"),
                ("TRANSITION_EVIDENCE", "TRANSITION_EVIDENCE")):
            if line.startswith(source_key + "="):
                add(trace_key, line[len(source_key) + 1:])
                break
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
                    "JDK8_RUNTIME_ACTIVE", "RESIDUAL_ID", "RESIDUAL_STATUS",
                    "RESIDUAL_FALSIFIER"):
            if line.startswith(key + "="):
                add(key, line[len(key) + 1:])
    if "ERROR" not in fields:
        m = re.search(r"(OutOfMemoryError|StackOverflowError|SQLException|JSONException"
                      r"|ArrayIndexOutOfBoundsException|DateTimeException|"
                      r"NegativeArraySizeException|NumberFormatException|IllegalArgument\w*)",
                      combined)
        if m:
            add("RUNTIME_ERROR_PATTERN", m.group(1))
    if "ENV_ERROR" not in fields:
        m = ENV_ERROR_PATTERN.search(combined)
        if m:
            add("ENV_ERROR_PATTERN", m.group(1))
    return {"schema_version": POC_CLAIMS_SCHEMA,
            "source": "poc-stdout-stderr",
            "fields": fields}


def parse_observations(stdout: str, stderr: str = "") -> Dict[str, Any]:
    """Deprecated compatibility alias; parsed output is explicitly a claim."""
    return parse_poc_claims(stdout, stderr)


def _trusted_observations(cell: Dict[str, Any]) -> Dict[str, Any]:
    """Read only validated observations emitted by a supported collector."""
    provenance = cell.get("observation_provenance") or {}
    if not isinstance(provenance, dict):
        return {}
    capture_scope = provenance.get("capture_scope")
    network_isolation = cell.get("network_isolation")
    resource_limits = cell.get("resource_limits")
    scratch_limits = cell.get("scratch_limits")
    process_tree_limits = (resource_limits.get("process_tree_rss")
                           if isinstance(resource_limits, dict) else None)
    process_tree_limits_valid = (
        isinstance(process_tree_limits, dict)
        and process_tree_limits.get("policy") ==
        POC_PROCESS_TREE_RSS_POLICY_VERSION
        and process_tree_limits.get("status") == "completed"
        and type(process_tree_limits.get("max_bytes")) is int
        and process_tree_limits.get("max_bytes") ==
        POC_MAX_PROCESS_TREE_RSS_BYTES
        and type(process_tree_limits.get("sample_interval_ms")) is int
        and process_tree_limits.get("sample_interval_ms") ==
        int(POC_PROCESS_TREE_SAMPLE_INTERVAL_SECONDS * 1000)
        and type(process_tree_limits.get("peak_rss_bytes")) is int
        and 0 <= process_tree_limits["peak_rss_bytes"] <=
        POC_MAX_PROCESS_TREE_RSS_BYTES
        and type(process_tree_limits.get("peak_process_count")) is int
        and process_tree_limits["peak_process_count"] >= 1
        and type(process_tree_limits.get("sample_count")) is int
        and process_tree_limits["sample_count"] >= 1
        and type(process_tree_limits.get("tracked_process_count")) is int
        and process_tree_limits["tracked_process_count"] >= 1
        and process_tree_limits.get("cleanup_status") == "complete")
    resource_limits_valid = (
        isinstance(resource_limits, dict)
        and resource_limits.get("policy") == POC_RESOURCE_POLICY_VERSION
        and type(resource_limits.get("cpu_seconds_per_process")) is int
        and 1 <= resource_limits["cpu_seconds_per_process"] <= 3600
        and type(resource_limits.get("max_address_space_bytes")) is int
        and POC_MIN_ADDRESS_SPACE_BYTES <=
        resource_limits["max_address_space_bytes"] <= POC_MAX_ADDRESS_SPACE_BYTES
        and type(resource_limits.get("max_file_bytes")) is int
        and resource_limits.get("max_file_bytes") == POC_MAX_FILE_BYTES
        and type(resource_limits.get("max_open_files")) is int
        and resource_limits.get("max_open_files") == POC_MAX_OPEN_FILES
        and type(resource_limits.get("user_process_baseline")) is int
        and type(resource_limits.get("max_user_processes")) is int
        and resource_limits["max_user_processes"] >
        resource_limits["user_process_baseline"]
        and resource_limits["max_user_processes"] -
        resource_limits["user_process_baseline"] <= POC_MAX_PROCESS_SPAWN_DELTA
        and type(resource_limits.get("core_bytes")) is int
        and resource_limits.get("core_bytes") == 0
        and process_tree_limits_valid
        and provenance.get("resource_limits") == resource_limits)
    scratch_limits_valid = (
        isinstance(scratch_limits, dict)
        and scratch_limits.get("policy") == POC_SCRATCH_LIMIT_POLICY_VERSION
        and scratch_limits.get("status") == "completed"
        and type(scratch_limits.get("max_bytes")) is int
        and scratch_limits.get("max_bytes") == POC_MAX_SCRATCH_BYTES
        and type(scratch_limits.get("max_entries")) is int
        and scratch_limits.get("max_entries") == POC_MAX_SCRATCH_ENTRIES
        and type(scratch_limits.get("sample_interval_ms")) is int
        and scratch_limits.get("sample_interval_ms") ==
        int(POC_SCRATCH_SAMPLE_INTERVAL_SECONDS * 1000)
        and type(scratch_limits.get("peak_bytes")) is int
        and 0 <= scratch_limits["peak_bytes"] <= POC_MAX_SCRATCH_BYTES
        and type(scratch_limits.get("peak_entries")) is int
        and 0 <= scratch_limits["peak_entries"] <= POC_MAX_SCRATCH_ENTRIES
        and cell.get("resource_limit_exceeded") == ""
        and provenance.get("scratch_limits") == scratch_limits
        and provenance.get("resource_limit_exceeded") == "")
    capture_policy_valid = (
        (capture_scope == "seatbelt-host-local-port"
         and network_isolation == SEATBELT_PROXY_POLICY
         and cell.get("filesystem_isolation") == SEATBELT_POC_FILESYSTEM_POLICY
         and provenance.get("filesystem_isolation") ==
         SEATBELT_POC_FILESYSTEM_POLICY
         and resource_limits_valid
         and scratch_limits_valid
         and cell.get("runner_policy") == RUNNER_POLICY_VERSION)
    )
    if (not isinstance(provenance, dict)
            or provenance.get("schema_version") != HARNESS_OBSERVATIONS_SCHEMA
            or provenance.get("producer") != "vulngate-harness"
            or provenance.get("collector_version") != OBSERVER_VERSION
            or not capture_policy_valid
            or provenance.get("network_isolation") != network_isolation
            or provenance.get("candidate_id") != cell.get("candidate_id")
            or provenance.get("cell_id") != cell.get("cell_id")
            or provenance.get("returncode") != cell.get("returncode")
            or provenance.get("timed_out") != cell.get("timed_out")):
        return {}
    for field in ("run_id", "cell_id", "source_digest", "target_digest"):
        value = str(provenance.get(field, ""))
        if field == "run_id":
            try:
                if str(uuid.UUID(value)) != value:
                    return {}
            except (ValueError, AttributeError):
                return {}
        elif not re.fullmatch(r"[0-9a-f]{64}", value):
            return {}
    features = cell.get("features", [])
    args = cell.get("args", [])
    if not isinstance(features, list) or not isinstance(args, list):
        return {}
    cell_identity = {
        "candidate_id": cell.get("candidate_id"),
        "version": cell.get("version"),
        "safe_mode": cell.get("safe_mode"),
        "precondition": cell.get("precondition"),
        "features": features,
        "args": args,
        "source_digest": provenance["source_digest"],
        "target_digest": provenance["target_digest"],
        "authz_fixture_id": cell.get("authz_fixture_id"),
    }
    expected_cell_id = hashlib.sha256(json.dumps(
        cell_identity, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")).hexdigest()
    if expected_cell_id != provenance.get("cell_id"):
        return {}
    observations = cell.get("observations")
    if not isinstance(observations, dict) or set(observations) - {
            "HTTP_CODE", "HTTP_RESPONSES"}:
        return {}
    responses = observations.get("HTTP_RESPONSES")
    if not isinstance(responses, list) or len(responses) > 256:
        return {}
    allowed_methods = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
    request_ids = []
    for row in responses:
        if (not isinstance(row, dict)
                or row.get("kind") != "http-response"
                or row.get("method") not in allowed_methods
                or type(row.get("request_id")) is not int
                or row["request_id"] < 1
                or type(row.get("status")) is not int
                or not 100 <= row["status"] <= 599
                or type(row.get("response_bytes")) is not int
                or row["response_bytes"] < 0
                or not isinstance(row.get("body_complete"), bool)
                or not isinstance(row.get("response_truncated"), bool)
                or (row.get("response_truncated") and row.get("body_complete"))
                or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("request_digest", "")))
                or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("response_body_sha256", "")))):
            return {}
        request_ids.append(row["request_id"])
    if len(request_ids) != len(set(request_ids)):
        return {}
    if (type(provenance.get("response_count")) is not int
            or provenance.get("response_count") != len(responses)
            or not isinstance(provenance.get("observer_gaps"), list)
            or any(not isinstance(gap, str) or not gap
                   for gap in provenance.get("observer_gaps", []))):
        return {}
    gaps = provenance["observer_gaps"]
    expected_code = (str(responses[0]["status"])
                     if len(responses) == 1 and not gaps else None)
    if observations.get("HTTP_CODE") != expected_code:
        return {}
    return observations


def _cell_poc_claims(cell: Dict[str, Any]) -> Dict[str, Any]:
    """Return explicitly untrusted claims, including legacy marker artifacts."""
    claims = cell.get("poc_claims")
    if isinstance(claims, dict) and isinstance(claims.get("fields"), dict):
        return claims
    if _trusted_observations(cell):
        return {}
    # Older cells stored PoC marker output directly under `observations`.
    # Treat it as claims until a harness-native observation producer exists.
    legacy = cell.get("observations")
    if isinstance(legacy, dict) and legacy:
        return {"schema_version": "legacy-observations-as-claims-v1",
                "source": "legacy-cell-observations",
                "fields": {str(key): (value if isinstance(value, list) else [value])
                           for key, value in legacy.items()}}
    return {}


class JavaMatrixRunner:
    def __init__(self, workspace: Path, target: str, round_no: int,
                 approval: Optional[ApprovalGate] = None,
                 authorized_staging: bool = False,
                 staging_hosts: Optional[List[str]] = None,
                 execution_budget: Optional[S4ExecutionBudget] = None):
        self.workspace = workspace.resolve()
        self.target = _safe_component(target, "target")
        self.round_no = int(round_no)
        if self.round_no < 1:
            raise ValueError("round must be a positive integer")
        self.approval = approval or ApprovalGate()
        self.authorized_staging = authorized_staging
        self.execution_budget = execution_budget or S4ExecutionBudget()
        self.staging_hosts = {str(h).strip().lower().rstrip(".") for h in (staging_hosts or [])}
        self.runner = CommandRunner(workspace, approval, authorized_staging=authorized_staging,
                                    staging_hosts=list(self.staging_hosts),
                                    execution_budget=self.execution_budget)
        round_dir = "round-%02d" % self.round_no
        self.src_dir = _contained_path(
            self.workspace, "poc/%s/%s/src" % (self.target, round_dir),
            "PoC source directory")
        self.out_dir = _contained_path(
            self.workspace, "poc/%s/%s/out" % (self.target, round_dir),
            "PoC output directory")
        self.matrix_dir = _contained_path(
            self.workspace, "state/%s/%s/S4/matrix-runs" % (self.target, round_dir),
            "S4 matrix directory")
        self._network_sandbox_result: Optional[tuple] = None

    def _network_sandbox(self) -> tuple:
        if self._network_sandbox_result is None:
            self._network_sandbox_result = verify_network_sandbox()
        return self._network_sandbox_result

    def _requires_network_observer(self, spec: POCSpec) -> bool:
        for source_name in [spec.src] + list(spec.extra_srcs):
            source = _contained_path(self.src_dir, source_name, "Java PoC source")
            try:
                if _NETWORK_PRIMITIVE.search(
                        source.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                continue
        return False

    @staticmethod
    def _policy_cell(spec: POCSpec, cell: MatrixCell, status: str,
                     reason: str, network_isolation: str) -> Dict[str, Any]:
        result = {
            "candidate_id": spec.candidate_id,
            "poc_class": spec.class_name,
            "version": cell.version,
            "safe_mode": cell.safe_mode,
            "features": cell.features,
            "precondition": cell.precondition,
            "required_runtime": cell.required_runtime,
            "authz": normalize_authz_case(cell.authz),
            "returncode": None,
            "timed_out": False,
            "duration_ms": 0,
            "observations": {},
            "poc_claims": {},
            "network_isolation": network_isolation,
            "policy_status": status,
            "harness_error": reason[:400],
            "observation_gaps": ["os-network-isolation-unavailable"],
            "runner_policy": JAVA_RUNNER_POLICY_VERSION,
        }
        result.update(_cell_metadata(cell))
        return result

    # ------------------------------------------------------------------
    def compile(self, spec: POCSpec, version: str, jars: List[Path],
                runtime: Optional[Dict[str, str]] = None,
                timeout: Optional[int] = None) -> RunResult:
        version = _safe_component(version, "version")
        out = _contained_path(self.out_dir, version, "Java PoC output directory")
        out.mkdir(parents=True, exist_ok=True)
        src_file = _contained_path(self.src_dir, spec.src, "Java PoC source")
        if not src_file.exists():
            raise FileNotFoundError(
                "PoC source missing: %s (stage PoCs into %s first)" % (src_file, self.src_dir))
        safe_jars = [_contained_path(self.workspace, jar, "dependency jar",
                                     allow_absolute=True)
                     for jar in jars]
        cp = ":".join(str(j) for j in safe_jars)
        files = [str(src_file)] + [str(_contained_path(
            self.src_dir, source, "Java extra source")) for source in spec.extra_srcs]
        # Baseline fix #4: source-level egress screen before javac. Any explicit
        # non-loopback URL/IP literal blocks the build and is recorded.
        egress = []
        declared_targets = [str(arg) for cell in spec.cells
                            if cell.version == version for arg in cell.args]
        for f in files:
            try:
                text = Path(f).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            egress += scan_source_egress(
                text, f,
                self.staging_hosts if self.authorized_staging else None,
                declared_targets)
        if egress:
            detail = "PoC 源码未满足网络执行边界: %s" % "; ".join(sorted(set(egress))[:6])
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
        readable_roots = ([Path(runtime["java_home"])]
                          if runtime.get("java_home") else [])
        policy, error = verify_network_sandbox(
            filesystem_workspace=self.workspace,
            readable_paths=readable_roots, writable_paths=[out])
        if error or policy != SEATBELT_DENY_ALL_POLICY:
            return RunResult(cmd=cmd, returncode=-5, stdout="",
                             stderr="NETWORK_ISOLATION_UNAVAILABLE " +
                             (error or "unexpected network policy: %s" % policy),
                             duration_ms=0)
        isolated_cmd, wrapped_policy = wrap_network_command(
            cmd, filesystem_workspace=self.workspace,
            readable_paths=readable_roots, writable_paths=[out])
        if wrapped_policy != SEATBELT_DENY_ALL_POLICY:
            return RunResult(cmd=cmd, returncode=-5, stdout="",
                             stderr="NETWORK_ISOLATION_UNAVAILABLE invalid policy",
                             duration_ms=0)
        scratch_env = {
            "HOME": str(out), "TMPDIR": str(out), "TMP": str(out),
            "TEMP": str(out), "VULNGATE_SCRATCH_DIR": str(out),
            "JAVA_HOME": runtime.get("java_home", ""),
        }
        return self.runner.run(isolated_cmd, cwd=self.src_dir,
                               env_extra=scratch_env, minimal_env=True,
                               restrict_poc_path=True,
                               timeout=timeout)

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
            "observations": {}, "poc_claims": {},
            "policy_status": "precondition-unavailable",
            "harness_error": runtime.get("reason", "java runtime unavailable"),
            "precondition_status": RUNTIME_UNAVAILABLE,
            "stderr": runtime.get("reason", "java runtime unavailable"),
            "cmd": "",
            "runner_policy": JAVA_RUNNER_POLICY_VERSION,
        }
        result.update(_cell_metadata(cell))
        result.update(self._runtime_fields(runtime))
        return result

    def run_cell(self, spec: POCSpec, cell: MatrixCell, jars: List[Path],
                 runtime: Optional[Dict[str, str]] = None,
                 timeout: Optional[int] = None) -> Dict:
        _safe_component(spec.candidate_id, "candidate_id")
        budget_id = _budget_key(spec)
        timeout = _bounded_timeout(self.execution_budget, budget_id,
                                   timeout if timeout is not None else cell.timeout,
                                   self.runner.default_timeout)
        if timeout is None:
            stopped = _stoploss_cell(spec.candidate_id, cell,
                                      self.execution_budget, "java", budget_id)
            stopped["poc_class"] = spec.class_name
            return stopped
        runtime = runtime or resolve_java_runtime(cell)
        if runtime.get("available") != "true":
            return self._unavailable_cell(spec, cell, runtime)
        policy, sandbox_error = self._network_sandbox()
        if sandbox_error or policy != SEATBELT_DENY_ALL_POLICY:
            denied = self._policy_cell(
                spec, cell, "needs-network-isolation",
                sandbox_error or "unexpected network policy: %s" % policy,
                policy)
            denied.update(self._runtime_fields(runtime))
            return denied
        if self._requires_network_observer(spec):
            denied = self._policy_cell(
                spec, cell, "needs-harness-observer",
                "Java PoC uses network APIs, but the Java runner has no "
                "independent loopback protocol observer",
                SEATBELT_DENY_ALL_POLICY)
            denied["observation_gaps"] = ["java-network-observer-unavailable"]
            denied.update(self._runtime_fields(runtime))
            return denied
        version = _safe_component(cell.version, "version")
        out = _contained_path(self.out_dir, version, "Java PoC output directory")
        out.mkdir(parents=True, exist_ok=True)
        safe_jars = [_contained_path(self.workspace, jar, "dependency jar",
                                     allow_absolute=True)
                     for jar in jars]
        cp = ":".join([str(j) for j in safe_jars] + [str(out)])
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
        readable_roots = ([Path(runtime["java_home"])]
                          if runtime.get("java_home") else [])
        policy, sandbox_error = verify_network_sandbox(
            filesystem_workspace=self.workspace,
            readable_paths=readable_roots, writable_paths=[out])
        if sandbox_error or policy != SEATBELT_DENY_ALL_POLICY:
            denied = self._policy_cell(
                spec, cell, "needs-network-isolation",
                sandbox_error or "unexpected network policy: %s" % policy,
                policy)
            denied.update(self._runtime_fields(runtime))
            return denied
        isolated_cmd, wrapped_policy = wrap_network_command(
            java_cmd, filesystem_workspace=self.workspace,
            readable_paths=readable_roots, writable_paths=[out])
        if wrapped_policy != SEATBELT_DENY_ALL_POLICY:
            denied = self._policy_cell(
                spec, cell, "needs-network-isolation",
                "failed to construct deny-all network profile",
                wrapped_policy)
            denied.update(self._runtime_fields(runtime))
            return denied
        try:
            result = self.runner.run(
                isolated_cmd,
                cwd=out,
                env_extra=dict(_cell_experiment_env(cell), HOME=str(out),
                               TMPDIR=str(out), TMP=str(out), TEMP=str(out),
                               JAVA_HOME=runtime.get("java_home", ""),
                               VULNGATE_SCRATCH_DIR=str(out)),
                operation="loopback_connect",
                operation_detail="mechanism-level PoC %s (Java network access denied by runner policy)" % spec.class_name,
                timeout=timeout if timeout is not None else cell.timeout,
            )
        except PermissionError as exc:
            denied = {
                "candidate_id": spec.candidate_id, "poc_class": spec.class_name,
                "version": cell.version, "safe_mode": cell.safe_mode,
                "features": cell.features, "precondition": cell.precondition,
                "required_runtime": cell.required_runtime,
                "authz": normalize_authz_case(cell.authz),
                "returncode": -3, "timed_out": False, "duration_ms": 0,
                "observations": {}, "poc_claims": {},
                "policy_status": "blocked",
                "harness_error": "policy_denied: %s" % exc,
                "stderr": str(exc), "cmd": " ".join(java_cmd),
                "runner_policy": JAVA_RUNNER_POLICY_VERSION,
            }
            denied.update(_cell_metadata(cell))
            denied.update(self._runtime_fields(runtime))
            return denied
        poc_claims = parse_poc_claims(result.stdout, result.stderr)
        obs: Dict[str, Any] = {}
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
            "runner_timeout_seconds": result.timeout_seconds,
            "runner_timeout_capped": result.timeout_capped,
            "observations": obs,
            "poc_claims": poc_claims,
            "observation_provenance": {
                "schema_version": POC_CLAIMS_SCHEMA,
                "producer": "poc-stdout-stderr",
                "trust": "untrusted-claim",
            },
            "authz_assertion": authz_assertion,
            "stdout": result.stdout,
            "stderr": result.stderr[-4000:],
            "cmd": " ".join(java_cmd),
            "network_isolation": SEATBELT_DENY_ALL_POLICY,
            "filesystem_isolation": SEATBELT_POC_FILESYSTEM_POLICY,
            "resource_limits": result.resource_limits,
            "scratch_limits": result.scratch_limits,
            "process_tree_cleanup": result.process_tree_cleanup,
            "resource_limit_exceeded": result.resource_limit_exceeded,
            "abort_reason": result.abort_reason,
            "policy_status": ("resource-limit-exceeded"
                              if result.resource_limit_exceeded else
                              "aborted" if result.abort_reason else "allowed"),
            "runner_policy": JAVA_RUNNER_POLICY_VERSION,
        }
        if result.resource_limit_exceeded:
            result_payload["harness_error"] = (
                "PoC resource watchdog stopped or invalidated the run: %s" %
                result.resource_limit_exceeded)
        if result.abort_reason:
            result_payload["harness_error"] = (
                "S4 run aborted by shared stop-loss: %s" % result.abort_reason)
            result_payload["stop_reason"] = result.abort_reason
        elif result.timed_out and self.execution_budget.exhausted(budget_id):
            result_payload["stop_reason"] = self.execution_budget.stop_reason(
                budget_id)
        result_payload.update(_cell_metadata(cell))
        result_payload.update(self._runtime_fields(runtime))
        return result_payload

    def run_manifest(self, specs: List[POCSpec], jars_by_version: Dict[str, List[Path]]) -> Dict[str, List[Dict]]:
        """Run every cell of every spec; return {candidate_id: [cell results]}."""
        all_results: Dict[str, List[Dict]] = {}
        for spec in specs:
            _safe_component(spec.candidate_id, "candidate_id")
            results = []
            budget_id = _budget_key(spec)
            self.execution_budget.deadline_for(budget_id)
            sandbox_policy, sandbox_error = self._network_sandbox()
            if sandbox_error or sandbox_policy != SEATBELT_DENY_ALL_POLICY:
                reason = sandbox_error or "unexpected network policy: %s" % sandbox_policy
                results = [self._policy_cell(
                    spec, cell, "needs-network-isolation", reason, sandbox_policy)
                    for cell in spec.cells]
                all_results.setdefault(spec.candidate_id, []).extend(results)
                continue
            if self._requires_network_observer(spec):
                results = [self._policy_cell(
                    spec, cell, "needs-harness-observer",
                    "Java PoC uses network APIs, but the Java runner has no "
                    "independent loopback protocol observer",
                    SEATBELT_DENY_ALL_POLICY)
                    for cell in spec.cells]
                for item in results:
                    item["observation_gaps"] = ["java-network-observer-unavailable"]
                all_results.setdefault(spec.candidate_id, []).extend(results)
                continue
            # Compile separately for different requested runtimes.  This keeps
            # a JDK8 cell from accidentally running bytecode/tools selected by
            # another cell or by the host agent default.
            groups: Dict[tuple, List[MatrixCell]] = {}
            for cell in spec.cells:
                key = (cell.version, cell.java_home, cell.java_bin,
                       cell.required_runtime or cell.precondition)
                groups.setdefault(key, []).append(cell)
            for (version, _java_home, _java_bin, _required), group in groups.items():
                if self.execution_budget.exhausted(budget_id):
                    results.extend(_stoploss_cell(
                        spec.candidate_id, cell, self.execution_budget,
                        "java", budget_id) for cell in group)
                    continue
                jars = jars_by_version.get(version, [])
                runtime = resolve_java_runtime(group[0])
                if runtime.get("available") != "true":
                    results.extend(self._unavailable_cell(spec, cell, runtime) for cell in group)
                    continue
                compile_timeout = _bounded_timeout(
                    self.execution_budget, budget_id, None,
                    self.runner.default_timeout)
                if compile_timeout is None:
                    results.extend(_stoploss_cell(spec.candidate_id, cell,
                                                  self.execution_budget, "java",
                                                  budget_id)
                                   for cell in group)
                    continue
                compiled = self.compile(spec, version, jars, runtime,
                                        timeout=compile_timeout)
                if (compiled.timed_out
                        and self.execution_budget.exhausted(budget_id)):
                    results.extend(_stoploss_cell(spec.candidate_id, cell,
                                                  self.execution_budget, "java",
                                                  budget_id)
                                   for cell in group)
                    continue
                if compiled.returncode != 0:
                    # Keep one result per declared cell so matrix coverage is
                    # honest even when compilation fails for a whole group.
                    for cell in group:
                        isolation_failed = compiled.returncode == -5
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
                        "compile_timed_out": compiled.timed_out,
                        "compile_duration_ms": compiled.duration_ms,
                        "compile_timeout_seconds": compiled.timeout_seconds,
                        "compile_timeout_capped": compiled.timeout_capped,
                        "observations": {},
                        "cmd": " ".join(compiled.cmd),
                        "network_isolation": ("network-sandbox-unavailable"
                                              if isolation_failed
                                              else SEATBELT_DENY_ALL_POLICY),
                        "policy_status": ("needs-network-isolation"
                                          if isolation_failed else "compile-failed"),
                        }
                        item.update(_cell_metadata(cell))
                        item.update(self._runtime_fields(runtime))
                        results.append(item)
                    continue
                for cell in group:
                    cell_timeout = _bounded_timeout(
                        self.execution_budget, budget_id, cell.timeout,
                        self.runner.default_timeout)
                    if cell_timeout is None:
                        results.append(_stoploss_cell(
                            spec.candidate_id, cell, self.execution_budget,
                            "java", budget_id))
                        continue
                    results.append(self.run_cell(
                        spec, cell, jars, runtime, timeout=cell_timeout))
            all_results.setdefault(spec.candidate_id, []).extend(results)
        for candidate_id, cells in all_results.items():
            self._write_cells(candidate_id, cells)
        return all_results

    def _write_cells(self, candidate_id: str, cells: List[Dict]) -> None:
        candidate_id = _safe_component(candidate_id, "candidate_id")
        d = _contained_path(
            self.workspace,
            "state/%s/round-%02d/S4/matrix-runs/%s" % (
                self.target, self.round_no, candidate_id),
            "candidate matrix directory")
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
    budget_key: str = ""


class ShellMatrixRunner:
    """Shell/HTTP PoC matrix runner for web apps, services and protocol tests.

    Produces the same cells.json schema as JavaMatrixRunner so G4 sees one
    observation contract. PoC output is optional diagnostic material and is
    retained only as untrusted claims. HTTP response metadata comes from the
    independent loopback observer; unsupported or missing observations remain
    explicit gaps rather than being inferred from stdout/stderr.

    Literal network targets are checked by source screening, then each cell
    requires a preflighted OS network profile. On macOS, declared plain-HTTP
    loopback traffic is restricted to the harness observer; all other shell
    cells receive a deny-all network profile. Unsupported platforms fail
    closed before the PoC starts.
    Cells receive VULNGATE_VERSION / VULNGATE_SAFE_MODE / VULNGATE_PRECONDITION
    / VULNGATE_FEATURES plus bounded sequence/concurrency metadata via
    environment.
    """

    def __init__(self, workspace: Path, target: str, round_no: int,
                 approval: Optional[ApprovalGate] = None,
                 authorized_staging: bool = False,
                 staging_hosts: Optional[List[str]] = None,
                 execution_budget: Optional[S4ExecutionBudget] = None):
        self.workspace = workspace.resolve()
        self.target = _safe_component(target, "target")
        self.round_no = int(round_no)
        if self.round_no < 1:
            raise ValueError("round must be a positive integer")
        self.approval = approval or ApprovalGate()
        self.authorized_staging = authorized_staging
        self.execution_budget = execution_budget or S4ExecutionBudget()
        self.staging_hosts = {str(h).strip().lower().rstrip(".") for h in (staging_hosts or [])}
        self.runner = CommandRunner(workspace, approval, authorized_staging=authorized_staging,
                                    staging_hosts=list(self.staging_hosts),
                                    execution_budget=self.execution_budget)
        round_dir = "round-%02d" % self.round_no
        self.src_dir = _contained_path(
            self.workspace, "poc/%s/%s/src" % (self.target, round_dir),
            "PoC source directory")
        self.matrix_dir = _contained_path(
            self.workspace, "state/%s/%s/S4/matrix-runs" % (self.target, round_dir),
            "S4 matrix directory")

    def run_manifest(self, specs: List[ShellPOCSpec]) -> Dict[str, List[Dict]]:
        all_results: Dict[str, List[Dict]] = {}
        for spec in specs:
            _safe_component(spec.candidate_id, "candidate_id")
            budget_id = _budget_key(spec)
            self.execution_budget.deadline_for(budget_id)
            results = []
            for cell in spec.cells:
                timeout = _bounded_timeout(
                    self.execution_budget, budget_id, cell.timeout,
                    self.runner.default_timeout)
                if timeout is None:
                    results.append(_stoploss_cell(
                        spec.candidate_id, cell, self.execution_budget,
                        "shell", budget_id))
                    continue
                results.append(self.run_cell(spec, cell, timeout=timeout))
            all_results.setdefault(spec.candidate_id, []).extend(results)
        for candidate_id, cells in all_results.items():
            self._write_cells(candidate_id, cells)
        return all_results

    def run_cell(self, spec: ShellPOCSpec, cell: MatrixCell,
                 timeout: Optional[int] = None) -> Dict:
        _safe_component(spec.candidate_id, "candidate_id")
        budget_id = _budget_key(spec)
        timeout = _bounded_timeout(self.execution_budget, budget_id,
                                   timeout if timeout is not None else cell.timeout,
                                   self.runner.default_timeout)
        if timeout is None:
            return _stoploss_cell(spec.candidate_id, cell,
                                  self.execution_budget, "shell", budget_id)
        try:
            script = _contained_path(self.src_dir, spec.script, "shell PoC script")
        except ValueError as exc:
            result = {
                "candidate_id": spec.candidate_id,
                "poc_script": str(spec.script),
                "version": cell.version,
                "safe_mode": cell.safe_mode,
                "precondition": cell.precondition,
                "observations": {}, "poc_claims": {},
                "policy_status": "blocked",
                "harness_error": str(exc),
                "lang": "shell",
            }
            result.update(_cell_metadata(cell))
            return result
        if not script.exists():
            result = {
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
            result.update(_cell_metadata(cell))
            return result
        source_bytes = script.read_bytes()
        source_digest = hashlib.sha256(source_bytes).hexdigest()
        source_text = source_bytes.decode("utf-8", "replace")
        egress = scan_source_egress(
            source_text, str(script),
            self.staging_hosts if self.authorized_staging else None,
            [spec.urls.get(cell.version, ""),
             spec.env.get("VULNGATE_TARGET_URL", "")] + [str(arg) for arg in cell.args])
        if egress:
            detail = "PoC 脚本未满足网络执行边界: %s" % "; ".join(sorted(set(egress))[:6])
            self.approval.request("external_egress", detail)
            result = {
                "candidate_id": spec.candidate_id,
                "poc_script": spec.script,
                "version": cell.version,
                "safe_mode": cell.safe_mode,
                "precondition": cell.precondition,
                "observations": {}, "poc_claims": {},
                "policy_status": "blocked",
                "stderr": "EGRESS_DENIED " + detail,
                "lang": "shell",
            }
            result.update(_cell_metadata(cell))
            return result
        env_extra = {
            "VULNGATE_VERSION": cell.version,
            "VULNGATE_SAFE_MODE": "true" if cell.safe_mode else "false",
            "VULNGATE_PRECONDITION": cell.precondition,
            "VULNGATE_FEATURES": ",".join(cell.features),
            "VULNGATE_TARGET_URL": spec.urls.get(cell.version, spec.env.get("VULNGATE_TARGET_URL", "")),
        }
        env_extra.update(spec.env)
        # Structured experiment metadata wins over free-form PoC environment
        # values, just like the authorization context below.
        env_extra.update(_cell_experiment_env(cell))
        # Structured authorization context wins over free-form PoC env values;
        # credentials are never part of this contract.
        env_extra.update(authz_env(cell.authz))
        target_url = str(env_extra.get("VULNGATE_TARGET_URL", "") or "").strip()
        authz_case = normalize_authz_case(cell.authz)
        requires_http_observation = bool(authz_case.get("expected_http_codes"))
        try:
            parsed_target = urlsplit(target_url) if target_url else None
        except ValueError as exc:
            result_payload = {
                "candidate_id": spec.candidate_id,
                "poc_script": spec.script,
                "version": cell.version,
                "safe_mode": cell.safe_mode,
                "features": cell.features,
                "args": list(cell.args),
                "precondition": cell.precondition,
                "authz": authz_case,
                "returncode": None,
                "timed_out": False,
                "duration_ms": 0,
                "observations": {},
                "poc_claims": {},
                "authz_assertion": assert_authz_observations(cell.authz, {}),
                "policy_status": "needs-harness-observer",
                "harness_error": "invalid declared target URL: %s" % str(exc)[:160],
                "observation_gaps": ["target-url-invalid"],
                "lang": "shell",
                "runner_policy": RUNNER_POLICY_VERSION,
            }
            result_payload.update(_cell_metadata(cell))
            return result_payload
        wants_http_observer = bool(parsed_target and parsed_target.scheme.lower() in {
            "http", "https"})
        network_capable = bool(_NETWORK_PRIMITIVE.search(source_text))
        if network_capable and not wants_http_observer:
            result_payload = {
                "candidate_id": spec.candidate_id,
                "poc_script": spec.script,
                "version": cell.version,
                "safe_mode": cell.safe_mode,
                "features": cell.features,
                "args": list(cell.args),
                "precondition": cell.precondition,
                "authz": authz_case,
                "returncode": None,
                "timed_out": False,
                "duration_ms": 0,
                "observations": {},
                "poc_claims": {},
                "authz_assertion": assert_authz_observations(cell.authz, {}),
                "policy_status": "needs-harness-observer",
                "harness_error": (
                    "network-capable shell PoC requires a supported declared "
                    "loopback HTTP target"),
                "observation_gaps": ["network-observer-target-unavailable"],
                "lang": "shell",
                "runner_policy": RUNNER_POLICY_VERSION,
            }
            result_payload.update(_cell_metadata(cell))
            return result_payload
        if requires_http_observation and not wants_http_observer:
            result_payload = {
                "candidate_id": spec.candidate_id,
                "poc_script": spec.script,
                "version": cell.version,
                "safe_mode": cell.safe_mode,
                "features": cell.features,
                "precondition": cell.precondition,
                "authz": authz_case,
                "returncode": None,
                "timed_out": False,
                "duration_ms": 0,
                "observations": {},
                "poc_claims": {},
                "authz_assertion": assert_authz_observations(cell.authz, {}),
                "policy_status": "needs-harness-observer",
                "harness_error": "HTTP authorization evidence requires a declared target URL",
                "observation_gaps": ["target-url-unavailable"],
                "lang": "shell",
                "runner_policy": RUNNER_POLICY_VERSION,
            }
            result_payload.update(_cell_metadata(cell))
            return result_payload

        observer = None
        run_id = str(uuid.uuid4())
        try:
            if wants_http_observer:
                observer = LoopbackHTTPObserver(target_url, run_id).start()
        except (OSError, ValueError) as exc:
            result_payload = {
                "candidate_id": spec.candidate_id,
                "poc_script": spec.script,
                "version": cell.version,
                "safe_mode": cell.safe_mode,
                "features": cell.features,
                "precondition": cell.precondition,
                "authz": authz_case,
                "returncode": None,
                "timed_out": False,
                "duration_ms": 0,
                "observations": {},
                "poc_claims": {},
                "authz_assertion": assert_authz_observations(cell.authz, {}),
                "policy_status": "needs-harness-observer",
                "harness_error": "HTTP observer unavailable: %s" % str(exc)[:240],
                "observation_gaps": ["http-observer-unavailable"],
                "lang": "shell",
                "runner_policy": RUNNER_POLICY_VERSION,
            }
            result_payload.update(_cell_metadata(cell))
            return result_payload

        if observer is not None:
            for key in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
                        "ALL_PROXY", "all_proxy"):
                env_extra[key] = observer.proxy_url
            # Many HTTP clients otherwise bypass proxies for loopback hosts.
            env_extra["NO_PROXY"] = ""
            env_extra["no_proxy"] = ""

        try:
            scratch = tempfile.TemporaryDirectory(
                prefix=".vulngate-poc-", dir=str(self.workspace))
            scratch_dir = Path(scratch.name).resolve()
        except OSError as exc:
            if observer is not None:
                observer.close()
            return {
                "candidate_id": spec.candidate_id,
                "poc_script": spec.script,
                "version": cell.version,
                "safe_mode": cell.safe_mode,
                "precondition": cell.precondition,
                "observations": {}, "poc_claims": {},
                "policy_status": "needs-network-isolation",
                "harness_error": "cannot create isolated PoC scratch: %s" % str(exc)[:180],
                "observation_gaps": ["poc-scratch-unavailable"],
                "lang": "shell",
                "runner_policy": RUNNER_POLICY_VERSION,
            }
        env_extra.update({
            "HOME": str(scratch_dir), "TMPDIR": str(scratch_dir),
            "TMP": str(scratch_dir), "TEMP": str(scratch_dir),
            "VULNGATE_SCRATCH_DIR": str(scratch_dir),
        })

        cmd = ["bash", str(script)] + list(cell.args)
        proxy_url = observer.proxy_url if observer is not None else None
        network_isolation, sandbox_error = verify_network_sandbox(
            proxy_url, filesystem_workspace=self.workspace,
            writable_paths=[scratch_dir])
        expected_network_policy = (SEATBELT_PROXY_POLICY if observer is not None
                                   else SEATBELT_DENY_ALL_POLICY)
        if sandbox_error or network_isolation != expected_network_policy:
            if observer is not None:
                observer.close()
            scratch.cleanup()
            result_payload = {
                "candidate_id": spec.candidate_id,
                "poc_script": spec.script,
                "version": cell.version,
                "safe_mode": cell.safe_mode,
                "features": cell.features,
                "args": list(cell.args),
                "precondition": cell.precondition,
                "authz": authz_case,
                "returncode": None,
                "timed_out": False,
                "duration_ms": 0,
                "observations": {},
                "poc_claims": {},
                "authz_assertion": assert_authz_observations(cell.authz, {}),
                "network_isolation": network_isolation,
                "policy_status": "needs-network-isolation",
                "harness_error": (sandbox_error or
                                  "required network policy is unavailable"),
                "observation_gaps": ["os-network-isolation-unavailable"],
                "lang": "shell",
                "runner_policy": RUNNER_POLICY_VERSION,
            }
            result_payload.update(_cell_metadata(cell))
            return result_payload
        run_cmd, wrapped_policy = wrap_network_command(
            cmd, proxy_url, filesystem_workspace=self.workspace,
            writable_paths=[scratch_dir])
        if wrapped_policy != network_isolation:
            if observer is not None:
                observer.close()
            scratch.cleanup()
            result_payload = {
                "candidate_id": spec.candidate_id,
                "poc_script": spec.script,
                "version": cell.version,
                "safe_mode": cell.safe_mode,
                "features": cell.features,
                "args": list(cell.args),
                "precondition": cell.precondition,
                "authz": authz_case,
                "returncode": None,
                "timed_out": False,
                "duration_ms": 0,
                "observations": {},
                "poc_claims": {},
                "authz_assertion": assert_authz_observations(cell.authz, {}),
                "network_isolation": wrapped_policy,
                "policy_status": "needs-network-isolation",
                "harness_error": "network policy changed between preflight and launch",
                "observation_gaps": ["os-network-isolation-policy-mismatch"],
                "lang": "shell",
                "runner_policy": RUNNER_POLICY_VERSION,
            }
            result_payload.update(_cell_metadata(cell))
            return result_payload
        run_error = None
        result = None
        try:
            result = self.runner.run(
                run_cmd,
                cwd=self.src_dir,
                env_extra=env_extra,
                operation="loopback_connect",
                operation_detail="shell/HTTP PoC %s (observer port restricted to a host-owned address)" % spec.candidate_id,
                timeout=timeout if timeout is not None else cell.timeout,
            )
        except PermissionError as exc:
            run_error = exc
        finally:
            if observer is not None:
                observer.close()
            scratch.cleanup()

        obs_snapshot = observer.snapshot() if observer is not None else None
        obs = dict(obs_snapshot.get("observations", {})) if obs_snapshot else {}
        observer_gaps = list(obs_snapshot.get("observer_gaps", [])) if obs_snapshot else []
        if observer is not None and not obs.get("HTTP_RESPONSES"):
            observer_gaps.append("no-proxied-response-captured")
        if observer is not None and requires_http_observation and "HTTP_CODE" not in obs:
            observer_gaps.append("expected-http-code-not-independently-observed")

        target_digest = str(obs_snapshot.get("target_digest", "")) if obs_snapshot else ""
        cell_identity = {
            "candidate_id": spec.candidate_id,
            "version": cell.version,
            "safe_mode": cell.safe_mode,
            "precondition": cell.precondition,
            "features": list(cell.features),
            "args": list(cell.args),
            "source_digest": source_digest,
            "target_digest": target_digest,
            "authz_fixture_id": authz_fixture_id(cell.authz),
        }
        cell_id = hashlib.sha256(json.dumps(
            cell_identity, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")).hexdigest()
        if result is None:
            returncode = -3
            timed_out = False
            duration_ms = 0
            stdout = ""
            stderr = str(run_error or "runner failed")[-4000:]
            policy_status = "blocked"
        else:
            returncode = result.returncode
            timed_out = result.timed_out
            duration_ms = result.duration_ms
            stdout = result.stdout
            stderr = result.stderr[-4000:]
            policy_status = ("resource-limit-exceeded"
                             if result.resource_limit_exceeded else
                             "aborted" if result.abort_reason else "allowed")
        poc_claims = parse_poc_claims(stdout, stderr)
        authz_assertion = assert_authz_observations(cell.authz, obs)
        if (observer is not None and authz_assertion.get("status") == "passed"
                and network_isolation != SEATBELT_PROXY_POLICY):
            # A proxy capture is positive evidence for that response, but
            # cannot prove the PoC did not also issue uncaptured direct traffic.
            authz_assertion["status"] = "unsupported"
            authz_assertion.setdefault("missing", []).append(
                "complete-request-capture-requires-os-network-isolation")
            observer_gaps.append("authz-pass-not-closed-by-proxy-only-capture")
        result_payload = {
            "candidate_id": spec.candidate_id,
            "poc_script": spec.script,
            "version": cell.version,
            "safe_mode": cell.safe_mode,
            "features": cell.features,
            "args": list(cell.args),
            "precondition": cell.precondition,
            "authz": authz_case,
            "cell_id": cell_id,
            "returncode": returncode,
            "timed_out": timed_out,
            "duration_ms": duration_ms,
            "runner_timeout_seconds": (result.timeout_seconds
                                       if result is not None else 0),
            "runner_timeout_capped": (result.timeout_capped
                                      if result is not None else False),
            "observations": obs,
            "poc_claims": poc_claims,
            "authz_assertion": authz_assertion,
            "stdout": stdout,
            "stderr": stderr,
            "cmd": " ".join(cmd),
            "lang": "shell",
            "network_isolation": network_isolation,
            "filesystem_isolation": SEATBELT_POC_FILESYSTEM_POLICY,
            "resource_limits": result.resource_limits if result is not None else {},
            "scratch_limits": result.scratch_limits if result is not None else {},
            "process_tree_cleanup": (result.process_tree_cleanup
                                     if result is not None else {}),
            "resource_limit_exceeded": (result.resource_limit_exceeded
                                        if result is not None else ""),
            "abort_reason": result.abort_reason if result is not None else "",
            "policy_status": policy_status,
            "runner_policy": RUNNER_POLICY_VERSION,
        }
        if result is not None and result.resource_limit_exceeded:
            result_payload["harness_error"] = (
                "PoC resource watchdog stopped or invalidated the run: %s" %
                result.resource_limit_exceeded)
        if result is not None and result.abort_reason:
            result_payload["harness_error"] = (
                "S4 run aborted by shared stop-loss: %s" % result.abort_reason)
        if obs_snapshot:
            result_payload["observation_provenance"] = {
                "schema_version": obs_snapshot["schema_version"],
                "producer": obs_snapshot["producer"],
                "collector_version": obs_snapshot["collector_version"],
                "capture_scope": ("seatbelt-host-local-port"
                                  if network_isolation == SEATBELT_PROXY_POLICY
                                  else "proxy-environment-only"),
                "network_isolation": network_isolation,
                "filesystem_isolation": SEATBELT_POC_FILESYSTEM_POLICY,
                "resource_limits": result.resource_limits if result is not None else {},
                "scratch_limits": result.scratch_limits if result is not None else {},
                "resource_limit_exceeded": (result.resource_limit_exceeded
                                            if result is not None else ""),
                "abort_reason": result.abort_reason if result is not None else "",
                "run_id": obs_snapshot["run_id"],
                "candidate_id": spec.candidate_id,
                "cell_id": cell_id,
                "source_digest": source_digest,
                "target_digest": target_digest,
                "response_count": obs_snapshot["response_count"],
                "observer_gaps": observer_gaps,
                "returncode": returncode,
                "timed_out": timed_out,
            }
            if observer_gaps:
                result_payload["observation_gaps"] = observer_gaps
        else:
            result_payload["observation_provenance"] = {
                "schema_version": POC_CLAIMS_SCHEMA,
                "producer": "poc-stdout-stderr",
                "trust": "untrusted-claim",
            }
        if result is not None and result.abort_reason:
            result_payload["stop_reason"] = result.abort_reason
        elif timed_out and self.execution_budget.exhausted(budget_id):
            result_payload["stop_reason"] = self.execution_budget.stop_reason(
                budget_id)
        result_payload.update(_cell_metadata(cell))
        return result_payload

    def _write_cells(self, candidate_id: str, cells: List[Dict]) -> None:
        candidate_id = _safe_component(candidate_id, "candidate_id")
        d = _contained_path(
            self.workspace,
            "state/%s/round-%02d/S4/matrix-runs/%s" % (
                self.target, self.round_no, candidate_id),
            "candidate matrix directory")
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / ("cells.json.tmp.%d" % os.getpid())
        tmp.write_text(json.dumps(cells, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(d / "cells.json")


_FALSY_MARKERS = ("", "true", "yes", "ok", "none", "null", "0", "false")


def _trace_values(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item)[:240] for item in value[:32] if str(item).strip()]
    if value is None or not str(value).strip():
        return []
    return [str(value)[:240]]


def _capability_name(value: Any, allowed: List[str]) -> str:
    """Extract a declared capability id from one PoC trace value."""
    text = str(value or "").strip()
    for candidate in (text, text.split("=", 1)[0].strip(),
                      text.split(":", 1)[0].strip()):
        if candidate in allowed:
            return candidate
    return ""


def _transition_name(value: Any) -> str:
    text = str(value or "").strip()
    if "=" in text:
        text = text.split("=", 1)[0].strip()
    if ":" in text:
        text = text.split(":", 1)[0].strip()
    if "->" not in text:
        return ""
    left, right = (part.strip() for part in text.split("->", 1))
    return "%s->%s" % (left, right) if left and right else ""


def _capability_cell_evidence(cell: Dict[str, Any], obs: Dict[str, Any]
                              ) -> Optional[Dict[str, Any]]:
    """Summarize intermediate capability observations without judging impact."""
    experiment = cell.get("experiment") or {}
    contract = normalize_capability_contract(
        cell.get("capability_contract") or experiment.get("capability_contract"))
    required = list(contract.get("required_capabilities") or [])
    if not required:
        return None
    capability_trace = _trace_values(obs.get("CAPABILITY_TRACE"))
    capability_evidence = _trace_values(obs.get("CAPABILITY_EVIDENCE"))
    transition_trace = _trace_values(obs.get("TRANSITION_TRACE"))
    transition_evidence = _trace_values(obs.get("TRANSITION_EVIDENCE"))
    observed = []
    for raw in capability_trace:
        name = _capability_name(raw, required)
        if name and name not in observed:
            observed.append(name)
    missing = [name for name in required if name not in observed]
    evidence_capabilities = []
    for raw in capability_evidence:
        name = _capability_name(raw, required)
        if name and name not in evidence_capabilities:
            evidence_capabilities.append(name)
    missing_capability_evidence = [name for name in observed
                                   if name not in evidence_capabilities]
    expected_transitions = [
        "%s->%s" % (rule["from"], rule["to"])
        for rule in contract.get("transition_rules", [])
    ]
    observed_transitions = []
    for raw in transition_trace:
        name = _transition_name(raw)
        if name in expected_transitions and name not in observed_transitions:
            observed_transitions.append(name)
    missing_transitions = [name for name in expected_transitions
                           if name not in observed_transitions]
    evidence_transitions = []
    for raw in transition_evidence:
        name = _transition_name(raw)
        if name in expected_transitions and name not in evidence_transitions:
            evidence_transitions.append(name)
    missing_transition_evidence = [name for name in observed_transitions
                                   if name not in evidence_transitions]
    effect_kind = str(obs.get("EFFECT_KIND", "")).strip().lower()
    effect = str(obs.get("EFFECT", obs.get("SIDE_EFFECT", ""))).strip()
    safe_effect = any(marker in effect_kind
                      for marker in ("canary", "simulat", "shape-only", "in-memory"))
    typed_effect_observed = bool(effect_kind and effect and not safe_effect)
    if not capability_trace:
        status = "no-trace"
    elif (missing or missing_transitions or missing_capability_evidence or
          missing_transition_evidence or
          (contract.get("typed_effect_required") and not typed_effect_observed)):
        status = "partial"
    else:
        status = "complete"
    return {
        "version": cell.get("version"),
        "safe": cell.get("safe_mode"),
        "precondition": cell.get("precondition"),
        "declared_capabilities": required,
        "observed_capabilities": observed,
        "missing_capabilities": missing,
        "capability_evidence_ids": evidence_capabilities,
        "missing_capability_evidence": missing_capability_evidence,
        "declared_transitions": expected_transitions,
        "observed_transitions": observed_transitions,
        "missing_transitions": missing_transitions,
        "transition_evidence_ids": evidence_transitions,
        "missing_transition_evidence": missing_transition_evidence,
        "capability_trace": capability_trace,
        "capability_evidence": capability_evidence,
        "transition_trace": transition_trace,
        "transition_evidence": transition_evidence,
        "status": status,
        "typed_effect_required": bool(contract.get("typed_effect_required")),
        "typed_effect_observed": typed_effect_observed,
        "claim_status": "not-a-finding",
    }


def classify_s4_execution(cells: List[Dict]) -> Dict[str, object]:
    """Classify what S4 actually established, independently of host control flow.

    A proxy/agent timeout is not a matrix result. Persisted cells are scoped to
    one candidate. PoC output markers do not classify a run as blocked or
    effected; only runner policy/status fields and trusted observations do.
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
        obs = _trusted_observations(cell)
        effect_kind = str(obs.get("EFFECT_KIND", "")).strip().lower()
        effect = str(obs.get("EFFECT", obs.get("SIDE_EFFECT", ""))).strip()
        if effect_kind and effect and not any(x in effect_kind for x in
                                             ("canary", "simulat", "shape-only", "in-memory")):
            return True
        instantiated = str(obs.get("INSTANTIATED", "")).strip()
        if instantiated and "." in instantiated:
            return True
        error = str(obs.get("ERROR", ""))
        if any(marker in error for marker in (
                "OutOfMemoryError", "StackOverflowError", "SQLException",
                "JSONException", "ArrayIndexOutOfBoundsException",
                "NegativeArraySizeException", "NumberFormatException")):
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
                                if c.get("precondition_status") == RUNTIME_UNAVAILABLE
                                or c.get("policy_status") == "precondition-unavailable"]
    blocked = [c for c in cells
               if (c.get("policy_status") == "blocked"
                   or c.get("returncode") == -3)
               and c.get("precondition_status") != RUNTIME_UNAVAILABLE]
    stop_loss = [c for c in cells
                 if (c.get("policy_status") == "stop-loss"
                     or "timebox-exhausted" in str(c.get("stop_reason", "")))]
    executed = [c for c in cells if _ran(c)]
    failed = [c for c in cells if c not in executed and c not in blocked
              and c not in precondition_unavailable and c not in stop_loss]
    effected = [c for c in executed if _has_effect(c)]

    if stop_loss and executed:
        state = "partial-matrix"
    elif stop_loss:
        state = "timebox-exhausted"
    elif executed and (failed or blocked or precondition_unavailable):
        state = "partial-matrix"
    elif not executed and precondition_unavailable and not failed and not blocked:
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
        "stop_loss_cell_count": len(stop_loss),
        "effect_cell_count": len(effected),
    }


def _extract_s4_cells(payload: object, candidate_id: str) -> List[Dict]:
    """Accept persisted result shapes without mixing candidate evidence."""
    candidate_id = _safe_component(candidate_id, "candidate_id")

    def scoped(items: object) -> List[Dict]:
        if not isinstance(items, list):
            return []
        out = []
        for item in items:
            if not isinstance(item, dict):
                continue
            declared = str(item.get("candidate_id") or "").strip()
            if declared != candidate_id:
                continue
            row = dict(item)
            out.append(row)
        return out

    if isinstance(payload, list):
        return scoped(payload)
    if not isinstance(payload, dict):
        return []
    for key in ("cells", "fallback_cells", "matrix_cells"):
        if isinstance(payload.get(key), list):
            return scoped(payload[key])
    results = payload.get("results")
    if isinstance(results, dict) and isinstance(results.get(candidate_id), list):
        return scoped(results[candidate_id])
    if isinstance(payload.get(candidate_id), list):
        return scoped(payload[candidate_id])
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
    root = Path(workspace).resolve()
    target = _safe_component(target, "target")
    candidate_id = _safe_component(candidate_id, "candidate_id")
    round_no = int(round_no)
    if round_no < 1:
        raise ValueError("round must be a positive integer")
    round_dir = "round-%02d" % round_no
    s4_dir = _contained_path(
        root, "state/%s/%s/S4" % (target, round_dir), "S4 artifact directory")
    matrix_file = _contained_path(
        root, "state/%s/%s/S4/matrix-runs/%s/cells.json" % (
            target, round_dir, candidate_id), "candidate matrix artifact")
    candidates = []
    if runner_cells:
        scoped_runner = _extract_s4_cells(runner_cells, candidate_id)
        if scoped_runner:
            candidates.append(("runner", scoped_runner))
    if matrix_file.is_file() and matrix_file.resolve().is_relative_to(s4_dir.resolve()):
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
                if not path.resolve().is_relative_to(s4_dir.resolve()):
                    continue
            except OSError:
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


_RESIDUAL_ID = re.compile(r"^rr-[0-9a-f]{20}$")
_RESIDUAL_CODE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def _residual_cell_ref(cell: Dict[str, Any], residual_id: str) -> str:
    """Return a non-sensitive, stable reference for one S4 cell."""
    core = "%s|%s|%s|%s|%s" % (
        cell.get("candidate_id", ""), residual_id, cell.get("version", ""),
        bool(cell.get("safe_mode")), cell.get("precondition", ""))
    return "s4c-" + hashlib.sha256(core.encode("utf-8", errors="replace")).hexdigest()[:20]


def _residual_execution_state(cell: Dict[str, Any], obs: Dict[str, Any]) -> str:
    if cell.get("precondition_status") == RUNTIME_UNAVAILABLE:
        return "precondition-unavailable"
    if cell.get("policy_status") == "blocked" or cell.get("returncode") == -3:
        return "gate-blocked"
    if (isinstance(cell.get("returncode"), int)
            and cell.get("returncode") == 0
            and not cell.get("compile_error")
            and not cell.get("harness_error")
            and not cell.get("timed_out")
            and not obs.get("ERROR")
            and not obs.get("ENV_ERROR")):
        return "executed"
    if cell.get("returncode") is not None or cell.get("harness_error") \
            or cell.get("compile_error") or cell.get("timed_out"):
        return "run-failed"
    return "unexecuted"


def _declared_residual_contracts(cell: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    experiment = cell.get("experiment") or {}
    rows = normalize_residual_contracts(
        cell.get("residual_contracts") or experiment.get("residual_contracts"))
    return {row["residual_id"]: row for row in rows}


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
    experiment_evidence = []
    capability_evidence = []
    authz_results = []
    authz_boundary_violations = []
    residual_falsifiers = []
    poc_claim_rows = []
    untrusted_claim_field_count = 0

    def truthy(v: str) -> bool:
        # LLM-authored PoCs may emit INSTANTIATED=false / GATE_BLOCKED=none /
        # NETWORK=null; those are "not observed", never evidence.
        return str(v).strip().lower() not in ("", "false", "none", "null", "0")

    for c in cells:
        obs = _trusted_observations(c)
        claims = _cell_poc_claims(c)
        claim_fields = claims.get("fields", {}) if isinstance(claims, dict) else {}
        if isinstance(claim_fields, dict) and claim_fields:
            untrusted_claim_field_count += len(claim_fields)
            if len(poc_claim_rows) < 16:
                poc_claim_rows.append({
                    "version": c.get("version"),
                    "safe_mode": c.get("safe_mode"),
                    "precondition": c.get("precondition"),
                    "source": claims.get("source", "unknown"),
                    "fields": {
                        str(key): _trace_values(value)[:4]
                        for key, value in list(claim_fields.items())[:12]
                    },
                    "trust": "untrusted-claim",
                })
        experiment = c.get("experiment") or {}
        declared_sequence = c.get("sequence", experiment.get("sequence", [])) or []
        declared_concurrency = c.get(
            "concurrency", experiment.get("concurrency", 1))
        declared_probe = c.get(
            "availability_probe", experiment.get("availability_probe", False))
        if not isinstance(declared_sequence, list):
            declared_sequence = [str(declared_sequence)] if declared_sequence else []
        try:
            declared_workers = int(declared_concurrency or 1)
        except (TypeError, ValueError):
            declared_workers = 1
        step_trace = obs.get("STEP_TRACE", [])
        step_evidence = obs.get("STEP_EVIDENCE", [])
        state_trace = obs.get("STATE_TRACE", [])
        if not isinstance(step_trace, list):
            step_trace = [str(step_trace)] if step_trace else []
        if not isinstance(step_evidence, list):
            step_evidence = [str(step_evidence)] if step_evidence else []
        if not isinstance(state_trace, list):
            state_trace = [str(state_trace)] if state_trace else []
        if declared_sequence or declared_workers > 1 or declared_probe \
                or step_trace or step_evidence or state_trace:
            experiment_row = {
                "version": c.get("version"),
                "safe": c.get("safe_mode"),
                "precondition": c.get("precondition"),
                "declared_sequence": list(declared_sequence),
                "declared_concurrency": declared_workers,
                "declared_availability_probe": bool(declared_probe),
                "sequence_status": sequence_trace_status(
                    [str(step) for step in declared_sequence],
                    [str(step) for step in step_trace]),
                "step_trace": [str(x)[:240] for x in step_trace[:32]],
                "step_evidence": [str(x)[:240] for x in step_evidence[:32]],
                "state_trace": [str(x)[:240] for x in state_trace[:32]],
                "warnings": list(experiment.get("warnings", [])),
            }
            capability_row = _capability_cell_evidence(c, obs)
            if capability_row:
                experiment_row["capability"] = capability_row
                capability_evidence.append(capability_row)
            experiment_evidence.append(experiment_row)
        else:
            capability_row = _capability_cell_evidence(c, obs)
            if capability_row:
                capability_evidence.append(capability_row)
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
        # HTTP transport evidence comes only from the harness observer. Status
        # and body digest help review, but do not establish content or impact.
        code = str(obs.get("HTTP_CODE", "")).strip()
        if code.isdigit():
            provenance = c.get("observation_provenance") or {}
            responses = obs.get("HTTP_RESPONSES", [])
            rec = {"version": c["version"], "safe": c["safe_mode"],
                   "precondition": c["precondition"],
                   "cell_id": c.get("cell_id", ""),
                   "observer_run_id": provenance.get("run_id", ""),
                   "observer": provenance.get("collector_version", ""),
                   "response_count": len(responses),
                   "http_code": int(code)}
            http_evidence.append(rec)
        residual_id = str(obs.get("RESIDUAL_ID", "")).strip().lower()
        residual_status = str(obs.get("RESIDUAL_STATUS", "")).strip().lower()[:40]
        residual_code = str(obs.get("RESIDUAL_FALSIFIER", "")).strip().lower()[:64]
        if _RESIDUAL_ID.fullmatch(residual_id):
            effect_observed = bool(
                (effect and effect_kind and not any(marker in effect_kind for marker in
                                                    ("canary", "simulat", "shape-only", "in-memory")))
                or (lk and lk.lower() not in _FALSY_MARKERS)
                or (truthy(obs.get("NETWORK")) and "://" in str(obs.get("NETWORK")))
                or (ev and ev.lower() not in _FALSY_MARKERS)
                or bool(assertion and assertion.get("boundary_violation")))
            contract = _declared_residual_contracts(c).get(residual_id, {})
            residual_falsifiers.append({
                "residual_id": residual_id,
                "status": residual_status,
                "falsifier_code": residual_code if _RESIDUAL_CODE.fullmatch(
                    residual_code) else "",
                "execution_state": _residual_execution_state(c, obs),
                "effect_observed": effect_observed,
                "contract_declared": bool(contract),
                "contract_match": residual_code in set(
                    contract.get("allowed_falsifiers") or []),
                "cell_ref": _residual_cell_ref(c, residual_id),
                "claim_status": "not-a-finding",
            })
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
        "experiment_evidence": experiment_evidence,
        "capability_evidence": capability_evidence,
        "authz_results": authz_results,
        "authz_boundary_violations": authz_boundary_violations,
        "residual_falsifiers": residual_falsifiers[:32],
        "residual_falsifier_count": len(residual_falsifiers),
        "poc_claims": poc_claim_rows,
        "untrusted_claim_field_count": untrusted_claim_field_count,
        "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION,
        "cells_ran": sum(1 for c in cells if c.get("returncode") == 0
                         and not c.get("compile_error") and not c.get("harness_error")
                         and not c.get("timed_out")),
        "cells_attempted": sum(1 for c in cells if c.get("returncode") is not None),
    }
    if harness_errors:
        summary["harness_error"] = harness_errors[0]
    if compile_errors:
        summary["compile_error"] = compile_errors[0]
    summary.update(classify_s4_execution(cells))
    observer_reported_unavailable = any(
        cell.get("policy_status") == "needs-harness-observer" for cell in cells)
    explicit_observer_gaps = sorted({
        str(gap)
        for cell in cells
        if cell.get("policy_status") == "needs-harness-observer"
        for gap in (cell.get("observation_gaps") or [])
        if str(gap).strip()
    })
    missing_http_capture = any(
        gap in {"no-proxied-response-captured",
                "expected-http-code-not-independently-observed"}
        for cell in cells
        for gap in (cell.get("observation_gaps") or [])
    )
    java_observer_gap = any(
        (str(cell.get("lang", "")).lower() == "java" or cell.get("poc_class"))
        and cell.get("returncode") == 0
        and not cell.get("compile_error")
        and not cell.get("harness_error")
        and not cell.get("timed_out")
        and not _trusted_observations(cell)
        for cell in cells
    )
    if observer_reported_unavailable:
        summary["evidence_gap"] = "needs-harness-observer"
        summary["observation_gaps"] = (explicit_observer_gaps or
                                        ["runner-reported-needs-harness-observer"])
        summary.setdefault("validation_issues", []).append(
            "needs-harness-observer: runner reported unsupported independent "
            "observation (%s)" % ", ".join(
                summary["observation_gaps"][:8]))
    elif missing_http_capture:
        summary["evidence_gap"] = "no-independent-http-response"
        summary.setdefault("validation_issues", []).append(
            "no independent HTTP response was captured; this does not establish "
            "that the candidate had no effect")
    elif java_observer_gap:
        summary["evidence_gap"] = "needs-harness-observer"
        summary["observation_gaps"] = [
            "java-runtime-effect-not-independently-observed"]
        summary.setdefault("validation_issues", []).append(
            "Java cell executed, but this adapter has no independent JVM effect "
            "observer; PoC output remains an untrusted claim")
    if untrusted_claim_field_count:
        summary.setdefault("validation_issues", []).append(
            "%d PoC output fields are retained as untrusted claims; they do not "
            "establish a target effect"
            % untrusted_claim_field_count)
    return summary
