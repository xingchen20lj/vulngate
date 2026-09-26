"""Bounded local service lifecycle for stateful S4 research.

Web and protocol PoCs often need a reproducible service boundary, but a
generated PoC must never become a general process launcher or a remote
deployment tool.  This module accepts only an explicit, argv-based local
configuration, validates it with the same command policy as the PoC runner,
health-checks loopback only, and kills the complete process group on teardown.

The lifecycle result is research metadata.  It cannot satisfy G4/G5 and a
failed health check is an explicit precondition gap, never a negative result.
"""

from __future__ import annotations

import hashlib
import fcntl
import json
import os
import re
import shlex
import signal
import socket
import ssl
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse, urlunsplit
import ipaddress

from ..sandbox.approval import ApprovalGate
from ..orchestrator.work_budget import WorkBudgetExceeded
from ..sandbox.isolation import detect_isolation_backend
from ..sandbox.runner import (CommandRunner, minimal_poc_env,
                              POC_MAX_PROCESS_TREE_RSS_BYTES,
                              POC_PROCESS_TREE_RSS_POLICY_VERSION,
                              POC_PROCESS_TREE_SAMPLE_INTERVAL_SECONDS,
                              POC_PROCESS_TABLE_TIMEOUT_SECONDS,
                              _process_tree_snapshot,
                              prepare_posix_resource_limited_command,
                              validate_global_command, validate_poc_command)
from .redaction import redact_text


SERVICE_SCHEMA_VERSION = "service-lifecycle-v6-isolation-backend"
PROCESS_SCHEMA_VERSION = "service-processes-v4-isolation-contract"
SERVICE_ISOLATION_POLICY_VERSION = "managed-service-isolation-backend-v1"
CLAIM_STATUS = "not-a-finding"
MAX_COMMAND_TOKENS = 32
MAX_ENV_KEYS = 32
MAX_PROCESS_RECORDS = 32
MAX_TIMEOUT = 120
_SHELL_META = re.compile(r"[;&|<>`\n\r]")
_RUNTIME_EXECUTABLES = {
    "bash", "dash", "java", "node", "perl", "php", "python", "python3",
    "ruby", "sh",
}


def _text(value: Any, limit: int = 180) -> str:
    return " ".join(redact_text(value).replace("\x00", "").split())[:limit]


def _digest(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")[:12000]).hexdigest()


def _loopback(host: str) -> bool:
    return bool(_loopback_connect_host(host))


def _loopback_connect_host(host: str) -> str:
    """Return a numeric loopback address without resolving arbitrary names."""
    host = str(host or "").strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    # Map these conventional aliases directly rather than asking the system
    # resolver, whose hosts/DNS configuration could redirect the healthcheck.
    if host in {"localhost", "localhost.localdomain"}:
        return "127.0.0.1"
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return ""
    return str(address) if address.is_loopback else ""


def _command(value: Any) -> List[str]:
    if isinstance(value, (list, tuple)):
        tokens = [str(item) for item in value]
    elif isinstance(value, str):
        try:
            tokens = shlex.split(value)
        except ValueError:
            return []
    else:
        return []
    tokens = [token for token in tokens if token]
    if not tokens or len(tokens) > MAX_COMMAND_TOKENS:
        return []
    if any(_SHELL_META.search(token) for token in tokens):
        return []
    # Shell -c turns a safe argv contract back into an arbitrary command
    # string.  A script may still be invoked as ``bash path/to/script.sh``.
    if any(token in {"-c", "--command", "/c"} for token in tokens[1:]):
        return []
    return tokens


def _bounded_timeout(value: Any, default: int) -> int:
    try:
        return max(1, min(int(value), MAX_TIMEOUT))
    except (TypeError, ValueError):
        return default


def _raw_service(config: Any) -> Tuple[bool, Dict[str, Any]]:
    if isinstance(config, dict):
        runtime = config.get("runtime_lab", {})
    else:
        runtime = getattr(config, "runtime_lab", {}) if config is not None else {}
    if not isinstance(runtime, dict):
        return False, {}
    raw = runtime.get("service", runtime.get("lifecycle"))
    if raw is None:
        return False, {}
    if raw is True:
        raw = {}
    if raw is False or not isinstance(raw, dict):
        return True, {"enabled": False}
    return True, dict(raw)


def _health_config(raw: Dict[str, Any]) -> Tuple[str, List[str], int]:
    health = raw.get("healthcheck", {})
    if isinstance(health, str):
        url = health
        command = []
    elif isinstance(health, dict):
        url = health.get("url", raw.get("healthcheck_url", ""))
        command = _command(health.get("command", raw.get("healthcheck_command")))
    else:
        url = raw.get("healthcheck_url", "")
        command = _command(raw.get("healthcheck_command"))
    expected = raw.get("expected_status", raw.get("healthcheck_status", [200, 204]))
    if isinstance(health, dict):
        expected = health.get("expected_status", expected)
    values = expected if isinstance(expected, (list, tuple, set)) else [expected]
    codes: List[str] = []
    for value in values:
        try:
            code = int(value)
        except (TypeError, ValueError):
            continue
        if 100 <= code <= 599 and str(code) not in codes:
            codes.append(str(code))
    return _text(url, 500), command, int(codes[0]) if len(codes) == 1 else 0


class ServiceLifecycle:
    """Manage one optional workspace-local service for a bounded S4 lab."""

    def __init__(self, workspace: Path, target: str, round_no: int,
                 config: Any, approval: Optional[ApprovalGate] = None,
                 execution_budget: Optional[Any] = None):
        self.workspace = Path(workspace).resolve()
        self.target = str(target)
        self.round_no = int(round_no)
        self.configured, raw = _raw_service(config)
        self.raw = raw
        self.run_id = str(raw.get("run_id") or
                         "%s:round-%02d" % (self.target, self.round_no))
        self.enabled = self.configured and raw.get("enabled", True) is not False
        # A repository config can request a backend, but it cannot authorize a
        # launch by itself.  Backend detection is side-effect free and is
        # persisted with every service artifact.
        self.isolation_backend, self.isolation_descriptor = (
            detect_isolation_backend(self.workspace, raw))
        # Kept as a compatibility/deprecation field for old configs.  It is
        # never sufficient to start a process and is not included in the
        # authorization decision.
        self.allow_unconfined_start = raw.get("allow_unconfined_start") is True
        self.start_command = _command(raw.get("start_command", raw.get("start")))
        self.stop_command = _command(raw.get("stop_command", raw.get("stop")))
        # A healthcheck may observe a service that the operator started
        # outside this run. Never stop that service implicitly; an explicit
        # opt-in is required for a configured external stop command.
        self.stop_external = raw.get("stop_external", False) is True
        self.health_url, self.health_command, _single_expected = _health_config(raw)
        expected = raw.get("expected_status", raw.get("healthcheck_status", [200, 204]))
        health = raw.get("healthcheck")
        if isinstance(health, dict):
            expected = health.get("expected_status", expected)
        values = expected if isinstance(expected, (list, tuple, set)) else [expected]
        self.expected_status = []
        for value in values:
            try:
                code = int(value)
            except (TypeError, ValueError):
                continue
            if 100 <= code <= 599 and code not in self.expected_status:
                self.expected_status.append(code)
        if not self.expected_status:
            self.expected_status = [200, 204]
        self.startup_timeout = _bounded_timeout(raw.get("startup_timeout"), 20)
        self.shutdown_timeout = _bounded_timeout(raw.get("shutdown_timeout"), 8)
        try:
            self.health_timeout = max(1, min(int(raw.get("health_timeout", 2) or 2), 10))
        except (TypeError, ValueError):
            self.health_timeout = 2
        try:
            self.poll_interval = min(max(float(raw.get("poll_interval", 0.25) or 0.25), 0.05), 2.0)
        except (TypeError, ValueError):
            self.poll_interval = 0.25
        working_dir = str(raw.get("working_dir", "") or ".")
        self.working_dir = (self.workspace / working_dir).resolve()
        env = raw.get("env", {})
        self.env = {str(key): str(value) for key, value in env.items()
                    if str(key) and value is not None} if isinstance(env, dict) else {}
        self.env = dict(list(sorted(self.env.items()))[:MAX_ENV_KEYS])
        self.approval = approval or ApprovalGate()
        self.runner = CommandRunner(self.workspace, self.approval)
        self.execution_budget = execution_budget
        self.state_dir = (self.workspace / "state" / self.target
                          / ("round-%02d" % self.round_no) / "S4")
        self.process_registry = self.state_dir / "processes.json"
        self.lock_path = self.state_dir / "service.lock"
        self._lock_handle = None
        self.registry_error = ""
        self.resource_limits: Dict[str, Any] = {}
        self.resource_limit_error = ""
        self.cgroup_controller = None
        self.process: Optional[subprocess.Popen] = None
        self.registry_pid: Optional[int] = None
        self._managed_service_started = False
        self._tree_monitor_stop = threading.Event()
        self._tree_monitor_thread: Optional[threading.Thread] = None
        self._tracked_process_start_times: Dict[int, str] = {}
        self._state: Dict[str, Any] = self.snapshot()

    def _within_workspace(self, path: Path) -> bool:
        return str(path) == str(self.workspace) or str(path).startswith(str(self.workspace) + os.sep)

    def _resolve_command_paths(self, command: Sequence[str]) -> List[str]:
        output = list(command)
        for index, token in enumerate(output):
            path = Path(token)
            if path.is_absolute():
                continue
            candidate = (self.working_dir / path).resolve()
            if candidate.exists() and candidate.is_file() and index > 0:
                output[index] = str(candidate)
        return output

    def _validate_command(self, command: Sequence[str]) -> Optional[str]:
        if not command:
            return "lifecycle command missing or contains unsupported shell syntax"
        for index, token in enumerate(command):
            path = Path(str(token))
            path_like = path.is_absolute() or "/" in str(token) or "\\" in str(token)
            if not path_like:
                continue
            candidate = path if path.is_absolute() else (self.working_dir / path).resolve()
            if index == 0 and candidate.suffix.lower() in {".sh", ".py", ".rb", ".pl"}:
                return "direct script executable denied; invoke it through an inspected interpreter"
            if (index == 0 and candidate.exists() and not self._within_workspace(candidate)
                    and candidate.name.lower() not in _RUNTIME_EXECUTABLES
                    and not candidate.name.lower().startswith(("python", "java", "node"))):
                return "lifecycle executable outside workspace is not an approved runtime"
            if index > 0 and candidate.exists() and not self._within_workspace(candidate):
                return "lifecycle argument escapes workspace"
        resolved = self._resolve_command_paths(command)
        global_error = validate_global_command(resolved, False, None)
        if global_error:
            return global_error
        return validate_poc_command(resolved, self.env, False, None)

    def _health_url_info(self) -> Dict[str, Any]:
        if not self.health_url:
            return {"configured": False, "kind": "none"}
        try:
            parsed = urlparse(self.health_url)
            host = parsed.hostname or ""
            port = parsed.port
        except ValueError:
            return {"configured": True, "kind": "url", "valid": False}
        return {
            "configured": True,
            "kind": "url",
            "valid": bool(parsed.scheme in {"http", "https"} and _loopback(host)
                       and not parsed.username and not parsed.password),
            "scheme": parsed.scheme,
            "host": _text(host, 120),
            "port": port or (443 if parsed.scheme == "https" else 80),
            "path_digest": _digest(parsed.path or "/")[:20],
            "url_digest": _digest(self.health_url)[:20],
        }

    def snapshot(self) -> Dict[str, Any]:
        return {
            "schema_version": SERVICE_SCHEMA_VERSION,
            "configured": bool(self.configured),
            "run_id": self.run_id,
            "enabled": bool(self.enabled),
            "start_command_configured": bool(self.start_command),
            "allow_unconfined_start": bool(self.allow_unconfined_start),
            "stop_command_configured": bool(self.stop_command),
            "stop_external": bool(self.stop_external),
            "start_command_digest": _digest(self.start_command)[:24] if self.start_command else "",
            "stop_command_digest": _digest(self.stop_command)[:24] if self.stop_command else "",
            "working_dir": str(self.working_dir.relative_to(self.workspace))
            if self._within_workspace(self.working_dir) else "outside-workspace",
            "process_registry": str(self.process_registry.relative_to(self.workspace)),
            "process_registry_error": self.registry_error,
            "resource_limits": dict(self.resource_limits),
            "cgroup_v2": (self.cgroup_controller.snapshot()
                          if self.cgroup_controller is not None else {}),
            "resource_limit_error": self.resource_limit_error,
            "isolation_policy": SERVICE_ISOLATION_POLICY_VERSION,
            "isolation_backend": self.isolation_descriptor.as_dict(),
            **self._isolation_contract("pending"),
            "env_keys": sorted(self.env),
            "healthcheck": self._health_url_info() if self.health_url
            else {"configured": bool(self.health_command), "kind": "command" if self.health_command else "none"},
            "expected_status": list(self.expected_status),
            "startup_timeout": self.startup_timeout,
            "shutdown_timeout": self.shutdown_timeout,
            "config_digest": _digest({
                "enabled": self.enabled, "start": self.start_command,
                "allow_unconfined_start": self.allow_unconfined_start,
                "stop": self.stop_command, "health_url": self.health_url,
                "health_command": self.health_command, "working_dir": str(self.working_dir),
                "env_keys": sorted(self.env), "expected_status": self.expected_status,
                "stop_external": self.stop_external,
                "isolation_policy": SERVICE_ISOLATION_POLICY_VERSION,
                "isolation_backend": self.isolation_descriptor.as_dict(),
                "run_id": self.run_id,
            })[:24],
            "claim_status": CLAIM_STATUS,
        }

    def _isolation_contract(self, status: str) -> Dict[str, Any]:
        if self._managed_service_started:
            descriptor = self.isolation_descriptor
            isolation_status = "isolated"
            reason = ("managed target service runs under %s (%s)" %
                      (descriptor.backend, descriptor.version))
            result = {
                "policy": SERVICE_ISOLATION_POLICY_VERSION,
                "status": isolation_status,
                "enforced": True,
                "backend": descriptor.backend,
                "backend_version": descriptor.version,
                "reason": reason,
                "claim_status": CLAIM_STATUS,
            }
        elif status == "external-ready":
            isolation_status = "unknown-external-process"
            reason = ("VulnGate did not start or sandbox this already-ready "
                      "service; its host access is unknown")
            result = {
                "policy": SERVICE_ISOLATION_POLICY_VERSION,
                "status": isolation_status,
                "enforced": False,
                "backend": "external-process",
                "backend_version": "unknown",
                "reason": reason,
                "claim_status": CLAIM_STATUS,
            }
        else:
            isolation_status = "not-started"
            reason = ("no target service process was started by this lifecycle; "
                      + self.isolation_descriptor.reason)
            result = {
                "policy": SERVICE_ISOLATION_POLICY_VERSION,
                "status": isolation_status,
                "enforced": False,
                "backend": self.isolation_descriptor.backend,
                "backend_version": self.isolation_descriptor.version,
                "reason": reason,
                "claim_status": CLAIM_STATUS,
            }
        return {
            "network_isolation": dict(result),
            "filesystem_isolation": dict(result),
        }

    def _read_process_registry(self) -> List[Dict[str, Any]]:
        try:
            payload = json.loads(self.process_registry.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        records = payload.get("processes", []) if isinstance(payload, dict) else []
        return [item for item in records if isinstance(item, dict)][-MAX_PROCESS_RECORDS:]

    def _acquire_lock(self) -> None:
        if self._lock_handle is not None:
            return
        self.state_dir.mkdir(parents=True, exist_ok=True)
        handle = self.lock_path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except OSError:
            handle.close()
            raise
        self._lock_handle = handle

    def _release_lock(self) -> None:
        if self._lock_handle is None:
            return
        try:
            fcntl.flock(self._lock_handle.fileno(), fcntl.LOCK_UN)
            self._lock_handle.close()
        except OSError:
            pass
        self._lock_handle = None

    def _write_process_registry(self, records: List[Dict[str, Any]]) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": PROCESS_SCHEMA_VERSION,
            "processes": records[-MAX_PROCESS_RECORDS:],
            "claim_status": CLAIM_STATUS,
        }
        tmp = self.process_registry.with_name(
            self.process_registry.name + ".tmp.%d" % os.getpid())
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                       encoding="utf-8")
        tmp.replace(self.process_registry)

    def _register_process(self, pid: int) -> None:
        health = self._health_url_info()
        records = []
        for item in self._read_process_registry():
            try:
                same_pid = int(item.get("pid", -1) or -1) == int(pid)
            except (TypeError, ValueError):
                same_pid = False
            if not same_pid:
                records.append(item)
        records.append({
            "target": _text(self.target, 120),
            "round": self.round_no,
            "pid": int(pid),
            "port": health.get("port") if health.get("configured") else None,
            "healthcheck_url_digest": health.get("url_digest", ""),
            "config_digest": self.snapshot().get("config_digest", ""),
            "resource_limits": dict(self.resource_limits),
            **self._isolation_contract("started"),
            "active": True,
            "status": "started",
            "started_at": int(time.time()),
            "claim_status": CLAIM_STATUS,
        })
        try:
            self._write_process_registry(records)
        except OSError as exc:
            # The process itself is still bounded and will be cleaned up; a
            # filesystem bookkeeping failure must not turn into a finding.
            self.registry_error = type(exc).__name__

    def _mark_process_stopped(self, pid: Optional[int], status: str) -> None:
        if pid is None:
            return
        tree_limits = self.resource_limits.get("process_tree_rss")
        still_active = (status in {"cleanup-incomplete", "stop-timeout"}
                        or (isinstance(tree_limits, dict)
                            and tree_limits.get("cleanup_status") in {
                                "incomplete", "unverified"}))
        records = self._read_process_registry()
        changed = False
        for item in records:
            try:
                same_pid = int(item.get("pid", -1)) == int(pid)
            except (TypeError, ValueError):
                same_pid = False
            if same_pid and item.get("target") == _text(self.target, 120):
                item.update({"active": still_active,
                             "status": status,
                             "stopped_at": None if still_active else int(time.time()),
                             "resource_limits": dict(self.resource_limits),
                             "claim_status": CLAIM_STATUS})
                changed = True
        if changed:
            try:
                self._write_process_registry(records)
            except OSError as exc:
                self.registry_error = type(exc).__name__

    def _base_result(self, status: str, ready: bool, **extra: Any) -> Dict[str, Any]:
        result = self.snapshot()
        result.update({"status": status, "ready": bool(ready), "claim_status": CLAIM_STATUS})
        result.update(self._isolation_contract(status))
        result.update(extra)
        self._state = result
        return result

    def _start_process_tree_monitor(self) -> None:
        limits = self.resource_limits.get("process_tree_rss")
        if not isinstance(limits, dict) or self.process is None:
            return
        limits["status"] = "monitoring"
        self._tree_monitor_stop.clear()

        def observe(snapshot: Dict[str, Any]) -> bool:
            limits["sample_count"] += 1
            limits["tracked_process_count"] = max(
                limits["tracked_process_count"],
                len(self._tracked_process_start_times))
            limits["peak_process_count"] = max(
                limits["peak_process_count"], snapshot["process_count"])
            limits["peak_rss_bytes"] = max(
                limits["peak_rss_bytes"], snapshot["rss_bytes"])
            if snapshot["rss_bytes"] > limits["max_bytes"]:
                limits["status"] = "limit-exceeded"
                self.resource_limit_error = "process-tree-rss-exceeded"
                return True
            return False

        def abort_service(status: str, error: str = "") -> None:
            limits["status"] = status
            if error:
                limits["monitor_error"] = error
            self.resource_limit_error = (
                "process-tree-rss-exceeded" if status == "limit-exceeded"
                else "process-tree-rss-monitor-unavailable")
            if self.execution_budget is not None:
                self.execution_budget.abort(
                    "managed-service-process-tree-" + status)
            self._cleanup_managed_process_tree(immediate=True)
            self._mark_tree_monitor_failure()

        # Take the first sample synchronously, before startup code can call
        # Popen.poll() and reap a short-lived leader. That sample establishes
        # the root PID/start-time identity and captures children before they
        # can be reparented.
        snapshot, error = _process_tree_snapshot(
            self.process.pid, self._tracked_process_start_times)
        if error or snapshot is None:
            abort_service("monitor-error", error or
                          "process-tree-snapshot-unavailable")
            return
        if observe(snapshot):
            abort_service("limit-exceeded")
            return

        def monitor() -> None:
            while not self._tree_monitor_stop.wait(
                    POC_PROCESS_TREE_SAMPLE_INTERVAL_SECONDS):
                process = self.process
                if process is None:
                    return
                snapshot, error = _process_tree_snapshot(
                    process.pid, self._tracked_process_start_times)
                if error or snapshot is None:
                    abort_service(
                        "monitor-error",
                        error or "process-tree-snapshot-unavailable")
                    return
                if observe(snapshot):
                    abort_service("limit-exceeded")
                    return

        self._tree_monitor_thread = threading.Thread(
            target=monitor, name="vulngate-service-rss-%d" % self.process.pid,
            daemon=True)
        self._tree_monitor_thread.start()

    def _mark_tree_monitor_failure(self) -> None:
        limits = self.resource_limits.get("process_tree_rss")
        if not isinstance(limits, dict) or not isinstance(self._state, dict):
            return
        status = ("resource-limit-exceeded"
                  if limits.get("status") == "limit-exceeded"
                  else "resource-monitor-error")
        self._state.update({
            "status": status,
            "ready": False,
            "reason": self.resource_limit_error or status,
            "resource_limits": dict(self.resource_limits),
            "resource_limit_error": self.resource_limit_error,
        })

    def _signal_managed_process_tree(self, signum: int) -> Optional[Dict[str, Any]]:
        process = self.process
        limits = self.resource_limits.get("process_tree_rss")
        if process is None:
            return None
        snapshot, error = _process_tree_snapshot(
            process.pid, self._tracked_process_start_times)
        if error or snapshot is None:
            if isinstance(limits, dict):
                limits["cleanup_status"] = "unverified"
                limits["cleanup_error"] = error or "process-tree-snapshot-unavailable"
            if signum == signal.SIGKILL and process.poll() is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                except OSError:
                    if isinstance(limits, dict):
                        limits["cleanup_status"] = "incomplete"
            return None
        if snapshot["process_group_tracked"]:
            try:
                os.killpg(process.pid, signum)
            except ProcessLookupError:
                pass
            except OSError:
                if isinstance(limits, dict):
                    limits["cleanup_status"] = "incomplete"
        for pid in snapshot["pids"]:
            if pid == process.pid:
                continue
            try:
                os.kill(pid, signum)
            except ProcessLookupError:
                pass
            except OSError:
                if isinstance(limits, dict):
                    limits["cleanup_status"] = "incomplete"
        if signum == signal.SIGKILL and process.poll() is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            except OSError:
                if isinstance(limits, dict):
                    limits["cleanup_status"] = "incomplete"
        return snapshot

    def _cleanup_managed_process_tree(self, immediate: bool) -> str:
        process = self.process
        limits = self.resource_limits.get("process_tree_rss")
        if process is None:
            return "not-managed"
        timed_out = False
        if immediate:
            self._signal_managed_process_tree(signal.SIGKILL)
            if process.poll() is None:
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    if isinstance(limits, dict):
                        limits["cleanup_status"] = "incomplete"
        else:
            self._signal_managed_process_tree(signal.SIGTERM)
            if process.poll() is None:
                try:
                    process.wait(timeout=self.shutdown_timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    self._signal_managed_process_tree(signal.SIGKILL)
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        if isinstance(limits, dict):
                            limits["cleanup_status"] = "incomplete"
        # The group leader may exit before descendants. Re-snapshot and kill
        # observed survivors individually; never signal an unverified PGID.
        cleanup_deadline = time.monotonic() + 0.5
        while True:
            snapshot, error = _process_tree_snapshot(
                process.pid, self._tracked_process_start_times)
            if error or snapshot is None:
                if isinstance(limits, dict):
                    limits["cleanup_status"] = "unverified"
                    limits["cleanup_error"] = error or "process-tree-snapshot-unavailable"
                break
            survivors = [pid for pid in snapshot["live_pids"]
                         if pid != process.pid]
            if not survivors:
                if (isinstance(limits, dict) and limits.get("cleanup_status")
                        not in {"incomplete", "unverified"}):
                    limits["cleanup_status"] = "complete"
                break
            self._signal_managed_process_tree(signal.SIGKILL)
            if time.monotonic() >= cleanup_deadline:
                if isinstance(limits, dict):
                    limits["cleanup_status"] = "incomplete"
                    limits["cleanup_remaining_count"] = len(survivors)
                break
            time.sleep(0.05)
        if isinstance(limits, dict) and limits.get("cleanup_status") == "complete":
            if limits.get("status") == "monitoring":
                limits["status"] = "completed"
        if isinstance(limits, dict) and limits.get("cleanup_status") in {
                "incomplete", "unverified"}:
            self.resource_limit_error = (
                self.resource_limit_error or "process-tree-cleanup-incomplete")
        if timed_out:
            return "killed-after-timeout"
        if isinstance(limits, dict) and limits.get("cleanup_status") != "complete":
            return "cleanup-incomplete"
        return "stopped"

    def _stop_process_tree_monitor(self) -> None:
        self._tree_monitor_stop.set()
        thread = self._tree_monitor_thread
        if (thread is not None and thread.is_alive()
                and thread is not threading.current_thread()):
            thread.join(timeout=POC_PROCESS_TABLE_TIMEOUT_SECONDS + 2)
            if thread.is_alive():
                limits = self.resource_limits.get("process_tree_rss")
                if isinstance(limits, dict):
                    limits["cleanup_status"] = "unverified"
                    limits["cleanup_error"] = "process-tree-monitor-did-not-stop"

    def _probe(self) -> Dict[str, Any]:
        if self.health_url:
            if (self._managed_service_started and self.isolation_backend is not None
                    and self.isolation_descriptor.network in {
                        "private-network-namespace-loopback-only",
                        "container-network-none",
                    }):
                return {"kind": "url", "ready": False,
                        "status": "policy-denied",
                        "reason": "isolated service requires an in-namespace healthcheck_command"}
            info = self._health_url_info()
            if not info.get("valid"):
                return {"kind": "url", "ready": False, "status": "policy-denied"}
            # A service healthcheck is explicitly loopback-only.  Use a direct
            # socket and one HTTP/1.0 request instead of urllib/http.client:
            # macOS runners can expose system proxy and keep-alive behaviour
            # that makes a local request time out even when the service is up.
            # This still performs a real TCP/HTTP healthcheck and never follows
            # redirects, uses a proxy, or contacts a non-loopback host.
            parsed = urlparse(self.health_url)
            host = parsed.hostname or ""
            connect_host = _loopback_connect_host(host)
            if not connect_host:
                return {"kind": "url", "ready": False,
                        "status": "policy-denied"}
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
            connection = None
            phase = "connect"
            try:
                connection = socket.create_connection(
                    (connect_host, port), timeout=self.health_timeout)
                if parsed.scheme == "https":
                    phase = "tls"
                    connection = ssl.create_default_context().wrap_socket(
                        connection, server_hostname=host)
                connection.settimeout(self.health_timeout)
                phase = "request"
                request = (
                    "GET %s HTTP/1.0\r\n"
                    "Host: %s\r\n"
                    "User-Agent: VulnGate-HealthCheck/1\r\n"
                    "Connection: close\r\n\r\n"
                ) % (target, host)
                connection.sendall(request.encode("ascii", "ignore"))
                phase = "response"
                status_line = connection.recv(4096).split(b"\r\n", 1)[0]
                match = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", status_line)
                code = int(match.group(1)) if match else 0
                return {"kind": "url", "ready": code in self.expected_status,
                        "http_status": code}
            except (OSError, TimeoutError) as exc:
                return {"kind": "url", "ready": False,
                        "error": type(exc).__name__, "phase": phase}
            finally:
                if connection is not None:
                    connection.close()
        if self.health_command:
            command = self._resolve_command_paths(self.health_command)
            if self._managed_service_started and self.isolation_backend is not None:
                command = self.isolation_backend.health_command(
                    command, int(self.process.pid) if self.process is not None else None)
            error = self._validate_command(command)
            if error:
                return {"kind": "command", "ready": False, "status": "policy-denied"}
            try:
                result = self.runner.run(
                    command, cwd=self.working_dir,
                    env_extra={**self.env, "VULNGATE_SERVICE_HEALTHCHECK": "true"},
                    operation="service_lifecycle",
                    operation_detail="local service healthcheck",
                    timeout=self.health_timeout, minimal_env=True)
                return {"kind": "command", "ready": result.returncode == 0,
                        "returncode": result.returncode,
                        "timed_out": result.timed_out}
            except (OSError, PermissionError) as exc:
                return {"kind": "command", "ready": False,
                        "error": type(exc).__name__}
        return {"kind": "none", "ready": False, "status": "healthcheck-missing"}

    def ensure_ready(self) -> Dict[str, Any]:
        if not self.configured:
            return self._base_result("not-configured", True)
        if not self.enabled:
            return self._base_result("disabled", True)
        try:
            self._acquire_lock()
        except OSError as exc:
            return self._base_result("run-failed", False,
                                     reason="service lock: %s" % type(exc).__name__)
        if not self._within_workspace(self.working_dir) or not self.working_dir.is_dir():
            self._release_lock()
            return self._base_result("precondition-unavailable", False,
                                     reason="working_dir outside workspace or missing")
        if not self.health_url and not self.health_command:
            self._release_lock()
            return self._base_result("precondition-unavailable", False,
                                     reason="explicit loopback healthcheck required")
        # Reuse an already-running authorized local service.  This makes the
        # ordinary S4 matrix and the runtime lab composable without launching
        # two copies of the target.
        existing = self._probe()
        if existing.get("ready"):
            return self._base_result("external-ready", True, health=existing)
        if not self.start_command:
            self._release_lock()
            return self._base_result("precondition-unavailable", False,
                                     health=existing,
                                     reason="service is not ready and start_command is absent")
        if self.isolation_backend is None:
            reason = ("managed service start requires an available isolation "
                      "backend; refusing unconfined launch: "
                      + self.isolation_descriptor.reason)
            self.approval.request("policy_denied", "service lifecycle start: " + reason)
            self._release_lock()
            return self._base_result("policy-denied", False,
                                     health=existing, reason=reason)
        error = self._validate_command(self.start_command)
        if error:
            self.approval.request("policy_denied", "service lifecycle start: " + error)
            self._release_lock()
            return self._base_result("policy-denied", False, reason=error)
        try:
            self.approval.assert_allowed(
                "service_lifecycle",
                "start local service for target %s" % self.target)
        except PermissionError as exc:
            self._release_lock()
            return self._base_result("policy-denied", False,
                                     health=existing, reason=str(exc))
        config_digest = str(self.snapshot().get("config_digest", ""))
        if not self.approval.consume_authorized(
                "service_lifecycle", self.run_id, config_digest):
            reason = ("service start requires a one-time operator approval "
                      "bound to run_id=%s and config_digest=%s" %
                      (self.run_id, config_digest))
            self.approval.request("policy_denied", reason)
            self._release_lock()
            return self._base_result("policy-denied", False,
                                     health=existing, reason=reason)
        service_env = minimal_poc_env({
            **self.env, "VULNGATE_SERVICE_LIFECYCLE": "true"})
        try:
            limited_command, self.resource_limits = (
                prepare_posix_resource_limited_command(
                    self._resolve_command_paths(self.start_command), service_env,
                    cpu_seconds_per_process=3600, preflight_timeout=5))
            self.resource_limits["process_tree_rss"] = {
                "policy": POC_PROCESS_TREE_RSS_POLICY_VERSION,
                "status": "pending",
                "max_bytes": POC_MAX_PROCESS_TREE_RSS_BYTES,
                "sample_interval_ms": int(
                    POC_PROCESS_TREE_SAMPLE_INTERVAL_SECONDS * 1000),
                "peak_rss_bytes": 0,
                "peak_process_count": 0,
                "sample_count": 0,
                "tracked_process_count": 0,
            }
            if self.isolation_descriptor.backend == "linux-bubblewrap":
                self.cgroup_controller = self.isolation_backend.prepare_cgroup(
                    self.workspace, "%s-%s" % (self.target, self.round_no))
                if self.cgroup_controller is None:
                    raise PermissionError("delegated cgroup v2 unavailable")
                self.resource_limits["cgroup_v2"] = self.cgroup_controller.snapshot()
        except PermissionError as exc:
            self.resource_limit_error = str(exc)[:300]
            self.approval.request(
                "policy_denied", "service resource limit preflight: " +
                self.resource_limit_error)
            self._release_lock()
            return self._base_result("policy-denied", False,
                                     health=existing,
                                     reason="service resource limits unavailable")
        try:
            isolated_command = self.isolation_backend.wrap_command(
                limited_command, self.workspace, self.working_dir, service_env)
            work_budget = getattr(self.execution_budget, "work_budget", None)
            if work_budget is not None:
                work_budget.acquire_process()
            self.process = subprocess.Popen(
                isolated_command,
                cwd=str(self.working_dir),
                env=service_env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                text=True, start_new_session=True)
            if self.cgroup_controller is not None:
                try:
                    self.cgroup_controller.attach(int(self.process.pid))
                    self.resource_limits["cgroup_v2"] = self.cgroup_controller.snapshot()
                except OSError as exc:
                    self.resource_limit_error = "cgroup v2 attach failed: %s" % type(exc).__name__
                    self._cleanup_managed_process_tree(immediate=True)
                    raise PermissionError(self.resource_limit_error) from exc
            self._managed_service_started = True
            self.registry_pid = int(self.process.pid)
            self._register_process(self.registry_pid)
            self._start_process_tree_monitor()
        except WorkBudgetExceeded as exc:
            self._release_lock()
            return self._base_result(
                "budget-exhausted", False, health=existing,
                reason="shared process budget exhausted: %s" % str(exc)[:160])
        except OSError as exc:
            self._release_lock()
            return self._base_result("run-failed", False,
                                     reason=type(exc).__name__)
        deadline = time.monotonic() + self.startup_timeout
        last_health: Dict[str, Any] = {}
        while time.monotonic() < deadline:
            tree_limits = self.resource_limits.get("process_tree_rss")
            if (isinstance(tree_limits, dict) and tree_limits.get("status") in
                    {"limit-exceeded", "monitor-error"}):
                status = ("resource-limit-exceeded"
                          if tree_limits.get("status") == "limit-exceeded"
                          else "resource-monitor-error")
                stop_info = self.stop()
                return self._base_result(
                    status, False, health=last_health,
                    stop=stop_info, reason=self.resource_limit_error or status)
            if self.process.poll() is not None:
                returncode = self.process.returncode
                stop_info = self.stop()
                return self._base_result(
                    "run-failed", False, returncode=returncode,
                    health=last_health, stop=stop_info,
                    reason=("managed service resource monitor: "
                            + self.resource_limit_error)
                    if self.resource_limit_error else
                    "managed service exited before healthcheck")
            last_health = self._probe()
            if last_health.get("ready"):
                return self._base_result("started-ready", True, health=last_health,
                                         process_managed=True)
            time.sleep(self.poll_interval)
        stop_info = self.stop()
        return self._base_result("precondition-unavailable", False,
                                 health=last_health,
                                 stop=stop_info,
                                 reason="healthcheck timeout")

    def stop(self) -> Dict[str, Any]:
        stopped = False
        stop_status = "not-managed"
        managed_pid = self.registry_pid
        if self.process is not None:
            managed_pid = int(self.process.pid)
            self._stop_process_tree_monitor()
            stop_status = self._cleanup_managed_process_tree(immediate=False)
            tree_limits = self.resource_limits.get("process_tree_rss")
            if isinstance(tree_limits, dict):
                if tree_limits.get("status") == "limit-exceeded":
                    stop_status = "resource-limit-exceeded"
                elif tree_limits.get("status") == "monitor-error":
                    stop_status = "resource-monitor-error"
            stopped = (self.process.poll() is not None
                       and stop_status not in {"cleanup-incomplete", "stop-timeout"})
        elif (self.stop_external and self.stop_command and self.configured
              and self.enabled):
            error = self._validate_command(self.stop_command)
            if error:
                stop_status = "policy-denied"
            else:
                try:
                    self.approval.assert_allowed(
                        "service_lifecycle",
                        "stop external local service for target %s" % self.target)
                    result = self.runner.run(
                        self._resolve_command_paths(self.stop_command),
                        cwd=self.working_dir, env_extra=self.env,
                        operation="service_lifecycle",
                        operation_detail="stop local service",
                        timeout=self.shutdown_timeout, minimal_env=True)
                    stopped = result.returncode == 0
                    stop_status = "stopped" if stopped else "run-failed"
                except (OSError, PermissionError) as exc:
                    stop_status = type(exc).__name__
        tree_limits = self.resource_limits.get("process_tree_rss")
        still_active = (stop_status in {"cleanup-incomplete", "stop-timeout"}
                        or (isinstance(tree_limits, dict)
                            and tree_limits.get("cleanup_status") in {
                                "incomplete", "unverified"}))
        if (self.process is not None and self.process.poll() is not None
                and not still_active):
            self.process = None
        self._mark_process_stopped(managed_pid, stop_status)
        if not still_active:
            self.registry_pid = None
            self._release_lock()
            if self.cgroup_controller is not None:
                self.cgroup_controller.close()
                self.cgroup_controller = None
        return {
            "status": stop_status,
            "stopped": stopped,
            "process_tree_cleanup_status": (
                tree_limits.get("cleanup_status", "")
                if isinstance(tree_limits, dict) else ""),
            "process_registry_error": self.registry_error,
            "claim_status": CLAIM_STATUS,
        }

    def result(self) -> Dict[str, Any]:
        return dict(self._state)
