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
import http.client
import json
import os
import re
import shlex
import signal
import ssl
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse, urlunsplit
import ipaddress

from ..sandbox.approval import ApprovalGate
from ..sandbox.runner import (CommandRunner, minimal_poc_env,
                              validate_global_command, validate_poc_command)
from .redaction import redact_text


SERVICE_SCHEMA_VERSION = "service-lifecycle-v1"
PROCESS_SCHEMA_VERSION = "service-processes-v1"
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
    host = str(host or "").strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host in {"localhost", "localhost.localdomain", "::1"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


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
                 config: Any, approval: Optional[ApprovalGate] = None):
        self.workspace = Path(workspace).resolve()
        self.target = str(target)
        self.round_no = int(round_no)
        self.configured, raw = _raw_service(config)
        self.raw = raw
        self.enabled = self.configured and raw.get("enabled", True) is not False
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
        self.state_dir = (self.workspace / "state" / self.target
                          / ("round-%02d" % self.round_no) / "S4")
        self.process_registry = self.state_dir / "processes.json"
        self.lock_path = self.state_dir / "service.lock"
        self._lock_handle = None
        self.registry_error = ""
        self.process: Optional[subprocess.Popen] = None
        self.registry_pid: Optional[int] = None
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
            "enabled": bool(self.enabled),
            "start_command_configured": bool(self.start_command),
            "stop_command_configured": bool(self.stop_command),
            "stop_external": bool(self.stop_external),
            "start_command_digest": _digest(self.start_command)[:24] if self.start_command else "",
            "stop_command_digest": _digest(self.stop_command)[:24] if self.stop_command else "",
            "working_dir": str(self.working_dir.relative_to(self.workspace))
            if self._within_workspace(self.working_dir) else "outside-workspace",
            "process_registry": str(self.process_registry.relative_to(self.workspace)),
            "process_registry_error": self.registry_error,
            "env_keys": sorted(self.env),
            "healthcheck": self._health_url_info() if self.health_url
            else {"configured": bool(self.health_command), "kind": "command" if self.health_command else "none"},
            "expected_status": list(self.expected_status),
            "startup_timeout": self.startup_timeout,
            "shutdown_timeout": self.shutdown_timeout,
            "config_digest": _digest({
                "enabled": self.enabled, "start": self.start_command,
                "stop": self.stop_command, "health_url": self.health_url,
                "health_command": self.health_command, "working_dir": str(self.working_dir),
                "env_keys": sorted(self.env), "expected_status": self.expected_status,
                "stop_external": self.stop_external,
            })[:24],
            "claim_status": CLAIM_STATUS,
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
        records = self._read_process_registry()
        changed = False
        for item in records:
            try:
                same_pid = int(item.get("pid", -1)) == int(pid)
            except (TypeError, ValueError):
                same_pid = False
            if same_pid and item.get("target") == _text(self.target, 120):
                item.update({"active": False, "status": status,
                             "stopped_at": int(time.time()),
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
        result.update(extra)
        self._state = result
        return result

    def _probe(self) -> Dict[str, Any]:
        if self.health_url:
            info = self._health_url_info()
            if not info.get("valid"):
                return {"kind": "url", "ready": False, "status": "policy-denied"}
            # A service healthcheck is explicitly loopback-only.  Use a direct
            # HTTP client instead of urllib's environment-sensitive opener:
            # macOS runners can expose system proxy settings that make a
            # loopback request fail even when NO_PROXY is deliberately empty.
            # Direct connection also keeps the policy obvious: no redirect,
            # proxy, DNS rebinding or remote request is involved here.
            parsed = urlparse(self.health_url)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
            connection = None
            try:
                if parsed.scheme == "https":
                    connection = http.client.HTTPSConnection(
                        host, port, timeout=self.health_timeout,
                        context=ssl.create_default_context())
                else:
                    connection = http.client.HTTPConnection(
                        host, port, timeout=self.health_timeout)
                connection.request(
                    "GET", target,
                    headers={"User-Agent": "VulnGate-HealthCheck/1"})
                response = connection.getresponse()
                code = int(response.status or 0)
                return {"kind": "url", "ready": code in self.expected_status,
                        "http_status": code}
            except (http.client.HTTPException, OSError, TimeoutError) as exc:
                return {"kind": "url", "ready": False,
                        "error": type(exc).__name__}
            finally:
                if connection is not None:
                    connection.close()
        if self.health_command:
            command = self._resolve_command_paths(self.health_command)
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
        error = self._validate_command(self.start_command)
        if error:
            self.approval.request("policy_denied", "service lifecycle start: " + error)
            self._release_lock()
            return self._base_result("policy-denied", False, reason=error)
        try:
            self.approval.assert_allowed(
                "service_lifecycle",
                "start local service for target %s" % self.target)
            self.process = subprocess.Popen(
                self._resolve_command_paths(self.start_command),
                cwd=str(self.working_dir),
                env=minimal_poc_env({**self.env, "VULNGATE_SERVICE_LIFECYCLE": "true"}),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                text=True, start_new_session=True)
            self.registry_pid = int(self.process.pid)
            self._register_process(self.registry_pid)
        except (OSError, PermissionError) as exc:
            self._release_lock()
            return self._base_result("run-failed", False,
                                     reason=type(exc).__name__)
        deadline = time.monotonic() + self.startup_timeout
        last_health: Dict[str, Any] = {}
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                result = self._base_result("run-failed", False,
                                           returncode=self.process.returncode,
                                           health=last_health)
                self._mark_process_stopped(self.registry_pid, "run-failed")
                self.registry_pid = None
                self.process = None
                self._release_lock()
                return result
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
        if self.process is not None and self.process.poll() is None:
            managed_pid = int(self.process.pid)
            try:
                self.approval.assert_allowed(
                    "service_lifecycle",
                    "stop local service for target %s" % self.target)
                os.killpg(self.process.pid, signal.SIGTERM)
                self.process.wait(timeout=self.shutdown_timeout)
                stopped = True
                stop_status = "stopped"
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait(timeout=2)
                    stopped = True
                    stop_status = "killed-after-timeout"
                except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
                    stop_status = "stop-timeout"
            except (OSError, PermissionError) as exc:
                stop_status = type(exc).__name__
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
        if self.process is not None and self.process.poll() is not None:
            self.process = None
        self._mark_process_stopped(managed_pid, stop_status)
        self.registry_pid = None
        self._release_lock()
        return {
            "status": stop_status,
            "stopped": stopped,
            "process_registry_error": self.registry_error,
            "claim_status": CLAIM_STATUS,
        }

    def result(self) -> Dict[str, Any]:
        return dict(self._state)
