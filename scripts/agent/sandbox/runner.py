"""Constrained command execution for build/run steps.

* commands are passed as argv lists (no shell interpretation);
* cwd must stay under the workspace roots;
* one command cannot hold the audit host longer than its fixed wall-clock cap;
* POSIX PoCs inherit hard CPU, address-space, file-size, descriptor,
  user-process, and core-dump limits;
* approval-gated operations (loopback connects) are recorded.
"""

from __future__ import annotations

import os
import ipaddress
import codecs
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from urllib.parse import urlparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .approval import ApprovalGate
from ..orchestrator.work_budget import WorkBudgetExceeded


@dataclass
class RunResult:
    cmd: List[str]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    resource_limits: Dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 0
    timeout_capped: bool = False
    scratch_limits: Dict[str, Any] = field(default_factory=dict)
    resource_limit_exceeded: str = ""
    abort_reason: str = ""
    process_tree_cleanup: Dict[str, Any] = field(default_factory=dict)


POC_RESOURCE_POLICY_VERSION = "posix-rlimit-as4g-headroom-cpu-fsize64m-nofile512-nproc128-core0-v6"
POC_MAX_FILE_BYTES = 64 * 1024 * 1024
POC_MAX_OPEN_FILES = 512
POC_MAX_PROCESS_SPAWN_DELTA = 128
POC_MAX_ADDRESS_SPACE_BYTES = 4 * 1024 * 1024 * 1024
POC_MIN_ADDRESS_SPACE_BYTES = 256 * 1024 * 1024
POC_DEFAULT_JAVA_HEAP_BYTES = 1024 * 1024 * 1024
POC_SCRATCH_LIMIT_POLICY_VERSION = "scratch-watchdog-256m-4096-v1"
POC_MAX_SCRATCH_BYTES = 256 * 1024 * 1024
POC_MAX_SCRATCH_ENTRIES = 4096
POC_SCRATCH_SAMPLE_INTERVAL_SECONDS = 0.25
POC_PROCESS_TREE_RSS_POLICY_VERSION = "process-tree-rss-watchdog-2g-100ms-v1"
POC_MAX_PROCESS_TREE_RSS_BYTES = 2 * 1024 * 1024 * 1024
POC_PROCESS_TREE_SAMPLE_INTERVAL_SECONDS = 0.1
POC_PROCESS_TABLE_TIMEOUT_SECONDS = 1
MAX_COMMAND_WALL_TIMEOUT_SECONDS = 15 * 60
PROCESS_TREE_CLEANUP_POLICY_VERSION = "verified-pid-starttime-cleanup-v2"

_POSIX_RESOURCE_LAUNCHER = r'''set -eu
cpu_limit="$1"
file_blocks="$2"
open_files="$3"
user_process_limit="$4"
address_space_kib="$5"
shift 5
ulimit -S -c 0
ulimit -H -c 0
ulimit -S -n "$open_files"
ulimit -H -n "$open_files"
ulimit -S -f "$file_blocks"
ulimit -H -f "$file_blocks"
ulimit -S -t "$cpu_limit"
ulimit -H -t "$cpu_limit"
ulimit -S -u "$user_process_limit"
ulimit -H -u "$user_process_limit"
ulimit -S -v "$address_space_kib"
ulimit -H -v "$address_space_kib"
exec "$@"
'''


def _user_process_limit() -> Tuple[int, int]:
    """Cap descendants at 128 above the current real-UID process baseline."""
    import resource

    if not hasattr(resource, "RLIMIT_NPROC"):
        raise PermissionError("RLIMIT_NPROC is unavailable")
    try:
        result = subprocess.run(
            ["/bin/ps", "-axo", "ruid="], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PermissionError("cannot measure current user process count") from exc
    if result.returncode != 0:
        raise PermissionError("cannot measure current user process count")
    uid = str(os.getuid())
    baseline = sum(1 for line in result.stdout.splitlines()
                   if line.strip() == uid)
    if baseline < 1:
        raise PermissionError("current user process count is unavailable")
    _soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
    requested = baseline + POC_MAX_PROCESS_SPAWN_DELTA
    limit = requested if hard == resource.RLIM_INFINITY else min(requested, int(hard))
    if limit <= baseline:
        raise PermissionError("RLIMIT_NPROC is below the current user process count")
    return baseline, limit


def _address_space_baseline_bytes() -> int:
    """Measure the controller VM map that Darwin executables inherit."""
    if sys.platform != "darwin":
        return 0
    try:
        result = subprocess.run(
            ["/bin/ps", "-o", "vsz=", "-p", str(os.getpid())],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, timeout=3, check=True)
        value = int(result.stdout.strip()) * 1024
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise PermissionError(
            "cannot determine Darwin address-space baseline: %s" %
            type(exc).__name__) from exc
    if value < 1 or value > 1024 * 1024 * 1024 * 1024:
        raise PermissionError("Darwin address-space baseline is out of range")
    return value


def _address_space_limit_bytes(baseline_bytes: int) -> int:
    """Set a 4 GiB cap, measured from the inherited Darwin VM-map baseline."""
    import resource

    if not hasattr(resource, "RLIMIT_AS"):
        raise PermissionError("RLIMIT_AS is unavailable")
    _soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    baseline = max(0, int(baseline_bytes))
    limit = baseline + POC_MAX_ADDRESS_SPACE_BYTES
    if hard != resource.RLIM_INFINITY:
        limit = min(limit, int(hard))
    limit = (limit // 1024) * 1024
    if limit - baseline < POC_MIN_ADDRESS_SPACE_BYTES:
        raise PermissionError("RLIMIT_AS hard limit is below the 256 MiB minimum")
    return limit


def _resource_limit_contract(cpu_seconds_per_process: int, process_baseline: int,
                             process_limit: int,
                             address_space_limit: int,
                             address_space_baseline: int) -> Dict[str, Any]:
    import resource

    def clamp_to_hard(which: int, requested: int) -> int:
        _soft, hard = resource.getrlimit(which)
        return (requested if hard == resource.RLIM_INFINITY else
                min(requested, int(hard)))

    cpu_seconds = clamp_to_hard(
        resource.RLIMIT_CPU, max(1, min(int(cpu_seconds_per_process), 3600)))
    file_bytes = clamp_to_hard(resource.RLIMIT_FSIZE, POC_MAX_FILE_BYTES)
    open_files = clamp_to_hard(resource.RLIMIT_NOFILE, POC_MAX_OPEN_FILES)
    user_processes = clamp_to_hard(resource.RLIMIT_NPROC, process_limit)
    address_space_bytes = clamp_to_hard(
        resource.RLIMIT_AS, max(1, int(address_space_limit)))
    address_space_headroom = address_space_bytes - max(
        0, int(address_space_baseline))
    if cpu_seconds < 1 or file_bytes < 1 or open_files < 16:
        raise PermissionError("host hard limits are too low for the PoC resource profile")
    if user_processes <= process_baseline:
        raise PermissionError("RLIMIT_NPROC is below the current user process count")
    if not (POC_MIN_ADDRESS_SPACE_BYTES <= address_space_headroom <=
            POC_MAX_ADDRESS_SPACE_BYTES):
        raise PermissionError("RLIMIT_AS hard limit is below the 256 MiB minimum")
    return {
        "policy": POC_RESOURCE_POLICY_VERSION,
        "cpu_seconds_per_process": cpu_seconds,
        "address_space_baseline_bytes": max(0, int(address_space_baseline)),
        "max_address_space_bytes": address_space_bytes,
        "max_file_bytes": file_bytes,
        "max_open_files": open_files,
        "user_process_baseline": process_baseline,
        "max_user_processes": user_processes,
        "core_bytes": 0,
    }


def _resource_limited_argv(command: List[str],
                           resource_limits: Dict[str, Any]) -> List[str]:
    """Set non-raiseable POSIX resource limits before exec, without preexec_fn."""
    file_blocks = max(1, int(resource_limits["max_file_bytes"]) // 1024)
    address_space_kib = max(
        1, int(resource_limits["max_address_space_bytes"]) // 1024)
    return ["/bin/bash", "-c", _POSIX_RESOURCE_LAUNCHER,
            "vulngate-resource-limits",
            str(resource_limits["cpu_seconds_per_process"]),
            str(file_blocks),
            str(resource_limits["max_open_files"]),
            str(resource_limits["max_user_processes"]),
            str(address_space_kib)] + list(command)


def prepare_posix_resource_limited_command(
        command: List[str], env: Dict[str, str], *,
        cpu_seconds_per_process: int = 3600,
        preflight_timeout: int = 5
        ) -> Tuple[List[str], Dict[str, Any]]:
    """Preflight and wrap a long-lived POSIX child with the shared hard caps."""
    if os.name != "posix":
        raise PermissionError("required POSIX resource limits are unavailable")
    try:
        process_baseline, process_limit = _user_process_limit()
    except PermissionError:
        raise
    address_space_baseline = _address_space_baseline_bytes()
    resource_limits = _resource_limit_contract(
        cpu_seconds_per_process, process_baseline, process_limit,
        _address_space_limit_bytes(address_space_baseline),
        address_space_baseline)
    limit_check = (
        "import resource,sys; e=sys.argv; "
        "pairs=((resource.RLIMIT_CPU,int(e[1])),"
        "(resource.RLIMIT_FSIZE,int(e[2])),"
        "(resource.RLIMIT_NOFILE,int(e[3])),"
        "(resource.RLIMIT_NPROC,int(e[4])),"
        "(resource.RLIMIT_CORE,0),"
        "(resource.RLIMIT_AS,int(e[5]))); "
        "sys.exit(0 if all(resource.getrlimit(r) == (v,v) "
        "for r,v in pairs) else 1)"
    )
    try:
        preflight = subprocess.run(
            _resource_limited_argv([
                sys.executable, "-c", limit_check,
                str(resource_limits["cpu_seconds_per_process"]),
                str(resource_limits["max_file_bytes"]),
                str(resource_limits["max_open_files"]),
                str(resource_limits["max_user_processes"]),
                str(resource_limits["max_address_space_bytes"]),
            ], resource_limits),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, text=True,
            timeout=max(1, min(int(preflight_timeout), 5)), check=False,
            env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PermissionError(
            "required POSIX resource-limit preflight failed: %s" %
            type(exc).__name__) from exc
    if preflight.returncode != 0:
        detail = (preflight.stderr or "preflight exited %d" % preflight.returncode)
        raise PermissionError("required POSIX resource-limit profile failed: %s" %
                              detail[-240:])
    return (_resource_limited_argv(list(command), resource_limits),
            resource_limits)


def _measure_scratch_tree(root: Path) -> Tuple[Optional[Dict[str, int]], str]:
    """Count scratch entries without following symlinks or walking past the cap."""
    entries = 0
    files = 0
    total_bytes = 0
    pending = [root]
    try:
        if not stat.S_ISDIR(root.lstat().st_mode):
            return None, "scratch-root-is-not-directory"
    except OSError as exc:
        return None, "scratch-root-unavailable:%s" % type(exc).__name__

    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    entries += 1
                    if entries > POC_MAX_SCRATCH_ENTRIES:
                        return {"entries": entries, "files": files,
                                "bytes": total_bytes}, ""
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        # Ignore a temporary file removed during this sample.
                        continue
                    except OSError as exc:
                        return None, "scratch-entry-unavailable:%s" % type(exc).__name__
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(Path(entry.path))
                    else:
                        files += 1
                        if stat.S_ISREG(info.st_mode):
                            total_bytes += max(0, int(info.st_size))
                            if total_bytes > POC_MAX_SCRATCH_BYTES:
                                return {"entries": entries, "files": files,
                                        "bytes": total_bytes}, ""
        except OSError as exc:
            return None, "scratch-directory-unavailable:%s" % type(exc).__name__
    return {"entries": entries, "files": files, "bytes": total_bytes}, ""


def _process_tree_snapshot(
        root_pid: int, tracked_start_times: Dict[int, str]
        ) -> Tuple[Optional[Dict[str, Any]], str]:
    """Measure RSS for the command descendants, including known reparented children.

    `ps` reports RSS in KiB and a process start timestamp. The timestamp lets
    the runner distinguish a tracked child from an unrelated process that later
    reuses its PID. This is sampled stop-loss monitoring, not a kernel quota.
    """
    try:
        result = subprocess.run(
            ["/bin/ps", "-axo", "pid=,ppid=,pgid=,rss=,stat=,lstart="],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            timeout=POC_PROCESS_TABLE_TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, "process-table-unavailable:%s" % type(exc).__name__
    if result.returncode != 0:
        return None, "process-table-exit-%d" % result.returncode

    processes: Dict[int, Tuple[int, int, int, str, str]] = {}
    try:
        for line in result.stdout.splitlines():
            fields = line.strip().split(None, 5)
            if not fields:
                continue
            if len(fields) != 6:
                return None, "process-table-malformed-row"
            pid, ppid, pgid, rss_kib = (int(fields[index]) for index in range(4))
            if pid <= 0 or ppid < 0 or pgid < 0 or rss_kib < 0:
                return None, "process-table-invalid-row"
            processes[pid] = (ppid, pgid, rss_kib * 1024, fields[5], fields[4])
    except (TypeError, ValueError):
        return None, "process-table-invalid-row"

    root = processes.get(root_pid)
    expected_root_start_time = tracked_start_times.get(root_pid)
    root_identity_verified = (
        root is not None and
        (expected_root_start_time is None
         or root[3] == expected_root_start_time))
    children: Dict[int, List[int]] = {}
    for pid, (ppid, _pgid, _rss, _start_time, _state) in processes.items():
        children.setdefault(ppid, []).append(pid)

    descendants = set()
    # Only discover new descendants while the original root is still present
    # with its known identity (or on the first sample, before the Popen handle
    # has had a chance to reap it). Once the root is gone, retain only children
    # that were already observed and identity-tracked. Walking from a vanished
    # PID could adopt and kill an unrelated process tree after PID reuse.
    if root_identity_verified:
        pending = [int(root_pid)]
        while pending:
            parent = pending.pop()
            if parent in descendants:
                continue
            descendants.add(parent)
            pending.extend(children.get(parent, ()))
    if root_pid not in processes:
        descendants.discard(root_pid)

    for pid in descendants:
        _ppid, _pgid, _rss, start_time, _state = processes[pid]
        tracked_start_times[pid] = start_time

    live_tracked = set()
    for pid, start_time in list(tracked_start_times.items()):
        current = processes.get(pid)
        if current is None:
            continue
        if current[3] == start_time:
            live_tracked.add(pid)
        elif pid in descendants and pid != root_pid:
            # The process table shows this PID as a current descendant, so a
            # generation change is a new process in this command's tree.
            tracked_start_times[pid] = current[3]
            live_tracked.add(pid)

    rss_bytes = sum(processes[pid][2] for pid in live_tracked)
    live_pids = sorted(
        pid for pid in live_tracked
        if not processes[pid][4].upper().startswith("Z"))
    return {
        "rss_bytes": rss_bytes,
        "process_count": len(live_tracked),
        "pids": sorted(live_tracked),
        "live_pids": live_pids,
        # A reused process-group ID is never signalled unless a currently
        # tracked, live member still belongs to that original group.
        "process_group_tracked": any(
            processes[pid][1] == root_pid for pid in live_pids),
    }, ""


REMOTE_EXECUTABLES = {
    "ssh", "ssh-add", "ssh-keygen", "scp", "sftp", "telnet", "rlogin",
    "ftp", "rsync", "mosh", "kubectl", "docker", "podman", "aliyun",
    "aws", "gcloud",
}
NETWORK_EXECUTABLES = {"curl", "wget", "nc", "ncat", "socat", "openssl"}
STAGING_REMOTE_EXECUTABLES = {"ssh", "scp", "sftp", "rsync"}
REMOTE_URL_RE = re.compile(r"\b(?:https?|ftp|ldap|ldaps|rmi|tcp|udp|gopher)://[^\s'\"]+", re.I)
HOST_ASSIGNMENT_RE = re.compile(r"(?:https?|ftp|ldap|ldaps|rmi|tcp|udp|gopher)://[^\s'\"]+", re.I)
USER_AT_HOST_RE = re.compile(r"^[^/\s:@]+@[^/\s:@]+(?::\d+)?$")
IP_LITERAL_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")

# Agent processes commonly carry service URLs, proxy settings, API keys and
# other unrelated values in their environment.  They are not part of a PoC's
# execution contract and must not affect the loopback policy (or be inherited
# by generated code). Keep only the small execution contract; PoC PATH is
# replaced with platform tool roots before launch and scratch values are
# supplied explicitly by ``minimal_poc_env``.
POC_ENV_POLICY_VERSION = "poc-minimal-v5-explicit-java-home-safe-path"
MINIMAL_ENV_POLICY_VERSION = "poc-minimal-v3-java-heap-cap"
AUDIT_COMMAND_ENV_POLICY_VERSION = "audit-command-minimal-v1"
POC_SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
POC_INHERITED_ENV_KEYS = (
    "PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "LC_CTYPE",
    "JAVA_HOME",
)


def minimal_poc_env(env_extra: Optional[dict] = None, *,
                    restrict_path: bool = False) -> Dict[str, str]:
    """Build the explicit environment contract for a generated PoC.

    ``env_extra`` is caller-supplied target context (for example
    ``VULNGATE_TARGET_URL``), not the host agent's environment.  No full
    environment dump is returned or logged, and agent API/proxy credentials
    never cross the process boundary.
    """
    explicit_java_home = str((env_extra or {}).get("JAVA_HOME") or "")
    env: Dict[str, str] = {}
    for key in POC_INHERITED_ENV_KEYS:
        value = os.environ.get(key)
        if value:
            env[key] = value
    for key, value in (env_extra or {}).items():
        if key and value is not None:
            env[str(key)] = str(value)
    if restrict_path:
        # Avoid selecting executables from ambient user or package-manager
        # directories; the Seatbelt profile separately limits exec/read roots.
        env["PATH"] = POC_SAFE_PATH
        env.pop("JAVA_HOME", None)
        # Java build/run callers may pass a runtime that was separately
        # resolved and added to the Seatbelt read allowlist. Preserve only that
        # explicit value; never inherit the host's ambient JAVA_HOME.
        if explicit_java_home:
            env["JAVA_HOME"] = explicit_java_home
    # HotSpot honors this on JDK 8+; an explicit command-line -Xmx remains
    # authoritative, while RLIMIT_AS provides the hard per-process ceiling.
    heap_mib = max(1, POC_DEFAULT_JAVA_HEAP_BYTES // (1024 * 1024))
    env["JAVA_TOOL_OPTIONS"] = "-Xmx%dm" % heap_mib
    env.setdefault("PYTHONUNBUFFERED", "1")
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    env["VULNGATE_ENV_POLICY"] = (
        POC_ENV_POLICY_VERSION if restrict_path else MINIMAL_ENV_POLICY_VERSION)
    return env


def minimal_audit_command_env(env_extra: Optional[dict] = None) -> Dict[str, str]:
    """Keep ambient credentials out of bounded host-side audit commands."""
    env: Dict[str, str] = {}
    safe_keys = POC_INHERITED_ENV_KEYS + (
        "DEVELOPER_DIR", "SDKROOT", "MACOSX_DEPLOYMENT_TARGET")
    for key in safe_keys:
        value = os.environ.get(key)
        if value:
            env[key] = value
    for key, value in (env_extra or {}).items():
        if key and value is not None:
            env[str(key)] = str(value)
    env.setdefault("PYTHONUNBUFFERED", "1")
    env["VULNGATE_ENV_POLICY"] = AUDIT_COMMAND_ENV_POLICY_VERSION
    return env


def _is_loopback_host(host: str) -> bool:
    host = str(host or "").strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host in {"localhost", "localhost.localdomain", "::1"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _hosts_in_value(value: str) -> List[str]:
    hosts: List[str] = []
    for match in REMOTE_URL_RE.finditer(str(value)):
        try:
            host = urlparse(match.group(0)).hostname or ""
        except ValueError:
            host = ""
        if host:
            hosts.append(host)
    for token in re.split(r"[\s,;]+", str(value)):
        if USER_AT_HOST_RE.fullmatch(token):
            hosts.append(token.rsplit("@", 1)[1].split(":", 1)[0])
        elif "@" in token and not token.startswith("@"):
            # scp/rsync syntax: user@host:/path.  Do not interpret ordinary
            # filesystem paths such as /opt/openjdk@17/... as remote hosts.
            suffix = token.rsplit("@", 1)[1]
            if ":" in suffix:
                remote_host = suffix.split(":", 1)[0]
                if remote_host and "/" not in remote_host:
                    hosts.append(remote_host)
    hosts.extend(IP_LITERAL_RE.findall(str(value)))
    return hosts


def _script_path_from_command(cmd: List[str]) -> Optional[Path]:
    for token in cmd[1:]:
        value = str(token)
        # Wrapper arguments can contain a full Seatbelt profile or another
        # multiline policy document. Such data is not a path, and probing it
        # with Path.exists() can raise ENAMETOOLONG before the command runs.
        if (not value or len(value) >= 1024 or "\n" in value or "\r" in value
                or "\x00" in value or value.startswith("-")):
            continue
        try:
            p = Path(value)
            if p.exists() and p.is_file() and p.suffix in {".sh", ".py", ".rb", ".pl"}:
                return p
        except (OSError, ValueError):
            continue
    return None


def _host_allowed(host: str, authorized_staging: bool,
                  allowed_hosts: Optional[set]) -> bool:
    return authorized_staging and str(host).strip().lower().rstrip(".") in (allowed_hosts or set())


def validate_poc_command(cmd: List[str], env: dict,
                         authorized_staging: bool = False,
                         allowed_hosts: Optional[set] = None) -> Optional[str]:
    """Return a reason when a PoC command cannot run under VulnGate policy.

    This is intentionally conservative. Prompt instructions are not a security
    boundary: a generated shell/Python PoC must not be able to turn the audit
    runner into an SSH client, cloud deployment helper, or public scanner.
    Explicit staging commands are handled separately and are never accepted
    from a generated PoC script.
    """
    if not cmd:
        return "empty command"
    executable = Path(str(cmd[0])).name.lower()
    global_violation = validate_global_command(cmd, authorized_staging, allowed_hosts)
    if global_violation:
        return global_violation

    # ``env`` is deliberately the explicit PoC environment supplied by the
    # caller.  CommandRunner passes only env_extra here, never the inherited
    # agent environment.  This keeps an unrelated value such as
    # ANTHROPIC_BASE_URL from becoming a fake PoC target.
    values = [str(x) for x in cmd] + [str(v) for v in env.values()]
    hosts = [h for value in values for h in _hosts_in_value(value)]
    bad_hosts = [h for h in hosts if not _is_loopback_host(h) and
                 not _host_allowed(h, authorized_staging, allowed_hosts)]
    if bad_hosts:
        return "non-loopback host denied: %s" % ", ".join(sorted(set(bad_hosts))[:4])

    script = _script_path_from_command(cmd)
    if script is not None:
        try:
            source = script.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return "cannot inspect PoC script: %s" % exc
        lowered = source.lower()
        remote_in_script = re.findall(
            r"\b(?:ssh|scp|sftp|telnet|rlogin|rsync|kubectl|docker|podman|aliyun|aws|gcloud)\b",
            lowered)
        if remote_in_script:
            return "remote/cloud command in PoC script denied; use explicit staging command"
        script_hosts = [h for value in source.splitlines() for h in _hosts_in_value(value)]
        bad_script_hosts = [h for h in script_hosts if not _is_loopback_host(h) and
                            not _host_allowed(h, authorized_staging, allowed_hosts)]
        if bad_script_hosts:
            return "non-loopback host in PoC script denied: %s" % ", ".join(sorted(set(bad_script_hosts))[:4])
        if executable in NETWORK_EXECUTABLES or re.search(
                r"\b(?:curl|wget|nc|ncat|socat|socket|requests|urllib|http\.client)\b", lowered):
            # A network-capable script is allowed only when its effective target
            # is explicit and loopback. This blocks opaque DNS/variable escapes.
            effective = [h for value in values + [source] for h in _hosts_in_value(value)]
            if not effective:
                return "network-capable PoC has no explicit loopback target"
    command_text = " ".join(values).lower()
    if (executable in NETWORK_EXECUTABLES or re.search(
            r"\b(?:curl|wget|nc|ncat|socat|socket|requests|urllib|http\.client)\b",
            command_text)) and not hosts:
        return "network-capable PoC has no explicit loopback target"
    return None


def validate_global_command(cmd: List[str], authorized_staging: bool = False,
                            allowed_hosts: Optional[set] = None) -> Optional[str]:
    """Reject remote/deployment primitives in every runner context.

    Read-only network operations remain available to the dedicated novelty
    checker. Remote staging is possible only with an explicit host allowlist;
    a missing operation label never enables it accidentally.
    """
    if not cmd:
        return "empty command"
    executable = Path(str(cmd[0])).name.lower()
    basenames = [Path(str(token)).name.lower() for token in cmd]
    remote_tools = [x for x in basenames if x in REMOTE_EXECUTABLES]
    if remote_tools:
        if not authorized_staging or not all(x in STAGING_REMOTE_EXECUTABLES for x in remote_tools):
            return "remote/cloud execution command denied: %s" % executable
        hosts = [h for value in cmd for h in _hosts_in_value(value)]
        if not hosts:
            return "authorized staging command has no explicit destination host"
        bad = [h for h in hosts if not _host_allowed(h, True, allowed_hosts)]
        if bad:
            return "staging host not in allowlist: %s" % ", ".join(sorted(set(bad))[:4])
    if executable == "git" and any(str(x).lower() in {"push", "receive-pack"}
                                   for x in cmd[1:]):
        return "git write/remote operation denied"
    script = _script_path_from_command(cmd)
    if script is not None:
        try:
            source = script.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return "cannot inspect script: %s" % exc
        remote_in_script = re.findall(
            r"\b(?:ssh|scp|sftp|telnet|rlogin|rsync|kubectl|docker|podman|aliyun|aws|gcloud)\b",
            source, re.I)
        if remote_in_script:
            return "remote/cloud command in script denied; use explicit staging command"
    return None


class CommandRunner:
    def __init__(self, workspace: Path, approval: Optional[ApprovalGate] = None,
                 default_timeout: int = 180, max_output_chars: int = 200_000,
                 authorized_staging: bool = False,
                 staging_hosts: Optional[List[str]] = None,
                 execution_budget: Optional[Any] = None):
        self.workspace = workspace.resolve()
        self.approval = approval or ApprovalGate()
        self.default_timeout = default_timeout
        self.max_output_chars = max_output_chars
        self.authorized_staging = authorized_staging
        self.staging_hosts = {
            str(h).strip().lower().rstrip(".") for h in (staging_hosts or []) if str(h).strip()
        }
        self.execution_budget = execution_budget

    def _check_cwd(self, cwd: Path) -> None:
        cwd = cwd.resolve()
        if not (str(cwd) == str(self.workspace) or str(cwd).startswith(str(self.workspace) + os.sep)):
            raise PermissionError("cwd escapes workspace: %s" % cwd)

    def run(self, cmd: List[str], *, cwd: Optional[Path] = None, timeout: Optional[int] = None,
            env_extra: Optional[dict] = None, operation: Optional[str] = None,
            operation_detail: str = "", minimal_env: bool = False,
            restrict_poc_path: bool = False,
            audit_command_env: bool = False) -> RunResult:
        cwd = (cwd or self.workspace).resolve()
        self._check_cwd(cwd)
        if operation:
            self.approval.assert_allowed(operation, operation_detail)
        normalized_cmd = [str(c) for c in cmd]
        is_poc_operation = minimal_env or operation in {
            "loopback_connect", "port_listen", "external_egress"}
        if is_poc_operation:
            restrict_poc_path = restrict_poc_path or operation in {
                "loopback_connect", "port_listen", "external_egress"}
            env = minimal_poc_env(env_extra, restrict_path=restrict_poc_path)
        elif audit_command_env:
            env = minimal_audit_command_env(env_extra)
        else:
            env = dict(os.environ)
        if env_extra and not is_poc_operation and not audit_command_env:
            env.update({str(k): str(v) for k, v in env_extra.items()})
        env.setdefault("PYTHONUNBUFFERED", "1")
        global_violation = validate_global_command(
            normalized_cmd, self.authorized_staging, self.staging_hosts)
        if global_violation:
            self.approval.request("policy_denied", global_violation)
            raise PermissionError("command denied by hard policy: %s" % global_violation)
        if operation in {"loopback_connect", "port_listen", "external_egress"}:
            violation = validate_poc_command(
                normalized_cmd, {str(k): str(v) for k, v in (env_extra or {}).items()},
                self.authorized_staging, self.staging_hosts)
            if violation:
                self.approval.request("policy_denied", violation)
                raise PermissionError("PoC command denied by hard policy: %s" % violation)
        if self.authorized_staging and any(
                Path(str(c)).name.lower() in STAGING_REMOTE_EXECUTABLES for c in normalized_cmd):
            self.approval.record_authorized(
                "remote_staging", operation_detail or "authorized staging command",
                "hosts=" + ",".join(sorted(self.staging_hosts)))
        requested_timeout = max(1, int(timeout or self.default_timeout))
        effective_timeout = min(requested_timeout, MAX_COMMAND_WALL_TIMEOUT_SECONDS)
        timeout_capped = requested_timeout > MAX_COMMAND_WALL_TIMEOUT_SECONDS
        t0 = time.monotonic()
        resource_limits: Dict[str, Any] = {}
        scratch_dir: Optional[Path] = None
        scratch_limits: Dict[str, Any] = {
            "policy": POC_SCRATCH_LIMIT_POLICY_VERSION,
            "status": "not-configured",
            "max_bytes": POC_MAX_SCRATCH_BYTES,
            "max_entries": POC_MAX_SCRATCH_ENTRIES,
            "sample_interval_ms": int(POC_SCRATCH_SAMPLE_INTERVAL_SECONDS * 1000),
            "peak_bytes": 0,
            "peak_entries": 0,
        }
        process_tree_cleanup: Dict[str, Any] = {
            "policy": PROCESS_TREE_CLEANUP_POLICY_VERSION,
            "status": "not-started",
            "tracked_process_count": 0,
        }
        initial_abort_reason = str(
            getattr(self.execution_budget, "abort_reason", "") or "")[:160]
        if initial_abort_reason:
            scratch_limits["status"] = "aborted"
            scratch_limits["abort_reason"] = initial_abort_reason
            return RunResult(
                normalized_cmd, -1, "", "S4 execution aborted: " + initial_abort_reason,
                0, resource_limits=resource_limits,
                timeout_seconds=effective_timeout, timeout_capped=timeout_capped,
                scratch_limits=scratch_limits, abort_reason=initial_abort_reason,
                process_tree_cleanup=process_tree_cleanup)
        resource_limit_exceeded = ""
        popen_cmd = normalized_cmd
        scratch_value = env.get("VULNGATE_SCRATCH_DIR") if is_poc_operation else None
        if scratch_value:
            try:
                configured_scratch = Path(scratch_value)
                if not configured_scratch.is_absolute():
                    raise PermissionError("PoC scratch directory must be absolute")
                scratch_info = configured_scratch.lstat()
                if not stat.S_ISDIR(scratch_info.st_mode):
                    raise PermissionError("PoC scratch root must be a real directory")
                scratch_dir = configured_scratch.resolve(strict=True)
                self._check_cwd(scratch_dir)
                usage, usage_error = _measure_scratch_tree(scratch_dir)
                if usage_error or usage is None:
                    raise PermissionError("PoC scratch preflight failed: %s" %
                                          (usage_error or "usage unavailable"))
                scratch_limits["peak_bytes"] = usage["bytes"]
                scratch_limits["peak_entries"] = usage["entries"]
                if usage["bytes"] > POC_MAX_SCRATCH_BYTES:
                    raise PermissionError("PoC scratch already exceeds 256 MiB")
                if usage["entries"] > POC_MAX_SCRATCH_ENTRIES:
                    raise PermissionError("PoC scratch already exceeds 4096 entries")
                scratch_limits["status"] = "monitoring"
            except PermissionError as exc:
                self.approval.request("policy_denied", str(exc))
                raise
            except (OSError, RuntimeError) as exc:
                reason = "PoC scratch preflight failed: %s" % type(exc).__name__
                self.approval.request("policy_denied", reason)
                raise PermissionError(reason) from exc
        if is_poc_operation:
            bounded_timeout = effective_timeout
            try:
                popen_cmd, resource_limits = prepare_posix_resource_limited_command(
                    normalized_cmd, env,
                    cpu_seconds_per_process=min(bounded_timeout + 1, 3600),
                    preflight_timeout=min(5, effective_timeout))
                resource_limits["process_tree_rss"] = {
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
            except PermissionError as exc:
                self.approval.request("policy_denied", str(exc))
                raise
        prelaunch_abort_reason = str(
            getattr(self.execution_budget, "abort_reason", "") or "")[:160]
        if prelaunch_abort_reason:
            scratch_limits["status"] = "aborted"
            scratch_limits["abort_reason"] = prelaunch_abort_reason
            tree_limits = resource_limits.get("process_tree_rss")
            if isinstance(tree_limits, dict):
                tree_limits["status"] = "aborted"
                tree_limits["abort_reason"] = prelaunch_abort_reason
            return RunResult(
                normalized_cmd, -1, "", "S4 execution aborted: " + prelaunch_abort_reason,
                int((time.monotonic() - t0) * 1000),
                resource_limits=resource_limits,
                timeout_seconds=effective_timeout, timeout_capped=timeout_capped,
                scratch_limits=scratch_limits, abort_reason=prelaunch_abort_reason,
                process_tree_cleanup=process_tree_cleanup)
        work_budget = getattr(self.execution_budget, "work_budget", None)
        if work_budget is not None:
            try:
                work_budget.acquire_process()
            except WorkBudgetExceeded as exc:
                reason = "shared process budget exhausted: %s" % str(exc)[:160]
                scratch_limits["status"] = "aborted"
                scratch_limits["abort_reason"] = reason
                return RunResult(
                    normalized_cmd, -1, "", reason, int((time.monotonic() - t0) * 1000),
                    resource_limits=resource_limits,
                    timeout_seconds=effective_timeout, timeout_capped=timeout_capped,
                    scratch_limits=scratch_limits, abort_reason=reason,
                    process_tree_cleanup=process_tree_cleanup)
        try:
            proc = subprocess.Popen(
                popen_cmd, cwd=str(cwd), env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True)
            streams = {"stdout": proc.stdout, "stderr": proc.stderr}
            decoders = {key: codecs.getincrementaldecoder("utf-8")("replace")
                        for key in streams}
            captured = {"stdout": [], "stderr": []}
            captured_size = {"stdout": 0, "stderr": 0}
            selector = selectors.DefaultSelector()
            for key, stream in streams.items():
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, key)

            def retain(key, text):
                room = self.max_output_chars - captured_size[key]
                if room > 0 and text:
                    kept = text[:room]
                    captured[key].append(kept)
                    captured_size[key] += len(kept)

            timed_out = False
            abort_reason = ""
            deadline = t0 + effective_timeout
            process_exited_at = None
            cleanup_deadline = None
            group_killed = False
            next_scratch_sample = time.monotonic() + POC_SCRATCH_SAMPLE_INTERVAL_SECONDS
            tracked_process_start_times: Dict[int, str] = {}
            next_process_tree_sample = time.monotonic()
            process_tree_cleanup["status"] = "tracking"

            def sample_process_tree() -> str:
                nonlocal resource_limit_exceeded
                limits = resource_limits.get("process_tree_rss")
                if not isinstance(limits, dict):
                    return ""
                snapshot, error = _process_tree_snapshot(
                    proc.pid, tracked_process_start_times)
                if error or snapshot is None:
                    limits["status"] = "monitor-error"
                    limits["monitor_error"] = error or "process-tree-snapshot-unavailable"
                    if not resource_limit_exceeded:
                        resource_limit_exceeded = "process-tree-rss-monitor-unavailable"
                    return resource_limit_exceeded
                limits["sample_count"] += 1
                limits["tracked_process_count"] = max(
                    limits["tracked_process_count"],
                    len(tracked_process_start_times))
                limits["peak_process_count"] = max(
                    limits["peak_process_count"], snapshot["process_count"])
                limits["peak_rss_bytes"] = max(
                    limits["peak_rss_bytes"], snapshot["rss_bytes"])
                if snapshot["rss_bytes"] > limits["max_bytes"]:
                    limits["status"] = "limit-exceeded"
                    if not resource_limit_exceeded:
                        resource_limit_exceeded = "process-tree-rss-exceeded"
                return resource_limit_exceeded

            def kill_process_family() -> None:
                nonlocal group_killed, resource_limit_exceeded
                limits = resource_limits.get("process_tree_rss")
                snapshot, snapshot_error = _process_tree_snapshot(
                    proc.pid, tracked_process_start_times)
                cleanup_status = ""
                process_tree_cleanup["attempted"] = True
                process_tree_cleanup["tracked_process_count"] = len(
                    tracked_process_start_times)
                if isinstance(limits, dict):
                    if snapshot_error or snapshot is None:
                        limits["cleanup_status"] = "unverified"
                        limits["cleanup_error"] = (
                            snapshot_error or "process-tree-snapshot-unavailable")
                        if not resource_limit_exceeded:
                            limits["status"] = "monitor-error"
                            resource_limit_exceeded = (
                                "process-tree-rss-monitor-unavailable")
                if snapshot is not None and not snapshot_error:
                    process_tree_cleanup["process_group_tracked"] = bool(
                        snapshot["process_group_tracked"])
                    process_tree_cleanup["observed_process_count"] = int(
                        snapshot["process_count"])
                    if (isinstance(limits, dict) and proc.poll() is not None
                            and any(pid != proc.pid for pid in snapshot["live_pids"])
                            and not resource_limit_exceeded):
                        resource_limit_exceeded = (
                            "process-tree-child-outlived-leader")
                    if snapshot["process_group_tracked"]:
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        except OSError:
                            cleanup_status = "incomplete"
                    for pid in snapshot["pids"]:
                        if pid == proc.pid:
                            continue
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        except OSError:
                            cleanup_status = "incomplete"
                    live_descendants = [
                        pid for pid in snapshot["live_pids"] if pid != proc.pid]
                    tree_cleanup_deadline = time.monotonic() + 0.25
                    while live_descendants and cleanup_status != "incomplete":
                        time.sleep(0.05)
                        remaining, error = _process_tree_snapshot(
                            proc.pid, tracked_process_start_times)
                        if error or remaining is None:
                            cleanup_status = "unverified"
                            if isinstance(limits, dict):
                                limits["cleanup_error"] = (
                                    error or "process-tree-snapshot-unavailable")
                                if not resource_limit_exceeded:
                                    resource_limit_exceeded = (
                                        "process-tree-rss-monitor-unavailable")
                            break
                        live_descendants = [
                            pid for pid in remaining["live_pids"]
                            if pid != proc.pid]
                        if not live_descendants:
                            break
                        if time.monotonic() >= tree_cleanup_deadline:
                            cleanup_status = "incomplete"
                            if isinstance(limits, dict):
                                limits["cleanup_remaining_count"] = len(
                                    live_descendants)
                            break
                        for pid in live_descendants:
                            try:
                                os.kill(pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            except OSError:
                                cleanup_status = "incomplete"
                                break
                    if not cleanup_status:
                        cleanup_status = "complete"
                    if isinstance(limits, dict):
                        limits["cleanup_status"] = cleanup_status
                        if (cleanup_status != "complete"
                                and not resource_limit_exceeded):
                            resource_limit_exceeded = (
                                "process-tree-cleanup-incomplete")
                    process_tree_cleanup["remaining_count"] = len(
                        live_descendants)
                else:
                    process_tree_cleanup["error"] = (
                        snapshot_error or "process-tree-snapshot-unavailable")
                    cleanup_status = "unverified"
                if proc.poll() is None:
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                    except OSError:
                        cleanup_status = "incomplete"
                        limits = resource_limits.get("process_tree_rss")
                        if isinstance(limits, dict):
                            limits["cleanup_status"] = "incomplete"
                        if not resource_limit_exceeded:
                            resource_limit_exceeded = (
                                "process-tree-cleanup-incomplete")
                process_tree_cleanup["status"] = cleanup_status or "unverified"
                group_killed = True

            def sample_scratch() -> str:
                nonlocal resource_limit_exceeded
                if scratch_dir is None:
                    return ""
                usage, usage_error = _measure_scratch_tree(scratch_dir)
                if usage_error or usage is None:
                    if not resource_limit_exceeded:
                        resource_limit_exceeded = "scratch-monitor-unavailable"
                    return resource_limit_exceeded
                scratch_limits["peak_bytes"] = max(
                    int(scratch_limits["peak_bytes"]), usage["bytes"])
                scratch_limits["peak_entries"] = max(
                    int(scratch_limits["peak_entries"]), usage["entries"])
                if usage["bytes"] > POC_MAX_SCRATCH_BYTES:
                    if not resource_limit_exceeded:
                        resource_limit_exceeded = "scratch-bytes-exceeded"
                elif usage["entries"] > POC_MAX_SCRATCH_ENTRIES:
                    if not resource_limit_exceeded:
                        resource_limit_exceeded = "scratch-entries-exceeded"
                return resource_limit_exceeded

            if isinstance(resource_limits.get("process_tree_rss"), dict):
                resource_limits["process_tree_rss"]["status"] = "monitoring"
                if sample_process_tree() and not group_killed:
                    kill_process_family()
                    cleanup_deadline = time.monotonic() + 1.0
                next_process_tree_sample = (
                    time.monotonic() + POC_PROCESS_TREE_SAMPLE_INTERVAL_SECONDS)

            while selector.get_map() or proc.poll() is None:
                now = time.monotonic()
                returncode = proc.poll()
                budget_abort = getattr(self.execution_budget, "abort_reason", "")
                if budget_abort and not abort_reason:
                    abort_reason = str(budget_abort)[:160]
                if abort_reason and not group_killed:
                    tree_limits = resource_limits.get("process_tree_rss")
                    if isinstance(tree_limits, dict):
                        if tree_limits.get("status") == "monitoring":
                            tree_limits["status"] = "aborted"
                        tree_limits["abort_reason"] = abort_reason
                    if scratch_dir is not None:
                        scratch_limits["status"] = "aborted"
                        scratch_limits["abort_reason"] = abort_reason
                    kill_process_family()
                    cleanup_deadline = time.monotonic() + 1.0
                if (isinstance(resource_limits.get("process_tree_rss"), dict)
                        and now >= next_process_tree_sample):
                    exceeded = sample_process_tree()
                    next_process_tree_sample = (
                        now + POC_PROCESS_TREE_SAMPLE_INTERVAL_SECONDS)
                    if exceeded and not group_killed:
                        kill_process_family()
                        cleanup_deadline = now + 1.0
                if scratch_dir is not None and now >= next_scratch_sample:
                    exceeded = sample_scratch()
                    next_scratch_sample = now + POC_SCRATCH_SAMPLE_INTERVAL_SECONDS
                    if exceeded and not group_killed:
                        scratch_limits["status"] = (
                            "monitor-error" if exceeded == "scratch-monitor-unavailable"
                            else "limit-exceeded")
                        kill_process_family()
                        cleanup_deadline = now + 1.0
                if returncode is not None and process_exited_at is None:
                    process_exited_at = now
                if (process_exited_at is not None and not group_killed
                        and now - process_exited_at >= 0.2):
                    # Reap background children that inherited the runner's
                    # pipes after the main PoC process returned.
                    kill_process_family()
                    cleanup_deadline = now + 1.0
                if (now >= deadline and returncode is None
                        and not resource_limit_exceeded):
                    timed_out = True
                    kill_process_family()
                    cleanup_deadline = time.monotonic() + 1.0
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                if cleanup_deadline is not None and now >= cleanup_deadline:
                    for key in list(selector.get_map().values()):
                        stream = key.fileobj
                        selector.unregister(stream)
                        retain(key.data, decoders[key.data].decode(b"", final=True))
                        stream.close()
                    break
                if selector.get_map():
                    events = selector.select(timeout=0.05)
                else:
                    # A child can close both output streams and keep running;
                    # continue enforcing the wall deadline without busy-spin.
                    time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
                    events = []
                for key, _mask in events:
                    stream = key.fileobj
                    try:
                        chunk = os.read(stream.fileno(), 8192)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        retain(key.data, decoders[key.data].decode(b"", final=True))
                        stream.close()
                        continue
                    retain(key.data, decoders[key.data].decode(chunk))
            selector.close()
            stdout = "".join(captured["stdout"])
            stderr = "".join(captured["stderr"])
            if scratch_dir is not None:
                sample_scratch()
                if resource_limit_exceeded:
                    scratch_limits["status"] = (
                        "monitor-error" if resource_limit_exceeded ==
                        "scratch-monitor-unavailable" else
                        "limit-exceeded" if resource_limit_exceeded.startswith("scratch-")
                        else "aborted-resource-limit")
                    kill_process_family()
                elif abort_reason:
                    scratch_limits["status"] = "aborted"
                    scratch_limits["abort_reason"] = abort_reason
                elif timed_out:
                    scratch_limits["status"] = "timed-out"
                else:
                    scratch_limits["status"] = "completed"
            tree_limits = resource_limits.get("process_tree_rss")
            if isinstance(tree_limits, dict):
                sample_process_tree()
                if not resource_limit_exceeded and not timed_out and not abort_reason:
                    tree_limits["status"] = "completed"
                elif tree_limits.get("status") == "monitoring":
                    tree_limits["status"] = "timed-out" if timed_out else "aborted"
            tree_limits = resource_limits.get("process_tree_rss")
            if (not group_killed or
                    (isinstance(tree_limits, dict) and
                     tree_limits.get("cleanup_status") in {"incomplete", "unverified"})):
                # The parent may exit after closing its pipes while a child in
                # the same process group remains alive. Always make one final
                # verified cleanup attempt before reaping the group leader.
                kill_process_family()
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            if timed_out:
                return RunResult(cmd, -1, stdout, stderr,
                                 int((time.monotonic() - t0) * 1000), timed_out=True,
                                 resource_limits=resource_limits,
                                 timeout_seconds=effective_timeout,
                                 timeout_capped=timeout_capped,
                                 scratch_limits=scratch_limits,
                                 resource_limit_exceeded=resource_limit_exceeded,
                                 abort_reason=abort_reason,
                                 process_tree_cleanup=process_tree_cleanup)
        except OSError as exc:
            if scratch_dir is not None and not resource_limit_exceeded:
                scratch_limits["status"] = "launch-failed"
            if "proc" in locals():
                process_tree_cleanup["attempted"] = True
                try:
                    cleanup = locals().get("kill_process_family")
                    if callable(cleanup):
                        cleanup()
                    else:
                        tracked = locals().get("tracked_process_start_times", {})
                        snapshot, snapshot_error = _process_tree_snapshot(
                            proc.pid, tracked)
                        if snapshot is not None and not snapshot_error:
                            if snapshot["process_group_tracked"]:
                                try:
                                    os.killpg(proc.pid, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                            for pid in snapshot["pids"]:
                                if pid == proc.pid:
                                    continue
                                try:
                                    os.kill(pid, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                            process_tree_cleanup.update({
                                "status": "complete",
                                "process_group_tracked": bool(
                                    snapshot["process_group_tracked"]),
                                "observed_process_count": int(
                                    snapshot["process_count"]),
                                "tracked_process_count": len(tracked),
                            })
                        else:
                            if proc.poll() is None:
                                proc.kill()
                            process_tree_cleanup.update({
                                "status": "unverified",
                                "error": snapshot_error or
                                "process-tree-snapshot-unavailable",
                            })
                    if proc.poll() is None:
                        proc.kill()
                    proc.wait(timeout=2)
                    tracked = locals().get("tracked_process_start_times", {})
                    remaining, verify_error = _process_tree_snapshot(
                        proc.pid, tracked)
                    if verify_error or remaining is None:
                        process_tree_cleanup["status"] = "unverified"
                        process_tree_cleanup["error"] = (
                            verify_error or "process-tree-snapshot-unavailable")
                    else:
                        survivors = [pid for pid in remaining["live_pids"]
                                     if pid != proc.pid]
                        # A descendant can race the first kill while its
                        # parent is exiting. Signal only the identities matched
                        # by this fresh PID/start-time snapshot, then verify.
                        for pid in survivors:
                            try:
                                os.kill(pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            except OSError:
                                process_tree_cleanup["status"] = "incomplete"
                        if survivors:
                            time.sleep(0.05)
                            remaining, verify_error = _process_tree_snapshot(
                                proc.pid, tracked)
                            if verify_error or remaining is None:
                                process_tree_cleanup["status"] = "unverified"
                                process_tree_cleanup["error"] = (
                                    verify_error or
                                    "process-tree-snapshot-unavailable")
                                survivors = []
                            else:
                                survivors = [pid for pid in remaining["live_pids"]
                                             if pid != proc.pid]
                        process_tree_cleanup["remaining_count"] = len(survivors)
                        if survivors and process_tree_cleanup.get("status") != "unverified":
                            process_tree_cleanup["status"] = "incomplete"
                        elif (not survivors and
                              process_tree_cleanup.get("status") != "unverified"):
                            process_tree_cleanup["status"] = "complete"
                except (OSError, subprocess.TimeoutExpired) as cleanup_error:
                    process_tree_cleanup["status"] = "incomplete"
                    process_tree_cleanup["error"] = type(cleanup_error).__name__
                selector_obj = locals().get("selector")
                if selector_obj is not None:
                    try:
                        selector_obj.close()
                    except OSError:
                        pass
            return RunResult(cmd, -1, "", "%s: %s" % (type(exc).__name__, exc),
                             int((time.monotonic() - t0) * 1000),
                             resource_limits=resource_limits,
                             timeout_seconds=effective_timeout,
                             timeout_capped=timeout_capped,
                             scratch_limits=scratch_limits,
                             resource_limit_exceeded=resource_limit_exceeded,
                             abort_reason=locals().get("abort_reason", ""),
                             process_tree_cleanup=process_tree_cleanup)
        return RunResult(
            cmd,
            proc.returncode,
            stdout,
            stderr,
            int((time.monotonic() - t0) * 1000),
            timed_out,
            resource_limits,
            effective_timeout,
            timeout_capped,
            scratch_limits,
            resource_limit_exceeded,
            abort_reason,
            process_tree_cleanup,
        )
