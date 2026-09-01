"""Constrained command execution for build/run steps.

* commands are passed as argv lists (no shell interpretation);
* cwd must stay under the workspace roots;
* timeouts prevent runaway PoCs;
* approval-gated operations (loopback connects) are recorded.
"""

from __future__ import annotations

import os
import ipaddress
import re
import signal
import subprocess
import time
from urllib.parse import urlparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .approval import ApprovalGate


@dataclass
class RunResult:
    cmd: List[str]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False


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


def _is_loopback_host(host: str) -> bool:
    host = str(host or "").strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host in {"localhost", "localhost.localdomain", "0.0.0.0", "::1"}:
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
            # scp/rsync syntax: user@host:/path
            remote_host = token.rsplit("@", 1)[1].split(":", 1)[0]
            if remote_host:
                hosts.append(remote_host)
    hosts.extend(IP_LITERAL_RE.findall(str(value)))
    return hosts


def _script_path_from_command(cmd: List[str]) -> Optional[Path]:
    for token in cmd[1:]:
        p = Path(str(token))
        if p.exists() and p.is_file() and p.suffix in {".sh", ".py", ".rb", ".pl"}:
            return p
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
                 staging_hosts: Optional[List[str]] = None):
        self.workspace = workspace.resolve()
        self.approval = approval or ApprovalGate()
        self.default_timeout = default_timeout
        self.max_output_chars = max_output_chars
        self.authorized_staging = authorized_staging
        self.staging_hosts = {
            str(h).strip().lower().rstrip(".") for h in (staging_hosts or []) if str(h).strip()
        }

    def _check_cwd(self, cwd: Path) -> None:
        cwd = cwd.resolve()
        if not (str(cwd) == str(self.workspace) or str(cwd).startswith(str(self.workspace) + os.sep)):
            raise PermissionError("cwd escapes workspace: %s" % cwd)

    def run(self, cmd: List[str], *, cwd: Optional[Path] = None, timeout: Optional[int] = None,
            env_extra: Optional[dict] = None, operation: Optional[str] = None,
            operation_detail: str = "") -> RunResult:
        cwd = (cwd or self.workspace).resolve()
        self._check_cwd(cwd)
        if operation:
            self.approval.assert_allowed(operation, operation_detail)
        env = dict(os.environ)
        if env_extra:
            env.update(env_extra)
        env.setdefault("PYTHONUNBUFFERED", "1")
        normalized_cmd = [str(c) for c in cmd]
        global_violation = validate_global_command(
            normalized_cmd, self.authorized_staging, self.staging_hosts)
        if global_violation:
            self.approval.request("policy_denied", global_violation)
            raise PermissionError("command denied by hard policy: %s" % global_violation)
        if operation in {"loopback_connect", "port_listen", "external_egress"}:
            violation = validate_poc_command(
                normalized_cmd, env, self.authorized_staging, self.staging_hosts)
            if violation:
                self.approval.request("policy_denied", violation)
                raise PermissionError("PoC command denied by hard policy: %s" % violation)
        if self.authorized_staging and any(
                Path(str(c)).name.lower() in STAGING_REMOTE_EXECUTABLES for c in normalized_cmd):
            self.approval.record_authorized(
                "remote_staging", operation_detail or "authorized staging command",
                "hosts=" + ",".join(sorted(self.staging_hosts)))
        t0 = time.monotonic()
        try:
            proc = subprocess.Popen(
                [str(c) for c in cmd], cwd=str(cwd), env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, errors="replace", start_new_session=True)
            try:
                stdout, stderr = proc.communicate(timeout=timeout or self.default_timeout)
            except subprocess.TimeoutExpired as exc:
                # Kill the whole process group; generated PoCs must not leave a
                # listener/server child behind after a timeout.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    proc.kill()
                stdout, stderr = proc.communicate()
                out = stdout or exc.stdout or ""
                err = stderr or exc.stderr or ""
                return RunResult(cmd, -1, str(out)[: self.max_output_chars],
                                 str(err)[: self.max_output_chars],
                                 int((time.monotonic() - t0) * 1000), timed_out=True)
            timed_out = False
        except OSError as exc:
            return RunResult(cmd, -1, "", "%s: %s" % (type(exc).__name__, exc),
                             int((time.monotonic() - t0) * 1000))
        return RunResult(
            cmd,
            proc.returncode,
            (stdout or "")[: self.max_output_chars],
            (stderr or "")[: self.max_output_chars],
            int((time.monotonic() - t0) * 1000),
            timed_out,
        )
