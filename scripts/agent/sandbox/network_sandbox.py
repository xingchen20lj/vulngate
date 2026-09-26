"""Platform network and bounded-write confinement for generated PoCs.

The macOS backend uses Seatbelt to restrict a PoC's outbound TCP traffic to
the current run's loopback HTTP observer, confine writes to explicit
workspace-local scratch/output roots, and apply a read allowlist for system
toolchain paths, the audit workspace, and explicit runtime roots. Sensitive
host-data paths stay denied even when they fall under a broad system root.
Other platforms are reported as unavailable; source screening and proxy
variables are not treated as OS-level network isolation. This is not a
complete process-tree or resource sandbox.
"""

from __future__ import annotations

import os
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlsplit


SEATBELT_PROXY_POLICY = "seatbelt-host-local-proxy-port-v5-read-allowlist-direct-session-call-guard"
SEATBELT_DENY_ALL_POLICY = "seatbelt-network-deny-all-v4-read-allowlist-direct-session-call-guard"
SEATBELT_POC_FILESYSTEM_POLICY = "seatbelt-poc-read-allowlist-write-confined-v3"
POC_SYSTEM_READ_ROOTS = (
    "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec",
)
POC_SYSTEM_RUNTIME_EXEC_ROOTS = tuple(
    str(path) for path in (
        Path("/System/Cryptexes/OS/usr/bin"),
        Path("/Library/Developer/CommandLineTools"),
        Path("/Applications/Xcode.app/Contents/Developer"),
    ) if path.is_dir())
POC_SYSTEM_LIBRARY_ROOTS = (
    ("/usr/lib", "/System/Library") + tuple(
        str(path) for path in (
            Path("/System/Cryptexes/OS/usr/lib"),
            Path("/System/Cryptexes/OS/System/Library"),
            Path("/System/Volumes/Preboot/Cryptexes/OS/System/Library"),
        ) if path.is_dir())
)
POC_REOPENABLE_READ_DENY_ROOTS = (
    "/Users",
    "/System/Volumes/Data/Users",
    "/private/var/root",
    "/System/Volumes/Data/private/var/root",
    "/Volumes",
    "/System/Volumes/Data/Volumes",
    "/Network",
    "/net",
    "/private/var/folders",
    "/System/Volumes/Data/private/var/folders",
    "/private/tmp",
    "/System/Volumes/Data/private/tmp",
    "/private/var/tmp",
    "/System/Volumes/Data/private/var/tmp",
)
POC_NEVER_REOPEN_READ_ROOTS = (
    "/Library/Keychains",
    "/System/Volumes/Data/Library/Keychains",
    "/System/Library/Keychains",
    "/private/var/db/keychains",
    "/System/Volumes/Data/private/var/db/keychains",
    "/private/var/db/shadow/hash",
    "/System/Volumes/Data/private/var/db/shadow/hash",
    "/private/var/db/dslocal/nodes/Default/users",
    "/System/Volumes/Data/private/var/db/dslocal/nodes/Default/users",
    "/private/etc/ssh",
    "/System/Volumes/Data/private/etc/ssh",
    "/private/etc/sudoers",
    "/System/Volumes/Data/private/etc/sudoers",
    "/private/etc/sudoers.d",
    "/System/Volumes/Data/private/etc/sudoers.d",
    "/private/etc/krb5.keytab",
    "/System/Volumes/Data/private/etc/krb5.keytab",
)
POC_DENIED_READ_ROOTS = (
    POC_REOPENABLE_READ_DENY_ROOTS + POC_NEVER_REOPEN_READ_ROOTS)


def _filesystem_rules(workspace_root: Path, readable_paths: List[Path],
                      writable_paths: List[Path]) -> Tuple[List[str], str]:
    """Allow reads only from runtime/system roots and the scoped audit workspace.

    Seatbelt's default-deny profile calls this after importing Apple's basic
    system rules. Target/runtime roots are explicit exceptions to broad user,
    temp, and mounted-volume denies; credential stores are denied last and can
    never be reopened by those exceptions. Writes stay confined to output.
    """
    workspace = workspace_root.resolve()
    read_roots = [workspace] + [Path(path).resolve() for path in readable_paths]
    write_roots = [Path(path).resolve() for path in writable_paths]
    users_root = Path("/Users").resolve()
    user_home = Path.home().resolve()
    protected_roots = [Path(root) for root in POC_DENIED_READ_ROOTS]
    never_reopen_roots = [Path(root) for root in POC_NEVER_REOPEN_READ_ROOTS]
    if (any(workspace == root or root.is_relative_to(workspace)
            for root in protected_roots)
            or any(workspace.is_relative_to(root)
                   for root in never_reopen_roots)
            or workspace == users_root
            or workspace.parent == users_root
            or user_home.is_relative_to(workspace)):
        return [], "audit workspace must not be a protected filesystem root"
    if any(user_home.is_relative_to(path) for path in read_roots[1:]):
        return [], "runtime read root must not include the user-home root"
    if any(path == root or root.is_relative_to(path)
           for path in read_roots[1:] for root in protected_roots):
        return [], "runtime read root must not include a protected filesystem root"
    if any(path.is_relative_to(root)
           for path in read_roots[1:] for root in never_reopen_roots):
        return [], "runtime read root is inside a protected credential store"
    for path in write_roots:
        if path == workspace or not path.is_relative_to(workspace):
            return [], "filesystem write root escapes the audit workspace"

    def quote(path: Path) -> str:
        return json.dumps(str(path), ensure_ascii=True)
    rules = []
    system_roots = [Path(root) for root in POC_SYSTEM_READ_ROOTS]
    system_roots.extend(Path(root) for root in POC_SYSTEM_RUNTIME_EXEC_ROOTS)
    for root in system_roots:
        rules.append('(allow file-read* file-test-existence (subpath %s))' %
                     quote(root))
        rules.append('(allow file-map-executable (subpath %s))' % quote(root))
        rules.append('(allow process-exec* (subpath %s))' % quote(root))

    # Dynamic libraries and Apple frameworks are runtime inputs, not an
    # executable search path. Keep their read/map grants separate so a PoC
    # cannot use this compatibility allowance to launch arbitrary OS helpers.
    for root in (Path(path) for path in POC_SYSTEM_LIBRARY_ROOTS):
        rules.append('(allow file-read* file-test-existence (subpath %s))' %
                     quote(root))
        rules.append('(allow file-map-executable (subpath %s))' % quote(root))

    # Apple's system curl initializes LibreSSL even for plain HTTP and reads
    # this non-secret system configuration file. Grant only the exact file;
    # do not reopen the surrounding /private/etc/ssl tree.
    ssl_config = Path("/private/etc/ssl/openssl.cnf")
    if ssl_config.is_file():
        rules.append('(allow file-read* file-test-existence (literal %s))' %
                     quote(ssl_config.resolve()))

    # Apply broad denials after system.sb's standard path grants.
    for root in POC_REOPENABLE_READ_DENY_ROOTS:
        rules.append('(deny file-read* (literal %s))' % quote(Path(root)))
        rules.append('(deny file-read* (subpath %s))' % quote(Path(root)))
    rules.extend('(allow file-read* file-map-executable (subpath %s))' % quote(path)
                 for path in read_roots)
    rules.extend('(allow process-exec* (subpath %s))' % quote(path)
                 for path in read_roots)
    # Sensitive roots are never exceptions, including when nested under /System.
    for root in POC_NEVER_REOPEN_READ_ROOTS:
        rules.append('(deny file-read* (literal %s))' % quote(Path(root)))
        rules.append('(deny file-read* (subpath %s))' % quote(Path(root)))
    rules.extend(("(allow process-fork)",
                  "(allow signal (target same-sandbox))"))
    rules.append("(deny file-write*)")
    rules.append('(allow file-write* (literal "/dev/null"))')
    rules.extend('(allow file-write* (subpath %s))' % quote(path)
                 for path in write_roots)
    return rules, ""


def wrap_network_command(command: List[str], proxy_url: Optional[str] = None,
                         filesystem_workspace: Optional[Path] = None,
                         readable_paths: Optional[List[Path]] = None,
                         writable_paths: Optional[List[Path]] = None
                         ) -> Tuple[List[str], str]:
    """Wrap a command in macOS Seatbelt or return an explicit unavailable state.

    When a proxy URL is supplied, outbound TCP is allowed only to its exact
    port on an address assigned to this host. Seatbelt's `localhost` network
    filter is not interface-exact: it can match a host-owned non-loopback
    address too. With no proxy, all outbound and inbound operations are denied.
    Process creation/execution remains enabled, but direct setsid/setpgid
    syscalls are denied; Darwin posix_spawn attributes can still request a
    separate process group/session.
    """
    if sys.platform != "darwin":
        return list(command), "network-sandbox-unavailable-platform"

    sandbox_exec = Path("/usr/bin/sandbox-exec")
    if not sandbox_exec.is_file() or not os.access(str(sandbox_exec), os.X_OK):
        return list(command), "network-sandbox-unavailable-tool"

    allowed_proxy_port: Optional[int] = None
    if proxy_url:
        try:
            parsed = urlsplit(str(proxy_url))
            if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
                    or parsed.username is not None or parsed.password is not None
                    or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
                return list(command), "network-sandbox-invalid-proxy"
            allowed_proxy_port = parsed.port
        except ValueError:
            return list(command), "network-sandbox-invalid-proxy"
        if allowed_proxy_port is None or not 1 <= allowed_proxy_port <= 65535:
            return list(command), "network-sandbox-invalid-proxy"

    rules = ["(version 1)"]
    if filesystem_workspace is None:
        # This network-only profile is used for capability discovery before
        # the exact per-cell filesystem roots exist. Executed PoCs always pass
        # filesystem_workspace and use the default-deny profile below.
        rules.append("(allow default)")
    else:
        rules.extend((
            '(import "bsd.sb")',
            "(deny default)",
        ))
    rules.extend([
        # The runner owns a fresh process group and uses killpg for timeout
        # cleanup. Block direct session/group changes in inherited child
        # sandboxes. Darwin posix_spawn attributes can still request these
        # changes, so this is a guard against the direct syscall path, not a
        # complete process-tree containment boundary.
        "(deny syscall-unix (syscall-number SYS_setsid))",
        "(deny syscall-unix (syscall-number SYS_setpgid))",
        "(deny network-outbound)",
        "(deny network-inbound)",
        "(deny network-bind)",
        # Permit client sockets to bind only to loopback ephemeral addresses.
        # Seatbelt's network filters require the symbolic host `localhost`;
        # a numeric 127.0.0.1 here makes sandbox-exec reject the whole profile.
        '(allow network-bind (local ip "localhost:*"))',
    ])
    if allowed_proxy_port is not None:
        # macOS Seatbelt accepts `localhost` here, but that means an address
        # assigned to this host, not specifically 127.0.0.1. Keep this policy
        # port-scoped, version its narrower-than-literal-loopback semantics,
        # and do not reuse it for services that need inbound connections.
        rules.append('(allow network-outbound (remote ip "localhost:%d"))'
                     % allowed_proxy_port)
        policy = SEATBELT_PROXY_POLICY
    else:
        policy = SEATBELT_DENY_ALL_POLICY
    if filesystem_workspace is not None:
        filesystem_rules, error = _filesystem_rules(
            Path(filesystem_workspace), list(readable_paths or []),
            list(writable_paths or []))
        if error:
            return list(command), "network-sandbox-invalid-filesystem"
        rules.extend(filesystem_rules)
    return [str(sandbox_exec), "-p", "\n".join(rules)] + list(command), policy


def verify_network_sandbox(proxy_url: Optional[str] = None,
                           filesystem_workspace: Optional[Path] = None,
                           readable_paths: Optional[List[Path]] = None,
                           writable_paths: Optional[List[Path]] = None
                           ) -> Tuple[str, str]:
    """Preflight the exact Seatbelt profile before starting an untrusted PoC.

    `sandbox-exec` can reject a syntactically invalid profile with exit 65. A
    runner must not label the subsequent command isolated unless the same
    profile has first been accepted by the host sandbox implementation.
    Returns `(policy, error)`; an empty error means the profile was accepted.
    """
    probe, policy = wrap_network_command(
        ["/usr/bin/true"], proxy_url,
        filesystem_workspace=filesystem_workspace,
        readable_paths=readable_paths, writable_paths=writable_paths)
    if policy.startswith("network-sandbox-unavailable"):
        return policy, "required macOS Seatbelt network backend is unavailable"
    if policy == "network-sandbox-invalid-proxy":
        return policy, "invalid loopback proxy configuration"
    if policy == "network-sandbox-invalid-filesystem":
        return policy, "configured filesystem roots violate the PoC read/write allowlist"
    try:
        result = subprocess.run(
            probe, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "network-sandbox-profile-rejected", str(exc)[:240]
    if result.returncode != 0:
        detail = (result.stderr or "sandbox preflight exited %d" % result.returncode)
        return "network-sandbox-profile-rejected", detail[-400:]
    return policy, ""
