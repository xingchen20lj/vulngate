"""Runtime-lab isolation backends.

The service lifecycle used to launch a target directly on the host after a
boolean opt-in.  This module makes the isolation decision explicit and
fail-closed.  Backends are deliberately small: they report the exact backend
identity, wrap an argv command, and expose the capability contract that is
persisted with the service artifact.

The Linux backend uses bubblewrap when available.  It creates a private mount,
PID, IPC, UTS and network namespace, exposes only the workspace plus the
standard runtime directories, and gives the service a loopback-only network
namespace.  A configured container backend is also supported for macOS and
Linux.  Seatbelt is intentionally not used as a runtime-lab substitute: it is
the PoC backend, not a reliable target-service boundary.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import hashlib
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, TypeAlias

from ..orchestrator.security_types import IsolationState


ISOLATION_SCHEMA_VERSION = "isolation-backend-v1"


def _version(executable: str) -> str:
    try:
        result = subprocess.run(
            [executable, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    return " ".join((result.stdout or "").split())[:160] or "unknown"


def _contained(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


IsolationDescriptor: TypeAlias = IsolationState


class IsolationBackend:
    """Minimal backend contract used by :class:`ServiceLifecycle`."""

    descriptor: IsolationDescriptor

    def wrap_command(self, command: Sequence[str], workspace: Path,
                     working_dir: Path, env: Dict[str, str]) -> List[str]:
        raise NotImplementedError

    def health_command(self, command: Sequence[str], pid: Optional[int]) -> List[str]:
        """Return a command that runs inside the service's network namespace.

        A backend may return the original command for a health probe that does
        not need namespace entry.  Linux namespace backends use ``nsenter``
        when it is available; callers still treat a failed probe as an
        inconclusive precondition rather than a negative result.
        """
        return list(command)

    def prepare_cgroup(self, workspace: Path, name: str) -> Optional["CgroupV2Controller"]:
        return None


class CgroupV2Controller:
    """Best-effort delegated cgroup v2 controller with fail-closed attach."""

    ROOT = Path("/sys/fs/cgroup")

    def __init__(self, path: Path):
        self.path = path
        self.limits = {
            "memory.max": str(2 * 1024 * 1024 * 1024),
            "pids.max": "128",
            "cpu.max": "3600000 100000",
        }
        self.attached_pid: Optional[int] = None

    @classmethod
    def available(cls) -> bool:
        return (platform.system().lower() == "linux"
                and (cls.ROOT / "cgroup.controllers").is_file()
                and os.access(cls.ROOT, os.W_OK))

    @classmethod
    def create(cls, workspace: Path, name: str) -> Optional["CgroupV2Controller"]:
        if not cls.available():
            return None
        suffix = hashlib.sha256((str(workspace) + name).encode()).hexdigest()[:16]
        path = cls.ROOT / ("vulngate-" + suffix)
        try:
            path.mkdir(exist_ok=True)
            controller = cls(path)
            for filename, value in controller.limits.items():
                (path / filename).write_text(value, encoding="ascii")
            return controller
        except OSError:
            try:
                path.rmdir()
            except OSError:
                pass
            return None

    def attach(self, pid: int) -> None:
        (self.path / "cgroup.procs").write_text(str(int(pid)), encoding="ascii")
        self.attached_pid = int(pid)

    def snapshot(self) -> Dict[str, Any]:
        return {"backend": "cgroup-v2", "path_digest": hashlib.sha256(
            str(self.path).encode()).hexdigest()[:20], "limits": dict(self.limits),
                "attached_pid": self.attached_pid, "enforced": self.attached_pid is not None}

    def close(self) -> None:
        try:
            self.path.rmdir()
        except OSError:
            pass


class LinuxBubblewrapBackend(IsolationBackend):
    def __init__(self, executable: str):
        self.executable = executable
        self.descriptor = IsolationDescriptor(
            backend="linux-bubblewrap",
            version=_version(executable),
            available=True,
            network="private-network-namespace-loopback-only",
            filesystem="private-mount-namespace-workspace-plus-runtime",
            capabilities=(
                "mount-namespace", "pid-namespace", "network-namespace",
                "ipc-namespace", "uts-namespace", "read-only-system-runtime",
                "workspace-bind", "die-with-parent", "cgroup-v2",
            ),
        )

    def wrap_command(self, command: Sequence[str], workspace: Path,
                     working_dir: Path, env: Dict[str, str]) -> List[str]:
        # Do not bind the host root.  Only standard runtime paths are exposed;
        # the audit workspace is the sole writable target tree.
        args = [
            self.executable, "--die-with-parent", "--new-session",
            "--unshare-user", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--unshare-net", "--proc", "/proc",
            "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/workspace",
            "--bind", str(workspace), "/workspace",
        ]
        for path in ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"):
            if Path(path).exists():
                args.extend(["--ro-bind", path, path])
        relative = "."
        if _contained(working_dir, workspace):
            relative = "/workspace/" + str(working_dir.relative_to(workspace))
        args.extend(["--chdir", relative])
        for key, value in sorted(env.items()):
            # Environment keys/values have already passed the lifecycle
            # allowlist.  Bubblewrap receives them explicitly, never inherit
            # the host environment wholesale.
            args.extend(["--setenv", str(key), str(value)])
        args.append("--")
        args.extend(str(item) for item in command)
        return args

    def health_command(self, command: Sequence[str], pid: Optional[int]) -> List[str]:
        nsenter = shutil.which("nsenter")
        if nsenter and pid:
            return [nsenter, "-t", str(int(pid)), "-n", "--", *map(str, command)]
        return list(command)

    def prepare_cgroup(self, workspace: Path, name: str) -> Optional[CgroupV2Controller]:
        return CgroupV2Controller.create(workspace, name)


class ContainerBackend(IsolationBackend):
    def __init__(self, executable: str, image: str):
        self.executable = executable
        self.image = image
        self.descriptor = IsolationDescriptor(
            backend="%s-runtime-container" % Path(executable).name,
            version=_version(executable),
            available=True,
            network="container-network-none",
            filesystem="read-only-container-workspace-bind",
            capabilities=("network-none", "read-only-root", "workspace-bind",
                           "cap-drop-all", "no-new-privileges", "pids-limit",
                           "memory-max-2g", "cpu-max-4"),
        )

    def wrap_command(self, command: Sequence[str], workspace: Path,
                     working_dir: Path, env: Dict[str, str]) -> List[str]:
        relative = "."
        if _contained(working_dir, workspace):
            relative = "/workspace/" + str(working_dir.relative_to(workspace))
        args = [
            self.executable, "run", "--rm", "--init", "--network", "none",
            "--read-only", "--memory", "2g", "--cpus", "4",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "128", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev", "-v",
            "%s:/workspace:rw" % workspace, "-w", relative,
        ]
        for key, value in sorted(env.items()):
            args.extend(["-e", "%s=%s" % (key, value)])
        args.append(self.image)
        args.extend(str(item) for item in command)
        return args


def detect_isolation_backend(workspace: Path, raw: Any) -> Tuple[Optional[IsolationBackend], IsolationDescriptor]:
    """Resolve a concrete, available backend or return an unavailable record.

    ``raw`` is intentionally operator-controlled configuration.  A repository
    config can request a backend, but it cannot authorize an unconfined launch.
    """
    config = raw if isinstance(raw, dict) else {}
    requested = str(config.get("isolation_backend", "auto") or "auto").strip().lower()
    image = str(config.get("isolation_image", "") or "").strip()
    system = platform.system().lower()
    backend: IsolationBackend

    if requested in {"docker", "podman", "container"} or image:
        candidates = [requested] if requested in {"docker", "podman"} else ["docker", "podman"]
        for name in candidates:
            executable = shutil.which(name)
            if executable and image:
                backend = ContainerBackend(executable, image)
                return backend, backend.descriptor
        return None, IsolationDescriptor(
            backend="container", version="unavailable", available=False,
            network="unknown", filesystem="unknown",
            reason="configured container backend or image is unavailable",
        )

    if system == "linux" and requested in {"auto", "bubblewrap", "linux-bubblewrap"}:
        executable = shutil.which("bwrap")
        if executable and CgroupV2Controller.available():
            backend = LinuxBubblewrapBackend(executable)
            return backend, backend.descriptor
        return None, IsolationDescriptor(
            backend="linux-bubblewrap", version="unavailable", available=False,
            network="unknown", filesystem="unknown",
            reason=("bubblewrap or delegated writable cgroup v2 is unavailable; "
                    "refusing service start"),
        )

    return None, IsolationDescriptor(
        backend="none", version="unavailable", available=False,
        network="unsupported", filesystem="unsupported",
        reason=("no supported runtime-lab isolation backend for %s; "
                "Seatbelt/PoC isolation is not a target-service backend" % system),
    )


def capability_matrix() -> Dict[str, Any]:
    """Return a side-effect-free platform capability matrix for ``doctor``."""
    from .effects import supported_effect_kinds

    system = platform.system().lower()
    backends: Dict[str, Dict[str, Any]] = {}
    for name in ("bwrap", "docker", "podman", "nsenter"):
        path = shutil.which(name)
        backends[name] = {"available": bool(path), "path": path or ""}
    cgroup_available = CgroupV2Controller.available()
    backends["cgroup-v2"] = {"available": cgroup_available,
                              "path": str(CgroupV2Controller.ROOT)}
    return {
        "schema_version": ISOLATION_SCHEMA_VERSION,
        "platform": system,
        "poc_isolation": system == "darwin" and bool(shutil.which("sandbox-exec")),
        "service_isolation": bool((backends["bwrap"]["available"] and cgroup_available) or
                                   backends["docker"]["available"] or
                                   backends["podman"]["available"]),
        "http_observer": True,
        # This capability is deliberately limited to process lifecycle
        # observation. Target-specific protocol state is reported separately.
        "jvm_observer": "jvm-effect" in supported_effect_kinds(),
        "jvm_protocol_observer": "jvm-protocol" in supported_effect_kinds(),
        "effect_collectors": {
            kind: kind in supported_effect_kinds()
            for kind in ("http-semantic", "filesystem-diff", "process-effect",
                         "fixture-db", "jvm-effect", "jvm-protocol",
                         "authorization-state")
        },
        "backends": backends,
    }
