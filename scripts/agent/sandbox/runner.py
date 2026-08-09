"""Constrained command execution for build/run steps.

* commands are passed as argv lists (no shell interpretation);
* cwd must stay under the workspace roots;
* timeouts prevent runaway PoCs;
* approval-gated operations (loopback connects) are recorded.
"""

from __future__ import annotations

import os
import subprocess
import time
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


class CommandRunner:
    def __init__(self, workspace: Path, approval: Optional[ApprovalGate] = None,
                 default_timeout: int = 180, max_output_chars: int = 200_000):
        self.workspace = workspace.resolve()
        self.approval = approval or ApprovalGate()
        self.default_timeout = default_timeout
        self.max_output_chars = max_output_chars

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
        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                [str(c) for c in cmd],
                cwd=str(cwd),
                env=env,
                capture_output=True,
                timeout=timeout or self.default_timeout,
                text=True,
                errors="replace",
            )
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout or b""
            err = exc.stderr or b""
            if isinstance(out, bytes):
                out = out.decode("utf-8", "replace")
            if isinstance(err, bytes):
                err = err.decode("utf-8", "replace")
            return RunResult(cmd, -1, out[: self.max_output_chars], err[: self.max_output_chars],
                             int((time.monotonic() - t0) * 1000), timed_out=True)
        return RunResult(
            cmd,
            proc.returncode,
            (proc.stdout or "")[: self.max_output_chars],
            (proc.stderr or "")[: self.max_output_chars],
            int((time.monotonic() - t0) * 1000),
            timed_out,
        )
