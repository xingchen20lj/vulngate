"""Bounded audit-exec command implementation.

The public executable remains scripts/agent_cli.py; this module owns the
privileged host-command handler so parser and policy code stay reviewable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shlex
from pathlib import Path
from typing import Any, Dict, Optional


def _out(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def cmd_audit_exec(args: argparse.Namespace) -> int:
    """Run one bounded host-side audit command under the active round deadline."""
    import fcntl
    import time
    from datetime import datetime, timezone
    from agent.analysis.audit_budget import (
        load_round_budget,
        round_budget_snapshot,
    )
    from agent.sandbox.approval import ApprovalGate
    from agent.sandbox.runner import (
        AUDIT_COMMAND_ENV_POLICY_VERSION,
        MAX_COMMAND_WALL_TIMEOUT_SECONDS,
        CommandRunner,
    )

    workspace = Path(args.workspace).resolve()
    try:
        source_root = Path(args.root).resolve(strict=True)
        if not source_root.is_dir():
            raise ValueError("source root must be a directory")
        command = list(args.command or [])
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            raise ValueError("audit-exec requires a command after --")
        shell_names = {"sh", "bash", "zsh", "fish", "csh", "tcsh"}
        executable_name = Path(command[0]).name.lower()
        inspected_command = command
        git_subcommand = ""
        # `env bash -c ...` is still a shell wrapper. Unwrap the common env
        # forms so the simple bypass does not evade the command contract.
        if executable_name == "env":
            index = 1
            while index < len(command):
                token = command[index]
                if token == "--":
                    index += 1
                    break
                if token in {"-u", "--unset", "-C", "--chdir"}:
                    index += 2
                    continue
                if token in {"-S", "--split-string"}:
                    if index + 1 >= len(command):
                        break
                    try:
                        inspected_command = (shlex.split(command[index + 1])
                                             + command[index + 2:])
                    except ValueError:
                        inspected_command = []
                    break
                if token.startswith("--unset=") or token.startswith("--chdir="):
                    index += 1
                    continue
                if token.startswith("--split-string="):
                    try:
                        inspected_command = (
                            shlex.split(token.split("=", 1)[1])
                            + command[index + 1:])
                    except ValueError:
                        inspected_command = []
                    break
                if token.startswith("-") or re.fullmatch(
                        r"[A-Za-z_][A-Za-z0-9_]*=.*", token):
                    index += 1
                    continue
                break
            else:
                index = len(command)
            if inspected_command is command:
                inspected_command = command[index:]
            executable_name = (Path(inspected_command[0]).name.lower()
                               if inspected_command else "")
        if (executable_name in shell_names and any(
                token.startswith("-") and "c" in token[1:]
                or token == "--command" or token.startswith("--command=")
                for token in inspected_command[1:])):
            raise ValueError("audit-exec rejects shell -c commands; pass argv directly")
        network_tools = {
            "curl", "wget", "nc", "ncat", "socat", "ssh", "scp", "sftp",
            "rsync", "telnet", "rlogin", "ftp", "mosh",
        }
        if executable_name in network_tools:
            raise ValueError(
                "audit-exec is for local audit commands; use the approved network adapter")
        if executable_name == "git":
            git_index = 1
            while git_index < len(inspected_command):
                token = inspected_command[git_index]
                if token in {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}:
                    git_index += 2
                    continue
                if token.startswith("-"):
                    git_index += 1
                    continue
                git_subcommand = token.lower()
                break
            if git_subcommand in {
                    "clone", "fetch", "pull", "push", "remote", "submodule",
                    "ls-remote", "fetch-pack", "send-pack", "receive-pack",
                    "upload-pack"}:
                raise ValueError(
                    "audit-exec blocks Git remote operations; use approved source/network workflows")
        if isinstance(args.timeout, bool) or int(args.timeout) < 1:
            raise ValueError("timeout must be a positive number of seconds")
        if not 1000 <= int(args.max_output_chars) <= 200_000:
            raise ValueError("max-output-chars must be between 1000 and 200000")
        retry_reason = str(args.retry_reason or "").strip()[:400]

        env_extra: Dict[str, str] = {}
        for assignment in args.env or []:
            key, separator, value = str(assignment).partition("=")
            if (not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
                    or any(secret_word in key.upper() for secret_word in
                           ("TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH",
                            "PROXY", "API_KEY", "ACCESS_KEY"))):
                raise ValueError("--env requires a non-secret KEY=VALUE assignment")
            env_extra[key] = value

        if args.cwd:
            requested_cwd = Path(args.cwd)
            cwd = (requested_cwd if requested_cwd.is_absolute()
                   else source_root / requested_cwd).resolve(strict=True)
        else:
            cwd = source_root
        if not cwd.is_dir() or not (
                str(cwd) == str(source_root)
                or str(cwd).startswith(str(source_root) + os.sep)):
            raise ValueError("cwd must be a directory under --root")

        command_digest = hashlib.sha256(json.dumps(
            command, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")).hexdigest()
        cwd_relative = ("." if cwd == source_root else
                        cwd.relative_to(source_root).as_posix())
        run_log = (workspace / "state" / args.target
                   / ("round-%02d" % args.round) / "S0"
                   / "host-command-runs.jsonl")

        def write_run_record(record: Dict[str, Any], check_duplicate: bool = False
                             ) -> Optional[Dict[str, Any]]:
            run_log.parent.mkdir(parents=True, exist_ok=True)
            with run_log.open("a+b") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                prior_rows = []
                handle.seek(0, os.SEEK_END)
                log_size = handle.tell()
                tail_start = max(0, log_size - 16 * 1024 * 1024)
                handle.seek(tail_start)
                tail = handle.read()
                if tail_start:
                    tail = tail.partition(b"\n")[2]
                for line in tail.splitlines()[-4096:]:
                    try:
                        row = json.loads(line.decode("utf-8", "replace"))
                    except (TypeError, ValueError):
                        continue
                    if isinstance(row, dict):
                        prior_rows.append(row)
                if check_duplicate:
                    for previous in reversed(prior_rows):
                        if (previous.get("source_root") == str(source_root)
                                and previous.get("cwd") == cwd_relative
                                and previous.get("command_digest") == command_digest
                                and previous.get("status") in {
                                    "running", "timed-out", "cleanup-incomplete",
                                    "command-failed", "command-error"}):
                            if not retry_reason:
                                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                                return previous
                            break
                handle.seek(0, os.SEEK_END)
                handle.write((json.dumps(
                    record, ensure_ascii=False, separators=(",", ":"))
                    + "\n").encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            return None

        budget_record = load_round_budget(workspace, args.target, args.round)
        budget_before = round_budget_snapshot(budget_record)
        remaining = float(budget_before["remaining_seconds"])
        if budget_before["expired"] or remaining < 1.0:
            _out({"error": "audit round deadline expired; command not started",
                  "audit_budget": budget_before,
                  "claim_status": "not-a-finding"})
            return 3

        requested_timeout = int(args.timeout)
        inspection_executables = {
            "rg", "grep", "egrep", "fgrep", "ack", "ag", "find", "fd",
            "du",
        }
        bounded_git_inspections = {"grep", "status", "diff", "ls-files"}
        inline_code_flags = {
            "perl": {"-e", "-p", "-n"},
            "ruby": {"-e"},
            "node": {"-e", "--eval", "-p", "--print", "-"},
            "osascript": {"-e"},
        }
        python_interpreter = bool(re.fullmatch(
            r"(?:python|pypy)(?:\d+(?:\.\d+)*)?", executable_name))
        inline_flags = inline_code_flags.get(executable_name, set())
        inline_code_command = any(
            (python_interpreter and (token in {"-", "-c", "--command"}
             or token.startswith("-") and "c" in token[1:]))
            or token in inline_flags
            for token in inspected_command[1:])
        is_bounded_inspection = (
            executable_name in inspection_executables
            or (executable_name == "git"
                and git_subcommand in bounded_git_inspections)
            or inline_code_command)
        inspection_timeout_cap = 120
        command_timeout_cap = min(
            MAX_COMMAND_WALL_TIMEOUT_SECONDS,
            inspection_timeout_cap if is_bounded_inspection
            else MAX_COMMAND_WALL_TIMEOUT_SECONDS)
        timeout_cap_reason = (
            "inline-code" if inline_code_command else
            "recursive-search-or-inspection" if executable_name in inspection_executables else
            "git-metadata-inspection" if executable_name == "git"
            and git_subcommand in bounded_git_inspections else "")
        timeout_policy = (
            "audit-host-command-timeout-v3-inspection-120s"
            if is_bounded_inspection else "audit-host-command-timeout-v1")
        effective_timeout = min(
            requested_timeout, command_timeout_cap, max(1, int(remaining)))
        attempt_id = secrets.token_hex(8)
        executable = Path(command[0]).name
        started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        initial_record = {
            "schema_version": "audit-host-command-v1",
            "attempt_id": attempt_id,
            "target": args.target,
            "round": args.round,
            "source_root": str(source_root),
            "cwd": cwd_relative,
            "command_executable": executable,
            "command_digest": command_digest,
            "status": "running",
            "started_at": started_at,
            "requested_timeout_seconds": requested_timeout,
            "applied_timeout_seconds": effective_timeout,
            "timeout_policy": timeout_policy,
            "timeout_cap_seconds": command_timeout_cap,
            "timeout_cap_reason": timeout_cap_reason,
            "retry_reason": retry_reason,
            "claim_status": "not-a-finding",
        }
        duplicate = write_run_record(initial_record, check_duplicate=True)
        if duplicate:
            _out({
                "error": "same command previously timed out, failed, or remained running; inspect its process/output, then use --retry-reason only if the scope or environment changed",
                "previous_attempt": duplicate,
                "command_digest": command_digest,
                "claim_status": "not-a-finding",
            })
            return 2

        approval_path = (workspace / "state" / args.target
                         / ("round-%02d" % args.round) / "approval-log.jsonl")
        runner = CommandRunner(
            source_root,
            approval=ApprovalGate(log_path=approval_path),
            default_timeout=effective_timeout,
            max_output_chars=int(args.max_output_chars))
        command_started = time.monotonic()
        try:
            result = runner.run(
                command, cwd=cwd, timeout=effective_timeout,
                env_extra=env_extra, audit_command_env=True)
        except Exception as exc:
            write_run_record({
                **initial_record,
                "status": "command-error",
                "finished_at": datetime.now(timezone.utc).isoformat(
                    timespec="seconds"),
                "duration_ms": int((time.monotonic() - command_started) * 1000),
                "error_type": type(exc).__name__,
                "error": str(exc)[:300],
            })
            raise
        budget_after = round_budget_snapshot(budget_record)
        cleanup_status = str(
            (result.process_tree_cleanup or {}).get("status") or "unknown")
        run_status = (
            "timed-out" if result.timed_out else
            "cleanup-incomplete" if cleanup_status in {"incomplete", "unverified"} else
            "completed" if result.returncode == 0 else "command-failed")
        write_run_record({
            **initial_record,
            "status": run_status,
            "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_ms": result.duration_ms,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "process_tree_cleanup": result.process_tree_cleanup,
            "stdout_chars": len(result.stdout),
            "stdout_sha256": hashlib.sha256(
                result.stdout.encode("utf-8", "replace")).hexdigest(),
            "stderr_chars": len(result.stderr),
            "stderr_sha256": hashlib.sha256(
                result.stderr.encode("utf-8", "replace")).hexdigest(),
        })
        _out({
            "attempt_id": attempt_id,
            "run_log": str(run_log.relative_to(workspace)),
            "target": args.target,
            "round": args.round,
            "source_root": str(source_root),
            "cwd": cwd_relative,
            "command_executable": Path(command[0]).name,
            "command_digest": command_digest,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "duration_ms": result.duration_ms,
            "requested_timeout_seconds": requested_timeout,
            "applied_timeout_seconds": result.timeout_seconds,
            "timeout_policy": timeout_policy,
            "timeout_cap_seconds": command_timeout_cap,
            "timeout_cap_reason": timeout_cap_reason,
            "timeout_capped": (requested_timeout > effective_timeout
                               or result.timeout_capped),
            "audit_budget_before": budget_before,
            "audit_budget_after": budget_after,
            "environment_policy": AUDIT_COMMAND_ENV_POLICY_VERSION,
            "explicit_env_keys": sorted(env_extra),
            "process_tree_cleanup": result.process_tree_cleanup,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "network_isolation": "not-applied-to-host-audit-commands",
            "filesystem_isolation": "cwd-checked-only; no OS sandbox",
            "evidence_role": "host-command-output-not-finding",
            "claim_status": "not-a-finding",
        })
        if result.timed_out:
            return 124
        if cleanup_status in {"incomplete", "unverified"}:
            return 2
        return result.returncode if result.returncode >= 0 else 2
    except (OSError, PermissionError, ValueError, TypeError) as exc:
        _out({"error": str(exc), "target": args.target,
              "round": args.round, "claim_status": "not-a-finding"})
        return 2
