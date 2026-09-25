"""Local registry and PreToolUse policy for active VulnGate audit roots.

The hook is a Codex tool guardrail, not an operating-system sandbox. It blocks
ordinary Bash/Unified Exec calls that touch a registered audit root unless the
call goes through VulnGate's bundled CLI. Expired rounds stay guarded until an
explicit release; after expiry only status and release commands are allowed.
Direct host commands use audit-exec; round-control calls must match the
registered audit identity.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple


REGISTRY_SCHEMA = "vulngate-active-audits-v1"
MAX_ACTIVE_AUDITS = 32
MAX_REGISTRY_BYTES = 256 * 1024
MAX_GUARD_COMMAND_CHARS = 64 * 1024
MAX_SHELL_TOKENS = 2048
ROUND_RE = re.compile(r"[1-9][0-9]{0,6}\Z")
_SHELL_PUNCTUATION = set(";&|<>")
_RECURSIVE_OR_METADATA_TOOLS = {
    "ack", "ag", "du", "fd", "find", "git", "grep", "rg", "tree",
}
_EXECUTION_TOOLS = {
    "ant", "awk", "bash", "bazel", "bundle", "cargo", "cmake", "composer",
    "csh", "ctest", "docker", "env", "fish", "gawk", "go", "gradle",
    "gradlew", "groovy", "java", "javac", "jshell", "lua", "luajit",
    "make", "mvn", "mvnw", "ninja", "node", "npm", "npx", "osascript",
    "pants", "perl", "php", "pip", "pnpm", "podman", "poetry", "pytest",
    "python", "python2", "python3", "r", "rscript", "ruby", "sbt", "sh",
    "swift", "swiftc", "tcsh", "tox", "uv", "yarn", "zsh",
}
_PATH_VALUE_FLAGS = {
    "-C", "--directory", "--file", "--git-dir", "--output",
    "--root", "--work-tree", "-f",
}


class _TooManyShellTokens(ValueError):
    """Internal signal that a command exceeded the hook parser's work bound."""


def registry_path() -> Path:
    """Use the same stable, per-Codex-home registry from CLI and hook calls."""
    codex_home = os.environ.get("CODEX_HOME") or str(Path.home() / ".codex")
    return Path(codex_home).expanduser().resolve() / "vulngate" / "active-audits.json"


def workspace_target_root(workspace: Path, target: str) -> Path:
    """Mirror the pipeline's prepared-target layout for native audit rounds."""
    root = Path(workspace).resolve(strict=True)
    candidate = root / "targets" / str(target)
    return candidate.resolve(strict=True) if candidate.is_dir() else root


def _parse_deadline(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("active audit deadline is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("active audit deadline is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError("active audit deadline has no timezone")
    return parsed.astimezone(timezone.utc)


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+b") as handle:
        if os.name == "nt":
            import msvcrt

            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _read_records(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    if path.stat().st_size > MAX_REGISTRY_BYTES:
        raise ValueError("active audit registry exceeds its size limit")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError("active audit registry cannot be read") from exc
    if (not isinstance(data, dict) or data.get("schema_version") != REGISTRY_SCHEMA
            or not isinstance(data.get("audits"), list)):
        raise ValueError("active audit registry has an unsupported schema")
    records = data["audits"]
    if any(not isinstance(record, dict) for record in records):
        raise ValueError("active audit registry contains an invalid record")
    for record in records:
        if (not isinstance(record.get("workspace"), str)
                or not record.get("workspace")
                or not isinstance(record.get("target"), str)
                or not record.get("target")
                or not isinstance(record.get("source_root"), str)
                or not record.get("source_root")
                or isinstance(record.get("round"), bool)
                or not isinstance(record.get("round"), int)
                or record["round"] < 1):
            raise ValueError("active audit registry contains an invalid scope")
        _parse_deadline(record.get("deadline_at"))
    return records


def _write_records(path: Path, records: List[Dict[str, Any]]) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".active-audits.", suffix=".tmp",
                                     dir=str(path.parent))
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"schema_version": REGISTRY_SCHEMA, "audits": records},
                      handle, ensure_ascii=False, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _same_path(left: str, right: str) -> bool:
    a = Path(left).expanduser().resolve(strict=False)
    b = Path(right).expanduser().resolve(strict=False)
    if os.name == "nt":
        return str(a).casefold() == str(b).casefold()
    return a == b


def _within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _roots_overlap(left: str, right: str) -> bool:
    a = Path(left).expanduser().resolve(strict=False)
    b = Path(right).expanduser().resolve(strict=False)
    if os.name == "nt":
        a, b = Path(str(a).casefold()), Path(str(b).casefold())
    return _within(a, b) or _within(b, a)


def register_active_audit(root: Path, workspace: Path, target: str,
                          round_no: int, deadline_at: str) -> Dict[str, Any]:
    """Register one immutable target root under an existing round deadline."""
    source_root = Path(root).resolve(strict=True)
    if not source_root.is_dir():
        raise ValueError("source root must be a directory")
    audit_workspace = Path(workspace).resolve(strict=True)
    if not ROUND_RE.fullmatch(str(round_no)):
        raise ValueError("round must be a positive integer")
    deadline = _parse_deadline(deadline_at)
    now = datetime.now(timezone.utc)
    if deadline <= now:
        raise ValueError("cannot register an expired audit round")

    path = registry_path()
    identity = (str(audit_workspace), str(target), int(round_no))
    record = {
        "workspace": str(audit_workspace),
        "target": str(target),
        "round": int(round_no),
        "source_root": str(source_root),
        "deadline_at": deadline.isoformat().replace("+00:00", "Z"),
    }
    with _locked(path):
        # Keep expired roots registered: expiration must stop further target
        # work, not silently remove the shell guard. The user/driver releases
        # a completed or expired round explicitly.
        records = _read_records(path)
        for existing in records:
            existing_identity = (str(existing.get("workspace")),
                                 str(existing.get("target")),
                                 int(existing.get("round", 0)))
            if existing_identity == identity:
                if not _same_path(str(existing.get("source_root", "")),
                                  str(source_root)):
                    raise ValueError(
                        "this audit round is already bound to a different source root")
                existing.update(record)
                _write_records(path, records)
                return dict(existing)
            if _roots_overlap(str(existing.get("source_root", "")),
                              str(source_root)):
                raise ValueError(
                    "another registered VulnGate round already covers this source root; "
                    "release the prior round explicitly")
        if len(records) >= MAX_ACTIVE_AUDITS:
            raise ValueError("too many active VulnGate audit roots")
        records.append(record)
        _write_records(path, records)
    return record


def release_active_audit(workspace: Path, target: str, round_no: int,
                         root: Optional[Path] = None) -> bool:
    """Remove a completed round's host-shell guard entry."""
    audit_workspace = str(Path(workspace).resolve(strict=False))
    source_root = (str(Path(root).resolve(strict=False)) if root is not None else None)
    path = registry_path()
    with _locked(path):
        try:
            records = _read_records(path)
        except ValueError:
            # The explicit release operation is also the recovery path for a
            # malformed local registry; it only removes guard metadata.
            records = []
        retained = []
        removed = False
        for record in records:
            same_scope = (
                str(record.get("workspace")) == audit_workspace
                and str(record.get("target")) == str(target)
                and int(record.get("round", 0)) == int(round_no))
            same_root = (source_root is None or _same_path(
                str(record.get("source_root", "")), source_root))
            if same_scope and same_root:
                removed = True
            else:
                retained.append(record)
        _write_records(path, retained)
    return removed


def _active_records() -> List[Dict[str, Any]]:
    path = registry_path()
    if not path.exists():
        return []
    with _locked(path):
        # Expired records still enforce the stop condition until a matching
        # audit-budget release removes them.
        return _read_records(path)


def _shell_tokens(command: str) -> Optional[List[str]]:
    # Command substitution is unsafe to inspect statically; the one ordinary
    # variable accepted in the wrapper is PLUGIN_ROOT in the CLI path.
    if "\x00" in command or "`" in command or re.search(r"\$\(", command):
        return None
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = []
        for token in lexer:
            if len(tokens) >= MAX_SHELL_TOKENS:
                raise _TooManyShellTokens()
            tokens.append(token)
    except _TooManyShellTokens:
        raise
    except ValueError:
        return None
    if any(token and all(char in _SHELL_PUNCTUATION for char in token)
           for token in tokens):
        return None
    return tokens


def _normalize_argument(value: str, cwd: Path) -> str:
    expanded = os.path.expandvars(value)
    path = Path(expanded).expanduser()
    if not path.is_absolute():
        path = cwd / path
    return str(path.resolve(strict=False))


def _command_touches_root(command: str, cwd: Path, root: Path) -> bool:
    """Conservatively detect shell commands that can address a registered root.

    Codex supplies a command string rather than an argv path manifest. Resolve
    explicit path arguments (including relative paths and symlink aliases),
    and treat ambiguous commands from an ancestor directory as in-scope when
    they can recursively inspect the working tree or execute arbitrary code.
    """
    root = Path(root).expanduser().resolve(strict=False)
    cwd = Path(cwd).expanduser().resolve(strict=False)
    if _within(cwd, root):
        return True
    normalized = command.replace("\\", "/")
    if str(root).replace("\\", "/") in normalized:
        return True

    if len(command) > MAX_GUARD_COMMAND_CHARS:
        return True
    try:
        tokens = _shell_tokens(command)
    except _TooManyShellTokens:
        return True
    cwd_is_ancestor = _within(root, cwd)
    if tokens is None:
        # Shell composition, substitutions, and redirections cannot be
        # interpreted reliably from the hook's command string.
        return cwd_is_ancestor
    if not tokens:
        return False

    path_values: List[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in _PATH_VALUE_FLAGS:
            if index + 1 < len(tokens):
                path_values.append(tokens[index + 1])
                index += 2
                continue
        elif token.startswith("--") and "=" in token:
            path_values.append(token.split("=", 1)[1])
        elif not token.startswith("-"):
            path_values.append(token)
        index += 1

    for value in path_values:
        if not value or "://" in value:
            continue
        expanded = os.path.expandvars(value)
        path = Path(expanded).expanduser()
        if not path.is_absolute():
            path = cwd / path
        # A single-word argument can still name the root or one of its
        # children (for example `rg pattern target/`).
        path_like = ("/" in expanded or "\\" in expanded
                     or expanded.startswith((".", "~", "$"))
                     or path.exists())
        if path_like and _within(path.resolve(strict=False), root):
            return True

    if cwd_is_ancestor:
        executable_names = {
            Path(token.split("=", 1)[-1]).name.lower()
            for token in tokens if token and not token.startswith("-")
        }
        if (executable_names & (_RECURSIVE_OR_METADATA_TOOLS
                                | _EXECUTION_TOOLS)
                or any(name.startswith(("python", "pypy"))
                       for name in executable_names)):
            return True
    return False


def _trusted_cli_operation(command: str, cwd: Path, plugin_root: Path
                           ) -> Optional[str]:
    tokens = _shell_tokens(command)
    if not tokens:
        return None
    executable = Path(tokens[0]).name.lower()
    if not (executable.startswith("python") or executable == "py"):
        return None
    script_index = 1
    if executable == "py" and script_index < len(tokens) and tokens[script_index] in {
            "-2", "-3"}:
        script_index += 1
    if script_index + 1 >= len(tokens):
        return None
    script_path_text = os.path.expandvars(tokens[script_index])
    script_path = Path(script_path_text).expanduser()
    if not script_path.is_absolute():
        script_path = cwd / script_path
    script_path = script_path.resolve(strict=False)
    try:
        script_path.relative_to(plugin_root.resolve(strict=True))
    except (OSError, ValueError):
        return None
    if script_path.name != "agent_cli.py":
        return None
    return tokens[script_index + 1]


def _matching_cli_scope(tokens: List[str], plugin_root: Path, cwd: Path
                        ) -> Optional[Tuple[str, str, int, str, str, str]]:
    if not tokens:
        return None
    executable = Path(tokens[0]).name.lower()
    if not (executable.startswith("python") or executable == "py"):
        return None
    script_index = 1
    if executable == "py" and script_index < len(tokens) and tokens[script_index] in {
            "-2", "-3"}:
        script_index += 1
    if script_index >= len(tokens):
        return None
    script_path_text = os.path.expandvars(tokens[script_index])
    script_path = Path(script_path_text).expanduser()
    if not script_path.is_absolute():
        script_path = cwd / script_path
    script_path = script_path.resolve(strict=False)
    try:
        script_path.relative_to(plugin_root.resolve(strict=True))
    except (OSError, ValueError):
        return None
    if script_path.name != "agent_cli.py" or script_index + 1 >= len(tokens):
        return None

    command_name = tokens[script_index + 1]
    if command_name == "audit-exec":
        target_index = script_index + 2
    elif command_name == "audit-budget":
        if (script_index + 3 >= len(tokens)
                or tokens[script_index + 2] not in {"start", "status", "release"}):
            return None
        command_name = "audit-budget:" + tokens[script_index + 2]
        target_index = script_index + 3
    else:
        return None
    if target_index >= len(tokens):
        return None
    target = tokens[target_index]
    values: Dict[str, str] = {}
    index = target_index + 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            break
        if token in {"--workspace", "--root", "--round"}:
            if index + 1 >= len(tokens):
                return None
            values[token[2:]] = tokens[index + 1]
            index += 2
            continue
        if token.startswith(("--workspace=", "--root=", "--round=")):
            key, value = token[2:].split("=", 1)
            values[key] = value
        index += 1
    if command_name == "audit-exec" and (index >= len(tokens) or index + 1 >= len(tokens)):
        return None
    if not all(key in values for key in ("workspace", "root", "round")):
        return None
    if not ROUND_RE.fullmatch(values["round"]):
        return None
    return (command_name, target, int(values["round"]),
            _normalize_argument(values["workspace"], cwd),
            _normalize_argument(values["root"], cwd),
            str(script_path))


def _is_allowed_audit_command(command: str, cwd: Path, plugin_root: Path,
                              record: Dict[str, Any]) -> bool:
    tokens = _shell_tokens(command)
    if tokens is None:
        return False
    operation_name = _trusted_cli_operation(command, cwd, plugin_root)
    if operation_name is None:
        return False
    expired = _parse_deadline(record.get("deadline_at")) <= datetime.now(timezone.utc)
    if expired:
        scope = _matching_cli_scope(tokens, plugin_root, cwd)
        if scope is None:
            return False
        operation, target, round_no, workspace, root, _script = scope
        same_scope = (
            target == str(record.get("target"))
            and round_no == int(record.get("round", 0))
            and _same_path(workspace, str(record.get("workspace", "")))
            and _same_path(root, str(record.get("source_root", ""))))
        return same_scope and operation in {
            "audit-budget:status", "audit-budget:release"}
    if operation_name not in {"audit-exec", "audit-budget"}:
        # Other calls to the bundled deterministic CLI use their own bounded
        # contracts and do not launch arbitrary shell argv from the host.
        return True
    scope = _matching_cli_scope(tokens, plugin_root, cwd)
    if scope is None:
        return False
    operation, target, round_no, workspace, root, _script = scope
    if (target != str(record.get("target"))
            or round_no != int(record.get("round", 0))
            or not _same_path(workspace, str(record.get("workspace", "")))
            or not _same_path(root, str(record.get("source_root", "")))):
        return False
    if operation == "audit-exec":
        return True
    return operation in {"audit-budget:start", "audit-budget:status",
                         "audit-budget:release"}


def _is_registry_recovery_release(command: str, cwd: Path,
                                  plugin_root: Path) -> bool:
    tokens = _shell_tokens(command)
    if tokens is None:
        return False
    scope = _matching_cli_scope(tokens, plugin_root, cwd)
    return bool(scope and scope[0] == "audit-budget:release")


def _deny(reason: str) -> Dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def evaluate_pre_tool_use(event: Dict[str, Any], plugin_root: Path
                          ) -> Optional[Dict[str, Any]]:
    """Return a Codex hook denial for raw Bash touching an active audit root."""
    if event.get("tool_name") != "Bash":
        return None
    try:
        records = _active_records()
    except (OSError, ValueError) as exc:
        tool_input = event.get("tool_input")
        command = (tool_input.get("command")
                   if isinstance(tool_input, dict) else "")
        cwd_value = event.get("cwd")
        cwd = (Path(cwd_value).expanduser().resolve(strict=False)
               if isinstance(cwd_value, str) else Path.cwd())
        if _is_registry_recovery_release(
                command if isinstance(command, str) else "",
                cwd, Path(plugin_root).resolve(strict=False)):
            return None
        return _deny(
            "VulnGate could not verify its active-audit guard registry (%s); "
            "use audit-budget release to recover it." % type(exc).__name__)
    if not records:
        return None

    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        return _deny("VulnGate could not verify the Bash tool input while an "
                     "active audit guard exists.")
    command = tool_input.get("command")
    cwd_value = event.get("cwd")
    if not isinstance(command, str) or not isinstance(cwd_value, str):
        return _deny("VulnGate could not verify the Bash command or working "
                     "directory while an active audit guard exists.")
    if len(command) > MAX_GUARD_COMMAND_CHARS:
        return _deny("VulnGate cannot inspect a Bash command larger than 64 KiB "
                     "while an active audit guard exists; move large argv lists "
                     "to a bounded input file or use audit-exec.")
    cwd = Path(cwd_value).expanduser().resolve(strict=False)

    applicable = []
    for record in records:
        root_text = str(record.get("source_root") or "")
        root = Path(root_text).expanduser().resolve(strict=False)
        if _command_touches_root(command, cwd, root):
            applicable.append(record)
    if not applicable:
        return None
    resolved_plugin_root = Path(plugin_root).resolve(strict=False)
    if all(_is_allowed_audit_command(command, cwd, resolved_plugin_root, record)
           for record in applicable):
        return None
    scopes = ", ".join("%s round %s" % (
        record.get("target"), record.get("round")) for record in applicable)
    expired = [record for record in applicable
               if _parse_deadline(record.get("deadline_at")) <=
               datetime.now(timezone.utc)]
    if expired:
        return _deny(
            "VulnGate round deadline expired (%s). The source root remains "
            "blocked; only matching audit-budget status or release calls are "
            "allowed." % scopes)
    return _deny(
        "Raw shell access to an active VulnGate source root is blocked (%s). "
        "Run this command through the matching agent_cli.py audit-exec wrapper; "
        "use audit-budget status/release for round control." % scopes)
