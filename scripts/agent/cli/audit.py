"""Audit command parsing shared by the CLI and host guard."""

from __future__ import annotations

import sys
from typing import List, Optional


AUDIT_EXEC_VALUE_OPTIONS = {
    "--workspace", "--root", "--round", "--cwd", "--timeout",
    "--max-output-chars", "--env", "--retry-reason",
}


def normalize_audit_exec_argv(argv: Optional[List[str]]) -> Optional[List[str]]:
    """Normalize both documented ``target options -- command`` spellings."""
    raw = list(sys.argv[1:] if argv is None else argv)
    try:
        command_index = raw.index("audit-exec")
    except ValueError:
        return argv
    if command_index != 0:
        return argv
    try:
        separator = raw.index("--", command_index + 1)
    except ValueError:
        separator = len(raw)
    header = raw[command_index + 1:separator]
    target_index: Optional[int] = None
    index = 0
    while index < len(header):
        token = header[index]
        if token in AUDIT_EXEC_VALUE_OPTIONS:
            index += 2
            continue
        if any(token.startswith(option + "=")
               for option in AUDIT_EXEC_VALUE_OPTIONS):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        target_index = index
        break
    if target_index is None:
        return argv
    target = header[target_index]
    normalized_header = header[:target_index] + header[target_index + 1:] + [target]
    normalized = raw[:command_index + 1] + normalized_header
    if separator < len(raw):
        normalized += ["--"] + raw[separator + 1:]
    return normalized
