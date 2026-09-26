#!/usr/bin/env python3
"""Codex PreToolUse hook for active VulnGate audit roots."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


MAX_HOOK_EVENT_BYTES = 1024 * 1024
MAX_REGISTRY_BYTES = 256 * 1024
REGISTRY_SCHEMA = "vulngate-active-audits-v1"


def _guard_registry_may_be_active() -> bool:
    """Fail closed on bad hook input when an audit guard may be registered."""
    try:
        codex_home = os.environ.get("CODEX_HOME") or str(Path.home() / ".codex")
        path = (Path(codex_home).expanduser().resolve()
                / "vulngate" / "active-audits.json")
        with path.open("rb") as handle:
            raw = handle.read(MAX_REGISTRY_BYTES + 1)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if len(raw) > MAX_REGISTRY_BYTES:
        return True
    try:
        data = json.loads(raw)
    except (UnicodeError, ValueError):
        return True
    if (not isinstance(data, dict)
            or data.get("schema_version") != REGISTRY_SCHEMA
            or not isinstance(data.get("audits"), list)):
        return True
    return bool(data["audits"])


def _deny_unverifiable_event() -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                "VulnGate could not verify the Bash hook event while an active "
                "audit guard may exist; retry with a normal-sized command or "
                "use the matching audit-budget status/release operation."),
        }
    }


def main() -> int:
    try:
        plugin_root = Path(os.environ.get("PLUGIN_ROOT") or __file__).resolve()
        if plugin_root.is_file():
            plugin_root = plugin_root.parent.parent
        scripts = plugin_root / "scripts"
        sys.path.insert(0, str(scripts))
        from agent.analysis.audit_guard import evaluate_pre_tool_use

        raw = sys.stdin.buffer.read(MAX_HOOK_EVENT_BYTES + 1)
        if len(raw) > MAX_HOOK_EVENT_BYTES:
            raise ValueError("hook event exceeds the size limit")
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError("hook event must be an object")
        if event.get("tool_name") != "Bash":
            if "tool_name" in event:
                return 0
            raise ValueError("hook event is missing its tool name")
        decision = evaluate_pre_tool_use(event, plugin_root)
    except Exception as exc:
        if os.environ.get("VULNGATE_HOOK_DEBUG") == "1":
            print("VulnGate PreToolUse hook error: %s" % type(exc).__name__,
                  file=sys.stderr)
        if _guard_registry_may_be_active():
            print(json.dumps(_deny_unverifiable_event(), ensure_ascii=False,
                             separators=(",", ":")))
        return 0
    if decision is not None:
        print(json.dumps(decision, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
