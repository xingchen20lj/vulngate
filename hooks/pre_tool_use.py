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


def _trusted_plugin_root() -> Path:
    """Resolve the hook's own plugin root; reject arbitrary import roots."""
    actual = Path(__file__).resolve().parent.parent
    requested = os.environ.get("PLUGIN_ROOT")
    root = Path(requested).expanduser().resolve() if requested else actual
    if root != actual:
        raise PermissionError("PLUGIN_ROOT does not match the hook installation root")
    manifest = root / ".codex-plugin" / "plugin.json"
    scripts = root / "scripts"
    if not manifest.is_file() or not scripts.is_dir():
        raise PermissionError("hook plugin root is incomplete")
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise PermissionError("hook plugin manifest is unreadable") from exc
    version = str(data.get("version", ""))
    if data.get("name") != "vulngate" or not version:
        raise PermissionError("hook plugin manifest identity is invalid")
    return root


def main() -> int:
    try:
        plugin_root = _trusted_plugin_root()
        scripts = plugin_root / "scripts"
        # The path is derived from the hook itself and has a validated
        # manifest identity; an environment variable can only repeat that
        # exact path, never replace it with attacker-controlled code.
        if str(scripts) not in sys.path:
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
