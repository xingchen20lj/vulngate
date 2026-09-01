"""Approval registry for privileged operations.

Hard security discipline (AGENTS.md):
  * read-only network (GitHub API / Maven) is the default for Novelty gate;
  * outbound connects (JNDI/LDAP/HTTP) are limited to 127.0.0.1 and recorded;
  * port listening and any non-loopback egress require explicit approval.
Every decision is appended to the round approval log (JSONL) for audit.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class ApprovalRule:
    operation: str
    allowed: bool
    constraint: str = ""
    note: str = ""


DEFAULT_RULES: List[ApprovalRule] = [
    ApprovalRule("read_network", True, "GitHub API / release pages / Maven metadata (read-only)",
                 "Novelty gate data collection"),
    ApprovalRule("maven_download", True, "Maven Central jar/sources into workspace cache only",
                 "Version matrix + static audit inputs"),
    ApprovalRule("loopback_connect", True, "127.0.0.1 only, mechanism-level PoC",
                 "JNDI/HTTP connect attempts must not leave the host"),
    ApprovalRule("port_listen", False, "loopback only, requires explicit per-run approval",
                 "LDAP/HTTP listeners for network side-effect evidence"),
    ApprovalRule("external_egress", False, "denied",
                 "No non-loopback network egress under any PoC"),
    ApprovalRule("policy_denied", False, "hard policy violation",
                 "The runner refused an unsafe command or scope escape"),
]


class ApprovalGate:
    """Records and enforces per-operation approval decisions."""

    def __init__(self, log_path: Optional[Path] = None, rules: Optional[List[ApprovalRule]] = None):
        self.log_path = log_path
        self.rules = rules or DEFAULT_RULES
        self.decisions: List[dict] = []
        self._lock = threading.Lock()

    def _rule(self, operation: str) -> ApprovalRule:
        for r in self.rules:
            if r.operation == operation:
                return r
        return ApprovalRule(operation, False, "unknown operation - deny by default", "")

    def request(self, operation: str, detail: str) -> bool:
        rule = self._rule(operation)
        entry = {
            "operation": operation,
            "allowed": rule.allowed,
            "constraint": rule.constraint,
            "detail": detail,
            "note": rule.note,
        }
        with self._lock:
            self.decisions.append(entry)
            if self.log_path is not None:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                with self.log_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return rule.allowed

    def assert_allowed(self, operation: str, detail: str) -> None:
        if not self.request(operation, detail):
            raise PermissionError(
                "operation '%s' denied by approval gate: %s" % (operation, detail)
            )

    def record_authorized(self, operation: str, detail: str,
                          constraint: str = "") -> None:
        """Record an explicit per-run user authorization.

        This is intentionally separate from the default rules: authorized
        staging is opt-in and must never silently change the normal local-only
        policy.
        """
        entry = {
            "operation": operation,
            "allowed": True,
            "constraint": constraint or "explicit authorized staging",
            "detail": detail,
            "note": "user-authorized staging exception",
        }
        with self._lock:
            self.decisions.append(entry)
            if self.log_path is not None:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                with self.log_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
