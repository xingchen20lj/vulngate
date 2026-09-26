"""Approval registry for privileged operations.

Hard security discipline (AGENTS.md):
  * read-only network (GitHub API / Maven) is the default for Novelty gate;
  * outbound connects (JNDI/LDAP/HTTP) are limited to 127.0.0.1 and recorded;
  * port listening and any non-loopback egress require explicit approval.
Every decision is appended to the round approval log (JSONL) for audit.
"""

from __future__ import annotations

import json
import hashlib
import secrets
import threading
import time
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
    ApprovalRule("loopback_connect", True,
                 "declared literal loopback target; source screening, not OS isolation",
                 "JNDI/HTTP connect attempts must not leave the host"),
    ApprovalRule("service_lifecycle", True,
                 "explicit one-time run/config-bound authorization plus an available isolation backend",
                 "Bounded target service start/stop for stateful research"),
    ApprovalRule("port_listen", False,
                 "source-screened loopback only; requires explicit per-run approval",
                 "LDAP/HTTP listeners for network side-effect evidence"),
    ApprovalRule("external_egress", False,
                 "known non-loopback targets denied by source screening",
                 "Not an OS-level network sandbox"),
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
        self._load_persisted_decisions()

    def _load_persisted_decisions(self) -> None:
        if self.log_path is None:
            return
        try:
            lines = self.log_path.read_text(encoding="utf-8").splitlines()[-1024:]
        except (OSError, UnicodeError):
            return
        by_id = {}
        for raw in lines:
            try:
                entry = json.loads(raw)
            except (TypeError, ValueError):
                continue
            if not isinstance(entry, dict):
                continue
            approval_id = entry.get("approval_id")
            if entry.get("consumed") is True and approval_id in by_id:
                by_id[approval_id]["consumed"] = True
                by_id[approval_id]["consumed_at"] = entry.get("consumed_at")
            elif entry.get("operation"):
                self.decisions.append(entry)
                if approval_id:
                    by_id[approval_id] = entry

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
                try:
                    self.log_path.chmod(0o600)
                except OSError:
                    pass
        return rule.allowed

    def assert_allowed(self, operation: str, detail: str) -> None:
        if not self.request(operation, detail):
            raise PermissionError(
                "operation '%s' denied by approval gate: %s" % (operation, detail)
            )

    def record_authorized(self, operation: str, detail: str,
                          constraint: str = "", *, run_id: str = "",
                          config_digest: str = "", expires_at: Optional[float] = None,
                          nonce: str = "") -> str:
        """Record an explicit per-run user authorization.

        This is intentionally separate from the default rules: authorized
        staging is opt-in and must never silently change the normal local-only
        policy.
        """
        approval_id = hashlib.sha256(
            (nonce or secrets.token_hex(24)).encode("utf-8")).hexdigest()[:24]
        entry = {
            "approval_id": approval_id,
            "operation": operation,
            "allowed": True,
            "constraint": constraint or "explicit authorized staging",
            "detail": detail,
            "note": "user-authorized staging exception",
            "run_id": str(run_id or ""),
            "config_digest": str(config_digest or ""),
            "expires_at": float(expires_at) if expires_at is not None else None,
            "consumed": False,
        }
        with self._lock:
            self.decisions.append(entry)
            if self.log_path is not None:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                with self.log_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
                try:
                    self.log_path.chmod(0o600)
                except OSError:
                    pass
        return approval_id

    def consume_authorized(self, operation: str, run_id: str,
                           config_digest: str) -> bool:
        """Consume a single run/config-bound operator approval.

        A persisted repository boolean is never enough.  The record must have
        been created by the current operator and persisted in the approval log,
        match the exact run and config digest, be
        unexpired, and can only be consumed once.
        """
        now = time.time()
        with self._lock:
            for entry in self.decisions:
                if entry.get("operation") != operation or not entry.get("allowed"):
                    continue
                if entry.get("consumed"):
                    continue
                if str(entry.get("run_id", "")) != str(run_id):
                    continue
                if str(entry.get("config_digest", "")) != str(config_digest):
                    continue
                expiry = entry.get("expires_at")
                if not isinstance(expiry, (int, float)) or expiry <= now:
                    continue
                entry["consumed"] = True
                entry["consumed_at"] = now
                if self.log_path is not None:
                    self.log_path.parent.mkdir(parents=True, exist_ok=True)
                    with self.log_path.open("a", encoding="utf-8") as fh:
                        fh.write(json.dumps({
                            "approval_id": entry.get("approval_id", ""),
                            "operation": operation,
                            "run_id": str(run_id),
                            "config_digest": str(config_digest),
                            "consumed": True,
                            "consumed_at": now,
                        }, ensure_ascii=False) + "\n")
                    try:
                        self.log_path.chmod(0o600)
                    except OSError:
                        pass
                return True
        return False
