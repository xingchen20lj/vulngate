#!/usr/bin/env python3
"""Validate the repository's declared branch-governance contract.

This is a local policy check, not proof that GitHub has applied the settings.
Remote protection still requires an administrator to configure and read back
the corresponding ruleset/branch-protection API state.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List


def _load(path: Path) -> Dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("policy must be a JSON object")
    return value


def validate(root: Path) -> Dict[str, Any]:
    policy = _load(root / ".github" / "branch-protection.json")
    if policy.get("schema_version") != "branch-governance-v1":
        raise ValueError("unsupported branch policy schema_version")
    required = {
        "branch": "main",
        "require_pull_request": True,
        "required_approvals": 1,
        "dismiss_stale_reviews": True,
        "require_code_owner_review": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "enforce_admins": True,
        "remote_enforcement_required": True,
    }
    for key, expected in required.items():
        if policy.get(key) != expected:
            raise ValueError("branch policy %s must be %r" % (key, expected))
    checks = policy.get("required_checks")
    if checks != ["test", "security"]:
        raise ValueError("required_checks must be exactly test and security")

    workflow = (root / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8")
    job_ids = set(re.findall(r"^  ([A-Za-z0-9_-]+):\s*$", workflow, re.MULTILINE))
    missing_jobs = sorted(set(checks) - job_ids)
    if missing_jobs:
        raise ValueError("required CI job(s) missing: %s" % ", ".join(missing_jobs))

    codeowners = (root / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    if not re.search(r"^/scripts/agent/sandbox/\s+@", codeowners, re.MULTILINE):
        raise ValueError("sandbox security path is not covered by CODEOWNERS")
    return {
        "schema_version": "branch-governance-v1",
        "branch": "main",
        "required_checks": checks,
        "codeowners_security_path": True,
        "local_policy_valid": True,
        "remote_enforcement": "requires-github-admin-readback",
        "claim_status": "not-a-finding",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = validate(args.root.resolve())
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        payload = {"local_policy_valid": False, "error": str(exc),
                   "claim_status": "not-a-finding"}
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 2
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("branch governance policy: valid locally")
        print("remote enforcement: requires GitHub admin readback")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
