#!/usr/bin/env python3
"""Prepare or apply the declared GitHub branch-governance policy.

The default is a local, non-mutating dry run.  Remote writes require both
``--apply`` and ``--confirm-main`` so an operator's authorization is explicit.
After an apply, the script reads the protection back and fails if the remote
state does not match the repository policy.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def load_policy(root: Path) -> Dict[str, Any]:
    path = root / ".github" / "branch-protection.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != "branch-governance-v1":
        raise ValueError("invalid branch-governance policy")
    return data


def repository_slug(root: Path, explicit: Optional[str]) -> str:
    if explicit:
        if not re.fullmatch(r"[^/\s]+/[^/\s]+", explicit):
            raise ValueError("--repo must be OWNER/REPOSITORY")
        return explicit
    result = subprocess.run(
        ["git", "-C", str(root), "remote", "get-url", "origin"],
        check=False, capture_output=True, text=True, timeout=10,
    )
    remote = (result.stdout or "").strip()
    match = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$", remote)
    if not match:
        raise ValueError("cannot derive GitHub OWNER/REPOSITORY; pass --repo")
    return match.group(1)


def build_payload(policy: Dict[str, Any]) -> Dict[str, Any]:
    checks = [str(item) for item in policy["required_checks"]]
    return {
        "required_status_checks": {"strict": True, "contexts": checks},
        "enforce_admins": bool(policy["enforce_admins"]),
        "required_pull_request_reviews": {
            "dismiss_stale_reviews": bool(policy["dismiss_stale_reviews"]),
            "require_code_owner_reviews": bool(policy["require_code_owner_review"]),
            "required_approving_review_count": int(policy["required_approvals"]),
        },
        "restrictions": None,
        "required_linear_history": False,
        "allow_force_pushes": bool(policy["allow_force_pushes"]),
        "allow_deletions": bool(policy["allow_deletions"]),
    }


def verify_readback(remote: Dict[str, Any], policy: Dict[str, Any]) -> List[str]:
    mismatches: List[str] = []
    status = remote.get("required_status_checks") or {}
    expected_checks = sorted(str(item) for item in policy["required_checks"])
    actual_checks = sorted(str(item) for item in status.get("contexts") or [])
    if status.get("strict") is not True:
        mismatches.append("required_status_checks.strict")
    if actual_checks != expected_checks:
        mismatches.append("required_status_checks.contexts")
    if (remote.get("enforce_admins") or {}).get("enabled") is not True:
        mismatches.append("enforce_admins.enabled")
    reviews = remote.get("required_pull_request_reviews") or {}
    review_checks = {
        "dismiss_stale_reviews": bool(policy["dismiss_stale_reviews"]),
        "require_code_owner_reviews": bool(policy["require_code_owner_review"]),
        "required_approving_review_count": int(policy["required_approvals"]),
    }
    for key, expected in review_checks.items():
        if reviews.get(key) != expected:
            mismatches.append("required_pull_request_reviews.%s" % key)
    if (remote.get("allow_force_pushes") or {}).get("enabled") is not False:
        mismatches.append("allow_force_pushes.enabled")
    if (remote.get("allow_deletions") or {}).get("enabled") is not False:
        mismatches.append("allow_deletions.enabled")
    return mismatches


def _gh_api(endpoint: str, *, method: str = "GET",
            payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    command = ["gh", "api", endpoint]
    if method != "GET":
        command += ["--method", method, "--input", "-"]
    result = subprocess.run(
        command,
        input=(json.dumps(payload, ensure_ascii=False) if payload is not None else None),
        check=False, capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:400]
        raise RuntimeError("gh api failed: %s" % detail)
    value = json.loads(result.stdout or "{}")
    if not isinstance(value, dict):
        raise RuntimeError("gh api returned a non-object response")
    return value


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument("--repo", help="GitHub OWNER/REPOSITORY")
    parser.add_argument("--apply", action="store_true",
                        help="apply the policy; requires --confirm-main")
    parser.add_argument("--confirm-main", action="store_true",
                        help="explicitly authorize mutating main branch protection")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        root = args.root.resolve()
        policy = load_policy(root)
        branch = str(policy["branch"])
        if args.apply and (branch != "main" or not args.confirm_main):
            raise ValueError("--apply requires --confirm-main for main")
        slug = repository_slug(root, args.repo)
        endpoint = "repos/%s/branches/%s/protection" % (slug, branch)
        payload = build_payload(policy)
        result: Dict[str, Any] = {
            "mode": "apply" if args.apply else "dry-run",
            "endpoint": endpoint,
            "method": "PUT",
            "payload": payload,
            "claim_status": "not-a-finding",
        }
        if args.apply:
            _gh_api(endpoint, method="PUT", payload=payload)
            readback = _gh_api(endpoint)
            mismatches = verify_readback(readback, policy)
            result["remote_readback"] = {
                "verified": not mismatches,
                "mismatches": mismatches,
            }
            if mismatches:
                raise RuntimeError("remote protection mismatch: %s" % ", ".join(mismatches))
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print("branch governance %s prepared: %s" % (result["mode"], endpoint))
        return 0
    except (OSError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) as exc:
        payload = {"local_policy_valid": False, "error": str(exc),
                   "claim_status": "not-a-finding"}
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
