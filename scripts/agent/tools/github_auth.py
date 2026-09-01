"""Resolve GitHub API credentials without exposing token material.

The GitHub CLI stores credentials in the platform keychain, so a logged-in
``gh`` process does not imply that ``GITHUB_TOKEN`` is present in the parent
environment.  VulnGate uses this small resolver for both diagnostics and live
Novelty requests.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Optional


def resolve_github_token(explicit: Optional[str] = None) -> str:
    """Return an explicit/env token, or a token from ``gh auth token``.

    The token is returned only to the caller in memory.  Command output and
    errors are suppressed so credentials cannot enter audit artifacts.
    """
    for value in (explicit, os.environ.get("GITHUB_TOKEN"), os.environ.get("GH_TOKEN")):
        if value and value.strip():
            return value.strip()

    gh = shutil.which("gh")
    if not gh:
        return ""
    try:
        result = subprocess.run(
            [gh, "auth", "token"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def github_token_source(explicit: Optional[str] = None) -> str:
    """Return a non-secret source label for diagnostics."""
    if explicit and explicit.strip():
        return "explicit"
    if os.environ.get("GITHUB_TOKEN", "").strip():
        return "GITHUB_TOKEN"
    if os.environ.get("GH_TOKEN", "").strip():
        return "GH_TOKEN"
    return "gh-keychain" if resolve_github_token() else "missing"
