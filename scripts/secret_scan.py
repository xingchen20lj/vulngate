#!/usr/bin/env python3
"""High-confidence secret scan for tracked source and release files."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path


PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b"),
)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
    findings = []
    for name in raw.decode("utf-8").split("\0"):
        if not name:
            continue
        path = root / name
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            if any(pattern.search(line) for pattern in PATTERNS):
                findings.append("%s:%d" % (name, line_no))
    if findings:
        print("possible secrets found:")
        print("\n".join(findings[:32]))
        return 1
    print("secret-scan: no high-confidence tracked secrets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
