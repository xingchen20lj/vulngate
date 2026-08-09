"""Read-only source/jar inspection helpers (rg, jar tf, hashing, unzip)."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import List, Optional


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def rg(pattern: str, path: Path, globs: Optional[List[str]] = None,
       max_count: Optional[int] = None) -> List[str]:
    cmd = ["rg", "-n", "--no-heading", pattern, str(path)]
    for g in globs or []:
        cmd += ["-g", g]
    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if proc.returncode not in (0, 1):
        return []
    lines = [ln for ln in (proc.stdout or "").splitlines() if ln.strip()]
    if max_count is not None:
        lines = lines[:max_count]
    return lines


def count_references(path: Path, symbol: str, globs: Optional[List[str]] = None) -> int:
    return len(rg(symbol, path, globs))


def jar_classes(jar: Path) -> List[str]:
    proc = subprocess.run(["jar", "tf", str(jar)], capture_output=True, text=True, errors="replace")
    if proc.returncode != 0:
        return []
    return [ln for ln in (proc.stdout or "").splitlines() if ln.strip()]


def unzip_jar(jar: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    subprocess.run(["unzip", "-q", "-o", str(jar), "-d", str(dest)],
                   capture_output=True, check=True)


def module_map(classes: List[str], top_levels: int = 3) -> dict:
    from collections import Counter
    prefixes = Counter()
    for cls in classes:
        if cls.endswith(".class") and not cls.endswith("module-info.class"):
            parts = cls.split("/")
            prefixes[".".join(parts[:top_levels])] += 1
    return dict(prefixes.most_common(40))
