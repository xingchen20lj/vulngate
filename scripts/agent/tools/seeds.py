"""Seed PoC library (plan 2.4): verified PoCs that S4 PoC generation can
attach as reference when a candidate matches their attack surface.

Seeds live under agent/regression/seeds/<target>/ with manifest.json.
Matching is keyword-based (seed.surface + keywords vs candidate text); a
match requires >=2 keyword hits or an exact surface-core phrase.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def load_seeds(root: Path) -> Dict[str, List[Dict[str, Any]]]:
    manifest_p = root / "agent" / "regression" / "seeds" / "manifest.json"
    if not manifest_p.exists():
        return {}
    manifest = json.loads(manifest_p.read_text(encoding="utf-8"))
    out: Dict[str, List[Dict[str, Any]]] = {}
    for s in manifest.get("seeds", []):
        tgt = s.get("target", "")
        src_p = root / "agent" / "regression" / "seeds" / tgt / s["file"]
        if not src_p.exists():
            continue
        out.setdefault(tgt, []).append({
            "file": s["file"],
            "class": s.get("class", ""),
            "surface": s.get("surface", ""),
            "keywords": s.get("keywords", []),
            "verdict": s.get("verdict", ""),
            "notes": s.get("notes", ""),
            "src": src_p.read_text(encoding="utf-8"),
        })
    return out


def match_seeds(seeds: Dict[str, List[Dict[str, Any]]], target: str,
                candidate: Dict[str, Any], min_hits: int = 2,
                max_results: int = 2) -> List[Dict[str, Any]]:
    """Return seeds whose surface/keywords overlap the candidate text."""
    text = " ".join(str(candidate.get(k, "")) for k in
                    ("surface", "logic", "entry", "preconditions", "novelty_keywords")).lower()
    hits: List[tuple] = []
    for s in seeds.get(target, []):
        n = sum(1 for kw in s["keywords"] if str(kw).lower() in text)
        core = str(s.get("surface", "")).split("（")[0].strip().lower()
        if n >= min_hits or (core and core[:10] in text):
            hits.append((n, s))
    hits.sort(key=lambda x: -x[0])
    return [s for _, s in hits[:max_results]]


def seed_reference_block(seeds: Dict[str, List[Dict[str, Any]]], target: str,
                         candidate: Dict[str, Any]) -> str:
    matched = match_seeds(seeds, target, candidate)
    if not matched:
        return ""
    parts = ["\n已验证种子参考（同攻击面的历史 PoC，仅作结构参考，不要照抄类名/入口）："]
    for s in matched:
        parts.append("\n--- seed %s (%s) ---\n%s" % (s["file"], s["surface"], s["src"]))
    return "\n".join(parts)
