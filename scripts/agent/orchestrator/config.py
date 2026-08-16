"""Target configuration loading (jars, entries, candidates, baselines)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class TargetConfig:
    name: str
    discovery_date: str
    target_type: str = "library"  # library | web-app | middleware | logging | expression | message-rpc
    target_urls: Dict[str, str] = field(default_factory=dict)  # version -> base URL (web-app S4)
    scope_constraints: str = ""  # project SECURITY.md scope rules, injected into S2/S3 prompts
    upstream_repo: Optional[str] = None
    api_hint: str = ""
    add_exports: List[str] = field(default_factory=list)
    add_opens: List[str] = field(default_factory=list)
    safe_mode_switch: str = "none"  # none | stream-constraints | legacy-jvm-prop
    safe_mode_jvm_prop: str = ""  # if set, matrix emits -D<prop>=true/false
    output_lang: str = "zh"  # "zh" | "en" (ledger/finding output language)
    llm_audit: bool = False  # S5b mechanism audit (LLM) in config-driven pipeline
    fuzzer: Dict[str, Any] = field(default_factory=dict)  # directed fuzz config (plan 2.1)
    public_scan: Dict[str, Any] = field(default_factory=dict)  # internet novelty scan (plan 2.7)
    jars: List[Dict[str, str]] = field(default_factory=list)
    deps: List[Dict[str, str]] = field(default_factory=list)
    source_dirs: List[str] = field(default_factory=list)
    poc_src_dir: Optional[str] = None
    entry_points: List[Dict[str, Any]] = field(default_factory=list)
    candidates: List[Dict[str, Any]] = field(default_factory=list)
    exclusions: List[Dict[str, Any]] = field(default_factory=list)
    baselines: List[Dict[str, Any]] = field(default_factory=list)
    notes: str = ""

    @classmethod
    def load(cls, path: Path) -> "TargetConfig":
        data = json.loads(path.read_text(encoding="utf-8"))
        kwargs = {}
        for name, f in cls.__dataclass_fields__.items():
            if name in data:
                kwargs[name] = data[name]
        return cls(**kwargs)

    def resolve_jars(self, workspace: Path) -> Dict[str, List[Path]]:
        out: Dict[str, List[Path]] = {}
        for j in self.jars:
            p = (workspace / j["path"]).resolve()
            out.setdefault(j["version"], []).append(p)
        for dep in self.deps:
            p = (workspace / dep["path"]).resolve()
            if dep.get("version"):
                if dep["version"] in out:
                    out[dep["version"]].append(p)
            else:
                for version_jars in out.values():
                    version_jars.append(p)
        return out
