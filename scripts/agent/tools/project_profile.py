"""Conservative project-value profile for audit prioritization (no network)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List


def _source_file_count(root: Path, source_dirs: List[str]) -> int:
    suffixes = {".java", ".kt", ".scala", ".go", ".py", ".js", ".ts", ".clj",
                ".c", ".cpp", ".rs", ".rb", ".php", ".cs"}
    count = 0
    for source_dir in source_dirs:
        path = (root / source_dir).resolve()
        if not str(path).startswith(str(root.resolve()) + "/") and path != root.resolve():
            continue
        if path.exists():
            count += sum(1 for item in path.rglob("*")
                         if item.is_file() and item.suffix in suffixes)
    return count


def build_project_profile(config: Any, root: Path, danger_site_count: int = 0,
                          source_sink_path_count: int = 0,
                          security_fix_count: int = 0) -> Dict[str, Any]:
    """Score attack-surface value, never vulnerability likelihood."""
    target_type = str(getattr(config, "target_type", "library"))
    entries = list(getattr(config, "entry_points", []) or [])
    text = " ".join([
        target_type, str(getattr(config, "api_hint", "")),
        str(getattr(config, "scope_constraints", "")),
        " ".join(str(e) for e in entries),
    ]).lower()
    signals = {
        "network_or_http": 18 if target_type == "web-app" or "http" in text or "rpc" in text else 0,
        "authorization_boundary": 16 if any(k in text for k in ("auth", "permission", "tenant", "role", "owner")) else 0,
        "parser_or_deserializer": 16 if any(k in text for k in ("parse", "json", "xml", "yaml", "deserialize", "decode")) else 0,
        "file_config_template": 12 if any(k in text for k in ("file", "config", "template", "plugin", "upload", "import", "export")) else 0,
        "execution_or_class_loading": 15 if any(k in text for k in ("exec", "classloader", "jndi", "script", "expression")) else 0,
        "protocol_or_messaging": 10 if any(k in text for k in ("protocol", "message", "rpc", "netty", "socket")) else 0,
        "security_history": min(8, security_fix_count),
        "danger_call_sites": min(3, danger_site_count // 10),
        "source_sink_paths": min(2, source_sink_path_count // 20),
    }
    score = min(100, sum(signals.values()) + min(10, len(entries) * 2)
                + min(5, _source_file_count(root, getattr(config, "source_dirs", []) or []) // 100))
    band = "high" if score >= 60 else "medium" if score >= 30 else "low"
    return {
        "score": score,
        "band": band,
        "meaning": "攻击面与审计价值排序，不是漏洞存在概率或严重性",
        "signals": signals,
        "entry_count": len(entries),
        "source_file_count": _source_file_count(root, getattr(config, "source_dirs", []) or []),
        "target_type": target_type,
    }
