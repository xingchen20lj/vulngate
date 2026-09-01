"""Stable, local-only finding record shape used by S7 renderers."""

from __future__ import annotations

from typing import Any, Dict, List


def _list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def normalize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Fill the report schema while preserving only report-safe structures."""
    data = dict(finding or {})
    data.setdefault("title", "")
    data.setdefault("status", "候选（待验证）")
    data.setdefault("summary", "")
    data.setdefault("repro", "")
    data.setdefault("evidence", "")
    data["preconditions"] = [str(x) for x in _list(data.get("preconditions"))]
    data["affected_versions"] = [str(x) for x in _list(data.get("affected_versions"))]
    data["fixed_versions"] = [str(x) for x in _list(data.get("fixed_versions"))]
    data["source_to_sink"] = [str(x) if not isinstance(x, dict) else dict(x)
                               for x in _list(data.get("source_to_sink"))]
    data["negative_results"] = [str(x) for x in _list(data.get("negative_results"))]
    data["authorization_matrix"] = [dict(x) for x in _list(
        data.get("authorization_matrix")) if isinstance(x, dict)]
    data["novelty"] = dict(data.get("novelty") or {})
    data["cvss"] = dict(data.get("cvss") or {})
    data["scope"] = str(data.get("scope", ""))
    data["entrypoint"] = str(data.get("entrypoint", ""))
    data["code_location"] = [str(x) for x in _list(data.get("code_location"))]
    return data
