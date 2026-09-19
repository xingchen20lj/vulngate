"""Deterministic research-strategy candidate producers.

This module turns high-value S1 research signals into ordinary S2 candidate
descriptors.  The source-to-sink scanner is deliberately heuristic: it can
suggest a path, but it cannot prove that the same subject remains authorized
after a transform.  That is precisely why a composite path must become a
candidate for S3/S4 instead of ending as an informational S1 artifact.

The output is shaped like an LLM proposal and carries its provenance loudly.
It is deterministic for a given hint set, bounded by the caller, and safe to
merge with the existing control-map / differential candidate pool.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Iterable, List, Sequence, Tuple


_LOCATION_RE = re.compile(r"(?P<location>[^\s:]+:\d+)")


def _text(value: Any, limit: int = 240) -> str:
    """Return bounded, single-line text for persisted candidate metadata."""
    if value is None:
        return ""
    return " ".join(str(value).replace("\x00", "").split())[:limit]


def _items(value: Any, limit: int = 8) -> List[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [_text(item) for item in value if _text(item)][:limit]


def _location(value: Any) -> str:
    match = _LOCATION_RE.search(_text(value))
    return match.group("location") if match else ""


def _canonical_hint(hint: Dict[str, Any]) -> Tuple[str, ...]:
    """Build the stable identity material for one path hint."""
    return (
        _text(hint.get("source")),
        *_items(hint.get("transform")),
        *_items(hint.get("validation")),
        *_items(hint.get("authorization")),
        _text(hint.get("sink")),
    )


def _candidate_id(identity: Sequence[str]) -> str:
    digest = "\x1f".join(identity).encode("utf-8", errors="replace")
    return "chain-%s" % hashlib.sha1(digest).hexdigest()[:12]


def _poc_class(candidate_id: str) -> str:
    parts = [part for part in candidate_id.replace("_", "-").split("-") if part]
    return "".join(part[:1].upper() + part[1:] for part in parts) or "ChainCandidate"


def _authz_cases() -> List[Dict[str, Any]]:
    """Return credential-free negative cases for a transformed-object chain."""
    return [
        {"case_id": "anonymous", "principal": "anonymous",
         "expected_http_codes": [401, 403], "expected_authz": "deny",
         "expected_object_mutated": False},
        {"case_id": "cross-tenant", "principal": "user-b",
         "role": "user", "tenant_id": "tenant-b",
         "object_tenant_id": "tenant-a", "expected_http_codes": [403],
         "expected_authz": "deny", "expected_object_mutated": False},
        {"case_id": "other-principal", "principal": "user-b",
         "role": "user", "expected_http_codes": [403],
         "expected_authz": "deny", "expected_object_mutated": False},
    ]


def composite_chain_candidates(hints: Iterable[Dict[str, Any]],
                               max_items: int = 80) -> List[Dict[str, Any]]:
    """Convert composite source/sink hints into bounded S2 candidates.

    The candidate asks a narrow question: does the authorization observed near
    the path actually protect the transformed value and the final sink?  It
    never upgrades the heuristic confidence and never claims that the path is
    reachable under the default deployment.
    """
    if max_items == 0:
        return []
    out: List[Dict[str, Any]] = []
    seen = set()
    for hint in hints or []:
        if not isinstance(hint, dict):
            continue
        source = _text(hint.get("source"))
        sink = _text(hint.get("sink"))
        auth = _items(hint.get("authorization"))
        transforms = _items(hint.get("transform"))
        if not source or not sink or not auth:
            continue

        identity = _canonical_hint(hint)
        candidate_id = _candidate_id(identity)
        if candidate_id in seen:
            continue
        seen.add(candidate_id)

        locations = []
        for value in (source, *transforms, *auth, sink):
            loc = _location(value)
            if loc and loc not in locations:
                locations.append(loc)

        transform_text = " -> ".join(transforms) or "(无显式 transform 命中)"
        auth_text = "；".join(auth)
        sink_location = _location(sink) or sink
        out.append({
            "candidate_id": candidate_id,
            "surface": "possible-composite-chain: authorization-to-sink binding",
            "entry": source,
            "input_shape": "source-transform-authorized-sink",
            "logic": (
                "启发式路径 %s -> %s -> %s -> %s；需确认授权针对的是同一"
                " subject/object，且变换后参数仍受保护。"
                % (source, transform_text, auth_text, sink)
            ),
            "hypothesis": (
                "授权检查可能只保护原始请求或旧对象，而 transform 后的对象/参数"
                "仍可到达危险 sink，形成越权、跨租户操作或组合攻击链。"
            ),
            "precondition_tier_hint": "single-feature",
            "preconditions": [
                "静态路径为 heuristic-nearby，需确认入口在目标配置下实际暴露",
                "需在匿名、低权、跨租户和非归属对象上下文中验证对象绑定与最终效果",
            ],
            "poc_class": _poc_class(candidate_id),
            "jvm": {},
            "target_classes": [],
            "authz_cases": _authz_cases(),
            "chain_components": [
                "untrusted-input", "transform", "authorization", "dangerous-sink",
            ],
            "novelty_keywords": [
                "composite-chain", "authorization", "transformed-object",
                sink_location,
            ],
            "code_location": locations,
            "category": "authz",
            "source": "composite-chain",
            "producer": "chain-analysis",
            "confidence": "heuristic-nearby",
            "evidence_type": "static-inferred",
            "requires_manual_dataflow": True,
            "chain_hint": {
                "source": source,
                "transform": transforms,
                "authorization": auth,
                "sink": sink,
            },
        })
        if max_items > 0 and len(out) >= max_items:
            break

    return out
