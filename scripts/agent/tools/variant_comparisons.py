"""Bounded cross-version and fix-variant comparison orchestration.

This module turns a candidate's version/fix metadata into an executable
comparison contract, then classifies only the redacted cell summaries that S4
actually produced.  It never checks out a revision, treats a patch as proof,
or upgrades a difference into a finding.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple


COMPARISON_SCHEMA_VERSION = "comparison-orchestration-v1"
CLAIM_STATUS = "not-a-finding"
MAX_VERSIONS = 16
MAX_PAIRS = 8
MAX_VARIANTS = 8
MAX_TEXT = 120

_COMMIT_RE = re.compile(r"^[0-9a-f]{7,64}$", re.I)
_KNOWN_VARIANT_HINTS = (
    "alternate-codec", "boundary-variant", "production-path", "multi-file",
    "state-variant", "method-body", "lifecycle-variant", "identity-boundary",
)
_GAP_BUCKETS = frozenset({
    "harness-error", "precondition-unavailable", "run-failed",
    "gate-blocked", "policy-denied", "empty",
})


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    if value is None:
        return ""
    return " ".join(str(value).replace("\x00", "").split())[:limit]


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _versions(values: Iterable[Any]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        item = _text(value, 80)
        if item and item not in seen:
            seen.add(item)
            result.append(item)
        if len(result) >= MAX_VERSIONS:
            break
    return sorted(result)


def _commit(value: Any) -> str:
    item = _text(value, 80).lower()
    return item if _COMMIT_RE.fullmatch(item) else ""


def _variant_hints(values: Any) -> List[str]:
    if not isinstance(values, (list, tuple, set)):
        return []
    result = []
    for value in values:
        item = _text(value, 120).lower()
        match = next((hint for hint in _KNOWN_VARIANT_HINTS
                      if item.startswith(hint) or hint in item), "")
        if match and match not in result:
            result.append(match)
        if len(result) >= MAX_VARIANTS:
            break
    return sorted(result)


def build_comparison_contract(candidate: Mapping[str, Any],
                              versions: Sequence[Any] = ()) -> Dict[str, Any]:
    """Build a deterministic comparison contract from bounded candidate data."""
    candidate = candidate if isinstance(candidate, Mapping) else {}
    all_versions = _versions(
        list(versions)
        + list(candidate.get("affected_versions") or [])
        + list(candidate.get("fixed_versions") or [])
    )
    version_pairs = [
        {"before": all_versions[index], "after": all_versions[index + 1],
         "axis": "configured-version"}
        for index in range(min(len(all_versions) - 1, MAX_PAIRS))
    ]
    parent = _commit(candidate.get("patch_parent"))
    fixed = _commit(candidate.get("patch_commit"))
    sibling_hints = _variant_hints(candidate.get("patch_variants"))
    if not version_pairs and not (parent and fixed) and not sibling_hints:
        return {}

    source_revision = []
    if parent and fixed:
        source_revision = [
            {"role": "before", "ref": parent,
             "execution_state": "build-required"},
            {"role": "after", "ref": fixed,
             "execution_state": "build-required"},
        ]
    seed = {
        "candidate_id": _text(candidate.get("candidate_id"), 120),
        "versions": all_versions,
        "version_pairs": version_pairs,
        "source_revision": source_revision,
        "sibling_hints": sibling_hints,
    }
    return {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "comparison_id": "cmp-" + _digest(seed)[:20],
        "version_pairs": version_pairs,
        "source_revision": source_revision,
        "sibling_variants": [
            {"variant": item, "execution_state": "requires-sibling-lane"}
            for item in sibling_hints
        ],
        "required_observations": [
            "matching fixture and lane identity across comparison arms",
            "before/after runtime bucket classification",
            "signature drift is separate from bucket change",
            "source revision build availability is explicit",
        ],
        "falsifiers": [
            "a patch commit alone is not runtime evidence",
            "missing parent/fixed runtime is an environment gap, not a fix",
            "signature-only drift does not establish a behavioral difference",
            "missing sibling lane leaves the comparison incomplete",
        ],
        "claim_status": CLAIM_STATUS,
    }


def normalize_comparison_contract(raw: Any) -> Dict[str, Any]:
    """Normalize a persisted contract without trusting free-form fields."""
    if not isinstance(raw, Mapping) or raw.get(
            "schema_version") != COMPARISON_SCHEMA_VERSION:
        return {}
    pairs: List[Dict[str, str]] = []
    for item in raw.get("version_pairs") or []:
        if not isinstance(item, Mapping):
            continue
        before = _text(item.get("before"), 80)
        after = _text(item.get("after"), 80)
        if before and after and before != after:
            pairs.append({"before": before, "after": after,
                          "axis": "configured-version"})
        if len(pairs) >= MAX_PAIRS:
            break
    source_rows = []
    for item in raw.get("source_revision") or []:
        if not isinstance(item, Mapping):
            continue
        role = _text(item.get("role"), 16)
        ref = _commit(item.get("ref"))
        if role in {"before", "after"} and ref:
            source_rows.append({"role": role, "ref": ref,
                                "execution_state": "build-required"})
    source_rows = sorted(source_rows, key=lambda row: row["role"])
    sibling_rows = []
    for item in raw.get("sibling_variants") or []:
        value = item.get("variant") if isinstance(item, Mapping) else item
        hint = _variant_hints([value])
        if hint and hint[0] not in {row["variant"] for row in sibling_rows}:
            sibling_rows.append({"variant": hint[0],
                                 "execution_state": "requires-sibling-lane"})
        if len(sibling_rows) >= MAX_VARIANTS:
            break
    if not pairs and not (len(source_rows) >= 2) and not sibling_rows:
        return {}
    seed = {"pairs": pairs, "source_revision": source_rows,
            "sibling_variants": sibling_rows}
    raw_id = _text(raw.get("comparison_id"), 40)
    comparison_id = (raw_id if re.fullmatch(r"cmp-[0-9a-f]{20}", raw_id)
                     else "cmp-" + _digest(seed)[:20])
    return {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "comparison_id": comparison_id,
        "version_pairs": pairs,
        "source_revision": source_rows[:2],
        "sibling_variants": sibling_rows,
        "required_observations": [
            "matching fixture and lane identity across comparison arms",
            "before/after runtime bucket classification",
            "signature drift is separate from bucket change",
            "source revision build availability is explicit",
        ],
        "falsifiers": [
            "a patch commit alone is not runtime evidence",
            "missing parent/fixed runtime is an environment gap, not a fix",
            "signature-only drift does not establish a behavioral difference",
            "missing sibling lane leaves the comparison incomplete",
        ],
        "claim_status": CLAIM_STATUS,
    }


def _row_bucket(row: Mapping[str, Any]) -> str:
    return _text(row.get("bucket"), 60).lower() or "empty"


def _row_signature(row: Mapping[str, Any]) -> str:
    return _text(row.get("signature"), 240)


def _classify_pair(before: Mapping[str, Any],
                   after: Mapping[str, Any]) -> Tuple[str, str]:
    before_bucket = _row_bucket(before)
    after_bucket = _row_bucket(after)
    if before_bucket in _GAP_BUCKETS or after_bucket in _GAP_BUCKETS:
        return "environment-gap", "cell-unavailable-or-gated"
    if before_bucket != after_bucket:
        return "bucket-difference", "bucket-changed"
    if _row_signature(before) != _row_signature(after):
        return "signature-drift", "signature-changed"
    return "same-observation", "bucket-and-signature-match"


def summarize_comparison_observations(contract: Any,
                                     records: Iterable[Dict[str, Any]],
                                     primary_version: str = "") -> Dict[str, Any]:
    """Summarize actual version-cell observations against a contract."""
    normalized = normalize_comparison_contract(contract)
    if not normalized:
        return {}
    rows = [row for row in records if isinstance(row, dict)]
    index: Dict[Tuple[str, bool], Dict[str, Any]] = {}
    safe_modes = set()
    for row in rows:
        version = _text(row.get("version"), 80)
        if not version:
            continue
        safe = bool(row.get("safe_mode", False))
        safe_modes.add(safe)
        index.setdefault((version, safe), row)
    if not safe_modes:
        safe_modes = {False, True}
    observations = []
    for pair in normalized["version_pairs"]:
        for safe in sorted(safe_modes):
            before = index.get((pair["before"], safe))
            after = index.get((pair["after"], safe))
            if before is None or after is None:
                status, reason = "inconclusive", "missing-comparison-cell"
            else:
                status, reason = _classify_pair(before, after)
            observations.append({
                "before": pair["before"], "after": pair["after"],
                "safe_mode": safe, "status": status,
                "reason_code": reason, "claim_status": CLAIM_STATUS,
            })

    source_observations = [
        {"role": row["role"], "ref": row["ref"],
         "status": "not-executed", "reason_code": "source-revision-build-required",
         "claim_status": CLAIM_STATUS}
        for row in normalized["source_revision"]
    ]
    sibling_observations = [
        {"variant": row["variant"], "status": "not-executed",
         "reason_code": "requires-sibling-lane", "claim_status": CLAIM_STATUS}
        for row in normalized["sibling_variants"]
    ]
    statuses = {row["status"] for row in observations}
    if "bucket-difference" in statuses:
        overall = "difference-observed"
    elif "signature-drift" in statuses:
        overall = "signature-drift"
    elif "environment-gap" in statuses or "inconclusive" in statuses:
        overall = "inconclusive"
    elif "same-observation" in statuses:
        overall = "same-observation"
    else:
        overall = "unobserved"
    return {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "comparison_id": normalized["comparison_id"],
        "primary_version": _text(primary_version, 80),
        "status": overall,
        "version_observations": observations[:MAX_PAIRS * 4],
        "source_revision_observations": source_observations[:2],
        "sibling_observations": sibling_observations[:MAX_VARIANTS],
        "observed_count": sum(1 for row in observations
                               if row["status"] not in {"inconclusive", "environment-gap"}),
        "inconclusive_count": sum(1 for row in observations
                                   if row["status"] in {"inconclusive", "environment-gap"}),
        "claim_status": CLAIM_STATUS,
    }
