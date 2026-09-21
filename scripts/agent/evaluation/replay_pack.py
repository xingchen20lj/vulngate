"""Build and validate a provenance-carrying replay pack.

The per-target replay calibration is useful, but a copied calibration JSON
does not say which local round artifacts produced it.  This module adds that
missing chain of custody without copying source code, payloads, commands,
stdout/stderr, credentials, or finding conclusions.  A pack contains only
bounded summaries and SHA-256 metadata for an allowlisted set of workspace
local artifacts.

The pack is research metadata, never a finding.  A missing runtime cell is
recorded as an environment/provenance gap and is never converted into a
negative security observation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ..memory.research import _normalize_variant_evidence
from ..tools.redaction import redact_text
from .replay_calibration import (
    calibrate_replay_history,
    load_replay_history,
    normalize_replay_calibration,
)


PACK_SCHEMA_VERSION = "research-replay-pack-v1"
PACK_FILENAME = "research-replay-pack.json"
PACK_CLAIM_STATUS = "not-a-finding"

MAX_ROUNDS = 128
MAX_ARTIFACTS_PER_ROUND = 8
MAX_TARGET_ARTIFACTS = 8
MAX_LANES_PER_ROUND = 32
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
MAX_TEXT = 120

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$", re.I)
_DIGEST_RE = re.compile(r"^(?:target|pack|rpk|cmp)-[0-9a-f]{24}$")
_ROUND_RE = re.compile(r"^round-(\d+)$")
_SURFACES = frozenset({"web", "protocol", "cloud", "mobile", "native"})
_LANES = frozenset({"positive", "negative", "environment-gap"})
_LANE_STATUSES = frozenset({
    "observed", "partial", "environment-gap", "not-executed",
})
_COMPARISON_STATUSES = frozenset({
    "difference-observed", "signature-drift", "inconclusive",
    "same-observation", "unobserved",
})
_ROUND_PROVENANCE_STATUSES = frozenset({
    "complete", "partial", "environment-gap", "not-executed", "invalid",
})
_PACK_PROVENANCE_STATUSES = frozenset({
    "complete", "partial", "environment-gap", "not-executed", "invalid",
})
_ENVIRONMENT_STATUSES = frozenset({
    "precondition-unavailable", "policy-denied", "run-failed",
    "environment-gap", "degraded", "disabled", "no-fixtures",
    "no-candidates", "not-executed",
})
_SIGNALS = frozenset({
    "execution", "entry-behavior", "authorization", "negative-baseline",
    "capability-trace", "state-sequence", "typed-effect",
    "safe-equivalent", "environment-gap", "evidence-field", "runtime-error",
})
_RUNTIME_STATUSES = frozenset({
    "completed", "completed-with-gaps", "precondition-unavailable",
    "policy-denied", "run-failed", "no-fixtures", "disabled",
    "environment-gap", "degraded", "no-candidates", "not-executed",
    "unavailable",
    "unknown", "",
})
_SOURCE_STATUSES = frozenset({
    "observed", "environment-gap", "not-executed", "inconclusive",
    "unobserved", "run-failed", "precondition-unavailable", "unknown",
})
_SEQUENCE_STATUSES = frozenset({
    "not-declared", "no-trace", "partial", "out-of-order",
    "unexpected-step", "complete",
})
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,95}$")

# The allowlist is intentionally explicit.  A replay pack is a provenance
# summary, not a generic filesystem snapshot.
_ROUND_SPECS: Tuple[Tuple[str, str, str], ...] = (
    ("S4", "runtime-lab.json", "runtime-lab-v1"),
    ("S8", "research-guidance.json", "research-strategy-guidance-v1"),
    ("S8", "research-strategy-feedback.json", "research-strategy-feedback-v1"),
    ("S8", "research-consistency.json", "research-consistency-v1"),
    ("S8", "research-consistency-actions.json",
     "research-consistency-action-v1"),
    ("S8", "research-consistency-rechecks.json",
     "research-consistency-recheck-v1"),
    ("S8", "research-portfolio.json", "research-portfolio-v1"),
    ("S8", "research-replay-calibration.json",
     "research-replay-calibration-v1"),
)
_TARGET_SPECS: Tuple[Tuple[str, str], ...] = (
    ("research-memory.json", "research-memory-v1"),
    ("research-portfolio.json", "research-portfolio-v1"),
    ("research-strategy.json", "research-strategy-v1"),
    ("coverage/research-guidance.json", "research-strategy-guidance-v1"),
    ("coverage/research-consistency.json", "research-consistency-v1"),
    ("coverage/research-consistency-actions.json",
     "research-consistency-action-v1"),
    ("coverage/research-consistency-rechecks.json",
     "research-consistency-recheck-v1"),
    ("coverage/research-replay-calibration.json",
     "research-replay-calibration-v1"),
)
_ROUND_SPEC_BY_ARTIFACT = {
    "%s/%s" % (stage, name): (stage, name, schema)
    for stage, name, schema in _ROUND_SPECS
}
_TARGET_SCHEMA_BY_ARTIFACT = dict(_TARGET_SPECS)

# Closure was added after the first replay-pack schema.  Treat its absence as
# a backwards-compatible missing capability, but still record and validate it
# whenever a round/target actually contains the artifact.
_OPTIONAL_ARTIFACTS = frozenset({
    "S8/research-consistency-rechecks.json",
    "coverage/research-consistency-rechecks.json",
})


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    try:
        value = redact_text(value)
    except Exception:  # pragma: no cover - defensive redaction boundary
        value = str(value)
    return " ".join(str(value or "").replace("\x00", "").split())[:limit]


def _int(value: Any, default: int = 0, minimum: int = 0,
         maximum: int = 1000000) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def _digest(value: Any, prefix: str = "rpk") -> str:
    return prefix + "-" + hashlib.sha256(
        _canonical(value).encode("utf-8", errors="replace")).hexdigest()[:24]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _runtime_status(value: Any) -> str:
    status = _text(value, 48).lower()
    return status if status in _RUNTIME_STATUSES else "unknown"


def _read_json(path: Path) -> Tuple[Optional[Dict[str, Any]], str, int, str]:
    """Read one allowlisted artifact and return raw dict plus safe metadata."""
    try:
        if not path.is_file():
            return None, "absent", 0, ""
        size = int(path.stat().st_size)
        if size > MAX_ARTIFACT_BYTES:
            return None, "oversize", size, ""
        digest = "sha256:" + _sha256(path)
        if size > MAX_JSON_BYTES:
            return None, "oversize", size, digest
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError,
            json.JSONDecodeError):
        return None, "invalid", 0, ""
    if not isinstance(value, dict):
        return None, "invalid", size, digest
    return value, "present", size, digest


def _safe_target_dir(workspace: Path, target: str) -> Optional[Path]:
    state_root = Path(workspace).resolve() / "state"
    candidate = state_root / str(target)
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(state_root)
    except (OSError, ValueError):
        return None
    return resolved


def _artifact_metadata(round_no: int, artifact: str, stage: str,
                       name: str, expected_schema: str,
                       path: Path) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    raw, file_status, size, digest = _read_json(path)
    status = file_status
    raw_schema = _text((raw or {}).get("schema_version"), 80) if raw else ""
    schema = raw_schema if raw_schema == expected_schema else ""
    if status == "present" and raw_schema != expected_schema:
        status = "invalid-schema"
    metadata = {
        "round": round_no,
        "stage": stage,
        "artifact": "%s/%s" % (stage, name),
        "status": status,
        "size": _int(size, 0, 0, MAX_ARTIFACT_BYTES),
        "sha256": digest if _SHA256_RE.fullmatch(digest) else "",
        "schema_version": schema,
        "claim_status": PACK_CLAIM_STATUS,
    }
    return metadata, raw if status == "present" else None


def _optional_artifact(artifact: str) -> bool:
    return artifact in _OPTIONAL_ARTIFACTS


def _target_artifact_metadata(name: str, expected_schema: str,
                              path: Path) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    raw, file_status, size, digest = _read_json(path)
    status = file_status
    raw_schema = _text((raw or {}).get("schema_version"), 80) if raw else ""
    schema = raw_schema if raw_schema == expected_schema else ""
    if status == "present" and raw_schema != expected_schema:
        status = "invalid-schema"
    metadata = {
        "artifact": name,
        "status": status,
        "size": _int(size, 0, 0, MAX_ARTIFACT_BYTES),
        "sha256": digest if _SHA256_RE.fullmatch(digest) else "",
        "schema_version": schema,
        "claim_status": PACK_CLAIM_STATUS,
    }
    return metadata, raw if status == "present" else None


def _bounded_set(values: Any, allowed: Iterable[str], limit: int) -> List[str]:
    if not isinstance(values, (list, tuple, set)):
        return []
    allow = set(allowed)
    return sorted({str(value).strip().lower() for value in values
                   if str(value).strip().lower() in allow})[:limit]


def _lane_status(statuses: Iterable[str]) -> str:
    values = {item for item in statuses if item in _LANE_STATUSES}
    if not values:
        return "not-executed"
    if values == {"observed"}:
        return "observed"
    if values == {"environment-gap"}:
        return "environment-gap"
    if values == {"not-executed"}:
        return "not-executed"
    return "partial"


def _lane_summary(runtime: Mapping[str, Any]) -> Dict[str, Any]:
    buckets: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    fixtures = runtime.get("fixtures") if isinstance(runtime, Mapping) else []
    if not isinstance(fixtures, list):
        fixtures = []
    for fixture in fixtures[:128]:
        if not isinstance(fixture, Mapping):
            continue
        witness = _normalize_variant_evidence(fixture.get("variant_evidence"))
        if not witness:
            continue
        surface = _text(witness.get("surface"), 32).lower()
        variant_id = _text(witness.get("variant_id"), 96)
        lane = _text(witness.get("lane"), 24).lower()
        if (surface not in _SURFACES or lane not in _LANES or
                not _IDENTIFIER_RE.fullmatch(variant_id)):
            continue
        key = (surface, variant_id, lane)
        bucket = buckets.setdefault(key, {
            "statuses": [],
            "cells_observed": 0,
            "cells_with_gap": 0,
            "signals": set(),
            "sequence_statuses": set(),
            "typed_effect_observed": False,
            "safe_equivalent_observed": False,
        })
        status = _text(witness.get("status"), 32).lower()
        if status not in _LANE_STATUSES:
            status = "partial"
        bucket["statuses"].append(status)
        bucket["cells_observed"] = min(
            4096, bucket["cells_observed"] + _int(
                witness.get("cells_observed"), 0, 0, 64))
        bucket["cells_with_gap"] = min(
            4096, bucket["cells_with_gap"] + _int(
                witness.get("cells_with_gap"), 0, 0, 64))
        bucket["signals"].update(_bounded_set(
            witness.get("observed_signals"), _SIGNALS, 11))
        bucket["sequence_statuses"].update(_bounded_set(
            witness.get("sequence_statuses"), _SEQUENCE_STATUSES, 8))
        bucket["typed_effect_observed"] = bool(
            bucket["typed_effect_observed"] or
            any(bool(cell.get("typed_effect_observed"))
                for cell in witness.get("cells") or []
                if isinstance(cell, Mapping)))
        bucket["safe_equivalent_observed"] = bool(
            bucket["safe_equivalent_observed"] or
            "safe-equivalent" in bucket["signals"])

    lanes: List[Dict[str, Any]] = []
    for (surface, variant_id, lane), bucket in sorted(buckets.items()):
        lanes.append({
            "surface": surface,
            "variant_id": variant_id,
            "lane": lane,
            "observation_count": min(128, len(bucket["statuses"])),
            "status": _lane_status(bucket["statuses"]),
            "cells_observed": bucket["cells_observed"],
            "cells_with_gap": bucket["cells_with_gap"],
            "observed_signals": sorted(bucket["signals"])[:11],
            "sequence_statuses": sorted(bucket["sequence_statuses"])[:8],
            "typed_effect_observed": bool(bucket["typed_effect_observed"]),
            "safe_equivalent_observed": bool(
                bucket["safe_equivalent_observed"]),
            "claim_status": PACK_CLAIM_STATUS,
        })
        if len(lanes) >= MAX_LANES_PER_ROUND:
            break
    counts = Counter(row["status"] for row in lanes)
    return {
        "lane_count": len(lanes),
        "observed_lanes": counts.get("observed", 0),
        "partial_lanes": counts.get("partial", 0),
        "environment_gap_lanes": counts.get("environment-gap", 0),
        "not_executed_lanes": counts.get("not-executed", 0),
        "cells_observed": min(4096, sum(row["cells_observed"] for row in lanes)),
        "cells_with_gap": min(4096, sum(row["cells_with_gap"] for row in lanes)),
        "typed_effect_lanes": sum(
            bool(row["typed_effect_observed"]) for row in lanes),
        "safe_equivalent_lanes": sum(
            bool(row["safe_equivalent_observed"]) for row in lanes),
        "observed_signals": sorted({signal for row in lanes
                                     for signal in row["observed_signals"]})[:11],
        "sequence_statuses": sorted({status for row in lanes
                                      for status in row["sequence_statuses"]})[:8],
        "lanes": lanes,
        "claim_status": PACK_CLAIM_STATUS,
    }


def _comparison_summary(runtime: Mapping[str, Any]) -> Dict[str, Any]:
    fixtures = runtime.get("fixtures") if isinstance(runtime, Mapping) else []
    if not isinstance(fixtures, list):
        fixtures = []
    status_counts: Counter = Counter()
    comparison_ids: List[str] = []
    inconclusive_cells = 0
    pending_arms = 0
    source_statuses: Counter = Counter()
    comparison_count = 0
    for fixture in fixtures[:128]:
        if not isinstance(fixture, Mapping):
            continue
        comparison = fixture.get("comparison")
        if not isinstance(comparison, Mapping):
            continue
        comparison_count += 1
        status = _text(comparison.get("status"), 48).lower()
        if status not in _COMPARISON_STATUSES:
            status = "unobserved"
        status_counts[status] += 1
        comparison_id = _text(comparison.get("comparison_id"), 40)
        if comparison_id:
            comparison_ids.append(comparison_id)
        inconclusive_cells += _int(
            comparison.get("inconclusive_count"), 0, 0, 128)
        for key in ("source_revision_observations", "sibling_observations"):
            for arm in comparison.get(key) or []:
                if not isinstance(arm, Mapping):
                    continue
                arm_status = _text(arm.get("status"), 48).lower()
                if arm_status not in _SOURCE_STATUSES:
                    arm_status = "unknown"
                source_statuses[arm_status or "unobserved"] += 1
                if arm_status in {"not-executed", "inconclusive", "unobserved"}:
                    pending_arms += 1
        source_comparison = comparison.get("source_revision_comparison")
        if isinstance(source_comparison, Mapping):
            for pair in source_comparison.get("pairs") or []:
                if isinstance(pair, Mapping):
                    pair_status = _text(pair.get("status"), 48).lower()
                    if pair_status not in _SOURCE_STATUSES:
                        pair_status = "unknown"
                    source_statuses[pair_status or "unobserved"] += 1
    gap_count = status_counts.get("inconclusive", 0) + \
        status_counts.get("unobserved", 0)
    if pending_arms:
        gap_count = max(gap_count, 1)
    return {
        "comparison_count": comparison_count,
        "status_counts": dict(sorted(status_counts.items())),
        "gap_count": min(128, gap_count),
        "inconclusive_cells": min(128, inconclusive_cells),
        "pending_arms": min(128, pending_arms),
        "contract_count": min(16, len(runtime.get("comparison_contracts") or [])),
        "source_revision_status_counts": dict(sorted(source_statuses.items())),
        "comparison_id_digest": (_digest(sorted(set(comparison_ids)), "cmp")
                                  if comparison_ids else ""),
        "claim_status": PACK_CLAIM_STATUS,
    }


def _round_provenance(artifacts: Sequence[Mapping[str, Any]],
                      runtime: Mapping[str, Any]) -> str:
    statuses = [str(row.get("status", "")) for row in artifacts]
    present = sum(status == "present" for status in statuses)
    invalid = any(status not in {"present", "absent"} for status in statuses)
    if invalid:
        return "invalid"
    if not present:
        return "not-executed"
    runtime_status = _text(runtime.get("status"), 48).lower()
    if runtime_status in _ENVIRONMENT_STATUSES and present <= 1:
        return "environment-gap"
    if all(status == "present" for status in statuses):
        return "complete"
    if runtime_status in _ENVIRONMENT_STATUSES and not runtime.get("fixtures"):
        return "environment-gap"
    return "partial"


def _pack_status(rounds: Sequence[Mapping[str, Any]],
                 target_artifacts: Sequence[Mapping[str, Any]],
                 calibration_consistency: str) -> str:
    if calibration_consistency == "mismatch":
        return "invalid"
    if not rounds:
        return "not-executed"
    round_statuses = [row.get("provenance_status") for row in rounds]
    artifact_statuses = [row.get("status") for row in target_artifacts]
    if any(status in {"invalid", "invalid-schema", "oversize"}
           for status in artifact_statuses):
        return "invalid"
    if any(status == "invalid" for status in round_statuses):
        return "invalid"
    if all(status == "not-executed" for status in round_statuses):
        return "not-executed"
    if all(status == "complete" for status in round_statuses) and \
            all(status == "present" for status in artifact_statuses) and \
            calibration_consistency == "match":
        return "complete"
    if all(status in {"not-executed", "environment-gap"}
           for status in round_statuses):
        return "environment-gap"
    return "partial"


def _pack_body(pack: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "schema_version": pack.get("schema_version", PACK_SCHEMA_VERSION),
        "target_digest": pack.get("target_digest", ""),
        "provenance": pack.get("provenance") or {},
        "target_artifacts": pack.get("target_artifacts") or [],
        "rounds": pack.get("rounds") or [],
        "calibration": pack.get("calibration") or {},
        "claim_status": pack.get("claim_status", PACK_CLAIM_STATUS),
    }


def _normal_lane(raw: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, Mapping):
        return None
    surface = _text(raw.get("surface"), 32).lower()
    lane = _text(raw.get("lane"), 24).lower()
    variant = _text(raw.get("variant_id"), 96)
    status = _text(raw.get("status"), 32).lower()
    if surface not in _SURFACES or lane not in _LANES or \
            not _IDENTIFIER_RE.fullmatch(variant):
        return None
    if status not in _LANE_STATUSES:
        status = "partial"
    return {
        "surface": surface,
        "variant_id": variant,
        "lane": lane,
        "observation_count": _int(raw.get("observation_count"), 0, 0, 128),
        "status": status,
        "cells_observed": _int(raw.get("cells_observed"), 0, 0, 4096),
        "cells_with_gap": _int(raw.get("cells_with_gap"), 0, 0, 4096),
        "observed_signals": _bounded_set(raw.get("observed_signals"), _SIGNALS, 11),
        "sequence_statuses": _bounded_set(
            raw.get("sequence_statuses"), _SEQUENCE_STATUSES, 8),
        "typed_effect_observed": bool(raw.get("typed_effect_observed")),
        "safe_equivalent_observed": bool(raw.get("safe_equivalent_observed")),
        "claim_status": PACK_CLAIM_STATUS,
    }


def _normal_lane_summary(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        raw = {}
    lanes: List[Dict[str, Any]] = []
    seen = set()
    for item in raw.get("lanes") or []:
        lane = _normal_lane(item)
        if not lane:
            continue
        key = (lane["surface"], lane["variant_id"], lane["lane"])
        if key in seen:
            continue
        seen.add(key)
        lanes.append(lane)
        if len(lanes) >= MAX_LANES_PER_ROUND:
            break
    lanes.sort(key=lambda row: (row["surface"], row["variant_id"], row["lane"]))
    counts = Counter(row["status"] for row in lanes)
    return {
        "lane_count": len(lanes),
        "observed_lanes": counts.get("observed", 0),
        "partial_lanes": counts.get("partial", 0),
        "environment_gap_lanes": counts.get("environment-gap", 0),
        "not_executed_lanes": counts.get("not-executed", 0),
        "cells_observed": min(4096, sum(row["cells_observed"] for row in lanes)),
        "cells_with_gap": min(4096, sum(row["cells_with_gap"] for row in lanes)),
        "typed_effect_lanes": sum(bool(row["typed_effect_observed"]) for row in lanes),
        "safe_equivalent_lanes": sum(bool(row["safe_equivalent_observed"])
                                     for row in lanes),
        "observed_signals": sorted({signal for row in lanes
                                     for signal in row["observed_signals"]})[:11],
        "sequence_statuses": sorted({status for row in lanes
                                      for status in row["sequence_statuses"]})[:8],
        "lanes": lanes,
        "claim_status": PACK_CLAIM_STATUS,
    }


def _normal_comparison_summary(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        raw = {}
    status_counts = {}
    for key, value in (raw.get("status_counts") or {}).items():
        status = _text(key, 48).lower()
        if status in _COMPARISON_STATUSES:
            status_counts[status] = _int(value, 0, 0, 128)
    source_counts = {}
    for key, value in (raw.get("source_revision_status_counts") or {}).items():
        status = _text(key, 48).lower()
        if status not in _SOURCE_STATUSES:
            status = "unknown"
        source_counts[status] = min(
            128, source_counts.get(status, 0) + _int(value, 0, 0, 128))
    digest = _text(raw.get("comparison_id_digest"), 40)
    if digest and not _DIGEST_RE.fullmatch(digest):
        digest = ""
    return {
        "comparison_count": _int(raw.get("comparison_count"), 0, 0, 128),
        "status_counts": dict(sorted(status_counts.items())),
        "gap_count": _int(raw.get("gap_count"), 0, 0, 128),
        "inconclusive_cells": _int(raw.get("inconclusive_cells"), 0, 0, 128),
        "pending_arms": _int(raw.get("pending_arms"), 0, 0, 128),
        "contract_count": _int(raw.get("contract_count"), 0, 0, 16),
        "source_revision_status_counts": dict(sorted(source_counts.items())),
        "comparison_id_digest": digest,
        "claim_status": PACK_CLAIM_STATUS,
    }


def _normal_artifact(raw: Any, round_no: int = 0,
                     target: bool = False) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, Mapping):
        return None
    artifact = _text(raw.get("artifact"), 120).replace("\\", "/")
    allowed = _TARGET_SCHEMA_BY_ARTIFACT if target else _ROUND_SPEC_BY_ARTIFACT
    if artifact not in allowed:
        return None
    status = _text(raw.get("status"), 32).lower()
    if status not in {"present", "absent", "invalid", "invalid-schema", "oversize"}:
        return None
    digest = _text(raw.get("sha256"), 80).lower()
    if digest and not _SHA256_RE.fullmatch(digest):
        digest = ""
    expected_schema = (allowed[artifact] if target
                       else allowed[artifact][2])
    raw_schema = _text(raw.get("schema_version"), 80)
    schema = raw_schema if raw_schema == expected_schema else ""
    if status == "present" and raw_schema != expected_schema:
        status = "invalid-schema"
    result = {
        "artifact": artifact,
        "status": status,
        "size": _int(raw.get("size"), 0, 0, MAX_ARTIFACT_BYTES),
        "sha256": digest,
        "schema_version": schema,
        "claim_status": PACK_CLAIM_STATUS,
    }
    if not target:
        result["round"] = _int(raw.get("round"), round_no, 0, 1000000)
        stage, name, _schema = _ROUND_SPEC_BY_ARTIFACT[artifact]
        result["stage"] = stage
        # `name` is intentionally not copied from user input; it comes from the
        # allowlist and makes verification deterministic.
        result["artifact"] = "%s/%s" % (stage, name)
    return result


def _normal_round(raw: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, Mapping):
        return None
    round_no = _int(raw.get("round"), 0, 1, 1000000)
    if not round_no:
        return None
    artifacts: List[Dict[str, Any]] = []
    seen = set()
    for item in raw.get("artifacts") or []:
        artifact = _normal_artifact(item, round_no=round_no)
        if not artifact or artifact["artifact"] in seen:
            continue
        seen.add(artifact["artifact"])
        artifacts.append(artifact)
        if len(artifacts) >= MAX_ARTIFACTS_PER_ROUND:
            break
    artifacts.sort(key=lambda row: row["artifact"])
    status = _text(raw.get("provenance_status"), 32).lower()
    if status not in _ROUND_PROVENANCE_STATUSES:
        return None
    return {
        "round": round_no,
        "provenance_status": status,
        "runtime_status": _runtime_status(raw.get("runtime_status")),
        "artifact_count": sum(row["status"] == "present" for row in artifacts),
        "missing_artifact_count": sum(row["status"] == "absent" for row in artifacts),
        "invalid_artifact_count": sum(row["status"] not in {"present", "absent"}
                                      for row in artifacts),
        "artifacts": artifacts,
        "lane_summary": _normal_lane_summary(raw.get("lane_summary")),
        "comparison_summary": _normal_comparison_summary(
            raw.get("comparison_summary")),
        "claim_status": PACK_CLAIM_STATUS,
    }


def _provenance_for(rounds: Sequence[Mapping[str, Any]],
                    target_artifacts: Sequence[Mapping[str, Any]],
                    consistency: str) -> Dict[str, Any]:
    status = _pack_status(rounds, target_artifacts, consistency)
    round_statuses = Counter(row["provenance_status"] for row in rounds)
    return {
        "status": status,
        "source_kind": "workspace-local-round-artifacts",
        "verification": "sha256-file-digests",
        "valid_for_cohort": bool(status == "complete" and
                                   consistency == "match"),
        "round_count": len(rounds),
        "complete_rounds": round_statuses.get("complete", 0),
        "partial_rounds": round_statuses.get("partial", 0),
        "environment_gap_rounds": round_statuses.get("environment-gap", 0),
        "not_executed_rounds": round_statuses.get("not-executed", 0),
        "invalid_rounds": round_statuses.get("invalid", 0),
        "artifact_count": sum(row["status"] == "present"
                               for row in target_artifacts),
        "round_artifact_count": sum(
            artifact["status"] == "present"
            for row in rounds for artifact in row["artifacts"]),
        "missing_artifact_count": sum(
            artifact["status"] == "absent"
            for row in rounds for artifact in row["artifacts"])
            + sum(artifact["status"] == "absent"
                  for artifact in target_artifacts),
        "invalid_artifact_count": sum(
            artifact["status"] not in {"present", "absent"}
            for row in rounds for artifact in row["artifacts"])
            + sum(artifact["status"] not in {"present", "absent"}
                  for artifact in target_artifacts),
        "calibration_consistency": consistency,
        "claim_status": PACK_CLAIM_STATUS,
    }


def normalize_replay_pack(raw: Any) -> Dict[str, Any]:
    """Normalize a pack and reject a digest that does not match its body."""
    if not isinstance(raw, Mapping) or raw.get("schema_version") != PACK_SCHEMA_VERSION:
        return {}
    target_digest = _text(raw.get("target_digest"), 40).lower()
    if not re.fullmatch(r"target-[0-9a-f]{24}", target_digest):
        return {}
    target_artifacts: List[Dict[str, Any]] = []
    seen_target = set()
    for item in raw.get("target_artifacts") or []:
        artifact = _normal_artifact(item, target=True)
        if not artifact or artifact["artifact"] in seen_target:
            continue
        seen_target.add(artifact["artifact"])
        target_artifacts.append(artifact)
        if len(target_artifacts) >= MAX_TARGET_ARTIFACTS:
            break
    target_artifacts.sort(key=lambda row: row["artifact"])
    rounds: List[Dict[str, Any]] = []
    seen_rounds = set()
    for item in raw.get("rounds") or []:
        row = _normal_round(item)
        if not row or row["round"] in seen_rounds:
            continue
        seen_rounds.add(row["round"])
        rounds.append(row)
        if len(rounds) >= MAX_ROUNDS:
            break
    rounds.sort(key=lambda row: row["round"])
    calibration = normalize_replay_calibration(raw.get("calibration"))
    if not calibration:
        return {}
    # A pack is bound to its target digest; do not preserve a copied target
    # label/path from an untrusted external calibration payload.
    calibration["target"] = ""
    consistency = _text(
        (raw.get("provenance") or {}).get("calibration_consistency"), 32).lower()
    if consistency not in {"match", "missing", "not-verifiable", "mismatch"}:
        consistency = "not-verifiable"
    provenance = _provenance_for(rounds, target_artifacts, consistency)
    supplied_provenance = raw.get("provenance")
    if not isinstance(supplied_provenance, Mapping):
        return {}
    # Derived provenance fields are part of the signed body too.  Recompute
    # them, but reject a caller that changes one while retaining the old pack
    # digest; otherwise a forged ``valid_for_cohort`` bit could be normalized
    # back into an apparently trusted pack.
    for key in (
            "status", "source_kind", "verification", "valid_for_cohort",
            "round_count", "complete_rounds", "partial_rounds",
            "environment_gap_rounds", "not_executed_rounds", "invalid_rounds",
            "artifact_count", "round_artifact_count", "missing_artifact_count",
            "invalid_artifact_count", "calibration_consistency"):
        if key in supplied_provenance and supplied_provenance.get(key) != provenance.get(key):
            return {}
    pack = {
        "schema_version": PACK_SCHEMA_VERSION,
        "target_digest": target_digest,
        "provenance": provenance,
        "target_artifacts": target_artifacts,
        "rounds": rounds,
        "calibration": calibration,
        "claim_status": PACK_CLAIM_STATUS,
    }
    expected_digest = _digest(_pack_body(pack), "rpk")
    supplied_digest = _text(raw.get("pack_digest"), 40).lower()
    if supplied_digest != expected_digest:
        return {}
    pack["pack_digest"] = expected_digest
    pack["pack_id"] = "pack-" + expected_digest.split("-", 1)[1]
    return pack


def _history_for_rounds(workspace: Path, target: str,
                        selected_rounds: Optional[Sequence[int]]) -> List[Dict[str, Any]]:
    history = load_replay_history(workspace, target)
    if not selected_rounds:
        return history[:MAX_ROUNDS]
    wanted = {_int(value, 0, 1, 1000000) for value in selected_rounds}
    return [row for row in history if _round_no(row.get("round")) in wanted][:MAX_ROUNDS]


def _round_no(value: Any) -> int:
    return _int(value, 0, 0, 1000000)


def build_replay_pack(workspace: Path, target: str,
                      selected_rounds: Optional[Sequence[int]] = None) -> Dict[str, Any]:
    """Build a pack from allowlisted local artifacts only."""
    root = Path(workspace).resolve()
    target_dir = _safe_target_dir(root, target)
    if target_dir is None:
        return {}
    selected = {_int(value, 0, 1, 1000000) for value in selected_rounds or []}
    round_dirs: List[Tuple[int, Path]] = []
    if target_dir.is_dir():
        for directory in target_dir.glob("round-*"):
            match = _ROUND_RE.fullmatch(directory.name)
            if not match:
                continue
            round_no = _int(match.group(1), 0, 1, 1000000)
            if selected and round_no not in selected:
                continue
            round_dirs.append((round_no, directory))
    round_dirs = sorted(round_dirs, key=lambda item: item[0])[:MAX_ROUNDS]
    rounds: List[Dict[str, Any]] = []
    for round_no, directory in round_dirs:
        artifacts: List[Dict[str, Any]] = []
        raw_by_artifact: Dict[str, Dict[str, Any]] = {}
        for stage, name, schema in _ROUND_SPECS:
            artifact_name = "%s/%s" % (stage, name)
            artifact_path = directory / stage / name
            if _optional_artifact(artifact_name) and not artifact_path.is_file():
                continue
            metadata, raw = _artifact_metadata(
                round_no, artifact_name, stage, name, schema, artifact_path)
            artifacts.append(metadata)
            if raw is not None:
                raw_by_artifact[metadata["artifact"]] = raw
        artifacts.sort(key=lambda row: row["artifact"])
        runtime = raw_by_artifact.get("S4/runtime-lab.json") or {}
        lane_summary = _lane_summary(runtime)
        comparison_summary = _comparison_summary(runtime)
        round_status = _round_provenance(artifacts, runtime)
        rounds.append({
            "round": round_no,
            "provenance_status": round_status,
            "runtime_status": _runtime_status(runtime.get("status")),
            "artifact_count": sum(row["status"] == "present" for row in artifacts),
            "missing_artifact_count": sum(row["status"] == "absent" for row in artifacts),
            "invalid_artifact_count": sum(row["status"] not in {"present", "absent"}
                                          for row in artifacts),
            "artifacts": artifacts,
            "lane_summary": lane_summary,
            "comparison_summary": comparison_summary,
            "claim_status": PACK_CLAIM_STATUS,
        })

    target_artifacts: List[Dict[str, Any]] = []
    target_raw: Dict[str, Dict[str, Any]] = {}
    for name, schema in _TARGET_SPECS:
        artifact_path = target_dir / name
        if _optional_artifact(name) and not artifact_path.is_file():
            continue
        metadata, raw = _target_artifact_metadata(
            name, schema, artifact_path)
        target_artifacts.append(metadata)
        if raw is not None:
            target_raw[name] = raw
    target_artifacts.sort(key=lambda row: row["artifact"])

    history = _history_for_rounds(root, target, sorted(selected) if selected else None)
    calibration = normalize_replay_calibration(
        calibrate_replay_history(history, target=""))
    target_calibration = normalize_replay_calibration(
        target_raw.get("coverage/research-replay-calibration.json"))
    if target_calibration and calibration:
        consistency = ("match" if target_calibration.get("history_digest") ==
                       calibration.get("history_digest") else "mismatch")
    elif target_calibration:
        consistency = "not-verifiable"
    else:
        consistency = "missing"
    # If a filtered pack intentionally selects a subset of rounds, the
    # target-level calibration describes a larger history and cannot be called
    # a match.  This is a provenance limitation, not a finding.
    if selected:
        consistency = "not-verifiable"

    provisional = {
        "schema_version": PACK_SCHEMA_VERSION,
        "target_digest": _digest(_text(target, 120), "target"),
        "provenance": _provenance_for(rounds, target_artifacts, consistency),
        "target_artifacts": target_artifacts,
        "rounds": rounds,
        "calibration": calibration,
        "claim_status": PACK_CLAIM_STATUS,
    }
    normalized = normalize_replay_pack({
        **provisional,
        "pack_digest": _digest(_pack_body(provisional), "rpk"),
    })
    return normalized


def verify_replay_pack(workspace: Path, target: str,
                       pack: Mapping[str, Any]) -> Dict[str, Any]:
    """Re-hash the pack's allowlisted files without reading them into output."""
    normalized = normalize_replay_pack(pack)
    if not normalized:
        return {"valid": False, "status": "invalid", "claim_status": PACK_CLAIM_STATUS}
    if normalized.get("target_digest") != _digest(_text(target, 120), "target"):
        return {
            "valid": False,
            "status": "target-mismatch",
            "pack_digest": normalized.get("pack_digest", ""),
            "claim_status": PACK_CLAIM_STATUS,
        }
    target_dir = _safe_target_dir(Path(workspace), target)
    if target_dir is None:
        return {"valid": False, "status": "invalid", "claim_status": PACK_CLAIM_STATUS}
    mismatches: List[str] = []
    checked = 0
    for row in normalized.get("target_artifacts") or []:
        if row.get("status") != "present":
            continue
        path = target_dir / str(row.get("artifact"))
        _raw, status, size, digest = _read_json(path)
        checked += 1
        if status != "present" or digest != row.get("sha256") or size != row.get("size"):
            mismatches.append(str(row.get("artifact")))
    for round_row in normalized.get("rounds") or []:
        round_dir = target_dir / ("round-%02d" % _int(round_row.get("round"), 0, 1, 1000000))
        for row in round_row.get("artifacts") or []:
            if row.get("status") != "present":
                continue
            path = round_dir / str(row.get("artifact"))
            _raw, status, size, digest = _read_json(path)
            checked += 1
            if status != "present" or digest != row.get("sha256") or size != row.get("size"):
                mismatches.append("round-%02d/%s" % (
                    _int(round_row.get("round"), 0, 1, 1000000),
                    row.get("artifact")))
    return {
        "valid": not mismatches,
        "status": "verified" if not mismatches else "mismatch",
        "checked_artifacts": checked,
        "mismatches": mismatches[:16],
        "pack_digest": normalized.get("pack_digest", ""),
        "claim_status": PACK_CLAIM_STATUS,
    }


def pack_path(workspace: Path, target: str) -> Path:
    return (Path(workspace).resolve() / "state" / str(target) /
            "coverage" / PACK_FILENAME)


def write_replay_pack(workspace: Path, target: str,
                      pack: Mapping[str, Any]) -> Path:
    path = pack_path(workspace, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = normalize_replay_pack(pack)
    if not payload:
        payload = build_replay_pack(workspace, target)
    temporary = path.with_name(".%s.tmp.%d" % (path.name, os.getpid()))
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                         encoding="utf-8")
    temporary.replace(path)
    return path


def load_replay_pack_file(path: Path) -> Dict[str, Any]:
    try:
        if not Path(path).is_file() or Path(path).stat().st_size > MAX_JSON_BYTES:
            return {}
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError,
            json.JSONDecodeError):
        return {}
    if isinstance(raw, Mapping) and isinstance(raw.get("pack"), Mapping):
        raw = raw["pack"]
    return normalize_replay_pack(raw)


def load_replay_pack(workspace: Path, target: str) -> Dict[str, Any]:
    return load_replay_pack_file(pack_path(workspace, target))
