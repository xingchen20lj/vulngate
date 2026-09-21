"""Deterministic bookkeeping for bounded runtime research experiments.

The runtime lab deliberately separates three things that are often conflated by
an autonomous security agent:

* a fixed input fixture that can be replayed;
* whether repeated executions are reproducible; and
* whether configured versions/configurations behave differently.

This module does not promote any of those observations to a vulnerability
finding.  It only normalizes bounded metadata and classifies the evidence that
the existing isolated matrix runner produced.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Optional

from .redaction import redact_text


LAB_SCHEMA_VERSION = "runtime-lab-v1"
MAX_FIXTURES = 256
MAX_HEX_LENGTH = 512 * 1024
MAX_LABEL_LENGTH = 160
MAX_SIGNATURE_LENGTH = 240
MAX_CELLS = 64

_HEX = re.compile(r"^[0-9a-fA-F]*$")


def _text(value: Any, limit: int = MAX_LABEL_LENGTH) -> str:
    return redact_text(value).replace("\x00", "").strip()[:limit]


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def context_digest(value: Any) -> str:
    """Hash a generator/configuration context without persisting its contents."""
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _hex(value: Any) -> str:
    text = str(value or "").strip().replace(" ", "").replace("\n", "")
    if len(text) > MAX_HEX_LENGTH or len(text) % 2 or not _HEX.fullmatch(text):
        return ""
    return text.lower()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def fixture_id(entry: Any, payload_hex: Any, group: Any = "") -> str:
    """Return a stable id for an entry/payload pair, independent of ordering."""
    core = {
        "entry": _text(entry),
        "group": _text(group, 80),
        "payload_hex": _hex(payload_hex),
    }
    digest = hashlib.sha256(_canonical(core).encode("utf-8")).hexdigest()
    return "fx-" + digest[:16]


def _fixture_core(value: Dict[str, Any]) -> Dict[str, Any]:
    payload = _hex(value.get("payload_hex", value.get("hex")))
    if not payload:
        return {}
    entry = _text(value.get("entry", ""))
    group = _text(value.get("group", ""), 80)
    supplied_id = fixture_id(entry, payload, group)
    core: Dict[str, Any] = {
        "schema_version": LAB_SCHEMA_VERSION,
        "fixture_id": supplied_id,
        "entry": entry,
        "group": group,
        "payload_hex": payload,
        "payload_bytes": len(payload) // 2,
        "claim_status": "not-a-finding",
    }
    for key in ("seed", "input_id", "primary_version", "safe_mode",
                "expected_bucket", "expected_signature", "source",
                "original_fixture_id"):
        if key not in value or value.get(key) in (None, ""):
            continue
        if key == "seed" or key == "input_id":
            core[key] = _safe_int(value.get(key))
        elif key == "safe_mode":
            core[key] = bool(value.get(key))
        elif key == "expected_signature":
            core[key] = _text(value.get(key), MAX_SIGNATURE_LENGTH)
        elif key == "primary_version":
            core[key] = _text(value.get(key), 80)
        else:
            core[key] = _text(value.get(key), MAX_LABEL_LENGTH)
    return core


def normalize_fixture(value: Any) -> Dict[str, Any]:
    """Normalize one replay fixture and attach a content digest.

    Invalid or over-sized payloads become an empty record so callers can treat
    them as an unavailable fixture instead of accidentally executing malformed
    metadata.
    """
    if not isinstance(value, dict):
        return {}
    core = _fixture_core(value)
    if not core:
        return {}
    digest_core = {key: core[key] for key in
                   ("entry", "group", "payload_hex")}
    digest = hashlib.sha256(_canonical(digest_core).encode("utf-8")).hexdigest()
    core["digest"] = digest
    return core


def fixture_from_input(value: Any, seed: int = 0,
                       primary_version: str = "",
                       safe_mode: bool = False) -> Dict[str, Any]:
    """Convert a generated fuzz input/dataclass into a fixed fixture record."""
    if isinstance(value, dict):
        group = value.get("group", "")
        entry = value.get("entry", "")
        payload = value.get("payload_hex", value.get("hex", ""))
        input_id = value.get("id", 0)
    else:
        group = getattr(value, "group", "")
        entry = getattr(value, "entry", "")
        payload = getattr(value, "hex", "")
        input_id = getattr(value, "id", 0)
    return normalize_fixture({
        "group": group,
        "entry": entry,
        "payload_hex": payload,
        "seed": seed,
        "input_id": input_id,
        "primary_version": primary_version,
        "safe_mode": safe_mode,
        "source": "deterministic-fuzz-corpus",
    })


def build_fixture_manifest(inputs: Iterable[Any], seed: int,
                           generator: str = "directed-fuzz-2.1",
                           primary_version: str = "",
                           limit: int = MAX_FIXTURES,
                           budget: Optional[int] = None,
                           template_digest: str = "") -> Dict[str, Any]:
    """Build a bounded, deterministic corpus artifact from generated inputs."""
    try:
        max_items = max(1, min(int(limit), MAX_FIXTURES))
    except (TypeError, ValueError):
        max_items = MAX_FIXTURES
    fixtures: List[Dict[str, Any]] = []
    seen = set()
    input_count = 0
    truncated = False
    for item in inputs:
        input_count += 1
        fixture = fixture_from_input(item, seed, primary_version)
        if not fixture or fixture["fixture_id"] in seen:
            continue
        if len(fixtures) >= max_items:
            truncated = True
            continue
        seen.add(fixture["fixture_id"])
        fixtures.append(fixture)
    core = {
        "schema_version": LAB_SCHEMA_VERSION,
        "generator": _text(generator, 80),
        "seed": _safe_int(seed),
        "budget": _safe_int(budget, input_count) if budget is not None else input_count,
        "primary_version": _text(primary_version, 80),
        "input_count": input_count,
        "fixture_count": len(fixtures),
        "truncated": truncated,
        "template_digest": _text(template_digest, 64),
        "fixtures": fixtures,
        "claim_status": "not-a-finding",
    }
    core["corpus_digest"] = hashlib.sha256(
        _canonical(core).encode("utf-8")).hexdigest()
    return core


def _outcome(record: Dict[str, Any]) -> str:
    explicit = _text(record.get("bucket", ""), 60).lower()
    if explicit:
        return explicit
    if record.get("precondition_status") == "precondition-unavailable":
        return "precondition-unavailable"
    if record.get("compile_error") or record.get("harness_error"):
        return "harness-error"
    if record.get("timed_out"):
        return "hang"
    obs = record.get("observations") or {}
    if not isinstance(obs, dict):
        obs = {}
    if str(obs.get("GATE_BLOCKED", "")).strip():
        return "gate-blocked"
    if str(obs.get("ERROR", "")).strip():
        return "error"
    if str(obs.get("PARSED", "")).strip():
        return "ok"
    return "empty"


def _signature(record: Dict[str, Any]) -> str:
    return _text(record.get("signature", record.get("observed_signature", "")),
                 MAX_SIGNATURE_LENGTH)


def _cell_key(record: Dict[str, Any]) -> str:
    return "%s|safe=%s" % (
        _text(record.get("version", ""), 80),
        "true" if bool(record.get("safe_mode", False)) else "false")


def summarize_replay(records: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Classify repeated executions of one fixed fixture."""
    rows = [r for r in records if isinstance(r, dict)]
    if not rows:
        return {
            "status": "unexecuted", "attempts": 0,
            "distinct_outcomes": [], "claim_status": "not-a-finding",
        }
    outcomes: Dict[str, int] = {}
    signatures: Dict[str, int] = {}
    keys = []
    for row in rows:
        bucket = _outcome(row)
        sig = _signature(row)
        key = "%s|%s" % (bucket, sig)
        keys.append(key)
        outcomes[bucket] = outcomes.get(bucket, 0) + 1
        signatures[sig or "<none>"] = signatures.get(sig or "<none>", 0) + 1
    failure_buckets = {"harness-error", "precondition-unavailable", "run-failed",
                       "gate-blocked"}
    observed = [key for key in keys if key.split("|", 1)[0] not in failure_buckets]
    if not observed:
        if set(outcomes) == {"precondition-unavailable"}:
            status = "precondition-unavailable"
        elif set(outcomes) == {"gate-blocked"}:
            status = "gate-blocked"
        else:
            status = "run-failed"
    elif len(set(keys)) == 1 and len(observed) == len(keys):
        status = "stable"
    else:
        status = "unstable"
    distinct = [
        {"outcome": bucket, "signature": sig, "count": count}
        for (bucket, sig), count in sorted(
            ((tuple(key.split("|", 1)), keys.count(key)) for key in set(keys)),
            key=lambda item: (item[0][0], item[0][1]))
    ]
    representative = rows[0]
    return {
        "status": status,
        "attempts": len(rows),
        "distinct_outcomes": distinct[:16],
        "outcome_counts": dict(sorted(outcomes.items())),
        "signature_counts": dict(sorted(signatures.items())),
        "representative": {
            "version": _text(representative.get("version", ""), 80),
            "safe_mode": bool(representative.get("safe_mode", False)),
            "outcome": _outcome(representative),
            "signature": _signature(representative),
        },
        "claim_status": "not-a-finding",
    }


def summarize_version_differential(records: Iterable[Dict[str, Any]],
                                   primary_version: str = "") -> Dict[str, Any]:
    """Compare observed outcomes across version/safe-mode cells.

    Bucket changes are reported as differences.  Signature-only changes are
    retained separately because stack-frame drift across versions is not by
    itself a vulnerability or a behavioral proof.
    """
    rows = [r for r in records if isinstance(r, dict)]
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(_cell_key(row), []).append(row)
    cells: List[Dict[str, Any]] = []
    for key in sorted(grouped):
        sample = grouped[key][0]
        replay = summarize_replay(grouped[key])
        cells.append({
            "version": _text(sample.get("version", ""), 80),
            "safe_mode": bool(sample.get("safe_mode", False)),
            "cell_key": key,
            "status": replay["status"],
            "outcome": replay.get("representative", {}).get("outcome", ""),
            "signature": replay.get("representative", {}).get("signature", ""),
            "attempts": replay.get("attempts", 0),
        })
    baseline_version = _text(primary_version, 80)
    if not cells:
        return {
            "status": "unexecuted", "primary_version": baseline_version,
            "cells": [], "differences": [], "signature_variations": [],
            "inconclusive_cells": ["no-cells"],
            "claim_status": "not-a-finding",
        }
    versions_seen = sorted({str(cell.get("version", "")) for cell in cells})
    if not baseline_version:
        baseline_version = versions_seen[-1]
    if baseline_version not in versions_seen:
        return {
            "status": "inconclusive", "primary_version": baseline_version,
            "cells": cells[:MAX_CELLS], "differences": [],
            "signature_variations": [],
            "inconclusive_cells": ["baseline:%s" % baseline_version],
            "claim_status": "not-a-finding",
        }
    differences: List[Dict[str, Any]] = []
    signature_variations: List[Dict[str, Any]] = []
    inconclusive: List[str] = []
    for safe in (False, True):
        baseline = next((c for c in cells
                         if c["version"] == baseline_version
                         and c["safe_mode"] == safe), None)
        if baseline is None:
            inconclusive.append("%s|safe=%s" % (
                baseline_version, "true" if safe else "false"))
            continue
        if baseline["status"] != "stable":
            inconclusive.append(baseline["cell_key"])
            continue
        for cell in cells:
            if cell["safe_mode"] != safe or cell is baseline:
                continue
            if cell["status"] != "stable":
                inconclusive.append(cell["cell_key"])
                continue
            bucket_changed = cell["outcome"] != baseline["outcome"]
            signature_changed = (
                bool(cell["signature"] and baseline["signature"])
                and cell["signature"] != baseline["signature"])
            if bucket_changed:
                differences.append({
                    "version": cell["version"],
                    "safe_mode": safe,
                    "baseline_outcome": baseline["outcome"],
                    "observed_outcome": cell["outcome"],
                    "baseline_signature": baseline["signature"],
                    "observed_signature": cell["signature"],
                })
            elif signature_changed:
                signature_variations.append({
                    "version": cell["version"], "safe_mode": safe,
                    "baseline_signature": baseline["signature"],
                    "observed_signature": cell["signature"],
                })
    if differences:
        status = "difference-with-inconclusive" if inconclusive else "difference-observed"
    elif signature_variations:
        status = ("signature-variation-with-inconclusive"
                  if inconclusive else "signature-variation")
    elif inconclusive:
        status = "inconclusive"
    else:
        status = "no-difference"
    return {
        "status": status,
        "primary_version": baseline_version,
        "cells": cells[:MAX_CELLS],
        "differences": differences[:MAX_CELLS],
        "signature_variations": signature_variations[:MAX_CELLS],
        "inconclusive_cells": sorted(set(inconclusive))[:MAX_CELLS],
        "claim_status": "not-a-finding",
    }
