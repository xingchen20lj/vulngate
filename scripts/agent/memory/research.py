"""Cross-round research memory for the VulnGate audit loop.

The ledger answers "what did this round conclude?"  The research memory
answers a different question: "what did we already try on this mechanism, and
what is the cheapest evidence-producing next move?"  It is deliberately
research-only.  Runtime observations are classified, never promoted to a
finding, and environment failures are kept distinct from negative evidence.

The module has three safety properties that are important for an autonomous
security worker:

* a mechanism key is stable across candidate ids and round numbers;
* only bounded, redacted metadata is persisted (raw args, payloads and process
  output are represented by counts/digests or omitted); and
* merge is append-like and idempotent, so resuming S8 cannot erase an earlier
  gap or manufacture a second copy of the same event.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..tools.redaction import redact_text


MEMORY_SCHEMA_VERSION = "research-memory-v1"
MEMORY_FILENAME = "research-memory.json"
MEMORY_CLAIM_STATUS = "not-a-finding"
REVIEW_SCHEMA_VERSION = "research-review-v1"
REVIEW_FILENAME = "review-feedback.json"

MAX_MEMORY_ENTRIES = 2048
MAX_EVENTS_PER_ENTRY = 24
MAX_HINTS = 4
MAX_LOCATIONS = 12
MAX_TARGET_CLASSES = 12
MAX_TEXT = 180
MAX_SURFACE = 220
MAX_DIGEST_INPUT = 12000
MAX_REVIEW_ENTRIES = 512
MAX_REVIEW_REFS = 8
MAX_REVIEW_NOTE = 240
MAX_CONTEXT_VERSIONS = 16
MAX_CONTEXT_AUTHZ = 16
MAX_RESIDUALS_PER_ENTRY = 8
MAX_RESIDUAL_KIND = 48

STATE_STABLE_REPRODUCER = "stable-reproducer"
STATE_ACTIONABLE_DIFFERENCE = "actionable-difference"
STATE_ENVIRONMENT_GAP = "environment-gap"
STATE_UNSTABLE_REPLAY = "unstable-replay"
STATE_STABLE_OBSERVATION = "stable-observation"
STATE_INCONCLUSIVE = "inconclusive"
STATE_DECISION_RECORDED = "decision-recorded"
STATE_REVIEW_ACCEPTED = "review-accepted"
STATE_REVIEW_REJECTED = "review-rejected"
STATE_REVIEW_NEEDS_EVIDENCE = "review-needs-evidence"
STATE_REVIEW_SCOPE_CORRECTED = "review-scope-corrected"
STATE_PENDING_RESIDUAL = "pending-residual"
STATE_RESIDUAL_FALSIFIED = "residual-falsified"

REVIEW_STATUS_ACCEPTED = "accepted"
REVIEW_STATUS_REJECTED = "rejected"
REVIEW_STATUS_NEEDS_EVIDENCE = "needs-evidence"
REVIEW_STATUS_SCOPE_CORRECTED = "scope-corrected"

REVIEW_STATUSES = frozenset({
    REVIEW_STATUS_ACCEPTED, REVIEW_STATUS_REJECTED,
    REVIEW_STATUS_NEEDS_EVIDENCE, REVIEW_STATUS_SCOPE_CORRECTED,
})
REVIEW_REASON_CODES = frozenset({
    "false-positive", "confirmed-mechanism", "missing-typed-effect",
    "environment-gap", "scope-correction", "duplicate",
    "needs-source-review",
})

_REVIEW_STATE_BY_STATUS = {
    REVIEW_STATUS_ACCEPTED: STATE_REVIEW_ACCEPTED,
    REVIEW_STATUS_REJECTED: STATE_REVIEW_REJECTED,
    REVIEW_STATUS_NEEDS_EVIDENCE: STATE_REVIEW_NEEDS_EVIDENCE,
    REVIEW_STATUS_SCOPE_CORRECTED: STATE_REVIEW_SCOPE_CORRECTED,
}

_GAP_STATUSES = frozenset({
    "unexecuted", "run-failed", "precondition-unavailable", "gate-blocked",
    "harness-error", "inconclusive", "disabled",
})
_DIFFERENCE_PREFIXES = ("difference-observed", "difference-with-inconclusive")

# S3 residuals are deliberately reduced to a small vocabulary.  A residual's
# free-form reason or probe plan may contain payloads, commands, or source
# prose, so durable memory keeps only a category, a digest, and a boolean that
# says whether an executable plan was supplied.
_RESIDUAL_KINDS = frozenset({
    "fix-completeness", "variant", "control-gap", "authz", "validation",
    "typed-effect", "capability-chain", "environment-gap", "source-sink",
    "differential", "state", "race", "availability", "parser", "default",
})
_RESIDUAL_REASONS = frozenset({
    "unverified", "missing-effect", "missing-transition", "fix-gap",
    "control-gap", "environment-gap", "inconclusive", "requires-runtime",
    "needs-source-review", "pending", "unclassified",
})

# A residual is closed only by an explicit, bounded falsifier emitted by an
# executed S4 cell.  These are research-state labels, not vulnerability
# verdicts.  In particular, an environment gap has no falsifier here: it must
# remain pending until the environment is repaired and the probe is rerun.
_RESIDUAL_FALSIFIERS_BY_KIND = {
    "fix-completeness": ("variant-rejected", "no-new-effect", "source-disproved",
                         "safe-equivalent"),
    "variant": ("variant-rejected", "no-new-effect", "source-disproved",
                 "safe-equivalent"),
    "control-gap": ("control-binds", "authz-denied", "no-new-effect",
                     "source-disproved"),
    "authz": ("authz-denied", "ownership-bound"),
    "validation": ("validation-enforced", "no-new-effect", "safe-equivalent"),
    "typed-effect": ("typed-effect-absent", "no-new-effect", "safe-equivalent"),
    "capability-chain": ("transition-blocked", "capability-missing",
                         "typed-effect-absent", "safe-equivalent"),
    "environment-gap": (),
    "source-sink": ("path-unreachable", "control-binds", "source-disproved"),
    "differential": ("no-difference", "safe-equivalent", "no-new-effect"),
    "state": ("state-reset", "no-new-effect", "safe-equivalent"),
    "race": ("no-race", "state-reset", "no-new-effect", "safe-equivalent"),
    "availability": ("availability-preserved", "no-amplification",
                      "no-new-effect", "safe-equivalent"),
    "parser": ("default-blocked", "validation-enforced", "no-new-effect",
                "safe-equivalent"),
    "default": ("default-blocked", "validation-enforced", "no-new-effect",
                 "safe-equivalent"),
    "unclassified": ("no-new-effect", "source-disproved", "safe-equivalent"),
}
_RESIDUAL_FALSIFIERS = frozenset(
    code for values in _RESIDUAL_FALSIFIERS_BY_KIND.values() for code in values)
_RESIDUAL_STATES = frozenset({STATE_PENDING_RESIDUAL, STATE_RESIDUAL_FALSIFIED})


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    """Return bounded text safe for a durable research artifact."""
    try:
        value = redact_text(value)
    except Exception:  # pragma: no cover - redaction is defensive by design
        value = str(value)
    return " ".join(str(value).replace("\x00", "").split())[:limit]


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")[:MAX_DIGEST_INPUT]
                          ).hexdigest()


def _bounded_strings(values: Any, limit: int, item_limit: int = MAX_TEXT) -> List[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes)):
        values = [values]
    else:
        try:
            iter(values)
        except TypeError:
            return []
    out: List[str] = []
    seen = set()
    for value in values:
        item = _text(value, item_limit)
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
        if len(out) >= limit:
            break
    return sorted(out)


def _location(value: Any) -> str:
    if isinstance(value, dict):
        file_name = _text(value.get("file", value.get("path", "")), 160)
        line = _text(value.get("line", ""), 20)
        return "%s:%s" % (file_name, line) if file_name and line else file_name
    return _text(value, 180)


def _locations(candidate: Dict[str, Any]) -> List[str]:
    raw = candidate.get("code_location") or candidate.get("code_locations") or []
    if not isinstance(raw, (list, tuple)):
        raw = [raw]
    return _bounded_strings((_location(item) for item in raw), MAX_LOCATIONS, 180)


def _path_digest(path: Any) -> str:
    """Digest source-to-sink structure without copying arbitrary path text."""
    if not isinstance(path, (list, tuple)):
        path = [path]
    compact: List[Any] = []
    for item in path[:16]:
        if isinstance(item, dict):
            compact.append({
                key: _text(item.get(key), 100)
                for key in ("source", "entry", "transform", "validation",
                            "authorization", "sink", "flow_id", "sink_id")
                if item.get(key) not in (None, "", [])
            })
        else:
            compact.append(_text(item, 120))
    return _digest(compact)[:24] if compact else ""


def research_key(candidate: Dict[str, Any]) -> str:
    """Return a round-independent key for the candidate's research target.

    Candidate ids are intentionally excluded when structural evidence exists:
    an LLM is allowed to rename a hypothesis without making the mechanism
    novel.  A sparse candidate falls back to its id so it still has a traceable
    memory record rather than silently disappearing from the ledger.
    """
    candidate = candidate if isinstance(candidate, dict) else {}
    target_classes = _bounded_strings(candidate.get("target_classes"),
                                      MAX_TARGET_CLASSES, 160)
    fuzz = candidate.get("fuzz_spec") or {}
    fuzz_core = {}
    if isinstance(fuzz, dict):
        # Keep the entry/bucket visible, but never persist the minimized input.
        fuzz_core = {
            "entry": _text(fuzz.get("entry"), 160),
            "bucket": _text(fuzz.get("bucket"), 80),
            "payload_digest": _digest(_text(
                fuzz.get("hex", fuzz.get("payload_hex", "")), 4096))
            if fuzz.get("hex", fuzz.get("payload_hex", "")) else "",
        }
    core = {
        "surface": _text(candidate.get("surface"), MAX_SURFACE),
        "entry": _text(candidate.get("entry"), 180),
        "input_shape": _text(candidate.get("input_shape"), 140),
        "logic": _text(candidate.get("logic"), MAX_TEXT),
        "rule_label": _text(candidate.get("rule_label"), 120),
        "vuln_class": _text(candidate.get("vuln_class"), 120),
        "entry_feature": _text(candidate.get("entry_feature"), 120),
        "target_classes": target_classes,
        "locations": _locations(candidate),
        "source_sink_digest": _path_digest(candidate.get("source_to_sink")),
        "capability_digest": _digest(candidate.get("capability_contract"))
        if candidate.get("capability_contract") else "",
        "fix_variants": _bounded_strings(
            candidate.get("patch_variants") or candidate.get("fix_variants"),
            8, 160),
        "fuzz": fuzz_core,
    }
    structural = any(value for key, value in core.items()
                     if key not in {"surface", "fuzz"} and value)
    if not structural:
        core["candidate_id_fallback"] = _text(candidate.get("candidate_id"), 120)
    return "rk-" + _digest(core)[:20]


def _candidate_meta(candidate: Dict[str, Any], key: str) -> Dict[str, Any]:
    research_surface = _text(candidate.get("research_surface"), 32).lower()
    if research_surface not in {"web", "protocol", "cloud", "mobile", "native"}:
        exact_surface = _text(candidate.get("surface"), 32).lower()
        research_surface = (exact_surface if exact_surface in {
            "web", "protocol", "cloud", "mobile", "native"
        } else "")
    target_type = _text(candidate.get("target_type"), 60).lower()
    attack_class = _text(
        candidate.get("attack_class") or candidate.get("vuln_class")
        or candidate.get("category"), 80).lower()
    variant = _text(candidate.get("variant"), 100)
    precondition_class = _text(
        candidate.get("precondition_class")
        or candidate.get("precondition_tier")
        or candidate.get("precondition_tier_hint"), 60).lower()
    fix_variants = _bounded_strings(
        candidate.get("patch_variants") or candidate.get("fix_variants"),
        8, 160)
    residuals = _residual_meta(candidate, key)
    return {
        "candidate_id": _text(candidate.get("candidate_id"), 120),
        "surface": _text(candidate.get("surface"), MAX_SURFACE),
        "research_surface": research_surface,
        "target_type": target_type,
        "attack_class": attack_class,
        "variant": variant,
        "precondition_class": precondition_class,
        "variants": _bounded_strings([variant] + fix_variants, 12, 100),
        "attack_classes": _bounded_strings([attack_class], 8, 80),
        "precondition_classes": _bounded_strings([precondition_class], 8, 60),
        "entry": _text(candidate.get("entry"), 180),
        "input_shape": _text(candidate.get("input_shape"), 140),
        "code_locations": _locations(candidate),
        "target_classes": _bounded_strings(candidate.get("target_classes"),
                                             MAX_TARGET_CLASSES, 160),
        "fix_variants": fix_variants,
        "patch_commit": _text(candidate.get("patch_commit"), 80),
        "research_key": key,
        "residuals": residuals,
        "pending_residual_count": len(residuals),
    }


def _safe_residual_code(value: Any, allowed: Iterable[str]) -> str:
    """Map arbitrary S3 text to one of a small, non-sensitive code set."""
    text = _text(value, MAX_RESIDUAL_KIND).lower()
    text = re.sub(r"[^a-z0-9_-]+", "-", text).strip("-")
    return text if text in allowed else "unclassified"


def residual_falsifiers(kind: Any) -> List[str]:
    """Return the bounded falsifier vocabulary for one residual kind."""
    normalized = _safe_residual_code(kind, _RESIDUAL_KINDS)
    return list(_RESIDUAL_FALSIFIERS_BY_KIND.get(normalized, ()))


def _residual_locations(residual: Dict[str, Any],
                        candidate: Dict[str, Any]) -> List[str]:
    raw = (residual.get("code_location") or residual.get("code_locations")
           or residual.get("location") or [])
    if not isinstance(raw, (list, tuple)):
        raw = [raw]
    locations = [_location(item) for item in raw]
    # A residual without its own location is still tied to the candidate's
    # bounded source locations; this preserves traceability without copying
    # the residual's free-form explanation.
    if not locations:
        fallback = (candidate.get("code_location") or
                    candidate.get("code_locations") or [])
        if not isinstance(fallback, (list, tuple)):
            fallback = [fallback]
        locations = [_location(item) for item in fallback]
    return _bounded_strings(locations, MAX_LOCATIONS, 180)


def _residual_meta(candidate: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    raw_rows = candidate.get("residuals")
    if not isinstance(raw_rows, (list, tuple)):
        return []
    rows: List[Dict[str, Any]] = []
    seen = set()
    for residual in raw_rows:
        if not isinstance(residual, dict):
            continue
        kind = _safe_residual_code(
            residual.get("kind") or residual.get("category")
            or residual.get("type"), _RESIDUAL_KINDS)
        reason = _safe_residual_code(
            residual.get("reason_code") or residual.get("status")
            or residual.get("reason"), _RESIDUAL_REASONS)
        locations = _residual_locations(residual, candidate)
        probe = (residual.get("probe_plan") or residual.get("next_probe")
                 or residual.get("probe") or "")
        probe_digest = _digest(_text(probe, 4000))[:24] if probe else ""
        residual_id = "rr-" + _digest({
            "research_key": key,
            "kind": kind,
            "reason_code": reason,
            "locations": locations,
            "probe_digest": probe_digest,
        })[:20]
        if residual_id in seen:
            continue
        seen.add(residual_id)
        rows.append({
            "residual_id": residual_id,
            "kind": kind,
            "reason_code": reason,
            "code_locations": locations,
            "has_probe_plan": bool(probe),
            "probe_digest": probe_digest,
            "allowed_falsifiers": residual_falsifiers(kind),
            "state": STATE_PENDING_RESIDUAL,
            "claim_status": MEMORY_CLAIM_STATUS,
        })
        if len(rows) >= MAX_RESIDUALS_PER_ENTRY:
            break
    rows.sort(key=lambda item: str(item.get("residual_id", "")))
    return rows


def _normalize_residual(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    kind = _safe_residual_code(value.get("kind"), _RESIDUAL_KINDS)
    reason = _safe_residual_code(value.get("reason_code"), _RESIDUAL_REASONS)
    residual_id = _text(value.get("residual_id"), 80)
    if not re.fullmatch(r"rr-[0-9a-f]{20}", residual_id):
        return {}
    raw_locations = value.get("code_locations") or []
    if not isinstance(raw_locations, (list, tuple)):
        raw_locations = [raw_locations]
    locations = _bounded_strings(
        (_location(item) for item in raw_locations), MAX_LOCATIONS, 180)
    probe_digest = _text(value.get("probe_digest"), 40).lower()
    if probe_digest and not re.fullmatch(r"[0-9a-f]{1,40}", probe_digest):
        probe_digest = ""
    allowed_falsifiers = residual_falsifiers(kind)
    state = _text(value.get("state"), 64)
    if state not in _RESIDUAL_STATES:
        state = STATE_PENDING_RESIDUAL
    falsifier_code = _safe_residual_code(
        value.get("falsifier_code") or value.get("outcome_code"),
        _RESIDUAL_FALSIFIERS)
    if falsifier_code not in allowed_falsifiers:
        falsifier_code = ""
        state = STATE_PENDING_RESIDUAL
    evidence_cells = _bounded_strings(value.get("evidence_cells"), 8, 80)
    if state == STATE_RESIDUAL_FALSIFIED and not evidence_cells:
        state = STATE_PENDING_RESIDUAL
    outcome_round = _safe_int(value.get("outcome_round"), 0, 0, 1000000)
    return {
        "residual_id": residual_id,
        "kind": kind,
        "reason_code": reason,
        "code_locations": locations,
        "has_probe_plan": bool(value.get("has_probe_plan")),
        "probe_digest": probe_digest,
        "allowed_falsifiers": allowed_falsifiers,
        "state": state,
        "falsifier_code": falsifier_code,
        "evidence_cells": evidence_cells,
        "outcome_round": outcome_round,
        "claim_status": MEMORY_CLAIM_STATUS,
    }


def _residual_outcomes(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Accept only normalized S4 residual-falsifier observations."""
    if not isinstance(summary, dict):
        return []
    rows = []
    for raw in summary.get("residual_falsifiers") or []:
        if not isinstance(raw, dict):
            continue
        residual_id = _text(raw.get("residual_id"), 80)
        code = _safe_residual_code(raw.get("falsifier_code"), _RESIDUAL_FALSIFIERS)
        status = _text(raw.get("status"), 40).lower()
        execution_state = _text(raw.get("execution_state"), 48).lower()
        cell_ref = _text(raw.get("cell_ref"), 80)
        if not re.fullmatch(r"rr-[0-9a-f]{20}", residual_id):
            continue
        if code == "unclassified" or status != "falsified":
            continue
        rows.append({
            "residual_id": residual_id,
            "falsifier_code": code,
            "status": status,
            "execution_state": execution_state,
            "effect_observed": bool(raw.get("effect_observed")),
            "contract_declared": bool(raw.get("contract_declared")),
            "cell_ref": cell_ref,
        })
    return rows[:32]


def _close_residuals(residuals: Sequence[Dict[str, Any]],
                     summary: Dict[str, Any], round_no: int
                     ) -> List[Dict[str, Any]]:
    """Apply explicit S4 falsifiers without treating absence as evidence."""
    outcomes = _residual_outcomes(summary)
    closed: List[Dict[str, Any]] = []
    for raw in residuals:
        residual = _normalize_residual(raw)
        if not residual:
            continue
        if residual.get("state") == STATE_RESIDUAL_FALSIFIED:
            closed.append(residual)
            continue
        residual_id = residual.get("residual_id")
        accepted = next((row for row in outcomes
                         if row.get("residual_id") == residual_id
                         and row.get("contract_declared")
                         and row.get("execution_state") == "executed"
                         and not row.get("effect_observed")
                         and row.get("falsifier_code") in
                         set(residual.get("allowed_falsifiers") or [])), None)
        if accepted:
            residual["state"] = STATE_RESIDUAL_FALSIFIED
            residual["falsifier_code"] = accepted["falsifier_code"]
            residual["evidence_cells"] = ([accepted.get("cell_ref")]
                                            if accepted.get("cell_ref") else [])
            residual["outcome_round"] = _safe_int(round_no, 0, 0, 1000000)
        closed.append(residual)
    return closed[:MAX_RESIDUALS_PER_ENTRY]


def residual_meta(candidate: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Public, stable residual identities for planner/runner contracts."""
    candidate = candidate if isinstance(candidate, dict) else {}
    return _residual_meta(candidate, research_key(candidate))


def build_residual_closure_report(candidates: Sequence[Dict[str, Any]],
                                  summaries: Optional[Dict[str, Any]],
                                  round_no: int) -> List[Dict[str, Any]]:
    """Build a bounded S4 report of residual outcomes, never a finding list."""
    summaries = summaries if isinstance(summaries, dict) else {}
    rows: List[Dict[str, Any]] = []
    for candidate in candidates or []:
        if not isinstance(candidate, dict):
            continue
        cid = _text(candidate.get("candidate_id"), 120)
        key = research_key(candidate)
        residuals = _close_residuals(
            _residual_meta(candidate, key), summaries.get(cid, {}), round_no)
        for residual in residuals:
            rows.append({
                "candidate_id": cid,
                "research_key": key,
                "residual_id": residual.get("residual_id"),
                "kind": residual.get("kind"),
                "reason_code": residual.get("reason_code"),
                "state": residual.get("state"),
                "falsifier_code": residual.get("falsifier_code", ""),
                "evidence_cells": list(residual.get("evidence_cells") or []),
                "outcome_round": residual.get("outcome_round", 0),
                "claim_status": MEMORY_CLAIM_STATUS,
            })
    return rows[:MAX_MEMORY_ENTRIES]


def _runtime_state(replay: Dict[str, Any], differential: Dict[str, Any],
                   reproduces_expected: Any) -> Tuple[str, List[str]]:
    replay_status = _text(replay.get("status"), 80).lower()
    diff_status = _text(differential.get("status"), 100).lower()
    hints: List[str] = []
    if diff_status.startswith(_DIFFERENCE_PREFIXES):
        hints.append("固定差异的版本/SafeMode，补做最小复现并定位差异路径")
        if "inconclusive" in diff_status or differential.get("inconclusive_cells"):
            hints.append("先补齐不稳定或缺失 cell；差异本身不等于漏洞")
        return STATE_ACTIONABLE_DIFFERENCE, hints
    if replay_status in _GAP_STATUSES or diff_status in _GAP_STATUSES:
        hints.append("修复 harness、运行时或前置条件后重试；不可解释为无效")
        return STATE_ENVIRONMENT_GAP, hints
    if replay_status == "unstable":
        hints.append("增加受控重放或缩小 fixture，先解决结果不稳定")
        return STATE_UNSTABLE_REPLAY, hints
    if replay_status == "stable" and reproduces_expected is True:
        hints.append("重放已稳定；转向 source→sink、授权边界和 typed effect 证据")
        return STATE_STABLE_REPRODUCER, hints
    if replay_status == "stable":
        # A stable observation is not a negative result: the lab cannot infer
        # exploitability from an empty/parsed bucket alone.
        hints.append("观察已稳定但未形成复现闭环；补充语义影响证据，不得视为漏洞不存在")
        return STATE_STABLE_OBSERVATION, hints
    hints.append("补齐可执行 cell 或明确前置条件，再决定下一轮探针")
    return STATE_INCONCLUSIVE, hints


def _safe_int(value: Any, default: int = 0, minimum: Optional[int] = None,
              maximum: Optional[int] = None) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    if minimum is not None:
        number = max(minimum, number)
    if maximum is not None:
        number = min(maximum, number)
    return number


def _runtime_context(runtime_lab: Any, candidate_id: str = "") -> Dict[str, Any]:
    """Return the credential-free S4 context useful for the next probe.

    ``runtime-context-v1`` already owns the detailed snapshot.  Research
    memory keeps a smaller view so a later round can answer *which service,
    configuration and authorization fixture did we actually exercise?*
    without copying URLs, commands, environment values or identities.
    """
    if not isinstance(runtime_lab, dict):
        return {}
    configuration = runtime_lab.get("configuration")
    if not isinstance(configuration, dict):
        configuration = {}

    versions = _bounded_strings(configuration.get("versions"),
                               MAX_CONTEXT_VERSIONS, 80)
    target_urls = configuration.get("target_urls")
    target_url_digests: Dict[str, str] = {}
    if isinstance(target_urls, dict):
        for version, snapshot in sorted(target_urls.items(),
                                        key=lambda item: str(item[0]))[:MAX_CONTEXT_VERSIONS]:
            if not isinstance(snapshot, dict):
                continue
            digest = _text(snapshot.get("url_digest"), 40)
            if digest:
                target_url_digests[_text(version, 80)] = digest

    options = configuration.get("runtime_lab")
    if not isinstance(options, dict):
        options = {}
    safe_modes: List[bool] = []
    for value in options.get("safe_modes") or []:
        if isinstance(value, bool):
            parsed = value
        else:
            parsed = str(value).strip().lower() in {"true", "1", "yes", "on"}
        if parsed not in safe_modes:
            safe_modes.append(parsed)
        if len(safe_modes) >= 4:
            break

    service = configuration.get("service_lifecycle")
    if not isinstance(service, dict):
        service = runtime_lab.get("service_lifecycle")
    if not isinstance(service, dict):
        service = {}
    health = service.get("healthcheck")
    if not isinstance(health, dict):
        health = {}
    service_view: Dict[str, Any] = {}
    for key, limit in (("status", 80), ("config_digest", 40),
                       ("schema_version", 60)):
        value = _text(service.get(key), limit)
        if value:
            service_view[key] = value
    for key in ("configured", "enabled", "ready", "process_managed"):
        if isinstance(service.get(key), bool):
            service_view[key] = service[key]
    if health:
        service_view["healthcheck_kind"] = _text(health.get("kind"), 40)
        service_view["healthcheck_configured"] = bool(health.get("configured"))
        if isinstance(health.get("port"), int):
            service_view["healthcheck_port"] = _safe_int(
                health.get("port"), 0, 1, 65535)

    authz_rows: List[Dict[str, Any]] = []
    raw_authz = configuration.get("authz_fixtures") or []
    if isinstance(raw_authz, list):
        for fixture in raw_authz:
            if not isinstance(fixture, dict):
                continue
            fixture_candidate = _text(fixture.get("candidate_id"), 120)
            if candidate_id and fixture_candidate and fixture_candidate != candidate_id:
                continue
            fixture_id = _text(fixture.get("fixture_id") or
                               fixture.get("authz_fixture_id"), 80)
            if not fixture_id:
                continue
            row: Dict[str, Any] = {"fixture_id": fixture_id}
            expected = _text(fixture.get("expected_authz"), 24).lower()
            if expected in {"allow", "deny"}:
                row["expected_authz"] = expected
            codes = []
            for code in fixture.get("expected_http_codes") or []:
                code = _safe_int(code, 0, 100, 599)
                if code and code not in codes:
                    codes.append(code)
            if codes:
                row["expected_http_codes"] = codes[:8]
            authz_rows.append(row)
            if len(authz_rows) >= MAX_CONTEXT_AUTHZ:
                break

    context: Dict[str, Any] = {
        "schema_version": _text(configuration.get("schema_version"), 60),
        "target_type": _text(configuration.get("target_type"), 60),
        "versions": versions,
        "target_url_digests": target_url_digests,
        "runtime_options": {
            "enabled": bool(options.get("enabled")),
            "replay_runs": _safe_int(options.get("replay_runs"), 0, 0, 5),
            "safe_modes": safe_modes,
        },
        "service_lifecycle": service_view,
        "authz_fixtures": authz_rows,
        "claim_status": MEMORY_CLAIM_STATUS,
    }
    # A digest makes a configuration change visible even if the individual
    # fields above are absent in an older runtime-lab artifact.
    context["context_digest"] = _digest(context)[:24]
    return context


def _fixture_event(item: Dict[str, Any], round_no: int,
                   fixture_index: int = 0,
                   runtime_context: Optional[Dict[str, Any]] = None
                   ) -> Dict[str, Any]:
    fixture = item.get("fixture") or {}
    replay = item.get("replay") or {}
    differential = item.get("differential") or {}
    reproduces = item.get("reproduces_expected")
    state, hints = _runtime_state(replay, differential, reproduces)
    differences = []
    for diff in differential.get("differences") or []:
        if not isinstance(diff, dict):
            continue
        differences.append({
            "version": _text(diff.get("version"), 80),
            "safe_mode": bool(diff.get("safe_mode", False)),
            "baseline_outcome": _text(diff.get("baseline_outcome"), 80),
            "observed_outcome": _text(diff.get("observed_outcome"), 80),
        })
        if len(differences) >= 12:
            break
    try:
        replay_attempts = int(replay.get("attempts", 0) or 0)
    except (TypeError, ValueError):
        replay_attempts = 0
    evidence = {
        "fixture_id": _text(fixture.get("fixture_id"), 120),
        "fixture_kind": _text(fixture.get("fixture_kind"), 60),
        "replay_status": _text(replay.get("status"), 80),
        "replay_attempts": replay_attempts,
        "differential_status": _text(differential.get("status"), 100),
        "primary_version": _text(differential.get("primary_version"), 80),
        "differences": differences,
        "inconclusive_cells": _bounded_strings(
            differential.get("inconclusive_cells"), 16, 120),
        "reproduces_expected": reproduces if isinstance(reproduces, bool) else None,
        "authz_fixture_id": _text(fixture.get("authz_fixture_id"), 80),
    }
    context = dict(runtime_context or {})
    authz_fixture_id = evidence["authz_fixture_id"]
    if authz_fixture_id:
        rows = list(context.get("authz_fixtures") or [])
        known = {str(row.get("fixture_id")) for row in rows
                 if isinstance(row, dict)}
        if authz_fixture_id not in known:
            rows.append({"fixture_id": authz_fixture_id})
        context["authz_fixtures"] = rows[:MAX_CONTEXT_AUTHZ]
        context["context_digest"] = _digest({
            key: value for key, value in context.items()
            if key != "context_digest"
        })[:24]
    if context:
        evidence["runtime_context"] = context
    event_core = {
        "research_key": _text(fixture.get("research_key"), 80),
        "fixture_id": evidence["fixture_id"],
        "fixture_index": int(fixture_index),
        "round": int(round_no),
        "state": state,
    }
    event = {
        "event_id": "re-" + _digest(event_core)[:24],
        "round": int(round_no),
        "state": state,
        "evidence": evidence,
        "next_probe_hints": hints[:MAX_HINTS],
        "claim_status": MEMORY_CLAIM_STATUS,
    }
    return event


def _summary_gap_event(summary: Dict[str, Any], round_no: int,
                       runtime_context: Optional[Dict[str, Any]] = None
                       ) -> Optional[Dict[str, Any]]:
    if not isinstance(summary, dict):
        return None
    markers = []
    for key in ("harness_error", "compile_error", "execution_state",
                "precondition_status"):
        value = _text(summary.get(key), 160)
        if value:
            markers.append(key + "=" + value)
    if not markers:
        return None
    core = {"round": int(round_no), "state": STATE_ENVIRONMENT_GAP,
            "markers": markers[:8]}
    evidence: Dict[str, Any] = {"summary_markers": markers[:8]}
    if runtime_context:
        evidence["runtime_context"] = dict(runtime_context)
    return {
        "event_id": "re-" + _digest(core)[:24],
        "round": int(round_no),
        "state": STATE_ENVIRONMENT_GAP,
        "evidence": evidence,
        "next_probe_hints": ["先修复 S4 前置条件或 harness，再解释运行时结果"],
        "claim_status": MEMORY_CLAIM_STATUS,
    }


def _runtime_items(runtime_lab: Any) -> Dict[str, List[Dict[str, Any]]]:
    by_candidate: Dict[str, List[Dict[str, Any]]] = {}
    if not isinstance(runtime_lab, dict):
        return by_candidate
    for item in runtime_lab.get("fixtures") or []:
        if not isinstance(item, dict):
            continue
        fixture = item.get("fixture") or {}
        cid = _text(fixture.get("candidate_id", item.get("candidate_id", "")), 120)
        if cid:
            by_candidate.setdefault(cid, []).append(item)
    return by_candidate


def build_round_memory(candidates: Sequence[Dict[str, Any]],
                       summaries: Optional[Dict[str, Any]],
                       conclusions: Optional[Dict[str, str]],
                       runtime_lab: Optional[Dict[str, Any]],
                       round_no: int,
                       target_type: str = "") -> Dict[str, Any]:
    """Create a bounded, target-independent memory delta for one round."""
    summaries = summaries if isinstance(summaries, dict) else {}
    conclusions = conclusions if isinstance(conclusions, dict) else {}
    runtime_by_candidate = _runtime_items(runtime_lab)
    entries: List[Dict[str, Any]] = []
    for candidate in candidates or []:
        if not isinstance(candidate, dict):
            continue
        cid = _text(candidate.get("candidate_id"), 120)
        key = research_key(candidate)
        summary = summaries.get(cid, {}) if cid else {}
        context = _runtime_context(runtime_lab, cid)
        events: List[Dict[str, Any]] = []
        for fixture_index, item in enumerate(runtime_by_candidate.get(cid, [])):
            event = _fixture_event(item, round_no, fixture_index, context)
            event["evidence"]["research_key"] = key
            events.append(event)
        if not events:
            gap = _summary_gap_event(summary, round_no, context)
            if gap:
                gap["event_id"] = "re-" + _digest({
                    "research_key": key,
                    "round": int(round_no),
                    "state": gap.get("state"),
                    "evidence": gap.get("evidence", {}),
                })[:24]
                events.append(gap)
        if not events:
            events.append({
                "event_id": "re-" + _digest({
                    "research_key": key, "round": int(round_no),
                    "state": STATE_DECISION_RECORDED,
                })[:24],
                "round": int(round_no),
                "state": STATE_DECISION_RECORDED,
                "evidence": {},
                "next_probe_hints": [],
                "claim_status": MEMORY_CLAIM_STATUS,
            })
        entry = _candidate_meta(candidate, key)
        if not entry.get("target_type") and target_type:
            entry["target_type"] = _text(target_type, 60).lower()
        if not entry.get("research_surface"):
            target_surface = {
                "web-app": "web",
                "middleware": "protocol",
                "message-rpc": "protocol",
                "cloud-service": "cloud",
                "mobile-app": "mobile",
                "native-app": "native",
            }.get(entry.get("target_type", ""), "")
            if target_surface:
                entry["research_surface"] = target_surface
        entry["residuals"] = _close_residuals(
            entry.get("residuals") or [], summary, round_no)
        entry["pending_residual_count"] = sum(
            1 for item in entry["residuals"]
            if item.get("state") == STATE_PENDING_RESIDUAL)
        entry["resolved_residual_count"] = sum(
            1 for item in entry["residuals"]
            if item.get("state") == STATE_RESIDUAL_FALSIFIED)
        entry.update({
            "round": int(round_no),
            "decision": _text(conclusions.get(cid, ""), 100),
            "decision_status": _text(summary.get("execution_state", ""), 80)
            if isinstance(summary, dict) else "",
            "events": events[:MAX_EVENTS_PER_ENTRY],
            "claim_status": MEMORY_CLAIM_STATUS,
        })
        entries.append(entry)
    states = Counter(event.get("state") for entry in entries
                     for event in entry.get("events", []))
    return {
        "schema_version": MEMORY_SCHEMA_VERSION,
        "round": int(round_no),
        "entries": entries[:MAX_MEMORY_ENTRIES],
        "summary": {
            "candidate_count": len(entries),
            "event_count": sum(len(e.get("events", [])) for e in entries),
            "residual_count": sum(len(e.get("residuals") or [])
                                   for e in entries),
            "pending_residual_count": sum(
                int(e.get("pending_residual_count", 0) or 0)
                for e in entries),
            "resolved_residual_count": sum(
                int(e.get("resolved_residual_count", 0) or 0)
                for e in entries),
            "states": dict(sorted((str(k), int(v)) for k, v in states.items()
                                   if k)),
        },
        "claim_status": MEMORY_CLAIM_STATUS,
    }


def _empty_memory() -> Dict[str, Any]:
    return {
        "schema_version": MEMORY_SCHEMA_VERSION,
        "round": 0,
        "entries": [],
        "summary": {"candidate_count": 0, "event_count": 0,
                    "residual_count": 0, "pending_residual_count": 0,
                    "resolved_residual_count": 0, "states": {}},
        "claim_status": MEMORY_CLAIM_STATUS,
    }


def memory_path(workspace: Path, target: str) -> Path:
    return Path(workspace).resolve() / "state" / str(target) / MEMORY_FILENAME


def review_feedback_path(workspace: Path, target: str) -> Path:
    return Path(workspace).resolve() / "state" / str(target) / REVIEW_FILENAME


def _empty_review_feedback() -> Dict[str, Any]:
    return {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "entries": [],
        "summary": {"feedback_count": 0, "statuses": {}},
        "claim_status": MEMORY_CLAIM_STATUS,
    }


def _normalize_review_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize one operator review without accepting raw execution data."""
    if not isinstance(entry, dict):
        return {}
    status = _text(entry.get("status"), 40).lower()
    reason_code = _text(entry.get("reason_code"), 60).lower()
    research = _text(entry.get("research_key"), 80)
    candidate_id = _text(entry.get("candidate_id"), 120)
    if status not in REVIEW_STATUSES or not research:
        return {}
    if reason_code not in REVIEW_REASON_CODES:
        reason_code = "needs-source-review"
    round_no = _safe_int(entry.get("round"), 0, 0, 1000000)
    evidence_refs = _bounded_strings(entry.get("evidence_refs"),
                                     MAX_REVIEW_REFS, 160)
    next_probe_hints = _bounded_strings(entry.get("next_probe_hints"),
                                        MAX_HINTS, 220)
    note = _text(entry.get("reviewer_note"), MAX_REVIEW_NOTE)
    feedback_id = _text(entry.get("feedback_id"), 80)
    if not feedback_id:
        feedback_id = "rf-" + _digest({
            "research_key": research,
            "candidate_id": candidate_id,
            "status": status,
            "reason_code": reason_code,
            "reviewer_note": note,
            "evidence_refs": evidence_refs,
            "next_probe_hints": next_probe_hints,
            "round": round_no,
        })[:24]
    return {
        "feedback_id": feedback_id,
        "research_key": research,
        "candidate_id": candidate_id,
        "status": status,
        "reason_code": reason_code,
        "reviewer_note": note,
        "evidence_refs": evidence_refs,
        "next_probe_hints": next_probe_hints,
        "round": round_no,
        "claim_status": MEMORY_CLAIM_STATUS,
    }


def _review_summary(entries: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    statuses = Counter(entry.get("status") for entry in entries
                       if entry.get("status"))
    return {
        "feedback_count": len(entries),
        "statuses": dict(sorted((str(k), int(v))
                                 for k, v in statuses.items() if k)),
    }


def load_review_feedback(workspace: Path, target: str) -> Dict[str, Any]:
    path = review_feedback_path(workspace, target)
    if not path.exists():
        return _empty_review_feedback()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return _empty_review_feedback()
    if not isinstance(value, dict):
        return _empty_review_feedback()
    entries: List[Dict[str, Any]] = []
    seen = set()
    for raw in value.get("entries") or []:
        item = _normalize_review_entry(raw)
        if not item or item["feedback_id"] in seen:
            continue
        seen.add(item["feedback_id"])
        entries.append(item)
    entries.sort(key=lambda item: (int(item.get("round", 0) or 0),
                                   str(item.get("feedback_id", ""))))
    entries = entries[-MAX_REVIEW_ENTRIES:]
    return {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "entries": entries,
        "summary": _review_summary(entries),
        "claim_status": MEMORY_CLAIM_STATUS,
    }


def write_review_feedback(workspace: Path, target: str,
                          feedback: Dict[str, Any]) -> Path:
    path = review_feedback_path(workspace, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    entries = []
    seen = set()
    for raw in (feedback or {}).get("entries") or []:
        item = _normalize_review_entry(raw)
        if not item or item["feedback_id"] in seen:
            continue
        seen.add(item["feedback_id"])
        entries.append(item)
    entries.sort(key=lambda item: (int(item.get("round", 0) or 0),
                                   str(item.get("feedback_id", ""))))
    entries = entries[-MAX_REVIEW_ENTRIES:]
    payload = {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "entries": entries,
        "summary": _review_summary(entries),
        "claim_status": MEMORY_CLAIM_STATUS,
    }
    tmp = path.with_name(".%s.tmp.%d" % (path.name, os.getpid()))
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    tmp.replace(path)
    return path


def record_review_feedback(workspace: Path, target: str,
                           research_key_value: str,
                           status: str,
                           reason_code: str = "needs-source-review",
                           candidate_id: str = "",
                           reviewer_note: str = "",
                           evidence_refs: Optional[Sequence[str]] = None,
                           next_probe_hints: Optional[Sequence[str]] = None,
                           round_no: int = 0) -> Dict[str, Any]:
    """Append one bounded human-review event and return its normalized entry."""
    item = _normalize_review_entry({
        "research_key": research_key_value,
        "candidate_id": candidate_id,
        "status": status,
        "reason_code": reason_code,
        "reviewer_note": reviewer_note,
        "evidence_refs": list(evidence_refs or []),
        "next_probe_hints": list(next_probe_hints or []),
        "round": round_no,
    })
    if not item:
        raise ValueError("research_key, status and a supported review shape are required")
    current = load_review_feedback(workspace, target)
    entries = list(current.get("entries") or [])
    entries.append(item)
    write_review_feedback(workspace, target, {"entries": entries})
    return item


def _review_event(feedback: Dict[str, Any]) -> Dict[str, Any]:
    state = _REVIEW_STATE_BY_STATUS.get(
        str(feedback.get("status")), STATE_REVIEW_NEEDS_EVIDENCE)
    evidence = {
        "feedback_id": _text(feedback.get("feedback_id"), 80),
        "research_key": _text(feedback.get("research_key"), 80),
        "review_status": _text(feedback.get("status"), 40),
        "reason_code": _text(feedback.get("reason_code"), 60),
        "reviewer_note": _text(feedback.get("reviewer_note"), MAX_REVIEW_NOTE),
        "evidence_refs": _bounded_strings(feedback.get("evidence_refs"),
                                           MAX_REVIEW_REFS, 160),
    }
    core = {
        "feedback_id": evidence["feedback_id"],
        "research_key": evidence["research_key"],
        "round": _safe_int(feedback.get("round"), 0, 0, 1000000),
        "state": state,
    }
    hints = _bounded_strings(feedback.get("next_probe_hints"), MAX_HINTS, 220)
    if not hints:
        hints = {
            STATE_REVIEW_REJECTED: ["仅在出现新差异或更强数据流证据后重开，不要重复原探针"],
            STATE_REVIEW_ACCEPTED: ["保留机制证据，继续补齐 G4/G5 所需的 typed effect 与严重性证据"],
            STATE_REVIEW_NEEDS_EVIDENCE: ["按复核意见补最小可复现实验、source→sink 或 typed effect 证据"],
            STATE_REVIEW_SCOPE_CORRECTED: ["按修正后的范围重建候选键并重新做覆盖与运行时验证"],
        }.get(state, [])
    return {
        "event_id": "re-" + _digest(core)[:24],
        "round": core["round"],
        "state": state,
        "evidence": evidence,
        "next_probe_hints": hints,
        "claim_status": MEMORY_CLAIM_STATUS,
    }


def _apply_review_feedback(memory: Dict[str, Any],
                           feedback_entries: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Overlay review events so scheduling sees feedback before the next S8."""
    normalized = memory if isinstance(memory, dict) else _empty_memory()
    grouped: Dict[str, Dict[str, Any]] = {}
    for raw in normalized.get("entries") or []:
        entry = _normalize_entry(raw) if isinstance(raw, dict) else {}
        key = str(entry.get("research_key") or "")
        if key:
            grouped[key] = entry
    max_round = _safe_int(normalized.get("round"), 0, 0, 1000000)
    for raw in feedback_entries or []:
        feedback = _normalize_review_entry(raw)
        key = str(feedback.get("research_key") or "")
        if not key:
            continue
        event = _review_event(feedback)
        max_round = max(max_round, int(event.get("round", 0) or 0))
        entry = grouped.get(key)
        if entry is None:
            entry = _normalize_entry({
                "research_key": key,
                "candidate_id": feedback.get("candidate_id", ""),
                "round": event.get("round", 0),
                "events": [],
            })
            grouped[key] = entry
        elif feedback.get("candidate_id") and not entry.get("candidate_id"):
            entry["candidate_id"] = _text(feedback.get("candidate_id"), 120)
        events = entry.setdefault("events", [])
        ids = {str(item.get("event_id")) for item in events}
        if event["event_id"] not in ids:
            events.append(event)
        events.sort(key=_event_sort_key)
        entry["events"] = events[-MAX_EVENTS_PER_ENTRY:]
        entry["round"] = max(int(entry.get("round", 0) or 0),
                             int(event.get("round", 0) or 0))
        entry["claim_status"] = MEMORY_CLAIM_STATUS
    entries = sorted(grouped.values(),
                     key=lambda item: str(item.get("research_key", "")))
    entries = entries[-MAX_MEMORY_ENTRIES:]
    return {
        "schema_version": MEMORY_SCHEMA_VERSION,
        "round": max_round,
        "entries": entries,
        "summary": _memory_summary(entries, max_round),
        "claim_status": MEMORY_CLAIM_STATUS,
    }


def load_research_memory(workspace: Path, target: str) -> Dict[str, Any]:
    path = memory_path(workspace, target)
    value: Dict[str, Any]
    if not path.exists():
        value = _empty_memory()
    else:
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            loaded = None
        value = loaded if isinstance(loaded, dict) else _empty_memory()
    entries = [_normalize_entry(entry) for entry in (value.get("entries") or [])
               if isinstance(entry, dict) and entry.get("research_key")]
    value["schema_version"] = MEMORY_SCHEMA_VERSION
    value["entries"] = entries[:MAX_MEMORY_ENTRIES]
    value["claim_status"] = MEMORY_CLAIM_STATUS
    result = _apply_review_feedback(
        value, load_review_feedback(workspace, target).get("entries") or [])
    try:
        round_no = int(result.get("round", 0) or 0)
    except (TypeError, ValueError):
        round_no = 0
    result["summary"] = _memory_summary(result.get("entries") or [], round_no)
    return result


def _event_sort_key(event: Dict[str, Any]) -> Tuple[int, str]:
    try:
        round_no = int(event.get("round", 0) or 0)
    except (TypeError, ValueError):
        round_no = 0
    return round_no, str(event.get("event_id", ""))


def _latest_research_event(events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Choose the latest meaningful observation.

    A later round may only record a ledger decision because it was deferred or
    resumed without another lab execution.  That bookkeeping event must not
    erase the last actionable runtime state from the scheduler's view.
    """
    items = [event for event in events
             if isinstance(event, dict) and event.get("state")]
    meaningful = [event for event in items
                  if event.get("state") != STATE_DECISION_RECORDED]
    chosen = meaningful or items
    return max(chosen, key=_event_sort_key) if chosen else {}


def _normalize_runtime_context(value: Any) -> Dict[str, Any]:
    """Whitelist the replay context copied from ``runtime-context-v1``."""
    if not isinstance(value, dict):
        return {}
    out: Dict[str, Any] = {}
    for key, limit in (("schema_version", 60), ("target_type", 60),
                       ("context_digest", 40)):
        text = _text(value.get(key), limit)
        if text:
            out[key] = text
    out["versions"] = _bounded_strings(value.get("versions"),
                                       MAX_CONTEXT_VERSIONS, 80)
    url_digests = value.get("target_url_digests")
    if isinstance(url_digests, dict):
        out["target_url_digests"] = {
            _text(version, 80): _text(digest, 40)
            for version, digest in sorted(url_digests.items(),
                                          key=lambda item: str(item[0]))
            if _text(version, 80) and _text(digest, 40)
        }  # bounded below after construction
        out["target_url_digests"] = dict(
            list(out["target_url_digests"].items())[:MAX_CONTEXT_VERSIONS])

    options = value.get("runtime_options")
    if isinstance(options, dict):
        safe_modes = []
        for item in options.get("safe_modes") or []:
            if isinstance(item, bool):
                parsed = item
            else:
                parsed = str(item).strip().lower() in {"true", "1", "yes", "on"}
            if parsed not in safe_modes:
                safe_modes.append(parsed)
        out["runtime_options"] = {
            "enabled": bool(options.get("enabled")),
            "replay_runs": _safe_int(options.get("replay_runs"), 0, 0, 5),
            "safe_modes": safe_modes[:4],
        }

    service = value.get("service_lifecycle")
    if isinstance(service, dict):
        service_out: Dict[str, Any] = {}
        for key, limit in (("status", 80), ("config_digest", 40),
                           ("schema_version", 60), ("healthcheck_kind", 40)):
            text = _text(service.get(key), limit)
            if text:
                service_out[key] = text
        for key in ("configured", "enabled", "ready", "process_managed",
                    "healthcheck_configured"):
            if isinstance(service.get(key), bool):
                service_out[key] = service[key]
        if isinstance(service.get("healthcheck_port"), int):
            service_out["healthcheck_port"] = _safe_int(
                service.get("healthcheck_port"), 0, 1, 65535)
        out["service_lifecycle"] = service_out

    authz_out: List[Dict[str, Any]] = []
    for row in value.get("authz_fixtures") or []:
        if not isinstance(row, dict):
            continue
        fixture_id = _text(row.get("fixture_id") or
                           row.get("authz_fixture_id"), 80)
        if not fixture_id:
            continue
        item: Dict[str, Any] = {"fixture_id": fixture_id}
        expected = _text(row.get("expected_authz"), 24).lower()
        if expected in {"allow", "deny"}:
            item["expected_authz"] = expected
        codes = []
        for code in row.get("expected_http_codes") or []:
            code = _safe_int(code, 0, 100, 599)
            if code and code not in codes:
                codes.append(code)
        if codes:
            item["expected_http_codes"] = codes[:8]
        authz_out.append(item)
        if len(authz_out) >= MAX_CONTEXT_AUTHZ:
            break
    out["authz_fixtures"] = authz_out
    return out


def _normalize_evidence(value: Any) -> Dict[str, Any]:
    """Whitelist the small evidence view allowed in durable memory."""
    if not isinstance(value, dict):
        return {}
    out: Dict[str, Any] = {}
    for key, limit in (("fixture_id", 120), ("fixture_kind", 60),
                       ("replay_status", 80), ("differential_status", 100),
                       ("primary_version", 80), ("research_key", 80),
                       ("authz_fixture_id", 80), ("configuration_digest", 40),
                       ("feedback_id", 80), ("review_status", 40),
                       ("reason_code", 60), ("reviewer_note", MAX_REVIEW_NOTE)):
        if value.get(key) not in (None, ""):
            out[key] = _text(value.get(key), limit)
    if value.get("replay_attempts") is not None:
        try:
            out["replay_attempts"] = int(value.get("replay_attempts"))
        except (TypeError, ValueError):
            out["replay_attempts"] = 0
    if isinstance(value.get("reproduces_expected"), bool):
        out["reproduces_expected"] = value["reproduces_expected"]
    out["inconclusive_cells"] = _bounded_strings(
        value.get("inconclusive_cells"), 16, 120)
    differences = []
    for diff in value.get("differences") or []:
        if not isinstance(diff, dict):
            continue
        differences.append({
            "version": _text(diff.get("version"), 80),
            "safe_mode": bool(diff.get("safe_mode", False)),
            "baseline_outcome": _text(diff.get("baseline_outcome"), 80),
            "observed_outcome": _text(diff.get("observed_outcome"), 80),
        })
        if len(differences) >= 12:
            break
    out["differences"] = differences
    out["summary_markers"] = _bounded_strings(
        value.get("summary_markers"), 8, 180)
    context = _normalize_runtime_context(value.get("runtime_context"))
    if context:
        out["runtime_context"] = context
    out["evidence_refs"] = _bounded_strings(
        value.get("evidence_refs"), MAX_REVIEW_REFS, 160)
    return out


def _normalize_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    try:
        entry_round = int(entry.get("round", 0) or 0)
    except (TypeError, ValueError):
        entry_round = 0
    normalized = {
        "research_key": _text(entry.get("research_key"), 80),
        "candidate_id": _text(entry.get("candidate_id"), 120),
        "surface": _text(entry.get("surface"), MAX_SURFACE),
        "research_surface": _text(entry.get("research_surface"), 32).lower(),
        "target_type": _text(entry.get("target_type"), 60).lower(),
        "attack_class": _text(entry.get("attack_class"), 80).lower(),
        "variant": _text(entry.get("variant"), 100),
        "precondition_class": _text(entry.get("precondition_class"), 60).lower(),
        "entry": _text(entry.get("entry"), 180),
        "input_shape": _text(entry.get("input_shape"), 140),
        "code_locations": _bounded_strings(entry.get("code_locations"),
                                             MAX_LOCATIONS, 180),
        "target_classes": _bounded_strings(entry.get("target_classes"),
                                            MAX_TARGET_CLASSES, 160),
        "fix_variants": _bounded_strings(entry.get("fix_variants"), 8, 160),
        "patch_commit": _text(entry.get("patch_commit"), 80),
        "round": entry_round,
        "decision": _text(entry.get("decision"), 100),
        "decision_status": _text(entry.get("decision_status"), 80),
    }
    normalized["variants"] = _bounded_strings(
        entry.get("variants") or [normalized["variant"]]
        + list(normalized.get("fix_variants") or []), 12, 100)
    normalized["attack_classes"] = _bounded_strings(
        entry.get("attack_classes") or [normalized["attack_class"]], 8, 80)
    normalized["precondition_classes"] = _bounded_strings(
        entry.get("precondition_classes") or [normalized["precondition_class"]],
        8, 60)
    residuals = []
    seen_residuals = set()
    for raw_residual in entry.get("residuals") or []:
        residual = _normalize_residual(raw_residual)
        residual_id = residual.get("residual_id")
        if not residual_id or residual_id in seen_residuals:
            continue
        seen_residuals.add(residual_id)
        residuals.append(residual)
    residuals.sort(key=lambda item: str(item.get("residual_id", "")))
    normalized["residuals"] = residuals[-MAX_RESIDUALS_PER_ENTRY:]
    normalized["pending_residual_count"] = sum(
        1 for item in normalized["residuals"]
        if item.get("state") == STATE_PENDING_RESIDUAL)
    normalized["resolved_residual_count"] = sum(
        1 for item in normalized["residuals"]
        if item.get("state") == STATE_RESIDUAL_FALSIFIED)
    events = []
    seen = set()
    for event in entry.get("events") or []:
        if not isinstance(event, dict):
            continue
        event_id = _text(event.get("event_id"), 80)
        if not event_id or event_id in seen:
            continue
        seen.add(event_id)
        try:
            event_round = int(event.get("round", 0) or 0)
        except (TypeError, ValueError):
            event_round = 0
        item = {
            "event_id": event_id,
            "round": event_round,
            "state": _text(event.get("state"), 80),
            "evidence": _normalize_evidence(event.get("evidence")),
            "next_probe_hints": _bounded_strings(event.get("next_probe_hints"), MAX_HINTS, 220),
            "claim_status": MEMORY_CLAIM_STATUS,
        }
        events.append(item)
    events.sort(key=_event_sort_key)
    normalized["events"] = events[-MAX_EVENTS_PER_ENTRY:]
    normalized["claim_status"] = MEMORY_CLAIM_STATUS
    return normalized


def _memory_summary(entries: Sequence[Dict[str, Any]], round_no: int) -> Dict[str, Any]:
    states = Counter(event.get("state") for entry in entries
                     for event in entry.get("events", []) if event.get("state"))
    return {
        "candidate_count": len(entries),
        "event_count": sum(len(entry.get("events", [])) for entry in entries),
        "residual_count": sum(len(entry.get("residuals") or [])
                               for entry in entries),
        "pending_residual_count": sum(
            int(entry.get("pending_residual_count", 0) or 0)
            for entry in entries),
        "resolved_residual_count": sum(
            int(entry.get("resolved_residual_count", 0) or 0)
            for entry in entries),
        "states": dict(sorted((str(k), int(v)) for k, v in states.items())),
        "last_round": int(round_no),
    }


def _merge_residual(current: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
    """Merge one residual monotonically; a falsified state never regresses."""
    left = _normalize_residual(current)
    right = _normalize_residual(incoming)
    if not left:
        return right
    if not right:
        return left
    result = dict(left)
    # Keep the newest bounded source metadata, but never erase a recorded
    # falsifier with a later bookkeeping/pending copy.
    for field in ("kind", "reason_code", "code_locations", "has_probe_plan",
                  "probe_digest", "allowed_falsifiers"):
        value = right.get(field)
        if value not in (None, "", [], {}):
            result[field] = value
    if left.get("state") != STATE_RESIDUAL_FALSIFIED and \
            right.get("state") == STATE_RESIDUAL_FALSIFIED:
        result.update({
            "state": STATE_RESIDUAL_FALSIFIED,
            "falsifier_code": right.get("falsifier_code", ""),
            "evidence_cells": list(right.get("evidence_cells") or []),
            "outcome_round": _safe_int(right.get("outcome_round"), 0, 0, 1000000),
        })
    elif left.get("state") == STATE_RESIDUAL_FALSIFIED:
        result["state"] = STATE_RESIDUAL_FALSIFIED
        result["falsifier_code"] = left.get("falsifier_code", "")
        result["evidence_cells"] = list(left.get("evidence_cells") or [])
        result["outcome_round"] = _safe_int(left.get("outcome_round"), 0, 0, 1000000)
    else:
        result["state"] = STATE_PENDING_RESIDUAL
        result["falsifier_code"] = ""
        result["evidence_cells"] = []
        result["outcome_round"] = 0
    result["claim_status"] = MEMORY_CLAIM_STATUS
    return _normalize_residual(result)


def merge_research_memory(existing: Optional[Dict[str, Any]],
                          delta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Idempotently append a round delta while retaining old gaps."""
    existing = existing if isinstance(existing, dict) else _empty_memory()
    delta = delta if isinstance(delta, dict) else _empty_memory()
    merged: Dict[str, Dict[str, Any]] = {}
    for group in (existing.get("entries") or [], delta.get("entries") or []):
        for source in group:
            if not isinstance(source, dict):
                continue
            key = _text(source.get("research_key"), 80)
            if not key:
                continue
            if key not in merged:
                merged[key] = _normalize_entry(source)
                continue
            target = merged[key]
            if source.get("candidate_id"):
                target["candidate_id"] = _text(source.get("candidate_id"), 120)
            for field in ("surface", "entry", "input_shape", "variant"):
                if source.get(field):
                    target[field] = _text(source.get(field),
                                          MAX_SURFACE if field == "surface" else
                                          (100 if field == "variant" else 180))
            for field, limit in (("research_surface", 32),
                                 ("target_type", 60),
                                 ("attack_class", 80),
                                 ("precondition_class", 60)):
                if source.get(field):
                    target[field] = _text(source.get(field), limit).lower()
            for field, limit, item_limit, fallback in (
                    ("variants", 12, 100,
                     [source.get("variant")] + list(source.get("fix_variants") or [])),
                    ("attack_classes", 8, 80, [source.get("attack_class")]),
                    ("precondition_classes", 8, 60,
                     [source.get("precondition_class")])):
                values = list(target.get(field) or []) + list(source.get(field) or fallback)
                target[field] = _bounded_strings(values, limit, item_limit)
            if source.get("code_locations"):
                target["code_locations"] = _bounded_strings(
                    source.get("code_locations"), MAX_LOCATIONS, 180)
            if source.get("target_classes"):
                target["target_classes"] = _bounded_strings(
                    source.get("target_classes"), MAX_TARGET_CLASSES, 160)
            if source.get("fix_variants"):
                target["fix_variants"] = _bounded_strings(
                    source.get("fix_variants"), 8, 160)
            if source.get("patch_commit"):
                target["patch_commit"] = _text(source.get("patch_commit"), 80)
            residuals = list(target.get("residuals") or [])
            residual_index = {
                str(item.get("residual_id")): index
                for index, item in enumerate(residuals)
                if isinstance(item, dict) and item.get("residual_id")
            }
            for raw_residual in source.get("residuals") or []:
                residual = _normalize_residual(raw_residual)
                residual_id = residual.get("residual_id")
                if not residual_id:
                    continue
                if residual_id in residual_index:
                    index = residual_index[residual_id]
                    residuals[index] = _merge_residual(residuals[index], residual)
                else:
                    residual_index[residual_id] = len(residuals)
                    residuals.append(residual)
            residuals.sort(key=lambda item: str(item.get("residual_id", "")))
            target["residuals"] = residuals[-MAX_RESIDUALS_PER_ENTRY:]
            target["pending_residual_count"] = sum(
                1 for item in target["residuals"]
                if item.get("state") == STATE_PENDING_RESIDUAL)
            target["resolved_residual_count"] = sum(
                1 for item in target["residuals"]
                if item.get("state") == STATE_RESIDUAL_FALSIFIED)
            target["decision"] = _text(source.get("decision", target.get("decision", "")), 100)
            events = target.setdefault("events", [])
            seen = {str(event.get("event_id")) for event in events}
            for event in source.get("events") or []:
                if not isinstance(event, dict):
                    continue
                event_id = _text(event.get("event_id"), 80)
                if not event_id or event_id in seen:
                    continue
                events.append(_normalize_entry({"research_key": key, "events": [event]})["events"][0])
                seen.add(event_id)
            events.sort(key=_event_sort_key)
            target["events"] = events[-MAX_EVENTS_PER_ENTRY:]
            target["claim_status"] = MEMORY_CLAIM_STATUS
    entries = sorted(merged.values(),
                     key=lambda item: (str(item.get("research_key", ""))))
    if len(entries) > MAX_MEMORY_ENTRIES:
        entries = entries[-MAX_MEMORY_ENTRIES:]
    round_values = []
    for source in (existing, delta):
        try:
            round_values.append(int(source.get("round", 0) or 0))
        except (TypeError, ValueError):
            pass
    round_no = max(round_values or [0])
    return {
        "schema_version": MEMORY_SCHEMA_VERSION,
        "round": round_no,
        "entries": entries,
        "summary": _memory_summary(entries, round_no),
        "claim_status": MEMORY_CLAIM_STATUS,
    }


def write_research_memory(workspace: Path, target: str,
                          memory: Dict[str, Any]) -> Path:
    """Write memory atomically at target scope and return its path."""
    path = memory_path(workspace, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(memory, indent=2, ensure_ascii=False)
    tmp = path.with_name(".%s.tmp.%d" % (path.name, os.getpid()))
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)
    return path


def memory_match(candidate: Dict[str, Any],
                 entries: Iterable[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Return the latest matching entry plus its latest runtime event."""
    key = research_key(candidate)
    matches = [entry for entry in entries or []
               if isinstance(entry, dict) and str(entry.get("research_key")) == key]
    if not matches:
        return None
    entry = sorted(matches, key=lambda item: str(item.get("research_key")))[0]
    events = [event for event in entry.get("events", [])
              if isinstance(event, dict) and event.get("state")]
    latest = _latest_research_event(events)
    return {
        "research_key": key,
        "candidate_id": _text(entry.get("candidate_id"), 120),
        "surface": _text(entry.get("surface"), MAX_SURFACE),
        "latest_event": latest,
        "events": sorted(events, key=_event_sort_key)[-MAX_EVENTS_PER_ENTRY:],
        "decision": _text(entry.get("decision"), 100),
        "claim_status": MEMORY_CLAIM_STATUS,
    }


def memory_prompt_rows(entries: Iterable[Dict[str, Any]],
                       limit: int = 12) -> List[Dict[str, Any]]:
    """Make a bounded prompt view without exposing the full memory file."""
    rows = []
    for entry in entries or []:
        events = [event for event in entry.get("events", [])
                  if isinstance(event, dict) and event.get("state")]
        latest = _latest_research_event(events)
        latest_evidence = latest.get("evidence") or {}
        rows.append({
            "research_key": _text(entry.get("research_key"), 80),
            "candidate_id": _text(entry.get("candidate_id"), 120),
            "state": _text(latest.get("state"), 80) or STATE_DECISION_RECORDED,
            "round": latest.get("round", entry.get("round", 0)),
            "fix_variants": _bounded_strings(entry.get("fix_variants"), 4, 160),
            "next_probe_hints": _bounded_strings(
                latest.get("next_probe_hints"), 2, 220),
            "review_status": _text(latest_evidence.get("review_status"), 40),
            "reason_code": _text(latest_evidence.get("reason_code"), 60),
            "pending_residuals": [{
                "residual_id": _text(item.get("residual_id"), 80),
                "kind": _text(item.get("kind"), MAX_RESIDUAL_KIND),
                "reason_code": _text(item.get("reason_code"), MAX_RESIDUAL_KIND),
                "has_probe_plan": bool(item.get("has_probe_plan")),
                "claim_status": MEMORY_CLAIM_STATUS,
            } for item in (entry.get("residuals") or [])
                if isinstance(item, dict)
                and item.get("state") == STATE_PENDING_RESIDUAL][:4],
            "resolved_residuals": [{
                "residual_id": _text(item.get("residual_id"), 80),
                "kind": _text(item.get("kind"), MAX_RESIDUAL_KIND),
                "falsifier_code": _text(item.get("falsifier_code"), 48),
                "outcome_round": _safe_int(item.get("outcome_round"), 0),
                "claim_status": MEMORY_CLAIM_STATUS,
            } for item in (entry.get("residuals") or [])
                if isinstance(item, dict)
                and item.get("state") == STATE_RESIDUAL_FALSIFIED][:4],
            "claim_status": MEMORY_CLAIM_STATUS,
        })
    rows.sort(key=lambda row: (-int(row.get("round", 0) or 0),
                               str(row.get("research_key", ""))))
    return rows[:max(0, int(limit))]
