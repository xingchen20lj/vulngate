"""Bounded surface-specific research variant plans.

The strategy layer can say *what kind* of follow-up is needed, but a strong
research workflow also needs a small, repeatable experiment shape.  This
module supplies that shape for the five supported research surfaces.  It is
planning metadata only: every selected variant contains a positive lane, a
negative/safe lane, and an environment-gap lane, and none of those lanes is a
finding or a runtime result.

The library intentionally contains no payloads, commands, URLs, credentials,
or source prose.  It describes only bounded observation classes and
allowlisted falsifier codes so the same plan can be shown to the host agent,
the S2 experiment planner, and the S4 PoC writer.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any, Dict, List, Mapping, Sequence


SURFACE_VARIANT_SCHEMA_VERSION = "surface-variant-plan-v1"
VARIANT_FIXTURE_SCHEMA_VERSION = "surface-variant-fixture-v1"
SURFACES = frozenset({"web", "protocol", "cloud", "mobile", "native"})
TARGET_TYPE_TO_SURFACE = {
    "web-app": "web",
    "middleware": "protocol",
    "message-rpc": "protocol",
    "cloud-service": "cloud",
    "mobile-app": "mobile",
    "native-app": "native",
}
LANES = ("positive", "negative", "environment-gap")
OBSERVATION_SIGNALS = frozenset({
    "execution", "entry-behavior", "authorization", "negative-baseline",
    "capability-trace", "state-sequence", "typed-effect", "safe-equivalent",
    "environment-gap", "evidence-field", "runtime-error",
})
GUIDANCE_ACTIONS = frozenset({
    "repair-environment", "replay-residual-variant", "review-followup",
    "reframe-scope", "add-negative-control", "trace-capability-transition",
    "review-source-dataflow", "add-typed-effect", "replay-new-variant",
    "continue-path-closure", "hold-for-new-evidence",
    "repeat-with-controlled-context",
})
MAX_VARIANTS = 3
MAX_LANES = MAX_VARIANTS * len(LANES)
MAX_SIGNALS = 6
MAX_FALSIFIERS = 5
MAX_TEXT = 96
MAX_STATE_STEPS = 8
CLAIM_STATUS = "not-a-finding"


# These are state identifiers, not requests, payloads, commands, or runtime
# results.  Keeping them in the deterministic library means a malformed plan
# cannot smuggle arbitrary process instructions into an S4 environment.
_STATE_STEPS: Dict[str, Sequence[str]] = {
    "web-tenant-object-boundary":
        ("entry", "principal", "tenant", "object", "sink"),
    "web-route-middleware-default":
        ("route", "middleware", "handler", "sink"),
    "web-egress-allowlist-redirect":
        ("entry", "destination", "allowlist", "redirect", "sink"),
    "protocol-frame-state-order":
        ("connect", "frame", "state", "replay", "response"),
    "protocol-parser-type-boundary":
        ("frame", "length", "type", "parser", "effect"),
    "protocol-concurrency-availability":
        ("baseline", "concurrent", "resource", "availability"),
    "cloud-metadata-identity-boundary":
        ("identity", "metadata", "credential", "policy", "effect"),
    "cloud-policy-delegation-boundary":
        ("principal", "policy", "delegation", "resource", "effect"),
    "cloud-provider-emulator-replay":
        ("provider", "identity", "request", "response", "effect"),
    "mobile-deep-link-lifecycle":
        ("cold-start", "deep-link", "resume", "authorization", "sink"),
    "mobile-webview-origin-bridge":
        ("webview", "origin", "bridge", "ipc", "sink"),
    "mobile-storage-permission-lifecycle":
        ("install", "permission", "storage", "lifecycle", "read"),
    "native-url-scheme-method-body":
        ("scheme", "selector", "method", "body", "effect"),
    "native-webview-ipc-origin":
        ("origin", "message", "ipc", "sink", "effect"),
    "native-symbol-method-body-runtime":
        ("symbol", "method-body", "instrumentation", "runtime", "effect"),
}


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    if value is None:
        return ""
    return " ".join(str(value).replace("\x00", "").split())[:limit]


def _bounded(values: Any, limit: int, item_limit: int = MAX_TEXT) -> List[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes)):
        values = [values]
    if not isinstance(values, (list, tuple, set)):
        return []
    result: List[str] = []
    seen = set()
    for value in values:
        item = _text(value, item_limit)
        if item and item not in seen:
            seen.add(item)
            result.append(item)
        if len(result) >= limit:
            break
    return sorted(result)


def _surface(surface: Any, target_type: Any = "") -> str:
    value = _text(surface, 32).lower()
    if value in SURFACES:
        return value
    return TARGET_TYPE_TO_SURFACE.get(_text(target_type, 32).lower(), "")


def _lane(signals: Sequence[str], falsifiers: Sequence[str],
          expected: str) -> Dict[str, Any]:
    return {
        "required_observations": list(signals)[:MAX_SIGNALS],
        "falsifiers": list(falsifiers)[:MAX_FALSIFIERS],
        "expected_observation": expected,
        "claim_status": CLAIM_STATUS,
    }


# Each template describes one meaningful surface variant.  Every template is
# expanded into the same three lanes by ``build_surface_variant_plan``.
_LIBRARY: Dict[str, Sequence[Dict[str, Any]]] = {
    "web": (
        {
            "variant_id": "web-tenant-object-boundary",
            "family": "authorization-boundary",
            "axis": "principal-tenant-object",
            "markers": ("authz", "authorization", "tenant", "object", "idor"),
            "action_families": ("add-negative-control", "review-followup",
                                 "replay-new-variant", "reframe-scope"),
            "positive": _lane(
                ("execution", "authorization", "typed-effect"),
                ("typed-effect-missing", "subject-object-binding-missing"),
                "typed-effect"),
            "negative": _lane(
                ("execution", "authorization", "negative-baseline",
                 "safe-equivalent"),
                ("negative-baseline-missing", "ownership-boundary-difference"),
                "safe-equivalent"),
            "environment-gap": _lane(
                ("environment-gap",),
                ("runtime-unavailable", "non-comparable-replay"),
                "environment-gap"),
        },
        {
            "variant_id": "web-route-middleware-default",
            "family": "route-control",
            "axis": "route-registration-default-feature",
            "markers": ("route", "endpoint", "middleware", "default", "http"),
            "action_families": ("review-source-dataflow", "review-followup",
                                 "continue-path-closure", "replay-new-variant"),
            "positive": _lane(
                ("execution", "entry-behavior", "authorization", "typed-effect"),
                ("entry-not-reachable", "typed-effect-missing"),
                "typed-effect"),
            "negative": _lane(
                ("execution", "entry-behavior", "negative-baseline",
                 "safe-equivalent"),
                ("default-route-disabled", "negative-baseline-missing"),
                "safe-equivalent"),
            "environment-gap": _lane(
                ("environment-gap",),
                ("service-harness-unavailable", "route-not-comparable"),
                "environment-gap"),
        },
        {
            "variant_id": "web-egress-allowlist-redirect",
            "family": "egress-boundary",
            "axis": "destination-redirect-allowlist",
            "markers": ("ssrf", "egress", "redirect", "url", "allowlist"),
            "action_families": ("add-negative-control", "add-typed-effect",
                                 "replay-new-variant", "review-source-dataflow"),
            "positive": _lane(
                ("execution", "entry-behavior", "typed-effect"),
                ("destination-not-reached", "typed-effect-missing"),
                "typed-effect"),
            "negative": _lane(
                ("execution", "negative-baseline", "safe-equivalent"),
                ("allowlist-not-observed", "safe-equivalent-missing"),
                "safe-equivalent"),
            "environment-gap": _lane(
                ("environment-gap",),
                ("loopback-harness-unavailable", "egress-not-comparable"),
                "environment-gap"),
        },
    ),
    "protocol": (
        {
            "variant_id": "protocol-frame-state-order",
            "family": "state-machine",
            "axis": "frame-order-fragmentation-replay",
            "markers": ("state", "race", "frame", "sequence", "replay", "toctou"),
            "action_families": ("trace-capability-transition", "replay-new-variant",
                                 "replay-residual-variant", "add-negative-control"),
            "positive": _lane(
                ("execution", "state-sequence", "typed-effect"),
                ("transition-not-observed", "typed-effect-missing"),
                "typed-effect"),
            "negative": _lane(
                ("execution", "state-sequence", "negative-baseline",
                 "safe-equivalent"),
                ("out-of-order-state-rejected", "safe-equivalent-missing"),
                "safe-equivalent"),
            "environment-gap": _lane(
                ("environment-gap",),
                ("required-runtime-unavailable", "service-not-comparable"),
                "environment-gap"),
        },
        {
            "variant_id": "protocol-parser-type-boundary",
            "family": "parser-boundary",
            "axis": "frame-length-type-mode",
            "markers": ("parser", "deserialize", "serialization", "type", "frame", "length"),
            "action_families": ("review-source-dataflow", "add-negative-control",
                                 "add-typed-effect", "replay-new-variant"),
            "positive": _lane(
                ("execution", "entry-behavior", "typed-effect"),
                ("type-boundary-rejects", "typed-effect-missing"),
                "typed-effect"),
            "negative": _lane(
                ("execution", "negative-baseline", "safe-equivalent"),
                ("safe-mode-not-observed", "negative-baseline-missing"),
                "safe-equivalent"),
            "environment-gap": _lane(
                ("environment-gap",),
                ("jdk-or-dependency-unavailable", "parser-replay-inconclusive"),
                "environment-gap"),
        },
        {
            "variant_id": "protocol-concurrency-availability",
            "family": "resource-availability",
            "axis": "concurrency-saturation-service-availability",
            "markers": ("dos", "resource", "concurrency", "availability", "thread", "connection"),
            "action_families": ("trace-capability-transition", "replay-new-variant",
                                 "add-negative-control", "replay-residual-variant"),
            "positive": _lane(
                ("execution", "state-sequence", "typed-effect"),
                ("concurrency-not-observed", "service-unavailable-not-observed"),
                "typed-effect"),
            "negative": _lane(
                ("execution", "negative-baseline", "safe-equivalent"),
                ("single-request-only", "availability-probe-missing"),
                "safe-equivalent"),
            "environment-gap": _lane(
                ("environment-gap",),
                ("service-lifecycle-unavailable", "concurrency-not-comparable"),
                "environment-gap"),
        },
    ),
    "cloud": (
        {
            "variant_id": "cloud-metadata-identity-boundary",
            "family": "identity-boundary",
            "axis": "metadata-role-credential-source",
            "markers": ("ssrf", "metadata", "iam", "identity", "credential", "role"),
            "action_families": ("add-negative-control", "add-typed-effect",
                                 "review-followup", "replay-new-variant"),
            "positive": _lane(
                ("execution", "authorization", "typed-effect"),
                ("identity-boundary-not-crossed", "typed-effect-missing"),
                "typed-effect"),
            "negative": _lane(
                ("execution", "authorization", "negative-baseline",
                 "safe-equivalent"),
                ("iam-policy-not-observed", "credential-boundary-difference"),
                "safe-equivalent"),
            "environment-gap": _lane(
                ("environment-gap",),
                ("provider-or-emulator-unavailable", "identity-replay-inconclusive"),
                "environment-gap"),
        },
        {
            "variant_id": "cloud-policy-delegation-boundary",
            "family": "policy-delegation",
            "axis": "principal-role-resource-policy",
            "markers": ("policy", "permission", "role", "resource", "tenant", "delegation"),
            "action_families": ("add-negative-control", "review-followup",
                                 "review-source-dataflow", "replay-new-variant"),
            "positive": _lane(
                ("execution", "authorization", "typed-effect"),
                ("policy-denies", "resource-binding-missing"),
                "typed-effect"),
            "negative": _lane(
                ("execution", "authorization", "negative-baseline",
                 "safe-equivalent"),
                ("unauthorized-policy-case-missing", "safe-equivalent-missing"),
                "safe-equivalent"),
            "environment-gap": _lane(
                ("environment-gap",),
                ("cloud-identity-unavailable", "policy-replay-not-comparable"),
                "environment-gap"),
        },
        {
            "variant_id": "cloud-provider-emulator-replay",
            "family": "provider-runtime",
            "axis": "provider-region-sdk-runtime",
            "markers": ("provider", "emulator", "sdk", "region", "runtime", "cloud"),
            "action_families": ("repair-environment", "replay-residual-variant",
                                 "replay-new-variant", "review-source-dataflow"),
            "positive": _lane(
                ("execution", "entry-behavior", "typed-effect"),
                ("provider-path-not-reached", "typed-effect-missing"),
                "typed-effect"),
            "negative": _lane(
                ("execution", "negative-baseline", "safe-equivalent"),
                ("provider-guard-not-observed", "safe-equivalent-missing"),
                "safe-equivalent"),
            "environment-gap": _lane(
                ("environment-gap",),
                ("provider-emulator-unavailable", "sdk-runtime-missing"),
                "environment-gap"),
        },
    ),
    "mobile": (
        {
            "variant_id": "mobile-deep-link-lifecycle",
            "family": "lifecycle-boundary",
            "axis": "cold-warm-background-resume-deep-link",
            "markers": ("deep-link", "lifecycle", "background", "resume", "intent", "url"),
            "action_families": ("trace-capability-transition", "add-negative-control",
                                 "replay-new-variant", "review-followup"),
            "positive": _lane(
                ("execution", "state-sequence", "authorization", "typed-effect"),
                ("lifecycle-transition-not-observed", "typed-effect-missing"),
                "typed-effect"),
            "negative": _lane(
                ("execution", "state-sequence", "negative-baseline",
                 "safe-equivalent"),
                ("ownership-check-missing", "safe-equivalent-missing"),
                "safe-equivalent"),
            "environment-gap": _lane(
                ("environment-gap",),
                ("device-or-simulator-unavailable", "lifecycle-not-comparable"),
                "environment-gap"),
        },
        {
            "variant_id": "mobile-webview-origin-bridge",
            "family": "origin-bridge-boundary",
            "axis": "webview-origin-ipc-bridge",
            "markers": ("webview", "origin", "bridge", "ipc", "javascript", "scheme"),
            "action_families": ("add-negative-control", "review-source-dataflow",
                                 "add-typed-effect", "replay-new-variant"),
            "positive": _lane(
                ("execution", "authorization", "typed-effect"),
                ("origin-not-accepted", "typed-effect-missing"),
                "typed-effect"),
            "negative": _lane(
                ("execution", "authorization", "negative-baseline",
                 "safe-equivalent"),
                ("origin-allowlist-missing", "bridge-safe-case-missing"),
                "safe-equivalent"),
            "environment-gap": _lane(
                ("environment-gap",),
                ("webview-harness-unavailable", "ipc-replay-inconclusive"),
                "environment-gap"),
        },
        {
            "variant_id": "mobile-storage-permission-lifecycle",
            "family": "storage-permission",
            "axis": "keychain-file-permission-lifecycle",
            "markers": ("keychain", "storage", "permission", "file", "credential", "lifecycle"),
            "action_families": ("add-negative-control", "trace-capability-transition",
                                 "replay-new-variant", "review-source-dataflow"),
            "positive": _lane(
                ("execution", "authorization", "typed-effect"),
                ("permission-boundary-holds", "typed-effect-missing"),
                "typed-effect"),
            "negative": _lane(
                ("execution", "authorization", "negative-baseline",
                 "safe-equivalent"),
                ("unauthorized-storage-case-missing", "safe-equivalent-missing"),
                "safe-equivalent"),
            "environment-gap": _lane(
                ("environment-gap",),
                ("device-storage-unavailable", "permission-replay-not-comparable"),
                "environment-gap"),
        },
    ),
    "native": (
        {
            "variant_id": "native-url-scheme-method-body",
            "family": "url-method-body",
            "axis": "url-scheme-selector-method-body",
            "markers": ("url", "scheme", "selector", "method", "command", "exec"),
            "action_families": ("review-source-dataflow", "add-typed-effect",
                                 "replay-new-variant", "review-followup"),
            "positive": _lane(
                ("execution", "entry-behavior", "typed-effect"),
                ("method-body-not-established", "typed-effect-missing"),
                "typed-effect"),
            "negative": _lane(
                ("execution", "negative-baseline", "safe-equivalent"),
                ("scheme-guard-not-observed", "safe-equivalent-missing"),
                "safe-equivalent"),
            "environment-gap": _lane(
                ("environment-gap",),
                ("native-runtime-unavailable", "method-body-tool-missing"),
                "environment-gap"),
        },
        {
            "variant_id": "native-webview-ipc-origin",
            "family": "webview-ipc-boundary",
            "axis": "origin-message-ipc-sink",
            "markers": ("webview", "ipc", "origin", "message", "bridge", "sink"),
            "action_families": ("add-negative-control", "review-source-dataflow",
                                 "add-typed-effect", "replay-new-variant"),
            "positive": _lane(
                ("execution", "authorization", "typed-effect"),
                ("ipc-boundary-not-crossed", "typed-effect-missing"),
                "typed-effect"),
            "negative": _lane(
                ("execution", "authorization", "negative-baseline",
                 "safe-equivalent"),
                ("origin-policy-missing", "safe-bridge-case-missing"),
                "safe-equivalent"),
            "environment-gap": _lane(
                ("environment-gap",),
                ("native-webview-harness-unavailable", "ipc-not-comparable"),
                "environment-gap"),
        },
        {
            "variant_id": "native-symbol-method-body-runtime",
            "family": "method-body-evidence",
            "axis": "symbol-reconstruction-instrumentation-runtime",
            "markers": ("symbol", "method", "body", "ghidra", "runtime", "binary"),
            "action_families": ("repair-environment", "review-source-dataflow",
                                 "replay-residual-variant", "replay-new-variant"),
            "positive": _lane(
                ("execution", "entry-behavior", "typed-effect"),
                ("method-body-evidence-missing", "typed-effect-missing"),
                "typed-effect"),
            "negative": _lane(
                ("execution", "negative-baseline", "safe-equivalent"),
                ("method-body-not-comparable", "safe-equivalent-missing"),
                "safe-equivalent"),
            "environment-gap": _lane(
                ("environment-gap",),
                ("ghidra-or-instrumentation-unavailable", "native-replay-inconclusive"),
                "environment-gap"),
        },
    ),
}


def _candidate_tokens(attack_class: Any = "", variants: Any = ()) -> set:
    values = [_text(attack_class, MAX_TEXT).lower()]
    if isinstance(variants, (str, bytes)):
        variants = [variants]
    values.extend(_text(value, MAX_TEXT).lower() for value in variants or [])
    tokens = set()
    for value in values:
        tokens.update(value.replace("_", "-").split())
        tokens.add(value)
    return {token for token in tokens if token}


def _variant_score(template: Mapping[str, Any], action: str,
                   tokens: set) -> tuple:
    score = 0
    markers = set(template.get("markers") or [])
    score += 3 * len(tokens & markers)
    if action in set(template.get("action_families") or []):
        score += 5
    if action in {"replay-new-variant", "replay-residual-variant",
                  "hold-for-new-evidence"}:
        score += 1
    return score, str(template.get("variant_id") or "")


def _normalized_template(template: Mapping[str, Any], lane: str
                         ) -> Dict[str, Any]:
    raw = template.get(lane) if isinstance(template.get(lane), Mapping) else {}
    variant_id = _text(template.get("variant_id"), MAX_TEXT)
    signals = [item for item in _bounded(
        raw.get("required_observations"), MAX_SIGNALS, MAX_TEXT)
               if item in OBSERVATION_SIGNALS]
    falsifiers = _bounded(raw.get("falsifiers"), MAX_FALSIFIERS, MAX_TEXT)
    return {
        "variant_id": variant_id,
        "family": _text(template.get("family"), MAX_TEXT),
        "axis": _text(template.get("axis"), MAX_TEXT),
        "lane": lane,
        "state_steps": list(_STATE_STEPS.get(variant_id, ()))[:MAX_STATE_STEPS],
        "required_observations": signals,
        "falsifiers": falsifiers,
        "expected_observation": _text(raw.get("expected_observation"), 48),
        "claim_status": CLAIM_STATUS,
    }


def build_surface_variant_plan(surface: Any = "", target_type: Any = "",
                               action: Any = "", attack_class: Any = "",
                               variants: Any = ()) -> Dict[str, Any]:
    """Build a deterministic three-lane plan for one research surface."""
    surface_value = _surface(surface, target_type)
    action_value = _text(action, 48).lower()
    if action_value not in GUIDANCE_ACTIONS:
        action_value = "continue-path-closure"
    templates = list(_LIBRARY.get(surface_value) or [])
    tokens = _candidate_tokens(attack_class, variants)
    ranked = sorted(templates,
                    key=lambda row: _variant_score(row, action_value, tokens),
                    reverse=True)
    if action_value in {"replay-new-variant", "replay-residual-variant",
                        "hold-for-new-evidence"}:
        selected_limit = 2
    else:
        selected_limit = 1
    selected = ranked[:selected_limit]
    variant_rows: List[Dict[str, Any]] = []
    lanes: List[Dict[str, Any]] = []
    for template in selected:
        variant_rows.append({
            "variant_id": _text(template.get("variant_id"), MAX_TEXT),
            "family": _text(template.get("family"), MAX_TEXT),
            "axis": _text(template.get("axis"), MAX_TEXT),
            "claim_status": CLAIM_STATUS,
        })
        for lane in LANES:
            lanes.append(_normalized_template(template, lane))
    lane_counts = Counter(row.get("lane") for row in lanes)
    return {
        "schema_version": SURFACE_VARIANT_SCHEMA_VERSION,
        "surface": surface_value,
        "action": action_value,
        "selected_variants": variant_rows[:MAX_VARIANTS],
        "lanes": lanes[:MAX_LANES],
        "summary": {
            "variant_count": len(variant_rows[:MAX_VARIANTS]),
            "lane_count": len(lanes[:MAX_LANES]),
            "lane_counts": dict(sorted(lane_counts.items())),
            "claim_status": CLAIM_STATUS,
        },
        "claim_status": CLAIM_STATUS,
    }


def normalize_surface_variant_plan(raw: Any) -> Dict[str, Any]:
    """Normalize a plan loaded from strategy/planner artifacts."""
    if not isinstance(raw, Mapping) or raw.get(
            "schema_version") != SURFACE_VARIANT_SCHEMA_VERSION:
        return {}
    surface_value = _surface(raw.get("surface"))
    if not surface_value:
        return {}
    action_value = _text(raw.get("action"), 48).lower()
    if action_value not in GUIDANCE_ACTIONS:
        action_value = "continue-path-closure"
    allowed = {
        _text(row.get("variant_id"), MAX_TEXT): row
        for row in _LIBRARY.get(surface_value, [])
        if _text(row.get("variant_id"), MAX_TEXT)
    }
    selected = []
    seen = set()
    for row in raw.get("selected_variants") or []:
        if not isinstance(row, Mapping):
            continue
        variant_id = _text(row.get("variant_id"), MAX_TEXT)
        template = allowed.get(variant_id)
        if not template or variant_id in seen:
            continue
        seen.add(variant_id)
        selected.append({
            "variant_id": variant_id,
            "family": _text(template.get("family"), MAX_TEXT),
            "axis": _text(template.get("axis"), MAX_TEXT),
            "claim_status": CLAIM_STATUS,
        })
        if len(selected) >= MAX_VARIANTS:
            break
    selected_ids = {row["variant_id"] for row in selected}
    lanes = []
    for row in raw.get("lanes") or []:
        if not isinstance(row, Mapping):
            continue
        variant_id = _text(row.get("variant_id"), MAX_TEXT)
        lane = _text(row.get("lane"), 24)
        if variant_id not in selected_ids or lane not in LANES:
            continue
        template = allowed[variant_id]
        canonical = _normalized_template(template, lane)
        lanes.append(canonical)
        if len(lanes) >= MAX_LANES:
            break
    # A malformed but otherwise trusted-looking artifact must not create a
    # one-sided plan.  Rebuild from its bounded identity when any selected
    # variant lacks one of the three lanes.
    expected_pairs = {(row["variant_id"], lane)
                      for row in selected for lane in LANES}
    actual_pairs = {(row.get("variant_id"), row.get("lane")) for row in lanes}
    if expected_pairs != actual_pairs:
        rebuilt = build_surface_variant_plan(
            surface_value, action=action_value,
            variants=[row["variant_id"] for row in selected])
        if selected:
            rebuilt["selected_variants"] = selected
        return rebuilt
    counts = Counter(row.get("lane") for row in lanes)
    return {
        "schema_version": SURFACE_VARIANT_SCHEMA_VERSION,
        "surface": surface_value,
        "action": action_value,
        "selected_variants": selected,
        "lanes": lanes,
        "summary": {
            "variant_count": len(selected),
            "lane_count": len(lanes),
            "lane_counts": dict(sorted(counts.items())),
            "claim_status": CLAIM_STATUS,
        },
        "claim_status": CLAIM_STATUS,
    }


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def _fixture_digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def normalize_variant_fixture_context(raw: Any) -> Dict[str, Any]:
    """Return one allowlisted, credential-free fixture/state context.

    The caller may pass a row loaded from an artifact, so the row is rebuilt
    from the deterministic template library instead of trusting its free-form
    observations, state steps, or falsifiers.
    """
    if not isinstance(raw, Mapping):
        return {}
    surface_value = _surface(raw.get("surface"), raw.get("target_type"))
    variant_id = _text(raw.get("variant_id"), MAX_TEXT)
    lane = _text(raw.get("lane"), 24)
    template = next(
        (row for row in _LIBRARY.get(surface_value, [])
         if _text(row.get("variant_id"), MAX_TEXT) == variant_id),
        None,
    )
    if template is None or lane not in LANES:
        return {}
    canonical = _normalized_template(template, lane)
    fixture_key = _text(raw.get("fixture_key"), 80)
    if not (fixture_key.startswith("vf-")
            and len(fixture_key) == 23
            and all(char in "0123456789abcdef" for char in fixture_key[3:])):
        fixture_key = "vf-" + _fixture_digest({
            "surface": surface_value,
            "variant_id": variant_id,
            "lane": lane,
        })[:20]
    return {
        "fixture_key": fixture_key,
        "surface": surface_value,
        "variant_id": canonical["variant_id"],
        "family": canonical["family"],
        "axis": canonical["axis"],
        "lane": canonical["lane"],
        "state_steps": list(canonical["state_steps"]),
        "required_observations": list(canonical["required_observations"]),
        "falsifiers": list(canonical["falsifiers"]),
        "expected_observation": canonical["expected_observation"],
        "execution_mode": "gap-check" if lane == "environment-gap" else "probe",
        "claim_status": CLAIM_STATUS,
    }


def build_variant_fixture_plan(surface_plan: Any,
                               candidate_id: Any = "") -> Dict[str, Any]:
    """Expand a surface plan into bounded lane-specific fixture contexts.

    This is still a plan: ``fixture_key`` identifies the intended experiment,
    while the runner must supply real observations before any S4 summary can
    use them.  Each selected variant retains all three lanes.
    """
    plan = normalize_surface_variant_plan(surface_plan)
    if not plan:
        return {}
    candidate_value = _text(candidate_id, 120)
    fixtures: List[Dict[str, Any]] = []
    for row in plan.get("lanes") or []:
        if not isinstance(row, Mapping):
            continue
        seed = {
            "candidate_id": candidate_value,
            "surface": plan.get("surface", ""),
            "variant_id": row.get("variant_id", ""),
            "lane": row.get("lane", ""),
        }
        context = normalize_variant_fixture_context({
            **dict(row),
            "surface": plan.get("surface", ""),
            "fixture_key": "vf-" + _fixture_digest(seed)[:20],
        })
        if context:
            fixtures.append(context)
        if len(fixtures) >= MAX_LANES:
            break
    counts = Counter(row.get("lane") for row in fixtures)
    return {
        "schema_version": VARIANT_FIXTURE_SCHEMA_VERSION,
        "surface": plan.get("surface", ""),
        "action": plan.get("action", ""),
        "fixtures": fixtures,
        "summary": {
            "fixture_count": len(fixtures),
            "lane_counts": dict(sorted(counts.items())),
            "claim_status": CLAIM_STATUS,
        },
        "claim_status": CLAIM_STATUS,
    }


def normalize_variant_fixture_plan(raw: Any,
                                   surface_plan: Any = None,
                                   candidate_id: Any = "") -> Dict[str, Any]:
    """Rebuild a fixture plan from its trusted surface-plan identity.

    ``surface_plan`` is preferred.  The fallback accepts a nested surface plan
    for callers loading a planner artifact, but never trusts raw fixture rows.
    """
    source = surface_plan
    if source is None and isinstance(raw, Mapping):
        source = raw.get("surface_variant_plan")
        if source is None and raw.get("schema_version") == SURFACE_VARIANT_SCHEMA_VERSION:
            source = raw
    return build_variant_fixture_plan(source, candidate_id)
