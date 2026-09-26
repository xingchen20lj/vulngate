"""Candidate intake, research guidance, and bounded pool preparation."""

from __future__ import annotations

# Shared scheduler state is centralized in common.py; this keeps phase imports
# explicit at the package boundary while retaining a small compatibility API.
# ruff: noqa: F403,F405
from .common import *
from .common import _COLOCATION, _safe_delta, _safe_weight

def _threat_model_snapshot(model: Any, path_limit: int = 24,
                           boundary_limit: int = 16) -> Dict[str, Any]:
    """Keep schedule artifacts bounded while retaining attacker-path context."""
    if not isinstance(model, dict):
        return {}
    paths = [row for row in (model.get("attack_paths") or [])
             if isinstance(row, dict)]
    paths.sort(key=lambda row: (
        -int(row.get("research_priority") or 0),
        str(row.get("path_id") or ""),
    ))
    unresolved = model.get("unresolved")
    if not isinstance(unresolved, dict):
        unresolved = {}
    return {
        "schema_version": str(model.get("schema_version") or ""),
        "summary": dict(model.get("summary") or {})
        if isinstance(model.get("summary"), dict) else {},
        "boundaries": [row for row in (model.get("boundaries") or [])
                       if isinstance(row, dict)][:boundary_limit],
        "attack_paths": paths[:path_limit],
        "unresolved": {
            "unmapped_entries": [row for row in
                                  (unresolved.get("unmapped_entries") or [])
                                  if isinstance(row, dict)][:path_limit],
            "unmapped_sinks": [row for row in
                                (unresolved.get("unmapped_sinks") or [])
                                if isinstance(row, dict)][:path_limit],
        },
        "claim_status": "not-a-finding",
    }


def _research_strategy_snapshot(strategy: Any, item_limit: int = 32
                                ) -> Dict[str, Any]:
    """Keep strategy context bounded in a schedule and model prompt."""
    normalized = normalize_research_strategy(strategy)
    if not normalized:
        return {}
    normalized["items"] = list(normalized.get("items") or [])[
        :max(0, int(item_limit))]
    return normalized


# ---------------------------------------------------------------------------
# candidate -> coverage linkage
# ---------------------------------------------------------------------------

def candidate_locations(candidate: Dict[str, Any]) -> List[Tuple[str, int]]:
    """``[(file, line), ...]`` from the candidate's ``code_location`` field."""
    raw = candidate.get("code_location") or candidate.get("code_locations") or []
    if isinstance(raw, str):
        raw = [raw]
    out: List[Tuple[str, int]] = []
    for item in raw:
        match = _COLOCATION.match(str(item).strip())
        if not match:
            continue
        out.append((match.group("file"), int(match.group("line"))))
    return out


def candidate_text(candidate: Dict[str, Any]) -> str:
    """The candidate's own words, for category classification."""
    parts: List[str] = []
    for key in ("surface", "logic", "hypothesis", "input_shape", "entry",
                "poc_class", "vuln_class", "rule_label"):
        value = candidate.get(key)
        if isinstance(value, str):
            parts.append(value)
    for key in ("chain_components", "novelty_keywords", "mechanisms", "tags"):
        value = candidate.get(key)
        if isinstance(value, (list, tuple)):
            parts.extend(str(x) for x in value)
    return " ".join(parts).lower()


def candidate_category(candidate: Dict[str, Any]) -> str:
    """Coarse bucket used for the stratified quota (spec §13.3)."""
    explicit = str(candidate.get("category") or candidate.get("vuln_class") or "").lower()
    if explicit in CATEGORY_ORDER:
        return explicit
    text = candidate_text(candidate)
    for name, pattern in CATEGORY_RULES:
        if re.search(pattern, text):
            return name
    return CATEGORY_FALLBACK


def _candidate_intake_identity(candidate: Dict[str, Any]) -> str:
    """Stable, non-secret identity used only for an intake window/digest."""
    candidate_id = str(candidate.get("candidate_id") or "").strip()
    if candidate_id:
        return candidate_id
    material = {
        key: candidate.get(key) for key in (
            "surface", "entry", "input_shape", "logic", "hypothesis",
            "code_location", "flow_id", "sink_id", "control_id",
        )
    }
    encoded = json.dumps(material, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), default=str).encode("utf-8")
    return "anonymous-" + hashlib.sha256(encoded).hexdigest()[:20]


def bounded_candidate_intake(
        candidates: Sequence[Dict[str, Any]], slots: int,
        round_no: int = 0, window_size: Optional[int] = None,
        pinned: Sequence[str] = (), priority_ids: Sequence[str] = (),
        ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Return a deterministic, category-stratified active candidate window.

    Candidate discovery can legitimately be broad; executing and fully scoring
    every static lead in one round is neither an audit budget nor an evidence
    claim.  This function preserves the complete upstream pool, selects a
    finite rotating slice for the current round, and emits enough metadata to
    prove what remains queued.  It does not mark intake-deferred candidates as
    excluded, reviewed, or non-findings.

    Each category receives a fair share of the window.  Within that category,
    the start offset advances by its allocation on every round, so one large
    producer cannot permanently starve later candidates behind a fixed prefix.
    """
    pool = [candidate for candidate in candidates if isinstance(candidate, dict)]
    requested_slots = max(1, int(slots or DEFAULT_SLOTS))
    if window_size is None:
        window_size = max(DEFAULT_CANDIDATE_INTAKE_MINIMUM,
                          requested_slots * CANDIDATE_INTAKE_MULTIPLIER)
        window_size = min(MAX_CANDIDATE_INTAKE_WINDOW, window_size)
    window = max(1, int(window_size))

    groups: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
    digest_sum = 0
    digest_xor = 0
    digest_modulus = 1 << 256
    for candidate in pool:
        category = candidate_category(candidate)
        identity = _candidate_intake_identity(candidate)
        groups.setdefault(category, []).append((identity, candidate))
        row_hash = int.from_bytes(hashlib.sha256(
            (category + "\0" + identity).encode("utf-8")).digest(), "big")
        digest_sum = (digest_sum + row_hash) % digest_modulus
        digest_xor ^= row_hash
    categories = sorted(groups)
    for category in categories:
        groups[category].sort(key=lambda row: row[0])
    # A commutative multiset digest stays independent of input ordering while
    # avoiding a second 129k-row allocation, sort, and giant JSON serialization.
    digest_material = "%d:%064x:%064x" % (len(pool), digest_sum, digest_xor)
    source_digest = "pool-" + hashlib.sha256(
        digest_material.encode("ascii")).hexdigest()[:24]

    capacity = min(window, len(pool))
    allocations = {category: 0 for category in categories}
    # Round-robin allocation, not a top-K prefix.  The loop is bounded by the
    # small active window, never by the full (possibly 80k+) candidate pool.
    while sum(allocations.values()) < capacity:
        advanced = False
        for category in categories:
            if sum(allocations.values()) >= capacity:
                break
            if allocations[category] >= len(groups[category]):
                continue
            allocations[category] += 1
            advanced = True
        if not advanced:
            break

    round_index = max(0, int(round_no) - 1)
    active: List[Dict[str, Any]] = []
    category_meta: Dict[str, Dict[str, int]] = {}
    for category in categories:
        rows = groups[category]
        allocation = allocations[category]
        start = ((round_index * allocation) % len(rows)) if rows and allocation else 0
        for offset in range(allocation):
            active.append(rows[(start + offset) % len(rows)][1])
        category_meta[category] = {
            "total": len(rows), "active": allocation,
            "deferred_intake": max(0, len(rows) - allocation),
            "offset": start,
        }

    # Runtime-backed candidates (for example fuzz reproducers) must reach the
    # scheduler even if a broad static category happened to fill the window.
    # They still count against both the intake window and the later round slot
    # budget; this is priority, not a way to bypass a budget.
    priority_ids = normalize_candidate_ids(priority_ids)
    wanted_ids = ({str(candidate_id) for candidate_id in pinned if candidate_id}
                  | set(priority_ids))
    by_id = {}
    if wanted_ids:
        for candidate in pool:
            candidate_id = str(candidate.get("candidate_id") or "")
            if candidate_id in wanted_ids:
                by_id[candidate_id] = candidate
    pinned_candidates = []
    seen_pinned = set()
    for candidate_id in pinned:
        candidate_id = str(candidate_id)
        if candidate_id in seen_pinned or candidate_id not in by_id:
            continue
        seen_pinned.add(candidate_id)
        pinned_candidates.append(by_id[candidate_id])
    selected_pinned = pinned_candidates[:capacity]
    selected_ids = {str(candidate.get("candidate_id") or "")
                    for candidate in selected_pinned}
    priority_candidates = []
    seen_priority = set()
    for candidate_id in priority_ids:
        candidate = by_id.get(candidate_id)
        if (candidate is None or candidate_id in selected_ids
                or candidate_id in seen_priority):
            continue
        seen_priority.add(candidate_id)
        priority_candidates.append(candidate)
    selected_priority = priority_candidates[
        :max(0, capacity - len(selected_pinned))]
    selected_ids.update(str(candidate.get("candidate_id") or "")
                        for candidate in selected_priority)
    if selected_pinned or selected_priority:
        remaining = [candidate for candidate in active
                     if str(candidate.get("candidate_id") or "") not in selected_ids]
        active = (selected_pinned + selected_priority +
                  remaining[:max(0, capacity - len(selected_pinned)
                                 - len(selected_priority))])
    active_by_category = Counter(candidate_category(candidate) for candidate in active)
    for category, detail in category_meta.items():
        detail["active"] = int(active_by_category.get(category, 0))
        detail["deferred_intake"] = max(0, detail["total"] - detail["active"])

    active_rows = [
        {"candidate_id": _candidate_intake_identity(candidate),
         "category": candidate_category(candidate)}
        for candidate in active
    ]
    active_rows.sort(key=lambda row: (row["category"], row["candidate_id"]))
    active_digest = "active-" + hashlib.sha256(json.dumps(
        active_rows, ensure_ascii=False, sort_keys=True,
        separators=(",", ":")).encode("utf-8")).hexdigest()[:24]
    metadata = {
        "schema_version": CANDIDATE_INTAKE_SCHEMA_VERSION,
        "round": int(round_no),
        "slots": requested_slots,
        "window_limit": window,
        "pool_candidates": len(pool),
        "active_candidates": len(active),
        "deferred_intake_candidates": max(0, len(pool) - len(active)),
        "deferred_intake_status": "not-scheduled-yet",
        "pool_digest": source_digest,
        "active_digest": active_digest,
        "active_candidate_ids": [row["candidate_id"] for row in active_rows],
        "pinned_candidate_ids": [str(candidate.get("candidate_id") or "")
                                 for candidate in selected_pinned],
        "requested_priority_candidate_ids": priority_ids,
        "priority_candidate_ids": [str(candidate.get("candidate_id") or "")
                                   for candidate in selected_priority],
        "unmatched_priority_candidate_ids": [
            candidate_id for candidate_id in priority_ids
            if candidate_id not in by_id],
        "categories": category_meta,
        "claim_status": "not-a-finding",
    }
    return active, metadata


def candidate_research_surface(candidate: Dict[str, Any]) -> str:
    """Return an explicit benchmark surface, never infer one from prose.

    Candidate ``surface`` is historically free-form (for example,
    ``"cross-tenant authz"``), so substring matching would silently apply
    benchmark feedback to unrelated candidates.  Only the explicit
    ``research_surface``/``target_type`` fields or an exact surface value are
    eligible for surface-aware scheduling.
    """
    for key in ("research_surface", "surface"):
        value = str(candidate.get(key) or "").strip().lower()
        if value in RESEARCH_SURFACES:
            return value
    target_type = str(candidate.get("target_type") or "").strip().lower()
    return RESEARCH_SURFACE_TARGET_TYPES.get(target_type, "")


def _benchmark_surface_guidance(candidate: Dict[str, Any],
                               benchmark_feedback: Dict[str, Any]
                               ) -> Dict[str, Any]:
    """Find bounded guidance for a candidate's explicit research surface."""
    surface = candidate_research_surface(candidate)
    if not surface:
        return {}
    for item in benchmark_feedback.get("surface_guidance") or []:
        if isinstance(item, dict) and item.get("surface") == surface:
            try:
                priority_delta = int(item.get("priority_delta") or 0)
            except (TypeError, ValueError):
                priority_delta = 0
            return {
                "surface": surface,
                "priority_delta": priority_delta,
                "metric_snapshot": dict(item.get("metric_snapshot") or {}),
                "strategy_tags": list(item.get("strategy_tags") or [])[:12],
                "required_observations": list(
                    item.get("required_observations") or [])[:12],
                "falsifiers": list(item.get("falsifiers") or [])[:12],
                "claim_status": "not-a-finding",
            }
    return {}


def _candidate_portfolio_values(candidate: Dict[str, Any]) -> Dict[str, set]:
    """Return exact, explicit metadata eligible for portfolio matching."""
    surface = candidate_research_surface(candidate)
    target_type = str(candidate.get("target_type") or "").strip().lower()
    attack_class = str(candidate.get("attack_class") or
                       candidate.get("vuln_class") or
                       candidate.get("category") or "").strip().lower()
    precondition = str(candidate.get("precondition_class") or
                       candidate.get("precondition_tier") or
                       candidate.get("precondition_tier_hint") or "").strip().lower()
    if precondition == "0":
        precondition = "default"
    variants = set()
    for value in ([candidate.get("variant")] +
                  list(candidate.get("variants") or []) +
                  list(candidate.get("fix_variants") or []) +
                  list(candidate.get("patch_variants") or [])):
        text = str(value or "").strip().lower()
        if text:
            variants.add(text)
    return {
        "research_surface": {surface} if surface else set(),
        "target_type": {target_type} if target_type else set(),
        "attack_class": {attack_class} if attack_class else set(),
        "precondition_class": {precondition} if precondition else set(),
        "variant": variants,
    }


def _portfolio_probe_guidance(candidate: Dict[str, Any],
                              portfolio: Dict[str, Any]) -> Dict[str, Any]:
    """Find a bounded exact metadata match for a pending portfolio probe.

    A free-form surface or a single shared word is never enough.  The match is
    either the stable research key or at least two explicit dimensions,
    including a variant when one is present.  This keeps project-level memory
    useful without turning broad labels into an authorization or impact claim.
    """
    if not isinstance(portfolio, dict):
        return {}
    probes = [item for item in portfolio.get("next_probes") or []
              if isinstance(item, dict)]
    if not probes:
        return {}
    candidate_key = research_key(candidate)
    values = _candidate_portfolio_values(candidate)
    matches: List[Tuple[int, int, str, Dict[str, Any]]] = []
    for probe in probes:
        probe_key = str(probe.get("research_key") or "")
        if not probe_key:
            continue
        probe_priority = min(5, _safe_weight(probe.get("priority")))
        if probe_key == candidate_key:
            matches.append((2, probe_priority, probe_key, probe))
            continue
        probe_values = {
            "research_surface": {str(probe.get("research_surface") or "").lower()},
            "target_type": {str(probe.get("target_type") or "").lower()},
            "attack_class": {str(probe.get("attack_class") or "").lower()},
            "precondition_class": {str(probe.get("precondition_class") or "").lower()},
            "variant": {str(value).strip().lower()
                        for value in (probe.get("variant") or [])
                        if str(value).strip()},
        }
        dimensions = sum(bool(values[name] and probe_values[name] and
                              values[name] & probe_values[name])
                         for name in values)
        variant_match = bool(values["variant"] & probe_values["variant"])
        if dimensions >= 2 and (variant_match or not probe_values["variant"]):
            matches.append((1, probe_priority, probe_key, probe))
    if not matches:
        return {}
    match_kind, priority, probe_key, probe = sorted(
        matches, key=lambda item: (-item[0], -item[1], item[2]))[0]
    return {
        "match_kind": "research-key" if match_kind == 2 else "explicit-dimensions",
        "research_key": probe_key,
        "priority": max(0, min(5, priority)),
        "state": str(probe.get("state") or ""),
        "claim_status": "not-a-finding",
    }


def _research_strategy_guidance(candidate: Dict[str, Any],
                                strategy: Dict[str, Any],
                                link: "LinkedRegions") -> Dict[str, Any]:
    """Match a candidate to one bounded strategy item by explicit evidence.

    Exact research-key/candidate matches are strongest.  Static path items may
    match through a persisted flow, or through both its entry and sink; a
    single shared label is never enough to trigger a boost.
    """
    if not isinstance(strategy, dict):
        return {}
    items = [item for item in strategy.get("items") or []
             if isinstance(item, dict)]
    if not items:
        return {}
    candidate_key = research_key(candidate)
    candidate_id = str(candidate.get("candidate_id") or "")
    flow_ids = {str(flow.get("flow_id")) for flow in link.all_flows()}
    entry_ids = {str(entry.get("entry_id")) for entry in link.entries}
    sink_ids = {str(sink.get("sink_id")) for sink in link.sinks}
    matches: List[Tuple[int, int, str, Dict[str, Any]]] = []
    for item in items:
        strength = 0
        match_kind = ""
        if candidate_key and str(item.get("research_key") or "") == candidate_key:
            strength, match_kind = 4, "research-key"
        elif candidate_id and str(item.get("candidate_id") or "") == candidate_id:
            strength, match_kind = 4, "candidate-id"
        elif str(item.get("flow_id") or "") in flow_ids:
            strength, match_kind = 3, "flow"
        elif (str(item.get("entry_id") or "") in entry_ids and
              str(item.get("sink_id") or "") in sink_ids):
            strength, match_kind = 2, "entry-sink"
        if not strength:
            continue
        matches.append((
            strength,
            min(5, _safe_weight(item.get("priority"))),
            str(item.get("strategy_id") or ""),
            dict(item, _match_kind=match_kind),
        ))
    if not matches:
        return {}
    _strength, priority, _strategy_id, item = sorted(
        matches, key=lambda value: (-value[0], -value[1], value[2]))[0]
    raw_guidance = item.get("guidance") or {}
    raw_action = str(raw_guidance.get(
        "next_action") or "continue-path-closure")
    guidance = {
        "next_action": (raw_action if raw_action in STRATEGY_GUIDANCE_ACTIONS
                         else "continue-path-closure"),
        "priority_delta": min(3, _safe_weight(
            raw_guidance.get("priority_delta") or 0)),
        "replacement_recommended": bool(
            raw_guidance.get("replacement_recommended")),
        "reason_codes": list(raw_guidance.get("reason_codes") or [])[:6],
        "sources": list(raw_guidance.get("sources") or [])[:4],
        "variant_gaps": list(raw_guidance.get("variant_gaps") or [])[:8],
        "review_status": str(raw_guidance.get("review_status") or "")[:32],
        "claim_status": "not-a-finding",
    }
    variant_plan = normalize_surface_variant_plan(
        raw_guidance.get("surface_variant_plan"))
    if variant_plan:
        guidance["surface_variant_plan"] = {
            "schema_version": variant_plan.get("schema_version"),
            "surface": variant_plan.get("surface"),
            "action": variant_plan.get("action"),
            "selected_variants": [
                str(row.get("variant_id"))
                for row in variant_plan.get("selected_variants") or []
                if isinstance(row, dict) and row.get("variant_id")
            ][:3],
            "lanes": [{
                "variant_id": row.get("variant_id"),
                "lane": row.get("lane"),
                "required_observations": list(
                    row.get("required_observations") or [])[:6],
                "falsifiers": list(row.get("falsifiers") or [])[:5],
            } for row in variant_plan.get("lanes") or []
              if isinstance(row, dict)][:6],
            "claim_status": "not-a-finding",
        }
    return {
        "match_kind": item.get("_match_kind", "path"),
        "strategy_id": str(item.get("strategy_id") or ""),
        "kind": str(item.get("kind") or ""),
        "state": str(item.get("state") or ""),
        "priority": priority,
        "reason_codes": list(item.get("reason_codes") or [])[:4],
        "observation": {
            "status": str((item.get("observation") or {}).get(
                "status") or "unobserved"),
            "current_status": str((item.get("observation") or {}).get(
                "current_status") or "unobserved"),
            "information_gain": min(5, max(0, int(
                (item.get("observation") or {}).get("information_gain") or 0))),
            "missing_observations": list(
                (item.get("observation") or {}).get(
                    "missing_observations") or [])[:8],
            "claim_status": "not-a-finding",
        },
        "guidance": guidance,
        "claim_status": "not-a-finding",
    }


def _research_agenda_guidance(candidate: Dict[str, Any],
                              agenda: Dict[str, Any]) -> Dict[str, Any]:
    """Match one candidate to the bounded active research agenda.

    Exact research-key and candidate-id matches are accepted.  A broad
    surface/attack label is intentionally not enough: the agenda is a budget
    signal, not a free-form priority hint.
    """
    if not isinstance(agenda, dict):
        return {}
    items = [item for item in agenda.get("items") or []
             if isinstance(item, dict)]
    if not items:
        return {}
    candidate_key = research_key(candidate)
    candidate_id = str(candidate.get("candidate_id") or "")
    matches: List[Tuple[int, int, str, Dict[str, Any]]] = []
    for item in items:
        strength = 0
        match_kind = ""
        if candidate_key and str(item.get("research_key") or "") == candidate_key:
            strength, match_kind = 3, "research-key"
        elif candidate_id and str(item.get("candidate_id") or "") == candidate_id:
            strength, match_kind = 2, "candidate-id"
        if not strength:
            continue
        matches.append((
            strength,
            1 if item.get("selection_status") == "selected" else 0,
            str(item.get("agenda_id") or ""),
            dict(item, _match_kind=match_kind),
        ))
    if not matches:
        return {}
    _, _, _, item = sorted(
        matches, key=lambda row: (-row[0], -row[1], row[2]))[0]
    return {
        "agenda_id": str(item.get("agenda_id") or ""),
        "strategy_id": str(item.get("strategy_id") or ""),
        "selection_status": str(item.get("selection_status") or ""),
        "rank": _safe_weight(item.get("rank")),
        "priority_score": _safe_weight(item.get("priority_score")),
        "expected_information_gain": _safe_weight(
            item.get("expected_information_gain")),
        "estimated_cost": _safe_weight(item.get("estimated_cost")),
        "action": str(item.get("action") or ""),
        "last_outcome": str(item.get("last_outcome") or ""),
        "outcome_round": _safe_weight(item.get("outcome_round")),
        "outcome_information_gain": _safe_weight(
            item.get("outcome_information_gain")),
        "outcome_observed_signals": [
            str(value) for value in item.get("outcome_observed_signals", [])[:8]
            if str(value)
        ],
        "outcome_consecutive_no_information": _safe_weight(
            item.get("outcome_consecutive_no_information")),
        "budget_recommendation": str(
            item.get("budget_recommendation") or ""),
        "budget_priority_delta": _safe_delta(
            item.get("budget_priority_delta")),
        "budget_cap_hint": _safe_weight(item.get("budget_cap_hint")),
        "match_kind": str(item.get("_match_kind") or ""),
        "claim_status": "not-a-finding",
    }
