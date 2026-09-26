"""Candidate linkage and evidence-weighted scoring."""

from __future__ import annotations

# Shared scheduler state is centralized in common.py; this keeps phase imports
# explicit at the package boundary while retaining a small compatibility API.
# ruff: noqa: F403,F405
from .common import *
from .intake import *
from .common import _COLOCATION, _safe_weight
from .intake import (_benchmark_surface_guidance, _candidate_portfolio_values,
                     _portfolio_probe_guidance, _research_agenda_guidance,
                     _research_strategy_guidance)

@dataclass
class LinkedRegions:
    """Which persisted regions a candidate points at, and how.

    Linkage is **symbol-tight**: a candidate's ``file:line`` is resolved to its
    innermost symbol (spec §4.2, built by PR2) and the region must belong to one
    of those symbols.  A wide line window would be cheaper, but on a dense file
    it links every sink in the neighbourhood -- in this repository that turned a
    single candidate into 2 380 linked flows and saturated every factor to 1.0,
    which is exactly the "Top-K by danger" behaviour the scheduler replaces.

    The line window survives only as a fallback for locations whose file has no
    symbol index, so an unindexed file is still scored rather than skipped.
    """

    symbols: set = field(default_factory=set)
    sinks: List[Dict[str, Any]] = field(default_factory=list)
    entries: List[Dict[str, Any]] = field(default_factory=list)
    #: flows where the candidate's code is the destination (the sink end)
    flows_reaching: List[Dict[str, Any]] = field(default_factory=list)
    #: flows that merely pass through the candidate's code
    flows_on_path: List[Dict[str, Any]] = field(default_factory=list)
    locations: List[Tuple[str, int]] = field(default_factory=list)
    fallback_used: bool = False

    def all_flows(self) -> List[Dict[str, Any]]:
        seen: Dict[str, Dict[str, Any]] = {}
        for flow in self.flows_reaching + self.flows_on_path:
            seen.setdefault(str(flow.get("flow_id")), flow)
        return [seen[key] for key in sorted(seen)]


def _symbols_at(ctx: ScheduleContext,
                locations: Sequence[Tuple[str, int]]) -> Tuple[set, bool]:
    """Innermost symbols owning ``locations``; second value = any file indexed.

    "Innermost" follows the call graph's own attribution rule (PR2): a class and
    its method both contain the line, but only the method *owns* it.  Linking to
    every enclosing declaration would make the class a hub, and every flow
    through any of its methods would then look like it reaches the candidate --
    the same saturation that motivated symbol-tight linkage in the first place.
    """
    names: set = set()
    resolved = False
    for file, line in locations:
        enclosing: List[Tuple[int, int, str]] = []
        for symbol in ctx.symbols_by_file().get(file, ()):
            try:
                start = int(symbol.get("start_line") or 0)
                end = int(symbol.get("end_line") or 0)
            except (TypeError, ValueError):
                continue
            resolved = True
            if start <= line <= end:
                enclosing.append((end - start, start,
                                  str(symbol.get("symbol_id"))))
        if enclosing:
            enclosing.sort()  # smallest range, then earliest start, then id
            names.add(enclosing[0][2])
    return names, resolved


def linked_regions(candidate: Dict[str, Any],
                   ctx: ScheduleContext) -> LinkedRegions:
    """Resolve a candidate to symbols, sinks, entries and flows.

    Every lookup goes through a memoised index rather than a scan of the whole
    collection, so linking a candidate costs what it actually touches instead of
    ``len(sinks) + len(entries) + len(flows)``.
    """
    locations = candidate_locations(candidate)
    link = LinkedRegions(locations=list(locations))
    if not locations:
        return link
    link.symbols, resolved = _symbols_at(ctx, locations)
    if not link.symbols and not resolved:
        # No symbol index for these files: fall back to the coverage window so
        # the candidate is still linked to something rather than scored blind.
        link.fallback_used = True
        fallback_sinks: Dict[str, Dict[str, Any]] = {}
        fallback_entries: Dict[str, Dict[str, Any]] = {}
        for file, line in locations:
            for sink in ctx.sinks_by_file().get(file, ()):
                if abs(int(sink.get("line") or 0) - line) <= LINK_FALLBACK_WINDOW:
                    fallback_sinks.setdefault(str(sink.get("sink_id")), sink)
            for entry in ctx.entries_by_file().get(file, ()):
                if abs(int(entry.get("line") or 0) - line) <= LINK_FALLBACK_WINDOW:
                    fallback_entries.setdefault(str(entry.get("entry_id")), entry)
        link.sinks = [fallback_sinks[key] for key in sorted(fallback_sinks)]
        link.entries = [fallback_entries[key] for key in sorted(fallback_entries)]
    else:
        by_sink: Dict[str, Dict[str, Any]] = {}
        for symbol_id in sorted(link.symbols):
            for sink in ctx.sinks_by_symbol().get(symbol_id, ()):
                by_sink.setdefault(str(sink.get("sink_id")), sink)
        # A sink may sit on the candidate's exact line without being bound to a
        # symbol (the binding step can miss), so both routes are kept.
        for file, line in locations:
            for sink in ctx.sinks_by_file().get(file, ()):
                if int(sink.get("line") or 0) == line:
                    by_sink.setdefault(str(sink.get("sink_id")), sink)
        link.sinks = [by_sink[key] for key in sorted(by_sink)]

        by_entry: Dict[str, Dict[str, Any]] = {}
        for symbol_id in sorted(link.symbols):
            for entry in ctx.entries_by_symbol().get(symbol_id, ()):
                by_entry.setdefault(str(entry.get("entry_id")), entry)
        link.entries = [by_entry[key] for key in sorted(by_entry)]

    sink_ids = {str(s.get("sink_id")) for s in link.sinks}
    related: Dict[str, Dict[str, Any]] = {}
    for sink_id in sorted(sink_ids):
        for flow in ctx.flows_by_sink().get(sink_id, ()):
            related.setdefault(str(flow.get("flow_id")), flow)
    for symbol_id in sorted(link.symbols):
        for flow in ctx.flows_by_symbol().get(symbol_id, ()):
            related.setdefault(str(flow.get("flow_id")), flow)
    for flow_id in sorted(related):
        flow = related[flow_id]
        path = [str(x) for x in flow.get("path") or []]
        # Destination = the candidate's code is where the flow ends (or is the
        # sink it feeds).  Anything else reached through one of its symbols is a
        # link in the chain.
        if str(flow.get("sink_id")) in sink_ids or (path and path[-1] in link.symbols):
            link.flows_reaching.append(flow)
        else:
            link.flows_on_path.append(flow)
    return link


def candidate_sinks(candidate: Dict[str, Any],
                    ctx: ScheduleContext) -> List[Dict[str, Any]]:
    """Sinks the candidate points at."""
    return linked_regions(candidate, ctx).sinks


def candidate_entries(candidate: Dict[str, Any],
                      ctx: ScheduleContext) -> List[Dict[str, Any]]:
    """Entries the candidate points at."""
    return linked_regions(candidate, ctx).entries


def candidate_flows(candidate: Dict[str, Any],
                    ctx: ScheduleContext) -> List[Dict[str, Any]]:
    """Every flow the candidate is linked to, destination flows first."""
    link = linked_regions(candidate, ctx)
    return link.flows_reaching + [f for f in link.flows_on_path
                                  if f not in link.flows_reaching]


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------
@dataclass
class CandidateScore:
    candidate_id: str
    category: str
    total: float
    band: str
    factors: Dict[str, float] = field(default_factory=dict)
    weighted: Dict[str, float] = field(default_factory=dict)
    reasons: Dict[str, str] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    duplicate_of: str = ""
    #: The candidate's own ``file:line`` evidence, carried so a persisted plan
    #: can be re-linked (prompt block, reports) without the original dict.
    locations: List[Tuple[str, int]] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "category": self.category,
            "score": round(self.total, 2),
            "band": self.band,
            "duplicate_of": self.duplicate_of,
            "code_locations": ["%s:%d" % (f, n) for f, n in self.locations],
            "factors": {k: round(v, 4) for k, v in self.factors.items()},
            "weighted": {k: round(v, 2) for k, v in self.weighted.items()},
            "reasons": dict(self.reasons),
            "evidence": self.evidence,
        }


def _band(total: float, scale: float) -> str:
    if scale <= 0:
        return "low"
    ratio = total / scale
    if ratio >= BAND_HIGH:
        return "high"
    if ratio >= BAND_MEDIUM:
        return "medium"
    return "low"


def _best_shape(flows: Sequence[Dict[str, Any]]) -> Tuple[float, str, Optional[Dict[str, Any]]]:
    ranked = sorted(
        flows,
        key=lambda f: (-FLOW_SHAPE_REACHABILITY.get(str(f.get("direction")), 0.0),
                       str(f.get("flow_id"))))
    if not ranked:
        return 0.0, "", None
    best = ranked[0]
    shape = str(best.get("direction") or "")
    return FLOW_SHAPE_REACHABILITY.get(shape, 0.4), shape, best


def _score_reachability(candidate, ctx, link):
    """How well the persisted analysis connects *this* candidate's code.

    The distinction that matters is whether the candidate's code is where the
    data *arrives* (a sink-side flow) or merely a link in the chain.  Both are
    worth auditing, so both count -- but at different weights, because only the
    first answers "can an attacker get here?".
    """
    if link.flows_reaching:
        value, shape, best = _best_shape(link.flows_reaching)
        return value, "%s flow %s reaches this code (%d flow(s))" % (
            shape or "unclassified", best.get("flow_id") if best else "?",
            len(link.flows_reaching)), {
            "mode": "destination", "flows": len(link.flows_reaching),
            "best_flow": best.get("flow_id") if best else "",
            "best_path": list((best or {}).get("path") or [])}
    if link.flows_on_path:
        value, shape, best = _best_shape(link.flows_on_path)
        return value * ON_PATH_ONLY, "%s flow %s passes through this code (%d flow(s))" % (
            shape or "unclassified", best.get("flow_id") if best else "?",
            len(link.flows_on_path)), {
            "mode": "on-path", "flows": len(link.flows_on_path),
            "best_flow": best.get("flow_id") if best else "",
            "best_path": list((best or {}).get("path") or [])}
    if link.sinks:
        verdicts = [ctx.reachability.get(str(s.get("sink_id"))) for s in link.sinks]
        seen = [v for v in verdicts if v]
        bound = [v for v in seen if v.get("bound")]
        if bound:
            return 0.4, ("sink bound to a symbol but no entry-path flow reached "
                         "it"), {"mode": "sink-only", "sinks": len(link.sinks),
                                 "bound": len(bound)}
        if seen:
            return 0.15, "sink has no symbol binding; reachability is not computable", {
                "mode": "sink-unbound", "sinks": len(link.sinks)}
        return 0.3, "sink indexed but never analysed for reachability", {
            "mode": "sink-unanalysed", "sinks": len(link.sinks)}
    if link.symbols:
        return 0.2, "location resolved to a symbol, but no flow or sink involves it", {
            "mode": "symbol-only", "symbols": sorted(link.symbols)[:5]}
    return 0.0, "no indexed location, symbol, sink or flow for this candidate", {
        "mode": "unlinked"}


def _score_attacker_control(candidate, ctx, link):
    entry_kinds: List[str] = []
    untrusted = False
    for flow in link.flows_reaching + link.flows_on_path:
        entry = ctx.entries.get(str(flow.get("entry_id")))
        if entry:
            entry_kinds.append(str(entry.get("kind") or ""))
            untrusted = untrusted or bool(entry.get("untrusted"))
    if not entry_kinds:
        entry_kinds = [str(e.get("kind") or "") for e in link.entries]
        untrusted = any(bool(e.get("untrusted")) for e in link.entries)
    if not entry_kinds:
        return 0.2, "no external entry linked", {"entry_kinds": []}
    best = max(ENTRY_KIND_LEVERAGE.get(kind, ENTRY_LEVERAGE_FALLBACK)
               for kind in entry_kinds)
    if untrusted and best < 1.0:
        best = min(1.0, best + 0.1)
    kinds = sorted(set(entry_kinds))
    return best, "entry kind(s) %s%s" % (
        ", ".join(kinds), ", untrusted input" if untrusted else ""), {
        "entry_kinds": kinds, "untrusted": untrusted}


def _boundary_kinds(ctx: ScheduleContext,
                    flows: Sequence[Dict[str, Any]]) -> List[str]:
    """The trust-boundary entry kinds the given flows cross."""
    kinds: List[str] = []
    for flow in flows:
        entry = ctx.entries.get(str(flow.get("entry_id")))
        if entry:
            kind = str(entry.get("kind") or "")
            if kind in BOUNDARY_ENTRY_KINDS:
                kinds.append(kind)
    return kinds


def _exposure(ctx: ScheduleContext, flows: Sequence[Dict[str, Any]]
              ) -> Tuple[float, List[Dict[str, Any]], int]:
    """``(unguarded/total boundary paths, unguarded paths, total boundary paths)``.

    Exposure, not a flag, because a flag saturates: on this repository's own
    tree every high-value sink is reached by at least one unguarded path, so a
    binary verdict pinned control_gap at 1.0 for a third of all candidates and
    left the round ordered by candidate id -- the "rank by danger" degeneracy
    the scheduler exists to replace.  Exposure keeps the ordering informative
    while preserving the property that matters: any unguarded path still scores
    strictly above every fully guarded one.
    """
    boundary = 0
    unguarded: List[Dict[str, Any]] = []
    for flow in flows:
        entry = ctx.entries.get(str(flow.get("entry_id"))) or {}
        if str(entry.get("kind") or "") not in BOUNDARY_ENTRY_KINDS:
            continue
        boundary += 1
        if not flow.get("authorizations"):
            unguarded.append(flow)
    if not boundary:
        return 0.0, [], 0
    return len(unguarded) / float(boundary), unguarded, boundary


def _score_security_boundary(candidate, ctx, link):
    flows = link.flows_reaching + link.flows_on_path
    crossing = _boundary_kinds(ctx, flows)
    if not crossing:
        crossed_by_entry = [str(e.get("kind") or "") for e in link.entries
                            if str(e.get("kind") or "") in BOUNDARY_ENTRY_KINDS]
        if not crossed_by_entry:
            return 0.2, "no trust boundary crossed by an indexed entry", {
                "boundary_kinds": []}
        return 1.0, ("boundary %s crossed at an indexed entry, but no analysed "
                     "path establishes a control"
                     % ", ".join(sorted(set(crossed_by_entry)))), {
            "boundary_kinds": sorted(set(crossed_by_entry)),
            "authorization_on_path": False}
    kinds_text = ", ".join(sorted(set(crossing)))
    exposure, unguarded, boundary = _exposure(ctx, flows)
    if unguarded:
        value = BOUNDARY_GUARDED + (1.0 - BOUNDARY_GUARDED) * exposure
        return value, ("boundary %s crossed with %d of %d path(s) unguarded "
                       "(exposure %.2f)"
                       % (kinds_text, len(unguarded), boundary, exposure)), {
            "boundary_kinds": sorted(set(crossing)),
            "authorization_on_path": False,
            "exposure": round(exposure, 4),
            "boundary_paths": boundary,
            "unguarded_paths": [str(f.get("flow_id")) for f in unguarded]}
    return BOUNDARY_GUARDED, (
        "boundary %s crossed and every one of %d analysed path(s) carries an "
        "authorization control (presence is not proof: ordering is not "
        "established)" % (kinds_text, boundary)), {
        "boundary_kinds": sorted(set(crossing)), "authorization_on_path": True,
        "exposure": 0.0, "boundary_paths": boundary}


def _score_sink_impact(candidate, ctx, link):
    if not link.sinks:
        return 0.0, "no sink linked", {"categories": []}
    best, best_cat = 0.0, ""
    for sink in link.sinks:
        severity = str(sink.get("severity_hint") or "")
        category = str(sink.get("category") or "")
        value = max(SEVERITY_BAND.get(severity, SEVERITY_FALLBACK),
                    SINK_IMPACT_CEILING.get(category, 0.0))
        if value > best or (value == best and category < best_cat):
            best, best_cat = value, category
    categories = sorted({str(s.get("category") or "") for s in link.sinks})
    return best, "worst linked sink category %s" % (best_cat or "unknown"), {
        "categories": categories}


def _score_control_gap(candidate, ctx, link):
    """Spec §11: a boundary with no control is the highest-value gap.

    The gap is judged per path and scaled by exposure, so a sink with one
    unguarded path among ten is still a gap -- but a smaller one than a sink
    no path guards.  ``CONTROL_PRESENT_UNREVIEWED`` stays strictly below every
    unguarded case: "a control exists but nobody looked" and "no control on this
    path" are different findings, and the second must not be ranked under the
    first.
    """
    all_flows = link.flows_reaching + link.flows_on_path
    on_path_authorizations = sorted({
        label for flow in all_flows for label in (flow.get("authorizations") or [])})
    on_path_validations = sorted({
        label for flow in all_flows for label in (flow.get("validations") or [])})
    exposure, unguarded, boundary = _exposure(ctx, all_flows)
    if unguarded:
        value = CONTROL_PRESENT_UNREVIEWED + \
            (1.0 - CONTROL_PRESENT_UNREVIEWED) * exposure
        return value, ("trust boundary with no authorization control on %d of "
                       "%d path(s) (exposure %.2f)"
                       % (len(unguarded), boundary, exposure)), {
            "authorizations": [],
            "validations": on_path_validations,
            "exposure": round(exposure, 4),
            "unguarded_paths": [str(f.get("flow_id")) for f in unguarded]}
    unreviewed_controls = [
        str(c.get("control_id")) for c in ctx.controls.values()
        if str(c.get("review_state") or "") in ("indexed", "unseen")
        and not c.get("candidate_ids")]
    if on_path_authorizations or on_path_validations:
        if unreviewed_controls:
            return CONTROL_PRESENT_UNREVIEWED, (
                "controls on the path are unreviewed; %d security "
                "control(s) repo-wide have no candidate" % len(unreviewed_controls)
            ), {"authorizations": on_path_authorizations,
                "validations": on_path_validations,
                "unreviewed_controls": len(unreviewed_controls)}
        return 0.3, "controls on the path are already reviewed", {
            "authorizations": on_path_authorizations,
            "validations": on_path_validations}
    if link.sinks:
        return 0.5, ("no security control on the path and no authorization "
                     "boundary detected"), {"authorizations": [],
                                            "validations": []}
    return 0.0, "no control dimension applicable", {}


def candidate_evidence_signal(candidate: Mapping[str, Any]) -> Dict[str, Any]:
    """Count provenance groups, not repeated derived evidence rows.

    A semantic path, guard, CFG, AST and value-binding row may all describe
    the same flow.  The rows remain useful for review, but they are not five
    independent witnesses.  This helper is deliberately side-effect free so
    tests and prompt builders can inspect the exact scheduler interpretation.
    """
    def strings(value):
        if not isinstance(value, (list, tuple)):
            return []
        return sorted({v for v in value if isinstance(v, str) and v})

    evidence_ids = strings(candidate.get("evidence_ids"))
    groups = strings(candidate.get("independence_groups"))
    if not groups:
        group = str(candidate.get("independence_group") or "")
        if group:
            groups = [group]
    groups = sorted(set(groups))
    derived_count = len(evidence_ids)
    independent_count = len(groups)
    # Legacy/manual candidates receive no invented independence bonus. Row
    # multiplicity and externally supplied counts never increase the score.
    return {
        "evidence_ids": sorted(set(evidence_ids)),
        "independence_groups": groups,
        "independent_evidence_count": independent_count,
        "derived_evidence_count": max(0, derived_count),
        "correlated_evidence_count": max(0, derived_count - independent_count),
        "provenance_complete": bool(candidate.get("provenance_complete")),
    }


def _score_evidence_quality(candidate, ctx, link):
    """Monotone in evidence: absence never scores, and it cannot be gamed."""
    value = EVIDENCE_NO_LOCATION
    for threshold, score in LOCATION_EVIDENCE:
        if len(link.locations) >= threshold:
            value = score
            break
    indexed_files = sorted({f for f, _ in link.locations if f in ctx.sources})
    if indexed_files:
        value = min(1.0, value + 0.2)
    if link.sinks:
        value = min(1.0, value + 0.2)
    if link.flows_reaching or link.flows_on_path:
        value = min(1.0, value + 0.2)
    reason = ("%d code_location(s), %d indexed file(s), %d sink(s), "
              "%d destination flow(s), %d on-path flow(s)"
              % (len(link.locations), len(indexed_files), len(link.sinks),
                 len(link.flows_reaching), len(link.flows_on_path)))
    if not link.locations:
        reason = "no file:line evidence in the candidate record"
    elif link.fallback_used:
        reason += "; linked by line window (no symbol index for the file)"
    provenance = candidate_evidence_signal(candidate)
    if provenance["derived_evidence_count"]:
        reason += ("; %d source provenance group(s), %d derived row(s)" %
                   (provenance["independent_evidence_count"],
                    provenance["derived_evidence_count"]))
    return value, reason, {
        "code_locations": ["%s:%d" % (f, n) for f, n in link.locations],
        "indexed_files": indexed_files, "sinks": len(link.sinks),
        "flows_reaching": len(link.flows_reaching),
        "flows_on_path": len(link.flows_on_path),
        "symbols": sorted(link.symbols)[:10],
        "line_window_fallback": link.fallback_used,
        "provenance": provenance,
    }


def _score_coverage_novelty(candidate, ctx, link):
    """Spec §13.2 across the novelty dimensions."""
    reviewed = ctx.reviewed_surfaces()
    all_flows = link.all_flows()
    dimensions: Dict[str, set] = {
        "files": {f for f, _ in link.locations},
        "entries": {str(f.get("entry_id")) for f in all_flows} |
                   {str(e.get("entry_id")) for e in link.entries},
        "sinks": {str(s.get("sink_id")) for s in link.sinks},
        "categories": {str(s.get("category")) for s in link.sinks},
        "flows": {str(f.get("flow_id")) for f in all_flows},
    }
    fresh: List[str] = []
    stale: List[str] = []
    scored = 0.0
    applicable = 0
    for name, touched in dimensions.items():
        if not touched:
            continue
        applicable += 1
        novel = touched - reviewed.get(name, set())
        if novel:
            fresh.append("%s:%d" % (name, len(novel)))
            scored += 1.0
        else:
            stale.append(name)
    # Control novelty is deliberately absent: the control-gap factor already
    # scores whether the path's controls have been looked at, and scoring it
    # twice would double-count the same evidence.
    if not applicable:
        return 0.0, "nothing to compare against existing coverage", {
            "fresh": fresh, "stale": stale, "dimensions": applicable}
    value = scored / applicable
    # Duplicate damping is applied once, on the total, in :func:`score_candidate`
    # -- a candidate that re-covers a reviewed region already scores 0 here
    # because every dimension is stale, so damping this factor too would
    # double-count the same signal.
    return value, "%d/%d dimension(s) untouched" % (len(fresh), applicable), {
        "fresh": fresh, "stale": stale, "dimensions": applicable}


def _jaccard(left: set, right: set) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / float(len(left | right))


def _coverage_ratio(own: set, reviewed: set) -> float:
    """Fraction of the candidate's *own* evidence sitting in a reviewed region.

    One-directional, unlike :func:`_jaccard`, because the two sides are built at
    different granularities: a ``candidate-coverage`` record is produced by a
    window-based linkage (``coverage.CANDIDATE_COVER_WINDOW``) and therefore
    names far more regions than the candidate's own ``file:line`` evidence.  A
    symmetric test divides by that inflated union and reports "not a duplicate"
    for a candidate whose entire evidence is already covered -- which is what
    happened before this existed.
    """
    if not own or not reviewed:
        return 0.0
    return len(own & reviewed) / float(len(own))


@dataclass
class _PoolDuplicateIndex:
    """Indexes the two same-pool duplicate tests used during scoring."""

    question_ids: Dict[Any, List[str]] = field(default_factory=dict)
    legacy_locations: Dict[str, List[Tuple[str, frozenset]]] = field(
        default_factory=dict)


def _build_pool_duplicate_index(
        pool: Optional[Sequence[Dict[str, Any]]]) -> _PoolDuplicateIndex:
    """Build once per scored pool, avoiding quadratic peer scans.

    The result preserves ``_near_duplicate_of`` semantics: provenance-backed
    candidates compare only documented research questions, while legacy rows
    compare only peers sharing at least one exact location before calculating
    the Jaccard overlap.
    """
    from ..evidence_provenance import research_question_key

    questions: Dict[Any, List[str]] = {}
    legacy: Dict[str, List[Tuple[str, frozenset]]] = {}
    for candidate in pool or ():
        if not isinstance(candidate, dict):
            continue
        candidate_id = str(candidate.get("candidate_id") or "")
        if not candidate_id:
            continue
        question = research_question_key(candidate)
        if question:
            questions.setdefault(question, []).append(candidate_id)
        if candidate.get("provenance_schema_version"):
            continue
        locations = frozenset(
            "%s:%d" % (file, line)
            for file, line in candidate_locations(candidate))
        for location in locations:
            legacy.setdefault(location, []).append((candidate_id, locations))
    for question in questions:
        questions[question] = sorted(set(questions[question]))
    for location in legacy:
        legacy[location].sort(key=lambda row: row[0])
    return _PoolDuplicateIndex(question_ids=questions, legacy_locations=legacy)


def _near_duplicate_of(candidate: Dict[str, Any], ctx: ScheduleContext,
                       pool: Optional[Sequence[Dict[str, Any]]] = None,
                       link: Optional[LinkedRegions] = None,
                       duplicate_index: Optional[_PoolDuplicateIndex] = None,
                       ) -> str:
    """The id this candidate duplicates, or ``""``.

    Complete provenance peers are first compared by source group AND a known
    verification question. Other provenance-bearing hypotheses are never
    merged by coarse location overlap. Legacy candidates use these fallbacks:

    * a region already **reviewed** in an earlier round (``candidate-coverage``)
      -- re-running it spends a slot without closing a new gap;
    * an **earlier candidate in the same pool** (strictly lower id, so the
      verdict never depends on iteration order) that occupies the same
      ``file:line``.

    The first comparison is containment of the candidate's sink ids (or files,
    when no sink is linked) in the reviewed region; the second is symmetric
    overlap of locations, because pool peers are equally coarse and must not
    flag each other one-sidedly.  Neither can make a candidate disappear -- a
    duplicate is only damped and the id is reported in
    ``CandidateScore.duplicate_of``.

    A record with the *same* candidate id counts as a duplicate.  The most
    common repeat is the same pool being scheduled a second round, so exempting
    the id would exempt exactly the case the factor exists for.
    """
    if link is None:
        link = linked_regions(candidate, ctx)
    cid = str(candidate.get("candidate_id") or "")
    from ..evidence_provenance import research_question_key

    if duplicate_index is None and pool is not None:
        duplicate_index = _build_pool_duplicate_index(pool)

    question = research_question_key(candidate)
    if question:
        if duplicate_index is not None:
            peers = [other_id for other_id in
                     duplicate_index.question_ids.get(question, ())
                     if other_id < cid]
        else:
            peers = [str(other.get("candidate_id")) for other in pool or ()
                     if other.get("candidate_id") and str(other["candidate_id"]) < cid
                     and research_question_key(other) == question]
        if peers:
            return min(peers)
    own_sinks = {str(s.get("sink_id")) for s in link.sinks}
    own_key = own_sinks or {f for f, _ in link.locations}
    if not own_key:
        return ""

    for record in ctx.prior_coverage:
        if str(record.get("status") or "open") in ("open", "", "candidate"):
            continue
        other_id = str(record.get("candidate_id") or "")
        if not other_id:
            continue
        # Old coverage rows lack a research-question key. A reviewed sink alone
        # cannot close a different, now explicitly modeled question on it.
        if candidate.get("provenance_schema_version") and other_id != cid:
            continue
        other = {str(x) for x in record.get("sinks") or []} or \
            {str(x) for x in record.get("files") or []}
        if _coverage_ratio(own_key, other) >= NEAR_DUPLICATE_OVERLAP:
            return other_id

    own_locations = {"%s:%d" % (f, n) for f, n in link.locations}
    if not own_locations:
        return ""
    if not candidate.get("provenance_schema_version") and duplicate_index is not None:
        peers: Dict[str, frozenset] = {}
        for location in own_locations:
            for other_id, other_locations in duplicate_index.legacy_locations.get(
                    location, ()):
                if other_id < cid:
                    peers.setdefault(other_id, other_locations)
        for other_id in sorted(peers):
            if _jaccard(own_locations, set(peers[other_id])) >= NEAR_DUPLICATE_OVERLAP:
                return other_id
    else:
        for other_candidate in pool or ():
            other_id = str(other_candidate.get("candidate_id") or "")
            if not other_id or other_id >= cid:
                continue
            if candidate.get("provenance_schema_version") or other_candidate.get("provenance_schema_version"):
                continue
            other_locations = {"%s:%d" % (f, n)
                               for f, n in candidate_locations(other_candidate)}
            if _jaccard(own_locations, other_locations) >= NEAR_DUPLICATE_OVERLAP:
                return other_id
    return ""


def score_candidate(candidate: Dict[str, Any], ctx: ScheduleContext,
                    pool: Optional[Sequence[Dict[str, Any]]] = None,
                    duplicate_index: Optional[_PoolDuplicateIndex] = None,
                    ) -> CandidateScore:
    """Score one candidate against every weight in ``ctx.weights``.

    The weight scale is the sum of the configured weights, so ``total`` is
    directly readable as a percentage of the achievable maximum even when a
    caller overrides the defaults.  Every factor contributes its raw value,
    its weighted value, a human-readable reason and the evidence behind it, so
    no number in the plan is unattributable.
    """
    link = linked_regions(candidate, ctx)
    raw = {
        "reachability": _score_reachability(candidate, ctx, link),
        "attacker_control": _score_attacker_control(candidate, ctx, link),
        "security_boundary": _score_security_boundary(candidate, ctx, link),
        "sink_impact": _score_sink_impact(candidate, ctx, link),
        "control_gap": _score_control_gap(candidate, ctx, link),
        "evidence_quality": _score_evidence_quality(candidate, ctx, link),
        "coverage_novelty": _score_coverage_novelty(candidate, ctx, link),
    }
    factors = {name: float(raw[name][0]) for name in FACTOR_ORDER}
    reasons = {name: str(raw[name][1]) for name in FACTOR_ORDER}
    evidence = {name: raw[name][2] for name in FACTOR_ORDER}
    weighted = {name: round(factors[name] * float(ctx.weights.get(name, 0)), 4)
                for name in FACTOR_ORDER}
    total = sum(weighted.values())
    scale = float(sum(max(0, int(ctx.weights.get(name, 0))) for name in FACTOR_ORDER))
    surface_guidance = _benchmark_surface_guidance(
        candidate, ctx.benchmark_feedback)
    if surface_guidance:
        requested = max(-MAX_FEEDBACK_WEIGHT_DELTA,
                        min(MAX_FEEDBACK_WEIGHT_DELTA,
                            int(surface_guidance.get("priority_delta") or 0)))
        before = total
        total = max(0.0, min(scale, total + requested))
        surface_guidance["applied_delta"] = round(total - before, 4)
    duplicate = _near_duplicate_of(candidate, ctx, pool, link, duplicate_index)
    if duplicate:
        total *= DUPLICATE_DAMPING
        evidence["duplicate"] = {"of": duplicate, "damping": DUPLICATE_DAMPING}
    remembered = memory_match(candidate, ctx.research_memory)
    if remembered:
        latest = remembered.get("latest_event") or {}
        state = str(latest.get("state") or STATE_DECISION_RECORDED)
        adjustment = 1.0
        if state in ("stable-reproducer", "stable-observation"):
            total *= RESEARCH_STABLE_DAMPING
            adjustment = RESEARCH_STABLE_DAMPING
        elif state == "unstable-replay":
            total *= RESEARCH_UNSTABLE_DAMPING
            adjustment = RESEARCH_UNSTABLE_DAMPING
        elif state == "actionable-difference":
            before = total
            total = min(scale, total + RESEARCH_DIFFERENCE_BOOST)
            adjustment = round(total - before, 4)
        elif state == STATE_REVIEW_ACCEPTED:
            total *= RESEARCH_REVIEW_ACCEPTED_DAMPING
            adjustment = RESEARCH_REVIEW_ACCEPTED_DAMPING
        elif state == STATE_REVIEW_REJECTED:
            total *= RESEARCH_REVIEW_REJECTED_DAMPING
            adjustment = RESEARCH_REVIEW_REJECTED_DAMPING
        elif state == STATE_REVIEW_SCOPE_CORRECTED:
            total *= RESEARCH_REVIEW_SCOPE_DAMPING
            adjustment = RESEARCH_REVIEW_SCOPE_DAMPING
        elif state == STATE_REVIEW_NEEDS_EVIDENCE:
            before = total
            total = min(scale, total + RESEARCH_REVIEW_NEEDS_EVIDENCE_BOOST)
            adjustment = round(total - before, 4)
        latest_evidence = latest.get("evidence") or {}
        evidence["research_memory"] = {
            "research_key": remembered.get("research_key", ""),
            "latest_state": state,
            "latest_round": latest.get("round", 0),
            "next_probe_hints": list(latest.get("next_probe_hints") or [])[:4],
            "score_adjustment": adjustment,
            "claim_status": "not-a-finding",
        }
        for key in ("review_status", "reason_code", "reviewer_note",
                    "evidence_refs", "feedback_id"):
            if latest_evidence.get(key) not in (None, "", []):
                evidence["research_memory"][key] = latest_evidence[key]
    portfolio_guidance = _portfolio_probe_guidance(
        candidate, ctx.research_portfolio)
    if portfolio_guidance:
        before = total
        total = min(scale, total + RESEARCH_PORTFOLIO_PROBE_BOOST)
        portfolio_guidance["applied_delta"] = round(total - before, 4)
        evidence["research_portfolio"] = portfolio_guidance
    strategy_guidance = _research_strategy_guidance(
        candidate, ctx.research_strategy, link)
    if strategy_guidance:
        observation = strategy_guidance.get("observation") or {}
        action_guidance = strategy_guidance.get("guidance") or {}
        status = str(observation.get("status") or "unobserved")
        try:
            information_gain = int(observation.get("information_gain") or 0)
        except (TypeError, ValueError):
            information_gain = 0
        # A strategy item that already has complete/falsifier evidence and
        # produced no new signal should remain visible, but must not receive a
        # fresh priority nudge merely because it is still linked statically.
        # This is a scheduling rule, never a candidate suppression rule.
        strategy_delta = 0.0 if status in {
            "complete", "falsifier-observed"} and information_gain == 0 \
            else RESEARCH_STRATEGY_BOOST
        if action_guidance.get("next_action") in {
                "hold-for-new-evidence", "reframe-scope"}:
            # Keep the candidate eligible, but do not reward repeating a
            # review-rejected or zero-yield experiment.
            strategy_delta = 0.0
        else:
            strategy_delta += min(
                2.25, 0.75 * min(3, _safe_weight(
                    action_guidance.get("priority_delta") or 0)))
        before = total
        total = min(scale, total + strategy_delta)
        strategy_guidance["applied_delta"] = round(total - before, 4)
        evidence["research_strategy"] = strategy_guidance
    agenda_guidance = _research_agenda_guidance(
        candidate, ctx.research_agenda)
    if agenda_guidance:
        if agenda_guidance.get("selection_status") == "selected":
            before = total
            total = min(scale, total + RESEARCH_AGENDA_BOOST)
            agenda_guidance["applied_delta"] = round(total - before, 4)
        else:
            agenda_guidance["applied_delta"] = 0.0
        evidence["research_agenda"] = agenda_guidance
    if ctx.benchmark_feedback:
        evidence["benchmark_feedback"] = {
            "benchmark_id": ctx.benchmark_feedback.get("benchmark_id", ""),
            "alert_codes": [str(item.get("code")) for item in
                            ctx.benchmark_feedback.get("alerts", [])
                            if isinstance(item, dict) and item.get("code")][:8],
            "weight_adjustments": dict(ctx.weight_adjustments),
            "surface_guidance": surface_guidance,
            "claim_status": "not-a-finding",
        }
    return CandidateScore(
        candidate_id=str(candidate.get("candidate_id") or ""),
        category=candidate_category(candidate),
        total=total,
        band=_band(total, scale),
        factors=factors,
        weighted=weighted,
        reasons=reasons,
        evidence=evidence,
        duplicate_of=duplicate,
        locations=list(link.locations),
    )


def score_candidates(candidates: Sequence[Dict[str, Any]], ctx: ScheduleContext
                     ) -> List[CandidateScore]:
    """Score every candidate, highest first; ties broken by candidate id."""
    pool = list(candidates)
    duplicate_index = _build_pool_duplicate_index(pool)
    scores = [score_candidate(c, ctx, pool, duplicate_index) for c in pool]
    scores.sort(key=lambda s: (-s.total, s.candidate_id))
    return scores
