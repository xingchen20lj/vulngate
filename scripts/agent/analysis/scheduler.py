"""Coverage-aware candidate scheduling (spec §13, §14, §15).

The scheduler replaces "Top-K by danger" with::

    Risk Score + Coverage Novelty + Category Diversity + Residual Risk

It answers one question, deterministically and without an LLM: **given this
round's budget of N candidates, which N should be audited, and which unaudited
region does each one close?**

Four properties are load-bearing:

* **Ordering is derived from evidence, never from absence.**  Every factor is
  computed from the persisted indices (entries, sinks, controls, flows, symbol
  index) and each one is reported alongside its score, so a reviewer can audit
  any number the scheduler produces.  A factor that cannot be evaluated scores
  low, not high.
* **Diversity is enforced by quota, not by hope.**  Spec §13.3 forbids a round
  in which every candidate comes from the same category.  Quota that cannot be
  filled is *relocated* and the relocation is reported -- it is never silently
  dropped, and it never reduces the number of candidates returned.
* **Coverage novelty is measured against candidates actually reviewed**, taken
  from ``candidate-coverage.json``; a candidate that re-covers an already
  reviewed region is down-weighted rather than re-run.
* **Nothing is discarded.**  Deferred candidates keep their score and their
  reason and are handed back for the next round; the residual sweep re-derives
  the uncovered regions so the next round's input is the *new* gap list.

Scoring is a weighted sum, per spec §13.1's "实际代码可以使用加权和".
``DEFAULT_FACTOR_WEIGHTS`` sums to 100, so a total is readable as a percentage.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import coverage as cov
from .inventory import CoverageStore, load_inventory
from ..evaluation.benchmark import (
    BENCHMARK_FEEDBACK_FACTORS,
    MAX_FEEDBACK_WEIGHT_DELTA,
    RESEARCH_SURFACES,
    normalize_benchmark_feedback,
)
from ..memory.research import (
    STATE_DECISION_RECORDED,
    STATE_REVIEW_ACCEPTED,
    STATE_REVIEW_NEEDS_EVIDENCE,
    STATE_REVIEW_REJECTED,
    STATE_REVIEW_SCOPE_CORRECTED,
    load_research_memory,
    memory_match,
    memory_prompt_rows,
)

# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------

#: Spec §13.1's suggested weights.  ``DefaultReachability`` from the spec's
#: multiplicative list is folded into ``reachability`` rather than carried as a
#: separate factor: it is derived from the same persisted reachability verdicts
#: and splitting it would double-count the same evidence.
DEFAULT_FACTOR_WEIGHTS: Dict[str, int] = {
    "reachability": 20,
    "attacker_control": 15,
    "security_boundary": 15,
    "sink_impact": 15,
    "control_gap": 15,
    "evidence_quality": 10,
    "coverage_novelty": 10,
}

FACTOR_ORDER: Tuple[str, ...] = (
    "reachability", "attacker_control", "security_boundary", "sink_impact",
    "control_gap", "evidence_quality", "coverage_novelty",
)

#: Default round width and its stratified quota (spec §13.3's example shape).
DEFAULT_SLOTS = 8
DEFAULT_QUOTA: Dict[str, int] = {
    "authz": 2, "parser": 1, "file": 1, "ssrf": 1, "exec": 1, "dos": 1,
    "residual": 1,
}

#: Priority bands, as a fraction of the achievable total.
BAND_HIGH = 0.65
BAND_MEDIUM = 0.40

RESEARCH_SURFACE_TARGET_TYPES: Dict[str, str] = {
    "web-app": "web", "middleware": "protocol", "message-rpc": "protocol",
    "cloud-service": "cloud", "mobile-app": "mobile", "native-app": "native",
}


def _safe_weight(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _normalize_weight_total(raw: Dict[str, int], target: int) -> Dict[str, int]:
    """Scale integer weights back to the original total deterministically."""
    names = list(FACTOR_ORDER)
    if target <= 0:
        return {name: 0 for name in names}
    total = sum(max(0, int(raw.get(name, 0))) for name in names)
    if total <= 0:
        return {name: 0 for name in names}
    floors: Dict[str, int] = {}
    fractions: List[Tuple[float, int, str]] = []
    for index, name in enumerate(names):
        exact = max(0, int(raw.get(name, 0))) * target / float(total)
        floor_value = int(exact)
        floors[name] = floor_value
        fractions.append((exact - floor_value, -index, name))
    remainder = target - sum(floors.values())
    for _fraction, _order, name in sorted(fractions, reverse=True)[:max(0, remainder)]:
        floors[name] += 1
    return floors


def apply_benchmark_feedback_weights(
        weights: Optional[Dict[str, int]],
        benchmark_feedback: Optional[Dict[str, Any]],
        ) -> Tuple[Dict[str, int], Dict[str, int]]:
    """Apply bounded feedback while preserving the caller's weight scale.

    A feedback artifact can only move existing scheduler factors by a small
    signed delta.  Unknown factors and oversized values are ignored/clamped;
    the resulting weights are rescaled to the original total so benchmark
    feedback cannot silently change the meaning of a score from a percentage
    into an arbitrary raw number.
    """
    provided = dict(weights or DEFAULT_FACTOR_WEIGHTS)
    feedback = normalize_benchmark_feedback(benchmark_feedback or {})
    if not feedback:
        return provided, {}
    base = {name: _safe_weight(provided.get(name, 0))
            for name in FACTOR_ORDER}
    target = sum(base.values())
    requested = feedback.get("weight_deltas") or {}
    adjusted = dict(base)
    for name in FACTOR_ORDER:
        # Parse the signed value explicitly so a balanced feedback object stays
        # explainable instead of silently dropping negative deltas.
        try:
            signed = int(requested.get(name, 0))
        except (TypeError, ValueError):
            signed = 0
        signed = max(-MAX_FEEDBACK_WEIGHT_DELTA,
                     min(MAX_FEEDBACK_WEIGHT_DELTA, signed))
        adjusted[name] = max(0, base[name] + signed)
    effective = _normalize_weight_total(adjusted, target)
    actual = {name: effective[name] - base[name]
              for name in FACTOR_ORDER if effective[name] != base[name]}
    return effective, actual

# --- coarse category buckets (spec §13.3) ----------------------------------

#: Ordered: the first matching rule wins, so the more specific security classes
#: come before the general ones.  Matching is done over the candidate's own
#: text (surface / logic / hypothesis / chain components).
CATEGORY_RULES: Tuple[Tuple[str, str], ...] = (
    ("authz", r"authz|auth\b|authoriz|permission|privileg|owner|tenant|\bacl\b"
              r"|\brole\b|idor|access control|bypass|escalat"),
    ("ssrf", r"ssrf|server.side.request|redirect|webhook|dns.rebind|"
             r"\burg\b|\burl\b|\buri\b|outbound|egress"),
    ("exec", r"\brce\b|command.exec|shell|processbuilder|code.eval|\beval\b"
             r"|deserial|unserial|serializ|template|spel|ognl|mvel|jndi|ldap"
             r"|xpath|xxe|expression|groovy|script.engine|dynamic.class"),
    ("file", r"file|path.travers|upload|download|zip|archive|symlink|"
             r"directory|sandbox.escape"),
    ("parser", r"pars|json|xml|yaml|csv|protobuf|type.dispatch|polymorph"
               r"|autotype|schema|grammar|token|lexer"),
    ("dos", r"\bdos\b|denial|amplif|recurs|depth|length|billion|hang|\boom\b"
            r"|memory.exhaust|stack.overflow|infinite.loop|quadratic"),
    ("crypto", r"crypto|random|\bhash\b|signature|\bkey\b|\bjwt\b|secret"
               r"|credential|password|encrypt|decrypt"),
    ("network", r"network|socket|\bport\b|http.client|proxy|tunnel"),
)
CATEGORY_FALLBACK = "other"
CATEGORY_ORDER: Tuple[str, ...] = tuple(name for name, _ in CATEGORY_RULES) + \
    (CATEGORY_FALLBACK,)

# --- evidence tables -------------------------------------------------------

#: How much attacker leverage an entry kind carries.  Remote protocol handlers
#: are directly reachable by an anonymous attacker; a CLI flag is reachable by
#: whoever can run the binary.
ENTRY_KIND_LEVERAGE: Dict[str, float] = {
    "http": 1.0, "rpc": 0.95, "message": 0.9, "url-scheme": 0.9, "webview": 0.9,
    "ipc": 0.8, "file-input": 0.8, "network": 0.8, "config": 0.6, "cli": 0.6,
    "target-rule": 0.7, "library-api": 0.4,
}
ENTRY_LEVERAGE_FALLBACK = 0.2

#: Entry kinds that cross a trust boundary by construction.
BOUNDARY_ENTRY_KINDS = frozenset({
    "http", "rpc", "message", "url-scheme", "webview", "ipc", "file-input",
    "network", "config",
})

#: Worst-case impact of a sink category, independent of ``severity_hint``.
#: The factor takes ``max(severity band, category ceiling)`` so a catalog that
#: under-grades a category cannot hide it.
SINK_IMPACT_CEILING: Dict[str, float] = {
    "command-exec": 1.0, "code-eval": 1.0, "deserialization": 0.95,
    "expression-eval": 0.9, "dynamic-class-load": 0.9, "jndi": 0.9,
    "template-render": 0.85, "sql-exec": 0.85, "xxe": 0.8, "privilege": 0.8,
    "credential-access": 0.8, "network-egress": 0.7, "native-ipc": 0.7,
    "webview-bridge": 0.7, "file-mutation": 0.6, "file-read": 0.5,
}
SEVERITY_BAND: Dict[str, float] = {"high": 1.0, "medium": 0.6, "low": 0.3}
SEVERITY_FALLBACK = 0.3

#: Path shapes (``FlowRecord.direction``) mapped to reachability confidence.
FLOW_SHAPE_REACHABILITY: Dict[str, float] = {
    "cross-procedural": 1.0, "intra-symbol": 0.85, "module-scope": 0.5,
}

#: Location evidence: distinct ``file:line`` entries in ``code_location``.
LOCATION_EVIDENCE: Tuple[Tuple[int, float], ...] = ((4, 1.0), (2, 0.7), (1, 0.4))
EVIDENCE_NO_LOCATION = 0.0

#: A boundary crossed with an authorization control present on every analysed
#: path.  Not 0.0: the control's *presence* is all a static path proves -- that
#: it runs before the sink, on the same branch, with the right subject, is
#: exactly what the audit still has to establish.
BOUNDARY_GUARDED = 0.6

#: A control exists on the path but no candidate has ever looked at it (spec §11).
CONTROL_PRESENT_UNREVIEWED = 0.8

#: A candidate that re-covers an already reviewed region is damped, not banned.
DUPLICATE_DAMPING = 0.3

# Research memory changes the order only when it has an observed runtime state.
# These are deliberately mild: the memory can avoid repeating a stable probe,
# but it must not suppress a candidate or turn a lab observation into a verdict.
RESEARCH_STABLE_DAMPING = 0.55
RESEARCH_UNSTABLE_DAMPING = 0.85
RESEARCH_DIFFERENCE_BOOST = 5.0
# Human review is a scheduling signal, never a hard ban or a conclusion.
RESEARCH_REVIEW_ACCEPTED_DAMPING = 0.75
RESEARCH_REVIEW_REJECTED_DAMPING = 0.35
RESEARCH_REVIEW_SCOPE_DAMPING = 0.85
RESEARCH_REVIEW_NEEDS_EVIDENCE_BOOST = 4.0

#: Duplicate threshold, used two ways.  Against a *reviewed region* it is the
#: fraction of the candidate's own evidence that must already be covered
#: (one-directional -- the reviewed region is coarser by construction); against
#: a *pool peer* it is the symmetric Jaccard overlap of locations.
NEAR_DUPLICATE_OVERLAP = 0.6

#: Line window used only as a *fallback* when a candidate location has no owning
#: symbol (an unindexed file).  Linkage is symbol-tight whenever the symbol
#: index can answer -- see :func:`linked_regions`.
LINK_FALLBACK_WINDOW = cov.CANDIDATE_COVER_WINDOW

#: Score multiplier for a candidate that sits *on* a reachable path but is not
#: its destination.  A chain member is worth auditing, but it is not the sink an
#: attacker drives input into, so it must not score as if it were.
ON_PATH_ONLY = 0.65

_COLOCATION = re.compile(r"^(?P<file>[^:]+?):(?P<line>\d+)")


# ---------------------------------------------------------------------------
# context
# ---------------------------------------------------------------------------

@dataclass
class ScheduleContext:
    """Everything the scoring functions read, loaded once per round."""

    entries: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    sinks: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    controls: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    symbols: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    sources: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    flows: List[Dict[str, Any]] = field(default_factory=list)
    reachability: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    prior_coverage: List[Dict[str, Any]] = field(default_factory=list)
    research_memory: List[Dict[str, Any]] = field(default_factory=list)
    weights: Dict[str, int] = field(default_factory=lambda: dict(DEFAULT_FACTOR_WEIGHTS))
    benchmark_feedback: Dict[str, Any] = field(default_factory=dict)
    weight_adjustments: Dict[str, int] = field(default_factory=dict)

    #: Indexes built on demand (memoised, never mutated afterwards).
    _flows_by_entry: Optional[Dict[str, List[Dict[str, Any]]]] = None
    _sinks_by_file: Optional[Dict[str, List[Dict[str, Any]]]] = None
    _controls_by_file: Optional[Dict[str, List[Dict[str, Any]]]] = None
    _symbols_by_file: Optional[Dict[str, List[Dict[str, Any]]]] = None
    _flows_by_symbol: Optional[Dict[str, List[Dict[str, Any]]]] = None
    _flows_by_sink: Optional[Dict[str, List[Dict[str, Any]]]] = None
    _sinks_by_symbol: Optional[Dict[str, List[Dict[str, Any]]]] = None
    _entries_by_symbol: Optional[Dict[str, List[Dict[str, Any]]]] = None
    _entries_by_file: Optional[Dict[str, List[Dict[str, Any]]]] = None

    @classmethod
    def from_store(cls, store: CoverageStore,
                   weights: Optional[Dict[str, int]] = None,
                   research_memory: Optional[Sequence[Dict[str, Any]]] = None,
                   benchmark_feedback: Optional[Dict[str, Any]] = None
                   ) -> "ScheduleContext":
        indices = load_inventory(store)
        reachability = {str(r.get("sink_id")): r
                        for r in indices.get("sink-reachability") or []}
        feedback = normalize_benchmark_feedback(benchmark_feedback or {})
        effective_weights, weight_adjustments = apply_benchmark_feedback_weights(
            weights, feedback)
        return cls(
            entries={str(e.get("entry_id")): e
                     for e in indices.get("entry-index") or []},
            sinks={str(s.get("sink_id")): s
                   for s in indices.get("sink-index") or []},
            controls={str(c.get("control_id")): c
                      for c in indices.get("security-control-index") or []},
            symbols={str(s.get("symbol_id")): s
                     for s in indices.get("symbol-index") or []},
            sources={str(f.get("file")): f
                     for f in indices.get("source-inventory") or []},
            flows=list(indices.get("flow-index") or []),
            reachability=reachability,
            prior_coverage=list(indices.get("candidate-coverage") or []),
            research_memory=[item for item in (research_memory or [])
                             if isinstance(item, dict)],
            weights=effective_weights,
            benchmark_feedback=feedback,
            weight_adjustments=weight_adjustments,
        )

    # --- lazy indexes ------------------------------------------------------

    def flows_by_entry(self) -> Dict[str, List[Dict[str, Any]]]:
        if self._flows_by_entry is None:
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for flow in self.flows:
                grouped.setdefault(str(flow.get("entry_id")), []).append(flow)
            self._flows_by_entry = grouped
        return self._flows_by_entry

    def sinks_by_file(self) -> Dict[str, List[Dict[str, Any]]]:
        if self._sinks_by_file is None:
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for sink in self.sinks.values():
                grouped.setdefault(str(sink.get("file")), []).append(sink)
            self._sinks_by_file = grouped
        return self._sinks_by_file

    def symbols_by_file(self) -> Dict[str, List[Dict[str, Any]]]:
        """Symbols per file, so a location resolves without a full scan.

        Without this, resolving one candidate is O(symbols) and the whole round
        is O(candidates x symbols x locations) -- on this repository's own
        ``scripts/`` tree that is ~130k range tests per round for no reason.
        """
        if self._symbols_by_file is None:
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for symbol in self.symbols.values():
                grouped.setdefault(str(symbol.get("file")), []).append(symbol)
            self._symbols_by_file = grouped
        return self._symbols_by_file

    def flows_by_symbol(self) -> Dict[str, List[Dict[str, Any]]]:
        """Flows per symbol appearing anywhere in the flow's path."""
        if self._flows_by_symbol is None:
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for flow in self.flows:
                for symbol_id in sorted({str(x) for x in flow.get("path") or []}):
                    grouped.setdefault(symbol_id, []).append(flow)
            self._flows_by_symbol = grouped
        return self._flows_by_symbol

    def flows_by_sink(self) -> Dict[str, List[Dict[str, Any]]]:
        if self._flows_by_sink is None:
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for flow in self.flows:
                grouped.setdefault(str(flow.get("sink_id")), []).append(flow)
            self._flows_by_sink = grouped
        return self._flows_by_sink

    def sinks_by_symbol(self) -> Dict[str, List[Dict[str, Any]]]:
        if self._sinks_by_symbol is None:
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for sink in self.sinks.values():
                symbol_id = str(sink.get("symbol_id") or "")
                if symbol_id:
                    grouped.setdefault(symbol_id, []).append(sink)
            self._sinks_by_symbol = grouped
        return self._sinks_by_symbol

    def entries_by_symbol(self) -> Dict[str, List[Dict[str, Any]]]:
        if self._entries_by_symbol is None:
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for entry in self.entries.values():
                symbol_id = str(entry.get("symbol_id") or "")
                if symbol_id:
                    grouped.setdefault(symbol_id, []).append(entry)
            self._entries_by_symbol = grouped
        return self._entries_by_symbol

    def entries_by_file(self) -> Dict[str, List[Dict[str, Any]]]:
        if self._entries_by_file is None:
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for entry in self.entries.values():
                grouped.setdefault(str(entry.get("file")), []).append(entry)
            self._entries_by_file = grouped
        return self._entries_by_file

    def controls_by_file(self) -> Dict[str, List[Dict[str, Any]]]:
        if self._controls_by_file is None:
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for control in self.controls.values():
                grouped.setdefault(str(control.get("file")), []).append(control)
            self._controls_by_file = grouped
        return self._controls_by_file

    def reviewed_surfaces(self) -> Dict[str, set]:
        """Surfaces already audited, keyed by novelty dimension (spec §13.2)."""
        reviewed = {
            "files": set(), "entries": set(), "sinks": set(),
            "categories": set(), "controls": set(), "flows": set(),
        }
        for record in self.prior_coverage:
            if str(record.get("status") or "open") in ("open", "", "candidate"):
                continue
            reviewed["files"].update(str(x) for x in record.get("files") or [])
            reviewed["entries"].update(str(x) for x in record.get("entries") or [])
            reviewed["sinks"].update(str(x) for x in record.get("sinks") or [])
            reviewed["categories"].update(str(x) for x in record.get("categories") or [])
            reviewed["flows"].update(str(x) for x in record.get("flows") or [])
        return reviewed


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
    return value, reason, {
        "code_locations": ["%s:%d" % (f, n) for f, n in link.locations],
        "indexed_files": indexed_files, "sinks": len(link.sinks),
        "flows_reaching": len(link.flows_reaching),
        "flows_on_path": len(link.flows_on_path),
        "symbols": sorted(link.symbols)[:10],
        "line_window_fallback": link.fallback_used}


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


def _near_duplicate_of(candidate: Dict[str, Any], ctx: ScheduleContext,
                       pool: Optional[Sequence[Dict[str, Any]]] = None,
                       link: Optional[LinkedRegions] = None) -> str:
    """The id this candidate duplicates, or ``""``.

    Two deterministic sources, checked in this order:

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
        other = {str(x) for x in record.get("sinks") or []} or \
            {str(x) for x in record.get("files") or []}
        if _coverage_ratio(own_key, other) >= NEAR_DUPLICATE_OVERLAP:
            return other_id

    own_locations = {"%s:%d" % (f, n) for f, n in link.locations}
    if not own_locations:
        return ""
    for other_candidate in pool or ():
        other_id = str(other_candidate.get("candidate_id") or "")
        if not other_id or other_id >= cid:
            continue
        other_locations = {"%s:%d" % (f, n)
                           for f, n in candidate_locations(other_candidate)}
        if _jaccard(own_locations, other_locations) >= NEAR_DUPLICATE_OVERLAP:
            return other_id
    return ""


def score_candidate(candidate: Dict[str, Any], ctx: ScheduleContext,
                    pool: Optional[Sequence[Dict[str, Any]]] = None
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
    duplicate = _near_duplicate_of(candidate, ctx, pool, link)
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
    scores = [score_candidate(c, ctx, pool) for c in pool]
    scores.sort(key=lambda s: (-s.total, s.candidate_id))
    return scores


# ---------------------------------------------------------------------------
# stratified selection (spec §13.3)
# ---------------------------------------------------------------------------

@dataclass
class SchedulePlan:
    round_no: int = 0
    slots: int = 0
    selected: List[CandidateScore] = field(default_factory=list)
    deferred: List[CandidateScore] = field(default_factory=list)
    requested_quota: Dict[str, int] = field(default_factory=dict)
    filled_quota: Dict[str, int] = field(default_factory=dict)
    relocated_quota: Dict[str, int] = field(default_factory=dict)
    category_counts: Dict[str, int] = field(default_factory=dict)
    coverage: Dict[str, Any] = field(default_factory=dict)
    residual: Dict[str, Any] = field(default_factory=dict)
    weights: Dict[str, int] = field(default_factory=dict)
    benchmark_feedback: Dict[str, Any] = field(default_factory=dict)
    weight_adjustments: Dict[str, int] = field(default_factory=dict)
    #: Candidates selected outside the quota because they carry runtime
    #: evidence the static score cannot see (see :func:`stratified_select`).
    pinned: List[str] = field(default_factory=list)

    def selected_ids(self) -> List[str]:
        return [s.candidate_id for s in self.selected]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "round": self.round_no,
            "slots": self.slots,
            "weights": dict(self.weights),
            "weight_adjustments": dict(self.weight_adjustments),
            "benchmark_feedback": self.benchmark_feedback,
            "selected": [s.as_dict() for s in self.selected],
            "deferred": [s.as_dict() for s in self.deferred],
            "pinned": list(self.pinned),
            "quota": {
                "requested": dict(self.requested_quota),
                "filled": dict(self.filled_quota),
                "relocated": {k: v for k, v in self.relocated_quota.items() if v},
            },
            "category_counts": dict(self.category_counts),
            "coverage": self.coverage,
            "residual": self.residual,
            "selected_ids": self.selected_ids(),
            "deferred_ids": [s.candidate_id for s in self.deferred],
            "producer": "scheduler",
            "confidence": "heuristic",
            "evidence_type": "static-inferred",
        }


def stratified_select(scores: Sequence[CandidateScore], slots: int,
                      quota: Optional[Dict[str, int]] = None,
                      pinned: Sequence[str] = ()
                      ) -> Tuple[List[CandidateScore], List[CandidateScore],
                                 Dict[str, int], Dict[str, int], Dict[str, int]]:
    """Fill per-category quota, then relocate whatever could not be filled.

    Returns ``(selected, deferred, requested, filled, relocated)``.

    Spec §13.3: "如果某类别不存在则动态转移配额".  Relocation means an unfilled
    slot is given to the globally highest-scoring candidate that has not been
    taken yet -- so the round is always ``min(slots, len(scores))`` wide, and the
    relocation is reported per category rather than disappearing.

    ``residual`` is an ordinary bucket here: spec §13.3 reserves a slot for
    candidates derived from the residual sweep, and the residual sweep tags them
    ``category="residual"``.  Treating it as a bucket rather than a special case
    means the reserved slot is filled when such a candidate exists and *reported
    as relocated* when it does not -- the two alternatives are silently spending
    the slot on something else, or losing the round width.

    ``pinned`` ids are selected first, in the order given, outside the quota and
    against the slot budget.  This exists for candidates carrying runtime
    evidence (a fuzz reproducer with a crash dump): the scheduler's factors are
    all static, so letting it drop one in favour of a better-scoring static
    candidate would discard the strongest evidence in the round.  Pinning is
    reported in the plan, and pinning more ids than ``slots`` truncates rather
    than over-filling.
    """
    quota = dict(quota if quota is not None else DEFAULT_QUOTA)
    slots = max(0, int(slots))
    by_category: Dict[str, List[CandidateScore]] = {}
    for score in scores:
        by_category.setdefault(score.category, []).append(score)

    taken: set = set()
    selected: List[CandidateScore] = []
    by_id = {s.candidate_id: s for s in scores}
    for candidate_id in pinned:
        score = by_id.get(str(candidate_id))
        if score is None or score.candidate_id in taken:
            continue
        if len(selected) >= slots:
            break
        selected.append(score)
        taken.add(score.candidate_id)

    # 1. quota categories, in the declared order
    filled: Dict[str, int] = {}
    for category in quota:
        want = max(0, int(quota[category]))
        available = [s for s in by_category.get(category, ())
                     if s.candidate_id not in taken]
        got = 0
        for score in available[:want]:
            if len(selected) >= slots:
                break
            selected.append(score)
            taken.add(score.candidate_id)
            got += 1
        filled[category] = got

    # 2. relocate unfilled quota, then spend any remaining slots
    remaining = [s for s in scores if s.candidate_id not in taken]
    for score in remaining:
        if len(selected) >= slots:
            break
        selected.append(score)
        taken.add(score.candidate_id)

    relocated: Dict[str, int] = {}
    for category, want in quota.items():
        shortfall = max(0, int(want)) - filled.get(category, 0)
        if shortfall:
            relocated[category] = shortfall

    selected.sort(key=lambda s: (-s.total, s.candidate_id))
    deferred = [s for s in scores if s.candidate_id not in taken]
    return selected, deferred, quota, filled, relocated


# ---------------------------------------------------------------------------
# residual sweep (spec §14)
# ---------------------------------------------------------------------------

def residual_sweep(store: CoverageStore, workspace: Path, target: str,
                   round_no: int = 0) -> Dict[str, Any]:
    """Recompute the uncovered regions and coverage summary for the next round.

    Spec §14 requires this after every round.  It goes through
    :func:`agent.analysis.coverage.refresh_candidate_coverage`, so the review
    state is re-derived from the round ledgers (the durable record of what was
    decided) before the gaps are recomputed.
    """
    info = cov.refresh_candidate_coverage(store, workspace, target, round_no or None)
    summary = store.read("coverage-summary") or {}
    regions = summary.get("uncovered_regions") or []
    kinds = Counter(str(r.get("kind")) for r in regions)
    risks = Counter(str(r.get("risk")) for r in regions)
    return {
        "round": round_no,
        "metrics": summary.get("metrics", {}),
        "acceptance": summary.get("acceptance", {}),
        "high_risk_uncovered": summary.get("high_risk_uncovered", 0),
        "stop_condition_met": summary.get("stop_condition_met", False),
        "regions": len(regions),
        "regions_by_kind": dict(sorted(kinds.items())),
        "regions_by_risk": dict(sorted(risks.items())),
        "refresh": info,
    }


# ---------------------------------------------------------------------------
# top level
# ---------------------------------------------------------------------------

def build_schedule(workspace: Path, target: str,
                   candidates: Sequence[Dict[str, Any]],
                   slots: int = DEFAULT_SLOTS,
                   quota: Optional[Dict[str, int]] = None,
                   weights: Optional[Dict[str, int]] = None,
                   round_no: int = 0,
                   refresh: bool = True,
                   pinned: Sequence[str] = (),
                   benchmark_feedback: Optional[Dict[str, Any]] = None
                   ) -> SchedulePlan:
    """Score, dedupe and select this round's candidates.

    Writes ``state/<target>/coverage/schedule-round-NN.json`` (and
    ``schedule-latest.json``) so the decision is reproducible and reviewable
    after the fact.  Returns the plan; it never mutates ``candidates``.
    ``pinned`` ids are always selected -- see :func:`stratified_select`.
    """
    workspace = Path(workspace).resolve()
    store = CoverageStore(workspace, target)
    # Order matters: the sweep must run *before* the context is loaded, or the
    # scores are computed against the previous round's coverage and this round
    # re-picks exactly the same candidates.  The sweep doubles as the scoring
    # input and as spec §14's post-round gap recomputation -- one refresh, and
    # the residual recorded on the plan is the one the scores were based on.
    coverage: Dict[str, Any] = {}
    if refresh:
        coverage = residual_sweep(store, workspace, target, round_no)
    memory = load_research_memory(workspace, target)
    ctx = ScheduleContext.from_store(
        store, weights, research_memory=memory.get("entries") or [],
        benchmark_feedback=benchmark_feedback)
    scores = score_candidates(candidates, ctx)
    selected, deferred, requested, filled, relocated = stratified_select(
        scores, slots, quota, pinned)
    # ``refresh=False`` is used when the caller recomputes coverage itself; the
    # plan then records that the residual was *not* measured rather than
    # reporting ``0`` uncovered -- an absent measurement must not read as "clean".
    residual = {
        "high_risk_uncovered": coverage.get("high_risk_uncovered"),
        "regions_by_kind": coverage.get("regions_by_kind"),
        "stop_condition_met": coverage.get("stop_condition_met"),
        "measured": bool(refresh),
    }
    selected_ids = {s.candidate_id for s in selected}
    plan = SchedulePlan(
        round_no=round_no, slots=slots, selected=selected, deferred=deferred,
        requested_quota=requested, filled_quota=filled,
        relocated_quota=relocated,
        category_counts=dict(sorted(Counter(s.category for s in selected).items())),
        coverage=coverage,
        residual=residual,
        weights=dict(ctx.weights),
        benchmark_feedback=dict(ctx.benchmark_feedback),
        weight_adjustments=dict(ctx.weight_adjustments),
        pinned=[str(cid) for cid in pinned if str(cid) in selected_ids],
    )
    payload = plan.as_dict()
    store.ensure()
    store.write("schedule-round-%02d" % round_no, payload)
    store.write("schedule-latest", payload)
    return plan


def load_schedule(store: CoverageStore, round_no: Optional[int] = None
                  ) -> Dict[str, Any]:
    """Read back a persisted schedule (latest when ``round_no`` is omitted)."""
    name = ("schedule-round-%02d" % round_no) if round_no else "schedule-latest"
    return store.read(name) or {}


def deferred_carryover(plan: SchedulePlan,
                       candidates: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Re-attach deferral reasons to the candidate dicts for the next round.

    The pipeline carries candidates forward as plain dicts, so the scheduler's
    verdict is written onto the candidate rather than kept in a side table --
    otherwise the reason would be lost the moment the round ends.
    """
    by_id = {str(c.get("candidate_id")): c for c in candidates}
    carried: List[Dict[str, Any]] = []
    for score in plan.deferred:
        candidate = by_id.get(score.candidate_id)
        if candidate is None:
            continue
        candidate["schedule"] = {
            "score": round(score.total, 2),
            "band": score.band,
            "category": score.category,
            "deferred": True,
            "reason": "not selected in round %d (score %.2f, band %s)"
                      % (plan.round_no, score.total, score.band),
        }
        carried.append(candidate)
    for score in plan.selected:
        candidate = by_id.get(score.candidate_id)
        if candidate is None:
            continue
        candidate["schedule"] = {
            "score": round(score.total, 2),
            "band": score.band,
            "category": score.category,
            "deferred": False,
            "factors": {k: round(v, 4) for k, v in score.factors.items()},
            "reasons": dict(score.reasons),
        }
    return carried


def apply_schedule_order(plan: SchedulePlan,
                         candidates: Sequence[Dict[str, Any]]
                         ) -> List[Dict[str, Any]]:
    """Reorder ``candidates`` so the scheduled ones come first, by score.

    Pure ordering: every candidate is returned exactly once, so no stage can
    lose one to the scheduler.  Deferred candidates keep their relative order by
    score, which keeps the carry-over deterministic.
    """
    by_id = {str(c.get("candidate_id")): c for c in candidates}
    ordered: List[Dict[str, Any]] = []
    for score in plan.selected + plan.deferred:
        candidate = by_id.pop(score.candidate_id, None)
        if candidate is not None:
            ordered.append(candidate)
    for candidate in candidates:  # ids the scheduler never saw (defensive)
        if str(candidate.get("candidate_id")) in by_id:
            ordered.append(candidate)
    return ordered


def selected_candidates(plan: SchedulePlan,
                        candidates: Sequence[Dict[str, Any]]
                        ) -> List[Dict[str, Any]]:
    """Just the candidates this round selected, in the plan's (score) order.

    This is the budget-honouring counterpart to :func:`apply_schedule_order`:
    a round of ``slots`` candidates must run ``slots`` audits, not the whole
    pool.  The deferred ones are not lost -- they stay in the pool and their
    verdict is on the plan, so the next round re-scores them against coverage
    that has since moved.
    """
    by_id = {str(c.get("candidate_id")): c for c in candidates}
    out: List[Dict[str, Any]] = []
    for score in plan.selected:
        candidate = by_id.get(score.candidate_id)
        if candidate is not None:
            out.append(candidate)
    return out


def round_selection(workspace, target: str,
                    candidates: Sequence[Dict[str, Any]], slots: int,
                    round_no: int = 0,
                    quota: Optional[Dict[str, int]] = None,
                    weights: Optional[Dict[str, int]] = None,
                    pinned: Sequence[str] = (),
                    refresh: bool = True,
                    benchmark_feedback: Optional[Dict[str, Any]] = None
                    ) -> Tuple[List[Dict[str, Any]], Optional[SchedulePlan], str]:
    """Pick this round's candidates, degrading to proposal order on failure.

    Returns ``(selected, plan, note)``.  ``plan`` is ``None`` and ``note`` is
    non-empty when the coverage index could not be read; the caller then gets
    the pre-PR3 behaviour -- the first ``slots`` candidates as proposed -- and a
    reason to record.  Degrading rather than raising is deliberate: an
    unavailable scheduler must cost a round its *ordering*, never its audit.
    The note is what keeps that degradation from being silent.
    """
    pool = [c for c in candidates if isinstance(c, dict)]
    slots = max(0, int(slots))
    if not pool:
        return [], None, "empty candidate pool"
    try:
        plan = build_schedule(workspace, target, pool, slots=slots, quota=quota,
                              weights=weights, round_no=round_no,
                              refresh=refresh, pinned=pinned,
                              benchmark_feedback=benchmark_feedback)
    except Exception as exc:  # pragma: no cover - defensive by design
        return pool[:slots], None, (
            "scheduler unavailable (%s: %s); fell back to proposal order"
            % (type(exc).__name__, exc))
    selected = selected_candidates(plan, pool)
    note = ""
    if len(selected) < len(plan.selected):
        note = ("%d scheduled candidate(s) are not in the pool"
                % (len(plan.selected) - len(selected)))
    return selected, plan, note


def render_schedule_text(plan: SchedulePlan, lang: str = "zh") -> str:
    """Human-readable plan, for the CLI and round logs."""
    zh = lang == "zh"
    lines: List[str] = []
    lines.append("安全审计候选调度" if zh else "Candidate Schedule")
    lines.append("─" * 52)
    lines.append(("%-10s %-8s %-7s %s" % ("候选", "类别", "分数", "档位")) if zh
                 else ("%-10s %-8s %-7s %s" % ("id", "category", "score", "band")))
    for score in plan.selected:
        lines.append("%-10s %-8s %-7.2f %s%s" % (
            score.candidate_id, score.category, score.total, score.band,
            "  (dup of %s)" % score.duplicate_of if score.duplicate_of else ""))
    lines.append("")
    quota_line = ", ".join("%s %d/%d" % (k, plan.filled_quota.get(k, 0), v)
                           for k, v in plan.requested_quota.items())
    lines.append(("配额：" if zh else "quota: ") + (quota_line or "—"))
    moved = {k: v for k, v in plan.relocated_quota.items() if v}
    if moved:
        lines.append(("配额转移：" if zh else "relocated: ")
                     + ", ".join("%s-%d" % (k, v) for k, v in sorted(moved.items())))
    lines.append(("类别分布：" if zh else "categories: ")
                 + (", ".join("%s=%d" % (k, v)
                              for k, v in plan.category_counts.items()) or "—"))
    if plan.deferred:
        lines.append(("延后 %d 个：" if zh else "%d deferred: ") % len(plan.deferred)
                     + ", ".join("%s(%.1f)" % (s.candidate_id, s.total)
                                 for s in plan.deferred[:8]))
    residual = plan.residual or {}
    if residual:
        if not residual.get("measured", True):
            lines.append(("高风险未审计：" if zh else "HIGH-risk uncovered: ")
                         + ("未测量（本轮未刷新覆盖）" if zh
                            else "not measured this round"))
            return "\n".join(lines)
        lines.append(("高风险未审计：" if zh else "HIGH-risk uncovered: ")
                     + str(residual.get("high_risk_uncovered") or "n/a"))
        met = bool(residual.get("stop_condition_met"))
        lines.append(("停止条件满足：" if zh else "stop condition met: ")
                     + (("是" if met else "否") if zh else ("yes" if met else "no")))
    return "\n".join(lines)


def _linked_from_score(score: CandidateScore,
                       ctx: ScheduleContext) -> LinkedRegions:
    """Re-link a persisted score from its own locations (no candidate dict)."""
    return linked_regions(
        {"code_location": ["%s:%d" % (f, n) for f, n in score.locations]}, ctx)


def prompt_coverage_block(ctx: ScheduleContext, plan: Optional[SchedulePlan] = None,
                          limit_regions: int = 15, limit_flows: int = 12,
                          limit_selected: int = 12, limit_candidates: int = 12) -> str:
    """The structured prompt input spec §15 requires.

    The section names and their order follow the spec's list literally --
    coverage summary, gaps, high-risk unreviewed regions, selected entries,
    selected sinks, security controls, candidate-relevant flows, prior
    candidates, rejected candidates, novelty requirement -- so the block can be
    diffed against the spec by eye.

    "Selected" means *selected by this round's plan*.  When ``plan`` is omitted
    there is no selection to report, and the two sections say so and fall back
    to an index snapshot rather than silently presenting everything as chosen.
    """
    indices = {
        "source-inventory": list(ctx.sources.values()),
        "entry-index": list(ctx.entries.values()),
        "sink-index": list(ctx.sinks.values()),
        "security-control-index": list(ctx.controls.values()),
        "flow-index": list(ctx.flows),
    }
    summary = cov.compute_coverage(indices, uncovered_probe=True)
    regions = summary.get("uncovered_regions") or []

    def top(regions_list, predicate, count):
        return [r for r in regions_list if predicate(r)][:count]

    lines: List[str] = []
    lines.append("## 覆盖率摘要 / Project Coverage Summary")
    counts = summary.get("counts", {})
    lines.append(json.dumps({
        "production_source_files": counts.get("production_source_files"),
        "indexed_source_files": counts.get("indexed_source_files"),
        "entries": counts.get("entries"),
        "entries_reviewed": counts.get("entries_reviewed"),
        "sinks": counts.get("sinks"),
        "sinks_reachability_analyzed": counts.get("sinks_reachability_analyzed"),
        "flows": counts.get("flows_total"),
        "flows_reviewed": counts.get("flows_reviewed"),
        "high_risk_uncovered": summary.get("high_risk_uncovered"),
    }, ensure_ascii=False))
    lines.append("## 验收指标 / Acceptance")
    for name, item in sorted((summary.get("acceptance") or {}).items()):
        actual = item.get("actual")
        lines.append("  %-32s %s (target >= %s)" % (
            name, "n/a" if actual is None else "%.1f%%" % (actual * 100),
            item.get("target")))
    lines.append("## 覆盖缺口 / Coverage Gaps")
    lines.append("  " + json.dumps({
        "high": counts.get("uncovered_high", 0),
        "medium": counts.get("uncovered_medium", 0),
        "low": counts.get("uncovered_low", 0),
    }, ensure_ascii=False))
    lines.append("## 高风险未审计区域 / High-risk Unreviewed Regions")
    for region in top(regions, lambda r: r.get("risk") == "high", limit_regions):
        location = ("%s:%s" % (region.get("file"), region.get("line"))
                    if region.get("file") else region.get("ref", ""))
        lines.append("  [%s] %s %s" % (region.get("kind"), location,
                                       region.get("reason", "")))

    selected_links = [_linked_from_score(s, ctx) for s in (plan.selected if plan else [])]
    lines.append("## 已选入口 / Selected Entries")
    if plan is None:
        lines.append("  （本轮无调度计划，以下为索引快照 / no round plan: index snapshot）")
        for entry in sorted(ctx.entries.values(),
                            key=lambda e: str(e.get("entry_id")))[:limit_selected]:
            lines.append("  %s (%s, %s:%s)" % (
                entry.get("entry_id"), entry.get("kind"),
                entry.get("file"), entry.get("line")))
    else:
        chosen: Dict[str, Dict[str, Any]] = {}
        for link in selected_links:
            for entry in link.entries:
                chosen.setdefault(str(entry.get("entry_id")), entry)
        for key in sorted(chosen)[:limit_selected]:
            entry = chosen[key]
            lines.append("  %s (%s, %s:%s)" % (
                entry.get("entry_id"), entry.get("kind"),
                entry.get("file"), entry.get("line")))

    lines.append("## 已选 Sink / Selected Sinks")
    if plan is None:
        lines.append("  （同上 / no round plan: index snapshot）")
        sink_pool = [s for s in ctx.sinks.values()
                     if str(s.get("severity_hint")) == "high"]
    else:
        sink_pool = []
        seen_sink: Dict[str, Dict[str, Any]] = {}
        for link in selected_links:
            for sink in link.sinks:
                seen_sink.setdefault(str(sink.get("sink_id")), sink)
        sink_pool = [seen_sink[k] for k in sorted(seen_sink)]
    for sink in sorted(sink_pool, key=lambda s: str(s.get("sink_id")))[:limit_selected]:
        lines.append("  %s (%s, %s:%s)" % (sink.get("sink_id"), sink.get("category"),
                                           sink.get("file"), sink.get("line")))

    lines.append("## 安全控制 / Security Controls")
    control_kinds = Counter(str(c.get("category")) for c in ctx.controls.values())
    lines.append("  " + json.dumps(dict(sorted(control_kinds.items())),
                                   ensure_ascii=False))

    lines.append("## 候选相关数据流 / Candidate-relevant Flows")
    if plan is None:
        flow_pool = list(ctx.flows)
    else:
        seen_flow: Dict[str, Dict[str, Any]] = {}
        for link in selected_links:
            for flow in link.flows_reaching + link.flows_on_path:
                seen_flow.setdefault(str(flow.get("flow_id")), flow)
        flow_pool = [seen_flow[k] for k in sorted(seen_flow)]
    for flow in sorted(flow_pool, key=lambda f: str(f.get("flow_id")))[:limit_flows]:
        lines.append("  %s %s -> %s | %s" % (
            flow.get("flow_id"), flow.get("entry_id"), flow.get("sink_id"),
            " -> ".join(flow.get("path") or [])))

    reviewed_records = [r for r in ctx.prior_coverage
                        if str(r.get("status") or "") == "confirmed"]
    lines.append("## 已审候选 / Prior Candidates")
    for record in sorted(reviewed_records,
                         key=lambda r: str(r.get("candidate_id")))[:limit_candidates]:
        lines.append("  %s [%s] %s" % (record.get("candidate_id"),
                                       record.get("status"),
                                       record.get("conclusion", "")))

    rejected_records = [r for r in ctx.prior_coverage
                        if str(r.get("status") or "") == "excluded"]
    lines.append("## 已否决候选 / Rejected Candidates")
    for record in sorted(rejected_records,
                         key=lambda r: str(r.get("candidate_id")))[:limit_candidates]:
        lines.append("  %s [%s] %s" % (record.get("candidate_id"),
                                       record.get("status"),
                                       record.get("conclusion", "")))

    lines.append("## 跨轮研究记忆 / Cross-round Research Memory")
    memory_rows = memory_prompt_rows(ctx.research_memory, limit_candidates)
    if not memory_rows:
        lines.append("  （暂无可复用的运行时记忆 / no reusable runtime memory）")
    for row in memory_rows:
        hints = "; ".join(row.get("next_probe_hints") or []) or "-"
        review = row.get("review_status")
        review_text = (" review=%s/%s" % (
            review, row.get("reason_code") or "-") if review else "")
        variants = "; ".join(row.get("fix_variants") or [])
        variant_text = (" fix_variants=%s" % variants) if variants else ""
        lines.append("  %s [%s, round=%s]%s next=%s claim_status=%s" % (
            row.get("candidate_id") or row.get("research_key"),
            row.get("state"), row.get("round", 0), review_text + variant_text, hints,
            row.get("claim_status", "not-a-finding")))

    lines.append("## 评测反馈 / Benchmark Feedback")
    if not ctx.benchmark_feedback:
        lines.append("  （暂无：本轮未提供 research-benchmark feedback / none supplied）")
    else:
        feedback = ctx.benchmark_feedback
        lines.append("  " + json.dumps({
            "benchmark_id": feedback.get("benchmark_id"),
            "alerts": [item.get("code") for item in feedback.get("alerts", [])
                       if isinstance(item, dict)],
            "weight_adjustments": ctx.weight_adjustments,
            "surface_guidance": list(feedback.get("surface_guidance") or [])[:8],
            "trend": feedback.get("trend") or {},
            "prompt_hints": list(feedback.get("prompt_hints") or [])[:8],
            "claim_status": feedback.get("claim_status", "not-a-finding"),
        }, ensure_ascii=False))

    lines.append("## 覆盖新颖性要求 / Coverage Novelty Requirement")
    lines.append("  优先生成来自未覆盖区域的候选；禁止重复已排除的机制，"
                 "除非存在新的数据流、安全控制差分或版本差分证据。稳定重放"
                 "只能减少重复实验，不能证明不存在漏洞；环境缺口必须修复后重试；"
                 "可行动版本差异应优先转化为最小复现和 source→sink 证据。")
    return "\n".join(lines)
