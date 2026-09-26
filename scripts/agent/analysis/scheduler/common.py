"""Shared scheduler context, policy constants, and score model types."""

from __future__ import annotations


import json
import hashlib
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .. import coverage as cov
from ..inventory import (COVERAGE_SCOPE_VERSION, CoverageStore,
                        load_inventory)
from ...evaluation.benchmark import (
    BENCHMARK_FEEDBACK_FACTORS,
    MAX_FEEDBACK_WEIGHT_DELTA,
    RESEARCH_SURFACES,
    normalize_benchmark_feedback,
)
from ...memory.research import (
    STATE_DECISION_RECORDED,
    STATE_REVIEW_ACCEPTED,
    STATE_REVIEW_NEEDS_EVIDENCE,
    STATE_REVIEW_REJECTED,
    STATE_REVIEW_SCOPE_CORRECTED,
    load_research_memory,
    load_review_feedback,
    memory_match,
    memory_prompt_rows,
    research_key,
)
from ...memory.portfolio import load_research_portfolio
from ..research_agenda import (load_research_agenda,
                              normalize_candidate_ids,
                              normalize_research_agenda)
from ..research_strategy import (
    STRATEGY_GUIDANCE_ACTIONS,
    apply_research_guidance,
    build_research_strategy,
    load_research_strategy,
    normalize_research_strategy,
    write_research_guidance,
    write_research_strategy,
)
from ...tools.surface_variants import normalize_surface_variant_plan
from ..threat_model import load_threat_model

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

# A candidate *pool* is evidence inventory, not a per-round work order.  The
# active window bounds score computation and artifact size even when static
# layers emit tens of thousands of leads.  All source candidates remain in
# their producer artifacts; the intake artifact records the deterministic
# window and the still-unscheduled count.
CANDIDATE_INTAKE_SCHEMA_VERSION = "candidate-intake-v2"
DEFAULT_CANDIDATE_INTAKE_MINIMUM = 64
CANDIDATE_INTAKE_MULTIPLIER = 12
MAX_CANDIDATE_INTAKE_WINDOW = 256

#: Priority bands, as a fraction of the achievable total.
BAND_HIGH = 0.65
BAND_MEDIUM = 0.40

RESEARCH_SURFACE_TARGET_TYPES: Dict[str, str] = {
    "web-app": "web", "middleware": "protocol", "message-rpc": "protocol",
    "cloud-service": "cloud", "mobile-app": "mobile", "native-app": "native",
}

# The agenda is a bounded scheduling signal.  It can make an explicitly
# selected research item visible within a finite candidate budget, but it is
# deliberately smaller than a finding-impact adjustment and never suppresses
# an otherwise eligible candidate.
RESEARCH_AGENDA_BOOST = 3.0


def _safe_weight(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _safe_delta(value: Any) -> int:
    try:
        return max(-8, min(8, int(value)))
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
# The portfolio is a project-level view, so its scheduling signal is smaller
# than a mechanism's direct runtime/review event.  It is a nudge for an
# explicitly matching pending probe, never a finding or a hard selection.
RESEARCH_PORTFOLIO_PROBE_BOOST = 2.0
# The synthesized strategy is a cross-artifact planning signal.  It is smaller
# than direct runtime/review feedback and can never exceed the score scale.
RESEARCH_STRATEGY_BOOST = 1.5

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
    research_portfolio: Dict[str, Any] = field(default_factory=dict)
    research_strategy: Dict[str, Any] = field(default_factory=dict)
    research_agenda: Dict[str, Any] = field(default_factory=dict)
    threat_model: Dict[str, Any] = field(default_factory=dict)
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
                   benchmark_feedback: Optional[Dict[str, Any]] = None,
                   research_portfolio: Optional[Dict[str, Any]] = None,
                   research_strategy: Optional[Dict[str, Any]] = None,
                   research_agenda: Optional[Dict[str, Any]] = None,
                   threat_model: Optional[Dict[str, Any]] = None
                   ) -> "ScheduleContext":
        indices = load_inventory(store)
        reachability = {str(r.get("sink_id")): r
                        for r in indices.get("sink-reachability") or []}
        feedback = normalize_benchmark_feedback(benchmark_feedback or {})
        portfolio = (research_portfolio if isinstance(research_portfolio, dict)
                     else load_research_portfolio(store.workspace, store.target))
        strategy = (research_strategy if isinstance(research_strategy, dict)
                    else load_research_strategy(store.workspace, store.target))
        agenda = (normalize_research_agenda(research_agenda)
                  if isinstance(research_agenda, dict)
                  else load_research_agenda(store.workspace, store.target))
        model = (threat_model if isinstance(threat_model, dict)
                 else load_threat_model(store.workspace, store.target))
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
            research_portfolio=portfolio,
            research_strategy=strategy,
            research_agenda=agenda,
            threat_model=model,
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


def _coverage_scope_blocker(store: CoverageStore,
                            check_coverage_summary: bool = True) -> str:
    """Explain why persisted indices cannot support a coverage-aware schedule."""
    build_status = store.read("coverage-build-status") or {}
    if isinstance(build_status, dict) and build_status.get("status") in {
            "running", "incomplete", "failed"}:
        return "coverage build %s" % build_status.get("status")
    inventory = store.read("inventory-summary") or {}
    scope = inventory.get("scope") if isinstance(inventory, dict) else None
    if not isinstance(scope, dict):
        return "inventory scope metadata missing"
    if scope.get("schema_version") != COVERAGE_SCOPE_VERSION:
        return "inventory scope schema is missing or outdated"
    if scope.get("valid") is not True:
        gaps = [str(value) for value in scope.get("analysis_gaps") or [] if value]
        return "inventory scope invalid%s" % (
            ": " + ", ".join(gaps[:4]) if gaps else "")
    try:
        source_count = int(scope.get("source_file_count") or 0)
    except (TypeError, ValueError):
        source_count = 0
    if source_count <= 0:
        return "source universe is empty"
    required_indices = {
        "source-inventory", "entry-index", "sink-index",
        "security-control-index", "symbol-index", "flow-index",
    }
    missing = sorted(required_indices - set(store.existing_indices()))
    if missing:
        return "required indices missing: %s" % ", ".join(missing)
    if check_coverage_summary:
        coverage = store.read("coverage-summary") or {}
        audit_status = (coverage.get("audit_status")
                        if isinstance(coverage, dict) else None)
        if isinstance(audit_status, dict) and (
                audit_status.get("scope_present") is False
                or audit_status.get("scope_valid") is False):
            return "coverage summary reports an invalid scope"
    return ""

