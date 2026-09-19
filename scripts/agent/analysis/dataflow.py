"""Cross-procedural Source → Sink and Sink → Source analysis (spec §9, §10).

The pipeline this module reasons about is::

    Entry → Source → Transform → Validation → Authorization → Sink

Two independent passes, because they answer two different questions:

* **forward** (§9) -- "from this external entry, which sinks are reachable?"
  A breadth-first walk from every symbol that hosts an entry.
* **backward** (§10) -- "who can call this sink, and does it trace back to an
  external entry?"  A breadth-first walk from every symbol that hosts a sink.
  §19.4 asks that a path only the sink scan could see either becomes a valid
  flow or a recorded coverage gap; running both passes is what makes that
  decidable instead of hopeful.

Confidence discipline (spec §9: 禁止把 heuristic 自动提升为"已证实漏洞"):

* Every flow produced here is ``heuristic-callgraph`` / ``static-inferred``.
* A flow is a **lead**, never a proof.  Nothing here sets ``runtime-verified``;
  only runtime evidence may satisfy that gate, and it does not come from this
  module.

Cost model.  Reachability is one BFS per *unique entry symbol* plus one per
*unique sink symbol* -- not one per (entry, sink) pair.  Paths are read off the
recorded BFS parents, so emitting N flows costs O(N · path length) rather than
O(N · |E|).

Bounds.  ``max_hops`` caps how long a single chain may run (a 12-hop chain
through a name-resolved graph is mostly accumulated ambiguity, not signal), and
``max_flows`` is a safety valve against pathological explosion.  Neither is a
silent truncation: both are counted and surfaced in :meth:`FlowIndex.summary`.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import models
from .callgraph import CallGraph, backward_tree, forward_tree, path_from_tree
from .symbols import FILE_KIND, group_by_file, innermost_at

# --- control classification (spec §11 vocabulary) --------------------------

#: Controls that gate *identity or entitlement*.
AUTHORIZATION_CATEGORIES = frozenset({
    "authentication", "authorization", "permission", "role", "owner", "tenant",
    "acl",
})

#: Controls that gate the *shape or content* of the data.
VALIDATION_CATEGORIES = frozenset({
    "validation", "sanitization", "normalization", "allowlist", "denylist",
    "length-limit", "depth-limit", "path-check", "origin-check",
    "signature-check", "csrf",
})

#: Controls that only rewrite the data as it moves.
TRANSFORM_CATEGORIES = frozenset({"encoding"})

#: Sink severity that earns a short chain the ``high`` band.
HIGH_SEVERITY = "high"

#: Hops (path length minus one) at which a chain stops being trivially auditable.
HIGH_PRIORITY_MAX_HOPS = 3
MEDIUM_PRIORITY_MAX_HOPS = 5

#: Default reach cap for one chain.  Beyond this the graph is mostly heuristic
#: noise; the tail is counted, not hidden.
DEFAULT_MAX_HOPS = 8

#: Safety valve, not a design limit.  A monorepo with a densely connected
#: name-resolved graph can otherwise emit flows without bound.
DEFAULT_MAX_FLOWS = 100_000

#: Sort order for bounded presentation.
PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}

#: Path shapes recorded in ``FlowRecord.direction``.  A one-node path is still a
#: real entry->sink relation, but its meaning depends entirely on who owns the
#: node: a *method* is a handler, a *file* is not.
DIRECTION_CROSS = "cross-procedural"
DIRECTION_INTRA = "intra-symbol"
DIRECTION_MODULE = "module-scope"

#: Reachability verdicts recorded per sink.  Empty string means "clean".
GAP_UNBOUND = "unbound"
GAP_ISOLATED = "isolated"
GAP_FORWARD_ONLY = "forward-only"
GAP_BACKWARD_ONLY = "backward-only"
GAP_PATH_MISMATCH = "path-mismatch"


@dataclass
class SinkReachability:
    """Per-sink verdict of the two passes (drives coverage §5.3 and gap §14.5)."""

    sink_id: str
    file: str = ""
    line: int = 0
    symbol_id: str = ""
    bound: bool = False
    forward: bool = False
    backward: bool = False
    forward_entries: List[str] = field(default_factory=list)
    backward_entries: List[str] = field(default_factory=list)
    flow_count: int = 0
    coverage_gap: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "sink_id": self.sink_id,
            "file": self.file,
            "line": self.line,
            "symbol_id": self.symbol_id,
            "bound": self.bound,
            "forward_seen": self.forward,
            "backward_seen": self.backward,
            "forward_entries": list(self.forward_entries),
            "backward_entries": list(self.backward_entries),
            "flow_count": self.flow_count,
            "coverage_gap": self.coverage_gap,
            "confidence": "heuristic-callgraph",
            "producer": "callgraph",
            "evidence_type": "static-inferred",
        }


@dataclass
class FlowIndex:
    """The persisted ``flow-index`` plus the per-sink reachability verdict."""

    flows: List[models.FlowRecord] = field(default_factory=list)
    reachability: Dict[str, SinkReachability] = field(default_factory=dict)
    entries_total: int = 0
    sinks_total: int = 0
    entries_unbound: int = 0
    sinks_unbound: int = 0
    max_hops: int = DEFAULT_MAX_HOPS
    truncated: bool = False
    dropped_flows: int = 0
    unbound_samples: List[Dict[str, str]] = field(default_factory=list)

    def as_dicts(self) -> List[Dict[str, Any]]:
        return [flow.as_dict() for flow in self.flows]

    def reachability_dicts(self) -> List[Dict[str, Any]]:
        return [self.reachability[key].as_dict()
                for key in sorted(self.reachability)]

    def gaps(self) -> List[Dict[str, Any]]:
        """Sinks carrying a coverage gap, highest-signal verdict first."""
        order = {GAP_BACKWARD_ONLY: 0, GAP_PATH_MISMATCH: 1, GAP_FORWARD_ONLY: 2,
                 GAP_UNBOUND: 3, GAP_ISOLATED: 4}
        records = [r for r in self.reachability.values() if r.coverage_gap]
        records.sort(key=lambda r: (order.get(r.coverage_gap, 9), r.sink_id))
        return [r.as_dict() for r in records]

    def summary(self, sample_limit: int = 20) -> Dict[str, Any]:
        priority = Counter(flow.priority for flow in self.flows)
        confidence = Counter(flow.confidence for flow in self.flows)
        direction = Counter(flow.direction for flow in self.flows)
        gaps = Counter(r.coverage_gap for r in self.reachability.values()
                       if r.coverage_gap)
        hops = [len(flow.path) - 1 for flow in self.flows]
        return {
            "entries": self.entries_total,
            "sinks": self.sinks_total,
            "entries_unbound": self.entries_unbound,
            "sinks_unbound": self.sinks_unbound,
            "flows": len(self.flows),
            "flows_by_priority": dict(sorted(priority.items())),
            "flows_by_confidence": dict(sorted(confidence.items())),
            "flows_by_direction": dict(sorted(direction.items())),
            "hops_max_observed": max(hops) if hops else 0,
            "hops_max_allowed": self.max_hops,
            "sinks_forward_seen": sum(1 for r in self.reachability.values()
                                      if r.forward),
            "sinks_backward_seen": sum(1 for r in self.reachability.values()
                                       if r.backward),
            "coverage_gaps": dict(sorted(gaps.items())),
            "truncated": self.truncated,
            "dropped_flows": self.dropped_flows,
            "unbound_samples": self.unbound_samples[:sample_limit],
            "confidence": "heuristic-callgraph",
            "producer": "callgraph",
            "evidence_type": "static-inferred",
            "limitations": [
                "reachability over a name-resolved call graph; no virtual "
                "dispatch, DI container, reflection or async modelling",
                "a flow is a lead, not a proof; only runtime evidence may "
                "satisfy the verification gate",
                "temporal ordering of controls along a path is not established: "
                "a control on the path is not a control protecting the sink",
                "module-scope flows are kept but ranked below real call chains, "
                "because a file is not a handler",
            ],
        }


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _bind_by_symbol(records: Iterable[object], grouped, known_ids,
                    unbound: List[str]) -> Dict[str, List[Any]]:
    """Group records by owning symbol, falling back to the line lookup.

    A record whose ``symbol_id`` is a PR1-style ``<file>#<name>`` hint, or is
    empty, is re-bound to the innermost real symbol.  If even that fails the
    record is appended to ``unbound`` so the caller can surface the shortfall.
    """
    index: Dict[str, List[Any]] = {}
    for record in records:
        symbol_id = str(getattr(record, "symbol_id", "") or "")
        if symbol_id not in known_ids:
            owner = innermost_at(grouped, str(getattr(record, "file", "")),
                                 int(getattr(record, "line", 0) or 0))
            if owner is None:
                unbound.append(symbol_id or str(getattr(record, "file", "")))
                continue
            symbol_id = owner.symbol_id
            record.symbol_id = symbol_id
        index.setdefault(symbol_id, []).append(record)
    return index


def _control_buckets(controls: Iterable[models.SecurityControlRecord],
                     path: Sequence[str]
                     ) -> Tuple[List[str], List[str], List[str]]:
    """Split the controls on ``path`` into (authorizations, validations, transforms).

    Membership is by owning symbol, i.e. "this control lives in a function the
    flow passes through".  That is deliberately coarse: it does not prove the
    control runs before the sink, or on the same branch.  Callers must read
    ``authorizations`` / ``validations`` as "present on the path", never as
    "protects this sink" -- the scheduler raises control-gap candidates exactly
    because presence is not protection.
    """
    on_path = set(path)
    authz: List[str] = []
    validation: List[str] = []
    transform: List[str] = []
    for control in controls:
        if getattr(control, "symbol_id", "") not in on_path:
            continue
        label = "%s:%s" % (control.category, control.api or control.control_type)
        if control.category in AUTHORIZATION_CATEGORIES:
            if label not in authz:
                authz.append(label)
        elif control.category in VALIDATION_CATEGORIES:
            if label not in validation:
                validation.append(label)
        elif control.category in TRANSFORM_CATEGORIES:
            if label not in transform:
                transform.append(label)
    authz.sort()
    validation.sort()
    transform.sort()
    return authz, validation, transform


def _priority(hops: int, severity: str, gap: str) -> str:
    if gap:
        return "high"
    if severity == HIGH_SEVERITY and hops <= HIGH_PRIORITY_MAX_HOPS:
        return "high"
    if severity == HIGH_SEVERITY or hops <= MEDIUM_PRIORITY_MAX_HOPS:
        return "medium"
    return "low"


def _shape(hops: int, source_kind: str) -> str:
    """Classify a path by shape, which is what makes its evidence comparable.

    A zero-hop path means entry and sink sit in the *same* symbol.  That is a
    genuine relation and must not be dropped -- ``@PostMapping void up() {
    Runtime.exec(x); }`` is the archetypal finding -- but it is a different
    kind of evidence from a multi-hop call chain, and the two must not be
    ranked as if they were the same.

    The discriminating question is whether the owning symbol is a *handler*.
    A method is, so a direct hit inside it keeps its full priority.  A file is
    not: entry and sink both in module scope says nothing about who controls
    the input, so it is reported but not allowed to outrank real call chains.
    """
    if hops > 0:
        return DIRECTION_CROSS
    return DIRECTION_MODULE if source_kind == FILE_KIND else DIRECTION_INTRA


# ---------------------------------------------------------------------------
# main entry point
# ---------------------------------------------------------------------------

def build_flow_index(root: Path,
                     symbols: Sequence[models.SymbolRecord],
                     graph: CallGraph,
                     entries: Sequence[models.EntryRecord],
                     sinks: Sequence[models.SinkRecord],
                     controls: Sequence[models.SecurityControlRecord] = (),
                     max_hops: int = DEFAULT_MAX_HOPS,
                     max_flows: int = DEFAULT_MAX_FLOWS) -> FlowIndex:
    """Run both passes and emit the flow index.

    ``entries``/``sinks`` are mutated in place where the symbol binding changes,
    and ``sinks`` also receives the reachability verdict -- that is how §5.3
    (sink coverage) and gap kind 5 (forward/backward mismatch) get their inputs.
    """
    del root  # paths come from the graph; uniform call signature with siblings
    grouped = group_by_file(symbols)
    known_ids = {symbol.symbol_id for symbol in symbols}

    entry_unbound: List[str] = []
    sink_unbound: List[str] = []
    entries_by_symbol = _bind_by_symbol(entries, grouped, known_ids, entry_unbound)
    sinks_by_symbol = _bind_by_symbol(sinks, grouped, known_ids, sink_unbound)

    index = FlowIndex(
        entries_total=len(entries), sinks_total=len(sinks),
        entries_unbound=len(entry_unbound), sinks_unbound=len(sink_unbound),
        max_hops=max_hops,
    )
    for label, names in (("entry", entry_unbound), ("sink", sink_unbound)):
        for name in names[:10]:
            index.unbound_samples.append({"kind": label, "symbol_id": name})
    if entry_unbound or sink_unbound:
        # Surfaced, not silent: a symbol-less record cannot be reached by any
        # graph walk, so without this note it would vanish from flow analysis.
        index.unbound_samples.append({
            "kind": "unbound-summary",
            "symbol_id": "%d entries / %d sinks have no symbol binding"
                        % (len(entry_unbound), len(sink_unbound)),
        })

    entry_symbols = sorted(entries_by_symbol)
    sink_symbols = sorted(sinks_by_symbol)
    entry_ids_by_symbol = {symbol: sorted(
        str(getattr(record, "entry_id", ""))
        for record in entries_by_symbol[symbol]) for symbol in entry_symbols}

    # --- pass 1: forward reachability from every entry symbol ---------------
    forward_trees: Dict[str, Dict[str, Tuple[int, Optional[str]]]] = {
        symbol: forward_tree(graph, symbol, max_hops) for symbol in entry_symbols}

    # --- pass 2: backward reachability from every sink symbol ---------------
    backward_trees: Dict[str, Dict[str, Tuple[int, Optional[str]]]] = {
        symbol: backward_tree(graph, symbol, max_hops) for symbol in sink_symbols}

    reachability: Dict[str, SinkReachability] = {}
    for sink in sinks:
        sink_id = str(getattr(sink, "sink_id", ""))
        symbol_id = str(getattr(sink, "symbol_id", "") or "")
        entry_ids: List[str] = []
        tree = backward_trees.get(symbol_id, {})
        for node in sorted(tree):
            entry_ids.extend(entry_ids_by_symbol.get(node, ()))
        reachability[sink_id] = SinkReachability(
            sink_id=sink_id, file=str(getattr(sink, "file", "")),
            line=int(getattr(sink, "line", 0) or 0), symbol_id=symbol_id,
            bound=bool(symbol_id) and symbol_id in known_ids,
            backward=bool(entry_ids),
            backward_entries=sorted(set(entry_ids)),
        )

    # --- pass 3: emit flows (also fills forward reachability) ---------------
    severity_of = {str(getattr(sink, "sink_id", "")):
                   str(getattr(sink, "severity_hint", "medium")) for sink in sinks}
    kind_of = {symbol.symbol_id: symbol.kind for symbol in symbols}
    ordered_sinks = sorted(sinks,
                           key=lambda s: (str(getattr(s, "sink_id", "")),
                                          str(getattr(s, "file", "")),
                                          int(getattr(s, "line", 0) or 0)))
    flows: List[models.FlowRecord] = []
    for sink in ordered_sinks:
        sink_id = str(getattr(sink, "sink_id", ""))
        reach = reachability[sink_id]
        symbol_id = reach.symbol_id
        if not symbol_id or not reach.bound:
            # No symbol node to walk from.  Recorded, never dropped: §14 kind 2
            # still lists every unreviewed high-severity sink.
            reach.coverage_gap = GAP_UNBOUND
            continue
        if not entry_symbols:
            # Nothing external to reach it from; a property of the target, not
            # of this sink.
            reach.coverage_gap = GAP_ISOLATED
            continue
        backward = backward_trees.get(symbol_id, {})
        forward_entries: List[str] = []
        worst_gap = ""
        for entry_symbol in entry_symbols:
            tree = forward_trees[entry_symbol]
            if symbol_id not in tree:
                continue
            forward_entries.extend(entry_ids_by_symbol[entry_symbol])
            hops = tree[symbol_id][0]
            forward_path = path_from_tree(tree, symbol_id)
            backward_path = path_from_tree(backward, entry_symbol)
            if backward_path:
                backward_path = list(reversed(backward_path))
            if not backward_path:
                gap = GAP_FORWARD_ONLY
            elif backward_path != forward_path:
                # §10: forward path != backward path.  Both are shortest chains
                # in a name-resolved graph, so a disagreement means the resolver
                # saw more than one candidate at some hop.
                gap = GAP_PATH_MISMATCH
            else:
                gap = ""
            if gap and not worst_gap:
                worst_gap = gap
            shape = _shape(hops, kind_of.get(entry_symbol, ""))
            authz, validation, transform = _control_buckets(controls, forward_path)
            priority = _priority(hops, severity_of.get(sink_id, "medium"), gap)
            if shape == DIRECTION_MODULE and priority == "high":
                # Module scope is not a handler: keep the finding, lose the
                # precedence it would otherwise take from real call chains.
                priority = "medium"
            for entry in entries_by_symbol[entry_symbol]:
                if len(flows) >= max_flows:
                    index.truncated = True
                    index.dropped_flows += 1
                    continue
                flows.append(models.FlowRecord(
                    flow_id="flow-%08d" % (len(flows) + 1),
                    entry_id=str(getattr(entry, "entry_id", "")),
                    source_symbol=entry_symbol,
                    sink_id=sink_id,
                    path=list(forward_path),
                    transforms=transform,
                    validations=validation,
                    authorizations=authz,
                    confidence="heuristic-callgraph",
                    direction=shape,
                    priority=priority,
                    review_state="pending",
                    coverage_gap=gap,
                ))
                reach.flow_count += 1
        reach.forward = bool(forward_entries)
        reach.forward_entries = sorted(set(forward_entries))
        if not reach.forward and reach.backward:
            # §19.4: only the sink scan could see the path.
            reach.coverage_gap = GAP_BACKWARD_ONLY
        elif not reach.forward and not reach.backward:
            # Bound to a real symbol, but no entry reaches it and it has no
            # caller that reaches one: dead code, or a path the heuristic graph
            # cannot express (reflection, DI, callbacks).  Worth a look.
            reach.coverage_gap = GAP_ISOLATED
        else:
            reach.coverage_gap = worst_gap

    # --- reflect onto the sink records (drives §5.3 and gap kind 5) ----------
    for sink in sinks:
        reach = reachability.get(str(getattr(sink, "sink_id", "")))
        if reach is None:
            continue
        # Entry ids, not a bool: ``coverage.py`` reads these for truthiness, so
        # "empty means no reachability known" still holds, and the sink index
        # additionally records *which* entries reach it.
        sink.reachable_from_entries = list(reach.forward_entries)
        sink.backward_reachable = reach.backward
        sink.backward_entries = list(reach.backward_entries)

    index.flows = flows
    index.reachability = reachability
    return index


def summarize_flows(flows: Sequence[models.FlowRecord],
                    limit: int = 25) -> List[Dict[str, Any]]:
    """Bounded, priority-ordered presenter for prompts and the ledger.

    The index itself is never truncated; this only bounds what is *shown*.
    """
    ordered = sorted(flows, key=lambda f: (PRIORITY_ORDER.get(f.priority, 9),
                                           len(f.path), f.flow_id))
    out: List[Dict[str, Any]] = []
    for flow in ordered[:max(0, limit)]:
        out.append({
            "flow_id": flow.flow_id,
            "priority": flow.priority,
            "entry_id": flow.entry_id,
            "sink_id": flow.sink_id,
            "hops": len(flow.path) - 1,
            "path": list(flow.path),
            "authorizations": list(flow.authorizations),
            "validations": list(flow.validations),
            "coverage_gap": flow.coverage_gap,
            "review_state": flow.review_state,
        })
    return out


def flow_stats(flows: Sequence[models.FlowRecord]) -> Dict[str, Any]:
    """Aggregate counts used by the ledger and the coverage CLI."""
    priorities = Counter(flow.priority for flow in flows)
    return {
        "total": len(flows),
        "high": priorities.get("high", 0),
        "medium": priorities.get("medium", 0),
        "low": priorities.get("low", 0),
        "pending": sum(1 for f in flows if f.review_state == "pending"),
        "gapped": sum(1 for f in flows if f.coverage_gap),
    }
