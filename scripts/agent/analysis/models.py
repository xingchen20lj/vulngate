"""Coverage ledger data model (spec §4).

Every record carries the provenance fields required by spec §21.2 --
``producer`` / ``confidence`` / ``evidence_type`` -- plus ``file``/``line``/
``symbol`` where they apply.  Coverage numbers are computed from these records
by :mod:`agent.analysis.coverage`; nothing here consults an LLM.

Audit-state vocabulary (spec §4.1) is shared by every record type so the
``coverage`` query language is uniform:

    unseen -> indexed -> triaged -> reviewed -> runtime-verified
                          \\-> excluded

``reviewed-or-better`` (the numerator of most coverage ratios) means
``reviewed``, ``runtime-verified`` or ``excluded`` -- an explicitly excluded
region *has* been looked at, which is exactly what coverage measures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

AUDIT_STATES: Tuple[str, ...] = (
    "unseen",
    "indexed",
    "triaged",
    "reviewed",
    "runtime-verified",
    "excluded",
)

#: States that count as "an analyst has looked at this" (coverage numerator).
REVIEWED_STATES: Tuple[str, ...] = ("reviewed", "runtime-verified", "excluded")

#: States that count as "still owed an answer" (residual / gap material).
OPEN_STATES: Tuple[str, ...] = ("unseen", "indexed", "triaged")

_STATE_RANK: Dict[str, int] = {state: i for i, state in enumerate(AUDIT_STATES)}

#: States that may never be reached without runtime evidence (spec §9 / G4).
RUNTIME_ONLY_STATES: Tuple[str, ...] = ("runtime-verified",)

CONFIDENCE_LEVELS: Tuple[str, ...] = (
    "exact",
    "ast",
    "heuristic-callgraph",
    "heuristic-nearby",
    "unknown",
)

#: Confidences that must never be silently promoted to "proven" (spec §9).
NON_PROVING_CONFIDENCES: Tuple[str, ...] = ("heuristic-callgraph",
                                            "heuristic-nearby", "unknown")


def normalize_audit_state(value: Any, default: str = "indexed") -> str:
    text = str(value or "").strip().lower().replace("_", "-")
    if text in _STATE_RANK:
        return text
    return default


def state_rank(value: Any) -> int:
    return _STATE_RANK.get(normalize_audit_state(value), 0)


def is_reviewed(value: Any) -> bool:
    return normalize_audit_state(value) in REVIEWED_STATES


def is_open(value: Any) -> bool:
    state = normalize_audit_state(value)
    return state in OPEN_STATES


def is_proving(confidence: Any) -> bool:
    """True when ``confidence`` may back a *confirmed* conclusion."""
    return str(confidence or "").strip().lower() in ("exact", "ast")


def merge_state(current: Any, incoming: Any) -> str:
    """Keep the stronger of two audit states (monotonic coverage updates)."""
    return (normalize_audit_state(incoming)
            if state_rank(incoming) > state_rank(current)
            else normalize_audit_state(current))


def _provenance(producer: str, confidence: str,
                evidence_type: str = "static-observed") -> Dict[str, str]:
    return {"producer": producer, "confidence": confidence,
            "evidence_type": evidence_type}


@dataclass
class SourceFileRecord:
    """One file in the source universe (spec §4.1)."""

    file: str
    language: Optional[str] = None
    size: int = 0
    production: bool = False
    generated: bool = False
    vendor: bool = False
    test: bool = False
    indexed: bool = False
    skip_reason: str = ""
    #: Symbols declared in this file, including the synthetic file-level one.
    symbols: int = 0
    #: Symbols that are actually callable/typed (i.e. excluding the file-level
    #: symbol).  ``symbols > 0 and callables == 0`` means the file contains only
    #: module-level code -- legal, but worth seeing when flow analysis finds
    #: nothing to traverse.
    callables: int = 0
    entries: int = 0
    sinks: int = 0
    controls: int = 0
    audit_state: str = "unseen"
    producer: str = "walk"
    confidence: str = "exact"
    evidence_type: str = "static-observed"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "language": self.language,
            "size": self.size,
            "production": self.production,
            "generated": self.generated,
            "vendor": self.vendor,
            "test": self.test,
            "indexed": self.indexed,
            "skip_reason": self.skip_reason,
            "symbols": self.symbols,
            "callables": self.callables,
            "entries": self.entries,
            "sinks": self.sinks,
            "controls": self.controls,
            "audit_state": self.audit_state,
            "producer": self.producer,
            "confidence": self.confidence,
            "evidence_type": self.evidence_type,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SourceFileRecord":
        kwargs = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        return cls(**kwargs)


@dataclass
class SymbolRecord:
    """A class/method/function (spec §4.2)."""

    symbol_id: str
    language: str
    file: str
    start_line: int
    end_line: int
    kind: str
    name: str
    class_name: str = ""
    namespace: str = ""
    parameters: List[str] = field(default_factory=list)
    callers: List[str] = field(default_factory=list)
    callees: List[str] = field(default_factory=list)
    reachable_from_entries: List[str] = field(default_factory=list)
    security_surfaces: List[str] = field(default_factory=list)
    audit_state: str = "indexed"
    candidate_ids: List[str] = field(default_factory=list)
    producer: str = "regex"
    confidence: str = "heuristic"
    evidence_type: str = "static-observed"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "symbol_id": self.symbol_id,
            "language": self.language,
            "file": self.file,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "kind": self.kind,
            "name": self.name,
            "class": self.class_name,
            "namespace": self.namespace,
            "parameters": list(self.parameters),
            "callers": list(self.callers),
            "callees": list(self.callees),
            "reachable_from_entries": list(self.reachable_from_entries),
            "security_surfaces": list(self.security_surfaces),
            "audit_state": self.audit_state,
            "candidate_ids": list(self.candidate_ids),
            "producer": self.producer,
            "confidence": self.confidence,
            "evidence_type": self.evidence_type,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SymbolRecord":
        payload = dict(data)
        if "class" in payload and "class_name" not in payload:
            payload["class_name"] = payload.pop("class")
        kwargs = {k: payload[k] for k in cls.__dataclass_fields__ if k in payload}
        return cls(**kwargs)


@dataclass
class EntryRecord:
    """An external input entry point (spec §4.3)."""

    entry_id: str
    kind: str
    file: str
    line: int
    symbol_id: str = ""
    input_shape: str = ""
    untrusted: bool = True
    framework: str = ""
    api: str = ""
    target_type: str = ""
    #: Target-type rule label (``http-entry`` / ``authz-boundary`` / ...) when the
    #: entry came from ``tools.target_rules.TARGET_RULES`` rather than the
    #: language-agnostic catalog.  Keeps ``kind`` a clean enum.
    rule_label: str = ""
    review_state: str = "indexed"
    candidate_ids: List[str] = field(default_factory=list)
    producer: str = "regex"
    confidence: str = "heuristic"
    evidence_type: str = "static-observed"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "kind": self.kind,
            "file": self.file,
            "line": self.line,
            "symbol_id": self.symbol_id,
            "input_shape": self.input_shape,
            "untrusted": self.untrusted,
            "framework": self.framework,
            "api": self.api,
            "target_type": self.target_type,
            "rule_label": self.rule_label,
            "review_state": self.review_state,
            "candidate_ids": list(self.candidate_ids),
            "producer": self.producer,
            "confidence": self.confidence,
            "evidence_type": self.evidence_type,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EntryRecord":
        kwargs = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        return cls(**kwargs)


@dataclass
class SinkRecord:
    """A dangerous operation (spec §4.4)."""

    sink_id: str
    category: str
    file: str
    line: int
    symbol_id: str = ""
    api: str = ""
    text: str = ""
    severity_hint: str = "medium"
    #: Entry ids whose forward walk reaches this sink (spec §9).  Read for
    #: truthiness by the coverage model, so an empty list is the "no
    #: reachability known yet" state -- it is *not* the same as "unreachable",
    #: which is recorded in ``sink-reachability.json`` as a coverage gap.
    reachable_from_entries: List[str] = field(default_factory=list)
    #: True when the backward walk (spec §10) traced this sink to an entry.
    backward_reachable: bool = False
    backward_entries: List[str] = field(default_factory=list)
    review_state: str = "indexed"
    candidate_ids: List[str] = field(default_factory=list)
    producer: str = "regex"
    confidence: str = "heuristic"
    evidence_type: str = "static-observed"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "sink_id": self.sink_id,
            "category": self.category,
            "file": self.file,
            "line": self.line,
            "symbol_id": self.symbol_id,
            "api": self.api,
            "text": self.text,
            "severity_hint": self.severity_hint,
            "reachable_from_entries": list(self.reachable_from_entries),
            "backward_reachable": self.backward_reachable,
            "backward_entries": list(self.backward_entries),
            "review_state": self.review_state,
            "candidate_ids": list(self.candidate_ids),
            "producer": self.producer,
            "confidence": self.confidence,
            "evidence_type": self.evidence_type,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SinkRecord":
        kwargs = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        return cls(**kwargs)


@dataclass
class SecurityControlRecord:
    """An authentication / authorization / validation control (spec §4.5)."""

    control_id: str
    category: str
    file: str
    line: int
    symbol_id: str = ""
    control_type: str = ""
    api: str = ""
    text: str = ""
    confidence: str = "heuristic"
    review_state: str = "indexed"
    candidate_ids: List[str] = field(default_factory=list)
    producer: str = "regex"
    evidence_type: str = "static-observed"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control_id,
            "category": self.category,
            "file": self.file,
            "line": self.line,
            "symbol_id": self.symbol_id,
            "control_type": self.control_type,
            "api": self.api,
            "text": self.text,
            "confidence": self.confidence,
            "review_state": self.review_state,
            "candidate_ids": list(self.candidate_ids),
            "producer": self.producer,
            "evidence_type": self.evidence_type,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityControlRecord":
        kwargs = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        return cls(**kwargs)


@dataclass
class CallEdge:
    """One heuristic call edge (spec §8.1)."""

    caller: str
    callee: str
    confidence: str = "heuristic-callgraph"
    file: str = ""
    line: int = 0
    propagation: str = "direct"
    callee_name: str = ""
    producer: str = "regex"
    evidence_type: str = "static-observed"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "caller": self.caller,
            "callee": self.callee,
            "callee_name": self.callee_name,
            "confidence": self.confidence,
            "propagation": self.propagation,
            "file": self.file,
            "line": self.line,
            "producer": self.producer,
            "evidence_type": self.evidence_type,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CallEdge":
        kwargs = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        return cls(**kwargs)


@dataclass
class FlowRecord:
    """An entry -> ... -> sink path (spec §4.6)."""

    flow_id: str
    entry_id: str
    source_symbol: str
    sink_id: str
    path: List[str] = field(default_factory=list)
    transforms: List[str] = field(default_factory=list)
    validations: List[str] = field(default_factory=list)
    authorizations: List[str] = field(default_factory=list)
    confidence: str = "heuristic-callgraph"
    direction: str = "forward"
    priority: str = "medium"
    review_state: str = "pending"
    candidate_ids: List[str] = field(default_factory=list)
    coverage_gap: str = ""
    producer: str = "callgraph"
    evidence_type: str = "static-inferred"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "entry_id": self.entry_id,
            "source_symbol": self.source_symbol,
            "sink_id": self.sink_id,
            "path": list(self.path),
            "transforms": list(self.transforms),
            "validations": list(self.validations),
            "authorizations": list(self.authorizations),
            "confidence": self.confidence,
            "direction": self.direction,
            "priority": self.priority,
            "review_state": self.review_state,
            "candidate_ids": list(self.candidate_ids),
            "coverage_gap": self.coverage_gap,
            "producer": self.producer,
            "evidence_type": self.evidence_type,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FlowRecord":
        kwargs = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        return cls(**kwargs)


@dataclass
class CandidateCoverageRecord:
    """Which coverage regions a candidate touched (spec §13.2/§14)."""

    candidate_id: str
    round: int = 0
    conclusion: str = ""
    entries: List[str] = field(default_factory=list)
    sinks: List[str] = field(default_factory=list)
    flows: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    mechanisms: List[str] = field(default_factory=list)
    status: str = "open"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "round": self.round,
            "conclusion": self.conclusion,
            "entries": list(self.entries),
            "sinks": list(self.sinks),
            "flows": list(self.flows),
            "files": list(self.files),
            "categories": list(self.categories),
            "mechanisms": list(self.mechanisms),
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CandidateCoverageRecord":
        kwargs = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        return cls(**kwargs)


@dataclass
class UncoveredRegion:
    """A residual coverage gap handed to the next round (spec §14)."""

    region_id: str
    kind: str
    risk: str = "medium"
    reason: str = ""
    file: str = ""
    line: int = 0
    ref: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)
    producer: str = "coverage"
    confidence: str = "heuristic"
    evidence_type: str = "static-inferred"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "region_id": self.region_id,
            "kind": self.kind,
            "risk": self.risk,
            "reason": self.reason,
            "file": self.file,
            "line": self.line,
            "ref": self.ref,
            "detail": dict(self.detail),
            "producer": self.producer,
            "confidence": self.confidence,
            "evidence_type": self.evidence_type,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UncoveredRegion":
        kwargs = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        return cls(**kwargs)


#: Registry used by the store to (de)serialise homogeneous index files.
RECORD_TYPES: Dict[str, Any] = {
    "source-inventory": SourceFileRecord,
    "symbol-index": SymbolRecord,
    "entry-index": EntryRecord,
    "sink-index": SinkRecord,
    "security-control-index": SecurityControlRecord,
    "call-graph": CallEdge,
    "flow-index": FlowRecord,
    "candidate-coverage": CandidateCoverageRecord,
    "uncovered-regions": UncoveredRegion,
}
