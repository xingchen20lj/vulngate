"""Security control map (spec §11).

The inventory already knows *where* the security controls are
(``security-control-index``, PR1).  This module answers the question the audit
actually needs answered:

    on the path from this Entry to this Sink, is the control that *should* be
    there actually there?

Two path shapes, straight out of the spec::

    Path A:  Entry -> Auth -> Sink        (guarded)
    Path B:  Entry --------> Sink         (possible-auth-bypass)

Design commitments, each one deliberate:

**Presence is not protection.**  A control *on the path* is all a name-resolved
static walk can prove.  That it runs before the sink, on the same branch, for
the right subject, is exactly what the audit still has to establish.  Every
verdict here is therefore ``guarded`` / ``partial`` / ``uncontrolled`` -- never
"safe" -- and each one carries the control ids it was derived from so a reviewer
can disagree with it.

**Absence is graded, not asserted.**  "No ``authorization`` control found on
this path" is a heuristic about a heuristic call graph.  The output is named
``possible-`` for that reason, and the candidate it produces is
``precondition_tier_hint = "single-feature"`` with an explicit precondition
naming the assumption (an upstream filter / interceptor outside the scanned
scope could be enforcing it).  Claiming tier ``"0"`` would assert "reachable
under default configuration", which static absence cannot establish.

**Requirements come from a matrix, not from a vibe.**  :data:`SINK_CONTROL_REQ`
and :data:`AUTH_ENTRY_KINDS` state *which* control class each sink category and
each entry kind owes.  Without that table, "expected security control missing"
would be unfalsifiable -- every absent control would look like a finding, and
the analysis would degenerate into noise (spec §25).

**Nothing here is an LLM.**  Deterministic over the persisted indices (spec
§21.1), reproducible: same tree + same review state => same map.

Category vocabulary note: :data:`CONTROL_VOCABULARY` is the spec §11 list.
Producers normalise into the inventory's concrete vocabulary (``owner`` ->
``authorization`` with ``control_type="owner-check"``), so
:func:`normalize_category` folds the spec words back onto it before any
comparison.  ``dataflow`` keeps its own pre-normalisation sets on purpose --
changing them would change the contents of the persisted ``flow-index``, which
is a PR2 artifact this PR does not get to rewrite.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

# --- storage names ---------------------------------------------------------

#: ``state/<target>/coverage/control-map.json`` (per-flow verdicts + summary).
CONTROL_MAP_INDEX = "control-map"

#: ``state/<target>/coverage/control-candidates.json`` (generated candidates).
CONTROL_CANDIDATE_INDEX = "control-candidates"

# --- vocabulary (spec §11) -------------------------------------------------

#: The spec §11 control vocabulary, verbatim and in spec order.  Kept as a
#: constant so the map can be diffed against the spec by eye and so a producer
#: can name a control the way the spec does.
CONTROL_VOCABULARY: Tuple[str, ...] = (
    "authentication", "authorization", "permission", "role", "owner", "tenant",
    "ACL", "validation", "sanitization", "normalization", "allowlist",
    "denylist", "length-limit", "depth-limit", "rate-limit", "CSRF",
    "feature-flag", "safe-mode", "path-check", "origin-check",
    "signature-check",
)

#: Spec vocabulary -> the concrete category the inventory emits.  Anything not
#: in here is already concrete and passes through unchanged.
CATEGORY_ALIASES: Dict[str, str] = {
    "permission": "authorization",
    "role": "authorization",
    "owner": "authorization",
    "tenant": "authorization",
    "acl": "authorization",
    "normalization": "sanitization",
    "denylist": "allowlist",
    "safe-mode": "feature-flag",
}

#: Control classes that gate *identity or entitlement* (spec §5.5).
AUTHZ_CATEGORIES = frozenset({"authentication", "authorization"})

#: Control classes that gate the *shape or content* of the data.
VALIDATION_CATEGORIES = frozenset({
    "validation", "sanitization", "allowlist", "length-limit", "depth-limit",
    "path-check", "origin-check", "signature-check", "csrf",
})

#: Control classes that gate the *feature* rather than the data.  A missing one
#: is worth recording, but it is not a bypass of an authorization boundary.
POLICY_CATEGORIES = frozenset({"feature-flag", "rate-limit"})

#: ``family name -> categories``.  The family is what the *diff* compares
#: (spec §12); the category is what the *map* requires.
CONTROL_FAMILIES: Dict[str, frozenset] = {
    "authz": AUTHZ_CATEGORIES,
    "validation": VALIDATION_CATEGORIES,
    "policy": POLICY_CATEGORIES,
}

#: Inverse lookup, built once.
CATEGORY_FAMILY: Dict[str, str] = {
    category: family
    for family, categories in CONTROL_FAMILIES.items()
    for category in categories
}

# --- expected-control matrix ----------------------------------------------

#: Entry kinds that carry an authenticated principal across a trust boundary.
#: ``config`` / ``cli`` / ``file-input`` deliberately absent: an environment
#: variable or a local file does not name a principal, so a missing
#: authorization check on that path is a different threat model (local attacker
#: with read access to env), not an authorization bypass.  Requiring authz there
#: would manufacture a bypass candidate per entry and drown the real ones.
AUTH_ENTRY_KINDS = frozenset({
    "http", "rpc", "message", "url-scheme", "webview", "ipc", "network",
})

#: Sink category -> the control classes that would be expected to stand between
#: an external entry and this operation (spec §11 "expected security control
#: missing").  Each tuple is a *requirement group*: an **any-of** set.  The
#: grouping is the whole point -- ``command-exec`` is controlled by a validator
#: **or** a sanitizer **or** an allowlist, and flattening those into "all three
#: are required" would mark every correctly guarded path as only partially
#: guarded.  The authz group is added separately from the entry kind, so a path
#: with ``hasPermission`` is guarded at the entitlement boundary even when its
#: validation story is still open.
SINK_CONTROL_REQ: Dict[str, Tuple[Tuple[str, ...], ...]] = {
    "command-exec": (("validation", "sanitization", "allowlist"),),
    "code-eval": (("validation", "sanitization", "allowlist"),),
    "expression-eval": (("validation", "sanitization", "allowlist"),),
    "template-render": (("sanitization", "validation"),),
    "sql-exec": (("sanitization", "validation"),),
    "deserialization": (("validation", "allowlist"),
                        ("depth-limit", "length-limit")),
    "dynamic-class-load": (("allowlist", "validation"),),
    "reflection": (("allowlist", "validation"),),
    "jndi": (("allowlist", "validation"),),
    "xxe": (("validation", "allowlist"),),
    "network-egress": (("allowlist", "origin-check"),),
    "file-read": (("path-check", "sanitization", "allowlist"),),
    "file-mutation": (("path-check", "sanitization", "allowlist"),),
    "privilege": (("authorization", "authentication"),),
    "credential-access": (("authorization", "authentication"),),
    "native-ipc": (("validation", "origin-check", "signature-check"),),
    "webview-bridge": (("validation", "origin-check", "allowlist"),),
    "unsafe-c": (("validation", "length-limit"),),
}

#: Fallback requirement for a sink category the matrix does not know.  Fail-safe
#: rather than fail-open: a catalog entry nobody has classified yet is still a
#: dangerous operation, so it owes *some* input constraint.  Without this,
#: adding a sink category in a later phase would silently yield
#: ``not-applicable`` verdicts -- no candidate, no gap, nothing to notice --
#: which is the omission spec §19.7 forbids.  Unknown categories are listed in
#: the summary so the gap in the matrix is visible rather than absorbed.
DEFAULT_SINK_REQUIREMENT: Tuple[str, ...] = ("allowlist", "sanitization",
                                             "validation")

#: The entitlement group, added for every entry kind that carries a principal.
AUTH_REQUIREMENT_GROUP: Tuple[str, ...] = ("authentication", "authorization")

#: What a missing control of each family means.  Printed with the map so the
#: reason a category is required travels with the verdict.
FAMILY_RATIONALE: Dict[str, str] = {
    "authz": "identity/entitlement boundary: without it any principal (or none) "
             "reaches the operation",
    "validation": "data-shape boundary: attacker-shaped input reaches a parser, "
                  "interpreter or filesystem",
    "policy": "feature/abuse boundary: a missing rate limit or feature flag is a "
              "hardening gap, not an authorization bypass",
}


def normalize_category(value: Any) -> str:
    """Fold spec §11 vocabulary and producer spellings onto one category."""
    text = str(value or "").strip().lower().replace("_", "-")
    if not text:
        return ""
    return CATEGORY_ALIASES.get(text, text)


def family_of(category: Any) -> str:
    """``"authz"`` / ``"validation"`` / ``"policy"`` / ``"other"``."""
    return CATEGORY_FAMILY.get(normalize_category(category), "other")


def requirement_groups_for(sink_category: Any, entry_kind: Any = ""
                           ) -> List[Tuple[str, ...]]:
    """Sorted any-of requirement groups for one entry kind / sink category pair.

    Empty is a real -- and rare -- answer: it means there is no sink category to
    reason about (the sink record is missing from the index) and the entry kind
    carries no principal, so the path is ``not-applicable`` rather than
    "uncontrolled".  A ``cli`` entry still owes the sink's own requirement group.
    """
    groups: List[Tuple[str, ...]] = []
    if normalize_category(entry_kind) in AUTH_ENTRY_KINDS:
        groups.append(AUTH_REQUIREMENT_GROUP)
    category = str(sink_category or "")
    if category:
        groups.extend(SINK_CONTROL_REQ.get(category, (DEFAULT_SINK_REQUIREMENT,)))
    return [tuple(sorted(g)) for g in groups]


def requirements_for(sink_category: Any, entry_kind: Any = "") -> List[str]:
    """Flattened union of :func:`requirement_groups_for` -- the *expected* set.

    For display and summaries.  Never use it to decide a verdict: it loses the
    any-of structure, and ``command-exec`` would appear to require three
    sanitizers at once.
    """
    flat: set = set()
    for group in requirement_groups_for(sink_category, entry_kind):
        flat.update(group)
    return sorted(flat)


# --- verdict vocabulary ----------------------------------------------------

VERDICT_GUARDED = "guarded"
VERDICT_PARTIAL = "partial"
VERDICT_UNCONTROLLED = "uncontrolled"
VERDICT_NOT_APPLICABLE = "not-applicable"

#: Worst first -- used to order candidates and the text renderer.
VERDICT_ORDER: Dict[str, int] = {
    VERDICT_UNCONTROLLED: 0, VERDICT_PARTIAL: 1, VERDICT_GUARDED: 2,
    VERDICT_NOT_APPLICABLE: 3,
}

#: Candidate kinds (spec §11 / §12 share the naming).
KIND_AUTH_BYPASS = "possible-auth-bypass"
KIND_CONTROL_BYPASS = "possible-control-bypass"

#: Sink severity ranking, for deterministic candidate ordering.
_SEVERITY_RANK: Dict[str, int] = {"high": 0, "medium": 1, "low": 2}


def _field(record: Any, name: str, default: Any = None) -> Any:
    """Read ``name`` from a dataclass record or a persisted dict."""
    if isinstance(record, dict):
        return record.get(name, default)
    return getattr(record, name, default)


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# records
# ---------------------------------------------------------------------------

@dataclass
class ControlMapEntry:
    """One ``Entry -> ... -> Sink`` path and whether it is controlled."""

    flow_id: str
    entry_id: str = ""
    sink_id: str = ""
    entry_kind: str = ""
    entry_api: str = ""
    entry_input_shape: str = ""
    sink_category: str = ""
    sink_api: str = ""
    severity: str = "medium"
    path: List[str] = field(default_factory=list)
    #: Any-of requirement groups (the form the verdict is computed from).
    required_groups: List[List[str]] = field(default_factory=list)
    satisfied_groups: List[List[str]] = field(default_factory=list)
    missing_groups: List[List[str]] = field(default_factory=list)
    #: Flattened views, for display and for the candidate text.
    required: List[str] = field(default_factory=list)
    present: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    unrelated: List[str] = field(default_factory=list)
    verdict: str = VERDICT_NOT_APPLICABLE
    #: Control ids backing ``present`` (evidence, spec §21.2).
    control_ids: List[str] = field(default_factory=list)
    entry_file: str = ""
    entry_line: int = 0
    sink_file: str = ""
    sink_line: int = 0
    producer: str = "controls"
    confidence: str = "heuristic"
    evidence_type: str = "static-inferred"

    def location(self) -> str:
        if self.sink_file:
            return "%s:%d" % (self.sink_file, self.sink_line)
        return self.sink_id

    def missing_authz(self) -> List[str]:
        return [c for c in self.missing if c in AUTHZ_CATEGORIES]

    def missing_validation(self) -> List[str]:
        return [c for c in self.missing if c in VALIDATION_CATEGORIES]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "entry_id": self.entry_id,
            "sink_id": self.sink_id,
            "entry_kind": self.entry_kind,
            "entry_api": self.entry_api,
            "entry_input_shape": self.entry_input_shape,
            "sink_category": self.sink_category,
            "sink_api": self.sink_api,
            "severity": self.severity,
            "path": list(self.path),
            "required_groups": [list(g) for g in self.required_groups],
            "satisfied_groups": [list(g) for g in self.satisfied_groups],
            "missing_groups": [list(g) for g in self.missing_groups],
            "required": list(self.required),
            "present": list(self.present),
            "missing": list(self.missing),
            "unrelated": list(self.unrelated),
            "verdict": self.verdict,
            "control_ids": list(self.control_ids),
            "entry_file": self.entry_file,
            "entry_line": self.entry_line,
            "sink_file": self.sink_file,
            "sink_line": self.sink_line,
            "location": self.location(),
            "producer": self.producer,
            "confidence": self.confidence,
            "evidence_type": self.evidence_type,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ControlMapEntry":
        kwargs = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        return cls(**kwargs)


@dataclass
class ControlMap:
    """Per-flow control verdicts plus the aggregate views."""

    entries: List[ControlMapEntry] = field(default_factory=list)
    generated_at: str = ""
    producer: str = "controls"
    confidence: str = "heuristic"
    evidence_type: str = "static-inferred"

    def by_flow(self) -> Dict[str, ControlMapEntry]:
        return {entry.flow_id: entry for entry in self.entries}

    def unguarded(self, family: str = "authz") -> List[ControlMapEntry]:
        """Paths missing a control of ``family``, worst verdict first."""
        out = [
            entry for entry in self.entries
            if entry.missing
            and any(family_of(c) == family for c in entry.missing)
        ]
        out.sort(key=lambda e: (VERDICT_ORDER.get(e.verdict, 9),
                                _SEVERITY_RANK.get(e.severity, 3),
                                e.sink_id, e.flow_id))
        return out

    def verdict_histogram(self) -> Dict[str, int]:
        return dict(sorted(Counter(e.verdict for e in self.entries).items()))

    def missing_histogram(self) -> Dict[str, int]:
        """Unsatisfied requirement *groups*, keyed ``"a|b|c"`` (any-of set).

        Keyed by group rather than by category so the number means "paths on
        which this whole requirement was unmet" -- counting categories would say
        "sanitization missing on 40 paths" when one validator would have covered
        all 40.
        """
        counts: Counter = Counter()
        for entry in self.entries:
            for group in entry.missing_groups:
                counts["|".join(group)] += 1
        return dict(sorted(counts.items()))

    def unclassified_sink_categories(self) -> List[str]:
        """Sink categories that fell back to :data:`DEFAULT_SINK_REQUIREMENT`.

        Surfaced so the matrix gap is visible: these paths *were* judged (that is
        the point of the fallback) but with a generic requirement.
        """
        return sorted({e.sink_category for e in self.entries
                       if e.sink_category
                       and e.sink_category not in SINK_CONTROL_REQ})

    def summary(self) -> Dict[str, Any]:
        verdicts = self.verdict_histogram()
        missing = self.missing_histogram()
        return {
            "flows": len(self.entries),
            "verdicts": verdicts,
            "guarded": verdicts.get(VERDICT_GUARDED, 0),
            "partial": verdicts.get(VERDICT_PARTIAL, 0),
            "uncontrolled": verdicts.get(VERDICT_UNCONTROLLED, 0),
            "not_applicable": verdicts.get(VERDICT_NOT_APPLICABLE, 0),
            "missing_controls": missing,
            "guarded_but_incomplete": verdicts.get(VERDICT_PARTIAL, 0),
            "auth_bypass_paths": len(self.unguarded("authz")),
            "validation_gap_paths": len(self.unguarded("validation")),
            "uncontrolled_high_severity": len([
                e for e in self.entries
                if e.verdict == VERDICT_UNCONTROLLED and e.severity == "high"]),
            "unclassified_sink_categories": self.unclassified_sink_categories(),
            "family_rationale": dict(FAMILY_RATIONALE),
            "producer": self.producer,
            "confidence": self.confidence,
            "evidence_type": self.evidence_type,
            "limitations": list(LIMITATIONS),
        }

    def as_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": self.generated_at or
            datetime.now().isoformat(timespec="seconds"),
            "summary": self.summary(),
            "entries": [entry.as_dict() for entry in self.entries],
            "producer": self.producer,
            "confidence": self.confidence,
            "evidence_type": self.evidence_type,
            "limitations": list(LIMITATIONS),
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "ControlMap":
        if not data:
            return cls()
        return cls(
            entries=[ControlMapEntry.from_dict(r)
                     for r in data.get("entries") or []],
            generated_at=str(data.get("generated_at") or ""),
            producer=str(data.get("producer") or "controls"),
            confidence=str(data.get("confidence") or "heuristic"),
            evidence_type=str(data.get("evidence_type") or "static-inferred"),
        )


#: Carried on every persisted map and every candidate, so a reader never has to
#: guess how strong the claim is.
LIMITATIONS: Tuple[str, ...] = (
    "control presence is read off a name-resolved call graph: no virtual "
    "dispatch, DI container, reflection, annotation processing or async "
    "modelling, so a control invoked through any of those is invisible here",
    "path membership is not temporal order: a control in a function the flow "
    "passes through is not proven to run before the sink, or on the same branch",
    "an absent control is a *lead*: an upstream filter, interceptor, gateway or "
    "deployment policy outside the scanned scope may enforce it, which is why "
    "the generated candidates are named possible-* and carry a precondition",
    "requirement matrix (SINK_CONTROL_REQ) is a per-category any-of set, not a "
    "per-target policy: a target with a stricter internal standard will agree "
    "with 'missing' and disagree with 'sufficient'",
)

# ---------------------------------------------------------------------------
# builder
# ---------------------------------------------------------------------------

def _symbol_controls(controls: Sequence[Any]) -> Dict[str, List[Dict[str, Any]]]:
    """``symbol_id -> controls`` so a path lookup is a dict hit, not a scan."""
    index: Dict[str, List[Dict[str, Any]]] = {}
    for control in controls:
        symbol_id = str(_field(control, "symbol_id", "") or "")
        if not symbol_id:
            continue
        index.setdefault(symbol_id, []).append({
            "control_id": str(_field(control, "control_id", "") or ""),
            "category": normalize_category(_field(control, "category", "")),
            "control_type": str(_field(control, "control_type", "") or ""),
            "api": str(_field(control, "api", "") or ""),
            "file": str(_field(control, "file", "") or ""),
            "line": _int(_field(control, "line", 0)),
        })
    for symbol_id in index:
        index[symbol_id].sort(key=lambda c: (c["category"], c["control_id"]))
    return index


def _index_by(records: Sequence[Any], key: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for record in records:
        value = str(_field(record, key, "") or "")
        if value and value not in out:
            out[value] = record
    return out


def build_control_map(entries: Sequence[Any] = (),
                      sinks: Sequence[Any] = (),
                      flows: Sequence[Any] = (),
                      controls: Sequence[Any] = ()) -> ControlMap:
    """Verdict every flow against the expected-control matrix.

    Cost is O(flows x path length): one dict hit per symbol on the path.
    Accepts dataclass records (inventory path) or persisted dicts (store path).
    """
    entry_index = _index_by(entries, "entry_id")
    sink_index = _index_by(sinks, "sink_id")
    controls_by_symbol = _symbol_controls(controls)

    mapped: List[ControlMapEntry] = []
    for flow in flows:
        flow_id = str(_field(flow, "flow_id", "") or "")
        entry_id = str(_field(flow, "entry_id", "") or "")
        sink_id = str(_field(flow, "sink_id", "") or "")
        entry = entry_index.get(entry_id)
        sink = sink_index.get(sink_id)
        path = [str(x) for x in (_field(flow, "path", []) or [])]

        entry_kind = str(_field(entry, "kind", "") or "") if entry else ""
        sink_category = str(_field(sink, "category", "") or "") if sink else ""
        groups = requirement_groups_for(sink_category, entry_kind)

        on_path_categories: set = set()
        carriers: List[str] = []
        for symbol_id in path:
            for control in controls_by_symbol.get(symbol_id, ()):
                category = control["category"]
                if not category:
                    continue
                on_path_categories.add(category)
                if control["control_id"]:
                    carriers.append(control["control_id"])

        satisfied = [list(g) for g in groups
                     if any(c in on_path_categories for c in g)]
        unsatisfied = [list(g) for g in groups
                       if not any(c in on_path_categories for c in g)]
        required = sorted({c for g in groups for c in g})
        present = sorted(c for c in on_path_categories if c in required)
        missing = sorted({c for g in unsatisfied for c in g})
        unrelated = sorted(on_path_categories - set(required))

        if not groups:
            verdict = VERDICT_NOT_APPLICABLE
        elif not unsatisfied:
            verdict = VERDICT_GUARDED
        elif not satisfied:
            verdict = VERDICT_UNCONTROLLED
        else:
            verdict = VERDICT_PARTIAL

        mapped.append(ControlMapEntry(
            flow_id=flow_id, entry_id=entry_id, sink_id=sink_id,
            entry_kind=entry_kind,
            entry_api=str(_field(entry, "api", "") or "") if entry else "",
            entry_input_shape=str(_field(entry, "input_shape", "") or "") if entry else "",
            sink_category=sink_category,
            sink_api=str(_field(sink, "api", "") or "") if sink else "",
            severity=_severity_of(sink),
            path=path, required_groups=[list(g) for g in groups],
            satisfied_groups=satisfied, missing_groups=unsatisfied,
            required=required, present=present,
            missing=missing, unrelated=unrelated, verdict=verdict,
            control_ids=sorted(set(carriers)),
            entry_file=str(_field(entry, "file", "") or "") if entry else "",
            entry_line=_int(_field(entry, "line", 0)) if entry else 0,
            sink_file=str(_field(sink, "file", "") or "") if sink else "",
            sink_line=_int(_field(sink, "line", 0)) if sink else 0,
        ))
    mapped.sort(key=lambda e: (e.flow_id, e.sink_id))
    return ControlMap(entries=mapped,
                      generated_at=datetime.now().isoformat(timespec="seconds"))


def _severity_of(sink: Any) -> str:
    """Sink severity, defaulting to ``medium`` rather than ``high``.

    Used for ordering only, so an unknown severity must not sort as the most
    urgent thing on the board.
    """
    if sink is None:
        return "medium"
    return str(_field(sink, "severity_hint", "medium") or "medium")


# ---------------------------------------------------------------------------
# candidates (spec §11 "应自动提升为高价值候选")
# ---------------------------------------------------------------------------

def _candidate_id(kind: str, ordinal: int) -> str:
    stem = "authz" if kind == KIND_AUTH_BYPASS else "ctrl"
    return "ctl-%s-%04d" % (stem, ordinal)


def poc_class_for(candidate_id: Any) -> str:
    """A valid Java identifier for a candidate id (``ctl-authz-0001`` ->
    ``CtlAuthz0001``).

    S4 compiles the generated PoC under ``cand["poc_class"] or
    cand["candidate_id"]``; a hyphenated id is not a legal class name, so the
    static candidates cannot leave this to the fallback.
    """
    parts = [p for p in str(candidate_id or "").replace("_", "-").split("-") if p]
    return "".join(part.capitalize() for part in parts) or "Candidate"


def authz_cases_for() -> List[Dict[str, Any]]:
    """Negative-test contract for an authorization-bypass hypothesis.

    Each case states what a *correctly guarded* target owes: denied, 401/403,
    nothing mutated.  A PoC that observes the opposite is the evidence that the
    control is missing -- which is the only way this static hypothesis can ever
    become a finding.  Cases carry no credentials (spec §21.2): principal / role
    / tenant are labels, and the local PoC fabricates its own session.
    """
    return [
        {"case_id": "anonymous", "principal": "anonymous",
         "expected_http_codes": [401, 403], "expected_authz": "deny",
         "expected_object_mutated": False},
        {"case_id": "other-principal", "principal": "user-b", "role": "user",
         "expected_http_codes": [403], "expected_authz": "deny",
         "expected_object_mutated": False},
        {"case_id": "cross-tenant", "principal": "user-b", "role": "user",
         "tenant_id": "tenant-b", "object_tenant_id": "tenant-a",
         "expected_http_codes": [403], "expected_authz": "deny",
         "expected_object_mutated": False},
    ]


def _entry_label(entry: ControlMapEntry) -> str:
    name = entry.entry_api or entry.entry_id
    if entry.entry_file:
        return "%s@%s:%d" % (name, entry.entry_file, entry.entry_line)
    return name


def _sink_label(entry: ControlMapEntry) -> str:
    name = entry.sink_api or entry.sink_category or entry.sink_id
    return "%s@%s" % (name, entry.location()) if entry.sink_file else name


def _control_kind_candidate(entry: ControlMapEntry, kind: str,
                            missing: Sequence[str], ordinal: int) -> Dict[str, Any]:
    """One deterministic candidate dict, shaped like an S2 proposal.

    Field names match ``run_agent.propose_candidates``' output so the scheduler
    and the ledger cannot tell the two apart structurally -- only ``source`` /
    ``producer`` say where it came from, and they say it loudly.
    """
    missing_text = "/".join(missing)
    entry_label = _entry_label(entry)
    sink_label = _sink_label(entry)
    path_text = " -> ".join(entry.path) if entry.path else "(same symbol)"
    logic = (
        "%s：%s 经 %s 到达 %s，路径上未满足的控制需求组 %s"
        "（required=%s, present=%s, 未满足组=%s）。证据：%s；路径 %s"
        % (kind, entry.entry_id, path_text, sink_label,
           missing_text, ",".join(entry.required) or "-",
           ",".join(entry.present) or "-",
           "; ".join("|".join(g) for g in entry.missing_groups) or "-",
           entry.location(), path_text)
    )
    if kind == KIND_AUTH_BYPASS:
        hypothesis = (
            "此路径在授权边界上无控制（%s），而同一入口族中存在带授权控制的路径；"
            "匿名或低权主体可能直接到达 %s。" % (missing_text, sink_label)
        )
        surface = "possible-auth-bypass: %s -> %s" % (entry_label, sink_label)
        category = "authz"
    else:
        hypothesis = (
            "该 sink 类别的预期校验控制（%s）在此路径上不满足，输入未经约束即到达 %s。"
            % (missing_text, sink_label))
        surface = "possible-control-bypass: %s -> %s" % (entry_label, sink_label)
        category = ""

    code_location = [entry.location()] if entry.sink_file else []
    if entry.entry_file:
        code_location.append("%s:%d" % (entry.entry_file, entry.entry_line))

    candidate_id = _candidate_id(kind, ordinal)
    return {
        "candidate_id": candidate_id,
        "surface": surface,
        "entry": entry.entry_api or entry.entry_id,
        "input_shape": entry.entry_input_shape or "unknown",
        "logic": logic,
        "hypothesis": hypothesis,
        # Deliberately not "0": static absence of a control cannot establish
        # that the path is open under default configuration.
        "precondition_tier_hint": "single-feature",
        "preconditions": [
            "路径上未满足 %s 类控制需求；需运行时确认无上游 "
            "filter/interceptor/gateway 兜底" % missing_text,
            "需确认该入口在目标默认配置下确有路由暴露（非仅注册）",
        ],
        # The fields S3/S4 read, filled here so a static candidate is
        # structurally identical to a proposed one.
        "poc_class": poc_class_for(candidate_id),
        "jvm": {},
        "target_classes": [],
        "authz_cases": (authz_cases_for()
                        if kind == KIND_AUTH_BYPASS else []),
        "chain_components": ["request-body", "authorization"
                             if kind == KIND_AUTH_BYPASS else "validation",
                             entry.sink_category or "sink"],
        "novelty_keywords": sorted(set(
            [kind, "missing-control"] + list(missing)
            + ([entry.sink_category] if entry.sink_category else [])
            + ([entry.entry_kind] if entry.entry_kind else []))),
        "code_location": code_location,
        "category": category,
        # --- provenance + traceability (spec §21.2) ------------------------
        "flow_id": entry.flow_id,
        "entry_id": entry.entry_id,
        "sink_id": entry.sink_id,
        "control_kind": kind,
        "control_verdict": entry.verdict,
        "required_groups": [list(g) for g in entry.required_groups],
        "missing_groups": [list(g) for g in entry.missing_groups],
        "required_controls": list(entry.required),
        "present_controls": list(entry.present),
        # The subset this candidate is *about* (one family), not everything the
        # path is missing: the other family is a separate candidate.
        "missing_controls": list(missing),
        "carrier_control_ids": list(entry.control_ids),
        "path": list(entry.path),
        "source": "control-map",
        "producer": "controls",
        "confidence": "heuristic",
        "evidence_type": "static-inferred",
    }


def control_candidates(cmap: ControlMap, limit_per_kind: int = 0
                       ) -> List[Dict[str, Any]]:
    """Deterministic candidates for every unguarded / partially guarded path.

    ``limit_per_kind`` (0 = unbounded) bounds *presentation* only, and it is
    applied after the deterministic sort, so a truncated list is a prefix of the
    full list rather than a different list.
    """
    ranked = sorted(
        [e for e in cmap.entries if e.verdict in (VERDICT_UNCONTROLLED, VERDICT_PARTIAL)],
        key=lambda e: (VERDICT_ORDER.get(e.verdict, 9),
                       _SEVERITY_RANK.get(e.severity, 3),
                       e.sink_id, e.flow_id))

    out: List[Dict[str, Any]] = []
    counters: Dict[str, int] = {KIND_AUTH_BYPASS: 0, KIND_CONTROL_BYPASS: 0}
    for entry in ranked:
        for kind, missing in ((KIND_AUTH_BYPASS, entry.missing_authz()),
                              (KIND_CONTROL_BYPASS, entry.missing_validation())):
            if not missing:
                continue
            if limit_per_kind and counters[kind] >= limit_per_kind:
                continue
            counters[kind] += 1
            out.append(_control_kind_candidate(entry, kind, missing,
                                               counters[kind]))
    return out


# ---------------------------------------------------------------------------
# persistence
# ---------------------------------------------------------------------------

def write_control_map(store: Any, cmap: ControlMap,
                      candidates: Optional[Sequence[Dict[str, Any]]] = None
                      ) -> Dict[str, str]:
    """Persist the map (and, when given, its generated candidates)."""
    written = {CONTROL_MAP_INDEX: str(store.write(CONTROL_MAP_INDEX,
                                                  cmap.as_dict()))}
    if candidates is not None:
        written[CONTROL_CANDIDATE_INDEX] = str(
            store.write(CONTROL_CANDIDATE_INDEX, list(candidates)))
    return written


def load_control_map(store: Any) -> ControlMap:
    return ControlMap.from_dict(store.read(CONTROL_MAP_INDEX))


def load_control_candidates(store: Any) -> List[Dict[str, Any]]:
    data = store.read(CONTROL_CANDIDATE_INDEX)
    return [c for c in data if isinstance(c, dict)] if isinstance(data, list) else []


# ---------------------------------------------------------------------------
# candidate pool hand-off (spec §11 "应自动提升为高价值候选")
# ---------------------------------------------------------------------------

def static_candidates(store: Any) -> List[Dict[str, Any]]:
    """Every index-derived candidate: controls, differential, capability paths.

    Both are already persisted by :func:`agent.analysis.inventory.build_inventory`,
    so this is a read -- it never re-derives, and it never consults an LLM.

    There is deliberately **no cap here**.  A cap would have to keep a
    deterministic prefix, and since these candidates are regenerated identically
    every round, a truncated prefix would starve every flow after it forever --
    the silent omission spec §19.7 forbids.  Oversized pools are the scheduler's
    problem (spec §13.3): it stratifies and rotates, so a pool of 600 yields a
    different few each round as coverage moves.
    """
    candidates = load_control_candidates(store)
    # Late import: ``differential`` imports this module (it reads the same
    # control vocabulary), so the dependency may only be resolved at call time.
    from . import differential as differential_analysis
    candidates.extend(differential_analysis.load_differential_candidates(store))
    # Capability paths are deliberately read-only here.  Inventory owns graph
    # construction; S2 only merges the persisted, explicitly non-finding leads.
    from . import capability_graph as capability_analysis
    candidates.extend(capability_analysis.load_capability_candidates(store))
    # Semantic path leads are also persisted by inventory.  Keep this import
    # late so the semantic module can use the control vocabulary without a
    # module-import cycle.
    from . import semantic_paths as semantic_path_analysis
    candidates.extend(semantic_path_analysis.load_semantic_candidates(store))
    return candidates


def merge_static_candidates(store: Any, candidates: Sequence[Dict[str, Any]],
                            enabled: bool = True
                            ) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Put the index-derived candidates into a round's pool.

    Returns ``(pool, added_ids)``.  ``added_ids`` is returned so the caller can
    report the merge instead of it happening invisibly -- a round whose pool
    grew by 40 must say so.

    Static candidates go **first**: the scheduler re-scores everything, so
    position only decides exact ties, and on a tie the candidate with a citable
    ``file:line`` and a named missing control should win over one that has
    neither.  Existing ids are never displaced.
    """
    pool = [c for c in candidates if isinstance(c, dict)]
    if not enabled:
        return pool, []
    known = {str(c.get("candidate_id")) for c in pool}
    added: List[str] = []
    prefix: List[Dict[str, Any]] = []
    for candidate in static_candidates(store):
        candidate_id = str(candidate.get("candidate_id") or "")
        if not candidate_id or candidate_id in known:
            continue
        known.add(candidate_id)
        added.append(candidate_id)
        prefix.append(candidate)
    return prefix + pool, added


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

_LABELS = {
    "zh": {
        "title": "安全控制图（Entry → Sink）",
        "rule": "─" * 46,
        "flows": "已判定路径",
        "guarded": "已守卫",
        "partial": "部分守卫",
        "uncontrolled": "无守卫",
        "not_applicable": "不适用",
        "auth_bypass": "授权缺失路径（possible-auth-bypass）",
        "validation_gap": "校验缺失路径（possible-control-bypass）",
        "missing": "缺失控制类（按路径计）",
        "top": "高风险未守卫路径",
        "none": "（无）",
        "candidates": "生成候选",
        "limitations": "局限",
    },
    "en": {
        "title": "Security Control Map (Entry -> Sink)",
        "rule": "─" * 46,
        "flows": "Paths judged",
        "guarded": "Guarded",
        "partial": "Partially guarded",
        "uncontrolled": "Uncontrolled",
        "not_applicable": "Not applicable",
        "auth_bypass": "Authorization-missing paths (possible-auth-bypass)",
        "validation_gap": "Validation-missing paths (possible-control-bypass)",
        "missing": "Missing control classes (paths)",
        "top": "High-signal unguarded paths",
        "none": "(none)",
        "candidates": "Generated candidates",
        "limitations": "Limitations",
    },
}


def render_control_map_text(cmap: ControlMap, lang: str = "zh",
                            limit: int = 20,
                            candidates: Optional[Sequence[Dict[str, Any]]] = None
                            ) -> str:
    labels = _LABELS.get(lang, _LABELS["zh"])
    summary = cmap.summary()
    lines = [labels["title"], labels["rule"]]
    width = 40

    def row(label: str, value: Any, extra: str = "") -> None:
        lines.append("%-*s %8s  %s" % (width, label, value, extra))

    row(labels["flows"], summary["flows"])
    row(labels["guarded"], summary["guarded"])
    row(labels["partial"], summary["partial"])
    row(labels["uncontrolled"], summary["uncontrolled"])
    row(labels["not_applicable"], summary["not_applicable"])
    lines.append("")
    row(labels["auth_bypass"], summary["auth_bypass_paths"])
    row(labels["validation_gap"], summary["validation_gap_paths"])

    missing = summary.get("missing_controls") or {}
    if missing:
        lines += ["", labels["missing"], labels["rule"]]
        for category, count in sorted(missing.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append("%-*s %8d" % (width, category, count))

    worst = cmap.unguarded("authz")[:max(0, limit)]
    lines += ["", labels["top"], labels["rule"]]
    if not worst:
        lines.append("  " + labels["none"])
    for entry in worst:
        lines.append("  [%s] %s  %s" % (entry.verdict, entry.location(),
                                        entry.sink_category))
        lines.append("      %s" % entry.entry_id)
        lines.append("      missing: %s" % (", ".join(entry.missing) or "-"))
        lines.append("      path: %s" % (" -> ".join(entry.path) or "-"))

    if candidates is not None:
        lines += ["", "%s: %d" % (labels["candidates"], len(candidates)),
                  labels["rule"]]
        for candidate in candidates[:max(0, limit)]:
            lines.append("  %s  %s" % (candidate.get("candidate_id"),
                                       candidate.get("surface", "")))

    lines += ["", labels["limitations"], labels["rule"]]
    for item in LIMITATIONS:
        lines.append("  - %s" % item)
    return "\n".join(lines)
