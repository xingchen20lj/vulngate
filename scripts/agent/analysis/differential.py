"""Sibling / differential analysis (spec §12, §19.5, §18 Phase 4).

The single highest-precision question a static audit can ask about a security
control is not "is one here?" but **"why is one here in this handler and not in
its sibling?"**::

    createUser()     -> checkPermission()      <- guarded
    updateUser()     -> checkPermission()      <- guarded
    bulkUpdateUser() -> (nothing)              <- the finding

    19.5 fixture:
    getUser()        -> checkOwner()           <- guarded
    updateUser()     -> checkOwner()           <- guarded
    deleteUser()     -> (nothing)              <- possible-auth-bypass

Path analysis (:mod:`agent.analysis.controls`) answers "is this path guarded?".
This module answers "is this path guarded *the way its siblings are?*" -- and
inconsistency is a far stronger signal than absence, because a family that
mostly enforces a control tells you the control is *expected* here.  That is
also why this analysis is allowed to name its output ``possible-auth-bypass``
without hedging it into a different kind: §12 and §19.5 are describing the same
detection, so one finding carries both names (``kind="possible-auth-bypass"``,
``differential="security-control-differential"``).

Grouping (spec §12: 相同 class/module + 相似命名 + 相似 sink + 相似调用链).  Two
passes, because the spec's own examples need both:

* **name token** -- ``createUser`` / ``updateUser`` / ``bulkUpdateUser`` share
  the token ``user`` once the verb prefixes are stripped.  Verb stripping is not
  cosmetic: it is what makes ``bulkUpdateUser`` a sibling of ``updateUser``
  instead of an unrelated endpoint.
* **sink signature** -- ``uploadAvatar`` / ``importArchive`` share no name token
  but both reach ``file-mutation``; §12's second example (extension validation
  present in one, absent in the other) is only visible through this lens.

A member may land in both kinds of group.  That is intentional: they are two
views of the same code, and a finding always names the group that produced it.

Control membership uses the **call closure**, not the handler body.  In
``deleteUser() -> no check`` the missing call is to a *different function*
(``checkOwner``), so a body-local scan would miss exactly the case §19.5
requires.  Depth is bounded (:data:`DEFAULT_CLOSURE_DEPTH`) and the closure is
read off the call graph, so what the profile contains is "controls the handler
can reach", which is the honest reading of "this handler is guarded".

Discipline: deterministic (spec §21.1), no LLM, every finding carries
``producer`` / ``confidence`` / ``evidence_type`` plus the members it compared
(spec §21.2).  Agreement is reported, so a 2-of-2 split is visibly weaker than
3-of-4.
"""

from __future__ import annotations

import re
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .controls import (KIND_AUTH_BYPASS, authz_cases_for, family_of,
                       normalize_category, poc_class_for)

# --- storage names ---------------------------------------------------------

SIBLING_GROUP_INDEX = "sibling-groups"
DIFFERENTIAL_INDEX = "differential-index"
DIFFERENTIAL_CANDIDATE_INDEX = "differential-candidates"

# --- grouping parameters ---------------------------------------------------

#: The *operation* a handler performs -- the HTTP verb, the CRUD verb, the I/O
#: verb.  Removing these is what groups ``bulkUpdateUser`` with ``updateUser``;
#: keeping them would split every CRUD family into singletons.
#:
#: A family may never be founded on one of these: ``checkOwner`` and
#: ``checkTenant`` share the operation and nothing else, so grouping them would
#: report a "sibling inconsistency" between two unrelated audits.  See
#: :func:`group_siblings`, which refuses verb-only tokens even on the fallback
#: path where they are still present in :func:`name_tokens`.
VERB_TOKENS = frozenset({
    "get", "set", "create", "update", "delete", "add", "remove", "list", "save",
    "find", "query", "fetch", "load", "put", "post", "patch", "read", "write",
    "edit", "view", "send", "run", "exec", "apply", "upload", "download",
    "import", "export", "enable", "disable", "reset", "toggle", "bind", "sync",
    "copy", "move", "open", "close", "start", "stop", "register", "login",
    "logout", "handle", "process", "do", "check", "verify", "validate",
    "assert", "ensure", "enforce",
})

#: Tokens that carry no sibling signal even when nothing better is left: the
#: batching adjective, the transport decoration, the layer suffix.
GENERIC_TOKENS = frozenset({
    "bulk", "batch", "all", "one", "two", "new", "by", "id", "api", "v1", "v2",
    "v3", "item", "items", "internal", "admin", "public", "private",
    "controller", "resource", "service",
})

#: Everything stripped from a name before matching.
STOP_TOKENS = VERB_TOKENS | GENERIC_TOKENS

#: Minimum members for a group to be worth diffing.
MIN_GROUP_SIZE = 2

#: Carriers needed before the absence is a finding.  A family of three or more
#: has to show a convention (two carriers); a pair cannot, so one carrier is the
#: strongest evidence it can hold -- and demanding two would make spec §12's own
#: example (``uploadAvatar`` validates the extension, ``importArchive`` does not)
#: undetectable.  Findings from a pair are graded ``medium``, never ``high``
#: (:func:`_risk_for`), which is where the weaker evidence shows up.
MIN_CARRIERS = 2


def _carrier_floor(size: int) -> int:
    return 1 if size <= 2 else MIN_CARRIERS

#: Fraction of the group that must carry the control.  0.5 keeps a genuine
#: 2-of-4 split visible while dropping 1-of-30 noise.
MIN_AGREEMENT = 0.5

#: How far the call closure walks from a handler when collecting its controls.
#: 2 covers handler -> service -> util, which is where authorization helpers
#: live; deeper and the profile becomes "everything the module can reach".
DEFAULT_CLOSURE_DEPTH = 2

#: Safety valve, not a design limit: a monorepo where every handler shares a
#: token can otherwise enumerate groups without bound.  Truncation is counted
#: and surfaced (``truncated`` / ``dropped_groups``), never silent.
DEFAULT_MAX_GROUPS = 2000

#: Finding kinds.
KIND_VALIDATION_DIFF = "validation-differential"
KIND_CONTROL_DIFF = "control-differential"
KIND_PATCH_SIBLING = "patch-sibling-differential"

#: spec §12's general name for the differential product.
DIFF_SECURITY_CONTROL = "security-control-differential"

#: Risk ranking used when the differential feeds the residual (spec §14 #7).
RISK_ORDER: Dict[str, int] = {"high": 0, "medium": 1, "low": 2}

_SPLIT_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SPLIT_WORD = re.compile(r"[^A-Za-z0-9]+")


def _field(record: Any, name: str, default: Any = None) -> Any:
    if isinstance(record, dict):
        return record.get(name, default)
    return getattr(record, name, default)


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def name_tokens(name: Any) -> Tuple[str, ...]:
    """Normalised tokens for sibling matching (``bulkUpdateUser`` -> ``user``).

    Falls back to the un-filtered tokens when every part is a stop token
    (``getItem`` / ``listItems``), so a pure-CRUD pair still shares a signal
    rather than collapsing to nothing.  The fallback keeps the operations in
    the set; refusing to found a family on one of them is
    :func:`group_siblings`' job, not this function's.
    """
    text = str(name or "").strip()
    if not text:
        return ()
    parts = _SPLIT_WORD.split(_SPLIT_CAMEL.sub("_", text))
    words: List[str] = []
    for part in parts:
        word = part.lower()
        # Singularise before matching so ``listItems`` and ``readItem`` agree
        # on the noun instead of differing on a trailing "s".
        if len(word) > 3 and word.endswith("s") and not word.endswith("ss"):
            word = word[:-1]
        if len(word) > 1:
            words.append(word)
    residual = sorted({word for word in words if word not in STOP_TOKENS})
    return tuple(residual or sorted(set(words)))


# ---------------------------------------------------------------------------
# records
# ---------------------------------------------------------------------------

@dataclass
class Member:
    """One handler: a symbol that hosts at least one external entry."""

    symbol_id: str
    file: str = ""
    line: int = 0
    name: str = ""
    class_name: str = ""
    scope: str = ""
    tokens: Tuple[str, ...] = ()
    entries: List[str] = field(default_factory=list)
    entry_kinds: List[str] = field(default_factory=list)
    sink_categories: List[str] = field(default_factory=list)
    #: ``category -> control ids`` reachable within the call closure.
    controls: Dict[str, List[str]] = field(default_factory=dict)
    #: ``category -> the symbols that supplied it`` (evidence for the finding).
    control_via: Dict[str, List[str]] = field(default_factory=dict)

    def categories(self) -> Set[str]:
        return set(self.controls)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "symbol_id": self.symbol_id,
            "file": self.file,
            "line": self.line,
            "name": self.name,
            "class": self.class_name,
            "scope": self.scope,
            "tokens": list(self.tokens),
            "entries": list(self.entries),
            "entry_kinds": list(self.entry_kinds),
            "sink_categories": list(self.sink_categories),
            "controls": {k: list(v) for k, v in sorted(self.controls.items())},
            "control_via": {k: list(v) for k, v in sorted(self.control_via.items())},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Member":
        payload = dict(data)
        # Same alias every other record uses (``models.SymbolRecord``): the
        # persisted key is ``class``, the field is ``class_name``.  Without it a
        # reloaded group silently loses the class -- and the class is what the
        # scope is built from, so every later diff would re-scope to the file.
        if "class" in payload and "class_name" not in payload:
            payload["class_name"] = payload.pop("class")
        payload["tokens"] = tuple(payload.get("tokens") or ())
        kwargs = {k: payload[k] for k in cls.__dataclass_fields__ if k in payload}
        return cls(**kwargs)


@dataclass
class SiblingGroup:
    """A set of handlers that are expected to enforce the same controls."""

    group_id: str
    scope: str = ""
    basis: List[str] = field(default_factory=list)
    members: List[Member] = field(default_factory=list)
    producer: str = "differential"
    confidence: str = "heuristic-nearby"
    evidence_type: str = "static-inferred"

    def size(self) -> int:
        return len(self.members)

    def member_ids(self) -> List[str]:
        return [m.symbol_id for m in self.members]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "group_id": self.group_id,
            "scope": self.scope,
            "basis": list(self.basis),
            "size": self.size(),
            "members": [m.as_dict() for m in self.members],
            "producer": self.producer,
            "confidence": self.confidence,
            "evidence_type": self.evidence_type,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SiblingGroup":
        return cls(
            group_id=str(data.get("group_id") or ""),
            scope=str(data.get("scope") or ""),
            basis=[str(x) for x in data.get("basis") or []],
            members=[Member.from_dict(m) for m in data.get("members") or []],
            producer=str(data.get("producer") or "differential"),
            confidence=str(data.get("confidence") or "heuristic-nearby"),
            evidence_type=str(data.get("evidence_type") or "static-inferred"),
        )


@dataclass
class DifferentialFinding:
    """One control class present in some siblings and absent in others."""

    finding_id: str
    group_id: str
    kind: str
    differential: str
    category: str = ""
    family: str = ""
    risk: str = "medium"
    agreement: float = 0.0
    carriers: List[Dict[str, Any]] = field(default_factory=list)
    missing: List[Dict[str, Any]] = field(default_factory=list)
    scope: str = ""
    basis: List[str] = field(default_factory=list)
    #: Patch evidence when the finding came from a fix-history comparison.
    patch_commit: str = ""
    patch_subject: str = ""
    producer: str = "differential"
    confidence: str = "heuristic-nearby"
    evidence_type: str = "static-inferred"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "group_id": self.group_id,
            "kind": self.kind,
            "differential": self.differential,
            "category": self.category,
            "family": self.family,
            "risk": self.risk,
            "agreement": self.agreement,
            "size": len(self.carriers) + len(self.missing),
            "carriers": list(self.carriers),
            "missing": list(self.missing),
            "scope": self.scope,
            "basis": list(self.basis),
            "patch_commit": self.patch_commit,
            "patch_subject": self.patch_subject,
            "producer": self.producer,
            "confidence": self.confidence,
            "evidence_type": self.evidence_type,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DifferentialFinding":
        kwargs = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        return cls(**kwargs)


#: Carried on the persisted index and every candidate.
LIMITATIONS: Tuple[str, ...] = (
    "sibling grouping is textual + structural (same class/module, shared name "
    "token, same sink signature): a family related only by business meaning "
    "will not be grouped",
    "control membership is the call closure of the handler, not its body, so "
    "'guarded' means reachable -- not that the control runs on the same branch "
    "or before the sink",
    "the differential flags *inconsistency*, which is high precision but not "
    "proof: the divergent sibling may be protected by a filter, an annotation "
    "or a gateway the scan cannot see",
    "agreement is reported rather than thresholded away: a 2-of-3 family and a "
    "2-of-20 family both surface, with different strength",
)

# ---------------------------------------------------------------------------
# members
# ---------------------------------------------------------------------------

def build_members(entries: Sequence[Any], symbols: Sequence[Any],
                  controls: Sequence[Any] = (), sinks: Sequence[Any] = (),
                  call_edges: Sequence[Any] = (),
                  closure_depth: int = DEFAULT_CLOSURE_DEPTH
                  ) -> Tuple[List[Member], Dict[str, Any]]:
    """Turn entry-hosting symbols into diffable members.

    Returns ``(members, notes)``.  ``notes`` counts what could not be bound --
    an entry whose ``symbol_id`` is not in the symbol index is reported there
    rather than dropped, because a silently skipped handler is exactly the kind
    of omission spec §19.7 forbids.
    """
    by_symbol = {str(_field(s, "symbol_id", "") or ""): s for s in symbols}
    controls_by_symbol: Dict[str, List[Dict[str, Any]]] = {}
    for control in controls:
        symbol_id = str(_field(control, "symbol_id", "") or "")
        if not symbol_id:
            continue
        controls_by_symbol.setdefault(symbol_id, []).append({
            "control_id": str(_field(control, "control_id", "") or ""),
            "category": normalize_category(_field(control, "category", "")),
            "control_type": str(_field(control, "control_type", "") or ""),
            "file": str(_field(control, "file", "") or ""),
            "line": _int(_field(control, "line", 0)),
        })
    sinks_by_symbol: Dict[str, List[str]] = {}
    for sink in sinks:
        symbol_id = str(_field(sink, "symbol_id", "") or "")
        if symbol_id:
            sinks_by_symbol.setdefault(symbol_id, []).append(
                str(_field(sink, "category", "") or ""))

    callees: Dict[str, List[str]] = {}
    for edge in call_edges:
        caller = str(_field(edge, "caller", "") or "")
        callee = str(_field(edge, "callee", "") or "")
        if caller and callee:
            callees.setdefault(caller, []).append(callee)
    for caller in callees:
        callees[caller] = sorted(set(callees[caller]))

    entries_by_symbol: Dict[str, List[Any]] = {}
    unbound: List[str] = []
    for entry in entries:
        symbol_id = str(_field(entry, "symbol_id", "") or "")
        if not symbol_id or symbol_id not in by_symbol:
            unbound.append(symbol_id or str(_field(entry, "entry_id", "") or ""))
            continue
        entries_by_symbol.setdefault(symbol_id, []).append(entry)

    members: List[Member] = []
    for symbol_id in sorted(entries_by_symbol):
        symbol = by_symbol[symbol_id]
        class_name = str(_field(symbol, "class_name", "") or "")
        file = str(_field(symbol, "file", "") or "")
        name = str(_field(symbol, "name", "") or "")
        closure = _closure(symbol_id, callees, closure_depth)
        owned: Dict[str, List[str]] = {}
        via: Dict[str, List[str]] = {}
        sink_categories: Set[str] = set()
        for visited in sorted(closure):
            sink_categories.update(sinks_by_symbol.get(visited, ()))
            for control in controls_by_symbol.get(visited, ()):
                category = control["category"]
                if not category:
                    continue
                owned.setdefault(category, [])
                if control["control_id"]:
                    owned[category].append(control["control_id"])
                via.setdefault(category, [])
                if visited not in via[category]:
                    via[category].append(visited)
        for category in owned:
            owned[category] = sorted(set(owned[category]))
            via[category] = sorted(via[category])
        members.append(Member(
            symbol_id=symbol_id, file=file,
            line=_int(_field(symbol, "start_line", 0)), name=name,
            class_name=class_name, scope=class_name or file,
            tokens=name_tokens(name),
            entries=sorted(str(_field(e, "entry_id", "") or "")
                           for e in entries_by_symbol[symbol_id]),
            entry_kinds=sorted({str(_field(e, "kind", "") or "")
                                for e in entries_by_symbol[symbol_id]
                                if _field(e, "kind", "")}),
            # Reached sinks, not owned ones: a handler almost never holds the
            # sink itself, so reading only its own line would leave the sink
            # signature empty for every real endpoint and disable the
            # "same sink" grouping (spec §12) without saying so.
            sink_categories=sorted(sink_categories),
            controls=owned, control_via=via,
        ))
    notes = {
        "members": len(members),
        "entries_total": len(entries),
        "entries_unbound": len(unbound),
        "unbound_samples": sorted(set(u for u in unbound if u))[:10],
        "call_edges": sum(len(v) for v in callees.values()),
        "closure_depth": closure_depth,
    }
    return members, notes


def _closure(root: str, callees: Dict[str, List[str]], depth: int) -> Set[str]:
    """Symbols reachable from ``root`` within ``depth`` call hops (inclusive)."""
    seen = {root}
    queue: deque = deque([(root, 0)])
    while queue:
        node, level = queue.popleft()
        if level >= depth:
            continue
        for callee in callees.get(node, ()):
            if callee in seen:
                continue
            seen.add(callee)
            queue.append((callee, level + 1))
    return seen


# ---------------------------------------------------------------------------
# grouping
# ---------------------------------------------------------------------------

def group_siblings(members: Sequence[Member], min_size: int = MIN_GROUP_SIZE,
                   max_groups: int = DEFAULT_MAX_GROUPS
                   ) -> Tuple[List[SiblingGroup], Dict[str, Any]]:
    """Group members into sibling families by name token, then by sink signature.

    Both passes are deterministic (sorted iteration, stable member order), and a
    group must span at least ``min_size`` distinct members.  Two passes that pick
    out the *same* member set collapse into one group whose ``basis`` lists both
    reasons -- e.g. ``userAvatar`` / ``userArchive`` grouped by token *and* by
    their shared ``file-mutation`` signature is one family, not two.

    The ``scope`` (class, else file) is a hard boundary: two handlers in
    different classes are never siblings, however alike their names are.  And a
    shared *operation* is not a family (:data:`VERB_TOKENS`): grouping asks
    whether two handlers act on the same thing, not whether they both "check".
    """
    by_scope: Dict[str, List[Member]] = {}
    for member in sorted(members, key=lambda m: m.symbol_id):
        by_scope.setdefault(member.scope, []).append(member)

    merged: Dict[Tuple[str, ...], SiblingGroup] = {}
    truncated = 0
    for scope in sorted(by_scope):
        scoped = by_scope[scope]

        def _add(reason: str, bucket: List[Member]) -> None:
            nonlocal truncated
            if len(bucket) < min_size:
                return
            key = tuple(sorted(m.symbol_id for m in bucket))
            existing = merged.get(key)
            if existing is not None:
                if reason not in existing.basis:
                    existing.basis.append(reason)
                return
            if len(merged) >= max_groups:
                truncated += 1
                return
            merged[key] = SiblingGroup(
                group_id="sib-%04d" % (len(merged) + 1), scope=scope,
                basis=[reason], members=list(bucket))

        # pass 1: shared name token
        tokens: Dict[str, List[Member]] = {}
        for member in scoped:
            for token in member.tokens:
                # A name whose tokens all fell back to the raw words still
                # carries its operations; they are the one thing a family must
                # not be founded on (``checkOwner`` / ``checkTenant`` share
                # "check" and nothing else).  A residual token set never
                # contains a verb, so this only rejects the fallback's weakest
                # signal.
                if token in VERB_TOKENS:
                    continue
                tokens.setdefault(token, []).append(member)
        for token in sorted(tokens):
            _add("name-token:%s" % token, tokens[token])

        # pass 2: shared sink signature
        signatures: Dict[Tuple[str, ...], List[Member]] = {}
        for member in scoped:
            if member.sink_categories:
                signatures.setdefault(tuple(member.sink_categories), []).append(member)
        for signature in sorted(signatures):
            _add("sink-signature:%s" % "|".join(signature), signatures[signature])

    groups = [merged[key] for key in sorted(merged,
                                            key=lambda k: merged[k].group_id)]
    notes = {
        "groups": len(groups),
        "truncated": bool(truncated),
        "dropped_groups": truncated,
        "by_basis": dict(sorted(Counter(
            basis.split(":", 1)[0] for g in groups for basis in g.basis).items())),
    }
    return groups, notes


# ---------------------------------------------------------------------------
# differential
# ---------------------------------------------------------------------------

def _member_evidence(member: Member, category: str) -> Dict[str, Any]:
    return {
        "symbol_id": member.symbol_id,
        "file": member.file,
        "line": member.line,
        "name": member.name,
        "entries": list(member.entries),
        "control_ids": list(member.controls.get(category, [])),
        "control_via": list(member.control_via.get(category, [])),
        "sink_categories": list(member.sink_categories),
    }


def _agreement(carriers: int, missing: int) -> float:
    """Fraction of the compared members that carry the control.

    One definition, used when a finding is created *and* when a later carrier is
    merged into it, so the number can never drift away from the carrier/missing
    lists it is displayed next to.  Rounded because the index is persisted and a
    raw fraction makes every diff of it noisy.
    """
    total = carriers + missing
    return round(carriers / total, 4) if total else 0.0


def _risk_for(category: str, family: str, size: int, carriers: int) -> str:
    """Grade the finding, deliberately independent of the sink catalog.

    The evidence *is* the inconsistency: "2 of 3 siblings enforce ownership,
    this one does not" is the strongest statement this analysis can make, and it
    should not evaporate because the sink scanner happened to miss the operation
    the divergent handler performs.  Authorization inconsistency in a family of
    three or more with a majority carrying the control is therefore ``high``;
    a validation inconsistency is ``medium`` (real, but a hardening class with a
    larger benign explanation surface); everything else is ``low``.
    """
    if family == "authz" and size >= 3 and carriers >= 2:
        return "high"
    if family in ("authz", "validation"):
        return "medium"
    return "low"


def _finding_kind(family: str) -> Tuple[str, str]:
    """``(kind, differential)`` for a control family (spec §12 + §19.5)."""
    if family == "authz":
        return KIND_AUTH_BYPASS, DIFF_SECURITY_CONTROL
    if family == "validation":
        return KIND_VALIDATION_DIFF, KIND_VALIDATION_DIFF
    return KIND_CONTROL_DIFF, DIFF_SECURITY_CONTROL


def diff_group(group: SiblingGroup, min_carriers: int = 0,
               min_agreement: float = MIN_AGREEMENT,
               finding_offset: int = 0
               ) -> List[DifferentialFinding]:
    """Compare the control classes of a group's members.

    A finding needs the control in at least :func:`_carrier_floor` members *and*
    absent from at least one, with ``min_agreement`` of the group carrying it.
    A family where nobody enforces a control produces nothing here -- that is
    :mod:`agent.analysis.controls`' job (absence), not this module's
    (inconsistency).
    """
    size = group.size()
    if size < MIN_GROUP_SIZE:
        return []
    carriers_needed = min_carriers or _carrier_floor(size)
    categories: Set[str] = set()
    for member in group.members:
        categories.update(member.categories())

    findings: List[DifferentialFinding] = []
    for category in sorted(categories):
        carriers = [m for m in group.members if category in m.controls]
        missing = [m for m in group.members if category not in m.controls]
        if len(carriers) < carriers_needed or not missing:
            continue
        agreement = _agreement(len(carriers), len(missing))
        if agreement < min_agreement:
            continue
        family = family_of(category)
        kind, differential = _finding_kind(family)
        finding_offset += 1
        findings.append(DifferentialFinding(
            finding_id="dif-%04d" % finding_offset,
            group_id=group.group_id, kind=kind, differential=differential,
            category=category, family=family,
            risk=_risk_for(category, family, size, len(carriers)),
            agreement=agreement,
            carriers=[_member_evidence(m, category) for m in carriers],
            missing=[_member_evidence(m, category) for m in missing],
            scope=group.scope, basis=list(group.basis),
        ))
    return findings


def patch_sibling_findings(fix_history: Sequence[Any],
                           groups: Sequence[SiblingGroup],
                           finding_offset: int = 0) -> List[DifferentialFinding]:
    """Spec §18 Phase 4 "Patch sibling diff".

    For every sibling family touched by a security fix, ask whether the *rest*
    of the family carries the control the fixed member carries.  The patch is
    the evidence that the maintainers consider this control required here; the
    sibling that lacks it is the reason fix-completeness bugs ship.

    Matching is by ``affected_paths`` -> member file, which is coarse, so these
    findings are recorded at ``heuristic-nearby`` confidence with the commit
    subject attached.  A fix that names neither a path nor a member produces
    nothing rather than a guess.

    Findings that agree on ``(group, category, missing members)`` are merged, so
    a patch touching a file with several carriers reports the gap once with all
    of them as evidence instead of once per carrier.
    """
    touched: Dict[str, Dict[str, Any]] = {}
    for fix in fix_history:
        if not isinstance(fix, dict):
            continue
        paths = [str(p) for p in (fix.get("affected_paths") or [])]
        for path in paths:
            touched.setdefault(path, fix)

    merged: Dict[Tuple[str, str, Tuple[str, ...]], DifferentialFinding] = {}
    for group in groups:
        for member in group.members:
            fix = touched.get(member.file)
            if fix is None or not member.controls:
                continue
            others = [m for m in group.members if m.symbol_id != member.symbol_id]
            if not others:
                continue
            for category in sorted(member.controls):
                missing = [m for m in others if category not in m.controls]
                if not missing:
                    continue
                key = (group.group_id, category,
                       tuple(m.symbol_id for m in missing))
                existing = merged.get(key)
                if existing is not None:
                    if member.symbol_id not in [
                            e.get("symbol_id") for e in existing.carriers]:
                        existing.carriers.append(_member_evidence(member, category))
                        # The merge added a carrier, so the reported strength
                        # has to move with it: an agreement frozen at "1 of 3"
                        # next to a carrier list of two is exactly the kind of
                        # internal contradiction this module exists to avoid.
                        existing.agreement = _agreement(len(existing.carriers),
                                                        len(existing.missing))
                    if existing.patch_commit != str(fix.get("commit") or ""):
                        existing.patch_subject = (
                            "%s / %s" % (existing.patch_subject,
                                         str(fix.get("subject") or "")))
                    continue
                family = family_of(category)
                finding_kind, _ = _finding_kind(family)
                merged[key] = DifferentialFinding(
                    finding_id="dif-%04d" % (len(merged) + 1 + finding_offset),
                    group_id=group.group_id, kind=KIND_PATCH_SIBLING,
                    differential=DIFF_SECURITY_CONTROL,
                    category=category, family=family,
                    risk=_risk_for(category, family, group.size(), 1),
                    agreement=_agreement(1, len(missing)),
                    carriers=[_member_evidence(member, category)],
                    missing=[_member_evidence(m, category) for m in missing],
                    scope=group.scope,
                    basis=list(group.basis) + ["patch:%s" % finding_kind],
                    patch_commit=str(fix.get("commit") or ""),
                    patch_subject=str(fix.get("subject") or ""),
                )
    return [merged[key] for key in sorted(merged)]


def build_differential(entries: Sequence[Any] = (),
                       symbols: Sequence[Any] = (),
                       controls: Sequence[Any] = (),
                       sinks: Sequence[Any] = (),
                       call_edges: Sequence[Any] = (),
                       fix_history: Sequence[Any] = (),
                       closure_depth: int = DEFAULT_CLOSURE_DEPTH,
                       max_groups: int = DEFAULT_MAX_GROUPS
                       ) -> "DifferentialIndex":
    """Group siblings, diff their controls, optionally fold in patch evidence."""
    members, member_notes = build_members(entries, symbols, controls, sinks,
                                          call_edges, closure_depth)
    groups, group_notes = group_siblings(members, max_groups=max_groups)
    findings: List[DifferentialFinding] = []
    for group in groups:
        findings.extend(diff_group(group, finding_offset=len(findings)))
    patch_findings: List[DifferentialFinding] = []
    if fix_history:
        patch_findings = patch_sibling_findings(fix_history, groups,
                                               finding_offset=len(findings))
        findings.extend(patch_findings)
    findings.sort(key=lambda f: (RISK_ORDER.get(f.risk, 9), f.kind,
                                 f.group_id, f.category, f.finding_id))
    return DifferentialIndex(
        groups=groups, findings=findings,
        members=len(members), member_notes=member_notes,
        group_notes=group_notes,
        generated_at=datetime.now().isoformat(timespec="seconds"))


@dataclass
class DifferentialIndex:
    """Sibling groups + findings + the notes about what was skipped."""

    groups: List[SiblingGroup] = field(default_factory=list)
    findings: List[DifferentialFinding] = field(default_factory=list)
    members: int = 0
    member_notes: Dict[str, Any] = field(default_factory=dict)
    group_notes: Dict[str, Any] = field(default_factory=dict)
    generated_at: str = ""
    producer: str = "differential"
    confidence: str = "heuristic-nearby"
    evidence_type: str = "static-inferred"

    def by_kind(self) -> Dict[str, int]:
        return dict(sorted(Counter(f.kind for f in self.findings).items()))

    def by_risk(self) -> Dict[str, int]:
        return dict(sorted(Counter(f.risk for f in self.findings).items()))

    def summary(self) -> Dict[str, Any]:
        kinds = self.by_kind()
        return {
            "members": self.members,
            "groups": len(self.groups),
            "findings": len(self.findings),
            "findings_by_kind": kinds,
            "findings_by_risk": self.by_risk(),
            "auth_bypass_findings": kinds.get(KIND_AUTH_BYPASS, 0),
            "groups_by_basis": self.group_notes.get("by_basis", {}),
            "groups_truncated": self.group_notes.get("truncated", False),
            "dropped_groups": self.group_notes.get("dropped_groups", 0),
            "entries_unbound": self.member_notes.get("entries_unbound", 0),
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
            "findings": [f.as_dict() for f in self.findings],
            "member_notes": dict(self.member_notes),
            # Persisted explicitly rather than rebuilt from ``summary``: the
            # group notes are what ``summary()`` reads, so rebuilding them from
            # the summary would lose ``by_basis`` on every reload.
            "group_notes": dict(self.group_notes),
            "producer": self.producer,
            "confidence": self.confidence,
            "evidence_type": self.evidence_type,
            "limitations": list(LIMITATIONS),
        }

    def group_dicts(self) -> List[Dict[str, Any]]:
        return [g.as_dict() for g in self.groups]

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]],
                  group_data: Optional[Sequence[Dict[str, Any]]] = None
                  ) -> "DifferentialIndex":
        if not data:
            return cls(groups=[SiblingGroup.from_dict(g) for g in (group_data or [])],
                       group_notes={})
        return cls(
            groups=[SiblingGroup.from_dict(g) for g in (group_data or [])],
            findings=[DifferentialFinding.from_dict(f)
                      for f in data.get("findings") or []],
            members=_int((data.get("summary") or {}).get("members")),
            member_notes=dict(data.get("member_notes") or {}),
            group_notes=_restore_group_notes(data),
            generated_at=str(data.get("generated_at") or ""),
            producer=str(data.get("producer") or "differential"),
            confidence=str(data.get("confidence") or "heuristic-nearby"),
            evidence_type=str(data.get("evidence_type") or "static-inferred"),
        )


def _restore_group_notes(data: Dict[str, Any]) -> Dict[str, Any]:
    """``group_notes`` from their own key, else from the rendered ``summary``.

    The fallback keeps an index written before the key existed readable instead
    of resurrecting it with empty grouping statistics.
    """
    notes = data.get("group_notes")
    if isinstance(notes, dict) and notes:
        return dict(notes)
    summary = data.get("summary") or {}
    return {
        "groups": _int(summary.get("groups")),
        "truncated": bool(summary.get("groups_truncated")),
        "dropped_groups": _int(summary.get("dropped_groups")),
        "by_basis": dict(summary.get("groups_by_basis") or {}),
    }


# ---------------------------------------------------------------------------
# candidates
# ---------------------------------------------------------------------------

_CANDIDATE_STEM = {
    KIND_AUTH_BYPASS: "authz",
    KIND_VALIDATION_DIFF: "valid",
    KIND_CONTROL_DIFF: "ctrl",
    KIND_PATCH_SIBLING: "patch",
}


def differential_candidates(findings: Sequence[DifferentialFinding],
                            limit: int = 0) -> List[Dict[str, Any]]:
    """Deterministic candidates from the findings (spec §12 / §19.5 output).

    ``limit`` (0 = unbounded) bounds presentation only and is applied after the
    deterministic sort, so a truncated list is a prefix of the full one.
    """
    ranked = sorted(findings, key=lambda f: (RISK_ORDER.get(f.risk, 9), f.kind,
                                             f.group_id, f.category, f.finding_id))
    counters: Dict[str, int] = {}
    out: List[Dict[str, Any]] = []
    for finding in ranked:
        if limit and len(out) >= limit:
            break
        stem = _CANDIDATE_STEM.get(finding.kind, "diff")
        counters[stem] = counters.get(stem, 0) + 1
        out.append(_candidate_from_finding(finding, stem, counters[stem]))
    return out


def _candidate_from_finding(finding: DifferentialFinding, stem: str,
                            ordinal: int) -> Dict[str, Any]:
    missing_names = [str(m.get("name") or m.get("symbol_id")) for m in finding.missing]
    carrier_names = [str(m.get("name") or m.get("symbol_id")) for m in finding.carriers]
    target = finding.missing[0] if finding.missing else {}
    location = ("%s:%d" % (target.get("file"), target.get("line"))
                if target.get("file") else "")
    carrier_text = "; ".join(
        "%s@%s:%s" % (m.get("name"), m.get("file"), m.get("line"))
        for m in finding.carriers[:4])
    patch_text = ""
    if finding.patch_commit:
        patch_text = "；补丁证据 %s %s" % (finding.patch_commit[:12],
                                         finding.patch_subject)

    logic = (
        "%s：同族（%s）%d/%d 个处理函数具备 %s 控制（%s），但 %s 不具"
        "备。缺失方证据：%s%s"
        % (finding.kind, ", ".join(finding.basis), len(finding.carriers),
           len(finding.carriers) + len(finding.missing), finding.category,
           carrier_text or "-", ", ".join(missing_names) or "-", location,
           patch_text)
    )
    if finding.family == "authz":
        hypothesis = (
            "同族接口对同一对象/权限执行了 %s，此接口未执行：可能是新增接口遗漏授权、"
            "补丁未覆盖同族分支，或存在越权（IDOR）路径。" % finding.category
        )
    else:
        hypothesis = (
            "同族接口对输入执行了 %s，此接口未执行：输入校验不一致，"
            "可能被低强度入口绕过。" % finding.category
        )

    code_location: List[str] = []
    if location:
        code_location.append(location)
    for member in finding.missing[1:4]:
        if member.get("file"):
            code_location.append("%s:%s" % (member.get("file"), member.get("line")))
    for member in finding.carriers[:3]:
        if member.get("file"):
            code_location.append("%s:%s" % (member.get("file"), member.get("line")))

    candidate_id = "dif-%s-%04d" % (stem, ordinal)
    return {
        "candidate_id": candidate_id,
        "surface": "%s: %s 缺少 %s（同族 %d/%d 具备）"
                   % (finding.kind, ", ".join(missing_names) or "-",
                      finding.category, len(finding.carriers),
                      len(finding.carriers) + len(finding.missing)),
        "entry": "; ".join(
            str(e) for m in finding.missing for e in (m.get("entries") or [])) or
            (target.get("symbol_id") or ""),
        "input_shape": "unknown",
        "logic": logic,
        "hypothesis": hypothesis,
        # Same reasoning as the control map: static inconsistency does not
        # establish that the path is open under default configuration.
        "precondition_tier_hint": "single-feature",
        "preconditions": [
            "同族成员存在 %s 控制而此成员未见；需确认差异不是扫描范围/上游兜底造成"
            % finding.category,
            "需以同族已守卫接口作为对照，验证缺失方是否可被匿名或低权主体触发",
        ],
        # The fields S3/S4 read, filled here so a static candidate is
        # structurally identical to a proposed one.
        "poc_class": poc_class_for(candidate_id),
        "jvm": {},
        "target_classes": [],
        "authz_cases": (authz_cases_for()
                        if finding.family == "authz" else []),
        "chain_components": ["request-body",
                             "authorization" if finding.family == "authz"
                             else "validation", finding.category],
        "novelty_keywords": sorted(set(
            [finding.kind, finding.differential, "sibling-differential",
             finding.category] + [str(x) for x in finding.basis])),
        "code_location": code_location,
        "category": "authz" if finding.family == "authz" else "",
        # --- provenance + traceability (spec §21.2) ------------------------
        "finding_id": finding.finding_id,
        "group_id": finding.group_id,
        # Same key the control map (spec §11) puts on its candidates: the kind
        # is what a scheduler or a report groups by, so a differential candidate
        # must not be the one that spells it differently.
        "control_kind": finding.kind,
        "differential_kind": finding.differential,
        "control_category": finding.category,
        "control_family": finding.family,
        "agreement": finding.agreement,
        "carriers": [m.get("symbol_id") for m in finding.carriers],
        "missing_members": [m.get("symbol_id") for m in finding.missing],
        "patch_commit": finding.patch_commit,
        "patch_subject": finding.patch_subject,
        "source": "differential",
        "producer": "differential",
        "confidence": "heuristic-nearby",
        "evidence_type": "static-inferred",
    }


# ---------------------------------------------------------------------------
# residual hand-off (spec §14 kind 7)
# ---------------------------------------------------------------------------

def differential_regions(index: Any, reviewed_controls: Optional[Set[str]] = None,
                         reviewed_entries: Optional[Set[str]] = None
                         ) -> List[Dict[str, Any]]:
    """Uncovered-region dicts for findings no review has touched yet.

    A finding leaves the residual once *any* of the control ids it compared has
    been reviewed (``reviewed_controls``) or any of the entries it points at has
    been reviewed (``reviewed_entries``) -- the differential asked a question
    about those controls, and a reviewed control means the question was
    answered.  Findings whose evidence has no id at all stay open, because
    "nothing to check against" is not the same as "checked".
    """
    if index is None:
        return []
    reviewed_controls = reviewed_controls or set()
    reviewed_entries = reviewed_entries or set()
    groups = {g.group_id: g for g in index.groups}
    regions: List[Dict[str, Any]] = []
    for finding in index.findings:
        control_ids = {str(cid) for m in (finding.carriers + finding.missing)
                       for cid in (m.get("control_ids") or [])}
        entry_ids = {str(e) for m in (finding.carriers + finding.missing)
                     for e in (m.get("entries") or [])}
        if control_ids & reviewed_controls or entry_ids & reviewed_entries:
            continue
        group = groups.get(finding.group_id)
        target = finding.missing[0] if finding.missing else {}
        # Evidence comes off the finding itself when the group record was not
        # loaded with the index (the two live in separate files): a residual
        # region must not lose its member list just because a caller read only
        # ``differential-index.json``.
        member_ids = (group.member_ids() if group is not None else
                      [str(m.get("symbol_id")) for m in
                       finding.carriers + finding.missing])
        regions.append({
            "region_id": "gap:differential-candidate:%s" % finding.finding_id,
            "kind": "differential-candidate",
            "risk": finding.risk,
            "reason": "%s：%s 缺少 %s（同族 %d/%d 具备）"
                      % (finding.kind, ", ".join(
                          str(m.get("name") or m.get("symbol_id"))
                          for m in finding.missing) or "-",
                         finding.category, len(finding.carriers),
                         len(finding.carriers) + len(finding.missing)),
            "file": str(target.get("file") or ""),
            "line": _int(target.get("line")),
            "ref": finding.finding_id,
            "detail": {
                "kind": finding.kind,
                "differential": finding.differential,
                "category": finding.category,
                "family": finding.family,
                "agreement": finding.agreement,
                "group_id": finding.group_id,
                "scope": finding.scope,
                "basis": list(group.basis if group is not None else finding.basis),
                "members": member_ids,
                "missing_members": [m.get("symbol_id") for m in finding.missing],
                "carrier_members": [m.get("symbol_id") for m in finding.carriers],
                # The ids above are what a later stage can resolve; the names
                # are what a reader (or the report) needs in order to see the
                # family without opening the sibling index.
                "missing_member_names": [str(m.get("name") or m.get("symbol_id"))
                                         for m in finding.missing],
                "carrier_member_names": [str(m.get("name") or m.get("symbol_id"))
                                         for m in finding.carriers],
                "control_ids": sorted(control_ids),
                "patch_commit": finding.patch_commit,
            },
            "producer": "differential",
            "confidence": finding.confidence,
            "evidence_type": finding.evidence_type,
        })
    regions.sort(key=lambda r: (RISK_ORDER.get(str(r.get("risk")), 9),
                                str(r.get("ref"))))
    return regions


# ---------------------------------------------------------------------------
# persistence
# ---------------------------------------------------------------------------

def write_differential(store: Any, index: DifferentialIndex,
                       candidates: Optional[Sequence[Dict[str, Any]]] = None
                       ) -> Dict[str, str]:
    written: Dict[str, str] = {}
    written[SIBLING_GROUP_INDEX] = str(
        store.write(SIBLING_GROUP_INDEX, index.group_dicts()))
    written[DIFFERENTIAL_INDEX] = str(store.write(DIFFERENTIAL_INDEX,
                                                  index.as_dict()))
    if candidates is not None:
        written[DIFFERENTIAL_CANDIDATE_INDEX] = str(
            store.write(DIFFERENTIAL_CANDIDATE_INDEX, list(candidates)))
    return written


def load_differential(store: Any) -> DifferentialIndex:
    groups = store.read(SIBLING_GROUP_INDEX) or []
    return DifferentialIndex.from_dict(
        store.read(DIFFERENTIAL_INDEX),
        groups if isinstance(groups, list) else [])


def load_differential_candidates(store: Any) -> List[Dict[str, Any]]:
    data = store.read(DIFFERENTIAL_CANDIDATE_INDEX)
    return [c for c in data if isinstance(c, dict)] if isinstance(data, list) else []


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

_LABELS = {
    "zh": {
        "title": "同族接口差分分析（spec §12）",
        "rule": "─" * 46,
        "members": "处理函数（含入口）",
        "groups": "同族分组",
        "findings": "差分发现",
        "by_kind": "按类型",
        "by_risk": "按风险",
        "groups_basis": "分组依据",
        "top": "高危差分",
        "none": "（无）",
        "candidates": "生成候选",
        "limitations": "局限",
    },
    "en": {
        "title": "Sibling / Differential Analysis (spec §12)",
        "rule": "─" * 46,
        "members": "Handlers (entry-hosting)",
        "groups": "Sibling groups",
        "findings": "Findings",
        "by_kind": "By kind",
        "by_risk": "By risk",
        "groups_basis": "Grouping basis",
        "top": "High-risk differentials",
        "none": "(none)",
        "candidates": "Generated candidates",
        "limitations": "Limitations",
    },
}


def render_differential_text(index: DifferentialIndex, lang: str = "zh",
                             limit: int = 20,
                             candidates: Optional[Sequence[Dict[str, Any]]] = None
                             ) -> str:
    labels = _LABELS.get(lang, _LABELS["zh"])
    summary = index.summary()
    lines = [labels["title"], labels["rule"]]
    width = 40

    def row(label: str, value: Any, extra: str = "") -> None:
        lines.append("%-*s %8s  %s" % (width, label, value, extra))

    row(labels["members"], summary["members"])
    row(labels["groups"], summary["groups"])
    row(labels["findings"], summary["findings"])
    lines.append("")
    row(labels["by_kind"], "")
    for kind, count in sorted((summary.get("findings_by_kind") or {}).items()):
        lines.append("  %-*s %6d" % (width - 2, kind, count))
    lines.append("")
    row(labels["by_risk"], "")
    for risk, count in sorted((summary.get("findings_by_risk") or {}).items(),
                              key=lambda kv: (RISK_ORDER.get(kv[0], 9), kv[0])):
        lines.append("  %-*s %6d" % (width - 2, risk, count))
    basis = summary.get("groups_by_basis") or {}
    if basis:
        lines += ["", labels["groups_basis"], labels["rule"]]
        for name, count in sorted(basis.items()):
            lines.append("  %-*s %6d" % (width - 2, name, count))

    ranked = sorted(index.findings, key=lambda f: (RISK_ORDER.get(f.risk, 9),
                                                   f.kind, f.finding_id))
    lines += ["", labels["top"], labels["rule"]]
    if not ranked:
        lines.append("  " + labels["none"])
    for finding in ranked[:max(0, limit)]:
        target = finding.missing[0] if finding.missing else {}
        lines.append("  [%s] %s  %s" % (finding.risk, finding.kind, finding.category))
        lines.append("      group %s  agreement %.2f  scope %s"
                     % (finding.group_id, finding.agreement, finding.scope))
        lines.append("      missing: %s" % ", ".join(
            str(m.get("name") or m.get("symbol_id")) for m in finding.missing))
        lines.append("      carriers: %s" % ", ".join(
            str(m.get("name") or m.get("symbol_id")) for m in finding.carriers))
        if target.get("file"):
            lines.append("      %s:%s" % (target.get("file"), target.get("line")))
        if finding.patch_commit:
            lines.append("      patch: %s %s" % (finding.patch_commit[:12],
                                                 finding.patch_subject))

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
