"""Revision-bound lineage for static evidence; never an independent witness.

This is a sidecar over existing bounded analyses, not another semantic pass.
Rows identify their producer payload by digest without copying source text.
Missing facts or upstream rows remain gaps, and all claims stay not-a-finding.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

EVIDENCE_PROVENANCE_INDEX = "evidence-provenance"
EVIDENCE_PROVENANCE_VERSION = "evidence-provenance-v1"
CLAIM_STATUS = "not-a-finding"
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 64 * 1024 * 1024

_LAYER_SPECS = (
    ("semantic-paths", "semantic-path", ""),
    ("semantic-calls", "call-binding", ""),
    ("semantic-guards", "semantic-guard", "semantic-paths"),
    ("semantic-controlflow", "control-flow", "semantic-guards"),
    ("semantic-ast", "ast-fact", "semantic-controlflow"),
    ("semantic-transforms", "transform-binding", "semantic-paths"),
    ("semantic-python-binding", "value-binding", "semantic-transforms"),
)
_ALIASES = {
    "semantic-paths": ("semantic_paths", "semantic_path", "semantic"),
    "semantic-calls": ("semantic_calls", "semantic_call"),
    "semantic-guards": ("semantic_guards", "semantic_guard"),
    "semantic-controlflow": ("semantic_controlflow", "semantic_control_flow"),
    "semantic-ast": ("semantic_ast", "semantic_ast_evidence"),
    "semantic-transforms": ("semantic_transforms", "semantic_transform"),
    "semantic-python-binding": ("semantic_bindings", "semantic_binding", "semantic_python_binding"),
}


def _dict(row):
    return dict(row) if isinstance(row, Mapping) else asdict(row) if is_dataclass(row) else {}


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":"), default=str).encode()).hexdigest()


def _unique(values):
    return sorted({str(v) for v in values if v})


def _location(row):
    row = _dict(row)
    file = str(row.get("file") or "")
    line = int(row.get("line") or row.get("start_line") or 0)
    span = row.get("span") or row.get("source_span") or {}
    if not span and line:
        span = {"start": line, "end": int(row.get("end_line") or line)}
    if file and line:
        return file, line, span
    for key in ("sink", "control", "guard", "callsite", "entry"):
        nested = row.get(key)
        if isinstance(nested, Mapping):
            location = _location(nested)
            if location[0] and location[1]:
                return location
    locations = row.get("code_location") or []
    for value in [locations] if isinstance(locations, str) else locations:
        match = re.match(r"^(.+?):(\d+)", str(value))
        if match:
            return match[1], int(match[2]), {}
    return file, line, span


class _SourceRevisions:
    """One bounded read per source file, including failed reads."""
    def __init__(self, root):
        self.root = Path(root).resolve() if root is not None else None
        self.cache = {}
        self.bytes_read = 0

    def get(self, file):
        if file in self.cache:
            return self.cache[file]
        digest, gap = "", ""
        try:
            if not self.root or not file:
                gap = "source-root-or-file-missing"
            else:
                path = (self.root / file).resolve()
                if not path.is_relative_to(self.root):
                    gap = "source-outside-root"
                elif not path.is_file():
                    gap = "source-unavailable"
                else:
                    before = path.stat()
                    if before.st_size > MAX_SOURCE_BYTES:
                        gap = "source-file-budget-exceeded"
                    elif before.st_size + self.bytes_read > MAX_TOTAL_SOURCE_BYTES:
                        gap = "source-total-budget-exceeded"
                    else:
                        with path.open("rb") as stream:
                            data = stream.read(MAX_SOURCE_BYTES + 1)
                        self.bytes_read += len(data)
                        after = path.stat()
                        if len(data) > MAX_SOURCE_BYTES or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                            gap = "source-changed-during-read"
                        else:
                            digest = hashlib.sha256(data).hexdigest()
        except OSError:
            gap = "source-unreadable"
        self.cache[file] = (digest, ["%s:%s" % (gap, file)] if gap else [])
        return self.cache[file]


def _artifact(artifacts, producer):
    for key in (producer,) + _ALIASES.get(producer, ()):
        if isinstance(artifacts.get(key), Mapping):
            return artifacts[key]
    return {}


def _candidate_identity(candidate):
    # Scheduling annotations, ordering and reviewer decisions are not identity.
    return _digest({k: candidate.get(k) for k in (
        "candidate_id", "source", "flow_id", "sink_id", "control_id", "category",
        "surface", "code_location", "entry_id", "path", "hypothesis", "logic",
        "semantic_relation", "binding_relation", "transform_relation")})


def research_question_key(candidate):
    """Only documented related surfaces share a verification question.

    A shared source flow alone cannot deduplicate authorization, branch and
    transformation hypotheses. Unknown surfaces are deliberately not merged.
    """
    families = {
        "semantic-transform-gap": "transform-value-binding",
        "semantic-python-binding-gap": "transform-value-binding",
        "semantic-branch-posture": "branch-controlflow",
        "semantic-controlflow-gap": "branch-controlflow",
        "semantic-ast-cfg-gap": "branch-controlflow",
        "semantic-subject-binding": "subject-binding",
    }
    family = families.get(candidate.get("surface"))
    control = candidate.get("control_id")
    group = candidate.get("independence_group")
    if not family or not control or not group or not candidate.get("provenance_complete"):
        return ()
    return (group, str(candidate.get("category") or ""), str(control), family)


def build_evidence_provenance(
        entries: Sequence[Any] = (), sinks: Sequence[Any] = (),
        controls: Sequence[Any] = (), symbols: Sequence[Any] = (),
        flows: Sequence[Any] = (), artifacts: Optional[Mapping[str, Any]] = None,
        candidates: Optional[Mapping[str, Sequence[Mapping[str, Any]]]] = None,
        target: str = "", root: Optional[Path] = None) -> Dict[str, Any]:
    artifacts = artifacts or {}
    revisions = _SourceRevisions(root)
    records, raw, flow_records = {}, {}, {}
    layers = defaultdict(lambda: defaultdict(set))
    details = defaultdict(lambda: defaultdict(set))

    def emit(producer, kind, payload, parents=(), sources=(), group="", gaps=(), fallback=None, **extra):
        parents = _unique(parents)
        sources = _unique(list(sources) + [s for p in parents for s in records[p]["source_fact_ids"]])
        inherited = list(gaps)
        for eid in parents + sources:
            inherited.extend(records[eid]["provenance_gaps"])
        file, line, span = _location(payload)
        if not file or not line:
            file, line, span = _location(fallback)
        row = dict(producer=producer, evidence_type=kind, source_fact_ids=sources,
                   parent_evidence_ids=parents, independence_group=group,
                   confidence=str(payload.get("confidence") or "unknown"),
                   file=file, line=line, span=span, schema_version=EVIDENCE_PROVENANCE_VERSION,
                   claim_status=CLAIM_STATUS, provenance_gaps=_unique(inherited),
                   payload_digest=_digest(payload), **extra)
        row["evidence_id"] = "ev-" + _digest(row)[:32]
        records[row["evidence_id"]] = row
        return row["evidence_id"]

    by_kind, controls_by_symbol = {}, defaultdict(list)
    for kind, rows, key in (("entry", entries, "entry_id"), ("sink", sinks, "sink_id"),
                            ("control", controls, "control_id"), ("symbol", symbols, "symbol_id")):
        by_kind[kind] = {}
        variants = defaultdict(set)
        rows = list(map(_dict, rows))
        for row in rows:
            variants[str(row.get(key) or "")].add(_digest(row))
        for row in sorted(rows, key=lambda r: (str(r.get(key)), _digest(r))):
            rid = str(row.get(key) or "")
            if not rid:
                continue
            revision, gaps = revisions.get(str(row.get("file") or ""))
            gaps = list(gaps)
            if not all(_location(row)[:2]):
                gaps.append("source-location-missing:%s:%s" % (kind, rid))
            if len(variants[rid]) > 1:
                gaps.append("ambiguous-source-id:%s:%s" % (kind, rid))
            eid = emit(str(row.get("producer") or "source-inventory"), "source-fact", row,
                       gaps=gaps, source_revision=revision, fact_kind=kind, fact_id=rid)
            raw[kind, rid] = eid
            by_kind[kind][rid] = row
        if kind == "control":
            for rid, row in by_kind[kind].items():
                controls_by_symbol[row.get("symbol_id")].append(rid)

    for flow in sorted(map(_dict, flows), key=lambda r: (str(r.get("flow_id")), _digest(r))):
        fid = str(flow.get("flow_id") or "")
        if not fid:
            continue
        sink = by_kind["sink"].get(flow.get("sink_id"), {})
        symbols_on_path = _unique(list(flow.get("path") or []) + [flow.get("source_symbol"), sink.get("symbol_id")])
        keys = [("entry", flow.get("entry_id")), ("sink", flow.get("sink_id"))]
        keys += [("symbol", s) for s in symbols_on_path]
        identity_sources = _unique(raw[k] for k in keys if k in raw)
        gaps = ["missing-%s:%s" % k for k in keys if k not in raw]
        keys += [("control", c) for s in symbols_on_path for c in controls_by_symbol.get(s, ())]
        sources = _unique(raw[k] for k in keys if k in raw)
        # Forward/backward aliases share lineage. This is conservative source
        # correlation, not a claim of statistical independence or path equality.
        group = "flow:" + _digest(identity_sources)[:32] if identity_sources else ""
        flow_records[fid] = emit("flow-index", "source-sink-flow", flow, sources=sources,
                                 group=group, gaps=gaps, flow_id=fid, fallback=sink)

    for producer, kind, upstream in _LAYER_SPECS:
        rows = _artifact(artifacts, producer).get("flows") or []
        for row in sorted((r for r in rows if isinstance(r, Mapping)), key=_digest):
            row_digest = _digest(row)
            fid = str(row.get("flow_id") or "")
            base = flow_records.get(fid)
            fact = records.get(base, {})
            sources, group = fact.get("source_fact_ids", []), fact.get("independence_group", "")
            gaps = [] if base else ["missing-flow:%s" % fid]
            upstream_ids = layers[upstream].get(fid, set()) if upstream else set()
            if upstream and not upstream_ids:
                gaps.append("missing-upstream:%s:%s" % (upstream, fid))
            children = []
            for field in ("controls", "guards", "transforms", "call_steps", "taint"):
                values = row.get(field) or []
                values = [values] if isinstance(values, Mapping) else values
                for child in (v for v in values if isinstance(v, Mapping)):
                    control = str(child.get("control_id") or "")
                    child_gaps = list(gaps)
                    child_parents = details[upstream].get((fid, control), set()) if upstream and control else upstream_ids
                    child_sources = list(sources)
                    if control:
                        if ("control", control) in raw:
                            child_sources.append(raw["control", control])
                        else:
                            child_gaps.append("missing-control:%s" % control)
                        if upstream and not child_parents:
                            child_gaps.append("missing-upstream-control:%s:%s" % (upstream, control))
                    eid = emit(producer, kind + "-detail", child,
                               parents=[base] + list(child_parents), sources=child_sources,
                               group=group, gaps=child_gaps, fallback=row, flow_id=fid,
                               control_id=control, artifact_field=field,
                               artifact_row_digest=row_digest)
                    children.append(eid)
                    if control:
                        details[producer][fid, control].add(eid)
            eid = emit(producer, kind, row, parents=[base] + list(upstream_ids) + children,
                       sources=sources, group=group, gaps=gaps, fallback=fact, flow_id=fid)
            layers[producer][fid].add(eid)

    candidate_rows = candidates if candidates is not None else {
        p: _artifact(artifacts, p).get("candidates", []) for p, _, _ in _LAYER_SPECS}
    lookup, groups = {}, defaultdict(list)
    candidate_identities = defaultdict(set)
    for rows in candidate_rows.values():
        for candidate in rows or []:
            candidate_identities[str(candidate.get("candidate_id") or "")].add(_candidate_identity(candidate))
    semantic_producers = {p for p, _, _ in _LAYER_SPECS}
    for producer in sorted(candidate_rows):
        for candidate in sorted(candidate_rows[producer] or [], key=_digest):
            cid = str(candidate.get("candidate_id") or "")
            if not cid or cid in lookup:
                continue
            fid, control = str(candidate.get("flow_id") or ""), str(candidate.get("control_id") or "")
            base = flow_records.get(fid)
            fact = records.get(base, {})
            group, sources = fact.get("independence_group", ""), fact.get("source_fact_ids", [])
            gaps = [] if base else ["missing-flow:%s" % fid]
            if len(candidate_identities[cid]) > 1:
                gaps.append("ambiguous-candidate-id:%s" % cid)
            upstream_ids = details[producer].get((fid, control), set()) if control else layers[producer].get(fid, set())
            if producer in semantic_producers and not upstream_ids:
                gaps.append("missing-candidate-evidence:%s:%s:%s" % (producer, fid, control))
            if producer not in semantic_producers:
                gaps.append("producer-lineage-not-modeled:%s" % producer)
            eid = emit(producer, "static-candidate", candidate,
                       parents=[base] + list(upstream_ids), sources=sources,
                       group=group, gaps=gaps, candidate_id=cid, control_id=control)
            closure, pending = set(), [eid]
            while pending:
                parent = pending.pop()
                if parent not in closure:
                    closure.add(parent)
                    pending.extend(records[parent]["parent_evidence_ids"])
            metadata = dict(candidate_id=cid, candidate_identity=(
                                _candidate_identity(candidate) if len(candidate_identities[cid]) == 1 else ""),
                            evidence_ids=sorted(closure), source_fact_ids=records[eid]["source_fact_ids"],
                            parent_evidence_ids=records[eid]["parent_evidence_ids"],
                            independence_group=group, independence_groups=[group] if group else [],
                            independent_evidence_count=int(bool(group)), derived_evidence_count=len(closure),
                            correlated_evidence_count=max(0, len(closure) - int(bool(group))),
                            provenance_complete=not records[eid]["provenance_gaps"],
                            provenance_gaps=records[eid]["provenance_gaps"],
                            schema_version=EVIDENCE_PROVENANCE_VERSION, claim_status=CLAIM_STATUS)
            lookup[cid] = metadata
            if group:
                groups[group].append(cid)

    correlations = []
    for group, ids in sorted(groups.items()):
        ids = sorted(ids)
        for cid in ids:
            lookup[cid]["correlated_candidate_count"] = len(ids) - 1
        # Store peers once per group, not an O(candidates²) list per candidate.
        correlations.append(dict(independence_group=group, candidate_ids=ids,
                                 representative_candidate_id=ids[0], candidate_count=len(ids),
                                 independent_evidence_count=1, claim_status=CLAIM_STATUS))
    counts = Counter("raw" if r.get("fact_kind") else "candidate" if r["evidence_type"] == "static-candidate"
                     else "derived" for r in records.values())
    return dict(schema_version=EVIDENCE_PROVENANCE_VERSION, target=target,
                records=[records[k] for k in sorted(records)],
                candidate_provenance={k: lookup[k] for k in sorted(lookup)},
                candidate_correlations=correlations, claim_status=CLAIM_STATUS,
                producer=EVIDENCE_PROVENANCE_INDEX, confidence="heuristic-nearby", evidence_type="static-inferred",
                summary=dict(records=len(records), raw_source_facts=counts["raw"], derived_evidence=counts["derived"],
                             candidate_evidence=counts["candidate"], candidates=len(lookup), independence_groups=len(groups),
                             correlated_groups=sum(len(v) > 1 for v in groups.values()),
                             correlated_candidates=sum(len(v) - 1 for v in groups.values()),
                             incomplete_candidates=sum(not m["provenance_complete"] for m in lookup.values()),
                             source_files=len(revisions.cache), source_bytes_read=revisions.bytes_read,
                             source_files_hashed=sum(bool(v[0]) for v in revisions.cache.values()),
                             claim_status=CLAIM_STATUS),
                limitations=[
                    "Groups measure shared source lineage, not statistical independence or equivalent hypotheses.",
                    "Source hashes identify files read during this build, not an atomic repository snapshot.",
                    "Missing sources, upstream rows and unmodeled candidate producers remain explicit gaps.",
                    "Semantic uncertainty is separate from lineage completeness; neither proves a vulnerability.",
                    "Static provenance never changes S4/G4/G5 or promotes a finding."])


def enrich_candidates(candidates, provenance):
    """Attach a defensive metadata copy only to the original hypothesis."""
    lookup = provenance.get("candidate_provenance", {}) if isinstance(provenance, Mapping) else {}
    output = []
    for row in candidates:
        if not isinstance(row, Mapping):
            continue
        candidate = copy.deepcopy(dict(row))
        metadata = lookup.get(str(row.get("candidate_id") or ""), {})
        if candidate.get("provenance_schema_version") == EVIDENCE_PROVENANCE_VERSION:
            for key in ("evidence_ids", "source_fact_ids", "parent_evidence_ids",
                        "independence_group", "independence_groups", "independent_evidence_count",
                        "derived_evidence_count", "correlated_evidence_count", "correlated_candidate_count",
                        "provenance_complete", "provenance_gaps", "provenance_schema_version", "provenance_claim_status"):
                candidate.pop(key, None)
        if metadata.get("candidate_identity") == _candidate_identity(row):
            for key, value in metadata.items():
                if key not in ("candidate_id", "candidate_identity", "schema_version", "claim_status"):
                    candidate[key] = copy.deepcopy(value)
            candidate["provenance_schema_version"] = EVIDENCE_PROVENANCE_VERSION
            candidate["provenance_claim_status"] = CLAIM_STATUS
        output.append(candidate)
    return output


def load_evidence_provenance(store):
    data = store.read(EVIDENCE_PROVENANCE_INDEX)
    return data if isinstance(data, dict) else {}


def render_evidence_provenance_text(provenance, lang="zh"):
    summary = provenance.get("summary") or {}
    template = ("Evidence provenance: %s records, %s source groups, %s correlated candidates"
                if lang == "en" else "证据溯源：%s 条记录，%s 个同源组，%s 个相关候选")
    return template % (summary.get("records", 0), summary.get("independence_groups", 0),
                       summary.get("correlated_candidates", 0))
