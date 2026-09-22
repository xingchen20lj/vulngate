"""Security coverage metrics (spec §5, §16, §20) and residual-gap derivation (§14).

Coverage is computed **only** from deterministic scanner output plus review
state -- never from an LLM (spec §21.1).  Consequently every ratio here is
reproducible: same tree + same review states => same numbers.

Denominators always come from the full inventory.  A ratio that only counted
the regions already discovered would be the very failure mode this layer exists
to eliminate (spec §20, closing note).

Definitions used below (stated explicitly because "reviewed" is easy to weaken
into meaninglessness):

``reviewed``
    ``review_state``/``audit_state`` in ``reviewed``, ``runtime-verified`` or
    ``excluded``.  An explicitly excluded region *has* been looked at.
``sink with reachability analysis``
    forward reachable from a discovered entry, **or** backward reachable from
    itself to an entry, **or** already reviewed/excluded.
``runtime verification coverage``
    runtime-verified regions / (runtime-verified + statically reviewed).  This
    measures how much of the review is backed by observed runtime behaviour --
    the project's evidence-gate culture expressed as a number, not a claim.
``HIGH-risk uncovered``
    high-severity sink, high-risk entry kind, security-critical control, or
    high-priority flow that is neither reviewed nor explicitly excluded.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..tools.conclusion import conclusion_status
from . import controls as control_map
from . import differential as differential_analysis
from . import models
from .inventory import CoverageStore

#: Entry kinds whose input is attacker-controlled over a network / IPC boundary.
HIGH_RISK_ENTRY_KINDS = frozenset({
    "http", "rpc", "message", "url-scheme", "webview", "ipc", "target-rule",
})

#: Control categories whose absence is itself a vulnerability class.
SECURITY_CRITICAL_CONTROL_CATEGORIES = frozenset({
    "authentication", "authorization", "validation", "sanitization",
    "allowlist", "signature-check", "path-check", "csrf", "origin-check",
})

#: Control categories feeding the "authorization boundary" ratio (spec §5.5).
AUTH_BOUNDARY_CONTROL_CATEGORIES = frozenset({"authentication", "authorization"})

#: Control categories feeding the "validation" ratio.
VALIDATION_CONTROL_CATEGORIES = frozenset({
    "validation", "sanitization", "allowlist", "length-limit", "depth-limit",
    "path-check", "origin-check", "signature-check",
})

#: Acceptance targets (spec §20).
ACCEPTANCE_TARGETS: Dict[str, float] = {
    "source_coverage": 0.98,
    "entry_coverage": 0.95,
    "sink_coverage": 0.95,
    "flow_coverage": 0.90,
    "auth_boundary_coverage": 0.95,
}

#: Flow priorities counted in the flow-coverage denominator (spec §5.4).
FLOW_COVERAGE_PRIORITIES = frozenset({"high", "medium"})

#: How far from a candidate's code_location a record still counts as touched.
CANDIDATE_COVER_WINDOW = 160


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    """Coverage ratio, or ``None`` when there is nothing to cover.

    ``None`` -- not ``1.0`` -- is the honest answer for a zero denominator.  A
    target with no discovered sinks has *undefined* sink coverage; reporting
    "100% covered" would be exactly the kind of unearned number this layer
    exists to prevent.
    """
    if denominator <= 0:
        return None
    return round(numerator / denominator, 4)


def _pct(value: Optional[float]) -> str:
    if value is None:
        return "n/a"
    return "%.1f%%" % (value * 100.0)


def _state_of(record: Dict[str, Any]) -> str:
    return models.normalize_audit_state(
        record.get("review_state") or record.get("audit_state") or "indexed")


def _reviewed(record: Dict[str, Any]) -> bool:
    return models.is_reviewed(_state_of(record))


def _excluded(record: Dict[str, Any]) -> bool:
    return _state_of(record) == "excluded"


def _runtime_verified(record: Dict[str, Any]) -> bool:
    return _state_of(record) == "runtime-verified"


def _is_source_critical(record: Dict[str, Any]) -> bool:
    """High-risk source file: production code carrying sinks or entries."""
    return (bool(record.get("production"))
            and (int(record.get("sinks") or 0) > 0
                 or int(record.get("entries") or 0) > 0
                 or bool(record.get("controls"))))


def _audit_status(scope: Optional[Dict[str, Any]], high_risk_uncovered: int
                  ) -> Dict[str, Any]:
    """State machine for coverage closure, separate from vulnerability status.

    ``coverage-closed`` says only that this inventory's high-risk residual is
    empty.  It does not claim a vulnerability, runtime effect, novelty result,
    CVSS result or S4/G4 completion.  Invalid or unknown scope is a hard
    blocker even when the resulting index happens to have zero denominators.
    """
    scope = dict(scope or {})
    scope_present = bool(scope)
    scope_valid = bool(scope.get("valid", True))
    blockers: List[str] = []
    if scope_present and not scope_valid:
        blockers.append("scope-invalid")
        blockers.extend(str(item) for item in scope.get("analysis_gaps") or []
                       if item)
        state = "scope-invalid"
    elif high_risk_uncovered:
        blockers.append("high-risk-uncovered:%d" % int(high_risk_uncovered))
        state = "partial-coverage"
    else:
        state = "coverage-closed"
    return {
        "state": state,
        "scope_id": str(scope.get("scope_id") or ""),
        "scope_valid": scope_valid,
        "scope_present": scope_present,
        "blockers": blockers,
        "claim_status": "not-a-finding",
    }


# ---------------------------------------------------------------------------
# metric computation
# ---------------------------------------------------------------------------

def compute_coverage(indices: Dict[str, List[Dict[str, Any]]],
                     uncovered_probe: bool = True,
                     scope: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Compute every coverage ratio from the persisted indices."""
    sources = indices.get("source-inventory") or []
    entries = indices.get("entry-index") or []
    sinks = indices.get("sink-index") or []
    controls = indices.get("security-control-index") or []
    flows = indices.get("flow-index") or []

    production = [s for s in sources if s.get("production")]
    indexed = [s for s in production if s.get("indexed")]
    skipped = [s for s in sources if not s.get("production")]

    reviewed_entries = [e for e in entries if _reviewed(e)]
    reachability_sinks = [
        s for s in sinks
        if (s.get("reachable_from_entries") or s.get("backward_reachable")
            or _reviewed(s))
    ]
    priority_flows = [f for f in flows
                      if str(f.get("priority", "medium")) in FLOW_COVERAGE_PRIORITIES]
    reviewed_flows = [f for f in priority_flows if _reviewed(f)]

    auth_controls = [c for c in controls
                     if c.get("category") in AUTH_BOUNDARY_CONTROL_CATEGORIES]
    val_controls = [c for c in controls
                    if c.get("category") in VALIDATION_CONTROL_CATEGORIES]

    all_records = entries + sinks + controls + flows
    reviewed_records = [r for r in all_records if _reviewed(r)]
    runtime_records = [r for r in all_records if _runtime_verified(r)]
    static_reviewed = [r for r in reviewed_records if not _runtime_verified(r)]

    uncovered = build_uncovered_regions(indices) if uncovered_probe else []
    uncovered_hist: Dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for region in uncovered:
        uncovered_hist[str(region.get("risk", "medium"))] = \
            uncovered_hist.get(str(region.get("risk", "medium")), 0) + 1

    source_cov = _ratio(len(indexed), len(production))
    entry_cov = _ratio(len(reviewed_entries), len(entries))
    sink_cov = _ratio(len(reachability_sinks), len(sinks))
    flow_cov = _ratio(len(reviewed_flows), len(priority_flows))
    auth_cov = _ratio(len([c for c in auth_controls if _reviewed(c)]), len(auth_controls))
    val_cov = _ratio(len([c for c in val_controls if _reviewed(c)]), len(val_controls))
    runtime_cov = _ratio(len(runtime_records),
                         len(runtime_records) + len(static_reviewed))

    metrics = {
        "source_coverage": source_cov,
        "entry_coverage": entry_cov,
        "sink_coverage": sink_cov,
        "flow_coverage": flow_cov,
        "auth_boundary_coverage": auth_cov,
        "validation_coverage": val_cov,
        "runtime_verification_coverage": runtime_cov,
    }
    audit_status = _audit_status(scope, uncovered_hist.get("high", 0))
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "counts": {
            "production_source_files": len(production),
            "indexed_source_files": len(indexed),
            "skipped_source_files": len(skipped),
            "source_files_total": len(sources),
            "entries": len(entries),
            "entries_reviewed": len(reviewed_entries),
            "sinks": len(sinks),
            "sinks_reachability_analyzed": len(reachability_sinks),
            "flows_total": len(flows),
            "flows_priority": len(priority_flows),
            "flows_reviewed": len(reviewed_flows),
            "flows_confirmed": len([f for f in priority_flows if _runtime_verified(f)]),
            "flows_excluded": len([f for f in priority_flows if _excluded(f)]),
            "flows_pending": len([f for f in priority_flows if not _reviewed(f)]),
            "auth_boundaries": len(auth_controls),
            "auth_boundaries_reviewed": len([c for c in auth_controls if _reviewed(c)]),
            "validation_controls": len(val_controls),
            "validation_controls_reviewed": len([c for c in val_controls if _reviewed(c)]),
            "controls": len(controls),
            "records_reviewed": len(reviewed_records),
            "records_runtime_verified": len(runtime_records),
            "records_statically_reviewed": len(static_reviewed),
            "uncovered_high": uncovered_hist.get("high", 0),
            "uncovered_medium": uncovered_hist.get("medium", 0),
            "uncovered_low": uncovered_hist.get("low", 0),
        },
        "metrics": metrics,
        "acceptance": {name: {"target": target, "actual": metrics[name],
                              "met": metrics[name] is not None
                                     and metrics[name] >= target}
                       for name, target in ACCEPTANCE_TARGETS.items()},
        "high_risk_uncovered": uncovered_hist.get("high", 0),
        "stop_condition_met": audit_status["state"] == "coverage-closed",
        "audit_status": audit_status,
        "uncovered_regions": uncovered,
    }


# ---------------------------------------------------------------------------
# residual sweep (spec §14)
# ---------------------------------------------------------------------------

def build_uncovered_regions(indices: Dict[str, List[Dict[str, Any]]],
                            limit_per_kind: Optional[int] = None
                            ) -> List[Dict[str, Any]]:
    """Derive the residual gap list handed to the next round (spec §14).

    Categories, in the order spec §14 lists them:

    1. unreviewed high-risk entry
    2. unreviewed high-severity sink
    3. unreviewed entry->sink flow (enriched with the §11 control verdict)
    4. security-critical control with no candidate
    5. forward/backward coverage mismatch on a sink
    6. unreviewed high-risk source file
    7. newly discovered differential candidate (spec §12, PR4)

    Kind 3 is *enriched* rather than duplicated: an unguarded flow is already a
    flow gap, so its region records the missing control classes in ``detail``
    instead of becoming a second region of its own.  Counting it twice would
    inflate ``high_risk_uncovered`` -- the number the stop condition reads --
    without adding a single thing left to look at.  Kind 7 is genuinely new
    material (a sibling inconsistency is not a flow), so it does add regions.
    """
    sources = indices.get("source-inventory") or []
    entries = indices.get("entry-index") or []
    sinks = indices.get("sink-index") or []
    controls = indices.get("security-control-index") or []
    flows = indices.get("flow-index") or []
    cmap = indices.get(control_map.CONTROL_MAP_INDEX) or {}
    diff_index = indices.get(differential_analysis.DIFFERENTIAL_INDEX) or {}
    verdicts = {str(entry.get("flow_id")): entry
                for entry in (cmap.get("entries") or [])}
    regions: List[Dict[str, Any]] = []
    counters: Dict[str, int] = {}

    def add(kind: str, risk: str, reason: str, file: str = "", line: int = 0,
            ref: str = "", detail: Optional[Dict[str, Any]] = None) -> None:
        counters[kind] = counters.get(kind, 0) + 1
        if limit_per_kind is not None and counters[kind] > limit_per_kind:
            return
        region = models.UncoveredRegion(
            region_id="gap:%s:%04d" % (kind, counters[kind]),
            kind=kind, risk=risk, reason=reason, file=file, line=line,
            ref=ref, detail=detail or {},
        )
        regions.append(region.as_dict())

    # 1. unreviewed high-risk entries
    for entry in entries:
        if _reviewed(entry):
            continue
        if str(entry.get("kind")) not in HIGH_RISK_ENTRY_KINDS:
            continue
        add("unreviewed-entry", "high",
            "external entry kind=%s has no review evidence" % entry.get("kind"),
            str(entry.get("file", "")), int(entry.get("line") or 0),
            str(entry.get("entry_id", "")),
            {"kind": entry.get("kind"), "framework": entry.get("framework"),
             "input_shape": entry.get("input_shape")})

    # 2. unreviewed high-severity sinks
    for sink in sinks:
        if _reviewed(sink):
            continue
        severity = str(sink.get("severity_hint", "medium"))
        if severity != "high":
            continue
        add("unreviewed-sink", "high",
            "high-severity sink category=%s has no reachability review"
            % sink.get("category"),
            str(sink.get("file", "")), int(sink.get("line") or 0),
            str(sink.get("sink_id", "")),
            {"category": sink.get("category"), "api": sink.get("api")})

    # 3. unreviewed entry->sink flows
    for flow in flows:
        if _reviewed(flow):
            continue
        priority = str(flow.get("priority", "medium"))
        risk = "high" if priority == "high" else "medium"
        detail: Dict[str, Any] = {"path": flow.get("path", []),
                                  "priority": priority}
        verdict = verdicts.get(str(flow.get("flow_id", "")))
        if verdict is not None:
            # spec §11: the region now says *which* control class is missing and
            # how strong the absence is, so the next round does not have to
            # re-derive it from the flow record.
            detail["control_verdict"] = verdict.get("verdict")
            detail["missing_controls"] = list(verdict.get("missing") or [])
            detail["missing_groups"] = [list(g) for g in
                                        (verdict.get("missing_groups") or [])]
            detail["present_controls"] = list(verdict.get("present") or [])
            detail["control_evidence"] = list(verdict.get("control_ids") or [])
        reason = ("flow %s from %s to %s is pending"
                  % (flow.get("confidence"), flow.get("entry_id"),
                     flow.get("sink_id")))
        if verdict is not None and verdict.get("verdict") in ("uncontrolled",
                                                              "partial"):
            reason += "; missing controls: %s" % (
                ",".join(str(c) for c in verdict.get("missing") or []) or "-")
        add("unreviewed-flow", risk, reason, "", 0,
            str(flow.get("flow_id", "")), detail)

    # 4. security-critical controls with no candidate touching them
    for control in controls:
        if _reviewed(control) or control.get("candidate_ids"):
            continue
        if str(control.get("category")) not in SECURITY_CRITICAL_CONTROL_CATEGORIES:
            continue
        add("control-gap", "medium",
            "security control %s has neither review nor candidate coverage"
            % control.get("category"),
            str(control.get("file", "")), int(control.get("line") or 0),
            str(control.get("control_id", "")),
            {"category": control.get("category"),
             "control_type": control.get("control_type")})

    # 5. forward/backward coverage mismatch
    for sink in sinks:
        forward = bool(sink.get("reachable_from_entries"))
        backward = bool(sink.get("backward_reachable"))
        if forward == backward:
            continue
        add("forward-backward-mismatch", "high" if backward else "medium",
            "sink seen by %s analysis only" % ("backward" if backward else "forward"),
            str(sink.get("file", "")), int(sink.get("line") or 0),
            str(sink.get("sink_id", "")),
            {"forward_seen": forward, "backward_seen": backward})

    # 6. unreviewed high-risk production source files
    for source in sources:
        if _reviewed(source) or not _is_source_critical(source):
            continue
        add("unreviewed-source", "medium",
            "production file with %s sink(s)/%s entry(ies) is unreviewed"
            % (source.get("sinks"), source.get("entries")),
            str(source.get("file", "")), 0, str(source.get("file", "")),
            {"sinks": source.get("sinks"), "entries": source.get("entries"),
             "controls": source.get("controls")})

    # 7. sibling/differential findings nobody has reviewed yet (spec §12)
    if diff_index:
        reviewed_controls = {str(c.get("control_id")) for c in controls
                             if _reviewed(c)}
        reviewed_entries = {str(e.get("entry_id")) for e in entries
                            if _reviewed(e)}
        for region in differential_analysis.differential_regions(
                differential_analysis.DifferentialIndex.from_dict(diff_index),
                reviewed_controls, reviewed_entries):
            counters["differential-candidate"] = \
                counters.get("differential-candidate", 0) + 1
            if limit_per_kind is not None \
                    and counters["differential-candidate"] > limit_per_kind:
                continue
            regions.append(region)

    return regions


# ---------------------------------------------------------------------------
# candidate -> coverage linkage
# ---------------------------------------------------------------------------

def _parse_locations(candidate: Dict[str, Any]) -> List[Tuple[str, int]]:
    raw = candidate.get("code_location") or candidate.get("code_locations") or []
    if isinstance(raw, str):
        raw = [raw]
    out: List[Tuple[str, int]] = []
    for item in raw:
        text = str(item).strip()
        if not text:
            continue
        if ":" in text:
            head, _, tail = text.rpartition(":")
            if tail.isdigit() and head:
                out.append((head, int(tail)))
                continue
        out.append((text, 0))
    entry_file = str(candidate.get("entry_file") or "")
    if entry_file:
        out.append((entry_file, 0))
    return out


def _touches(record_file: str, record_line: int,
             locations: Sequence[Tuple[str, int]],
             window: int = CANDIDATE_COVER_WINDOW) -> bool:
    for file, line in locations:
        if not file:
            continue
        if file != record_file and not record_file.endswith(file) \
                and not file.endswith(record_file):
            continue
        if not line or not record_line:
            return True
        if abs(int(record_line) - int(line)) <= window:
            return True
    return False


def build_candidate_coverage(ledger_rows: Iterable[Dict[str, Any]],
                             indices: Dict[str, List[Dict[str, Any]]],
                             round_no: int = 0
                             ) -> List[models.CandidateCoverageRecord]:
    """Map ledger rows onto coverage regions.

    The linkage is a *heuristic* (file match, or same-file line distance within
    :data:`CANDIDATE_COVER_WINDOW`); it is recorded with ``producer`` /
    ``confidence`` so a reviewer can see why a region flipped to reviewed.  It
    never promotes a candidate to a confirmed finding -- that stays the job of
    the conclusion rules and the G-gates.
    """
    entries = indices.get("entry-index") or []
    sinks = indices.get("sink-index") or []
    flows = indices.get("flow-index") or []
    controls = indices.get("security-control-index") or []
    records: List[models.CandidateCoverageRecord] = []

    for row in ledger_rows:
        if not isinstance(row, dict):
            continue
        cid = str(row.get("candidate_id") or row.get("id") or row.get("surface") or "")
        if not cid:
            continue
        locations = _parse_locations(row)
        status = conclusion_status(row.get("conclusion"))
        matched_entries = [str(e.get("entry_id")) for e in entries
                           if _touches(str(e.get("file", "")), int(e.get("line") or 0),
                                       locations)]
        matched_sinks = [str(s.get("sink_id")) for s in sinks
                         if _touches(str(s.get("file", "")), int(s.get("line") or 0),
                                     locations)]
        matched_controls = [str(c.get("control_id")) for c in controls
                            if _touches(str(c.get("file", "")), int(c.get("line") or 0),
                                        locations)]
        entry_ids = set(matched_entries)
        matched_flows = [str(f.get("flow_id")) for f in flows
                         if str(f.get("entry_id")) in entry_ids]
        mechanisms = [str(x) for x in (row.get("novelty_keywords") or [])]
        records.append(models.CandidateCoverageRecord(
            candidate_id=cid, round=round_no,
            conclusion=str(row.get("conclusion") or ""),
            entries=sorted(set(matched_entries)),
            sinks=sorted(set(matched_sinks)),
            flows=sorted(set(matched_flows)),
            files=sorted({f for f, _ in locations if f}),
            categories=sorted(set(
                [str(s.get("category")) for s in sinks
                 if str(s.get("sink_id")) in set(matched_sinks)]
                + [str(c.get("category")) for c in controls
                   if str(c.get("control_id")) in set(matched_controls)])),
            mechanisms=mechanisms,
            status=status if status != "unknown" else "open",
        ))
    return records


def apply_candidate_coverage(indices: Dict[str, List[Dict[str, Any]]],
                             coverage_records: Sequence[Dict[str, Any]],
                             ) -> Dict[str, int]:
    """Flip review state on regions a candidate touched.

    Mutates the index dicts in place (they are freshly loaded plain dicts, not
    shared state) and returns a ``{collection: regions_marked}`` summary.
    ``excluded`` conclusions mark regions ``excluded``; any other non-open
    conclusion marks them ``reviewed``.  Runtime verification is never inferred
    here -- only the G-gates and S4 can set ``runtime-verified``.
    """
    marks: Dict[str, int] = {"entries": 0, "sinks": 0, "flows": 0, "controls": 0}
    by_id: Dict[str, Dict[str, Dict[str, Any]]] = {
        "entries": {str(r.get("entry_id")): r for r in indices.get("entry-index") or []},
        "sinks": {str(r.get("sink_id")): r for r in indices.get("sink-index") or []},
        "flows": {str(r.get("flow_id")): r for r in indices.get("flow-index") or []},
        "controls": {str(r.get("control_id")): r for r in
                     indices.get("security-control-index") or []},
    }
    for record in coverage_records:
        status = str(record.get("status") or "open")
        if status in ("open", "", "candidate"):
            continue
        target_state = "excluded" if status == "excluded" else "reviewed"
        cid = str(record.get("candidate_id") or "")
        for collection, key in (("entries", "entries"), ("sinks", "sinks"),
                               ("flows", "flows"), ("controls", "controls")):
            for region_id in record.get(key) or []:
                region = by_id[collection].get(str(region_id))
                if region is None:
                    continue
                region["review_state"] = models.merge_state(
                    region.get("review_state"), target_state)
                if cid and cid not in (region.get("candidate_ids") or []):
                    region.setdefault("candidate_ids", []).append(cid)
                marks[collection] += 1
    return marks


# ---------------------------------------------------------------------------
# rendering (spec §16)
# ---------------------------------------------------------------------------

_LABELS = {
    "zh": {
        "title": "安全审计覆盖率",
        "rule": "─" * 46,
        "production": "生产源码文件",
        "indexed": "已索引",
        "skipped": "已跳过",
        "entries": "外部入口",
        "entries_reviewed": "已审计",
        "sinks": "危险 sink",
        "sinks_analyzed": "已完成可达性分析",
        "flows": "入口 → sink 路径",
        "flows_reviewed": "已审计",
        "confirmed": "已确认",
        "excluded": "已排除",
        "pending": "待验证",
        "high_unreviewed": "高风险未审计",
        "medium_unreviewed": "中风险未审计",
        "low_unreviewed": "低风险未审计",
        "auth": "鉴权边界",
        "validation": "校验控制",
        "runtime": "运行时验证占比",
        "acceptance": "验收指标",
        "stop": "停止条件（高风险未审计 == 0）",
        "met": "达标",
        "unmet": "未达标",
        "yes": "是",
        "no": "否",
        "gaps": "覆盖缺口（按类型）",
    },
    "en": {
        "title": "Security Audit Coverage",
        "rule": "─" * 46,
        "production": "Production source files",
        "indexed": "Indexed",
        "skipped": "Skipped",
        "entries": "External entries",
        "entries_reviewed": "Reviewed",
        "sinks": "Danger sinks",
        "sinks_analyzed": "Reachability analyzed",
        "flows": "Entry → Sink flows",
        "flows_reviewed": "Reviewed",
        "confirmed": "Confirmed",
        "excluded": "Excluded",
        "pending": "Pending",
        "high_unreviewed": "HIGH-risk unreviewed",
        "medium_unreviewed": "MEDIUM-risk unreviewed",
        "low_unreviewed": "LOW-risk unreviewed",
        "auth": "Auth boundaries",
        "validation": "Validation controls",
        "runtime": "Runtime-verified share",
        "acceptance": "Acceptance targets",
        "stop": "Stop condition (HIGH-risk uncovered == 0)",
        "met": "met",
        "unmet": "NOT met",
        "yes": "yes",
        "no": "no",
        "gaps": "Coverage gaps by kind",
    },
}


def _t(lang: str) -> Dict[str, str]:
    return _LABELS.get(lang, _LABELS["zh"])


def _display_width(text: str) -> int:
    """Terminal columns for ``text`` (CJK wide chars count as two)."""
    import unicodedata
    width = 0
    for char in text:
        width += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
    return width


def _pad(text: str, width: int) -> str:
    text = str(text)
    return text + " " * max(0, width - _display_width(text))


def render_coverage_text(summary: Dict[str, Any], lang: str = "zh",
                         gap_limit: Optional[int] = None) -> str:
    """Render the spec §16 coverage report."""
    t = _t(lang)
    counts = summary.get("counts", {})
    metrics = summary.get("metrics", {})
    lines: List[str] = [t["title"], t["rule"]]
    label_width = 32

    def row(label: str, count: Any, extra: str = "") -> None:
        lines.append("%s %8s  %s" % (_pad(label, label_width), count, extra))

    row(t["production"], counts.get("production_source_files", 0))
    row(t["indexed"], counts.get("indexed_source_files", 0),
        _pct(metrics.get("source_coverage")))
    total_source = counts.get("source_files_total", 0) or 0
    skipped_share = (None if not total_source
                     else round(counts.get("skipped_source_files", 0) / total_source, 4))
    row(t["skipped"], counts.get("skipped_source_files", 0), _pct(skipped_share))
    lines.append("")
    row(t["entries"], counts.get("entries", 0))
    row(t["entries_reviewed"], counts.get("entries_reviewed", 0),
        _pct(metrics.get("entry_coverage")))
    lines.append("")
    row(t["sinks"], counts.get("sinks", 0))
    row(t["sinks_analyzed"], counts.get("sinks_reachability_analyzed", 0),
        _pct(metrics.get("sink_coverage")))
    lines.append("")
    row(t["flows"], counts.get("flows_priority", 0))
    row(t["flows_reviewed"], counts.get("flows_reviewed", 0),
        _pct(metrics.get("flow_coverage")))
    row(t["confirmed"], counts.get("flows_confirmed", 0))
    row(t["excluded"], counts.get("flows_excluded", 0))
    row(t["pending"], counts.get("flows_pending", 0))
    lines.append("")
    row(t["auth"], counts.get("auth_boundaries", 0),
        _pct(metrics.get("auth_boundary_coverage")))
    row(t["validation"], counts.get("validation_controls", 0),
        _pct(metrics.get("validation_coverage")))
    row(t["runtime"], counts.get("records_runtime_verified", 0),
        _pct(metrics.get("runtime_verification_coverage")))
    lines.append("")
    row(t["high_unreviewed"], counts.get("uncovered_high", 0))
    row(t["medium_unreviewed"], counts.get("uncovered_medium", 0))
    row(t["low_unreviewed"], counts.get("uncovered_low", 0))

    acceptance = summary.get("acceptance") or {}
    if acceptance:
        lines += ["", t["acceptance"], t["rule"]]
        for name, entry in sorted(acceptance.items()):
            state = t["met"] if entry.get("met") else t["unmet"]
            lines.append("%s %8s  %s" % (
                _pad(name, label_width), _pct(entry.get("actual")),
                "%s (>= %s)" % (state, _pct(entry.get("target")))))
    lines += ["", "%s: %s" % (t["stop"],
                              t["yes"] if summary.get("stop_condition_met") else t["no"])]

    if gap_limit:
        hist: Dict[str, int] = {}
        for region in summary.get("uncovered_regions") or []:
            kind = str(region.get("kind", "unknown"))
            hist[kind] = hist.get(kind, 0) + 1
        if hist:
            lines += ["", t["gaps"], t["rule"]]
            for kind, count in sorted(hist.items(), key=lambda kv: (-kv[1], kv[0])):
                lines.append("%s %8d" % (_pad(kind, label_width), count))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# convenience entry points
# ---------------------------------------------------------------------------

def load_coverage_inputs(workspace, target: str) -> Dict[str, List[Dict[str, Any]]]:
    """Load every index the coverage model reads.

    The two PR4 entries are read as their native shapes (an object, and a list
    of findings inside ``differential-index``), not as record lists, because
    that is what :mod:`agent.analysis.controls` and
    :mod:`agent.analysis.differential` persist.  Their absence is normal: a
    store built before PR4 simply has no control verdicts, and the residual then
    reports flows without the enrichment.
    """
    store = CoverageStore(workspace, target)
    return {
        "source-inventory": store.read_records("source-inventory"),
        "entry-index": store.read_records("entry-index"),
        "sink-index": store.read_records("sink-index"),
        "security-control-index": store.read_records("security-control-index"),
        "flow-index": store.read_records("flow-index"),
        "candidate-coverage": store.read_records("candidate-coverage"),
        control_map.CONTROL_MAP_INDEX: store.read(control_map.CONTROL_MAP_INDEX) or {},
        differential_analysis.DIFFERENTIAL_INDEX:
            store.read(differential_analysis.DIFFERENTIAL_INDEX) or {},
    }


def refresh_candidate_coverage(store: CoverageStore,
                               workspace, target: str,
                               round_no: Optional[int] = None,
                               extra_rows: Optional[Sequence[Dict[str, Any]]] = None,
                               ) -> Dict[str, Any]:
    """Re-derive candidate coverage from the round ledgers, then recompute.

    Ledgers are the durable record of what was decided (``ledger/<target>/
    round-NN/ledger.json``); coverage is derived from them so the two can never
    disagree about what a candidate touched.

    ``round_no`` is a *high-water mark*, not a filter: passing ``N`` reads every
    round up to and including ``N``, and ``None`` reads all of them.  Coverage
    accumulates, so an equality filter here silently dropped every earlier
    round's verdicts -- and with them the only reason a scheduler would pass a
    round number at all.  The symptom was a round whose candidates came back
    byte-identical to the previous round's, with nothing flagged as already
    covered.

    ``extra_rows`` lets S8 derive its closure state from the verdicts it has
    just produced *before* the durable ledger is written.  They are treated as
    an in-memory overlay for the current round, never as a substitute for a
    ledger.  This prevents an S8 report from claiming closure based on a stale
    coverage summary while retaining the ledger as the authoritative record.
    """
    import json as _json

    ledger_root = (workspace / "ledger" / target)
    rows_by_identity: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def add_row(row: Dict[str, Any], number: int) -> None:
        """Keep one deterministic verdict per round/candidate identity.

        Modern ledgers contain ``rows`` and an ``excluded`` view derived from
        those rows.  Reading both used to duplicate coverage evidence.  An
        explicit current-round row should additionally supersede an already
        persisted row with the same identity, which makes retries idempotent.
        """
        item = dict(row)
        item.setdefault("_round", number)
        candidate = str(item.get("candidate_id") or item.get("research_key")
                        or item.get("id") or "")
        if not candidate:
            candidate = _json.dumps(item, ensure_ascii=False, sort_keys=True,
                                    default=str)
        identity = (str(item.get("_round") or number), candidate)
        rows_by_identity[identity] = item

    if ledger_root.exists():
        for path in sorted(ledger_root.glob("round-*/ledger.json")):
            try:
                payload = _json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            number = int(payload.get("round") or 0)
            if round_no is not None and number > int(round_no):
                continue
            # ``excluded`` is a legacy fallback / presentation subset.  A
            # modern ledger's ``rows`` already contains its decisions.
            ledger_rows = payload.get("rows")
            if not isinstance(ledger_rows, list):
                ledger_rows = payload.get("excluded") or []
            for row in ledger_rows:
                if isinstance(row, dict):
                    add_row(row, number)
    overlay_round = int(round_no) if round_no is not None else 0
    for row in extra_rows or []:
        if isinstance(row, dict):
            add_row(row, overlay_round)

    rows = [rows_by_identity[key] for key in sorted(rows_by_identity)]
    indices = load_coverage_inputs(workspace, target)
    records = build_candidate_coverage(rows, indices)
    store.write_records("candidate-coverage", records)
    marks = apply_candidate_coverage(indices, [r.as_dict() for r in records])
    for name, key in (("entry-index", "entry-index"), ("sink-index", "sink-index"),
                      ("security-control-index", "security-control-index"),
                      ("flow-index", "flow-index")):
        store.write(name, indices.get(key) or [])
    inventory_summary = store.read("inventory-summary") or {}
    scope = (inventory_summary.get("scope") if isinstance(inventory_summary, dict)
             else None)
    if not isinstance(scope, dict):
        # ``compute_coverage`` remains usable as a pure function in unit tests,
        # but a persisted coverage report without an inventory contract must
        # never announce closure merely because its denominators are empty.
        scope = {
            "schema_version": "coverage-scope-v1",
            "scope_id": "",
            "valid": False,
            "analysis_gaps": ["inventory-scope-missing"],
            "claim_status": "not-a-finding",
        }
    summary = compute_coverage(indices, scope=scope)
    store.write("coverage-summary", summary)
    store.write_records("uncovered-regions", [models.UncoveredRegion.from_dict(r)
                                              for r in summary["uncovered_regions"]])
    return {"candidates": len(records), "marks": marks,
            "high_risk_uncovered": summary["high_risk_uncovered"],
            "coverage": summary["metrics"],
            "audit_status": summary["audit_status"],
            "stop_condition_met": summary["stop_condition_met"]}
