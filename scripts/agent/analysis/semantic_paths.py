"""Bounded semantic evidence for Entry -> Sink paths.

The call graph and control map deliberately stop at *membership*: a control
being reachable on a path does not prove that it dominates the sink, protects
the same subject, or even runs before the dangerous operation.  This module
adds a deterministic, source-local evidence layer for the two questions that
are cheap to answer without pretending to be a compiler:

* does a path control occur before the sink in the same lexical scope; and
* when entry and sink share one symbol, does a bounded identifier/alias walk
  connect a parameter to the sink argument?

It is intentionally conservative.  Cross-symbol data flow, virtual dispatch,
DI, reflection, callbacks and branch dominance remain unresolved.  Every
artifact and generated lead is therefore ``claim_status=not-a-finding`` with
``confidence=heuristic-nearby`` and ``evidence_type=static-inferred``.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from . import controls as control_rules


SEMANTIC_PATH_INDEX = "semantic-path-evidence"
SEMANTIC_CANDIDATE_INDEX = "semantic-path-candidates"
SEMANTIC_PATH_VERSION = "semantic-path-evidence-v1"
CLAIM_STATUS = "not-a-finding"
CONFIDENCE = "heuristic-nearby"
EVIDENCE_TYPE = "static-inferred"

_IDENTIFIER = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b")
_ASSIGNMENT = re.compile(
    r"(?P<lhs>[A-Za-z_$][A-Za-z0-9_$]*)\s*(?::=|=(?!=))\s*(?P<rhs>[^;]+)"
)
_PARAM_DECL = re.compile(
    r"\b(?:def|function|fun|proc|sub)\s+[A-Za-z_$][\w$]*\s*\((?P<args>[^)]*)\)"
)
_GENERIC_DECL = re.compile(
    r"\b[A-Za-z_$][\w$<>?,.\[\]]*\s+[A-Za-z_$][\w$]*\s*"
    r"\((?P<args>[^)]*)\)"
)
_QUOTED = re.compile(r"(['\"])(?:\\.|(?!\1).)*\1")
_LINE_COMMENT = re.compile(r"//.*$|#.*$")

_NON_DATA_IDENTIFIERS = frozenset({
    "if", "else", "elif", "for", "while", "return", "throw", "new",
    "try", "catch", "finally", "switch", "case", "break", "continue",
    "true", "false", "null", "none", "nil", "this", "self", "super",
    "public", "private", "protected", "static", "final", "const", "let",
    "var", "def", "function", "class", "void", "int", "long", "short",
    "byte", "char", "float", "double", "boolean", "string", "stringview",
    "async", "await", "in", "is", "as", "from", "import", "using",
})

_LIMITATIONS = (
    "same-symbol identifier tracking is not a typed or interprocedural data-flow proof",
    "cross-symbol flows remain unresolved because virtual dispatch, DI, reflection and callbacks are not modeled",
    "lexical order is not branch dominance: a control may protect a different branch or subject",
    "absence of a parameter-to-sink token match is an evidence gap, never evidence of safety",
)


def _field(record: Any, name: str, default: Any = None) -> Any:
    if isinstance(record, dict):
        return record.get(name, default)
    return getattr(record, name, default)


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _text(value: Any, limit: int = 180) -> str:
    return " ".join(str(value or "").replace("\x00", "").split())[:limit]


def _digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")[:12000]).hexdigest()


def _stable_id(prefix: str, *parts: Any) -> str:
    return "%s-%s" % (prefix, _digest([str(part or "") for part in parts])[:12])


def _identifiers(value: Any) -> Set[str]:
    return {token for token in _IDENTIFIER.findall(str(value or ""))
            if token.lower() not in _NON_DATA_IDENTIFIERS}


def _strip_code(line: str) -> str:
    # This is only for scope/alias heuristics.  It is deliberately not a
    # language parser and does not get persisted as source evidence.
    value = _QUOTED.sub(" ", str(line or ""))
    return _LINE_COMMENT.sub("", value)


def _read_lines(root: Path, rel: str, cache: Dict[str, Optional[List[str]]]
                ) -> List[str]:
    key = str(rel or "")
    if key in cache:
        return cache[key] or []
    path = Path(key)
    if not path.is_absolute():
        path = root / path
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, UnicodeError):
        lines = None
    cache[key] = lines
    return lines or []


def _symbol_index(symbols: Sequence[Any]) -> Dict[str, Any]:
    return {str(_field(symbol, "symbol_id", "") or ""): symbol
            for symbol in symbols
            if str(_field(symbol, "symbol_id", "") or "")}


def _index_by(records: Iterable[Any], key: str) -> Dict[str, Any]:
    output: Dict[str, Any] = {}
    for record in records:
        value = str(_field(record, key, "") or "")
        if value and value not in output:
            output[value] = record
    return output


def _normalise_parameter(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    text = text.split("=", 1)[0].strip().replace("...", "")
    names = _IDENTIFIER.findall(text)
    for name in reversed(names):
        if name.lower() not in _NON_DATA_IDENTIFIERS:
            return name
    return ""


def _parameters(symbol: Any, lines: Sequence[str]) -> List[str]:
    # The inventory creates a synthetic file symbol for module-scope code.  A
    # generic ``name(...)`` regex over that file would mistake prose, comments,
    # or unrelated calls for a function signature.
    if str(_field(symbol, "kind", "") or "") == "file":
        return []
    declared = [_normalise_parameter(item)
                for item in (_field(symbol, "parameters", []) or [])]
    declared = [item for item in declared if item]
    if declared:
        return sorted(set(declared))
    start = max(1, _int(_field(symbol, "start_line", 1)))
    end = min(len(lines), start + 4)
    header = " ".join(lines[start - 1:end])
    match = _PARAM_DECL.search(header) or _GENERIC_DECL.search(header)
    if not match:
        return []
    args = match.group("args") or ""
    found = []
    for item in args.split(","):
        name = _normalise_parameter(item)
        if name and name not in {"self", "this"}:
            found.append(name)
    return sorted(set(found))


def _scope_keys(lines: Sequence[str]) -> Dict[int, Tuple[int, int]]:
    """Return a bounded brace/indent scope key for 1-based source lines."""
    result: Dict[int, Tuple[int, int]] = {}
    brace_depth = 0
    for number, line in enumerate(lines, 1):
        code = _strip_code(line)
        indent = len(line) - len(line.lstrip(" \t"))
        result[number] = (brace_depth, indent)
        brace_depth = max(0, brace_depth + code.count("{") - code.count("}"))
    return result


def _scope_relation(scope: Mapping[int, Tuple[int, int]], first: int,
                    second: int) -> str:
    if first <= 0 or second <= 0:
        return "unknown"
    left = scope.get(first)
    right = scope.get(second)
    if left is None or right is None:
        return "unknown"
    if left == right:
        return "same-lexical-block"
    if left[0] <= right[0] and left[1] <= right[1]:
        return "enclosing-block"
    if left[0] >= right[0] and left[1] >= right[1]:
        return "nested-block"
    return "different-block"


def _control_alignment(control: Any, sink: Any,
                       sink_symbol_id: str,
                       scope_cache: Dict[str, Dict[int, Tuple[int, int]]],
                       root: Path, line_cache: Dict[str, Optional[List[str]]]
                       ) -> Dict[str, Any]:
    control_symbol = str(_field(control, "symbol_id", "") or "")
    control_file = str(_field(control, "file", "") or "")
    sink_file = str(_field(sink, "file", "") or "")
    control_line = _int(_field(control, "line", 0))
    sink_line = _int(_field(sink, "line", 0))
    category = control_rules.normalize_category(_field(control, "category", ""))
    row: Dict[str, Any] = {
        "control_id": str(_field(control, "control_id", "") or ""),
        "category": category,
        "control_type": _text(_field(control, "control_type", ""), 80),
        "api": _text(_field(control, "api", ""), 100),
        "file": control_file,
        "line": control_line,
        "symbol_id": control_symbol,
        "claim_status": CLAIM_STATUS,
        "producer": "semantic-paths",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
    }
    if not control_symbol or control_symbol != sink_symbol_id or control_file != sink_file:
        row.update({"alignment": "cross-symbol-unverified", "scope": "unknown"})
        return row
    if control_line < sink_line:
        alignment = "before-sink"
    elif control_line > sink_line:
        alignment = "after-sink"
    else:
        alignment = "same-line"
    if control_file not in scope_cache:
        scope_cache[control_file] = _scope_keys(
            _read_lines(root, control_file, line_cache))
    row.update({
        "alignment": alignment,
        "scope": _scope_relation(scope_cache[control_file], control_line, sink_line),
    })
    return row


def _taint_evidence(root: Path, symbol: Any, sink: Any,
                    line_cache: Dict[str, Optional[List[str]]]) -> Dict[str, Any]:
    symbol_id = str(_field(symbol, "symbol_id", "") or "")
    sink_symbol_id = str(_field(sink, "symbol_id", "") or "")
    sink_file = str(_field(sink, "file", "") or "")
    sink_line = _int(_field(sink, "line", 0))
    same_symbol = bool(symbol_id and symbol_id == sink_symbol_id)
    result: Dict[str, Any] = {
        "status": "not-traced",
        "source_symbol": symbol_id,
        "sink_symbol": sink_symbol_id,
        "parameters": [],
        "sink_variables": [],
        "alias_variables": [],
        "claim_status": CLAIM_STATUS,
        "producer": "semantic-paths",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
    }
    if not same_symbol:
        result["status"] = "cross-symbol-unresolved"
        result["manual_checks"] = [
            "trace arguments and return values across the call edge",
            "resolve virtual dispatch/DI/reflection/callback targets",
        ]
        return result
    lines = _read_lines(root, sink_file, line_cache)
    params = _parameters(symbol, lines)
    result["parameters"] = params
    if not params or sink_line <= 0:
        result["manual_checks"] = [
            "recover the source parameter and sink argument types",
            "trace aliases and sanitizer semantics manually",
        ]
        return result
    start = max(1, _int(_field(symbol, "start_line", 1)))
    end = min(len(lines), sink_line)
    active: Set[str] = set(params)
    aliases: Set[str] = set()
    for line in lines[start - 1:end]:
        code = _strip_code(line)
        for match in _ASSIGNMENT.finditer(code):
            rhs = _identifiers(match.group("rhs"))
            if rhs & active:
                lhs = match.group("lhs")
                if lhs not in _NON_DATA_IDENTIFIERS:
                    active.add(lhs)
                    if lhs not in params:
                        aliases.add(lhs)
    sink_text = ""
    if 0 < sink_line <= len(lines):
        sink_text = lines[sink_line - 1]
    sink_text = "%s %s" % (sink_text, _field(sink, "text", "") or "")
    sink_variables = sorted(_identifiers(sink_text) & active)
    result["sink_variables"] = sink_variables
    result["alias_variables"] = sorted(aliases)
    if set(sink_variables) & set(params):
        result["status"] = "direct"
    elif set(sink_variables) & aliases:
        result["status"] = "propagated"
    else:
        result["status"] = "not-traced"
    result["manual_checks"] = [
        "verify the sink argument is the externally controlled value, not a coincidental token",
        "verify sanitizer/normalizer semantics and branch dominance",
    ]
    return result


def _control_map_entry(control_map: Any, flow_id: str) -> Any:
    if not control_map:
        return None
    entries = control_map.get("entries") if isinstance(control_map, dict) \
        else getattr(control_map, "entries", [])
    for entry in entries or []:
        if str(_field(entry, "flow_id", "") or "") == flow_id:
            return entry
    return None


def _group_evidence(groups: Sequence[Sequence[str]], controls: Sequence[Dict[str, Any]]
                    ) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    aligned_scopes = {"same-lexical-block", "enclosing-block"}
    for group in groups:
        required = sorted(set(str(item) for item in group if item))
        matching = [row for row in controls if row.get("category") in required]
        aligned = [row for row in matching
                   if row.get("alignment") == "before-sink"
                   and row.get("scope") in aligned_scopes]
        order_unknown = [row for row in matching if not aligned]
        if aligned:
            state = "aligned"
        elif matching:
            state = "order-unverified"
        else:
            state = "missing"
        rows.append({
            "required": required,
            "state": state,
            "control_ids": sorted(str(row.get("control_id") or "")
                                   for row in matching if row.get("control_id")),
            "aligned_control_ids": sorted(str(row.get("control_id") or "")
                                           for row in aligned if row.get("control_id")),
            "order_unverified_control_ids": sorted(
                str(row.get("control_id") or "") for row in order_unknown
                if row.get("control_id")),
            "claim_status": CLAIM_STATUS,
            "producer": "semantic-paths",
            "confidence": CONFIDENCE,
            "evidence_type": EVIDENCE_TYPE,
        })
    return rows


def _semantic_verdict(groups: Sequence[Dict[str, Any]]) -> str:
    if not groups:
        return "not-applicable"
    states = [str(group.get("state") or "missing") for group in groups]
    if all(state == "aligned" for state in states):
        return "aligned"
    if any(state == "aligned" for state in states):
        return "partially-aligned"
    if any(state == "order-unverified" for state in states):
        return "order-unverified"
    return "no-aligned-control"


def _location(file_name: Any, line: Any) -> str:
    return "%s:%d" % (str(file_name or ""), _int(line)) if file_name else ""


def _candidate(entry: Any, sink: Any, flow: Any, row: Dict[str, Any],
               group: Optional[Dict[str, Any]], taint: Dict[str, Any]
               ) -> Dict[str, Any]:
    flow_id = str(_field(flow, "flow_id", "") or "")
    sink_id = str(_field(sink, "sink_id", "") or "")
    if group is not None:
        required = list(group.get("required") or [])
        kind = "semantic-control-order"
        surface = "control-order-unverified"
        detail = "|".join(required)
        missing_text = ",".join(required) or "required-control"
        hypothesis = ("静态控制图显示路径上存在 %s，但未证明其在 sink 前、同一语义块并支配该操作"
                      % missing_text)
        logic = "control-order: %s" % ("|".join(required) or "unknown")
        category = ("authz" if any(control_rules.family_of(item) == "authz"
                                   for item in required) else "logic")
        tier = "app-cooperation" if any(
            control.get("alignment") == "cross-symbol-unverified"
            for control in row.get("controls") or []) else "single-feature"
        preconditions = [
            "需确认该静态路径在目标默认配置下确有路由暴露",
            "需人工验证控制的 branch dominance、subject binding 与调用实现",
        ]
        authz_cases = control_rules.authz_cases_for() if category == "authz" else []
    else:
        kind = "semantic-dataflow-gap"
        surface = "semantic-dataflow-gap"
        detail = taint.get("status", "not-traced")
        hypothesis = "入口参数与危险 sink 的同符号数据流未被有限别名追踪闭合"
        logic = "dataflow: %s" % detail
        category = "exec" if str(_field(sink, "category", "")) == "command-exec" else "logic"
        tier = "single-feature"
        preconditions = [
            "需人工确认入口参数可由攻击者控制并到达 sink",
            "需补充类型、变换语义和运行时 typed-effect 证据",
        ]
        authz_cases = []
    candidate_id = _stable_id("sem", kind, flow_id, detail)
    code_locations = []
    entry_file = _field(entry, "file", "") if entry is not None else ""
    entry_line = _field(entry, "line", 0) if entry is not None else 0
    sink_file = _field(sink, "file", "")
    sink_line = _field(sink, "line", 0)
    for location in (_location(entry_file, entry_line), _location(sink_file, sink_line)):
        if location and location not in code_locations:
            code_locations.append(location)
    for control in row.get("controls") or []:
        if control.get("control_id") and control.get("alignment") != "before-sink":
            location = _location(control.get("file"), control.get("line"))
            if location and location not in code_locations:
                code_locations.append(location)
    entry_name = ""
    if entry is not None:
        entry_name = str(_field(entry, "api", "") or
                         _field(entry, "entry_id", "") or "")
    return {
        "candidate_id": candidate_id,
        "surface": surface,
        "entry": entry_name,
        "input_shape": _field(entry, "input_shape", "unknown") if entry else "unknown",
        "logic": logic,
        "hypothesis": hypothesis,
        "precondition_tier_hint": tier,
        "preconditions": preconditions,
        "poc_class": control_rules.poc_class_for(candidate_id),
        "jvm": {},
        "target_classes": [],
        "authz_cases": authz_cases,
        "chain_components": ["request-input", category,
                             str(_field(sink, "category", "sink") or "sink")],
        "novelty_keywords": sorted(set([surface, kind, category,
                                          str(_field(sink, "category", "sink") or "sink")])),
        "code_location": code_locations,
        "category": category,
        "flow_id": flow_id,
        "entry_id": str(_field(flow, "entry_id", "") or ""),
        "sink_id": sink_id,
        "path": list(_field(flow, "path", []) or []),
        "semantic_verdict": row.get("semantic_verdict", ""),
        "taint_status": taint.get("status", "not-traced"),
        "required_group": list(group.get("required") or []) if group else [],
        "control_order": [
            {"control_id": control.get("control_id"),
             "alignment": control.get("alignment"),
             "scope": control.get("scope")}
            for control in row.get("controls") or []
        ],
        "requires_manual_dataflow": True,
        "source": "semantic-paths",
        "producer": "semantic-paths",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "claim_status": CLAIM_STATUS,
    }


def build_semantic_path_evidence(
        root: Path, entries: Sequence[Any], sinks: Sequence[Any],
        flows: Sequence[Any], controls: Sequence[Any], symbols: Sequence[Any],
        control_map: Any = None) -> Dict[str, Any]:
    """Build deterministic, bounded semantic evidence for every persisted flow."""
    root = Path(root).resolve()
    entry_index = _index_by(entries, "entry_id")
    sink_index = _index_by(sinks, "sink_id")
    symbol_index = _symbol_index(symbols)
    controls_by_symbol: Dict[str, List[Any]] = {}
    for control in controls:
        symbol_id = str(_field(control, "symbol_id", "") or "")
        if symbol_id:
            controls_by_symbol.setdefault(symbol_id, []).append(control)
    for rows in controls_by_symbol.values():
        rows.sort(key=lambda item: (_int(_field(item, "line", 0)),
                                   str(_field(item, "control_id", "") or "")))

    line_cache: Dict[str, Optional[List[str]]] = {}
    scope_cache: Dict[str, Dict[int, Tuple[int, int]]] = {}
    evidence_rows: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    status_counts: Counter = Counter()
    verdict_counts: Counter = Counter()
    alignment_counts: Counter = Counter()

    for flow in sorted(flows, key=lambda item: str(_field(item, "flow_id", "") or "")):
        flow_id = str(_field(flow, "flow_id", "") or "")
        entry = entry_index.get(str(_field(flow, "entry_id", "") or ""))
        sink = sink_index.get(str(_field(flow, "sink_id", "") or ""))
        path = [str(item) for item in (_field(flow, "path", []) or [])]
        source_symbol_id = str(_field(flow, "source_symbol", "") or "")
        sink_symbol_id = str(_field(sink, "symbol_id", "") or "") if sink else ""
        source_symbol = symbol_index.get(source_symbol_id)
        same_symbol = bool(source_symbol_id and source_symbol_id == sink_symbol_id)
        taint = _taint_evidence(root, source_symbol, sink, line_cache) \
            if source_symbol is not None and sink is not None else {
                "status": "not-traced", "source_symbol": source_symbol_id,
                "sink_symbol": sink_symbol_id, "parameters": [],
                "sink_variables": [], "alias_variables": [],
                "manual_checks": ["recover missing source or sink symbol metadata"],
                "claim_status": CLAIM_STATUS, "producer": "semantic-paths",
                "confidence": CONFIDENCE, "evidence_type": EVIDENCE_TYPE,
            }
        status_counts[taint.get("status", "not-traced")] += 1

        path_controls = []
        for symbol_id in path:
            path_controls.extend(controls_by_symbol.get(symbol_id, ()))
        control_rows = [
            _control_alignment(control, sink, sink_symbol_id, scope_cache, root, line_cache)
            for control in path_controls if sink is not None
        ]
        for control in control_rows:
            alignment_counts[control.get("alignment", "unknown")] += 1
        cmap_entry = _control_map_entry(control_map, flow_id)
        static_groups = (_field(cmap_entry, "required_groups", []) or []) if cmap_entry else []
        group_rows = _group_evidence(static_groups, control_rows)
        semantic_verdict = _semantic_verdict(group_rows)
        verdict_counts[semantic_verdict] += 1
        row: Dict[str, Any] = {
            "flow_id": flow_id,
            "entry_id": str(_field(flow, "entry_id", "") or ""),
            "sink_id": str(_field(flow, "sink_id", "") or ""),
            "source_symbol": source_symbol_id,
            "sink_symbol": sink_symbol_id,
            "same_symbol": same_symbol,
            "path": path,
            "direction": str(_field(flow, "direction", "") or ""),
            "priority": str(_field(flow, "priority", "") or ""),
            "entry": {
                "entry_id": str(_field(entry, "entry_id", "") or "") if entry else "",
                "kind": str(_field(entry, "kind", "") or "") if entry else "",
                "api": _text(_field(entry, "api", ""), 100) if entry else "",
                "input_shape": _text(_field(entry, "input_shape", "unknown"), 120) if entry else "unknown",
                "file": str(_field(entry, "file", "") or "") if entry else "",
                "line": _int(_field(entry, "line", 0)) if entry else 0,
            },
            "sink": {
                "sink_id": str(_field(sink, "sink_id", "") or "") if sink else "",
                "category": str(_field(sink, "category", "") or "") if sink else "",
                "api": _text(_field(sink, "api", ""), 100) if sink else "",
                "file": str(_field(sink, "file", "") or "") if sink else "",
                "line": _int(_field(sink, "line", 0)) if sink else 0,
                "severity": str(_field(sink, "severity_hint", "medium") or "medium") if sink else "medium",
            },
            "taint": taint,
            "controls": control_rows,
            "required_groups": group_rows,
            "static_control_verdict": str(_field(cmap_entry, "verdict", "") or "") if cmap_entry else "",
            "semantic_verdict": semantic_verdict,
            "required_manual_checks": [
                "verify route exposure and attacker-controlled input",
                "verify branch dominance and subject binding for every control",
            ] + list(taint.get("manual_checks") or []),
            "claim_status": CLAIM_STATUS,
            "producer": "semantic-paths",
            "confidence": CONFIDENCE,
            "evidence_type": EVIDENCE_TYPE,
        }
        evidence_rows.append(row)

        static_verdict = row.get("static_control_verdict")
        if static_verdict in (control_rules.VERDICT_GUARDED,
                              control_rules.VERDICT_PARTIAL):
            for group in group_rows:
                if group.get("state") == "order-unverified":
                    candidates.append(_candidate(entry, sink, flow, row, group, taint))
        if (same_symbol and taint.get("parameters")
                and taint.get("status") == "not-traced"
                and str(_field(sink, "severity_hint", "medium") or "medium") == "high"):
            candidates.append(_candidate(entry, sink, flow, row, None, taint))

    candidates.sort(key=lambda item: (str(item.get("surface", "")),
                                     str(item.get("flow_id", "")),
                                     str(item.get("candidate_id", ""))))
    evidence_rows.sort(key=lambda item: item.get("flow_id", ""))
    summary = {
        "flows": len(evidence_rows),
        "same_symbol_flows": sum(1 for row in evidence_rows if row.get("same_symbol")),
        "cross_symbol_flows": sum(1 for row in evidence_rows if not row.get("same_symbol")),
        "taint_status": dict(sorted(status_counts.items())),
        "semantic_verdicts": dict(sorted(verdict_counts.items())),
        "control_alignment": dict(sorted(alignment_counts.items())),
        "order_gap_flows": sum(1 for row in evidence_rows
                                if row.get("semantic_verdict") in {"order-unverified", "partially-aligned"}),
        "dataflow_gap_flows": sum(1 for row in evidence_rows
                                   if row.get("taint", {}).get("status") == "not-traced"
                                   and row.get("same_symbol")),
        "candidates": len(candidates),
        "claim_status": CLAIM_STATUS,
        "producer": "semantic-paths",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "limitations": list(_LIMITATIONS),
    }
    return {
        "schema_version": SEMANTIC_PATH_VERSION,
        "summary": summary,
        "flows": evidence_rows,
        "candidates": candidates,
        "claim_status": CLAIM_STATUS,
        "producer": "semantic-paths",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "limitations": list(_LIMITATIONS),
    }


def load_semantic_evidence(store: Any) -> Dict[str, Any]:
    data = store.read(SEMANTIC_PATH_INDEX)
    return data if isinstance(data, dict) else {}


def load_semantic_candidates(store: Any) -> List[Dict[str, Any]]:
    data = store.read(SEMANTIC_CANDIDATE_INDEX)
    return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []


def semantic_candidates(evidence: Mapping[str, Any], limit: int = 0
                        ) -> List[Dict[str, Any]]:
    data = evidence.get("candidates") if isinstance(evidence, Mapping) else []
    rows = [item for item in data or [] if isinstance(item, dict)]
    return rows[:limit] if limit and limit > 0 else rows


def render_semantic_paths_text(evidence: Mapping[str, Any], lang: str = "zh",
                               limit: int = 20) -> str:
    summary = dict(evidence.get("summary") or {}) if isinstance(evidence, Mapping) else {}
    rows = list(evidence.get("flows") or []) if isinstance(evidence, Mapping) else []
    candidates = list(evidence.get("candidates") or []) if isinstance(evidence, Mapping) else []
    if lang == "en":
        lines = ["Semantic path evidence (static research leads)", "─" * 52,
                 "  flows %s  same-symbol %s  candidates %s" % (
                     summary.get("flows", 0), summary.get("same_symbol_flows", 0),
                     summary.get("candidates", 0)),
                 "  taint %s" % (summary.get("taint_status") or {}),
                 "  verdicts %s" % (summary.get("semantic_verdicts") or {})]
        title = "  leads:"
    else:
        lines = ["语义路径证据（静态研究线索）", "─" * 52,
                 "  路径 %s  同符号 %s  候选 %s" % (
                     summary.get("flows", 0), summary.get("same_symbol_flows", 0),
                     summary.get("candidates", 0)),
                 "  数据流 %s" % (summary.get("taint_status") or {}),
                 "  判定 %s" % (summary.get("semantic_verdicts") or {})]
        title = "  待验证线索："
    lines.append(title)
    for candidate in candidates[:max(0, limit)]:
        lines.append("    %-22s %-28s %s" % (
            candidate.get("candidate_id", ""), candidate.get("surface", ""),
            ",".join(candidate.get("code_location") or []) or "-"))
    if len(candidates) > limit:
        lines.append("    ... %d more" % (len(candidates) - limit))
    return "\n".join(lines)
