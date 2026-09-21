"""Bounded control-flow relation evidence for semantic security guards.

The semantic path and guard layers deliberately stop short of claiming that a
check dominates a dangerous sink.  This module adds a small, deterministic
structural bridge for the most useful review question: does the sink appear in
the guarded branch, after a terminating rejection branch, or on an alternate
branch such as ``else``/``except``?

It is intentionally not a parser or a full CFG.  It uses bounded brace /
indent intervals and branch groups, keeps only locations and normalized branch
metadata, and leaves loops, short-circuit semantics, exceptions, dispatch,
macros and path feasibility unresolved.  Every row and candidate remains a
static research lead with ``claim_status=not-a-finding``.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from . import controls as control_rules
from . import semantic_paths as semantic


SEMANTIC_CONTROLFLOW_INDEX = "semantic-controlflow-evidence"
SEMANTIC_CONTROLFLOW_CANDIDATE_INDEX = "semantic-controlflow-candidates"
SEMANTIC_CONTROLFLOW_VERSION = "semantic-controlflow-evidence-v1"
CLAIM_STATUS = "not-a-finding"
CONFIDENCE = "heuristic-nearby"
EVIDENCE_TYPE = "static-inferred"

_BRANCH_HEADER = re.compile(
    r"^(?:if|elif|else\s+if|unless|when|switch|case|catch|except|try|finally|else)\b",
    re.IGNORECASE,
)
_TERMINATOR = re.compile(
    r"\b(?:return|throw|raise|abort|exit|break|continue)\b",
    re.IGNORECASE,
)
_NEGATIVE = re.compile(
    r"(?:\bnot\b|!\s*(?:[A-Za-z_$][\w$]*\s*\()?)",
    re.IGNORECASE,
)
_INDENT_SUFFIXES = frozenset({".py", ".pyw", ".rb"})
_ALTERNATE_KINDS = frozenset({"elif", "else", "except", "finally", "case"})
_CONDITION_KINDS = frozenset({"if", "elif", "unless", "when"})
_CANDIDATE_RELATIONS = frozenset({
    "alternate-path-likely",
    "same-block-unverified",
    "path-unresolved",
    "cross-symbol-unverified",
})

_LIMITATIONS = (
    "branch intervals are bounded brace/indent evidence and do not implement a complete CFG or dominance algorithm",
    "alternate-branch detection does not model short-circuit conditions, loops, exceptions, macros, fallthrough or path feasibility",
    "a likely dominating guard does not prove return/throw semantics, subject identity, sanitizer behavior or authorization correctness",
    "cross-symbol, callback, virtual-dispatch, DI and reflection control flow remains unresolved",
    "all relations and candidates are static review leads, never proof of a vulnerability or proof of safety",
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


def _read_lines(root: Path, file_name: Any,
                cache: Dict[str, Optional[List[str]]]) -> List[str]:
    name = str(file_name or "")
    if name in cache:
        return cache[name] or []
    path = Path(name)
    if not path.is_absolute():
        path = root / path
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, UnicodeError):
        lines = None
    cache[name] = lines
    return lines or []


def _line(lines: Sequence[str], number: int) -> str:
    return lines[number - 1] if 0 < number <= len(lines) else ""


def _indent(text: str) -> int:
    return len(text) - len(text.lstrip(" \t"))


def _suffix(file_name: Any) -> str:
    return Path(str(file_name or "")).suffix.lower()


def _header_kind(line: str) -> str:
    """Return a normalized branch keyword for a declaration-shaped line."""
    code = semantic._strip_code(line).strip()
    # A closing brace may precede ``else``/``catch`` on the same line.
    code = code.lstrip("}").lstrip()
    match = _BRANCH_HEADER.match(code)
    if not match:
        return ""
    kind = match.group(0).lower().replace("else if", "elif")
    return kind.split()[0]


def _next_nonempty(lines: Sequence[str], start: int) -> int:
    for number in range(max(1, start), len(lines) + 1):
        if semantic._strip_code(_line(lines, number)).strip():
            return number
    return 0


def _inline_body(line: str, kind: str) -> bool:
    """Whether a branch carries a one-line body after its condition."""
    code = semantic._strip_code(line).strip()
    if kind in {"else", "try", "finally"}:
        colon = code.find(":")
        if colon >= 0:
            return bool(code[colon + 1:].strip())
        marker = kind
    else:
        marker = ":"
    if marker == ":":
        position = code.find(":")
        return position >= 0 and bool(code[position + 1:].strip())
    position = code.find(marker)
    if position < 0:
        return False
    tail = code[position + len(marker):].strip()
    if tail.startswith("if "):
        return False
    return bool(tail and tail not in {"{"})


def _brace_body_end(lines: Sequence[str], header_line: int,
                    kind: str) -> Tuple[int, int]:
    """Return ``(body_start, body_end)`` for a bounded brace branch."""
    header_code = semantic._strip_code(_line(lines, header_line))
    if _inline_body(_line(lines, header_line), kind):
        return header_line, header_line

    opened = False
    depth = 0
    open_line = 0
    limit = min(len(lines), header_line + 2000)
    for number in range(header_line, limit + 1):
        code = semantic._strip_code(_line(lines, number))
        if not opened:
            position = code.find("{")
            if position < 0:
                continue
            opened = True
            open_line = number
            suffix = code[position:]
            depth = suffix.count("{") - suffix.count("}")
        else:
            depth += code.count("{") - code.count("}")
        if opened and depth <= 0:
            return (open_line if open_line == header_line else open_line + 1,
                    number)

    # Braceless C-like one-line control.  It is evidence of a possible body,
    # not a claim that the language's grammar accepts the construct.
    body = _next_nonempty(lines, header_line + 1)
    return (body, body) if body else (header_line, header_line)


def _indent_body_end(lines: Sequence[str], header_line: int,
                     kind: str) -> Tuple[int, int]:
    """Return ``(body_start, body_end)`` for Python/Ruby-style blocks."""
    text = _line(lines, header_line)
    base = _indent(text)
    if _inline_body(text, kind):
        return header_line, header_line
    body = _next_nonempty(lines, header_line + 1)
    if not body:
        return header_line, header_line
    if _indent(_line(lines, body)) <= base:
        return header_line, header_line
    end = body
    for number in range(body + 1, min(len(lines), header_line + 2000) + 1):
        current = _line(lines, number)
        if not current.strip() or current.lstrip().startswith("#"):
            continue
        if _indent(current) <= base:
            break
        end = number
    return body, end


def _stable(value: str, prefix: str, length: int = 12) -> str:
    return "%s-%s" % (prefix, hashlib.sha256(value.encode("utf-8")).hexdigest()[:length])


def _branch_regions(file_name: str, lines: Sequence[str]
                    ) -> List[Dict[str, Any]]:
    """Extract bounded branch intervals and group alternate siblings."""
    scope = semantic._scope_keys(lines)
    suffix = _suffix(file_name)
    indent_style = suffix in _INDENT_SUFFIXES
    headers: List[Dict[str, Any]] = []
    for number, raw in enumerate(lines, 1):
        kind = _header_kind(raw)
        if not kind:
            continue
        body_start, body_end = (
            _indent_body_end(lines, number, kind)
            if indent_style else _brace_body_end(lines, number, kind)
        )
        depth, source_indent = scope.get(number, (0, _indent(raw)))
        headers.append({
            "header_line": number,
            "kind": kind,
            "body_start": body_start,
            "body_end": max(body_start, body_end),
            "depth": depth,
            "indent": source_indent,
        })

    previous: Dict[Tuple[int, int], Dict[str, Any]] = {}
    regions: List[Dict[str, Any]] = []
    for header in headers:
        context = (int(header["depth"]), int(header["indent"]))
        kind = str(header["kind"])
        previous_header = previous.get(context)
        if kind in _ALTERNATE_KINDS and previous_header is not None:
            group_id = str(previous_header["group_id"])
        else:
            group_id = _stable(
                "%s|%s|%s|%s" % (file_name, context[0], context[1],
                                  header["header_line"]), "branch-group")
        branch_id = _stable(
            "%s|%s|%s" % (file_name, kind, header["header_line"]), "branch")
        region = dict(header)
        region.update({
            "group_id": group_id,
            "branch_id": branch_id,
            "role": "alternate" if kind in _ALTERNATE_KINDS else "primary",
        })
        regions.append(region)
        header["group_id"] = group_id
        previous[context] = header
    return regions


def _active_regions(regions: Sequence[Mapping[str, Any]], line: int
                    ) -> List[Dict[str, Any]]:
    active = [dict(region) for region in regions
              if _int(region.get("body_start")) <= line <= _int(region.get("body_end"))]
    return sorted(active, key=lambda item: (
        _int(item.get("body_start")), -_int(item.get("body_end"))))


def _header_region(regions: Sequence[Mapping[str, Any]], line: int
                   ) -> Optional[Dict[str, Any]]:
    for region in regions:
        if _int(region.get("header_line")) == line:
            return dict(region)
    return None


def _deepest(regions: Sequence[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    if not regions:
        return None
    return dict(sorted(regions, key=lambda item: (
        _int(item.get("body_start")), -_int(item.get("body_end"))),
                      reverse=True)[0])


def _public_region(region: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    if not region:
        return {}
    return {
        "branch_id": str(region.get("branch_id") or ""),
        "group_id": str(region.get("group_id") or ""),
        "kind": str(region.get("kind") or ""),
        "role": str(region.get("role") or ""),
        "header_line": _int(region.get("header_line")),
        "body_start": _int(region.get("body_start")),
        "body_end": _int(region.get("body_end")),
    }


def _terminator_in(lines: Sequence[str], region: Mapping[str, Any],
                   control_line: int, sink_line: int) -> bool:
    start = max(_int(region.get("body_start")), control_line)
    end = min(_int(region.get("body_end")), sink_line - 1)
    if start <= 0 or end < start:
        return False
    for number in range(start, end + 1):
        if _TERMINATOR.search(semantic._strip_code(_line(lines, number))):
            return True
    return False


def _negative_header(lines: Sequence[str], line: int) -> bool:
    return bool(_NEGATIVE.search(semantic._strip_code(_line(lines, line))))


def _same_scope(scope: Mapping[int, Tuple[int, int]], first: int,
                second: int) -> bool:
    left = scope.get(first)
    right = scope.get(second)
    return bool(left is not None and left == right)


def _relation(guard: Mapping[str, Any], sink: Mapping[str, Any],
              lines: Sequence[str], regions: Sequence[Mapping[str, Any]],
              scope: Mapping[int, Tuple[int, int]]) -> Dict[str, Any]:
    control_file = str(guard.get("file") or "")
    sink_file = str(sink.get("file") or "")
    control_symbol = str(guard.get("symbol_id") or "")
    sink_symbol = str(sink.get("symbol_id") or "")
    control_line = _int(guard.get("line"))
    sink_line = _int(sink.get("line"))
    base = {
        "control_id": str(guard.get("control_id") or ""),
        "control_line": control_line,
        "sink_line": sink_line,
        "control_branch": {},
        "sink_branch": {},
        "alternate_branch_count": 0,
        "alternate_path_status": "unresolved",
        "dominance": "unverified",
    }
    if not control_file or not sink_file or control_file != sink_file \
            or not control_symbol or control_symbol != sink_symbol:
        base.update({
            "relation": "cross-symbol-unverified",
            "alternate_path_status": "unresolved",
        })
        return base
    if control_line <= 0 or sink_line <= 0:
        base["relation"] = "unresolved"
        return base
    if control_line == sink_line:
        base.update({"relation": "same-line", "alternate_path_status": "unknown"})
        return base
    if control_line > sink_line:
        base.update({"relation": "after-sink", "alternate_path_status": "unknown"})
        return base

    control_header = _header_region(regions, control_line)
    control_active = _active_regions(regions, control_line)
    sink_active = _active_regions(regions, sink_line)
    control_branch = control_header or _deepest(control_active)
    sink_branch = _deepest(sink_active)
    base["control_branch"] = _public_region(control_branch)
    base["sink_branch"] = _public_region(sink_branch)

    if control_branch:
        siblings = [region for region in regions
                    if str(region.get("group_id") or "")
                    == str(control_branch.get("group_id") or "")
                    and str(region.get("branch_id") or "")
                    != str(control_branch.get("branch_id") or "")
                    and _int(region.get("body_start")) <= sink_line
                    <= _int(region.get("body_end"))]
        base["alternate_branch_count"] = len(siblings)
        if siblings:
            base.update({
                "relation": "alternate-path-likely",
                "alternate_path_status": "present",
                "dominance": "alternate-path",
            })
            return base

        inside_control_branch = (
            _int(control_branch.get("body_start")) <= sink_line
            <= _int(control_branch.get("body_end")))
        if inside_control_branch:
            base.update({
                "relation": "enclosing-branch-likely",
                "alternate_path_status": "present"
                if any(str(region.get("group_id") or "")
                       == str(control_branch.get("group_id") or "")
                       and str(region.get("branch_id") or "")
                       != str(control_branch.get("branch_id") or "")
                       for region in regions) else "none",
                "dominance": "dominates-likely",
            })
            return base

        if (str(control_branch.get("kind") or "") in _CONDITION_KINDS
                and _negative_header(lines, control_line)
                and _terminator_in(lines, control_branch, control_line, sink_line)):
            base.update({
                "relation": "terminating-guard-likely",
                "alternate_path_status": "none",
                "dominance": "dominates-likely",
            })
            return base

    if _same_scope(scope, control_line, sink_line):
        base.update({
            "relation": "same-block-unverified",
            "alternate_path_status": "unknown",
        })
        return base
    if control_active and any(
            str(control.get("branch_id") or "")
            == str(sink.get("branch_id") or "")
            for control in control_active for sink in sink_active):
        base.update({
            "relation": "enclosing-branch-likely",
            "alternate_path_status": "unknown",
            "dominance": "dominates-likely",
        })
        return base
    base["relation"] = "path-unresolved"
    return base


def _location(file_name: Any, line: Any) -> str:
    return "%s:%d" % (str(file_name or ""), _int(line)) if file_name else ""


def _candidate(flow: Mapping[str, Any], guard: Mapping[str, Any],
               relation: Mapping[str, Any]) -> Dict[str, Any]:
    flow_id = str(flow.get("flow_id") or "")
    control_id = str(guard.get("control_id") or "")
    relation_name = str(relation.get("relation") or "unresolved")
    candidate_id = _stable(
        "%s|%s|%s" % (flow_id, control_id, relation_name), "cfg", 14)
    entry = flow.get("entry") or {}
    sink = flow.get("sink") or {}
    sink_category = str(sink.get("category") or "sink")
    category = "authz" if guard.get("category") in control_rules.AUTHZ_CATEGORIES \
        else "logic"
    locations: List[str] = []
    for location in (
            _location(entry.get("file"), entry.get("line")),
            _location(sink.get("file"), sink.get("line")),
            _location(guard.get("file"), guard.get("line"))):
        if location and location not in locations:
            locations.append(location)
    return {
        "candidate_id": candidate_id,
        "surface": "semantic-controlflow-gap",
        "entry": str(entry.get("api") or entry.get("entry_id") or ""),
        "input_shape": str(entry.get("input_shape") or "unknown"),
        "logic": "control-flow: %s" % relation_name,
        "hypothesis": "安全控制与 sink 的结构化控制流关系未闭合，可能存在 alternate path 或未验证的执行路径；需人工补充 CFG 与运行时证据",
        "precondition_tier_hint": "app-cooperation"
        if relation_name == "cross-symbol-unverified" else "single-feature",
        "preconditions": [
            "需确认控制与 sink 属于同一真实符号、分支和调用目标",
            "需验证返回、异常、循环、短路和 fallthrough 语义",
        ],
        "poc_class": control_rules.poc_class_for(candidate_id),
        "jvm": {},
        "target_classes": [],
        "authz_cases": control_rules.authz_cases_for()
        if category == "authz" else [],
        "chain_components": ["request-input", category, sink_category],
        "novelty_keywords": sorted({"semantic-controlflow-gap", category,
                                     relation_name, sink_category}),
        "code_location": locations,
        "category": category,
        "flow_id": flow_id,
        "entry_id": str(flow.get("entry_id") or ""),
        "sink_id": str(flow.get("sink_id") or ""),
        "control_id": control_id,
        "path": list(flow.get("path") or []),
        "branch_relation": relation_name,
        "dominance": str(relation.get("dominance") or "unverified"),
        "alternate_path_status": str(
            relation.get("alternate_path_status") or "unresolved"),
        "alternate_branch_count": _int(relation.get("alternate_branch_count")),
        "control_branch_kind": str(
            (relation.get("control_branch") or {}).get("kind") or ""),
        "sink_branch_kind": str(
            (relation.get("sink_branch") or {}).get("kind") or ""),
        "requires_manual_dataflow": True,
        "source": "semantic-controlflow",
        "producer": "semantic-controlflow",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "claim_status": CLAIM_STATUS,
    }


def build_semantic_controlflow_evidence(
        root: Path, semantic_guard_evidence: Mapping[str, Any]
        ) -> Dict[str, Any]:
    """Build bounded branch relation evidence from semantic guard rows."""
    root = Path(root).resolve()
    line_cache: Dict[str, Optional[List[str]]] = {}
    region_cache: Dict[str, List[Dict[str, Any]]] = {}
    scope_cache: Dict[str, Dict[int, Tuple[int, int]]] = {}
    flow_rows: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    relation_counts: Counter = Counter()
    branch_counts: Counter = Counter()
    flow_alternate = 0
    flow_dominance = 0

    flows = semantic_guard_evidence.get("flows") or [] \
        if isinstance(semantic_guard_evidence, Mapping) else []
    for flow in sorted(flows, key=lambda item: str(item.get("flow_id") or "")):
        sink = dict(flow.get("sink") or {})
        if not sink.get("symbol_id"):
            path = list(flow.get("path") or [])
            sink["symbol_id"] = str(
                flow.get("sink_symbol") or (path[-1] if path else ""))
        controls: List[Dict[str, Any]] = []
        alternate_for_flow = False
        dominance_for_flow = False
        for guard in flow.get("guards") or []:
            guard = dict(guard)
            file_name = str(guard.get("file") or sink.get("file") or "")
            lines = _read_lines(root, file_name, line_cache)
            if file_name not in region_cache:
                region_cache[file_name] = _branch_regions(file_name, lines)
                scope_cache[file_name] = semantic._scope_keys(lines)
            relation = _relation(
                guard, sink, lines, region_cache[file_name],
                scope_cache.get(file_name, {}))
            row = dict(guard)
            row.update({
                "control_flow": relation,
                "claim_status": CLAIM_STATUS,
                "producer": "semantic-controlflow",
                "confidence": CONFIDENCE,
                "evidence_type": EVIDENCE_TYPE,
            })
            controls.append(row)
            relation_name = str(relation.get("relation") or "unresolved")
            relation_counts[relation_name] += 1
            branch_kind = str(
                (relation.get("control_branch") or {}).get("kind") or "none")
            branch_counts[branch_kind] += 1
            if relation_name == "alternate-path-likely":
                alternate_for_flow = True
            if relation.get("dominance") == "dominates-likely":
                dominance_for_flow = True

            static_verdict = str(flow.get("static_control_verdict") or "")
            if (relation_name in _CANDIDATE_RELATIONS
                    and static_verdict in (control_rules.VERDICT_GUARDED,
                                           control_rules.VERDICT_PARTIAL)
                    and guard.get("required_category")):
                candidates.append(_candidate(flow, guard, relation))

        if alternate_for_flow:
            flow_alternate += 1
        if dominance_for_flow:
            flow_dominance += 1
        flow_rows.append({
            "flow_id": str(flow.get("flow_id") or ""),
            "entry_id": str(flow.get("entry_id") or ""),
            "sink_id": str(flow.get("sink_id") or ""),
            "source_symbol": str(flow.get("source_symbol") or ""),
            "sink_symbol": str(flow.get("sink_symbol") or ""),
            "path": list(flow.get("path") or []),
            "entry": dict(flow.get("entry") or {}),
            "sink": sink,
            "static_control_verdict": str(
                flow.get("static_control_verdict") or ""),
            "controls": controls,
            "alternate_path": alternate_for_flow,
            "dominance_likely": dominance_for_flow,
            "required_manual_checks": [
                "verify the real CFG, alternate branches, exceptions, loops and fallthrough",
                "verify guard return/throw semantics and whether the sink is reachable on every path",
                "verify subject/object/tenant binding separately from structural branch relation",
            ],
            "claim_status": CLAIM_STATUS,
            "producer": "semantic-controlflow",
            "confidence": CONFIDENCE,
            "evidence_type": EVIDENCE_TYPE,
        })

    candidates.sort(key=lambda item: (
        str(item.get("flow_id") or ""),
        str(item.get("control_id") or ""),
        str(item.get("candidate_id") or "")))
    summary = {
        "flows": len(flow_rows),
        "controls": sum(len(row.get("controls") or []) for row in flow_rows),
        "flows_with_alternate_paths": flow_alternate,
        "flows_with_dominance_likely": flow_dominance,
        "relations": dict(sorted(relation_counts.items())),
        "branch_kinds": dict(sorted(branch_counts.items())),
        "candidates": len(candidates),
        "claim_status": CLAIM_STATUS,
        "producer": "semantic-controlflow",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "limitations": list(_LIMITATIONS),
    }
    return {
        "schema_version": SEMANTIC_CONTROLFLOW_VERSION,
        "summary": summary,
        "flows": flow_rows,
        "candidates": candidates,
        "claim_status": CLAIM_STATUS,
        "producer": "semantic-controlflow",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "limitations": list(_LIMITATIONS),
    }


def load_semantic_controlflow(store: Any) -> Dict[str, Any]:
    data = store.read(SEMANTIC_CONTROLFLOW_INDEX)
    return data if isinstance(data, dict) else {}


def load_semantic_controlflow_candidates(store: Any) -> List[Dict[str, Any]]:
    data = store.read(SEMANTIC_CONTROLFLOW_CANDIDATE_INDEX)
    return [item for item in data if isinstance(item, dict)] \
        if isinstance(data, list) else []


def render_semantic_controlflow_text(evidence: Mapping[str, Any],
                                     lang: str = "zh", limit: int = 20) -> str:
    summary = dict(evidence.get("summary") or {}) \
        if isinstance(evidence, Mapping) else {}
    candidates = list(evidence.get("candidates") or []) \
        if isinstance(evidence, Mapping) else []
    if lang == "en":
        lines = [
            "Semantic control-flow evidence (dominance / alternate paths)",
            "─" * 62,
            "  flows %s  controls %s  alternate %s  dominance-likely %s  candidates %s"
            % (summary.get("flows", 0), summary.get("controls", 0),
               summary.get("flows_with_alternate_paths", 0),
               summary.get("flows_with_dominance_likely", 0),
               summary.get("candidates", 0)),
            "  relations %s" % (summary.get("relations") or {}),
            "  leads:",
        ]
    else:
        lines = [
            "语义控制流证据（分支支配 / alternate path）", "─" * 62,
            "  路径 %s  控制 %s  备用分支 %s  可能支配 %s  候选 %s" % (
                summary.get("flows", 0), summary.get("controls", 0),
                summary.get("flows_with_alternate_paths", 0),
                summary.get("flows_with_dominance_likely", 0),
                summary.get("candidates", 0)),
            "  关系 %s" % (summary.get("relations") or {}),
            "  待验证线索：",
        ]
    for candidate in candidates[:max(0, limit)]:
        lines.append("    %-22s %-28s %s" % (
            candidate.get("candidate_id", ""),
            candidate.get("branch_relation", ""),
            ",".join(candidate.get("code_location") or []) or "-"))
    if len(candidates) > limit:
        lines.append("    ... %d more" % (len(candidates) - limit))
    return "\n".join(lines)
