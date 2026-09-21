"""Bounded transform / validator-result binding evidence.

The existing semantic layers can tell us that a validation or sanitization
control is present on an Entry -> Sink path and that it is lexically before
the sink.  An experienced reviewer immediately asks one more question:

    did the value returned by that control become the value consumed by the
    dangerous operation, or was it discarded / overwritten / never resolved?

This module answers only that narrow source-local question.  It uses a small
bounded call/assignment/alias walk over the control and sink lines; it is not a
type system, SSA engine, complete CFG, or sanitizer-semantics proof.  Every
row and generated lead remains ``claim_status=not-a-finding``.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from . import controls as control_rules


SEMANTIC_TRANSFORM_INDEX = "semantic-transform-evidence"
SEMANTIC_TRANSFORM_CANDIDATE_INDEX = "semantic-transform-candidates"
SEMANTIC_TRANSFORM_VERSION = "semantic-transform-evidence-v1"
CLAIM_STATUS = "not-a-finding"
CONFIDENCE = "heuristic-nearby"
EVIDENCE_TYPE = "static-inferred"

# These are the controls whose result can be data-bearing or whose predicate
# decides whether the sink receives the original value.  Authentication and
# rate limiting are intentionally excluded: their semantics are important, but
# they are not value transforms in this bounded layer.
TRANSFORM_CATEGORIES = frozenset({
    "validation", "sanitization", "allowlist", "length-limit", "depth-limit",
    "path-check", "origin-check", "signature-check", "csrf",
})
PREDICATE_CATEGORIES = frozenset({
    "validation", "allowlist", "length-limit", "depth-limit", "path-check",
    "origin-check", "signature-check", "csrf",
})
VALUE_CATEGORIES = frozenset({"sanitization"})

_IDENTIFIER = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b")
_CALL = re.compile(
    r"(?<![\w$])(?P<name>[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\(")
_ASSIGNMENT = re.compile(
    r"(?<![=!<>])(?P<lhs>[A-Za-z_$][A-Za-z0-9_$]*)\s*(?::=|=(?!=))\s*(?P<rhs>[^;]+)"
)
_CONDITION = re.compile(r"^\s*(?:if|elif|unless|when|while|case|guard)\b|\?\s*$",
                        re.IGNORECASE)
_QUOTED = re.compile(r"(['\"])(?:\\.|(?!\1).)*\1")
_LINE_COMMENT = re.compile(r"//.*$|#.*$")
_NOISE = frozenset({
    "and", "as", "async", "await", "bool", "boolean", "break", "case",
    "catch", "char", "const", "continue", "def", "do", "else", "elif",
    "false", "final", "finally", "float", "for", "from", "if", "in",
    "int", "is", "let", "long", "new", "nil", "none", "null", "or",
    "private", "protected", "public", "raise", "return", "static", "string",
    "this", "throw", "true", "try", "var", "void", "when", "while",
})

_LIMITATIONS = (
    "call and assignment binding is bounded lexical evidence, not typed data-flow or SSA",
    "a transform name does not prove sanitizer, validator, parser or canonicalization semantics",
    "branch dominance, short-circuiting, exceptions, loops, overloads and aliasing beyond the bounded window remain unresolved",
    "cross-symbol, callback, DI, reflection, virtual-dispatch and framework-interceptor effects are not modeled",
    "not-bound, discarded and overwritten relations are manual review leads, never proof of a vulnerability or proof of safety",
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


def _text(value: Any, limit: int = 160) -> str:
    return " ".join(str(value or "").replace("\x00", "").split())[:limit]


def _digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")[:12000]).hexdigest()


def _stable_id(prefix: str, *parts: Any) -> str:
    return "%s-%s" % (prefix, _digest([str(part or "") for part in parts])[:12])


def _strip_code(line: Any) -> str:
    text = _QUOTED.sub(" ", str(line or ""))
    return _LINE_COMMENT.sub("", text)


def _identifiers(value: Any) -> Set[str]:
    return {token for token in _IDENTIFIER.findall(str(value or ""))
            if token.lower() not in _NOISE}


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


def _balanced_close(text: str, opening: int) -> int:
    depth = 0
    quote = ""
    escaped = False
    for index in range(opening, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in "'\"`":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _call_names(control: Mapping[str, Any]) -> Set[str]:
    names: Set[str] = set()
    for key in ("api", "control_type", "category"):
        value = str(control.get(key) or "")
        for match in _IDENTIFIER.findall(value):
            lowered = match.lower()
            if lowered not in _NOISE and len(lowered) > 2:
                names.add(lowered)
    # The category itself is often the only stable spelling for a generic
    # control.  Keep both the API leaf and the normalized category.
    category = control_rules.normalize_category(control.get("category"))
    if category:
        names.add(category.lower())
    return names


def _call_info(text: str, names: Set[str]) -> Optional[Dict[str, Any]]:
    masked = _strip_code(text)
    for match in _CALL.finditer(masked):
        leaf = match.group("name").rsplit(".", 1)[-1].lower()
        if leaf not in names and match.group("name").lower() not in names:
            continue
        opening = masked.find("(", match.start(), match.end())
        closing = _balanced_close(text, opening)
        if opening < 0 or closing < 0:
            return {
                "status": "unresolved",
                "name": leaf,
                "arguments": [],
            }
        arguments = text[opening + 1:closing]
        return {
            "status": "resolved",
            "name": leaf,
            "arguments": sorted(_identifiers(arguments)),
        }
    return None


def _assignment_parts(line: str) -> List[Tuple[str, Set[str], str]]:
    rows: List[Tuple[str, Set[str], str]] = []
    for match in _ASSIGNMENT.finditer(_strip_code(line)):
        lhs = match.group("lhs")
        rhs = match.group("rhs")
        rows.append((lhs, _identifiers(rhs), rhs))
    return rows


def _line(lines: Sequence[str], number: int) -> str:
    return lines[number - 1] if 0 < number <= len(lines) else ""


def _is_condition(line: str) -> bool:
    code = _strip_code(line).strip()
    if _CONDITION.search(code):
        return True
    return bool(re.search(r"\b(?:if|unless|when|while)\s*\(", code,
                          re.IGNORECASE))


def _locations(*values: Tuple[Any, Any]) -> List[str]:
    output: List[str] = []
    for file_name, line in values:
        if file_name:
            location = "%s:%d" % (str(file_name), _int(line))
            if location not in output:
                output.append(location)
    return output


def _required_categories(flow: Mapping[str, Any]) -> Set[str]:
    categories: Set[str] = set()
    for group in flow.get("required_groups") or []:
        for category in group.get("required") or []:
            categories.add(control_rules.normalize_category(category))
    return categories


def _trace_binding(root: Path, flow: Mapping[str, Any],
                   control: Mapping[str, Any],
                   line_cache: Dict[str, Optional[List[str]]]
                   ) -> Dict[str, Any]:
    control_file = str(control.get("file") or "")
    sink = dict(flow.get("sink") or {})
    sink_file = str(sink.get("file") or "")
    control_line = _int(control.get("line"))
    sink_line = _int(sink.get("line"))
    base: Dict[str, Any] = {
        "control_id": str(control.get("control_id") or ""),
        "category": control_rules.normalize_category(control.get("category")),
        "control_type": _text(control.get("control_type"), 80),
        "api": _text(control.get("api"), 100),
        "file": control_file,
        "line": control_line,
        "symbol_id": str(control.get("symbol_id") or ""),
        "alignment": str(control.get("alignment") or ""),
        "scope": str(control.get("scope") or "unknown"),
        "relation": "unresolved",
        "transform_variables": [],
        "input_variables": [],
        "sink_variables": [],
        "overwritten_variables": [],
        "raw_variables_after_transform": [],
        "parser": "bounded-lexical",
        "requires_manual_dataflow": True,
        "required_manual_checks": [
            "verify the control API contract and whether it returns, mutates or only checks",
            "verify the transformed value dominates the sink on every reachable path",
            "verify aliases, type conversions, exceptions and framework-level filters",
        ],
        "claim_status": CLAIM_STATUS,
        "producer": "semantic-transforms",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
    }
    if (not control_file or not sink_file or control_file != sink_file
            or not control.get("symbol_id")
            or str(control.get("symbol_id")) != str(flow.get("sink_symbol") or "")):
        base["relation"] = "cross-symbol-unresolved"
        return base
    if control_line <= 0 or sink_line <= 0:
        return base
    if control_line > sink_line:
        base["relation"] = "after-sink"
        return base

    lines = _read_lines(root, control_file, line_cache)
    if not lines:
        base["relation"] = "transform-unresolved"
        return base
    code = _strip_code(_line(lines, control_line))
    names = _call_names(control)
    window = "\n".join(lines[control_line - 1:min(len(lines), control_line + 7)])
    call = _call_info(window, names)
    if call is None:
        base["relation"] = "transform-unresolved"
        return base
    if call.get("status") != "resolved":
        base["relation"] = "transform-unresolved"
        return base
    input_variables = sorted(set(call.get("arguments") or []))
    base["input_variables"] = input_variables[:16]

    sink_line_text = _strip_code(_line(lines, sink_line))
    sink_api = str(sink.get("api") or "").rsplit(".", 1)[-1]
    sink_has_call = bool(sink_api and re.search(
        r"\b%s\s*\(" % re.escape(sink_api), sink_line_text))
    # ``sink(sanitize(value))`` is the clearest source-local binding, even if
    # the control record was attributed to an earlier nearby line.
    sink_call = _call_info(sink_line_text, names)
    if sink_call is not None and sink_has_call:
        bound_variables = sorted(
            set(input_variables) & set(sink_call.get("arguments") or []))
        # The presence of the same sanitizer name at the sink is not enough:
        # ``sanitize(value); sink(sanitize(other))`` must not be reported as a
        # binding of ``value``.  Keep the relation unresolved/discarded unless
        # the nested call actually carries the control's input variable.
        if bound_variables:
            base["relation"] = "direct-bound"
            base["sink_variables"] = bound_variables[:16]
            return base

    assignments = _assignment_parts(code)
    transform_variables: List[str] = []
    for lhs, rhs_ids, rhs_text in assignments:
        if call.get("name") and re.search(
                r"\b%s\s*\(" % re.escape(str(call["name"])), rhs_text,
                re.IGNORECASE):
            transform_variables.append(lhs)
    transform_variables = sorted(set(transform_variables))
    base["transform_variables"] = transform_variables[:16]

    active: Set[str] = set(transform_variables)
    overwritten: Set[str] = set()
    raw_after_transform: Set[str] = set()
    source_variables = set(input_variables)
    # A short one-hop alias walk is enough to distinguish ``safe = clean(x);"
    # ``cmd = safe; sink(cmd)`` from ``safe = clean(x); safe = x; sink(safe)``.
    for number in range(control_line + 1, min(len(lines), sink_line) + 1):
        for lhs, rhs_ids, _rhs_text in _assignment_parts(_line(lines, number)):
            rhs_active = rhs_ids & active
            rhs_raw = rhs_ids & (raw_after_transform | source_variables)
            if lhs in active:
                if rhs_active and not rhs_raw:
                    continue
                active.discard(lhs)
                overwritten.add(lhs)
                raw_after_transform.add(lhs)
            elif rhs_active and not rhs_raw:
                active.add(lhs)
                raw_after_transform.discard(lhs)
            elif rhs_raw:
                # An alias created after the transformed value was replaced
                # carries the raw value forward.  Keep it separate from the
                # active transformed set so ``safe=value; cmd=safe; sink(cmd)``
                # stays an explicit overwritten-value lead.
                active.discard(lhs)
                raw_after_transform.add(lhs)

    sink_variables = sorted(
        _identifiers(sink_line_text) & (active | raw_after_transform))
    base["sink_variables"] = sink_variables[:16]
    base["overwritten_variables"] = sorted(overwritten)[:16]
    base["raw_variables_after_transform"] = sorted(raw_after_transform)[:16]

    if _is_condition(code):
        base["relation"] = "guard-condition"
    elif transform_variables:
        if overwritten and set(sink_variables) & overwritten:
            base["relation"] = "overwritten-after-transform"
        elif set(sink_variables) & active:
            base["relation"] = "assignment-bound"
        elif set(sink_variables) & (source_variables | raw_after_transform):
            if set(sink_variables) & raw_after_transform:
                base["relation"] = "overwritten-after-transform"
            else:
                base["relation"] = "not-bound"
        else:
            base["relation"] = "transform-result-discarded"
    else:
        category = str(base.get("category") or "")
        if _is_condition(code):
            base["relation"] = "guard-condition"
        elif category in PREDICATE_CATEGORIES:
            base["relation"] = "validator-result-discarded"
        else:
            base["relation"] = "transform-result-discarded"
    return base


def _candidate(flow: Mapping[str, Any], transform: Mapping[str, Any]
               ) -> Dict[str, Any]:
    relation = str(transform.get("relation") or "unresolved")
    flow_id = str(flow.get("flow_id") or "")
    control_id = str(transform.get("control_id") or "")
    category = str(transform.get("category") or "logic")
    sink = dict(flow.get("sink") or {})
    sink_category = str(sink.get("category") or "sink")
    if category in control_rules.AUTHZ_CATEGORIES:
        candidate_category = "authz"
    elif sink_category == "command-exec":
        candidate_category = "exec"
    else:
        candidate_category = "logic"
    if relation in {"validator-result-discarded", "transform-result-discarded"}:
        hypothesis = "校验/清洗调用的返回结果看似未绑定到 sink 使用的值；需人工验证该 API 是否原地修改或由外部拦截器保证"
    elif relation == "overwritten-after-transform":
        hypothesis = "变换后的变量在 sink 前可能被原始值覆盖；需人工验证覆盖分支与真实数据流"
    elif relation == "not-bound":
        hypothesis = "变换结果与 sink 使用的变量未闭合绑定；需人工验证是否存在别名、类型转换或框架层保护"
    else:
        hypothesis = "控制调用与 sink 的变换结果关系未被有限分析解析；需人工补充类型和运行时语义"
    entry = dict(flow.get("entry") or {})
    locations = _locations(
        (entry.get("file"), entry.get("line")),
        (transform.get("file"), transform.get("line")),
        (sink.get("file"), sink.get("line")),
    )
    return {
        "candidate_id": _stable_id("xform", flow_id, control_id, relation),
        "surface": "semantic-transform-gap",
        "entry": str(entry.get("api") or entry.get("entry_id") or ""),
        "input_shape": str(entry.get("input_shape") or "unknown"),
        "logic": "transform-binding: %s" % relation,
        "hypothesis": hypothesis,
        "precondition_tier_hint": "app-cooperation"
        if relation in {"cross-symbol-unresolved", "transform-unresolved"}
        else "single-feature",
        "preconditions": [
            "需确认入口在目标默认配置下可达且 sink 确实消费该输入",
            "需确认控制 API 的真实返回/原地修改/异常语义",
            "需补充分支、类型、别名和框架拦截器证据",
        ],
        "poc_class": control_rules.poc_class_for(
            _stable_id("xform", flow_id, control_id, relation)),
        "jvm": {},
        "target_classes": [],
        "authz_cases": control_rules.authz_cases_for()
        if candidate_category == "authz" else [],
        "chain_components": ["request-input", candidate_category, sink_category],
        "novelty_keywords": sorted({"semantic-transform-gap", category,
                                     relation, sink_category}),
        "code_location": locations,
        "category": candidate_category,
        "flow_id": flow_id,
        "entry_id": str(flow.get("entry_id") or ""),
        "sink_id": str(flow.get("sink_id") or ""),
        "control_id": control_id,
        "path": list(flow.get("path") or []),
        "transform_category": category,
        "transform_relation": relation,
        "transform_variables": list(transform.get("transform_variables") or []),
        "input_variables": list(transform.get("input_variables") or []),
        "sink_variables": list(transform.get("sink_variables") or []),
        "requires_manual_dataflow": True,
        "source": "semantic-transforms",
        "producer": "semantic-transforms",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "claim_status": CLAIM_STATUS,
    }


def build_semantic_transform_evidence(
        root: Path, semantic_evidence: Mapping[str, Any]) -> Dict[str, Any]:
    """Build bounded transform-result binding evidence from semantic paths."""
    root = Path(root).resolve()
    line_cache: Dict[str, Optional[List[str]]] = {}
    flow_rows: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    relation_counts: Counter = Counter()
    verdict_counts: Counter = Counter()
    gap_flows = 0

    source_flows = semantic_evidence.get("flows") or [] \
        if isinstance(semantic_evidence, Mapping) else []
    for flow in sorted(source_flows,
                       key=lambda item: str(item.get("flow_id") or "")):
        required = _required_categories(flow)
        transforms: List[Dict[str, Any]] = []
        for control in flow.get("controls") or []:
            category = control_rules.normalize_category(control.get("category"))
            if category not in TRANSFORM_CATEGORIES:
                continue
            transform = _trace_binding(root, flow, dict(control), line_cache)
            transform["required_category"] = category in required
            transforms.append(transform)
            relation_counts[str(transform.get("relation") or "unresolved")] += 1

        gaps = [item for item in transforms if item.get("relation") in {
            "after-sink", "cross-symbol-unresolved", "transform-unresolved",
            "validator-result-discarded", "transform-result-discarded",
            "overwritten-after-transform", "not-bound",
        }]
        if not transforms:
            verdict = "not-applicable"
        elif gaps and any(item.get("relation") in {"assignment-bound",
                                                     "direct-bound",
                                                     "guard-condition"}
                          for item in transforms):
            verdict = "partially-bound"
        elif gaps:
            verdict = "unresolved"
        elif all(item.get("relation") in {"assignment-bound", "direct-bound",
                                           "guard-condition"}
                 for item in transforms):
            verdict = "bound"
        else:
            verdict = "unresolved"
        verdict_counts[verdict] += 1
        if gaps:
            gap_flows += 1

        row = {
            "flow_id": str(flow.get("flow_id") or ""),
            "entry_id": str(flow.get("entry_id") or ""),
            "sink_id": str(flow.get("sink_id") or ""),
            "source_symbol": str(flow.get("source_symbol") or ""),
            "sink_symbol": str(flow.get("sink_symbol") or ""),
            "path": list(flow.get("path") or []),
            "entry": dict(flow.get("entry") or {}),
            "sink": dict(flow.get("sink") or {}),
            "static_control_verdict": str(flow.get("static_control_verdict") or ""),
            "required_groups": list(flow.get("required_groups") or []),
            "transforms": transforms,
            "semantic_transform_verdict": verdict,
            "required_manual_checks": [
                "verify the control API contract and whether it returns, mutates or only checks",
                "verify the transformed value dominates the sink on every reachable path",
                "verify aliases, type conversions, exceptions and framework-level filters",
            ],
            "claim_status": CLAIM_STATUS,
            "producer": "semantic-transforms",
            "confidence": CONFIDENCE,
            "evidence_type": EVIDENCE_TYPE,
        }
        flow_rows.append(row)

        static_verdict = str(flow.get("static_control_verdict") or "")
        if static_verdict in (control_rules.VERDICT_GUARDED,
                              control_rules.VERDICT_PARTIAL):
            for transform in gaps:
                if transform.get("required_category"):
                    candidates.append(_candidate(flow, transform))

    candidates.sort(key=lambda item: (str(item.get("flow_id") or ""),
                                     str(item.get("control_id") or ""),
                                     str(item.get("candidate_id") or "")))
    summary = {
        "flows": len(flow_rows),
        "controls": sum(len(row.get("transforms") or []) for row in flow_rows),
        "relation_counts": dict(sorted(relation_counts.items())),
        "verdicts": dict(sorted(verdict_counts.items())),
        "flows_with_binding_gaps": gap_flows,
        "candidates": len(candidates),
        "claim_status": CLAIM_STATUS,
        "producer": "semantic-transforms",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "limitations": list(_LIMITATIONS),
    }
    return {
        "schema_version": SEMANTIC_TRANSFORM_VERSION,
        "summary": summary,
        "flows": flow_rows,
        "candidates": candidates,
        "claim_status": CLAIM_STATUS,
        "producer": "semantic-transforms",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "limitations": list(_LIMITATIONS),
    }


def load_semantic_transform_evidence(store: Any) -> Dict[str, Any]:
    data = store.read(SEMANTIC_TRANSFORM_INDEX)
    return data if isinstance(data, dict) else {}


def load_semantic_transform_candidates(store: Any) -> List[Dict[str, Any]]:
    data = store.read(SEMANTIC_TRANSFORM_CANDIDATE_INDEX)
    return [item for item in data if isinstance(item, dict)] \
        if isinstance(data, list) else []


def render_semantic_transforms_text(evidence: Mapping[str, Any], lang: str = "zh",
                                    limit: int = 20) -> str:
    summary = dict(evidence.get("summary") or {}) \
        if isinstance(evidence, Mapping) else {}
    candidates = list(evidence.get("candidates") or []) \
        if isinstance(evidence, Mapping) else []
    if lang == "en":
        lines = ["Semantic transform binding evidence (static research leads)",
                 "─" * 56,
                 "  flows %s  controls %s  binding gaps %s  candidates %s" % (
                     summary.get("flows", 0), summary.get("controls", 0),
                     summary.get("flows_with_binding_gaps", 0),
                     summary.get("candidates", 0)),
                 "  relations %s" % (summary.get("relation_counts") or {}),
                 "  verdicts %s" % (summary.get("verdicts") or {}),
                 "  leads:"]
    else:
        lines = ["语义变换绑定证据（静态研究线索）", "─" * 56,
                 "  路径 %s  控制 %s  绑定缺口 %s  候选 %s" % (
                     summary.get("flows", 0), summary.get("controls", 0),
                     summary.get("flows_with_binding_gaps", 0),
                     summary.get("candidates", 0)),
                 "  关系 %s" % (summary.get("relation_counts") or {}),
                 "  判定 %s" % (summary.get("verdicts") or {}),
                 "  待验证线索："]
    for candidate in candidates[:max(0, limit)]:
        lines.append("    %-22s %-30s %s" % (
            candidate.get("candidate_id", ""),
            candidate.get("transform_relation", ""),
            ",".join(candidate.get("code_location") or []) or "-"))
    if len(candidates) > limit:
        lines.append("    ... %d more" % (len(candidates) - limit))
    return "\n".join(lines)
