"""Bounded one-hop interprocedural argument/return evidence.

The call graph answers whether a caller and callee are heuristically related;
the semantic path layer answers what happens inside one symbol.  This module
connects those two facts at the smallest useful granularity: for every edge on
an Entry -> Sink flow it extracts the bounded call-site argument positions,
binds them to the callee's parameters when possible, and records whether a
callee return appears to carry a tainted parameter back to the caller.

This is intentionally not a parser, type checker, SSA engine, or CFG.  It
keeps identifiers and locations only, never source prose or payloads, and
leaves all cross-symbol ambiguity as an explicit research lead.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from . import controls as control_rules


SEMANTIC_CALL_INDEX = "semantic-call-evidence"
SEMANTIC_CALL_CANDIDATE_INDEX = "semantic-call-candidates"
SEMANTIC_CALL_VERSION = "semantic-call-evidence-v1"
CLAIM_STATUS = "not-a-finding"
CONFIDENCE = "heuristic-nearby"
EVIDENCE_TYPE = "static-inferred"

_IDENTIFIER = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b")
_PARAM_NOISE = frozenset({
    "and", "as", "async", "bool", "boolean", "byte", "case", "catch",
    "char", "const", "def", "do", "else", "final", "float", "for",
    "func", "if", "in", "int", "let", "long", "map", "mut", "new",
    "private", "protected", "public", "return", "short", "static", "string",
    "struct", "this", "throw", "true", "false", "var", "void", "when",
    "while", "with", "yield",
})
_LITERAL = re.compile(
    r"^(?:[-+]?\d+(?:\.\d+)?|true|false|null|nil|none|undefined|"
    r"[\"'].*[\"']|[\[\]{(].*[\])}])$",
    re.IGNORECASE,
)

_LIMITATIONS = (
    "call-site binding is a bounded lexical extraction and does not prove overload, type, virtual dispatch, DI, reflection, callback or async resolution",
    "argument propagation does not prove that a callee returns, transforms, preserves or uses the bound value on every path",
    "return evidence is a source-shape hint and does not prove dominance, path feasibility or sanitizer semantics",
    "unresolved or not-bound states are manual source-review leads, never proof of a vulnerability or proof of safety",
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


def _tokens(value: Any, limit: int = 16) -> List[str]:
    tokens = {
        token for token in _IDENTIFIER.findall(str(value or ""))
        if token.lower() not in _PARAM_NOISE
    }
    return sorted(tokens, key=lambda token: (token.lower(), token))[:limit]


def _mask(text: str) -> str:
    """Mask strings/comments while preserving punctuation for balancing."""
    result: List[str] = []
    quote = ""
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            result.append(" " if char not in "\n\r" else char)
            index += 1
            continue
        if char in "\"'`":
            quote = char
            result.append(" ")
            index += 1
            continue
        if char == "/" and nxt == "/":
            result.extend(" " for _ in text[index:])
            break
        if char == "#":
            result.extend(" " for _ in text[index:])
            break
        if char == "/" and nxt == "*":
            result.extend("  ")
            index += 2
            while index < len(text):
                if text[index:index + 2] == "*/":
                    result.extend("  ")
                    index += 2
                    break
                result.append("\n" if text[index] == "\n" else " ")
                index += 1
            continue
        result.append(char)
        index += 1
    return "".join(result)


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
    masked = _mask(text)
    for index in range(opening, len(masked)):
        if masked[index] == "(":
            depth += 1
        elif masked[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _split_arguments(text: str) -> List[str]:
    masked = _mask(text)
    pieces: List[str] = []
    start = 0
    depths = {"(": 0, "[": 0, "{": 0, "<": 0}
    pairs = {")": "(", "]": "[", "}": "{", ">": "<",
    }
    for index, char in enumerate(masked):
        if char in depths:
            depths[char] += 1
        elif char in pairs:
            opener = pairs[char]
            if depths[opener] > 0:
                depths[opener] -= 1
        elif char == "," and not any(depths.values()):
            pieces.append(text[start:index].strip())
            start = index + 1
    tail = text[start:].strip()
    if tail or pieces:
        pieces.append(tail)
    return pieces


def _call_arguments(lines: Sequence[str], line_number: int, name: str
                    ) -> Tuple[str, List[str]]:
    if line_number < 1 or line_number > len(lines) or not name:
        return "unresolved", []
    # A short window handles the common multi-line call without turning this
    # evidence layer into an unbounded parser.
    start = line_number - 1
    text = "\n".join(lines[start:min(len(lines), start + 8)])
    masked = _mask(text)
    match = re.search(r"(?<![\w$.])%s\s*\(" % re.escape(name), masked)
    if match is None:
        # Method calls can be preceded by a dot; the resolver records only the
        # callee name, so allow the dot on a second bounded pass.
        match = re.search(r"\b%s\s*\(" % re.escape(name), masked)
    if match is None:
        return "unresolved", []
    opening = masked.find("(", match.start(), match.end())
    closing = _balanced_close(text, opening)
    if opening < 0 or closing < 0:
        return "unresolved", []
    return "resolved", _split_arguments(text[opening + 1:closing])


def _parameter_name(part: str, language: str) -> str:
    masked = _mask(part).strip()
    if not masked:
        return ""
    # Defaults and type annotations are not part of the parameter identity.
    masked = masked.split("=", 1)[0].strip()
    if ":" in masked:
        masked = masked.split(":", 1)[0].strip()
    names = [name for name in _IDENTIFIER.findall(masked)
             if name.lower() not in _PARAM_NOISE]
    if not names:
        return ""
    # Go/Rust generally put the type after the name; Java/C/TS generally put
    # the type before it.  This is a bounded convention, not type inference.
    if str(language or "").lower() in {"go", "rust"}:
        return names[0]
    return names[-1]


def _parameters(root: Path, symbol: Any,
                cache: Dict[str, List[str]],
                line_cache: Dict[str, Optional[List[str]]]) -> List[str]:
    symbol_id = str(_field(symbol, "symbol_id", "") or "")
    if symbol_id in cache:
        return cache[symbol_id]
    declared = [str(item) for item in (_field(symbol, "parameters", []) or [])
                if str(item)]
    if declared:
        cache[symbol_id] = declared[:16]
        return cache[symbol_id]
    lines = _read_lines(root, _field(symbol, "file", ""), line_cache)
    name = str(_field(symbol, "name", "") or "")
    start = max(0, _int(_field(symbol, "start_line", 1)) - 1)
    end = min(len(lines), start + 10)
    pattern = re.compile(r"\b%s\s*\(" % re.escape(name)) if name else None
    found: List[str] = []
    if pattern is not None:
        for index in range(start, end):
            masked = _mask("\n".join(lines[index:end]))
            match = pattern.search(masked)
            if match is None:
                continue
            opening = masked.find("(", match.start(), match.end())
            closing = _balanced_close("\n".join(lines[index:end]), opening)
            if opening < 0 or closing < 0:
                continue
            for part in _split_arguments("\n".join(lines[index:end])
                                        [opening + 1:closing]):
                parameter = _parameter_name(
                    part, str(_field(symbol, "language", "") or ""))
                if parameter:
                    found.append(parameter)
            break
    cache[symbol_id] = found[:16]
    return cache[symbol_id]


def _return_parameters(root: Path, symbol: Any, params: Sequence[str],
                       line_cache: Dict[str, Optional[List[str]]]
                       ) -> Tuple[List[str], int]:
    lines = _read_lines(root, _field(symbol, "file", ""), line_cache)
    start = max(0, _int(_field(symbol, "start_line", 1)) - 1)
    end = min(len(lines), _int(_field(symbol, "end_line", len(lines))))
    returned: Set[str] = set()
    sites = 0
    wanted = set(params)
    for line in lines[start:end]:
        masked = _mask(line)
        if not re.search(r"\breturn\b", masked):
            continue
        sites += 1
        returned.update(token for token in _tokens(masked, 16) if token in wanted)
    return sorted(returned)[:16], sites


def _callsite_result(line: str, name: str) -> Tuple[str, List[str]]:
    masked = _mask(line)
    match = re.search(r"\b%s\s*\(" % re.escape(name), masked) if name else None
    if match is None:
        return "unresolved", []
    prefix = masked[:match.start()].strip()
    if re.match(r"^(?:return|yield)\b", prefix):
        return "returned", []
    if "=" in prefix:
        lhs = prefix.rsplit("=", 1)[0]
        return "assigned", _tokens(lhs)
    return "discarded", []


def _sink_tokens(root: Path, sink: Mapping[str, Any],
                 line_cache: Dict[str, Optional[List[str]]]) -> Tuple[str, List[str]]:
    lines = _read_lines(root, sink.get("file", ""), line_cache)
    line_number = _int(sink.get("line"))
    api = str(sink.get("api") or "")
    name = api.rsplit(".", 1)[-1].rsplit("#", 1)[-1]
    status, args = _call_arguments(lines, line_number, name)
    if status == "resolved":
        return status, sorted(set(token for arg in args for token in _tokens(arg)))[:16]
    line = lines[line_number - 1] if 0 < line_number <= len(lines) else ""
    fallback = _tokens(line)
    if name:
        fallback = [token for token in fallback
                    if token.lower() != name.lower()]
    return "unresolved", fallback[:16]


def _location(file_name: Any, line: Any) -> str:
    return "%s:%d" % (str(file_name or ""), _int(line)) if file_name else ""


def _stable_id(flow_id: str, status: str, steps: Sequence[Mapping[str, Any]]) -> str:
    digest_input = "%s|%s|%s" % (
        flow_id, status,
        "|".join("%s:%s:%s" % (
            step.get("caller_symbol", ""), step.get("callee_symbol", ""),
            step.get("binding_status", "")) for step in steps))
    return "call-%s" % hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:14]


def _candidate(flow: Mapping[str, Any], row: Mapping[str, Any]) -> Dict[str, Any]:
    entry = flow.get("entry") or {}
    sink = flow.get("sink") or {}
    steps = list(row.get("call_steps") or [])
    status = str((row.get("sink_binding") or {}).get("status") or "unresolved")
    candidate_id = _stable_id(str(flow.get("flow_id") or ""), status, steps)
    locations: List[str] = []
    for location in (
        _location(entry.get("file"), entry.get("line")),
        _location(sink.get("file"), sink.get("line")),
        *[_location(step.get("callsite", {}).get("file"),
                    step.get("callsite", {}).get("line")) for step in steps],
    ):
        if location and location not in locations:
            locations.append(location)
    sink_category = str(sink.get("category") or "")
    category = "exec" if sink_category in {
        "command-exec", "code-eval", "expression-eval",
    } else "logic"
    return {
        "candidate_id": candidate_id,
        "surface": "semantic-interprocedural-binding",
        "entry": str(entry.get("api") or entry.get("entry_id") or ""),
        "input_shape": str(entry.get("input_shape") or "unknown"),
        "logic": "interprocedural-binding: %s" % status,
        "hypothesis": "跨符号调用的参数/返回绑定未闭合，入口输入可能未被正确追踪到 sink；需人工补充调用、类型和分支证据",
        "precondition_tier_hint": "app-cooperation" if any(
            step.get("callsite_status") != "resolved" for step in steps
        ) else "single-feature",
        "preconditions": [
            "需确认启发式 call edge 对应真实调用点和 overload/dispatch",
            "需验证 callee 参数、返回值、变换和 sink 操作对象的真实语义",
        ],
        "poc_class": control_rules.poc_class_for(candidate_id),
        "jvm": {},
        "target_classes": [],
        "authz_cases": control_rules.authz_cases_for()
        if category == "authz" else [],
        "chain_components": ["request-input", category, sink_category or "sink"],
        "novelty_keywords": sorted({"semantic-interprocedural-binding", category,
                                     sink_category or "sink"}),
        "code_location": locations,
        "category": category,
        "flow_id": str(flow.get("flow_id") or ""),
        "entry_id": str(flow.get("entry_id") or ""),
        "sink_id": str(flow.get("sink_id") or ""),
        "path": list(flow.get("path") or []),
        "callsite_status": row.get("callsite_status", "unresolved"),
        "binding_status": status,
        "unresolved_steps": row.get("unresolved_steps", 0),
        "requires_manual_dataflow": True,
        "source": "semantic-calls",
        "producer": "semantic-calls",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "claim_status": CLAIM_STATUS,
    }


def build_semantic_call_evidence(
        root: Path, entries: Sequence[Any], sinks: Sequence[Any],
        flows: Sequence[Any], symbols: Sequence[Any],
        call_edges: Sequence[Any]) -> Dict[str, Any]:
    """Build bounded call-site and tainted-parameter evidence for all flows."""
    root = Path(root).resolve()
    symbol_index = {
        str(_field(symbol, "symbol_id", "")): symbol for symbol in symbols
        if _field(symbol, "symbol_id", "")
    }
    entry_index = {
        str(_field(entry, "entry_id", "")): entry for entry in entries
    }
    sink_index = {
        str(_field(sink, "sink_id", "")): sink for sink in sinks
    }
    edge_index: Dict[Tuple[str, str], Any] = {}
    for edge in call_edges:
        key = (str(_field(edge, "caller", "")),
               str(_field(edge, "callee", "")))
        edge_index.setdefault(key, edge)

    line_cache: Dict[str, Optional[List[str]]] = {}
    parameter_cache: Dict[str, List[str]] = {}
    flow_rows: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    callsite_counts: Counter = Counter()
    binding_counts: Counter = Counter()
    return_counts: Counter = Counter()
    sink_counts: Counter = Counter()
    cross_symbol_flows = 0

    ordered_flows = sorted(flows, key=lambda item: str(
        _field(item, "flow_id", "") or ""))
    for flow in ordered_flows:
        flow_id = str(_field(flow, "flow_id", "") or "")
        path = [str(item) for item in (_field(flow, "path", []) or [])]
        entry = entry_index.get(str(_field(flow, "entry_id", "") or ""))
        sink = sink_index.get(str(_field(flow, "sink_id", "") or ""))
        entry_symbol_id = str(_field(flow, "source_symbol", "") or "")
        entry_symbol = symbol_index.get(entry_symbol_id)
        current_taint = set(_parameters(root, entry_symbol, parameter_cache,
                                        line_cache)) if entry_symbol else set()
        call_steps: List[Dict[str, Any]] = []
        unresolved_steps = 0
        if len(path) > 1:
            cross_symbol_flows += 1
        for caller_id, callee_id in zip(path, path[1:]):
            edge = edge_index.get((caller_id, callee_id))
            caller = symbol_index.get(caller_id)
            callee = symbol_index.get(callee_id)
            edge_name = str(_field(edge, "callee_name", "") or "") if edge else ""
            if not edge_name and callee is not None:
                edge_name = str(_field(callee, "name", "") or "")
            edge_file = str(_field(edge, "file", "") or "") if edge else ""
            edge_line = _int(_field(edge, "line", 0)) if edge else 0
            caller_lines = _read_lines(root, edge_file or _field(caller, "file", ""),
                                       line_cache)
            callsite_status, arguments = _call_arguments(
                caller_lines, edge_line, edge_name)
            callsite_counts[callsite_status] += 1
            callee_parameters = _parameters(root, callee, parameter_cache,
                                            line_cache) if callee else []
            caller_parameters = _parameters(root, caller, parameter_cache,
                                            line_cache) if caller else []
            bindings: List[Dict[str, Any]] = []
            callee_taint: Set[str] = set()
            if callsite_status == "resolved":
                for index, parameter in enumerate(callee_parameters):
                    argument = arguments[index] if index < len(arguments) else ""
                    argument_tokens = _tokens(argument)
                    tainted_tokens = sorted(set(argument_tokens) & current_taint)
                    if tainted_tokens:
                        binding_status = "direct" if len(argument_tokens) == 1 else "propagated"
                        callee_taint.add(parameter)
                    elif not argument:
                        binding_status = "unresolved"
                    elif _LITERAL.match(argument.strip()):
                        binding_status = "literal"
                    elif argument_tokens:
                        binding_status = "unresolved"
                    else:
                        binding_status = "unresolved"
                    binding_counts[binding_status] += 1
                    bindings.append({
                        "parameter": parameter,
                        "argument_tokens": argument_tokens[:16],
                        "binding_status": binding_status,
                        "tainted_tokens": tainted_tokens[:16],
                    })
                if len(arguments) != len(callee_parameters):
                    binding_status = "arity-unresolved"
                elif any(item["binding_status"] == "unresolved"
                         for item in bindings):
                    binding_status = "unresolved"
                elif callee_taint:
                    binding_status = "bound"
                else:
                    binding_status = "not-bound"
            else:
                binding_status = "unresolved"
            if binding_status in {"unresolved", "arity-unresolved"}:
                unresolved_steps += 1
            result, target_tokens = _callsite_result(
                caller_lines[edge_line - 1] if 0 < edge_line <= len(caller_lines) else "",
                edge_name)
            returned_parameters, return_sites = (
                _return_parameters(root, callee, callee_parameters, line_cache)
                if callee else ([], 0))
            tainted_returns = sorted(set(returned_parameters) & callee_taint)
            if not returned_parameters:
                return_status = "not-observed"
            elif tainted_returns and result in {"returned", "assigned"}:
                return_status = "tainted-return-likely"
            elif result in {"returned", "assigned"}:
                return_status = "unresolved"
            else:
                return_status = "not-bound"
            return_counts[return_status] += 1
            step = {
                "caller_symbol": caller_id,
                "callee_symbol": callee_id,
                "callsite": {"file": edge_file or str(
                    _field(caller, "file", "") or ""), "line": edge_line},
                "callee_name": edge_name,
                "propagation": str(_field(edge, "propagation", "") or "") if edge else "",
                "callsite_status": callsite_status,
                "caller_parameters": caller_parameters[:16],
                "callee_parameters": callee_parameters[:16],
                "argument_bindings": bindings,
                "binding_status": binding_status,
                "tainted_callee_parameters": sorted(callee_taint)[:16],
                "return_binding": {
                    "callsite_result": result,
                    "target_tokens": target_tokens[:16],
                    "returned_parameters": returned_parameters[:16],
                    "tainted_return_parameters": tainted_returns[:16],
                    "return_sites": return_sites,
                    "status": return_status,
                },
                "claim_status": CLAIM_STATUS,
                "producer": "semantic-calls",
                "confidence": CONFIDENCE,
                "evidence_type": EVIDENCE_TYPE,
            }
            call_steps.append(step)
            current_taint = callee_taint

        sink_dict = {
            "category": str(_field(sink, "category", "") or "") if sink else "",
            "api": str(_field(sink, "api", "") or "") if sink else "",
            "file": str(_field(sink, "file", "") or "") if sink else "",
            "line": _int(_field(sink, "line", 0)) if sink else 0,
        }
        sink_status, sink_variables = _sink_tokens(root, sink_dict, line_cache)
        if len(path) <= 1:
            sink_binding_status = "not-applicable"
        elif not current_taint or not sink_variables:
            sink_binding_status = "unresolved"
        elif set(current_taint) & set(sink_variables):
            sink_binding_status = "bound"
        else:
            sink_binding_status = "not-bound"
        sink_counts[sink_binding_status] += 1
        callsite_status = (
            "resolved" if call_steps and all(
                step.get("callsite_status") == "resolved" for step in call_steps
            ) else "unresolved" if call_steps else "not-applicable"
        )
        if call_steps and all(step.get("binding_status") == "bound"
                              for step in call_steps):
            overall_binding = "bound"
        elif call_steps and any(step.get("binding_status") in {
                "unresolved", "arity-unresolved"} for step in call_steps):
            overall_binding = "unresolved"
        elif call_steps:
            overall_binding = "partial"
        else:
            overall_binding = "not-applicable"
        row = {
            "flow_id": flow_id,
            "entry_id": str(_field(flow, "entry_id", "") or ""),
            "sink_id": str(_field(flow, "sink_id", "") or ""),
            "path": path,
            "same_symbol": len(path) <= 1,
            "call_steps": call_steps,
            "callsite_status": callsite_status,
            "binding_status": overall_binding,
            "sink": sink_dict,
            "sink_parse_status": sink_status,
            "sink_variables": sink_variables,
            "sink_binding": {
                "status": sink_binding_status,
                "tainted_variables": sorted(current_taint)[:16],
                "sink_variables": sink_variables,
            },
            "unresolved_steps": unresolved_steps,
            "required_manual_checks": [
                "verify each callsite against the real overload, dispatch, DI or callback target",
                "verify parameter/return transformations and branch dominance in the callee",
                "verify the final sink argument is the same object, tenant and security subject",
            ],
            "claim_status": CLAIM_STATUS,
            "producer": "semantic-calls",
            "confidence": CONFIDENCE,
            "evidence_type": EVIDENCE_TYPE,
        }
        flow_rows.append(row)
        if len(path) > 1 and sink_binding_status != "bound":
            candidates.append(_candidate({
                "flow_id": flow_id,
                "entry_id": _field(flow, "entry_id", ""),
                "sink_id": _field(flow, "sink_id", ""),
                "path": path,
                "entry": {
                    "entry_id": _field(entry, "entry_id", "") if entry else "",
                    "api": _field(entry, "api", "") if entry else "",
                    "input_shape": _field(entry, "input_shape", "unknown") if entry else "unknown",
                    "file": _field(entry, "file", "") if entry else "",
                    "line": _field(entry, "line", 0) if entry else 0,
                },
                "sink": sink_dict,
            }, row))

    candidates.sort(key=lambda item: (str(item.get("flow_id") or ""),
                                     str(item.get("candidate_id") or "")))
    summary = {
        "flows": len(flow_rows),
        "cross_symbol_flows": cross_symbol_flows,
        "call_steps": sum(len(row.get("call_steps") or []) for row in flow_rows),
        "callsite_status": dict(sorted(callsite_counts.items())),
        "parameter_bindings": dict(sorted(binding_counts.items())),
        "return_bindings": dict(sorted(return_counts.items())),
        "sink_binding": dict(sorted(sink_counts.items())),
        "candidates": len(candidates),
        "claim_status": CLAIM_STATUS,
        "producer": "semantic-calls",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "limitations": list(_LIMITATIONS),
    }
    return {
        "schema_version": SEMANTIC_CALL_VERSION,
        "summary": summary,
        "flows": flow_rows,
        "candidates": candidates,
        "claim_status": CLAIM_STATUS,
        "producer": "semantic-calls",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "limitations": list(_LIMITATIONS),
    }


def load_semantic_call_evidence(store: Any) -> Dict[str, Any]:
    data = store.read(SEMANTIC_CALL_INDEX)
    return data if isinstance(data, dict) else {}


def load_semantic_call_candidates(store: Any) -> List[Dict[str, Any]]:
    data = store.read(SEMANTIC_CALL_CANDIDATE_INDEX)
    return [item for item in data if isinstance(item, dict)] \
        if isinstance(data, list) else []


def render_semantic_calls_text(evidence: Mapping[str, Any], lang: str = "zh",
                               limit: int = 20) -> str:
    summary = dict(evidence.get("summary") or {}) \
        if isinstance(evidence, Mapping) else {}
    candidates = list(evidence.get("candidates") or []) \
        if isinstance(evidence, Mapping) else []
    if lang == "en":
        lines = ["Semantic call evidence (argument / return binding)",
                 "─" * 58,
                 "  flows %s  cross-symbol %s  steps %s  candidates %s" % (
                     summary.get("flows", 0), summary.get("cross_symbol_flows", 0),
                     summary.get("call_steps", 0), summary.get("candidates", 0)),
                 "  callsites %s" % (summary.get("callsite_status") or {}),
                 "  sink binding %s" % (summary.get("sink_binding") or {}),
                 "  leads:"]
    else:
        lines = ["语义调用证据（参数 / 返回绑定）", "─" * 58,
                 "  路径 %s  跨符号 %s  调用步 %s  候选 %s" % (
                     summary.get("flows", 0), summary.get("cross_symbol_flows", 0),
                     summary.get("call_steps", 0), summary.get("candidates", 0)),
                 "  调用点 %s" % (summary.get("callsite_status") or {}),
                 "  sink 绑定 %s" % (summary.get("sink_binding") or {}),
                 "  待验证线索："]
    for candidate in candidates[:max(0, limit)]:
        lines.append("    %-22s %-30s %s" % (
            candidate.get("candidate_id", ""), candidate.get("binding_status", ""),
            ",".join(candidate.get("code_location") or []) or "-"))
    if len(candidates) > limit:
        lines.append("    ... %d more" % (len(candidates) - limit))
    return "\n".join(lines)
