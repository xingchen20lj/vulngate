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
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from . import controls as control_rules
from .semantic_frontend import FrontendSession, ParsedUnit, JAVA_AST_PARSER


SEMANTIC_CALL_INDEX = "semantic-call-evidence"
SEMANTIC_CALL_CANDIDATE_INDEX = "semantic-call-candidates"
SEMANTIC_CALL_VERSION = "semantic-call-evidence-v2"
CLAIM_STATUS = "not-a-finding"
CONFIDENCE = "heuristic-nearby"
EVIDENCE_TYPE = "static-inferred"

# These limits belong to this semantic layer even though the call graph has
# its own reachability cap.  Keeping them here prevents a large/stale flow
# input from turning a bounded evidence pass into an unbounded analysis.
DEFAULT_MAX_CALL_DEPTH = 8
DEFAULT_MAX_PROPAGATION_NODES = 256
DEFAULT_MAX_PROPAGATION_PATHS = 10000
DEFAULT_TIMEOUT_SECONDS = 5.0

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
_SYNTAX_LITERAL = "<syntax-literal>"

_LIMITATIONS = (
    "call-site binding uses bounded lexical extraction or Java parser syntax facts and does not prove overload, type, virtual dispatch, DI, reflection, callback or async resolution",
    "Java parser facts come from parse-only JavacTask and do not resolve types, overloads, classpaths or target dispatch",
    "argument propagation does not prove that a callee returns, transforms, preserves or uses the bound value on every path",
    "return evidence is a source-shape hint and does not prove dominance, path feasibility or sanitizer semantics",
    "unresolved or not-bound states are manual source-review leads, never proof of a vulnerability or proof of safety",
    "alias/return propagation is limited to simple identifier assignments and bounded call paths",
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
                       ) -> Tuple[List[str], int, Dict[str, str], List[str]]:
    """Return parameter origins through a small, syntax-only alias walk.

    This deliberately recognizes only ``alias = parameter`` (and a bounded
    chain of the same shape).  A transform, container write, attribute access,
    or conditional assignment is left unresolved instead of being guessed as
    a preserved taint value.
    """
    lines = _read_lines(root, _field(symbol, "file", ""), line_cache)
    start = max(0, _int(_field(symbol, "start_line", 1)) - 1)
    end = min(len(lines), _int(_field(symbol, "end_line", len(lines))))
    origins: Dict[str, str] = {str(param): str(param) for param in params if str(param)}
    aliases: Dict[str, str] = {}
    sites = 0
    returned_aliases: Set[str] = set()
    for line in lines[start:end]:
        masked = _mask(line)
        assignment = re.match(
            r"^\s*(?:var\s+|let\s+|const\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=(?!=)\s*(.*?)\s*;?\s*$",
            masked,
        )
        if assignment:
            lhs, rhs = assignment.group(1), assignment.group(2).strip()
            rhs_tokens = _tokens(rhs)
            # A pure identifier assignment is the only alias shape accepted.
            # This prevents ``safe = sanitize(value)`` from being mistaken for
            # a return-preserving alias.
            if len(rhs_tokens) == 1 and rhs_tokens[0] in origins:
                origins[lhs] = origins[rhs_tokens[0]]
                aliases[lhs] = origins[lhs]
            else:
                origins.pop(lhs, None)
                aliases.pop(lhs, None)
        if not re.search(r"\breturn\b", masked):
            continue
        sites += 1
        for token in _tokens(masked, 16):
            if token in origins:
                returned_aliases.add(token)
    returned = sorted({origins[token] for token in returned_aliases})[:16]
    return returned, sites, dict(sorted(aliases.items())[:16]), sorted(returned_aliases)[:16]


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


class _JavaSyntaxLookup:
    """Read bounded Java syntax facts without re-reading source text.

    ``None`` means the caller is not a Java AST record and must use the legacy
    lexical path.  A non-parsed Java unit is deliberately an explicit gap: it
    must not be silently replaced by a more permissive regex match.
    """

    def __init__(self, session: Optional[FrontendSession]):
        self.session = session
        self.units: Dict[str, ParsedUnit] = {}

    def unit(self, file_name: Any) -> Optional[ParsedUnit]:
        if self.session is None:
            return None
        file_name = str(file_name or "")
        if not file_name or not file_name.lower().endswith(".java"):
            return None
        if file_name not in self.units:
            self.units[file_name] = self.session.parse(file_name)
        unit = self.units[file_name]
        return unit if unit.parser == JAVA_AST_PARSER else None

    @staticmethod
    def _leaf(fact: Any) -> str:
        return str(fact.attributes.get("leaf_name") or fact.name.rsplit(".", 1)[-1])

    def call_arguments(self, file_name: Any, line: int, name: str
                       ) -> Optional[Tuple[str, List[str], List[str]]]:
        unit = self.unit(file_name)
        if unit is None:
            return None
        if unit.status != "parsed":
            return "unresolved", [], list(unit.analysis_gaps)
        matches = [fact for fact in unit.select("call")
                   if fact.line == line and self._leaf(fact) == name]
        if len(matches) != 1:
            return "unresolved", [], ["java-ast-callsite-unresolved"]
        attributes = matches[0].attributes
        raw_arguments = list(attributes.get("argument_tokens") or [])
        kinds = list(attributes.get("argument_kinds") or [])
        arguments = []
        for position, raw in enumerate(raw_arguments):
            tokens = [str(item) for item in raw if str(item)] \
                if isinstance(raw, (list, tuple)) else []
            kind = str(kinds[position] if position < len(kinds) else "")
            arguments.append(_SYNTAX_LITERAL if kind == "literal"
                             else " ".join(tokens))
        return "resolved", arguments, []

    def callsite_result(self, file_name: Any, line: int, name: str
                        ) -> Optional[Tuple[str, List[str], List[str]]]:
        unit = self.unit(file_name)
        if unit is None:
            return None
        if unit.status != "parsed":
            return "unresolved", [], list(unit.analysis_gaps)
        matches = [fact for fact in unit.select("call")
                   if fact.line == line and self._leaf(fact) == name]
        if len(matches) != 1:
            return "unresolved", [], ["java-ast-callsite-unresolved"]
        attributes = matches[0].attributes
        context = str(attributes.get("use_context") or "direct")
        result = context if context in {"returned", "assigned"} else "discarded"
        targets = [str(item) for item in (attributes.get("target_tokens") or [])
                   if str(item)][:16]
        return result, targets, []

    def return_parameters(self, symbol: Any, params: Sequence[str]
                          ) -> Optional[Tuple[List[str], int, Dict[str, str],
                                                List[str], List[str]]]:
        unit = self.unit(_field(symbol, "file", ""))
        if unit is None:
            return None
        if unit.status != "parsed":
            return [], 0, {}, [], list(unit.analysis_gaps)
        start = _int(_field(symbol, "start_line", 1))
        end = _int(_field(symbol, "end_line", unit.line_count))
        origins: Dict[str, str] = {str(param): str(param) for param in params
                                   if str(param)}
        aliases: Dict[str, str] = {}
        for fact in unit.select("assignment"):
            if not start <= fact.line <= end:
                continue
            targets = [str(item) for item in
                       (fact.attributes.get("target_tokens") or []) if str(item)]
            values = [str(item) for item in
                      (fact.attributes.get("value_tokens") or []) if str(item)]
            if len(targets) != 1:
                continue
            target = targets[0]
            if len(values) == 1 and values[0] in origins:
                origins[target] = origins[values[0]]
                aliases[target] = origins[target]
            else:
                origins.pop(target, None)
                aliases.pop(target, None)
        sites = 0
        returned_aliases: Set[str] = set()
        for fact in unit.select("return"):
            if not start <= fact.line <= end:
                continue
            sites += 1
            for token in fact.attributes.get("value_tokens") or []:
                token = str(token)
                if token in origins:
                    returned_aliases.add(token)
        returned = sorted({origins[token] for token in returned_aliases})[:16]
        return returned, sites, dict(sorted(aliases.items())[:16]), \
            sorted(returned_aliases)[:16], []

    def sink_tokens(self, sink: Mapping[str, Any]
                    ) -> Optional[Tuple[str, List[str], List[str]]]:
        unit = self.unit(sink.get("file", ""))
        if unit is None:
            return None
        if unit.status != "parsed":
            return "unresolved", [], list(unit.analysis_gaps)
        api = str(sink.get("api") or "")
        name = api.rsplit(".", 1)[-1].rsplit("#", 1)[-1]
        line = _int(sink.get("line"))
        matches = [fact for fact in unit.select("call")
                   if fact.line == line and self._leaf(fact) == name]
        if len(matches) != 1:
            return "unresolved", [], ["java-ast-sink-unresolved"]
        tokens: Set[str] = set()
        for argument in matches[0].attributes.get("argument_tokens") or []:
            if isinstance(argument, (list, tuple)):
                tokens.update(str(item) for item in argument if str(item))
        return "resolved", sorted(tokens)[:16], []


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
        "analysis_gaps": list(row.get("analysis_gaps") or []),
        "analysis_budget": dict(row.get("analysis_budget") or {}),
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
        call_edges: Sequence[Any],
        max_call_depth: int = DEFAULT_MAX_CALL_DEPTH,
        max_propagation_nodes: int = DEFAULT_MAX_PROPAGATION_NODES,
        max_propagation_paths: int = DEFAULT_MAX_PROPAGATION_PATHS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        frontend_session: Optional[FrontendSession] = None) -> Dict[str, Any]:
    """Build bounded call-site and tainted-parameter evidence for all flows.

    The result retains a row for every supplied flow.  If a depth/node/path or
    wall-clock budget is exhausted, the row carries an explicit analysis gap
    and remains a manual research lead rather than disappearing or becoming a
    negative result.
    """
    root = Path(root).resolve()
    max_call_depth = max(0, int(max_call_depth))
    max_propagation_nodes = max(1, int(max_propagation_nodes))
    max_propagation_paths = max(0, int(max_propagation_paths))
    timeout_seconds = max(0.0, float(timeout_seconds))
    started_at = time.monotonic()
    deadline = started_at + timeout_seconds if timeout_seconds else None
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
    java_syntax = _JavaSyntaxLookup(frontend_session)
    flow_rows: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    callsite_counts: Counter = Counter()
    binding_counts: Counter = Counter()
    return_counts: Counter = Counter()
    sink_counts: Counter = Counter()
    budget_counts: Counter = Counter()
    cross_symbol_flows = 0
    visited_nodes = 0
    processed_paths = 0

    ordered_flows = sorted(flows, key=lambda item: str(
        _field(item, "flow_id", "") or ""))
    for flow in ordered_flows:
        flow_id = str(_field(flow, "flow_id", "") or "")
        path = [str(item) for item in (_field(flow, "path", []) or [])]
        entry = entry_index.get(str(_field(flow, "entry_id", "") or ""))
        sink = sink_index.get(str(_field(flow, "sink_id", "") or ""))
        entry_symbol_id = str(_field(flow, "source_symbol", "") or "")
        entry_symbol = symbol_index.get(entry_symbol_id)
        path_nodes = set(path)
        analysis_gaps: List[str] = []
        if len(path) - 1 > max_call_depth:
            analysis_gaps.append("call-depth-budget-exceeded")
        if processed_paths >= max_propagation_paths:
            analysis_gaps.append("path-budget-exceeded")
        if visited_nodes + len(path_nodes) > max_propagation_nodes:
            analysis_gaps.append("node-budget-exceeded")
        if deadline is not None and time.monotonic() >= deadline:
            analysis_gaps.append("timeout-budget-exceeded")
        if analysis_gaps:
            for gap in analysis_gaps:
                budget_counts[gap] += 1
            row = {
                "flow_id": flow_id,
                "entry_id": str(_field(flow, "entry_id", "") or ""),
                "sink_id": str(_field(flow, "sink_id", "") or ""),
                "path": path,
                "same_symbol": len(path) <= 1,
                "call_steps": [],
                "callsite_status": "unresolved" if len(path) > 1 else "not-applicable",
                "binding_status": "unresolved" if len(path) > 1 else "not-applicable",
                "sink": {
                    "category": str(_field(sink, "category", "") or "") if sink else "",
                    "api": str(_field(sink, "api", "") or "") if sink else "",
                    "file": str(_field(sink, "file", "") or "") if sink else "",
                    "line": _int(_field(sink, "line", 0)) if sink else 0,
                },
                "sink_parse_status": "unresolved",
                "sink_variables": [],
                "sink_binding": {"status": "unresolved", "tainted_variables": [],
                                  "sink_variables": []},
                "unresolved_steps": max(0, len(path) - 1),
                "analysis_gaps": sorted(set(analysis_gaps)),
                "analysis_budget": {
                    "max_call_depth": max_call_depth,
                    "max_propagation_nodes": max_propagation_nodes,
                    "max_propagation_paths": max_propagation_paths,
                    "timeout_seconds": timeout_seconds,
                },
                "required_manual_checks": [
                    "rerun with a larger bounded budget or inspect the truncated path",
                    "verify each callsite against the real overload, dispatch, DI or callback target",
                ],
                "claim_status": CLAIM_STATUS,
                "producer": "semantic-calls",
                "confidence": CONFIDENCE,
                "evidence_type": EVIDENCE_TYPE,
            }
            flow_rows.append(row)
            if len(path) > 1:
                candidates.append(_candidate({
                    "flow_id": flow_id,
                    "entry_id": _field(flow, "entry_id", ""),
                    "sink_id": _field(flow, "sink_id", ""),
                    "path": path,
                    "entry": {"entry_id": _field(entry, "entry_id", "") if entry else "",
                              "api": _field(entry, "api", "") if entry else "",
                              "input_shape": _field(entry, "input_shape", "unknown") if entry else "unknown",
                              "file": _field(entry, "file", "") if entry else "",
                              "line": _field(entry, "line", 0) if entry else 0},
                    "sink": row["sink"],
                }, row))
            continue
        visited_nodes += len(path_nodes)
        processed_paths += 1
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
            callsite_file = edge_file or str(_field(caller, "file", "") or "")
            caller_lines = _read_lines(root, callsite_file, line_cache)
            callsite_parser = "lexical"
            step_gaps: List[str] = []
            java_call = (java_syntax.call_arguments(callsite_file, edge_line, edge_name)
                         if str(_field(caller, "parser", "")) == JAVA_AST_PARSER
                         else None)
            if java_call is None:
                callsite_status, arguments = _call_arguments(
                    caller_lines, edge_line, edge_name)
            else:
                callsite_status, arguments, java_gaps = java_call
                callsite_parser = JAVA_AST_PARSER
                step_gaps.extend(java_gaps)
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
                    argument_tokens = ([] if argument == _SYNTAX_LITERAL
                                       else _tokens(argument))
                    tainted_tokens = sorted(set(argument_tokens) & current_taint)
                    if tainted_tokens:
                        binding_status = "direct" if len(argument_tokens) == 1 else "propagated"
                        callee_taint.add(parameter)
                    elif not argument:
                        binding_status = "unresolved"
                    elif argument == _SYNTAX_LITERAL or _LITERAL.match(argument.strip()):
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
            java_result = (java_syntax.callsite_result(callsite_file, edge_line, edge_name)
                           if callsite_parser == JAVA_AST_PARSER else None)
            if java_result is None:
                result, target_tokens = _callsite_result(
                    caller_lines[edge_line - 1] if 0 < edge_line <= len(caller_lines) else "",
                    edge_name)
            else:
                result, target_tokens, result_gaps = java_result
                step_gaps.extend(result_gaps)
            return_parser = "lexical"
            java_return = (java_syntax.return_parameters(callee, callee_parameters)
                           if callee is not None and
                           str(_field(callee, "parser", "")) == JAVA_AST_PARSER
                           else None)
            if java_return is None:
                if callee:
                    returned_parameters, return_sites, alias_map, returned_aliases = (
                        _return_parameters(root, callee, callee_parameters, line_cache))
                else:
                    returned_parameters, return_sites, alias_map, returned_aliases = (
                        [], 0, {}, [])
            else:
                (returned_parameters, return_sites, alias_map, returned_aliases,
                 return_gaps) = java_return
                return_parser = JAVA_AST_PARSER
                step_gaps.extend(return_gaps)
            analysis_gaps.extend(step_gaps)
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
                "callsite": {"file": callsite_file, "line": edge_line},
                "callee_name": edge_name,
                "propagation": str(_field(edge, "propagation", "") or "") if edge else "",
                "callsite_status": callsite_status,
                "callsite_parser": callsite_parser,
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
                    "alias_map": alias_map,
                    "returned_aliases": returned_aliases,
                    "tainted_return_aliases": [alias for alias in returned_aliases
                                               if alias in alias_map and
                                               alias_map[alias] in tainted_returns][:16],
                    "return_sites": return_sites,
                    "status": return_status,
                    "parser": return_parser,
                },
                "analysis_gaps": sorted(set(step_gaps)),
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
        sink_parser = "lexical"
        java_sink = java_syntax.sink_tokens(sink_dict)
        if java_sink is None:
            sink_status, sink_variables = _sink_tokens(root, sink_dict, line_cache)
        else:
            sink_status, sink_variables, sink_gaps = java_sink
            sink_parser = JAVA_AST_PARSER
            analysis_gaps.extend(sink_gaps)
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
            "sink_parser": sink_parser,
            "sink_variables": sink_variables,
            "sink_binding": {
                "status": sink_binding_status,
                "tainted_variables": sorted(current_taint)[:16],
                "sink_variables": sink_variables,
            },
            "unresolved_steps": unresolved_steps,
            "analysis_gaps": sorted(set(analysis_gaps)),
            "analysis_budget": {
                "max_call_depth": max_call_depth,
                "max_propagation_nodes": max_propagation_nodes,
                "max_propagation_paths": max_propagation_paths,
                "timeout_seconds": timeout_seconds,
            },
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
        "analysis_budget": {
            "max_call_depth": max_call_depth,
            "max_propagation_nodes": max_propagation_nodes,
            "max_propagation_paths": max_propagation_paths,
            "timeout_seconds": timeout_seconds,
            "visited_nodes": visited_nodes,
            "processed_paths": processed_paths,
            "budget_gaps": dict(sorted(budget_counts.items())),
        },
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
