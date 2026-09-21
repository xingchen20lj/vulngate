"""Bounded language-aware value-binding evidence.

The lexical transform layer answers whether a control call appears near a
sink.  This module adds the next expert-review question for Python targets:
does a syntax-aware, bounded execution model carry the transformed value to
the sink on every enumerated local path?

The adapter deliberately stops short of being a compiler.  It parses Python
with the standard-library AST, follows simple names and assignments, explores
bounded branch/exception/loop shapes, and records explicit mixed or unresolved
states.  It never persists source text, payloads, AST dumps, or runtime
effects.  Other languages remain explicit adapter gaps until a corresponding
language backend exists.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections import Counter, OrderedDict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from . import controls as control_rules


SEMANTIC_BINDING_INDEX = "semantic-python-binding-evidence"
SEMANTIC_BINDING_CANDIDATE_INDEX = "semantic-python-binding-candidates"
SEMANTIC_BINDING_VERSION = "semantic-python-binding-evidence-v1"
CLAIM_STATUS = "not-a-finding"
CONFIDENCE = "heuristic-nearby"
EVIDENCE_TYPE = "static-inferred"

_PYTHON_SUFFIXES = frozenset({".py", ".pyw"})
_MAX_AST_BYTES = 2_000_000
_MAX_AST_NODES = 100_000
_MAX_AST_FILES = 8
_MAX_PATHS = 64
_MAX_RECURSION = 24
_AST_NAME_CONSTANT = getattr(ast, "NameConstant", ())
_IDENTIFIER = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b")
_CANDIDATE_RELATIONS = frozenset({
    "ast-raw-at-sink",
    "ast-branch-merged",
    "ast-derived-value",
    "ast-unresolved",
    "ast-sink-not-reached",
    "ast-after-sink",
    "ast-control-unresolved",
    "ast-sink-unresolved",
    "ast-parse-failed",
    "ast-too-large",
    "ast-node-limit",
    "ast-source-unreadable",
    "ast-cross-scope-unresolved",
    "unsupported-language",
})

_LIMITATIONS = (
    "the Python adapter is a bounded abstract interpreter, not a complete CFG, SSA, type or path-feasibility proof",
    "unknown calls, attributes, subscripts, comprehensions, decorators, imports, dynamic dispatch and aliasing remain unresolved or derived",
    "branch and loop exploration is finite and intentionally keeps mixed paths visible instead of collapsing them into safety",
    "the per-run parsed-file cache is bounded; evicted files may be reparsed instead of retaining unbounded AST memory",
    "non-Python files are explicit adapter gaps until a language-specific backend is installed",
    "all rows and candidates are static research leads, never proof of a vulnerability or proof of safety",
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


def _stable_id(prefix: str, *parts: Any) -> str:
    payload = json.dumps([str(part or "") for part in parts],
                         ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"))
    return "%s-%s" % (prefix, hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12])


def _span(node: Any) -> Tuple[int, int]:
    start = _int(getattr(node, "lineno", 0))
    end = _int(getattr(node, "end_lineno", 0)) or start
    return start, max(start, end)


def _contains(span: Tuple[int, int], line: int) -> bool:
    return bool(span[0] and span[0] <= line <= span[1])


def _identifiers(value: Any) -> Set[str]:
    return set(_IDENTIFIER.findall(str(value or "")))


def _location(file_name: Any, line: Any) -> str:
    return "%s:%d" % (str(file_name or ""), _int(line)) if file_name else ""


def _read_text(root: Path, file_name: Any,
               cache: Dict[str, Optional[str]]) -> Optional[str]:
    name = str(file_name or "")
    if name in cache:
        return cache[name]
    path = Path(name)
    if not path.is_absolute():
        path = root / path
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        text = None
    cache[name] = text
    return text


def _call_leaf(node: Any) -> str:
    func = getattr(node, "func", None)
    if isinstance(func, ast.Name):
        return str(func.id or "").lower()
    if isinstance(func, ast.Attribute):
        return str(func.attr or "").lower()
    return ""


def _call_names(control: Mapping[str, Any]) -> Set[str]:
    names: Set[str] = set()
    for key in ("api", "control_type", "category"):
        for token in _IDENTIFIER.findall(str(control.get(key) or "")):
            if len(token) > 2:
                names.add(token.lower())
    category = control_rules.normalize_category(control.get("category"))
    if category:
        names.add(category.lower())
    return names


def _expr_dependencies(node: Any) -> Set[str]:
    if node is None:
        return set()
    if isinstance(node, ast.Name):
        return {str(node.id)} if not isinstance(
            getattr(node, "ctx", None), ast.Store) else set()
    if isinstance(node, ast.Call):
        result: Set[str] = set()
        for arg in node.args:
            result.update(_expr_dependencies(arg))
        for keyword in node.keywords:
            result.update(_expr_dependencies(keyword.value))
        return result
    result: Set[str] = set()
    for child in ast.iter_child_nodes(node):
        result.update(_expr_dependencies(child))
    return result


def _state(kind: str, dependencies: Iterable[str] = ()) -> Dict[str, Any]:
    return {
        "kind": str(kind),
        "dependencies": sorted({str(item) for item in dependencies if item})[:16],
    }


def _copy_state(state: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "env": {str(key): dict(value)
                for key, value in (state.get("env") or {}).items()},
        "guards": set(state.get("guards") or set()),
        "control_seen": bool(state.get("control_seen")),
        "path": tuple(state.get("path") or ()),
    }


def _copy_path(state: Mapping[str, Any], label: str) -> Dict[str, Any]:
    result = _copy_state(state)
    result["path"] = tuple(list(result.get("path") or ()) + [str(label)])[-12:]
    return result


def _limit_states(states: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Keep path exploration finite while preserving deterministic order."""
    if len(states) <= _MAX_PATHS:
        return list(states)
    ordered = sorted(states, key=lambda item: repr(sorted(
        (str(key), str(value))
        for key, value in (item.get("env") or {}).items())))
    return ordered[:_MAX_PATHS]


def _value_kind(states: Sequence[Mapping[str, Any]]) -> str:
    kinds = {str(state.get("kind") or "unknown") for state in states}
    if not kinds:
        return "unknown"
    if len(kinds) == 1:
        return next(iter(kinds))
    if "unknown" in kinds:
        return "unknown"
    if "mixed" in kinds:
        return "mixed"
    if "derived" in kinds:
        return "derived"
    if "transformed" in kinds and "raw" in kinds:
        return "mixed"
    if "transformed" in kinds:
        return "transformed"
    if "raw" in kinds:
        return "raw"
    return "mixed"


def _combine_expression(states: Sequence[Mapping[str, Any]],
                        operation: str = "") -> Dict[str, Any]:
    dependencies: Set[str] = set()
    kinds: Set[str] = set()
    for state in states:
        dependencies.update(str(item) for item in state.get("dependencies") or [])
        kinds.add(str(state.get("kind") or "unknown"))
    if not kinds:
        return _state("unknown")
    if operation and operation != "alias":
        if "unknown" in kinds:
            return _state("unknown", dependencies)
        if "transformed" in kinds or "derived" in kinds:
            return _state("derived", dependencies)
        if "raw" in kinds:
            return _state("derived", dependencies)
        return _state("literal", dependencies)
    return _state(_value_kind(states), dependencies)


def _target_names(node: Any) -> List[str]:
    if isinstance(node, ast.Name):
        return [str(node.id)]
    if isinstance(node, (ast.Tuple, ast.List)):
        output: List[str] = []
        for item in node.elts:
            output.extend(_target_names(item))
        return output
    return []


class _PythonIndex:
    """One bounded AST parse and scope/call lookup for a Python file."""

    def __init__(self, file_name: str, text: Optional[str]):
        self.file_name = file_name
        self.status = "parsed"
        self.error_kind = ""
        self.tree: Optional[ast.AST] = None
        self.functions: List[ast.AST] = []
        self.calls_by_leaf: Dict[str, List[ast.Call]] = {}
        self.node_count = 0
        self.max_line = 1
        if text is None:
            self.status = "source-unreadable"
            self.error_kind = "source-read-failed"
            return
        if len(text.encode("utf-8", errors="replace")) > _MAX_AST_BYTES:
            self.status = "too-large"
            self.error_kind = "ast-byte-limit"
            return
        try:
            self.tree = ast.parse(text, filename=file_name, type_comments=False)
        except (SyntaxError, ValueError, TypeError, MemoryError) as exc:
            self.status = "parse-failed"
            self.error_kind = type(exc).__name__
            return
        self._walk(self.tree)
        if self.node_count > _MAX_AST_NODES:
            self.status = "node-limit"
            self.error_kind = "ast-node-limit"
            self.functions = []

    def _walk(self, node: ast.AST) -> None:
        self.node_count += 1
        self.max_line = max(self.max_line, _int(getattr(node, "end_lineno", 0))
                            or _int(getattr(node, "lineno", 0)) or 1)
        if self.node_count > _MAX_AST_NODES:
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.functions.append(node)
        if isinstance(node, ast.Call):
            leaf = _call_leaf(node)
            if leaf:
                self.calls_by_leaf.setdefault(leaf, []).append(node)
        for child in ast.iter_child_nodes(node):
            self._walk(child)

    def scope_for(self, symbol: Mapping[str, Any], control_line: int,
                  sink_line: int) -> Tuple[Optional[ast.AST], Dict[str, Any]]:
        if self.tree is None:
            return None, {}
        start = _int(symbol.get("start_line"))
        end = _int(symbol.get("end_line"))
        candidates = []
        for function in self.functions:
            span = _span(function)
            if not (_contains(span, control_line) and _contains(span, sink_line)):
                continue
            if start and end and not (span[1] >= start and span[0] <= end):
                continue
            candidates.append(function)
        if candidates:
            scope = sorted(candidates, key=lambda node: (
                _span(node)[1] - _span(node)[0], _span(node)[0]))[0]
            scope_start, scope_end = _span(scope)
            return scope, {
                "kind": "function",
                "name": str(getattr(scope, "name", "")),
                "start": scope_start,
                "end": scope_end,
            }
        tree_span = (1, self.max_line)
        if _contains(tree_span, control_line) and _contains(tree_span, sink_line):
            return self.tree, {"kind": "module", "start": 1, "end": tree_span[1]}
        return None, {}

    def calls_at(self, scope: ast.AST, line: int,
                 names: Set[str]) -> List[ast.Call]:
        if not names or line <= 0:
            return []
        scope_span = _span(scope) if scope is not self.tree else (1, self.max_line)
        calls: List[ast.Call] = []
        seen: Set[int] = set()
        for name in sorted({str(item).lower() for item in names if item}):
            for node in self.calls_by_leaf.get(name, []):
                node_id = id(node)
                if node_id in seen:
                    continue
                if not _contains(scope_span, _int(getattr(node, "lineno", 0))):
                    continue
                if not _contains(_span(node), line):
                    continue
                seen.add(node_id)
                calls.append(node)
        return sorted(calls, key=lambda node: (
            _span(node)[1] - _span(node)[0],
            abs(_int(getattr(node, "lineno", 0)) - line),
            _int(getattr(node, "col_offset", 0))))


class _FlowAnalyzer:
    """Small path-sensitive interpreter for one function and one control."""

    def __init__(self, scope: ast.AST, control_call: ast.Call,
                 sink_call: ast.Call, input_variables: Set[str],
                 parameters: Sequence[str]):
        self.scope = scope
        self.control_call = control_call
        self.sink_call = sink_call
        self.input_variables = set(input_variables)
        self.parameters = {str(item) for item in parameters if item}
        self.observations: List[Dict[str, Any]] = []
        self.depth_limited = False

    def run(self) -> List[Dict[str, Any]]:
        body = list(getattr(self.scope, "body", []) or [])
        initial = {
            "env": {name: _state("raw", [name]) for name in self.parameters},
            "guards": set(),
            "control_seen": False,
            "path": (),
        }
        self._block(body, initial, 0)
        return list(self.observations)

    def _contains(self, node: Any, target: ast.AST) -> bool:
        return any(child is target for child in ast.walk(node))

    def _mark_control(self, state: Mapping[str, Any], guard: bool = False
                      ) -> Dict[str, Any]:
        result = _copy_state(state)
        result["control_seen"] = True
        if guard:
            result["guards"].update(self.input_variables)
        return result

    def _expr_state(self, node: Any, state: Mapping[str, Any]
                    ) -> Dict[str, Any]:
        if isinstance(node, ast.Name):
            return dict((state.get("env") or {}).get(
                str(node.id), _state("unknown", [str(node.id)])))
        if isinstance(node, ast.Constant):
            return _state("literal")
        if isinstance(node, ast.Call):
            if node is self.control_call:
                return _state("transformed", _expr_dependencies(node))
            children = [self._expr_state(arg, state) for arg in node.args]
            children.extend(self._expr_state(keyword.value, state)
                            for keyword in node.keywords)
            dependencies = _expr_dependencies(node)
            if self._contains(node, self.control_call):
                return _state("derived", dependencies)
            if any(item.get("kind") in {"raw", "transformed", "derived",
                                         "unknown"} for item in children):
                return _state("unknown", dependencies)
            return _state("unknown", dependencies)
        if _AST_NAME_CONSTANT and isinstance(node, _AST_NAME_CONSTANT):
            return _state("literal")
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            base = self._expr_state(node.value, state)
            return _state("derived" if base.get("kind") != "unknown"
                          else "unknown", _expr_dependencies(node))
        if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.List, ast.Tuple,
                             ast.Set, ast.Dict, ast.ListComp, ast.SetComp,
                             ast.DictComp, ast.GeneratorExp)):
            children = [self._expr_state(child, state)
                        for child in ast.iter_child_nodes(node)]
            return _combine_expression(children, operation="derived")
        if isinstance(node, (ast.UnaryOp, ast.IfExp, ast.BoolOp, ast.Compare,
                             ast.NamedExpr)):
            children = [self._expr_state(child, state)
                        for child in ast.iter_child_nodes(node)]
            return _combine_expression(children, operation="derived")
        return _state("unknown", _expr_dependencies(node))

    def _assign(self, state: Mapping[str, Any], target: Any,
                value: Mapping[str, Any]) -> None:
        for name in _target_names(target):
            assigned = dict(value)
            dependencies = set(assigned.get("dependencies") or [])
            # Keep the local binding visible when its RHS is opaque (for
            # example ``value = request.args.get(...)``).  Without the local
            # name, a later ``sanitize(value); sink(value)`` looks unrelated
            # merely because the source-producing call is not understood.
            if str(assigned.get("kind") or "unknown") != "literal":
                dependencies.add(str(name))
            assigned["dependencies"] = sorted(dependencies)[:16]
            state.setdefault("env", {})[name] = assigned

    def _simple_statement(self, stmt: ast.stmt,
                          state: Mapping[str, Any]) -> Dict[str, Any]:
        result = _copy_state(state)
        if isinstance(stmt, ast.Assign):
            value = self._expr_state(stmt.value, result)
            for target in stmt.targets:
                self._assign(result, target, value)
        elif isinstance(stmt, ast.AnnAssign):
            value = self._expr_state(stmt.value, result) \
                if stmt.value is not None else _state("unknown")
            self._assign(result, stmt.target, value)
        elif isinstance(stmt, ast.AugAssign):
            left = self._expr_state(stmt.target, result)
            right = self._expr_state(stmt.value, result)
            self._assign(result, stmt.target,
                         _combine_expression((left, right), operation="derived"))
        elif isinstance(stmt, ast.NamedExpr):
            self._assign(result, stmt.target,
                         self._expr_state(stmt.value, result))
        elif isinstance(stmt, ast.Delete):
            for target in stmt.targets:
                for name in _target_names(target):
                    result.setdefault("env", {}).pop(name, None)
        return result

    def _sink_state(self, state: Mapping[str, Any]) -> Dict[str, Any]:
        args = list(self.sink_call.args or [])
        args.extend(keyword.value for keyword in self.sink_call.keywords or [])
        values = [self._expr_state(arg, state) for arg in args]
        dependencies: Set[str] = set()
        for value in values:
            dependencies.update(value.get("dependencies") or [])
        return {
            "kind": _value_kind(values),
            "dependencies": sorted(dependencies)[:16],
        }

    def _observe(self, state: Mapping[str, Any]) -> None:
        sink = self._sink_state(state)
        dependencies = set(sink.get("dependencies") or [])
        relevant = bool(dependencies & self.input_variables)
        guarded = bool(set(state.get("guards") or set()) & self.input_variables)
        kind = str(sink.get("kind") or "unknown")
        if guarded and relevant and kind in {"raw", "unknown", "mixed"}:
            relation = "ast-guard-condition"
        elif kind == "transformed" and relevant:
            relation = "ast-bound"
        elif kind == "raw" and relevant:
            relation = "ast-raw-at-sink"
        elif kind == "mixed" and relevant:
            relation = "ast-branch-merged"
        elif kind == "derived" and relevant:
            relation = "ast-derived-value"
        elif kind == "literal" or not relevant:
            relation = "ast-sink-unrelated"
        else:
            relation = "ast-unresolved"
        self.observations.append({
            "relation": relation,
            "sink_state": kind,
            "sink_dependencies": sorted(dependencies)[:16],
            "control_seen": bool(state.get("control_seen")),
            "guarded": guarded,
            "path": list(state.get("path") or ())[:12],
        })

    def _block(self, statements: Sequence[ast.stmt],
               state: Mapping[str, Any], depth: int) -> List[Dict[str, Any]]:
        if depth > _MAX_RECURSION:
            self.depth_limited = True
            return [_copy_state(state)]
        states = [_copy_state(state)]
        for stmt in statements:
            next_states: List[Dict[str, Any]] = []
            for current in states:
                next_states.extend(self._statement(stmt, current, depth))
            states = _limit_states(next_states)
            if not states:
                break
        return states

    def _statement(self, stmt: ast.stmt, state: Mapping[str, Any],
                   depth: int) -> List[Dict[str, Any]]:
        if isinstance(stmt, ast.If):
            current = _copy_state(state)
            test_has_control = self._contains(stmt.test, self.control_call)
            if test_has_control:
                current = self._mark_control(current)
            if self._contains(stmt.test, self.sink_call):
                self._observe(current)
                return []
            base_guards = set(current.get("guards") or set())
            body_seed = _copy_path(current, "if-body")
            if test_has_control:
                body_seed = self._mark_control(body_seed, guard=True)
            body_states = self._block(stmt.body, body_seed, depth + 1)
            for item in body_states:
                item["guards"] = set(base_guards)
            if stmt.orelse:
                else_states = self._block(
                    stmt.orelse, _copy_path(current, "if-else"), depth + 1)
            else:
                else_states = [_copy_path(current, "if-fallthrough")]
            return _limit_states(body_states + else_states)

        if isinstance(stmt, ast.Try):
            current = _copy_state(state)
            paths: List[Dict[str, Any]] = []
            paths.extend(self._block(stmt.body, _copy_path(current, "try-body"),
                                     depth + 1))
            for index, handler in enumerate(stmt.handlers):
                handler_seed = _copy_path(current, "except-%d" % index)
                if handler.name:
                    handler_seed.setdefault("env", {})[str(handler.name)] = _state(
                        "unknown", [str(handler.name)])
                paths.extend(self._block(handler.body, handler_seed, depth + 1))
            if stmt.orelse:
                paths.extend(self._block(stmt.orelse, _copy_path(current, "try-else"),
                                         depth + 1))
            if stmt.finalbody:
                finalized: List[Dict[str, Any]] = []
                for item in paths or [current]:
                    finalized.extend(self._block(
                        stmt.finalbody, _copy_path(item, "finally"), depth + 1))
                paths = finalized
            return _limit_states(paths or [current])

        if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
            current = _copy_state(state)
            loop_states: List[Dict[str, Any]] = [_copy_path(current, "loop-zero")]
            body_seed = _copy_path(current, "loop-body")
            if isinstance(stmt, (ast.For, ast.AsyncFor)):
                self._assign(body_seed, stmt.target, _state("unknown"))
            body_states = self._block(stmt.body, body_seed, depth + 1)
            loop_states.extend(body_states)
            if stmt.orelse:
                loop_states.extend(self._block(
                    stmt.orelse, _copy_path(current, "loop-else"), depth + 1))
            return _limit_states(loop_states)

        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            current = _copy_state(state)
            return self._block(stmt.body, _copy_path(current, "with"), depth + 1)

        if hasattr(ast, "Match") and isinstance(stmt, ast.Match):
            paths = [_copy_path(state, "match-none")]
            for index, case in enumerate(stmt.cases):
                paths.extend(self._block(
                    case.body, _copy_path(state, "match-%d" % index), depth + 1))
            return _limit_states(paths)

        current = _copy_state(state)
        if self._contains(stmt, self.control_call):
            current = self._mark_control(current)
        if self._contains(stmt, self.sink_call):
            self._observe(current)
            return []
        current = self._simple_statement(stmt, current)
        if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
            return []
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return [current]
        return [current]


def _function_parameters(scope: Optional[ast.AST]) -> List[str]:
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return []
    args = list(getattr(scope.args, "posonlyargs", []) or [])
    args.extend(getattr(scope.args, "args", []) or [])
    args.extend(getattr(scope.args, "kwonlyargs", []) or [])
    if scope.args.vararg:
        args.append(scope.args.vararg)
    if scope.args.kwarg:
        args.append(scope.args.kwarg)
    return [str(item.arg) for item in args if getattr(item, "arg", "")]


def _aggregate_observations(observations: Sequence[Mapping[str, Any]]) -> str:
    relations = {str(item.get("relation") or "ast-unresolved")
                 for item in observations}
    if not relations:
        return "ast-sink-not-reached"
    if relations == {"ast-bound"}:
        return "ast-bound"
    if relations == {"ast-guard-condition"}:
        return "ast-guard-condition"
    if relations == {"ast-raw-at-sink"}:
        return "ast-raw-at-sink"
    if relations == {"ast-sink-unrelated"}:
        return "ast-sink-unrelated"
    if "ast-raw-at-sink" in relations or "ast-guard-condition" in relations:
        return "ast-branch-merged"
    if "ast-derived-value" in relations:
        return "ast-derived-value"
    if "ast-unresolved" in relations:
        return "ast-unresolved"
    return "ast-branch-merged"


def _candidate(flow: Mapping[str, Any], transform: Mapping[str, Any],
               binding: Mapping[str, Any]) -> Dict[str, Any]:
    relation = str(binding.get("relation") or "ast-unresolved")
    flow_id = str(flow.get("flow_id") or "")
    control_id = str(transform.get("control_id") or "")
    sink = dict(flow.get("sink") or {})
    sink_category = str(sink.get("category") or "sink")
    category = "exec" if sink_category == "command-exec" else "logic"
    locations: List[str] = []
    for location in (
            _location((flow.get("entry") or {}).get("file"),
                      (flow.get("entry") or {}).get("line")),
            _location(transform.get("file"), transform.get("line")),
            _location(sink.get("file"), sink.get("line"))):
        if location and location not in locations:
            locations.append(location)
    if relation == "ast-raw-at-sink":
        hypothesis = "Python AST 值流显示 sink 仍可能消费原始输入；需人工确认分支、API 语义和真实执行路径"
    elif relation == "ast-branch-merged":
        hypothesis = "不同 AST 路径对同一 sink 输入产生变换后值与原始/未解析值；需逐路径复核"
    elif relation == "ast-derived-value":
        hypothesis = "变换后的值经过表达式或未知调用后进入 sink；需确认类型、编码和真实效果"
    elif relation in {"unsupported-language", "ast-parse-failed",
                      "ast-source-unreadable"}:
        hypothesis = "语言感知值流适配器未能解析该路径；需补充对应语言或源码证据"
    else:
        hypothesis = "语言感知值流仍未闭合控制结果到 sink 的绑定；需人工补充数据流与运行时证据"
    return {
        "candidate_id": _stable_id("pybind", flow_id, control_id, relation),
        "surface": "semantic-python-binding-gap",
        "entry": str((flow.get("entry") or {}).get("api")
                      or (flow.get("entry") or {}).get("entry_id") or ""),
        "input_shape": str((flow.get("entry") or {}).get("input_shape") or "unknown"),
        "logic": "python-ast-value-binding: %s" % relation,
        "hypothesis": hypothesis,
        "precondition_tier_hint": "app-cooperation"
        if relation in {"unsupported-language", "ast-parse-failed",
                        "ast-source-unreadable", "ast-cross-scope-unresolved"}
        else "single-feature",
        "preconditions": [
            "需确认入口在目标默认配置下可达且 sink 确实消费该参数",
            "需确认控制 API 的真实返回、原地修改、异常和类型语义",
            "需逐分支补充装饰器、动态调用、别名和框架拦截器证据",
        ],
        "poc_class": control_rules.poc_class_for(
            _stable_id("pybind", flow_id, control_id, relation)),
        "jvm": {},
        "target_classes": [],
        "authz_cases": [],
        "chain_components": ["request-input", category, sink_category],
        "novelty_keywords": sorted({"semantic-python-binding-gap", relation,
                                     sink_category}),
        "code_location": locations,
        "category": category,
        "flow_id": flow_id,
        "entry_id": str(flow.get("entry_id") or ""),
        "sink_id": str(flow.get("sink_id") or ""),
        "control_id": control_id,
        "path": list(flow.get("path") or []),
        "binding_relation": relation,
        "lexical_relation": str(transform.get("relation") or ""),
        "adapter": str(binding.get("adapter") or "python-ast-value-flow"),
        "requires_manual_dataflow": True,
        "source": "semantic-python-binding",
        "producer": "semantic-python-binding",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "claim_status": CLAIM_STATUS,
    }


def _unsupported_row(flow: Mapping[str, Any], transform: Mapping[str, Any],
                     reason: str, adapter: str = "unsupported") -> Dict[str, Any]:
    return {
        "control_id": str(transform.get("control_id") or ""),
        "category": control_rules.normalize_category(transform.get("category")),
        "file": str(transform.get("file") or ""),
        "line": _int(transform.get("line")),
        "symbol_id": str(transform.get("symbol_id") or ""),
        "lexical_relation": str(transform.get("relation") or ""),
        "relation": reason,
        "adapter": adapter,
        "parser": "unavailable",
        "parse_status": reason,
        "control_input_variables": list(transform.get("input_variables") or []),
        "sink_variables": list(transform.get("sink_variables") or []),
        "path_count": 0,
        "observed_relations": {},
        "claim_status": CLAIM_STATUS,
        "producer": "semantic-python-binding",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "requires_manual_dataflow": True,
    }


def build_semantic_binding_evidence(
        root: Path, semantic_transform_evidence: Mapping[str, Any],
        symbols: Sequence[Any]) -> Dict[str, Any]:
    """Build bounded AST value-flow evidence for transform rows."""
    root = Path(root).resolve()
    symbol_map = {str(_field(item, "symbol_id", "")): item for item in symbols
                  if str(_field(item, "symbol_id", ""))}
    text_cache: Dict[str, Optional[str]] = {}
    index_cache: "OrderedDict[str, _PythonIndex]" = OrderedDict()
    flow_rows: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    relation_counts: Counter = Counter()
    parser_status_by_file: Dict[str, Set[str]] = {}
    files_seen: Set[str] = set()

    source_flows = semantic_transform_evidence.get("flows") or [] \
        if isinstance(semantic_transform_evidence, Mapping) else []
    for flow in sorted(source_flows,
                       key=lambda item: str(item.get("flow_id") or "")):
        sink = dict(flow.get("sink") or {})
        controls: List[Dict[str, Any]] = []
        for transform in flow.get("transforms") or []:
            transform = dict(transform)
            file_name = str(transform.get("file") or sink.get("file") or "")
            files_seen.add(file_name)
            symbol_id = str(transform.get("symbol_id") or "")
            sink_symbol = str(flow.get("sink_symbol") or "")
            if (not file_name or file_name != str(sink.get("file") or "")
                    or not symbol_id or symbol_id != sink_symbol):
                binding = _unsupported_row(flow, transform,
                                           "ast-cross-scope-unresolved",
                                           "python-ast-value-flow")
            else:
                symbol = symbol_map.get(symbol_id)
                language = str(_field(symbol, "language", "") or "").lower()
                if language and language != "python":
                    binding = _unsupported_row(flow, transform,
                                               "unsupported-language",
                                               "%s-ast-value-flow" % language)
                elif Path(file_name).suffix.lower() not in _PYTHON_SUFFIXES:
                    binding = _unsupported_row(flow, transform,
                                               "unsupported-language",
                                               "suffix-ast-value-flow")
                elif symbol is None:
                    binding = _unsupported_row(flow, transform,
                                               "ast-cross-scope-unresolved",
                                               "python-ast-value-flow")
                else:
                    if file_name not in index_cache:
                        if len(index_cache) >= _MAX_AST_FILES:
                            index_cache.popitem(last=False)
                        index_cache[file_name] = _PythonIndex(
                            file_name, _read_text(root, file_name, text_cache))
                    else:
                        index_cache.move_to_end(file_name)
                    index = index_cache[file_name]
                    if index.status != "parsed":
                        binding = _unsupported_row(flow, transform,
                                                   "ast-%s" % index.status,
                                                   "python-ast-value-flow")
                        binding["parse_error"] = index.error_kind
                    else:
                        control_line = _int(transform.get("line"))
                        sink_line = _int(sink.get("line"))
                        scope, scope_info = index.scope_for(
                            {"start_line": _field(symbol, "start_line", 0),
                             "end_line": _field(symbol, "end_line", 0)},
                            control_line, sink_line)
                        names = _call_names(transform)
                        control_calls = index.calls_at(scope, control_line, names) \
                            if scope is not None else []
                        sink_names = {str(sink.get("api") or "").rsplit(".", 1)[-1].lower()}
                        sink_calls = index.calls_at(scope, sink_line, sink_names) \
                            if scope is not None else []
                        if scope is None:
                            binding = _unsupported_row(
                                flow, transform, "ast-cross-scope-unresolved",
                                "python-ast-value-flow")
                        elif not control_calls:
                            binding = _unsupported_row(
                                flow, transform, "ast-control-unresolved",
                                "python-ast-value-flow")
                        elif not sink_calls:
                            binding = _unsupported_row(
                                flow, transform, "ast-sink-unresolved",
                                "python-ast-value-flow")
                        elif control_line > sink_line:
                            binding = _unsupported_row(
                                flow, transform, "ast-after-sink",
                                "python-ast-value-flow")
                        else:
                            control_call = control_calls[0]
                            sink_call = sink_calls[0]
                            input_variables = _expr_dependencies(control_call)
                            analyzer = _FlowAnalyzer(
                                scope, control_call, sink_call, input_variables,
                                _function_parameters(scope))
                            observations = analyzer.run()
                            relation = _aggregate_observations(observations)
                            relation_counter = Counter(
                                str(item.get("relation") or "ast-unresolved")
                                for item in observations)
                            binding = {
                                "control_id": str(transform.get("control_id") or ""),
                                "category": control_rules.normalize_category(
                                    transform.get("category")),
                                "file": file_name,
                                "line": control_line,
                                "symbol_id": symbol_id,
                                "lexical_relation": str(
                                    transform.get("relation") or ""),
                                "relation": relation,
                                "adapter": "python-ast-value-flow",
                                "parser": "python-ast-value-flow",
                                "parse_status": index.status,
                                "scope": scope_info,
                                "control_input_variables": sorted(input_variables)[:16],
                                "sink_variables": list(
                                    transform.get("sink_variables") or []),
                                "path_count": len(observations),
                                "observed_relations": dict(sorted(
                                    relation_counter.items())),
                                "depth_limited": bool(analyzer.depth_limited),
                                "claim_status": CLAIM_STATUS,
                                "producer": "semantic-python-binding",
                                "confidence": CONFIDENCE,
                                "evidence_type": EVIDENCE_TYPE,
                                "requires_manual_dataflow": True,
                            }
            relation = str(binding.get("relation") or "ast-unresolved")
            relation_counts[relation] += 1
            parse_status = str(binding.get("parse_status") or "unavailable")
            if file_name:
                parser_status_by_file.setdefault(file_name, set()).add(parse_status)
            controls.append(binding)
            static_verdict = str(flow.get("static_control_verdict") or "")
            if (relation in _CANDIDATE_RELATIONS
                    and static_verdict in (control_rules.VERDICT_GUARDED,
                                           control_rules.VERDICT_PARTIAL)
                    and transform.get("required_category")):
                candidates.append(_candidate(flow, transform, binding))
        row = {
            "flow_id": str(flow.get("flow_id") or ""),
            "entry_id": str(flow.get("entry_id") or ""),
            "sink_id": str(flow.get("sink_id") or ""),
            "source_symbol": str(flow.get("source_symbol") or ""),
            "sink_symbol": str(flow.get("sink_symbol") or ""),
            "path": list(flow.get("path") or []),
            "entry": dict(flow.get("entry") or {}),
            "sink": sink,
            "static_control_verdict": str(flow.get("static_control_verdict") or ""),
            "controls": controls,
            "semantic_binding_verdict": (
                "bound" if controls and all(item.get("relation") == "ast-bound"
                                             for item in controls)
                else "unresolved" if controls else "not-applicable"),
            "required_manual_checks": [
                "verify the complete CFG, dominance, exceptions, loops and path feasibility",
                "verify control API return/mutation/type semantics and dynamic dispatch",
                "verify runtime typed effect and safe-equivalent behavior before any claim",
            ],
            "claim_status": CLAIM_STATUS,
            "producer": "semantic-python-binding",
            "confidence": CONFIDENCE,
            "evidence_type": EVIDENCE_TYPE,
        }
        flow_rows.append(row)

    candidates.sort(key=lambda item: (
        str(item.get("flow_id") or ""), str(item.get("control_id") or ""),
        str(item.get("candidate_id") or "")))
    summary = {
        "flows": len(flow_rows),
        "controls": sum(len(item.get("controls") or []) for item in flow_rows),
        "files": len(files_seen),
        "parsed_files": len([name for name in files_seen
                              if "parsed" in parser_status_by_file.get(name, set())]),
        "parser_status": dict(sorted(Counter(
            status for statuses in parser_status_by_file.values()
            for status in statuses).items())),
        "relations": dict(sorted(relation_counts.items())),
        "candidates": len(candidates),
        "claim_status": CLAIM_STATUS,
        "producer": "semantic-python-binding",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "limitations": list(_LIMITATIONS),
    }
    return {
        "schema_version": SEMANTIC_BINDING_VERSION,
        "summary": summary,
        "flows": flow_rows,
        "candidates": candidates,
        "claim_status": CLAIM_STATUS,
        "producer": "semantic-python-binding",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "limitations": list(_LIMITATIONS),
    }


def load_semantic_binding_evidence(store: Any) -> Dict[str, Any]:
    data = store.read(SEMANTIC_BINDING_INDEX)
    return data if isinstance(data, dict) else {}


def load_semantic_binding_candidates(store: Any) -> List[Dict[str, Any]]:
    data = store.read(SEMANTIC_BINDING_CANDIDATE_INDEX)
    return [item for item in data if isinstance(item, dict)] \
        if isinstance(data, list) else []


def render_semantic_bindings_text(evidence: Mapping[str, Any], lang: str = "zh",
                                  limit: int = 20) -> str:
    summary = dict(evidence.get("summary") or {}) \
        if isinstance(evidence, Mapping) else {}
    candidates = list(evidence.get("candidates") or []) \
        if isinstance(evidence, Mapping) else []
    if lang == "en":
        lines = [
            "Language-aware value binding evidence (static research leads)",
            "─" * 60,
            "  flows %s  controls %s  parsed files %s/%s  candidates %s" % (
                summary.get("flows", 0), summary.get("controls", 0),
                summary.get("parsed_files", 0), summary.get("files", 0),
                summary.get("candidates", 0)),
            "  relations %s" % (summary.get("relations") or {}),
            "  leads:",
        ]
    else:
        lines = [
            "语言感知值绑定证据（静态研究线索）", "─" * 60,
            "  路径 %s  控制 %s  已解析文件 %s/%s  候选 %s" % (
                summary.get("flows", 0), summary.get("controls", 0),
                summary.get("parsed_files", 0), summary.get("files", 0),
                summary.get("candidates", 0)),
            "  关系 %s" % (summary.get("relations") or {}),
            "  待验证线索：",
        ]
    for candidate in candidates[:max(0, limit)]:
        lines.append("    %-24s %-26s %s" % (
            candidate.get("candidate_id", ""),
            candidate.get("binding_relation", ""),
            ",".join(candidate.get("code_location") or []) or "-"))
    if len(candidates) > limit:
        lines.append("    ... %d more" % (len(candidates) - limit))
    return "\n".join(lines)
