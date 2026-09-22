"""Bounded syntax-tree control-flow witnesses for security review.

``semantic_controlflow`` deliberately works for many brace/indent languages,
but its intervals cannot tell whether a sink is in an ``else`` body, an
exception handler, or a function-local statement that merely shares a line
range with another construct.  This module adds a syntax-aware bridge for
Python files using the standard-library AST and Java files using the JDK
compiler parser in parse-only mode.

The result is still a review lead, not a CFG or a vulnerability proof.  It
records branch membership, scope identity, negative-test shape, and explicit
terminal statements without storing source text, payloads, or AST dumps.  A
parse failure is preserved as an environment/analysis gap rather than being
silently treated as a negative result.
"""

from __future__ import annotations

import ast
import hashlib
from collections import Counter, OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from . import controls as control_rules
from .semantic_frontend import (FrontendSession, ParsedUnit, SyntaxFact,
                                MAX_FILES, MAX_NODES)


SEMANTIC_AST_INDEX = "semantic-ast-evidence"
SEMANTIC_AST_CANDIDATE_INDEX = "semantic-ast-candidates"
SEMANTIC_AST_VERSION = "semantic-ast-evidence-v2"
CLAIM_STATUS = "not-a-finding"
CONFIDENCE = "heuristic-nearby"
EVIDENCE_TYPE = "static-inferred"

_MAX_AST_NODES = MAX_NODES
_CANDIDATE_RELATIONS = frozenset({
    "ast-alternate-path",
    "ast-same-block-unverified",
    "ast-path-unresolved",
    "ast-cross-scope-unverified",
    "ast-parse-failed",
})
_TERMINAL_NODES = (ast.Return, ast.Raise, ast.Break, ast.Continue)

_LIMITATIONS = (
    "syntax-tree membership is syntax-aware but does not implement a complete CFG, dominance, SSA or path-feasibility analysis",
    "Java uses JavacTask.parse only; it does not resolve types, overloads, virtual dispatch, classpaths, annotation semantics or runtime configuration",
    "terminal statements inside nested conditionals, loops, exception handlers and finally blocks are only structural witnesses",
    "dynamic dispatch, decorators, imports, monkey-patching, reflection, type identity, sanitizer semantics and runtime configuration remain unresolved",
    "parse failures, unavailable JDKs and unsupported languages are analysis gaps, never negative security evidence",
    "all rows and candidates are static review leads, never proof of a vulnerability or proof of safety",
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


def _span(node: Any) -> Tuple[int, int]:
    start = _int(getattr(node, "lineno", 0))
    end = _int(getattr(node, "end_lineno", 0)) or start
    return start, max(start, end)


def _block_span(nodes: Sequence[Any]) -> Optional[Tuple[int, int]]:
    if not nodes:
        return None
    spans = [_span(node) for node in nodes if _span(node)[0] > 0]
    if not spans:
        return None
    return min(item[0] for item in spans), max(item[1] for item in spans)


def _contains(span: Optional[Tuple[int, int]], line: int) -> bool:
    return bool(span and span[0] <= line <= span[1])


def _stable(value: str, prefix: str, length: int = 14) -> str:
    return "%s-%s" % (prefix, hashlib.sha256(value.encode("utf-8")).hexdigest()[:length])


def _public_span(span: Optional[Tuple[int, int]]) -> Dict[str, int]:
    if not span:
        return {}
    return {"start": int(span[0]), "end": int(span[1])}


def _scope_record(kind: str, node: Any) -> Dict[str, Any]:
    start, end = _span(node)
    return {
        "kind": kind,
        "start": start,
        "end": end,
    }


def _scope_key(scope: Mapping[str, Any]) -> Tuple[str, int, int]:
    return (str(scope.get("kind") or "module"),
            _int(scope.get("start")), _int(scope.get("end")))


def _branch_record(file_name: str, kind: str, node: Any,
                   scope: Mapping[str, Any], index: int,
                   parts: Sequence[Tuple[str, Optional[Tuple[int, int]]]],
                   test_span: Optional[Tuple[int, int]] = None,
                   terminal: str = "none",
                   negative: bool = False) -> Dict[str, Any]:
    header_line = _int(getattr(node, "lineno", 0))
    branch_id = _stable(
        "%s|%s|%s|%s|%s" % (
            file_name, kind, header_line, _scope_key(scope), index),
        "ast-branch")
    normalized_parts = []
    for name, span in parts:
        normalized_parts.append({
            "part": name,
            "span": _public_span(span),
        })
    return {
        "branch_id": branch_id,
        "kind": kind,
        "header_line": header_line,
        "scope": dict(scope),
        "parts": normalized_parts,
        "test_span": _public_span(test_span),
        "terminal": terminal,
        "negative_test": bool(negative),
    }


def _terminal_shape(nodes: Sequence[Any]) -> str:
    """Return a bounded terminal statement kind from a branch's direct body."""
    for node in nodes:
        if isinstance(node, ast.Return):
            return "return"
        if isinstance(node, ast.Raise):
            return "raise"
        if isinstance(node, ast.Break):
            return "break"
        if isinstance(node, ast.Continue):
            return "continue"
    return "none"


def _negative_test(node: Any) -> bool:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return True
    if isinstance(node, ast.Compare):
        return any(isinstance(op, (ast.NotEq, ast.IsNot, ast.NotIn))
                   for op in node.ops)
    return False


def _node_kind(node: Any) -> str:
    if isinstance(node, SyntaxFact):
        return node.kind
    return type(node).__name__ if node is not None else ""


_NODE_PRIORITY = {
    "Call": 0,
    "If": 1,
    "Try": 1,
    "Match": 1,
    "For": 2,
    "AsyncFor": 2,
    "While": 2,
    "Return": 3,
    "Raise": 3,
    "Assign": 4,
    "AnnAssign": 4,
    "Expr": 5,
}


class _AstIndex:
    """Small syntax index kept in memory for one target scan."""

    def __init__(self, file_name: str, unit: ParsedUnit):
        self.file_name = file_name
        self.status = "parsed"
        self.error_kind = ""
        self.tree: Optional[ast.AST] = None
        self.nodes: List[Tuple[ast.AST, Dict[str, Any]]] = []
        self.branches: List[Dict[str, Any]] = []
        self.scopes: List[Dict[str, Any]] = []
        self.node_count = 0
        self.module_end = 1
        self._scope_cache: Dict[int, Dict[str, Any]] = {}
        self._branches_cache: Dict[int, List[Tuple[Dict[str, Any], str]]] = {}
        self._control_cache: Dict[int, Optional[Dict[str, Any]]] = {}
        self._node_cache: Dict[int, Optional[ast.AST]] = {}
        self.source_revision = unit.source_revision
        self.analysis_gaps = list(unit.analysis_gaps)
        self.parser = unit.parser
        self._parse(unit)

    def _parse(self, unit: ParsedUnit) -> None:
        self.status = {"parse-failed": "syntax-error", "source-unreadable": "unreadable"}.get(unit.status, unit.status)
        self.error_kind = unit.error_kind
        self.tree = unit.tree
        if self.status != "parsed":
            return
        module_end = max(
            (_span(node)[1] for node in ast.walk(self.tree)
             if _span(node)[1] > 0), default=1)
        self.module_end = module_end
        module_scope = {"kind": "module", "start": 1, "end": module_end}
        self._walk(self.tree, module_scope, [])
        if self.node_count > _MAX_AST_NODES:
            self.status = "node-limit"
            self.error_kind = "ast-node-limit"
            self.nodes = []
            self.branches = []

    def _walk(self, node: ast.AST, scope: Mapping[str, Any],
              ancestors: Sequence[Dict[str, Any]]) -> None:
        self.node_count += 1
        if self.node_count > _MAX_AST_NODES:
            return
        self.nodes.append((node, dict(scope)))

        current_scope = dict(scope)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            current_scope = _scope_record("function", node)
            self.scopes.append(dict(current_scope))
        elif isinstance(node, ast.ClassDef):
            current_scope = _scope_record("class", node)
            self.scopes.append(dict(current_scope))

        if isinstance(node, ast.If):
            self._add_if(node, current_scope, len(self.branches))
        elif isinstance(node, ast.Try):
            self._add_try(node, current_scope, len(self.branches))
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            self._add_loop(node, current_scope, len(self.branches))
        else:
            match_type = getattr(ast, "Match", None)
            if match_type is not None and isinstance(node, match_type):
                self._add_match(node, current_scope, len(self.branches))

        for child in ast.iter_child_nodes(node):
            self._walk(child, current_scope, ancestors)

    def _add_if(self, node: ast.If, scope: Mapping[str, Any], index: int) -> None:
        self.branches.append(_branch_record(
            self.file_name, "if", node, scope, index,
            (("test", _span(node.test)),
             ("body", _block_span(node.body)),
             ("orelse", _block_span(node.orelse))),
            test_span=_span(node.test),
            terminal=_terminal_shape(node.body),
            negative=_negative_test(node.test)))

    def _add_try(self, node: ast.Try, scope: Mapping[str, Any], index: int) -> None:
        parts: List[Tuple[str, Optional[Tuple[int, int]]]] = [
            ("body", _block_span(node.body)),
            ("orelse", _block_span(node.orelse)),
            ("finally", _block_span(node.finalbody)),
        ]
        for handler_index, handler in enumerate(node.handlers):
            parts.append(("handler-%d" % handler_index,
                          _block_span(handler.body)))
        self.branches.append(_branch_record(
            self.file_name, "try", node, scope, index, parts,
            test_span=_span(node), terminal=_terminal_shape(node.body)))

    def _add_loop(self, node: Any, scope: Mapping[str, Any], index: int) -> None:
        self.branches.append(_branch_record(
            self.file_name, "loop", node, scope, index,
            (("body", _block_span(node.body)),
             ("orelse", _block_span(node.orelse))),
            test_span=_span(node), terminal=_terminal_shape(node.body)))

    def _add_match(self, node: Any, scope: Mapping[str, Any], index: int) -> None:
        parts: List[Tuple[str, Optional[Tuple[int, int]]]] = []
        for case_index, case in enumerate(node.cases):
            parts.append(("case-%d" % case_index, _block_span(case.body)))
        self.branches.append(_branch_record(
            self.file_name, "match", node, scope, index, parts,
            test_span=_span(node)))

    def scopes_at(self, line: int) -> List[Dict[str, Any]]:
        scopes = [dict(scope) for scope in self.scopes
                  if _contains((
                      _int(scope.get("start")), _int(scope.get("end"))), line)]
        scopes.sort(key=lambda item: (
            _int(item.get("end")) - _int(item.get("start")),
            -_int(item.get("start"))))
        return scopes

    def scope_at(self, line: int) -> Dict[str, Any]:
        if line in self._scope_cache:
            return dict(self._scope_cache[line])
        scopes = self.scopes_at(line)
        result = scopes[0] if scopes else {"kind": "module", "start": 1,
                                            "end": self.module_end}
        self._scope_cache[line] = dict(result)
        return dict(result)

    def branches_at(self, line: int) -> List[Tuple[Dict[str, Any], str]]:
        if line in self._branches_cache:
            return list(self._branches_cache[line])
        hits: List[Tuple[Dict[str, Any], str]] = []
        for branch in self.branches:
            for part in branch.get("parts") or []:
                span = part.get("span") or {}
                if _contains((_int(span.get("start")), _int(span.get("end"))),
                             line):
                    hits.append((branch, str(part.get("part") or "")))
                    break
        hits.sort(key=lambda item: (
            _int(item[0].get("scope", {}).get("end"))
            - _int(item[0].get("scope", {}).get("start")),
            -_int(item[0].get("header_line"))))
        self._branches_cache[line] = list(hits)
        return hits

    def branch_for_control(self, line: int) -> Optional[Dict[str, Any]]:
        if line in self._control_cache:
            branch = self._control_cache[line]
            return dict(branch) if branch else None
        candidates = []
        for branch in self.branches:
            test = branch.get("test_span") or {}
            test_span = (_int(test.get("start")), _int(test.get("end")))
            if _contains(test_span, line) or _int(branch.get("header_line")) == line:
                candidates.append(branch)
        if candidates:
            result = sorted(candidates, key=lambda item: (
                _int(item.get("test_span", {}).get("end"))
                - _int(item.get("test_span", {}).get("start")),
                _int(item.get("header_line"))))[0]
            self._control_cache[line] = dict(result)
            return dict(result)
        self._control_cache[line] = None
        return None

    def node_at(self, line: int) -> Optional[ast.AST]:
        if line in self._node_cache:
            return self._node_cache[line]
        candidates = [node for node, _scope in self.nodes
                      if _contains(_span(node), line)]
        if not candidates:
            self._node_cache[line] = None
            return None
        result = sorted(candidates, key=lambda node: (
            _span(node)[1] - _span(node)[0],
            _NODE_PRIORITY.get(_node_kind(node), 10),
            -_span(node)[0]))[0]
        self._node_cache[line] = result
        return result


class _JavaAstIndex:
    """Adapter over parse-only JDK facts with the same relation surface.

    It deliberately exposes only structural syntax facts supplied by
    :class:`JavaFrontend`: declaration ranges, branch body ranges and direct
    terminal shape.  No type or control-flow resolution is inferred here.
    """

    def __init__(self, file_name: str, unit: ParsedUnit):
        self.file_name = file_name
        self.status = {"parse-failed": "syntax-error",
                       "source-unreadable": "unreadable"}.get(unit.status,
                                                                  unit.status)
        self.error_kind = unit.error_kind
        self.source_revision = unit.source_revision
        self.analysis_gaps = list(unit.analysis_gaps)
        self.parser = unit.parser
        self.module_end = max(1, unit.line_count)
        self.scopes: List[Dict[str, Any]] = []
        self.branches: List[Dict[str, Any]] = []
        self.nodes: List[SyntaxFact] = list(unit.facts)
        self._scope_cache: Dict[int, Dict[str, Any]] = {}
        self._branches_cache: Dict[int, List[Tuple[Dict[str, Any], str]]] = {}
        self._control_cache: Dict[int, Optional[Dict[str, Any]]] = {}
        self._node_cache: Dict[int, Optional[SyntaxFact]] = {}
        if self.status != "parsed":
            return
        for fact in unit.select("symbol"):
            kind = str(fact.attributes.get("symbol_kind") or "symbol")
            self.scopes.append({"kind": kind, "start": fact.line,
                                "end": max(fact.line, fact.end_line),
                                "name": fact.name})
        for index, fact in enumerate(unit.select("branch")):
            attributes = fact.attributes
            body = dict(attributes.get("body_span") or {})
            alternate = dict(attributes.get("alternate_span") or {})
            test = dict(attributes.get("test_span") or {})
            scope = self.scope_at(fact.line)
            parts = [("body", body), ("alternate", alternate)]
            self.branches.append({
                "branch_id": _stable("%s|%s|%s|%s" % (
                    file_name, fact.line,
                    str(attributes.get("branch_kind") or "branch"), index),
                    "ast-branch"),
                "kind": str(attributes.get("branch_kind") or "branch"),
                "header_line": fact.line,
                "scope": scope,
                "parts": [{"part": name, "span": {
                    "start": _int(value.get("start")),
                    "end": _int(value.get("end"))}}
                          for name, value in parts
                          if _int(value.get("start"))],
                "test_span": {"start": _int(test.get("start")),
                              "end": _int(test.get("end"))},
                "terminal": str(attributes.get("terminal") or "none"),
                "negative_test": bool(attributes.get("negative_test")),
            })

    def scopes_at(self, line: int) -> List[Dict[str, Any]]:
        scopes = [dict(scope) for scope in self.scopes
                  if _contains((_int(scope.get("start")), _int(scope.get("end"))),
                               line)]
        scopes.sort(key=lambda item: (
            _int(item.get("end")) - _int(item.get("start")),
            -_int(item.get("start"))))
        return scopes

    def scope_at(self, line: int) -> Dict[str, Any]:
        if line in self._scope_cache:
            return dict(self._scope_cache[line])
        scopes = self.scopes_at(line)
        result = scopes[0] if scopes else {"kind": "module", "start": 1,
                                            "end": self.module_end}
        self._scope_cache[line] = dict(result)
        return dict(result)

    def branches_at(self, line: int) -> List[Tuple[Dict[str, Any], str]]:
        if line in self._branches_cache:
            return list(self._branches_cache[line])
        hits: List[Tuple[Dict[str, Any], str]] = []
        for branch in self.branches:
            for part in branch.get("parts") or []:
                span = part.get("span") or {}
                if _contains((_int(span.get("start")), _int(span.get("end"))),
                             line):
                    hits.append((branch, str(part.get("part") or "")))
                    break
        hits.sort(key=lambda item: (
            _int(item[0].get("scope", {}).get("end"))
            - _int(item[0].get("scope", {}).get("start")),
            -_int(item[0].get("header_line"))))
        self._branches_cache[line] = list(hits)
        return hits

    def branch_for_control(self, line: int) -> Optional[Dict[str, Any]]:
        if line in self._control_cache:
            branch = self._control_cache[line]
            return dict(branch) if branch else None
        candidates = []
        for branch in self.branches:
            test = branch.get("test_span") or {}
            if (_contains((_int(test.get("start")), _int(test.get("end"))), line)
                    or _int(branch.get("header_line")) == line):
                candidates.append(branch)
        if candidates:
            result = sorted(candidates, key=lambda item: (
                _int(item.get("test_span", {}).get("end"))
                - _int(item.get("test_span", {}).get("start")),
                _int(item.get("header_line"))))[0]
            self._control_cache[line] = dict(result)
            return dict(result)
        self._control_cache[line] = None
        return None

    def node_at(self, line: int) -> Optional[SyntaxFact]:
        if line in self._node_cache:
            return self._node_cache[line]
        candidates = [fact for fact in self.nodes
                      if fact.line <= line <= max(fact.line, fact.end_line)]
        if not candidates:
            self._node_cache[line] = None
            return None
        priority = {"call": 0, "branch": 1, "return": 2,
                    "assignment": 3, "symbol": 4}
        result = sorted(candidates, key=lambda fact: (
            fact.end_line - fact.line, priority.get(fact.kind, 10),
            -fact.line))[0]
        self._node_cache[line] = result
        return result


def _public_branch(branch: Optional[Mapping[str, Any]], part: str = "") -> Dict[str, Any]:
    if not branch:
        return {}
    result = {
        "branch_id": str(branch.get("branch_id") or ""),
        "kind": str(branch.get("kind") or ""),
        "header_line": _int(branch.get("header_line")),
        "part": part,
        "terminal": str(branch.get("terminal") or "none"),
        "negative_test": bool(branch.get("negative_test")),
    }
    return result


def _relation(index: Any, control: Mapping[str, Any],
              sink: Mapping[str, Any],
              fallback: Mapping[str, Any]) -> Dict[str, Any]:
    control_line = _int(control.get("line"))
    sink_line = _int(sink.get("line"))
    control_scope = index.scope_at(control_line)
    sink_scope = index.scope_at(sink_line)
    relation: Dict[str, Any] = {
        "relation": "ast-path-unresolved",
        "parser": index.parser,
        "source_revision": index.source_revision,
        "analysis_gaps": list(index.analysis_gaps),
        "parse_status": index.status,
        "control_line": control_line,
        "sink_line": sink_line,
        "control_node_kind": _node_kind(index.node_at(control_line)),
        "sink_node_kind": _node_kind(index.node_at(sink_line)),
        "control_scope": dict(control_scope),
        "sink_scope": dict(sink_scope),
        "same_scope": _scope_key(control_scope) == _scope_key(sink_scope),
        "control_branch": {},
        "sink_branch": {},
        "alternate_branch_count": 0,
        "terminal_shape": "none",
        "fallback_relation": str(fallback.get("relation") or ""),
    }
    if index.status != "parsed":
        relation["relation"] = "ast-parse-failed"
        relation["parse_error"] = index.error_kind
        return relation
    if not relation["same_scope"]:
        relation["relation"] = "ast-cross-scope-unverified"
        return relation
    if control_line <= 0 or sink_line <= 0:
        return relation
    if control_line > sink_line:
        relation["relation"] = "ast-after-sink"
        return relation
    if control_line == sink_line:
        relation["relation"] = "ast-same-line"
        return relation

    control_branch = index.branch_for_control(control_line)
    sink_branches = index.branches_at(sink_line)
    if control_branch:
        sink_match = next((item for item in sink_branches
                           if item[0].get("branch_id")
                           == control_branch.get("branch_id")), None)
        if sink_match:
            sink_branch, sink_part = sink_match
            relation["control_branch"] = _public_branch(control_branch, "test")
            relation["sink_branch"] = _public_branch(sink_branch, sink_part)
            if sink_part == "body":
                relation["relation"] = "ast-enclosing-branch"
                relation["terminal_shape"] = str(
                    control_branch.get("terminal") or "none")
                return relation
            relation["relation"] = "ast-alternate-path"
            relation["alternate_branch_count"] = max(
                1, len([part for part in control_branch.get("parts") or []
                        if part.get("part") not in {"test", "body"}
                        and part.get("span")]))
            return relation

        relation["control_branch"] = _public_branch(control_branch, "test")
        relation["terminal_shape"] = str(control_branch.get("terminal") or "none")
        body_end = 0
        for part in control_branch.get("parts") or []:
            if part.get("part") == "body":
                body_end = _int((part.get("span") or {}).get("end"))
                break
        if (str(control_branch.get("kind")) == "if"
                and bool(control_branch.get("negative_test"))
                and control_branch.get("terminal") != "none"
                and sink_line > body_end):
            relation["relation"] = "ast-terminating-guard"
            return relation
        if sink_line > body_end:
            relation["relation"] = "ast-path-unresolved"
            return relation

    shared = {str(branch.get("branch_id")): part
              for branch, part in index.branches_at(control_line)}
    for branch, part in index.branches_at(sink_line):
        if str(branch.get("branch_id")) in shared and part == shared[
                str(branch.get("branch_id"))]:
            relation["control_branch"] = _public_branch(
                branch, shared[str(branch.get("branch_id"))])
            relation["sink_branch"] = _public_branch(branch, part)
            relation["relation"] = "ast-same-block-unverified"
            return relation
    relation["relation"] = "ast-same-block-unverified"
    return relation


def _location(file_name: Any, line: Any) -> str:
    return "%s:%d" % (str(file_name or ""), _int(line)) if file_name else ""


def _candidate(flow: Mapping[str, Any], guard: Mapping[str, Any],
               relation: Mapping[str, Any]) -> Dict[str, Any]:
    flow_id = str(flow.get("flow_id") or "")
    control_id = str(guard.get("control_id") or "")
    relation_name = str(relation.get("relation") or "ast-path-unresolved")
    candidate_id = _stable("%s|%s|%s" % (flow_id, control_id, relation_name),
                           "ast")
    entry = flow.get("entry") or {}
    sink = flow.get("sink") or {}
    category = ("authz" if guard.get("category") in control_rules.AUTHZ_CATEGORIES
                else "logic")
    locations: List[str] = []
    for location in (
            _location(entry.get("file"), entry.get("line")),
            _location(sink.get("file"), sink.get("line")),
            _location(guard.get("file"), guard.get("line"))):
        if location and location not in locations:
            locations.append(location)
    return {
        "candidate_id": candidate_id,
        "surface": "semantic-ast-cfg-gap",
        "entry": str(entry.get("api") or entry.get("entry_id") or ""),
        "input_shape": str(entry.get("input_shape") or "unknown"),
        "logic": "ast-control-flow: %s" % relation_name,
        "hypothesis": "语法树显示安全控制与 sink 的分支关系仍未闭合；需人工补充真实 CFG、数据流和运行时证据",
        "precondition_tier_hint": "app-cooperation"
        if relation_name in {"ast-cross-scope-unverified", "ast-parse-failed"}
        else "single-feature",
        "preconditions": [
            "需确认语法树所在文件、符号和运行配置对应实际执行路径",
            "需验证异常、循环、装饰器、动态调用、主体绑定和 sink 效果",
        ],
        "poc_class": control_rules.poc_class_for(candidate_id),
        "jvm": {},
        "target_classes": [],
        "authz_cases": control_rules.authz_cases_for()
        if category == "authz" else [],
        "chain_components": ["request-input", category,
                             str(sink.get("category") or "sink")],
        "novelty_keywords": sorted({"semantic-ast-cfg-gap", category,
                                     relation_name,
                                     str(sink.get("category") or "sink")}),
        "code_location": locations,
        "category": category,
        "flow_id": flow_id,
        "entry_id": str(flow.get("entry_id") or ""),
        "sink_id": str(flow.get("sink_id") or ""),
        "control_id": control_id,
        "path": list(flow.get("path") or []),
        "ast_relation": relation_name,
        "parser": str(relation.get("parser") or "python-ast"),
        "parse_status": str(relation.get("parse_status") or ""),
        "terminal_shape": str(relation.get("terminal_shape") or "none"),
        "requires_manual_dataflow": True,
        "source": "semantic-ast",
        "producer": "semantic-ast",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "claim_status": CLAIM_STATUS,
    }


def build_semantic_ast_evidence(
        root: Path, semantic_controlflow_evidence: Mapping[str, Any],
        frontend_session: Optional[FrontendSession] = None
        ) -> Dict[str, Any]:
    """Build syntax-aware Python/Java branch witnesses from control-flow rows."""
    root = Path(root).resolve()
    frontend_session = frontend_session or FrontendSession(root)
    index_cache: "OrderedDict[str, Any]" = OrderedDict()
    parser_status_by_file: Dict[str, str] = {}
    flow_rows: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    relation_counts: Counter = Counter()
    files_seen = set()
    ordered_flows = sorted(
        semantic_controlflow_evidence.get("flows") or [],
        key=lambda item: str(item.get("flow_id") or ""))

    for flow in ordered_flows:
        sink = dict(flow.get("sink") or {})
        controls: List[Dict[str, Any]] = []
        sink_file = str(sink.get("file") or "")
        for guard in flow.get("controls") or []:
            guard = dict(guard)
            file_name = str(guard.get("file") or sink_file or "")
            if file_name not in index_cache:
                if len(index_cache) >= MAX_FILES:
                    index_cache.popitem(last=False)
                unit = frontend_session.parse(file_name)
                index_cache[file_name] = (
                    _JavaAstIndex(file_name, unit)
                    if unit.parser == "javac-ast" else _AstIndex(file_name, unit))
            index_cache.move_to_end(file_name)
            files_seen.add(file_name)
            index = index_cache[file_name]
            parser_status_by_file[file_name] = index.status
            fallback = dict(guard.get("control_flow") or {})
            relation = _relation(index, guard, sink, fallback)
            row = dict(guard)
            row["ast_control_flow"] = relation
            row.update({
                "claim_status": CLAIM_STATUS,
                "producer": "semantic-ast",
                "confidence": CONFIDENCE,
                "evidence_type": EVIDENCE_TYPE,
            })
            controls.append(row)
            relation_name = str(relation.get("relation") or "ast-path-unresolved")
            relation_counts[relation_name] += 1
            static_verdict = str(flow.get("static_control_verdict") or "")
            if (relation_name in _CANDIDATE_RELATIONS
                    and static_verdict in (control_rules.VERDICT_GUARDED,
                                           control_rules.VERDICT_PARTIAL)
                    and guard.get("required_category")):
                candidates.append(_candidate(flow, guard, relation))
        flow_rows.append({
            "flow_id": str(flow.get("flow_id") or ""),
            "entry_id": str(flow.get("entry_id") or ""),
            "sink_id": str(flow.get("sink_id") or ""),
            "path": list(flow.get("path") or []),
            "entry": dict(flow.get("entry") or {}),
            "sink": sink,
            "static_control_verdict": str(flow.get("static_control_verdict") or ""),
            "controls": controls,
            "required_manual_checks": [
                "verify the real CFG, dynamic dispatch, exception and loop paths",
                "verify source parameter, control subject, sink object and typed effect",
            ],
            "claim_status": CLAIM_STATUS,
            "producer": "semantic-ast",
            "confidence": CONFIDENCE,
            "evidence_type": EVIDENCE_TYPE,
        })

    candidates.sort(key=lambda item: (
        str(item.get("flow_id") or ""), str(item.get("control_id") or ""),
        str(item.get("candidate_id") or "")))
    parser_counts: Counter = Counter(
        parser_status_by_file[name] for name in sorted(files_seen))
    summary = {
        "flows": len(flow_rows),
        "controls": sum(len(row.get("controls") or []) for row in flow_rows),
        "files": len(files_seen),
        "parsed_files": len([name for name in files_seen
                              if parser_status_by_file[name] == "parsed"]),
        "parser_status": dict(sorted(parser_counts.items())),
        "relations": dict(sorted(relation_counts.items())),
        "candidates": len(candidates),
        "claim_status": CLAIM_STATUS,
        "producer": "semantic-ast",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "limitations": list(_LIMITATIONS),
    }
    return {
        "schema_version": SEMANTIC_AST_VERSION,
        "summary": summary,
        "flows": flow_rows,
        "candidates": candidates,
        "claim_status": CLAIM_STATUS,
        "producer": "semantic-ast",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "limitations": list(_LIMITATIONS),
    }


def load_semantic_ast(store: Any) -> Dict[str, Any]:
    data = store.read(SEMANTIC_AST_INDEX)
    return data if isinstance(data, dict) else {}


def load_semantic_ast_candidates(store: Any) -> List[Dict[str, Any]]:
    data = store.read(SEMANTIC_AST_CANDIDATE_INDEX)
    return [item for item in data if isinstance(item, dict)] \
        if isinstance(data, list) else []


def render_semantic_ast_text(evidence: Mapping[str, Any], lang: str = "zh",
                             limit: int = 20) -> str:
    summary = dict(evidence.get("summary") or {}) \
        if isinstance(evidence, Mapping) else {}
    candidates = list(evidence.get("candidates") or []) \
        if isinstance(evidence, Mapping) else []
    if lang == "en":
        lines = [
            "Syntax AST control-flow evidence",
            "─" * 56,
            "  flows %s  controls %s  parsed files %s/%s  candidates %s"
            % (summary.get("flows", 0), summary.get("controls", 0),
               summary.get("parsed_files", 0), summary.get("files", 0),
               summary.get("candidates", 0)),
            "  relations %s" % (summary.get("relations") or {}),
            "  leads:",
        ]
    else:
        lines = [
            "语法树控制流证据", "─" * 56,
            "  路径 %s  控制 %s  已解析文件 %s/%s  候选 %s" % (
                summary.get("flows", 0), summary.get("controls", 0),
                summary.get("parsed_files", 0), summary.get("files", 0),
                summary.get("candidates", 0)),
            "  关系 %s" % (summary.get("relations") or {}),
            "  待验证线索：",
        ]
    for candidate in candidates[:max(0, limit)]:
        lines.append("    %-22s %-28s %s" % (
            candidate.get("candidate_id", ""),
            candidate.get("ast_relation", ""),
            ",".join(candidate.get("code_location") or []) or "-"))
    if len(candidates) > limit:
        lines.append("    ... %d more" % (len(candidates) - limit))
    return "\n".join(lines)
