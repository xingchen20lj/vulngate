"""Shared, bounded syntax frontend. No imports or target code are executed.

The common facts are syntax, not resolved targets, typed data flow or proof of
safety. Existing symbol/semantic artifacts consume them; there is no new disk
artifact. Native AST nodes are read-only, process-local implementation details.
"""
from __future__ import annotations

import ast
import hashlib
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Protocol, Tuple

MAX_BYTES = 2_000_000
MAX_NODES = 100_000
MAX_DEPTH = 128
MAX_FILES = 8
MAX_CACHED_NODES = 200_000
CLAIM_STATUS = "not-a-finding"


@dataclass(frozen=True)
class SyntaxFact:
    fact_id: str
    kind: str
    file: str
    line: int
    end_line: int
    column: int
    end_column: int
    scope: str
    name: str = ""
    attributes: Mapping[str, Any] = field(default_factory=dict)
    node: Any = field(default=None, repr=False, compare=False)

    def as_dict(self) -> Dict[str, Any]:
        return {"fact_id": self.fact_id, "kind": self.kind, "file": self.file,
                "line": self.line, "end_line": self.end_line,
                "column": self.column, "end_column": self.end_column,
                "scope": self.scope, "name": self.name, "attributes": dict(self.attributes),
                "parser": "ast", "confidence": "ast", "claim_status": CLAIM_STATUS}


@dataclass(frozen=True)
class ParsedUnit:
    file: str
    status: str
    source_revision: str = ""
    error_kind: str = ""
    analysis_gaps: Tuple[str, ...] = ()
    tree: Any = field(default=None, repr=False, compare=False)
    facts: Tuple[SyntaxFact, ...] = ()
    node_count: int = 0
    line_count: int = 0
    parser: str = "ast"
    claim_status: str = CLAIM_STATUS

    def select(self, kind: str) -> Tuple[SyntaxFact, ...]:
        return tuple(f for f in self.facts if f.kind == kind)


class SemanticFrontend(Protocol):
    def parse(self, file: str, source: bytes) -> ParsedUnit: ...
    def symbols(self, unit: ParsedUnit) -> Tuple[SyntaxFact, ...]: ...
    def calls(self, unit: ParsedUnit) -> Tuple[SyntaxFact, ...]: ...
    def assignments(self, unit: ParsedUnit) -> Tuple[SyntaxFact, ...]: ...
    def branches(self, unit: ParsedUnit) -> Tuple[SyntaxFact, ...]: ...
    def returns(self, unit: ParsedUnit) -> Tuple[SyntaxFact, ...]: ...
    def parameters(self, unit: ParsedUnit) -> Tuple[SyntaxFact, ...]: ...
    def arguments(self, unit: ParsedUnit, call_id: str = "") -> Tuple[SyntaxFact, ...]: ...


def _parameters(node):
    args = node.args
    result = [(a, "positional-only") for a in args.posonlyargs]
    result += [(a, "positional-or-keyword") for a in args.args]
    if args.vararg:
        result.append((args.vararg, "var-positional"))
    result += [(a, "keyword-only") for a in args.kwonlyargs]
    if args.kwarg:
        result.append((args.kwarg, "var-keyword"))
    return result


def _call_name(node):
    names = []
    while isinstance(node, ast.Attribute):
        names.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        return ".".join([node.id] + list(reversed(names)))
    return ""  # e.g. factory()(), getattr(obj, name)(): no guessed target


class PythonFrontend:
    def __init__(self, max_bytes=MAX_BYTES, max_nodes=MAX_NODES, max_depth=MAX_DEPTH):
        self.max_bytes = max(0, int(max_bytes))
        self.max_nodes = max(0, int(max_nodes))
        self.max_depth = max(0, int(max_depth))

    def parse(self, file: str, source: bytes) -> ParsedUnit:
        revision = hashlib.sha256(source).hexdigest()
        lines = len(source.splitlines())

        def gap(status, error=""):
            return ParsedUnit(file, status, revision, error, (status,), line_count=lines)

        if len(source) > self.max_bytes:
            # A session may have supplied only a bounded prefix. Never label
            # that prefix hash as a revision of the complete source file.
            return ParsedUnit(file, "too-large", error_kind="ast-byte-limit",
                              analysis_gaps=("too-large",))
        try:
            # Bytes preserve Python's encoding-cookie/BOM semantics. Replacing
            # decode errors could turn invalid source into a valid, different AST.
            tree = ast.parse(source, filename=file, type_comments=False)
        except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError, UnicodeError) as exc:
            return gap("parse-failed", type(exc).__name__)
        count, pending = 0, [(tree, 0)]
        while pending:
            node, depth = pending.pop()
            count += 1
            if count > self.max_nodes:
                return gap("node-limit", "ast-node-limit")
            if depth > self.max_depth:
                return gap("depth-limit", "ast-depth-limit")
            pending.extend((c, depth + 1) for c in ast.iter_child_nodes(node))
        facts = self._facts(file, revision, tree)
        return ParsedUnit(file, "parsed", revision, tree=tree, facts=tuple(facts),
                          node_count=count, line_count=lines)

    @staticmethod
    def _facts(file, revision, tree):
        facts = []

        def add(kind, node, scope, name="", line=None, **attributes):
            start = line if line is not None else getattr(node, "lineno", 0)
            end = getattr(node, "end_lineno", start)
            column, end_column = getattr(node, "col_offset", 0), getattr(node, "end_col_offset", 0)
            identity = "%s|%s|%s|%s|%s|%s|%s" % (revision, file, kind, start, column, scope, len(facts))
            fact = SyntaxFact("syntax-" + hashlib.sha256(identity.encode()).hexdigest()[:24],
                              kind, file, start, end, column, end_column, scope, name,
                              MappingProxyType(attributes), node)
            facts.append(fact)
            return fact

        pending = [(tree, "")]
        while pending:
            node, scope = pending.pop()
            body_scope = scope
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                qualified = ".".join(filter(None, [scope, node.name]))
                is_function = not isinstance(node, ast.ClassDef)
                parameters = _parameters(node) if is_function else []
                start = min([node.lineno] + [d.lineno for d in node.decorator_list])
                symbol = add("symbol", node, scope, node.name, line=start,
                             symbol_kind="function" if is_function else "class",
                             qualified_name=qualified, definition_line=node.lineno,
                             parameters=tuple(p.arg for p, _ in parameters))
                for order, (param, kind) in enumerate(parameters):
                    add("parameter", param, qualified, param.arg, symbol_id=symbol.fact_id,
                        parameter_kind=kind, position=order)
                body_scope = qualified
            elif isinstance(node, ast.Lambda):
                body_scope = ".".join(filter(None, [scope, "<lambda@%d:%d>" % (node.lineno, node.col_offset)]))
            if isinstance(node, ast.Call):
                call = add("call", node, scope, _call_name(node.func),
                           dispatch="unresolved", callee_kind=type(node.func).__name__)
                for position, arg in enumerate(node.args):
                    add("argument", arg, scope, call_id=call.fact_id, position=position,
                        argument_kind="starred" if isinstance(arg, ast.Starred) else "positional")
                for position, keyword in enumerate(node.keywords):
                    add("argument", keyword.value, scope, keyword.arg or "", call_id=call.fact_id,
                        position=position, argument_kind="keyword" if keyword.arg else "keyword-expanded")
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                add("assignment", node, scope, assignment_kind=type(node).__name__)
            elif isinstance(node, (ast.If, ast.IfExp, ast.For, ast.AsyncFor, ast.While, ast.Try,
                                   getattr(ast, "TryStar", ast.Try), getattr(ast, "Match", ast.If))):
                add("branch", node, scope, branch_kind=type(node).__name__)
            elif isinstance(node, ast.Return):
                add("return", node, scope)
            children = []
            for field_name, value in ast.iter_fields(node):
                # Decorators, defaults, bases and annotations execute outside
                # the defined body. Do not attribute their calls to the callee.
                child_scope = body_scope if field_name == "body" else scope
                values = value if isinstance(value, list) else [value]
                children.extend((child, child_scope) for child in values if isinstance(child, ast.AST))
            pending.extend(reversed(children))
        return facts

    def symbols(self, unit):
        return unit.select("symbol")

    def calls(self, unit):
        return unit.select("call")

    def assignments(self, unit):
        return unit.select("assignment")

    def branches(self, unit):
        return unit.select("branch")

    def returns(self, unit):
        return unit.select("return")

    def parameters(self, unit):
        return unit.select("parameter")

    def arguments(self, unit, call_id=""):
        return tuple(f for f in unit.select("argument") if not call_id or f.attributes["call_id"] == call_id)


class FrontendSession:
    """Content-keyed, bounded cache shared within an inventory build only."""
    def __init__(self, root: Path, frontend: Optional[SemanticFrontend] = None,
                 max_files=MAX_FILES, max_cached_nodes=MAX_CACHED_NODES):
        self.root = Path(root).resolve()
        self.frontend = frontend or PythonFrontend()
        self.max_files = max(1, max_files)
        self.max_cached_nodes = max(1, max_cached_nodes)
        self.cache = OrderedDict()
        self._stats = Counter()
        self.status_by_file = {}
        self.lines_by_file = {}

    def parse(self, file: str) -> ParsedUnit:
        file = str(file)
        status, error, source = "", "", b""
        try:
            path = (self.root / file).resolve()
            if not path.is_relative_to(self.root):
                status = "source-outside-root"
            elif path.suffix.lower() not in (".py", ".pyw"):
                status = "unsupported-language"
            elif not path.is_file():
                status = "source-unreadable"
            else:
                with path.open("rb") as stream:
                    source = stream.read(max(0, getattr(self.frontend, "max_bytes", MAX_BYTES)) + 1)
                self._stats["bytes_read"] += len(source)
        except (OSError, RuntimeError, ValueError) as exc:
            status, error = "source-unreadable", type(exc).__name__
        digest = hashlib.sha256(source).hexdigest()
        # Compare content even when stat/mtime is unchanged; timestamps are not
        # source identity. Do not retain a second unbounded source-text cache.
        key = (digest, status, error)
        if file in self.cache and self.cache[file][0] == key:
            self._stats["cache_hits"] += 1
            self.cache.move_to_end(file)
            return self.cache[file][1]
        self.cache.pop(file, None)
        if status:
            unit = ParsedUnit(file, status, error_kind=error, analysis_gaps=(status,),
                              parser="unavailable" if status == "unsupported-language" else "ast")
        else:
            self._stats["parse_calls"] += 1
            unit = self.frontend.parse(file, source)
            self._stats["nodes_parsed"] += unit.node_count
        self.status_by_file[file] = unit.status
        self.lines_by_file[file] = unit.line_count
        if unit.node_count <= self.max_cached_nodes:
            while self.cache and (len(self.cache) >= self.max_files or
                                  sum(v[1].node_count for v in self.cache.values()) + unit.node_count > self.max_cached_nodes):
                self.cache.popitem(last=False)
                self._stats["evictions"] += 1
            self.cache[file] = (key, unit)
        return unit

    def stats(self) -> Dict[str, Any]:
        return {**{key: self._stats[key] for key in ("parse_calls", "cache_hits", "evictions", "bytes_read", "nodes_parsed")},
                "files": len(self.status_by_file), "cached_files": len(self.cache),
                "loc": sum(self.lines_by_file.values()),
                "cached_nodes": sum(v[1].node_count for v in self.cache.values()),
                "parser_status": dict(sorted(Counter(self.status_by_file.values()).items())),
                "analysis_gaps": {file: status for file, status in sorted(self.status_by_file.items()) if status != "parsed"},
                "claim_status": CLAIM_STATUS}
