"""Shared, bounded syntax frontend. No imports or target code are executed.

The common facts are syntax, not resolved targets, typed data flow or proof of
safety. Existing symbol/semantic artifacts consume them; there is no new disk
artifact. Native AST nodes are read-only, process-local implementation details.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import shutil
import subprocess
import tempfile
import threading
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
MAX_JAVA_FILES = 64
JAVA_AST_TIMEOUT_SECONDS = 3.0
JAVA_AST_COMPILE_TIMEOUT_SECONDS = 10.0
MAX_JAVA_PARSED_UNITS = 512
JAVA_AST_PARSER = "javac-ast"
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
    parser: str = "ast"

    def as_dict(self) -> Dict[str, Any]:
        return {"fact_id": self.fact_id, "kind": self.kind, "file": self.file,
                "line": self.line, "end_line": self.end_line,
                "column": self.column, "end_column": self.end_column,
                "scope": self.scope, "name": self.name, "attributes": dict(self.attributes),
                "parser": self.parser, "confidence": "ast", "claim_status": CLAIM_STATUS}


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


class JavaFrontend:
    """Bounded Java syntax adapter backed by ``JavacTask.parse`` only.

    The bundled helper receives already-bounded source bytes on stdin, invokes
    the JDK parser with annotation processing disabled, and never requests
    symbol analysis or code generation.  A missing JDK, helper compilation
    error, parser diagnostic, timeout, or resource limit returns an explicit
    ``ParsedUnit`` gap and *no partial facts*.  This is syntax evidence, not
    type resolution, virtual dispatch, taint proof, or a finding.
    """

    _compile_lock = threading.Lock()
    _compiled_helpers: Dict[Tuple[str, str], Tuple[Optional[Path], str]] = {}
    _parse_lock = threading.Lock()
    _parsed_units: "OrderedDict[Tuple[str, str, str, int, int], ParsedUnit]" = OrderedDict()

    def __init__(self, max_bytes=MAX_BYTES, max_nodes=MAX_NODES,
                 max_depth=MAX_DEPTH, timeout_seconds=JAVA_AST_TIMEOUT_SECONDS,
                 compile_timeout_seconds=JAVA_AST_COMPILE_TIMEOUT_SECONDS,
                 java_bin: Optional[str] = None, javac_bin: Optional[str] = None,
                 helper_path: Optional[Path] = None):
        self.max_bytes = max(0, int(max_bytes))
        self.max_nodes = max(0, int(max_nodes))
        self.max_depth = max(0, int(max_depth))
        self.timeout_seconds = max(0.1, float(timeout_seconds))
        self.compile_timeout_seconds = max(0.1, float(compile_timeout_seconds))
        self.java_bin = java_bin or shutil.which("java") or ""
        self.javac_bin = javac_bin or shutil.which("javac") or ""
        self.helper_path = Path(helper_path or Path(__file__).with_name(
            "java_ast") / "VulnGateJavaAst.java").resolve()

    @classmethod
    def available(cls) -> bool:
        """Whether the local machine appears able to run the adapter.

        This deliberately checks only the host tools and bundled source.  A
        later compile/run failure is represented by a parse gap rather than a
        speculative availability claim.
        """
        helper = Path(__file__).with_name("java_ast") / "VulnGateJavaAst.java"
        return bool(helper.is_file() and shutil.which("java") and shutil.which("javac"))

    @staticmethod
    def _decoded_field(value: str) -> str:
        padding = "=" * ((4 - len(value) % 4) % 4)
        return base64.urlsafe_b64decode((value + padding).encode("ascii")).decode("utf-8")

    def _helper_classpath(self) -> Tuple[Optional[Path], str]:
        if not self.java_bin or not self.javac_bin:
            return None, "java-or-javac-missing"
        try:
            source = self.helper_path.read_bytes()
        except OSError:
            return None, "java-helper-missing"
        digest = hashlib.sha256(source).hexdigest()
        key = (str(Path(self.javac_bin).resolve()), digest)
        with self._compile_lock:
            cached = self._compiled_helpers.get(key)
            if cached is not None:
                return cached
            output = Path(tempfile.mkdtemp(prefix="vulngate-java-ast-"))
            try:
                completed = subprocess.run(
                    [self.javac_bin, "-proc:none", "-d", str(output),
                     str(self.helper_path)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=self.compile_timeout_seconds,
                    check=False)
                if completed.returncode != 0:
                    result: Tuple[Optional[Path], str] = (None, "java-helper-compile-failed")
                else:
                    result = (output, "")
            except (OSError, subprocess.TimeoutExpired):
                result = (None, "java-helper-compile-unavailable")
            self._compiled_helpers[key] = result
            return result

    def _gap(self, file: str, status: str, *, revision: str = "",
             error: str = "", lines: int = 0) -> ParsedUnit:
        return ParsedUnit(file, status, revision, error, (status,),
                          line_count=lines, parser=JAVA_AST_PARSER)

    def _cached_unit(self, key: Tuple[str, str, str, int, int]) -> Optional[ParsedUnit]:
        with self._parse_lock:
            unit = self._parsed_units.get(key)
            if unit is not None:
                self._parsed_units.move_to_end(key)
            return unit

    def _cache_unit(self, key: Tuple[str, str, str, int, int],
                    unit: ParsedUnit) -> ParsedUnit:
        """Retain immutable Java syntax facts across bounded sessions.

        S1 builds several independent consumers over a target and test suites
        rebuild small inventories repeatedly. Re-running a JDK process for the
        same relative file, source revision, and parser limits adds latency but
        no evidence. Facts contain no target objects and ParsedUnit is frozen,
        so a process-local LRU is safe; the key retains the file because fact
        IDs and provenance intentionally include it.
        """
        with self._parse_lock:
            self._parsed_units[key] = unit
            self._parsed_units.move_to_end(key)
            while len(self._parsed_units) > MAX_JAVA_PARSED_UNITS:
                self._parsed_units.popitem(last=False)
        return unit

    def parse(self, file: str, source: bytes) -> ParsedUnit:
        if len(source) > self.max_bytes:
            return self._gap(file, "too-large", error="ast-byte-limit")
        if self.max_nodes < 1:
            return self._gap(file, "node-limit", error="ast-node-limit")
        if self.max_depth < 1:
            return self._gap(file, "depth-limit", error="ast-depth-limit")
        try:
            text = source.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            return self._gap(file, "parse-failed", error=type(exc).__name__)
        revision = hashlib.sha256(source).hexdigest()
        lines = len(text.splitlines())
        cache_key = (str(Path(self.javac_bin).resolve()), file, revision,
                     self.max_nodes, self.max_depth)
        cached = self._cached_unit(cache_key)
        if cached is not None:
            return cached
        classpath, helper_error = self._helper_classpath()
        if classpath is None:
            return self._cache_unit(cache_key, self._gap(
                file, "java-parser-unavailable", revision=revision,
                error=helper_error, lines=lines))
        try:
            completed = subprocess.run(
                [self.java_bin, "-cp", str(classpath), "VulnGateJavaAst",
                 str(self.max_nodes), str(self.max_depth)],
                input=source, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=self.timeout_seconds, check=False)
        except subprocess.TimeoutExpired:
            return self._cache_unit(cache_key, self._gap(
                file, "java-ast-timeout", revision=revision,
                error="timeout", lines=lines))
        except OSError as exc:
            return self._cache_unit(cache_key, self._gap(
                file, "java-parser-unavailable", revision=revision,
                error=type(exc).__name__, lines=lines))
        if completed.returncode != 0:
            return self._cache_unit(cache_key, self._gap(
                file, "parse-failed", revision=revision,
                error="java-helper-exit-%d" % completed.returncode,
                lines=lines))

        status = ""
        error = ""
        node_count = 0
        raw_facts = []
        try:
            for raw_line in completed.stdout.decode("utf-8", errors="strict").splitlines():
                fields = [self._decoded_field(item) for item in raw_line.split("\t")]
                if not fields:
                    continue
                if fields[0] == "M" and len(fields) == 4:
                    status, error = fields[1], fields[2]
                    node_count = int(fields[3] or 0)
                elif fields[0] == "F" and len(fields) == 9:
                    raw_facts.append(fields)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            return self._cache_unit(cache_key, self._gap(
                file, "parse-failed", revision=revision,
                error="java-helper-output-invalid", lines=lines))
        if status != "parsed":
            return self._cache_unit(cache_key, self._gap(
                file, status or "parse-failed", revision=revision,
                error=error or "java-helper-status-missing", lines=lines))

        facts = []
        try:
            for fields in raw_facts:
                _, kind, line, end_line, column, end_column, scope, name, attributes = fields
                identity = "%s|%s|%s|%s|%s|%s|%s" % (
                    revision, file, kind, line, column, scope, len(facts))
                facts.append(SyntaxFact(
                    "syntax-" + hashlib.sha256(identity.encode()).hexdigest()[:24],
                    kind, file, int(line or 0), int(end_line or line or 0),
                    int(column or 0), int(end_column or column or 0), scope, name,
                    MappingProxyType(dict(json.loads(attributes))), None, JAVA_AST_PARSER))
        except (TypeError, ValueError, json.JSONDecodeError):
            return self._cache_unit(cache_key, self._gap(
                file, "parse-failed", revision=revision,
                error="java-helper-fact-invalid", lines=lines))
        return self._cache_unit(cache_key, ParsedUnit(
            file, "parsed", revision, tree=None, facts=tuple(facts),
            node_count=max(0, node_count), line_count=lines,
            parser=JAVA_AST_PARSER))

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
        # Java call arguments are intentionally carried as bounded identifier
        # lists on their parent call fact.  They are not source snippets.
        return ()


class FrontendSession:
    """Content-keyed, bounded cache shared within an inventory build only."""
    def __init__(self, root: Path, frontend: Optional[SemanticFrontend] = None,
                 java_frontend: Optional[SemanticFrontend] = None,
                 max_files=MAX_FILES, max_cached_nodes=MAX_CACHED_NODES,
                 max_java_files=MAX_JAVA_FILES):
        self.root = Path(root).resolve()
        self.frontend = frontend or PythonFrontend()
        self.java_frontend = java_frontend or JavaFrontend(
            max_bytes=getattr(self.frontend, "max_bytes", MAX_BYTES))
        self.max_files = max(1, max_files)
        self.max_cached_nodes = max(1, max_cached_nodes)
        self.max_java_files = max(0, int(max_java_files))
        self.cache = OrderedDict()
        self._stats = Counter()
        self.status_by_file = {}
        self.lines_by_file = {}
        self._java_seen_files = set()

    def _frontend_for_suffix(self, suffix: str) -> Optional[SemanticFrontend]:
        if suffix in (".py", ".pyw"):
            return self.frontend
        if suffix == ".java":
            return self.java_frontend
        return None

    def parse(self, file: str) -> ParsedUnit:
        file = str(file)
        status, error, source = "", "", b""
        frontend: Optional[SemanticFrontend] = None
        try:
            path = (self.root / file).resolve()
            if not path.is_relative_to(self.root):
                status = "source-outside-root"
            elif not (frontend := self._frontend_for_suffix(path.suffix.lower())):
                status = "unsupported-language"
            elif not path.is_file():
                status = "source-unreadable"
            else:
                with path.open("rb") as stream:
                    source = stream.read(max(0, getattr(frontend, "max_bytes", MAX_BYTES)) + 1)
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
            is_java = frontend is self.java_frontend
            if (is_java and file not in self._java_seen_files
                    and len(self._java_seen_files) >= self.max_java_files):
                unit = ParsedUnit(file, "java-ast-file-budget-exceeded",
                                  error_kind="java-ast-file-budget-exceeded",
                                  analysis_gaps=("java-ast-file-budget-exceeded",),
                                  line_count=len(source.splitlines()),
                                  parser=JAVA_AST_PARSER)
            else:
                self._stats["parse_calls"] += 1
                if is_java:
                    self._java_seen_files.add(file)
                    self._stats["java_parse_calls"] += 1
                unit = frontend.parse(file, source)
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
        return {**{key: self._stats[key] for key in ("parse_calls", "cache_hits", "evictions", "bytes_read", "nodes_parsed", "java_parse_calls")},
                "files": len(self.status_by_file), "cached_files": len(self.cache),
                "loc": sum(self.lines_by_file.values()),
                "cached_nodes": sum(v[1].node_count for v in self.cache.values()),
                "java_parse_budget": self.max_java_files,
                "java_files_seen": len(self._java_seen_files),
                "parser_status": dict(sorted(Counter(self.status_by_file.values()).items())),
                "analysis_gaps": {file: status for file, status in sorted(self.status_by_file.items()) if status != "parsed"},
                "claim_status": CLAIM_STATUS}
