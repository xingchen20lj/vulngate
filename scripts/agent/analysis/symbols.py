"""Symbol index (spec §4.2, §8, §23 PR2).

Python uses the shared, bounded AST frontend. Other languages and Python parse
failures retain explicit regex fallback with brace / indent / paren ranges.

What it must get right, because everything downstream depends on it:

* **Stable ``symbol_id``.**  ``java:com.foo.UserController#updateUser`` for JVM
  languages (package-qualified), ``<language>:<file>#<name>`` otherwise.  The
  call graph, the flow index and the coverage ledger all key on this string, so
  it may not depend on line numbers.
* **Honest ``confidence``.** Python AST records describe syntax only; fallback
  remains heuristic. All records carry ``not-a-finding``. Neither kind proves
  data propagation, dispatch, reachability or runtime effects.

Known limitations (recorded rather than hidden): overloads collapse to one id
per name, lambdas/anonymous classes are not symbols, and preprocessor-conditional
C/C++ declarations are treated as if all branches were active.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import models
from .semantic_frontend import FrontendSession, ParsedUnit, PythonFrontend, MAX_BYTES
from .languages import (JVM_LANGUAGES, SourceFilter, read_source_lines,
                        scan_tree, suffix_owner_language)

# --- language families -----------------------------------------------------

BRACE_LANGUAGES = frozenset({
    "java", "kotlin", "scala", "c", "cpp", "csharp", "javascript",
    "typescript", "php", "go", "swift", "rust", "objective-c",
})
INDENT_LANGUAGES = frozenset({"python", "ruby"})
PAREN_LANGUAGES = frozenset({"clojure"})

TYPE_KINDS = ("class", "interface", "enum", "record", "struct", "protocol",
              "trait", "object", "extension", "impl", "union", "module")

#: Kind of the synthetic per-file symbol.  Deliberately *not* a member of
#: :data:`TYPE_KINDS`: a translation unit is a container, so treating it as a
#: type would splice the file path into every qualified name in the file.
FILE_KIND = "file"

#: Never a symbol name -- control flow, operators, and common builtins that
#: would otherwise be picked up as a "method declaration".
NOT_A_SYMBOL = frozenset({
    "if", "for", "while", "switch", "catch", "synchronized", "return", "new",
    "throw", "else", "do", "try", "case", "default", "assert", "yield",
    "await", "typeof", "sizeof", "delete", "in", "instanceof", "with", "print",
    "println", "printf", "elif", "unless", "when", "loop", "match", "lambda",
})

_MODIFIERS = (r"(?:public|protected|private|static|final|abstract|sealed|"
              r"synchronized|native|default|open|override|internal|inline|"
              r"suspend|async|unsafe|pub|extern|mutable|const|virtual|"
              r"partial|operator|convenience|required|nonisolated|readonly|"
              r"export|declare|override|late|data|annotation|value|inner|"
              r"companion|tailrec|infix|external|package|pure|nothrow|ref|out|in)")

_ANNOTATION = r"(?:@\w+(?:\([^)]*\))?\s*)*"

#: Statement keywords that may sit exactly where a result type would in a
#: declaration-shaped line.  Without this guard ``return execute(query);``
#: parses as a *method declaration* named ``execute`` (prefix ``return``), so
#: one real symbol is split into several overlapping ones and every call site
#: becomes a phantom symbol.  Guarding the prefix keeps call sites out.
_STMT_KEYWORDS = (
    r"(?:return|throw|new|else|case|default|assert|yield|await|break|continue|"
    r"goto|raise|del|print|using|typedef|super|this|instanceof|extends|"
    r"implements|package|with|if|for|while|switch|catch|do|try|synchronized)")

# A declaration line whose *name* is preceded by at least one type-ish token.
# Requiring that prefix is what keeps ``x = foo(`` and ``if (`` out.
_JAVA_LIKE_CALLABLE = re.compile(
    r"^[ \t]*" + _ANNOTATION + r"(?:(?:" + _MODIFIERS + r")\s+)*"
    r"(?!" + _STMT_KEYWORDS + r"\b)"
    r"(?P<prefix>[\w<>\[\],.?$&*:]+\s+)+"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*"
    r"(?:throws\s+[\w,.\s]+)?(?:=>|\{|;[ \t]*$|$)")

_KEYWORD_CALLABLE = re.compile(
    r"^[ \t]*" + _ANNOTATION + r"(?:(?:" + _MODIFIERS + r")\s+)*"
    r"(?P<keyword>fun|def|func|fn|function|sub|proc)\s+"
    r"(?:<[^>]*>\s*)?(?P<name>[A-Za-z_$][\w$!?.:]*)\s*[\(<]")

_VAR_CALLABLE = re.compile(
    r"^[ \t]*(?:export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*"
    r"(?::[^=]+)?=\s*(?:async\s+)?(?:function\s*)?\([^)]*\)\s*(?::[^=]+)?=>")

_METHOD_LIKE = re.compile(
    r"^[ \t]*(?:(?:async|static|get|set|public|private|protected|readonly|"
    r"public|virtual|override|abstract|\*)\s+)*(?P<name>[A-Za-z_$][\w$]*)\s*"
    r"\([^;{}]*\)\s*(?::[^={]+)?\{")

_OBJC_METHOD = re.compile(
    r"^[ \t]*[-+]\s*\([^)]*\)\s*(?P<name>[A-Za-z_]\w*)")

_CLOJURE_DEF = re.compile(r"\(def(?:n|macro|-)?\s+(?P<name>[\w!?*<>=+\-/]+)")

_TYPE_PATTERN = re.compile(
    r"^[ \t]*" + _ANNOTATION + r"(?:(?:" + _MODIFIERS + r")\s+)*"
    r"(?P<kind>" + "|".join(TYPE_KINDS) + r")\s+(?P<name>[A-Za-z_$][\w$]*)")

_GO_METHOD = re.compile(
    r"^[ \t]*func\s+(?:\(\s*\w+\s+\*?(?P<receiver>[\w.\[\]]+)\s*\)\s*)?"
    r"(?P<name>[A-Za-z_]\w*)\s*\(")

_PACKAGE = re.compile(r"^[ \t]*package\s+(?P<name>[\w.]+)\s*;?")
_NAMESPACE = re.compile(r"^[ \t]*(?:namespace|module)\s+(?P<name>[\w.:]+)")

#: Ordered so a language-specific rule wins over the generic one.
_FAMILY_PATTERNS: Dict[str, List[Tuple[str, "re.Pattern[str]"]]] = {
    "go": [("function", _GO_METHOD)],
    "clojure": [("function", _CLOJURE_DEF)],
    "objective-c": [("method", _OBJC_METHOD), ("function", _JAVA_LIKE_CALLABLE)],
    "javascript": [("function", _KEYWORD_CALLABLE), ("function", _VAR_CALLABLE),
                   ("method", _METHOD_LIKE)],
    "typescript": [("function", _KEYWORD_CALLABLE), ("function", _VAR_CALLABLE),
                   ("method", _METHOD_LIKE)],
    "php": [("function", _KEYWORD_CALLABLE), ("method", _METHOD_LIKE)],
    "kotlin": [("function", _KEYWORD_CALLABLE), ("method", _JAVA_LIKE_CALLABLE)],
    "scala": [("function", _KEYWORD_CALLABLE), ("method", _JAVA_LIKE_CALLABLE)],
    "rust": [("function", _KEYWORD_CALLABLE), ("method", _JAVA_LIKE_CALLABLE)],
    "swift": [("function", _KEYWORD_CALLABLE), ("method", _JAVA_LIKE_CALLABLE)],
    "python": [("function", _KEYWORD_CALLABLE)],
    "ruby": [("function", _KEYWORD_CALLABLE)],
}
_DEFAULT_PATTERNS = [("method", _JAVA_LIKE_CALLABLE), ("method", _METHOD_LIKE)]

#: Cap on how far a single symbol may extend.  A missing brace (truncated file)
#: must not turn one declaration into "the rest of the file" and swallow every
#: following symbol -- that would silently merge unrelated security surfaces.
MAX_SYMBOL_LINES = 2000


@dataclass
class Decl:
    kind: str
    name: str
    start: int
    end: int
    header: str = ""


def _brace_end(lines: Sequence[str], start_idx: int) -> int:
    """Index of the line closing the block opened at/after ``start_idx``."""
    depth = 0
    opened = False
    limit = min(len(lines), start_idx + MAX_SYMBOL_LINES)
    for i in range(start_idx, limit):
        line = _strip_literals(lines[i])
        depth += line.count("{") - line.count("}")
        if "{" in line:
            opened = True
        if opened and depth <= 0:
            return i
    return min(len(lines) - 1, start_idx + MAX_SYMBOL_LINES - 1)


def _paren_end(lines: Sequence[str], start_idx: int) -> int:
    depth = 0
    opened = False
    limit = min(len(lines), start_idx + MAX_SYMBOL_LINES)
    for i in range(start_idx, limit):
        line = _strip_literals(lines[i])
        depth += line.count("(") - line.count(")")
        if "(" in line:
            opened = True
        if opened and depth <= 0:
            return i
    return min(len(lines) - 1, start_idx + MAX_SYMBOL_LINES - 1)


def _strip_literals(line: str) -> str:
    """Remove string/char literals and line comments before brace counting.

    A ``{`` inside a string or a ``//`` comment does not open a block; counting
    it anyway shifts every following symbol's range.
    """
    out = []
    i = 0
    quote = ""
    while i < len(line):
        char = line[i]
        if quote:
            if char == "\\":
                i += 2
                continue
            if char == quote:
                quote = ""
            i += 1
            continue
        if char in "\"'`":
            quote = char
            i += 1
            continue
        if char == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break
        if char == "#" and line.lstrip().startswith("#"):
            break
        out.append(char)
        i += 1
    return "".join(out)


def _indent_end(lines: Sequence[str], start_idx: int) -> int:
    base = len(lines[start_idx]) - len(lines[start_idx].lstrip())
    last = start_idx
    limit = min(len(lines), start_idx + MAX_SYMBOL_LINES)
    for i in range(start_idx + 1, limit):
        text = lines[i]
        if not text.strip() or text.lstrip().startswith("#"):
            continue
        indent = len(text) - len(text.lstrip())
        if indent <= base:
            break
        last = i
    return last


def _end_of(lines: Sequence[str], language: str, start_idx: int) -> int:
    if language in INDENT_LANGUAGES:
        return _indent_end(lines, start_idx)
    if language in PAREN_LANGUAGES:
        return _paren_end(lines, start_idx)
    return _brace_end(lines, start_idx)


def _annotation_spans(lines: Sequence[str]) -> Dict[int, int]:
    """``line index -> start index`` of the annotation block ending there.

    Annotations belong to the declaration they precede, and the entry catalog
    is full of them (``@PostMapping`` / ``@RequestMapping`` / ``@Path`` /
    ``@Entity``).  Without this, a route annotation written on its own line
    falls *outside* the method's range and binds the entry to the enclosing
    class instead -- which silently disconnects the entry from the very method
    that handles it, and therefore from every flow through it.

    The scan is a single pass over the file:

    * a line whose stripped text starts with ``@`` opens a run;
    * the run ends at the first line where parentheses balance, so
      ``@Foo(\n  value = 1)\n`` is one run rather than two;
    * runs chain through :func:`_annotation_start`, covering stacked
      annotations such as ``@Valid\n@NotNull\npublic void f()``.
    """
    spans: Dict[int, int] = {}
    run_start: Optional[int] = None
    depth = 0
    for index, text in enumerate(lines):
        stripped = text.strip()
        if run_start is None:
            if not stripped.startswith("@"):
                continue
            run_start = index
            depth = stripped.count("(") - stripped.count(")")
        else:
            depth += stripped.count("(") - stripped.count(")")
        if depth <= 0:
            spans[index] = run_start
            run_start = None
            depth = 0
    return spans


def _annotation_start(spans: Dict[int, int], index: int) -> int:
    """Walk back through chained annotation blocks ending at ``index - 1``."""
    start = index
    guard = 0
    while start - 1 in spans and guard < 64:
        start = spans[start - 1]
        guard += 1
    return start


def _decls_in_file(lines: Sequence[str], language: str) -> List[Decl]:
    """All type + callable declarations in one file, in source order."""
    patterns = _FAMILY_PATTERNS.get(language, _DEFAULT_PATTERNS)
    annotation_spans = _annotation_spans(lines)
    decls: List[Decl] = []

    def append(kind: str, name: str, index: int) -> None:
        start = _annotation_start(annotation_spans, index)
        decls.append(Decl(kind=kind, name=name, start=start + 1,
                          end=_end_of(lines, language, index) + 1,
                          header=lines[index].strip()[:200]))

    for index, text in enumerate(lines):
        if not text.strip() or text.lstrip().startswith(("//", "*", "#")):
            continue
        match = _TYPE_PATTERN.match(text)
        if match and match.group("name") not in NOT_A_SYMBOL:
            append(match.group("kind"), match.group("name"), index)
            continue
        for kind, pattern in patterns:
            found = pattern.match(text)
            if not found:
                continue
            name = found.group("name")
            if not name or name in NOT_A_SYMBOL:
                continue
            append(kind, name, index)
            break
    decls.sort(key=lambda d: (d.start, -d.end))
    return decls


def _qualified_name(decl: Decl, parents: Sequence[Decl], language: str,
                    namespace: str, rel: str) -> str:
    """Owner path for a declaration, used as the tail of its ``symbol_id``.

    Two shapes, chosen by whether the language has a real namespace mechanism:

    * **JVM** (``JVM_LANGUAGES``) -- ``com.foo.UserController#updateUser``, the
      spec's example.  Nested types join with a dot.
    * **everything else** -- the *file* is the namespace:
      ``scripts/pkg/mod.py#CoverageStore.write``.  The earlier version used a
      bare dotted class name, so ``class Record`` in two files produced one id
      and the two classes silently merged in the symbol index and the call
      graph.  Symbol ids key the whole downstream layer, so uniqueness is not
      optional.

    A JVM file with no ``package`` declaration falls back to the file-namespaced
    shape rather than emitting ``java:#updateUser``, which would collide with the
    same method name in every unpackaged file of the tree.
    """
    types = [p.name for p in parents if p.kind in TYPE_KINDS]
    if language in JVM_LANGUAGES and namespace:
        owner = ".".join([namespace] + types)
        if decl.kind in TYPE_KINDS:
            return ".".join([owner, decl.name]) if owner else decl.name
        return "%s#%s" % (owner, decl.name) if owner else decl.name
    prefix = namespace or rel
    if not prefix:
        prefix = decl.name
    return "%s#%s" % (prefix, ".".join(types + [decl.name]))


def _symbol_id(language: str, qualified: str) -> str:
    """``<language>:<qualified name>`` -- the stable identity of a symbol.

    Depends only on language, namespace/file and declaration names, never on
    line numbers, so the id survives edits above the declaration.
    """
    return "%s:%s" % (language, qualified)


def _enclosing(decls: Sequence[Decl], decl: Decl) -> List[Decl]:
    return [d for d in decls
            if d is not decl and d.kind in TYPE_KINDS
            and d.start < decl.start and d.end >= decl.end]


def _python_symbols(unit: ParsedUnit) -> List[models.SymbolRecord]:
    declarations = unit.select("symbol")
    duplicates = Counter(s.attributes["qualified_name"] for s in declarations)
    class_scopes = {s.attributes["qualified_name"] for s in declarations
                    if s.attributes["symbol_kind"] == "class"}
    common = dict(language="python", file=unit.file, producer="python-ast",
                  parser="ast", parse_status=unit.status, source_revision=unit.source_revision,
                  confidence="ast", claim_status="not-a-finding")
    output = [models.SymbolRecord(symbol_id=_symbol_id("python", unit.file),
                                  start_line=1, end_line=max(1, unit.line_count),
                                  kind=FILE_KIND, name=unit.file, **common)]
    for fact in declarations:
        qualified = fact.attributes["qualified_name"]
        duplicate = duplicates[qualified] > 1
        suffix = "@%d:%d" % (fact.line, fact.column) if duplicate else ""
        components = fact.scope.split(".") if fact.scope else []
        classes = [part for i, part in enumerate(components)
                   if ".".join(components[:i + 1]) in class_scopes]
        output.append(models.SymbolRecord(
            symbol_id=_symbol_id("python", "%s#%s%s" % (unit.file, qualified, suffix)),
            start_line=fact.line, end_line=fact.end_line, name=fact.name,
            kind=fact.attributes["symbol_kind"], class_name=".".join(classes),
            parameters=list(fact.attributes["parameters"]),
            analysis_gaps=["duplicate-definition"] if duplicate else [], **common))
    return output


def extract_symbols(root: Path, rel_paths: Sequence[str],
                    source_filter: Optional[SourceFilter] = None,
                    frontend_session: Optional[FrontendSession] = None
                    ) -> Tuple[List[models.SymbolRecord], Dict[str, str]]:
    """Build the symbol index over ``rel_paths``.

    Every readable file also contributes a synthetic :data:`FILE_KIND` symbol
    spanning the whole file.  That is a modelling decision with a concrete
    payoff: module-level code (``_PATTERN = re.compile(...)``, Go ``init``, JS
    top-level awaits, ``if __name__ == "__main__"``) belongs to *no* declaration,
    so without a file symbol every such line -- and every entry or sink on it --
    is unbound and therefore invisible to the call graph and to flow analysis.
    On this repository's own ``scripts/`` tree that was 164 of 261 sinks.

    The file symbol is the outermost range, so :func:`innermost_at` still
    attributes a line inside a function to the function.  It is *not* added to
    the call graph's name-resolution tables (a file is not callable).

    Returns ``(symbols, read_failures)`` where ``read_failures`` maps a file to
    the reason it could not be read -- surfaced instead of silently contributing
    zero symbols.
    """
    root = Path(root).resolve()
    flt = source_filter or SourceFilter()
    frontend_session = frontend_session or FrontendSession(
        root, PythonFrontend(max_bytes=min(MAX_BYTES, flt.max_file_bytes or MAX_BYTES)))
    read_failures: Dict[str, str] = {}
    symbols: List[models.SymbolRecord] = []

    for rel in rel_paths:
        language = suffix_owner_language(rel)
        if language is None:
            continue
        parsed = frontend_session.parse(rel) if language == "python" else None
        if parsed is not None and parsed.status == "parsed":
            symbols.extend(_python_symbols(parsed))
            continue
        if parsed is not None:
            read_failures[rel] = "analysis-gap:%s" % parsed.status
            if parsed.status in {"source-outside-root", "source-unreadable"}:
                continue
        lines = read_source_lines(root / rel, flt.max_file_bytes)
        if lines is None:
            read_failures[rel] = "unreadable"
            continue
        namespace = ""
        fallback = dict(parser="regex-fallback",
                        parse_status=parsed.status if parsed is not None else "unsupported-language",
                        source_revision=parsed.source_revision if parsed is not None else "",
                        analysis_gaps=list(parsed.analysis_gaps) if parsed is not None else ["ast-adapter-unavailable"])
        for text in lines[:60]:
            match = _PACKAGE.match(text) or _NAMESPACE.match(text)
            if match:
                namespace = match.group("name")
                break
        symbols.append(models.SymbolRecord(
            # The file symbol is keyed by *path*, never by ``namespace``: a
            # package is shared by every file under it, so using it would give
            # all three files of ``com.foo`` the same id.
            symbol_id=_symbol_id(language, rel),
            language=language, file=rel, start_line=1, end_line=max(1, len(lines)),
            kind=FILE_KIND, name=namespace or rel, class_name="",
            namespace=namespace,
            **fallback,
        ))
        decls = _decls_in_file(lines, language)
        for decl in decls:
            parents = _enclosing(decls, decl)
            qualified = _qualified_name(decl, parents, language, namespace, rel)
            kind = decl.kind
            if kind in ("method", "function") and parents:
                nearest = parents[-1]
                if decl.name == nearest.name or decl.name == nearest.name.split(".")[-1]:
                    kind = "constructor"
            symbols.append(models.SymbolRecord(
                symbol_id=_symbol_id(language, qualified),
                language=language, file=rel, start_line=decl.start,
                end_line=decl.end, kind=kind, name=decl.name,
                class_name=".".join(p.name for p in parents if p.kind in TYPE_KINDS),
                namespace=namespace,
                **fallback,
            ))
    symbols.sort(key=lambda s: (s.file, s.start_line, s.end_line, s.symbol_id))
    return symbols, read_failures


def group_by_file(symbols: Sequence[models.SymbolRecord]
                  ) -> Dict[str, List[models.SymbolRecord]]:
    """``file -> symbols``, the lookup every line-level attribution needs."""
    grouped: Dict[str, List[models.SymbolRecord]] = {}
    for symbol in symbols:
        grouped.setdefault(symbol.file, []).append(symbol)
    return grouped


def innermost_at(grouped: Dict[str, List[models.SymbolRecord]], file: str,
                 line: int) -> Optional[models.SymbolRecord]:
    """The tightest symbol whose range contains ``file:line``.

    Innermost (smallest span) rather than first match: a class contains its
    methods, so first match would attribute every in-method record to the class
    and make the call graph look like the class does the work.
    """
    if not file or line <= 0:
        return None
    best: Optional[models.SymbolRecord] = None
    for symbol in grouped.get(file, ()):
        if symbol.start_line <= line <= symbol.end_line:
            if best is None or (symbol.end_line - symbol.start_line, symbol.kind == FILE_KIND) < \
                    (best.end_line - best.start_line, best.kind == FILE_KIND):
                best = symbol
    return best


def relink_records(symbols: Sequence[models.SymbolRecord],
                   records: Iterable[object]) -> int:
    """Point every record's ``symbol_id`` at the innermost enclosing symbol.

    PR1 attached a ``<file>#<nearest-declaration>`` hint.  Now that real symbols
    exist, the hint is replaced; records whose file has no symbol index keep
    their hint so the information is not lost (and the coverage layer can see
    which files produced no symbols at all -- itself a gap).
    """
    grouped = group_by_file(symbols)
    relinked = 0
    for record in records:
        file = getattr(record, "file", "")
        line = int(getattr(record, "line", 0) or 0)
        if not file or not line:
            continue
        best = innermost_at(grouped, file, line)
        if best is not None:
            if getattr(record, "symbol_id", "") != best.symbol_id:
                relinked += 1
            record.symbol_id = best.symbol_id
    return relinked


def index_security_surfaces(symbols: Sequence[models.SymbolRecord],
                            entries: Iterable[object],
                            sinks: Iterable[object],
                            controls: Iterable[object]) -> Dict[str, int]:
    """Tag each symbol with the sinks/entries/controls inside its line range."""
    by_id = {symbol.symbol_id: symbol for symbol in symbols}
    counts = {"sinks": 0, "entries": 0, "controls": 0}
    plural = {"sink": "sinks", "entry": "entries", "control": "controls"}
    for collection, label in ((sinks, "sink"), (entries, "entry"),
                             (controls, "control")):
        for record in collection:
            symbol = by_id.get(str(getattr(record, "symbol_id", "") or ""))
            if symbol is None:
                continue
            if label not in symbol.security_surfaces:
                symbol.security_surfaces.append(label)
            counts[plural[label]] += 1
    for symbol in symbols:
        symbol.security_surfaces.sort()
    return counts
