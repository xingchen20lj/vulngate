"""Heuristic cross-function call graph (spec §8, §23 PR2).

The spec is explicit that this is the single biggest coverage win ("当前
Source→Sink 主要是：同文件 / source ↓ 后续有限行距离 / sink") and equally explicit
that a first version does **not** need to be compiler-grade.  So:

* Nodes are :class:`agent.analysis.models.SymbolRecord` ids.
* Edges are name-resolved with a preference ladder (same class → same file →
  globally unique), and every edge is ``heuristic-callgraph`` confidence.
  An ambiguous name produces **no** edge rather than a guess; the ambiguity is
  counted so the shortfall is visible instead of silently missing.
* Propagation kinds are the spec's first-version set:
  ``direct`` / ``argument`` / ``return-value`` / ``field`` / ``constructor`` /
  ``callback``.

Nothing here may be promoted to a proof of reachability.  A path through the
graph is a *lead*: G1 still decides reachability, and only runtime evidence
satisfies G4.
"""

from __future__ import annotations

import re
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from . import models
from .languages import SourceFilter, read_source_lines
from .symbols import FILE_KIND, NOT_A_SYMBOL

#: Identifiers that look like calls but never resolve to a project symbol.
#: Kept short on purpose: resolution is name-based against the symbol index, so
#: anything not in the index is dropped anyway.  This list only avoids pointless
#: lookups for the highest-frequency language builtins.
COMMON_BUILTINS = frozenset({
    "if", "for", "while", "switch", "catch", "return", "new", "throw", "synchronized",
    "super", "this", "sizeof", "typeof", "delete", "assert", "print", "println",
    "printf", "len", "append", "make", "range", "str", "int", "float", "bool",
    "list", "dict", "set", "tuple", "map", "filter", "sorted", "sum", "min", "max",
    "require", "import", "console", "json", "Math", "System", "String", "Integer",
})

_CALL_SITE = re.compile(r"(?<![\w$.])(?P<name>[A-Za-z_$][\w$]*)\s*\(")
_METHOD_CALL_SITE = re.compile(r"\.\s*(?P<name>[A-Za-z_$][\w$]*)\s*\(")
_CONSTRUCTOR_SITE = re.compile(r"\bnew\s+[A-Za-z_$][\w$.<>]*\s*\(")
_ASSIGNMENT_SITE = re.compile(r"^[ \t]*[\w.$\[\]<>,?]+\s+\w+\s*[:=](?!=)")
_FIELD_SITE = re.compile(
    r"^[ \t]*(?:public|private|protected|static|final|readonly|const|val|var|"
    r"let|late|weak|strong|\w+[<>\[\].]*)\s+[\w$]+\s*[:=]")


@dataclass
class CallGraph:
    """Call edges plus the lookups the flow analysis needs."""

    edges: List[models.CallEdge] = field(default_factory=list)
    #: callee symbol id -> caller symbol ids (sorted, de-duplicated)
    callers: Dict[str, List[str]] = field(default_factory=dict)
    #: caller symbol id -> callee symbol ids
    callees: Dict[str, List[str]] = field(default_factory=dict)
    #: call-site identifier -> how many times it could not be resolved
    unresolved: Dict[str, int] = field(default_factory=dict)
    #: call-site identifier -> number of candidate symbols (ambiguity)
    ambiguous: Dict[str, int] = field(default_factory=dict)
    symbol_ids: Set[str] = field(default_factory=set)

    def as_dicts(self) -> List[Dict[str, object]]:
        return [edge.as_dict() for edge in self.edges]

    def summary(self) -> Dict[str, object]:
        propagation = Counter(edge.propagation for edge in self.edges)
        return {
            "nodes": len(self.symbol_ids),
            "edges": len(self.edges),
            "propagation": dict(sorted(propagation.items())),
            "unresolved_calls": sum(self.unresolved.values()),
            "unresolved_names": len(self.unresolved),
            "ambiguous_names": len(self.ambiguous),
            "top_unresolved": [{"name": name, "count": count} for name, count
                               in sorted(self.unresolved.items(),
                                         key=lambda kv: (-kv[1], kv[0]))[:20]],
            "confidence": "heuristic-callgraph",
            "producer": "regex",
            "evidence_type": "static-inferred",
            "limitations": [
                "name-based resolution; overloads collapse to one symbol",
                "no virtual dispatch, DI container, reflection or async model",
                "ambiguity yields no edge rather than a guess",
            ],
        }


def _parameters(lines: Sequence[str], symbol: models.SymbolRecord) -> List[str]:
    """Parameter names from the symbol's declaration line (best effort).

    Annotation lines are stepped over first.  A symbol's range now starts at its
    annotations, and the first ``(`` on ``@PostMapping("/api/user/update")``
    opens the *annotation*, not the parameter list -- reading from the raw
    ``start_line`` would splice route strings in as parameter names and make
    every argument appear attacker-controlled or not, at random.
    """
    if symbol.parser == "ast":
        return list(symbol.parameters)
    if symbol.start_line < 1 or symbol.start_line > len(lines):
        return []
    index = symbol.start_line - 1
    limit = min(len(lines), index + 4)
    while index < limit and lines[index].lstrip().startswith("@"):
        index += 1
    if index >= limit:
        return []
    text = " ".join(lines[index:min(len(lines), index + 3)])
    start = text.find("(")
    if start < 0:
        return []
    depth = 0
    for position in range(start, len(text)):
        if text[position] == "(":
            depth += 1
        elif text[position] == ")":
            depth -= 1
            if depth == 0:
                inner = text[start + 1:position]
                break
    else:
        return []
    names: List[str] = []
    for part in inner.split(","):
        tokens = re.findall(r"[A-Za-z_$][\w$]*", part)
        if not tokens:
            continue
        candidate = tokens[-1]
        if candidate not in NOT_A_SYMBOL:
            names.append(candidate)
    return names


def _classify(line: str, name: str, params: Sequence[str]) -> str:
    """Propagation kind for one call site (spec §8.2 first-version set)."""
    if _CONSTRUCTOR_SITE.search(line) and re.search(
            r"\bnew\s+[\w$.<>]*%s\s*\(" % re.escape(name), line):
        return "constructor"
    if re.search(r"[,(]\s*%s\s*[,)]" % re.escape(name), line):
        return "callback"
    if _ASSIGNMENT_SITE.match(line):
        return "return-value"
    if _FIELD_SITE.match(line):
        return "field"
    if params:
        call_args = re.search(r"%s\s*\((?P<args>[^)]*)\)" % re.escape(name), line)
        if call_args:
            args = call_args.group("args")
            if any(re.search(r"\b%s\b" % re.escape(param), args) for param in params):
                return "argument"
    return "direct"


def _innermost_by_line(file_symbols: Sequence[models.SymbolRecord],
                       line_count: int) -> List[Optional[models.SymbolRecord]]:
    """Map each 1-based line to its innermost enclosing symbol.

    Attribution has to be innermost-wins, not "every symbol whose range covers
    the line".  A class range covers all of its methods, so the naive version
    emits the same call twice -- once from the class and once from the method --
    and additionally invents class-level edges for calls that belong to a
    method.  Innermost-wins keeps field initialisers and top-level module code
    attributed to the type (which is the best owner available) while giving
    every in-method call exactly one owner.
    """
    owners: List[Optional[models.SymbolRecord]] = [None] * (line_count + 1)
    for symbol in file_symbols:
        span = symbol.end_line - symbol.start_line
        start = max(1, symbol.start_line)
        end = min(line_count, symbol.end_line)
        for number in range(start, end + 1):
            current = owners[number]
            if current is None or (span, symbol.kind == FILE_KIND) < \
                    (current.end_line - current.start_line, current.kind == FILE_KIND):
                owners[number] = symbol
    return owners


def build_call_graph(root: Path, symbols: Sequence[models.SymbolRecord],
                     source_filter: Optional[SourceFilter] = None,
                     lines_cache: Optional[Dict[str, List[str]]] = None
                     ) -> CallGraph:
    """Build the call graph over ``symbols``.  Full scan, no edge cap."""
    root = Path(root).resolve()
    flt = source_filter or SourceFilter()
    graph = CallGraph(symbol_ids={s.symbol_id for s in symbols})

    by_name: Dict[str, List[models.SymbolRecord]] = {}
    by_file_class: Dict[Tuple[str, str, str], List[models.SymbolRecord]] = {}
    by_file_name: Dict[Tuple[str, str], List[models.SymbolRecord]] = {}
    by_file: Dict[str, List[models.SymbolRecord]] = {}
    for symbol in symbols:
        # File symbols stay in ``by_file`` (they own module-level lines) but are
        # never resolution targets: a translation unit is not callable, and its
        # name is a path, so it could otherwise absorb a call to a same-named
        # module import.
        if symbol.kind != FILE_KIND:
            by_name.setdefault(symbol.name, []).append(symbol)
            by_file_class.setdefault((symbol.file, symbol.class_name, symbol.name),
                                     []).append(symbol)
            by_file_name.setdefault((symbol.file, symbol.name), []).append(symbol)
        by_file.setdefault(symbol.file, []).append(symbol)

    unresolved: Counter = Counter()
    ambiguous: Counter = Counter()
    edges: Dict[Tuple[str, str], models.CallEdge] = {}

    for rel, file_symbols in sorted(by_file.items()):
        lines: Optional[List[str]] = None
        if lines_cache is not None and rel in lines_cache:
            lines = lines_cache[rel]
        if lines is None:
            lines = read_source_lines(root / rel, flt.max_file_bytes) or []
            if lines_cache is not None:
                lines_cache[rel] = lines
        owners = _innermost_by_line(file_symbols, len(lines))
        params_cache: Dict[str, List[str]] = {}
        for number in range(1, len(lines) + 1):
            caller = owners[number]
            if caller is None:
                continue
            line = lines[number - 1]
            if not line.strip() or line.lstrip().startswith(
                    ("//", "*", "#", "/*")):
                continue
            stripped = _strip_strings(line)
            names = {match.group("name")
                     for match in _CALL_SITE.finditer(stripped)}
            names |= {match.group("name")
                      for match in _METHOD_CALL_SITE.finditer(stripped)}
            if not names:
                continue
            params = params_cache.get(caller.symbol_id)
            if params is None:
                params = _parameters(lines, caller)
                params_cache[caller.symbol_id] = params
            for name in sorted(names):
                if name in NOT_A_SYMBOL or name in COMMON_BUILTINS:
                    continue
                if name == caller.name:
                    continue
                callee = _resolve(name, caller, by_file_class,
                                  by_file_name, by_name, ambiguous)
                if callee is None:
                    unresolved[name] += 1
                    continue
                key = (caller.symbol_id, callee.symbol_id)
                if key in edges:
                    # First sighting wins: the earliest call site is the most
                    # informative line to cite in the finding.
                    continue
                edges[key] = models.CallEdge(
                    caller=caller.symbol_id, callee=callee.symbol_id,
                    callee_name=name, confidence="heuristic-callgraph",
                    file=rel, line=number,
                    propagation=_classify(line, name, params),
                )

    graph.edges = [edges[key] for key in sorted(edges, key=lambda k: (k[0], k[1]))]
    for edge in graph.edges:
        graph.callees.setdefault(edge.caller, []).append(edge.callee)
        graph.callers.setdefault(edge.callee, []).append(edge.caller)
    graph.unresolved = dict(unresolved)
    graph.ambiguous = dict(ambiguous)
    return graph


def _strip_strings(line: str) -> str:
    return re.sub(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'", '""', line)


def _resolve(name: str, caller: models.SymbolRecord,
             by_file_class: Dict[Tuple[str, str, str], List[models.SymbolRecord]],
             by_file_name: Dict[Tuple[str, str], List[models.SymbolRecord]],
             by_name: Dict[str, List[models.SymbolRecord]],
             ambiguous: Counter) -> Optional[models.SymbolRecord]:
    """Preference ladder: same class -> same file -> globally unique."""
    candidates = by_file_class.get((caller.file, caller.class_name, name))
    if candidates:
        if len(candidates) > 1:
            ambiguous[name] += 1
            return None
        return candidates[0]
    candidates = by_file_name.get((caller.file, name))
    if candidates:
        if len(candidates) > 1:
            ambiguous[name] += 1
            return None
        return candidates[0]
    candidates = by_name.get(name)
    if not candidates:
        return None
    if len(candidates) > 1:
        ambiguous[name] += 1
        return None
    return candidates[0]


# --- reachability ----------------------------------------------------------

def forward_depths(graph: CallGraph, starts: Iterable[str],
                   max_depth: Optional[int] = None) -> Dict[str, int]:
    """Breadth-first forward reachability: ``symbol id -> depth``.

    ``starts`` are included at depth 0.
    """
    return _bfs({k: v for k, v in graph.callees.items()}, starts, max_depth)


def backward_depths(graph: CallGraph, starts: Iterable[str],
                    max_depth: Optional[int] = None) -> Dict[str, int]:
    """Breadth-first backward reachability (spec §10, Sink → Source)."""
    return _bfs({k: v for k, v in graph.callers.items()}, starts, max_depth)


def forward_tree(graph: CallGraph, start: str,
                 max_depth: Optional[int] = None
                 ) -> Dict[str, Tuple[int, Optional[str]]]:
    """Forward BFS from one node, keeping the parent of each discovery.

    Returns ``{symbol id: (depth, parent)}``; ``start`` maps to ``(0, None)``.
    BFS order makes the parent chain the *shortest* call path, which is what
    the flow records cite.  Deterministic because adjacency is sorted.
    """
    return _bfs_tree(graph.callees, start, max_depth)


def backward_tree(graph: CallGraph, start: str,
                  max_depth: Optional[int] = None
                  ) -> Dict[str, Tuple[int, Optional[str]]]:
    """Backward BFS from one node, keeping parents (spec §10)."""
    return _bfs_tree(graph.callers, start, max_depth)


def path_from_tree(tree: Dict[str, Tuple[int, Optional[str]]], node: str
                   ) -> List[str]:
    """Reconstruct the shortest path ``start -> node`` from a BFS tree."""
    if node not in tree:
        return []
    path = [node]
    parent = tree[node][1]
    while parent is not None:
        path.append(parent)
        parent = tree.get(parent, (0, None))[1]
    path.reverse()
    return path


def _bfs_tree(adjacency: Dict[str, List[str]], start: str,
              max_depth: Optional[int]
              ) -> Dict[str, Tuple[int, Optional[str]]]:
    tree: Dict[str, Tuple[int, Optional[str]]] = {start: (0, None)}
    queue: deque = deque([start])
    while queue:
        node = queue.popleft()
        depth = tree[node][0]
        if max_depth is not None and depth >= max_depth:
            continue
        for neighbour in adjacency.get(node, ()):  # already sorted
            if neighbour in tree:
                continue
            tree[neighbour] = (depth + 1, node)
            queue.append(neighbour)
    return tree


def _bfs(adjacency: Dict[str, List[str]], starts: Iterable[str],
         max_depth: Optional[int]) -> Dict[str, int]:
    depths: Dict[str, int] = {}
    queue: deque = deque()
    for start in starts:
        if start not in depths:
            depths[start] = 0
            queue.append(start)
    while queue:
        node = queue.popleft()
        depth = depths[node]
        if max_depth is not None and depth >= max_depth:
            continue
        for neighbour in adjacency.get(node, ()):  # already sorted
            if neighbour in depths:
                continue
            depths[neighbour] = depth + 1
            queue.append(neighbour)
    return depths


def shortest_path(graph: CallGraph, start: str, goal: str,
                  max_depth: Optional[int] = None) -> Optional[List[str]]:
    """Shortest symbol path ``start -> goal``, or ``None`` if unreachable."""
    if start == goal:
        return [start]
    parents: Dict[str, Optional[str]] = {start: None}
    queue: deque = deque([start])
    while queue:
        node = queue.popleft()
        depth = 0
        cursor: Optional[str] = node
        while cursor is not None:
            depth += 1
            cursor = parents.get(cursor)
        if max_depth is not None and depth > max_depth:
            continue
        for neighbour in graph.callees.get(node, ()):
            if neighbour in parents:
                continue
            parents[neighbour] = node
            if neighbour == goal:
                path = [goal]
                cursor = node
                while cursor is not None:
                    path.append(cursor)
                    cursor = parents.get(cursor)
                path.reverse()
                return path
            queue.append(neighbour)
    return None
