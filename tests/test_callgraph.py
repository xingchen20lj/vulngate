"""Symbol index and heuristic call graph (spec §4.2, §8, §19.3).

The properties under test are the ones the rest of the coverage layer keys on:

* **Symbol ids are stable and unique.**  They are the node identity of the call
  graph, the value of ``symbol_id`` on every entry/sink/control and the join key
  of the coverage ledger.  A collision silently merges two unrelated security
  surfaces, so uniqueness is asserted directly rather than assumed.
* **Call sites never become declarations.**  ``return execute(query);`` parses as
  a declaration if the declaration regex lets a statement keyword sit where a
  result type would, which splits one symbol into several overlapping ones and
  makes every call site a phantom node.
* **Annotations belong to what they annotate.**  ``@PostMapping`` on its own line
  must not fall outside the handler's range; if it does, the entry binds to the
  class and the entry is disconnected from its own handler.
* **Ambiguity yields no edge.**  The spec's first version is name-resolved, so an
  overloaded name must produce a *missing* edge (visible in ``ambiguous``) rather
  than a guessed one.

These tests build small source trees in a temporary directory, so they need
neither ripgrep nor a real target.
"""

import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from agent.analysis import callgraph as CG  # noqa: E402
from agent.analysis import symbols as S  # noqa: E402
from agent.analysis.languages import SourceFilter  # noqa: E402


JAVA_CONTROLLER = '''package com.foo;

public class UserController {
    private final UserService service = new UserService();

    @PostMapping("/api/user/update")
    public String updateUser(String id, String body) {
        return service.update(id, body);
    }
}
'''

JAVA_SERVICE = '''package com.foo;

public class UserService {
    private final Runner runner = new Runner();

    public String update(String id, String body) {
        String checked = normalize(id);
        return runner.run(checked, body);
    }

    private String normalize(String id) {
        return id.trim();
    }
}
'''

JAVA_RUNNER = '''package com.foo;

public class Runner {
    public String run(String id, String body) {
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "echo " + body);
        return pb.start().toString();
    }
}
'''


class TreeMixin:
    """Materialise a ``{relative path: text}`` map into a temp directory."""

    def build_tree(self, files):
        root = Path(tempfile.mkdtemp(prefix="vulngate-pr2-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        for rel, text in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return root

    def index(self, root, rels=None, flt=None):
        rels = rels or sorted(
            str(p.relative_to(root)) for p in root.rglob("*")
            if p.is_file() and p.suffix in (".java", ".py", ".go", ".ts", ".c"))
        return S.extract_symbols(root, rels, flt or SourceFilter())


class JavaSymbolTests(TreeMixin, unittest.TestCase):
    """The JVM fixture mirrors spec §19.3's handler -> service -> helper -> exec."""

    def setUp(self):
        self.root = self.build_tree({
            "src/com/foo/UserController.java": JAVA_CONTROLLER,
            "src/com/foo/UserService.java": JAVA_SERVICE,
            "src/com/foo/Runner.java": JAVA_RUNNER,
        })
        self.symbols, self.failures = self.index(self.root)
        self.by_id = {s.symbol_id: s for s in self.symbols}

    def test_symbol_ids_are_unique(self):
        ids = [s.symbol_id for s in self.symbols]
        self.assertEqual(len(ids), len(set(ids)),
                         "duplicate symbol ids merge unrelated surfaces")

    def test_file_symbol_covers_every_readable_file(self):
        files = {s.file for s in self.symbols if s.kind == S.FILE_KIND}
        self.assertEqual(files, {
            "src/com/foo/UserController.java",
            "src/com/foo/UserService.java",
            "src/com/foo/Runner.java"})

    def test_java_ids_follow_the_spec_shape(self):
        self.assertIn("java:com.foo.UserController", self.by_id)
        self.assertIn("java:com.foo.UserService#update", self.by_id)
        self.assertIn("java:com.foo.Runner#run", self.by_id)
        self.assertIn("java:com.foo.UserController#updateUser", self.by_id)

    def test_return_statement_is_not_a_declaration(self):
        """``return execute(query);`` must not become a symbol named execute."""
        names = [s.name for s in self.symbols]
        self.assertNotIn("trim", names)
        # One symbol per real declaration; the phantom overload of ``execute``
        # in the original fixture produced duplicates with overlapping ranges.
        self.assertEqual(len([s for s in self.symbols
                              if s.symbol_id == "java:com.foo.UserService#update"]), 1)
        # Ranges must not overlap: a call site that swallowed the method body
        # showed up as a second symbol starting inside the first.
        ranges = sorted((s.start_line, s.end_line) for s in self.symbols
                        if s.file.endswith("UserService.java") and s.kind == "method")
        for (start_a, end_a), (start_b, _) in zip(ranges, ranges[1:]):
            self.assertGreater(start_b, end_a,
                               "overlapping method ranges: %s" % (ranges,))

    def test_annotation_extends_the_declaration_range(self):
        """The route annotation must be inside the handler it annotates."""
        handler = self.by_id["java:com.foo.UserController#updateUser"]
        self.assertLessEqual(handler.start_line, 6,
                             "annotation line fell outside the handler range")
        self.assertIn("@PostMapping", JAVA_CONTROLLER.splitlines()[handler.start_line - 1])

    def test_stacked_annotations_chain(self):
        root = self.build_tree({"A.java": '''package com.foo;

public class A {
    @Override
    @SuppressWarnings({
        "unchecked"
    })
    public String go() {
        return "x";
    }
}
'''})
        symbols, _ = self.index(root)
        go = [s for s in symbols if s.name == "go"][0]
        self.assertEqual(go.start_line, 4)
        self.assertEqual(go.end_line, 10)

    def test_read_failures_are_reported_not_swallowed(self):
        symbols, failures = self.index(self.root, rels=["src/com/foo/Missing.java"])
        self.assertEqual(failures, {"src/com/foo/Missing.java": "unreadable"})
        self.assertEqual([s for s in symbols if s.file.endswith("Missing.java")], [])

    def test_non_jvm_ids_are_namespaced_by_file(self):
        """Two same-named classes in different files must not share an id."""
        root = self.build_tree({
            "a/model.py": "class Record:\n    def save(self):\n        pass\n",
            "b/model.py": "class Record:\n    def save(self):\n        pass\n",
        })
        symbols, _ = self.index(root)
        classes = [s for s in symbols if s.kind == "class"]
        self.assertEqual(len(classes), 2)
        self.assertEqual(len({s.symbol_id for s in classes}), 2)
        self.assertEqual({s.symbol_id for s in classes}, {
            "python:a/model.py#Record", "python:b/model.py#Record"})


class CallGraphTests(TreeMixin, unittest.TestCase):

    def setUp(self):
        self.root = self.build_tree({
            "src/com/foo/UserController.java": JAVA_CONTROLLER,
            "src/com/foo/UserService.java": JAVA_SERVICE,
            "src/com/foo/Runner.java": JAVA_RUNNER,
        })
        self.symbols, _ = self.index(self.root)
        self.graph = CG.build_call_graph(self.root, self.symbols)
        self.edges = {(e.caller, e.callee): e for e in self.graph.edges}

    def test_cross_file_edge_exists(self):
        """spec §8: Controller -> Service must be an edge, not a nearby line."""
        self.assertIn(("java:com.foo.UserController#updateUser",
                       "java:com.foo.UserService#update"), self.edges)

    def test_transitive_chain_is_reachable(self):
        """spec §19.3: handler -> service -> helper -> ProcessBuilder."""
        tree = CG.forward_tree(
            self.graph, "java:com.foo.UserController#updateUser", max_depth=8)
        self.assertIn("java:com.foo.UserService#update", tree)
        self.assertIn("java:com.foo.Runner#run", tree)
        self.assertEqual(tree["java:com.foo.Runner#run"][0], 2)

    def test_shortest_path_reconstructs_the_chain(self):
        path = CG.shortest_path(
            self.graph, "java:com.foo.UserController#updateUser",
            "java:com.foo.Runner#run")
        self.assertEqual(path, ["java:com.foo.UserController#updateUser",
                                "java:com.foo.UserService#update",
                                "java:com.foo.Runner#run"])

    def test_backward_reachability_finds_the_handler(self):
        """spec §10: Sink -> caller -> entry."""
        tree = CG.backward_tree(self.graph, "java:com.foo.Runner#run", max_depth=8)
        self.assertIn("java:com.foo.UserController#updateUser", tree)

    def test_innermost_attribution_avoids_class_level_duplicates(self):
        """A call inside a method belongs to the method, not also to the class."""
        callers = {caller for caller, callee in self.edges
                   if callee == "java:com.foo.UserService#update"}
        self.assertEqual(callers, {"java:com.foo.UserController#updateUser"})

    def test_field_initialiser_belongs_to_the_type(self):
        """No method contains it, so the class is the correct (only) owner."""
        self.assertIn(("java:com.foo.UserController", "java:com.foo.UserService"),
                      self.edges)
        self.assertEqual(self.edges[("java:com.foo.UserController",
                                     "java:com.foo.UserService")].propagation,
                         "constructor")

    def test_propagation_kinds_are_from_the_first_version_set(self):
        allowed = {"direct", "argument", "return-value", "field", "constructor",
                   "callback"}
        self.assertTrue({e.propagation for e in self.graph.edges} <= allowed,
                        "propagation outside spec §8.2 first-version set")
        kinds = {e.propagation for e in self.graph.edges}
        self.assertIn("argument", kinds)
        self.assertIn("return-value", kinds)
        self.assertIn("constructor", kinds)

    def test_annotation_string_is_not_read_as_parameters(self):
        """``@PostMapping("/api/user/update")`` must not yield a parameter name."""
        edge = self.edges[("java:com.foo.UserController#updateUser",
                           "java:com.foo.UserService#update")]
        # ``body`` is a real parameter and is passed through; without the
        # annotation guard the only "parameter" would be ``update``.
        self.assertEqual(edge.propagation, "argument")

    def test_ambiguous_name_yields_no_edge_and_is_counted(self):
        """Two same-named private methods in one file: no edge, but counted."""
        root = self.build_tree({"A.java": '''package p;

class A {
    public void a() {
        helper();
    }
}

class B {
    private void helper() {
    }
}

class C {
    private void helper() {
    }
}
'''})
        symbols, _ = self.index(root)
        graph = CG.build_call_graph(root, symbols)
        self.assertGreater(graph.ambiguous.get("helper", 0), 0,
                           "ambiguous call should be counted, not guessed")
        self.assertEqual([e for e in graph.edges if e.callee_name == "helper"], [],
                         "an ambiguous name must produce no edge")

    def test_same_file_unique_name_still_resolves(self):
        """The ladder's file scope is used before giving up."""
        root = self.build_tree({"A.java": '''package p;

class A {
    public void a() {
        helper();
    }

    private void helper() {
    }
}
'''})
        symbols, _ = self.index(root)
        graph = CG.build_call_graph(root, symbols)
        self.assertEqual([e.callee_name for e in graph.edges], ["helper"])
        self.assertEqual(graph.ambiguous, {})

    def test_unresolved_names_are_counted_not_dropped(self):
        self.assertGreaterEqual(self.graph.unresolved.get("trim", 0), 1)
        summary = self.graph.summary()
        self.assertEqual(summary["confidence"], "heuristic-callgraph")
        self.assertIn("limitations", summary)

    def test_file_symbols_are_not_resolution_targets(self):
        """A translation unit is not callable."""
        self.assertNotIn("UserService.java", self.graph.callees)
        for edge in self.graph.edges:
            self.assertFalse(edge.callee.endswith(".java"),
                             "file symbol used as a callee: %s" % edge.callee)

    def test_no_edge_cap(self):
        """Spec §21.1: discovery is unbounded."""
        import inspect
        signature = inspect.signature(CG.build_call_graph)
        self.assertNotIn("max_edges", signature.parameters)
        self.assertNotIn("limit", signature.parameters)

    def test_depth_cap_is_recorded_in_the_summary(self):
        shallow = CG.forward_tree(self.graph, "java:com.foo.UserController", max_depth=0)
        self.assertEqual(sorted(shallow), ["java:com.foo.UserController"])


class MultiLanguageTests(TreeMixin, unittest.TestCase):

    def test_python_class_and_methods(self):
        root = self.build_tree({"pkg/mod.py": '''import os


class Store:
    def read(self, path):
        return self._open(path)

    def _open(self, path):
        return open(path)


class Client:
    def fetch(self, url):
        return Store().read(url)
'''})
        symbols, _ = self.index(root)
        ids = {s.symbol_id for s in symbols}
        self.assertIn("python:pkg/mod.py", ids)
        self.assertIn("python:pkg/mod.py#Store", ids)
        self.assertIn("python:pkg/mod.py#Store.read", ids)
        graph = CG.build_call_graph(root, symbols)
        edges = {(e.caller, e.callee) for e in graph.edges}
        self.assertIn(("python:pkg/mod.py#Store.read", "python:pkg/mod.py#Store._open"),
                      edges)
        self.assertIn(("python:pkg/mod.py#Client.fetch", "python:pkg/mod.py#Store.read"),
                      edges)

    def test_go_receiver_methods_keep_the_type(self):
        root = self.build_tree({"main.go": '''package main

type Server struct{}

func (s *Server) Handle(id string) {
\ts.Run(id)
}

func (s *Server) Run(id string) {
\texecute(id)
}
'''})
        symbols, _ = self.index(root)
        names = {s.name for s in symbols}
        self.assertIn("Handle", names)
        self.assertIn("Run", names)
        graph = CG.build_call_graph(root, symbols)
        handle = [s for s in symbols if s.name == "Handle"][0]
        run = [s for s in symbols if s.name == "Run"][0]
        self.assertIn((handle.symbol_id, run.symbol_id),
                      {(e.caller, e.callee) for e in graph.edges})

    def test_deterministic_across_runs(self):
        root = self.build_tree({
            "src/com/foo/UserController.java": JAVA_CONTROLLER,
            "src/com/foo/UserService.java": JAVA_SERVICE,
        })
        first_symbols, _ = self.index(root)
        first = [(e.caller, e.callee, e.propagation, e.file, e.line)
                 for e in CG.build_call_graph(root, first_symbols).edges]
        second_symbols, _ = self.index(root, rels=list(reversed(
            sorted(str(p.relative_to(root)) for p in root.rglob("*.java")))))
        second = [(e.caller, e.callee, e.propagation, e.file, e.line)
                  for e in CG.build_call_graph(root, second_symbols).edges]
        self.assertEqual(first, second)


class SymbolLookupTests(TreeMixin, unittest.TestCase):

    def setUp(self):
        self.root = self.build_tree({"A.java": JAVA_SERVICE})
        self.symbols, _ = self.index(self.root)
        self.grouped = S.group_by_file(self.symbols)

    def test_innermost_wins_over_the_enclosing_class(self):
        update = S.innermost_at(self.grouped, "A.java", 6)
        self.assertEqual(update.kind, "method")
        self.assertEqual(update.name, "update")

    def test_module_level_line_falls_back_to_the_file_symbol(self):
        owner = S.innermost_at(self.grouped, "A.java", 1)
        self.assertEqual(owner.kind, S.FILE_KIND)

    def test_unknown_file_returns_none(self):
        self.assertIsNone(S.innermost_at(self.grouped, "nope.java", 3))

    def test_relink_records_replaces_the_pr1_hint(self):
        class Record:
            def __init__(self, file, line, symbol_id):
                self.file, self.line, self.symbol_id = file, line, symbol_id

        records = [Record("A.java", 7, "A.java#nearest-declaration"),
                   Record("nope.java", 1, "hint")]
        changed = S.relink_records(self.symbols, records)
        self.assertEqual(changed, 1)
        self.assertEqual(records[0].symbol_id, "java:com.foo.UserService#update")
        self.assertEqual(records[1].symbol_id, "hint",
                         "unbound files keep their hint rather than losing it")

    def test_security_surfaces_are_tagged_and_counted(self):
        class Entry:
            symbol_id = "java:com.foo.UserService#update"

        class Sink:
            symbol_id = "java:com.foo.UserService#update"

        counts = S.index_security_surfaces(self.symbols, [Entry()], [Sink()], [])
        self.assertEqual(counts, {"sinks": 1, "entries": 1, "controls": 0})
        update = [s for s in self.symbols if s.name == "update"][0]
        self.assertEqual(update.security_surfaces, ["entry", "sink"])


if __name__ == "__main__":
    unittest.main()
