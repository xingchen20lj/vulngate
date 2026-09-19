"""Cross-procedural flow: forward (spec §9) and backward (spec §10).

Three properties carry the weight here, and each one guards a *specific* way
the coverage layer can lie:

1. **A flow is cross-procedural or it is labelled as not being.**  A one-node
   path inside a method is the archetypal finding and must be kept; a one-node
   path at module scope says nothing about who controls the input and must not
   outrank a real call chain.  Both are reported, in different bands.
2. **The backward pass is independent of the forward pass.**  §10 exists to catch
   what "Source -> Sink" cannot see, so the backward verdict is asserted against
   a hand-built graph whose forward adjacency is empty -- if it were derived from
   the forward result, that test would pass only by accident.
3. **Nothing is dropped silently.**  A sink with no symbol binding, and a sink
   with no caller, both get a recorded verdict and a place in the gap list
   instead of quietly contributing zero.

Fixtures are real source trees plus the real catalogs, so the flow path also
proves the inventory and the call graph agree about symbol identity.
"""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from agent.analysis import dataflow as DF  # noqa: E402
from agent.analysis import inventory as INV  # noqa: E402
from agent.analysis import models  # noqa: E402
from agent.analysis import symbols as S  # noqa: E402
from agent.analysis.languages import SourceFilter  # noqa: E402


# --- spec §19.3 fixture: HTTP handler -> service -> helper -> ProcessBuilder --

CONTROLLER = '''package com.foo;

public class UserController {
    private final UserService service = new UserService();

    @PostMapping("/api/user/update")
    public String updateUser(String id, String body) {
        return service.update(id, body);
    }
}
'''

SERVICE = '''package com.foo;

public class UserService {
    private final Runner runner = new Runner();

    public String update(String id, String body) {
        String checked = sanitize(id);
        return runner.run(checked, body);
    }

    private String sanitize(String id) {
        return id.trim();
    }
}
'''

RUNNER = '''package com.foo;

public class Runner {
    public String run(String id, String body) {
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "echo " + body);
        return pb.start().toString();
    }
}
'''

# --- a handler that reaches the sink without crossing a function boundary ----

DIRECT_HANDLER = '''package com.foo;

public class DirectController {
    @PostMapping("/api/run")
    public String run(String cmd) {
        return Runtime.getRuntime().exec(cmd).toString();
    }
}
'''


class FlowFixture(unittest.TestCase):
    """Build a real tree, run the real inventory and keep the pieces."""

    FILES = {
        "src/com/foo/UserController.java": CONTROLLER,
        "src/com/foo/UserService.java": SERVICE,
        "src/com/foo/Runner.java": RUNNER,
    }

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vulngate-flow-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))
        self.write(self.FILES)
        self.build()

    def write(self, files):
        for rel, text in files.items():
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    def source_dirs(self):
        """Top-level directories of the fixture, so a subclass can relocate it."""
        return sorted({rel.split("/")[0] for rel in self.FILES})

    def build(self, with_flows=True):
        self.result = INV.build_inventory(self.root, source_dirs=self.source_dirs(),
                                          target="fixture")
        self.symbols = self.result.symbols
        self.entries = self.result.entries
        self.sinks = self.result.sinks
        self.controls = self.result.controls
        self.graph = None
        return self.result


class CrossProceduralFlowTests(FlowFixture):

    def test_spec_19_3_fixture_produces_a_flow(self):
        self.assertTrue(self.result.flows,
                        "handler -> service -> helper -> ProcessBuilder must "
                        "produce a FlowRecord (spec §19.3)")
        flows = [f for f in self.result.flows if "command-exec" in f.sink_id]
        self.assertTrue(flows)
        flow = sorted(flows, key=lambda f: len(f.path))[0]
        self.assertEqual(flow.path, [
            "java:com.foo.UserController#updateUser",
            "java:com.foo.UserService#update",
            "java:com.foo.Runner#run"])
        self.assertEqual(flow.direction, DF.DIRECTION_CROSS)
        self.assertEqual(flow.confidence, "heuristic-callgraph")
        self.assertEqual(flow.review_state, "pending")

    def test_flow_spans_files_classes_and_modules(self):
        flow = [f for f in self.result.flows if "command-exec" in f.sink_id][0]
        files = {s.file for s in self.symbols if s.symbol_id in flow.path}
        self.assertEqual(len(files), 3, "flow must cross three files")

    def test_short_high_severity_chain_is_high_priority(self):
        flow = [f for f in self.result.flows if "command-exec" in f.sink_id][0]
        self.assertEqual(flow.priority, "high")

    def test_flow_is_never_runtime_verified(self):
        """spec §9: heuristic may not be promoted to proof."""
        for flow in self.result.flows:
            self.assertNotEqual(flow.review_state, "runtime-verified")
            self.assertFalse(models.is_proving(flow.confidence),
                             "heuristic flow marked as proving")

    def test_controls_on_the_path_are_recorded_without_claiming_protection(self):
        flow = [f for f in self.result.flows if "command-exec" in f.sink_id][0]
        self.assertIn("sanitization:sanitize", flow.validations)
        # The service is on the path; the controller is not, so nothing here
        # should have manufactured an authorization.
        self.assertEqual(flow.authorizations, [])

    def test_sink_reachability_is_reflected_onto_the_sink_record(self):
        sink = [s for s in self.sinks if s.category == "command-exec"][0]
        self.assertTrue(sink.reachable_from_entries,
                        "§5.3 sink coverage reads this list for truthiness")
        self.assertTrue(sink.backward_reachable)
        self.assertTrue(sink.backward_entries)

    def test_coverage_metrics_see_the_flow(self):
        from agent.analysis import coverage as cov
        summary = cov.compute_coverage({
            "source-inventory": [f.as_dict() for f in self.result.files],
            "entry-index": [e.as_dict() for e in self.entries],
            "sink-index": [s.as_dict() for s in self.sinks],
            "security-control-index": [c.as_dict() for c in self.controls],
            "flow-index": [f.as_dict() for f in self.result.flows],
        })
        self.assertGreater(summary["counts"]["flows_total"], 0)
        self.assertGreater(summary["counts"]["flows_priority"], 0)
        self.assertIsNotNone(summary["metrics"]["flow_coverage"])

    def test_index_is_never_truncated_by_default(self):
        flow_index = DF.build_flow_index(self.root, self.symbols, self._graph(),
                                         self.entries, self.sinks, self.controls)
        self.assertFalse(flow_index.truncated)
        self.assertEqual(flow_index.dropped_flows, 0)

    def test_flow_ids_are_deterministic(self):
        first = [f.flow_id for f in self.result.flows]
        second = [f.flow_id for f in DF.build_flow_index(
            self.root, self.symbols, self._graph(), self.entries, self.sinks,
            self.controls).flows]
        self.assertEqual(first, second)
        self.assertEqual(first, sorted(first))

    def _graph(self):
        from agent.analysis import callgraph
        return callgraph.build_call_graph(self.root, self.symbols)


class IntraSymbolTests(FlowFixture):

    FILES = {
        "src/com/foo/DirectController.java": DIRECT_HANDLER,
    }

    def test_handler_reaching_a_sink_directly_is_kept(self):
        """A zero-hop path inside a method is the archetypal finding."""
        flows = [f for f in self.result.flows if "command-exec" in f.sink_id]
        self.assertTrue(flows, "direct handler -> exec must not be dropped")
        flow = flows[0]
        self.assertEqual(len(flow.path), 1)
        self.assertEqual(flow.direction, DF.DIRECTION_INTRA)
        self.assertEqual(flow.priority, "high",
                         "a handler hitting a high-severity sink stays high")

    def test_handler_symbol_is_not_a_file_symbol(self):
        flow = [f for f in self.result.flows if "command-exec" in f.sink_id][0]
        kind = {s.symbol_id: s.kind for s in self.symbols}[flow.source_symbol]
        self.assertNotEqual(kind, S.FILE_KIND)


class ModuleScopeTests(FlowFixture):

    FILES = {
        "pkg/mod_scope.py": '''import os
import sys


def dispatch(payload):
    return _run(payload)


def _run(payload):
    return os.system(payload)


if __name__ == "__main__":
    dispatch(sys.argv[1])
    os.system(sys.argv[2])
''',
    }

    def test_module_level_pair_is_labelled_not_ranked_as_a_chain(self):
        module_flows = [f for f in self.result.flows
                        if f.direction == DF.DIRECTION_MODULE]
        self.assertTrue(module_flows,
                        "module-scope entry/sink pair must still be recorded")
        for flow in module_flows:
            self.assertEqual(len(flow.path), 1)
            self.assertNotEqual(flow.priority, "high",
                                "module scope must not outrank real call chains")

    def test_real_chain_out_of_module_scope_is_cross_procedural(self):
        chains = [f for f in self.result.flows
                  if f.direction == DF.DIRECTION_CROSS]
        self.assertTrue(chains, "module __main__ block must reach the callee chain")
        self.assertTrue(any("_run" in " ".join(f.path) for f in chains))

    def test_module_scope_flows_are_still_recorded(self):
        """Labelled differently, never dropped."""
        summary = self.result.flow_summary
        by_direction = summary.get("flows_by_direction", {})
        self.assertIn(DF.DIRECTION_MODULE, by_direction)
        self.assertEqual(sum(by_direction.values()), summary["flows"])


class BackwardPassTests(unittest.TestCase):
    """Spec §10: the backward verdict must not be derived from the forward one."""

    def setUp(self):
        self.symbols = [
            models.SymbolRecord(symbol_id="t:A#handler", language="t",
                                file="A.t", start_line=1, end_line=4,
                                kind="function", name="handler"),
            models.SymbolRecord(symbol_id="t:B#middle", language="t",
                                file="B.t", start_line=1, end_line=4,
                                kind="function", name="middle"),
            models.SymbolRecord(symbol_id="t:C#deep", language="t",
                                file="C.t", start_line=1, end_line=4,
                                kind="function", name="deep"),
        ]
        self.entries = [models.EntryRecord(
            entry_id="http:A.t:1", kind="http", file="A.t", line=1,
            symbol_id="t:A#handler")]
        self.sinks = [models.SinkRecord(
            sink_id="sink:command-exec:C.t:2", category="command-exec",
            file="C.t", line=2, symbol_id="t:C#deep", severity_hint="high")]

    def _graph(self, callees, callers):
        graph = __import__("agent.analysis.callgraph", fromlist=["CallGraph"]).CallGraph(
            symbol_ids={s.symbol_id for s in self.symbols})
        graph.callees = {k: sorted(v) for k, v in callees.items()}
        graph.callers = {k: sorted(v) for k, v in callers.items()}
        return graph

    def test_backward_only_sink_becomes_a_recorded_gap(self):
        """Forward adjacency is empty: only the backward walk can see the path."""
        graph = self._graph(
            callees={},
            callers={"t:C#deep": ["t:B#middle"], "t:B#middle": ["t:A#handler"]})
        index = DF.build_flow_index(Path("."), self.symbols, graph, self.entries,
                                    self.sinks)
        sink = self.sinks[0]
        self.assertTrue(sink.backward_reachable, "backward walk found the handler")
        self.assertEqual(sink.backward_entries, ["http:A.t:1"])
        self.assertFalse(sink.reachable_from_entries)
        verdict = index.reachability["sink:command-exec:C.t:2"]
        self.assertEqual(verdict.coverage_gap, DF.GAP_BACKWARD_ONLY,
                         "§19.4: a path only the sink scan can see must be a gap")
        self.assertTrue(index.gaps())

    def test_forward_and_backward_agreeing_paths_leave_no_gap(self):
        graph = self._graph(
            callees={"t:A#handler": ["t:B#middle"], "t:B#middle": ["t:C#deep"]},
            callers={"t:C#deep": ["t:B#middle"], "t:B#middle": ["t:A#handler"]})
        index = DF.build_flow_index(Path("."), self.symbols, graph, self.entries,
                                    self.sinks)
        flow = index.flows[0]
        self.assertEqual(flow.coverage_gap, "")
        self.assertEqual(flow.path, ["t:A#handler", "t:B#middle", "t:C#deep"])
        self.assertEqual(index.reachability["sink:command-exec:C.t:2"].coverage_gap,
                         "")

    def test_disagreeing_paths_are_flagged(self):
        """§10: forward path != backward path."""
        graph = self._graph(
            callees={"t:A#handler": ["t:B#middle"], "t:B#middle": ["t:C#deep"]},
            # The backward walk sees a *different* chain: A -> C -> sink.
            callers={"t:C#deep": ["t:A#handler"]})
        index = DF.build_flow_index(Path("."), self.symbols, graph, self.entries,
                                    self.sinks)
        self.assertEqual(index.flows[0].coverage_gap, DF.GAP_PATH_MISMATCH)
        self.assertEqual(index.flows[0].priority, "high",
                         "a gap escalates priority: the graph is ambiguous here")

    def test_sink_with_no_caller_is_isolated_not_ignored(self):
        graph = self._graph(callees={}, callers={})
        index = DF.build_flow_index(Path("."), self.symbols, graph, self.entries,
                                    self.sinks)
        verdict = index.reachability["sink:command-exec:C.t:2"]
        self.assertEqual(verdict.coverage_gap, DF.GAP_ISOLATED)
        self.assertEqual(index.flows, [])
        self.assertIn("isolated", index.summary()["coverage_gaps"])


class UnboundRecordTests(unittest.TestCase):
    """A record with no symbol cannot be walked -- so it must be surfaced."""

    def test_unbound_sink_is_counted_and_sampled(self):
        symbols = [models.SymbolRecord(symbol_id="t:A#f", language="t", file="A.t",
                                       start_line=1, end_line=3, kind="function",
                                       name="f")]
        entries = [models.EntryRecord(entry_id="http:A.t:1", kind="http", file="A.t",
                                      line=1, symbol_id="t:A#f")]
        # Line 99 is outside every symbol range, and the file has no symbol at
        # all, so neither the hint nor the line lookup can bind it.
        sinks = [models.SinkRecord(sink_id="sink:exec:Z.t:99", category="command-exec",
                                   file="Z.t", line=99, symbol_id="Z.t#hint",
                                   severity_hint="high")]
        graph = __import__("agent.analysis.callgraph", fromlist=["CallGraph"]).CallGraph(
            symbol_ids={"t:A#f"})
        index = DF.build_flow_index(Path("."), symbols, graph, entries, sinks)
        self.assertEqual(index.sinks_unbound, 1)
        self.assertEqual(index.reachability["sink:exec:Z.t:99"].coverage_gap,
                         DF.GAP_UNBOUND)
        summary = index.summary()
        self.assertEqual(summary["sinks_unbound"], 1)
        self.assertTrue(summary["unbound_samples"], "shortfall must be visible")

    def test_entry_bound_by_line_lookup_when_the_hint_is_stale(self):
        """PR1 wrote ``<file>#<declaration>`` hints; PR2 re-binds them."""
        symbols = [models.SymbolRecord(symbol_id="t:A#f", language="t", file="A.t",
                                       start_line=1, end_line=3, kind="function",
                                       name="f")]
        entries = [models.EntryRecord(entry_id="http:A.t:2", kind="http", file="A.t",
                                      line=2, symbol_id="A.t#f")]
        graph = __import__("agent.analysis.callgraph", fromlist=["CallGraph"]).CallGraph(
            symbol_ids={"t:A#f"})
        index = DF.build_flow_index(Path("."), symbols, graph, entries, [])
        self.assertEqual(index.entries_unbound, 0)
        self.assertEqual(entries[0].symbol_id, "t:A#f")


class BoundTests(unittest.TestCase):
    """``max_flows`` is a safety valve, and hitting it must be visible."""

    def test_truncation_is_recorded(self):
        symbols = [models.SymbolRecord(symbol_id="t:A#f", language="t", file="A.t",
                                       start_line=1, end_line=3, kind="function",
                                       name="f"),
                   models.SymbolRecord(symbol_id="t:B#g", language="t", file="B.t",
                                       start_line=1, end_line=3, kind="function",
                                       name="g")]
        entries = [models.EntryRecord(entry_id="http:A.t:%d" % n, kind="http",
                                      file="A.t", line=1, symbol_id="t:A#f")
                   for n in range(1, 4)]
        sinks = [models.SinkRecord(sink_id="sink:exec:B.t:%d" % n,
                                   category="command-exec", file="B.t", line=n,
                                   symbol_id="t:B#g", severity_hint="high")
                 for n in range(1, 4)]
        graph = __import__("agent.analysis.callgraph", fromlist=["CallGraph"]).CallGraph(
            symbol_ids={"t:A#f", "t:B#g"})
        graph.callees = {"t:A#f": ["t:B#g"]}
        graph.callers = {"t:B#g": ["t:A#f"]}
        index = DF.build_flow_index(Path("."), symbols, graph, entries, sinks,
                                    max_flows=2)
        self.assertTrue(index.truncated)
        self.assertEqual(index.dropped_flows, 7)
        self.assertEqual(len(index.flows), 2)
        self.assertTrue(index.summary()["truncated"])


class SummarizeTests(FlowFixture):

    def test_presenter_is_bounded_and_priority_ordered(self):
        shown = DF.summarize_flows(self.result.flows, limit=1)
        self.assertEqual(len(shown), 1)
        best = min(self.result.flows,
                   key=lambda f: (DF.PRIORITY_ORDER.get(f.priority, 9),
                                  len(f.path), f.flow_id))
        self.assertEqual(shown[0]["flow_id"], best.flow_id)
        self.assertIn("hops", shown[0])

    def test_stats_cover_every_flow(self):
        stats = DF.flow_stats(self.result.flows)
        self.assertEqual(stats["total"], len(self.result.flows))
        self.assertEqual(stats["high"] + stats["medium"] + stats["low"],
                         len(self.result.flows))
        self.assertEqual(stats["pending"], len(self.result.flows))


class PersistenceTests(FlowFixture):

    def test_pr2_indices_are_persisted_and_readable(self):
        store = INV.CoverageStore(self.root, "fixture")
        written = INV.persist_inventory(store, self.result)
        for name in ("symbol-index", "call-graph", "flow-index",
                     "sink-reachability", "call-graph-summary", "flow-summary"):
            self.assertIn(name, written)
        loaded = INV.load_inventory(store)
        self.assertEqual(len(loaded["symbol-index"]), len(self.symbols))
        self.assertEqual(len(loaded["flow-index"]), len(self.result.flows))
        self.assertTrue(loaded["sink-reachability"])
        self.assertEqual(loaded["flow-summary"]["flows"], len(self.result.flows))

    def test_persisted_flow_index_is_json_serialisable(self):
        store = INV.CoverageStore(self.root, "fixture")
        INV.persist_inventory(store, self.result)
        payload = json.loads((store.path("flow-index")).read_text(encoding="utf-8"))
        self.assertIsInstance(payload, list)
        self.assertEqual(len(payload), len(self.result.flows))

    def test_flow_summary_reports_limits_explicitly(self):
        summary = self.result.flow_summary
        self.assertEqual(summary["confidence"], "heuristic-callgraph")
        self.assertEqual(summary["evidence_type"], "static-inferred")
        self.assertIn("limitations", summary)
        self.assertFalse(summary["truncated"])


if __name__ == "__main__":
    unittest.main()
