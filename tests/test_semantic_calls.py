"""Tests for bounded one-hop interprocedural binding evidence."""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.analysis import controls  # noqa: E402
from agent.analysis import models  # noqa: E402
from agent.analysis import semantic_calls  # noqa: E402
from agent.analysis.inventory import CoverageStore  # noqa: E402


class SemanticCallEvidenceTests(unittest.TestCase):
    def _fixture(self, source, argument="path", sink_argument="value",
                 call_line=2, callee_end=6):
        root = Path(tempfile.mkdtemp(prefix="vulngate-calls-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        (root / "app.py").write_text(source, encoding="utf-8")
        handler_id = "python:app.py#handler"
        worker_id = "python:app.py#worker"
        symbols = [
            models.SymbolRecord(handler_id, "python", "app.py", 1, 3,
                                "function", "handler", parameters=["path"]),
            models.SymbolRecord(worker_id, "python", "app.py", 5, callee_end,
                                "function", "worker", parameters=["value"]),
        ]
        entry = models.EntryRecord("entry-1", "http", "app.py", 1,
                                  handler_id, "query")
        sink_line = next(number for number, line in enumerate(
            source.splitlines(), 1) if "os.system" in line)
        sink = models.SinkRecord("sink-1", "command-exec", "app.py", sink_line,
                                 worker_id, "os.system", "os.system(...)",
                                 severity_hint="high")
        flow = models.FlowRecord("flow-1", "entry-1", handler_id, "sink-1",
                                 [handler_id, worker_id])
        edge = models.CallEdge(handler_id, worker_id, file="app.py",
                               line=call_line, propagation="argument",
                               callee_name="worker")
        return root, entry, sink, flow, symbols, [edge]

    def test_direct_parameter_binding_closes_a_cross_symbol_sink(self):
        root, entry, sink, flow, symbols, edges = self._fixture(
            "def handler(path):\n"
            "    return worker(path)\n"
            "\n"
            "\n"
            "def worker(value):\n"
            "    os.system(value)\n")
        evidence = semantic_calls.build_semantic_call_evidence(
            root, [entry], [sink], [flow], symbols, edges)
        row = evidence["flows"][0]
        step = row["call_steps"][0]
        self.assertEqual("resolved", step["callsite_status"])
        self.assertEqual("bound", step["binding_status"])
        self.assertEqual("direct", step["argument_bindings"][0]["binding_status"])
        self.assertEqual("bound", row["sink_binding"]["status"])
        self.assertEqual(0, evidence["summary"]["candidates"])

    def test_unknown_argument_becomes_a_manual_binding_lead(self):
        root, entry, sink, flow, symbols, edges = self._fixture(
            "def handler(path):\n"
            "    return worker(config.value)\n"
            "\n"
            "\n"
            "def worker(value):\n"
            "    os.system(value)\n")
        evidence = semantic_calls.build_semantic_call_evidence(
            root, [entry], [sink], [flow], symbols, edges)
        row = evidence["flows"][0]
        self.assertEqual("unresolved", row["call_steps"][0]["binding_status"])
        self.assertEqual("unresolved", row["sink_binding"]["status"])
        self.assertEqual(1, evidence["summary"]["candidates"])
        self.assertEqual("semantic-interprocedural-binding",
                         evidence["candidates"][0]["surface"])

    def test_return_shape_is_recorded_without_becoming_effect_evidence(self):
        root, entry, sink, flow, symbols, edges = self._fixture(
            "def handler(path):\n"
            "    return worker(path)\n"
            "\n"
            "\n"
            "def worker(value):\n"
            "    return value\n"
            "    os.system(value)\n",
            callee_end=7)
        evidence = semantic_calls.build_semantic_call_evidence(
            root, [entry], [sink], [flow], symbols, edges)
        returned = evidence["flows"][0]["call_steps"][0]["return_binding"]
        self.assertEqual("tainted-return-likely", returned["status"])
        self.assertEqual("not-a-finding", evidence["claim_status"])

    def test_artifact_is_deterministic_bounded_and_enters_static_pool(self):
        root, entry, sink, flow, symbols, edges = self._fixture(
            "def handler(path):\n"
            "    return worker(config.value)\n"
            "\n"
            "\n"
            "def worker(value):\n"
            "    os.system(value)\n")
        first = semantic_calls.build_semantic_call_evidence(
            root, [entry], [sink], [flow], symbols, edges)
        second = semantic_calls.build_semantic_call_evidence(
            root, [entry], [sink], [flow], symbols, edges)
        self.assertEqual(first, second)
        self.assertNotIn("def handler", json.dumps(first, ensure_ascii=False))
        self.assertTrue(all(item["requires_manual_dataflow"]
                            for item in first["candidates"]))
        with tempfile.TemporaryDirectory() as workspace_dir:
            store = CoverageStore(Path(workspace_dir), "demo")
            store.write(semantic_calls.SEMANTIC_CALL_CANDIDATE_INDEX,
                        first["candidates"])
            merged = controls.static_candidates(store)
            self.assertEqual("semantic-calls", merged[0]["source"])


if __name__ == "__main__":
    unittest.main()
