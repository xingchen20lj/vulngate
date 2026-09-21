import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.analysis import controls  # noqa: E402
from agent.analysis import models  # noqa: E402
from agent.analysis import semantic_paths  # noqa: E402
from agent.analysis.inventory import CoverageStore  # noqa: E402


class SemanticPathEvidenceTests(unittest.TestCase):
    def _fixture(self, source, sink_line=5, control_lines=(2, 4),
                 sink_argument="safe"):
        root = Path(tempfile.mkdtemp())
        (root / "app.py").write_text(source, encoding="utf-8")
        symbol_id = "python:app.py#handler"
        symbol = models.SymbolRecord(
            symbol_id=symbol_id, language="python", file="app.py",
            start_line=1, end_line=len(source.splitlines()), kind="function",
            name="handler")
        entry = models.EntryRecord(
            entry_id="entry-1", kind="http", file="app.py", line=1,
            symbol_id=symbol_id, input_shape="query")
        sink = models.SinkRecord(
            sink_id="sink-1", category="command-exec", file="app.py",
            line=sink_line, symbol_id=symbol_id, api="os.system",
            text="os.system(%s)" % sink_argument, severity_hint="high")
        controls_list = []
        categories = ["authorization", "validation"]
        for index, line in enumerate(control_lines):
            controls_list.append(models.SecurityControlRecord(
                control_id="control-%d" % index, category=categories[index % 2],
                file="app.py", line=line, symbol_id=symbol_id,
                api="check_%d" % index))
        flow = models.FlowRecord(
            flow_id="flow-1", entry_id=entry.entry_id,
            source_symbol=symbol_id, sink_id=sink.sink_id, path=[symbol_id])
        cmap = controls.build_control_map(
            [entry], [sink], [flow], controls_list).as_dict()
        return root, symbol, entry, sink, controls_list, flow, cmap

    def test_propagated_same_symbol_taint_and_aligned_controls(self):
        root, symbol, entry, sink, controls_list, flow, cmap = self._fixture(
            "def handler(path):\n"
            "    check_auth(path)\n"
            "    safe = normalize(path)\n"
            "    check_input(safe)\n"
            "    os.system(safe)\n")
        evidence = semantic_paths.build_semantic_path_evidence(
            root, [entry], [sink], [flow], controls_list, [symbol], cmap)
        row = evidence["flows"][0]
        self.assertEqual(row["semantic_verdict"], "aligned")
        self.assertEqual(row["taint"]["status"], "propagated")
        self.assertEqual(evidence["summary"]["candidates"], 0)
        self.assertEqual(row["claim_status"], "not-a-finding")

    def test_after_sink_control_and_unresolved_alias_become_leads(self):
        root, symbol, entry, sink, controls_list, flow, cmap = self._fixture(
            "def handler(path):\n"
            "    os.system(untrusted_value)\n"
            "    check_input(path)\n"
            "    check_auth(path)\n",
            sink_line=2, control_lines=(3, 4), sink_argument="untrusted_value")
        evidence = semantic_paths.build_semantic_path_evidence(
            root, [entry], [sink], [flow], controls_list, [symbol], cmap)
        row = evidence["flows"][0]
        self.assertEqual(row["semantic_verdict"], "order-unverified")
        self.assertEqual(row["taint"]["status"], "not-traced")
        surfaces = {candidate["surface"] for candidate in evidence["candidates"]}
        self.assertIn("control-order-unverified", surfaces)
        self.assertIn("semantic-dataflow-gap", surfaces)
        self.assertTrue(all(candidate["claim_status"] == "not-a-finding"
                            for candidate in evidence["candidates"]))

    def test_cross_symbol_taint_remains_unresolved(self):
        root = Path(tempfile.mkdtemp())
        (root / "app.py").write_text(
            "def handler(path):\n    return worker(path)\n\n"
            "def worker(value):\n    os.system(value)\n",
            encoding="utf-8")
        source_id = "python:app.py#handler"
        sink_id = "python:app.py#worker"
        source = models.SymbolRecord(source_id, "python", "app.py", 1, 2,
                                     "function", "handler")
        sink_symbol = models.SymbolRecord(sink_id, "python", "app.py", 4, 5,
                                          "function", "worker")
        entry = models.EntryRecord("entry-1", "http", "app.py", 1, source_id,
                                   "query")
        sink = models.SinkRecord("sink-1", "command-exec", "app.py", 5,
                                 sink_id, "os.system", severity_hint="high")
        flow = models.FlowRecord("flow-1", "entry-1", source_id, "sink-1",
                                 [source_id, sink_id])
        evidence = semantic_paths.build_semantic_path_evidence(
            root, [entry], [sink], [flow], [], [source, sink_symbol],
            controls.build_control_map([entry], [sink], [flow], []).as_dict())
        self.assertEqual(evidence["flows"][0]["taint"]["status"],
                         "cross-symbol-unresolved")
        self.assertEqual(evidence["summary"]["cross_symbol_flows"], 1)

    def test_artifact_is_deterministic_and_static_candidates_are_merged(self):
        root, symbol, entry, sink, controls_list, flow, cmap = self._fixture(
            "def handler(path):\n"
            "    os.system(path)\n"
            "    check_input(path)\n",
            sink_line=2, control_lines=(3,), sink_argument="path")
        first = semantic_paths.build_semantic_path_evidence(
            root, [entry], [sink], [flow], controls_list, [symbol], cmap)
        second = semantic_paths.build_semantic_path_evidence(
            root, [entry], [sink], [flow], controls_list, [symbol], cmap)
        self.assertEqual(first, second)
        self.assertNotIn("def handler", json.dumps(first, ensure_ascii=False))

        with tempfile.TemporaryDirectory() as workspace_dir:
            store = CoverageStore(Path(workspace_dir), "demo")
            store.write(semantic_paths.SEMANTIC_CANDIDATE_INDEX,
                        [{"candidate_id": "sem-test", "claim_status": "not-a-finding"}])
            merged = controls.static_candidates(store)
            self.assertEqual(["sem-test"], [row["candidate_id"] for row in merged])


if __name__ == "__main__":
    unittest.main()
