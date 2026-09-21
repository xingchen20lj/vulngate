"""Tests for bounded language-aware Python value-binding evidence."""

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
from agent.analysis import semantic_bindings  # noqa: E402
from agent.analysis import semantic_paths  # noqa: E402
from agent.analysis import semantic_transforms  # noqa: E402
from agent.analysis.inventory import CoverageStore  # noqa: E402


class SemanticBindingEvidenceTests(unittest.TestCase):
    def _fixture(self, source, sink_line, control_line,
                 control_category="sanitization", api="sanitize",
                 parameters=None):
        root = Path(tempfile.mkdtemp(prefix="vulngate-binding-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        (root / "app.py").write_text(source, encoding="utf-8")
        symbol_id = "python:app.py#handler"
        symbol = models.SymbolRecord(
            symbol_id=symbol_id, language="python", file="app.py",
            start_line=1, end_line=len(source.splitlines()), kind="function",
            name="handler", parameters=parameters or ["value"])
        entry = models.EntryRecord(
            entry_id="entry-1", kind="http", file="app.py", line=1,
            symbol_id=symbol_id, input_shape="query")
        sink = models.SinkRecord(
            sink_id="sink-1", category="command-exec", file="app.py",
            line=sink_line, symbol_id=symbol_id, api="os.system",
            text="os.system(...)", severity_hint="high")
        control = models.SecurityControlRecord(
            control_id="control-transform", category=control_category,
            file="app.py", line=control_line, symbol_id=symbol_id,
            control_type=control_category, api=api)
        flow = models.FlowRecord(
            flow_id="flow-1", entry_id=entry.entry_id,
            source_symbol=symbol_id, sink_id=sink.sink_id, path=[symbol_id])
        control_map = controls.build_control_map(
            [entry], [sink], [flow], [control]).as_dict()
        paths = semantic_paths.build_semantic_path_evidence(
            root, [entry], [sink], [flow], [control], [symbol], control_map)
        transforms = semantic_transforms.build_semantic_transform_evidence(
            root, paths)
        bindings = semantic_bindings.build_semantic_binding_evidence(
            root, transforms, [symbol])
        return root, symbol, transforms, bindings

    def test_ast_binds_a_transformed_assignment(self):
        _root, _symbol, _transforms, evidence = self._fixture(
            "def handler(value):\n"
            "    safe = sanitize(value)\n"
            "    os.system(safe)\n",
            sink_line=3, control_line=2)
        binding = evidence["flows"][0]["controls"][0]
        self.assertEqual("ast-bound", binding["relation"])
        self.assertEqual(0, evidence["summary"]["candidates"])

    def test_ast_keeps_discarded_control_as_raw_at_sink(self):
        _root, _symbol, _transforms, evidence = self._fixture(
            "def handler(value):\n"
            "    sanitize(value)\n"
            "    os.system(value)\n",
            sink_line=3, control_line=2)
        binding = evidence["flows"][0]["controls"][0]
        self.assertEqual("ast-raw-at-sink", binding["relation"])
        self.assertEqual(1, evidence["summary"]["candidates"])
        self.assertEqual("not-a-finding",
                         evidence["candidates"][0]["claim_status"])

    def test_opaque_source_keeps_the_local_binding_relevant(self):
        _root, _symbol, _transforms, evidence = self._fixture(
            "def handler(value):\n"
            "    value = request.args.get('value')\n"
            "    sanitize(value)\n"
            "    os.system(value)\n",
            sink_line=4, control_line=3)
        binding = evidence["flows"][0]["controls"][0]
        self.assertEqual("ast-unresolved", binding["relation"])
        self.assertEqual(1, evidence["summary"]["candidates"])

    def test_ast_preserves_guard_and_branch_merge_states(self):
        _root, _symbol, _transforms, evidence = self._fixture(
            "def handler(value):\n"
            "    if validate(value):\n"
            "        os.system(value)\n",
            sink_line=3, control_line=2,
            control_category="validation", api="validate")
        self.assertEqual("ast-guard-condition",
                         evidence["flows"][0]["controls"][0]["relation"])

        _root, _symbol, _transforms, evidence = self._fixture(
            "def handler(value, ok):\n"
            "    if ok:\n"
            "        safe = sanitize(value)\n"
            "    else:\n"
            "        safe = value\n"
            "    os.system(safe)\n",
            sink_line=6, control_line=3, parameters=["value", "ok"])
        binding = evidence["flows"][0]["controls"][0]
        self.assertEqual("ast-branch-merged", binding["relation"])
        self.assertGreaterEqual(binding["path_count"], 2)

    def test_non_python_is_an_explicit_adapter_gap(self):
        root = Path(tempfile.mkdtemp(prefix="vulngate-binding-java-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        (root / "App.java").write_text(
            "class App { void run(String value) { sanitize(value); sink(value); } }\n",
            encoding="utf-8")
        symbol_id = "java:App#run"
        symbol = models.SymbolRecord(
            symbol_id=symbol_id, language="java", file="App.java",
            start_line=1, end_line=1, kind="method", name="run",
            parameters=["value"])
        evidence = semantic_bindings.build_semantic_binding_evidence(
            root, {
                "flows": [{
                    "flow_id": "flow-java", "entry_id": "entry-java",
                    "sink_id": "sink-java", "source_symbol": symbol_id,
                    "sink_symbol": symbol_id, "path": [symbol_id],
                    "entry": {"file": "App.java", "line": 1,
                              "entry_id": "entry-java"},
                    "sink": {"file": "App.java", "line": 1,
                             "category": "command-exec", "api": "sink"},
                    "static_control_verdict": "guarded",
                    "transforms": [{
                        "control_id": "control-java", "category": "sanitization",
                        "file": "App.java", "line": 1, "symbol_id": symbol_id,
                        "relation": "transform-result-discarded",
                        "input_variables": ["value"],
                        "required_category": True,
                    }],
                }]
            }, [symbol])
        binding = evidence["flows"][0]["controls"][0]
        self.assertEqual("unsupported-language", binding["relation"])
        self.assertEqual(1, evidence["summary"]["candidates"])

    def test_artifact_is_deterministic_bounded_and_enters_static_pool(self):
        root, _symbol, _transforms, first = self._fixture(
            "def handler(value):\n"
            "    sanitize(value)\n"
            "    os.system(value)\n",
            sink_line=3, control_line=2)
        second = semantic_bindings.build_semantic_binding_evidence(
            root, _transforms, [_symbol])
        self.assertEqual(first, second)
        self.assertNotIn("def handler", json.dumps(first, ensure_ascii=False))
        self.assertEqual("not-a-finding", first["claim_status"])

        with tempfile.TemporaryDirectory() as workspace_dir:
            store = CoverageStore(Path(workspace_dir), "demo")
            store.write(semantic_bindings.SEMANTIC_BINDING_CANDIDATE_INDEX,
                        first["candidates"])
            merged = controls.static_candidates(store)
            self.assertEqual("semantic-python-binding", merged[0]["source"])


if __name__ == "__main__":
    unittest.main()
