"""Tests for bounded transform-result binding evidence."""

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
from agent.analysis import semantic_paths  # noqa: E402
from agent.analysis import semantic_transforms  # noqa: E402
from agent.analysis.inventory import CoverageStore  # noqa: E402


class SemanticTransformEvidenceTests(unittest.TestCase):
    def _fixture(self, source, sink_line=3, control_line=2,
                 control_category="sanitization", api="sanitize"):
        root = Path(tempfile.mkdtemp(prefix="vulngate-transform-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        (root / "app.py").write_text(source, encoding="utf-8")
        symbol_id = "python:app.py#handler"
        symbol = models.SymbolRecord(
            symbol_id=symbol_id, language="python", file="app.py",
            start_line=1, end_line=len(source.splitlines()), kind="function",
            name="handler", parameters=["value"])
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
        return root, paths

    def test_bound_result_is_distinguished_from_a_binding_gap(self):
        root, paths = self._fixture(
            "def handler(value):\n"
            "    safe = sanitize(value)\n"
            "    os.system(safe)\n")
        evidence = semantic_transforms.build_semantic_transform_evidence(
            root, paths)
        transform = evidence["flows"][0]["transforms"][0]
        self.assertEqual("assignment-bound", transform["relation"])
        self.assertEqual(0, evidence["summary"]["candidates"])

    def test_discarded_result_becomes_a_manual_research_lead(self):
        root, paths = self._fixture(
            "def handler(value):\n"
            "    sanitize(value)\n"
            "    os.system(value)\n")
        evidence = semantic_transforms.build_semantic_transform_evidence(
            root, paths)
        transform = evidence["flows"][0]["transforms"][0]
        self.assertEqual("transform-result-discarded", transform["relation"])
        self.assertEqual(1, evidence["summary"]["candidates"])
        candidate = evidence["candidates"][0]
        self.assertEqual("semantic-transform-gap", candidate["surface"])
        self.assertTrue(candidate["requires_manual_dataflow"])
        self.assertEqual("not-a-finding", candidate["claim_status"])

    def test_overwrite_and_unresolved_scope_stay_explicit(self):
        root, paths = self._fixture(
            "def handler(value):\n"
            "    safe = sanitize(value)\n"
            "    safe = value\n"
            "    os.system(safe)\n",
            sink_line=4)
        evidence = semantic_transforms.build_semantic_transform_evidence(
            root, paths)
        transform = evidence["flows"][0]["transforms"][0]
        self.assertEqual("overwritten-after-transform", transform["relation"])
        self.assertIn("safe", transform["overwritten_variables"])

        root, paths = self._fixture(
            "def handler(value):\n"
            "    safe = sanitize(value)\n"
            "    safe = value\n"
            "    command = safe\n"
            "    os.system(command)\n",
            sink_line=5)
        evidence = semantic_transforms.build_semantic_transform_evidence(
            root, paths)
        transform = evidence["flows"][0]["transforms"][0]
        self.assertEqual("overwritten-after-transform", transform["relation"])
        self.assertIn("command", transform["raw_variables_after_transform"])

    def test_same_transform_name_with_a_different_input_is_not_bound(self):
        root, paths = self._fixture(
            "def handler(value, other):\n"
            "    sanitize(value)\n"
            "    os.system(sanitize(other))\n")
        evidence = semantic_transforms.build_semantic_transform_evidence(
            root, paths)
        transform = evidence["flows"][0]["transforms"][0]
        self.assertNotEqual("direct-bound", transform["relation"])
        self.assertEqual("transform-result-discarded", transform["relation"])
        self.assertEqual(1, evidence["summary"]["candidates"])

    def test_artifact_is_deterministic_bounded_and_enters_static_pool(self):
        root, paths = self._fixture(
            "def handler(value):\n"
            "    sanitize(value)\n"
            "    os.system(value)\n")
        first = semantic_transforms.build_semantic_transform_evidence(root, paths)
        second = semantic_transforms.build_semantic_transform_evidence(root, paths)
        self.assertEqual(first, second)
        self.assertNotIn("def handler", json.dumps(first, ensure_ascii=False))
        self.assertEqual("not-a-finding", first["claim_status"])

        with tempfile.TemporaryDirectory() as workspace_dir:
            store = CoverageStore(Path(workspace_dir), "demo")
            store.write(semantic_transforms.SEMANTIC_TRANSFORM_CANDIDATE_INDEX,
                        first["candidates"])
            merged = controls.static_candidates(store)
            self.assertEqual("semantic-transforms", merged[0]["source"])


if __name__ == "__main__":
    unittest.main()
