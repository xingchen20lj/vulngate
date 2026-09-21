"""Tests for bounded branch-dominance and alternate-path evidence."""

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
from agent.analysis import semantic_controlflow  # noqa: E402
from agent.analysis import semantic_guards  # noqa: E402
from agent.analysis import semantic_paths  # noqa: E402
from agent.analysis.inventory import CoverageStore  # noqa: E402


class SemanticControlflowEvidenceTests(unittest.TestCase):
    def _fixture(self, source, sink_category="privilege"):
        root = Path(tempfile.mkdtemp(prefix="vulngate-controlflow-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        (root / "app.py").write_text(source, encoding="utf-8")
        symbol_id = "python:app.py#handler"
        symbol = models.SymbolRecord(
            symbol_id=symbol_id, language="python", file="app.py",
            start_line=1, end_line=len(source.splitlines()), kind="function",
            name="handler", parameters=["user_id", "object_id"])
        entry = models.EntryRecord(
            entry_id="entry-1", kind="http", file="app.py", line=1,
            symbol_id=symbol_id, input_shape="query")
        sink_line = next(number for number, line in enumerate(
            source.splitlines(), 1) if "os.system" in line)
        sink = models.SinkRecord(
            sink_id="sink-1", category=sink_category, file="app.py",
            line=sink_line, symbol_id=symbol_id, api="os.system",
            text="os.system(...)", severity_hint="high")
        control = models.SecurityControlRecord(
            control_id="control-authz", category="authorization",
            file="app.py", line=2, symbol_id=symbol_id,
            control_type="authorization", api="has_permission")
        flow = models.FlowRecord(
            flow_id="flow-1", entry_id=entry.entry_id,
            source_symbol=symbol_id, sink_id=sink.sink_id, path=[symbol_id])
        cmap = controls.build_control_map(
            [entry], [sink], [flow], [control]).as_dict()
        paths = semantic_paths.build_semantic_path_evidence(
            root, [entry], [sink], [flow], [control], [symbol], cmap)
        guards = semantic_guards.build_semantic_guard_evidence(root, paths)
        return root, guards

    def test_rejecting_guard_after_its_body_is_dominance_lead(self):
        root, guards = self._fixture(
            "def handler(user_id, object_id):\n"
            "    if not has_permission(user_id):\n"
            "        return\n"
            "    os.system(object_id)\n")
        evidence = semantic_controlflow.build_semantic_controlflow_evidence(
            root, guards)
        relation = evidence["flows"][0]["controls"][0]["control_flow"]
        self.assertEqual("terminating-guard-likely", relation["relation"])
        self.assertEqual("dominates-likely", relation["dominance"])
        self.assertEqual("none", relation["alternate_path_status"])

    def test_sink_in_else_branch_is_an_alternate_path_lead(self):
        root, guards = self._fixture(
            "def handler(user_id, object_id):\n"
            "    if has_permission(user_id):\n"
            "        audit(object_id)\n"
            "    else:\n"
            "        os.system(object_id)\n")
        evidence = semantic_controlflow.build_semantic_controlflow_evidence(
            root, guards)
        relation = evidence["flows"][0]["controls"][0]["control_flow"]
        self.assertEqual("alternate-path-likely", relation["relation"])
        self.assertEqual("present", relation["alternate_path_status"])
        self.assertEqual(1, evidence["summary"]["candidates"])

    def test_positive_guard_branch_and_plain_check_are_distinct(self):
        root, guards = self._fixture(
            "def handler(user_id, object_id):\n"
            "    if has_permission(user_id):\n"
            "        os.system(object_id)\n")
        evidence = semantic_controlflow.build_semantic_controlflow_evidence(
            root, guards)
        relation = evidence["flows"][0]["controls"][0]["control_flow"]
        self.assertEqual("enclosing-branch-likely", relation["relation"])
        self.assertEqual("dominates-likely", relation["dominance"])

        root, guards = self._fixture(
            "def handler(user_id, object_id):\n"
            "    has_permission(user_id)\n"
            "    os.system(object_id)\n")
        evidence = semantic_controlflow.build_semantic_controlflow_evidence(
            root, guards)
        relation = evidence["flows"][0]["controls"][0]["control_flow"]
        self.assertEqual("same-block-unverified", relation["relation"])

    def test_artifact_is_deterministic_bounded_and_enters_static_pool(self):
        root, guards = self._fixture(
            "def handler(user_id, object_id):\n"
            "    if has_permission(user_id):\n"
            "        audit(object_id)\n"
            "    else:\n"
            "        os.system(object_id)\n")
        first = semantic_controlflow.build_semantic_controlflow_evidence(
            root, guards)
        second = semantic_controlflow.build_semantic_controlflow_evidence(
            root, guards)
        self.assertEqual(first, second)
        encoded = json.dumps(first, ensure_ascii=False)
        self.assertNotIn("def handler", encoded)
        self.assertEqual("not-a-finding", first["claim_status"])
        self.assertTrue(all(item["requires_manual_dataflow"]
                            for item in first["candidates"]))

        with tempfile.TemporaryDirectory() as workspace_dir:
            store = CoverageStore(Path(workspace_dir), "demo")
            store.write(semantic_controlflow.SEMANTIC_CONTROLFLOW_CANDIDATE_INDEX,
                        first["candidates"])
            merged = controls.static_candidates(store)
            self.assertEqual("semantic-controlflow", merged[0]["source"])


if __name__ == "__main__":
    unittest.main()
