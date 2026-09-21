"""Tests for bounded branch-posture and subject-binding evidence."""

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
from agent.analysis import semantic_guards  # noqa: E402
from agent.analysis import semantic_paths  # noqa: E402
from agent.analysis.inventory import CoverageStore  # noqa: E402


class SemanticGuardEvidenceTests(unittest.TestCase):
    def _fixture(self, source):
        root = Path(tempfile.mkdtemp(prefix="vulngate-guards-"))
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
            sink_id="sink-1", category="command-exec", file="app.py",
            line=sink_line, symbol_id=symbol_id, api="os.system",
            text="os.system(...)", severity_hint="high")
        controls_list = [models.SecurityControlRecord(
            control_id="control-authz", category="authorization",
            file="app.py", line=2, symbol_id=symbol_id,
            control_type="authorization", api="has_permission")]
        flow = models.FlowRecord(
            flow_id="flow-1", entry_id=entry.entry_id,
            source_symbol=symbol_id, sink_id=sink.sink_id, path=[symbol_id])
        cmap = controls.build_control_map(
            [entry], [sink], [flow], controls_list).as_dict()
        semantic = semantic_paths.build_semantic_path_evidence(
            root, [entry], [sink], [flow], controls_list, [symbol], cmap)
        return root, semantic

    def test_terminating_guard_exposes_subject_mismatch(self):
        root, semantic = self._fixture(
            "def handler(user_id, object_id):\n"
            "    if not has_permission(user_id):\n"
            "        return\n"
            "    os.system(object_id)\n")
        evidence = semantic_guards.build_semantic_guard_evidence(root, semantic)
        guard = evidence["flows"][0]["guards"][0]
        self.assertEqual("terminating-guard-likely", guard["branch_posture"])
        self.assertEqual("mismatch", guard["subject_binding"])
        self.assertIn("semantic-subject-binding",
                      {candidate["surface"] for candidate in evidence["candidates"]})

    def test_nested_branch_is_separate_from_terminating_guard(self):
        root, semantic = self._fixture(
            "def handler(user_id, object_id):\n"
            "    if has_permission(user_id):\n"
            "        os.system(object_id)\n")
        evidence = semantic_guards.build_semantic_guard_evidence(root, semantic)
        guard = evidence["flows"][0]["guards"][0]
        self.assertEqual("nested-branch-likely", guard["branch_posture"])
        self.assertEqual("mismatch", guard["subject_binding"])

    def test_non_branch_check_with_overlapping_subject_only_needs_posture_review(self):
        root, semantic = self._fixture(
            "def handler(user_id, object_id):\n"
            "    has_permission(user_id)\n"
            "    os.system(user_id)\n")
        evidence = semantic_guards.build_semantic_guard_evidence(root, semantic)
        guard = evidence["flows"][0]["guards"][0]
        self.assertEqual("non-branch-check", guard["branch_posture"])
        self.assertEqual("overlap", guard["subject_binding"])
        self.assertNotIn("semantic-subject-binding",
                         {candidate["surface"] for candidate in evidence["candidates"]})
        self.assertIn("semantic-branch-posture",
                      {candidate["surface"] for candidate in evidence["candidates"]})

    def test_artifact_is_deterministic_bounded_and_persisted(self):
        root, semantic = self._fixture(
            "def handler(user_id, object_id):\n"
            "    if not has_permission(user_id):\n"
            "        return\n"
            "    os.system(object_id)\n")
        first = semantic_guards.build_semantic_guard_evidence(root, semantic)
        second = semantic_guards.build_semantic_guard_evidence(root, semantic)
        self.assertEqual(first, second)
        encoded = json.dumps(first, ensure_ascii=False)
        self.assertNotIn("def handler", encoded)
        self.assertEqual("not-a-finding", first["claim_status"])
        self.assertTrue(all(item["requires_manual_dataflow"]
                            for item in first["candidates"]))

        with tempfile.TemporaryDirectory() as workspace_dir:
            store = CoverageStore(Path(workspace_dir), "demo")
            store.write(semantic_guards.SEMANTIC_GUARD_CANDIDATE_INDEX,
                        first["candidates"])
            merged = controls.static_candidates(store)
            self.assertEqual(
                {item["candidate_id"] for item in first["candidates"]},
                {item["candidate_id"] for item in merged})


if __name__ == "__main__":
    unittest.main()
