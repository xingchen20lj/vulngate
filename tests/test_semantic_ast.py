"""Tests for bounded Python-AST control-flow witnesses."""

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
from agent.analysis import semantic_ast  # noqa: E402
from agent.analysis import semantic_controlflow  # noqa: E402
from agent.analysis import semantic_guards  # noqa: E402
from agent.analysis import semantic_paths  # noqa: E402
from agent.analysis.semantic_frontend import JavaFrontend  # noqa: E402
from agent.analysis.inventory import CoverageStore  # noqa: E402


class SemanticAstEvidenceTests(unittest.TestCase):
    def _fixture(self, source):
        root = Path(tempfile.mkdtemp(prefix="vulngate-ast-"))
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
        control_line = next(number for number, line in enumerate(
            source.splitlines(), 1) if "has_permission" in line)
        control = models.SecurityControlRecord(
            control_id="control-authz", category="authorization",
            file="app.py", line=control_line, symbol_id=symbol_id,
            control_type="authorization", api="has_permission")
        flow = models.FlowRecord(
            flow_id="flow-1", entry_id=entry.entry_id,
            source_symbol=symbol_id, sink_id=sink.sink_id, path=[symbol_id])
        cmap = controls.build_control_map(
            [entry], [sink], [flow], [control]).as_dict()
        paths = semantic_paths.build_semantic_path_evidence(
            root, [entry], [sink], [flow], [control], [symbol], cmap)
        guards = semantic_guards.build_semantic_guard_evidence(root, paths)
        controlflow = semantic_controlflow.build_semantic_controlflow_evidence(
            root, guards)
        return root, controlflow

    def test_ast_confirms_terminating_guard_shape(self):
        root, controlflow = self._fixture(
            "def handler(user_id, object_id):\n"
            "    if not has_permission(user_id):\n"
            "        return\n"
            "    os.system(object_id)\n")
        evidence = semantic_ast.build_semantic_ast_evidence(root, controlflow)
        relation = evidence["flows"][0]["controls"][0]["ast_control_flow"]
        self.assertEqual("parsed", relation["parse_status"])
        self.assertEqual("ast-terminating-guard", relation["relation"])
        self.assertEqual("return", relation["terminal_shape"])
        self.assertEqual("if", relation["control_branch"]["kind"])

    def test_ast_separates_else_and_exception_paths(self):
        root, controlflow = self._fixture(
            "def handler(user_id, object_id):\n"
            "    try:\n"
            "        if has_permission(user_id):\n"
            "            audit(object_id)\n"
            "        else:\n"
            "            os.system(object_id)\n"
            "    except ValueError:\n"
            "        os.system(object_id)\n")
        evidence = semantic_ast.build_semantic_ast_evidence(root, controlflow)
        relations = [row["ast_control_flow"]["relation"]
                     for row in evidence["flows"][0]["controls"]]
        self.assertIn("ast-alternate-path", relations)

    def test_parse_failure_and_unsupported_files_are_explicit(self):
        root = Path(tempfile.mkdtemp(prefix="vulngate-ast-gap-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        (root / "bad.py").write_text("def broken(:\n", encoding="utf-8")
        controlflow = {
            "flows": [{
                "flow_id": "flow-1", "entry_id": "entry-1",
                "sink_id": "sink-1", "path": [],
                "static_control_verdict": "guarded",
                "entry": {}, "sink": {"file": "bad.py", "line": 1},
                "controls": [{
                    "control_id": "c1", "file": "bad.py", "line": 1,
                    "category": "authorization", "required_category": True,
                    "control_flow": {},
                }],
            }]
        }
        evidence = semantic_ast.build_semantic_ast_evidence(root, controlflow)
        relation = evidence["flows"][0]["controls"][0]["ast_control_flow"]
        self.assertEqual("ast-parse-failed", relation["relation"])
        self.assertEqual("syntax-error", relation["parse_status"])
        self.assertEqual(1, evidence["summary"]["candidates"])

    def test_java_parser_records_terminating_guard_without_claiming_cfg_proof(self):
        if not JavaFrontend.available():
            self.skipTest("JDK parser unavailable on this host")
        root = Path(tempfile.mkdtemp(prefix="vulngate-java-ast-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        (root / "Api.java").write_text(
            "package p;\nclass Api {\n"
            "  void handler(String value) {\n"
            "    if (!hasPermission(value)) { return; }\n"
            "    Runtime.getRuntime().exec(value);\n"
            "  }\n}\n", encoding="utf-8")
        controlflow = {"flows": [{
            "flow_id": "java-flow", "entry_id": "entry", "sink_id": "sink",
            "path": ["java:p.Api#handler"], "static_control_verdict": "partial",
            "entry": {"file": "Api.java", "line": 3},
            "sink": {"file": "Api.java", "line": 5, "category": "command-exec"},
            "controls": [{"control_id": "auth", "file": "Api.java", "line": 4,
                          "category": "authorization", "required_category": "authorization",
                          "control_flow": {}}],
        }]}
        evidence = semantic_ast.build_semantic_ast_evidence(root, controlflow)
        relation = evidence["flows"][0]["controls"][0]["ast_control_flow"]
        self.assertEqual("javac-ast", relation["parser"])
        self.assertEqual("parsed", relation["parse_status"])
        self.assertEqual("ast-terminating-guard", relation["relation"])
        self.assertEqual("not-a-finding", evidence["claim_status"])
        self.assertIn("does not resolve types", " ".join(evidence["limitations"]))

    def test_artifact_is_deterministic_bounded_and_enters_static_pool(self):
        root, controlflow = self._fixture(
            "def handler(user_id, object_id):\n"
            "    if has_permission(user_id):\n"
            "        audit(object_id)\n"
            "    else:\n"
            "        os.system(object_id)\n")
        first = semantic_ast.build_semantic_ast_evidence(root, controlflow)
        second = semantic_ast.build_semantic_ast_evidence(root, controlflow)
        self.assertEqual(first, second)
        encoded = json.dumps(first, ensure_ascii=False)
        self.assertNotIn("def handler", encoded)
        self.assertEqual("not-a-finding", first["claim_status"])
        self.assertTrue(all(item["requires_manual_dataflow"]
                            for item in first["candidates"]))

        with tempfile.TemporaryDirectory() as workspace_dir:
            store = CoverageStore(Path(workspace_dir), "demo")
            store.write(semantic_ast.SEMANTIC_AST_CANDIDATE_INDEX,
                        first["candidates"])
            merged = controls.static_candidates(store)
            self.assertEqual("semantic-ast", merged[0]["source"])


if __name__ == "__main__":
    unittest.main()
