"""The shared frontend must change real consumers, not just expose an API."""
import ast
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from agent.analysis import callgraph, evidence_provenance, semantic_ast, semantic_frontend as sf, symbols
from agent.analysis.inventory import CoverageStore, build_inventory, persist_inventory
from agent.analysis.languages import SourceFilter


class SemanticFrontendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def source(self, text, name="app.py"):
        (self.root / name).write_text(text, encoding="utf-8")
        return name

    def test_common_contract_exposes_syntax_without_executing_it(self):
        text = ("@app.route('/run')\n"
                "async def handler(\n"
                "    value: str, /, *args, limit: int = 3, **kwargs\n"
                "):\n"
                "    alias = value\n"
                "    if limit:\n"
                "        return send(alias, *args, count=limit, **kwargs)\n"
                "    raise ValueError()\n")
        frontend = sf.PythonFrontend()
        unit = frontend.parse("app.py", text.encode())
        self.assertEqual("parsed", unit.status)
        self.assertEqual("ast", unit.parser)
        self.assertEqual("not-a-finding", unit.claim_status)
        declarations = frontend.symbols(unit)
        self.assertEqual(["handler"], [s.name for s in declarations])
        self.assertEqual(1, declarations[0].line)
        self.assertEqual(8, declarations[0].end_line)
        self.assertEqual(["value", "args", "limit", "kwargs"],
                         [p.name for p in frontend.parameters(unit)])
        self.assertEqual(["positional-only", "var-positional", "keyword-only", "var-keyword"],
                         [p.attributes["parameter_kind"] for p in frontend.parameters(unit)])
        self.assertEqual(1, len(frontend.assignments(unit)))
        self.assertEqual(1, len(frontend.branches(unit)))
        self.assertEqual(1, len(frontend.returns(unit)))
        call = next(c for c in frontend.calls(unit) if c.name == "send")
        self.assertEqual("handler", call.scope)
        decorator = next(c for c in frontend.calls(unit) if c.name == "app.route")
        self.assertEqual("", decorator.scope)
        self.assertEqual("unresolved", call.attributes["dispatch"])
        arguments = frontend.arguments(unit, call.fact_id)
        self.assertEqual(["positional", "starred", "keyword", "keyword-expanded"],
                         [a.attributes["argument_kind"] for a in arguments])
        encoded = json.dumps([f.as_dict() for f in unit.facts])
        self.assertNotIn("/run", encoded)
        self.assertNotIn("async def", encoded)

    def test_ast_symbols_ignore_string_pseudo_definitions_and_keep_nested_scope(self):
        name = self.source('"""\ndef phantom(value):\n    pass\n"""\n'
                           'def outer(value):\n'
                           '    def helper():\n        return value\n'
                           '    return helper()\n'
                           'def second(value):\n'
                           '    def helper():\n        return value\n'
                           '    return helper()\n')
        records, failures = symbols.extract_symbols(self.root, [name])
        self.assertFalse(failures)
        ids = {s.symbol_id for s in records}
        self.assertNotIn("phantom", {s.name for s in records})
        self.assertIn("python:app.py#outer.helper", ids)
        self.assertIn("python:app.py#second.helper", ids)
        self.assertEqual(len(records), len(ids))
        self.assertTrue(all(s.parser == "ast" for s in records))
        self.assertTrue(all(s.claim_status == "not-a-finding" for s in records))

    def test_multiline_parameters_survive_callgraph_consumer(self):
        name = self.source("@app.route(\n    '/run'\n)\n"
                           "def handler(\n    value: str,\n    limit: int = 3,\n    *,\n    flag=True,\n):\n"
                           "    sink(value)\n")
        records, _ = symbols.extract_symbols(self.root, [name])
        handler = next(s for s in records if s.name == "handler")
        self.assertEqual(["value", "limit", "flag"], handler.parameters)
        self.assertEqual(1, handler.start_line)
        self.assertEqual(10, handler.end_line)
        callgraph.build_call_graph(self.root, records)
        self.assertEqual(["value", "limit", "flag"], handler.parameters)
        self.assertEqual(handler.symbol_id, symbols.innermost_at(symbols.group_by_file(records), name, 1).symbol_id)

    def test_parse_failure_remains_a_gap_even_when_regex_finds_a_symbol(self):
        name = self.source("def partial(value):\n    return value\nBROKEN(\n")
        records, failures = symbols.extract_symbols(self.root, [name])
        self.assertIn("parse-failed", failures[name])
        self.assertTrue(any(s.name == "partial" for s in records))
        self.assertTrue(all(s.parser == "regex-fallback" and s.analysis_gaps for s in records))
        self.assertTrue(all(s.confidence != "ast" for s in records))

    def test_redefinition_is_ambiguous_not_a_unique_target(self):
        name = self.source("def helper(value):\n    return value\n"
                           "def helper(value):\n    return value + 1\n"
                           "def handler(value):\n    return helper(value)\n")
        records, failures = symbols.extract_symbols(self.root, [name])
        helpers = [s for s in records if s.name == "helper"]
        self.assertEqual(2, len({s.symbol_id for s in helpers}))
        self.assertTrue(all("duplicate-definition" in s.analysis_gaps for s in helpers))
        graph = callgraph.build_call_graph(self.root, records)
        self.assertIn("helper", graph.ambiguous)
        self.assertFalse(any(e.callee in {s.symbol_id for s in helpers} for e in graph.edges))

    def test_digest_cache_invalidates_content_changes_and_evicts(self):
        name = self.source("def first():\n    return 1\n")
        session = sf.FrontendSession(self.root, max_files=1)
        first = session.parse(name)
        self.assertIs(first, session.parse(name))
        stat = (self.root / name).stat()
        self.source("def other():\n    return 2\n")
        os.utime(self.root / name, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        changed = session.parse(name)
        self.assertNotEqual(first.source_revision, changed.source_revision)
        self.assertIsNot(first, changed)
        session.parse(self.source("pass\n", "b.py"))
        self.assertLessEqual(session.stats()["cached_files"], 1)
        self.assertGreater(session.stats()["evictions"], 0)

    def test_facts_are_immutable_and_cache_respects_node_retention_budget(self):
        name = self.source("def function(value):\n    return value\n")
        session = sf.FrontendSession(self.root, max_cached_nodes=1)
        unit = session.parse(name)
        fact = sf.PythonFrontend().symbols(unit)[0]
        with self.assertRaises(TypeError):
            fact.attributes["parameters"] = ("changed",)
        public = fact.as_dict()
        public["attributes"]["parameters"] = ("changed",)
        self.assertEqual(("value",), fact.attributes["parameters"])
        self.assertEqual(0, session.stats()["cached_nodes"])

    def test_source_filter_limit_is_not_bypassed_by_ast(self):
        name = self.source("def function(value):\n    return value\n")
        records, failures = symbols.extract_symbols(self.root, [name], SourceFilter(max_file_bytes=3))
        self.assertFalse(records)
        self.assertTrue(failures)
        # Zero disables the source-universe size filter, not the frontend's
        # independent resource budget and not Python syntax analysis itself.
        records, failures = symbols.extract_symbols(self.root, [name], SourceFilter(max_file_bytes=0))
        self.assertFalse(failures)
        self.assertTrue(all(s.parser == "ast" for s in records))

    def test_node_depth_byte_and_decode_failures_never_return_partial_ast(self):
        for frontend, data, status in (
                (sf.PythonFrontend(max_bytes=3), b"pass\n", "too-large"),
                (sf.PythonFrontend(max_nodes=3), b"a = b + c\n", "node-limit"),
                (sf.PythonFrontend(max_depth=3), b"a = b + c\n", "depth-limit"),
                (sf.PythonFrontend(), b"a = '\xff'\n", "parse-failed")):
            unit = frontend.parse("app.py", data)
            self.assertEqual(status, unit.status)
            self.assertIsNone(unit.tree)
            self.assertFalse(unit.facts)
            self.assertTrue(unit.analysis_gaps)

    def test_encoding_cookie_and_non_python_gaps(self):
        unit = sf.PythonFrontend().parse("app.py", b"# coding: latin-1\nx = '\xe9'\n")
        self.assertEqual("parsed", unit.status)
        name = self.source("class A {}", "A.java")
        session = sf.FrontendSession(self.root)
        self.assertEqual("unsupported-language", session.parse(name).status)
        self.assertEqual("source-unreadable", session.parse("missing.py").status)
        self.assertEqual("source-outside-root", session.parse("../outside.py").status)

    def test_special_files_and_symlink_loops_are_gaps_not_blocking_reads(self):
        os.mkfifo(self.root / "pipe.py")
        (self.root / "loop.py").symlink_to("loop.py")
        session = sf.FrontendSession(self.root)
        self.assertEqual("source-unreadable", session.parse("pipe.py").status)
        self.assertEqual("source-unreadable", session.parse("loop.py").status)
        self.assertEqual(0, session.stats()["bytes_read"])
        records, failures = symbols.extract_symbols(self.root, ["pipe.py", "loop.py"])
        self.assertFalse(records)
        self.assertEqual(2, len(failures))

    def test_inventory_parses_once_and_exposes_gaps_without_new_artifact(self):
        self.source("@app.route('/run')\ndef handler(value):\n"
                    "    sanitize(value)\n    os.system(value)\n")
        with patch.object(sf.ast, "parse", wraps=ast.parse) as parse:
            result = build_inventory(self.root, target="demo")
        self.assertEqual(1, parse.call_count)
        self.assertEqual(1, result.counts()["semantic_frontend"]["parse_calls"])
        self.assertTrue(result.semantic_ast_evidence["flows"])
        self.assertTrue(result.semantic_binding_evidence["flows"])
        relation = result.semantic_ast_evidence["flows"][0]["controls"][0]["ast_control_flow"]
        self.assertEqual("ast", relation["parser"])
        binding = result.semantic_binding_evidence["flows"][0]["controls"][0]
        self.assertEqual("ast", binding["parser"])
        self.assertEqual(relation["source_revision"], binding["source_revision"])
        self.assertEqual("not-a-finding", binding["claim_status"])
        store = CoverageStore(self.root / "workspace", "demo")
        persist_inventory(store, result)
        self.assertEqual("ast", store.read("symbol-index")[0]["parser"])
        self.assertEqual(1, store.read("inventory-summary")["counts"]["semantic_frontend"]["parse_calls"])

    def test_synthetic_symbol_benchmark_removes_phantoms_without_losing_real_definitions(self):
        text = ('"""\ndef phantom(x):\n    pass\n"""\n'
                'def real(value):\n    return value\n')
        name = self.source(text)
        legacy = {d.name for d in symbols._decls_in_file(text.splitlines(), "python")}
        current, _ = symbols.extract_symbols(self.root, [name])
        current = {s.name for s in current if s.kind != symbols.FILE_KIND}
        truth = {"real"}
        self.assertEqual({"phantom"}, legacy - truth)
        self.assertEqual(truth, current)
        self.assertEqual(truth, legacy & truth)

    def test_inventory_persists_parser_gaps_even_without_a_candidate(self):
        self.source("def partial():\n    pass\nBROKEN(\n")
        result = build_inventory(self.root, target="demo")
        self.assertEqual("parse-failed", result.counts()["semantic_frontend"]["analysis_gaps"]["app.py"])
        self.assertTrue(all(s.parse_status == "parse-failed" for s in result.symbols))

    def test_source_changes_between_passes_are_provenance_gaps(self):
        name = self.source("def handler(value):\n    return value\n")
        records, _ = symbols.extract_symbols(self.root, [name])
        self.source("def handler(value):\n    return None\n")
        graph = evidence_provenance.build_evidence_provenance(root=self.root, symbols=records)
        self.assertTrue(all(any("source-revision-mismatch" in gap for gap in r["provenance_gaps"])
                            for r in graph["records"]))

    def test_ast_index_eviction_does_not_erase_parser_status_for_earlier_files(self):
        flows = []
        for n in range(12):
            name = self.source("def run(value):\n    if validate(value):\n        sink(value)\n", "app%d.py" % n)
            flows.append({"flow_id": "f%d" % n, "sink": {"file": name, "line": 3},
                          "controls": [{"control_id": "c%d" % n, "file": name, "line": 2,
                                        "control_flow": {}}]})
        session = sf.FrontendSession(self.root, max_files=1)
        result = semantic_ast.build_semantic_ast_evidence(self.root, {"flows": flows}, frontend_session=session)
        self.assertEqual(12, result["summary"]["parsed_files"])
        self.assertEqual({"parsed": 12}, result["summary"]["parser_status"])
        self.assertLessEqual(session.stats()["cached_files"], 1)


if __name__ == "__main__":
    unittest.main()
