"""Regression tests for revision-bound static lineage and scheduling."""

import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import agent_cli
from agent.analysis import controls, evidence_provenance as ep, models, scheduler
from agent.analysis.inventory import CoverageStore, build_inventory, persist_inventory
from agent.autonomous.run_agent import _ensure_capability_inventory
from agent.orchestrator.config import TargetConfig
from agent.orchestrator.stages import StageContext, run_s1


class EvidenceProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "app.py"
        self.source.write_text("def handler(value):\n"
                               "    value = request.args.get('value')\n"
                               "    sanitize(value)\n"
                               "    os.system(value)\n", encoding="utf-8")
        self.entries = [models.EntryRecord("entry", "http", "app.py", 2, "symbol")]
        self.sinks = [models.SinkRecord("sink", "command-exec", "app.py", 4, "symbol")]
        self.controls = [models.SecurityControlRecord(
            "control", "sanitization", "app.py", 3, "symbol")]
        self.symbols = [models.SymbolRecord(
            "symbol", "python", "app.py", 1, 4, "function", "handler")]
        self.flows = [models.FlowRecord("flow", "entry", "symbol", "sink", ["symbol"])]
        self.artifacts = {}
        for producer, field in (("semantic-paths", "controls"),
                                ("semantic-guards", "guards"),
                                ("semantic-controlflow", "controls"),
                                ("semantic-ast", "controls"),
                                ("semantic-transforms", "transforms"),
                                ("semantic-python-binding", "controls")):
            self.artifacts[producer] = {"flows": [{
                "flow_id": "flow", "sink_id": "sink",
                "sink": {"file": "app.py", "line": 4},
                field: [{"control_id": "control", "file": "app.py", "line": 3,
                         "relation": "unresolved", "confidence": "heuristic-nearby"}]}]}
        self.candidates = {}
        for cid, producer, surface in (
                ("a", "semantic-transforms", "semantic-transform-gap"),
                ("b", "semantic-python-binding", "semantic-python-binding-gap"),
                ("c", "semantic-guards", "semantic-branch-posture")):
            self.candidates[producer] = [{
                "candidate_id": cid, "source": producer, "surface": surface,
                "category": "logic", "flow_id": "flow", "control_id": "control",
                "code_location": ["app.py:3", "app.py:4"], "claim_status": "not-a-finding"}]

    def build(self, **overrides):
        args = dict(root=self.root, entries=self.entries, sinks=self.sinks,
                    controls=self.controls, symbols=self.symbols, flows=self.flows,
                    artifacts=self.artifacts, candidates=self.candidates, target="demo")
        args.update(overrides)
        return ep.build_evidence_provenance(**args)

    def pool(self, graph):
        return ep.enrich_candidates([c for rows in self.candidates.values() for c in rows], graph)

    def test_lineage_resolves_to_source_and_concrete_control(self):
        graph = self.build()
        self.assertEqual(graph, self.build())
        records = {r["evidence_id"]: r for r in graph["records"]}
        self.assertEqual(len(records), len(graph["records"]))
        for row in records.values():
            for key in ("producer", "evidence_type", "source_fact_ids", "parent_evidence_ids",
                        "confidence", "independence_group", "file", "line", "span", "schema_version"):
                self.assertIn(key, row)
            self.assertEqual("not-a-finding", row["claim_status"])
            for parent in row["source_fact_ids"] + row["parent_evidence_ids"]:
                self.assertIn(parent, records)
        binding = next(r for r in records.values() if r["producer"] == "semantic-python-binding"
                       and r.get("control_id") == "control" and r["evidence_type"] != "static-candidate")
        self.assertTrue(any(records[p]["producer"] == "semantic-transforms"
                            and records[p].get("control_id") == "control"
                            for p in binding["parent_evidence_ids"]))
        for metadata in graph["candidate_provenance"].values():
            self.assertTrue(metadata["provenance_complete"])
            self.assertEqual(1, metadata["independent_evidence_count"])
        flow = next(r for r in records.values() if r["evidence_type"] == "source-sink-flow")
        self.assertEqual(("app.py", 4), (flow["file"], flow["line"]))
        symbol = next(r for r in records.values() if r.get("fact_kind") == "symbol")
        self.assertEqual("heuristic", symbol["confidence"])
        self.assertNotIn("sanitize(value)", json.dumps(graph))

    def test_source_revision_changes_evidence_identity(self):
        before = self.build()["candidate_provenance"]["a"]
        self.source.write_text(self.source.read_text().replace("sanitize", "validate"))
        after = self.build()["candidate_provenance"]["a"]
        self.assertNotEqual(before["evidence_ids"], after["evidence_ids"])

    def test_missing_facts_files_and_upstream_stay_explicit(self):
        for overrides in ({"sinks": []}, {"artifacts": {}}):
            metadata = self.build(**overrides)["candidate_provenance"]["b"]
            self.assertFalse(metadata["provenance_complete"])
            self.assertTrue(metadata["provenance_gaps"])
        self.source.unlink()
        metadata = self.build()["candidate_provenance"]["a"]
        self.assertFalse(metadata["provenance_complete"])
        self.assertTrue(metadata["provenance_gaps"])
        orphan = self.build(flows=[])["candidate_provenance"]["a"]
        self.assertEqual(0, orphan["independent_evidence_count"])

    def test_duplicate_rows_are_idempotent(self):
        graph = self.build()
        self.artifacts["semantic-paths"]["flows"] *= 2
        self.entries *= 2
        self.assertEqual(graph, self.build())

    def test_long_rows_are_fully_hashed(self):
        row = self.artifacts["semantic-paths"]["flows"][0]
        row["a_padding"] = "x" * 17000
        first = self.build()
        row["z_relation"] = "changed-after-prefix"
        self.assertNotEqual(first, self.build())

    def test_flow_aliases_share_a_source_group(self):
        alias = copy.deepcopy(self.flows[0])
        alias.flow_id, alias.direction = "backward-alias", "backward"
        self.flows.append(alias)
        self.candidates["semantic-python-binding"][0]["flow_id"] = alias.flow_id
        graph = self.build()["candidate_provenance"]
        self.assertEqual(graph["a"]["independence_group"], graph["b"]["independence_group"])

    def test_scheduler_damps_restatements_not_other_questions(self):
        pool = self.pool(self.build())
        ctx = scheduler.ScheduleContext()
        scores = {s.candidate_id: s for s in scheduler.score_candidates(pool, ctx)}
        self.assertEqual("a", scores["b"].duplicate_of)
        self.assertFalse(scores["c"].duplicate_of)
        reverse = {s.candidate_id: s for s in scheduler.score_candidates(list(reversed(pool)), ctx)}
        self.assertEqual({k: s.as_dict() for k, s in scores.items()},
                         {k: s.as_dict() for k, s in reverse.items()})
        signal = scheduler.candidate_evidence_signal(pool[1])
        self.assertEqual(1, signal["independent_evidence_count"])
        self.assertGreater(signal["derived_evidence_count"], 1)
        pool[1]["evidence_ids"] *= 5
        pool[1]["derived_evidence_count"] = 999
        self.assertEqual(signal, scheduler.candidate_evidence_signal(pool[1]))

    def test_fixed_budget_keeps_distinct_question(self):
        # Synthetic scheduling benchmark, NOT a historical-CVE or recall claim.
        template = self.candidates["semantic-python-binding"][0]
        self.candidates["semantic-python-binding"] = [dict(template, candidate_id="b%d" % n)
                                                        for n in range(4)]
        pool = self.pool(self.build())
        scores = scheduler.score_candidates(pool, scheduler.ScheduleContext())
        selected, *_ = scheduler.stratified_select(scores, 2, {"logic": 2})
        self.assertEqual({"a", "c"}, {s.candidate_id for s in selected})
        legacy = [c for rows in self.candidates.values() for c in rows]
        baseline, *_ = scheduler.stratified_select(
            scheduler.score_candidates(legacy, scheduler.ScheduleContext()), 2, {"logic": 2})
        self.assertEqual({"a", "b0"}, {s.candidate_id for s in baseline})

    def test_enrichment_does_not_alias_or_rebind_changed_hypothesis(self):
        graph = self.build()
        before = copy.deepcopy(graph)
        pool = self.pool(graph)
        pool[0]["evidence_ids"].clear()
        self.assertEqual(before, graph)
        changed = dict(self.candidates["semantic-transforms"][0], flow_id="other")
        self.assertNotIn("evidence_ids", ep.enrich_candidates([changed], graph)[0])
        stale = dict(pool[1], hypothesis="a different research question")
        self.assertNotIn("evidence_ids", ep.enrich_candidates([stale], graph)[0])

    def test_correlation_metadata_does_not_expand_every_peer_list(self):
        template = self.candidates["semantic-transforms"][0]
        self.candidates = {"semantic-transforms": [dict(template, candidate_id=str(n)) for n in range(100)]}
        graph = self.build()
        self.assertEqual(99, graph["summary"]["correlated_candidates"])
        self.assertTrue(all("correlated_candidate_ids" not in row
                            for row in graph["candidate_provenance"].values()))
        first_size = len(json.dumps(graph))
        self.candidates["semantic-transforms"].extend(dict(template, candidate_id=str(n)) for n in range(100, 200))
        self.assertLess(len(json.dumps(self.build())), first_size * 2.2)
        self.assertEqual(self.source.stat().st_size, graph["summary"]["source_bytes_read"])

    def test_real_inventory_persistence_and_native_schedule(self):
        self.source.write_text("@app.route('/run')\n" + self.source.read_text(), encoding="utf-8")
        result = build_inventory(self.root, target="demo", with_flows=True)
        workspace = self.root / "workspace"
        store = CoverageStore(workspace, "demo")
        persist_inventory(store, result)
        graph = store.read(ep.EVIDENCE_PROVENANCE_INDEX)
        self.assertEqual(result.evidence_provenance, graph)
        self.assertTrue(graph["records"])
        raw = (store.read("semantic-transform-candidates") or []) + (store.read("semantic-python-binding-candidates") or [])
        self.assertTrue(raw)
        plan = scheduler.build_schedule(workspace, "demo", raw, refresh=False)
        for score in plan.selected + plan.deferred:
            self.assertTrue(score.evidence["evidence_quality"]["provenance"]["evidence_ids"])
        self.assertTrue(all(c.get("evidence_ids") for c in controls.static_candidates(store)))
        output = io.StringIO()
        with redirect_stdout(output):
            code = agent_cli.main(["evidence-provenance", "demo", "--workspace", str(workspace),
                                   "--json", "--limit", "2"])
        self.assertEqual(0, code, output.getvalue())
        payload = json.loads(output.getvalue())
        self.assertEqual(ep.EVIDENCE_PROVENANCE_VERSION, payload["schema_version"])
        self.assertEqual(2, len(payload["records"]))

    def test_configured_and_autonomous_s1_share_persisted_provenance(self):
        self.source.write_text("@app.route('/run')\n" + self.source.read_text(), encoding="utf-8")
        cfg = TargetConfig("demo", "2026-09-21", source_dirs=["app.py"])
        ctx = StageContext(self.root, "demo", 1, cfg, offline=True)
        with patch("agent.orchestrator.stages.analyze_patch_history", return_value=[]):
            run_s1(ctx)
        mirrored = ctx.store.read_artifact("S1", "evidence-provenance.json")
        self.assertIsNotNone(mirrored)
        self.assertTrue(mirrored["records"])
        self.assertIsNone(ctx.store.read_artifact("S1", "capability-graph-error.json"))
        reused = _ensure_capability_inventory(SimpleNamespace(root=self.root, cfg=cfg))
        self.assertFalse(reused["rebuilt"])
        self.assertEqual(mirrored, reused["evidence_provenance"])

    def test_source_hash_budget_and_outside_paths_are_gaps(self):
        with patch.object(ep, "MAX_SOURCE_BYTES", 1):
            self.assertFalse(self.build()["candidate_provenance"]["a"]["provenance_complete"])
        self.sinks[0].file = "../outside.py"
        graph = self.build()
        self.assertTrue(any("source-outside-root" in gap
                            for gap in graph["candidate_provenance"]["a"]["provenance_gaps"]))

    def test_missing_concrete_control_parent_is_not_replaced_by_nearby_one(self):
        self.artifacts["semantic-transforms"]["flows"][0]["transforms"][0]["control_id"] = "other"
        graph = self.build()
        binding = next(r for r in graph["records"] if r["producer"] == "semantic-python-binding"
                       and r["evidence_type"] == "value-binding-detail")
        self.assertTrue(any("missing-upstream-control" in gap for gap in binding["provenance_gaps"]))
        self.assertFalse(graph["candidate_provenance"]["b"]["provenance_complete"])

    def test_ambiguous_source_id_cannot_have_complete_provenance(self):
        self.sinks.append(models.SinkRecord("sink", "file-read", "app.py", 4, "symbol"))
        graph = self.build()
        self.assertFalse(graph["candidate_provenance"]["a"]["provenance_complete"])

    def test_conflicting_candidate_id_cannot_rebind_either_hypothesis(self):
        rows = self.candidates["semantic-transforms"]
        rows.append(dict(rows[0], hypothesis="a different question"))
        graph = self.build()
        self.assertFalse(graph["candidate_provenance"]["a"]["provenance_complete"])
        self.assertTrue(all("evidence_ids" not in row for row in ep.enrich_candidates(rows, graph)))


if __name__ == "__main__":
    unittest.main()
