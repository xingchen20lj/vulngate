"""Regression coverage for bounded source scans and safe stage-only resume."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import time
import unittest
import json
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.analysis.languages import (SOURCE_INVENTORY_POLICY_VERSION,
                                      SourceFilter, SourceScanTimeout,
                                      iter_source_files)
from agent.autonomous import run_agent
from agent.orchestrator import pipeline
from agent.orchestrator.config import TargetConfig
from agent.orchestrator.stages import StageContext
from agent.sandbox.runner import _script_path_from_command
from agent.tools.build import S4_EVIDENCE_POLICY_VERSION
from agent.tools.public_scan import NOVELTY_QUERY_POLICY_VERSION
from agent.tools import search
from agent.tools.source_evidence import (candidate_block, scan_all_hits,
                                         scan_all_labeled_hits)
from agent.tools.target_rules import patterns_for, scan_s1_source_rules


class SourceScanRegressionTests(unittest.TestCase):
    def test_labeled_scan_classifies_before_display_truncation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "src" / "long.py"
            source.parent.mkdir()
            source.write_text("x = 1\n", encoding="utf-8")
            line = "x" * 240 + " RARE_MARKER"
            with patch.object(search, "iter_rg_matches", return_value=iter([{
                    "file": str(source), "line": 1, "text": line}])) as scan:
                hits = scan_all_labeled_hits(
                    [(r"RARE_MARKER", "marker")], ["src"], root,
                    max_per_pattern=1, timeout=5)
            self.assertEqual(1, scan.call_count)
            self.assertEqual("marker", hits[0]["label"])
            self.assertLessEqual(len(str(hits[0]["text"])), 160)

    def test_ripgrep_timeout_becomes_explicit_scan_gap(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source_dir = root / "src"
            source_dir.mkdir()
            with patch.object(search, "rg_matches",
                              side_effect=subprocess.TimeoutExpired("rg", 1)):
                with self.assertRaises(SourceScanTimeout) as caught:
                    scan_all_hits("needle", ["src"], root, timeout=1)
            self.assertEqual("ripgrep", caught.exception.progress["scan"])
            self.assertEqual("src", caught.exception.progress["current_path"])

    def test_runtime_scan_deadline_does_not_change_persisted_scope_policy(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.py").write_text("x = 1\n", encoding="utf-8")
            (root / "b.py").write_text("y = 2\n", encoding="utf-8")
            source_filter = SourceFilter(
                scan_timeout_seconds=600,
                runtime_deadline_override_seconds=0.001)
            self.assertEqual(600, source_filter.as_dict()["scan_timeout_seconds"])
            self.assertNotIn("runtime_deadline_override_seconds",
                             source_filter.as_dict())
            with patch("agent.analysis.languages._looks_generated",
                       side_effect=lambda *args: (time.sleep(0.003) or False)):
                with self.assertRaises(SourceScanTimeout):
                    list(iter_source_files(root, source_filter=source_filter))

    def test_candidate_keywords_share_one_scan_and_keep_per_keyword_cap(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            src.mkdir()
            rels = ["src/a.py", "src/b.py", "src/c.py", "src/d.py", "src/e.py"]
            for rel in rels:
                (root / rel).write_text("def sample():\n    return 1\n", encoding="utf-8")
            hits = [
                {"file": rels[0], "line": 1, "text": "Alpha"},
                {"file": rels[1], "line": 2, "text": "Alpha"},
                {"file": rels[2], "line": 3, "text": "Alpha"},
                {"file": rels[3], "line": 4, "text": "Beta"},
                {"file": rels[4], "line": 5, "text": "Beta"},
            ]
            with patch("agent.tools.source_evidence.scan_all_labeled_hits",
                       return_value=[
                           {"label": "Alpha", "file": rels[0], "line": 1},
                           {"label": "Alpha", "file": rels[1], "line": 2},
                           {"label": "Beta", "file": rels[3], "line": 4},
                           {"label": "Beta", "file": rels[4], "line": 5},
                       ]) as scan, \
                    patch("agent.tools.source_evidence.extract_method",
                          side_effect=lambda path, line, max_chars: "line-%d" % line) as extract:
                candidate_block({"novelty_keywords": ["Alpha", "Beta"]},
                                [], ["src"], root, timeout=7)
            self.assertEqual(1, scan.call_count)
            self.assertIn((r"Alpha", "Alpha"), scan.call_args.args[0])
            self.assertIn((r"Beta", "Beta"), scan.call_args.args[0])
            self.assertEqual(2, scan.call_args.kwargs["max_per_pattern"])
            self.assertEqual(4, extract.call_count)
            self.assertEqual([1, 2, 4, 5],
                             [call.args[1] for call in extract.call_args_list])

    def test_candidate_source_hits_are_reused_within_round_cache(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            src.mkdir()
            (src / "a.py").write_text("def sample():\n    return 1\n",
                                      encoding="utf-8")
            cache = {}
            hits = [
                {"label": "Alpha", "file": "src/a.py", "line": 1},
                {"label": "Beta", "file": "src/a.py", "line": 1},
            ]
            with patch("agent.tools.source_evidence.scan_all_labeled_hits",
                       return_value=hits) as scan, \
                    patch("agent.tools.source_evidence.extract_method",
                          return_value="source-line"):
                first = candidate_block(
                    {"novelty_keywords": ["Alpha", "Beta"]}, [], ["src"],
                    root, hit_cache=cache)
                second = candidate_block(
                    {"novelty_keywords": ["Alpha", "Beta"]}, [], ["src"],
                    root, max_chars=8000, hit_cache=cache)
            self.assertEqual(1, scan.call_count)
            self.assertEqual(first, second)
            self.assertEqual(1, len(cache))
            cached = next(iter(cache.values()))
            self.assertEqual([("src/a.py", 1)], cached["Alpha"])
            self.assertEqual([("src/a.py", 1)], cached["Beta"])

    def test_finite_labeled_scan_streams_and_stops_when_labels_are_full(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "src"
            source.mkdir()
            closed = []

            def rows():
                try:
                    yield {"file": str(source / "a.py"), "line": 1,
                           "text": "Alpha"}
                    yield {"file": str(source / "b.py"), "line": 2,
                           "text": "Beta"}
                    yield {"file": str(source / "c.py"), "line": 3,
                           "text": "irrelevant"}
                finally:
                    closed.append(True)

            with patch.object(search, "iter_rg_matches",
                              return_value=rows()) as stream:
                hits = scan_all_labeled_hits(
                    [("Alpha", "alpha"), ("Beta", "beta")], ["src"], root,
                    max_per_pattern=1, timeout=5)
            self.assertEqual(1, stream.call_count)
            self.assertEqual([True], closed)
            self.assertEqual(["alpha", "beta"],
                             [hit["label"] for hit in hits])

    def test_s1_danger_and_target_rules_share_a_capped_scan(self):
        danger = (r"danger", "danger-label")
        target = patterns_for("library")[0]
        rows = [
            {"pattern": danger[0], "label": danger[1], "file": "a", "line": 1},
            {"pattern": danger[0], "label": danger[1], "file": "b", "line": 2},
            {"pattern": target[0], "label": target[1], "file": "c", "line": 3},
            {"pattern": target[0], "label": target[1], "file": "d", "line": 4},
            {"pattern": target[0], "label": target[1], "file": "e", "line": 5},
        ]
        with patch("agent.tools.source_evidence.DANGER_PATTERNS", [danger]), \
                patch("agent.tools.target_rules.scan_all_labeled_hits",
                      return_value=rows) as scan:
            danger_hits, target_hits = scan_s1_source_rules(
                "library", ["src"], Path("/tmp"),
                danger_limit=1, target_limit=2, timeout=4)
        self.assertEqual(1, scan.call_count)
        self.assertEqual(2, scan.call_args.kwargs["max_per_pattern"])
        self.assertEqual(1, len(danger_hits))
        self.assertEqual(2, len(target_hits))

    def test_ripgrep_nonzero_error_is_not_an_empty_hit_set(self):
        proc = subprocess.CompletedProcess(["rg"], 2, "", "invalid regex")
        with patch.object(search, "run_tool", return_value=proc):
            with self.assertRaisesRegex(RuntimeError, "invalid regex"):
                search.rg_matches("[", Path("."))

    def test_multiline_sandbox_policy_is_not_probed_as_a_script_path(self):
        policy = "(version 1)\n(allow default)\n(deny network-outbound)"
        self.assertIsNone(_script_path_from_command([
            "sandbox-exec", "-p", policy, "/usr/bin/java", "-version",
        ]))


class PipelineResumeRegressionTests(unittest.TestCase):
    def context(self, workspace: Path) -> StageContext:
        candidate = {"candidate_id": "scheduled", "surface": "parser input"}
        config = TargetConfig("fixture", "2026-09-25", candidates=[])
        ctx = StageContext(workspace, "fixture", 1, config, offline=True)
        ctx.store.write_artifact("S1", "coverage-summary.json", {
            "status": "complete",
            "scope": {"status": "matched", "valid": True},
        })
        ctx.store.save_stage("S1", {
            "coverage_policy_version": SOURCE_INVENTORY_POLICY_VERSION,
        })
        ctx.store.save_stage("S2", {"candidates": [candidate]})
        ctx.store.save_stage("S3", {"candidate_state": [candidate]})
        ctx.store.save_stage("S4", {
            "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION,
        })
        ctx.store.write_artifact("S4", "verification-matrix.json", {})
        ctx.store.save_stage("S5", {
            "query_policy_version": NOVELTY_QUERY_POLICY_VERSION,
        })
        ctx.store.write_artifact("S5", "novelty.json", {})
        ctx.store.save_stage("S6", {
            "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION,
        })
        ctx.store.write_artifact("S6", "severity.json", {})
        ctx.store.save_stage("S7", {
            "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION,
        })
        ctx.store.save_stage("S8", {
            "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION,
        })
        return ctx

    def test_stage_only_resume_restores_scheduled_candidates(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = self.context(Path(td))
            seen = []

            def run_s8(context, summaries, conclusions, novelties, severities):
                seen.extend(context.config.candidates)
                return {"coverage": {"state": "complete"},
                        "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION}

            with patch.object(pipeline, "run_s8", side_effect=run_s8):
                pipeline.run_round(ctx, only="S8")
            self.assertEqual(["scheduled"], [row["candidate_id"] for row in seen])

    def test_stage_only_resume_rejects_stale_dependency_policy(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = self.context(Path(td))
            ctx.store.save_stage("S5", {"query_policy_version": "old"})
            with patch.object(pipeline, "run_s8") as run_s8:
                pipeline.run_round(ctx, only="S8")
            self.assertFalse(run_s8.called)
            report = ctx.store.read_artifact("S0", "resume-prerequisite-report.json")
            self.assertEqual("incompatible-stage-resume", report["status"])
            self.assertIn("S5 checkpoint has stale query_policy_version",
                          report["issues"])

    def test_rerun_marks_downstream_stale_until_full_resume(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = self.context(Path(td))
            calls = []
            with patch.object(pipeline, "run_s4", return_value={
                    "summaries": {}, "execution_budget": {"round_exhausted": False},
                    "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION}), \
                    patch.object(pipeline, "run_s8", return_value={
                        "coverage": {"state": "complete"},
                        "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION}):
                pipeline.run_round(ctx, only="S4")
            pending = ctx.store.read_artifact("S0", "stage-resume-invalidations.json")
            self.assertEqual(["S5", "S6", "S7", "S8"], pending["pending_stages"])
            with patch.object(pipeline, "run_s5", side_effect=lambda *_: (
                    calls.append("S5") or {"novelty": {},
                                             "query_policy_version": NOVELTY_QUERY_POLICY_VERSION})), \
                    patch.object(pipeline, "run_s6", side_effect=lambda *_: (
                        calls.append("S6") or {"severity": {},
                            "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION})), \
                    patch.object(pipeline, "run_s7", side_effect=lambda *_: (
                        calls.append("S7") or {"evidence_policy_version": S4_EVIDENCE_POLICY_VERSION})), \
                    patch.object(pipeline, "run_s8", side_effect=lambda *_: (
                        calls.append("S8") or {"coverage": {"state": "complete"},
                            "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION})):
                pipeline.run_round(ctx)
            self.assertEqual(["S5", "S6", "S7", "S8"], calls)
            pending = ctx.store.read_artifact("S0", "stage-resume-invalidations.json")
            self.assertEqual([], pending["pending_stages"])


class AutonomousScopeRegressionTests(unittest.TestCase):
    def test_expired_autonomous_round_stops_before_source_scans(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ctx = run_agent.AutoCtx(
                root, TargetConfig("fixture", "2026-09-25"), llm=None,
                offline=True, max_candidates=1, max_rounds=1)
            budget = {
                "schema_version": "audit-round-budget-v1",
                "target": "fixture", "round": 1,
                "round_started_at": "2026-09-25T00:00:00Z",
                "deadline_at": "2026-09-25T00:00:01Z",
                "budget_seconds": 1,
            }
            expired = {"expired": True, "remaining_seconds": 0,
                       "elapsed_seconds": 1, "budget_seconds": 1,
                       "deadline_at": budget["deadline_at"],
                       "claim_status": "not-a-finding"}
            with patch("agent.analysis.audit_budget.start_round_budget",
                       return_value=budget), \
                    patch("agent.analysis.audit_budget.round_budget_snapshot",
                          return_value=expired), \
                    patch.object(run_agent, "scan_s1_source_rules") as scan:
                result = run_agent.run_round(ctx, 1)
            self.assertEqual("stopped-at-round-deadline", result["status"])
            self.assertFalse(scan.called)
            report_path = (root / "state" / "fixture" / "round-01" / "S0"
                           / "round-timebox-report.json")
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual("S1", report["next_stage"])

    def test_failed_scope_bypasses_coverage_scheduler(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = TargetConfig("fixture", "2026-09-25")
            ctx = run_agent.AutoCtx(root, cfg, llm=None, offline=True,
                                    max_candidates=1, max_rounds=1)
            candidate = {"candidate_id": "explicit", "surface": "configured"}
            with patch.object(run_agent, "_current_coverage_scope",
                              return_value={"status": "failed", "usable": False}), \
                    patch("agent.analysis.scheduler.round_selection") as scheduler:
                selected, note = run_agent.schedule_candidates(
                    ctx, 1, [candidate])
            self.assertEqual([candidate], selected)
            self.assertIn("configured candidates only", note)
            self.assertFalse(scheduler.called)

    def test_deferred_inventory_does_not_block_candidate_scheduling(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ctx = run_agent.AutoCtx(
                root, TargetConfig("fixture", "2026-09-25"), llm=None,
                offline=True, max_candidates=1, max_rounds=1)
            ctx._coverage_inventory_round = 1
            ctx._coverage_inventory_state = {"deferred": True}
            candidate = {"candidate_id": "first-wave", "surface": "candidate"}
            with patch.object(run_agent, "_current_coverage_scope",
                              side_effect=AssertionError("scope scan should be deferred")), \
                    patch("agent.analysis.scheduler.round_selection",
                          side_effect=AssertionError("scheduler should be deferred")):
                selected, note = run_agent.schedule_candidates(ctx, 1, [candidate])
            self.assertEqual([candidate], selected)
            self.assertIn("after the first candidate wave", note)

    def test_deferred_inventory_keeps_s1_composite_chain_candidates(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = TargetConfig("fixture", "2026-09-25", static_candidates=True)
            chain_path = (root / "state" / "fixture" / "round-01" / "S1"
                          / "composite-chain-candidates.json")
            chain_path.parent.mkdir(parents=True)
            chain_path.write_text(
                '[{"candidate_id":"chain-first-wave","surface":"chain"}]',
                encoding="utf-8")
            ctx = run_agent.AutoCtx(root, cfg, llm=None, offline=True,
                                    max_candidates=1, max_rounds=1)
            ctx._coverage_inventory_round = 1
            ctx._coverage_inventory_state = {
                "deferred": True,
                "error": "index build deferred",
                "scope": {"status": "deferred", "usable": False},
            }
            with patch.object(run_agent, "_ensure_capability_inventory",
                              side_effect=AssertionError("must not rebuild here")):
                candidates, ids = run_agent.static_candidates(ctx, 1)
            self.assertEqual(["chain-first-wave"], ids)
            self.assertEqual("chain", candidates[0]["surface"])

    def test_missing_capability_inventory_is_deferred_without_rebuild(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ctx = run_agent.AutoCtx(
                root, TargetConfig("fixture", "2026-09-25"), llm=None,
                offline=True, max_candidates=1, max_rounds=1)
            with patch("agent.analysis.inventory.coverage_scope_status",
                       return_value={"status": "missing", "usable": False,
                                     "expected": {}, "actual": {},
                                     "mismatches": ["scope-metadata-missing"]}), \
                    patch("agent.analysis.inventory.build_inventory") as build:
                state = run_agent._ensure_capability_inventory(
                    ctx, allow_rebuild=False)
            self.assertTrue(state["deferred"])
            self.assertEqual("deferred", state["status"])
            self.assertFalse(state["scope"]["usable"])
            self.assertFalse(build.called)

    def test_force_flag_is_preserved_in_autonomous_context(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = run_agent.AutoCtx(Path(td), TargetConfig("fixture", "2026-09-25"),
                                    llm=None, offline=True, max_candidates=1,
                                    max_rounds=1, force=True)
            self.assertTrue(ctx.force)


if __name__ == "__main__":
    unittest.main()
