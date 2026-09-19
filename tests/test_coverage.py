"""Coverage math contract (spec §5, §16, §19.6, §20).

The property under test is that no ratio can be improved by *discovering less*.
Every test here either pins a denominator to the full inventory or pins a
zero-denominator case to ``None``/``n/a`` -- the two ways a coverage number can
lie.

These tests are pure-DB (plain dicts in, metric dict out) so they need neither
ripgrep nor a target tree.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from agent.analysis import coverage as cov  # noqa: E402


def source(file, production=True, indexed=True, skip_reason="", sinks=0, entries=0,
           controls=0, **extra):
    record = {"file": file, "production": production, "indexed": indexed,
              "skip_reason": skip_reason, "sinks": sinks, "entries": entries,
              "controls": controls, "audit_state": "indexed" if indexed else "excluded",
              "review_state": "indexed" if indexed else "excluded"}
    record.update(extra)
    return record


def sink(sink_id="sink:command-exec:a.java:10", category="command-exec",
         severity="high", file="a.java", line=10, **extra):
    record = {"sink_id": sink_id, "category": category, "file": file, "line": line,
              "severity_hint": severity, "review_state": "indexed",
              "reachable_from_entries": [], "backward_reachable": False,
              "candidate_ids": []}
    record.update(extra)
    return record


def entry(entry_id="http:x.java:1", kind="http", file="x.java", line=1, **extra):
    record = {"entry_id": entry_id, "kind": kind, "file": file, "line": line,
              "review_state": "indexed", "candidate_ids": []}
    record.update(extra)
    return record


def control(control_id="authorization:a.java:5", category="authorization",
            file="a.java", **extra):
    record = {"control_id": control_id, "category": category, "file": file,
              "line": 5, "control_type": "permission-check",
              "review_state": "indexed", "candidate_ids": []}
    record.update(extra)
    return record


def flow(flow_id="flow-1", priority="high", entry_id="http:x.java:1", **extra):
    record = {"flow_id": flow_id, "entry_id": entry_id,
              "sink_id": "sink:command-exec:a.java:10", "path": ["a", "b"],
              "priority": priority, "review_state": "pending", "candidate_ids": []}
    record.update(extra)
    return record


def indices(sources=(), entries=(), sinks=(), controls=(), flows=()):
    return {
        "source-inventory": list(sources),
        "entry-index": list(entries),
        "sink-index": list(sinks),
        "security-control-index": list(controls),
        "flow-index": list(flows),
    }


class DenominatorTests(unittest.TestCase):
    """Ratios must divide by the full inventory, not by what was reviewed."""

    def test_source_coverage_uses_every_discovered_production_file(self):
        sources = [source("f%d.java" % i) for i in range(100)]
        for record in sources[:50]:
            record["review_state"] = "reviewed"
        summary = cov.compute_coverage(indices(sources=sources))
        self.assertEqual(summary["metrics"]["source_coverage"], 1.0)
        self.assertEqual(summary["counts"]["production_source_files"], 100)

    def test_skipped_files_are_out_of_the_denominator(self):
        sources = [source("a.java"), source("t.java", production=False,
                                            indexed=False, skip_reason="test")]
        summary = cov.compute_coverage(indices(sources=sources))
        self.assertEqual(summary["counts"]["production_source_files"], 1)
        self.assertEqual(summary["counts"]["skipped_source_files"], 1)
        self.assertEqual(summary["metrics"]["source_coverage"], 1.0)

    def test_one_hundred_sinks_with_ten_reviewed_is_ten_percent(self):
        sinks = []
        for i in range(100):
            record = sink(sink_id="s%d" % i)
            if i < 10:
                record["review_state"] = "reviewed"
            sinks.append(record)
        summary = cov.compute_coverage(indices(sinks=sinks))
        self.assertEqual(summary["metrics"]["sink_coverage"], 0.1)
        self.assertEqual(summary["counts"]["sinks"], 100)

    def test_zero_denominator_is_undefined_not_perfect(self):
        summary = cov.compute_coverage(indices())
        for name in ("source_coverage", "entry_coverage", "sink_coverage",
                     "flow_coverage", "auth_boundary_coverage"):
            self.assertIsNone(summary["metrics"][name],
                              "%s must be None, not 1.0, with no data" % name)
            self.assertFalse(summary["acceptance"][name]["met"])
        self.assertIn("n/a", cov.render_coverage_text(summary, "en"))

    def test_flow_coverage_only_counts_high_and_medium_priorities(self):
        flows = [flow("f1", "high", review_state="reviewed"),
                 flow("f2", "medium", review_state="pending"),
                 flow("f3", "low", review_state="pending")]
        summary = cov.compute_coverage(indices(flows=flows))
        self.assertEqual(summary["counts"]["flows_priority"], 2)
        self.assertEqual(summary["metrics"]["flow_coverage"], 0.5)

    def test_reachability_analysis_counts_beyond_review_state(self):
        sinks = [sink("s1", reachable_from_entries=["e1"]),
                 sink("s2", backward_reachable=True),
                 sink("s3", review_state="reviewed"),
                 sink("s4")]
        summary = cov.compute_coverage(indices(sinks=sinks))
        self.assertEqual(summary["counts"]["sinks_reachability_analyzed"], 3)
        self.assertEqual(summary["metrics"]["sink_coverage"], 0.75)


class ReviewStateTests(unittest.TestCase):
    def test_excluded_counts_as_reviewed(self):
        sinks = [sink("s1", review_state="excluded"), sink("s2")]
        summary = cov.compute_coverage(indices(sinks=sinks))
        # ``excluded`` is a decision; only s2's reachability is unresolved, so
        # the reviewed sink is evidence the region was looked at.
        self.assertEqual(summary["counts"]["records_reviewed"], 1)

    def test_runtime_verification_share_is_over_reviewed_records(self):
        sinks = [sink("s1", review_state="runtime-verified"),
                 sink("s2", review_state="reviewed"),
                 sink("s3", review_state="indexed")]
        summary = cov.compute_coverage(indices(sinks=sinks))
        self.assertEqual(summary["counts"]["records_runtime_verified"], 1)
        self.assertEqual(summary["counts"]["records_statically_reviewed"], 1)
        self.assertEqual(summary["metrics"]["runtime_verification_coverage"], 0.5)

    def test_auth_and_validation_ratios_use_their_own_categories(self):
        controls = [control("c1", "authorization"),
                    control("c2", "authorization", review_state="reviewed"),
                    control("c3", "validation"),
                    control("c4", "sanitization"),
                    control("c5", "rate-limit")]
        summary = cov.compute_coverage(indices(controls=controls))
        self.assertEqual(summary["counts"]["auth_boundaries"], 2)
        self.assertEqual(summary["metrics"]["auth_boundary_coverage"], 0.5)
        self.assertEqual(summary["counts"]["validation_controls"], 2)
        self.assertEqual(summary["metrics"]["validation_coverage"], 0.0)
        # Documented boundary: a resource control is indexed but belongs to
        # neither the auth-boundary nor the validation ratio.
        self.assertEqual(summary["counts"]["controls"], 5)
        self.assertNotIn("rate-limit", cov.AUTH_BOUNDARY_CONTROL_CATEGORIES)
        self.assertNotIn("rate-limit", cov.VALIDATION_CONTROL_CATEGORIES)


class UncoveredRegionTests(unittest.TestCase):
    def test_open_high_sink_is_a_high_gap(self):
        summary = cov.compute_coverage(indices(sinks=[sink(severity="high")]))
        self.assertGreaterEqual(summary["high_risk_uncovered"], 1)
        kinds = {r["kind"] for r in summary["uncovered_regions"]}
        self.assertIn("unreviewed-sink", kinds)
        self.assertFalse(summary["stop_condition_met"])

    def test_reviewed_high_sink_closes_the_gap(self):
        summary = cov.compute_coverage(indices(
            sinks=[sink(severity="high", review_state="reviewed")]))
        self.assertEqual(summary["high_risk_uncovered"], 0)
        self.assertTrue(summary["stop_condition_met"])

    def test_network_entry_kinds_are_high_risk(self):
        summary = cov.compute_coverage(indices(entries=[
            entry("e1", "http"), entry("e2", "config")]))
        gaps = [r for r in summary["uncovered_regions"] if r["kind"] == "unreviewed-entry"]
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0]["ref"], "e1")

    def test_control_gap_requires_no_candidate(self):
        controls = [control("c1", "authorization"),
                    control("c2", "authorization", candidate_ids=["C-1"])]
        summary = cov.compute_coverage(indices(controls=controls))
        gaps = [r for r in summary["uncovered_regions"] if r["kind"] == "control-gap"]
        self.assertEqual([g["ref"] for g in gaps], ["c1"])

    def test_forward_backward_mismatch_is_reported(self):
        sinks = [sink("s1", backward_reachable=True),
                 sink("s2", reachable_from_entries=["e1"])]
        summary = cov.compute_coverage(indices(sinks=sinks))
        gaps = [r for r in summary["uncovered_regions"]
                if r["kind"] == "forward-backward-mismatch"]
        self.assertEqual(len(gaps), 2)
        by_ref = {g["ref"]: g for g in gaps}
        self.assertTrue(by_ref["s1"]["detail"]["backward_seen"])
        self.assertTrue(by_ref["s2"]["detail"]["forward_seen"])

    def test_unreviewed_flow_is_a_gap_at_its_own_priority(self):
        summary = cov.compute_coverage(indices(flows=[
            flow("f-high", "high"), flow("f-med", "medium")]))
        risks = {r["ref"]: r["risk"] for r in summary["uncovered_regions"]
                 if r["kind"] == "unreviewed-flow"}
        self.assertEqual(risks.get("f-high"), "high")
        self.assertEqual(risks.get("f-med"), "medium")

    def test_limit_per_kind_truncates_without_changing_counts(self):
        sinks = [sink("s%d" % i) for i in range(20)]
        regions = cov.build_uncovered_regions(indices(sinks=sinks), limit_per_kind=5)
        self.assertEqual(len(regions), 5)


class CandidateCoverageTests(unittest.TestCase):
    def test_candidate_marks_touched_regions_reviewed(self):
        data = indices(
            entries=[entry("e1", file="src/UserController.java", line=100)],
            sinks=[sink("s1", file="src/UserController.java", line=120),
                   sink("s2", file="src/Other.java", line=5)],
            flows=[flow("f1", entry_id="e1")])
        rows = [{"candidate_id": "C-1", "conclusion": "排除",
                 "code_location": ["src/UserController.java:110"]}]
        records = cov.build_candidate_coverage(rows, data)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].entries, ["e1"])
        self.assertEqual(records[0].sinks, ["s1"])
        self.assertEqual(records[0].flows, ["f1"])
        self.assertEqual(records[0].status, "excluded")

        marks = cov.apply_candidate_coverage(data, [r.as_dict() for r in records])
        self.assertEqual(marks["sinks"], 1)
        self.assertEqual(data["sink-index"][0]["review_state"], "excluded")
        self.assertEqual(data["sink-index"][1]["review_state"], "indexed")
        self.assertEqual(data["entry-index"][0]["review_state"], "excluded")

    def test_confirmed_candidate_marks_regions_reviewed_not_verified(self):
        data = indices(sinks=[sink("s1", file="a.java", line=10)])
        rows = [{"candidate_id": "C-1", "conclusion": "确认；High",
                 "code_location": ["a.java:10"]}]
        records = cov.build_candidate_coverage(rows, data)
        cov.apply_candidate_coverage(data, [r.as_dict() for r in records])
        # Only S4/G4 may set runtime-verified; coverage linkage cannot.
        self.assertEqual(data["sink-index"][0]["review_state"], "reviewed")

    def test_line_distance_window_bounds_the_linkage(self):
        data = indices(sinks=[sink("near", file="a.java", line=110),
                              sink("far", file="a.java", line=9000)])
        rows = [{"candidate_id": "C-1", "conclusion": "排查中",
                 "code_location": ["a.java:100"]}]
        records = cov.build_candidate_coverage(rows, data)
        self.assertEqual(records[0].sinks, ["near"])

    def test_candidate_without_locations_matches_nothing(self):
        data = indices(sinks=[sink("s1")])
        records = cov.build_candidate_coverage(
            [{"candidate_id": "C-1", "conclusion": "确认"}], data)
        self.assertEqual(records[0].sinks, [])

    def test_open_status_does_not_change_review_state(self):
        data = indices(sinks=[sink("s1", file="a.java", line=10)])
        records = cov.build_candidate_coverage(
            [{"candidate_id": "C-1", "conclusion": "", "code_location": ["a.java:10"]}],
            data)
        self.assertEqual(records[0].status, "open")
        cov.apply_candidate_coverage(data, [r.as_dict() for r in records])
        self.assertEqual(data["sink-index"][0]["review_state"], "indexed")


class RefreshIntegrationTests(unittest.TestCase):
    """``coverage`` CLI path: index on disk + ledger on disk -> summary."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self):
        from agent.analysis.inventory import CoverageStore
        return CoverageStore(self.workspace, "demo")

    def _write_indices(self):
        store = self._store()
        store.write("source-inventory", [source("src/A.java", sinks=1)])
        store.write("entry-index", [entry("http:src/A.java:1",
                                          file="src/A.java", line=1)])
        store.write("sink-index", [sink("sink:command-exec:src/A.java:10",
                                        file="src/A.java", line=10)])
        store.write("security-control-index", [
            control("authorization:src/A.java:5", file="src/A.java")])
        store.write("flow-index", [flow("f1", priority="high",
                                       entry_id="http:src/A.java:1")])
        return store

    def _write_ledger(self, rows):
        directory = self.workspace / "ledger" / "demo" / "round-01"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "ledger.json").write_text(json.dumps(
            {"round": 1, "target": "demo", "rows": rows, "excluded": [],
             "summary": {}}, ensure_ascii=False), encoding="utf-8")

    def test_refresh_derives_state_from_the_ledger(self):
        store = self._write_indices()
        self._write_ledger([{"candidate_id": "C-1", "conclusion": "排除；不可达",
                             "code_location": ["src/A.java:10"]}])
        result = cov.refresh_candidate_coverage(store, self.workspace, "demo")
        self.assertEqual(result["candidates"], 1)
        self.assertGreaterEqual(result["marks"]["sinks"], 1)
        sinks = store.read_records("sink-index")
        self.assertEqual(sinks[0]["review_state"], "excluded")
        self.assertIn("C-1", sinks[0]["candidate_ids"])

    def test_second_refresh_is_idempotent(self):
        store = self._write_indices()
        self._write_ledger([{"candidate_id": "C-1", "conclusion": "排除",
                             "code_location": ["src/A.java:10"]}])
        first = cov.refresh_candidate_coverage(store, self.workspace, "demo")
        second = cov.refresh_candidate_coverage(store, self.workspace, "demo")
        self.assertEqual(first["coverage"], second["coverage"])
        self.assertEqual(second["marks"]["sinks"], 1)
        self.assertEqual(store.read_records("sink-index")[0]["candidate_ids"], ["C-1"])

    def test_without_a_ledger_the_summary_still_renders(self):
        store = self._write_indices()
        cov.refresh_candidate_coverage(store, self.workspace, "demo")
        summary = store.read("coverage-summary")
        self.assertIn("metrics", summary)
        self.assertEqual(summary["counts"]["sinks"], 1)
        self.assertGreaterEqual(summary["high_risk_uncovered"], 1)

    def test_uncovered_regions_are_persisted(self):
        store = self._write_indices()
        cov.refresh_candidate_coverage(store, self.workspace, "demo")
        regions = store.read_records("uncovered-regions")
        self.assertTrue(regions)
        self.assertTrue(all("region_id" in r and "kind" in r for r in regions))


class AcceptanceContractTests(unittest.TestCase):
    """Spec §20 thresholds, pinned so a "fix" cannot quietly relax them."""

    def test_targets_match_the_spec(self):
        self.assertEqual(cov.ACCEPTANCE_TARGETS, {
            "source_coverage": 0.98,
            "entry_coverage": 0.95,
            "sink_coverage": 0.95,
            "flow_coverage": 0.90,
            "auth_boundary_coverage": 0.95,
        })

    def test_acceptance_uses_the_spec_thresholds(self):
        summary = cov.compute_coverage(indices())
        self.assertEqual(summary["acceptance"]["source_coverage"]["target"], 0.98)
        self.assertEqual(summary["acceptance"]["flow_coverage"]["target"], 0.90)

    def test_summary_carries_the_stop_condition(self):
        summary = cov.compute_coverage(indices())
        self.assertIn("stop_condition_met", summary)
        self.assertIn("high_risk_uncovered", summary)


class RenderingTests(unittest.TestCase):
    def test_english_render_matches_the_spec_layout(self):
        summary = cov.compute_coverage(indices(sinks=[sink()]))
        text = cov.render_coverage_text(summary, "en")
        for needle in ("Security Audit Coverage", "Production source files",
                       "Danger sinks", "HIGH-risk unreviewed",
                       "Acceptance targets", "Stop condition"):
            self.assertIn(needle, text)

    def test_chinese_render_is_available(self):
        summary = cov.compute_coverage(indices(sinks=[sink()]))
        self.assertIn("安全审计覆盖率", cov.render_coverage_text(summary, "zh"))

    def test_gap_histogram_is_optional(self):
        summary = cov.compute_coverage(indices(sinks=[sink()]))
        self.assertNotIn("Coverage gaps", cov.render_coverage_text(summary, "en"))
        self.assertIn("Coverage gaps",
                      cov.render_coverage_text(summary, "en", gap_limit=1))


if __name__ == "__main__":
    unittest.main()
