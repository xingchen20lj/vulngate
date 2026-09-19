"""Coverage-aware candidate scheduling (spec §13, §14, §15).

The scheduler replaces "Top-K by danger" with a quota-stratified, coverage-aware
pick.  Each test below guards a specific way that replacement can fail silently:

1. **Linkage must not saturate.**  The first draft linked a candidate to every
   sink inside a 160-line window; on this repository one module-scope candidate
   then owned 2 380 flows and every factor pinned at 1.0 -- i.e. it degenerated
   straight back into "rank by danger".  Linkage is now symbol-tight and the
   innermost symbol wins, so a class is never a hub for its methods.
2. **Absence must not score.**  A factor the indices cannot evaluate returns a
   low value with a reason, never a high one.  Several tests assert the *low*
   end for exactly this reason.
3. **Quota must relocate, not shrink.**  Spec §13.3 allows an unfillable
   category to move its slot; the round must still come back `slots` wide and
   the relocation must be reported per category.
4. **Nothing may be dropped.**  Selected + deferred is the whole pool, disjoint,
   and every candidate keeps its score and reason into the next round.
5. **The prompt block must be checkable against the spec.**  §15 lists ten
   sections; the block emits them, named and ordered, or the test fails.

Fixtures run the real inventory (source scan -> symbols -> call graph -> flows),
so the scheduler is exercised against the same records production sees.
"""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from agent.analysis import inventory as INV  # noqa: E402
from agent.analysis import scheduler as SCH  # noqa: E402


# --- fixture: two HTTP handlers, one with an authorization control ----------

CONTROLLER = '''package com.foo;

public class UserController {
    private final UserService service = new UserService();

    @PostMapping("/api/user/update")
    public String updateUser(String id, String body) {
        return service.update(id, body);
    }

    @PostMapping("/api/admin/update")
    public String adminUpdate(String id, String body) {
        if (!service.hasPermission("admin")) {
            throw new IllegalStateException("forbidden");
        }
        return service.update(id, body);
    }
}
'''

SERVICE = '''package com.foo;

public class UserService {
    private final Runner runner = new Runner();

    public String update(String id, String body) {
        return runner.run(body);
    }

    public boolean hasPermission(String role) {
        return "admin".equals(role);
    }
}
'''

RUNNER = '''package com.foo;

public class Runner {
    public String run(String body) {
        return Runtime.getRuntime().exec(body).toString();
    }
}
'''

UPDATE_USER = "src/com/foo/UserController.java:6"
ADMIN_UPDATE = "src/com/foo/UserController.java:11"
CONTROLLER_MODULE_SCOPE = "src/com/foo/UserController.java:1"
RUNNER_SINK = "src/com/foo/Runner.java:5"
RUNNER_MODULE_SCOPE = "src/com/foo/Runner.java:1"
SINK_ID = "sink:command-exec:src/com/foo/Runner.java:5"


class ScheduleFixture(unittest.TestCase):
    """Real tree -> real inventory -> persisted store -> real context."""

    FILES = {
        "src/com/foo/UserController.java": CONTROLLER,
        "src/com/foo/UserService.java": SERVICE,
        "src/com/foo/Runner.java": RUNNER,
    }

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vulngate-sched-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))
        for rel, text in self.FILES.items():
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        self.result = INV.build_inventory(self.root, source_dirs=["src"],
                                          target="fixture")
        self.store = INV.CoverageStore(self.root, "fixture")
        INV.persist_inventory(self.store, self.result)
        self.context()

    # --- helpers -----------------------------------------------------------

    def context(self, weights=None):
        self.ctx = SCH.ScheduleContext.from_store(self.store, weights)
        return self.ctx

    def candidate(self, candidate_id, *locations, **extra):
        payload = {"candidate_id": candidate_id,
                   "code_location": list(locations)}
        payload.update(extra)
        return payload

    def coverage_record(self, candidate_id, status="confirmed", **fields):
        record = {"candidate_id": candidate_id, "round": 1, "status": status,
                  "conclusion": "确认" if status == "confirmed" else "排除",
                  "entries": [], "sinks": [], "flows": [], "files": [],
                  "categories": [], "mechanisms": []}
        record.update(fields)
        return record

    def save_coverage(self, records):
        self.store.write_records("candidate-coverage", records)
        return self.context()

    def entry_ids(self):
        return sorted(e.entry_id for e in self.result.entries)

    def flow_ids(self):
        return sorted(f.flow_id for f in self.result.flows)

    def factors(self, candidate):
        return SCH.score_candidate(candidate, self.ctx).factors


# ---------------------------------------------------------------------------
# 1. linkage
# ---------------------------------------------------------------------------

class LinkageTests(ScheduleFixture):

    def test_innermost_symbol_wins_over_enclosing_declarations(self):
        """A line inside a method belongs to the method -- not to class + file.

        Linking to every enclosing declaration would make the class a hub and
        let any flow through any of its methods look like it reaches the
        candidate.
        """
        link = SCH.linked_regions(self.candidate("C1", ADMIN_UPDATE), self.ctx)
        self.assertEqual({"java:com.foo.UserController#adminUpdate"}, link.symbols)

    def test_symbols_at_returns_one_symbol_per_location(self):
        ctx = SCH.ScheduleContext(symbols={
            "file": {"symbol_id": "file", "file": "a.java",
                     "start_line": 1, "end_line": 100},
            "cls": {"symbol_id": "cls", "file": "a.java",
                    "start_line": 5, "end_line": 90},
            "m1": {"symbol_id": "m1", "file": "a.java",
                   "start_line": 10, "end_line": 20},
            "m2": {"symbol_id": "m2", "file": "a.java",
                   "start_line": 30, "end_line": 40},
        })
        cases = ((15, {"m1"}), (35, {"m2"}), (50, {"cls"}), (95, {"file"}))
        for line, expected in cases:
            names, resolved = SCH._symbols_at(ctx, [("a.java", line)])
            self.assertTrue(resolved)
            self.assertEqual(expected, names, "line %d" % line)

    def test_symbols_at_is_empty_for_an_unindexed_file(self):
        names, resolved = SCH._symbols_at(self.ctx, [("nowhere/at/all.c", 3)])
        self.assertEqual(set(), names)
        self.assertFalse(resolved)

    def test_module_scope_location_binds_to_the_file_symbol(self):
        link = SCH.linked_regions(self.candidate("C1", RUNNER_MODULE_SCOPE),
                                  self.ctx)
        self.assertEqual({"java:src/com/foo/Runner.java"}, link.symbols)

    def test_destination_flow_is_separated_from_on_path_flow(self):
        sink = SCH.linked_regions(self.candidate("C1", RUNNER_SINK), self.ctx)
        self.assertEqual(2, len(sink.flows_reaching))
        self.assertEqual([], sink.flows_on_path)
        self.assertEqual([SINK_ID], [s.get("sink_id") for s in sink.sinks])

    def test_handler_is_on_the_path_not_at_the_destination(self):
        handler = SCH.linked_regions(self.candidate("C1", UPDATE_USER), self.ctx)
        self.assertEqual([], handler.flows_reaching)
        self.assertEqual(1, len(handler.flows_on_path))
        self.assertEqual([], handler.sinks)

    def test_unindexed_location_falls_back_to_the_line_window(self):
        """A file with no symbol index is still linked, and says that it was."""
        link = SCH.linked_regions(self.candidate("C1", "vendored/lib.c:10"),
                                  self.ctx)
        self.assertTrue(link.fallback_used)
        self.assertEqual(set(), link.symbols)
        quality = SCH.score_candidate(
            self.candidate("C1", "vendored/lib.c:10"), self.ctx)
        self.assertIn("line window", quality.reasons["evidence_quality"])

    def test_indexed_location_does_not_use_the_line_window(self):
        link = SCH.linked_regions(self.candidate("C1", RUNNER_SINK), self.ctx)
        self.assertFalse(link.fallback_used)

    def test_candidate_without_locations_links_to_nothing(self):
        link = SCH.linked_regions({"candidate_id": "C1"}, self.ctx)
        self.assertEqual(set(), link.symbols)
        self.assertEqual([], link.sinks)
        self.assertEqual([], link.all_flows())

    def test_locations_parse_from_string_and_list_forms(self):
        single = SCH.candidate_locations({"code_location": RUNNER_SINK})
        many = SCH.candidate_locations({"code_location": [RUNNER_SINK, UPDATE_USER]})
        self.assertEqual([("src/com/foo/Runner.java", 5)], single)
        self.assertEqual(2, len(many))

    def test_unparseable_locations_are_ignored_not_guessed(self):
        self.assertEqual([], SCH.candidate_locations({"code_location": ["nope"]}))
        self.assertEqual([], SCH.candidate_locations({}))

    def test_linkage_is_deterministic(self):
        candidate = self.candidate("C1", RUNNER_SINK)
        first = SCH.linked_regions(candidate, self.ctx)
        second = SCH.linked_regions(candidate, self.ctx)
        self.assertEqual(first.symbols, second.symbols)
        self.assertEqual([f.get("flow_id") for f in first.all_flows()],
                         [f.get("flow_id") for f in second.all_flows()])


# ---------------------------------------------------------------------------
# 2. scoring
# ---------------------------------------------------------------------------

class ScoringTests(ScheduleFixture):

    def score(self, candidate):
        return SCH.score_candidate(candidate, self.ctx)

    def test_every_factor_reports_a_reason_and_its_evidence(self):
        score = self.score(self.candidate("C1", RUNNER_SINK))
        for name in SCH.FACTOR_ORDER:
            self.assertIn(name, score.factors)
            self.assertTrue(score.reasons[name].strip(), name)
            self.assertIsInstance(score.evidence[name], dict, name)

    def test_total_is_a_percentage_of_the_configured_scale(self):
        score = self.score(self.candidate("C1", RUNNER_SINK))
        scale = sum(SCH.DEFAULT_FACTOR_WEIGHTS.values())
        self.assertEqual(100, scale)
        self.assertLessEqual(score.total, scale)
        expected = sum(score.factors[n] * SCH.DEFAULT_FACTOR_WEIGHTS[n]
                       for n in SCH.FACTOR_ORDER)
        self.assertAlmostEqual(expected, score.total, places=6)

    def test_weights_can_be_overridden_and_the_scale_follows(self):
        """A custom weight set stays readable: the total is still its own scale."""
        weights = {"reachability": 50, "evidence_quality": 50}
        ctx = self.context(weights=weights)
        score = SCH.score_candidate(self.candidate("C1", RUNNER_SINK), ctx)
        # This candidate scores 1.0 on both retained factors and 0 on the rest.
        self.assertEqual(1.0, score.factors["reachability"])
        self.assertEqual(1.0, score.factors["evidence_quality"])
        self.assertEqual(100.0, score.total)
        self.assertEqual(0.0, score.weighted["sink_impact"])
        self.assertEqual("high", score.band)

    def test_band_thresholds_are_fractions_of_the_scale(self):
        self.assertEqual("high", SCH._band(65, 100))
        self.assertEqual("high", SCH._band(100, 100))
        self.assertEqual("medium", SCH._band(64.9, 100))
        self.assertEqual("medium", SCH._band(40, 100))
        self.assertEqual("low", SCH._band(39.9, 100))
        self.assertEqual("low", SCH._band(0, 0))

    def test_a_candidate_with_no_evidence_scores_low_not_high(self):
        score = self.score({"candidate_id": "C1"})
        self.assertEqual(0.0, score.factors["reachability"])
        self.assertEqual(0.0, score.factors["sink_impact"])
        self.assertEqual(0.0, score.factors["control_gap"])
        self.assertEqual("low", score.band)

    def test_reachability_damps_a_candidate_that_is_only_on_the_path(self):
        on_path = self.score(self.candidate("C1", UPDATE_USER))
        destination = self.score(self.candidate("C2", RUNNER_SINK))
        self.assertAlmostEqual(1.0 * SCH.ON_PATH_ONLY,
                               on_path.factors["reachability"], places=6)
        self.assertAlmostEqual(1.0, destination.factors["reachability"], places=6)
        self.assertIn("passes through", on_path.reasons["reachability"])

    def test_sink_impact_ceiling_beats_an_under_graded_severity(self):
        """A catalog that grades command-exec "low" must not be able to hide it."""
        self.ctx.sinks[SINK_ID]["severity_hint"] = "low"
        score = self.score(self.candidate("C1", RUNNER_SINK))
        self.assertEqual(1.0, score.factors["sink_impact"])

    def test_sink_impact_is_zero_without_a_linked_sink(self):
        score = self.score(self.candidate("C1", UPDATE_USER))
        self.assertEqual(0.0, score.factors["sink_impact"])
        self.assertEqual("no sink linked", score.reasons["sink_impact"])

    def test_attacker_control_reads_the_entry_kind_of_the_path(self):
        score = self.score(self.candidate("C1", RUNNER_SINK))
        self.assertEqual(1.0, score.factors["attacker_control"])
        self.assertIn("http", score.reasons["attacker_control"])

    def test_security_boundary_is_crossed_by_an_http_entry(self):
        score = self.score(self.candidate("C1", RUNNER_SINK))
        boundary = score.evidence["security_boundary"]
        self.assertEqual(["http"], boundary["boundary_kinds"])
        self.assertEqual(2, boundary["boundary_paths"])
        self.assertFalse(boundary["authorization_on_path"])
        self.assertGreater(score.factors["security_boundary"],
                           SCH.BOUNDARY_GUARDED)

    def test_boundary_exposure_is_the_unguarded_fraction_of_paths(self):
        score = self.score(self.candidate("C1", RUNNER_SINK))
        self.assertAlmostEqual(0.5, score.evidence["security_boundary"]["exposure"],
                               places=6)
        self.assertAlmostEqual(
            SCH.BOUNDARY_GUARDED + (1.0 - SCH.BOUNDARY_GUARDED) * 0.5,
            score.factors["security_boundary"], places=6)

    def test_more_exposure_scores_monotonically_higher(self):
        """Partial exposure must sit between fully guarded and fully unguarded."""
        partial = self.score(self.candidate("C1", RUNNER_SINK))
        for flow in self.ctx.flows:
            flow["authorizations"] = []          # every path now unguarded
        full = self.score(self.candidate("C1", RUNNER_SINK))
        self.assertAlmostEqual(0.5, partial.evidence["security_boundary"]["exposure"],
                               places=6)
        self.assertAlmostEqual(1.0, full.evidence["security_boundary"]["exposure"],
                               places=6)
        self.assertLess(partial.factors["security_boundary"],
                        full.factors["security_boundary"])
        self.assertLess(partial.factors["control_gap"], full.factors["control_gap"])
        self.assertGreater(full.factors["security_boundary"], SCH.BOUNDARY_GUARDED)
        self.assertGreater(full.factors["control_gap"],
                           SCH.CONTROL_PRESENT_UNREVIEWED)

    def test_boundary_with_an_authorization_on_the_path_scores_lower(self):
        guarded = self.score(self.candidate("C1", ADMIN_UPDATE))
        unguarded = self.score(self.candidate("C2", UPDATE_USER))
        self.assertEqual(0.6, guarded.factors["security_boundary"])
        self.assertEqual(1.0, unguarded.factors["security_boundary"])
        self.assertIn("presence is not proof", guarded.reasons["security_boundary"])

    def test_control_gap_is_full_when_the_boundary_has_no_authorization(self):
        score = self.score(self.candidate("C1", UPDATE_USER))
        self.assertEqual(1.0, score.factors["control_gap"])
        self.assertEqual([], score.evidence["control_gap"]["authorizations"])

    def test_control_gap_is_lower_when_an_authorization_is_on_the_path(self):
        score = self.score(self.candidate("C1", ADMIN_UPDATE))
        self.assertLess(score.factors["control_gap"], 1.0)
        self.assertEqual(["authorization:hasPermission"],
                         score.evidence["control_gap"]["authorizations"])

    def test_one_guarded_path_must_not_mask_an_unguarded_one(self):
        """The sink here is reached by two paths; only one carries a control.

        Taking the union of the paths' controls would report this sink as
        guarded, hiding the unguarded path -- which is the only one an attacker
        needs.  The verdict is therefore per path, most exposed path winning.
        """
        score = self.score(self.candidate("C1", RUNNER_SINK))
        boundary = score.evidence["security_boundary"]
        self.assertFalse(boundary["authorization_on_path"])
        self.assertEqual(1, len(boundary["unguarded_paths"]))
        self.assertGreater(score.factors["security_boundary"], SCH.BOUNDARY_GUARDED)
        self.assertGreater(score.factors["control_gap"],
                           SCH.CONTROL_PRESENT_UNREVIEWED)
        self.assertEqual(1, len(score.evidence["control_gap"]["unguarded_paths"]))
        self.assertIn("no authorization control on 1 of 2 path(s)",
                      score.reasons["control_gap"])

    def test_a_fully_guarded_candidate_is_not_reported_as_unguarded(self):
        guarded = self.score(self.candidate("C1", ADMIN_UPDATE))
        self.assertTrue(guarded.evidence["security_boundary"]["authorization_on_path"])
        self.assertNotIn("unguarded_paths", guarded.evidence["control_gap"])

    def test_evidence_quality_grows_with_indexed_context(self):
        handler = self.score(self.candidate("C1", ADMIN_UPDATE))
        sink = self.score(self.candidate("C2", RUNNER_SINK))
        self.assertAlmostEqual(0.8, handler.factors["evidence_quality"], places=6)
        self.assertAlmostEqual(1.0, sink.factors["evidence_quality"], places=6)

    def test_evidence_quality_is_zero_without_locations(self):
        score = self.score({"candidate_id": "C1"})
        self.assertEqual(0.0, score.factors["evidence_quality"])
        self.assertIn("no file:line", score.reasons["evidence_quality"])

    def test_coverage_novelty_is_full_before_anything_is_reviewed(self):
        score = self.score(self.candidate("C1", RUNNER_SINK))
        self.assertEqual(1.0, score.factors["coverage_novelty"])

    def test_coverage_novelty_collapses_on_a_reviewed_region(self):
        self.save_coverage([self.coverage_record(
            "C-reviewed", files=["src/com/foo/Runner.java"],
            entries=self.entry_ids(), sinks=[SINK_ID],
            categories=["command-exec"], flows=self.flow_ids())])
        score = self.score(self.candidate("C1", RUNNER_SINK))
        self.assertEqual(0.0, score.factors["coverage_novelty"])
        self.assertIn("0/5", score.reasons["coverage_novelty"])

    def test_coverage_novelty_ignores_still_open_records(self):
        """A candidate that never got a verdict does not count as reviewed."""
        self.save_coverage([self.coverage_record(
            "C-open", status="candidate", sinks=[SINK_ID],
            files=["src/com/foo/Runner.java"])])
        score = self.score(self.candidate("C1", RUNNER_SINK))
        self.assertEqual(1.0, score.factors["coverage_novelty"])

    def test_bands_are_reachable_from_real_scores(self):
        low = self.score({"candidate_id": "C0"})
        high = self.score(self.candidate("C1", RUNNER_SINK))
        self.assertEqual("low", low.band)
        self.assertIn(high.band, ("medium", "high"))
        self.assertGreater(high.total, low.total)

    def test_score_is_deterministic(self):
        candidate = self.candidate("C1", RUNNER_SINK, surface="command exec")
        first = SCH.score_candidate(candidate, self.ctx)
        second = SCH.score_candidate(candidate, self.ctx)
        self.assertEqual(first.as_dict(), second.as_dict())

    def test_as_dict_carries_locations_for_after_the_fact_audit(self):
        score = self.score(self.candidate("C1", RUNNER_SINK))
        self.assertEqual([RUNNER_SINK], score.as_dict()["code_locations"])


# ---------------------------------------------------------------------------
# 2b. duplicate damping
# ---------------------------------------------------------------------------

class DuplicateTests(ScheduleFixture):

    def test_reviewed_region_marks_the_candidate_a_duplicate_and_damps_it(self):
        """Damping is applied once, to the total, and is visible in the score."""
        self.save_coverage([self.coverage_record("C1", sinks=[SINK_ID],
                                                 files=["src/com/foo/Runner.java"])])
        score = SCH.score_candidate(self.candidate("C1", RUNNER_SINK), self.ctx)
        self.assertEqual("C1", score.duplicate_of)
        self.assertEqual(SCH.DUPLICATE_DAMPING, score.evidence["duplicate"]["damping"])
        undamped = sum(score.factors[n] * SCH.DEFAULT_FACTOR_WEIGHTS[n]
                       for n in SCH.FACTOR_ORDER)
        self.assertAlmostEqual(undamped * SCH.DUPLICATE_DAMPING, score.total,
                               places=6)

    def test_a_repeat_of_a_reviewed_candidate_id_is_flagged(self):
        """The same pool scheduled a second round is the duplicate case that matters."""
        self.save_coverage([self.coverage_record("C1", sinks=[SINK_ID])])
        score = SCH.score_candidate(self.candidate("C1", RUNNER_SINK), self.ctx)
        self.assertEqual("C1", score.duplicate_of)

    def test_damping_lowers_the_total_against_an_unreviewed_context(self):
        """A reviewed region costs the candidate both novelty and damping."""
        candidate = self.candidate("C1", RUNNER_SINK, surface="command exec")
        before = SCH.score_candidate(candidate, self.ctx)
        self.assertEqual("", before.duplicate_of)
        self.save_coverage([self.coverage_record("C1", sinks=[SINK_ID],
                                                 files=["src/com/foo/Runner.java"])])
        after = SCH.score_candidate(candidate, self.ctx)
        self.assertEqual("C1", after.duplicate_of)
        self.assertLess(after.total, before.total)
        self.assertLessEqual(after.factors["coverage_novelty"],
                             before.factors["coverage_novelty"])

    def test_unreviewed_candidate_is_not_damped_at_all(self):
        self.save_coverage([self.coverage_record("C-other")])
        score = SCH.score_candidate(self.candidate("C1", RUNNER_SINK), self.ctx)
        self.assertEqual("", score.duplicate_of)
        self.assertNotIn("duplicate", score.evidence)

    def test_an_excluded_mechanism_also_damps_a_repeat(self):
        self.save_coverage([self.coverage_record(
            "C-excluded", status="excluded", sinks=[SINK_ID])])
        score = SCH.score_candidate(self.candidate("C1", RUNNER_SINK), self.ctx)
        self.assertEqual("C-excluded", score.duplicate_of)

    def test_a_different_region_is_not_a_duplicate(self):
        self.save_coverage([self.coverage_record(
            "C-other", sinks=["sink:jndi:src/com/foo/Other.java:9"])])
        score = SCH.score_candidate(self.candidate("C1", RUNNER_SINK), self.ctx)
        self.assertEqual("", score.duplicate_of)

    def test_pool_duplicate_resolves_to_the_lower_id_deterministically(self):
        pool = [self.candidate("C-A", RUNNER_SINK),
                self.candidate("C-B", RUNNER_SINK)]
        scores = {s.candidate_id: s for s in SCH.score_candidates(pool, self.ctx)}
        self.assertEqual("", scores["C-A"].duplicate_of)
        self.assertEqual("C-A", scores["C-B"].duplicate_of)
        self.assertLess(scores["C-B"].total, scores["C-A"].total)

    def test_pool_duplicate_verdict_does_not_depend_on_input_order(self):
        forward = [self.candidate("C-A", RUNNER_SINK),
                   self.candidate("C-B", RUNNER_SINK)]
        reverse = list(reversed(forward))
        first = {s.candidate_id: s.duplicate_of
                 for s in SCH.score_candidates(forward, self.ctx)}
        second = {s.candidate_id: s.duplicate_of
                  for s in SCH.score_candidates(reverse, self.ctx)}
        self.assertEqual(first, second)

    def test_candidates_at_different_lines_are_not_pool_duplicates(self):
        pool = [self.candidate("C-A", UPDATE_USER),
                self.candidate("C-B", ADMIN_UPDATE)]
        for score in SCH.score_candidates(pool, self.ctx):
            self.assertEqual("", score.duplicate_of)


# ---------------------------------------------------------------------------
# 3. stratified selection (spec §13.3)
# ---------------------------------------------------------------------------

def score_of(candidate_id, category, total):
    return SCH.CandidateScore(candidate_id=candidate_id, category=category,
                              total=total, band=SCH._band(total, 100))


class StratifiedSelectionTests(unittest.TestCase):

    def pool(self):
        return [
            score_of("A1", "authz", 90.0), score_of("A2", "authz", 80.0),
            score_of("P1", "parser", 70.0), score_of("F1", "file", 60.0),
            score_of("S1", "ssrf", 50.0), score_of("E1", "exec", 40.0),
            score_of("X1", "crypto", 30.0), score_of("X2", "crypto", 20.0),
        ]

    def test_quota_fills_the_declared_categories_first(self):
        selected, _, requested, filled, _ = SCH.stratified_select(
            self.pool(), 6, {"authz": 2, "parser": 1, "file": 1, "residual": 1})
        self.assertEqual(2, filled["authz"])
        self.assertEqual(1, filled["parser"])
        self.assertEqual(1, filled["file"])
        self.assertEqual({"authz": 2, "parser": 1, "file": 1, "residual": 1},
                         requested)

    def test_unfillable_quota_is_relocated_and_reported(self):
        """Spec §13.3: a category with no candidate moves its slot, and says so."""
        selected, _, _, filled, relocated = SCH.stratified_select(
            self.pool(), 5, {"authz": 2, "dos": 2, "residual": 1})
        self.assertEqual(0, filled["dos"])
        self.assertEqual(2, relocated["dos"])
        self.assertEqual(5, len(selected), "relocation must not shrink the round")

    def test_selection_is_a_partition_of_the_pool(self):
        pool = self.pool()
        selected, deferred, _, _, _ = SCH.stratified_select(pool, 4)
        ids = [s.candidate_id for s in selected] + \
              [s.candidate_id for s in deferred]
        self.assertEqual(sorted(s.candidate_id for s in pool), sorted(ids))

    def test_more_slots_than_candidates_selects_everything(self):
        pool = self.pool()
        selected, deferred, _, _, _ = SCH.stratified_select(pool, 50)
        self.assertEqual(len(pool), len(selected))
        self.assertEqual([], deferred)

    def test_zero_slots_selects_nothing_and_loses_nothing(self):
        pool = self.pool()
        selected, deferred, _, _, _ = SCH.stratified_select(pool, 0)
        self.assertEqual([], selected)
        self.assertEqual(len(pool), len(deferred))

    def test_selection_is_ordered_by_score(self):
        selected, _, _, _, _ = SCH.stratified_select(self.pool(), 6)
        totals = [s.total for s in selected]
        self.assertEqual(sorted(totals, reverse=True), totals)

    def test_deferred_keeps_its_score_and_ordering(self):
        _, deferred, _, _, _ = SCH.stratified_select(self.pool(), 2)
        totals = [s.total for s in deferred]
        self.assertEqual(sorted(totals, reverse=True), totals)
        self.assertTrue(all(s.total > 0 for s in deferred))

    def test_selection_is_deterministic(self):
        first = [s.candidate_id for s in SCH.stratified_select(self.pool(), 5)[0]]
        second = [s.candidate_id for s in SCH.stratified_select(self.pool(), 5)[0]]
        self.assertEqual(first, second)

    def test_an_unknown_category_does_not_break_the_quota(self):
        pool = self.pool() + [score_of("Z1", "other", 95.0)]
        selected, _, _, _, relocated = SCH.stratified_select(
            pool, 3, {"authz": 1, "crypto": 1, "residual": 1})
        self.assertEqual(3, len(selected))
        self.assertEqual(1, relocated["residual"])

    def test_pinned_candidates_are_selected_over_higher_scoring_ones(self):
        """Runtime evidence outranks a static score -- see the pin rationale."""
        pool = [score_of("A1", "authz", 99.0), score_of("A2", "authz", 98.0),
                score_of("F1", "config", 1.0)]
        selected, _, _, _, _ = SCH.stratified_select(pool, 1, {}, pinned=["F1"])
        self.assertEqual(["F1"], [s.candidate_id for s in selected])

    def test_pinned_candidates_count_against_the_slot_budget(self):
        pool = self.pool()
        selected, deferred, _, _, _ = SCH.stratified_select(
            pool, 3, {}, pinned=["X2", "X1"])
        self.assertEqual(3, len(selected))
        self.assertEqual(sorted(s.candidate_id for s in pool),
                         sorted([s.candidate_id for s in selected]
                                + [s.candidate_id for s in deferred]))
        self.assertTrue({"X1", "X2"}.issubset({s.candidate_id for s in selected}))

    def test_pinning_more_than_the_budget_truncates_rather_than_overfills(self):
        pool = self.pool()
        selected, _, _, _, _ = SCH.stratified_select(
            pool, 2, {}, pinned=["X2", "X1", "A1"])
        self.assertEqual(2, len(selected))

    def test_pinned_ids_not_in_the_pool_are_ignored(self):
        selected, _, _, _, _ = SCH.stratified_select(self.pool(), 1, {},
                                                     pinned=["nope"])
        self.assertEqual(1, len(selected))

    def test_pinning_does_not_change_the_rest_of_the_ordering(self):
        pool = self.pool()
        plain = [s.candidate_id for s in SCH.stratified_select(pool, 3)[0]]
        pinned = [s.candidate_id
                  for s in SCH.stratified_select(pool, 3, pinned=["X2"])[0]]
        self.assertEqual(3, len(plain))
        self.assertEqual(3, len(pinned))
        self.assertIn("X2", pinned)


# ---------------------------------------------------------------------------
# 4. residual sweep + plan persistence (spec §14)
# ---------------------------------------------------------------------------

class ResidualTests(ScheduleFixture):

    def plan(self, candidates, slots=3, refresh=True):
        return SCH.build_schedule(self.root, "fixture", candidates, slots=slots,
                                  round_no=1, refresh=refresh)

    def test_refreshed_residual_reports_the_uncovered_gaps(self):
        plan = self.plan([self.candidate("C1", RUNNER_SINK)], refresh=True)
        self.assertTrue(plan.residual["measured"])
        self.assertIsInstance(plan.residual["high_risk_uncovered"], int)
        self.assertIn("regions_by_kind", plan.residual)

    def test_unrefreshed_residual_is_marked_unmeasured_not_zero(self):
        """An absent measurement must not read as "clean"."""
        plan = self.plan([self.candidate("C1", RUNNER_SINK)], refresh=False)
        self.assertFalse(plan.residual["measured"])
        self.assertIsNone(plan.residual["high_risk_uncovered"])
        self.assertIn("未测量", SCH.render_schedule_text(plan))

    def test_schedule_is_persisted_per_round_and_as_latest(self):
        plan = self.plan([self.candidate("C1", RUNNER_SINK),
                          self.candidate("C2", UPDATE_USER)], slots=2,
                         refresh=False)
        round_file = SCH.load_schedule(self.store, 1)
        latest = SCH.load_schedule(self.store)
        self.assertEqual(plan.selected_ids(), round_file.get("selected_ids"))
        self.assertEqual(round_file, latest)

    def test_persisted_plan_carries_provenance(self):
        self.plan([self.candidate("C1", RUNNER_SINK)], refresh=False)
        payload = SCH.load_schedule(self.store)
        self.assertEqual("scheduler", payload.get("producer"))
        self.assertEqual("heuristic", payload.get("confidence"))
        self.assertEqual("static-inferred", payload.get("evidence_type"))
        self.assertEqual(SCH.DEFAULT_FACTOR_WEIGHTS, payload.get("weights"))

    def test_missing_schedule_reads_back_empty_rather_than_raising(self):
        self.assertEqual({}, SCH.load_schedule(self.store, 99))

    def test_residual_sweep_is_usable_on_its_own(self):
        info = SCH.residual_sweep(self.store, self.root, "fixture", 1)
        self.assertIn("metrics", info)
        self.assertIn("stop_condition_met", info)
        self.assertIn("regions_by_kind", info)


# ---------------------------------------------------------------------------
# 5. carry-over and ordering never lose a candidate
# ---------------------------------------------------------------------------

class CarryoverTests(ScheduleFixture):

    def plan_for(self, candidates, slots):
        return SCH.build_schedule(self.root, "fixture", candidates, slots=slots,
                                  round_no=1, refresh=False)

    def test_deferred_candidates_keep_a_reason_for_the_next_round(self):
        candidates = [self.candidate("C%d" % n, RUNNER_SINK,
                                     surface="exec %d" % n) for n in range(5)]
        plan = self.plan_for(candidates, slots=2)
        carried = SCH.deferred_carryover(plan, candidates)
        self.assertEqual(len(plan.deferred), len(carried))
        for candidate in carried:
            self.assertTrue(candidate["schedule"]["deferred"])
            self.assertIn("not selected", candidate["schedule"]["reason"])

    def test_selected_candidates_record_their_factors(self):
        candidates = [self.candidate("C1", RUNNER_SINK)]
        plan = self.plan_for(candidates, slots=1)
        SCH.deferred_carryover(plan, candidates)
        schedule = candidates[0]["schedule"]
        self.assertFalse(schedule["deferred"])
        self.assertEqual(set(SCH.FACTOR_ORDER), set(schedule["factors"]))
        self.assertEqual(set(SCH.FACTOR_ORDER), set(schedule["reasons"]))

    def test_ordering_is_a_permutation_with_the_scheduled_first(self):
        candidates = [self.candidate("C%d" % n, UPDATE_USER,
                                     surface="authz %d" % n) for n in range(4)]
        plan = self.plan_for(candidates, slots=1)
        ordered = SCH.apply_schedule_order(plan, candidates)
        self.assertEqual(sorted(c["candidate_id"] for c in candidates),
                         sorted(c["candidate_id"] for c in ordered))
        self.assertEqual(plan.selected_ids(), [ordered[0]["candidate_id"]])

    def test_ordering_survives_candidates_the_scheduler_never_saw(self):
        candidates = [self.candidate("C%d" % n, RUNNER_SINK) for n in range(3)]
        plan = self.plan_for(candidates, slots=1)
        stray = self.candidate("C-stray", RUNNER_SINK)
        ordered = SCH.apply_schedule_order(plan, candidates + [stray])
        self.assertEqual(4, len(ordered))
        self.assertIn("C-stray", [c["candidate_id"] for c in ordered])


# ---------------------------------------------------------------------------
# 6. the prompt block (spec §15)
# ---------------------------------------------------------------------------

SPEC_SECTIONS = [
    "Project Coverage Summary",
    "Coverage Gaps",
    "High-risk Unreviewed Regions",
    "Selected Entries",
    "Selected Sinks",
    "Security Controls",
    "Candidate-relevant Flows",
    "Prior Candidates",
    "Rejected Candidates",
    "Coverage Novelty Requirement",
]


class PromptBlockTests(ScheduleFixture):

    def headings(self, block):
        return [line for line in block.splitlines() if line.startswith("## ")]

    def test_block_emits_every_spec_section_in_spec_order(self):
        block = SCH.prompt_coverage_block(self.ctx)
        headings = self.headings(block)
        sequence = [name for heading in headings for name in SPEC_SECTIONS
                    if name in heading]
        self.assertEqual(SPEC_SECTIONS, sequence)

    def test_block_reports_the_coverage_numbers(self):
        block = SCH.prompt_coverage_block(self.ctx)
        self.assertIn("production_source_files", block)
        self.assertIn("sinks_reachability_analyzed", block)

    def test_block_reports_acceptance_targets(self):
        block = SCH.prompt_coverage_block(self.ctx)
        self.assertIn("sink_coverage", block)
        self.assertIn("target >=", block)

    def test_selected_sections_come_from_the_plan_not_the_index(self):
        candidates = [self.candidate("C1", RUNNER_SINK)]
        plan = SCH.build_schedule(self.root, "fixture", candidates, slots=1,
                                  round_no=1, refresh=False)
        block = SCH.prompt_coverage_block(self.ctx, plan=plan)
        sink_section = block.split("## 已选 Sink")[1].split("##")[0]
        self.assertIn(SINK_ID, sink_section)
        self.assertNotIn("no round plan", sink_section)

    def test_without_a_plan_the_selection_sections_say_they_are_a_snapshot(self):
        block = SCH.prompt_coverage_block(self.ctx)
        self.assertIn("no round plan", block)

    def test_plan_limits_selection_flows_to_the_selected_candidates(self):
        candidates = [self.candidate("C1", UPDATE_USER)]
        plan = SCH.build_schedule(self.root, "fixture", candidates, slots=1,
                                  round_no=1, refresh=False)
        block = SCH.prompt_coverage_block(self.ctx, plan=plan, limit_flows=10)
        flow_section = block.split("## 候选相关数据流")[1].split("##")[0]
        self.assertEqual(1, flow_section.count("flow-"))

    def test_prior_and_rejected_candidates_are_separated(self):
        self.save_coverage([
            self.coverage_record("C-confirmed"),
            self.coverage_record("C-rejected", status="excluded"),
        ])
        block = SCH.prompt_coverage_block(self.ctx)
        prior = block.split("## 已审候选")[1].split("##")[0]
        rejected = block.split("## 已否决候选")[1].split("##")[0]
        self.assertIn("C-confirmed", prior)
        self.assertNotIn("C-rejected", prior)
        self.assertIn("C-rejected", rejected)
        self.assertNotIn("C-confirmed", rejected)

    def test_the_novelty_requirement_is_stated_verbatim(self):
        block = SCH.prompt_coverage_block(self.ctx)
        self.assertIn("优先生成来自未覆盖区域的候选", block)
        self.assertIn("禁止重复已排除的机制", block)


# ---------------------------------------------------------------------------
# 7. category buckets
# ---------------------------------------------------------------------------

class CategoryTests(unittest.TestCase):

    def test_explicit_category_wins(self):
        self.assertEqual("ssrf", SCH.candidate_category({"category": "ssrf"}))

    def test_vuln_class_is_accepted_as_a_category(self):
        self.assertEqual("authz", SCH.candidate_category({"vuln_class": "authz"}))

    def test_text_is_classified_when_no_category_is_declared(self):
        candidate = {"surface": "missing permission check on the owner"}
        self.assertEqual("authz", SCH.candidate_category(candidate))

    def test_chain_components_take_part_in_classification(self):
        candidate = {"surface": "sink", "chain_components": ["deserialization"]}
        self.assertEqual("exec", SCH.candidate_category(candidate))

    def test_unclassifiable_candidates_fall_back_rather_than_raise(self):
        self.assertEqual(SCH.CATEGORY_FALLBACK,
                         SCH.candidate_category({"surface": "something else"}))

    def test_classification_is_deterministic(self):
        candidate = {"surface": "file upload path traversal"}
        self.assertEqual(SCH.candidate_category(candidate),
                         SCH.candidate_category(candidate))


# ---------------------------------------------------------------------------
# 8. context wiring
# ---------------------------------------------------------------------------

class ContextTests(ScheduleFixture):

    def test_context_loads_every_index_the_scheduler_reads(self):
        self.assertTrue(self.ctx.entries)
        self.assertTrue(self.ctx.sinks)
        self.assertTrue(self.ctx.controls)
        self.assertTrue(self.ctx.symbols)
        self.assertTrue(self.ctx.sources)
        self.assertTrue(self.ctx.flows)

    def test_lazy_indexes_agree_with_the_flat_collections(self):
        self.assertEqual(
            sum(len(v) for v in self.ctx.flows_by_sink().values()),
            len(self.ctx.flows))
        self.assertEqual(
            sum(len(v) for v in self.ctx.sinks_by_symbol().values()),
            len([s for s in self.ctx.sinks.values() if s.get("symbol_id")]))

    def test_sinks_by_file_only_returns_sinks_of_that_file(self):
        for file, sinks in self.ctx.sinks_by_file().items():
            self.assertTrue(all(str(s.get("file")) == file for s in sinks))

    def test_reviewed_surfaces_ignores_open_and_candidate_records(self):
        self.save_coverage([
            self.coverage_record("C-open", status="candidate", sinks=["s1"]),
            self.coverage_record("C-done", sinks=["s2"]),
        ])
        reviewed = self.ctx.reviewed_surfaces()
        self.assertNotIn("s1", reviewed["sinks"])
        self.assertIn("s2", reviewed["sinks"])

    def test_default_quota_matches_the_default_slot_count(self):
        self.assertEqual(SCH.DEFAULT_SLOTS, sum(SCH.DEFAULT_QUOTA.values()))

    def test_default_weights_are_the_documented_seven_factors(self):
        self.assertEqual(set(SCH.FACTOR_ORDER), set(SCH.DEFAULT_FACTOR_WEIGHTS))
        self.assertEqual(100, sum(SCH.DEFAULT_FACTOR_WEIGHTS.values()))


class IntegrationTests(ScheduleFixture):
    """The seam the pipeline actually calls: ``round_selection``."""

    def test_selection_is_capped_to_the_slot_budget(self):
        pool = [self.candidate("C%d" % n, RUNNER_SINK, surface="exec %d" % n)
                for n in range(6)]
        selected, plan, note = SCH.round_selection(self.root, "fixture", pool, 3,
                                                   refresh=False)
        self.assertEqual(3, len(selected))
        self.assertIsNotNone(plan)
        self.assertEqual("", note)
        self.assertEqual(3, len(plan.deferred))

    def test_selection_returns_candidates_not_scores(self):
        pool = [self.candidate("C1", RUNNER_SINK)]
        selected, _, _ = SCH.round_selection(self.root, "fixture", pool, 1,
                                             refresh=False)
        self.assertEqual(pool, selected)

    def test_selected_candidates_follow_the_plan_order(self):
        pool = [self.candidate("C-a", UPDATE_USER, surface="authz one"),
                self.candidate("C-b", RUNNER_SINK, surface="command exec")]
        plan = SCH.build_schedule(self.root, "fixture", pool, slots=2,
                                  round_no=1, refresh=False)
        ordered = SCH.selected_candidates(plan, pool)
        self.assertEqual(plan.selected_ids(),
                         [c["candidate_id"] for c in ordered])

    def test_pinned_candidates_survive_a_tight_budget(self):
        pool = [self.candidate("C-exec", RUNNER_SINK, surface="command exec"),
                self.candidate("C-fuzz", "src/com/foo/Service.java:1",
                               surface="unknown", fuzz_spec={"x": 1})]
        selected, plan, _ = SCH.round_selection(
            self.root, "fixture", pool, 1, refresh=False, pinned=["C-fuzz"])
        self.assertEqual(["C-fuzz"], [c["candidate_id"] for c in selected])
        self.assertEqual(["C-fuzz"], plan.pinned)

    def test_empty_pool_returns_a_reason_not_a_crash(self):
        selected, plan, note = SCH.round_selection(self.root, "fixture", [], 3)
        self.assertEqual([], selected)
        self.assertIsNone(plan)
        self.assertIn("empty", note)

    def test_round_selection_is_deterministic(self):
        pool = [self.candidate("C%d" % n, RUNNER_SINK, surface="exec %d" % n)
                for n in range(5)]
        first, _, _ = SCH.round_selection(self.root, "fixture", pool, 3,
                                          refresh=False)
        second, _, _ = SCH.round_selection(self.root, "fixture", pool, 3,
                                           refresh=False)
        self.assertEqual([c["candidate_id"] for c in first],
                         [c["candidate_id"] for c in second])

    def test_schedule_is_written_where_the_cli_can_read_it(self):
        pool = [self.candidate("C1", RUNNER_SINK)]
        SCH.round_selection(self.root, "fixture", pool, 1, round_no=2,
                            refresh=False)
        self.assertEqual(["C1"], SCH.load_schedule(self.store, 2)["selected_ids"])
        self.assertEqual(SCH.load_schedule(self.store, 2),
                         SCH.load_schedule(self.store))


if __name__ == "__main__":
    unittest.main()
