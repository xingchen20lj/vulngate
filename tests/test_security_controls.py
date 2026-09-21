"""Security control map (spec §11).

Each test below guards a way this analysis can go wrong quietly:

1. **Any-of requirements must not be flattened.**  ``command-exec`` is controlled
   by a validator *or* a sanitizer *or* an allowlist.  The first draft compared
   flattened category sets, so a handler that called ``Validator.validate`` was
   reported as still missing ``sanitization`` and ``allowlist`` -- i.e. every
   correctly guarded path looked only partially guarded.
2. **Absence must never score as presence.**  A path with no authorization
   control is ``uncontrolled``, and the candidate it produces is named
   ``possible-`` with a precondition -- never a claim that the path is open.
3. **A known sink category must always owe something.**  Sink categories that
   are not in the requirement matrix fall back to a generic group and are listed
   in the summary.  Without that, a catalog addition would silently produce
   ``not-applicable``: no candidate, no gap, nothing to notice.
4. **The map is an enrichment, not a second set of gaps.**  An unguarded flow is
   already an `unreviewed-flow` region; the verdict lands in its ``detail`` so
   ``high_risk_uncovered`` cannot be inflated by double counting.

Fixtures run the real inventory (source scan -> symbols -> call graph -> flows),
so the map is exercised against the same records production sees.
"""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from agent.analysis import controls as CTL  # noqa: E402
from agent.analysis import coverage as COV  # noqa: E402
from agent.analysis import inventory as INV  # noqa: E402
from agent.analysis import scheduler as SCH  # noqa: E402


# --- fixture ---------------------------------------------------------------
#
# UserController.updateUser  : authorization + validation  -> guarded
# UserController.adminShell  : nothing                     -> uncontrolled
# Tool.main                  : cli entry, nothing          -> validation only

USER_CONTROLLER = '''package com.foo;

public class UserController {
    private final UserService service = new UserService();

    @PostMapping("/api/user/update")
    public String updateUser(String id, String body) {
        if (!service.hasPermission("user")) {
            throw new IllegalStateException("forbidden");
        }
        Validator.validate(body);
        return service.update(id, body);
    }

    @PostMapping("/api/admin/shell")
    public String adminShell(String cmd) {
        return service.run(cmd);
    }
}
'''

USER_SERVICE = '''package com.foo;

public class UserService {
    private final UserRepository repository = new UserRepository();

    public String update(String id, String body) {
        return repository.save(body);
    }

    public String run(String cmd) {
        return Runner.exec(cmd);
    }

    public boolean hasPermission(String role) {
        return "admin".equals(role);
    }
}
'''

USER_REPOSITORY = '''package com.foo;

public class UserRepository {
    public String save(String body) {
        jdbcTemplate.update(body);
        return body;
    }
}
'''

RUNNER = '''package com.foo;

public class Runner {
    public static String exec(String cmd) {
        return Runtime.getRuntime().exec(cmd).toString();
    }
}
'''

TOOL = '''package com.foo;

public class Tool {
    public static void main(String[] args) {
        Runtime.getRuntime().exec(args[0]);
    }
}
'''

FILES = {
    "src/com/foo/UserController.java": USER_CONTROLLER,
    "src/com/foo/UserService.java": USER_SERVICE,
    "src/com/foo/UserRepository.java": USER_REPOSITORY,
    "src/com/foo/Runner.java": RUNNER,
    "src/com/foo/Tool.java": TOOL,
}

UPDATE_USER = "java:com.foo.UserController#updateUser"
ADMIN_SHELL = "java:com.foo.UserController#adminShell"
CLI_MAIN = "java:com.foo.Tool#main"


class ControlFixture(unittest.TestCase):
    """Real tree -> real inventory -> persisted store -> real control map."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vulngate-controls-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))
        for rel, text in FILES.items():
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        self.result = INV.build_inventory(self.root, source_dirs=["src"],
                                          target="fixture")
        self.store = INV.CoverageStore(self.root, "fixture")
        INV.persist_inventory(self.store, self.result)
        self.cmap = CTL.build_control_map(self.result.entries, self.result.sinks,
                                         self.result.flows, self.result.controls)

    # --- helpers -----------------------------------------------------------

    def line_of(self, rel: str, needle: str) -> int:
        for number, text in enumerate(FILES[rel].splitlines(), 1):
            if needle in text:
                return number
        raise AssertionError("fixture line not found: %r" % needle)

    def entry_for(self, symbol_id: str) -> dict:
        for entry in self.result.entries:
            if entry.symbol_id == symbol_id:
                return entry.as_dict()
        raise AssertionError("no entry for %s (have %s)"
                             % (symbol_id, [e.symbol_id for e in self.result.entries]))

    def entry_of(self, symbol_id: str):
        for flow in self.cmap.entries:
            if flow.entry_id in {
                    str(e.entry_id) for e in self.result.entries
                    if e.symbol_id == symbol_id}:
                return flow
        raise AssertionError("no flow for %s (have %s)"
                             % (symbol_id, [(f.entry_id, f.verdict)
                                            for f in self.cmap.entries]))

    def flow_of(self, symbol_id: str) -> CTL.ControlMapEntry:
        entry_ids = {str(e.entry_id) for e in self.result.entries
                     if e.symbol_id == symbol_id}
        for mapped in self.cmap.entries:
            if mapped.entry_id in entry_ids:
                return mapped
        raise AssertionError("no flow for %s" % symbol_id)

    def candidates(self, **kwargs):
        return CTL.control_candidates(self.cmap, **kwargs)

    def by_kind(self, kind):
        return [c for c in self.candidates() if c["control_kind"] == kind]


# ---------------------------------------------------------------------------
# 1. verdicts
# ---------------------------------------------------------------------------

class VerdictTests(ControlFixture):

    def test_the_fixture_actually_has_flows_to_judge(self):
        self.assertGreaterEqual(len(self.cmap.entries), 3)

    def test_a_path_with_every_requirement_group_met_is_guarded(self):
        self.assertEqual(CTL.VERDICT_GUARDED,
                         self.flow_of(UPDATE_USER).verdict)

    def test_a_path_with_no_requirement_group_met_is_uncontrolled(self):
        self.assertEqual(CTL.VERDICT_UNCONTROLLED,
                         self.flow_of(ADMIN_SHELL).verdict)

    def test_a_path_meeting_one_group_and_not_another_is_partial(self):
        flow = self.flow_of(ADMIN_SHELL)
        self.assertTrue(flow.required_groups)
        self.assertEqual([], flow.satisfied_groups)
        self.assertEqual(flow.required_groups, flow.missing_groups)

    def test_an_any_of_group_is_satisfied_by_a_single_member(self):
        """The regression this module was rewritten for."""
        flow = self.flow_of(UPDATE_USER)
        validation_group = [g for g in flow.required_groups
                            if "validation" in g]
        self.assertEqual(1, len(validation_group))
        self.assertIn("validation", flow.present)
        # ``sanitization`` / ``allowlist`` are alternatives, not co-requirements.
        self.assertNotIn("sanitization", flow.missing)
        self.assertNotIn("allowlist", flow.missing)
        self.assertNotIn(validation_group[0], flow.missing_groups)

    def test_guarded_paths_have_no_missing_group(self):
        flow = self.flow_of(UPDATE_USER)
        self.assertEqual([], flow.missing_groups)
        self.assertEqual([], flow.missing)

    def test_a_cli_entry_owes_no_authorization_control(self):
        flow = self.flow_of(CLI_MAIN)
        self.assertEqual("cli", flow.entry_kind)
        self.assertEqual([], flow.missing_authz())
        self.assertTrue(flow.missing_validation())

    def test_the_authorization_group_is_required_for_http_entries(self):
        flow = self.flow_of(ADMIN_SHELL)
        self.assertEqual(["authentication", "authorization"],
                         sorted(flow.missing_authz()))

    def test_control_ids_back_the_present_categories(self):
        flow = self.flow_of(UPDATE_USER)
        self.assertTrue(flow.control_ids)
        known = {c.control_id for c in self.result.controls}
        self.assertTrue(set(flow.control_ids) <= known)

    def test_absent_sink_evidence_degrades_to_medium_severity(self):
        mapped = CTL.build_control_map(
            entries=[{"entry_id": "e1", "kind": "http"}],
            sinks=[], flows=[{"flow_id": "f1", "entry_id": "e1",
                              "sink_id": "missing", "path": []}],
            controls=[])
        self.assertEqual("medium", mapped.entries[0].severity)

    def test_a_path_with_nothing_to_require_is_not_applicable(self):
        mapped = CTL.build_control_map(
            entries=[{"entry_id": "e1", "kind": "cli"}],
            sinks=[], flows=[{"flow_id": "f1", "entry_id": "e1",
                              "sink_id": "absent", "path": []}],
            controls=[])
        self.assertEqual(CTL.VERDICT_NOT_APPLICABLE, mapped.entries[0].verdict)
        self.assertEqual([], CTL.control_candidates(mapped))

    def test_summary_counts_verdicts_and_missing_groups(self):
        summary = self.cmap.summary()
        self.assertEqual(len(self.cmap.entries), summary["flows"])
        self.assertEqual(summary["guarded"] + summary["partial"]
                         + summary["uncontrolled"] + summary["not_applicable"],
                         summary["flows"])
        self.assertIn("authentication|authorization",
                      summary["missing_controls"])

    def test_the_map_is_deterministic(self):
        again = CTL.build_control_map(self.result.entries, self.result.sinks,
                                     self.result.flows, self.result.controls)
        self.assertEqual([e.as_dict() for e in self.cmap.entries],
                         [e.as_dict() for e in again.entries])

    def test_every_persisted_flow_is_judged(self):
        self.assertEqual(len(self.result.flows), len(self.cmap.entries))


# ---------------------------------------------------------------------------
# 2. the requirement matrix
# ---------------------------------------------------------------------------

class RequirementMatrixTests(unittest.TestCase):

    def test_any_of_groups_survive_the_lookup(self):
        groups = CTL.requirement_groups_for("command-exec", "http")
        self.assertIn(("allowlist", "sanitization", "validation"), groups)
        self.assertIn(("authentication", "authorization"), groups)

    def test_flattening_is_only_for_display(self):
        flat = CTL.requirements_for("command-exec", "http")
        groups = CTL.requirement_groups_for("command-exec", "http")
        self.assertEqual(5, len(flat))
        self.assertEqual(2, len(groups))

    def test_deserialization_owes_both_a_validation_and_a_bound(self):
        groups = CTL.requirement_groups_for("deserialization", "http")
        self.assertIn(("allowlist", "validation"), groups)
        self.assertIn(("depth-limit", "length-limit"), groups)

    def test_unknown_sink_categories_fall_back_rather_than_pass(self):
        self.assertEqual([CTL.DEFAULT_SINK_REQUIREMENT],
                         CTL.requirement_groups_for("some-future-category", "cli"))

    def test_unknown_sink_categories_are_reported(self):
        mapped = CTL.build_control_map(
            entries=[{"entry_id": "e1", "kind": "http"}],
            sinks=[{"sink_id": "s1", "category": "brand-new-sink"}],
            flows=[{"flow_id": "f1", "entry_id": "e1", "sink_id": "s1",
                    "path": []}], controls=[])
        self.assertEqual(["brand-new-sink"],
                         mapped.summary()["unclassified_sink_categories"])
        self.assertEqual(CTL.VERDICT_UNCONTROLLED, mapped.entries[0].verdict)

    def test_every_catalog_sink_category_has_an_explicit_requirement(self):
        """A new sink category must be classified, not absorbed by the fallback."""
        categories = {category for _pattern, category, _severity
                      in INV.SINK_PATTERNS}
        unclassified = sorted(c for c in categories
                              if c not in CTL.SINK_CONTROL_REQ)
        self.assertEqual([], unclassified)

    def test_spec_vocabulary_is_preserved_verbatim(self):
        for word in ("authentication", "authorization", "permission", "role",
                     "owner", "tenant", "ACL", "validation", "sanitization",
                     "normalization", "allowlist", "denylist", "length-limit",
                     "depth-limit", "rate-limit", "CSRF", "feature-flag",
                     "safe-mode", "path-check", "origin-check",
                     "signature-check"):
            self.assertIn(word, CTL.CONTROL_VOCABULARY,
                          "spec §11 vocabulary lost %r" % word)

    def test_aliases_normalise_onto_the_concrete_category(self):
        for alias, expected in (("permission", "authorization"),
                                ("role", "authorization"),
                                ("owner", "authorization"),
                                ("tenant", "authorization"),
                                ("ACL", "authorization"),
                                ("normalization", "sanitization"),
                                ("denylist", "allowlist"),
                                ("safe-mode", "feature-flag")):
            self.assertEqual(expected, CTL.normalize_category(alias))

    def test_families_are_classified(self):
        self.assertEqual("authz", CTL.family_of("owner"))
        self.assertEqual("authz", CTL.family_of("ACL"))
        self.assertEqual("validation", CTL.family_of("CSRF"))
        self.assertEqual("validation", CTL.family_of("denylist"))
        self.assertEqual("policy", CTL.family_of("rate-limit"))
        self.assertEqual("other", CTL.family_of("unheard-of"))

    def test_an_unrecognised_entry_kind_never_requires_authorization(self):
        self.assertEqual([], CTL.requirement_groups_for("", "library-api"))


# ---------------------------------------------------------------------------
# 3. candidates (spec §11 "应自动提升为高价值候选")
# ---------------------------------------------------------------------------

class CandidateTests(ControlFixture):

    def test_an_uncontrolled_authorization_path_becomes_possible_auth_bypass(self):
        candidates = [c for c in self.by_kind(CTL.KIND_AUTH_BYPASS)
                      if ADMIN_SHELL in str(c["path"])]
        self.assertEqual(1, len(candidates))
        self.assertIn("possible-auth-bypass", candidates[0]["surface"])
        self.assertEqual("authz", candidates[0]["category"])

    def test_a_guarded_path_produces_no_candidate(self):
        guarded_entries = {str(e.entry_id) for e in self.result.entries
                           if e.symbol_id == UPDATE_USER}
        self.assertEqual([], [c for c in self.candidates()
                              if c["entry_id"] in guarded_entries])

    def test_a_cli_path_never_becomes_an_auth_bypass(self):
        self.assertEqual([], [c for c in self.by_kind(CTL.KIND_AUTH_BYPASS)
                              if CLI_MAIN in str(c["path"])])

    def test_a_missing_validation_becomes_possible_control_bypass(self):
        candidates = self.by_kind(CTL.KIND_CONTROL_BYPASS)
        self.assertTrue(candidates)
        self.assertIn("possible-control-bypass", candidates[0]["surface"])
        self.assertEqual("", candidates[0]["category"])

    def test_the_scheduler_buckets_the_auth_bypass_under_authz(self):
        self.assertEqual("authz", SCH.candidate_category(self.by_kind(
            CTL.KIND_AUTH_BYPASS)[0]))

    def test_candidates_are_deterministic(self):
        first = self.candidates()
        second = CTL.control_candidates(
            CTL.build_control_map(self.result.entries, self.result.sinks,
                                  self.result.flows, self.result.controls))
        self.assertEqual([c["candidate_id"] for c in first],
                         [c["candidate_id"] for c in second])

    def test_candidate_ids_are_unique_and_namespaced(self):
        ids = [c["candidate_id"] for c in self.candidates()]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(i.startswith("ctl-") for i in ids))

    def test_candidates_carry_provenance(self):
        for candidate in self.candidates():
            self.assertEqual("controls", candidate["producer"])
            self.assertEqual("heuristic", candidate["confidence"])
            self.assertEqual("static-inferred", candidate["evidence_type"])
            self.assertEqual("control-map", candidate["source"])
            self.assertTrue(candidate["flow_id"])
            self.assertTrue(candidate["sink_id"])

    def test_code_locations_are_parseable_by_the_scheduler(self):
        for candidate in self.candidates():
            locations = SCH.candidate_locations(candidate)
            self.assertTrue(locations, candidate["candidate_id"])
            for file, line in locations:
                self.assertTrue(file.endswith(".java"), file)
                self.assertGreater(line, 0)

    def test_the_sink_location_is_the_first_code_location(self):
        candidate = [c for c in self.by_kind(CTL.KIND_AUTH_BYPASS)
                     if ADMIN_SHELL in str(c["path"])][0]
        sink_line = self.line_of("src/com/foo/Runner.java",
                                 "Runtime.getRuntime().exec")
        self.assertIn("src/com/foo/Runner.java:%d" % sink_line,
                      candidate["code_location"])

    def test_the_tier_is_not_claimed_as_zero(self):
        """Static absence cannot establish reachability under default config."""
        for candidate in self.candidates():
            self.assertEqual("single-feature",
                             candidate["precondition_tier_hint"])
            self.assertTrue(candidate["preconditions"])

    def test_the_poc_class_is_a_valid_java_identifier(self):
        for candidate in self.candidates():
            self.assertRegex(candidate["poc_class"], r"^[A-Za-z_]\w*$")

    def test_auth_cases_state_what_a_guarded_target_owes(self):
        cases = self.by_kind(CTL.KIND_AUTH_BYPASS)[0]["authz_cases"]
        self.assertTrue(cases)
        for case in cases:
            self.assertEqual("deny", case["expected_authz"])
            self.assertFalse(case["expected_object_mutated"])
            self.assertTrue(case["expected_http_codes"])

    def test_auth_cases_carry_no_secrets(self):
        forbidden = {"token", "cookie", "password", "secret", "authorization"}
        for candidate in self.by_kind(CTL.KIND_AUTH_BYPASS):
            for case in candidate["authz_cases"]:
                self.assertEqual(set(), set(case) & forbidden, case)

    def test_control_bypass_candidates_carry_no_authz_cases(self):
        for candidate in self.by_kind(CTL.KIND_CONTROL_BYPASS):
            self.assertEqual([], candidate["authz_cases"])

    def test_a_limit_is_a_prefix_of_the_unlimited_list(self):
        full = [c["candidate_id"] for c in self.candidates()]
        limited = [c["candidate_id"] for c in
                   CTL.control_candidates(self.cmap, limit_per_kind=1)]
        self.assertEqual(2, len(limited))
        self.assertTrue(set(limited) <= set(full))

    def test_every_candidate_names_the_requirement_it_failed(self):
        for candidate in self.candidates():
            self.assertTrue(candidate["missing_groups"])
            addressed = set(candidate["missing_controls"])
            every_missing = {g for group in candidate["missing_groups"]
                             for g in group}
            # ``missing_controls`` is the subset this candidate is *about*
            # (family-scoped); ``missing_groups`` is the whole unsatisfied set.
            self.assertTrue(addressed)
            self.assertTrue(addressed <= every_missing)
            if candidate["control_kind"] == CTL.KIND_AUTH_BYPASS:
                self.assertTrue(
                    all(CTL.family_of(c) == "authz" for c in addressed))
            else:
                self.assertTrue(
                    all(CTL.family_of(c) == "validation" for c in addressed))


# ---------------------------------------------------------------------------
# 4. persistence + pool hand-off
# ---------------------------------------------------------------------------

class PersistenceTests(ControlFixture):

    def test_the_map_round_trips(self):
        loaded = CTL.load_control_map(self.store)
        self.assertEqual([e.as_dict() for e in self.cmap.entries],
                         [e.as_dict() for e in loaded.entries])
        self.assertEqual(self.cmap.summary()["verdicts"],
                         loaded.summary()["verdicts"])

    def test_persisted_candidates_round_trip(self):
        candidates = self.candidates()
        CTL.write_control_map(self.store, self.cmap, candidates)
        self.assertEqual(candidates, CTL.load_control_candidates(self.store))

    def test_a_missing_index_loads_as_an_empty_map(self):
        empty = INV.CoverageStore(Path(tempfile.mkdtemp(prefix="vulngate-none-")),
                                  "nothing")
        self.addCleanup(lambda: shutil.rmtree(empty.workspace, ignore_errors=True))
        self.assertEqual([], CTL.load_control_map(empty).entries)
        self.assertEqual([], CTL.load_control_candidates(empty))

    def test_the_inventory_persists_the_map_and_its_candidates(self):
        index = INV.load_inventory(self.store)
        self.assertIn(CTL.CONTROL_MAP_INDEX, index)
        self.assertEqual(len(self.cmap.entries),
                         len(index[CTL.CONTROL_MAP_INDEX]["entries"]))
        self.assertEqual(len(self.candidates()),
                         len(index[CTL.CONTROL_CANDIDATE_INDEX]))

    def test_static_candidates_read_control_map_and_differential(self):
        from agent.analysis import differential as DIFF
        from agent.analysis import capability_graph as CAP
        from agent.analysis import semantic_guards as GUARD
        from agent.analysis import semantic_calls as CALLS
        from agent.analysis import semantic_paths as SEM
        static = CTL.static_candidates(self.store)
        sources = {c["source"] for c in static}
        self.assertIn("control-map", sources)
        self.assertTrue(sources <= {"control-map", "differential", "capability-graph",
                                    "semantic-paths", "semantic-guards",
                                    "semantic-calls"})
        self.assertEqual(len(self.candidates()) + len(
            DIFF.load_differential_candidates(self.store)) + len(
            CAP.load_capability_candidates(self.store)) + len(
            SEM.load_semantic_candidates(self.store)) + len(
            GUARD.load_semantic_guard_candidates(self.store)) + len(
            CALLS.load_semantic_call_candidates(self.store)), len(static))

    def test_merging_never_displaces_an_existing_id(self):
        existing = [{"candidate_id": "ctl-authz-0001", "surface": "kept"}]
        pool, added = CTL.merge_static_candidates(self.store, existing)
        self.assertNotIn("ctl-authz-0001", added)
        kept = [c for c in pool if c["candidate_id"] == "ctl-authz-0001"]
        self.assertEqual([existing[0]], kept)
        # Everything else from the store is added, ahead of the given pool.
        self.assertEqual(len(CTL.static_candidates(self.store)) - 1, len(added))
        self.assertEqual([c["candidate_id"] for c in pool
                          if c["candidate_id"] in added], added)
        self.assertEqual(pool[-1], existing[0])

    def test_merging_can_be_disabled(self):
        pool = [{"candidate_id": "X"}]
        merged, added = CTL.merge_static_candidates(self.store, pool,
                                                   enabled=False)
        self.assertEqual(pool, merged)
        self.assertEqual([], added)

    def test_a_second_merge_adds_nothing(self):
        pool, _ = CTL.merge_static_candidates(self.store, [])
        again, added = CTL.merge_static_candidates(self.store, pool)
        self.assertEqual([], added)
        self.assertEqual(len(pool), len(again))


# ---------------------------------------------------------------------------
# 5. residual integration (spec §14)
# ---------------------------------------------------------------------------

class ResidualTests(ControlFixture):

    def test_an_unguarded_flow_region_carries_the_verdict(self):
        regions = COV.build_uncovered_regions(INV.load_inventory(self.store))
        flow_regions = [r for r in regions if r["kind"] == "unreviewed-flow"]
        unguarded = [r for r in flow_regions
                     if r["detail"].get("control_verdict") == "uncontrolled"]
        self.assertTrue(unguarded)
        region = next(r for r in unguarded
                      if ADMIN_SHELL in str(r["detail"].get("path", [])))
        self.assertIn("authentication", region["detail"]["missing_controls"])
        self.assertTrue(region["detail"]["missing_groups"])

    def test_the_verdict_does_not_add_a_second_region_per_flow(self):
        """Counting a flow twice would inflate high_risk_uncovered."""
        regions = COV.build_uncovered_regions(INV.load_inventory(self.store))
        flow_regions = [r for r in regions if r["kind"] == "unreviewed-flow"]
        self.assertEqual(len(self.result.flows), len(flow_regions))

    def test_a_store_without_a_control_map_behaves_as_before(self):
        index = INV.load_inventory(self.store)
        index.pop(CTL.CONTROL_MAP_INDEX)
        regions = COV.build_uncovered_regions(index)
        self.assertTrue(regions)
        for region in regions:
            self.assertNotIn("control_verdict", region["detail"])

    def test_the_control_map_does_not_add_a_gap_kind_of_its_own(self):
        regions = COV.build_uncovered_regions(INV.load_inventory(self.store))
        self.assertNotIn("auth-bypass", {r["kind"] for r in regions})

    def test_control_gap_regions_still_count_security_critical_controls(self):
        regions = COV.build_uncovered_regions(INV.load_inventory(self.store))
        self.assertTrue([r for r in regions if r["kind"] == "control-gap"])


# ---------------------------------------------------------------------------
# 6. rendering
# ---------------------------------------------------------------------------

class RenderTests(ControlFixture):

    def test_the_report_states_its_limitations(self):
        for lang, needle in (("zh", "局限"), ("en", "Limitations")):
            text = CTL.render_control_map_text(self.cmap, lang, limit=3)
            self.assertIn(needle, text)
            for limitation in CTL.LIMITATIONS:
                self.assertIn(limitation[:40], text)

    def test_the_report_shows_the_verdict_counts(self):
        text = CTL.render_control_map_text(self.cmap, "zh", limit=3)
        summary = self.cmap.summary()
        self.assertIn(str(summary["flows"]), text)
        self.assertIn(str(summary["auth_bypass_paths"]), text)

    def test_candidates_are_printed_only_when_asked_for(self):
        without = CTL.render_control_map_text(self.cmap, "zh", limit=2)
        with_candidates = CTL.render_control_map_text(
            self.cmap, "zh", limit=2, candidates=self.candidates())
        self.assertNotIn("ctl-", without)
        self.assertIn("ctl-", with_candidates)


if __name__ == "__main__":
    unittest.main()
