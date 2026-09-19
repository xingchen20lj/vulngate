"""Sibling / differential analysis (spec §12, §19.5).

The tests guard the ways a differential can go wrong quietly:

1. **§19.5 is a hard requirement.**  ``getUser`` / ``updateUser`` /
   ``deleteUser`` with two ownership checks must produce ``possible-auth-bypass``.
2. **Two pairs is not a family.**  Spec §12's own example
   (``uploadAvatar`` validates, ``importArchive`` does not) is a *pair*, so the
   carrier floor has to allow one carrier at size two -- while still refusing
   "1 of 5" as noise.
3. **The closure, not the body.**  The missing call in ``deleteUser`` is to
   another function; a body-local scan would miss exactly the required case.
4. **Sink similarity needs reached sinks.**  A handler almost never owns the
   sink, so reading only its own line would leave the sink signature empty and
   quietly disable the "same sink" grouping.
5. **Inconsistency only.**  A family that uniformly lacks a control is *absence*
   (control-map's job, spec §11), not a differential -- otherwise this module
   would report every unauthenticated endpoint as a family finding.

Fixtures run the real inventory (source scan -> symbols -> call graph -> flows).
"""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from agent.analysis import controls as CTL        # noqa: E402
from agent.analysis import coverage as COV        # noqa: E402
from agent.analysis import differential as DIFF   # noqa: E402
from agent.analysis import inventory as INV       # noqa: E402


# --- fixture ---------------------------------------------------------------
#
# UserController    : getUser / updateUser carry checkOwner, deleteUser does not
#                     -> spec §19.5, 2-of-3 -> possible-auth-bypass (high)
# AccountController : readAccount reaches the control through a callee, writeAccount
#                     does not -> closure evidence, 1-of-2
# AssetController   : uploadAvatar validates, importArchive does not, same sinks
#                     -> spec §12 validation-differential (no shared name token)
# ItemController    : both carry the control -> consistent, no finding

USER_CONTROLLER = '''package com.foo;

public class UserController {
    private final OwnerService service = new OwnerService();

    @GetMapping("/api/user/{id}")
    public String getUser(String id) {
        service.checkOwner(id);
        return "user:" + id;
    }

    @PostMapping("/api/user/{id}")
    public String updateUser(String id, String body) {
        service.checkOwner(id);
        return "updated:" + id;
    }

    @DeleteMapping("/api/user/{id}")
    public String deleteUser(String id) {
        return "deleted:" + id;
    }
}
'''

ACCOUNT_CONTROLLER = '''package com.foo;

public class AccountController {
    private final OwnerService service = new OwnerService();

    @GetMapping("/api/account/{id}")
    public String readAccount(String id) {
        service.verifySubject(id);
        return "account:" + id;
    }

    @PostMapping("/api/account/{id}")
    public String writeAccount(String id, String body) {
        return "written:" + id;
    }
}
'''

ASSET_CONTROLLER = '''package com.foo;

public class AssetController {
    private final AssetService service = new AssetService();

    @PostMapping("/api/asset/avatar")
    public String uploadAvatar(String name, String body) {
        Validator.validate(name);
        return service.saveAsset(name, body);
    }

    @PostMapping("/api/asset/archive")
    public String importArchive(String name, String body) {
        return service.saveAsset(name, body);
    }
}
'''

ITEM_CONTROLLER = '''package com.foo;

public class ItemController {
    private final OwnerService service = new OwnerService();

    @GetMapping("/api/item/read")
    public String readItem(String id) {
        service.checkOwner(id);
        return "item:" + id;
    }

    @PostMapping("/api/item/write")
    public String writeItem(String id, String body) {
        service.checkOwner(id);
        return "item:" + id;
    }
}
'''

OWNER_SERVICE = '''package com.foo;

public class OwnerService {
    public void checkOwner(String id) {
        if (!id.equals(currentOwner())) {
            throw new IllegalStateException("forbidden");
        }
    }

    public void verifySubject(String id) {
        String ownerId = currentOwner();
        if (!ownerId.equals(id)) {
            throw new IllegalStateException("forbidden");
        }
    }

    public String currentOwner() {
        return "me";
    }
}
'''

ASSET_SERVICE = '''package com.foo;

public class AssetService {
    public String saveAsset(String name, String body) {
        Files.write(Paths.get(name), body.getBytes());
        return name;
    }
}
'''

FILES = {
    "src/com/foo/UserController.java": USER_CONTROLLER,
    "src/com/foo/AccountController.java": ACCOUNT_CONTROLLER,
    "src/com/foo/AssetController.java": ASSET_CONTROLLER,
    "src/com/foo/ItemController.java": ITEM_CONTROLLER,
    "src/com/foo/OwnerService.java": OWNER_SERVICE,
    "src/com/foo/AssetService.java": ASSET_SERVICE,
}

FIX_HISTORY = [{
    "commit": "abc123def4567890",
    "short_commit": "abc123d",
    "subject": "fix: enforce owner check on user endpoints",
    "affected_paths": ["src/com/foo/UserController.java"],
}]


class DifferentialFixture(unittest.TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vulngate-diff-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))
        for rel, text in FILES.items():
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        self.result = INV.build_inventory(self.root, source_dirs=["src"],
                                          target="fixture")
        self.store = INV.CoverageStore(self.root, "fixture")
        INV.persist_inventory(self.store, self.result)
        self.index = DIFF.build_differential(
            self.result.entries, self.result.symbols, self.result.controls,
            self.result.sinks, self.result.call_edges)

    # --- helpers -----------------------------------------------------------

    def group_for(self, name: str) -> DIFF.SiblingGroup:
        for group in self.index.groups:
            if any(m.name == name for m in group.members):
                return group
        raise AssertionError("no sibling group contains %s (groups: %s)"
                             % (name, [(g.group_id, [m.name for m in g.members])
                                       for g in self.index.groups]))

    def findings_for(self, name: str):
        group = self.group_for(name)
        return [f for f in self.index.findings if f.group_id == group.group_id]

    def member(self, name: str) -> DIFF.Member:
        for group in self.index.groups:
            for member in group.members:
                if member.name == name:
                    return member
        raise AssertionError("no member %s" % name)

    def names(self, evidence):
        return sorted(str(m.get("name")) for m in evidence)

    def candidates(self, **kwargs):
        return DIFF.differential_candidates(self.index.findings, **kwargs)

    def kinds(self):
        return {c["control_kind"] for c in self.candidates()}


# ---------------------------------------------------------------------------
# 1. spec §19.5 (hard requirement)
# ---------------------------------------------------------------------------

class AuthorizationDifferentialTests(DifferentialFixture):

    def test_the_19_5_fixture_produces_possible_auth_bypass(self):
        findings = self.findings_for("deleteUser")
        self.assertEqual(1, len(findings))
        self.assertEqual(CTL.KIND_AUTH_BYPASS, findings[0].kind)
        self.assertEqual("authorization", findings[0].category)
        self.assertEqual("authz", findings[0].family)

    def test_the_two_guarded_siblings_are_the_carriers(self):
        finding = self.findings_for("deleteUser")[0]
        self.assertEqual(["getUser", "updateUser"], self.names(finding.carriers))
        self.assertEqual(["deleteUser"], self.names(finding.missing))
        # Rounded for the persisted index (deterministic diffs), so compare to
        # the same precision rather than to the raw fraction.
        self.assertAlmostEqual(2 / 3, finding.agreement, places=4)

    def test_a_majority_inconsistency_in_a_family_of_three_is_high_risk(self):
        self.assertEqual("high", self.findings_for("deleteUser")[0].risk)

    def test_the_spec_12_name_and_the_spec_19_5_name_both_travel(self):
        finding = self.findings_for("deleteUser")[0]
        self.assertEqual(DIFF.DIFF_SECURITY_CONTROL, finding.differential)
        self.assertEqual(CTL.KIND_AUTH_BYPASS, finding.kind)

    def test_a_pair_disagreement_is_found_but_graded_medium(self):
        finding = self.findings_for("writeAccount")[0]
        self.assertEqual(CTL.KIND_AUTH_BYPASS, finding.kind)
        self.assertEqual("medium", finding.risk)
        self.assertEqual(1, len(finding.carriers))

    def test_a_consistent_family_produces_no_finding(self):
        self.assertEqual([], self.findings_for("readItem"))
        self.assertEqual([], self.findings_for("writeItem"))


# ---------------------------------------------------------------------------
# 2. grouping (spec §12 bases)
# ---------------------------------------------------------------------------

class GroupingTests(DifferentialFixture):

    def test_verb_prefixed_names_share_a_token(self):
        """deleteUser must be a sibling of updateUser, not an odd endpoint."""
        group = self.group_for("deleteUser")
        self.assertEqual(["deleteUser", "getUser", "updateUser"],
                         sorted(m.name for m in group.members))
        self.assertEqual(["name-token:user"], group.basis)

    def test_members_of_one_class_are_one_scope(self):
        self.assertEqual("UserController", self.group_for("deleteUser").scope)

    def test_a_shared_sink_signature_groups_members_without_a_shared_token(self):
        group = self.group_for("uploadAvatar")
        self.assertEqual(["importArchive", "uploadAvatar"],
                         sorted(m.name for m in group.members))
        self.assertTrue(any(b.startswith("sink-signature:")
                            for b in group.basis), group.basis)

    def test_reached_sinks_define_the_signature(self):
        """The handler does not own the sink; its callee does."""
        member = self.member("uploadAvatar")
        self.assertIn("file-mutation", member.sink_categories)

    def test_scope_separates_otherwise_identical_members(self):
        left = DIFF.Member(symbol_id="a", scope="ClassA", tokens=("user",))
        right = DIFF.Member(symbol_id="b", scope="ClassB", tokens=("user",))
        groups, _ = DIFF.group_siblings([left, right])
        self.assertEqual([], groups)

    def test_a_lone_member_is_not_a_family(self):
        single = DIFF.Member(symbol_id="a", scope="ClassA", tokens=("user",))
        groups, _ = DIFF.group_siblings([single])
        self.assertEqual([], groups)

    def test_an_operation_alone_is_not_a_family(self):
        """Fallback tokens still contain the verbs -- they must not group.

        ``runCheck`` / ``applyCheck`` share "check" and nothing else, so they
        *do* share a token and must still not become siblings.
        """
        left = DIFF.Member(symbol_id="a", scope="Cls", name="runCheck",
                           tokens=DIFF.name_tokens("runCheck"))
        right = DIFF.Member(symbol_id="b", scope="Cls", name="applyCheck",
                            tokens=DIFF.name_tokens("applyCheck"))
        self.assertTrue(set(left.tokens) & set(right.tokens), left.tokens)
        groups, _ = DIFF.group_siblings([left, right])
        self.assertEqual([], groups)

    def test_the_noun_survives_the_fallback(self):
        """Same operation, same object -> a family, unlike the verb-only pair."""
        left = DIFF.Member(symbol_id="a", scope="Cls", name="runItem",
                           tokens=DIFF.name_tokens("runItem"))
        right = DIFF.Member(symbol_id="b", scope="Cls", name="applyItem",
                            tokens=DIFF.name_tokens("applyItem"))
        groups, _ = DIFF.group_siblings([left, right])
        self.assertEqual(1, len(groups))

    def test_a_read_write_pair_is_a_family_by_its_noun(self):
        """``read``/``write`` are operations, ``item`` is what they act on."""
        group = self.group_for("readItem")
        self.assertEqual(["readItem", "writeItem"],
                         sorted(m.name for m in group.members))
        self.assertEqual(["name-token:item"], group.basis)

    def test_group_basis_is_reported_in_the_summary(self):
        summary = self.index.summary()
        self.assertEqual(self.index.group_notes["by_basis"],
                         summary["groups_by_basis"])
        self.assertGreaterEqual(summary["groups_by_basis"].get("name-token", 0), 2)
        self.assertEqual(1, summary["groups_by_basis"].get("sink-signature", 0))

    def test_groups_are_deterministic(self):
        again = DIFF.build_differential(
            self.result.entries, self.result.symbols, self.result.controls,
            self.result.sinks, self.result.call_edges)
        self.assertEqual([g.as_dict() for g in self.index.groups],
                         [g.as_dict() for g in again.groups])
        self.assertEqual([f.as_dict() for f in self.index.findings],
                         [f.as_dict() for f in again.findings])

    def test_only_entry_hosting_symbols_become_members(self):
        names = {m.name for g in self.index.groups for m in g.members}
        self.assertNotIn("checkOwner", names)   # no external entry
        self.assertNotIn("saveAsset", names)

    def test_an_unbound_entry_is_counted_rather_than_dropped(self):
        entries = [{"entry_id": "e9", "kind": "http", "symbol_id": "not-a-symbol"}]
        members, notes = DIFF.build_members(entries, [])
        self.assertEqual([], members)
        self.assertEqual(1, notes["entries_unbound"])
        self.assertEqual(["not-a-symbol"], notes["unbound_samples"])


# ---------------------------------------------------------------------------
# 3. name tokens
# ---------------------------------------------------------------------------

class NameTokenTests(unittest.TestCase):

    def test_verb_prefixes_are_stripped(self):
        self.assertEqual(("user",), DIFF.name_tokens("bulkUpdateUser"))
        self.assertEqual(("user",), DIFF.name_tokens("updateUser"))
        self.assertEqual(("user",), DIFF.name_tokens("get_user"))

    def test_plural_forms_collapse(self):
        self.assertEqual(("user",), DIFF.name_tokens("listUsers"))

    def test_camel_and_snake_case_agree(self):
        self.assertEqual(DIFF.name_tokens("uploadAvatar"),
                         DIFF.name_tokens("upload_avatar"))

    def test_all_stop_words_fall_back_to_the_verb(self):
        """A pure-CRUD pair still shares a signal instead of collapsing."""
        self.assertTrue(DIFF.name_tokens("getItem"))
        self.assertTrue(DIFF.name_tokens("listItems"))

    def test_an_empty_name_yields_no_tokens(self):
        self.assertEqual((), DIFF.name_tokens(""))


# ---------------------------------------------------------------------------
# 4. control profiles / closure
# ---------------------------------------------------------------------------

class ControlProfileTests(DifferentialFixture):

    def test_a_null_call_chain_misses_the_control(self):
        tokens = " -> ".join(sorted(self.member("deleteUser").symbol_id.split("#")))
        self.assertIn("deleteUser", tokens)
        self.assertEqual({}, self.member("deleteUser").control_via)

    def test_a_control_is_found_through_the_callee(self):
        member = self.member("readAccount")
        self.assertIn("authorization", member.controls)
        via = member.control_via["authorization"]
        self.assertTrue(any("OwnerService#verifySubject" in v for v in via), via)

    def test_the_call_site_control_is_found_without_the_closure(self):
        members, _ = DIFF.build_members(
            self.result.entries, self.result.symbols, self.result.controls,
            self.result.sinks, self.result.call_edges, closure_depth=0)
        by_name = {m.name: m for m in members}
        self.assertIn("authorization", by_name["getUser"].controls)
        self.assertNotIn("authorization", by_name["readAccount"].controls)

    def test_bounding_the_closure_removes_the_derived_finding(self):
        shallow = DIFF.build_differential(
            self.result.entries, self.result.symbols, self.result.controls,
            self.result.sinks, self.result.call_edges, closure_depth=0)
        kinds = {(f.group_id, f.kind) for f in shallow.findings}
        group = next(g for g in shallow.groups
                     if any(m.name == "readAccount" for m in g.members))
        self.assertNotIn((group.group_id, CTL.KIND_AUTH_BYPASS), kinds)

    def test_control_ids_are_recorded_as_evidence(self):
        member = self.member("getUser")
        self.assertTrue(member.controls["authorization"])
        known = {c.control_id for c in self.result.controls}
        self.assertTrue(set(member.controls["authorization"]) <= known)


# ---------------------------------------------------------------------------
# 5. diff thresholds
# ---------------------------------------------------------------------------

class DiffThresholdTests(DifferentialFixture):

    def test_a_single_carrier_of_a_family_of_three_is_not_enough(self):
        """"1 of 5" is a coin flip; the floor for size >= 3 is two carriers."""
        members = [DIFF.Member(symbol_id="m%d" % i, scope="S")
                   for i in range(3)]
        members[0].controls = {"authorization": ["c1"]}
        group = DIFF.SiblingGroup(group_id="g1", scope="S", members=members)
        self.assertEqual([], DIFF.diff_group(group))

    def test_two_carriers_of_three_are_enough(self):
        members = [DIFF.Member(symbol_id="m%d" % i, scope="S")
                   for i in range(3)]
        members[0].controls = {"authorization": ["c1"]}
        members[1].controls = {"authorization": ["c2"]}
        group = DIFF.SiblingGroup(group_id="g1", scope="S", members=members)
        findings = DIFF.diff_group(group)
        self.assertEqual(1, len(findings))
        self.assertEqual("high", findings[0].risk)

    def test_a_minority_of_carriers_is_below_the_agreement_threshold(self):
        members = [DIFF.Member(symbol_id="m%d" % i, scope="S")
                   for i in range(5)]
        members[0].controls = {"authorization": ["c1"]}
        members[1].controls = {"authorization": ["c2"]}
        group = DIFF.SiblingGroup(group_id="g1", scope="S", members=members)
        self.assertEqual([], DIFF.diff_group(group))

    def test_absence_without_inconsistency_is_not_a_differential(self):
        members = [DIFF.Member(symbol_id="m%d" % i, scope="S")
                   for i in range(3)]
        group = DIFF.SiblingGroup(group_id="g1", scope="S", members=members)
        self.assertEqual([], DIFF.diff_group(group))

    def test_a_pair_may_have_one_carrier(self):
        members = [DIFF.Member(symbol_id="a", scope="S"),
                   DIFF.Member(symbol_id="b", scope="S")]
        members[0].controls = {"validation": ["c1"]}
        group = DIFF.SiblingGroup(group_id="g1", scope="S", members=members)
        findings = DIFF.diff_group(group)
        self.assertEqual(1, len(findings))
        self.assertEqual("medium", findings[0].risk)

    def test_a_validation_gap_gets_the_validation_kind(self):
        finding = self.findings_for("importArchive")[0]
        self.assertEqual(DIFF.KIND_VALIDATION_DIFF, finding.kind)
        self.assertEqual(DIFF.KIND_VALIDATION_DIFF, finding.differential)
        self.assertEqual("validation", finding.family)

    def test_agreement_is_reported_not_hidden(self):
        finding = self.findings_for("deleteUser")[0]
        self.assertEqual(round(2 / 3, 4), finding.agreement)
        self.assertEqual(3, finding.as_dict()["size"])


# ---------------------------------------------------------------------------
# 6. patch sibling diff (spec §18 Phase 4)
# ---------------------------------------------------------------------------

class PatchSiblingTests(DifferentialFixture):

    def setUp(self):
        super().setUp()
        self.patched = DIFF.build_differential(
            self.result.entries, self.result.symbols, self.result.controls,
            self.result.sinks, self.result.call_edges, fix_history=FIX_HISTORY)

    def test_a_fix_on_a_file_flags_the_siblings_that_lacked_it(self):
        findings = [f for f in self.patched.findings
                    if f.kind == DIFF.KIND_PATCH_SIBLING]
        self.assertEqual(1, len(findings))
        self.assertEqual(["deleteUser"], self.names(findings[0].missing))

    def test_both_carriers_are_merged_into_one_finding(self):
        finding = next(f for f in self.patched.findings
                       if f.kind == DIFF.KIND_PATCH_SIBLING)
        self.assertEqual(["getUser", "updateUser"], self.names(finding.carriers))

    def test_the_merged_agreement_matches_the_carrier_list(self):
        """Two carriers of three must not be reported as "1 of 3"."""
        finding = next(f for f in self.patched.findings
                       if f.kind == DIFF.KIND_PATCH_SIBLING)
        self.assertEqual(2, len(finding.carriers))
        self.assertEqual(round(2 / 3, 4), finding.agreement)

    def test_the_patch_evidence_is_attached(self):
        finding = next(f for f in self.patched.findings
                       if f.kind == DIFF.KIND_PATCH_SIBLING)
        self.assertEqual("abc123def4567890", finding.patch_commit)
        self.assertIn("owner check", finding.patch_subject)
        self.assertTrue(any(b.startswith("patch:") for b in finding.basis))

    def test_a_fix_without_a_matching_member_changes_nothing(self):
        history = [{"commit": "x", "subject": "unrelated",
                    "affected_paths": ["src/com/foo/Nowhere.java"]}]
        index = DIFF.build_differential(
            self.result.entries, self.result.symbols, self.result.controls,
            self.result.sinks, self.result.call_edges, fix_history=history)
        self.assertEqual([], [f for f in index.findings
                              if f.kind == DIFF.KIND_PATCH_SIBLING])

    def test_a_fixed_member_without_controls_produces_nothing(self):
        history = [{"commit": "y", "subject": "touches the unguarded one",
                    "affected_paths": ["src/com/foo/AccountController.java"]}]
        index = DIFF.build_differential(
            self.result.entries, self.result.symbols, self.result.controls,
            self.result.sinks, self.result.call_edges,
            fix_history=history, closure_depth=0)
        patch = [f for f in index.findings if f.kind == DIFF.KIND_PATCH_SIBLING]
        self.assertEqual([], [f for f in patch
                              if "writeAccount" in self.names(f.missing)])

    def test_the_summary_counts_patch_findings(self):
        kinds = self.patched.summary()["findings_by_kind"]
        self.assertEqual(1, kinds.get(DIFF.KIND_PATCH_SIBLING, 0))


# ---------------------------------------------------------------------------
# 7. candidates
# ---------------------------------------------------------------------------

class CandidateTests(DifferentialFixture):

    def test_candidates_cover_every_finding(self):
        self.assertEqual(len(self.index.findings), len(self.candidates()))

    def test_ids_are_namespaced_by_kind(self):
        ids = {c["control_kind"]: c["candidate_id"] for c in self.candidates()}
        self.assertTrue(ids[CTL.KIND_AUTH_BYPASS].startswith("dif-authz-"))
        self.assertTrue(ids[DIFF.KIND_VALIDATION_DIFF].startswith("dif-valid-"))

    def test_the_highest_risk_finding_is_first(self):
        self.assertEqual(DIFF.DIFF_SECURITY_CONTROL,
                         self.candidates()[0]["differential_kind"])
        self.assertIn("deleteUser", self.candidates()[0]["surface"])

    def test_candidates_carry_provenance(self):
        for candidate in self.candidates():
            self.assertEqual("differential", candidate["producer"])
            self.assertEqual("heuristic-nearby", candidate["confidence"])
            self.assertEqual("static-inferred", candidate["evidence_type"])
            self.assertEqual("differential", candidate["source"])
            self.assertTrue(candidate["finding_id"])
            self.assertTrue(candidate["group_id"])

    def test_candidates_use_the_spec_11_kind_key(self):
        """One pool, one schema: the control map's key, not a second spelling."""
        known = {CTL.KIND_AUTH_BYPASS, CTL.KIND_CONTROL_BYPASS,
                 DIFF.KIND_VALIDATION_DIFF, DIFF.KIND_CONTROL_DIFF,
                 DIFF.KIND_PATCH_SIBLING}
        for candidate in self.candidates():
            self.assertIn(candidate["control_kind"], known)

    def test_candidates_point_at_real_locations(self):
        candidate = next(c for c in self.candidates()
                         if "deleteUser" in c["surface"])
        self.assertIn("src/com/foo/UserController.java", candidate["code_location"][0])

    def test_the_auth_bypass_candidate_is_bucketed_as_authz(self):
        candidate = next(c for c in self.candidates()
                         if c["control_kind"] == CTL.KIND_AUTH_BYPASS)
        self.assertEqual("authz", candidate["category"])

    def test_candidates_are_structurally_like_a_proposal(self):
        required = ("candidate_id", "surface", "entry", "input_shape", "logic",
                    "hypothesis", "precondition_tier_hint", "preconditions",
                    "poc_class", "jvm", "target_classes", "authz_cases",
                    "chain_components", "novelty_keywords", "code_location")
        for candidate in self.candidates():
            for field in required:
                self.assertIn(field, candidate)
            self.assertRegex(candidate["poc_class"], r"^[A-Za-z_]\w*$")
            self.assertNotEqual("0", candidate["precondition_tier_hint"])

    def test_only_authorization_findings_carry_authz_cases(self):
        for candidate in self.candidates():
            if candidate["control_family"] == "authz":
                self.assertTrue(candidate["authz_cases"])
            else:
                self.assertEqual([], candidate["authz_cases"])

    def test_a_limit_is_a_prefix(self):
        full = [c["candidate_id"] for c in self.candidates()]
        limited = [c["candidate_id"] for c in self.candidates(limit=1)]
        self.assertEqual(1, len(limited))
        self.assertEqual(full[0], limited[0])

    def test_candidates_are_deterministic(self):
        again = DIFF.differential_candidates(self.index.findings)
        self.assertEqual([c["candidate_id"] for c in self.candidates()],
                         [c["candidate_id"] for c in again])


# ---------------------------------------------------------------------------
# 8. persistence + residual (spec §14 kind 7)
# ---------------------------------------------------------------------------

class PersistenceTests(DifferentialFixture):

    def test_the_index_round_trips(self):
        loaded = DIFF.load_differential(self.store)
        self.assertEqual([f.as_dict() for f in self.index.findings],
                         [f.as_dict() for f in loaded.findings])
        self.assertEqual([g.as_dict() for g in self.index.groups],
                         [g.as_dict() for g in loaded.groups])

    def test_a_member_keeps_its_class_and_scope_across_the_reload(self):
        """The persisted key is ``class``; losing it empties the scope."""
        loaded = DIFF.load_differential(self.store)
        member = next(m for g in loaded.groups for m in g.members
                      if m.name == "deleteUser")
        self.assertEqual("UserController", member.class_name)
        self.assertEqual("UserController", member.scope)

    def test_the_grouping_statistics_survive_the_reload(self):
        loaded = DIFF.load_differential(self.store)
        self.assertEqual(self.index.group_notes, loaded.group_notes)
        self.assertEqual(self.index.summary()["groups_by_basis"],
                         loaded.summary()["groups_by_basis"])

    def test_group_notes_are_recovered_from_a_summary_only_index(self):
        payload = self.index.as_dict()
        payload.pop("group_notes")
        restored = DIFF.DifferentialIndex.from_dict(payload)
        self.assertEqual(self.index.group_notes, restored.group_notes)

    def test_candidates_round_trip(self):
        candidates = self.candidates()
        DIFF.write_differential(self.store, self.index, candidates)
        self.assertEqual(candidates, DIFF.load_differential_candidates(self.store))

    def test_a_missing_index_loads_empty(self):
        empty = INV.CoverageStore(Path(tempfile.mkdtemp(prefix="vulngate-none-")),
                                  "nothing")
        self.addCleanup(lambda: shutil.rmtree(empty.workspace, ignore_errors=True))
        loaded = DIFF.load_differential(empty)
        self.assertEqual([], loaded.groups)
        self.assertEqual([], loaded.findings)
        self.assertEqual([], DIFF.load_differential_candidates(empty))

    def test_the_inventory_persists_groups_and_candidates(self):
        index = INV.load_inventory(self.store)
        self.assertEqual(len(self.index.groups),
                         len(index[DIFF.SIBLING_GROUP_INDEX]))
        self.assertEqual(len(self.candidates()),
                         len(index[DIFF.DIFFERENTIAL_CANDIDATE_INDEX]))
        self.assertEqual(len(self.index.findings),
                         len(index[DIFF.DIFFERENTIAL_INDEX]["findings"]))


class ResidualTests(DifferentialFixture):

    def setUp(self):
        super().setUp()
        self.patched = DIFF.build_differential(
            self.result.entries, self.result.symbols, self.result.controls,
            self.result.sinks, self.result.call_edges, fix_history=FIX_HISTORY)
        DIFF.write_differential(self.store, self.patched, self.candidates())

    def regions(self):
        return COV.build_uncovered_regions(INV.load_inventory(self.store))

    def test_findings_become_differential_candidate_regions(self):
        regions = [r for r in self.regions()
                   if r["kind"] == "differential-candidate"]
        self.assertEqual(len(self.patched.findings), len(regions))

    def test_a_region_carries_the_group_and_the_agreement(self):
        region = next(r for r in self.regions()
                      if r["kind"] == "differential-candidate"
                      and "deleteUser" in r["reason"])
        self.assertEqual("high", region["risk"])
        self.assertEqual("possible-auth-bypass", region["detail"]["kind"])
        self.assertEqual("authorization", region["detail"]["category"])
        self.assertTrue(region["detail"]["group_id"])
        self.assertTrue(region["detail"]["control_ids"])
        # ``missing_members`` carries qualified symbol ids (resolvable later);
        # the friendly list is the one carrying bare names.
        self.assertTrue(any(str(m).endswith("#deleteUser")
                            for m in region["detail"]["missing_members"]),
                        region["detail"]["missing_members"])
        self.assertIn("deleteUser", region["detail"]["missing_member_names"])
        self.assertIn("getUser", region["detail"]["carrier_member_names"])

    def test_a_reviewed_control_closes_its_differential_region(self):
        region = next(r for r in self.regions()
                      if r["kind"] == "differential-candidate"
                      and "deleteUser" in r["reason"])
        reviewed = region["detail"]["control_ids"]
        self.assertTrue(reviewed)

        index = INV.load_inventory(self.store)
        for record in index["security-control-index"]:
            if record["control_id"] in reviewed:
                record["review_state"] = "reviewed"
        after = [r for r in COV.build_uncovered_regions(index)
                 if r["kind"] == "differential-candidate"
                 and "deleteUser" in r["reason"]]
        self.assertEqual([], after)

    def test_a_finding_without_ids_stays_open(self):
        """Nothing to check against is not the same as checked."""
        finding = DIFF.DifferentialFinding(
            finding_id="dif-9999", group_id="g", kind="possible-auth-bypass",
            differential=DIFF.DIFF_SECURITY_CONTROL, category="authorization",
            family="authz", risk="high",
            carriers=[{"symbol_id": "a"}], missing=[{"symbol_id": "b"}])
        index = DIFF.DifferentialIndex(groups=[], findings=[finding])
        regions = DIFF.differential_regions(index, {"something"}, {"else"})
        self.assertEqual(1, len(regions))

    def test_differential_regions_respect_the_per_kind_limit(self):
        regions = COV.build_uncovered_regions(INV.load_inventory(self.store),
                                              limit_per_kind=1)
        self.assertEqual(1, len([r for r in regions
                                 if r["kind"] == "differential-candidate"]))

    def test_regions_are_ordered_by_risk(self):
        risks = [r["risk"] for r in self.regions()
                 if r["kind"] == "differential-candidate"]
        self.assertEqual(sorted(risks, key=lambda r: DIFF.RISK_ORDER[r]), risks)

    def test_a_store_without_a_differential_index_behaves_as_before(self):
        index = INV.load_inventory(self.store)
        index.pop(DIFF.DIFFERENTIAL_INDEX)
        self.assertEqual([], [r for r in COV.build_uncovered_regions(index)
                              if r["kind"] == "differential-candidate"])


# ---------------------------------------------------------------------------
# 9. rendering
# ---------------------------------------------------------------------------

class RenderTests(DifferentialFixture):

    def test_the_report_states_its_limitations(self):
        for lang, needle in (("zh", "局限"), ("en", "Limitations")):
            text = DIFF.render_differential_text(self.index, lang, limit=2)
            self.assertIn(needle, text)
            for limitation in DIFF.LIMITATIONS:
                self.assertIn(limitation[:40], text)

    def test_the_report_names_the_group_and_the_missing_member(self):
        text = DIFF.render_differential_text(self.index, "zh", limit=5)
        self.assertIn("deleteUser", text)
        self.assertIn("getUser", text)

    def test_candidates_are_printed_only_when_asked_for(self):
        without = DIFF.render_differential_text(self.index, "zh", limit=2)
        with_candidates = DIFF.render_differential_text(
            self.index, "zh", limit=2, candidates=self.candidates())
        self.assertNotIn("dif-", without)
        self.assertIn("dif-", with_candidates)


if __name__ == "__main__":
    unittest.main()
