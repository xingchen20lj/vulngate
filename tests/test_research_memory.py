"""Regression tests for target-scoped cross-round research memory."""

from __future__ import annotations

import json
import contextlib
import io
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.analysis import scheduler as SCH  # noqa: E402
from agent.analysis.research_strategy import (  # noqa: E402
    build_research_strategy,
    write_research_strategy,
)
from agent.memory.research import (  # noqa: E402
    STATE_ACTIONABLE_DIFFERENCE,
    STATE_ENVIRONMENT_GAP,
    STATE_PENDING_RESIDUAL,
    STATE_RESIDUAL_FALSIFIED,
    STATE_REVIEW_NEEDS_EVIDENCE,
    STATE_REVIEW_REJECTED,
    STATE_STABLE_REPRODUCER,
    build_round_memory,
    load_review_feedback,
    load_research_memory,
    memory_match,
    merge_research_memory,
    record_review_feedback,
    research_key,
    residual_meta,
    write_research_memory,
)
from agent.orchestrator.config import TargetConfig  # noqa: E402
from agent.orchestrator.stages import StageContext, run_s8  # noqa: E402
import agent_cli  # noqa: E402


def candidate(candidate_id="C1", **extra):
    value = {
        "candidate_id": candidate_id,
        "surface": "typed parser dispatch",
        "entry": "readValue",
        "input_shape": "json object",
        "logic": "type dispatch reaches a dangerous sink",
        "code_location": ["src/Parser.java:42"],
        "target_classes": ["com.example.Gadget"],
    }
    value.update(extra)
    return value


def lab_for(candidate_id, replay_status="stable", diff_status="no-difference",
            reproduces=True):
    return {
        "fixtures": [{
            "fixture": {
                "candidate_id": candidate_id,
                "fixture_id": "s4fx-test-1",
                "fixture_kind": "java",
            },
            "expected": {"bucket": "parsed"},
            "replay": {
                "status": replay_status,
                "attempts": 3,
                "representative": {"outcome": "parsed"},
            },
            "reproduces_expected": reproduces,
            "differential": {
                "status": diff_status,
                "primary_version": "v2",
                "differences": [{
                    "version": "v1", "safe_mode": False,
                    "baseline_outcome": "parsed", "observed_outcome": "error",
                }] if diff_status.startswith("difference") else [],
                "inconclusive_cells": [],
            },
        }],
        "claim_status": "not-a-finding",
    }


class ResearchMemoryTests(unittest.TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vulngate-memory-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    def test_key_is_stable_across_candidate_ids_and_does_not_store_raw_input(self):
        first = candidate("C1")
        first["hypothesis"] = "super-secret raw hypothesis"
        second = candidate("renamed-by-next-round")
        self.assertEqual(research_key(first), research_key(second))
        delta = build_round_memory([first], {"C1": {}}, {"C1": "候选"},
                                   lab_for("C1"), 1)
        serialized = json.dumps(delta, ensure_ascii=False)
        self.assertNotIn("super-secret raw hypothesis", serialized)
        self.assertNotIn("typed dispatch reaches a dangerous sink", serialized)
        self.assertNotIn("--payload", serialized)
        self.assertEqual(["src/Parser.java:42"],
                         delta["entries"][0]["code_locations"])

    def test_fix_variant_hints_are_retained_as_bounded_research_metadata(self):
        c = candidate(patch_commit="deadbeef1234", patch_variants=[
            "boundary-variant", "alternate-codec",
        ])
        delta = build_round_memory([c], {"C1": {}}, {"C1": "候选"},
                                   lab_for("C1"), 1)
        entry = delta["entries"][0]
        self.assertEqual(["alternate-codec", "boundary-variant"],
                         entry["fix_variants"])
        self.assertEqual("deadbeef1234", entry["patch_commit"])

    def test_s3_residuals_are_bounded_pending_and_redacted(self):
        c = candidate(
            residuals=[{
                "kind": "variant",
                "reason": "secret=do-not-copy",
                "probe_plan": "curl --data @payload secret=do-not-copy",
                "code_location": [{"file": "src/Parser.java", "line": 44}],
            }])
        delta = build_round_memory([c], {"C1": {}}, {"C1": "候选"},
                                   lab_for("C1"), 1)
        entry = delta["entries"][0]
        residual = entry["residuals"][0]
        self.assertEqual(1, entry["pending_residual_count"])
        self.assertEqual(STATE_PENDING_RESIDUAL, residual["state"])
        self.assertEqual("variant", residual["kind"])
        self.assertEqual("unclassified", residual["reason_code"])
        self.assertTrue(residual["has_probe_plan"])
        self.assertTrue(residual["probe_digest"])
        self.assertEqual(["src/Parser.java:44"], residual["code_locations"])
        self.assertEqual("not-a-finding", residual["claim_status"])
        encoded = json.dumps(delta, ensure_ascii=False)
        self.assertNotIn("do-not-copy", encoded)
        self.assertNotIn("curl", encoded)

        merged = merge_research_memory({}, delta)
        self.assertEqual(1, merged["summary"]["residual_count"])
        self.assertEqual(merged, merge_research_memory(merged, delta))

    def test_residual_closes_only_with_declared_executed_falsifier(self):
        c = candidate(residuals=[{
            "kind": "variant", "reason_code": "unverified",
            "probe_plan": "secret raw probe must not persist",
        }])
        residual = residual_meta(c)[0]
        rid = residual["residual_id"]
        code = residual["allowed_falsifiers"][0]
        summary = {
            "execution_state": "executed-no-effect",
            "residual_falsifiers": [{
                "residual_id": rid, "status": "falsified",
                "falsifier_code": code, "execution_state": "executed",
                "effect_observed": False, "contract_declared": True,
                "cell_ref": "s4c-01234567890123456789",
            }],
        }
        delta = build_round_memory([c], {"C1": summary}, {}, None, 5)
        row = delta["entries"][0]["residuals"][0]
        self.assertEqual(STATE_RESIDUAL_FALSIFIED, row["state"])
        self.assertEqual(code, row["falsifier_code"])
        self.assertEqual(0, delta["entries"][0]["pending_residual_count"])
        self.assertEqual("not-a-finding", row["claim_status"])

        blocked = dict(summary)
        blocked["residual_falsifiers"] = [dict(summary["residual_falsifiers"][0],
                                                execution_state="gate-blocked")]
        still_pending = build_round_memory([c], {"C1": blocked}, {}, None, 6)
        self.assertEqual(STATE_PENDING_RESIDUAL,
                         still_pending["entries"][0]["residuals"][0]["state"])

        effected = dict(summary)
        effected["residual_falsifiers"] = [dict(summary["residual_falsifiers"][0],
                                                effect_observed=True)]
        still_pending = build_round_memory([c], {"C1": effected}, {}, None, 7)
        self.assertEqual(STATE_PENDING_RESIDUAL,
                         still_pending["entries"][0]["residuals"][0]["state"])

    def test_residual_resolution_is_monotonic_across_merge(self):
        c = candidate(residuals=[{
            "kind": "variant", "reason_code": "unverified",
            "probe_plan": "bounded probe",
        }])
        residual = residual_meta(c)[0]
        summary = {"residual_falsifiers": [{
            "residual_id": residual["residual_id"], "status": "falsified",
            "falsifier_code": residual["allowed_falsifiers"][0],
            "execution_state": "executed", "effect_observed": False,
            "contract_declared": True, "cell_ref": "s4c-abc",
        }]}
        pending = build_round_memory([c], {"C1": {}}, {}, None, 1)
        resolved = build_round_memory([c], {"C1": summary}, {}, None, 2)
        merged = merge_research_memory(pending, resolved)
        merged = merge_research_memory(merged, pending)
        row = merged["entries"][0]["residuals"][0]
        self.assertEqual(STATE_RESIDUAL_FALSIFIED, row["state"])
        self.assertEqual(1, merged["summary"]["resolved_residual_count"])

    def test_runtime_states_keep_difference_and_environment_gap_distinct(self):
        c = candidate()
        difference = build_round_memory(
            [c], {"C1": {}}, {"C1": "候选（待验证）"},
            lab_for("C1", diff_status="difference-with-inconclusive"), 2)
        self.assertEqual(STATE_ACTIONABLE_DIFFERENCE,
                         difference["entries"][0]["events"][0]["state"])

        gap = build_round_memory(
            [c], {"C1": {}}, {"C1": "候选（待验证）"},
            lab_for("C1", replay_status="precondition-unavailable",
                    diff_status="inconclusive", reproduces=None), 3)
        self.assertEqual(STATE_ENVIRONMENT_GAP,
                         gap["entries"][0]["events"][0]["state"])
        self.assertIn("不可解释为无效", " ".join(
            gap["entries"][0]["events"][0]["next_probe_hints"]))

        stable = build_round_memory(
            [c], {"C1": {}}, {"C1": "候选（待验证）"},
            lab_for("C1"), 4)
        self.assertEqual(STATE_STABLE_REPRODUCER,
                         stable["entries"][0]["events"][0]["state"])

    def test_runtime_context_is_carried_without_raw_service_or_authz_values(self):
        c = candidate()
        lab = lab_for("C1")
        lab["configuration"] = {
            "schema_version": "runtime-context-v1",
            "target_type": "web-app",
            "versions": ["v1"],
            "target_urls": {"v1": {"url_digest": "url-digest-1",
                                     "raw_url": "http://127.0.0.1/?token=secret"}},
            "runtime_lab": {"enabled": True, "replay_runs": 3,
                             "safe_modes": [False, True]},
            "service_lifecycle": {
                "schema_version": "service-lifecycle-v2",
                "status": "started-ready", "ready": True,
                "config_digest": "service-config-1",
                "healthcheck": {"kind": "url", "configured": True,
                                 "port": 8080, "raw": "secret=do-not-copy"},
            },
            "authz_fixtures": [{
                "candidate_id": "C1", "fixture_id": "azfx-1",
                "role": "tenant-admin", "tenant_id": "private-tenant",
                "expected_authz": "deny", "expected_http_codes": [403],
            }],
        }
        lab["fixtures"][0]["fixture"]["authz_fixture_id"] = "azfx-1"
        delta = build_round_memory([c], {"C1": {}}, {"C1": "候选"}, lab, 2)
        event = delta["entries"][0]["events"][0]
        context = event["evidence"]["runtime_context"]
        self.assertEqual("started-ready", context["service_lifecycle"]["status"])
        self.assertEqual("service-config-1",
                         context["service_lifecycle"]["config_digest"])
        self.assertEqual(["azfx-1"], [row["fixture_id"]
                                      for row in context["authz_fixtures"]])
        self.assertEqual("url-digest-1", context["target_url_digests"]["v1"])
        encoded = json.dumps(delta, ensure_ascii=False)
        self.assertNotIn("private-tenant", encoded)
        self.assertNotIn("secret=do-not-copy", encoded)
        self.assertNotIn("raw_url", encoded)

    def test_comparison_context_is_bounded_and_persisted_as_research_only(self):
        c = candidate()
        lab = lab_for("C1")
        lab["fixtures"][0]["comparison"] = {
            "schema_version": "comparison-orchestration-v1",
            "comparison_id": "cmp-" + "a" * 20,
            "status": "inconclusive",
            "primary_version": "v2",
            "observed_count": 1,
            "inconclusive_count": 2,
            "version_observations": [{
                "before": "v1", "after": "v2", "safe_mode": False,
                "status": "bucket-difference", "reason_code": "bucket-changed",
                "raw_payload": "secret=do-not-copy",
            }],
            "source_revision_observations": [{
                "role": "before", "ref": "deadbeef",
                "status": "not-executed",
            }],
            "sibling_observations": [{
                "variant": "alternate-codec", "status": "not-executed",
            }],
            "raw_command": "curl --data @payload",
        }
        delta = build_round_memory([c], {"C1": {}}, {"C1": "候选"}, lab, 5)
        event = delta["entries"][0]["events"][0]
        comparison = event["evidence"]["comparison"]
        self.assertEqual("inconclusive", comparison["status"])
        self.assertEqual("cmp-" + "a" * 20, comparison["comparison_id"])
        self.assertEqual("bucket-difference",
                         comparison["version_observations"][0]["status"])
        self.assertEqual("source-revision-build-required",
                         comparison["source_revision_observations"][0]["reason_code"])
        self.assertEqual("requires-sibling-lane",
                         comparison["sibling_observations"][0]["reason_code"])
        self.assertIn("不把缺口解释为修复", " ".join(
            event["next_probe_hints"]))
        self.assertEqual("not-a-finding", comparison["claim_status"])
        encoded = json.dumps(delta, ensure_ascii=False)
        self.assertNotIn("do-not-copy", encoded)
        self.assertNotIn("curl", encoded)
        self.assertNotIn("raw_command", encoded)

    def test_executed_source_revision_comparison_survives_memory_normalization(self):
        c = candidate()
        lab = lab_for("C1")
        lab["fixtures"][0]["comparison"] = {
            "schema_version": "comparison-orchestration-v1",
            "comparison_id": "cmp-" + "b" * 20,
            "status": "difference-observed",
            "source_revision_observations": [{
                "role": "before", "ref": "a" * 40,
                "status": "observed",
                "reason_code": "source-revision-artifact-executed",
                "observed_count": 1, "safe_modes": [False],
            }, {
                "role": "after", "ref": "b" * 40,
                "status": "observed",
                "reason_code": "source-revision-artifact-executed",
                "observed_count": 1, "safe_modes": [False],
            }],
            "source_revision_comparison": {
                "status": "difference-observed",
                "pairs": [{
                    "safe_mode": False, "status": "bucket-difference",
                    "reason_code": "bucket-changed",
                }],
                "observed_count": 1, "inconclusive_count": 0,
            },
        }
        delta = build_round_memory([c], {"C1": {}}, {"C1": "候选"},
                                   lab, 6)
        comparison = delta["entries"][0]["events"][0]["evidence"]["comparison"]
        self.assertEqual("observed",
                         comparison["source_revision_observations"][0]["status"])
        self.assertEqual("difference-observed",
                         comparison["source_revision_comparison"]["status"])
        self.assertEqual("bucket-difference",
                         comparison["source_revision_comparison"]["pairs"][0]["status"])
        self.assertEqual("not-a-finding", comparison["claim_status"])

    def test_surface_variant_witness_is_bounded_and_drives_next_probe(self):
        c = candidate()
        lab = lab_for("C1")
        lab["fixtures"][0]["variant_evidence"] = {
            "schema_version": "surface-variant-evidence-v1",
            "fixture_key": "vf-" + "c" * 20,
            "surface": "protocol",
            "variant_id": "protocol-frame-state-order",
            "lane": "positive",
            "expected_observation": "typed-effect",
            "required_observations": ["execution", "state-sequence",
                                       "typed-effect"],
            "observed_signals": ["execution", "state-sequence"],
            "missing_observations": ["typed-effect"],
            "falsifier_signals": ["typed-effect-missing", "secret=drop"],
            "sequence_statuses": ["partial"],
            "cells_observed": 1,
            "cells_with_gap": 0,
            "status": "partial",
            "cells": [{
                "version": "1.0", "safe_mode": "false",
                "status": "observed", "signals": ["execution"],
                "sequence_status": "partial",
                "typed_effect_observed": "false",
            }],
            "raw_output": "secret=drop",
        }
        delta = build_round_memory([c], {"C1": {}}, {"C1": "候选"},
                                   lab, 7)
        event = delta["entries"][0]["events"][0]
        witness = event["evidence"]["variant_evidence"]
        self.assertEqual("partial", witness["status"])
        self.assertEqual(["typed-effect-missing"],
                         witness["falsifier_signals"])
        self.assertFalse(witness["cells"][0]["safe_mode"])
        self.assertFalse(witness["cells"][0]["typed_effect_observed"])
        self.assertIn("补 typed-effect", " ".join(event["next_probe_hints"]))
        encoded = json.dumps(delta, ensure_ascii=False)
        self.assertNotIn("secret=drop", encoded)
        self.assertNotIn("raw_output", encoded)
        self.assertEqual("not-a-finding", witness["claim_status"])

    def test_merge_is_idempotent_and_preserves_old_events(self):
        c = candidate()
        first = build_round_memory([c], {"C1": {}}, {"C1": "候选"},
                                   lab_for("C1"), 1)
        second = build_round_memory([c], {"C1": {}}, {"C1": "候选"},
                                    lab_for("C1", diff_status="difference-observed"), 2)
        merged = merge_research_memory({}, first)
        merged = merge_research_memory(merged, second)
        merged_again = merge_research_memory(merged, second)
        self.assertEqual(2, merged["summary"]["event_count"])
        self.assertEqual(merged, merged_again)
        self.assertEqual(2, len(merged["entries"][0]["events"]))

    def test_bookkeeping_round_does_not_erase_latest_runtime_state(self):
        c = candidate()
        observed = build_round_memory(
            [c], {"C1": {}}, {"C1": "候选"},
            lab_for("C1", diff_status="difference-observed"), 1)
        bookkeeping = build_round_memory(
            [c], {"C1": {}}, {"C1": "候选（待验证）"}, None, 2)
        merged = merge_research_memory(observed, bookkeeping)
        self.assertEqual(STATE_ACTIONABLE_DIFFERENCE,
                         memory_match(c, merged["entries"])["latest_event"]["state"])

    def test_target_file_round_trips_and_memory_match_returns_latest_event(self):
        c = candidate()
        delta = build_round_memory([c], {"C1": {}}, {"C1": "候选"},
                                   lab_for("C1", diff_status="difference-observed"), 5)
        memory = merge_research_memory({}, delta)
        path = write_research_memory(self.root, "target", memory)
        self.assertTrue(path.exists())
        loaded = load_research_memory(self.root, "target")
        match = memory_match(c, loaded["entries"])
        self.assertEqual(STATE_ACTIONABLE_DIFFERENCE,
                         match["latest_event"]["state"])

    def test_scheduler_marks_stable_memory_without_turning_it_into_a_finding(self):
        c = candidate()
        base_ctx = SCH.ScheduleContext(
            entries={"e": {"entry_id": "e", "kind": "http", "file": "src/Parser.java", "line": 42}},
            sinks={"s": {"sink_id": "s", "category": "command-exec", "severity_hint": "high",
                         "file": "src/Parser.java", "line": 42}},
            flows=[{"flow_id": "f", "entry_id": "e", "sink_id": "s",
                    "direction": "cross-procedural", "path": [], "authorizations": []}],
        )
        before = SCH.score_candidate(c, base_ctx)
        delta = build_round_memory([c], {"C1": {}}, {"C1": "候选"},
                                   lab_for("C1"), 1)
        remembered_ctx = SCH.ScheduleContext(
            entries=base_ctx.entries, sinks=base_ctx.sinks,
            flows=base_ctx.flows, research_memory=delta["entries"])
        after = SCH.score_candidate(c, remembered_ctx)
        self.assertLess(after.total, before.total)
        self.assertEqual(STATE_STABLE_REPRODUCER,
                         after.evidence["research_memory"]["latest_state"])
        self.assertEqual("not-a-finding",
                         after.evidence["research_memory"]["claim_status"])

    def test_scheduler_prompt_exposes_bounded_residual_metadata(self):
        c = candidate(residuals=[{
            "kind": "control-gap",
            "reason_code": "missing-effect",
            "probe_plan": "raw probe must not be copied",
        }])
        delta = build_round_memory([c], {"C1": {}}, {"C1": "候选"},
                                   lab_for("C1"), 1)
        prompt = SCH.prompt_coverage_block(SCH.ScheduleContext(
            research_memory=delta["entries"]))
        self.assertIn("residuals=", prompt)
        self.assertIn("control-gap", prompt)
        self.assertIn("/plan", prompt)
        self.assertNotIn("raw probe must not be copied", prompt)

    def test_human_review_is_idempotent_and_overlays_memory(self):
        c = candidate()
        base = merge_research_memory(
            {}, build_round_memory([c], {"C1": {}}, {"C1": "候选"},
                                   lab_for("C1"), 1))
        write_research_memory(self.root, "target", base)
        key = research_key(c)
        first = record_review_feedback(
            self.root, "target", key, "needs-evidence",
            reason_code="missing-typed-effect", candidate_id="C1",
            reviewer_note="secret=do-not-persist", evidence_refs=["S4/runtime-lab.json"],
            next_probe_hints=["补 typed effect"], round_no=2)
        second = record_review_feedback(
            self.root, "target", key, "needs-evidence",
            reason_code="missing-typed-effect", candidate_id="C1",
            reviewer_note="secret=do-not-persist", evidence_refs=["S4/runtime-lab.json"],
            next_probe_hints=["补 typed effect"], round_no=2)
        self.assertEqual(first["feedback_id"], second["feedback_id"])
        feedback = load_review_feedback(self.root, "target")
        self.assertEqual(1, feedback["summary"]["feedback_count"])
        self.assertNotIn("do-not-persist",
                         json.dumps(feedback, ensure_ascii=False))
        memory = load_research_memory(self.root, "target")
        latest = memory_match(c, memory["entries"])["latest_event"]
        self.assertEqual(STATE_REVIEW_NEEDS_EVIDENCE, latest["state"])
        self.assertEqual("not-a-finding", latest["claim_status"])

    def test_review_feedback_changes_priority_but_not_claim_status(self):
        c = candidate()
        base_ctx = SCH.ScheduleContext(
            entries={"e": {"entry_id": "e", "kind": "http",
                            "file": "src/Parser.java", "line": 42}},
            sinks={"s": {"sink_id": "s", "category": "command-exec",
                          "severity_hint": "high", "file": "src/Parser.java",
                          "line": 42}},
            flows=[{"flow_id": "f", "entry_id": "e", "sink_id": "s",
                    "direction": "cross-procedural", "path": [],
                    "authorizations": []}],
        )
        before = SCH.score_candidate(c, base_ctx)
        key = research_key(c)
        record_review_feedback(self.root, "needs", key, "needs-evidence",
                               reason_code="needs-source-review", candidate_id="C1",
                               round_no=1)
        needs = load_research_memory(self.root, "needs")
        after_needs = SCH.score_candidate(
            c, SCH.ScheduleContext(entries=base_ctx.entries, sinks=base_ctx.sinks,
                                   flows=base_ctx.flows,
                                   research_memory=needs["entries"]))
        self.assertGreater(after_needs.total, before.total)
        self.assertEqual(STATE_REVIEW_NEEDS_EVIDENCE,
                         after_needs.evidence["research_memory"]["latest_state"])
        self.assertEqual("not-a-finding",
                         after_needs.evidence["research_memory"]["claim_status"])

        record_review_feedback(self.root, "rejected", key, "rejected",
                               reason_code="false-positive", candidate_id="C1",
                               round_no=1)
        rejected = load_research_memory(self.root, "rejected")
        after_rejected = SCH.score_candidate(
            c, SCH.ScheduleContext(entries=base_ctx.entries, sinks=base_ctx.sinks,
                                   flows=base_ctx.flows,
                                   research_memory=rejected["entries"]))
        self.assertLess(after_rejected.total, before.total)
        self.assertEqual(STATE_REVIEW_REJECTED,
                         after_rejected.evidence["research_memory"]["latest_state"])

    def test_review_cli_resolves_candidate_id_and_writes_feedback(self):
        c = candidate()
        memory = merge_research_memory(
            {}, build_round_memory([c], {"C1": {}}, {"C1": "候选"},
                                   lab_for("C1"), 1))
        write_research_memory(self.root, "target", memory)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = agent_cli.main([
                "review", "target", "--workspace", str(self.root),
                "--candidate-id", "C1", "--status", "accepted",
                "--reason-code", "confirmed-mechanism", "--json",
            ])
        self.assertEqual(0, code)
        self.assertIn("research_key", output.getvalue())
        self.assertEqual(1, load_review_feedback(self.root, "target")
                         ["summary"]["feedback_count"])

    def test_config_s8_writes_round_delta_and_target_memory(self):
        c = candidate()
        cfg = TargetConfig(name="target", discovery_date="2026-09-21",
                           candidates=[c], notes="test")
        ctx = StageContext(self.root, "target", 1, cfg, offline=True)
        ctx.store.write_artifact("S4", "runtime-lab.json", lab_for("C1"))
        write_research_strategy(
            self.root, "target",
            build_research_strategy(target="target", target_type="library"))
        result = run_s8(ctx, {"C1": {}}, {"C1": "候选（待验证）"}, {}, {})
        target_memory = self.root / "state" / "target" / "research-memory.json"
        round_delta = (self.root / "state" / "target" / "round-01" / "S8"
                       / "research-memory.json")
        round_feedback = (self.root / "state" / "target" / "round-01" / "S8"
                          / "review-feedback.json")
        round_portfolio = (self.root / "state" / "target" / "round-01" / "S8"
                           / "research-portfolio.json")
        round_strategy_feedback = (self.root / "state" / "target" / "round-01" / "S8"
                                   / "research-strategy-feedback.json")
        round_guidance = (self.root / "state" / "target" / "round-01" / "S8"
                          / "research-guidance.json")
        round_calibration = (self.root / "state" / "target" / "round-01" / "S8"
                             / "research-replay-calibration.json")
        round_pack = (self.root / "state" / "target" / "round-01" / "S8"
                      / "research-replay-pack.json")
        round_consistency = (self.root / "state" / "target" / "round-01" / "S8"
                             / "research-consistency.json")
        round_consistency_actions = (self.root / "state" / "target" /
                                     "round-01" / "S8" /
                                     "research-consistency-actions.json")
        round_consistency_rechecks = (self.root / "state" / "target" /
                                      "round-01" / "S8" /
                                      "research-consistency-rechecks.json")
        round_coverage_closure = (self.root / "state" / "target" /
                                  "round-01" / "S8" /
                                  "coverage-closure.json")
        round_budget = (self.root / "state" / "target" / "round-01" / "S8"
                        / "research-budget.json")
        target_portfolio = self.root / "state" / "target" / "research-portfolio.json"
        target_consistency = (self.root / "state" / "target" / "coverage"
                              / "research-consistency.json")
        target_consistency_actions = (self.root / "state" / "target" /
                                      "coverage" /
                                      "research-consistency-actions.json")
        target_consistency_rechecks = (self.root / "state" / "target" /
                                       "coverage" /
                                       "research-consistency-rechecks.json")
        target_budget = (self.root / "state" / "target" / "coverage" /
                         "research-budget.json")
        target_pack = (self.root / "state" / "target" / "coverage"
                       / "research-replay-pack.json")
        target_strategy = (self.root / "state" / "target" / "coverage"
                           / "research-strategy.json")
        target_guidance = (self.root / "state" / "target" / "coverage"
                           / "research-guidance.json")
        self.assertTrue(target_memory.exists())
        self.assertTrue(round_delta.exists())
        self.assertTrue(round_feedback.exists())
        self.assertTrue(round_portfolio.exists())
        self.assertTrue(round_strategy_feedback.exists())
        self.assertTrue(round_guidance.exists())
        self.assertTrue(round_calibration.exists())
        self.assertTrue(round_pack.exists())
        self.assertTrue(round_consistency.exists())
        self.assertTrue(round_consistency_actions.exists())
        self.assertTrue(round_consistency_rechecks.exists())
        self.assertTrue(round_coverage_closure.exists())
        self.assertTrue(round_budget.exists())
        self.assertTrue(target_pack.exists())
        self.assertTrue(target_consistency.exists())
        self.assertTrue(target_consistency_actions.exists())
        self.assertTrue(target_consistency_rechecks.exists())
        self.assertTrue(target_budget.exists())
        self.assertTrue(target_portfolio.exists())
        self.assertTrue(target_strategy.exists())
        self.assertTrue(target_guidance.exists())
        self.assertEqual("state/target/research-memory.json",
                         result["research_memory"]["artifact"])
        self.assertEqual("state/target/research-portfolio.json",
                         result["research_portfolio"]["artifact"])
        self.assertEqual("state/target/coverage/research-consistency.json",
                         result["research_consistency"]["artifact"])
        self.assertEqual("state/target/coverage/research-replay-calibration.json",
                         result["research_replay_calibration"]["artifact"])
        self.assertEqual("state/target/coverage/research-strategy.json",
                         result["research_strategy"]["artifact"])
        self.assertEqual("state/target/coverage/research-budget.json",
                         result["research_budget"]["artifact"])
        self.assertEqual("research-strategy-feedback-v1",
                         json.loads(round_strategy_feedback.read_text(
                             encoding="utf-8"))["schema_version"])
        self.assertEqual("research-strategy-guidance-v1",
                         json.loads(round_guidance.read_text(
                             encoding="utf-8"))["schema_version"])
        self.assertEqual("research-replay-calibration-v1",
                         json.loads(round_calibration.read_text(
                             encoding="utf-8"))["schema_version"])
        self.assertEqual("research-replay-pack-v1",
                         json.loads(round_pack.read_text(
                             encoding="utf-8"))["schema_version"])
        self.assertEqual("research-consistency-v1",
                         json.loads(round_consistency.read_text(
                             encoding="utf-8"))["schema_version"])
        self.assertEqual("research-consistency-action-v1",
                         json.loads(round_consistency_actions.read_text(
                             encoding="utf-8"))["schema_version"])
        self.assertEqual("research-consistency-recheck-v1",
                         json.loads(round_consistency_rechecks.read_text(
                             encoding="utf-8"))["schema_version"])
        self.assertEqual("research-budget-v1",
                         json.loads(round_budget.read_text(
                             encoding="utf-8"))["schema_version"])
        self.assertEqual("research-replay-pack-v1",
                         json.loads(target_pack.read_text(
                             encoding="utf-8"))["schema_version"])
        self.assertEqual("not-a-finding",
                         json.loads(target_pack.read_text(
                             encoding="utf-8"))["claim_status"])
        closure = json.loads(round_coverage_closure.read_text(encoding="utf-8"))
        # Direct S8 execution has no current S1 coverage artifact.  That is
        # an incomplete audit scope, not evidence that the configured source
        # scope itself was explicitly invalid.
        self.assertEqual("scope-incomplete", closure["state"])
        self.assertFalse(closure["stop_condition_met"])
        self.assertEqual("not-a-finding", closure["claim_status"])
        self.assertEqual(closure, result["coverage"])
        portfolio = json.loads(target_portfolio.read_text(encoding="utf-8"))
        self.assertEqual("research-portfolio-v1", portfolio["schema_version"])
        self.assertEqual("not-a-finding", portfolio["claim_status"])
        self.assertEqual("stable-reproducer",
                         json.loads(target_memory.read_text(encoding="utf-8")
                                    )["entries"][0]["events"][0]["state"])

    def test_s8_demotes_static_confirmation_and_withholds_cvss(self):
        c = candidate()
        cfg = TargetConfig(name="target", discovery_date="2026-09-21",
                           candidates=[c], notes="test")
        ctx = StageContext(self.root, "target", 1, cfg, offline=True)
        write_research_strategy(
            self.root, "target",
            build_research_strategy(target="target", target_type="library"))
        result = run_s8(
            ctx, {"C1": {}}, {"C1": "确认"},
            {"C1": {
                "novelty": {"verdict": "candidate-0day", "reason": "no record"},
                "g3": {"passed": True, "verdict": "candidate-0day"},
            }},
            {"C1": {"vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    "score": 7.5}},
        )
        consistency = ctx.store.read_artifact(
            "S8", "final-evidence-consistency.json")
        self.assertEqual("final-evidence-consistency-v1",
                         consistency["schema_version"])
        self.assertEqual("候选（待验证）",
                         consistency["rows"][0]["effective_conclusion"])
        self.assertEqual(1, result["final_evidence_consistency"]["demoted_count"])
        ledger = json.loads((self.root / result["ledger_dir"] /
                             "ledger.json").read_text(encoding="utf-8"))
        row = ledger["rows"][0]
        self.assertNotIn("cvss", row)
        self.assertFalse(row["novelty"]["claimable"])
        self.assertIn("S8_CVSS_WITHHELD=unconfirmed-not-a-finding",
                      row["evidence"])


if __name__ == "__main__":
    unittest.main()
