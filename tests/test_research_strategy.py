"""Tests for the bounded cross-artifact research strategy layer."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.analysis.scheduler import ScheduleContext, prompt_coverage_block, score_candidate  # noqa: E402
from agent.analysis.threat_model import build_threat_model  # noqa: E402
from agent.analysis.research_strategy import (  # noqa: E402
    STRATEGY_CLAIM_STATUS,
    STRATEGY_FEEDBACK_SCHEMA_VERSION,
    STRATEGY_GUIDANCE_SCHEMA_VERSION,
    STRATEGY_SCHEMA_VERSION,
    apply_research_guidance,
    apply_strategy_observations,
    build_research_strategy,
    load_research_guidance,
    load_research_strategy,
    normalize_research_strategy,
    strategy_path,
    write_research_guidance,
    write_research_strategy,
)
import agent_cli  # noqa: E402


class ResearchStrategyTests(unittest.TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vulngate-strategy-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    def _threat_model(self):
        return build_threat_model(
            entries=[{
                "entry_id": "entry-http-1", "kind": "http",
                "file": "src/Api.java", "line": 20,
                "target_type": "web-app",
            }],
            sinks=[{
                "sink_id": "sink-exec-1", "category": "command-exec",
                "file": "src/Task.java", "line": 80,
                "severity_hint": "high",
            }],
            flows=[{
                "flow_id": "flow-1", "entry_id": "entry-http-1",
                "sink_id": "sink-exec-1", "priority": "high",
                "path": ["sym-api", "sym-task"],
            }],
            control_map={"entries": [{
                "flow_id": "flow-1", "verdict": "uncontrolled",
                "missing_groups": [["authentication", "authorization"]],
            }]},
            capability_graph={"paths": [{
                "candidate_id": "cap-chain-1", "flow_ids": ["flow-1"],
                "goal": "command-execution", "chain_status": "partial-hypothesis",
                "required_capabilities": ["read", "exec"],
                "observed_capabilities": ["read"],
                "missing_capabilities": ["exec"],
            }]},
            target="demo", target_type="web-app")

    def test_strategy_closes_path_and_residual_with_falsifiers(self):
        strategy = build_research_strategy(
            self._threat_model(),
            {"schema_version": "research-portfolio-v1", "next_probes": [{
                "research_key": "rk-1", "candidate_id": "C1",
                "state": "pending-residual", "priority": 4,
                "residual_id": "rr-01234567890123456789",
                "residual_kind": "variant",
                "residual_reason_code": "unverified",
                "research_surface": "web", "target_type": "web-app",
                "variant": ["alternate-codec"],
            }]},
            target="demo", target_type="web-app", round_no=3)
        self.assertEqual(STRATEGY_SCHEMA_VERSION, strategy["schema_version"])
        self.assertEqual(STRATEGY_CLAIM_STATUS, strategy["claim_status"])
        kinds = {item["kind"] for item in strategy["items"]}
        self.assertIn("capability-closure", kinds)
        self.assertIn("residual-closure", kinds)
        path = next(item for item in strategy["items"]
                    if item["kind"] == "capability-closure")
        self.assertIn("capability-transition", path["required_observations"])
        self.assertTrue(path["falsifiers"])
        self.assertEqual(STRATEGY_CLAIM_STATUS, path["claim_status"])
        residual = next(item for item in strategy["items"]
                        if item["kind"] == "residual-closure")
        self.assertEqual("pending-residual", residual["state"])
        self.assertEqual("s3-residual", residual["reason_codes"][0])
        self.assertEqual(1, strategy["summary"]["pending_residuals"])

    def test_strategy_fallback_keeps_memory_residual_when_portfolio_is_missing(self):
        strategy = build_research_strategy(
            research_memory=[{
                "research_key": "rk-memory", "candidate_id": "C-memory",
                "research_surface": "web", "target_type": "web-app",
                "residuals": [{
                    "residual_id": "rr-abcdefabcdefabcdefab",
                    "kind": "variant", "reason_code": "unverified",
                }],
                "events": [{"event_id": "evt-1", "round": 2,
                            "state": "stable-reproducer"}],
            }],
            target="demo", target_type="web-app")
        residuals = [item for item in strategy["items"]
                     if item["kind"] == "residual-closure"]
        self.assertEqual(1, len(residuals))
        self.assertEqual("rr-abcdefabcdefabcdefab",
                         residuals[0]["residual_id"])
        self.assertNotIn("stable-reproducer", json.dumps(strategy))

    def test_strategy_fallback_drops_closed_memory_residual(self):
        strategy = build_research_strategy(
            research_memory=[{
                "research_key": "rk-closed", "candidate_id": "C-closed",
                "research_surface": "web", "target_type": "web-app",
                "residuals": [{
                    "residual_id": "rr-abcdefabcdefabcdefab",
                    "kind": "variant", "reason_code": "unverified",
                    "state": "residual-falsified",
                    "falsifier_code": "variant-rejected",
                    "evidence_cells": ["s4c-1"],
                }],
            }],
            target="demo", target_type="web-app")
        self.assertFalse(any(item["kind"] == "residual-closure"
                             for item in strategy["items"]))
        self.assertEqual(0, strategy["summary"]["pending_residuals"])

    def test_s4_observations_backfill_information_gain_without_finding_status(self):
        candidate = {
            "candidate_id": "C-residual",
            "surface": "web",
            "target_type": "web-app",
            "residuals": [{
                "kind": "variant", "reason_code": "unverified",
                "probe_plan": "bounded residual probe",
            }],
        }
        from agent.memory.research import residual_meta
        residual_id = residual_meta(candidate)[0]["residual_id"]
        strategy = build_research_strategy(
            research_portfolio={
                "schema_version": "research-portfolio-v1",
                "next_probes": [{
                    "research_key": "rk-residual",
                    "candidate_id": "C-residual",
                    "state": "pending-residual",
                    "priority": 4,
                    "residual_id": residual_id,
                    "residual_kind": "variant",
                    "residual_reason_code": "unverified",
                    "research_surface": "web",
                    "target_type": "web-app",
                }],
            },
            target="demo", target_type="web-app")
        summary = {
            "execution_state": "executed-no-effect",
            "cells_ran": 2,
            "residual_falsifiers": [{
                "residual_id": residual_id,
                "status": "falsified",
                "execution_state": "executed",
                "effect_observed": False,
                "contract_declared": True,
                "falsifier_code": "variant-rejected",
            }],
        }
        updated, feedback = apply_strategy_observations(
            strategy, [candidate], {"C-residual": summary}, round_no=4)
        item = updated["items"][0]
        observation = item["observation"]
        self.assertEqual("falsifier-observed", observation["status"])
        self.assertEqual([], observation["missing_observations"])
        self.assertGreater(observation["information_gain"], 0)
        self.assertEqual(STRATEGY_FEEDBACK_SCHEMA_VERSION,
                         feedback["schema_version"])
        self.assertEqual(STRATEGY_CLAIM_STATUS,
                         observation["claim_status"])
        self.assertEqual(STRATEGY_CLAIM_STATUS, feedback["claim_status"])

        repeated, repeated_feedback = apply_strategy_observations(
            updated, [candidate], {"C-residual": summary}, round_no=5)
        repeated_observation = repeated["items"][0]["observation"]
        self.assertEqual(0, repeated_observation["information_gain"])
        self.assertEqual(
            observation["cumulative_information_gain"],
            repeated_observation["cumulative_information_gain"])
        self.assertEqual(0, repeated_feedback["summary"]["information_gain"])

        rebuilt = build_research_strategy(
            research_portfolio={
                "schema_version": "research-portfolio-v1",
                "next_probes": [{
                    "research_key": "rk-residual",
                    "candidate_id": "C-residual",
                    "state": "pending-residual",
                    "priority": 4,
                    "residual_id": residual_id,
                    "residual_kind": "variant",
                    "residual_reason_code": "unverified",
                    "research_surface": "web",
                    "target_type": "web-app",
                }],
            },
            target="demo", target_type="web-app", prior_strategy=repeated)
        self.assertEqual(
            repeated_observation,
            next(item for item in rebuilt["items"]
                 if item.get("residual_id") == residual_id)["observation"])

    def test_strategy_feedback_keeps_environment_gap_pending(self):
        candidate = {
            "candidate_id": "C-gap", "surface": "web",
            "target_type": "web-app", "residuals": [{
                "kind": "environment-gap", "reason_code": "environment-gap",
            }],
        }
        from agent.memory.research import residual_meta
        residual_id = residual_meta(candidate)[0]["residual_id"]
        strategy = build_research_strategy(
            research_portfolio={
                "schema_version": "research-portfolio-v1",
                "next_probes": [{
                    "research_key": "rk-gap", "candidate_id": "C-gap",
                    "state": "pending-residual", "priority": 4,
                    "residual_id": residual_id, "residual_kind": "environment-gap",
                    "residual_reason_code": "environment-gap",
                    "research_surface": "web", "target_type": "web-app",
                }],
            },
            target="demo", target_type="web-app")
        updated, _ = apply_strategy_observations(
            strategy, [candidate], {"C-gap": {
                "execution_state": "precondition-unavailable",
                "cells_ran": 1,
            }}, round_no=2)
        observation = updated["items"][0]["observation"]
        self.assertEqual("environment-gap", observation["status"])
        self.assertTrue(observation["missing_observations"])
        self.assertEqual(STRATEGY_CLAIM_STATUS,
                         updated["claim_status"])

    def test_guidance_unifies_review_observation_and_variant_gap(self):
        strategy = build_research_strategy(
            research_portfolio={
                "schema_version": "research-portfolio-v1",
                "next_probes": [{
                    "research_key": "rk-guidance",
                    "candidate_id": "C-guidance",
                    "state": "actionable-difference",
                    "priority": 4,
                    "research_surface": "web",
                    "target_type": "web-app",
                    "variant": ["alternate-codec"],
                }],
                "variant_coverage": [{
                    "variant": "alternate-codec",
                    "status": "gap",
                    "unresolved_entries": 1,
                }],
            },
            target="demo", target_type="web-app")
        item = strategy["items"][0]
        item["observation"] = {
            "status": "partial", "current_status": "partial",
            "information_gain": 0,
            "missing_observations": ["typed-effect-or-safe-equivalent"],
        }
        updated, guidance = apply_research_guidance(
            strategy,
            strategy.get("research_portfolio") or {
                "schema_version": "research-portfolio-v1",
                "variant_coverage": [{
                    "variant": "alternate-codec", "status": "gap",
                }],
            },
            {"entries": [{
                "research_key": "rk-guidance",
                "status": "needs-evidence",
                "round": 3,
                "feedback_id": "rf-3",
                "reviewer_note": "must not persist",
            }]},
            round_no=4)
        item = updated["items"][0]
        self.assertEqual("review-followup", item["guidance"]["next_action"])
        self.assertTrue(item["guidance"]["replacement_recommended"])
        self.assertEqual(["alternate-codec"],
                         item["guidance"]["variant_gaps"])
        self.assertIn("human-review", item["guidance"]["sources"])
        self.assertIn("variant-coverage", item["guidance"]["sources"])
        variant_plan = item["guidance"]["surface_variant_plan"]
        self.assertEqual("surface-variant-plan-v1",
                         variant_plan["schema_version"])
        self.assertEqual(
            {"positive", "negative", "environment-gap"},
            {row["lane"] for row in variant_plan["lanes"]},
        )
        self.assertEqual(STRATEGY_GUIDANCE_SCHEMA_VERSION,
                         guidance["schema_version"])
        self.assertGreaterEqual(
            guidance["summary"]["replacement_recommendations"], 1)
        encoded = json.dumps((updated, guidance), ensure_ascii=False)
        self.assertNotIn("must not persist", encoded)
        self.assertEqual(STRATEGY_CLAIM_STATUS, guidance["claim_status"])

    def test_guidance_recommends_environment_repair_and_replaces_zero_gain(self):
        strategy = build_research_strategy(
            research_portfolio={
                "schema_version": "research-portfolio-v1",
                "next_probes": [{
                    "research_key": "rk-gap",
                    "candidate_id": "C-gap",
                    "state": "environment-gap",
                    "priority": 5,
                    "research_surface": "web",
                    "target_type": "web-app",
                }],
            },
            target="demo", target_type="web-app")
        strategy["items"][0]["observation"] = {
            "status": "environment-gap", "current_status": "environment-gap",
            "information_gain": 0,
            "missing_observations": ["runtime-availability"],
        }
        updated, guidance = apply_research_guidance(
            strategy,
            {"schema_version": "research-portfolio-v1"}, {}, round_no=5)
        self.assertEqual("repair-environment",
                         updated["items"][0]["guidance"]["next_action"])
        self.assertEqual(3, updated["items"][0]["guidance"]["priority_delta"])
        self.assertFalse(updated["items"][0]["guidance"][
            "replacement_recommended"])
        self.assertEqual(1, guidance["summary"]["environment_repairs"])

        complete = build_research_strategy(
            self._threat_model(), target="demo", target_type="web-app")
        complete["items"][0]["observation"] = {
            "status": "complete", "current_status": "complete",
            "information_gain": 0, "missing_observations": [],
        }
        complete, guidance = apply_research_guidance(
            complete, {"schema_version": "research-portfolio-v1"}, {}, 6)
        completed_item = complete["items"][0]
        self.assertEqual("hold-for-new-evidence",
                         completed_item["guidance"]["next_action"])
        self.assertTrue(completed_item["guidance"][
            "replacement_recommended"])
        self.assertEqual(0, completed_item["guidance"]["priority_delta"])

    def test_guidance_round_trip_is_bounded(self):
        strategy = build_research_strategy(
            self._threat_model(), target="demo", target_type="web-app")
        _strategy, guidance = apply_research_guidance(strategy, {}, {}, 2)
        forged = dict(guidance)
        forged["secret_payload"] = "do-not-persist"
        forged["items"] = list(guidance["items"]) + [{
            "strategy_id": "rs-01234567890123456789",
            "next_action": "execute-raw-command",
            "reviewer_note": "do-not-persist",
            "claim_status": "confirmed",
        }]
        path = write_research_guidance(self.root, "demo", forged)
        loaded = load_research_guidance(self.root, "demo")
        self.assertTrue(path.exists())
        encoded = json.dumps(loaded, ensure_ascii=False)
        self.assertNotIn("do-not-persist", encoded)
        self.assertNotIn("execute-raw-command", encoded)
        self.assertNotIn('"claim_status": "confirmed"', encoded)
        self.assertEqual(STRATEGY_GUIDANCE_SCHEMA_VERSION,
                         loaded["schema_version"])

    def test_strategy_round_trip_is_bounded_and_forces_research_status(self):
        strategy = build_research_strategy(
            self._threat_model(), target="demo", target_type="web-app", round_no=2)
        path = write_research_strategy(self.root, "demo", strategy)
        self.assertEqual(strategy_path(self.root, "demo"), path)
        self.assertEqual(strategy, load_research_strategy(self.root, "demo"))

        forged = dict(strategy)
        forged["secret_payload"] = "do-not-persist"
        forged["items"] = list(strategy["items"]) + [{
            "strategy_id": "raw-id", "kind": "raw-kind",
            "objective": "raw command payload", "claim_status": "confirmed",
        }]
        normalized = normalize_research_strategy(forged)
        encoded = json.dumps(normalized, ensure_ascii=False)
        self.assertNotIn("do-not-persist", encoded)
        self.assertNotIn("raw command payload", encoded)
        self.assertNotIn('"claim_status": "confirmed"', encoded)
        self.assertTrue(all(item["claim_status"] == STRATEGY_CLAIM_STATUS
                            for item in normalized["items"]))

    def test_scheduler_uses_strategy_and_prompt_exposes_it(self):
        model = self._threat_model()
        strategy = build_research_strategy(model, target="demo",
                                            target_type="web-app", round_no=1)
        strategy, _guidance = apply_research_guidance(
            strategy, {"schema_version": "research-portfolio-v1"}, {}, 1)
        candidate = {
            "candidate_id": "C1", "surface": "authorization path",
            "entry": "handle", "input_shape": "request",
            "logic": "command execution path",
            "code_location": ["src/Api.java:20", "src/Task.java:80"],
            "attack_class": "authz", "research_surface": "web",
            "target_type": "web-app",
        }
        context = ScheduleContext(
            entries={"entry-http-1": {"entry_id": "entry-http-1",
                                       "kind": "http", "file": "src/Api.java",
                                       "line": 20}},
            sinks={"sink-exec-1": {"sink_id": "sink-exec-1",
                                    "category": "command-exec",
                                    "file": "src/Task.java", "line": 80,
                                    "severity_hint": "high"}},
            flows=[{"flow_id": "flow-1", "entry_id": "entry-http-1",
                    "sink_id": "sink-exec-1", "path": []}],
            threat_model=model, research_strategy=strategy)
        score = score_candidate(candidate, context)
        self.assertIn("research_strategy", score.evidence)
        self.assertEqual("flow", score.evidence["research_strategy"]["match_kind"])
        self.assertEqual(STRATEGY_CLAIM_STATUS,
                         score.evidence["research_strategy"]["claim_status"])
        self.assertIn("guidance", score.evidence["research_strategy"])
        self.assertEqual(STRATEGY_CLAIM_STATUS,
                         score.evidence["research_strategy"]["guidance"][
                             "claim_status"])
        prompt = prompt_coverage_block(context)
        self.assertIn("研究策略 / Research Strategy", prompt)
        self.assertIn("capability-closure", prompt)
        self.assertIn("not-a-finding", prompt)

    def test_strategy_cli_reads_artifact(self):
        write_research_strategy(self.root, "demo", build_research_strategy(
            self._threat_model(), target="demo", target_type="web-app"))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = agent_cli.main([
                "research-strategy", "demo", "--workspace", str(self.root),
                "--json",
            ])
        self.assertEqual(0, code)
        payload = json.loads(output.getvalue())
        self.assertEqual(STRATEGY_SCHEMA_VERSION,
                         payload["strategy"]["schema_version"])
        self.assertEqual(STRATEGY_CLAIM_STATUS,
                         payload["strategy"]["claim_status"])


if __name__ == "__main__":
    unittest.main()
