"""Tests for the bounded project-level research portfolio."""

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

from agent.evaluation.benchmark import (  # noqa: E402
    BENCHMARK_FEEDBACK_SCHEMA_VERSION,
    BENCHMARK_TREND_SCHEMA_VERSION,
)
from agent.analysis.inventory import CoverageStore  # noqa: E402
from agent.analysis.scheduler import (  # noqa: E402
    ScheduleContext,
    prompt_coverage_block,
    score_candidate,
)
import agent_cli  # noqa: E402
from agent.memory.portfolio import (  # noqa: E402
    PORTFOLIO_CLAIM_STATUS,
    PORTFOLIO_SCHEMA_VERSION,
    build_research_portfolio,
    load_research_portfolio,
    normalize_research_portfolio,
    write_research_portfolio,
)
from agent.memory.surface_coverage import (  # noqa: E402
    SURFACE_LANE_COVERAGE_SCHEMA_VERSION,
)
from agent.memory.research import (  # noqa: E402
    STATE_RESIDUAL_FALSIFIED,
    STATE_INCONCLUSIVE,
    STATE_ENVIRONMENT_GAP,
    STATE_PENDING_RESIDUAL,
    build_round_memory,
    merge_research_memory,
    residual_meta,
    research_key,
)


def candidate(candidate_id: str, **extra):
    value = {
        "candidate_id": candidate_id,
        "surface": "explicit research surface",
        "entry": "handle",
        "input_shape": "bounded request",
        "logic": "candidate logic",
        "code_location": ["src/Handler.java:42"],
        "target_classes": ["com.example.Target"],
    }
    value.update(extra)
    return value


def lab_for(candidate_id: str, diff_status: str = "no-difference",
            replay_status: str = "stable", reproduces=True):
    return {
        "fixtures": [{
            "fixture": {
                "candidate_id": candidate_id,
                "fixture_id": "fixture-%s" % candidate_id,
                "fixture_kind": "bounded",
            },
            "replay": {"status": replay_status, "attempts": 2},
            "reproduces_expected": reproduces,
            "differential": {
                "status": diff_status,
                "primary_version": "v2",
                "differences": [],
                "inconclusive_cells": [],
            },
        }],
        "claim_status": "not-a-finding",
    }


class ResearchPortfolioTests(unittest.TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vulngate-portfolio-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    def _lane_witness(self, status="partial"):
        observed = ["execution", "state-sequence"]
        missing = ["typed-effect"]
        if status == "observed":
            observed.append("typed-effect")
            missing = []
        if status == "environment-gap":
            observed = ["environment-gap"]
            missing = ["execution", "state-sequence", "typed-effect"]
        return {
            "schema_version": "surface-variant-evidence-v1",
            "fixture_key": "vf-" + "a" * 20,
            "surface": "protocol",
            "variant_id": "protocol-frame-state-order",
            "lane": "positive",
            "expected_observation": "typed-effect",
            "required_observations": ["execution", "state-sequence",
                                       "typed-effect"],
            "observed_signals": observed,
            "missing_observations": missing,
            "falsifier_signals": ["typed-effect-missing"] if missing else [],
            "sequence_statuses": ["complete" if status == "observed"
                                  else "partial"],
            "cells_observed": 1 if status != "environment-gap" else 0,
            "cells_with_gap": 1 if status == "environment-gap" else 0,
            "status": status,
            "cells": [{
                "version": "1.0", "safe_mode": False,
                "status": "environment-gap"
                if status == "environment-gap" else "observed",
                "signals": observed,
                "sequence_status": "complete"
                if status == "observed" else "partial",
                "typed_effect_observed": status == "observed",
            }],
            "raw_output": "secret=not-persist",
        }

    def _memory(self):
        web = candidate(
            "WEB-1", research_surface="web", target_type="web-app",
            surface="web authorization path",
            attack_class="authorization", variant="tenant-object",
            precondition_class="app-cooperation",
            fix_variants=["ownership-check"],
        )
        protocol = candidate(
            "PROTO-1", research_surface="protocol", target_type="message-rpc",
            surface="protocol serializer path",
            attack_class="deserialization", variant="serializer-guard",
            precondition_class="single-feature",
        )
        cloud = candidate(
            "CLOUD-1", research_surface="cloud", target_type="cloud-service",
            surface="cloud metadata path",
            attack_class="ssrf", variant="provider-emulator",
            precondition_class="app-cooperation",
        )
        memory = merge_research_memory(
            {}, build_round_memory([web], {"WEB-1": {}}, {},
                                   lab_for("WEB-1"), 1))
        memory = merge_research_memory(
            memory, build_round_memory([protocol], {"PROTO-1": {}}, {},
                                       lab_for("PROTO-1", "difference-observed"), 2))
        memory = merge_research_memory(
            memory, build_round_memory([cloud], {"CLOUD-1": {}}, {},
                                       lab_for("CLOUD-1", "inconclusive",
                                               "precondition-unavailable", None), 3))
        return memory, web, protocol, cloud

    def test_portfolio_aggregates_surface_variants_and_next_probes(self):
        memory, web, protocol, cloud = self._memory()
        feedback = {
            "schema_version": BENCHMARK_FEEDBACK_SCHEMA_VERSION,
            "benchmark_id": "benchmark-current",
            "trend": {
                "schema_version": BENCHMARK_TREND_SCHEMA_VERSION,
                "baseline_benchmark_id": "benchmark-old",
                "current_benchmark_id": "benchmark-current",
                "regressions": [{
                    "metric": "evidence_completeness",
                    "baseline": 0.9, "current": 0.7,
                    "delta": -0.2, "threshold": 0.0,
                }],
                "surface_regressions": [{
                    "surface": "cloud", "metric": "environment_gap_fidelity",
                    "baseline": 0.9, "current": 0.5,
                    "delta": -0.4, "threshold": 0.0,
                }],
                "status": "regressed",
                "claim_status": "not-a-finding",
            },
        }
        reviews = {"entries": [{
            "research_key": research_key(protocol),
            "status": "needs-evidence",
            "reason_code": "missing-typed-effect",
            "reviewer_note": "secret-review-note",
            "next_probe_hints": ["add an independent typed-effect observation"],
            "round": 3,
        }]}
        portfolio = build_research_portfolio(memory, reviews, feedback)

        self.assertEqual(PORTFOLIO_SCHEMA_VERSION, portfolio["schema_version"])
        self.assertEqual(PORTFOLIO_CLAIM_STATUS, portfolio["claim_status"])
        self.assertEqual(3, portfolio["summary"]["mechanism_count"])
        self.assertEqual(1, portfolio["summary"]["stable_mechanisms"])
        self.assertEqual(1, portfolio["summary"]["actionable_differences"])
        self.assertEqual(1, portfolio["summary"]["unresolved_mechanisms"])
        self.assertEqual({"web", "protocol", "cloud"}, {
            row["value"] for row in portfolio["dimensions"]["research_surface"]
        })
        variants = {row["variant"]: row for row in portfolio["variant_coverage"]}
        self.assertEqual("stable-observed", variants["tenant-object"]["status"])
        self.assertEqual("gap", variants["provider-emulator"]["status"])
        self.assertEqual("regressed",
                         portfolio["benchmark"]["trend"]["status"])
        self.assertIn("CLOUD-1", json.dumps(portfolio, ensure_ascii=False))
        self.assertNotIn("secret-review-note", json.dumps(portfolio, ensure_ascii=False))
        self.assertNotIn("payload", json.dumps(portfolio, ensure_ascii=False).lower())
        self.assertEqual("not-a-finding",
                         portfolio["next_probes"][0]["claim_status"])
        self.assertGreaterEqual(portfolio["next_probes"][0]["priority"], 4)

        # Building the same view twice is safe for resumable S8 and produces
        # byte-for-byte equivalent JSON semantics.
        self.assertEqual(
            portfolio,
            build_research_portfolio(memory, reviews, feedback),
        )

    def test_surface_lane_coverage_preserves_latest_state_and_schedules_gap(self):
        c = candidate(
            "LANE-1", research_surface="protocol", target_type="message-rpc",
            attack_class="parser", variant="state-order",
        )
        lab = lab_for("LANE-1")
        lab["fixtures"][0]["variant_evidence"] = self._lane_witness()
        memory = build_round_memory([c], {"LANE-1": {}}, {}, lab, 1)
        portfolio = build_research_portfolio(memory)
        coverage = portfolio["surface_lane_coverage"]
        self.assertEqual(SURFACE_LANE_COVERAGE_SCHEMA_VERSION,
                         coverage["schema_version"])
        row = coverage["lanes"][0]
        self.assertEqual("partial", row["status"])
        self.assertEqual(["typed-effect"], row["missing_observations"])
        self.assertEqual(["execution", "state-sequence"],
                         sorted(row["latest_observed_signals"]))
        probe = next(item for item in portfolio["next_probes"]
                     if item.get("reason_code") == "surface-lane-witness")
        self.assertEqual(STATE_INCONCLUSIVE, probe["state"])
        self.assertEqual("protocol-frame-state-order",
                         probe["surface_variant_id"])
        self.assertEqual("positive", probe["surface_lane"])
        self.assertIn("补 typed-effect", " ".join(probe["next_probe_hints"]))
        self.assertNotIn("secret=not-persist",
                         json.dumps(portfolio, ensure_ascii=False))
        prompt = prompt_coverage_block(
            ScheduleContext.from_store(
                CoverageStore(self.root, "target"),
                research_portfolio=portfolio))
        self.assertIn("protocol-frame-state-order", prompt)
        self.assertIn("surface-lane-witness", prompt)

        observed_lab = lab_for("LANE-1")
        observed_lab["fixtures"][0]["variant_evidence"] = self._lane_witness(
            "observed")
        later = build_round_memory([c], {"LANE-1": {}}, {}, observed_lab, 2)
        merged = merge_research_memory(memory, later)
        latest = build_research_portfolio(merged)
        latest_row = latest["surface_lane_coverage"]["lanes"][0]
        self.assertEqual("observed", latest_row["status"])
        self.assertEqual(2, latest_row["latest_round"])
        self.assertEqual({"partial": 1, "observed": 1},
                         latest_row["status_counts"])
        self.assertFalse(any(item.get("reason_code") == "surface-lane-witness"
                             for item in latest["next_probes"]))

    def test_surface_lane_environment_gap_remains_gap_after_portfolio_normalization(self):
        c = candidate(
            "LANE-GAP", research_surface="cloud", target_type="cloud-service",
            attack_class="ssrf", variant="metadata-boundary",
        )
        lab = lab_for("LANE-GAP")
        lab["fixtures"][0]["variant_evidence"] = self._lane_witness(
            "environment-gap")
        memory = build_round_memory([c], {"LANE-GAP": {}}, {}, lab, 3)
        portfolio = build_research_portfolio(memory)
        normalized = normalize_research_portfolio(portfolio)
        row = normalized["surface_lane_coverage"]["lanes"][0]
        self.assertEqual("environment-gap", row["status"])
        self.assertEqual(1, normalized["surface_lane_coverage"]["summary"]
                         ["environment_gap_lanes"])
        probe = next(item for item in normalized["next_probes"]
                     if item.get("reason_code") == "surface-lane-witness")
        self.assertEqual(STATE_ENVIRONMENT_GAP, probe["state"])
        self.assertIn("缺口不等于安全", " ".join(probe["next_probe_hints"]))
        self.assertEqual("not-a-finding", row["claim_status"])

    def test_portfolio_round_trip_is_bounded_and_rejects_unknown_fields(self):
        memory, _web, _protocol, _cloud = self._memory()
        portfolio = build_research_portfolio(memory)
        path = write_research_portfolio(self.root, "target", portfolio)
        self.assertTrue(path.exists())
        loaded = load_research_portfolio(self.root, "target")
        self.assertEqual(portfolio, loaded)

        forged = dict(portfolio)
        forged["secret_payload"] = "do-not-copy"
        forged["next_probes"] = list(portfolio["next_probes"]) + [{
            "research_key": "rk-forged", "state": "environment-gap",
            "payload": "raw payload", "claim_status": "confirmed",
        }]
        forged["surface_lane_coverage"] = {
            "schema_version": SURFACE_LANE_COVERAGE_SCHEMA_VERSION,
            "lanes": [{
                "surface": "protocol",
                "variant_id": "protocol-frame-state-order",
                "lane": "positive",
                "status": "partial",
                "raw_output": "secret=not-persist",
            }],
            "raw_payload": "raw payload",
        }
        normalized = normalize_research_portfolio(forged)
        encoded = json.dumps(normalized, ensure_ascii=False)
        self.assertNotIn("do-not-copy", encoded)
        self.assertNotIn("raw payload", encoded)
        self.assertNotIn("secret=not-persist", encoded)
        self.assertNotIn('"claim_status": "confirmed"', encoded)
        self.assertEqual("not-a-finding", normalized["claim_status"])

    def test_residual_probe_survives_stable_replay_and_normalization(self):
        residual_candidate = candidate(
            "RES-1", research_surface="web", target_type="web-app",
            surface="web parser variant", attack_class="parser",
            variant="alternate-codec", precondition_class="single-feature",
            residuals=[{
                "kind": "variant",
                "reason_code": "unverified",
                "probe_plan": "secret raw probe should not persist",
            }])
        memory = merge_research_memory(
            {}, build_round_memory([residual_candidate], {"RES-1": {}}, {},
                                   lab_for("RES-1"), 4))
        portfolio = build_research_portfolio(memory)
        self.assertEqual(1, portfolio["summary"]["pending_residuals"])
        self.assertEqual(1, portfolio["summary"]["unresolved_mechanisms"])
        probe = next(item for item in portfolio["next_probes"]
                     if item.get("state") == STATE_PENDING_RESIDUAL)
        self.assertTrue(probe["residual_id"])
        self.assertEqual("variant", probe["residual_kind"])
        self.assertEqual("unverified", probe["residual_reason_code"])
        self.assertEqual("s3-residual", probe["reason_code"])
        self.assertEqual("not-a-finding", probe["claim_status"])
        self.assertIn("执行已声明的有界 residual probe",
                      json.dumps(portfolio, ensure_ascii=False))
        self.assertNotIn("secret raw probe", json.dumps(portfolio, ensure_ascii=False))

        normalized = normalize_research_portfolio(portfolio)
        normalized_probe = next(item for item in normalized["next_probes"]
                                if item.get("state") == STATE_PENDING_RESIDUAL)
        self.assertEqual(probe["residual_id"], normalized_probe["residual_id"])
        self.assertEqual("not-a-finding", normalized_probe["claim_status"])

    def test_falsified_residual_leaves_no_duplicate_portfolio_probe(self):
        residual_candidate = candidate(
            "RES-CLOSED", research_surface="web", target_type="web-app",
            residuals=[{
                "kind": "variant", "reason_code": "unverified",
                "probe_plan": "bounded residual probe",
            }])
        residual = residual_meta(residual_candidate)[0]
        summary = {"residual_falsifiers": [{
            "residual_id": residual["residual_id"], "status": "falsified",
            "falsifier_code": residual["allowed_falsifiers"][0],
            "execution_state": "executed", "effect_observed": False,
            "contract_declared": True, "cell_ref": "s4c-closed",
        }]}
        memory = merge_research_memory(
            {}, build_round_memory([residual_candidate], {"RES-CLOSED": summary},
                                   {}, None, 5))
        row = memory["entries"][0]["residuals"][0]
        self.assertEqual(STATE_RESIDUAL_FALSIFIED, row["state"])
        portfolio = build_research_portfolio(memory)
        self.assertEqual(0, portfolio["summary"]["pending_residuals"])
        self.assertFalse(any(item.get("residual_id") == residual["residual_id"]
                             for item in portfolio["next_probes"]))

    def test_same_mechanism_keeps_multiple_variant_labels_after_merge(self):
        first = candidate(
            "VAR-1", research_surface="protocol", target_type="message-rpc",
            surface="same mechanism", attack_class="deserialization",
            variant="serializer-a", precondition_class="single-feature",
        )
        second = candidate(
            "VAR-2", research_surface="protocol", target_type="message-rpc",
            surface="same mechanism", attack_class="deserialization",
            variant="serializer-b", precondition_class="app-cooperation",
        )
        first_memory = build_round_memory(
            [first], {"VAR-1": {}}, {}, lab_for("VAR-1"), 1)
        second_memory = build_round_memory(
            [second], {"VAR-2": {}}, {}, lab_for("VAR-2"), 2)
        self.assertEqual(first_memory["entries"][0]["research_key"],
                         second_memory["entries"][0]["research_key"])
        merged = merge_research_memory(first_memory, second_memory)
        portfolio = build_research_portfolio(merged)
        variants = {row["variant"] for row in portfolio["variant_coverage"]}
        preconditions = {
            row["value"] for row in portfolio["dimensions"]["precondition_class"]
        }
        self.assertIn("serializer-a", variants)
        self.assertIn("serializer-b", variants)
        self.assertEqual({"single-feature", "app-cooperation"}, preconditions)

    def test_scheduler_prompt_exposes_portfolio_as_research_context(self):
        memory, _web, _protocol, _cloud = self._memory()
        portfolio = build_research_portfolio(memory)
        store = CoverageStore(self.root, "target")
        context = ScheduleContext.from_store(
            store, research_portfolio=portfolio)
        prompt = prompt_coverage_block(context)
        self.assertIn("项目级研究组合 / Project Research Portfolio", prompt)
        self.assertIn("provider-emulator", prompt)
        self.assertIn("not-a-finding", prompt)

    def test_scheduler_gives_only_bounded_boost_to_matching_next_probe(self):
        memory, _web, protocol, _cloud = self._memory()
        portfolio = build_research_portfolio(memory)
        before = score_candidate(protocol, ScheduleContext())
        after = score_candidate(
            protocol, ScheduleContext(research_portfolio=portfolio))
        self.assertGreater(after.total, before.total)
        guidance = after.evidence["research_portfolio"]
        self.assertEqual("research-key", guidance["match_kind"])
        self.assertEqual("not-a-finding", guidance["claim_status"])
        self.assertLessEqual(guidance["applied_delta"], 2.0)

    def test_portfolio_cli_reads_and_rebuilds_the_bounded_artifact(self):
        memory, _web, _protocol, _cloud = self._memory()
        write_research_portfolio(
            self.root, "target", build_research_portfolio(memory))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = agent_cli.main([
                "portfolio", "target", "--workspace", str(self.root), "--json",
            ])
        self.assertEqual(0, code)
        payload = json.loads(output.getvalue())
        self.assertEqual("research-portfolio-v1",
                         payload["portfolio"]["schema_version"])
        self.assertEqual("not-a-finding", payload["portfolio"]["claim_status"])
        text_output = io.StringIO()
        with contextlib.redirect_stdout(text_output):
            code = agent_cli.main([
                "portfolio", "target", "--workspace", str(self.root),
            ])
        self.assertEqual(0, code)
        self.assertIn("lanes=0", text_output.getvalue())


if __name__ == "__main__":
    unittest.main()
