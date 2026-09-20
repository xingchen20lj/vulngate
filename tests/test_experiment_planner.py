import sys
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.tools.experiment_planner import plan_candidate_experiments  # noqa: E402
from agent.evaluation.benchmark import BENCHMARK_FEEDBACK_SCHEMA_VERSION  # noqa: E402
from agent.autonomous.run_agent import (  # noqa: E402
    AutoCtx, _attach_experiment_plans,
)
from agent.orchestrator.config import TargetConfig  # noqa: E402


class ExperimentPlannerTests(unittest.TestCase):
    def test_benchmark_feedback_adds_bounded_observation_without_changing_claims(self):
        feedback = {
            "schema_version": BENCHMARK_FEEDBACK_SCHEMA_VERSION,
            "benchmark_id": "planner-feedback",
            "alerts": [{
                "code": "severity-overstatement-high", "priority": "medium",
                "metric": "severity_overstatement_rate", "value": 0.5,
                "threshold": 0.2, "direction": "gt",
                "action": "tighten-severity-calibration",
            }],
            "weight_deltas": {"evidence_quality": 2,
                              "sink_impact": -1,
                              "coverage_novelty": -1},
            "planner_guidance": {
                "strategy_tags": ["benchmark-severity-calibration"],
                "required_observations": [
                    "severity must be consistent with observed typed effect and precondition tier",
                ],
                "falsifiers": [
                    "an unobserved stronger effect keeps the conservative severity",
                ],
            },
            "surface_guidance": [{
                "surface": "web",
                "priority_delta": 2,
                "metric_snapshot": {"evidence_completeness": 0.5},
                "strategy_tags": ["benchmark-surface-coverage"],
                "required_observations": [
                    "each research surface needs an observed status or explicit execution gap",
                ],
                "falsifiers": ["unobserved surface coverage is not evidence of absence"],
            }],
            "claim_status": "not-a-finding",
        }
        result = plan_candidate_experiments(
            {"candidate_id": "B-FEEDBACK", "surface": "web"},
            benchmark_feedback=feedback)
        baseline = next(item for item in result["plans"]
                        if item["kind"] == "baseline")
        self.assertIn("benchmark-severity-calibration", result["strategy_tags"])
        self.assertIn("severity must be consistent with observed typed effect and precondition tier",
                      baseline["required_observations"])
        self.assertIn("benchmark-surface-coverage", result["strategy_tags"])
        self.assertIn(
            "each research surface needs an observed status or explicit execution gap",
            baseline["required_observations"])
        self.assertEqual("planner-feedback",
                         result["benchmark_guidance"]["source_benchmark_id"])
        self.assertEqual("web", result["benchmark_guidance"]["surface"])
        self.assertEqual(2, result["benchmark_guidance"]["surface_priority_delta"])
        self.assertEqual("not-a-finding", result["provenance"]["claim_status"])
        self.assertNotIn("cvss", str(result).lower())

    def test_race_dos_plan_requires_actual_availability_evidence(self):
        candidate = {
            "candidate_id": "R1",
            "surface": "stateful race denial of service",
            "sequence": ["seed", "mutate", "probe"],
            "concurrency": 8,
            "availability_probe": True,
        }

        result = plan_candidate_experiments(candidate, ["1.0"])
        kinds = {item["kind"] for item in result["plans"]}
        availability = next(item for item in result["plans"]
                            if item["kind"] == "concurrency-availability")

        self.assertTrue({"baseline", "state-sequence", "concurrency-availability"}
                        <= kinds)
        self.assertIn("CONCURRENCY>=2", availability["required_observations"])
        self.assertIn("SERVICE_UNAVAILABLE=true or equivalent",
                      availability["required_observations"])
        self.assertEqual("not-a-finding", result["provenance"]["claim_status"])

    def test_authz_plan_keeps_only_credential_free_case_ids(self):
        candidate = {
            "candidate_id": "A1",
            "category": "authz",
            "surface": "cross-tenant object authorization bypass",
            "authz_cases": [{
                "case_id": "cross-tenant",
                "principal": "user-b",
                "tenant_id": "tenant-b",
                "object_tenant_id": "tenant-a",
                "token": "SECRET-TOKEN",
                "cookie": "SECRET-COOKIE",
                "password": "SECRET-PASSWORD",
                "expected_authz": "deny",
            }],
        }

        result = plan_candidate_experiments(candidate)
        authz_plan = next(item for item in result["plans"]
                          if item["kind"] == "authorization-boundary")

        self.assertEqual(["cross-tenant"], authz_plan["cases"])
        self.assertNotIn("SECRET-TOKEN", str(result))
        self.assertNotIn("SECRET-COOKIE", str(result))
        self.assertNotIn("SECRET-PASSWORD", str(result))

    def test_variant_and_typed_effect_plan_require_before_after_observations(self):
        candidate = {
            "candidate_id": "V1",
            "surface": "fix-completeness residual command execution variant",
            "fix_completeness": True,
        }

        result = plan_candidate_experiments(candidate, ["1.0", "1.1", "1.2"])
        by_kind = {item["kind"]: item for item in result["plans"]}

        self.assertIn("fix-variant-comparison", by_kind)
        self.assertIn("typed-effect", by_kind)
        self.assertEqual(
            [{"before": "1.0", "after": "1.1"},
             {"before": "1.1", "after": "1.2"}],
            by_kind["fix-variant-comparison"]["version_pairs"],
        )
        self.assertIn("pre-fix failure/effect observation",
                      by_kind["fix-variant-comparison"]["required_observations"])
        self.assertIn("EFFECT_KIND", by_kind["typed-effect"]["required_observations"])

    def test_capability_chain_plan_requires_each_primitive_transition_and_effect(self):
        candidate = {
            "candidate_id": "CAP1",
            "surface": "capability-chain: read -> credential-read -> exec",
            "attack_class": "capability-chain",
            "required_capabilities": ["read", "credential-read", "exec"],
            "observed_capabilities": ["read"],
            "missing_capabilities": ["credential-read", "exec"],
            "transition_rules": [
                {"from": "read", "to": "credential-read", "declared": False},
                {"from": "credential-read", "to": "exec", "declared": False},
            ],
            "runtime_required": True,
        }

        result = plan_candidate_experiments(candidate, ["1.0"])
        plan = next(item for item in result["plans"]
                    if item["kind"] == "capability-transition")

        self.assertIn("capability-chain", result["strategy_tags"])
        self.assertEqual(result["capability_contract"]["required_capabilities"],
                         ["read", "credential-read", "exec"])
        self.assertIn("CAPABILITY_TRACE for declared primitive ids",
                      plan["required_observations"])
        self.assertIn("CAPABILITY_EVIDENCE for each emitted primitive",
                      plan["required_observations"])
        self.assertIn("TRANSITION_TRACE for each declared transition",
                      plan["required_observations"])
        self.assertIn("EFFECT_KIND and EFFECT for typed effect",
                      plan["required_observations"])
        self.assertEqual(result["provenance"]["claim_status"], "not-a-finding")

    def test_plan_is_deterministic_and_bounded(self):
        candidate = {
            "candidate_id": "B1",
            "surface": "race cache authz command fix variant",
            "sequence": ["step-%03d" % index for index in range(100)],
            "authz_cases": [{"case_id": "case-%03d" % index}
                            for index in range(100)],
            "preconditions": ["pre-%03d" % index for index in range(100)],
        }

        first = plan_candidate_experiments(candidate, [str(index) for index in range(100)])
        second = plan_candidate_experiments(candidate, [str(index) for index in range(100)])

        self.assertEqual(first, second)
        self.assertLessEqual(len(first["plans"]), 6)
        self.assertLessEqual(len(first["matrix_axes"]["versions"]), 16)
        state_plan = next(item for item in first["plans"]
                          if item["kind"] == "state-sequence")
        self.assertLessEqual(len(state_plan["sequence"]), 16)
        self.assertLessEqual(len(first["matrix_axes"]["preconditions"]), 8)
        self.assertLessEqual(len(first["matrix_axes"]["authz_cases"]), 16)

    def test_autonomous_plan_covers_deferred_pool_and_marks_schedule(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = TargetConfig(name="planner-auto", discovery_date="2026-09-20",
                               jars=[{"version": "1.0", "path": "demo.jar"}])
            ctx = AutoCtx(root, cfg, llm=None, offline=True,
                          max_candidates=1, max_rounds=1)
            selected = [{"candidate_id": "selected", "surface": "authz bypass"}]
            pool = selected + [{"candidate_id": "deferred", "surface": "state race"}]

            plans = _attach_experiment_plans(ctx, 1, selected, pool)
            by_id = {item["candidate_id"]: item for item in plans}
            artifact = json.loads(
                (root / "state" / "planner-auto" / "round-01" / "S2" /
                 "experiment-plans.json").read_text(encoding="utf-8"))

            self.assertEqual({"selected", "deferred"}, set(by_id))
            self.assertTrue(by_id["selected"]["scheduled"])
            self.assertFalse(by_id["deferred"]["scheduled"])
            self.assertEqual(plans, artifact)


if __name__ == "__main__":
    unittest.main()
