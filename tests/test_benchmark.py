"""Regression tests for the deterministic research-quality benchmark."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import agent_cli  # noqa: E402
from agent.evaluation.benchmark import (  # noqa: E402
    BENCHMARK_CLAIM_STATUS,
    BENCHMARK_FEEDBACK_CLAIM_STATUS,
    BENCHMARK_FEEDBACK_FACTORS,
    BENCHMARK_FEEDBACK_SCHEMA_VERSION,
    derive_benchmark_feedback,
    evaluate_benchmark,
    load_benchmark_json,
    validate_manifest,
)


def manifest():
    return {
        "benchmark_id": "test-benchmark",
        "cases": [
            {
                "case_id": "vuln",
                "truth": "vulnerable",
                "expected_status": "confirmed",
                "required_evidence": ["source_to_sink", "runtime_effect", "severity"],
                "expected_severity": {"severity": "High", "score": 8.0},
            },
            {
                "case_id": "negative",
                "truth": "negative",
                "expected_status": "excluded",
                "required_evidence": ["source_to_sink", "negative_runtime"],
                "expected_severity": {"severity": "None", "score": 0.0},
            },
            {
                "case_id": "gap",
                "truth": "environment-gap",
                "expected_status": "candidate",
                "required_evidence": ["environment_gap", "precondition"],
            },
            {
                "case_id": "pending-vuln",
                "truth": "vulnerable",
                "expected_status": "candidate",
                "required_evidence": ["source_to_sink", "runtime_effect", "novelty_status"],
            },
        ],
    }


class BenchmarkTests(unittest.TestCase):

    def test_metrics_distinguish_safe_pending_gap_and_severity_error(self):
        result = evaluate_benchmark(manifest(), [{
            "run_id": "r1",
            "observations": [
                {
                    "case_id": "vuln", "status": "confirmed",
                    "research_events": [
                        {"research_key": "rk-v", "round": 1},
                        {"research_key": "rk-v", "round": 2},
                    ],
                    "evidence": {"source_to_sink": True, "runtime_effect": True,
                                 "severity": True},
                    "cvss": {"score": 9.5, "severity": "Critical"},
                },
                {
                    "case_id": "negative", "status": "candidate",
                    "research_key": "rk-n", "round": 1,
                    "evidence": {"source_to_sink": True, "negative_runtime": True},
                },
                {
                    "case_id": "gap", "status": "candidate",
                    "research_key": "rk-g", "round": 1,
                    "execution_state": "precondition-unavailable",
                    "evidence": {"environment_gap": True, "precondition": True},
                },
                {
                    "case_id": "pending-vuln", "status": "candidate",
                    "research_key": "rk-p", "round": 1,
                    "evidence": {"source_to_sink": True, "runtime_effect": True},
                },
            ],
        }])
        metrics = result["metrics"]
        self.assertEqual(BENCHMARK_CLAIM_STATUS, result["claim_status"])
        self.assertEqual(1.0, metrics["confirmed_recall"])
        self.assertEqual(0.0, metrics["unsafe_confirmation_rate"])
        self.assertEqual(0.0, metrics["negative_result_fidelity"])
        self.assertEqual(1.0, metrics["environment_gap_fidelity"])
        self.assertEqual(0.2, metrics["repeat"]["repeat_rate"])
        self.assertEqual(1.5, metrics["severity_calibration"]["mean_absolute_error"])
        self.assertEqual(1.0, metrics["severity_calibration"]["overstatement_rate"])

    def test_unsafe_confirmation_and_unjustified_repeat_are_visible(self):
        result = evaluate_benchmark(manifest(), [{
            "run_id": "unsafe",
            "observations": [
                {
                    "case_id": "negative", "status": "confirmed",
                    "research_events": [
                        {"research_key": "rk-n", "round": 1},
                        {"research_key": "rk-n", "round": 2, "new_evidence": False},
                    ],
                    "evidence": {"source_to_sink": True, "runtime_effect": True},
                },
            ],
        }])
        metrics = result["metrics"]
        self.assertEqual(1.0, metrics["unsafe_confirmation_rate"])
        self.assertEqual(0.5, metrics["repeat"]["unjustified_repeat_rate"])
        self.assertEqual("unsafe-false-positive",
                         result["case_results"][1]["classification"])

    def test_feedback_is_deterministic_bounded_and_not_a_finding(self):
        result = {
            "benchmark_id": "feedback-test",
            "run_count": 99,
            "case_count": 999,
            "metrics": {
                "unsafe_confirmation_rate": 1.0,
                "evidence_completeness": 0.2,
                "environment_gap_fidelity": 0.1,
                "decision_stability": 0.1,
                "repeat": {"unjustified_repeat_rate": 0.9},
                "severity_calibration": {"overstatement_rate": 0.9},
            },
        }
        first = derive_benchmark_feedback(result)
        second = derive_benchmark_feedback(result)
        self.assertEqual(first, second)
        self.assertEqual(BENCHMARK_FEEDBACK_SCHEMA_VERSION,
                         first["schema_version"])
        self.assertEqual(BENCHMARK_FEEDBACK_CLAIM_STATUS,
                         first["claim_status"])
        self.assertTrue(first["alerts"])
        self.assertTrue({
            "unsafe-confirmation", "evidence-completeness-low",
            "unjustified-repeat-high", "environment-gap-fidelity-low",
            "severity-overstatement-high", "decision-stability-low",
        } <= {item["code"] for item in first["alerts"]})
        self.assertTrue(set(first["weight_deltas"]) <= set(BENCHMARK_FEEDBACK_FACTORS))
        self.assertTrue(all(abs(value) <= 6
                            for value in first["weight_deltas"].values()))
        self.assertNotIn("case_results", first)
        self.assertNotIn("cvss", first)

    def test_feedback_without_metrics_is_empty(self):
        self.assertEqual({}, derive_benchmark_feedback({"benchmark_id": "empty"}))

    def test_sample_manifest_and_cli_are_machine_readable(self):
        gold = load_benchmark_json(ROOT / "benchmarks" / "research-benchmark-v1.json")
        run = load_benchmark_json(ROOT / "benchmarks" / "research-benchmark-sample-run.json")
        result = evaluate_benchmark(gold, [run])
        self.assertEqual(7, result["case_count"])
        self.assertEqual(1.0, result["metrics"]["negative_result_fidelity"])
        self.assertEqual(1.0, result["metrics"]["environment_gap_fidelity"])
        self.assertGreater(result["metrics"]["severity_calibration"]["overstatement_rate"], 0)
        self.assertEqual(BENCHMARK_CLAIM_STATUS,
                         result["metrics"]["claim_status"])

        with tempfile.TemporaryDirectory(prefix="vulngate-benchmark-") as td:
            out_path = Path(td) / "result.json"
            feedback_path = Path(td) / "feedback.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = agent_cli.main([
                    "benchmark", "--manifest",
                    str(ROOT / "benchmarks" / "research-benchmark-v1.json"),
                    "--run", str(ROOT / "benchmarks" / "research-benchmark-sample-run.json"),
                    "--out", str(out_path), "--feedback-out", str(feedback_path),
                    "--json",
                ])
            self.assertEqual(0, code)
            self.assertTrue(out_path.exists())
            self.assertEqual("research-benchmark-v1",
                             json.loads(out_path.read_text(encoding="utf-8"))["schema_version"])
            feedback = json.loads(feedback_path.read_text(encoding="utf-8"))
            self.assertEqual(BENCHMARK_FEEDBACK_SCHEMA_VERSION,
                             feedback["schema_version"])
            self.assertIn("feedback", json.loads(stdout.getvalue()))
            self.assertIn("case_results", stdout.getvalue())

    def test_cross_surface_manifest_preserves_profile_and_gap_contract(self):
        gold_path = ROOT / "benchmarks" / "research-benchmark-surfaces-v1.json"
        run_path = ROOT / "benchmarks" / "research-benchmark-surfaces-sample-run.json"
        gold = load_benchmark_json(gold_path)
        run = load_benchmark_json(run_path)

        self.assertEqual([], validate_manifest(gold))
        result = evaluate_benchmark(gold, [run])
        self.assertEqual(15, result["case_count"])
        self.assertEqual(
            ["cloud", "mobile", "native", "protocol", "web"],
            result["research_profile"]["surfaces"],
        )
        self.assertEqual(1.0, result["metrics"]["evidence_completeness"])
        self.assertEqual(1.0, result["metrics"]["negative_result_fidelity"])
        self.assertEqual(1.0, result["metrics"]["environment_gap_fidelity"])
        self.assertEqual(0.0, result["metrics"]["unsafe_confirmation_rate"])
        self.assertEqual(
            {"cloud", "mobile", "native", "protocol", "web"},
            set(result["metrics"]["coverage_by_surface"]),
        )
        for surface, metrics in result["metrics"]["coverage_by_surface"].items():
            self.assertEqual(3, metrics["case_results"], surface)
            self.assertEqual(1.0, metrics["observation_coverage"], surface)
            self.assertEqual(0.0, metrics["unsafe_confirmation_rate"], surface)
            self.assertEqual(1.0, metrics["environment_gap_fidelity"], surface)
            self.assertEqual(1.0, metrics["evidence_completeness"], surface)
        self.assertEqual(
            "tenant-object-authorization",
            result["case_results"][0]["variant"],
        )
        self.assertEqual(BENCHMARK_CLAIM_STATUS, result["claim_status"])

    def test_manifest_rejects_unknown_research_surface(self):
        bad = {
            "schema_version": "research-benchmark-v1",
            "cases": [{
                "case_id": "bad-surface",
                "truth": "vulnerable",
                "surface": "unknown",
            }],
        }
        self.assertIn("case[0] has unsupported surface", validate_manifest(bad))


if __name__ == "__main__":
    unittest.main()
