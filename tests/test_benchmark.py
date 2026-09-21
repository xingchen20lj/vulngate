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
    HISTORICAL_CVE_BENCHMARK_SCHEMA_VERSION,
    compare_benchmark_results,
    derive_benchmark_feedback,
    evaluate_benchmark,
    load_benchmark_json,
    normalize_benchmark_feedback,
    normalize_manifest,
    normalize_benchmark_trend,
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

    def test_feedback_derives_surface_specific_bounded_guidance(self):
        result = {
            "benchmark_id": "surface-feedback",
            "run_count": 1,
            "case_count": 6,
            "metrics": {
                "coverage_by_surface": {
                    "web": {
                        "observation_coverage": 0.5,
                        "unsafe_confirmation_rate": 0.25,
                        "environment_gap_fidelity": 0.5,
                        "evidence_completeness": 0.5,
                    },
                    "native": {
                        "observation_coverage": 1.0,
                        "unsafe_confirmation_rate": 0.0,
                        "environment_gap_fidelity": 1.0,
                        "evidence_completeness": 1.0,
                    },
                },
            },
        }
        feedback = derive_benchmark_feedback(result)
        self.assertEqual(["web"], [
            item["surface"] for item in feedback["surface_guidance"]])
        guidance = feedback["surface_guidance"][0]
        self.assertEqual(6, guidance["priority_delta"])
        self.assertEqual(0.5, guidance["metric_snapshot"]["evidence_completeness"])
        self.assertIn("benchmark-surface-coverage", guidance["strategy_tags"])
        self.assertIn("benchmark-confirmation-safety", guidance["strategy_tags"])
        self.assertEqual(BENCHMARK_FEEDBACK_CLAIM_STATUS,
                         guidance["claim_status"])
        self.assertNotIn("case_results", guidance)

    def test_surface_feedback_normalization_is_allowlisted_and_bounded(self):
        feedback = normalize_benchmark_feedback({
            "schema_version": BENCHMARK_FEEDBACK_SCHEMA_VERSION,
            "benchmark_id": "surface-normalization",
            "surface_guidance": [
                {
                    "surface": "WEB",
                    "priority_delta": 999,
                    "metric_snapshot": {
                        "evidence_completeness": 99,
                        "unsafe_confirmation_rate": -4,
                        "raw_payload": "discard-me",
                    },
                    "strategy_tags": ["benchmark-surface-coverage", "unknown"],
                    "required_observations": [
                        "each research surface needs an observed status or explicit execution gap",
                        "untrusted prose",
                    ],
                    "falsifiers": ["unobserved surface coverage is not evidence of absence"],
                    "case_results": ["discard-me"],
                },
                {"surface": "mars", "priority_delta": 6},
            ],
        })
        self.assertEqual(1, len(feedback["surface_guidance"]))
        guidance = feedback["surface_guidance"][0]
        self.assertEqual("web", guidance["surface"])
        self.assertEqual(6, guidance["priority_delta"])
        self.assertEqual(1.0, guidance["metric_snapshot"]["evidence_completeness"])
        self.assertEqual(0.0, guidance["metric_snapshot"]["unsafe_confirmation_rate"])
        self.assertNotIn("case_results", guidance)

    def test_benchmark_trend_detects_global_and_surface_regression(self):
        baseline = {
            "benchmark_id": "baseline",
            "metrics": {
                "case_observation_coverage": 1.0,
                "confirmed_precision": 1.0,
                "negative_result_fidelity": 1.0,
                "environment_gap_fidelity": 1.0,
                "evidence_completeness": 1.0,
                "severity_calibration": {
                    "overstatement_rate": 0.0,
                    "mean_absolute_error": 0.0,
                },
                "coverage_by_surface": {
                    "web": {
                        "observation_coverage": 1.0,
                        "unsafe_confirmation_rate": 0.0,
                        "environment_gap_fidelity": 1.0,
                        "evidence_completeness": 1.0,
                    },
                },
            },
        }
        current = {
            "benchmark_id": "current",
            "metrics": {
                "case_observation_coverage": 0.8,
                "confirmed_precision": 0.9,
                "negative_result_fidelity": 0.8,
                "environment_gap_fidelity": 0.8,
                "evidence_completeness": 0.8,
                "severity_calibration": {
                    "overstatement_rate": 0.2,
                    "mean_absolute_error": 1.0,
                },
                "coverage_by_surface": {
                    "web": {
                        "observation_coverage": 1.0,
                        "unsafe_confirmation_rate": 0.2,
                        "environment_gap_fidelity": 1.0,
                        "evidence_completeness": 0.7,
                    },
                },
            },
        }
        trend = compare_benchmark_results(current, baseline)
        self.assertEqual("research-benchmark-trend-v1",
                         trend["schema_version"])
        self.assertEqual("regressed", trend["status"])
        self.assertIn("evidence_completeness",
                      {item["metric"] for item in trend["regressions"]})
        self.assertEqual("web", trend["surface_regressions"][0]["surface"])
        normalized = normalize_benchmark_trend(trend)
        self.assertEqual(len(trend["regressions"]),
                         len(normalized["regressions"]))
        feedback = derive_benchmark_feedback(dict(current, trend=trend))
        self.assertIn("benchmark-regression",
                      {item["code"] for item in feedback["alerts"]})
        web_guidance = next(item for item in feedback["surface_guidance"]
                            if item["surface"] == "web")
        self.assertIn("benchmark-regression-control",
                      web_guidance["strategy_tags"])
        self.assertGreaterEqual(web_guidance["priority_delta"], 2)

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
            baseline_path = Path(td) / "baseline.json"
            baseline_path.write_text(json.dumps(result), encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = agent_cli.main([
                    "benchmark", "--manifest",
                    str(ROOT / "benchmarks" / "research-benchmark-v1.json"),
                    "--run", str(ROOT / "benchmarks" / "research-benchmark-sample-run.json"),
                    "--baseline", str(baseline_path),
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
            self.assertEqual("stable", json.loads(stdout.getvalue())["trend"]["status"])
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

    def test_historical_cve_benchmark_preserves_four_arm_and_candidate_contract(self):
        manifest_path = ROOT / "benchmarks" / "historical" / "historical-cve-v1.json"
        run_path = ROOT / "benchmarks" / "historical" / "historical-cve-sample-run.json"
        gold = load_benchmark_json(manifest_path)
        run = load_benchmark_json(run_path)
        self.assertEqual([], validate_manifest(gold))
        normalized = normalize_manifest(gold)
        self.assertEqual(HISTORICAL_CVE_BENCHMARK_SCHEMA_VERSION,
                         normalized["schema_version"])
        self.assertEqual(12, len(normalized["cases"]))
        self.assertTrue(all("::" in case["case_id"]
                            for case in normalized["cases"]))
        self.assertNotIn("payload", normalized["cases"][0])

        result = evaluate_benchmark(gold, [run])
        self.assertEqual(HISTORICAL_CVE_BENCHMARK_SCHEMA_VERSION,
                         result["schema_version"])
        self.assertEqual("historical-cve", result["benchmark_type"])
        self.assertEqual(BENCHMARK_CLAIM_STATUS, result["claim_status"])
        self.assertEqual(1.0, result["metrics"]["candidate_precision"])
        self.assertEqual(1.0, result["metrics"]["candidate_recall"])
        self.assertEqual(1.0, result["metrics"]["environment_gap_fidelity"])
        self.assertIsNone(result["metrics"]["confirmed_recall"])
        self.assertTrue(all(item["claim_status"] == BENCHMARK_CLAIM_STATUS
                            for item in result["case_results"]))
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = agent_cli.main([
                "benchmark", "--manifest", str(manifest_path),
                "--run", str(run_path), "--json",
            ])
        self.assertEqual(0, code)
        self.assertEqual(
            HISTORICAL_CVE_BENCHMARK_SCHEMA_VERSION,
            json.loads(stdout.getvalue())["schema_version"],
        )

    def test_historical_cve_manifest_rejects_incomplete_provenance(self):
        manifest_path = ROOT / "benchmarks" / "historical" / "historical-cve-v1.json"
        gold = load_benchmark_json(manifest_path)
        broken = json.loads(json.dumps(gold))
        broken["cases"][0]["cve"] = "not-a-cve"
        broken["cases"][0]["reference_evidence"] = [{"url": "http://unsafe"}]
        broken["cases"][0]["arms"] = broken["cases"][0]["arms"][:2]
        errors = validate_manifest(broken)
        self.assertTrue(any("invalid cve" in error for error in errors))
        self.assertTrue(any("HTTPS reference_evidence" in error for error in errors))
        self.assertTrue(any("must contain vulnerable/fixed" in error
                            for error in errors))

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
