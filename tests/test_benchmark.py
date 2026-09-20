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
    evaluate_benchmark,
    load_benchmark_json,
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
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = agent_cli.main([
                    "benchmark", "--manifest",
                    str(ROOT / "benchmarks" / "research-benchmark-v1.json"),
                    "--run", str(ROOT / "benchmarks" / "research-benchmark-sample-run.json"),
                    "--out", str(out_path), "--json",
                ])
            self.assertEqual(0, code)
            self.assertTrue(out_path.exists())
            self.assertEqual("research-benchmark-v1",
                             json.loads(out_path.read_text(encoding="utf-8"))["schema_version"])
            self.assertIn("case_results", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
