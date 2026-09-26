"""Small no-network S0-S8 golden smoke for the real pipeline."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.orchestrator import pipeline  # noqa: E402
from agent.orchestrator.gates import (  # noqa: E402
    g3_novelty,
    g4_runtime,
    g5_record_valid,
)
from agent.tools.build import (  # noqa: E402
    S4_EVIDENCE_POLICY_VERSION,
    summarize_candidate,
)
from agent.sandbox.effects import FilesystemDiffCollector  # noqa: E402


class HermeticPipelineTests(unittest.TestCase):
    def test_empty_candidate_round_writes_all_stage_and_golden_artifacts(self):
        with tempfile.TemporaryDirectory(prefix="vulngate-e2e-") as td:
            workspace = Path(td)
            target_root = workspace / "src"
            target_root.mkdir(parents=True)
            (target_root / "entry.py").write_text(
                "def main(value):\n    return value\n", encoding="utf-8")
            config = workspace / "config.json"
            config.write_text(json.dumps({
                "schema_version": "target-config-v1",
                "name": "hermetic",
                "discovery_date": "2026-09-27",
                "target_type": "library",
                "source_dirs": ["src"],
                "candidates": [],
                "max_candidates": 1,
                "audit_round_timeout_seconds": 90,
                "s4_timeout_seconds": 30,
                "s4_candidate_timeout_seconds": 10,
                "public_scan": {},
            }), encoding="utf-8")
            rc = pipeline.main([
                "--target", "hermetic", "--round", "1", "--config", str(config),
                "--workspace", str(workspace), "--offline",
            ])
            self.assertEqual(0, rc)
            round_root = workspace / "state" / "hermetic" / "round-01"
            for stage in ("S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8"):
                self.assertTrue((round_root / ("stage-%s.json" % stage)).is_file(), stage)
            self.assertTrue((round_root / "S0" / "execution-budget-status.json").is_file())
            report = json.loads((round_root / "S8" / "final-evidence-consistency.json").read_text())
            self.assertEqual("not-a-finding", report.get("claim_status"))

    def test_fail_closed_runtime_and_gate_fixture_matrix(self):
        def state(cell):
            summary = summarize_candidate([cell])
            summary["evidence_policy_version"] = S4_EVIDENCE_POLICY_VERSION
            return summary

        fixtures = {
            "executed-no-effect": {
                "candidate_id": "no-effect", "returncode": 0,
                "observations": {},
            },
            "run-failed": {
                "candidate_id": "failed", "returncode": 1,
                "stderr": "fixture failure",
            },
            "gate-blocked": {
                "candidate_id": "blocked", "returncode": -3,
                "policy_status": "blocked",
            },
            "precondition-unavailable": {
                "candidate_id": "unavailable", "returncode": -3,
                "policy_status": "precondition-unavailable",
                "precondition_status": "precondition-unavailable",
            },
            "timebox-exhausted": {
                "candidate_id": "timeout", "returncode": -2,
                "timed_out": True, "stop_reason": "timebox-exhausted",
            },
        }
        for expected, cell in fixtures.items():
            summary = state(cell)
            self.assertEqual(expected, summary["execution_state"])
            self.assertFalse(g4_runtime(summary).passed)

        effect = FilesystemDiffCollector().collect(
            "run-confirm", "confirmed", "cell-1",
            {"status": "ok", "entries": {}},
            {"status": "ok", "entries": {
                "marker": {"kind": "file", "size": 1, "digest": "fixture"},
            }},
        ).as_dict()
        confirmed = state({
            "candidate_id": "confirmed", "returncode": 0,
            "version": "fixture", "safe_mode": False,
            "precondition": "none", "cell_id": "cell-1",
            "observed_effects": [effect], "observations": {},
        })
        self.assertEqual("executed-with-effect", confirmed["execution_state"])
        self.assertTrue(g4_runtime(confirmed).passed)

        self.assertTrue(g4_runtime({
            "exclusion_basis": {
                "kind": "g1-unreachable",
                "source_refs": ["src/fixture.py:1"],
            },
        }, intended="排除").passed)
        self.assertFalse(g4_runtime({}, intended="排除").passed)

        novelty_hit = g3_novelty({
            "verdict": "known-family-with-increment", "reason": "fixture hit",
        })
        self.assertTrue(novelty_hit.passed)
        self.assertIn("downgraded", novelty_hit.verdict)
        query_failed = g3_novelty({
            "verdict": "unknown-query-failed", "reason": "offline fixture",
        })
        self.assertTrue(query_failed.passed)
        self.assertIn("needs-human-review", query_failed.verdict)
        self.assertFalse(g5_record_valid({}))


if __name__ == "__main__":
    unittest.main()
