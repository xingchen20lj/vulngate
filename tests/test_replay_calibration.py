"""Regression tests for real-project research replay calibration."""

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

import agent_cli  # noqa: E402
from agent.analysis.research_strategy import (  # noqa: E402
    STRATEGY_FEEDBACK_SCHEMA_VERSION,
    STRATEGY_GUIDANCE_SCHEMA_VERSION,
    apply_research_guidance,
    build_research_strategy,
)
from agent.evaluation.replay_calibration import (  # noqa: E402
    CALIBRATION_SCHEMA_VERSION,
    build_replay_calibration,
    calibrate_replay_history,
    load_replay_calibration,
    load_replay_history,
    write_replay_calibration,
)


def _guidance(strategy_id: str, round_no: int,
              replacement: bool = True) -> dict:
    return {
        "strategy_id": strategy_id,
        "research_key": "rk-" + strategy_id[-4:],
        "candidate_id": "C-" + strategy_id[-4:],
        "next_action": "continue-path-closure",
        "replacement_recommended": replacement,
        "observation_status": "partial",
        "last_round": round_no,
        "surface_variant_plan": {
            "schema_version": "surface-variant-plan-v1",
            "surface": "web",
            "action": "replay-new-variant",
            "selected_variants": [{
                "variant_id": "web-route-middleware-default",
                "family": "route-control", "axis": "route",
            }],
            "lanes": [{
                "variant_id": "web-route-middleware-default",
                "lane": "positive",
            }],
        },
        "raw_payload": "secret=do-not-copy",
    }


def _feedback(strategy_id: str, round_no: int, information_gain: int) -> dict:
    return {
        "strategy_id": strategy_id,
        "research_key": "rk-" + strategy_id[-4:],
        "candidate_id": "C-" + strategy_id[-4:],
        "observation": {
            "status": "partial",
            "current_status": "partial",
            "information_gain": information_gain,
            "new_signals": ["execution"] if information_gain else [],
            "execution_states": ["executed-no-effect"],
        },
        "raw_command": "curl --data @payload",
    }


def _round(round_no: int, guidance_rows: list[dict],
           feedback_rows: list[dict]) -> dict:
    return {
        "round": round_no,
        "guidance": {
            "schema_version": STRATEGY_GUIDANCE_SCHEMA_VERSION,
            "round": round_no,
            "items": guidance_rows,
        },
        "feedback": {
            "schema_version": STRATEGY_FEEDBACK_SCHEMA_VERSION,
            "round": round_no,
            "items": feedback_rows,
        },
        "runtime_lab": {
            "status": "completed",
            "fixture_count": 1,
            "fixture_budget": 1,
            "fixture_budget_truncated": round_no in {1, 2},
            "fixtures": [{
                "comparison": {
                    "comparison_id": "cmp-" + "%02d" % round_no + "a" * 18,
                    "status": "inconclusive",
                    "inconclusive_count": 1,
                    "source_revision_observations": [{
                        "status": "not-executed",
                    }],
                },
                "raw_stdout": "do-not-copy",
            }],
        },
    }


class ReplayCalibrationTests(unittest.TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vulngate-replay-calibration-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    def test_real_replay_metrics_calibrate_replacement_and_gaps(self):
        ids = ["rs-" + hex(index)[2:] * 20 for index in range(1, 5)]
        history = [
            _round(1, [_guidance(ids[0], 1)], []),
            _round(2, [_guidance(ids[0], 2), _guidance(ids[1], 2)],
                     [_feedback(ids[0], 2, 0)]),
            _round(3, [_guidance(ids[1], 3), _guidance(ids[2], 3)],
                     [_feedback(ids[1], 3, 0)]),
            _round(4, [_guidance(ids[2], 4), _guidance(ids[3], 4)],
                     [_feedback(ids[2], 4, 0)]),
            _round(5, [_guidance(ids[3], 5)],
                     [_feedback(ids[3], 5, 1)]),
        ]
        result = calibrate_replay_history(history, "demo")
        self.assertEqual(CALIBRATION_SCHEMA_VERSION, result["schema_version"])
        self.assertEqual("calibrated", result["status"])
        metrics = result["metrics"]
        self.assertEqual(4, metrics["replayed_guidance_items"])
        self.assertEqual(4, metrics["replacement_observed"])
        self.assertEqual(0, metrics["replacement_hits"])
        self.assertEqual(0.0, metrics["replacement_hit_rate"])
        self.assertEqual(1.0, metrics["comparison_gap_rate"])
        self.assertEqual(0.4, metrics["fixture_truncation_rate"])
        self.assertEqual(2, result["policy"]["replacement_zero_gain_rounds"])
        codes = {row["code"] for row in result["recommendations"]}
        self.assertIn("require-consecutive-zero-gain", codes)
        self.assertIn("increase-fixture-budget-or-split-lanes", codes)
        self.assertIn("prioritize-comparison-gap-recovery", codes)
        encoded = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("do-not-copy", encoded)
        self.assertNotIn("curl", encoded)
        self.assertEqual("not-a-finding", result["claim_status"])

    def test_calibrated_policy_requires_two_zero_gain_rounds(self):
        strategy = build_research_strategy(
            research_portfolio={
                "schema_version": "research-portfolio-v1",
                "next_probes": [{
                    "research_key": "rk-threshold",
                    "candidate_id": "C-threshold",
                    "state": "actionable-difference",
                    "priority": 4,
                    "research_surface": "web",
                    "target_type": "web-app",
                }],
            },
            target="demo", target_type="web-app")
        strategy["items"] = strategy["items"][:1]
        strategy["items"][0]["observation"] = {
            "status": "partial", "current_status": "partial",
            "information_gain": 0, "zero_gain_streak": 1,
            "missing_observations": ["typed-effect-or-safe-equivalent"],
        }
        calibration = calibrate_replay_history([
            _round(1, [_guidance("rs-" + "b" * 20, 1)], []),
            _round(2, [], [_feedback("rs-" + "b" * 20, 2, 0)]),
            _round(3, [], [_feedback("rs-" + "b" * 20, 3, 0)]),
            _round(4, [], [_feedback("rs-" + "b" * 20, 4, 0)]),
        ], "demo")
        # The history above is intentionally below the replay sample threshold;
        # use a bounded explicit policy to isolate the guidance behavior.
        calibration["status"] = "calibrated"
        calibration["metrics"]["replayed_guidance_items"] = 3
        calibration["policy"]["replacement_zero_gain_rounds"] = 2
        updated, _ = apply_research_guidance(
            strategy, {}, {}, 5, replay_calibration=calibration)
        guidance = updated["items"][0]["guidance"]
        self.assertEqual(2, guidance["replacement_zero_gain_rounds"])
        self.assertFalse(guidance["replacement_recommended"])

        strategy["items"][0]["observation"]["zero_gain_streak"] = 2
        updated, _ = apply_research_guidance(
            strategy, {}, {}, 6, replay_calibration=calibration)
        self.assertTrue(updated["items"][0]["guidance"]
                        ["replacement_recommended"])

    def test_filesystem_roundtrip_keeps_only_bounded_calibration_metadata(self):
        target = "demo"
        for round_no in (1, 2):
            directory = self.root / "state" / target / ("round-%02d" % round_no)
            (directory / "S8").mkdir(parents=True)
            (directory / "S4").mkdir(parents=True)
            data = _round(round_no, [], [])
            (directory / "S8" / "research-guidance.json").write_text(
                json.dumps(data["guidance"]), encoding="utf-8")
            (directory / "S8" / "research-strategy-feedback.json").write_text(
                json.dumps(data["feedback"]), encoding="utf-8")
            (directory / "S4" / "runtime-lab.json").write_text(
                json.dumps(data["runtime_lab"]), encoding="utf-8")
        self.assertEqual(2, len(load_replay_history(self.root, target)))
        result = build_replay_calibration(self.root, target)
        path = write_replay_calibration(self.root, target, result)
        loaded = load_replay_calibration(self.root, target)
        self.assertTrue(path.exists())
        self.assertEqual(CALIBRATION_SCHEMA_VERSION,
                         loaded["schema_version"])
        self.assertEqual(result["status"], loaded["status"])
        self.assertEqual(result["policy"], loaded["policy"])
        encoded = path.read_text(encoding="utf-8")
        self.assertNotIn("do-not-copy", encoded)
        self.assertNotIn("curl", encoded)
        self.assertEqual("not-a-finding", loaded["claim_status"])

    def test_cli_replay_calibrate_writes_target_artifact(self):
        target = "cli-demo"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = agent_cli.main([
                "replay-calibrate", target,
                "--workspace", str(self.root), "--json",
            ])
        self.assertEqual(0, status)
        payload = json.loads(output.getvalue())
        self.assertEqual(target, payload["target"])
        self.assertEqual(CALIBRATION_SCHEMA_VERSION,
                         payload["calibration"]["schema_version"])
        self.assertEqual("not-a-finding", payload["claim_status"])
        self.assertTrue((self.root / "state" / target / "coverage"
                         / "research-replay-calibration.json").exists())
