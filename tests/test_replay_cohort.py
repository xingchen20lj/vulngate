"""Regression tests for cross-project replay calibration."""

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

import agent_cli  # noqa: E402
from agent.evaluation.replay_cohort import (  # noqa: E402
    COHORT_SCHEMA_VERSION,
    calibrate_replay_cohort,
    normalize_replay_cohort,
    select_effective_replay_calibration,
)
from agent.orchestrator.config import TargetConfig  # noqa: E402
from agent.orchestrator.stages import StageContext  # noqa: E402


def _calibration(target: str, *, hits: int = 0,
                 status: str = "calibrated", surface: str = "web",
                 replayed: int = 4) -> dict:
    outcomes = []
    for index in range(3):
        outcomes.append({
            "strategy_id": "rs-%s%02d" % ("a" * 18, index),
            "surface": surface,
            "replacement_recommended": True,
            "next_action": "continue-path-closure",
            "outcome": ("replacement-productive" if index < hits else
                         "repeat-no-new-information"),
            "environment_recovered": False,
            "raw_stdout": "secret=do-not-copy",
        })
    return {
        "schema_version": "research-replay-calibration-v1",
        "target": target,
        "status": status,
        "history_digest": "history-" + target,
        "metrics": {
            "replayed_guidance_items": replayed,
            "replacement_recommendations": 3,
            "replacement_observed": 3,
            "replacement_hits": hits,
            "unproductive_repeats": 3 - hits,
            "environment_repair_recommendations": 1,
            "environment_recoveries": 0,
            "fixture_budget_rounds": 2,
            "fixture_truncated_rounds": 1,
            "comparison_fixtures": 2,
            "comparison_gaps": 1,
        },
        "outcomes": outcomes,
        "policy": {"replacement_zero_gain_rounds": 2},
        "raw_command": "do-not-copy",
    }


class ReplayCohortTests(unittest.TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vulngate-replay-cohort-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    def test_cohort_requires_distinct_sufficient_projects(self):
        cohort = calibrate_replay_cohort([
            {"calibration": _calibration("web-a"), "project_id": "web-a"},
            {"calibration": _calibration("web-b"), "project_id": "web-b"},
            {"calibration": _calibration("web-c"), "project_id": "web-c"},
        ])
        self.assertEqual(COHORT_SCHEMA_VERSION, cohort["schema_version"])
        self.assertEqual("calibrated", cohort["status"])
        self.assertEqual(3, cohort["metrics"]["eligible_projects"])
        self.assertEqual(2, cohort["policy"]["replacement_zero_gain_rounds"])
        self.assertEqual(3, cohort["surfaces"][0]["project_count"])
        self.assertEqual("sufficient", cohort["surfaces"][0]["status"])
        encoded = json.dumps(cohort, ensure_ascii=False)
        self.assertNotIn("do-not-copy", encoded)
        self.assertNotIn("raw_command", encoded)
        self.assertEqual("not-a-finding", cohort["claim_status"])

    def test_insufficient_project_cohort_does_not_change_policy(self):
        cohort = calibrate_replay_cohort([
            {"calibration": _calibration("one"), "project_id": "one"},
            {"calibration": _calibration("two"), "project_id": "two"},
            {"calibration": _calibration(
                "gap", status="insufficient-sample", replayed=1),
             "project_id": "gap"},
        ])
        self.assertEqual("insufficient-cohort", cohort["status"])
        self.assertEqual(2, cohort["metrics"]["eligible_projects"])
        self.assertEqual(1, cohort["policy"]["replacement_zero_gain_rounds"])
        self.assertIn(
            "collect-more-projects",
            {row["code"] for row in cohort["recommendations"]})

    def test_surface_sufficiency_is_not_created_by_pooled_rows(self):
        inputs = []
        for name in ("a", "b", "c"):
            calibration = _calibration(name)
            calibration["outcomes"] = calibration["outcomes"][:1]
            inputs.append({"calibration": calibration, "project_id": name})
        cohort = calibrate_replay_cohort(inputs)
        self.assertEqual("calibrated", cohort["status"])
        surface = cohort["surfaces"][0]
        self.assertEqual(3, surface["project_count"])
        self.assertEqual(0, surface["sufficient_project_count"])
        self.assertEqual("insufficient-sample", surface["status"])
        self.assertIn(
            "collect-more-surface-replay",
            {row["code"] for row in cohort["recommendations"]})

    def test_local_calibration_takes_precedence_over_cohort_fallback(self):
        cohort = calibrate_replay_cohort([
            {"calibration": _calibration("a"), "project_id": "a"},
            {"calibration": _calibration("b"), "project_id": "b"},
            {"calibration": _calibration("c"), "project_id": "c"},
        ])
        local = _calibration("local", hits=3)
        local["policy"]["replacement_zero_gain_rounds"] = 1
        selected = select_effective_replay_calibration(local, cohort)
        self.assertEqual("research-replay-calibration-v1",
                         selected["schema_version"])
        self.assertEqual(1, selected["policy"]["replacement_zero_gain_rounds"])

        fallback = select_effective_replay_calibration({}, cohort)
        self.assertEqual(2, fallback["policy"]["replacement_zero_gain_rounds"])
        self.assertEqual("cross-project-replay",
                         fallback["policy"]["source"])
        self.assertEqual("not-a-finding", fallback["claim_status"])

    def test_normalization_recomputes_policy_and_strips_unknown_fields(self):
        cohort = calibrate_replay_cohort([
            {"calibration": _calibration("a"), "project_id": "a"},
            {"calibration": _calibration("b"), "project_id": "b"},
            {"calibration": _calibration("c"), "project_id": "c"},
        ])
        forged = dict(cohort)
        forged["policy"] = {"replacement_zero_gain_rounds": 99}
        forged["unknown"] = "secret"
        normalized = normalize_replay_cohort(forged)
        self.assertEqual(2, normalized["policy"]["replacement_zero_gain_rounds"])
        self.assertNotIn("unknown", normalized)
        self.assertEqual("not-a-finding", normalized["claim_status"])

    def test_cli_aggregates_explicit_artifacts(self):
        paths = []
        for name in ("a", "b", "c"):
            path = self.root / (name + ".json")
            path.write_text(json.dumps(_calibration(name)), encoding="utf-8")
            paths.append(path)
        output_path = self.root / "cohort.json"
        argv = ["replay-cohort-calibrate"]
        for path in paths:
            argv.extend(["--artifact", str(path)])
        argv.extend(["--out", str(output_path), "--json"])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = agent_cli.main(argv)
        self.assertEqual(0, status)
        payload = json.loads(output.getvalue())
        self.assertEqual("calibrated", payload["cohort"]["status"])
        self.assertTrue(output_path.exists())
        self.assertEqual(COHORT_SCHEMA_VERSION,
                         json.loads(output_path.read_text())["schema_version"])

    def test_pipeline_reads_cohort_only_when_explicitly_configured(self):
        cohort = calibrate_replay_cohort([
            {"calibration": _calibration("a"), "project_id": "a"},
            {"calibration": _calibration("b"), "project_id": "b"},
            {"calibration": _calibration("c"), "project_id": "c"},
        ])
        cohort_path = self.root / "cohort.json"
        cohort_path.write_text(json.dumps(cohort), encoding="utf-8")
        cfg = TargetConfig(
            name="target", discovery_date="2026-09-21",
            replay_cohort_calibration_path="cohort.json")
        ctx = StageContext(self.root, "target", 1, cfg, offline=True)
        loaded = ctx.replay_cohort_calibration()
        self.assertEqual(COHORT_SCHEMA_VERSION, loaded["schema_version"])
        self.assertEqual(3, loaded["metrics"]["eligible_projects"])
