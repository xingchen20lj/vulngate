"""Regression tests for provenance-carrying replay packs."""

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
from agent.evaluation.replay_cohort import calibrate_replay_cohort  # noqa: E402
from agent.evaluation.replay_calibration import (  # noqa: E402
    build_replay_calibration,
    write_replay_calibration,
)
from agent.evaluation.replay_pack import (  # noqa: E402
    PACK_SCHEMA_VERSION,
    build_replay_pack,
    normalize_replay_pack,
    verify_replay_pack,
)


def _guidance(strategy_id: str, round_no: int) -> dict:
    return {
        "strategy_id": strategy_id,
        "research_key": "rk-" + strategy_id[-4:],
        "candidate_id": "C-" + strategy_id[-4:],
        "next_action": "continue-path-closure",
        "replacement_recommended": True,
        "observation_status": "partial",
        "last_round": round_no,
        "surface_variant_plan": {
            "schema_version": "surface-variant-plan-v1",
            "surface": "web",
            "action": "replay-new-variant",
            "selected_variants": [{
                "variant_id": "web-route-middleware-default",
                "family": "route-control",
                "axis": "route",
            }],
            "lanes": [{
                "variant_id": "web-route-middleware-default",
                "lane": "positive",
            }],
        },
        "raw_payload": "secret=must-not-enter-pack",
    }


def _feedback(strategy_id: str, round_no: int, gain: int = 0) -> dict:
    return {
        "strategy_id": strategy_id,
        "research_key": "rk-" + strategy_id[-4:],
        "candidate_id": "C-" + strategy_id[-4:],
        "observation": {
            "status": "partial",
            "current_status": "partial",
            "information_gain": gain,
            "new_signals": ["execution"] if gain else [],
            "execution_states": ["executed-no-effect"],
        },
        "raw_command": "curl --data @secret",
    }


def _runtime(round_no: int) -> dict:
    return {
        "schema_version": "runtime-lab-v1",
        "status": "completed",
        "fixture_count": 1,
        "fixture_budget": 1,
        "fixture_budget_truncated": False,
        "comparison_contracts": [],
        "fixtures": [{
            "variant_evidence": {
                "schema_version": "surface-variant-evidence-v1",
                "fixture_key": "vf-" + "a" * 20,
                "surface": "web",
                "variant_id": "web-route-middleware-default",
                "lane": "positive",
                "required_observations": ["execution", "typed-effect"],
                "observed_signals": ["execution", "typed-effect"],
                "sequence_statuses": ["complete"],
                "cells_observed": 1,
                "cells_with_gap": 0,
                "status": "observed",
                "cells": [{
                    "status": "observed",
                    "signals": ["execution", "typed-effect"],
                    "typed_effect_observed": True,
                }],
            },
            "comparison": {
                "comparison_id": "cmp-" + "b" * 20,
                "status": "difference-observed",
                "inconclusive_count": 0,
                "source_revision_observations": [],
            },
            "raw_stdout": "secret=do-not-copy",
        }],
        "claim_status": "not-a-finding",
        "round_marker": round_no,
    }


def _history_workspace(root: Path, target: str = "demo") -> Path:
    target_root = root / "state" / target
    ids = ["rs-" + value * 20 for value in ("1", "2", "3", "4")]
    guidance = {
        1: [_guidance(ids[0], 1)],
        2: [_guidance(ids[0], 2), _guidance(ids[1], 2)],
        3: [_guidance(ids[1], 3), _guidance(ids[2], 3)],
        4: [_guidance(ids[2], 4), _guidance(ids[3], 4)],
        5: [_guidance(ids[3], 5)],
    }
    feedback = {
        1: [],
        2: [_feedback(ids[0], 2)],
        3: [_feedback(ids[1], 3)],
        4: [_feedback(ids[2], 4)],
        5: [_feedback(ids[3], 5, gain=1)],
    }
    for round_no in range(1, 6):
        round_root = target_root / ("round-%02d" % round_no)
        (round_root / "S4").mkdir(parents=True, exist_ok=True)
        (round_root / "S8").mkdir(parents=True, exist_ok=True)
        (round_root / "S4" / "runtime-lab.json").write_text(
            json.dumps(_runtime(round_no)), encoding="utf-8")
        guidance_artifact = {
            "schema_version": "research-strategy-guidance-v1",
            "strategy_schema_version": "research-strategy-v1",
            "round": round_no,
            "summary": {"action_counts": {"continue-path-closure": len(guidance[round_no])}},
            "items": guidance[round_no],
        }
        feedback_artifact = {
            "schema_version": "research-strategy-feedback-v1",
            "round": round_no,
            "items": feedback[round_no],
        }
        (round_root / "S8" / "research-guidance.json").write_text(
            json.dumps(guidance_artifact), encoding="utf-8")
        (round_root / "S8" / "research-strategy-feedback.json").write_text(
            json.dumps(feedback_artifact), encoding="utf-8")
        (round_root / "S8" / "research-consistency.json").write_text(
            json.dumps({"schema_version": "research-consistency-v1"}),
            encoding="utf-8")
        (round_root / "S8" / "research-consistency-actions.json").write_text(
            json.dumps({"schema_version": "research-consistency-action-v1"}),
            encoding="utf-8")
        (round_root / "S8" / "research-budget.json").write_text(
            json.dumps({"schema_version": "research-budget-v1"}),
            encoding="utf-8")
        (round_root / "S8" / "research-portfolio.json").write_text(
            json.dumps({"schema_version": "research-portfolio-v1"}),
            encoding="utf-8")

    calibration = build_replay_calibration(root, target)
    write_replay_calibration(root, target, calibration)
    for round_no in range(1, 6):
        (target_root / ("round-%02d" % round_no) / "S8" /
         "research-replay-calibration.json").write_text(
            json.dumps(calibration), encoding="utf-8")

    coverage = target_root / "coverage"
    coverage.mkdir(parents=True, exist_ok=True)
    (target_root / "research-memory.json").write_text(
        json.dumps({"schema_version": "research-memory-v1"}), encoding="utf-8")
    (target_root / "research-portfolio.json").write_text(
        json.dumps({"schema_version": "research-portfolio-v1"}), encoding="utf-8")
    (target_root / "research-strategy.json").write_text(
        json.dumps({"schema_version": "research-strategy-v1"}), encoding="utf-8")
    (coverage / "research-guidance.json").write_text(
        json.dumps({"schema_version": "research-strategy-guidance-v1"}),
        encoding="utf-8")
    (coverage / "research-consistency.json").write_text(
        json.dumps({"schema_version": "research-consistency-v1"}),
        encoding="utf-8")
    (coverage / "research-consistency-actions.json").write_text(
        json.dumps({"schema_version": "research-consistency-action-v1"}),
        encoding="utf-8")
    (coverage / "research-budget.json").write_text(
        json.dumps({"schema_version": "research-budget-v1"}),
        encoding="utf-8")
    return target_root


class ReplayPackTests(unittest.TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vulngate-replay-pack-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    def test_pack_is_complete_bounded_and_verifiable(self):
        target_root = _history_workspace(self.root)
        pack = build_replay_pack(self.root, "demo")
        self.assertEqual(PACK_SCHEMA_VERSION, pack["schema_version"])
        self.assertEqual("complete", pack["provenance"]["status"])
        self.assertTrue(pack["provenance"]["valid_for_cohort"])
        self.assertEqual(5, pack["provenance"]["round_count"])
        self.assertEqual(5, pack["provenance"]["complete_rounds"])
        self.assertEqual("calibrated", pack["calibration"]["status"])
        self.assertEqual("match",
                         pack["provenance"]["calibration_consistency"])
        self.assertTrue(any(
            artifact.get("artifact") == "S8/research-budget.json"
            for artifact in pack["rounds"][0]["artifacts"]))
        self.assertTrue(any(
            artifact.get("artifact") == "coverage/research-budget.json"
            for artifact in pack["target_artifacts"]))
        self.assertTrue(verify_replay_pack(self.root, "demo", pack)["valid"])
        self.assertTrue(normalize_replay_pack(pack))
        encoded = json.dumps(pack, ensure_ascii=False)
        self.assertNotIn("secret=must-not-enter-pack", encoded)
        self.assertNotIn("secret=do-not-copy", encoded)
        self.assertNotIn("curl --data", encoded)
        self.assertEqual("not-a-finding", pack["claim_status"])

        runtime_path = target_root / "round-01" / "S4" / "runtime-lab.json"
        runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
        runtime["tampered_after_pack"] = True
        runtime_path.write_text(json.dumps(runtime), encoding="utf-8")
        verification = verify_replay_pack(self.root, "demo", pack)
        self.assertFalse(verification["valid"])
        self.assertIn("round-01/S4/runtime-lab.json",
                      verification["mismatches"])

    def test_pack_cohort_requires_complete_provenance(self):
        _history_workspace(self.root)
        pack = build_replay_pack(self.root, "demo")
        cohort = calibrate_replay_cohort([
            {"pack": pack, "project_id": "project-a"},
            {"pack": pack, "project_id": "project-b"},
            {"pack": pack, "project_id": "project-c"},
        ])
        self.assertEqual("insufficient-cohort", cohort["status"])
        self.assertEqual(1, cohort["metrics"]["pack_projects"])
        self.assertEqual(2, cohort["metrics"]["duplicate_project_inputs"])
        self.assertEqual(1, cohort["metrics"]["provenance_eligible_projects"])
        self.assertEqual(1, cohort["metrics"]["eligible_projects"])
        self.assertEqual(5, cohort["metrics"]["pack_rounds"])

        forged = dict(pack)
        forged["provenance"] = dict(pack["provenance"])
        forged["provenance"]["valid_for_cohort"] = False
        # The digest protects the pack body, so this is rejected before it can
        # become a cohort project.
        rejected = calibrate_replay_cohort([
            {"pack": forged, "project_id": "forged"},
        ])
        self.assertEqual("no-data", rejected["status"])
        self.assertEqual(0, rejected["metrics"]["project_count"])

    def test_cli_builds_pack_and_accepts_pack_inputs(self):
        _history_workspace(self.root)
        pack_path = self.root / "pack.json"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = agent_cli.main([
                "replay-pack", "demo", "--workspace", str(self.root),
                "--out", str(pack_path), "--json",
            ])
        self.assertEqual(0, status)
        payload = json.loads(output.getvalue())
        self.assertEqual(PACK_SCHEMA_VERSION, payload["pack"]["schema_version"])
        self.assertTrue(pack_path.exists())

        pack_paths = []
        for index in range(3):
            path = self.root / ("pack-%d.json" % index)
            path.write_text(pack_path.read_text(encoding="utf-8"),
                            encoding="utf-8")
            pack_paths.append(path)
        cohort_path = self.root / "cohort.json"
        argv = ["replay-cohort-calibrate"]
        for path in pack_paths:
            argv.extend(["--pack", str(path)])
        for label in ("project-a", "project-b", "project-c"):
            argv.extend(["--project-id", label])
        argv.extend(["--out", str(cohort_path), "--json"])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = agent_cli.main(argv)
        self.assertEqual(0, status)
        cohort_payload = json.loads(output.getvalue())
        self.assertEqual(1, cohort_payload["cohort"]["metrics"]["pack_projects"])
        self.assertEqual(2, cohort_payload["cohort"]["metrics"]["duplicate_project_inputs"])
        self.assertEqual("insufficient-cohort", cohort_payload["cohort"]["status"])
        self.assertEqual("not-a-finding", cohort_payload["claim_status"])


if __name__ == "__main__":
    unittest.main()
