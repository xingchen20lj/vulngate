"""Tests for the bounded active-agenda execution feedback loop."""

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
from agent.analysis.research_agenda import (  # noqa: E402
    build_research_agenda,
    normalize_research_agenda,
)
from agent.analysis.research_agenda_outcomes import (  # noqa: E402
    OUTCOME_SCHEMA_VERSION,
    build_research_agenda_outcomes,
    normalize_research_agenda_outcomes,
    write_research_agenda_outcomes,
)
from agent.analysis.research_agenda import write_research_agenda  # noqa: E402


class ResearchAgendaOutcomeTests(unittest.TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vulngate-agenda-outcome-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    @staticmethod
    def _agenda():
        raw = {
            "schema_version": "research-agenda-v1",
            "target": "demo",
            "round": 1,
            "policy": {"slots": 2, "max_per_surface": 2},
            "items": [
                {
                    "agenda_id": "ra-111111111111111111111111",
                    "strategy_id": "rs-11111111111111111111",
                    "research_key": "rk-executed",
                    "candidate_id": "C-executed",
                    "target_type": "web-app",
                    "surface": "web",
                    "attack_class": "authz",
                    "selection_status": "selected",
                    "action": "add-negative-control",
                    "observation_status": "unobserved",
                },
                {
                    "agenda_id": "ra-222222222222222222222222",
                    "strategy_id": "rs-22222222222222222222",
                    "research_key": "rk-deferred",
                    "candidate_id": "C-deferred",
                    "target_type": "cloud-service",
                    "surface": "cloud",
                    "attack_class": "ssrf",
                    "selection_status": "deferred",
                    "action": "trace-capability-transition",
                    "observation_status": "unobserved",
                },
            ],
        }
        return normalize_research_agenda(raw)

    def test_records_productive_strategy_feedback(self):
        agenda = self._agenda()
        outcomes = build_research_agenda_outcomes(
            agenda,
            schedule={
                "selected_ids": ["C-executed"],
                "selected": [{
                    "candidate_id": "C-executed",
                    "evidence": {"research_agenda": {
                        "agenda_id": "ra-111111111111111111111111",
                    }},
                }],
            },
            verification={"C-executed": {
                "cells_ran": 1, "execution_state": "executed",
            }},
            runtime_lab={"status": "completed", "candidate_status": {
                "C-executed": {"fixture_count": 1},
            }},
            strategy_feedback={"items": [{
                "strategy_id": "rs-11111111111111111111",
                "research_key": "rk-executed",
                "candidate_id": "C-executed",
                "observation": {
                    "status": "partial",
                    "information_gain": 2,
                    "new_signals": ["negative-baseline"],
                },
            }]},
            target="demo", round_no=1,
        )
        self.assertEqual(OUTCOME_SCHEMA_VERSION,
                         outcomes["schema_version"])
        executed = next(row for row in outcomes["entries"]
                        if row["candidate_id"] == "C-executed")
        deferred = next(row for row in outcomes["entries"]
                        if row["candidate_id"] == "C-deferred")
        self.assertEqual("new-information", executed["outcome_code"])
        self.assertEqual(2, executed["information_gain"])
        self.assertTrue(executed["scheduled"])
        self.assertEqual("not-selected", deferred["outcome_code"])
        self.assertEqual(1, outcomes["summary"]["productive_selected_count"])
        self.assertEqual(1, outcomes["summary"]["selected_yield"])
        self.assertTrue(all(row["claim_status"] == "not-a-finding"
                            for row in outcomes["entries"]))

    def test_distinguishes_environment_gap_and_missing_schedule(self):
        agenda = self._agenda()
        agenda["items"][1]["selection_status"] = "selected"
        outcomes = build_research_agenda_outcomes(
            agenda,
            schedule={"selected_ids": ["C-executed"]},
            verification={"C-executed": {
                "cells_ran": 0,
                "execution_state": "precondition-unavailable",
            }},
            runtime_lab={"status": "precondition-unavailable",
                         "candidate_status": {}},
            target="demo", round_no=2,
        )
        first = next(row for row in outcomes["entries"]
                     if row["candidate_id"] == "C-executed")
        second = next(row for row in outcomes["entries"]
                      if row["candidate_id"] == "C-deferred")
        self.assertEqual("environment-gap", first["outcome_code"])
        self.assertEqual("not-executed", second["outcome_code"])
        self.assertEqual(1, outcomes["summary"]["environment_gap_count"])
        self.assertEqual(1, outcomes["summary"]["not_executed_count"])

    def test_history_and_normalization_are_bounded_and_redacted(self):
        agenda = self._agenda()
        outcomes = build_research_agenda_outcomes(
            agenda, schedule={}, target="demo", round_no=3)
        raw = dict(outcomes)
        raw["raw_stdout"] = "secret=must-not-persist"
        raw["summary"] = {"selected_count": 999}
        normalized = normalize_research_agenda_outcomes(raw)
        encoded = json.dumps(normalized, ensure_ascii=False)
        self.assertEqual(OUTCOME_SCHEMA_VERSION,
                         normalized["schema_version"])
        self.assertNotIn("raw_stdout", encoded)
        self.assertNotIn("secret=", encoded)
        self.assertNotEqual(999, normalized["summary"]["selected_count"])
        self.assertEqual(len(outcomes["entries"]),
                         len(normalized["history"]))

    def test_cli_rebuilds_from_round_artifacts(self):
        write_research_agenda(self.root, "demo", self._agenda())
        round_root = self.root / "state" / "demo" / "round-01"
        (round_root / "S4").mkdir(parents=True)
        (round_root / "S8").mkdir(parents=True)
        (self.root / "state" / "demo" / "coverage").mkdir(parents=True,
                                                              exist_ok=True)
        (self.root / "state" / "demo" / "coverage" /
         "schedule-round-01.json").write_text(json.dumps({
             "selected_ids": ["C-executed"],
         }), encoding="utf-8")
        (round_root / "S4" / "verification-matrix.json").write_text(
            json.dumps({"C-executed": {
                "cells_ran": 1, "execution_state": "executed",
                "safe_equivalent": [{"kind": "negative-baseline"}],
            }}), encoding="utf-8")
        (round_root / "S4" / "runtime-lab.json").write_text(
            json.dumps({"status": "completed", "candidate_status": {
                "C-executed": {"fixture_count": 1},
            }}), encoding="utf-8")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = agent_cli.main([
                "research-agenda-outcomes", "demo", "--workspace",
                str(self.root), "--round", "1", "--rebuild", "--json",
            ])
        self.assertEqual(0, status)
        payload = json.loads(output.getvalue())
        self.assertEqual(OUTCOME_SCHEMA_VERSION,
                         payload["outcomes"]["schema_version"])
        self.assertTrue((self.root / "state" / "demo" / "coverage" /
                         "research-agenda-outcomes.json").exists())

    def test_write_round_trip_is_stable(self):
        outcomes = build_research_agenda_outcomes(
            self._agenda(), schedule={}, target="demo", round_no=1)
        path = write_research_agenda_outcomes(self.root, "demo", outcomes)
        loaded = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(outcomes, normalize_research_agenda_outcomes(loaded))

    def test_outcome_is_carried_into_the_next_agenda(self):
        from tests.test_research_agenda import ResearchAgendaTests

        strategy = ResearchAgendaTests._strategy()
        baseline = build_research_agenda(
            strategy, target="demo", round_no=4, slots=1)
        selected = next(row for row in baseline["items"]
                        if row["selection_status"] == "selected")
        outcomes = {
            "schema_version": OUTCOME_SCHEMA_VERSION,
            "entries": [{
                "outcome_id": "rao-333333333333333333333333",
                "round": 4,
                "agenda_id": selected["agenda_id"],
                "research_key": selected["research_key"],
                "candidate_id": selected["candidate_id"],
                "outcome_code": "environment-gap",
                "information_gain": 0,
                "observed_signals": ["environment-gap"],
            }],
        }
        next_agenda = build_research_agenda(
            strategy, target="demo", round_no=5, slots=1,
            outcomes=outcomes)
        row = next(item for item in next_agenda["items"]
                   if item["research_key"] == selected["research_key"])
        self.assertEqual("environment-gap", row["last_outcome"])
        self.assertEqual(4, row["outcome_round"])
        self.assertIn("outcome-recovery", row["selection_reason_codes"])


if __name__ == "__main__":
    unittest.main()
