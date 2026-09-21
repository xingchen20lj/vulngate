"""Tests for the bounded outcome-adaptive research budget policy."""

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
    write_research_agenda,
)
from agent.analysis.research_agenda_outcomes import (  # noqa: E402
    OUTCOME_SCHEMA_VERSION,
    write_research_agenda_outcomes,
)
from agent.analysis.research_budget import (  # noqa: E402
    BUDGET_SCHEMA_VERSION,
    build_research_budget,
    load_research_budget,
    normalize_research_budget,
    write_research_budget,
)
from agent.analysis.research_strategy import STRATEGY_SCHEMA_VERSION  # noqa: E402
from agent.analysis.scheduler import ScheduleContext, score_candidate  # noqa: E402


class ResearchBudgetTests(unittest.TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vulngate-budget-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    @staticmethod
    def _strategy():
        rows = [
            ("rk-web", "C-web", "web-app", "parser"),
            ("rk-cloud", "C-cloud", "cloud-service", "ssrf"),
            ("rk-mobile", "C-mobile", "mobile-app", "state"),
        ]
        items = []
        for index, (key, candidate_id, target_type, attack_class) in enumerate(
                rows, 1):
            surface = {
                "web-app": "web", "cloud-service": "cloud",
                "mobile-app": "mobile",
            }[target_type]
            items.append({
                "strategy_id": "rs-%020x" % index,
                "research_key": key,
                "candidate_id": candidate_id,
                "target_type": target_type,
                "research_surface": surface,
                "attack_class": attack_class,
                "kind": "path-closure",
                "priority": 4,
                "observation": {
                    "status": "partial",
                    "current_status": "partial",
                    "missing_observations": ["typed-effect"],
                    "information_gain": 0,
                },
                "guidance": {
                    "next_action": "add-typed-effect",
                    "priority_delta": 1,
                },
            })
        return {
            "schema_version": STRATEGY_SCHEMA_VERSION,
            "target": "demo",
            "target_type": "web-app",
            "round": 1,
            "items": items,
        }

    @staticmethod
    def _outcomes(agenda, rows):
        entries = []
        for index, (item, code, gain) in enumerate(rows, 1):
            entries.append({
                "outcome_id": "rao-%024x" % index,
                "round": 1,
                "agenda_id": item["agenda_id"],
                "strategy_id": item["strategy_id"],
                "research_key": item["research_key"],
                "candidate_id": item["candidate_id"],
                "selection_status": "selected",
                "schedule_status": "selected",
                "scheduled": True,
                "executed": True,
                "environment_gap": code == "environment-gap",
                "outcome_code": code,
                "information_gain": gain,
                "observed_signals": ["environment-gap"]
                if code == "environment-gap" else ["execution"],
                "missing_observations": [],
                "falsifier_codes": [],
                "reason_codes": [],
                "execution_state": "environment-gap"
                if code == "environment-gap" else "executed",
                "cells_ran": 1,
                "fixture_count": 1,
                "prior_outcome_code": "",
                "consecutive_no_information": 1
                if code == "no-new-information" else 0,
                "claim_status": "not-a-finding",
            })
        return {
            "schema_version": OUTCOME_SCHEMA_VERSION,
            "target": "demo",
            "round": 1,
            "schedule_available": True,
            "entries": entries,
            "history": [],
        }

    def _agenda(self, slots=3):
        return build_research_agenda(
            self._strategy(), target="demo", round_no=1, slots=slots,
            max_per_surface=3)

    def test_environment_gap_is_recovery_priority(self):
        agenda = self._agenda()
        item = next(row for row in agenda["items"]
                    if row["surface"] == "mobile")
        outcomes = self._outcomes(agenda, [(item, "environment-gap", 0)])
        budget = build_research_budget(agenda, outcomes, target="demo",
                                       round_no=1)
        row = next(row for row in budget["surfaces"]
                   if row["surface"] == "mobile")
        self.assertEqual("recover-environment", row["recommendation"])
        self.assertEqual(8, row["priority_delta"])
        self.assertEqual("not-a-finding", budget["claim_status"])

    def test_repeated_no_information_cools_down_surface(self):
        agenda = self._agenda(slots=3)
        web = [row for row in agenda["items"] if row["surface"] == "web"]
        outcomes = self._outcomes(
            agenda, [(web[0], "no-new-information", 0),
                     (web[0], "no-new-information", 0)])
        # Duplicate outcome ids are intentionally not used here; the policy
        # sees one selected item.  Add a prior round to reach the cooldown
        # threshold without fabricating a finding conclusion.
        outcomes["entries"] = [
            dict(outcomes["entries"][0], outcome_id="rao-%024x" % 1),
            dict(outcomes["entries"][1], outcome_id="rao-%024x" % 2,
                 round=2),
        ]
        prior = build_research_budget(agenda, outcomes, target="demo",
                                      round_no=2)
        row = next(row for row in prior["surfaces"]
                   if row["surface"] == "web")
        self.assertEqual("cooldown-low-yield", row["recommendation"])
        self.assertLess(row["priority_delta"], 0)

    def test_productive_surface_gets_bounded_exploitation_nudge(self):
        agenda = self._agenda(slots=3)
        cloud = next(row for row in agenda["items"]
                     if row["surface"] == "cloud")
        outcomes = self._outcomes(agenda, [(cloud, "new-information", 2)])
        budget = build_research_budget(agenda, outcomes, target="demo",
                                       round_no=1)
        row = next(row for row in budget["surfaces"]
                   if row["surface"] == "cloud")
        self.assertEqual("exploit-high-yield", row["recommendation"])
        self.assertEqual(4, row["priority_delta"])
        self.assertLessEqual(row["priority_delta"], 8)

    def test_budget_policy_changes_next_agenda_metadata_only(self):
        agenda = self._agenda(slots=3)
        item = next(row for row in agenda["items"]
                    if row["surface"] == "mobile")
        outcomes = self._outcomes(agenda, [(item, "environment-gap", 0)])
        budget = build_research_budget(agenda, outcomes, target="demo",
                                       round_no=1)
        next_agenda = build_research_agenda(
            self._strategy(), target="demo", round_no=2, slots=3,
            budget_policy=budget)
        mobile = next(row for row in next_agenda["items"]
                      if row["surface"] == "mobile")
        self.assertEqual("recover-environment",
                         mobile["budget_recommendation"])
        self.assertEqual(8, mobile["budget_priority_delta"])
        self.assertEqual("not-a-finding", next_agenda["claim_status"])
        self.assertEqual(BUDGET_SCHEMA_VERSION,
                         next_agenda["policy"]["budget_policy"]
                         ["schema_version"])

    def test_scheduler_preserves_budget_hint_as_research_evidence(self):
        agenda = self._agenda(slots=3)
        item = next(row for row in agenda["items"]
                    if row["surface"] == "mobile")
        outcomes = self._outcomes(agenda, [(item, "environment-gap", 0)])
        budget = build_research_budget(agenda, outcomes, target="demo",
                                       round_no=1)
        next_agenda = build_research_agenda(
            self._strategy(), target="demo", round_no=2, slots=3,
            budget_policy=budget)
        candidate = {
            "candidate_id": item["candidate_id"],
            "surface": "mobile",
            "entry": "src/Entry.m:10",
            "sink": "src/Sink.m:20",
            "attack_class": "state",
        }
        scored = score_candidate(
            candidate, ScheduleContext(research_agenda=next_agenda))
        evidence = scored.evidence["research_agenda"]
        self.assertEqual("recover-environment",
                         evidence["budget_recommendation"])
        self.assertEqual(8, evidence["budget_priority_delta"])
        self.assertEqual("not-a-finding", evidence["claim_status"])

    def test_normalization_discards_raw_fields_and_round_trip_is_stable(self):
        agenda = self._agenda()
        budget = build_research_budget(agenda, self._outcomes(agenda, []),
                                       target="demo", round_no=1)
        raw = dict(budget)
        raw["raw_stdout"] = "secret=must-not-persist"
        normalized = normalize_research_budget(raw)
        encoded = json.dumps(normalized, ensure_ascii=False)
        self.assertNotIn("raw_stdout", encoded)
        self.assertNotIn("secret=", encoded)
        path = write_research_budget(self.root, "demo", budget)
        self.assertEqual(normalized,
                         load_research_budget(self.root, "demo"))
        self.assertTrue(path.exists())

    def test_cli_rebuilds_budget_policy(self):
        agenda = self._agenda()
        outcomes = self._outcomes(agenda, [])
        write_research_agenda(self.root, "demo", agenda)
        write_research_agenda_outcomes(self.root, "demo", outcomes)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = agent_cli.main([
                "research-budget", "demo", "--workspace", str(self.root),
                "--rebuild", "--json",
            ])
        self.assertEqual(0, status)
        payload = json.loads(output.getvalue())
        self.assertEqual(BUDGET_SCHEMA_VERSION,
                         payload["budget"]["schema_version"])
        self.assertTrue((self.root / "state" / "demo" / "coverage" /
                         "research-budget.json").exists())


if __name__ == "__main__":
    unittest.main()
