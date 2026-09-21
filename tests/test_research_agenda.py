"""Tests for the bounded active research agenda."""

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
    AGENDA_SCHEMA_VERSION,
    build_research_agenda,
    normalize_research_agenda,
    write_research_agenda,
)
from agent.analysis.scheduler import ScheduleContext, score_candidate  # noqa: E402
from agent.analysis.research_strategy import (  # noqa: E402
    STRATEGY_SCHEMA_VERSION,
    build_research_strategy,
    write_research_strategy,
)


class ResearchAgendaTests(unittest.TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vulngate-agenda-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    @staticmethod
    def _strategy():
        items = []
        rows = [
            ("rk-web-parser", "C-web-parser", "web-app", "path-closure",
             "parser", 5, "partial", ["typed-effect-or-safe-equivalent"]),
            ("rk-web-authz", "C-web-authz", "web-app", "control-closure",
             "authz", 5, "unobserved", ["negative-unauthorized-baseline"]),
            ("rk-cloud-ssrf", "C-cloud-ssrf", "cloud-service",
             "capability-closure", "ssrf", 4, "partial",
             ["capability-transition"]),
            ("rk-mobile-state", "C-mobile-state", "mobile-app",
             "residual-closure", "state", 3, "environment-gap",
             ["runtime-availability"]),
        ]
        for index, (key, candidate_id, target_type, kind, attack_class,
                    priority, status, missing) in enumerate(rows, 1):
            items.append({
                "strategy_id": "rs-%020x" % index,
                "research_key": key,
                "candidate_id": candidate_id,
                "target_type": target_type,
                "research_surface": {
                    "web-app": "web", "cloud-service": "cloud",
                    "mobile-app": "mobile",
                }.get(target_type, ""),
                "attack_class": attack_class,
                "kind": kind,
                "priority": priority,
                "observation": {
                    "status": status,
                    "current_status": status,
                    "missing_observations": missing,
                    "information_gain": 0,
                },
                "guidance": {
                    "next_action": {
                        "path-closure": "add-typed-effect",
                        "control-closure": "add-negative-control",
                        "capability-closure": "trace-capability-transition",
                        "residual-closure": "repair-environment",
                    }[kind],
                    "priority_delta": 1,
                },
            })
        return {
            "schema_version": STRATEGY_SCHEMA_VERSION,
            "target": "demo",
            "target_type": "web-app",
            "round": 4,
            "items": items,
        }

    def test_selects_information_gain_with_surface_diversity(self):
        agenda = build_research_agenda(
            self._strategy(), target="demo", round_no=4, slots=2,
            max_per_surface=1)
        self.assertEqual(AGENDA_SCHEMA_VERSION, agenda["schema_version"])
        self.assertEqual(2, agenda["summary"]["selected_count"])
        selected = [item for item in agenda["items"]
                    if item["selection_status"] == "selected"]
        self.assertEqual(2, len(selected))
        self.assertEqual(2, len({item["surface"] for item in selected}))
        self.assertTrue(all(item["expected_information_gain"] >= 3
                            for item in selected))
        self.assertTrue(all(item["claim_status"] == "not-a-finding"
                            for item in agenda["items"]))

    def test_complete_observation_is_hold_and_not_budget_selected(self):
        strategy = self._strategy()
        strategy["items"][0]["observation"] = {
            "status": "complete", "current_status": "complete",
            "missing_observations": [], "information_gain": 0,
        }
        strategy["items"][0]["guidance"] = {
            "next_action": "hold-for-new-evidence",
            "priority_delta": 0,
        }
        agenda = build_research_agenda(strategy, target="demo", slots=1)
        row = next(item for item in agenda["items"]
                   if item["research_key"] == "rk-web-parser")
        self.assertEqual("hold", row["selection_status"])
        self.assertEqual(["evidence-satisfied"],
                         row["selection_reason_codes"])
        self.assertEqual(1, agenda["summary"]["selected_count"])

    def test_normalization_recomputes_summary_and_discards_raw_fields(self):
        agenda = build_research_agenda(self._strategy(), target="demo")
        raw = dict(agenda)
        raw["raw_stdout"] = "secret=must-not-persist"
        raw["summary"] = {"selected_count": 999}
        normalized = normalize_research_agenda(raw)
        encoded = json.dumps(normalized, ensure_ascii=False)
        self.assertNotIn("raw_stdout", encoded)
        self.assertNotIn("secret=", encoded)
        self.assertEqual(AGENDA_SCHEMA_VERSION,
                         normalized["schema_version"])
        self.assertNotEqual(999, normalized["summary"]["selected_count"])

    def test_cli_rebuilds_agenda_from_strategy(self):
        write_research_strategy(self.root, "demo", self._strategy())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = agent_cli.main([
                "research-agenda", "demo", "--workspace", str(self.root),
                "--rebuild", "--slots", "2", "--json",
            ])
        self.assertEqual(0, status)
        payload = json.loads(output.getvalue())
        self.assertEqual(AGENDA_SCHEMA_VERSION,
                         payload["agenda"]["schema_version"])
        self.assertEqual(2, payload["agenda"]["summary"]["selected_count"])
        self.assertTrue((self.root / "state" / "demo" / "coverage" /
                         "research-agenda.json").exists())

    def test_write_round_trip_is_stable(self):
        agenda = build_research_agenda(self._strategy(), target="demo")
        path = write_research_agenda(self.root, "demo", agenda)
        loaded = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(agenda, normalize_research_agenda(loaded))

    def test_scheduler_consumes_selected_agenda_item_without_claim_upgrade(self):
        agenda = build_research_agenda(
            self._strategy(), target="demo", slots=1, max_per_surface=1)
        selected = next(item for item in agenda["items"]
                        if item["selection_status"] == "selected")
        candidate = {
            "candidate_id": selected["candidate_id"],
            "surface": "web",
            "entry": "src/Api.java:10",
            "sink": "src/Task.java:20",
            "attack_class": "parser",
            "hypothesis": "bounded research candidate",
        }
        score = score_candidate(
            candidate, ScheduleContext(research_agenda=agenda))
        self.assertIn("research_agenda", score.evidence)
        self.assertEqual("selected",
                         score.evidence["research_agenda"]["selection_status"])
        self.assertEqual("not-a-finding",
                         score.evidence["research_agenda"]["claim_status"])
        self.assertGreater(score.evidence["research_agenda"]["applied_delta"], 0)


if __name__ == "__main__":
    unittest.main()
