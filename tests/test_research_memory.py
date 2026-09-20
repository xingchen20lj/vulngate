"""Regression tests for target-scoped cross-round research memory."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.analysis import scheduler as SCH  # noqa: E402
from agent.memory.research import (  # noqa: E402
    STATE_ACTIONABLE_DIFFERENCE,
    STATE_ENVIRONMENT_GAP,
    STATE_STABLE_REPRODUCER,
    build_round_memory,
    load_research_memory,
    memory_match,
    merge_research_memory,
    research_key,
    write_research_memory,
)
from agent.orchestrator.config import TargetConfig  # noqa: E402
from agent.orchestrator.stages import StageContext, run_s8  # noqa: E402


def candidate(candidate_id="C1", **extra):
    value = {
        "candidate_id": candidate_id,
        "surface": "typed parser dispatch",
        "entry": "readValue",
        "input_shape": "json object",
        "logic": "type dispatch reaches a dangerous sink",
        "code_location": ["src/Parser.java:42"],
        "target_classes": ["com.example.Gadget"],
    }
    value.update(extra)
    return value


def lab_for(candidate_id, replay_status="stable", diff_status="no-difference",
            reproduces=True):
    return {
        "fixtures": [{
            "fixture": {
                "candidate_id": candidate_id,
                "fixture_id": "s4fx-test-1",
                "fixture_kind": "java",
            },
            "expected": {"bucket": "parsed"},
            "replay": {
                "status": replay_status,
                "attempts": 3,
                "representative": {"outcome": "parsed"},
            },
            "reproduces_expected": reproduces,
            "differential": {
                "status": diff_status,
                "primary_version": "v2",
                "differences": [{
                    "version": "v1", "safe_mode": False,
                    "baseline_outcome": "parsed", "observed_outcome": "error",
                }] if diff_status.startswith("difference") else [],
                "inconclusive_cells": [],
            },
        }],
        "claim_status": "not-a-finding",
    }


class ResearchMemoryTests(unittest.TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vulngate-memory-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    def test_key_is_stable_across_candidate_ids_and_does_not_store_raw_input(self):
        first = candidate("C1")
        first["hypothesis"] = "super-secret raw hypothesis"
        second = candidate("renamed-by-next-round")
        self.assertEqual(research_key(first), research_key(second))
        delta = build_round_memory([first], {"C1": {}}, {"C1": "候选"},
                                   lab_for("C1"), 1)
        serialized = json.dumps(delta, ensure_ascii=False)
        self.assertNotIn("super-secret raw hypothesis", serialized)
        self.assertNotIn("typed dispatch reaches a dangerous sink", serialized)
        self.assertNotIn("--payload", serialized)
        self.assertEqual(["src/Parser.java:42"],
                         delta["entries"][0]["code_locations"])

    def test_runtime_states_keep_difference_and_environment_gap_distinct(self):
        c = candidate()
        difference = build_round_memory(
            [c], {"C1": {}}, {"C1": "候选（待验证）"},
            lab_for("C1", diff_status="difference-with-inconclusive"), 2)
        self.assertEqual(STATE_ACTIONABLE_DIFFERENCE,
                         difference["entries"][0]["events"][0]["state"])

        gap = build_round_memory(
            [c], {"C1": {}}, {"C1": "候选（待验证）"},
            lab_for("C1", replay_status="precondition-unavailable",
                    diff_status="inconclusive", reproduces=None), 3)
        self.assertEqual(STATE_ENVIRONMENT_GAP,
                         gap["entries"][0]["events"][0]["state"])
        self.assertIn("不可解释为无效", " ".join(
            gap["entries"][0]["events"][0]["next_probe_hints"]))

        stable = build_round_memory(
            [c], {"C1": {}}, {"C1": "候选（待验证）"},
            lab_for("C1"), 4)
        self.assertEqual(STATE_STABLE_REPRODUCER,
                         stable["entries"][0]["events"][0]["state"])

    def test_merge_is_idempotent_and_preserves_old_events(self):
        c = candidate()
        first = build_round_memory([c], {"C1": {}}, {"C1": "候选"},
                                   lab_for("C1"), 1)
        second = build_round_memory([c], {"C1": {}}, {"C1": "候选"},
                                    lab_for("C1", diff_status="difference-observed"), 2)
        merged = merge_research_memory({}, first)
        merged = merge_research_memory(merged, second)
        merged_again = merge_research_memory(merged, second)
        self.assertEqual(2, merged["summary"]["event_count"])
        self.assertEqual(merged, merged_again)
        self.assertEqual(2, len(merged["entries"][0]["events"]))

    def test_bookkeeping_round_does_not_erase_latest_runtime_state(self):
        c = candidate()
        observed = build_round_memory(
            [c], {"C1": {}}, {"C1": "候选"},
            lab_for("C1", diff_status="difference-observed"), 1)
        bookkeeping = build_round_memory(
            [c], {"C1": {}}, {"C1": "候选（待验证）"}, None, 2)
        merged = merge_research_memory(observed, bookkeeping)
        self.assertEqual(STATE_ACTIONABLE_DIFFERENCE,
                         memory_match(c, merged["entries"])["latest_event"]["state"])

    def test_target_file_round_trips_and_memory_match_returns_latest_event(self):
        c = candidate()
        delta = build_round_memory([c], {"C1": {}}, {"C1": "候选"},
                                   lab_for("C1", diff_status="difference-observed"), 5)
        memory = merge_research_memory({}, delta)
        path = write_research_memory(self.root, "target", memory)
        self.assertTrue(path.exists())
        loaded = load_research_memory(self.root, "target")
        match = memory_match(c, loaded["entries"])
        self.assertEqual(STATE_ACTIONABLE_DIFFERENCE,
                         match["latest_event"]["state"])

    def test_scheduler_marks_stable_memory_without_turning_it_into_a_finding(self):
        c = candidate()
        base_ctx = SCH.ScheduleContext(
            entries={"e": {"entry_id": "e", "kind": "http", "file": "src/Parser.java", "line": 42}},
            sinks={"s": {"sink_id": "s", "category": "command-exec", "severity_hint": "high",
                         "file": "src/Parser.java", "line": 42}},
            flows=[{"flow_id": "f", "entry_id": "e", "sink_id": "s",
                    "direction": "cross-procedural", "path": [], "authorizations": []}],
        )
        before = SCH.score_candidate(c, base_ctx)
        delta = build_round_memory([c], {"C1": {}}, {"C1": "候选"},
                                   lab_for("C1"), 1)
        remembered_ctx = SCH.ScheduleContext(
            entries=base_ctx.entries, sinks=base_ctx.sinks,
            flows=base_ctx.flows, research_memory=delta["entries"])
        after = SCH.score_candidate(c, remembered_ctx)
        self.assertLess(after.total, before.total)
        self.assertEqual(STATE_STABLE_REPRODUCER,
                         after.evidence["research_memory"]["latest_state"])
        self.assertEqual("not-a-finding",
                         after.evidence["research_memory"]["claim_status"])

    def test_config_s8_writes_round_delta_and_target_memory(self):
        c = candidate()
        cfg = TargetConfig(name="target", discovery_date="2026-09-21",
                           candidates=[c], notes="test")
        ctx = StageContext(self.root, "target", 1, cfg, offline=True)
        ctx.store.write_artifact("S4", "runtime-lab.json", lab_for("C1"))
        result = run_s8(ctx, {"C1": {}}, {"C1": "候选（待验证）"}, {}, {})
        target_memory = self.root / "state" / "target" / "research-memory.json"
        round_delta = (self.root / "state" / "target" / "round-01" / "S8"
                       / "research-memory.json")
        self.assertTrue(target_memory.exists())
        self.assertTrue(round_delta.exists())
        self.assertEqual("state/target/research-memory.json",
                         result["research_memory"]["artifact"])
        self.assertEqual("stable-reproducer",
                         json.loads(target_memory.read_text(encoding="utf-8")
                                    )["entries"][0]["events"][0]["state"])


if __name__ == "__main__":
    unittest.main()
