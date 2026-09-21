"""Regression tests for cross-round evidence consistency metadata."""

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
from agent.analysis.research_strategy import (  # noqa: E402
    apply_research_guidance,
    build_research_strategy,
)
from agent.evaluation.research_consistency import (  # noqa: E402
    CONSISTENCY_SCHEMA_VERSION,
    build_research_consistency,
    normalize_research_consistency,
)
from agent.evaluation.research_consistency_actions import (  # noqa: E402
    ACTION_SCHEMA_VERSION,
    build_research_consistency_actions,
    normalize_research_consistency_actions,
)
from agent.memory.portfolio import build_research_portfolio  # noqa: E402
from agent.memory.research import (  # noqa: E402
    build_round_memory,
    merge_research_memory,
)


def _candidate(candidate_id="C1"):
    return {
        "candidate_id": candidate_id,
        "surface": "protocol state path",
        "research_surface": "protocol",
        "target_type": "message-rpc",
        "entry": "decode",
        "input_shape": "bounded frame",
        "logic": "state transition reaches a typed effect",
        "attack_class": "state",
        "variant": "state-order",
        "code_location": ["src/Decoder.java:42"],
    }


def _lab(candidate_id, typed_effect, reproduces=True, context_digest=""):
    signals = ["execution"]
    if typed_effect:
        signals.append("typed-effect")
    else:
        signals.append("safe-equivalent")
    variant = {
        "schema_version": "surface-variant-evidence-v1",
        "fixture_key": "vf-" + ("a" if typed_effect else "b") * 20,
        "surface": "protocol",
        "variant_id": "protocol-state-order",
        "lane": "positive",
        "required_observations": ["execution", "typed-effect"],
        "observed_signals": signals,
        "missing_observations": [] if typed_effect else ["typed-effect"],
        "sequence_statuses": ["complete"],
        "cells_observed": 1,
        "cells_with_gap": 0,
        "status": "observed",
        "cells": [{
            "version": "1.0",
            "safe_mode": False,
            "status": "observed",
            "signals": signals,
            "sequence_status": "complete",
            "typed_effect_observed": typed_effect,
        }],
    }
    context = {}
    if context_digest:
        context = {
            "schema_version": "runtime-context-v1",
            "context_digest": context_digest,
            "versions": ["1.0"],
            "runtime_options": {"enabled": True, "safe_modes": [False]},
        }
    return {
        "fixtures": [{
            "fixture": {
                "candidate_id": candidate_id,
                "fixture_id": "fx-" + candidate_id,
                "fixture_kind": "bounded",
            },
            "replay": {"status": "stable", "attempts": 2},
            "reproduces_expected": reproduces,
            "differential": {
                "status": "no-difference",
                "primary_version": "1.0",
                "differences": [],
                "inconclusive_cells": [],
            },
            "variant_evidence": variant,
            "runtime_context": context,
        }],
        "claim_status": "not-a-finding",
    }


class ResearchConsistencyTests(unittest.TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vulngate-consistency-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    def _memory_with_two_observations(self):
        c = _candidate()
        first = build_round_memory(
            [c], {"C1": {}}, {}, _lab("C1", True, True, "a" * 24), 1)
        second = build_round_memory(
            [c], {"C1": {}}, {}, _lab("C1", False, False, "b" * 24), 2)
        return merge_research_memory(first, second)

    def test_conflict_is_explicit_and_never_a_finding(self):
        consistency = build_research_consistency(
            self._memory_with_two_observations())
        self.assertEqual(CONSISTENCY_SCHEMA_VERSION,
                         consistency["schema_version"])
        row = consistency["entries"][0]
        self.assertEqual("conflicted", row["status"])
        self.assertEqual("repeat-with-controlled-context", row["next_action"])
        self.assertIn("effect-presence-drift", row["conflict_codes"])
        self.assertIn("reproduction-drift", row["conflict_codes"])
        self.assertEqual(2, row["observation_count"])
        self.assertEqual(2, row["comparable_count"])
        self.assertEqual(1, consistency["summary"]["conflicted_entries"])
        encoded = json.dumps(consistency, ensure_ascii=False)
        self.assertNotIn("typed effect reaches a typed effect", encoded)
        self.assertEqual("not-a-finding", consistency["claim_status"])
        self.assertEqual("not-a-finding", row["claim_status"])

    def test_portfolio_and_strategy_turn_conflict_into_controlled_followup(self):
        memory = self._memory_with_two_observations()
        consistency = build_research_consistency(memory)
        portfolio = build_research_portfolio(memory, consistency=consistency)
        probe = next(item for item in portfolio["next_probes"]
                     if item.get("reason_code") == "evidence-consistency")
        self.assertEqual("conflicted", probe["consistency_status"])
        self.assertEqual("unstable-replay", probe["state"])
        self.assertGreaterEqual(probe["priority"], 4)

        strategy = build_research_strategy(
            research_portfolio=portfolio,
            research_memory=memory.get("entries") or [],
            target="demo", target_type="message-rpc", round_no=2)
        strategy, guidance = apply_research_guidance(
            strategy, portfolio, {}, 2)
        item = next(item for item in guidance["items"]
                    if item.get("research_key") == probe["research_key"])
        self.assertEqual("repeat-with-controlled-context",
                         item["next_action"])
        self.assertIn("evidence-inconsistent", item["reason_codes"])
        self.assertEqual("not-a-finding", guidance["claim_status"])

        action = item["consistency_action"]
        self.assertEqual("conflicted", action["status"])
        self.assertIn("effect-observation", action["isolation_axes"])
        self.assertEqual(["positive", "negative"],
                         action["matrix_shape"]["paired_lanes"])
        self.assertIn("independent-replay", action["required_observations"])
        self.assertEqual("not-a-finding", action["claim_status"])

    def test_action_artifact_is_bounded_and_recomputed(self):
        consistency = build_research_consistency(
            self._memory_with_two_observations())
        actions = build_research_consistency_actions(consistency)
        self.assertEqual(ACTION_SCHEMA_VERSION,
                         actions["schema_version"])
        row = actions["entries"][0]
        self.assertEqual("conflicted", row["status"])
        self.assertIn("state-reset-observed", row["required_observations"])
        self.assertEqual("not-a-finding", actions["claim_status"])
        raw = dict(actions)
        raw["raw_stdout"] = "secret=must-not-persist"
        raw["entries"] = [dict(row, isolation_axes=["raw-axis"],
                                matrix_shape={"repeat_count": 999})]
        normalized = normalize_research_consistency_actions(raw)
        self.assertNotIn("raw_stdout", json.dumps(normalized))
        self.assertNotIn("raw-axis", json.dumps(normalized))
        self.assertEqual(2, normalized["entries"][0]["matrix_shape"]
                         ["repeat_count"])

    def test_normalization_recomputes_summary_and_discards_raw_fields(self):
        raw = {
            "schema_version": CONSISTENCY_SCHEMA_VERSION,
            "entries": [{
                "research_key": "rk-demo",
                "candidate_id": "C1",
                "status": "conflicted",
                "next_action": "repeat-with-controlled-context",
                "observation_count": 99,
                "comparable_count": 2,
                "conflict_codes": ["effect-presence-drift", "secret-code"],
                "observations": [{
                    "round": 1,
                    "state": "secret-state",
                    "effect_class": "effect-observed",
                    "reproduction": "true",
                    "comparison_class": "same-observation",
                    "context_digest": "a" * 24,
                    "fingerprint": "b" * 24,
                }],
            }],
            "summary": {"conflicted_entries": 999},
            "raw_stdout": "secret=must-not-persist",
        }
        normalized = normalize_research_consistency(raw)
        self.assertEqual(1, normalized["summary"]["entry_count"])
        self.assertEqual(0, normalized["summary"]["conflicted_entries"])
        self.assertEqual("insufficient", normalized["entries"][0]["status"])
        self.assertEqual("inconclusive",
                         normalized["entries"][0]["observations"][0]["state"])
        self.assertEqual([], normalized["entries"][0]["conflict_codes"])
        self.assertNotIn("raw_stdout", json.dumps(normalized))
        self.assertEqual(1, normalized["entries"][0]["observation_count"])

    def test_cli_rebuilds_consistency_artifact(self):
        from agent.memory.research import write_research_memory

        write_research_memory(self.root, "demo",
                              self._memory_with_two_observations())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = agent_cli.main([
                "research-consistency", "demo", "--workspace", str(self.root),
                "--rebuild", "--json",
            ])
        self.assertEqual(0, status)
        payload = json.loads(output.getvalue())
        self.assertEqual(CONSISTENCY_SCHEMA_VERSION,
                         payload["consistency"]["schema_version"])
        self.assertTrue((self.root / "state" / "demo" / "coverage"
                         / "research-consistency.json").exists())

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = agent_cli.main([
                "research-consistency-actions", "demo",
                "--workspace", str(self.root), "--rebuild", "--json",
            ])
        self.assertEqual(0, status)
        action_payload = json.loads(output.getvalue())
        self.assertEqual(ACTION_SCHEMA_VERSION,
                         action_payload["actions"]["schema_version"])
        self.assertTrue((self.root / "state" / "demo" / "coverage"
                         / "research-consistency-actions.json").exists())


if __name__ == "__main__":
    unittest.main()
