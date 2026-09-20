"""Tests for the bounded cross-artifact research strategy layer."""

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

from agent.analysis.scheduler import ScheduleContext, prompt_coverage_block, score_candidate  # noqa: E402
from agent.analysis.threat_model import build_threat_model  # noqa: E402
from agent.analysis.research_strategy import (  # noqa: E402
    STRATEGY_CLAIM_STATUS,
    STRATEGY_SCHEMA_VERSION,
    build_research_strategy,
    load_research_strategy,
    normalize_research_strategy,
    strategy_path,
    write_research_strategy,
)
import agent_cli  # noqa: E402


class ResearchStrategyTests(unittest.TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vulngate-strategy-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    def _threat_model(self):
        return build_threat_model(
            entries=[{
                "entry_id": "entry-http-1", "kind": "http",
                "file": "src/Api.java", "line": 20,
                "target_type": "web-app",
            }],
            sinks=[{
                "sink_id": "sink-exec-1", "category": "command-exec",
                "file": "src/Task.java", "line": 80,
                "severity_hint": "high",
            }],
            flows=[{
                "flow_id": "flow-1", "entry_id": "entry-http-1",
                "sink_id": "sink-exec-1", "priority": "high",
                "path": ["sym-api", "sym-task"],
            }],
            control_map={"entries": [{
                "flow_id": "flow-1", "verdict": "uncontrolled",
                "missing_groups": [["authentication", "authorization"]],
            }]},
            capability_graph={"paths": [{
                "candidate_id": "cap-chain-1", "flow_ids": ["flow-1"],
                "goal": "command-execution", "chain_status": "partial-hypothesis",
                "required_capabilities": ["read", "exec"],
                "observed_capabilities": ["read"],
                "missing_capabilities": ["exec"],
            }]},
            target="demo", target_type="web-app")

    def test_strategy_closes_path_and_residual_with_falsifiers(self):
        strategy = build_research_strategy(
            self._threat_model(),
            {"schema_version": "research-portfolio-v1", "next_probes": [{
                "research_key": "rk-1", "candidate_id": "C1",
                "state": "pending-residual", "priority": 4,
                "residual_id": "rr-01234567890123456789",
                "residual_kind": "variant",
                "residual_reason_code": "unverified",
                "research_surface": "web", "target_type": "web-app",
                "variant": ["alternate-codec"],
            }]},
            target="demo", target_type="web-app", round_no=3)
        self.assertEqual(STRATEGY_SCHEMA_VERSION, strategy["schema_version"])
        self.assertEqual(STRATEGY_CLAIM_STATUS, strategy["claim_status"])
        kinds = {item["kind"] for item in strategy["items"]}
        self.assertIn("capability-closure", kinds)
        self.assertIn("residual-closure", kinds)
        path = next(item for item in strategy["items"]
                    if item["kind"] == "capability-closure")
        self.assertIn("capability-transition", path["required_observations"])
        self.assertTrue(path["falsifiers"])
        self.assertEqual(STRATEGY_CLAIM_STATUS, path["claim_status"])
        residual = next(item for item in strategy["items"]
                        if item["kind"] == "residual-closure")
        self.assertEqual("pending-residual", residual["state"])
        self.assertEqual("s3-residual", residual["reason_codes"][0])
        self.assertEqual(1, strategy["summary"]["pending_residuals"])

    def test_strategy_fallback_keeps_memory_residual_when_portfolio_is_missing(self):
        strategy = build_research_strategy(
            research_memory=[{
                "research_key": "rk-memory", "candidate_id": "C-memory",
                "research_surface": "web", "target_type": "web-app",
                "residuals": [{
                    "residual_id": "rr-abcdefabcdefabcdefab",
                    "kind": "variant", "reason_code": "unverified",
                }],
                "events": [{"event_id": "evt-1", "round": 2,
                            "state": "stable-reproducer"}],
            }],
            target="demo", target_type="web-app")
        residuals = [item for item in strategy["items"]
                     if item["kind"] == "residual-closure"]
        self.assertEqual(1, len(residuals))
        self.assertEqual("rr-abcdefabcdefabcdefab",
                         residuals[0]["residual_id"])
        self.assertNotIn("stable-reproducer", json.dumps(strategy))

    def test_strategy_round_trip_is_bounded_and_forces_research_status(self):
        strategy = build_research_strategy(
            self._threat_model(), target="demo", target_type="web-app", round_no=2)
        path = write_research_strategy(self.root, "demo", strategy)
        self.assertEqual(strategy_path(self.root, "demo"), path)
        self.assertEqual(strategy, load_research_strategy(self.root, "demo"))

        forged = dict(strategy)
        forged["secret_payload"] = "do-not-persist"
        forged["items"] = list(strategy["items"]) + [{
            "strategy_id": "raw-id", "kind": "raw-kind",
            "objective": "raw command payload", "claim_status": "confirmed",
        }]
        normalized = normalize_research_strategy(forged)
        encoded = json.dumps(normalized, ensure_ascii=False)
        self.assertNotIn("do-not-persist", encoded)
        self.assertNotIn("raw command payload", encoded)
        self.assertNotIn('"claim_status": "confirmed"', encoded)
        self.assertTrue(all(item["claim_status"] == STRATEGY_CLAIM_STATUS
                            for item in normalized["items"]))

    def test_scheduler_uses_strategy_and_prompt_exposes_it(self):
        model = self._threat_model()
        strategy = build_research_strategy(model, target="demo",
                                            target_type="web-app", round_no=1)
        candidate = {
            "candidate_id": "C1", "surface": "authorization path",
            "entry": "handle", "input_shape": "request",
            "logic": "command execution path",
            "code_location": ["src/Api.java:20", "src/Task.java:80"],
            "attack_class": "authz", "research_surface": "web",
            "target_type": "web-app",
        }
        context = ScheduleContext(
            entries={"entry-http-1": {"entry_id": "entry-http-1",
                                       "kind": "http", "file": "src/Api.java",
                                       "line": 20}},
            sinks={"sink-exec-1": {"sink_id": "sink-exec-1",
                                    "category": "command-exec",
                                    "file": "src/Task.java", "line": 80,
                                    "severity_hint": "high"}},
            flows=[{"flow_id": "flow-1", "entry_id": "entry-http-1",
                    "sink_id": "sink-exec-1", "path": []}],
            threat_model=model, research_strategy=strategy)
        score = score_candidate(candidate, context)
        self.assertIn("research_strategy", score.evidence)
        self.assertEqual("flow", score.evidence["research_strategy"]["match_kind"])
        self.assertEqual(STRATEGY_CLAIM_STATUS,
                         score.evidence["research_strategy"]["claim_status"])
        prompt = prompt_coverage_block(context)
        self.assertIn("研究策略 / Research Strategy", prompt)
        self.assertIn("capability-closure", prompt)
        self.assertIn("not-a-finding", prompt)

    def test_strategy_cli_reads_artifact(self):
        write_research_strategy(self.root, "demo", build_research_strategy(
            self._threat_model(), target="demo", target_type="web-app"))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = agent_cli.main([
                "research-strategy", "demo", "--workspace", str(self.root),
                "--json",
            ])
        self.assertEqual(0, code)
        payload = json.loads(output.getvalue())
        self.assertEqual(STRATEGY_SCHEMA_VERSION,
                         payload["strategy"]["schema_version"])
        self.assertEqual(STRATEGY_CLAIM_STATUS,
                         payload["strategy"]["claim_status"])


if __name__ == "__main__":
    unittest.main()
