"""Tests for the bounded attacker-path threat model."""

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

from agent.analysis.inventory import CoverageStore  # noqa: E402
from agent.analysis.scheduler import ScheduleContext, prompt_coverage_block  # noqa: E402
from agent.analysis.threat_model import (  # noqa: E402
    THREAT_MODEL_CLAIM_STATUS,
    THREAT_MODEL_SCHEMA_VERSION,
    build_threat_model,
    load_threat_model,
    normalize_threat_model,
    write_threat_model,
)
import agent_cli  # noqa: E402


class ThreatModelTests(unittest.TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vulngate-threat-model-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    def _model(self, verdict="uncontrolled"):
        entries = [{
            "entry_id": "entry-http-1", "kind": "http", "file": "src/Api.java",
            "line": 20, "framework": "spring", "api": "handle",
            "target_type": "web-app", "untrusted": True,
        }]
        sinks = [{
            "sink_id": "sink-exec-1", "category": "command-exec",
            "file": "src/Task.java", "line": 80, "severity_hint": "high",
        }]
        flows = [{
            "flow_id": "flow-1", "entry_id": "entry-http-1",
            "sink_id": "sink-exec-1", "path": ["sym-api", "sym-task"],
            "transforms": ["decode"], "validations": [], "authorizations": [],
            "priority": "high", "coverage_gap": "",
        }]
        control_map = {"entries": [{
            "flow_id": "flow-1", "verdict": verdict,
            "required_groups": [["authentication", "authorization"],
                                 ["allowlist", "sanitization", "validation"]],
            "missing_groups": ([["authentication", "authorization"],
                                ["allowlist", "sanitization", "validation"]]
                               if verdict != "guarded" else []),
            "present": [], "control_ids": [],
        }]}
        capability_graph = {"paths": [{
            "candidate_id": "cap-chain-1", "flow_ids": ["flow-1"],
            "goal": "command-execution", "chain_status": "partial-hypothesis",
            "required_capabilities": ["read", "exec"],
            "observed_capabilities": ["read"],
            "missing_capabilities": ["exec"],
        }]}
        return build_threat_model(
            entries, sinks, flows, control_map, capability_graph,
            reachability=[], target="demo", target_type="web-app")

    def test_links_boundary_control_gap_and_capability_hypothesis(self):
        model = self._model()
        self.assertEqual(THREAT_MODEL_SCHEMA_VERSION, model["schema_version"])
        self.assertEqual(THREAT_MODEL_CLAIM_STATUS, model["claim_status"])
        self.assertEqual("network-http", model["boundaries"][0]["boundary_type"])
        path = model["attack_paths"][0]
        self.assertEqual("control-gap-hypothesis", path["research_state"])
        self.assertEqual("uncontrolled", path["control_posture"])
        self.assertEqual(5, path["research_priority"])
        self.assertEqual("cap-chain-1",
                         path["capability_hypotheses"][0]["candidate_id"])
        self.assertIn("default-configuration", " ".join(path["research_questions"]))
        self.assertEqual("not-a-finding", path["claim_status"])
        self.assertNotIn('"claim_status": "confirmed"',
                         json.dumps(model, ensure_ascii=False))

    def test_guarded_path_remains_a_research_path_not_a_safety_claim(self):
        model = self._model(verdict="guarded")
        path = model["attack_paths"][0]
        self.assertEqual("guarded", path["control_posture"])
        self.assertEqual("dangerous-operation-path", path["research_state"])
        self.assertEqual([], path["missing_control_groups"])
        self.assertIn("runtime", " ".join(model["assumptions"]))

    def test_normalization_drops_raw_or_unknown_fields_and_forces_status(self):
        forged = self._model()
        forged["secret_payload"] = "do-not-persist"
        forged["attack_paths"][0]["payload"] = "raw-input"
        forged["attack_paths"][0]["claim_status"] = "confirmed"
        normalized = normalize_threat_model(forged)
        encoded = json.dumps(normalized, ensure_ascii=False)
        self.assertNotIn("do-not-persist", encoded)
        self.assertNotIn("raw-input", encoded)
        self.assertNotIn('"claim_status": "confirmed"', encoded)
        self.assertEqual(THREAT_MODEL_CLAIM_STATUS, normalized["claim_status"])
        self.assertEqual(THREAT_MODEL_CLAIM_STATUS,
                         normalized["attack_paths"][0]["claim_status"])

    def test_round_trip_and_scheduler_prompt(self):
        model = self._model()
        path = write_threat_model(self.root, "demo", model)
        self.assertTrue(path.exists())
        self.assertEqual(model, load_threat_model(self.root, "demo"))
        context = ScheduleContext.from_store(
            CoverageStore(self.root, "demo"), threat_model=model)
        prompt = prompt_coverage_block(context)
        self.assertIn("攻击路径威胁模型 / Attacker-Path Threat Model", prompt)
        self.assertIn("cap-chain-1", prompt)
        self.assertIn("not-a-finding", prompt)

    def test_cli_exposes_the_bounded_model(self):
        write_threat_model(self.root, "demo", self._model())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = agent_cli.main([
                "threat-model", "demo", "--workspace", str(self.root), "--json",
            ])
        self.assertEqual(0, code)
        payload = json.loads(output.getvalue())
        self.assertEqual(THREAT_MODEL_SCHEMA_VERSION,
                         payload["schema_version"])
        self.assertEqual(THREAT_MODEL_CLAIM_STATUS, payload["claim_status"])


if __name__ == "__main__":
    unittest.main()
