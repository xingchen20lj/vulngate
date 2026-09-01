import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.sandbox.approval import ApprovalGate  # noqa: E402
from agent.sandbox.runner import (CommandRunner, validate_global_command,
                                  validate_poc_command)  # noqa: E402
from agent.tools.build import scan_source_egress, summarize_candidate  # noqa: E402
from agent.tools.conclusion import derive_conclusion  # noqa: E402
from agent.tools.cvss import check_impact_consistency  # noqa: E402


class PolicyTests(unittest.TestCase):
    def test_remote_command_is_denied_and_logged(self):
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "approval.jsonl"
            gate = ApprovalGate(log_path=log)
            runner = CommandRunner(Path(td), gate)
            with self.assertRaises(PermissionError):
                runner.run(["ssh", "root@8.8.8.8"], operation="loopback_connect")
            records = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(records[-1]["operation"], "policy_denied")
            self.assertFalse(records[-1]["allowed"])

    def test_remote_command_is_denied_without_operation_label(self):
        with tempfile.TemporaryDirectory() as td:
            runner = CommandRunner(Path(td), ApprovalGate())
            with self.assertRaises(PermissionError):
                runner.run(["scp", "x", "root@host:/tmp/"])

    def test_authorized_staging_requires_allowlisted_host(self):
        self.assertIsNone(validate_global_command(
            ["ssh", "root@203.0.113.10", "true"], True, {"203.0.113.10"}))
        self.assertIsNotNone(validate_global_command(
            ["ssh", "root@203.0.113.11", "true"], True, {"203.0.113.10"}))
        self.assertIsNone(validate_poc_command(
            ["curl", "http://203.0.113.10:28080/health"], {},
            True, {"203.0.113.10"}))
        self.assertEqual(scan_source_egress(
            "http://203.0.113.10:28080/health", allowed_hosts={"203.0.113.10"}), [])

    def test_external_target_in_poc_environment_is_denied(self):
        with tempfile.TemporaryDirectory() as td:
            script = Path(td) / "probe.sh"
            script.write_text("#!/bin/sh\necho SHOULD_NOT_RUN\n", encoding="utf-8")
            runner = CommandRunner(Path(td), ApprovalGate())
            with self.assertRaises(PermissionError):
                runner.run(
                    ["bash", str(script)],
                    cwd=Path(td),
                    env_extra={"VULNGATE_TARGET_URL": "http://203.0.113.10:8080"},
                    operation="loopback_connect",
                )


class EvidenceTests(unittest.TestCase):
    def test_memory_canary_cannot_confirm_rce(self):
        cells = [{
            "version": "1.0", "safe_mode": False, "precondition": "none",
            "observations": {
                "INSTANTIATED": "com.example.Exploit",
                "CANARY": "Canary.mark",
                "EFFECT_KIND": "memory-canary-only",
            },
        }]
        summary = summarize_candidate(cells)
        result = derive_conclusion(summary, {
            "surface": "default-config RCE",
            "target_classes": ["com.example.Exploit"],
        }, cells)
        self.assertEqual(result, "候选（待验证）")
        self.assertTrue(summary["safe_equivalent"])

    def test_real_command_marker_can_confirm_rce(self):
        cells = [{
            "version": "1.0", "safe_mode": False, "precondition": "none",
            "observations": {
                "INSTANTIATED": "com.example.Exploit",
                "EFFECT_KIND": "command-marker",
                "EFFECT": "local harmless marker observed",
            },
        }]
        summary = summarize_candidate(cells)
        result = derive_conclusion(summary, {
            "surface": "RCE",
            "target_classes": ["com.example.Exploit"],
        }, cells)
        self.assertEqual(result, "确认")

    def test_high_availability_requires_concurrency_proof(self):
        candidate = {"surface": "CPU denial of service"}
        vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
        ok, _ = check_impact_consistency(candidate, {}, vector)
        self.assertFalse(ok)
        ok, _ = check_impact_consistency(candidate, {
            "availability_proof": [{"concurrency": 4, "service_unavailable": "true"}],
        }, vector)
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
