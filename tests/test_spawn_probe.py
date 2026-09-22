"""Challenge-bound S4 sub-agent preflight regression tests."""

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import agent_cli  # noqa: E402


class SpawnProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name)

    def invoke(self, *args):
        output = io.StringIO()
        with redirect_stdout(output):
            code = agent_cli.main(["spawn-probe", "--workspace", str(self.workspace),
                                   "--target", "demo", "--round", "1", *args])
        return code, json.loads(output.getvalue())

    def receipt(self, *args):
        output = io.StringIO()
        with redirect_stdout(output):
            code = agent_cli.main([
                "parallel-receipt", "--workspace", str(self.workspace),
                "--target", "demo", "--round", "1", "--candidate", "C67", *args,
            ])
        return code, json.loads(output.getvalue())

    def test_nonce_bound_heartbeat_and_reply_enable_parallelism(self):
        token = "probe_token_123456789"
        code, prepared = self.invoke("--prepare", "--token", token)
        self.assertEqual(0, code)
        heartbeat = Path(prepared["heartbeat_file"])
        heartbeat.write_text("PROBE %s\n" % token, encoding="utf-8")
        code, verified = self.invoke("--status", "ok", "--reply",
                                     "PROBE-DONE %s" % token)
        self.assertEqual(0, code)
        self.assertTrue(verified["verified"])
        self.assertEqual("parallel-per-candidate", verified["decision"])
        artifact = json.loads((self.workspace / "state" / "demo" / "round-01" /
                               "S4" / "spawn-probe.json").read_text())
        self.assertEqual("ok", artifact["status"])
        self.assertTrue(artifact["observed"]["heartbeat_token_valid"])
        self.assertTrue(artifact["observed"]["reply_token_valid"])

    def test_old_or_host_created_heartbeat_cannot_fake_probe_success(self):
        legacy = self.workspace / "state" / "demo" / "round-01" / "S4" / "spawn-probe.heartbeat"
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text("PROBE host-created\n", encoding="utf-8")
        code, result = self.invoke("--status", "ok", "--reply", "PROBE-DONE")
        self.assertEqual(2, code)
        self.assertFalse(result["verified"])
        self.assertEqual("challenge-missing", result["symptom"])
        self.assertEqual("host-sequential-whole-round", result["decision"])

    def test_generic_reply_downgrades_even_when_heartbeat_has_nonce(self):
        token = "probe_token_987654321"
        self.assertEqual(0, self.invoke("--prepare", "--token", token)[0])
        challenge = json.loads((self.workspace / "state" / "demo" / "round-01" /
                                "S4" / "spawn-probe-challenge.json").read_text())
        Path(challenge["heartbeat_file"]).write_text("PROBE %s\n" % token,
                                                       encoding="utf-8")
        code, result = self.invoke("--status", "ok", "--reply", "ready to help")
        self.assertEqual(2, code)
        self.assertEqual("probe-contract-invalid", result["symptom"])
        self.assertFalse(result["verified"])

    def test_candidate_receipt_requires_fresh_token_and_matrix_artifact(self):
        token = "receipt_token_123456789"
        code, prepared = self.receipt("--prepare", "--token", token)
        self.assertEqual(0, code)
        self.assertEqual("S4/matrix-runs/C67/cells.json",
                         prepared["expected_artifact"])
        cells = (self.workspace / "state" / "demo" / "round-01" /
                 "S4" / "matrix-runs" / "C67" / "cells.json")
        cells.parent.mkdir(parents=True)
        cells.write_text('{"status":"executed"}\n', encoding="utf-8")
        code, recorded = self.receipt(
            "--status", "completed", "--token", token,
            "--artifact", "S4/matrix-runs/C67/cells.json")
        self.assertEqual(0, code)
        self.assertEqual("completed", recorded["status"])
        code, verified = self.receipt("--verify")
        self.assertEqual(0, code)
        self.assertTrue(verified["verified"])
        self.assertEqual("accept-runtime-artifacts", verified["decision"])

    def test_candidate_receipt_cannot_claim_completion_without_output(self):
        token = "receipt_token_987654321"
        self.assertEqual(0, self.receipt("--prepare", "--token", token)[0])
        code, result = self.receipt("--status", "completed", "--token", token)
        self.assertEqual(2, code)
        self.assertIn("requires", result["error"])
        code, verified = self.receipt("--verify")
        self.assertEqual(2, code)
        self.assertFalse(verified["verified"])
        self.assertEqual("preserve-partial-and-run-host-sequentially",
                         verified["decision"])


if __name__ == "__main__":
    unittest.main()
