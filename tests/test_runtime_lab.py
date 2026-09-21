import sys
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.orchestrator.config import TargetConfig  # noqa: E402
from agent.tools.fuzzer import (  # noqa: E402
    FuzzInput,
    _run_lab_matrix,
    emit_candidates,
    run_fuzz_for_pipeline,
)
from agent.tools.runtime_lab import (  # noqa: E402
    build_fixture_manifest,
    fixture_from_input,
    normalize_fixture,
    summarize_replay,
    summarize_version_differential,
)


class RuntimeLabTests(unittest.TestCase):
    def test_fixture_identity_and_corpus_are_deterministic_and_bounded(self):
        first = fixture_from_input({
            "id": 1, "group": "json", "entry": "JSON.parse",
            "hex": "AA BB",
        }, seed=42, primary_version="2.0")
        second = fixture_from_input({
            "id": 99, "group": "json", "entry": "JSON.parse",
            "hex": "aabb",
        }, seed=42, primary_version="2.0")
        self.assertEqual(first["fixture_id"], second["fixture_id"])
        self.assertEqual(first["digest"], second["digest"])
        self.assertEqual(first["payload_hex"], "aabb")
        self.assertEqual(first["claim_status"], "not-a-finding")

        manifest = build_fixture_manifest([
            {"id": 1, "group": "json", "entry": "JSON.parse", "hex": "aabb"},
            {"id": 2, "group": "json", "entry": "JSON.parse", "hex": "aabb"},
            {"id": 3, "group": "json", "entry": "JSON.parse", "hex": "not-hex"},
        ], seed=42, primary_version="2.0", limit=1, budget=3,
           template_digest="template-digest")
        self.assertEqual(manifest["fixture_count"], 1)
        self.assertEqual(manifest["input_count"], 3)
        self.assertEqual(manifest["budget"], 3)
        self.assertEqual(manifest["template_digest"], "template-digest")
        self.assertFalse(manifest["truncated"])
        self.assertEqual(manifest["claim_status"], "not-a-finding")
        self.assertEqual(len(manifest["corpus_digest"]), 64)

        self.assertEqual(normalize_fixture({"payload_hex": "zz"}), {})

    def test_replay_classifies_stable_unstable_and_precondition_results(self):
        stable = summarize_replay([
            {"version": "1.0", "safe_mode": False,
             "bucket": "crash", "signature": "NullPointerException|A"},
            {"version": "1.0", "safe_mode": False,
             "bucket": "crash", "signature": "NullPointerException|A"},
        ])
        self.assertEqual(stable["status"], "stable")
        self.assertEqual(stable["attempts"], 2)

        unstable = summarize_replay([
            {"version": "1.0", "bucket": "crash", "signature": "A"},
            {"version": "1.0", "bucket": "ok", "signature": ""},
        ])
        self.assertEqual(unstable["status"], "unstable")

        unavailable = summarize_replay([
            {"version": "1.0", "precondition_status": "precondition-unavailable"},
        ])
        self.assertEqual(unavailable["status"], "precondition-unavailable")
        self.assertEqual(unavailable["claim_status"], "not-a-finding")

    def test_version_differential_separates_bucket_change_signature_drift_and_gaps(self):
        changed = summarize_version_differential([
            {"version": "1.0", "safe_mode": False,
             "bucket": "crash", "signature": "A"},
            {"version": "1.1", "safe_mode": False,
             "bucket": "ok", "signature": ""},
            {"version": "1.0", "safe_mode": True,
             "bucket": "ok", "signature": ""},
            {"version": "1.1", "safe_mode": True,
             "bucket": "ok", "signature": ""},
        ], primary_version="1.0")
        self.assertEqual(changed["status"], "difference-observed")
        self.assertEqual(changed["differences"][0]["version"], "1.1")

        drift = summarize_version_differential([
            {"version": "1.0", "safe_mode": False,
             "bucket": "crash", "signature": "A"},
            {"version": "1.1", "safe_mode": False,
             "bucket": "crash", "signature": "B"},
            {"version": "1.0", "safe_mode": True,
             "bucket": "ok", "signature": ""},
            {"version": "1.1", "safe_mode": True,
             "bucket": "ok", "signature": ""},
        ], primary_version="1.0")
        self.assertEqual(drift["status"], "signature-variation")
        self.assertEqual(drift["differences"], [])

        drift_with_gap = summarize_version_differential([
            {"version": "1.0", "safe_mode": False,
             "bucket": "crash", "signature": "A"},
            {"version": "1.1", "safe_mode": False,
             "bucket": "crash", "signature": "B"},
        ], primary_version="1.0")
        self.assertEqual(drift_with_gap["status"],
                         "signature-variation-with-inconclusive")
        self.assertTrue(drift_with_gap["inconclusive_cells"])

        gap = summarize_version_differential([
            {"version": "1.0", "safe_mode": False,
             "bucket": "crash", "signature": "A"},
            {"version": "1.1", "safe_mode": False,
             "precondition_status": "precondition-unavailable"},
        ], primary_version="1.0")
        self.assertEqual(gap["status"], "inconclusive")
        self.assertEqual(gap["claim_status"], "not-a-finding")

    def test_fuzz_candidate_carries_fixed_reproducer_identity(self):
        triggers = {
            ("jsonb", "crash", "NullPointerException|frame"): {
                "group": "jsonb-symbol", "entry": "jsonb-object",
                "bucket": "crash", "signature": "NullPointerException|frame",
                "hex": "aabb", "input_len": 2,
                "error": "NullPointerException", "error_msg": "boom",
                "frames": ["frame"], "cell": {"version": "1.0", "safe": False},
                "jvm": {"Xmx": "128m"},
            },
        }
        candidates = emit_candidates(triggers, {}, {"Xmx": "128m"}, "probe.java")
        spec = candidates[0]["fuzz_spec"]
        self.assertTrue(spec["fixture_id"].startswith("fx-"))
        self.assertEqual(spec["reproducer"]["payload_hex"], "aabb")
        self.assertEqual(spec["reproducer"]["claim_status"], "not-a-finding")

    def test_lab_matrix_passes_version_jars_to_isolated_runner(self):
        class FakeRunner:
            def __init__(self):
                self.calls = []

            def run_manifest(self, specs, jars_by_version):
                self.calls.append((specs, jars_by_version))
                return {specs[0].candidate_id: [{
                    "version": "1.0", "safe_mode": False,
                    "returncode": 0, "timed_out": False,
                    "stdout": "PARSED=ok\n",
                    "stderr": "",
                }]}

        runner = FakeRunner()
        records = _run_lab_matrix(
            runner, "LAB-1", [], {"1.0": [Path("a.jar")]},
            {"Xmx": "128m"}, "safe.mode", "replay", "fx-1")
        self.assertEqual(len(records), 1)
        self.assertEqual(runner.calls[0][1], {"1.0": [Path("a.jar")]})
        self.assertEqual(records[0]["bucket"], "ok")

    def test_fuzz_pipeline_persists_corpus_and_lab_refs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = TargetConfig(
                name="lab-pipeline", discovery_date="2026-09-21",
                fuzzer={"probe_src": "probe.java"},
            )
            trigger = {
                "group": "jsonb-symbol", "entry": "jsonb-object",
                "bucket": "crash", "signature": "NullPointerException|frame",
                "hex": "aabb", "input_len": 2,
                "error": "NullPointerException", "error_msg": "boom",
                "frames": ["frame"], "cell": {"version": "1.0", "safe": False},
                "jvm": {"Xmx": "128m"},
            }
            fixture = normalize_fixture({
                "entry": "jsonb-object", "group": "jsonb-symbol",
                "payload_hex": "aabb", "expected_bucket": "crash",
                "expected_signature": "NullPointerException|frame",
                "primary_version": "1.0", "safe_mode": False,
                "source": "runtime-lab-reproducer",
            })
            lab = {
                "schema_version": "runtime-lab-v1", "status": "completed",
                "replay_runs": 3, "fixture_count": 1,
                "fixtures": [{
                    "fixture": fixture,
                    "replay": {"status": "stable"},
                    "reproduces_expected": True,
                    "differential": {"status": "no-difference"},
                }],
                "claim_status": "not-a-finding",
            }
            report = {
                "engine": "directed-fuzz-2.1", "seed": 7, "budget": 1,
                "inputs_generated": 1, "cells_run": 2,
                "matrix": {"primary_version": "1.0", "safe_states": [False, True]},
                "bucket_counts": {"crash": 1}, "trigger_count": 1,
            }
            with patch("agent.tools.fuzzer.run_discovery", return_value={
                "report": report, "triggers": {("x", "crash", "sig"): trigger},
                "inputs": [FuzzInput(1, "jsonb-symbol", "jsonb-object", "aabb")],
            }), patch("agent.tools.fuzzer.run_runtime_lab", return_value=lab):
                candidates = run_fuzz_for_pipeline(
                    root, cfg, 1, budget=1, seed=7, skip_minimize=True)

            fuzz_dir = root / "state" / "lab-pipeline" / "round-01" / "FUZZ"
            self.assertTrue((fuzz_dir / "fuzz-corpus.json").exists())
            self.assertTrue((fuzz_dir / "runtime-lab.json").exists())
            self.assertEqual(
                json.loads((fuzz_dir / "runtime-lab.json").read_text())[
                    "status"], "completed")
            self.assertEqual(
                candidates[0]["fuzz_spec"]["runtime_lab"]["differential_status"],
                "no-difference")


if __name__ == "__main__":
    unittest.main()
