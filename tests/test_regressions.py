import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "scripts"))

from agent.memory.ledger import write_round_artifacts  # noqa: E402
from agent.sandbox.runner import CommandRunner, validate_poc_command  # noqa: E402
from agent.tools.build import (JavaMatrixRunner, MatrixCell, POCSpec,
                               classify_s4_execution, converge_s4_cells,
                               summarize_candidate)  # noqa: E402
from agent.tools.conclusion import is_confirmed_conclusion  # noqa: E402
from agent.tools.novelty import NoveltyChecker  # noqa: E402


class RunnerRegressionTests(unittest.TestCase):
    def test_agent_api_url_does_not_block_local_poc_or_cross_process(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            script = root / "probe.sh"
            script.write_text(
                "#!/bin/sh\n"
                "printf 'LOCAL_OK=1\\n'\n"
                "printf 'AGENT_URL=%s\\n' \"${ANTHROPIC_BASE_URL:-}\"\n",
                encoding="utf-8")
            with patch.dict(os.environ, {
                "PATH": "/usr/local/opt/curl/bin:/bin:/usr/bin",
                "ANTHROPIC_BASE_URL": "https://api.deepseek.com/anthropic",
                "HTTPS_PROXY": "https://proxy.invalid:8443",
                "DEEPSEEK_API_KEY": "must-not-cross-process",
            }, clear=True):
                self.assertIsNone(validate_poc_command(
                    ["bash", str(script)], {}, False, set()))
                result = CommandRunner(root).run(
                    ["bash", str(script)], cwd=root,
                    env_extra={"VULNGATE_TARGET_URL": "http://127.0.0.1:8080"},
                    operation="loopback_connect")
            self.assertEqual(result.returncode, 0)
            self.assertIn("LOCAL_OK=1", result.stdout)
            self.assertIn("AGENT_URL=", result.stdout)
            self.assertNotIn("deepseek.com", result.stdout)
            self.assertNotIn("must-not-cross-process", result.stdout)


class S4RegressionTests(unittest.TestCase):
    def test_execution_state_distinguishes_empty_failure_gate_and_no_effect(self):
        self.assertEqual(classify_s4_execution([])["execution_state"], "unexecuted")
        self.assertEqual(classify_s4_execution([{
            "returncode": 1, "timed_out": False, "observations": {},
        }])["execution_state"], "run-failed")
        self.assertEqual(classify_s4_execution([{
            "returncode": -3, "timed_out": False,
            "observations": {"GATE_BLOCKED": "policy-denied"},
        }])["execution_state"], "gate-blocked")
        self.assertEqual(classify_s4_execution([{
            "returncode": 0, "timed_out": False, "observations": {"PARSED": "ok"},
        }])["execution_state"], "executed-no-effect")

    def test_persisted_cells_override_proxy_timeout_and_fallback_is_merged(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            matrix = root / "state" / "demo" / "round-01" / "S4" / "matrix-runs" / "A1"
            matrix.mkdir(parents=True)
            persisted = [{"version": "1.0", "safe_mode": False,
                          "returncode": 0, "timed_out": False,
                          "observations": {"PARSED": "ok"}}]
            (matrix / "cells.json").write_text(json.dumps(persisted), encoding="utf-8")
            fallback = root / "state" / "demo" / "round-01" / "S4" / "host-fallback.json"
            fallback.write_text(json.dumps({"A1": [{
                "version": "1.0", "safe_mode": True, "returncode": 0,
                "timed_out": False, "observations": {"PARSED": "safe"},
            }]}), encoding="utf-8")
            cells, meta = converge_s4_cells(root, "demo", 1, "A1", [])
            self.assertEqual(len(cells), 2)
            self.assertEqual(meta["sources"], ["persisted", "fallback:host-fallback.json"])
            self.assertTrue(meta["proxy_timeout_does_not_override"])
            self.assertEqual(summarize_candidate(cells)["execution_state"], "executed-no-effect")


class JdkRegressionTests(unittest.TestCase):
    @staticmethod
    def _executable(path: Path, body: str) -> None:
        path.write_text(body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def test_jdk8_cell_uses_declared_java_home_and_records_actual_runtime(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "fake-jdk8"
            bindir = home / "bin"
            bindir.mkdir(parents=True)
            self._executable(bindir / "java", "#!/bin/sh\n"
                             "if [ \"$1\" = \"-version\" ]; then "
                             "echo 'openjdk version \"1.8.0_fake\"' >&2; exit 0; fi\n"
                             "echo 'INSTANTIATED=com.example.Probe'\n")
            self._executable(bindir / "javac", "#!/bin/sh\nexit 0\n")
            src = root / "poc" / "demo" / "round-01" / "src"
            src.mkdir(parents=True)
            (src / "Probe.java").write_text("class Probe {}\n", encoding="utf-8")
            cell = MatrixCell(version="1.0", safe_mode=False,
                              required_runtime="jdk8", java_home=str(home))
            spec = POCSpec(candidate_id="A1", class_name="Probe",
                           src="Probe.java", cells=[cell])
            cells = JavaMatrixRunner(root, "demo", 1).run_manifest(
                [spec], {"1.0": []})["A1"]
            self.assertEqual(cells[0]["java_bin"], str((bindir / "java").resolve()))
            self.assertEqual(cells[0]["java_home"], str(home.resolve()))
            self.assertEqual(cells[0]["java_version"], "1.8.0_fake")
            self.assertEqual(cells[0]["requested_runtime"], "jdk8")
            self.assertEqual(cells[0]["runtime_status"], "available")
            self.assertIn(str(bindir / "java"), cells[0]["cmd"])

    def test_missing_declared_jdk8_is_precondition_unavailable(self):
        cell = MatrixCell(version="1.0", safe_mode=False,
                          required_runtime="jdk8", java_home="/definitely/missing/jdk8")
        result = classify_s4_execution([{
            "returncode": -4, "timed_out": False,
            "precondition_status": "precondition-unavailable",
            "observations": {"GATE_BLOCKED": "precondition-unavailable"},
        }])
        self.assertEqual(result["execution_state"], "precondition-unavailable")
        self.assertEqual(cell.required_runtime, "jdk8")


class LedgerRegressionTests(unittest.TestCase):
    def test_composite_confirmed_conclusion_is_counted(self):
        conclusion = "确认；High；已知机制增量；非 RCE"
        self.assertTrue(is_confirmed_conclusion(conclusion))
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rows = [{"candidate_id": "A1", "surface": "demo",
                     "conclusion": conclusion, "evidence": ["runtime marker"]}]
            write_round_artifacts(root, "demo", 1, rows, [],
                                  {"metrics": {"确认数": 1}, "next_round": []})
            summary = root / "ledger" / "demo" / "round-01" / "挖洞-轮次汇总-01.md"
            self.assertTrue(summary.exists())
            self.assertIn("A1：demo", summary.read_text(encoding="utf-8"))


class NoveltyRegressionTests(unittest.TestCase):
    def test_query_failure_cannot_become_candidate_0day_and_metadata_is_safe(self):
        import urllib.error
        with patch.dict(os.environ, {"GH_TOKEN": "secret-token"}, clear=True):
            checker = NoveltyChecker(offline=False)
            checker._api = lambda _path: (_ for _ in ()).throw(
                urllib.error.URLError("network unavailable"))
            self.assertEqual(checker.search("org/repo", "security"), [])
            result = checker.evaluate([], [], "2026-01-01")
        self.assertEqual(result.verdict, "unknown-query-failed")
        metadata = result.query_metadata
        self.assertEqual(metadata["auth_source"], "GH_TOKEN")
        self.assertTrue(metadata["query_failed"])
        self.assertNotIn("secret-token", json.dumps(metadata))

    def test_upstream_ref_metadata_keeps_title_state_and_source(self):
        checker = NoveltyChecker(offline=False)
        checker._api = lambda _path: {
            "title": "security fix", "state": "closed", "created_at": "2025-01-02T00:00:00Z",
            "html_url": "https://github.com/org/repo/issues/7",
        }
        ref = checker.fetch_ref("org/repo", 7, "issues")
        self.assertEqual(ref.title, "security fix")
        self.assertEqual(ref.state, "closed")
        self.assertIn("live GitHub API", ref.evidence_source)


if __name__ == "__main__":
    unittest.main()
