import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.orchestrator.config import TargetConfig  # noqa: E402
from agent.orchestrator.stages import StageContext, run_s4  # noqa: E402
from agent.tools.build import (MatrixCell, POCSpec, ShellPOCSpec,
                               _cell_experiment_env)  # noqa: E402
from agent.tools.s4_runtime_lab import (  # noqa: E402
    build_s4_fixture,
    merge_runtime_lab_artifacts,
    normalize_matrix_record,
    run_s4_runtime_lab,
)
from agent.tools.surface_variants import build_surface_variant_plan  # noqa: E402


class S4RuntimeLabTests(unittest.TestCase):
    def test_fixture_is_stable_and_does_not_persist_raw_arguments(self):
        cell = MatrixCell(
            version="1.1", safe_mode=False,
            args=["--body", "token=super-secret-value"],
            authz={"case_id": "owner", "role": "user"},
            consistency_action={
                "research_key": "rk-recheck",
                "candidate_id": "C1",
                "status": "conflicted",
                "next_action": "repeat-with-controlled-context",
                "conflict_codes": ["effect-presence-drift"],
            },
        )
        spec = POCSpec(
            candidate_id="C1", class_name="Probe", src="Probe.java",
            cells=[cell], entry="parse", input_shape="json",
        )
        candidate = {"candidate_id": "C1", "entry": "parse"}
        first = build_s4_fixture(candidate, spec, cell, "java", 0)
        second = build_s4_fixture(candidate, spec, cell, "java", 0)
        self.assertEqual(first["fixture_id"], second["fixture_id"])
        self.assertEqual(first["digest"], second["digest"])
        encoded = json.dumps(first, ensure_ascii=False)
        self.assertNotIn("super-secret-value", encoded)
        self.assertNotIn("token=", encoded)
        self.assertEqual(first["claim_status"], "not-a-finding")
        self.assertEqual("conflicted",
                         first["consistency_action"]["status"])
        self.assertEqual("conflicted",
                         json.loads(_cell_experiment_env(cell)[
                             "VULNGATE_CONSISTENCY_ACTION"])["status"])

    def test_matrix_adapter_runs_replay_and_version_safe_mode_cells(self):
        class FakeJavaRunner:
            calls = []

            def __init__(self, *_args, **_kwargs):
                pass

            def run_manifest(self, specs, jars):
                spec = specs[0]
                self.calls.append((spec.candidate_id, spec.cells, jars))
                rows = []
                for cell in spec.cells:
                    observations = {"PARSED": "ok"}
                    if cell.version == "1.0" and cell.safe_mode:
                        observations = {"ERROR": "RejectedFixture"}
                    rows.append({
                        "candidate_id": spec.candidate_id,
                        "poc_class": spec.class_name,
                        "version": cell.version,
                        "safe_mode": cell.safe_mode,
                        "precondition": cell.precondition,
                        "returncode": 0,
                        "timed_out": False,
                        "observations": observations,
                    })
                return {spec.candidate_id: rows}

        cfg = TargetConfig(
            name="lab", discovery_date="2026-09-21",
            runtime_lab={"max_fixtures": 1, "replay_runs": 2},
        )
        candidate = {"candidate_id": "C1", "entry": "parse",
                     "input_shape": "json"}
        base = MatrixCell(version="1.1", safe_mode=False,
                          args=["--fixture", "fixed"])
        spec = POCSpec(candidate_id="C1", class_name="Probe", src="Probe.java",
                       cells=[base], entry="parse", input_shape="json")
        baseline = {
            "C1": [{
                "poc_class": "Probe", "version": "1.1",
                "safe_mode": False, "precondition": "none",
                "returncode": 0, "timed_out": False,
                "observations": {"PARSED": "ok"},
            }]
        }
        FakeJavaRunner.calls = []
        with tempfile.TemporaryDirectory() as td, patch(
                "agent.tools.s4_runtime_lab.JavaMatrixRunner", FakeJavaRunner):
            artifact = run_s4_runtime_lab(
                Path(td), "lab", 1, cfg, [candidate], [spec], [],
                {"1.0": [Path("a.jar")], "1.1": [Path("b.jar")]},
                baseline_results=baseline,
                version_universe=["1.0", "1.1"],
            )

        self.assertEqual(artifact["status"], "completed")
        self.assertEqual(artifact["fixture_count"], 1)
        item = artifact["fixtures"][0]
        self.assertEqual(item["replay"]["status"], "stable")
        self.assertTrue(item["reproduces_expected"])
        self.assertEqual("difference-observed", item["comparison"]["status"])
        self.assertEqual(1, len(artifact["comparison_contracts"]))
        self.assertEqual(len(FakeJavaRunner.calls), 2)
        self.assertEqual(len(FakeJavaRunner.calls[0][1]), 2)
        self.assertEqual(len(FakeJavaRunner.calls[1][1]), 4)
        self.assertEqual(FakeJavaRunner.calls[1][2]["1.0"], [Path("a.jar")])
        self.assertEqual(item["claim_status"], "not-a-finding")

    def test_consistency_action_materializes_paired_runtime_lanes(self):
        class FakeJavaRunner:
            calls = []

            def __init__(self, *_args, **_kwargs):
                pass

            def run_manifest(self, specs, _jars):
                spec = specs[0]
                self.calls.append(spec.cells)
                return {spec.candidate_id: [{
                    "candidate_id": spec.candidate_id,
                    "poc_class": spec.class_name,
                    "version": cell.version,
                    "safe_mode": cell.safe_mode,
                    "precondition": cell.precondition,
                    "returncode": 0,
                    "timed_out": False,
                    "observations": {
                        "PARSED": "ok",
                        "EFFECT_KIND": "canary",
                        "EFFECT": "shape-only",
                        "STATE_RESET": "yes",
                    },
                } for cell in spec.cells]}

        action = {
            "research_key": "rk-recheck",
            "candidate_id": "C1",
            "status": "conflicted",
            "conflict_codes": ["effect-presence-drift"],
        }
        candidate = {
            "candidate_id": "C1", "entry": "parse",
            "experiment_plan": {"consistency_action": action},
        }
        cfg = TargetConfig(
            name="consistency-lab", discovery_date="2026-09-21",
            runtime_lab={"max_fixtures": 2, "replay_runs": 2,
                         "safe_modes": [False]},
        )
        spec = POCSpec(
            candidate_id="C1", class_name="Probe", src="Probe.java",
            cells=[MatrixCell(version="1.0", safe_mode=False,
                              consistency_action=action)],
        )
        FakeJavaRunner.calls = []
        with tempfile.TemporaryDirectory() as td, patch(
                "agent.tools.s4_runtime_lab.JavaMatrixRunner", FakeJavaRunner):
            artifact = run_s4_runtime_lab(
                Path(td), "consistency-lab", 1, cfg, [candidate], [spec], [],
                {"1.0": [Path("a.jar")]}, version_universe=["1.0"],
            )
        self.assertEqual(2, artifact["fixture_count"])
        self.assertEqual({"positive", "negative"}, {
            row["fixture"]["consistency_lane"]
            for row in artifact["fixtures"]
        })
        self.assertNotEqual(
            artifact["fixtures"][0]["fixture"]["fixture_id"],
            artifact["fixtures"][1]["fixture"]["fixture_id"],
        )
        self.assertEqual(
            artifact["fixtures"][0]["fixture"]["context_digest"],
            artifact["fixtures"][1]["fixture"]["context_digest"],
        )
        self.assertTrue(all(
            item["consistency_recheck"]["replay_attempts"] == 2
            for item in artifact["fixtures"]
        ))
        self.assertEqual("positive",
                         _cell_experiment_env(MatrixCell(
                             version="1.0", safe_mode=False,
                             consistency_action=action,
                             consistency_lane="positive"))[
                                 "VULNGATE_CONSISTENCY_LANE"])

    def test_target_can_disable_non_repeatable_fixture_lab(self):
        cfg = TargetConfig(
            name="disabled-lab", discovery_date="2026-09-21",
            runtime_lab={"enabled": False},
        )
        cell = MatrixCell(version="local", safe_mode=False)
        spec = POCSpec(candidate_id="C1", class_name="Probe", src="Probe.java",
                       cells=[cell])
        artifact = run_s4_runtime_lab(
            Path(tempfile.gettempdir()), "disabled-lab", 1, cfg,
            [{"candidate_id": "C1"}], [spec], [], {},
        )
        self.assertEqual(artifact["status"], "disabled")
        self.assertEqual(artifact["claim_status"], "not-a-finding")

    def test_surface_plan_expands_runtime_lab_into_three_lane_fixtures(self):
        class FakeJavaRunner:
            calls = []

            def __init__(self, *_args, **_kwargs):
                pass

            def run_manifest(self, specs, _jars):
                spec = specs[0]
                self.calls.append(spec)
                return {spec.candidate_id: [{
                    "candidate_id": spec.candidate_id,
                    "poc_class": spec.class_name,
                    "version": cell.version,
                    "safe_mode": cell.safe_mode,
                    "precondition": cell.precondition,
                    "returncode": 0,
                    "timed_out": False,
                    "observations": {"PARSED": "ok"},
                } for cell in spec.cells]}

        surface_plan = build_surface_variant_plan(
            "mobile", action="add-negative-control",
            attack_class="webview origin bridge")
        candidate = {
            "candidate_id": "MOBILE-1",
            "entry": "bridge",
            "experiment_plan": {"surface_variant_plan": surface_plan},
        }
        cfg = TargetConfig(
            name="variant-lab", discovery_date="2026-09-21",
            runtime_lab={"max_fixtures": 3, "replay_runs": 1,
                         "safe_modes": [False]},
        )
        base = MatrixCell(version="1.0", safe_mode=False,
                          args=["--fixture", "fixed"])
        spec = POCSpec(candidate_id="MOBILE-1", class_name="Probe",
                       src="Probe.java", cells=[base])
        FakeJavaRunner.calls = []
        with tempfile.TemporaryDirectory() as td, patch(
                "agent.tools.s4_runtime_lab.JavaMatrixRunner", FakeJavaRunner):
            artifact = run_s4_runtime_lab(
                Path(td), "variant-lab", 1, cfg, [candidate], [spec], [],
                {"1.0": [Path("a.jar")]}, version_universe=["1.0"])

        self.assertEqual("completed", artifact["status"])
        self.assertEqual(3, artifact["fixture_count"])
        self.assertEqual(
            {"positive", "negative", "environment-gap"},
            {(row["fixture"]["variant_context"] or {})["lane"]
             for row in artifact["fixtures"]},
        )
        self.assertEqual(
            {"positive": 1, "negative": 1, "environment-gap": 1},
            artifact["candidate_status"]["MOBILE-1"]["variant_lane_counts"],
        )
        self.assertEqual(3, len([
            row for row in artifact["fixtures"]
            if row.get("variant_evidence", {}).get("schema_version")
            == "surface-variant-evidence-v1"
        ]))
        self.assertEqual(
            {"partial"},
            set(artifact["candidate_status"]["MOBILE-1"]
                ["variant_evidence_statuses"]),
        )
        # Each lane is a real runner invocation with a distinct state-machine
        # context; the plan still remains metadata and all rows are safe.
        self.assertEqual(6, len(FakeJavaRunner.calls))
        self.assertTrue(all(
            spec.cells[0].variant_context.get("lane") in {
                "positive", "negative", "environment-gap"
            } and spec.cells[0].sequence
            for spec in FakeJavaRunner.calls
        ))
        env = _cell_experiment_env(FakeJavaRunner.calls[0].cells[0])
        self.assertEqual("mobile", env["VULNGATE_VARIANT_SURFACE"])
        self.assertIn(env["VULNGATE_VARIANT_LANE"],
                      {"positive", "negative", "environment-gap"})
        self.assertNotIn("payload", json.dumps(env, ensure_ascii=False).lower())
        self.assertTrue(all(
            row["claim_status"] == "not-a-finding"
            for row in artifact["fixtures"]
        ))

    def test_shell_adapter_reuses_loopback_runner(self):
        if sys.platform != "darwin":
            self.skipTest("macOS Seatbelt is required for PoC execution")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "poc" / "shell-lab" / "round-01" / "src"
            src.mkdir(parents=True)
            (src / "probe.sh").write_text(
                "#!/bin/sh\nprintf 'PARSED=ok\\n'\n", encoding="utf-8")
            case = {"case_id": "cross-tenant", "principal": "u1",
                    "role": "user", "tenant_id": "a", "object_id": "o7",
                    "token": "do-not-persist"}
            cfg = TargetConfig(
                name="shell-lab", discovery_date="2026-09-21",
                target_urls={"local": "http://127.0.0.1:8080/?token=secret-value"},
                runtime_lab={"max_fixtures": 1, "replay_runs": 2},
            )
            cell = MatrixCell(version="local", safe_mode=False, authz=case)
            spec = ShellPOCSpec(
                candidate_id="C1", script="probe.sh", cells=[cell],
                urls={"local": ""},
            )
            artifact = run_s4_runtime_lab(
                root, "shell-lab", 1,
                cfg, [{"candidate_id": "C1", "authz_cases": [case]}],
                [], [spec], {}, version_universe=["local"],
            )
        self.assertEqual(artifact["status"], "completed")
        self.assertEqual(artifact["fixtures"][0]["replay"]["status"], "stable")
        self.assertEqual(artifact["configuration"]["schema_version"],
                         "runtime-context-v1")
        self.assertTrue(artifact["configuration"]["authz_fixtures"][0]["fixture_id"].startswith("azfx-"))
        encoded = json.dumps(artifact["configuration"], ensure_ascii=False)
        self.assertNotIn("secret-value", encoded)
        self.assertNotIn("do-not-persist", encoded)
        self.assertEqual(artifact["fixtures"][0]["fixture"]["authz_fixture_id"],
                         artifact["configuration"]["authz_fixtures"][0]["fixture_id"])

    def test_normalization_and_merge_retain_typed_gaps(self):
        row = normalize_matrix_record({
            "version": "1.0", "safe_mode": True,
            "precondition_status": "precondition-unavailable",
            "harness_error": "missing JDK",
        }, "s4fx-1", "replay")
        self.assertEqual(row["bucket"], "precondition-unavailable")
        self.assertEqual(row["claim_status"], "not-a-finding")

        merged = merge_runtime_lab_artifacts([{
            "status": "completed", "replay_runs": 2, "version_count": 2,
            "candidate_status": {"C1": {"fixture_count": 1}},
            "fixtures": [{"fixture": {"candidate_id": "C1"}}],
        }, {
            "status": "run-failed", "fixtures": [],
        }])
        self.assertEqual(merged["status"], "completed-with-gaps")
        self.assertEqual(merged["fixture_count"], 1)
        self.assertEqual(merged["claim_status"], "not-a-finding")

    def test_config_pipeline_persists_ordinary_s4_lab_artifact(self):
        class FakeJavaRunner:
            def __init__(self, *_args, **_kwargs):
                pass

            def run_manifest(self, specs, _jars):
                spec = specs[0]
                return {spec.candidate_id: [{
                    "candidate_id": spec.candidate_id,
                    "poc_class": spec.class_name,
                    "version": cell.version,
                    "safe_mode": cell.safe_mode,
                    "precondition": cell.precondition,
                    "returncode": 0,
                    "timed_out": False,
                    "observations": {"PARSED": "ok"},
                } for cell in spec.cells]}

        cfg = TargetConfig(
            name="pipeline-lab", discovery_date="2026-09-21",
            runtime_lab={"enabled": True},
            jars=[{"version": "1.0", "path": "missing.jar"}],
            candidates=[{
                "candidate_id": "C1", "surface": "parser",
                "pocs": [{
                    "class_name": "Probe", "src": "Probe.java",
                    "cells": [{"version": "1.0", "safe_mode": False}],
                }],
            }],
        )
        with tempfile.TemporaryDirectory() as td, patch(
                "agent.orchestrator.stages.JavaMatrixRunner", FakeJavaRunner), \
                patch("agent.tools.s4_runtime_lab.JavaMatrixRunner", FakeJavaRunner):
            result = run_s4(StageContext(Path(td), "pipeline-lab", 1, cfg,
                                         offline=True))
            artifact_path = (Path(td) / "state" / "pipeline-lab" /
                             "round-01" / "S4" / "runtime-lab.json")
            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))

        self.assertEqual(result["runtime_lab"]["scope"], "ordinary-s4")
        self.assertEqual(artifact["fixture_count"], 1)
        self.assertEqual(
            result["summaries"]["C1"]["runtime_lab"]["claim_status"],
            "not-a-finding")

    def test_config_pipeline_records_service_precondition_gap(self):
        cfg = TargetConfig(
            name="service-gap", discovery_date="2026-09-21",
            target_urls={"local": "http://127.0.0.1:1/"},
            runtime_lab={"service": {
                "healthcheck_url": "http://127.0.0.1:1/health",
            }},
            candidates=[{
                "candidate_id": "C1", "surface": "web handler",
                "pocs": [{"script": "probe.sh", "cells": [
                    {"version": "local", "safe_mode": False},
                ]}],
            }],
        )
        with tempfile.TemporaryDirectory() as td:
            result = run_s4(StageContext(Path(td), "service-gap", 1, cfg,
                                         offline=True))
        self.assertEqual(result["summaries"]["C1"]["execution_state"],
                         "precondition-unavailable")
        self.assertEqual(result["runtime_lab"]["status"],
                         "precondition-unavailable")
        self.assertEqual(result["runtime_lab"]["configuration"]["service_lifecycle"]["status"],
                         "precondition-unavailable")


if __name__ == "__main__":
    unittest.main()
