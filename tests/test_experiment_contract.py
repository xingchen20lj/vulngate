import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "scripts"))

from agent.tools.build import (  # noqa: E402
    MatrixCell,
    ShellMatrixRunner,
    ShellPOCSpec,
    parse_observations,
    summarize_candidate,
)
from agent.tools.experiment import normalize_experiment  # noqa: E402
from agent.tools.cvss import check_impact_consistency  # noqa: E402


class ExperimentContractTests(unittest.TestCase):
    def test_declaration_is_bounded_and_rejects_step_fragments(self):
        steps, workers, probe, warnings = normalize_experiment(
            ["seed", "bad step", "mutate", "$(touch /tmp/nope)"] +
            ["step-%d" % n for n in range(20)],
            999,
            True,
        )
        self.assertEqual(steps[:2], ["seed", "mutate"])
        self.assertLessEqual(len(steps), 16)
        self.assertEqual(workers, 64)
        self.assertTrue(probe)
        self.assertTrue(any("invalid sequence step" in item for item in warnings))
        self.assertTrue(any("capped" in item for item in warnings))

    def test_observation_parser_keeps_ordered_step_and_state_traces(self):
        observations = parse_observations(
            "STEP=seed\n"
            "STEP_EVIDENCE=seed:fixture-created\n"
            "STATE=seeded\n"
            "STEP=mutate\n"
            "STEP_EVIDENCE=mutate:second-write\n"
            "STATE=mutated\n"
        )
        self.assertEqual(observations["STEP_TRACE"], ["seed", "mutate"])
        self.assertEqual(observations["STEP_EVIDENCE"],
                         ["seed:fixture-created", "mutate:second-write"])
        self.assertEqual(observations["STATE_TRACE"], ["seeded", "mutated"])

    def test_shell_runner_persists_experiment_and_real_availability_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "poc" / "demo" / "round-01" / "src"
            src.mkdir(parents=True)
            (src / "probe.sh").write_text(
                "#!/bin/sh\n"
                "printf 'STEP=seed\\n'\n"
                "printf 'STEP_EVIDENCE=seed:fixture-created\\n'\n"
                "printf 'STATE=seeded\\n'\n"
                "printf 'STEP=mutate\\n'\n"
                "printf 'STEP_EVIDENCE=mutate:state-transition\\n'\n"
                "printf 'CONCURRENCY=%s\\n' \"$VULNGATE_CONCURRENCY\"\n"
                "printf 'SERVICE_UNAVAILABLE=true\\n'\n",
                encoding="utf-8",
            )
            cell = MatrixCell(
                version="local", safe_mode=False,
                sequence=["seed", "mutate", "probe"],
                concurrency=4,
                availability_probe=True,
            )
            spec = ShellPOCSpec(candidate_id="RACE1", script="probe.sh",
                                cells=[cell])
            cells = ShellMatrixRunner(root, "demo", 1).run_manifest([spec])["RACE1"]

            self.assertEqual(cells[0]["sequence"], ["seed", "mutate", "probe"])
            self.assertEqual(cells[0]["concurrency"], 4)
            self.assertTrue(cells[0]["availability_probe"])
            self.assertEqual(cells[0]["observations"]["CONCURRENCY"], "4")
            self.assertEqual(cells[0]["observations"]["STEP_TRACE"], ["seed", "mutate"])
            self.assertEqual(cells[0]["observations"]["STATE_TRACE"], ["seeded"])

            summary = summarize_candidate(cells)
            self.assertEqual(summary["availability_proof"][0]["concurrency"], 4)
            self.assertEqual(summary["experiment_evidence"][0]["declared_sequence"],
                             ["seed", "mutate", "probe"])
            self.assertEqual(summary["experiment_evidence"][0]["sequence_status"],
                             "partial")
            self.assertEqual(summary["experiment_evidence"][0]["step_evidence"],
                             ["seed:fixture-created", "mutate:state-transition"])
            ok, reason = check_impact_consistency(
                {"surface": "stateful race denial of service"}, summary,
                "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
            self.assertTrue(ok, reason)

    def test_declared_concurrency_without_observation_is_not_availability_proof(self):
        cell = MatrixCell(version="local", safe_mode=False,
                          sequence=["probe"], concurrency=8,
                          availability_probe=True)
        summary = summarize_candidate([{
            "version": cell.version,
            "safe_mode": cell.safe_mode,
            "precondition": cell.precondition,
            **{"sequence": cell.sequence,
               "concurrency": cell.concurrency,
               "availability_probe": cell.availability_probe,
               "experiment": {"warnings": cell.experiment_warnings}},
            "observations": {"ERROR": "TimeoutException"},
        }])
        self.assertEqual(summary["availability_proof"], [])
        self.assertEqual(summary["experiment_evidence"][0]["declared_concurrency"], 8)


if __name__ == "__main__":
    unittest.main()
