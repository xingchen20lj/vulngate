import json
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
    _cell_experiment_env,
    parse_observations,
    summarize_candidate,
)
from agent.tools.experiment import (  # noqa: E402
    normalize_capability_contract,
    normalize_experiment,
    normalize_residual_contracts,
)
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

    def test_capability_contract_is_bounded_and_exposed_as_metadata(self):
        contract = normalize_capability_contract({
            "required_capabilities": ["read", "bad value", "exec"] +
            ["cap-%d" % index for index in range(30)],
            "observed_capabilities": ["read", "$(touch /tmp/nope)"],
            "missing_capabilities": ["exec"],
            "transition_rules": [
                {"from": "read", "to": "exec", "declared": True},
                {"from": "bad value", "to": "exec"},
            ],
            "goal": "g" * 300,
            "typed_effect_required": True,
        })
        self.assertEqual(contract["required_capabilities"][:2], ["read", "exec"])
        self.assertEqual(len(contract["required_capabilities"]), 16)
        self.assertEqual(contract["observed_capabilities"], ["read"])
        self.assertEqual(contract["transition_rules"], [
            {"from": "read", "to": "exec", "declared": True},
        ])
        self.assertEqual(len(contract["goal"]), 160)
        self.assertTrue(contract["typed_effect_required"])

        cell = MatrixCell(version="local", safe_mode=False,
                          capability_contract=contract)
        env = _cell_experiment_env(cell)
        self.assertEqual(json.loads(env["VULNGATE_CAPABILITIES"])[:2],
                         ["read", "exec"])
        self.assertEqual(json.loads(env["VULNGATE_TRANSITIONS"]), [
            {"from": "read", "to": "exec", "declared": True},
        ])
        self.assertNotIn("touch", env["VULNGATE_CAPABILITY_CONTRACT"])

    def test_residual_contract_is_bounded_exposed_and_parsed(self):
        residual_id = "rr-01234567890123456789"
        contract = normalize_residual_contracts([{
            "residual_id": residual_id,
            "kind": "variant",
            "reason_code": "unverified",
            "allowed_falsifiers": ["variant-rejected", "bad value"],
            "secret": "must-not-cross",
        }])
        self.assertEqual(["variant-rejected"],
                         contract[0]["allowed_falsifiers"])
        cell = MatrixCell(version="local", safe_mode=False,
                          residual_contracts=contract)
        env = _cell_experiment_env(cell)
        self.assertEqual([residual_id], json.loads(env["VULNGATE_RESIDUAL_IDS"]))
        self.assertNotIn("must-not-cross", env["VULNGATE_RESIDUAL_CONTRACT"])
        observations = parse_observations(
            "RESIDUAL_ID=%s\nRESIDUAL_STATUS=falsified\n"
            "RESIDUAL_FALSIFIER=variant-rejected\n" % residual_id)
        self.assertEqual(residual_id, observations["RESIDUAL_ID"])
        self.assertEqual("falsified", observations["RESIDUAL_STATUS"])
        summary = summarize_candidate([{
            "candidate_id": "C1", "version": "local", "safe_mode": False,
            "precondition": "none", "returncode": 0, "timed_out": False,
            "residual_contracts": contract, "observations": observations,
        }])
        row = summary["residual_falsifiers"][0]
        self.assertTrue(row["contract_declared"])
        self.assertFalse(row["effect_observed"])
        self.assertEqual("executed", row["execution_state"])
        self.assertEqual("not-a-finding", row["claim_status"])

    def test_residual_error_does_not_count_as_executed_falsifier(self):
        residual_id = "rr-01234567890123456789"
        contract = normalize_residual_contracts([{
            "residual_id": residual_id,
            "kind": "variant",
            "allowed_falsifiers": ["variant-rejected"],
        }])
        summary = summarize_candidate([{
            "candidate_id": "C1", "version": "local", "safe_mode": False,
            "precondition": "none", "returncode": 0, "timed_out": False,
            "residual_contracts": contract,
            "observations": {
                "RESIDUAL_ID": residual_id,
                "RESIDUAL_STATUS": "falsified",
                "RESIDUAL_FALSIFIER": "variant-rejected",
                "ERROR": "probe failed after marker",
            },
        }])
        self.assertEqual("run-failed",
                         summary["residual_falsifiers"][0]["execution_state"])

    def test_parser_keeps_capability_and_transition_traces(self):
        observations = parse_observations(
            "CAPABILITY=read\n"
            "CAPABILITY_EVIDENCE=read:fixture\n"
            "TRANSITION=read->exec\n"
            "TRANSITION_EVIDENCE=read->exec:local-marker\n"
        )
        self.assertEqual(observations["CAPABILITY_TRACE"], ["read"])
        self.assertEqual(observations["CAPABILITY_EVIDENCE"], ["read:fixture"])
        self.assertEqual(observations["TRANSITION_TRACE"], ["read->exec"])
        self.assertEqual(observations["TRANSITION_EVIDENCE"],
                         ["read->exec:local-marker"])

    def test_capability_summary_distinguishes_partial_from_typed_complete(self):
        contract = {
            "required_capabilities": ["read", "credential-read", "exec"],
            "transition_rules": [
                {"from": "read", "to": "credential-read"},
                {"from": "credential-read", "to": "exec"},
            ],
            "typed_effect_required": True,
        }
        partial = summarize_candidate([{
            "version": "local", "safe_mode": False, "precondition": "none",
            "capability_contract": contract,
            "observations": {
                "CAPABILITY_TRACE": ["read", "exec"],
                "CAPABILITY_EVIDENCE": ["read:fixture"],
                "TRANSITION_TRACE": ["read->credential-read"],
                "TRANSITION_EVIDENCE": ["read->credential-read:fixture"],
            },
        }])
        row = partial["capability_evidence"][0]
        self.assertEqual(row["status"], "partial")
        self.assertEqual(row["missing_capabilities"], ["credential-read"])
        self.assertEqual(row["missing_transitions"], ["credential-read->exec"])
        self.assertEqual(row["missing_capability_evidence"], ["exec"])
        self.assertFalse(row["typed_effect_observed"])
        self.assertEqual(row["claim_status"], "not-a-finding")

        complete = summarize_candidate([{
            "version": "local", "safe_mode": False, "precondition": "none",
            "capability_contract": contract,
            "observations": {
                "CAPABILITY_TRACE": ["read", "credential-read", "exec"],
                "CAPABILITY_EVIDENCE": [
                    "read:fixture", "credential-read:fixture", "exec:fixture",
                ],
                "TRANSITION_TRACE": [
                    "read->credential-read", "credential-read->exec",
                ],
                "TRANSITION_EVIDENCE": [
                    "read->credential-read:fixture",
                    "credential-read->exec:fixture",
                ],
                "EFFECT_KIND": "command-marker",
                "EFFECT": "local fixture marker",
            },
        }])
        complete_row = complete["capability_evidence"][0]
        self.assertEqual(complete_row["status"], "complete")
        self.assertTrue(complete_row["typed_effect_observed"])

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
                "printf 'CAPABILITY=read\\n'\n"
                "printf 'CAPABILITY_EVIDENCE=read:fixture\\n'\n"
                "printf 'CAPABILITY=exec\\n'\n"
                "printf 'CAPABILITY_EVIDENCE=exec:fixture\\n'\n"
                "printf 'TRANSITION=read->exec\\n'\n"
                "printf 'TRANSITION_EVIDENCE=read->exec:fixture\\n'\n"
                "printf 'SERVICE_UNAVAILABLE=true\\n'\n",
                encoding="utf-8",
            )
            cell = MatrixCell(
                version="local", safe_mode=False,
                sequence=["seed", "mutate", "probe"],
                concurrency=4,
                availability_probe=True,
                capability_contract={
                    "required_capabilities": ["read", "exec"],
                    "transition_rules": [{"from": "read", "to": "exec"}],
                },
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
            self.assertEqual(cells[0]["observations"]["CAPABILITY_TRACE"],
                             ["read", "exec"])
            self.assertEqual(cells[0]["experiment"]["capability_contract"]
                             ["required_capabilities"], ["read", "exec"])

            summary = summarize_candidate(cells)
            self.assertEqual(summary["availability_proof"][0]["concurrency"], 4)
            self.assertEqual(summary["experiment_evidence"][0]["declared_sequence"],
                             ["seed", "mutate", "probe"])
            self.assertEqual(summary["experiment_evidence"][0]["sequence_status"],
                             "partial")
            self.assertEqual(summary["experiment_evidence"][0]["step_evidence"],
                             ["seed:fixture-created", "mutate:state-transition"])
            self.assertEqual(summary["capability_evidence"][0]["status"], "complete")
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
