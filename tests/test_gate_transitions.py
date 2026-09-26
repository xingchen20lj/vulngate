"""Table-style tests for the security decision transitions."""

import sys
import unittest
from pathlib import Path

from hypothesis import given, strategies as st


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.orchestrator.gates import (  # noqa: E402
    g0_dead_code,
    g1_reachable,
    g1b_gate_blocks,
    g3_novelty,
    g4_runtime,
    g5_cvss,
)
from agent.tools.build import S4_EVIDENCE_POLICY_VERSION  # noqa: E402


class GateTransitionTests(unittest.TestCase):
    @given(
        execution_state=st.sampled_from((
            "run-failed", "blocked", "timed-out", "unexecuted",
            "precondition-unavailable", "needs-harness-observer",
        )),
        marker=st.text(min_size=0, max_size=80),
    )
    def test_incomplete_cells_never_promote_from_claims(self, execution_state,
                                                        marker):
        summary = {
            "evidence_policy_version": S4_EVIDENCE_POLICY_VERSION,
            "execution_state": execution_state,
            "observations": {"RESP_MATCH": marker},
            "independent_effect_evidence": [],
        }
        self.assertFalse(g4_runtime(summary, candidate={"impact": "RCE"}).passed)

    def test_static_and_novelty_gate_states_are_explicit(self):
        self.assertFalse(g0_dead_code({"api": "dead"}, 0).passed)
        self.assertTrue(g0_dead_code({"api": "live"}, 1).passed)
        self.assertFalse(g1_reachable({"untrusted": False}).passed)
        self.assertTrue(g1_reachable({"untrusted": True}).passed)
        self.assertFalse(g1b_gate_blocks({
            "gate_status": "disabled", "default_config_reachable": False,
        }).passed)
        self.assertTrue(g1b_gate_blocks({
            "gate_status": "enabled", "default_config_reachable": True,
        }).passed)
        for verdict in ("candidate-0day", "known-family-with-increment",
                        "upstream-fixed", "unknown-query-failed"):
            self.assertTrue(g3_novelty({"verdict": verdict}).passed)
        self.assertFalse(g3_novelty({"verdict": "not-a-verdict"}).passed)

    def test_runtime_gate_never_promotes_incomplete_or_claim_only_cells(self):
        base = {"evidence_policy_version": S4_EVIDENCE_POLICY_VERSION,
                "execution_state": "executed-with-effect"}
        self.assertFalse(g4_runtime({}).passed)
        self.assertFalse(g4_runtime({**base, "execution_state": "run-failed"}).passed)
        self.assertFalse(g4_runtime({**base, "effect_evidence": [{
            "kind": "command-executed"}], "independent_effect_evidence": []},
            candidate={"impact": "RCE"}).passed)
        self.assertTrue(g4_runtime({**base, "instantiated": [{
            "class": "com.example.Target"}], "errors": []}).passed)
        self.assertTrue(g4_runtime({**base, "leaked": [{
            "leaked": "file=/tmp/marker"}], "errors": []}).passed)
        self.assertTrue(g4_runtime({**base, "errors": [{
            "error": "OutOfMemoryError: heap"}]}).passed)
        self.assertFalse(g4_runtime({**base}).passed)
        self.assertTrue(g4_runtime({"exclusion_basis": {
            "kind": "g1-unreachable", "source_refs": ["src/A.java:1"],
        }}, intended="排除").passed)
        self.assertFalse(g4_runtime({}, intended="排除").passed)

    def test_cvss_gate_checks_precondition_consistency(self):
        self.assertTrue(g5_cvss(
            "0", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H").passed)
        self.assertFalse(g5_cvss(
            "0", "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N").passed)


if __name__ == "__main__":
    unittest.main()
