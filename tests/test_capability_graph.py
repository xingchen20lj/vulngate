"""Capability-primitive search contracts.

The graph is intentionally tested as a lead generator: static composition may
show a useful path, but it must preserve missing primitives and the explicit
runtime/data-flow gate instead of manufacturing a vulnerability finding.
"""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from agent.analysis import capability_graph as CAP  # noqa: E402


def records():
    entries = [
        {"entry_id": "http:read:1", "kind": "http", "file": "api.py",
         "line": 10, "input_shape": "query", "api": "/read",
         "untrusted": True},
        {"entry_id": "http:admin:2", "kind": "http", "file": "api.py",
         "line": 20, "input_shape": "json", "api": "/admin/exec",
         "untrusted": True},
    ]
    sinks = [
        {"sink_id": "sink:read:1", "category": "file-read",
         "file": "service.py", "line": 40},
        {"sink_id": "sink:cred:1", "category": "credential-access",
         "file": "service.py", "line": 50},
        {"sink_id": "sink:exec:1", "category": "command-exec",
         "file": "service.py", "line": 60},
        {"sink_id": "sink:ssrf:1", "category": "network-egress",
         "file": "service.py", "line": 70},
    ]
    flows = [
        {"flow_id": "flow-read", "entry_id": "http:read:1",
         "sink_id": "sink:read:1", "path": ["api", "read"],
         "priority": "high"},
        {"flow_id": "flow-cred", "entry_id": "http:read:1",
         "sink_id": "sink:cred:1", "path": ["api", "credentials"],
         "priority": "high"},
        {"flow_id": "flow-exec", "entry_id": "http:admin:2",
         "sink_id": "sink:exec:1", "path": ["api", "exec"],
         "priority": "high"},
        {"flow_id": "flow-ssrf", "entry_id": "http:read:1",
         "sink_id": "sink:ssrf:1", "path": ["api", "fetch"],
         "priority": "medium"},
    ]
    return entries, sinks, flows


class CapabilityGraphTests(unittest.TestCase):
    def test_composes_observed_primitives_without_claiming_a_finding(self):
        entries, sinks, flows = records()
        graph = CAP.build_capability_graph(entries, sinks, flows)

        self.assertEqual(graph["schema_version"], CAP.CAPABILITY_GRAPH_VERSION)
        self.assertIn("read", graph["summary"]["observed_capabilities"])
        self.assertIn("credential-read", graph["summary"]["observed_capabilities"])
        self.assertIn("exec", graph["summary"]["observed_capabilities"])
        candidate = next(
            item for item in graph["candidates"]
            if item["chain_equation"] == "read -> credential-read -> exec"
        )
        self.assertEqual(candidate["missing_capabilities"], [])
        self.assertEqual(candidate["chain_status"], "composed-hypothesis")
        self.assertEqual(candidate["claim_status"], "not-a-finding")
        self.assertTrue(candidate["requires_manual_dataflow"])
        self.assertTrue(candidate["runtime_required"])
        self.assertTrue(all(rule["declared"]
                            for rule in candidate["transition_rules"]))

    def test_partial_path_keeps_missing_primitive_visible(self):
        entries, sinks, flows = records()
        flows = [flows[0], flows[2]]  # read + exec, but no credential-access flow
        graph = CAP.build_capability_graph(entries, sinks, flows)
        candidate = next(
            item for item in graph["candidates"]
            if item["chain_equation"] == "read -> credential-read -> exec"
        )
        self.assertEqual(candidate["chain_status"], "partial-hypothesis")
        self.assertEqual(candidate["missing_capabilities"], ["credential-read"])
        self.assertIn("need:credential-read", {
            node["node_id"] for node in graph["nodes"]
        })
        self.assertEqual(candidate["precondition_tier_hint"], "extra-primitive")

    def test_candidate_ids_are_order_independent(self):
        entries, sinks, flows = records()
        first = CAP.build_capability_graph(entries, sinks, flows)
        second = CAP.build_capability_graph(
            list(reversed(entries)), list(reversed(sinks)), list(reversed(flows)))
        first_ids = [item["candidate_id"] for item in first["candidates"]]
        second_ids = [item["candidate_id"] for item in second["candidates"]]
        self.assertEqual(first_ids, second_ids)
        self.assertEqual(first["edges"], second["edges"])

    def test_input_to_eval_records_declared_transition_and_typed_gate(self):
        entries, sinks, flows = records()
        sinks.append({"sink_id": "sink:eval:1", "category": "code-eval",
                      "file": "service.py", "line": 80})
        flows.append({"flow_id": "flow-eval", "entry_id": "http:read:1",
                      "sink_id": "sink:eval:1", "path": ["api", "eval"],
                      "priority": "high"})
        graph = CAP.build_capability_graph(entries, sinks, flows)
        candidate = next(item for item in graph["candidates"]
                         if item["chain_equation"] == "input -> eval")
        self.assertEqual(candidate["transition_rules"], [
            {"from": "input", "to": "eval", "declared": True}
        ])
        self.assertIn("typed-effect", candidate["chain_components"])
        self.assertEqual(candidate["claim_status"], "not-a-finding")

    def test_zero_path_limit_never_leaks_an_unbounded_candidate(self):
        entries, sinks, flows = records()
        graph = CAP.build_capability_graph(entries, sinks, flows, max_paths=0)
        self.assertEqual([], graph["candidates"])
        self.assertTrue(graph["summary"]["truncated"])


if __name__ == "__main__":
    unittest.main()
