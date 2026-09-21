import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.tools.research_strategies import composite_chain_candidates  # noqa: E402
from agent.autonomous.run_agent import AutoCtx, static_candidates  # noqa: E402
from agent.orchestrator.config import TargetConfig  # noqa: E402
from agent.orchestrator.stages import StageContext, run_s1, run_s2, run_s3  # noqa: E402


class CompositeChainCandidateTests(unittest.TestCase):
    def hint(self):
        return {
            "source": "src/Api.java:10 request.body()",
            "transform": ["src/Api.java:11 parse(body)"],
            "authorization": ["src/Api.java:12 checkOwner(request)"],
            "sink": "src/Api.java:13 writeObject(value)",
            "confidence": "heuristic-nearby",
            "requires_manual_dataflow": True,
        }

    def test_promotes_hint_to_authz_candidate_with_provenance(self):
        candidates = composite_chain_candidates([self.hint()])
        self.assertEqual(1, len(candidates))
        candidate = candidates[0]
        self.assertTrue(candidate["candidate_id"].startswith("chain-"))
        self.assertEqual("authz", candidate["category"])
        self.assertEqual("composite-chain", candidate["source"])
        self.assertEqual("chain-analysis", candidate["producer"])
        self.assertEqual("heuristic-nearby", candidate["confidence"])
        self.assertTrue(candidate["requires_manual_dataflow"])
        self.assertEqual(
            ["src/Api.java:10", "src/Api.java:11", "src/Api.java:12",
             "src/Api.java:13"],
            candidate["code_location"],
        )
        self.assertEqual(3, len(candidate["authz_cases"]))
        self.assertNotIn("token", str(candidate))

    def test_ids_are_stable_and_duplicates_are_removed(self):
        first = composite_chain_candidates([self.hint(), self.hint()])
        second = composite_chain_candidates([self.hint()])
        self.assertEqual(first, second)

    def test_missing_authorization_is_not_composite_chain_candidate(self):
        hint = self.hint()
        hint["authorization"] = []
        self.assertEqual([], composite_chain_candidates([hint]))

    def test_max_items_is_a_presentation_bound(self):
        hints = []
        for i in range(4):
            hint = self.hint()
            hint["source"] = "src/Api%d.java:10 request.body()" % i
            hints.append(hint)
        candidates = composite_chain_candidates(hints, max_items=2)
        self.assertEqual(2, len(candidates))
        self.assertEqual([], composite_chain_candidates(hints, max_items=0))

    def test_config_pipeline_promotes_s1_chain_into_s2(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            src.mkdir()
            (src / "Api.java").write_text(
                "class Api {\n"
                "  void handle(Request request) {\n"
                "    String body = request.body();\n"
                "    String value = parse(body);\n"
                "    checkPermission(request);\n"
                "    Runtime.getRuntime().exec(value);\n"
                "  }\n}\n",
                encoding="utf-8",
            )
            cfg = TargetConfig(
                name="chain-fixture", discovery_date="2026-09-20",
                target_type="web-app", source_dirs=["src"],
                max_candidates=0,
            )
            ctx = StageContext(root, cfg.name, 1, cfg, offline=True)
            s1 = run_s1(ctx)
            self.assertGreaterEqual(s1["composite_chain_candidate_count"], 1)
            s2 = run_s2(ctx)
            self.assertTrue(s2["generated_chain_candidates"])
            self.assertTrue(any(
                item["candidate_id"].startswith("chain-")
                for item in s2["matrix"]
            ))
            experiment_plans = ctx.store.read_artifact(
                "S2", "experiment-plans.json")
            self.assertTrue(experiment_plans)
            strategy = ctx.store.read_artifact("S2", "research-strategy.json")
            self.assertEqual("research-strategy-v1",
                             strategy["schema_version"])
            self.assertEqual("not-a-finding", strategy["claim_status"])
            chain_plan = next(item for item in experiment_plans
                              if item["candidate_id"].startswith("chain-"))
            self.assertTrue(chain_plan["scheduled"])
            self.assertEqual("surface-variant-plan-v1",
                             chain_plan["surface_variant_plan"]["schema_version"])
            self.assertEqual(
                {"positive", "negative", "environment-gap"},
                {row["lane"] for row in chain_plan["surface_variant_plan"][
                    "lanes"]},
            )
            self.assertIn("authorization-boundary",
                          {item["kind"] for item in chain_plan["plans"]})
            s3 = run_s3(ctx)
            chain_note = next(item for item in s3["notes"]
                              if item["candidate_id"].startswith("chain-"))
            self.assertEqual(chain_plan, chain_note["experiment_plan"])

    def test_autonomous_static_candidates_reads_chain_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = TargetConfig(
                name="chain-auto", discovery_date="2026-09-20",
                static_candidates=True,
            )
            path = (root / "state" / cfg.name / "round-01" / "S1" /
                    "composite-chain-candidates.json")
            path.parent.mkdir(parents=True)
            path.write_text(
                '[{"candidate_id":"chain-test", "surface":"chain"}]',
                encoding="utf-8",
            )
            ctx = AutoCtx(root, cfg, llm=None, offline=True,
                          max_candidates=1, max_rounds=1)
            candidates, ids = static_candidates(ctx, 1)
            self.assertEqual(["chain-test"], ids)
            self.assertEqual("chain-test", candidates[0]["candidate_id"])


if __name__ == "__main__":
    unittest.main()
