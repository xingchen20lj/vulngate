"""Tests for bounded surface-specific experiment variants."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.tools.experiment_planner import plan_candidate_experiments  # noqa: E402
from agent.tools.surface_variants import (  # noqa: E402
    SURFACE_VARIANT_SCHEMA_VERSION,
    build_surface_variant_plan,
    normalize_surface_variant_plan,
)


class SurfaceVariantTests(unittest.TestCase):

    def test_every_surface_has_positive_negative_and_environment_lanes(self):
        for surface, attack_class in (
                ("web", "authorization"),
                ("protocol", "stateful resource exhaustion"),
                ("cloud", "identity policy"),
                ("mobile", "deep-link lifecycle authorization"),
                ("native", "webview method body"),
        ):
            plan = build_surface_variant_plan(
                surface, action="replay-new-variant",
                attack_class=attack_class, variants=["alternate-variant"])
            self.assertEqual(SURFACE_VARIANT_SCHEMA_VERSION,
                             plan["schema_version"])
            self.assertEqual(surface, plan["surface"])
            self.assertEqual(
                {"positive", "negative", "environment-gap"},
                {row["lane"] for row in plan["lanes"]},
            )
            self.assertEqual(
                {"positive", "negative", "environment-gap"},
                set(plan["summary"]["lane_counts"]),
            )
            self.assertTrue(all(
                row["claim_status"] == "not-a-finding"
                for row in plan["lanes"]
            ))

    def test_action_and_target_type_select_surface_deterministically(self):
        first = build_surface_variant_plan(
            target_type="mobile-app", action="add-negative-control",
            attack_class="webview origin bridge")
        second = build_surface_variant_plan(
            target_type="mobile-app", action="add-negative-control",
            attack_class="webview origin bridge")
        self.assertEqual(first, second)
        self.assertEqual("mobile", first["surface"])
        self.assertEqual("add-negative-control", first["action"])
        self.assertIn("mobile-webview-origin-bridge", {
            row["variant_id"] for row in first["selected_variants"]
        })

    def test_normalization_rebuilds_incomplete_lanes_and_drops_untrusted_fields(self):
        plan = build_surface_variant_plan("native", action="review-source-dataflow")
        forged = dict(plan)
        forged["secret_payload"] = "do-not-persist"
        forged["lanes"] = list(plan["lanes"][:1])
        normalized = normalize_surface_variant_plan(forged)
        encoded = json.dumps(normalized, ensure_ascii=False)
        self.assertNotIn("do-not-persist", encoded)
        self.assertEqual(
            {"positive", "negative", "environment-gap"},
            {row["lane"] for row in normalized["lanes"]},
        )
        self.assertEqual("not-a-finding", normalized["claim_status"])

    def test_experiment_planner_reuses_strategy_surface_plan(self):
        surface_plan = build_surface_variant_plan(
            "protocol", action="trace-capability-transition",
            attack_class="state machine")
        result = plan_candidate_experiments(
            {"candidate_id": "P1", "target_type": "message-rpc",
             "surface": "protocol parser"},
            research_guidance={
                "next_action": "trace-capability-transition",
                "surface_variant_plan": surface_plan,
            })
        self.assertEqual(surface_plan, result["surface_variant_plan"])
        self.assertEqual("not-a-finding", result["provenance"]["claim_status"])
        self.assertNotIn("payload", json.dumps(result, ensure_ascii=False).lower())


if __name__ == "__main__":
    unittest.main()
