"""Tests for actual surface-variant lane/state-machine witnesses."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.tools.surface_variants import (  # noqa: E402
    normalize_variant_fixture_context,
)
from agent.tools.variant_evidence import (  # noqa: E402
    VARIANT_EVIDENCE_SCHEMA_VERSION,
    summarize_variant_evidence,
)


class VariantEvidenceTests(unittest.TestCase):

    def context(self, lane: str = "positive",
                variant_id: str = "protocol-parser-type-boundary"):
        return normalize_variant_fixture_context({
            "surface": "protocol",
            "variant_id": variant_id,
            "lane": lane,
        })

    def test_complete_lane_requires_actual_state_and_typed_effect(self):
        context = self.context(variant_id="protocol-frame-state-order")
        row = {
            "version": "1.0", "safe_mode": False,
            "returncode": 0, "timed_out": False,
            "sequence": context["state_steps"],
            "observations": {
                "STEP_TRACE": context["state_steps"],
                "PARSED": "ok",
                "EFFECT_KIND": "file-marker",
                "EFFECT": "local marker detail must not persist",
            },
        }
        summary = summarize_variant_evidence(context, [row])
        self.assertEqual(VARIANT_EVIDENCE_SCHEMA_VERSION,
                         summary["schema_version"])
        self.assertEqual("observed", summary["status"])
        self.assertEqual([], summary["missing_observations"])
        self.assertIn("state-sequence", summary["observed_signals"])
        self.assertTrue(summary["cells"][0]["typed_effect_observed"])
        self.assertNotIn("local marker detail", json.dumps(summary))
        self.assertEqual("not-a-finding", summary["claim_status"])

    def test_declared_lane_is_not_evidence_when_trace_is_partial(self):
        context = self.context(variant_id="protocol-frame-state-order")
        row = {
            "version": "1.0", "safe_mode": False,
            "returncode": 0, "timed_out": False,
            "sequence": context["state_steps"],
            "observations": {"STEP_TRACE": [context["state_steps"][0]],
                             "PARSED": "ok"},
        }
        summary = summarize_variant_evidence(context, [row])
        self.assertEqual("partial", summary["status"])
        self.assertIn("state-sequence", summary["missing_observations"])
        self.assertIn("typed-effect", summary["missing_observations"])
        self.assertIn("typed-effect-missing", summary["falsifier_signals"])

    def test_environment_lane_preserves_gap_without_negative_claim(self):
        context = self.context("environment-gap")
        row = {
            "version": "1.0", "safe_mode": False,
            "precondition_status": "precondition-unavailable",
            "harness_error": "missing runtime secret=do-not-copy",
        }
        summary = summarize_variant_evidence(context, [row])
        self.assertEqual("environment-gap", summary["status"])
        self.assertIn("environment-gap", summary["observed_signals"])
        self.assertEqual(1, summary["cells_with_gap"])
        self.assertNotIn("do-not-copy", json.dumps(summary))
        self.assertEqual("not-a-finding", summary["claim_status"])


if __name__ == "__main__":
    unittest.main()
