"""Tests for bounded cross-version/fix comparison orchestration."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.tools.variant_comparisons import (  # noqa: E402
    COMPARISON_SCHEMA_VERSION,
    build_comparison_contract,
    normalize_comparison_contract,
    summarize_comparison_observations,
)


class VariantComparisonTests(unittest.TestCase):

    def test_contract_keeps_version_fix_and_sibling_axes_bounded(self):
        contract = build_comparison_contract({
            "candidate_id": "FIX-1",
            "patch_parent": "0123456789abcdef0123456789abcdef01234567",
            "patch_commit": "89abcdef0123456789abcdef0123456789abcdef",
            "patch_variants": [
                "alternate-codec: inspect sibling",
                "boundary-variant: inspect ownership",
            ],
        }, ["1.0", "1.1", "1.2"])
        self.assertEqual(COMPARISON_SCHEMA_VERSION,
                         contract["schema_version"])
        self.assertEqual(
            [{"before": "1.0", "after": "1.1", "axis": "configured-version"},
             {"before": "1.1", "after": "1.2", "axis": "configured-version"}],
            contract["version_pairs"],
        )
        self.assertEqual(2, len(contract["source_revision"]))
        self.assertEqual({"alternate-codec", "boundary-variant"},
                         {row["variant"] for row in contract["sibling_variants"]})
        self.assertNotIn("inspect sibling", json.dumps(contract, ensure_ascii=False))
        self.assertEqual("not-a-finding", contract["claim_status"])

    def test_normalization_rebuilds_only_allowlisted_axes(self):
        raw = {
            "schema_version": COMPARISON_SCHEMA_VERSION,
            "version_pairs": [{"before": "1.0", "after": "1.1",
                                "axis": "forged"}],
            "source_revision": [{"role": "before", "ref": "not-a-commit"}],
            "sibling_variants": [{"variant": "payload-and-command"}],
            "sensitive": "must-not-persist",
        }
        normalized = normalize_comparison_contract(raw)
        encoded = json.dumps(normalized, ensure_ascii=False)
        self.assertNotIn("must-not-persist", encoded)
        self.assertEqual("configured-version",
                         normalized["version_pairs"][0]["axis"])
        self.assertEqual([], normalized["source_revision"])
        self.assertEqual([], normalized["sibling_variants"])
        self.assertEqual("not-a-finding", normalized["claim_status"])

    def test_summary_separates_bucket_change_signature_drift_and_gap(self):
        contract = build_comparison_contract(
            {"candidate_id": "C1"}, ["1.0", "1.1"])
        result = summarize_comparison_observations(contract, [
            {"version": "1.0", "safe_mode": False,
             "bucket": "crash", "signature": "A"},
            {"version": "1.1", "safe_mode": False,
             "bucket": "ok", "signature": ""},
            {"version": "1.0", "safe_mode": True,
             "bucket": "crash", "signature": "A"},
            {"version": "1.1", "safe_mode": True,
             "bucket": "crash", "signature": "B"},
        ], primary_version="1.1")
        self.assertEqual("difference-observed", result["status"])
        states = {(row["safe_mode"], row["status"])
                  for row in result["version_observations"]}
        self.assertIn((False, "bucket-difference"), states)
        self.assertIn((True, "signature-drift"), states)
        self.assertEqual("not-a-finding", result["claim_status"])

        gap = summarize_comparison_observations(contract, [
            {"version": "1.0", "safe_mode": False,
             "bucket": "crash", "signature": "A"},
            {"version": "1.1", "safe_mode": False,
             "bucket": "precondition-unavailable"},
        ])
        self.assertEqual("inconclusive", gap["status"])
        self.assertGreaterEqual(gap["inconclusive_count"], 1)


if __name__ == "__main__":
    unittest.main()
