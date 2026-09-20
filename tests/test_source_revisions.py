"""Tests for explicit, workspace-local source-revision build arms."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.orchestrator.config import TargetConfig  # noqa: E402
from agent.tools.build import MatrixCell, POCSpec  # noqa: E402
from agent.tools.s4_runtime_lab import run_s4_runtime_lab  # noqa: E402
from agent.tools.source_revisions import (  # noqa: E402
    SOURCE_REVISION_SCHEMA_VERSION,
    normalize_source_revision_artifacts,
    resolve_source_revision_artifacts,
    source_revision_snapshot,
)


class SourceRevisionTests(unittest.TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vulngate-source-revision-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))

    def test_only_explicit_workspace_artifacts_become_available(self):
        before = self.root / "build" / "before.jar"
        before.parent.mkdir(parents=True)
        before.write_bytes(b"before-build")
        declaration = {
            "enabled": True,
            "arms": [{
                "role": "before", "ref": "a" * 40,
                "jars": [str(before.relative_to(self.root))],
            }, {
                "role": "after", "ref": "b" * 40,
                "jars": [str(self.root.parent / "outside.jar")],
            }],
            "raw_command": "git checkout && mvn package",
        }
        normalized = normalize_source_revision_artifacts(declaration)
        self.assertEqual(SOURCE_REVISION_SCHEMA_VERSION,
                         normalized["schema_version"])
        self.assertEqual(2, len(normalized["arms"]))
        resolved = resolve_source_revision_artifacts(self.root, declaration)
        self.assertEqual("available", resolved["arms"][0]["status"])
        self.assertEqual("precondition-unavailable",
                         resolved["arms"][1]["status"])
        self.assertTrue(resolved["arms"][0]["artifact_digests"])
        snapshot = source_revision_snapshot(resolved)
        encoded = json.dumps(snapshot, ensure_ascii=False)
        self.assertNotIn("_paths", encoded)
        self.assertNotIn("git checkout", encoded)
        self.assertEqual("not-a-finding", snapshot["claim_status"])

        untrusted_snapshot = source_revision_snapshot({
            "enabled": True,
            "arms": [{
                "role": "before", "ref": "a" * 40,
                "status": "available", "reason": "secret=do-not-copy",
                "artifact_count": "not-an-int",
                "paths": ["/private/secret.jar", "../secret.jar",
                          "build/before.jar"],
                "artifact_digests": ["secret", "sha256:" + "c" * 64],
            }],
        })
        safe_encoded = json.dumps(untrusted_snapshot, ensure_ascii=False)
        self.assertNotIn("secret", safe_encoded)
        self.assertEqual(["build/before.jar"],
                         untrusted_snapshot["arms"][0]["paths"])
        self.assertEqual(["sha256:" + "c" * 64],
                         untrusted_snapshot["arms"][0]["artifact_digests"])

    def test_runtime_lab_executes_matching_source_arms_without_checkout(self):
        before = self.root / "build" / "before.jar"
        after = self.root / "build" / "after.jar"
        before.parent.mkdir(parents=True)
        before.write_bytes(b"before-build")
        after.write_bytes(b"after-build")
        before_ref = "a" * 40
        after_ref = "b" * 40
        cfg = TargetConfig(
            name="source-lab", discovery_date="2026-09-21",
            runtime_lab={"max_fixtures": 1, "replay_runs": 1,
                         "safe_modes": [False]},
            source_revision_artifacts={
                "enabled": True,
                "arms": [
                    {"role": "before", "ref": before_ref,
                     "jars": [str(before.relative_to(self.root))]},
                    {"role": "after", "ref": after_ref,
                     "jars": [str(after.relative_to(self.root))]},
                ],
            },
        )
        candidate = {
            "candidate_id": "FIX-1", "entry": "parse",
            "patch_parent": before_ref, "patch_commit": after_ref,
        }
        spec = POCSpec(
            candidate_id="FIX-1", class_name="Probe", src="Probe.java",
            cells=[MatrixCell(version="1.1", safe_mode=False,
                              args=["--fixed-fixture"])],
            entry="parse", input_shape="json",
        )

        class FakeJavaRunner:
            calls = []

            def __init__(self, *_args, **_kwargs):
                pass

            def run_manifest(self, specs, jars_by_version):
                spec_value = specs[0]
                self.calls.append((spec_value.candidate_id,
                                   [cell.version for cell in spec_value.cells],
                                   dict(jars_by_version)))
                rows = []
                for cell in spec_value.cells:
                    if cell.version in {"1.0", "source-before"}:
                        observations = {"ERROR": "OldBuildBehavior"}
                    else:
                        observations = {"PARSED": "safe"}
                    rows.append({
                        "candidate_id": spec_value.candidate_id,
                        "poc_class": spec_value.class_name,
                        "version": cell.version,
                        "safe_mode": cell.safe_mode,
                        "precondition": cell.precondition,
                        "returncode": 0,
                        "timed_out": False,
                        "observations": observations,
                    })
                return {spec_value.candidate_id: rows}

        FakeJavaRunner.calls = []
        with patch("agent.tools.s4_runtime_lab.JavaMatrixRunner",
                   FakeJavaRunner):
            artifact = run_s4_runtime_lab(
                self.root, "source-lab", 1, cfg, [candidate], [spec], [],
                {"1.0": [self.root / "v1.jar"],
                 "1.1": [self.root / "v2.jar"]},
                version_universe=["1.0", "1.1"],
            )

        self.assertEqual("available",
                         artifact["source_revision_artifacts"]["arms"][0]["status"])
        self.assertEqual("available",
                         artifact["source_revision_artifacts"]["arms"][1]["status"])
        self.assertTrue(any("source-before" in versions and
                            "source-after" in versions
                            for _, versions, _ in FakeJavaRunner.calls))
        comparison = artifact["fixtures"][0]["comparison"]
        self.assertEqual("difference-observed",
                         comparison["source_revision_comparison"]["status"])
        self.assertEqual(
            {"observed"},
            {row["status"] for row in comparison[
                "source_revision_observations"]},
        )
        self.assertNotIn("checkout", json.dumps(artifact, ensure_ascii=False).lower())
        self.assertEqual("not-a-finding", comparison["claim_status"])


if __name__ == "__main__":
    unittest.main()
