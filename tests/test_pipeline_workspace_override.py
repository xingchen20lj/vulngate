"""Regression: a caller must be able to give one run a private workspace.

Why this test exists
--------------------
``CheckpointStore`` keys its state directory by ``(target, round)`` alone::

    state/<target>/round-NN/stage-S1.json

There is no run id in that path.  ``run_round`` skips a stage whenever
``store.load_stage(stage)`` returns truthy and ``--force`` was not passed.  So a
second run of the same target and round that shares a workspace does not merely
reuse a *cache* -- it resumes from the first run's checkpoints and reports
success while having executed nothing.  The engine would print a plausible
S1->S8 trace for a run that never happened, which is exactly the class of
silent wrongness the platform must not introduce.

``--workspace`` is the additive escape hatch: default behaviour is untouched
(the value still comes from ``parents[2]``), and a caller may point a run at a
private directory.  These tests pin both halves of that contract.
"""

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"

sys.path.insert(0, str(SCRIPTS))

from agent.orchestrator import pipeline  # noqa: E402
from agent.memory.state import CheckpointStore  # noqa: E402


def _minimal_config(path: Path) -> Path:
    """Smallest config ``TargetConfig.load`` accepts: name + discovery_date."""
    path.write_text(
        json.dumps({"name": "fixture", "discovery_date": "2026-01-01"}),
        encoding="utf-8",
    )
    return path


class _CaptureContext:
    """Run ``main()`` but intercept the StageContext instead of running stages.

    ``main`` reaches the filesystem only through ``StageContext``; stubbing
    ``run_round`` keeps this a pure contract test with no stage side effects.
    """

    def __init__(self, argv):
        self.argv = argv
        self.ctx = None

    def __enter__(self):
        self._orig = pipeline.run_round

        def _fake(ctx, force=False, only=None):
            self.ctx = ctx

        pipeline.run_round = _fake
        return self

    def __exit__(self, *exc):
        pipeline.run_round = self._orig
        return False

    def run(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = pipeline.main(self.argv)
        return rc


class TestWorkspaceDefault(unittest.TestCase):
    """Without ``--workspace`` nothing changes for existing callers."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.cfg = _minimal_config(self.tmp / "cfg.json")

    def tearDown(self):
        self._tmp.cleanup()

    def test_default_workspace_is_the_scripts_directory(self):
        argv = ["--target", "t", "--round", "1", "--config", str(self.cfg)]
        with _CaptureContext(argv) as cap:
            cap.run()
        self.assertEqual(pipeline.WORKSPACE, cap.ctx.workspace)
        # The rule is parents[2] from scripts/agent/orchestrator/pipeline.py,
        # which is <repo>/scripts -- not <repo>.  Getting this wrong yields a
        # permanently empty dashboard with no error, so pin it.
        self.assertEqual(pipeline.WORKSPACE, SCRIPTS)
        self.assertEqual(pipeline.WORKSPACE.name, "scripts")

    def test_default_workspace_is_produced_by_the_parents_2_rule(self):
        self.assertEqual(
            pipeline.WORKSPACE,
            (SCRIPTS / "agent" / "orchestrator" / "pipeline.py").resolve().parents[2],
        )

    def test_parser_accepts_the_flag_and_documents_it(self):
        parser_calls = []

        class _Probe:
            def __call__(self, *a, **kw):
                parser_calls.append((a, kw))

        # Reach the parser the same way main() does, then confirm the option
        # exists and carries a help string (an undocumented flag is a trap).
        import argparse

        captured = {}

        orig = argparse.ArgumentParser.parse_args
        try:
            def _spy(self, argv=None):
                captured["parser"] = self
                return orig(self, argv)

            argparse.ArgumentParser.parse_args = _spy
            argv = ["--target", "t", "--round", "1", "--config", str(self.cfg)]
            with _CaptureContext(argv) as cap:
                cap.run()
        finally:
            argparse.ArgumentParser.parse_args = orig

        opts = {
            o: a for a in captured["parser"]._actions for o in a.option_strings
        }
        self.assertIn("--workspace", opts)
        self.assertIsNone(opts["--workspace"].default)
        self.assertTrue(opts["--workspace"].help)


class TestWorkspaceOverride(unittest.TestCase):
    """With ``--workspace`` the run is fully isolated."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.cfg = _minimal_config(self.tmp / "cfg.json")
        self.private = self.tmp / "private-ws"

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, workspace):
        argv = ["--target", "t", "--round", "3", "--config", str(self.cfg)]
        if workspace is not None:
            argv += ["--workspace", str(workspace)]
        with _CaptureContext(argv) as cap:
            cap.run()
        return cap.ctx

    def test_override_is_honoured(self):
        ctx = self._run(self.private)
        self.assertEqual(ctx.workspace, self.private.resolve())

    def test_override_redirects_the_checkpoint_store(self):
        ctx = self._run(self.private)
        self.assertEqual(
            ctx.store.base,
            (self.private / "state" / "t" / "round-03").resolve(),
        )
        self.assertTrue(ctx.store.base.is_dir())

    def test_override_redirects_reports_and_ledger_roots(self):
        ctx = self._run(self.private)
        reports = ctx.workspace / "reports" / ctx.target / "round-03"
        ledger = ctx.workspace / "ledger" / ctx.target / "round-03"
        self.assertEqual(reports.parts[-3:], ("reports", "t", "round-03"))
        self.assertEqual(ledger.parts[-3:], ("ledger", "t", "round-03"))
        # Both must sit under the override, not under the engine's own scripts/.
        for p in (reports, ledger):
            self.assertTrue(
                str(p.resolve()).startswith(str(self.private.resolve())),
                "%s escaped the private workspace" % p,
            )

    def test_two_runs_with_distinct_workspaces_do_not_share_checkpoints(self):
        ws_a = self.tmp / "run-a"
        ws_b = self.tmp / "run-b"
        ctx_a = self._run(ws_a)
        ctx_b = self._run(ws_b)

        # Write a checkpoint into run A only.
        ctx_a.store.save_stage("S1", {"stage": "S1", "entries": 7})

        self.assertIsNotNone(ctx_a.store.load_stage("S1"))
        self.assertIsNone(
            ctx_b.store.load_stage("S1"),
            "run B saw run A's checkpoint -- runs are not isolated",
        )
        self.assertNotEqual(ctx_a.store.base, ctx_b.store.base)

    def test_same_workspace_still_resumes(self):
        """Isolation must not break ordinary resume inside one workspace."""
        ctx1 = self._run(self.private)
        ctx1.store.save_stage("S2", {"stage": "S2", "candidates": []})
        ctx2 = self._run(self.private)
        self.assertIsNotNone(ctx2.store.load_stage("S2"))

    def test_relative_override_is_resolved(self):
        import os

        cwd = os.getcwd()
        try:
            os.chdir(self.tmp)
            ctx = self._run(Path("rel-ws"))
        finally:
            os.chdir(cwd)
        self.assertTrue(ctx.workspace.is_absolute())
        self.assertEqual(ctx.workspace, (self.tmp / "rel-ws").resolve())


class TestCheckpointLayoutInvariant(unittest.TestCase):
    """The layout the platform depends on, asserted directly on the store."""

    def test_stage_files_live_under_state_target_round(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            store = CheckpointStore(ws, "fastjson2", 2)
            self.assertEqual(
                store.base.resolve(),
                (ws / "state" / "fastjson2" / "round-02").resolve(),
            )
            self.assertEqual(
                store.base.parts[-3:], ("state", "fastjson2", "round-02")
            )
            f = store.save_stage("S4", {"stage": "S4"})
            self.assertEqual(f.parent, store.base)
            self.assertEqual(f.name, "stage-S4.json")

    def test_base_is_derived_from_the_raw_workspace_not_the_resolved_one(self):
        """Pin a pre-existing asymmetry so nobody "fixes" it by accident.

        ``CheckpointStore.__init__`` stores ``self.workspace`` *resolved* but
        builds ``self.base`` from the raw argument.  The two then differ
        whenever the caller's path crosses a symlink -- on macOS
        ``/var/folders/...`` resolves to ``/private/var/folders/...``.

        Both names point at the same inode, so no engine behaviour depends on
        the difference; what does depend on it is any caller that compares the
        two strings or does a string-prefix containment check.  The platform
        therefore always compares resolved paths (see core/paths.py), and this
        test records the reason instead of letting someone silently align the
        two fields and invalidate that reasoning.
        """
        with tempfile.TemporaryDirectory() as tmp:
            # A symlinked path is the only way to observe the difference; skip
            # where the platform's temp dir is already canonical.
            raw = Path(tmp)
            if raw.resolve() == raw:
                self.skipTest("temp dir is already canonical on this platform")

            store = CheckpointStore(raw, "t", 1)
            self.assertNotEqual(store.base, store.workspace / "state" / "t" / "round-01")
            self.assertEqual(
                store.base.resolve(),
                (store.workspace / "state" / "t" / "round-01").resolve(),
            )

    def test_artifact_paths_are_stage_scoped(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = CheckpointStore(Path(tmp), "t", 1)
            p = store.artifact_path("S4", "matrix-runs/C1/cells.json")
            self.assertEqual(
                p,
                (store.base / "S4" / "matrix-runs" / "C1" / "cells.json"),
            )


if __name__ == "__main__":
    unittest.main()
