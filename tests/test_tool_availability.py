"""Regression: a missing external tool must fail loudly and name itself.

Found while hardening the S1 ingress: ``tools/search.py`` shelled out to
``rg`` by bare name, and when the binary was not on ``PATH`` (a real situation --
macOS keeps ``rg`` in ``/usr/local/bin``, which a GUI-launched host often omits)
``subprocess.run`` raised a bare ``FileNotFoundError: [Errno 2] No such file or
directory: 'rg'`` from deep inside S1.

Two things were wrong with that:

* the message names neither the tool nor the fix, so the traceback reads as an
  engine bug rather than a missing dependency;
* it surfaced mid-stage, after S1 had already begun writing state.

The fix raises :class:`agent.tools.search.ToolUnavailable` with an actionable
message.  Degrading to an empty result was explicitly rejected: ``rg`` feeds
``count_references``, which feeds gate G0, where zero references *means dead
code*.  Returning ``[]`` for a missing binary would silently mark every entry
point as dead -- a wrong audit dressed up as a successful one.
"""

import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from agent.tools import search as search_mod  # noqa: E402


class TestToolUnavailable(unittest.TestCase):

    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_rg_missing_binary_raises_tool_unavailable(self):
        with mock.patch.object(subprocess, "run",
                               side_effect=FileNotFoundError(2, "No such file", "rg")):
            with self.assertRaises(search_mod.ToolUnavailable) as ctx:
                search_mod.rg("pattern", self.tmp)
        message = str(ctx.exception)
        self.assertIn("rg", message)
        self.assertIn("PATH", message)

    def test_jar_missing_binary_raises_tool_unavailable(self):
        with mock.patch.object(subprocess, "run",
                               side_effect=FileNotFoundError(2, "No such file", "jar")):
            with self.assertRaises(search_mod.ToolUnavailable) as ctx:
                search_mod.jar_classes(self.tmp / "x.jar")
        self.assertIn("jar", str(ctx.exception))

    def test_unzip_missing_binary_raises_tool_unavailable(self):
        with mock.patch.object(subprocess, "run",
                               side_effect=FileNotFoundError(2, "No such file", "unzip")):
            with self.assertRaises(search_mod.ToolUnavailable) as ctx:
                search_mod.unzip_jar(self.tmp / "x.jar", self.tmp / "out")
        self.assertIn("unzip", str(ctx.exception))

    def test_count_references_does_not_mask_a_missing_tool(self):
        """The dangerous alternative: returning 0 and reporting dead code."""
        with mock.patch.object(subprocess, "run",
                               side_effect=FileNotFoundError(2, "No such file", "rg")):
            with self.assertRaises(search_mod.ToolUnavailable):
                search_mod.count_references(self.tmp, "demo.Symbol")

    def test_tool_unavailable_is_not_a_plain_runtimeerror_only(self):
        """It must stay an ordinary exception so callers can catch it cheaply."""
        self.assertTrue(issubclass(search_mod.ToolUnavailable, RuntimeError))
        self.assertFalse(issubclass(search_mod.ToolUnavailable, OSError))

    def test_run_tool_passes_argv_through_without_a_shell(self):
        captured = {}

        def _fake(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return subprocess.CompletedProcess(argv, 0, "", "")

        with mock.patch.object(subprocess, "run", side_effect=_fake):
            search_mod.run_tool(["rg", "-n", "--no-heading", "pat", str(self.tmp)])
        self.assertIsInstance(captured["argv"], list)
        self.assertEqual(captured["argv"][0], "rg")
        # No shell, and the caller's keyword arguments are forwarded.
        self.assertNotIn("shell", captured["kwargs"])
        self.assertTrue(captured["kwargs"].get("capture_output"))


class TestRealToolPathStillWorks(unittest.TestCase):
    """The guard must not break the normal path when the tool is present."""

    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    @unittest.skipUnless(__import__("shutil").which("rg"), "rg not installed")
    def test_rg_finds_a_real_match(self):
        (self.tmp / "a.txt").write_text("needle here\n", encoding="utf-8")
        hits = search_mod.rg("needle", self.tmp)
        self.assertEqual(len(hits), 1)
        self.assertIn("needle", hits[0])

    @unittest.skipUnless(__import__("shutil").which("rg"), "rg not installed")
    def test_rg_returns_empty_for_no_match(self):
        (self.tmp / "a.txt").write_text("nothing\n", encoding="utf-8")
        self.assertEqual([], search_mod.rg("absent-symbol-xyz", self.tmp))

    @unittest.skipUnless(__import__("shutil").which("rg"), "rg not installed")
    def test_count_references_counts_real_hits(self):
        (self.tmp / "a.txt").write_text("demo.Symbol\ndemo.Symbol\n", encoding="utf-8")
        self.assertEqual(2, search_mod.count_references(self.tmp, "demo.Symbol"))


if __name__ == "__main__":
    unittest.main()
