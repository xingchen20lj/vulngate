"""Regression guards for the built-in macOS / native adaptation.

VulnGate's pipeline was written against JVM targets.  The eight changes listed in
``macos/README.md`` remove the hard-coded JVM assumptions so that native targets
(.app / Mach-O / Swift / ObjC) can be audited end to end.  They live in the
plugin source itself rather than being applied at runtime, which means a later
edit can drop one of them with no visible symptom -- these tests fail loudly
when that happens.

Everything asserted here is deliberately additive: JVM auditing remains the
primary use case and must not regress.
"""

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.analysis.languages import ALL_SUFFIXES, LANGUAGE_SUFFIXES  # noqa: E402
from agent.tools.project_profile import build_project_profile  # noqa: E402
from agent.tools.source_evidence import (DANGER_PATTERNS,  # noqa: E402
                                         DEFAULT_SOURCE_GLOBS,
                                         SOURCE_MAP_PRESETS)
from agent.tools.target_rules import TARGET_RULES  # noqa: E402

# Stamp written into every adapted site, so a lost change shows up as a missing
# marker rather than as a silent behavioural regression.
SENTINEL = "vulngate-macos-universal"

NATIVE_SUFFIXES = [".swift", ".m", ".mm", ".hpp", ".mjs", ".cjs"]

NATIVE_SINK_LABELS = [
    "native-command-exec", "native-credential", "native-deserialization",
    "native-dynamic-load", "native-webview-bridge", "native-ipc",
    "native-applescript", "native-unsafe-c", "native-url-scheme-entry",
    "native-privilege", "native-entitlement",
]

PATCHED_FILES = [
    "scripts/agent/tools/source_evidence.py",
    "scripts/agent/tools/target_rules.py",
    "scripts/agent/tools/project_profile.py",
    "scripts/agent/orchestrator/stages.py",
]


class NativeGlobTests(unittest.TestCase):
    """Change #1 -- DEFAULT_SOURCE_GLOBS."""

    def test_native_extensions_are_scanned(self):
        for suffix in NATIVE_SUFFIXES:
            self.assertIn("*" + suffix, DEFAULT_SOURCE_GLOBS)

    def test_jvm_extensions_still_scanned(self):
        for suffix in (".java", ".kt", ".py", ".js", ".ts", ".go", ".rs"):
            self.assertIn("*" + suffix, DEFAULT_SOURCE_GLOBS)


class NativeSinkTests(unittest.TestCase):
    """Change #2 -- DANGER_PATTERNS."""

    def test_all_macos_sink_labels_present(self):
        labels = {label for _, label in DANGER_PATTERNS}
        for label in NATIVE_SINK_LABELS:
            self.assertIn(label, labels)

    def test_native_sinks_match_real_code(self):
        samples = {
            "native-command-exec": "NSTask *task = [[NSTask alloc] init];",
            "native-credential": "OSStatus s = SecItemCopyMatching(query, &item);",
            "native-deserialization": "u = [[NSKeyedUnarchiver alloc] init];",
            "native-webview-bridge": 'webView.evaluateJavaScript("x");',
            "native-ipc": "NSXPCConnection *c = [[NSXPCConnection alloc] init];",
            "native-dynamic-load": 'void *h = dlopen("libx.dylib", RTLD_NOW);',
        }
        by_label = {label: pattern for pattern, label in DANGER_PATTERNS}
        for label, code in samples.items():
            self.assertIn(label, by_label, "missing sink label %s" % label)
            self.assertIsNotNone(re.search(by_label[label], code),
                                 "sink %s did not match %r" % (label, code))


class NativePresetAndRuleTests(unittest.TestCase):
    """Changes #3 and #4 -- SOURCE_MAP_PRESETS and TARGET_RULES."""

    def test_source_map_preset_exists(self):
        self.assertIn("native", SOURCE_MAP_PRESETS)

    def test_native_app_target_type_exists(self):
        self.assertIn("native-app", TARGET_RULES)

    def test_native_app_rules_match_real_code(self):
        samples = [
            "application:openURL:options:",
            "handleGetURLEvent",
            "NSXPCConnection",
            "WKWebView",
            "NSKeyedUnarchiver",
            "AuthorizationExecuteWithPrivileges",
        ]
        rules = TARGET_RULES["native-app"]
        for sample in samples:
            matched = [label for pattern, label in rules
                       if re.search(pattern, sample)]
            self.assertTrue(matched, "no native-app rule matched %r" % sample)

    def test_native_app_rules_are_distinct_from_library(self):
        # Falling back to the library rule set scored 1 hit where native-app
        # scores 28 on the same target -- guard the distinction.
        self.assertNotEqual([p for p, _ in TARGET_RULES["native-app"]],
                            [p for p, _ in TARGET_RULES["library"]])


class JvmHardcodingRemovedTests(unittest.TestCase):
    """Changes #5, #6 and #8 -- hard-coded .java assumptions in stages.py."""

    def setUp(self):
        self.stages = (ROOT / "scripts" / "agent" / "orchestrator"
                       / "stages.py").read_text(encoding="utf-8")

    def test_gate_scan_no_longer_pins_java_glob(self):
        self.assertNotIn('globs=["*.java"]', self.stages)

    def test_s2_entry_match_accepts_native_sources(self):
        self.assertNotIn('if t.endswith(".java")', self.stages)
        self.assertIn("_src_exts", self.stages)
        # The suffix set is now derived from the single source of truth
        # (agent.analysis.languages) rather than restated here, so assert both
        # halves: the matcher reads the shared table, and that table really
        # carries the native suffixes.
        self.assertRegex(self.stages, r"_src_exts = tuple\(ALL_SUFFIXES\)")
        for suffix in NATIVE_SUFFIXES:
            self.assertIn(suffix, ALL_SUFFIXES,
                          "unified suffix table lost %s" % suffix)

    def test_s1_jar_path_tolerates_outside_workspace(self):
        from unittest.mock import patch
        from agent.orchestrator.config import TargetConfig
        from agent.orchestrator.stages import StageContext, run_s1
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td) / "audit"
            workspace.mkdir()
            outside = Path(td) / "audit-other"
            outside.mkdir()
            jar = outside / "target.jar"
            jar.write_bytes(b"fixture")
            cfg = TargetConfig("fixture", "2026-09-16",
                               jars=[{"version": "1", "path": str(jar)}])
            ctx = StageContext(workspace, "fixture", 1, cfg, offline=True)
            with patch("agent.tools.search.jar_classes", return_value=[]):
                result = run_s1(ctx)
            self.assertEqual(str(jar), result["jars"][0]["path"])


class ProfileAndSentinelTests(unittest.TestCase):
    """Change #7 plus the sentinel contract for every patched site."""

    def test_native_sources_counted_in_profile(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            src.mkdir()
            for name in ("a.swift", "b.m", "c.mm", "d.hpp"):
                (src / name).write_text("// x\n", encoding="utf-8")
            # A JVM-only suffix set would count this project as empty.
            config = SimpleNamespace(target_type="native-app", entry_points=[],
                                     source_dirs=["src"])
            profile = build_project_profile(config, root)
            self.assertEqual(profile["source_file_count"], 4)

    def test_sentinel_present_at_every_patched_site(self):
        for rel in PATCHED_FILES:
            text = (ROOT / rel).read_text(encoding="utf-8")
            self.assertIn(SENTINEL, text, "sentinel missing from %s" % rel)


class AdapterToolkitTests(unittest.TestCase):
    """The macOS adapter ships with the plugin, not as a separate download."""

    def test_toolkit_is_complete(self):
        expected = [
            "macos/README.md",
            "macos/run-audit.sh",
            "macos/macos-app-recon.sh",
            "macos/templates/poc-native.sh",
            "macos/bin/app2source.sh",
            "macos/bin/macho2source.py",
            "macos/bin/asar_tool.py",
            "macos/bin/asar_stats.py",
            "macos/bin/jar2source.py",
            "macos/bin/gen-config.py",
            "macos/bin/patch-vulngate.py",
            "macos/bin/vg-run.py",
        ]
        missing = [rel for rel in expected if not (ROOT / rel).exists()]
        self.assertEqual(missing, [], "missing adapter files: %s" % missing)

    def test_verifier_confirms_all_eight_changes(self):
        script = ROOT / "macos" / "bin" / "patch-vulngate.py"
        proc = subprocess.run(
            [sys.executable, str(script), "--plugin", str(ROOT), "--verify"],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("已生效 8/8", proc.stdout)

    def test_repository_root_holds_no_patch_backup(self):
        """A backup directory at the repository root means `--apply` ran there.

        The eight changes are part of the source, so there is nothing to apply
        against this tree; such a backup could only hold the pre-patch state and
        would be shipped by install.sh.
        """
        backup = ROOT / ".vulngate-macos-backup"
        self.assertFalse(
            backup.exists(),
            "remove .vulngate-macos-backup/ from the repository root: it holds "
            "pre-patch copies of scripts/agent/** and install.sh would ship it")


if __name__ == "__main__":
    unittest.main()
