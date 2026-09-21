"""Source inventory / Top-N separation contract (spec §6, §19.1, §19.2, §19.7).

These tests exist because the failure they guard against is *invisible*: a
truncated scan does not error, it just reports a smaller number, and every
downstream ratio then looks healthy.  Each assertion below is the difference
between "we scanned everything" and "we scanned a prefix and called it
everything".
"""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from agent.analysis import inventory as inv  # noqa: E402
from agent.analysis import languages as lang  # noqa: E402
from agent.analysis import models  # noqa: E402
from agent.tools import source_evidence as se  # noqa: E402

HAVE_RG = shutil.which("rg") is not None


def write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def java_class(name: str, package: str, body_lines) -> str:
    body = "\n".join(body_lines)
    return ("package %s;\n\npublic class %s {\n    public void run() {\n%s\n    }\n}\n"
            % (package, name, body))


class InventoryFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()


@unittest.skipUnless(HAVE_RG, "ripgrep is required for the inventory scan")
class TopNIsolationTests(InventoryFixture):
    """Spec §19.1 -- Top-N must not affect coverage."""

    def test_one_hundred_sinks_are_all_indexed(self):
        lines = ["        ProcessBuilder pb%d = new ProcessBuilder(cmd);" % i
                 for i in range(100)]
        write(self.root, "src/main/java/com/foo/TaskService.java",
              java_class("TaskService", "com.foo", lines))

        result = inv.build_inventory(self.root, ["src/main/java"], target="fixture")
        command_sinks = [s for s in result.sinks if s.category == "command-exec"]
        self.assertEqual(len(command_sinks), 100,
                         "sink index must hold every hit, not a prefix")
        self.assertGreaterEqual(result.counts()["sinks"], 100)

    def test_presentation_cap_does_not_touch_the_index(self):
        lines = ["        ProcessBuilder pb%d = new ProcessBuilder(cmd);" % i
                 for i in range(60)]
        write(self.root, "src/main/java/com/foo/TaskService.java",
              java_class("TaskService", "com.foo", lines))
        result = inv.build_inventory(self.root, ["src/main/java"], target="fixture")

        digest = se.summarize_hits(result.sinks, 10)
        self.assertEqual(len(digest), 10)
        self.assertGreater(len(result.sinks), len(digest))

    def test_source_evidence_scan_all_is_uncapped_while_grep_hits_is_bounded(self):
        write(self.root, "src/A.java", java_class("A", "p", [
            "        ProcessBuilder pb%d = new ProcessBuilder(cmd);" % i
            for i in range(40)]))
        everything = se.scan_all_hits(r"ProcessBuilder", ["src"], self.root)
        bounded = se.grep_hits(r"ProcessBuilder", ["src"], self.root, max_lines=5)
        self.assertEqual(len(everything), 40)
        self.assertEqual(len(bounded), 5)

    def test_autonomous_entry_scan_is_uncapped(self):
        from agent.autonomous import run_agent
        for i in range(30):
            write(self.root, "src/main/java/p/Foo%d.java" % i,
                  java_class("Foo%d" % i, "p", ["        Object o = parseObject(s);"]))
        everything = run_agent.scan_all_entries([self.root / "src"])
        self.assertEqual(len(everything), 30,
                         "the old scanner returned at most 20 entries")
        bounded = run_agent.scan_entries([self.root / "src"])
        self.assertLessEqual(len(bounded), 20)


@unittest.skipUnless(HAVE_RG, "ripgrep is required for the inventory scan")
class MultiLanguageTests(InventoryFixture):
    """Spec §19.2 -- every language in the unified table is enumerated."""

    SAMPLES = [
        ("src/main/java/A.java", "java"),
        ("src/main/kotlin/B.kt", "kotlin"),
        ("src/app/C.py", "python"),
        ("src/app/D.go", "go"),
        ("src/web/E.js", "javascript"),
        ("src/web/F.ts", "typescript"),
        ("src/web/G.tsx", "typescript"),
        ("src/app/H.rs", "rust"),
        ("src/native/I.c", "c"),
        ("src/native/J.cpp", "cpp"),
        ("src/native/K.cs", "csharp"),
        ("src/native/L.swift", "swift"),
        ("src/native/M.m", "objective-c"),
        ("src/native/N.mm", "objective-c"),
    ]

    def test_all_languages_are_production_source(self):
        for rel, language in self.SAMPLES:
            write(self.root, rel, "// placeholder\n")
        result = inv.build_inventory(self.root, ["src"], target="fixture")
        indexed = {record.file: record for record in result.files}
        for rel, language in self.SAMPLES:
            self.assertIn(rel, indexed, "%s not enumerated" % rel)
            record = indexed[rel]
            self.assertEqual(record.language, language)
            self.assertTrue(record.production, "%s not production" % rel)
            self.assertTrue(record.indexed)
            self.assertEqual(record.skip_reason, "")

    def test_suffix_table_matches_the_spec(self):
        expected = {
            "java": [".java"], "kotlin": [".kt", ".kts"], "scala": [".scala"],
            "clojure": [".clj", ".cljc", ".cljs"], "python": [".py"],
            "go": [".go"], "ruby": [".rb"], "php": [".php"], "rust": [".rs"],
            "csharp": [".cs"], "swift": [".swift"],
        }
        for language, suffixes in expected.items():
            self.assertEqual(sorted(lang.LANGUAGE_SUFFIXES[language]), sorted(suffixes))
        for suffix in (".js", ".jsx", ".mjs", ".cjs"):
            self.assertEqual(lang.LANGUAGE_SUFFIXES["javascript"].count(suffix), 1)
        for suffix in (".ts", ".tsx"):
            self.assertEqual(lang.LANGUAGE_SUFFIXES["typescript"].count(suffix), 1)

    def test_shared_suffix_resolves_deterministically(self):
        # ``.h`` is declared by both c and objective-c; the owner is fixed and
        # overridable, so a target can opt into the other reading.
        self.assertEqual(lang.suffix_owner_language("x.h"), "c")
        original = dict(lang.AMBIGUOUS_SUFFIX_OWNER)
        try:
            lang.set_ambiguous_suffix_owner(".h", "objective-c")
            self.assertEqual(lang.suffix_owner_language("x.h"), "objective-c")
        finally:
            lang.AMBIGUOUS_SUFFIX_OWNER.clear()
            lang.AMBIGUOUS_SUFFIX_OWNER.update(original)
            lang._rebuild_indexes()
        self.assertEqual(lang.suffix_owner_language("x.h"), "c")

    def test_source_globs_covers_every_registered_suffix(self):
        globs = set(lang.source_globs())
        for suffixes in lang.LANGUAGE_SUFFIXES.values():
            for suffix in suffixes:
                self.assertIn("*%s" % suffix, globs)


@unittest.skipUnless(HAVE_RG, "ripgrep is required for the inventory scan")
class NoSilentOmissionTests(InventoryFixture):
    """Spec §19.7 -- a source file is ``indexed`` or carries a ``skip_reason``."""

    def _populate(self):
        write(self.root, "src/main/java/p/Prod.java", "class Prod {}\n")
        write(self.root, "src/test/java/p/ProdTest.java", "class ProdTest {}\n")
        write(self.root, "src/main/java/gen/Thing.generated.java",
              "class Thing {}\n")
        write(self.root, "vendor/lib/Vend.java", "class Vend {}\n")
        write(self.root, "README.md", "# not source\n")

    def test_every_source_file_has_an_explicit_state(self):
        self._populate()
        result = inv.build_inventory(self.root, ["src", "vendor"], target="fixture")
        self.assertTrue(result.files, "no files enumerated at all")
        for record in result.files:
            self.assertTrue(
                record.indexed or record.skip_reason,
                "%s is neither indexed nor explained" % record.file)
            if not record.production:
                self.assertTrue(record.skip_reason)

    def test_skip_reasons_name_the_actual_rule(self):
        self._populate()
        result = inv.build_inventory(self.root, ["src", "vendor"], target="fixture")
        by_file = {r.file: r for r in result.files}
        self.assertEqual(by_file["src/test/java/p/ProdTest.java"].skip_reason, "test")
        self.assertIn("generated", by_file["src/main/java/gen/Thing.generated.java"].skip_reason)
        self.assertEqual(by_file["vendor/lib/Vend.java"].skip_reason, "vendor")
        self.assertTrue(by_file["src/main/java/p/Prod.java"].production)

    def test_non_source_files_are_counted_not_indexed(self):
        self._populate()
        # Scan the whole root, not just the source dirs -- the count exists to
        # prove nothing source-shaped was dropped anywhere in the tree.
        result = inv.build_inventory(self.root, ["."], target="fixture")
        self.assertNotIn("README.md", [r.file for r in result.files])
        self.assertGreaterEqual(result.non_source_files, 1)

    def test_skip_histogram_is_reported(self):
        self._populate()
        result = inv.build_inventory(self.root, ["src", "vendor"], target="fixture")
        histogram = result.counts()["skip_reason_histogram"]
        self.assertEqual(histogram.get("test"), 1)
        self.assertEqual(histogram.get("vendor"), 1)
        self.assertEqual(histogram.get("generated"), 1)


@unittest.skipUnless(HAVE_RG, "ripgrep is required for the inventory scan")
class ExclusionAuditTests(InventoryFixture):
    """Excluded directories leave a record instead of vanishing."""

    def test_excluded_directory_is_recorded_with_a_file_count(self):
        for i in range(3):
            write(self.root, "node_modules/pkg/Lib%d.js" % i, "// dep\n")
        write(self.root, "src/main/java/p/Prod.java", "class Prod {}\n")
        result = inv.build_inventory(self.root, ["."], target="fixture")
        record = next((d for d in result.excluded_dirs
                       if d["rel_path"] == "node_modules"), None)
        self.assertIsNotNone(record, "node_modules exclusion was silent")
        self.assertEqual(record["reason"], "excluded-dir:node_modules")
        self.assertEqual(record["file_count"], 3)
        self.assertEqual(record["producer"], "walk")

    def test_include_override_reinstates_an_excluded_directory(self):
        write(self.root, "target/real/Source.java", "class Source {}\n")
        default = inv.build_inventory(self.root, ["."], target="fixture")
        self.assertNotIn("target/real/Source.java", [r.file for r in default.files])

        flt = lang.SourceFilter(include_overrides=["target"])
        overridden = inv.build_inventory(self.root, ["."], source_filter=flt,
                                         target="fixture")
        files = {r.file: r for r in overridden.files}
        self.assertIn("target/real/Source.java", files)
        self.assertTrue(files["target/real/Source.java"].production)

    def test_enumeration_is_deterministic(self):
        for name in ("b", "a", "c"):
            write(self.root, "src/%s/X.java" % name, "class X {}\n")
        first = [r.file for r in inv.build_inventory(
            self.root, ["src"], target="fixture").files]
        second = [r.file for r in inv.build_inventory(
            self.root, ["src"], target="fixture").files]
        self.assertEqual(first, second)
        self.assertEqual(first, sorted(first))


@unittest.skipUnless(HAVE_RG, "ripgrep is required for the inventory scan")
class IndexContentTests(InventoryFixture):
    """Entries / sinks / controls carry provenance and per-file counts."""

    def _populate(self):
        write(self.root, "src/main/java/com/foo/UserController.java", java_class(
            "UserController", "com.foo", [
                "        if (!permissionService.checkOwner(userId)) { throw new IllegalStateException(); }",
                "        ProcessBuilder pb = new ProcessBuilder(cmd);",
                "        String q = \"select * from t where id=\" + id;",
                "        session.execute(q);",
            ]))
        write(self.root, "src/main/java/com/foo/Service.java", java_class(
            "Service", "com.foo", ["        Object o = readValue(input);"]))

    def test_sinks_carry_provenance(self):
        self._populate()
        result = inv.build_inventory(self.root, ["src"], target="fixture")
        self.assertTrue(result.sinks)
        for sink in result.sinks:
            self.assertTrue(sink.sink_id)
            self.assertTrue(sink.file)
            self.assertGreater(sink.line, 0)
            self.assertIn(sink.severity_hint, ("high", "medium", "low"))
            self.assertEqual(sink.producer, "regex")
            self.assertEqual(sink.evidence_type, "static-observed")

    def test_sink_categories_cover_command_and_sql(self):
        self._populate()
        result = inv.build_inventory(self.root, ["src"], target="fixture")
        categories = {s.category for s in result.sinks}
        self.assertIn("command-exec", categories)
        self.assertIn("sql-exec", categories)

    def test_per_file_counts_are_written_back(self):
        self._populate()
        result = inv.build_inventory(self.root, ["src"], target="fixture")
        record = next(r for r in result.files
                      if r.file.endswith("UserController.java"))
        self.assertGreater(record.sinks, 0)
        self.assertGreater(record.controls, 0)
        self.assertEqual(record.entries, 0)

    def test_controls_include_authorization(self):
        self._populate()
        result = inv.build_inventory(self.root, ["src"], target="fixture")
        categories = {c.category for c in result.controls}
        self.assertIn("authorization", categories)

    def test_records_round_trip_through_json(self):
        self._populate()
        result = inv.build_inventory(self.root, ["src"], target="fixture")
        for record in (result.sinks[:3] + result.entries[:3] + result.controls[:3]):
            payload = record.as_dict()
            restored = type(record).from_dict(payload)
            self.assertEqual(restored.as_dict(), payload)


@unittest.skipUnless(HAVE_RG, "ripgrep is required for the inventory scan")
class CoverageStoreTests(InventoryFixture):
    def test_store_round_trip_and_index_listing(self):
        self._tmp2 = tempfile.TemporaryDirectory()
        workspace = Path(self._tmp2.name)
        try:
            write(self.root, "src/main/java/p/Prod.java",
                  java_class("Prod", "p", ["        ProcessBuilder pb = new ProcessBuilder(cmd);"]))
            result = inv.build_inventory(self.root, ["src"], target="demo")
            store = inv.CoverageStore(workspace, "demo")
            written = inv.persist_inventory(store, result)
            self.assertIn("source-inventory", written)
            self.assertEqual(store.base.name, "coverage")
            self.assertEqual(store.base.parent.name, "demo")
            self.assertEqual(store.base.parent.parent.name, "state")
            sinks = store.read_records("sink-index")
            self.assertTrue(sinks)
            self.assertIn("sink-index", store.existing_indices())
            summary = store.read("inventory-summary")
            self.assertIn("counts", summary)
            self.assertIn("excluded_dirs", summary)
            capability = store.read("capability-graph")
            self.assertEqual(capability.get("schema_version"),
                             "capability-graph-v1")
            self.assertIsInstance(store.read_records("capability-candidates"), list)
            self.assertEqual(store.read("does-not-exist", default=[]), [])
        finally:
            self._tmp2.cleanup()

    def test_persisted_index_matches_the_in_memory_result(self):
        self._tmp2 = tempfile.TemporaryDirectory()
        workspace = Path(self._tmp2.name)
        try:
            write(self.root, "src/main/java/p/Prod.java",
                  java_class("Prod", "p", ["        ProcessBuilder pb = new ProcessBuilder(cmd);"]))
            result = inv.build_inventory(self.root, ["src"], target="demo")
            store = inv.CoverageStore(workspace, "demo")
            inv.persist_inventory(store, result)
            self.assertEqual(len(store.read_records("sink-index")), len(result.sinks))
            self.assertEqual(len(store.read_records("entry-index")), len(result.entries))
            self.assertEqual(len(store.read_records("source-inventory")),
                             len(result.files))
        finally:
            self._tmp2.cleanup()


class ModelStateTests(unittest.TestCase):
    def test_rank_and_reviewed_semantics(self):
        self.assertTrue(models.is_reviewed("excluded"))
        self.assertTrue(models.is_reviewed("runtime-verified"))
        self.assertTrue(models.is_reviewed("reviewed"))
        self.assertFalse(models.is_reviewed("indexed"))
        self.assertTrue(models.is_open("indexed"))

    def test_merge_state_is_monotonic(self):
        self.assertEqual(models.merge_state("indexed", "reviewed"), "reviewed")
        self.assertEqual(models.merge_state("reviewed", "indexed"), "reviewed")
        self.assertEqual(models.merge_state("unseen", "excluded"), "excluded")

    def test_unknown_state_falls_back(self):
        self.assertEqual(models.normalize_audit_state("nonsense"), "indexed")
        self.assertEqual(models.normalize_audit_state(None, default="pending"), "pending")

    def test_heuristic_confidence_is_not_proving(self):
        self.assertFalse(models.is_proving("heuristic-callgraph"))
        self.assertFalse(models.is_proving("heuristic-nearby"))
        self.assertTrue(models.is_proving("exact"))


if __name__ == "__main__":
    unittest.main()
