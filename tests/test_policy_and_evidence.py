import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.sandbox.approval import ApprovalGate  # noqa: E402
from agent.sandbox.runner import (CommandRunner, validate_global_command,
                                  validate_poc_command)  # noqa: E402
from agent.tools.authz import (assert_authz_observations, authz_env,
                               authz_jvm_props, normalize_authz_case)  # noqa: E402
from agent.tools.build import (MatrixCell, ShellMatrixRunner, ShellPOCSpec,
                               scan_source_egress, summarize_candidate)  # noqa: E402
from agent.tools.patch_variants import analyze_patch_history  # noqa: E402
from agent.tools.source_evidence import (build_source_sink_graph,
                                         match_source_sink_paths)  # noqa: E402
from agent.tools.project_profile import build_project_profile  # noqa: E402
from agent.tools.redaction import redact_text  # noqa: E402
from agent.tools.target_rules import composite_chain_hints, patterns_for  # noqa: E402
from agent.tools.novelty import NoveltyChecker  # noqa: E402
from agent.memory.ledger import render_finding_md  # noqa: E402
from agent.tools.conclusion import derive_conclusion  # noqa: E402
from agent.tools.cvss import check_impact_consistency  # noqa: E402


class PolicyTests(unittest.TestCase):
    def test_remote_command_is_denied_and_logged(self):
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "approval.jsonl"
            gate = ApprovalGate(log_path=log)
            runner = CommandRunner(Path(td), gate)
            with self.assertRaises(PermissionError):
                runner.run(["ssh", "root@8.8.8.8"], operation="loopback_connect")
            records = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(records[-1]["operation"], "policy_denied")
            self.assertFalse(records[-1]["allowed"])

    def test_remote_command_is_denied_without_operation_label(self):
        with tempfile.TemporaryDirectory() as td:
            runner = CommandRunner(Path(td), ApprovalGate())
            with self.assertRaises(PermissionError):
                runner.run(["scp", "x", "root@host:/tmp/"])

    def test_authorized_staging_requires_allowlisted_host(self):
        self.assertIsNone(validate_global_command(
            ["ssh", "root@203.0.113.10", "true"], True, {"203.0.113.10"}))
        self.assertIsNotNone(validate_global_command(
            ["ssh", "root@203.0.113.11", "true"], True, {"203.0.113.10"}))
        self.assertIsNone(validate_poc_command(
            ["curl", "http://203.0.113.10:28080/health"], {},
            True, {"203.0.113.10"}))
        self.assertEqual(scan_source_egress(
            "http://203.0.113.10:28080/health", allowed_hosts={"203.0.113.10"}), [])

    def test_external_target_in_poc_environment_is_denied(self):
        with tempfile.TemporaryDirectory() as td:
            script = Path(td) / "probe.sh"
            script.write_text("#!/bin/sh\necho SHOULD_NOT_RUN\n", encoding="utf-8")
            runner = CommandRunner(Path(td), ApprovalGate())
            with self.assertRaises(PermissionError):
                runner.run(
                    ["bash", str(script)],
                    cwd=Path(td),
                    env_extra={"VULNGATE_TARGET_URL": "http://203.0.113.10:8080"},
                    operation="loopback_connect",
                )

    def test_homebrew_at_path_is_not_misread_as_remote_host(self):
        self.assertIsNone(validate_poc_command(
            ["bash", "/tmp/probe.sh"],
            {"JAVA_HOME": "/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home"},
            False, set()))

    def test_patch_history_extracts_fix_variants_read_only(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            subprocess = __import__("subprocess")
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            source = root / "Parser.java"
            source.write_text("class Parser { int readLength(int n) { return n; } }\n", encoding="utf-8")
            subprocess.run(["git", "add", "Parser.java"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "baseline"], cwd=root, check=True)
            source.write_text("class Parser { int readLength(int n) { if (n < 0) throw new IllegalArgumentException(); return n; } }\n", encoding="utf-8")
            subprocess.run(["git", "add", "Parser.java"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "fix: prevent parser overflow"], cwd=root, check=True)
            fixes = analyze_patch_history(root, max_count=30)
            self.assertEqual(len(fixes), 1)
            self.assertEqual(fixes[0]["affected_paths"], ["Parser.java"])
            self.assertTrue(fixes[0]["security_lines"])
            self.assertIn("production-path: validate the changed production path",
                          fixes[0]["variant_hints"])

    def test_source_sink_graph_is_heuristic_and_line_grounded(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            src.mkdir()
            (src / "Handler.java").write_text(
                "class Handler {\n"
                "  void handle(Request request) {\n"
                "    String payload = request.body();\n"
                "    String value = parse(payload);\n"
                "    checkPermission(request);\n"
                "    Runtime.getRuntime().exec(value);\n"
                "  }\n}\n", encoding="utf-8")
            graph = build_source_sink_graph(["src"], root)
            self.assertTrue(graph)
            self.assertTrue(graph[0]["requires_manual_dataflow"])
            self.assertIn("Handler.java", graph[0]["source"])
            self.assertTrue(match_source_sink_paths(
                graph, {"entry": "handle", "code_location": []}))

    def test_project_profile_is_priority_signal_not_vulnerability_verdict(self):
        class Config:
            target_type = "web-app"
            api_hint = "tenant permission upload template"
            scope_constraints = "local"
            entry_points = [{"api": "POST /upload"}]
            source_dirs = []
        profile = build_project_profile(Config(), Path("/tmp"),
                                       danger_site_count=20,
                                       source_sink_path_count=40,
                                       security_fix_count=3)
        self.assertGreaterEqual(profile["score"], 30)
        self.assertIn("不是漏洞存在概率", profile["meaning"])

    def test_report_redaction_masks_common_credentials(self):
        text = redact_text("Authorization: Bearer abc.def; token=secret123; ghp_abc123")
        self.assertNotIn("abc.def", text)
        self.assertNotIn("secret123", text)
        self.assertNotIn("ghp_abc123", text)
        self.assertIn("[REDACTED]", text)

    def test_target_rules_and_composite_hints_are_explicitly_heuristic(self):
        rules = patterns_for("message-rpc")
        self.assertTrue(any(label == "serializer-boundary" for _, label in rules))
        hints = composite_chain_hints([{
            "source": "Api.java:1 body", "transform": ["Api.java:2 parse"],
            "authorization": ["Api.java:3 checkPermission"],
            "sink": "Api.java:4 writeObject",
        }])
        self.assertEqual(hints[0]["confidence"], "heuristic-nearby")
        self.assertTrue(hints[0]["requires_manual_dataflow"])

    def test_novelty_network_error_is_recorded(self):
        import urllib.error
        checker = NoveltyChecker(offline=False)
        checker._api = lambda _path: (_ for _ in ()).throw(
            urllib.error.URLError("offline"))
        self.assertEqual(checker.search("org/repo", "security"), [])
        self.assertTrue(checker.query_errors)


class EvidenceTests(unittest.TestCase):
    def test_memory_canary_cannot_confirm_rce(self):
        cells = [{
            "version": "1.0", "safe_mode": False, "precondition": "none",
            "observations": {
                "INSTANTIATED": "com.example.Exploit",
                "CANARY": "Canary.mark",
                "EFFECT_KIND": "memory-canary-only",
            },
        }]
        summary = summarize_candidate(cells)
        result = derive_conclusion(summary, {
            "surface": "default-config RCE",
            "target_classes": ["com.example.Exploit"],
        }, cells)
        self.assertEqual(result, "候选（待验证）")
        self.assertTrue(summary["safe_equivalent"])

    def test_authz_context_is_metadata_only(self):
        case = normalize_authz_case({
            "case_id": "cross-tenant", "principal": "user-1", "role": "user",
            "tenant_id": "tenant-a", "object_id": "doc-7",
            "object_tenant_id": "tenant-b", "expected_http_codes": [403],
            "expected_object_mutated": False, "expected_authz": "deny",
            "token": "must-not-be-persisted",
        })
        self.assertNotIn("token", case)
        self.assertNotIn("must-not-be-persisted", str(case))
        self.assertNotIn("token", " ".join(authz_env(case)))
        self.assertTrue(any("vulngate.authz.case" in p for p in authz_jvm_props(case)))

    def test_authz_deny_contract_passes(self):
        case = {
            "case_id": "cross-tenant", "principal": "user-1", "role": "user",
            "tenant_id": "tenant-a", "object_id": "doc-7",
            "expected_http_codes": [403], "expected_object_mutated": False,
            "expected_authz": "deny",
        }
        result = assert_authz_observations(case, {
            "HTTP_CODE": "403", "OBJECT_MUTATED": "false", "AUTHZ_RESULT": "deny",
        })
        self.assertEqual(result["status"], "passed")
        self.assertFalse(result["boundary_violation"])

    def test_authz_cross_tenant_allow_is_boundary_violation(self):
        case = {
            "case_id": "cross-tenant", "principal": "user-1", "role": "user",
            "tenant_id": "tenant-a", "object_id": "doc-7",
            "expected_http_codes": [403], "expected_object_mutated": False,
            "expected_authz": "deny",
        }
        result = assert_authz_observations(case, {
            "HTTP_CODE": "200", "OBJECT_MUTATED": "true", "AUTHZ_RESULT": "allow",
        })
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["boundary_violation"])

    def test_authz_missing_observation_is_not_confirmed(self):
        result = assert_authz_observations(
            {"case_id": "admin-only", "expected_authz": "deny"}, {})
        self.assertEqual(result["status"], "unsupported")
        self.assertFalse(result["boundary_violation"])

    def test_shell_matrix_passes_structured_authz_context(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "poc" / "demo" / "round-01" / "src"
            src.mkdir(parents=True)
            (src / "probe.sh").write_text(
                "#!/bin/sh\nprintf 'HTTP_CODE=403\\n'\n"
                "printf 'OBJECT_MUTATED=false\\n'\n"
                "printf 'AUTHZ_RESULT=deny\\n'\n", encoding="utf-8")
            case = {"case_id": "cross-tenant", "principal": "u1", "role": "user",
                    "tenant_id": "a", "object_id": "o7",
                    "expected_http_codes": [403], "expected_object_mutated": False,
                    "expected_authz": "deny"}
            spec = ShellPOCSpec(
                candidate_id="A1", script="probe.sh",
                cells=[MatrixCell(version="local", safe_mode=False, authz=case)])
            results = ShellMatrixRunner(root, "demo", 1).run_manifest([spec])["A1"]
            self.assertEqual(results[0]["authz_assertion"]["status"], "passed")

    def test_finding_report_contains_structured_sections(self):
        report = render_finding_md({
            "title": "test", "summary": "summary", "entrypoint": "/api/x",
            "affected_versions": ["1.0"], "fixed_versions": ["1.1"],
            "source_to_sink": [{"source": "body", "transform": "parse",
                                "validation": "missing", "authorization": "deny",
                                "sink": "write"}],
            "negative_results": ["safe mode blocked"],
            "novelty": {"verdict": "unknown"}, "cvss": {"vector": "-", "score": "-"},
        })
        for marker in ("范围与版本", "Source→Sink 路径", "负向结果与排除项",
                       "Novelty 证据", "CVSS 与前置一致性"):
            self.assertIn(marker, report)

    def test_real_command_marker_can_confirm_rce(self):
        cells = [{
            "version": "1.0", "safe_mode": False, "precondition": "none",
            "observations": {
                "INSTANTIATED": "com.example.Exploit",
                "EFFECT_KIND": "command-marker",
                "EFFECT": "local harmless marker observed",
            },
        }]
        summary = summarize_candidate(cells)
        result = derive_conclusion(summary, {
            "surface": "RCE",
            "target_classes": ["com.example.Exploit"],
        }, cells)
        self.assertEqual(result, "确认")

    def test_high_availability_requires_concurrency_proof(self):
        candidate = {"surface": "CPU denial of service"}
        vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
        ok, _ = check_impact_consistency(candidate, {}, vector)
        self.assertFalse(ok)
        ok, _ = check_impact_consistency(candidate, {
            "availability_proof": [{"concurrency": 4, "service_unavailable": "true"}],
        }, vector)
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
