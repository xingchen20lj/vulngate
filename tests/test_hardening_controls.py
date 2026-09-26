"""Regression tests for the security controls added in the 1.3 remediation."""

import json
import http.server
import io
import sqlite3
import socket
import ssl
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.orchestrator.config import TargetConfig  # noqa: E402
import agent_cli  # noqa: E402
import apply_branch_governance  # noqa: E402
import validate_branch_governance  # noqa: E402
from agent.analysis import audit_guard  # noqa: E402
from agent.sandbox.approval import ApprovalGate  # noqa: E402
from agent.sandbox.http_observer import (  # noqa: E402
    LoopbackHTTPObserver,
    _origin,
)
from agent.sandbox.isolation import detect_isolation_backend  # noqa: E402
from agent.sandbox.effects import (  # noqa: E402
    EFFECT_KINDS,
    AuthorizationStateCollector,
    FilesystemDiffCollector,
    FixtureDBCollector,
    JVMProtocolStateCollector,
    ProcessEffectCollector,
    supported_effect_kinds,
)
from agent.orchestrator.work_budget import (  # noqa: E402
    WorkBudget,
    WorkBudgetExceeded,
)
from agent.tools.build import (  # noqa: E402
    _collect_effect_observers,
    _prepare_effect_observers,
    summarize_candidate,
)


class HardeningControlTests(unittest.TestCase):
    def test_branch_governance_apply_payload_is_explicit_and_bounded(self):
        policy = apply_branch_governance.load_policy(ROOT)
        payload = apply_branch_governance.build_payload(policy)
        self.assertEqual(["test", "security"],
                         payload["required_status_checks"]["contexts"])
        self.assertTrue(payload["enforce_admins"])
        self.assertFalse(payload["allow_force_pushes"])
        self.assertFalse(payload["allow_deletions"])

    def test_branch_governance_policy_matches_ci_contract(self):
        result = validate_branch_governance.validate(ROOT)
        self.assertTrue(result["local_policy_valid"])
        self.assertEqual(["test", "security"], result["required_checks"])
        self.assertEqual("requires-github-admin-readback",
                         result["remote_enforcement"])

    def test_work_budget_children_cannot_mint_parent_resources(self):
        now = [0.0]
        root = WorkBudget(
            name="round", wall_seconds=10, candidate_slots=1,
            scan_files=5, clock=lambda: now[0])
        child = root.child(
            "candidate-1", wall_seconds=900, candidate_slots=2,
            scan_files=4)
        self.assertEqual(10.0, child.remaining("wall_seconds"))
        child.acquire_candidate()
        child.record_scan(files=4)
        sibling = root.child("candidate-2", candidate_slots=2)
        with self.assertRaises(WorkBudgetExceeded):
            sibling.acquire_candidate()
        with self.assertRaises(WorkBudgetExceeded):
            child.record_scan(files=2)
        now[0] = 11.0
        with self.assertRaises(WorkBudgetExceeded):
            child.check()

    def test_independent_effect_collectors_observe_only_bounded_diffs(self):
        self.assertEqual(set(EFFECT_KINDS), set(supported_effect_kinds()))
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            observed_file = root / "marker.txt"
            fs = FilesystemDiffCollector()
            before = fs.snapshot(root)
            observed_file.write_text("secret marker", encoding="utf-8")
            after = fs.snapshot(root)
            effect = fs.collect("run-1", "C1", "cell-1", before, after).as_dict()
            self.assertEqual("observed", effect["status"])
            self.assertIn("marker.txt", effect["details"]["added"])
            self.assertNotIn("secret marker", json.dumps(effect))

            proc = ProcessEffectCollector()
            before_proc = {"status": "ok", "processes": {}}
            after_proc = {"status": "ok", "processes": {
                "12": {"pid": 12, "ppid": 1, "comm": "fixture-worker"},
            }}
            proc_effect = proc.collect(
                "run-1", "C1", "cell-1", before_proc, after_proc,
                ["fixture-worker"]).as_dict()
            self.assertEqual("observed", proc_effect["status"])
            self.assertEqual([], proc_effect["details"]["removed_processes"])
            pending = proc.collect(
                "run-1", "C1", "cell-1", before_proc, after_proc, []).as_dict()
            self.assertEqual("pending", pending["status"])

            db_path = root / "fixture.sqlite"
            connection = sqlite3.connect(db_path)
            connection.execute("create table auth (user text, role text)")
            connection.execute("insert into auth values ('alice', 'user')")
            connection.commit()
            connection.close()
            db = FixtureDBCollector()
            db_before = db.snapshot(db_path, ["auth"])
            connection = sqlite3.connect(db_path)
            connection.execute("update auth set role='admin' where user='alice'")
            connection.commit()
            connection.close()
            db_after = db.snapshot(db_path, ["auth"])
            db_effect = db.collect(
                "run-1", "C1", "cell-1", db_before, db_after).as_dict()
            self.assertEqual("observed", db_effect["status"])
            self.assertEqual(["auth"], db_effect["details"]["changed_tables"])
            self.assertNotIn("alice", json.dumps(db_before))
            self.assertNotIn("admin", json.dumps(db_after))

            auth_path = root / "auth.json"
            auth_path.write_text(json.dumps({"users": {"alice": "user"}}),
                                 encoding="utf-8")
            auth = AuthorizationStateCollector()
            auth_before = auth.snapshot(auth_path, ["/users/alice"])
            auth_path.write_text(json.dumps({"users": {"alice": "admin"}}),
                                 encoding="utf-8")
            auth_after = auth.snapshot(auth_path, ["/users/alice"])
            auth_effect = auth.collect(
                "run-1", "C1", "cell-1", auth_before, auth_after).as_dict()
            self.assertEqual("observed", auth_effect["status"])
            self.assertEqual(["/users/alice"],
                             auth_effect["details"]["changed_paths"])
            self.assertNotIn("admin", json.dumps(auth_after))

    def test_only_registered_independent_effects_reach_runtime_summary(self):
        valid = FilesystemDiffCollector().collect(
            "run-1", "C1", "cell-1",
            {"status": "ok", "entries": {}},
            {"status": "ok", "entries": {
                "marker": {"kind": "file", "size": 1, "digest": "x"},
            }},
        ).as_dict()
        forged = dict(valid)
        forged["collector_id"] = "poc.stdout"
        summary = summarize_candidate([{
            "candidate_id": "C1", "version": "1", "safe_mode": False,
            "precondition": "none", "cell_id": "cell-1",
            "returncode": 0, "timed_out": False,
            "observed_effects": [valid, forged], "observations": {},
        }])
        self.assertEqual(1, len(summary["independent_effect_evidence"]))
        self.assertEqual("filesystem-diff",
                         summary["independent_effect_evidence"][0]["kind"])

    def test_target_specific_effect_plan_is_wired_to_bounded_snapshots(self):
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            fixture = workspace / "fixture"
            fixture.mkdir()
            spec = SimpleNamespace(effect_observers={
                "filesystem-diff": {"root": "fixture"},
            })
            prepared = _prepare_effect_observers(workspace, spec)
            (fixture / "changed.txt").write_text("private", encoding="utf-8")
            rows = _collect_effect_observers(
                workspace, prepared, "run-1", "C1", "cell-1")
            self.assertEqual(1, len(rows))
            self.assertEqual("observed", rows[0]["status"])
            self.assertIn("changed.txt", rows[0]["details"]["added"])
            self.assertNotIn("private", json.dumps(rows))

    def test_target_specific_jvm_protocol_observer_is_bounded(self):
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            state = workspace / "jvm-protocol.json"
            state.write_text(json.dumps({
                "phase": "before", "secret": "must-not-leak",
            }), encoding="utf-8")
            spec = SimpleNamespace(effect_observers={
                "jvm-protocol": {
                    "path": "jvm-protocol.json",
                    "paths": ["/phase", "/secret"],
                },
            })
            prepared = _prepare_effect_observers(workspace, spec)
            state.write_text(json.dumps({
                "phase": "after", "secret": "must-not-leak",
            }), encoding="utf-8")
            rows = _collect_effect_observers(
                workspace, prepared, "run-1", "C1", "cell-1")
            self.assertEqual(1, len(rows))
            self.assertEqual("jvm-protocol", rows[0]["kind"])
            self.assertEqual("observed", rows[0]["status"])
            self.assertEqual(["/phase"], rows[0]["details"]["changed_paths"])
            self.assertNotIn("must-not-leak", json.dumps(rows))
            self.assertTrue(JVMProtocolStateCollector.available)

    @unittest.skipUnless(shutil.which("git"), "git is required for indexed coverage")
    def test_coverage_rebuild_records_excluded_git_directories(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            source = base / "source"
            workspace = base / "workspace"
            source.mkdir()
            (source / "src").mkdir()
            (source / "src" / "main.py").write_text(
                "def run(value):\n    return value\n", encoding="utf-8")
            (source / "vendor" / "pkg").mkdir(parents=True)
            (source / "vendor" / "pkg" / "dependency.py").write_text(
                "def dependency():\n    return 1\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=source, check=True)
            subprocess.run(["git", "add", "."], cwd=source, check=True)
            output = io.StringIO()
            with redirect_stdout(output):
                status = agent_cli.main([
                    "coverage", "demo", "--workspace", str(workspace),
                    "--root", str(source), "--rebuild", "--json",
                ])
            self.assertEqual(0, status, output.getvalue())
            payload = json.loads(output.getvalue())
            self.assertEqual("demo", payload["target"])
            self.assertGreaterEqual(
                payload["rebuilt"]["counts"]["excluded_dirs"], 1)

    def test_audit_exec_parser_and_host_guard_accept_the_same_forms(self):
        plugin_root = ROOT
        forms = (
            "python3 %s audit-exec demo --workspace /tmp/w --root /tmp/r "
            "--round 1 -- echo ok" % (plugin_root / "scripts" / "agent_cli.py"),
            "env PYTHONPATH=%s python3 %s audit-exec --workspace /tmp/w "
            "--root /tmp/r --round 1 demo --cwd src -- echo ok" % (
                plugin_root / "scripts", plugin_root / "scripts" / "agent_cli.py"),
        )
        for command in forms:
            tokens = audit_guard._shell_tokens(command)
            scope = audit_guard._matching_cli_scope(tokens, plugin_root, ROOT)
            self.assertIsNotNone(scope, command)
            self.assertEqual("audit-exec", scope[0])
            self.assertEqual("demo", scope[1])
            self.assertEqual(1, scope[2])
        rogue = "PYTHONPATH=/tmp/attacker python3 %s audit-exec demo" % (
            plugin_root / "scripts" / "agent_cli.py")
        self.assertIsNone(audit_guard._trusted_cli_operation(
            rogue, ROOT, plugin_root))

        with patch("agent.cli.legacy.cmd_audit_exec", return_value=0) as handler:
            for argv in (
                ["audit-exec", "demo", "--workspace", "/tmp/w",
                 "--root", "/tmp/r", "--round", "1", "--", "echo", "ok"],
                ["audit-exec", "--workspace", "/tmp/w", "--root", "/tmp/r",
                 "--round", "1", "demo", "--cwd", "src", "--", "echo", "ok"],
            ):
                self.assertEqual(0, agent_cli.main(argv))
                parsed = handler.call_args.args[0]
                self.assertEqual("demo", parsed.target)
                self.assertEqual(["echo", "ok"], parsed.command)

    def test_service_approval_is_persisted_and_one_time(self):
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "approval.jsonl"
            gate = ApprovalGate(log)
            gate.record_authorized(
                "service_lifecycle", "test", run_id="run-1",
                config_digest="a" * 64, expires_at=time.time() + 60,
            )
            restored = ApprovalGate(log)
            self.assertTrue(restored.consume_authorized(
                "service_lifecycle", "run-1", "a" * 64))
            self.assertFalse(restored.consume_authorized(
                "service_lifecycle", "run-1", "a" * 64))
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)

    def test_target_config_rejects_unknown_security_fields(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "target.json"
            path.write_text(json.dumps({
                "name": "strict", "discovery_date": "2026-09-27",
                "runtime_lab": {"service": {
                    "allow_unconfined_startt": True,
                }},
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unknown runtime_lab.service"):
                TargetConfig.load(path)

    def test_http_predicates_are_semantic_and_body_is_not_persisted(self):
        self.assertEqual("https", _origin("https://127.0.0.1:8443")[0])
        observer = LoopbackHTTPObserver(
            "http://127.0.0.1:8080", "run-1", predicates=[
                {"id": "marker", "kind": "exact", "expression": "safe"},
                {"id": "role", "kind": "jsonpath", "expression": "$.user.role"},
            ])
        results = observer._predicate_results(
            b'{"user":{"role":"admin"},"message":"safe"}')
        self.assertEqual([True, True], [row["matched"] for row in results])
        snapshot = observer.snapshot()
        self.assertNotIn("admin", json.dumps(snapshot, sort_keys=True))
        self.assertNotIn("safe", json.dumps(snapshot, sort_keys=True))

    def test_https_fixture_proxy_records_semantics_without_body(self):
        if shutil.which("openssl") is None:
            self.skipTest("openssl is required for the HTTPS fixture")

        class FixtureHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                body = b'{"user":{"role":"admin"},"message":"fixture-secret"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                return

        with tempfile.TemporaryDirectory() as td:
            cert = Path(td) / "fixture-cert.pem"
            key = Path(td) / "fixture-key.pem"
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "1", "-subj", "/CN=127.0.0.1",
                "-keyout", str(key), "-out", str(cert),
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            fixture = http.server.ThreadingHTTPServer(
                ("127.0.0.1", 0), FixtureHandler)
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.load_cert_chain(str(cert), str(key))
            fixture.socket = tls_context.wrap_socket(
                fixture.socket, server_side=True)
            fixture_thread = threading.Thread(
                target=fixture.serve_forever, daemon=True)
            fixture_thread.start()
            target_port = fixture.server_port
            observer = LoopbackHTTPObserver(
                "https://127.0.0.1:%d" % target_port, "https-run",
                predicates=[{
                    "id": "role", "kind": "jsonpath",
                    "expression": "$.user.role",
                }], tls_certfile=str(cert), tls_keyfile=str(key)).start()
            client = None
            try:
                client = socket.create_connection(
                    ("127.0.0.1", observer._server.server_port), timeout=5)
                client.sendall(("CONNECT 127.0.0.1:%d HTTP/1.1\r\n"
                                "Host: 127.0.0.1:%d\r\n\r\n"
                                % (target_port, target_port)).encode("ascii"))
                connect_response = b""
                while b"\r\n\r\n" not in connect_response:
                    connect_response += client.recv(4096)
                self.assertTrue(connect_response.startswith(
                    b"HTTP/1.0 200 Connection Established"))
                tls_client = ssl._create_unverified_context().wrap_socket(
                    client, server_hostname="127.0.0.1")
                client = None
                tls_client.sendall(("GET / HTTP/1.1\r\n"
                                    "Host: 127.0.0.1:%d\r\n"
                                    "Connection: close\r\n\r\n"
                                    % target_port).encode("ascii"))
                response = b""
                while True:
                    chunk = tls_client.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                tls_client.close()
                self.assertTrue(response.startswith(b"HTTP/1.1 200 OK"))
            finally:
                if client is not None:
                    client.close()
                observer.close()
                fixture.shutdown()
                fixture.server_close()
                fixture_thread.join(timeout=2)

            snapshot = observer.snapshot()
            self.assertEqual(1, snapshot["response_count"])
            self.assertEqual([], snapshot["observer_gaps"])
            self.assertEqual("200", snapshot["observations"]["HTTP_CODE"])
            self.assertEqual([True], [row["matched"] for row in
                             snapshot["observations"]["HTTP_PREDICATES"]])
            encoded = json.dumps(snapshot, sort_keys=True)
            self.assertNotIn("fixture-secret", encoded)
            self.assertNotIn("admin", encoded)

    def test_macos_without_container_backend_fails_closed(self):
        with patch("agent.sandbox.isolation.platform.system", return_value="Darwin"), \
                patch("agent.sandbox.isolation.shutil.which", return_value=None):
            backend, descriptor = detect_isolation_backend(Path("/tmp"), {})
        self.assertIsNone(backend)
        self.assertFalse(descriptor.available)
        self.assertEqual(descriptor.backend, "none")


if __name__ == "__main__":
    unittest.main()
