import socket
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.orchestrator.config import TargetConfig  # noqa: E402
from agent.tools.service_lifecycle import ServiceLifecycle  # noqa: E402


def _free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _nc_http_start_command(root, port):
    """Create a portable loopback fixture for lifecycle subprocess tests.

    Current macOS-latest GitHub runners can leave Python's listener in CLOSED
    rather than LISTEN, while the runner's netcat listener works normally.
    The fixture still exercises the real lifecycle boundary: it is a child
    process, binds only to loopback, returns an HTTP status, and stays alive
    until ServiceLifecycle terminates its process group.
    """
    fixture = (root / "loopback-http-fixture.sh").resolve()
    fixture.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "port=\"$1\"\n"
        "while :; do\n"
        "  printf 'HTTP/1.0 200 OK\\r\\nContent-Length: 0\\r\\n'\n"
        "  printf 'Connection: close\\r\\n\\r\\n'\n"
        "  sleep 1\n"
        "done | nc -lk 127.0.0.1 \"$port\"\n",
        encoding="utf-8",
    )
    fixture.chmod(fixture.stat().st_mode | 0o700)
    return ["sh", str(fixture), str(port)]


class ServiceLifecycleTests(unittest.TestCase):
    def test_starts_healthchecks_and_kills_owned_process_group(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            port = _free_port()
            cfg = TargetConfig(
                name="service-lab", discovery_date="2026-09-21",
                runtime_lab={"service": {
                    "start_command": _nc_http_start_command(root, port),
                    "healthcheck_url": "http://127.0.0.1:%d/" % port,
                    "startup_timeout": 5,
                    "poll_interval": 0.05,
                }},
            )
            lifecycle = ServiceLifecycle(root, "service-lab", 1, cfg)
            ready = lifecycle.ensure_ready()
            self.assertTrue(ready["ready"], ready)
            self.assertEqual(ready["status"], "started-ready")
            self.assertTrue(ready.get("process_managed"))
            registry = root / "state" / "service-lab" / "round-01" / "S4" / "processes.json"
            self.assertTrue(registry.exists())
            self.assertTrue(json.loads(registry.read_text(encoding="utf-8"))["processes"][-1]["active"])
            stopped = lifecycle.stop()
            self.assertTrue(stopped["stopped"], stopped)
            self.assertIn(stopped["status"], {"stopped", "killed-after-timeout"})
            self.assertFalse(json.loads(registry.read_text(encoding="utf-8"))["processes"][-1]["active"])

    def test_loopback_healthcheck_ignores_host_proxy_environment(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            port = _free_port()
            cfg = TargetConfig(
                name="proxied-service", discovery_date="2026-09-21",
                runtime_lab={"service": {
                    "start_command": _nc_http_start_command(root, port),
                    "healthcheck_url": "http://127.0.0.1:%d/" % port,
                    "startup_timeout": 5,
                    "poll_interval": 0.05,
                }},
            )
            lifecycle = ServiceLifecycle(root, "proxied-service", 1, cfg)
            proxy_env = {
                "HTTP_PROXY": "http://127.0.0.1:1",
                "HTTPS_PROXY": "http://127.0.0.1:1",
                "ALL_PROXY": "http://127.0.0.1:1",
            }
            with patch.dict("os.environ", proxy_env, clear=False), \
                    patch.dict("os.environ", {"NO_PROXY": "", "no_proxy": ""},
                               clear=False):
                ready = lifecycle.ensure_ready()
            try:
                self.assertTrue(ready["ready"], ready)
                self.assertEqual(ready["status"], "started-ready")
            finally:
                lifecycle.stop()

    def test_non_loopback_healthcheck_is_a_policy_gap(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = TargetConfig(
                name="remote-health", discovery_date="2026-09-21",
                runtime_lab={"service": {
                    "healthcheck_url": "https://example.invalid/health",
                }},
            )
            result = ServiceLifecycle(root, "remote-health", 1, cfg).ensure_ready()
            self.assertFalse(result["ready"])
            self.assertEqual(result["status"], "precondition-unavailable")
            self.assertEqual(result["health"]["status"], "policy-denied")

    def test_missing_healthcheck_never_launches_a_process(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = TargetConfig(
                name="no-health", discovery_date="2026-09-21",
                runtime_lab={"service": {
                    "start_command": [sys.executable, "-m", "http.server", "0"],
                }},
            )
            lifecycle = ServiceLifecycle(root, "no-health", 1, cfg)
            result = lifecycle.ensure_ready()
            self.assertFalse(result["ready"])
            self.assertEqual(result["status"], "precondition-unavailable")
            self.assertFalse((root / "state" / "no-health" / "round-01" /
                              "S4" / "service-lifecycle.log").exists())

    def test_external_ready_service_is_not_stopped_implicitly(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = TargetConfig(
                name="external", discovery_date="2026-09-21",
                runtime_lab={"service": {
                    "healthcheck_url": "http://127.0.0.1:1/health",
                    "stop_command": [sys.executable, "-m", "http.server", "0"],
                }},
            )
            lifecycle = ServiceLifecycle(root, "external", 1, cfg)
            stopped = lifecycle.stop()
            self.assertEqual(stopped["status"], "not-managed")
            self.assertFalse(stopped["stopped"])


if __name__ == "__main__":
    unittest.main()
