"""Bounded loopback HTTP proxy that records harness-owned response metadata.

Only the exact declared loopback origin is supported. HTTPS uses a caller-
supplied local fixture certificate/key and a bounded CONNECT tunnel. Other
origins, oversized request bodies, and malformed proxy requests fail closed.
Request and response sizes, concurrent handlers, and capture rows are bounded.
Response bodies are streamed to the PoC and hashed in memory; optional
allowlisted predicates run in memory and persist only predicate IDs/results.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit


OBSERVER_VERSION = "loopback-http-observer-v2-https-predicates"
MAX_REQUEST_BODY_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_BODY_BYTES = 64 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
MAX_CAPTURE_ROWS = 256
MAX_CONCURRENT_REQUESTS = 8
MAX_PREDICATE_BODY_BYTES = 4 * 1024 * 1024
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
}
_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")


def _normalize_host(host: str) -> str:
    value = str(host or "").strip().lower().rstrip(".")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    return value


def _is_loopback(host: str) -> bool:
    value = _normalize_host(host)
    if value in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _origin(url: str) -> Tuple[str, str, int, str]:
    parsed = urlsplit(str(url or ""))
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("HTTP observer requires an explicit loopback http(s) target")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("userinfo is not allowed in the observed target URL")
    host = _normalize_host(parsed.hostname)
    if not _is_loopback(host):
        raise ValueError("HTTP observer target must be a loopback host")
    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise ValueError("invalid target port") from exc
    if not 1 <= port <= 65535:
        raise ValueError("invalid target port")
    # The digest intentionally excludes query, fragment and userinfo.
    path = parsed.path or "/"
    target_digest = hashlib.sha256(
        ("%s://%s:%d%s" % (parsed.scheme.lower(), host, port, path)).encode("utf-8", "replace")
    ).hexdigest()
    return parsed.scheme.lower(), host, port, target_digest


class _HTTPObserverServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: Tuple[str, int], handler_class: Any,
                 overload_callback: Any = None):
        self._request_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        self._overload_callback = overload_callback
        self._active_condition = threading.Condition()
        self._active_handlers = 0
        super().__init__(server_address, handler_class)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._request_slots.acquire(blocking=False):
            if self._overload_callback is not None:
                self._overload_callback("capture-concurrency-limit-reached")
            request.close()
            return
        with self._active_condition:
            self._active_handlers += 1
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            with self._active_condition:
                self._active_handlers -= 1
                self._active_condition.notify_all()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()
            with self._active_condition:
                self._active_handlers -= 1
                self._active_condition.notify_all()

    def wait_for_handlers(self, timeout: float) -> bool:
        with self._active_condition:
            return self._active_condition.wait_for(
                lambda: self._active_handlers == 0, timeout=max(0.0, timeout))

    def active_handlers(self) -> int:
        with self._active_condition:
            return self._active_handlers


class LoopbackHTTPObserver:
    """Observe requests sent through an HTTP proxy to one declared origin."""

    def __init__(self, target_url: str, run_id: str,
                 *, predicates: Optional[List[Dict[str, Any]]] = None,
                 tls_certfile: Optional[str] = None,
                 tls_keyfile: Optional[str] = None):
        self.scheme, self.host, self.port, self.target_digest = _origin(target_url)
        self.run_id = str(run_id)
        self.predicates = self._normalize_predicates(predicates)
        self.tls_certfile = str(tls_certfile or "")
        self.tls_keyfile = str(tls_keyfile or "")
        self._rows: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._next_request_id = 1
        self._dropped_rows = 0
        self._handlers_drained = True
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *_args: Any) -> None:
                return

            def do_CONNECT(self) -> None:  # noqa: N802
                owner._proxy_connect(self)

            def _proxy(self) -> None:
                owner._proxy_request(self)

        for method in _METHODS:
            setattr(Handler, "do_" + method, Handler._proxy)
        self._server = _HTTPObserverServer(("127.0.0.1", 0), Handler,
                                           self._record_gap)
        self._thread: Optional[threading.Thread] = None

    @property
    def proxy_url(self) -> str:
        return "http://127.0.0.1:%d" % self._server.server_port

    def start(self) -> "LoopbackHTTPObserver":
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="vulngate-http-observer",
            daemon=True,
        )
        self._thread.start()
        return self

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)
        # Existing proxy handlers can still be relaying a response after the
        # listener stops. Drain them before the caller snapshots evidence.
        self._handlers_drained = self._server.wait_for_handlers(timeout=12)

    def __enter__(self) -> "LoopbackHTTPObserver":
        return self.start()

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def _append(self, row: Dict[str, Any]) -> None:
        with self._lock:
            if len(self._rows) < MAX_CAPTURE_ROWS:
                self._rows.append(row)
            else:
                self._dropped_rows += 1

    def _record_gap(self, reason: str) -> None:
        self._append({"kind": "observer-gap", "reason": reason})

    @staticmethod
    def _normalize_predicates(value: Any) -> List[Dict[str, str]]:
        if not isinstance(value, list):
            return []
        out: List[Dict[str, str]] = []
        for item in value[:32]:
            if not isinstance(item, dict):
                continue
            identifier = str(item.get("id", "")).strip()[:80]
            kind = str(item.get("kind", "")).strip().lower()[:16]
            expression = str(item.get("expression", ""))[:512]
            if (identifier and kind in {"exact", "regex", "jsonpath"}
                    and expression):
                out.append({"id": identifier, "kind": kind,
                            "expression": expression})
        return out

    def _predicate_results(self, body: bytes) -> List[Dict[str, Any]]:
        sample = body[:MAX_PREDICATE_BODY_BYTES]
        text = sample.decode("utf-8", "replace")
        out: List[Dict[str, Any]] = []
        for predicate in self.predicates:
            matched = False
            error = ""
            try:
                if predicate["kind"] == "exact":
                    matched = predicate["expression"].encode("utf-8") in sample
                elif predicate["kind"] == "regex":
                    matched = re.search(predicate["expression"], text,
                                        re.MULTILINE) is not None
                else:
                    current: Any = json.loads(text)
                    path = predicate["expression"]
                    if not path.startswith("$."):
                        error = "jsonpath-must-start-with-$."
                    else:
                        for component in path[2:].split("."):
                            if not isinstance(current, dict) or component not in current:
                                current = None
                                break
                            current = current[component]
                        matched = current is not None
            except (UnicodeError, ValueError, TypeError, re.error) as exc:
                error = type(exc).__name__
            row: Dict[str, Any] = {"id": predicate["id"], "matched": bool(matched)}
            if error:
                row["error"] = error
            out.append(row)
        return out

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            rows = [dict(row) for row in self._rows]
            dropped_rows = self._dropped_rows
        active_handlers = self._server.active_handlers()
        responses = [row for row in rows if row.get("kind") == "http-response"]
        codes = [row["status"] for row in responses]
        observations: Dict[str, Any] = {"HTTP_RESPONSES": responses}
        gaps = ([row["reason"] for row in rows
                 if row.get("kind") == "observer-gap"]
                + (["capture-row-limit-reached"] if dropped_rows else [])
                + (["request-handlers-still-active"]
                   if active_handlers or not self._handlers_drained else []))
        if len(codes) == 1 and dropped_rows == 0 and not gaps:
            observations["HTTP_CODE"] = str(codes[0])
        if self.predicates:
            observations["HTTP_PREDICATES"] = [
                {"id": row.get("predicate_id", ""),
                 "matched": bool(row.get("matched")),
                 **({"error": row["error"]} if row.get("error") else {})}
                for row in rows if row.get("kind") == "http-predicate"
            ]
        return {
            "schema_version": "harness-observations-v1",
            "producer": "vulngate-harness",
            "collector_version": OBSERVER_VERSION,
            "run_id": self.run_id,
            "target_digest": self.target_digest,
            # The proxy captures only clients that honor the proxy environment.
            # OS-level network isolation is required to make absence meaningful.
            "capture_scope": "requests-routed-through-env-proxy",
            "response_count": len(responses),
            "observer_gaps": gaps,
            "observations": observations,
        }

    def _request_origin(self, handler: BaseHTTPRequestHandler
                        ) -> Tuple[str, int, str]:
        raw = handler.path
        parsed = urlsplit(raw)
        if parsed.scheme:
            if parsed.scheme.lower() != "http" or not parsed.hostname:
                raise ValueError("unsupported-proxy-scheme")
            host = _normalize_host(parsed.hostname)
            port = parsed.port or 80
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
        else:
            host_header = handler.headers.get("Host", "")
            host_parsed = urlsplit("//" + host_header)
            host = _normalize_host(host_parsed.hostname or "")
            port = host_parsed.port or 80
            path = raw if raw.startswith("/") else "/"
        if (host != self.host or port != self.port
                or not _is_loopback(host)):
            raise ValueError("target-origin-not-allowlisted")
        return host, port, path

    def _proxy_connect(self, handler: BaseHTTPRequestHandler) -> None:
        """Handle one bounded HTTPS CONNECT request for a local fixture.

        The fixture certificate/key are operator-supplied local files.  No
        certificate material or decrypted body is persisted; only the same
        status/digest/predicate rows as plain HTTP are retained.
        """
        if self.scheme != "https":
            self._record_gap("https-connect-target-mismatch")
            handler.send_error(403, "HTTPS target is not declared")
            return
        if not self.tls_certfile or not self.tls_keyfile:
            self._record_gap("https-fixture-certificate-unavailable")
            handler.send_error(501, "HTTPS fixture certificate is unavailable")
            return
        try:
            host_text, port_text = str(handler.path or "").rsplit(":", 1)
            host = _normalize_host(host_text)
            port = int(port_text)
            if host != self.host or port != self.port or not _is_loopback(host):
                raise ValueError("target-origin-not-allowlisted")
            with self._lock:
                request_id = self._next_request_id
                self._next_request_id += 1
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.tls_certfile, self.tls_keyfile)
            handler.send_response(200, "Connection Established")
            handler.end_headers()
            client = context.wrap_socket(handler.connection, server_side=True)
            client.settimeout(10)
            reader = client.makefile("rb")
            request_line = reader.readline(8192).decode("latin-1", "replace").strip()
            parts = request_line.split()
            if len(parts) != 3 or parts[0] not in _METHODS:
                raise ValueError("invalid-https-request-line")
            headers = http.client.parse_headers(reader)
            length_text = headers.get("Content-Length", "0")
            if not length_text.isdigit() or int(length_text) > MAX_REQUEST_BODY_BYTES:
                raise ValueError("https-request-body-over-observer-limit")
            body = reader.read(int(length_text)) if int(length_text) else None
            path = parts[1] if parts[1].startswith("/") else "/"
            upstream = http.client.HTTPSConnection(
                host, port, timeout=10, context=ssl._create_unverified_context())
            forwarded = {key: value for key, value in headers.items()
                         if key.lower() not in _HOP_BY_HOP
                         and key.lower() not in {"host", "content-length"}}
            forwarded["Host"] = headers.get("Host", host)
            forwarded["Connection"] = "close"
            upstream.request(parts[0], path, body=body, headers=forwarded)
            response = upstream.getresponse()
            response_body = response.read(MAX_RESPONSE_BODY_BYTES)
            complete = len(response_body) < MAX_RESPONSE_BODY_BYTES
            digest = hashlib.sha256(response_body).hexdigest()
            response_headers = ["HTTP/1.1 %d %s\r\n" %
                                (response.status, response.reason or "")]
            for key, value in response.getheaders():
                if key.lower() not in _HOP_BY_HOP:
                    response_headers.append("%s: %s\r\n" % (key, value))
            response_headers.append("Connection: close\r\n\r\n")
            client.sendall("".join(response_headers).encode("latin-1", "replace"))
            if parts[0].upper() != "HEAD":
                client.sendall(response_body)
            self._append({
                "kind": "http-response", "request_id": request_id,
                "request_digest": hashlib.sha256(json.dumps({
                    "method": parts[0], "path": path, "host": host,
                    "port": port,
                }, sort_keys=True).encode("utf-8")).hexdigest(),
                "method": parts[0], "status": int(response.status),
                "response_bytes": len(response_body),
                "response_body_sha256": digest,
                "body_complete": complete,
                "response_truncated": not complete,
            })
            for predicate in self._predicate_results(response_body):
                self._append({"kind": "http-predicate",
                              "predicate_id": predicate.get("id", ""),
                              "matched": bool(predicate.get("matched")),
                              "error": predicate.get("error", "")})
            upstream.close()
            client.close()
        except (OSError, ValueError, ssl.SSLError, http.client.HTTPException) as exc:
            self._record_gap(str(exc)[:96] or type(exc).__name__)

    def _proxy_request(self, handler: BaseHTTPRequestHandler) -> None:
        request_id = None
        connection: Optional[http.client.HTTPConnection] = None
        response_started = False
        try:
            host, port, path = self._request_origin(handler)
            length_text = handler.headers.get("Content-Length", "0")
            if not length_text.isdigit():
                raise ValueError("invalid-content-length")
            body_length = int(length_text)
            if body_length > MAX_REQUEST_BODY_BYTES:
                raise ValueError("request-body-over-observer-limit")
            if handler.headers.get("Transfer-Encoding"):
                raise ValueError("chunked-request-body-unsupported")
            request_body = handler.rfile.read(body_length) if body_length else None

            digest_path = urlsplit(path).path or "/"
            request_digest = hashlib.sha256(json.dumps({
                "method": handler.command,
                "path": digest_path,
                "host": host,
                "port": port,
            }, sort_keys=True).encode("utf-8", "replace")).hexdigest()
            with self._lock:
                request_id = self._next_request_id
                self._next_request_id += 1

            connection = (http.client.HTTPSConnection(
                host, port, timeout=10, context=ssl._create_unverified_context())
                          if self.scheme == "https" else
                          http.client.HTTPConnection(host, port, timeout=10))
            headers = {}
            for key, value in handler.headers.items():
                if key.lower() not in _HOP_BY_HOP and key.lower() not in {
                        "host", "content-length", "expect"}:
                    headers[key] = value
            headers["Host"] = handler.headers.get(
                "Host", ("[%s]" % host if ":" in host else host) +
                (":" + str(port) if port != 80 else ""))
            headers["Connection"] = "close"
            connection.request(handler.command, path, body=request_body,
                               headers=headers)
            response = connection.getresponse()
            handler.send_response(response.status, response.reason)
            for key, value in response.getheaders():
                if key.lower() not in _HOP_BY_HOP:
                    handler.send_header(key, value)
            handler.send_header("Connection", "close")
            handler.end_headers()
            response_started = True

            digest = hashlib.sha256()
            response_bytes = 0
            body_for_predicate = bytearray()
            complete = True
            truncated = False
            if handler.command.upper() != "HEAD":
                while True:
                    remaining = MAX_RESPONSE_BODY_BYTES - response_bytes
                    if remaining <= 0:
                        complete = False
                        truncated = True
                        break
                    chunk = response.read(min(READ_CHUNK_BYTES, remaining))
                    if not chunk:
                        break
                    digest.update(chunk)
                    response_bytes += len(chunk)
                    if len(body_for_predicate) < MAX_PREDICATE_BODY_BYTES:
                        body_for_predicate.extend(
                            chunk[:MAX_PREDICATE_BODY_BYTES - len(body_for_predicate)])
                    try:
                        handler.wfile.write(chunk)
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        complete = False
                        break
                    if response_bytes >= MAX_RESPONSE_BODY_BYTES:
                        complete = False
                        truncated = True
                        break
            connection.close()
            connection = None
            self._append({
                "kind": "http-response",
                "request_id": request_id,
                "request_digest": request_digest,
                "method": handler.command[:12],
                "status": int(response.status),
                "response_bytes": response_bytes,
                "response_body_sha256": digest.hexdigest(),
                "body_complete": complete,
                "response_truncated": truncated,
            })
            for predicate in self._predicate_results(bytes(body_for_predicate)):
                self._append({"kind": "http-predicate",
                              "predicate_id": predicate.get("id", ""),
                              "matched": bool(predicate.get("matched")),
                              "error": predicate.get("error", "")})
        except (OSError, ValueError, http.client.HTTPException) as exc:
            if connection is not None:
                connection.close()
            reason = str(exc)[:96] or type(exc).__name__
            self._record_gap(reason)
            try:
                if not response_started and not handler.wfile.closed:
                    handler.send_error(502, "observer could not forward request")
            except OSError:
                pass
