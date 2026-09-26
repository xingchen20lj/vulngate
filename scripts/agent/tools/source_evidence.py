"""Source-evidence extraction for LLM prompts (baseline fix #3).

Deterministic, token-bounded extraction of *real* source snippets so the LLM
proposes and audits candidates from actual code, not entry names + file paths.

Two entry points:
  * surface_block(...)   -- S1.5/S2: danger-pattern call-site digest + hot
                            entry-class headers
  * candidate_block(...) -- S3/S4: snippets located from candidate entry API
                            and keywords (file + method anchored)

The same DANGER_PATTERNS list is reused by S1 for the attack-surface scan, so
the LLM prompt evidence and the deterministic scan stay in sync.

Scanning vs. presentation (spec §2.1 / §6.1)
--------------------------------------------
Every scan helper here is split in two:

``scan_all_hits()`` / ``scan_all_source_sink_paths()``
    Full, uncapped.  These are the entry points for anything that builds an
    index or a coverage number.
``summarize_hits()`` / ``build_source_sink_graph()``
    Bounded.  These exist only for prompt digests and report excerpts.

``grep_hits()`` remains as a *display* helper (bounded) and is now implemented
as ``summarize_hits(scan_all_hits(...))`` so there is exactly one scan
implementation.  It does not cap what ripgrep reads -- it caps the returned
list -- so callers that need the full picture must call ``scan_all_hits``.

Language coverage derives from :mod:`agent.analysis.languages`, so the suffix
set here can no longer drift from the inventory's.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from collections import OrderedDict
from bisect import bisect_left, bisect_right
from dataclasses import replace
from pathlib import Path
from threading import RLock
from typing import Dict, List, Optional, Sequence, Tuple

from ..analysis.languages import (LANGUAGE_SUFFIXES, SourceFilter,
                                  SourceScanTimeout, iter_source_files,
                                  source_globs)

# (regex, label) pairs. Used both for the S1 danger-call-site scan and for
# locating candidate-relevant snippets. Keep patterns rg/Rust-regex safe.
DANGER_PATTERNS: List[Tuple[str, str]] = [
    (r"checkAutoType|SupportAutoType|autoType|auto_type", "autotype"),
    (r"Class\.forName|loadClass\(|ClassLoader", "dynamic-class-load"),
    (r"URLClassLoader|JarURLConnection|new\s+URL\(", "remote-resource"),
    (r"lookup\(|InitialContext|Jndi|JNDI", "jndi"),
    (r"readObject|parseObject|readValue|fromJson|fromXML|unmarshal|decodeObject",
     "deserialization-entry"),
    (r"@type|seeAlso|JsonTypeInfo|TypeInfo", "polymorphic-type"),
    (r"readLength|readString|maxDepth|maxLevel|hugeLength|\blimit\b", "bounds-limit"),
    (r"Runtime\.getRuntime|ProcessBuilder|\bexec\s*\(", "command-exec"),
    (r"getDeclaredMethod|getDeclaredField|setAccessible|\.invoke\s*\(", "reflection"),
    (r"getResourceAsStream|getResource\s*\(", "resource-load"),
    # --- [vulngate-macos-universal] macOS / native sinks ---
    (r"posix_spawn|posix_spawnp|execve|execv\(|execl\(|system\s*\(|popen\s*\("
     r"|NSTask|NSAppleScript|Process\(", "native-command-exec"),
    (r"SecItemCopyMatching|SecItemAdd|SecItemDelete|SecKeychain|SecKeyRawSign"
     r"|SecKeyDecrypt|SecKeyCreateDecryptedData", "native-credential"),
    (r"NSKeyedUnarchiver|unarchive[A-Za-z]*|CFPropertyListCreate|"
     r"propertyListWithData|sqlite3_open|sqlite3_exec", "native-deserialization"),
    (r"dlopen|dlsym|NSAddImage|NSCreateObjectFileImageFromFile", "native-dynamic-load"),
    (r"WKWebView|evaluateJavaScript|JSContext|addScriptMessageHandler"
     r"|userContentController", "native-webview-bridge"),
    (r"NSXPCConnection|xpc_connection_create|mach_msg|bootstrap_look_up"
     r"|CFMessagePort", "native-ipc"),
    (r"AESend|OSAScript|executeAppleEvent|AEDesc|NSAppleEventDescriptor",
     "native-applescript"),
    (r"strcpy\s*\(|strcat\s*\(|sprintf\s*\(|gets\s*\(|alloca\s*\(",
     "native-unsafe-c"),
    (r"application:openURL|handleGetURLEvent|openURL|handleOpenURL"
     r"|CFBundleURLSchemes", "native-url-scheme-entry"),
    (r"AuthorizationExecuteWithPrivileges|AuthorizationCreate|SMJobBless"
     r"|\bsetuid\s*\(|\bsetgid\s*\(", "native-privilege"),
    (r"get-task-allow|disable-library-validation|com.apple.security"
     r"|allow-dyld-environment-variables", "native-entitlement"),
]

SOURCE_MAP_PRESETS: Dict[str, str] = {
    "parsers": r"(parse\w*|read\w*|deserialize\w*|decode\w*|load\w*|convert\w*)\s*\(",
    # Language-agnostic route surface: Java servlet/Spring, Clojure compojure
    # (defendpoint/defroutes appear as `(api.macros/defendpoint :get "/x" ...)`
    # so they are matched as bare words, not call forms), Python Flask,
    # Go net/http, JS Express/Fastify. Flask/Flask-AppBuilder:
    # @bp.route("/x"), @expose("/x"), @app.get(...), app.add_url_rule(...).
    # `@`-prefixed decorators must not be anchored by \b (non-word char).
    "http": r"(?:@[\w.]+\.route|@expose|@[\w.]+\.(?:get|post|put|delete|patch))\s*\(|\b(?:doGet|doPost|service|handleRequest|onRequest|DispatcherServlet|Controller|RequestMapping|router\.(?:GET|POST|PUT|DELETE|PATCH|ANY)|app\.(?:get|post|put|delete|patch)|http\.HandleFunc|HandleFunc|add_route|add_url_rule)\s*\(|(?:^|[^-\w])(?:defendpoint|defroutes|defroute|compojure)\b",
    "expression": r"(evaluate|eval|invoke|getValue|template|render|lookup|format)\s*\(",
    "io": r"(read\w*|write\w*|copy\w*|unzip|extract\w*|download\w*|openConnection|getInputStream|getOutputStream)\s*\(",
    "exec": r"(Runtime|ProcessBuilder|exec\w*|CommandLine|startProcess)\s*\(",
    "config": r"(load\w*|parse\w*|readConfig|getProperty|Properties|Yaml|Xml)\s*\(",
    "all": r"(parse\w*|read\w*|deserialize\w*|decode\w*|load\w*|convert\w*|doGet|doPost|service|evaluate|eval|invoke|lookup|format|exec\w*|openConnection|getInputStream)\s*\(",
    # [vulngate-macos-universal] macOS 原生入口/危险调用候选面
    "native": (r"(?:application:openURL|handleGetURLEvent|openURL|NSApplicationMain"
               r"|NSXPCConnection|xpc_connection_create|shouldAcceptNewConnection"
               r"|WKWebView|evaluateJavaScript|addScriptMessageHandler"
               r"|NSKeyedUnarchiver|unarchive[A-Za-z]*|propertyListWithData"
               r"|posix_spawn|NSTask|execve|popen|SecItem[A-Za-z]*"
               r"|AuthorizationExecuteWithPrivileges|SMJobBless"
               r"|applicationDidFinishLaunching)"),
}

MAX_FILE_BYTES = 1024 * 1024

# Language-agnostic source scan. Java-only globs made S1 miss Clojure/Go/Python
# route declarations (Metabase lesson, 2026-08-10): the host fell back to manual
# rg sweeps because source-map returned nothing for .clj targets.
#
# The suffix set is now owned by agent.analysis.languages (spec §6.3) so the
# prompt digest, the S1 scan and the coverage inventory enumerate the same
# universe.  Kept as a module-level name because existing callers pass it as
# ``globs=``.
DEFAULT_SOURCE_GLOBS: List[str] = source_globs()

#: Suffixes scanned by the source-evidence scan (derived, do not hardcode).
DEFAULT_SOURCE_SUFFIXES: Tuple[str, ...] = tuple(
    sorted({s for suffixes in LANGUAGE_SUFFIXES.values() for s in suffixes},
           key=lambda s: (len(s), s)))

_FLOW_PATTERNS = {
    "source": re.compile(
        r"(?:request|query|param|header|body|input|payload|argv|env|config|read|load|parse|decode)", re.I),
    "transform": re.compile(
        r"(?:parse|decode|deserialize|unmarshal|convert|normalize|resolve|interpolat|template|eval)", re.I),
    "validation": re.compile(
        r"(?:validat|sanitize|allow.?list|deny.?list|check|bound|limit|schema|isValid)", re.I),
    "authorization": re.compile(
        r"(?:auth|permission|role|tenant|owner|access|privilege)", re.I),
    "sink": re.compile(
        r"(?:Runtime\.getRuntime|ProcessBuilder|\.exec\s*\(|Class\.forName|loadClass|"
        r"InitialContext|Jndi|File(?:Output|Input)Stream|openConnection|execute(?:Query|Update)?|"
        r"write(?:Bytes|Object)?\s*\(|render\s*\()", re.I),
}

_CLASS_DECL = re.compile(
    r"^(public\s+|protected\s+|private\s+)?(final\s+|abstract\s+|sealed\s+)?"
    r"(class|interface|enum|record)\s+\w+")
_METHOD_LIKE = re.compile(
    r"^\s*(public|protected|private|static|final|synchronized|native|abstract|"
    r"default|@Override|@SuppressWarnings)[^\n]*\(")


def _safe_resolve(root: Path, rel: str) -> Optional[Path]:
    root = root.resolve()
    p = (root / str(rel)).resolve()
    if str(p) == str(root) or str(p).startswith(str(root) + "/"):
        return p
    return None


def _read_lines(path: Path) -> Optional[List[str]]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


def scan_all_hits(pattern: str, source_dirs: List[str], root: Path,
                  globs: Optional[List[str]] = None,
                  timeout: Optional[float] = 600, *,
                  text_limit: Optional[int] = 160) -> List[Dict[str, object]]:
    """**Full** ripgrep scan; every hit in every source dir, no cap.

    This is the index-building entry point (spec §6.1).  ``grep_hits`` is now a
    bounded wrapper over it, so there is exactly one scan implementation.

    Raises :class:`agent.tools.search.ToolUnavailable` when ripgrep is missing
    rather than returning ``[]``: an empty result must mean "scanned, nothing
    found", never "could not scan" (spec §19.7).

    ``text_limit`` caps only the displayed source text, never the scan. Callers
    that classify the matching line must request ``None`` and truncate after
    classification so matches beyond the display prefix are retained.
    """
    from . import search as srch
    globs = globs if globs is not None else DEFAULT_SOURCE_GLOBS
    hits: List[Dict[str, object]] = []
    root_resolved = root.resolve()
    started = time.monotonic()
    try:
        timeout_seconds = float(timeout) if timeout is not None else 0.0
    except (TypeError, ValueError):
        raise ValueError("source scan timeout must be a nonnegative number or None")
    if timeout_seconds < 0:
        raise ValueError("source scan timeout must be a nonnegative number or None")
    deadline = started + timeout_seconds if timeout_seconds else None

    def raise_timeout(source_dir: str, dirs_seen: int) -> None:
        now = time.monotonic()
        raise SourceScanTimeout({
            "elapsed_seconds": round(now - started, 3),
            "files_seen": 0,
            "source_files": 0,
            "directories_seen": dirs_seen,
            "hits_seen": len(hits),
            "current_path": source_dir,
            "scan": "ripgrep",
        })

    for directory_index, sd in enumerate(source_dirs):
        d = _safe_resolve(root, sd)
        if not d or not d.exists():
            continue
        remaining = None
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise_timeout(str(sd), directory_index)
        try:
            matches = srch.rg_matches(pattern, d, globs=globs,
                                      timeout=remaining)
        except subprocess.TimeoutExpired:
            raise_timeout(str(sd), directory_index)
        if deadline is not None and time.monotonic() >= deadline:
            raise_timeout(str(sd), directory_index + 1)
        for match in matches:
            if deadline is not None and time.monotonic() >= deadline:
                raise_timeout(str(sd), directory_index + 1)
            try:
                rel = str(Path(match["file"]).resolve().relative_to(root_resolved))
            except (ValueError, OSError):
                continue
            text = str(match["text"])
            hits.append({"file": rel, "line": int(match["line"]),
                         "text": text if text_limit is None else text[:text_limit]})
    hits.sort(key=lambda h: (str(h["file"]), int(h["line"])))
    return hits


def scan_all_labeled_hits(patterns: Sequence[Tuple[str, str]],
                          source_dirs: List[str], root: Path,
                          max_per_pattern: Optional[int] = None,
                          timeout: Optional[float] = 600) -> List[Dict[str, object]]:
    """Scan a labeled pattern set in one ripgrep pass.

    ``rg`` emits one row per matching line even when several alternatives
    match. Python then assigns that row to every matching label, preserving
    the old per-pattern result and per-label cap without rescanning the tree.
    This is for finite pattern sets such as the S1 danger and target rules.
    """
    rows = [(str(pattern), str(label), re.compile(pattern))
            for pattern, label in patterns]
    if not rows:
        return []
    combined = "|".join("(?:%s)" % pattern for pattern, _label, _rx in rows)
    grouped: List[List[Dict[str, object]]] = [[] for _ in rows]
    # Both complete inventories and finite prompt/digest scans stream rows.
    # Complete scans retain the labeled result set, but avoid also buffering
    # ripgrep's raw output and an intermediate unlabeled hit list in memory.
    if max_per_pattern is None or max_per_pattern < 0:
        from . import search as srch

        try:
            timeout_seconds = float(timeout) if timeout is not None else 0.0
        except (TypeError, ValueError):
            raise ValueError("source scan timeout must be a nonnegative number or None")
        if timeout_seconds < 0:
            raise ValueError("source scan timeout must be a nonnegative number or None")
        started = time.monotonic()
        deadline = started + timeout_seconds if timeout_seconds else None
        root_resolved = root.resolve()

        def raise_full_timeout(source_dir: str, dirs_seen: int) -> None:
            raise SourceScanTimeout({
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "files_seen": 0,
                "source_files": 0,
                "directories_seen": dirs_seen,
                "hits_seen": sum(len(items) for items in grouped),
                "current_path": source_dir,
                "scan": "ripgrep",
            })

        for directory_index, source_dir in enumerate(source_dirs):
            directory = _safe_resolve(root, source_dir)
            if not directory or not directory.exists():
                continue
            remaining = (None if deadline is None else
                         deadline - time.monotonic())
            if remaining is not None and remaining <= 0:
                raise_full_timeout(str(source_dir), directory_index)
            process = srch.iter_rg_matches(
                combined, directory, globs=DEFAULT_SOURCE_GLOBS,
                timeout=remaining)
            try:
                for match in process:
                    if deadline is not None and time.monotonic() >= deadline:
                        raise_full_timeout(str(source_dir), directory_index + 1)
                    try:
                        rel = str(Path(match["file"]).resolve().relative_to(
                            root_resolved))
                    except (ValueError, OSError):
                        continue
                    text = str(match.get("text") or "")
                    for index, (pattern, label, compiled) in enumerate(rows):
                        if compiled.search(text):
                            grouped[index].append({
                                "label": label, "pattern": pattern,
                                "file": rel, "line": int(match.get("line") or 0),
                                "text": text[:160],
                            })
            except subprocess.TimeoutExpired:
                raise_full_timeout(str(source_dir), directory_index)
            finally:
                close = getattr(process, "close", None)
                if callable(close):
                    close()
        if deadline is not None and time.monotonic() >= deadline:
            raise_full_timeout(str(source_dirs[-1] if source_dirs else root),
                               len(source_dirs))
    if max_per_pattern is not None and max_per_pattern >= 0 and max_per_pattern:
        from . import search as srch

        try:
            timeout_seconds = float(timeout) if timeout is not None else 0.0
        except (TypeError, ValueError):
            raise ValueError("source scan timeout must be a nonnegative number or None")
        if timeout_seconds < 0:
            raise ValueError("source scan timeout must be a nonnegative number or None")
        started = time.monotonic()
        deadline = started + timeout_seconds if timeout_seconds else None
        root_resolved = root.resolve()

        def raise_timeout(source_dir: str, dirs_seen: int) -> None:
            raise SourceScanTimeout({
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "files_seen": 0,
                "source_files": 0,
                "directories_seen": dirs_seen,
                "hits_seen": sum(len(items) for items in grouped),
                "current_path": source_dir,
                "scan": "ripgrep",
            })

        for directory_index, source_dir in enumerate(source_dirs):
            directory = _safe_resolve(root, source_dir)
            if not directory or not directory.exists():
                continue
            remaining = (None if deadline is None else
                         deadline - time.monotonic())
            if remaining is not None and remaining <= 0:
                raise_timeout(str(source_dir), directory_index)
            process = srch.iter_rg_matches(
                combined, directory, globs=DEFAULT_SOURCE_GLOBS,
                extra_args=["--sort", "path"],
                timeout=remaining)
            try:
                for match in process:
                    if deadline is not None and time.monotonic() >= deadline:
                        raise_timeout(str(source_dir), directory_index + 1)
                    try:
                        rel = str(Path(match["file"]).resolve().relative_to(
                            root_resolved))
                    except (ValueError, OSError):
                        continue
                    text = str(match.get("text") or "")
                    for index, (pattern, label, compiled) in enumerate(rows):
                        if len(grouped[index]) >= max_per_pattern:
                            continue
                        if compiled.search(text):
                            grouped[index].append({
                                "label": label, "pattern": pattern,
                                "file": rel, "line": int(match.get("line") or 0),
                                "text": text[:160],
                            })
                    if all(len(items) >= max_per_pattern for items in grouped):
                        break
            except subprocess.TimeoutExpired:
                raise_timeout(str(source_dir), directory_index)
            finally:
                close = getattr(process, "close", None)
                if callable(close):
                    close()
            if all(len(items) >= max_per_pattern for items in grouped):
                break
    for group in grouped:
        group.sort(key=lambda item: (str(item["file"]), int(item["line"])))
    return [item for group in grouped for item in group]


def summarize_hits(hits: List[Dict[str, object]],
                   max_items: int = 20) -> List[Dict[str, object]]:
    """Presentation-level truncation.  Must never feed an index (spec §2.1)."""
    if max_items is None or max_items < 0:
        return list(hits)
    return list(hits[:max_items])


def grep_hits(pattern: str, source_dirs: List[str], root: Path,
              max_lines: int = 12,
              globs: Optional[List[str]] = None) -> List[Dict[str, object]]:
    """Bounded digest for **prompt/report display only**.

    Retained for the existing call sites (S1 danger digest, surface_block,
    candidate_block, target rules).  If you are building an index or a coverage
    number, call :func:`scan_all_hits` instead -- a capped list here reads as
    "only N of these exist", which is precisely the truncation the coverage
    layer must not inherit.
    """
    return summarize_hits(scan_all_hits(pattern, source_dirs, root, globs), max_lines)


def _method_start(lines: List[str], anchor_idx: int, max_back: int = 14) -> int:
    """Walk back from an anchor line to a plausible method signature line."""
    for i in range(anchor_idx, max(-1, anchor_idx - max_back), -1):
        t = lines[i].strip()
        if _METHOD_LIKE.match(t):
            return i
        if "(" in t and ")" in t and (t.endswith("{") or t.endswith(")") or "throws" in t):
            return i
    return max(0, anchor_idx - 8)


def _extract_method_lines(lines: Optional[List[str]], anchor_line: int,
                          max_chars: int) -> Optional[str]:
    if not lines or anchor_line < 1 or anchor_line > len(lines):
        return None
    start = _method_start(lines, anchor_line - 1)
    # capture signature + body until brace balance closes (depth==0) or cap.
    out_lines: List[str] = []
    depth = 0
    started = False
    for ln in lines[start:]:
        out_lines.append(ln)
        started = started or "{" in ln
        depth += ln.count("{") - ln.count("}")
        if started and depth <= 0 and len(out_lines) > 1:
            break
        if len("\n".join(out_lines)) > max_chars:
            out_lines.append("// ... (truncated)")
            break
    s = "\n".join(out_lines)
    if len(s) > max_chars:
        s = s[:max_chars] + "\n// ... (truncated)"
    return s


def extract_method(path: Path, anchor_line: int, max_chars: int = 1600) -> Optional[str]:
    return _extract_method_lines(_read_lines(path), anchor_line, max_chars)


def _extract_class_header_lines(lines: Optional[List[str]],
                                max_chars: int) -> Optional[str]:
    if not lines:
        return None
    out: List[str] = []
    for ln in lines[:80]:
        out.append(ln)
        if _CLASS_DECL.match(ln.strip()):
            break
    s = "\n".join(out)
    if len(s) > max_chars:
        s = s[:max_chars] + "\n// ... (truncated)"
    return s


def extract_class_header(path: Path, max_chars: int = 1200) -> Optional[str]:
    return _extract_class_header_lines(_read_lines(path), max_chars)


class CandidateSourceSnippetCache:
    """Bounded source snapshot and content-digest cache for autonomous prompts.

    A stable source file is normally read once while it remains in the bounded
    in-memory LRU; observed file changes or LRU eviction can trigger a reread.
    Persisted snippets are keyed by the source root, relative
    path, full file SHA-256, anchor and extraction policy. The file is still
    read and hashed once in each new round, so a source edit cannot reuse stale
    prompt evidence. Cache failures are deliberately fail-open to extraction.
    """

    SCHEMA_VERSION = 1
    POLICY_VERSION = "candidate-snippet-v1"
    MAX_ENTRIES = 512
    MAX_CACHE_BYTES = 2 * 1024 * 1024
    MAX_FILE_BYTES = 1024 * 1024
    MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
    MAX_CACHED_LINE_BYTES = 2 * 1024 * 1024
    MAX_CACHED_LINE_COUNT = 50000
    MAX_SNIPPET_CHARS = 10000

    def __init__(self, cache_path: Path):
        self.cache_path = Path(cache_path)
        self._snippets: Dict[str, str] = {}
        self._files = OrderedDict()  # path -> stat key, bytes, digest, lines
        self._snapshot_bytes = 0
        self._cached_line_bytes = 0
        self._cached_line_count = 0
        self._dirty = False
        self._lock = RLock()
        self._metrics_path: Optional[Path] = None
        self._round_no: Optional[int] = None
        self._round_started = time.monotonic()
        self._round_status = "not-started"
        self._round_cache_keys = set()
        self._metrics = self._empty_metrics()
        self._load()

    @staticmethod
    def _empty_metrics() -> Dict[str, Any]:
        return {
            "source_file_reads": 0,
            "source_bytes_hashed": 0,
            "source_read_hash_ms": 0.0,
            "source_files_decoded": 0,
            "source_decode_ms": 0.0,
            "source_snapshot_hits": 0,
            "source_stat_invalidations": 0,
            "source_read_errors": 0,
            "source_file_too_large": 0,
            "snapshot_lru_evictions": 0,
            "snippet_cache_hits_persisted": 0,
            "snippet_cache_hits_round": 0,
            "snippet_cache_misses": 0,
            "snippet_extractions": 0,
            "snippet_extraction_ms": 0.0,
            "snippet_entries_evicted": 0,
            "snippet_cache_writes": 0,
            "snippet_cache_write_bytes": 0,
            "snippet_cache_write_ms": 0.0,
            "snippet_cache_write_errors": 0,
            "snippet_cache_load_errors": 0,
            "snippet_cache_entries_loaded": 0,
        }

    def _load(self) -> None:
        try:
            cache_size = self.cache_path.stat().st_size
            if cache_size > self.MAX_CACHE_BYTES:
                self._metrics["snippet_cache_load_errors"] += 1
                return
            value = json.loads(self.cache_path.read_text(encoding="utf-8"))
            if (not isinstance(value, dict)
                    or value.get("schema_version") != self.SCHEMA_VERSION
                    or not isinstance(value.get("entries"), dict)):
                return
            for key, record in value["entries"].items():
                if not isinstance(key, str) or len(key) != 64:
                    continue
                if not isinstance(record, dict):
                    continue
                snippet = record.get("text")
                checksum = record.get("text_sha256")
                if (not isinstance(snippet, str)
                        or len(snippet) > self.MAX_SNIPPET_CHARS
                        or not isinstance(checksum, str)
                        or hashlib.sha256(snippet.encode("utf-8")).hexdigest() != checksum):
                    continue
                self._snippets[key] = snippet
            self._metrics["snippet_cache_entries_loaded"] = len(self._snippets)
            self._trim_snippets()
        except FileNotFoundError:
            # A cold cache on the first round is normal.
            return
        except (OSError, UnicodeError, ValueError, TypeError):
            # An unavailable or malformed cache is a performance miss only.
            self._snippets = {}
            self._metrics["snippet_cache_load_errors"] += 1

    @staticmethod
    def _stat_key(path: Path) -> Tuple[int, int, int, int]:
        st = path.stat()
        return (int(st.st_dev), int(st.st_ino), int(st.st_size),
                int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))))

    def _source_snapshot(self, path: Path
                         ) -> Optional[Tuple[str, bytes, Optional[List[str]]]]:
        try:
            resolved = path.resolve()
            cache_key = str(resolved)
            before = self._stat_key(resolved)
            cached = self._files.get(cache_key)
            if cached is not None and cached[0] == before:
                self._metrics["source_snapshot_hits"] += 1
                self._files.move_to_end(cache_key)
                return cached[2], cached[1], cached[3]
            if cached is not None:
                self._metrics["source_stat_invalidations"] += 1
            if before[2] > self.MAX_FILE_BYTES:
                self._metrics["source_file_too_large"] += 1
                return None
            read_started = time.monotonic()
            raw = resolved.read_bytes()
            self._metrics["source_file_reads"] += 1
            if len(raw) > self.MAX_FILE_BYTES:
                self._metrics["source_file_too_large"] += 1
                return None
            digest = hashlib.sha256(raw).hexdigest()
            self._metrics["source_bytes_hashed"] += len(raw)
            self._metrics["source_read_hash_ms"] += (
                time.monotonic() - read_started) * 1000.0
            lines: Optional[List[str]] = None
            after = self._stat_key(resolved)
            if before == after and len(raw) <= self.MAX_SNAPSHOT_BYTES:
                old = self._files.pop(cache_key, None)
                if old is not None:
                    self._snapshot_bytes -= len(old[1])
                    if old[3] is not None:
                        self._cached_line_bytes -= len(old[1])
                        self._cached_line_count -= len(old[3])
                while (self._files
                       and self._snapshot_bytes + len(raw) > self.MAX_SNAPSHOT_BYTES):
                    _old_key, old_value = self._files.popitem(last=False)
                    self._snapshot_bytes -= len(old_value[1])
                    self._metrics["snapshot_lru_evictions"] += 1
                    if old_value[3] is not None:
                        self._cached_line_bytes -= len(old_value[1])
                        self._cached_line_count -= len(old_value[3])
                self._files[cache_key] = (after, raw, digest, lines)
                self._snapshot_bytes += len(raw)
            return digest, raw, lines
        except OSError:
            self._metrics["source_read_errors"] += 1
            return None

    def _snippet_key(self, root: Path, relative_path: str, digest: str,
                     kind: str, anchor_line: Optional[int],
                     max_chars: int) -> str:
        identity = {
            "policy": self.POLICY_VERSION,
            "root": hashlib.sha256(
                str(root.resolve()).encode("utf-8", "replace")).hexdigest(),
            "file": str(relative_path),
            "content_sha256": digest,
            "kind": kind,
            "anchor_line": anchor_line,
            "max_chars": int(max_chars),
        }
        payload = json.dumps(identity, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def extract(self, path: Path, root: Path, relative_path: str,
                kind: str, anchor_line: Optional[int],
                max_chars: int) -> Optional[str]:
        with self._lock:
            return self._extract_locked(path, root, relative_path, kind,
                                        anchor_line, max_chars)

    def _extract_locked(self, path: Path, root: Path, relative_path: str,
                        kind: str, anchor_line: Optional[int],
                        max_chars: int) -> Optional[str]:
        snapshot = self._source_snapshot(path)
        if snapshot is None:
            return None
        digest, raw, lines = snapshot
        key = self._snippet_key(root, relative_path, digest, kind,
                                anchor_line, max_chars)
        cached_snippet = self._snippets.get(key)
        if cached_snippet is not None:
            if key in self._round_cache_keys:
                self._metrics["snippet_cache_hits_round"] += 1
            else:
                self._metrics["snippet_cache_hits_persisted"] += 1
            self._snippets.pop(key)
            self._snippets[key] = cached_snippet
            return cached_snippet
        self._metrics["snippet_cache_misses"] += 1
        if lines is None:
            decode_started = time.monotonic()
            lines = raw.decode("utf-8", errors="replace").splitlines()
            self._metrics["source_files_decoded"] += 1
            self._metrics["source_decode_ms"] += (
                time.monotonic() - decode_started) * 1000.0
            file_key = str(path.resolve())
            file_snapshot = self._files.get(file_key)
            if (file_snapshot is not None and file_snapshot[2] == digest
                    and self._cached_line_bytes + len(raw)
                    <= self.MAX_CACHED_LINE_BYTES
                    and self._cached_line_count + len(lines)
                    <= self.MAX_CACHED_LINE_COUNT):
                self._files[file_key] = (file_snapshot[0], file_snapshot[1],
                                         digest, lines)
                self._cached_line_bytes += len(raw)
                self._cached_line_count += len(lines)
        extraction_started = time.monotonic()
        if kind == "method":
            snippet = _extract_method_lines(lines, int(anchor_line or 0), max_chars)
        elif kind == "class-header":
            snippet = _extract_class_header_lines(lines, max_chars)
        else:
            return None
        self._metrics["snippet_extractions"] += 1
        self._metrics["snippet_extraction_ms"] += (
            time.monotonic() - extraction_started) * 1000.0
        if snippet is not None and len(snippet) <= self.MAX_SNIPPET_CHARS:
            self._snippets[key] = snippet
            self._round_cache_keys.add(key)
            self._trim_snippets()
            self._dirty = True
        return snippet

    def _trim_snippets(self) -> None:
        while len(self._snippets) > self.MAX_ENTRIES:
            self._snippets.pop(next(iter(self._snippets)))
            self._metrics["snippet_entries_evicted"] += 1

    def reset_round(self, round_no: int,
                    metrics_path: Optional[Path] = None) -> None:
        """Drop source snapshots between rounds, retaining digest snippets."""
        with self._lock:
            self._files.clear()
            self._snapshot_bytes = 0
            self._cached_line_bytes = 0
            self._cached_line_count = 0
            self._round_no = int(round_no)
            self._metrics_path = Path(metrics_path) if metrics_path else None
            self._round_started = time.monotonic()
            self._round_status = "in-progress"
            self._round_cache_keys = set()
            load_errors = self._metrics["snippet_cache_load_errors"]
            self._metrics = self._empty_metrics()
            self._metrics["snippet_cache_entries_loaded"] = len(self._snippets)
            self._metrics["snippet_cache_load_errors"] = load_errors
            self._write_metrics_locked()

    def finish_round(self, status: str, round_no: int) -> None:
        """Persist the last cache counters when the autonomous round exits."""
        with self._lock:
            if self._metrics_path is None or self._round_no != int(round_no):
                return
            self._flush_locked()
            self._round_status = str(status or "completed")[:80]
            self._write_metrics_locked()

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        if self._dirty:
            records = {
                key: {"text": snippet,
                      "text_sha256": hashlib.sha256(
                          snippet.encode("utf-8")).hexdigest()}
                for key, snippet in self._snippets.items()
            }
            payload = {"schema_version": self.SCHEMA_VERSION,
                       "entries": records}
            started = time.monotonic()
            try:
                encoded = json.dumps(payload, ensure_ascii=False,
                                     separators=(",", ":"))
                if len(encoded.encode("utf-8")) > self.MAX_CACHE_BYTES:
                    # Entries are individually bounded; retain only the newest
                    # subset if old state was unusually large.
                    while (self._snippets
                           and len(encoded.encode("utf-8")) > self.MAX_CACHE_BYTES):
                        oldest = next(iter(self._snippets))
                        self._snippets.pop(oldest, None)
                        records.pop(oldest, None)
                        payload["entries"] = records
                        encoded = json.dumps(payload, ensure_ascii=False,
                                             separators=(",", ":"))
                self.cache_path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.cache_path.with_name(
                    ".%s.tmp.%d" % (self.cache_path.name, os.getpid()))
                tmp.write_text(encoded, encoding="utf-8")
                tmp.replace(self.cache_path)
                self._dirty = False
                self._metrics["snippet_cache_writes"] += 1
                self._metrics["snippet_cache_write_bytes"] += len(
                    encoded.encode("utf-8"))
            except (OSError, UnicodeError, ValueError, TypeError):
                # Cache persistence must never turn a successful evidence read
                # into an audit failure.
                self._metrics["snippet_cache_write_errors"] += 1
            self._metrics["snippet_cache_write_ms"] += (
                time.monotonic() - started) * 1000.0
        self._write_metrics_locked()

    def _write_metrics_locked(self) -> None:
        if self._metrics_path is None:
            return
        payload = {
            "schema_version": 1,
            "round": self._round_no,
            "status": self._round_status,
            "cache_policy": self.POLICY_VERSION,
            "elapsed_ms": round((time.monotonic() - self._round_started) * 1000.0, 3),
            "metrics": {key: (round(value, 3) if isinstance(value, float) else value)
                        for key, value in self._metrics.items()},
            "claim_status": "not-a-finding",
        }
        try:
            encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            self._metrics_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._metrics_path.with_name(
                ".%s.tmp.%d" % (self._metrics_path.name, os.getpid()))
            tmp.write_text(encoded, encoding="utf-8")
            tmp.replace(self._metrics_path)
        except (OSError, UnicodeError, ValueError, TypeError):
            # Telemetry is best-effort and cannot alter evidence handling.
            return


def scan_all_source_sink_paths(source_dirs: List[str], root: Path,
                               source_filter: Optional[SourceFilter] = None,
                               timeout: int = 600) -> List[Dict[str, object]]:
    """**Full** same-file source->sink heuristic paths; no cap (spec §6.1).

    Every edge stays ``heuristic-nearby`` and ``requires_manual_dataflow`` -- this
    is a *lead* generator, not a dataflow proof.  Cross-procedural flow analysis
    is :mod:`agent.analysis.dataflow`.

    Note this is still same-file / line-distance based, which is exactly the
    limitation spec §8 says the call graph must remove. It stays a lead
    generator; cross-procedural coverage comes from the flow index. Traversal
    uses the bounded source inventory instead of recursively walking build or
    repository metadata. A timeout raises :class:`SourceScanTimeout`; callers
    must preserve that gap.
    """
    # Unlike the inventory API, these scan helpers historically treat an
    # empty root list as an empty scope, not as an instruction to scan ".".
    if not source_dirs:
        return []
    flt = source_filter or SourceFilter(scan_timeout_seconds=timeout)
    paths: List[Dict[str, object]] = []
    root = root.resolve()
    budget = max(0.0, float(flt.scan_timeout_seconds or 0))
    started = time.monotonic()
    deadline = started + budget if budget else None

    def check_deadline(seen: int, rel: str, line: int = 0) -> None:
        if deadline is None:
            return
        now = time.monotonic()
        if now >= deadline:
            raise SourceScanTimeout({
                "elapsed_seconds": round(now - started, 3),
                "files_seen": seen,
                "source_files": seen,
                "directories_seen": 0,
                "current_path": rel,
                "current_line": line,
                "analysis": "source-sink-heuristics",
            })

    # Use the bounded Git-index-aware source universe rather than recursively
    # walking every directory (including .git, build output, and vendor trees).
    enumeration_filter = flt
    if deadline is not None:
        check_deadline(0, "")
        remaining = max(0.001, deadline - time.monotonic())
        enumeration_filter = replace(flt, scan_timeout_seconds=remaining)
    source_files = list(iter_source_files(
        root, source_dirs, source_filter=enumeration_filter))
    check_deadline(0, "")
    for seen, (path, rel) in enumerate(source_files, 1):
        check_deadline(seen - 1, rel)
        lines = _read_lines(path)
        check_deadline(seen, rel)
        if not lines:
            continue
        hits = {kind: [] for kind in _FLOW_PATTERNS}
        for number, text in enumerate(lines, 1):
            for kind, pattern in _FLOW_PATTERNS.items():
                check_deadline(seen, rel, number)
                if pattern.search(text):
                    hits[kind].append((number, text.strip()[:200]))
        hit_lines = {kind: [number for number, _text in items]
                     for kind, items in hits.items()}
        for source in hits["source"]:
            check_deadline(seen, rel, source[0])
            sink_start = bisect_left(hit_lines["sink"], source[0])
            sink_end = bisect_right(hit_lines["sink"], source[0] + 160)
            # Only the first few annotations at/after this source can ever
            # appear in an edge. Bisect once per source instead of repeatedly
            # walking every annotation and every sink in a large file.
            annotations = {}
            for kind, cap in (("transform", 4), ("validation", 3),
                              ("authorization", 3)):
                start = bisect_left(hit_lines[kind], source[0])
                annotations[kind] = hits[kind][start:start + cap]
            for sink in hits["sink"][sink_start:sink_end]:
                check_deadline(seen, rel, sink[0])
                transforms = [item for item in annotations["transform"]
                              if item[0] <= sink[0]]
                validations = [item for item in annotations["validation"]
                               if item[0] <= sink[0]]
                authorizations = [item for item in annotations["authorization"]
                                  if item[0] <= sink[0]]
                paths.append({
                    "source": "%s:%d %s" % (rel, source[0], source[1]),
                    "transform": ["%s:%d %s" % (rel, n, text) for n, text in transforms],
                    "validation": ["%s:%d %s" % (rel, n, text) for n, text in validations],
                    "authorization": ["%s:%d %s" % (rel, n, text) for n, text in authorizations],
                    "sink": "%s:%d %s" % (rel, sink[0], sink[1]),
                    "confidence": "heuristic-nearby",
                    "requires_manual_dataflow": True,
                })
        check_deadline(seen, rel)
    return paths


def build_source_sink_graph(source_dirs: List[str], root: Path,
                            max_paths: int = 160,
                            source_filter: Optional[SourceFilter] = None
                            ) -> List[Dict[str, object]]:
    """Bounded view over :func:`scan_all_source_sink_paths` for prompt budgets."""
    return summarize_hits(scan_all_source_sink_paths(source_dirs, root, source_filter),
                          max_paths)


def match_source_sink_paths(graph: List[Dict[str, object]], candidate: Dict[str, object],
                            max_paths: int = 8) -> List[Dict[str, object]]:
    """Select paths near candidate evidence without upgrading their confidence."""
    needles = [str(candidate.get("entry", ""))]
    needles += [str(x).split(":", 1)[0] for x in (candidate.get("code_location") or [])]
    needles = [x for x in needles if x]
    if not needles:
        return []
    selected = []
    for path in graph:
        blob = " ".join(str(path.get(key, "")) for key in ("source", "transform", "validation", "authorization", "sink"))
        if any(needle in blob for needle in needles):
            selected.append(path)
        if len(selected) >= max_paths:
            break
    return selected


def _budget_trim(parts: List[str], budget: int) -> List[str]:
    kept: List[str] = []
    used = 0
    for p in parts:
        if used + len(p) > budget:
            break
        kept.append(p)
        used += len(p)
    return kept


def surface_block(entries: List[Dict[str, object]], source_dirs: List[str],
                  root: Path, max_chars: int = 6000,
                  snippet_cache: Optional[CandidateSourceSnippetCache] = None,
                  timeout: Optional[float] = 600
                  ) -> str:
    """S1.5/S2: danger call-site digest + headers of hot entry classes.

    Bounded by design: this is a *prompt* budget, not an index (spec §2.1).  The
    ``[:6]`` / ``max_lines=4`` numbers below may be tuned freely without any
    effect on coverage.
    """
    parts: List[str] = []
    digs = []
    danger_hits = scan_all_labeled_hits(
        DANGER_PATTERNS, source_dirs, root, max_per_pattern=4,
        timeout=timeout)
    by_label: Dict[str, List[Dict[str, object]]] = {}
    for hit in danger_hits:
        by_label.setdefault(str(hit["label"]), []).append(hit)
    for _pat, label in DANGER_PATTERNS:
        hits = by_label.get(label, [])
        if hits:
            first = hits[0]
            digs.append("%s: %d hits; e.g. %s:%s" % (
                label, len(hits), first["file"], first["line"]))
    if digs:
        parts.append("## 危险模式命中摘要（源码证据）\n" + "\n".join("- " + d for d in digs))

    seen = set()
    for ep in (entries or [])[:6]:
        fl = ep.get("file_line") or ep.get("file")
        if not fl or fl in seen:
            continue
        seen.add(fl)
        p = _safe_resolve(root, str(fl))
        if not p or not p.exists():
            continue
        hdr = (snippet_cache.extract(
            p, root, str(fl), "class-header", None, 1200)
            if snippet_cache is not None else
            extract_class_header(p, max_chars=1200))
        if hdr:
            parts.append("### %s\n```java\n%s\n```" % (fl, hdr))
    if snippet_cache is not None:
        snippet_cache.flush()
    return "\n\n".join(_budget_trim(parts, max_chars)) or ""


def candidate_block(candidate: Dict[str, object], entries: List[Dict[str, object]],
                    source_dirs: List[str], root: Path,
                    max_chars: int = 6000,
                    timeout: Optional[float] = 600,
                    hit_cache: Optional[Dict[Tuple[object, ...], Dict[
                        str, List[Tuple[str, int]]]]] = None,
                    snippet_cache: Optional[CandidateSourceSnippetCache] = None
                    ) -> str:
    """S3/S4: snippets anchored at the candidate's entry API and keywords."""
    parts: List[str] = []
    anchors: List[Tuple[str, Optional[int]]] = []

    entry_api = str(candidate.get("entry") or "").strip("\\b().*")
    for ep in (entries or []):
        api = str(ep.get("api") or "").strip("\\b().*")
        if api and entry_api and api == entry_api:
            fl = ep.get("file_line") or ep.get("file")
            if fl:
                anchors.append((str(fl), None))
            break

    keywords = list(candidate.get("novelty_keywords") or [])
    logic = "%s %s" % (candidate.get("logic") or "", candidate.get("surface") or "")
    stop = {"public", "class", "static", "void", "json", "string", "object",
            "value", "input", "type", "parse", "using", "with", "from", "into",
            "result", "calls", "method", "when", "this", "return", "new"}
    for m in re.findall(r"[A-Za-z_][A-Za-z0-9_]{4,}", logic):
        if m.lower() not in stop:
            keywords.append(m)

    unique_keywords = []
    seen_kw = set()
    for value in keywords[:6]:
        kw = str(value or "")
        if kw and kw not in seen_kw:
            seen_kw.add(kw)
            unique_keywords.append(kw)
    if unique_keywords:
        combined = "|".join("(?:%s)" % re.escape(kw)
                            for kw in unique_keywords)
        cache_key = (str(root.resolve()), tuple(source_dirs), combined, timeout)
        keyword_anchors = hit_cache.get(cache_key) if hit_cache is not None else None
        if keyword_anchors is None:
            keyword_anchors = {kw: [] for kw in unique_keywords}
            labeled_hits = scan_all_labeled_hits(
                [(re.escape(kw), kw) for kw in unique_keywords],
                source_dirs, root, max_per_pattern=2, timeout=timeout)
            for hit in labeled_hits:
                keyword_anchors[str(hit["label"])].append((
                    str(hit["file"]), int(hit["line"])))
            if hit_cache is not None:
                # Store only the bounded anchors, never the full set of rg
                # matches. Callers own this cache and should keep it scoped to
                # one immutable audit round; it is intentionally not persisted.
                hit_cache[cache_key] = keyword_anchors
        for kw in unique_keywords:
            anchors.extend(keyword_anchors.get(kw, []))

    seen_files = set()
    for rel, line in anchors:
        if rel in seen_files:
            continue
        seen_files.add(rel)
        p = _safe_resolve(root, rel)
        if not p or not p.exists():
            continue
        if snippet_cache is not None:
            body = snippet_cache.extract(
                p, root, rel, "method" if line else "class-header", line,
                1600 if line else 1200)
        else:
            body = (extract_method(p, line, max_chars=1600) if line
                    else extract_class_header(p, max_chars=1200))
        if body:
            parts.append("### %s:%s\n```java\n%s\n```" % (rel, line or "1", body))
    if snippet_cache is not None:
        snippet_cache.flush()
    return "\n\n".join(_budget_trim(parts, max_chars)) or ""
