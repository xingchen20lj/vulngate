"""Read-only source/jar inspection helpers (rg, jar tf, hashing, unzip)."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import selectors
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence


class ToolUnavailable(RuntimeError):
    """An external tool this module shells out to is not on ``PATH``.

    Raised instead of the bare ``FileNotFoundError`` that ``subprocess``
    produces, because the bare error names neither the tool nor the fix and
    surfaces mid-stage as an unhandled traceback.  Callers that can degrade
    catch this; callers that cannot get an actionable message.

    Note on degradation: returning an empty result for a missing tool is *not*
    a safe fallback here.  ``count_references`` feeds gate G0, where an empty
    result reads as "zero external references" -- i.e. dead code.  Silently
    reporting every entry point as dead is a wrong audit, not a degraded one,
    so this must raise.
    """


def _argv0(argv: Sequence[str], tool: Optional[str]) -> str:
    """Resolve the executable that ``subprocess`` would run for ``argv``."""
    return str(tool or argv[0])


def run_tool(argv: Sequence[str], tool: Optional[str] = None,
             **kwargs) -> "subprocess.CompletedProcess[str]":
    """Run ``argv``, turning a missing binary into :class:`ToolUnavailable`.

    A separate helper (rather than a try/except at each call site) so every
    external dependency in this module fails the same way and says the same
    thing.
    """
    name = _argv0(argv, tool)
    try:
        return subprocess.run(list(argv), capture_output=True, text=True,
                              errors="replace", **kwargs)
    except FileNotFoundError as exc:
        raise ToolUnavailable(
            "required tool %r is not on PATH; install it and re-run "
            "(for ripgrep: brew install ripgrep, or add its directory to PATH)"
            % name) from exc


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def rg(pattern: str, path: Path, globs: Optional[List[str]] = None,
       max_count: Optional[int] = None) -> List[str]:
    cmd = ["rg", "-n", "--no-heading", pattern, str(path)]
    for g in globs or []:
        cmd += ["-g", g]
    proc = run_tool(cmd)
    if proc.returncode not in (0, 1):
        return []
    lines = [ln for ln in (proc.stdout or "").splitlines() if ln.strip()]
    if max_count is not None:
        lines = lines[:max_count]
    return lines


def count_references(path: Path, symbol: str, globs: Optional[List[str]] = None) -> int:
    return len(rg(symbol, path, globs))


def _decode_path(data: Dict[str, Any]) -> str:
    """Decode an ``rg --json`` path field (``text`` or base64 ``bytes``)."""
    path = data.get("path") or {}
    if "text" in path:
        return str(path["text"])
    if "bytes" in path:
        try:
            return base64.b64decode(path["bytes"]).decode("utf-8", "replace")
        except Exception:  # pragma: no cover - malformed rg payload
            return ""
    return ""


def rg_matches(pattern: str, path: Path, globs: Optional[List[str]] = None,
               exclude_globs: Optional[Iterable[str]] = None,
               extra_args: Optional[Sequence[str]] = None,
               max_count: Optional[int] = None,
               timeout: Optional[float] = 300) -> List[Dict[str, Any]]:
    """Structured ripgrep scan: ``[{file, line, text}]``.

    Uses ``rg --json`` rather than parsing ``file:line:text`` strings.  The
    string form silently drops every hit whose *path* contains a colon, which
    is unacceptable for the coverage inventory where a missing hit reads as
    "not present in the codebase" (spec §19.7, no silent omission).

    ``max_count`` (when given) truncates the returned list.  Callers building an
    index must leave it ``None``.
    """
    cmd = ["rg", "--json", "-n"]
    for g in globs or []:
        cmd += ["-g", g]
    cmd += ["-e", pattern, str(path)]
    for g in exclude_globs or []:
        cmd += ["-g", g]
    cmd += list(extra_args or [])
    proc = run_tool(cmd, timeout=timeout)
    if proc.returncode not in (0, 1):
        detail = (proc.stderr or "").strip().replace("\n", " ")[:400]
        raise RuntimeError("ripgrep failed with exit code %d%s" % (
            proc.returncode, (": " + detail) if detail else ""))
    hits: List[Dict[str, Any]] = []
    for raw in (proc.stdout or "").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            event = json.loads(raw)
        except ValueError as exc:  # pragma: no cover - rg emits valid JSON
            raise RuntimeError("ripgrep emitted malformed JSON output") from exc
        if event.get("type") != "match":
            continue
        data = event.get("data") or {}
        line_data = data.get("lines") or {}
        lines = line_data.get("text")
        if lines is None:
            encoded_lines = line_data.get("bytes")
            if not encoded_lines:
                raise RuntimeError("ripgrep match omitted line content")
            try:
                lines = base64.b64decode(encoded_lines).decode("utf-8", "replace")
            except Exception as exc:  # pragma: no cover - malformed rg payload
                raise RuntimeError("ripgrep emitted invalid encoded line content") from exc
        hits.append({
            "file": _decode_path(data),
            "line": int(data.get("line_number") or 0),
            "text": lines.rstrip("\n"),
        })
        if max_count is not None and len(hits) >= max_count:
            break
    return hits


def iter_rg_matches(pattern: str, path: Path,
                    globs: Optional[List[str]] = None,
                    exclude_globs: Optional[Iterable[str]] = None,
                    extra_args: Optional[Sequence[str]] = None,
                    timeout: Optional[float] = 300) -> Iterator[Dict[str, Any]]:
    """Stream structured ripgrep hits so bounded prompt scans retain bounded memory.

    Unlike :func:`rg_matches`, this iterator does not accumulate every JSON
    event in a captured stdout string. Closing it early terminates ripgrep;
    callers that require a complete inventory must use the uncapped scan path.
    """
    cmd = ["rg", "--json", "-n"]
    for glob in globs or []:
        cmd += ["-g", glob]
    cmd += ["-e", pattern, str(path)]
    for glob in exclude_globs or []:
        cmd += ["-g", glob]
    cmd += list(extra_args or [])

    # Windows selectors cannot wait on anonymous pipes. Keep the compatibility
    # fallback there; Codex's supported macOS/Linux paths stream incrementally.
    if os.name == "nt":  # pragma: no cover - Windows fallback
        yield from rg_matches(pattern, path, globs, exclude_globs,
                              extra_args, timeout=timeout)
        return

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, bufsize=0)
    except FileNotFoundError as exc:
        raise ToolUnavailable(
            "required tool 'rg' is not on PATH; install ripgrep or add its directory to PATH"
        ) from exc

    selector = selectors.DefaultSelector()
    stdout = proc.stdout
    stderr = proc.stderr
    assert stdout is not None and stderr is not None
    selector.register(stdout, selectors.EVENT_READ, "stdout")
    selector.register(stderr, selectors.EVENT_READ, "stderr")
    started = time.monotonic()
    deadline = (started + float(timeout)) if timeout is not None else None
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    completed = False

    def decode_hit(raw: bytes) -> Optional[Dict[str, Any]]:
        if not raw.strip():
            return None
        try:
            event = json.loads(raw.decode("utf-8", "replace"))
        except ValueError as exc:
            raise RuntimeError("ripgrep emitted malformed JSON output") from exc
        if event.get("type") != "match":
            return None
        data = event.get("data") or {}
        line_data = data.get("lines") or {}
        line_text = line_data.get("text")
        if line_text is None:
            encoded = line_data.get("bytes")
            if not encoded:
                raise RuntimeError("ripgrep match omitted line content")
            try:
                line_text = base64.b64decode(encoded).decode("utf-8", "replace")
            except Exception as exc:  # pragma: no cover - malformed rg payload
                raise RuntimeError("ripgrep emitted invalid encoded line content") from exc
        return {
            "file": _decode_path(data),
            "line": int(data.get("line_number") or 0),
            "text": str(line_text).rstrip("\n"),
        }

    try:
        streams_open = 2
        while streams_open:
            remaining = (None if deadline is None else
                         max(0.0, deadline - time.monotonic()))
            if remaining == 0.0:
                raise subprocess.TimeoutExpired(cmd, timeout)
            events = selector.select(remaining)
            if not events:
                raise subprocess.TimeoutExpired(cmd, timeout)
            for key, _mask in events:
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    streams_open -= 1
                    if key.data == "stdout" and stdout_buffer:
                        hit = decode_hit(bytes(stdout_buffer))
                        stdout_buffer.clear()
                        if hit is not None:
                            yield hit
                    continue
                if key.data == "stderr":
                    if len(stderr_buffer) < 4096:
                        stderr_buffer.extend(chunk[:4096 - len(stderr_buffer)])
                    continue
                stdout_buffer.extend(chunk)
                while True:
                    newline = stdout_buffer.find(b"\n")
                    if newline < 0:
                        break
                    raw = bytes(stdout_buffer[:newline])
                    del stdout_buffer[:newline + 1]
                    hit = decode_hit(raw)
                    if hit is not None:
                        yield hit
        remaining = (None if deadline is None else
                     max(0.0, deadline - time.monotonic()))
        returncode = proc.wait(timeout=remaining)
        completed = True
        if returncode not in (0, 1):
            detail = stderr_buffer.decode("utf-8", "replace").strip().replace(
                "\n", " ")[:400]
            raise RuntimeError("ripgrep failed with exit code %d%s" % (
                returncode, (": " + detail) if detail else ""))
    finally:
        selector.close()
        if not completed and proc.poll() is None:
            proc.kill()
        if not completed:
            proc.wait()
        for stream in (stdout, stderr):
            try:
                stream.close()
            except OSError:
                pass


def jar_classes(jar: Path) -> List[str]:
    proc = run_tool(["jar", "tf", str(jar)], tool="jar")
    if proc.returncode != 0:
        return []
    return [ln for ln in (proc.stdout or "").splitlines() if ln.strip()]


def unzip_jar(jar: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    run_tool(["unzip", "-q", "-o", str(jar), "-d", str(dest)],
             tool="unzip", check=True)


def module_map(classes: List[str], top_levels: int = 3) -> dict:
    from collections import Counter
    prefixes = Counter()
    for cls in classes:
        if cls.endswith(".class") and not cls.endswith("module-info.class"):
            parts = cls.split("/")
            prefixes[".".join(parts[:top_levels])] += 1
    return dict(prefixes.most_common(40))
