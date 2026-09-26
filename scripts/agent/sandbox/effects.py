"""Independent runtime-effect collectors.

PoC output is a claim.  This module contains bounded observers that the
harness may use to turn an explicitly declared before/after state into an
``ObservedEffect``.  Collectors never persist file contents, process command
lines, database rows, or authorization values: only bounded names, counts and
digests cross the artifact boundary.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


EFFECT_SCHEMA_VERSION = "observed-effect-v1"
EFFECT_KINDS = (
    "http-semantic", "filesystem-diff", "process-effect", "fixture-db",
    "jvm-effect", "jvm-protocol", "authorization-state",
)
EFFECT_STATUSES = {"observed", "absent", "pending"}
MAX_SNAPSHOT_ENTRIES = 4096
MAX_SNAPSHOT_FILE_BYTES = 4 * 1024 * 1024
MAX_DATABASE_ROWS = 2048
MAX_DATABASE_COLUMNS = 128
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_CHANGED_PATHS = 128
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), default=str).encode("utf-8")[:65536]).hexdigest()


def _bytes_digest(path: Path, limit: int = MAX_SNAPSHOT_FILE_BYTES) -> str:
    digest = hashlib.sha256()
    remaining = max(0, int(limit))
    with path.open("rb") as handle:
        while remaining:
            block = handle.read(min(64 * 1024, remaining))
            if not block:
                break
            digest.update(block)
            remaining -= len(block)
    return digest.hexdigest()


def _safe_name(value: Any) -> str:
    return Path(str(value or "")).name.strip().lower()


def _bounded_list(values: Iterable[Any], limit: int = MAX_CHANGED_PATHS) -> List[str]:
    return sorted({str(value)[:240] for value in values})[:limit]


def _snapshot_ok(snapshot: Any) -> bool:
    return isinstance(snapshot, Mapping) and snapshot.get("status") == "ok"


@dataclass(frozen=True)
class ObservedEffect:
    kind: str
    collector_id: str
    run_id: str
    candidate_id: str = ""
    cell_id: str = ""
    status: str = "observed"
    predicate_id: str = ""
    value_digest: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)
    independent: bool = True

    def as_dict(self) -> Dict[str, Any]:
        if self.kind not in EFFECT_KINDS:
            raise ValueError("unknown observed-effect kind: %s" % self.kind)
        status = self.status if self.status in EFFECT_STATUSES else "pending"
        return {
            "schema_version": EFFECT_SCHEMA_VERSION,
            "kind": self.kind,
            "collector_id": self.collector_id[:120],
            "run_id": self.run_id[:120],
            "candidate_id": self.candidate_id[:120],
            "cell_id": self.cell_id[:120],
            "status": status,
            "predicate_id": self.predicate_id[:120],
            "value_digest": self.value_digest or _digest(self.details),
            "details": dict(self.details),
            "independent": bool(self.independent),
        }


class EffectCollector:
    kind = ""
    collector_id = "unconfigured"
    available = False

    def collect(self, *args: Any, **kwargs: Any) -> Optional[ObservedEffect]:
        raise NotImplementedError

    @staticmethod
    def _pending(run_id: str, candidate_id: str, cell_id: str,
                 kind: str, collector_id: str, reason: str) -> ObservedEffect:
        return ObservedEffect(
            kind=kind, collector_id=collector_id, run_id=run_id,
            candidate_id=candidate_id, cell_id=cell_id, status="pending",
            details={"reason": str(reason)[:240]}, independent=True)


class HTTPSemanticCollector(EffectCollector):
    kind = "http-semantic"
    collector_id = "vulngate.http-observer"
    available = True

    def collect(self, run_id: str, candidate_id: str, cell_id: str,
                predicate_id: str, matched: bool,
                details: Optional[Mapping[str, Any]] = None) -> ObservedEffect:
        return ObservedEffect(
            kind=self.kind, collector_id=self.collector_id,
            run_id=run_id, candidate_id=candidate_id, cell_id=cell_id,
            predicate_id=predicate_id, status="observed" if matched else "absent",
            details=dict(details or {}), independent=True)


class FilesystemDiffCollector(EffectCollector):
    """Observe bounded changes below one explicitly selected directory."""

    kind = "filesystem-diff"
    collector_id = "vulngate.filesystem-snapshot-v1"
    available = True

    def __init__(self, *, max_entries: int = MAX_SNAPSHOT_ENTRIES,
                 max_file_bytes: int = MAX_SNAPSHOT_FILE_BYTES):
        self.max_entries = max(1, min(int(max_entries), MAX_SNAPSHOT_ENTRIES))
        self.max_file_bytes = max(1, min(int(max_file_bytes),
                                         MAX_SNAPSHOT_FILE_BYTES))

    def snapshot(self, root: Path) -> Dict[str, Any]:
        root = Path(root).expanduser().resolve(strict=False)
        if not root.is_dir():
            return {"status": "pending", "reason": "filesystem-root-unavailable"}
        entries: Dict[str, Dict[str, Any]] = {}
        pending = False
        stack = [root]
        while stack and len(entries) < self.max_entries:
            current = stack.pop()
            try:
                children = sorted(os.scandir(current), key=lambda item: item.name)
            except OSError:
                pending = True
                continue
            for item in children:
                if len(entries) >= self.max_entries:
                    pending = True
                    break
                try:
                    stat = item.stat(follow_symlinks=False)
                    relative = str(Path(item.path).relative_to(root))
                    if item.is_symlink():
                        row = {"kind": "symlink", "size": int(stat.st_size)}
                    elif item.is_dir(follow_symlinks=False):
                        row = {"kind": "directory"}
                        stack.append(Path(item.path))
                    elif item.is_file(follow_symlinks=False):
                        row = {"kind": "file", "size": int(stat.st_size)}
                        if stat.st_size <= self.max_file_bytes:
                            try:
                                row["digest"] = _bytes_digest(
                                    Path(item.path), self.max_file_bytes)
                            except OSError:
                                row["read_error"] = True
                                pending = True
                        else:
                            row["digest"] = "size:%d" % stat.st_size
                            row["truncated"] = True
                    else:
                        row = {"kind": "special"}
                    entries[relative[:240]] = row
                except (OSError, ValueError):
                    pending = True
        return {
            "status": "ok" if not pending else "pending",
            "entries": entries,
            "entry_count": len(entries),
            "truncated": len(entries) >= self.max_entries,
        }

    def collect(self, run_id: str, candidate_id: str, cell_id: str,
                before: Mapping[str, Any], after: Mapping[str, Any]) -> ObservedEffect:
        if not _snapshot_ok(before) or not _snapshot_ok(after):
            return self._pending(run_id, candidate_id, cell_id, self.kind,
                                 self.collector_id, "incomplete-filesystem-snapshot")
        old = before.get("entries", {})
        new = after.get("entries", {})
        if not isinstance(old, Mapping) or not isinstance(new, Mapping):
            return self._pending(run_id, candidate_id, cell_id, self.kind,
                                 self.collector_id, "invalid-filesystem-snapshot")
        added = set(new) - set(old)
        removed = set(old) - set(new)
        modified = {key for key in set(old) & set(new) if old[key] != new[key]}
        changed = bool(added or removed or modified)
        details = {
            "added": _bounded_list(added),
            "removed": _bounded_list(removed),
            "modified": _bounded_list(modified),
            "change_count": len(added) + len(removed) + len(modified),
            "snapshot_truncated": bool(before.get("truncated") or
                                        after.get("truncated")),
        }
        return ObservedEffect(
            kind=self.kind, collector_id=self.collector_id, run_id=run_id,
            candidate_id=candidate_id, cell_id=cell_id,
            status="observed" if changed else "absent", details=details)


class ProcessEffectCollector(EffectCollector):
    """Observe process lifecycle changes using names, never command lines."""

    kind = "process-effect"
    collector_id = "vulngate.process-snapshot-v1"
    available = True

    @staticmethod
    def snapshot(*, max_processes: int = MAX_SNAPSHOT_ENTRIES) -> Dict[str, Any]:
        rows: Dict[str, Dict[str, Any]] = {}
        limit = max(1, min(int(max_processes), MAX_SNAPSHOT_ENTRIES))
        proc_root = Path("/proc")
        if proc_root.is_dir():
            for entry in sorted(proc_root.iterdir(), key=lambda item: item.name):
                if len(rows) >= limit or not entry.name.isdigit():
                    continue
                try:
                    comm = (entry / "comm").read_text(
                        encoding="utf-8", errors="replace").strip()[:120]
                    stat = (entry / "stat").read_text(
                        encoding="utf-8", errors="replace")
                    tail = stat.rsplit(")", 1)[-1].split()
                    ppid = int(tail[1]) if len(tail) > 1 else 0
                    rows[entry.name] = {"pid": int(entry.name), "ppid": ppid,
                                        "comm": comm}
                except (OSError, ValueError, IndexError):
                    continue
        else:
            try:
                result = subprocess.run(
                    ["ps", "-axo", "pid=,ppid=,comm="],
                    check=False, capture_output=True, text=True, timeout=2)
            except (OSError, subprocess.SubprocessError):
                return {"status": "pending", "reason": "process-snapshot-unavailable"}
            for line in result.stdout.splitlines()[:limit]:
                parts = line.strip().split(None, 2)
                if len(parts) != 3:
                    continue
                try:
                    pid, ppid = int(parts[0]), int(parts[1])
                except ValueError:
                    continue
                rows[str(pid)] = {"pid": pid, "ppid": ppid,
                                  "comm": parts[2][:120]}
        return {"status": "ok", "processes": rows,
                "process_count": len(rows), "truncated": len(rows) >= limit}

    def collect(self, run_id: str, candidate_id: str, cell_id: str,
                before: Mapping[str, Any], after: Mapping[str, Any],
                expected_names: Sequence[str]) -> ObservedEffect:
        names = {_safe_name(name) for name in expected_names if _safe_name(name)}
        if not names:
            return self._pending(run_id, candidate_id, cell_id, self.kind,
                                 self.collector_id, "expected-process-name-required")
        if not _snapshot_ok(before) or not _snapshot_ok(after):
            return self._pending(run_id, candidate_id, cell_id, self.kind,
                                 self.collector_id, "incomplete-process-snapshot")
        old = before.get("processes", {})
        new = after.get("processes", {})
        if not isinstance(old, Mapping) or not isinstance(new, Mapping):
            return self._pending(run_id, candidate_id, cell_id, self.kind,
                                 self.collector_id, "invalid-process-snapshot")

        def matches(row: Any) -> bool:
            return isinstance(row, Mapping) and _safe_name(row.get("comm")) in names

        added = [new[key] for key in set(new) - set(old) if matches(new[key])]
        removed = [old[key] for key in set(old) - set(new) if matches(old[key])]
        details = {
            "expected_names": sorted(names),
            "added_count": len(added),
            "removed_count": len(removed),
            "added_processes": sorted({str(row.get("comm", ""))[:120]
                                       for row in added}),
            "removed_processes": sorted({str(row.get("comm", ""))[:120]
                                         for row in removed}),
            "snapshot_truncated": bool(before.get("truncated") or
                                        after.get("truncated")),
        }
        return ObservedEffect(
            kind=self.kind, collector_id=self.collector_id, run_id=run_id,
            candidate_id=candidate_id, cell_id=cell_id,
            status="observed" if added or removed else "absent", details=details)


class FixtureDBCollector(EffectCollector):
    """Observe selected SQLite fixture tables without persisting row values."""

    kind = "fixture-db"
    collector_id = "vulngate.fixture-db-v1"
    available = True

    def __init__(self, *, max_rows: int = MAX_DATABASE_ROWS):
        self.max_rows = max(1, min(int(max_rows), MAX_DATABASE_ROWS))

    @staticmethod
    def _table_name(value: Any) -> str:
        table = str(value or "").strip()
        if not _IDENTIFIER.fullmatch(table):
            raise ValueError("fixture DB table must be a simple identifier")
        return table

    def snapshot(self, path: Path, tables: Sequence[str]) -> Dict[str, Any]:
        path = Path(path).expanduser().resolve(strict=False)
        if not path.is_file() or not tables:
            return {"status": "pending", "reason": "fixture-db-scope-unavailable"}
        normalized = []
        try:
            normalized = [self._table_name(item) for item in tables[:64]]
            uri = "file:%s?mode=ro" % path.as_posix().replace("%", "%25")
            connection = sqlite3.connect(uri, uri=True)
            connection.row_factory = sqlite3.Row
        except (OSError, sqlite3.Error, ValueError):
            return {"status": "pending", "reason": "fixture-db-read-only-open-failed"}
        try:
            result: Dict[str, Any] = {}
            for table in normalized:
                quoted = '"%s"' % table.replace('"', '""')
                try:
                    cursor = connection.execute("SELECT * FROM %s LIMIT ?" % quoted,
                                               (self.max_rows + 1,))
                    columns = [str(item[0])[:120] for item in (cursor.description or [])]
                    columns = columns[:MAX_DATABASE_COLUMNS]
                    row_digests = []
                    for row in cursor.fetchall()[:self.max_rows]:
                        values = [row[index] for index in range(min(len(columns), len(row)))]
                        row_digests.append(_digest(values))
                    result[table] = {
                        "columns": columns,
                        "row_count": len(row_digests),
                        "row_digests": sorted(row_digests),
                        "truncated": len(row_digests) >= self.max_rows,
                    }
                except sqlite3.Error:
                    result[table] = {"missing_or_unreadable": True}
            return {"status": "ok", "tables": result}
        finally:
            connection.close()

    def collect(self, run_id: str, candidate_id: str, cell_id: str,
                before: Mapping[str, Any], after: Mapping[str, Any]) -> ObservedEffect:
        if not _snapshot_ok(before) or not _snapshot_ok(after):
            return self._pending(run_id, candidate_id, cell_id, self.kind,
                                 self.collector_id, "incomplete-fixture-db-snapshot")
        old, new = before.get("tables", {}), after.get("tables", {})
        if not isinstance(old, Mapping) or not isinstance(new, Mapping):
            return self._pending(run_id, candidate_id, cell_id, self.kind,
                                 self.collector_id, "invalid-fixture-db-snapshot")
        changed = sorted(key for key in set(old) | set(new) if old.get(key) != new.get(key))
        details = {
            "changed_tables": _bounded_list(changed),
            "change_count": len(changed),
            "snapshot_truncated": any(
                bool(row.get("truncated"))
                for row in list(old.values()) + list(new.values())
                if isinstance(row, Mapping)),
        }
        return ObservedEffect(
            kind=self.kind, collector_id=self.collector_id, run_id=run_id,
            candidate_id=candidate_id, cell_id=cell_id,
            status="observed" if changed else "absent", details=details)


class JVMEffectCollector(ProcessEffectCollector):
    """Observe an explicitly named JVM process lifecycle, not JVM stderr."""

    kind = "jvm-effect"
    collector_id = "vulngate.jvm-process-observer-v1"
    available = True

    def collect(self, run_id: str, candidate_id: str, cell_id: str,
                before: Mapping[str, Any], after: Mapping[str, Any],
                expected_names: Sequence[str] = ("java", "javaw", "java.exe")) -> ObservedEffect:
        effect = super().collect(run_id, candidate_id, cell_id, before, after,
                                 expected_names)
        return ObservedEffect(
            kind=self.kind, collector_id=self.collector_id, run_id=run_id,
            candidate_id=candidate_id, cell_id=cell_id, status=effect.status,
            details=dict(effect.details), independent=True)


class AuthorizationStateCollector(EffectCollector):
    """Observe selected JSON authorization state paths by digest only."""

    kind = "authorization-state"
    collector_id = "vulngate.authorization-state-v1"
    available = True

    def snapshot(self, path: Path, allowed_paths: Sequence[str]) -> Dict[str, Any]:
        path = Path(path).expanduser().resolve(strict=False)
        paths = [str(item).strip() for item in allowed_paths[:64]
                 if str(item).strip()]
        if not path.is_file() or not paths:
            return {"status": "pending", "reason": "authorization-state-scope-unavailable"}
        try:
            if path.stat().st_size > MAX_JSON_BYTES:
                return {"status": "pending", "reason": "authorization-state-too-large"}
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError):
            return {"status": "pending", "reason": "authorization-state-invalid-json"}
        values: Dict[str, Dict[str, Any]] = {}
        for pointer in paths:
            current: Any = document
            found = True
            parts = pointer.strip("/").split("/") if pointer.strip("/") else []
            for part in parts:
                if isinstance(current, Mapping) and part in current:
                    current = current[part]
                else:
                    found = False
                    break
            values[pointer[:160]] = {
                "present": found,
                "type": type(current).__name__ if found else "missing",
                "digest": _digest(current) if found else "",
            }
        return {"status": "ok", "paths": values}

    def collect(self, run_id: str, candidate_id: str, cell_id: str,
                before: Mapping[str, Any], after: Mapping[str, Any]) -> ObservedEffect:
        if not _snapshot_ok(before) or not _snapshot_ok(after):
            return self._pending(run_id, candidate_id, cell_id, self.kind,
                                 self.collector_id, "incomplete-authorization-state-snapshot")
        old, new = before.get("paths", {}), after.get("paths", {})
        if not isinstance(old, Mapping) or not isinstance(new, Mapping):
            return self._pending(run_id, candidate_id, cell_id, self.kind,
                                 self.collector_id, "invalid-authorization-state-snapshot")
        changed = sorted(key for key in set(old) | set(new) if old.get(key) != new.get(key))
        return ObservedEffect(
            kind=self.kind, collector_id=self.collector_id, run_id=run_id,
            candidate_id=candidate_id, cell_id=cell_id,
            status="observed" if changed else "absent",
            details={"changed_paths": _bounded_list(changed),
                     "change_count": len(changed)})


class JVMProtocolStateCollector(AuthorizationStateCollector):
    """Observe target-declared, bounded JVM protocol state by digest only.

    The target adapter must expose a workspace-local JSON state snapshot and
    explicitly allowlist JSON-pointer paths. This is intentionally a state
    observer rather than a stdout/stderr parser: a target that cannot provide
    such a snapshot remains pending instead of turning a protocol claim into
    evidence.
    """

    kind = "jvm-protocol"
    collector_id = "vulngate.jvm-protocol-state-v1"
    available = True


_COLLECTORS = {
    cls.kind: cls() for cls in (
        HTTPSemanticCollector, FilesystemDiffCollector, ProcessEffectCollector,
        FixtureDBCollector, JVMEffectCollector, AuthorizationStateCollector,
        JVMProtocolStateCollector,
    )
}


def collector_for(kind: str) -> Optional[EffectCollector]:
    collector = _COLLECTORS.get(str(kind or "").strip().lower())
    return collector if collector is not None and collector.available else None


def supported_effect_kinds() -> Tuple[str, ...]:
    return tuple(sorted(kind for kind, collector in _COLLECTORS.items()
                       if collector.available))


def effect_status(effects: Iterable[Mapping[str, Any]], kind: str) -> str:
    rows = [row for row in effects if row.get("kind") == kind]
    if not rows:
        return "pending"
    if any(row.get("status") == "observed" and row.get("independent") is True
           for row in rows):
        return "observed"
    if any(row.get("status") == "absent" for row in rows):
        return "absent"
    return "pending"
