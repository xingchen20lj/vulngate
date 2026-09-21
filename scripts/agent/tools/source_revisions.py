"""Resolve explicitly supplied historical build artifacts.

The source-revision comparison arm is deliberately an artifact adapter, not a
build system.  An operator may opt in with workspace-local JAR/WAR/ZIP files
for the exact ``before``/``after`` commit references already present in the
bounded comparison contract.  VulnGate validates and fingerprints those
files, then lets the existing isolated Java matrix runner execute the same
fixture/lane.  It never checks out a commit, invokes a build command, follows
an arbitrary path outside the workspace, or treats a missing artifact as a
negative observation.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Tuple


SOURCE_REVISION_SCHEMA_VERSION = "source-revision-artifacts-v1"
CLAIM_STATUS = "not-a-finding"
MAX_ARMS = 2
MAX_ARTIFACTS_PER_ARM = 8
MAX_PATH_LENGTH = 240
MAX_REASON_LENGTH = 120
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024

_COMMIT_RE = re.compile(r"^[0-9a-f]{7,64}$", re.I)
_ALLOWED_SUFFIXES = frozenset({".jar", ".war", ".zip"})
_ROLES = frozenset({"before", "after"})
_ALLOWED_STATUSES = frozenset({"available", "precondition-unavailable"})
_ALLOWED_REASONS = frozenset({
    "artifact-path-unresolvable", "artifact-outside-workspace",
    "artifact-not-a-file", "unsupported-artifact-type", "artifact-stat-failed",
    "artifact-empty", "artifact-too-large", "artifact-read-failed",
    "artifact-list-empty",
})
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$", re.I)


def _text(value: Any, limit: int = MAX_PATH_LENGTH) -> str:
    return " ".join(str(value or "").replace("\x00", "").split())[:limit]


def _commit(value: Any) -> str:
    item = _text(value, 80).lower()
    return item if _COMMIT_RE.fullmatch(item) else ""


def _path_values(value: Any) -> List[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    result: List[str] = []
    seen = set()
    for item in value:
        path = _text(item)
        if not path or path in seen:
            continue
        seen.add(path)
        result.append(path)
        if len(result) >= MAX_ARTIFACTS_PER_ARM:
            break
    return result


def _safe_relative_paths(value: Any) -> List[str]:
    result: List[str] = []
    for path in _path_values(value):
        normalized = path.replace("\\", "/")
        if (normalized.startswith("/")
                or re.match(r"^[a-z]:/", normalized, re.I)
                or ".." in normalized.split("/")):
            continue
        result.append(path)
        if len(result) >= MAX_ARTIFACTS_PER_ARM:
            break
    return result


def _safe_digests(value: Any) -> List[str]:
    return [item.lower() for item in _path_values(value)
            if _SHA256_RE.fullmatch(item)][:MAX_ARTIFACTS_PER_ARM]


def _safe_reason(value: Any) -> str:
    reasons = [item for item in _text(value, MAX_REASON_LENGTH).lower().split(";")
               if item in _ALLOWED_REASONS]
    return ";".join(reasons)[:MAX_REASON_LENGTH]


def _raw_declaration(value: Any) -> Mapping[str, Any]:
    """Accept a TargetConfig, its field, or a whole config mapping."""
    if isinstance(value, Mapping) and "source_revision_artifacts" in value:
        value = value.get("source_revision_artifacts")
    elif not isinstance(value, Mapping):
        value = getattr(value, "source_revision_artifacts", {})
    return value if isinstance(value, Mapping) else {}


def normalize_source_revision_artifacts(value: Any) -> Dict[str, Any]:
    """Normalize only the explicit declaration, without touching the FS."""
    raw = _raw_declaration(value)
    enabled = raw.get("enabled") is True
    arms = raw.get("arms") if isinstance(raw.get("arms"), list) else []
    normalized: List[Dict[str, Any]] = []
    seen = set()
    for item in arms:
        if not isinstance(item, Mapping):
            continue
        role = _text(item.get("role"), 16).lower()
        ref = _commit(item.get("ref"))
        paths = _path_values(
            item.get("jars", item.get("artifacts", item.get("paths"))))
        key = (role, ref)
        if role not in _ROLES or not ref or not paths or key in seen:
            continue
        seen.add(key)
        normalized.append({"role": role, "ref": ref, "paths": paths})
        if len(normalized) >= MAX_ARMS:
            break
    normalized.sort(key=lambda row: ({"before": 0, "after": 1}.get(
        row["role"], 9), row["ref"]))
    return {
        "schema_version": SOURCE_REVISION_SCHEMA_VERSION,
        "enabled": bool(enabled),
        "arms": normalized if enabled else [],
        "claim_status": CLAIM_STATUS,
    }


def _within(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_source_revision_artifacts(workspace: Path, value: Any) -> Dict[str, Any]:
    """Validate operator-supplied artifacts and return runner-ready entries.

    Each available arm contains a private ``_paths`` list for the in-process
    runner.  The private value is intentionally removed by
    :func:`source_revision_snapshot` before anything is persisted.
    """
    root = Path(workspace).resolve()
    declaration = normalize_source_revision_artifacts(value)
    result: List[Dict[str, Any]] = []
    for arm in declaration["arms"]:
        resolved: List[Path] = []
        relative_paths: List[str] = []
        digests: List[str] = []
        errors: List[str] = []
        for raw_path in arm["paths"]:
            candidate = Path(raw_path).expanduser()
            if not candidate.is_absolute():
                candidate = root / candidate
            try:
                candidate = candidate.resolve(strict=False)
            except OSError:
                errors.append("artifact-path-unresolvable")
                continue
            if not _within(root, candidate):
                errors.append("artifact-outside-workspace")
                continue
            if not candidate.is_file():
                errors.append("artifact-not-a-file")
                continue
            if candidate.suffix.lower() not in _ALLOWED_SUFFIXES:
                errors.append("unsupported-artifact-type")
                continue
            try:
                size = candidate.stat().st_size
            except OSError:
                errors.append("artifact-stat-failed")
                continue
            if size <= 0:
                errors.append("artifact-empty")
                continue
            if size > MAX_ARTIFACT_BYTES:
                errors.append("artifact-too-large")
                continue
            try:
                digest = _sha256(candidate)
                relative = str(candidate.relative_to(root))
            except (OSError, ValueError):
                errors.append("artifact-read-failed")
                continue
            resolved.append(candidate)
            relative_paths.append(relative[:MAX_PATH_LENGTH])
            digests.append("sha256:" + digest)

        if errors or not resolved:
            status = "precondition-unavailable"
            reason = ";".join(sorted(set(errors))) or "artifact-list-empty"
            resolved = []
            relative_paths = []
            digests = []
        else:
            status = "available"
            reason = ""
        result.append({
            "role": arm["role"],
            "ref": arm["ref"],
            "status": status,
            "reason": reason[:MAX_REASON_LENGTH],
            "artifact_count": len(resolved),
            "paths": relative_paths,
            "artifact_digests": digests,
            "_paths": resolved,
            "claim_status": CLAIM_STATUS,
        })
    return {
        "schema_version": SOURCE_REVISION_SCHEMA_VERSION,
        "enabled": bool(declaration["enabled"]),
        "arms": result,
        "claim_status": CLAIM_STATUS,
    }


def source_revision_index(resolved: Any) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """Index resolved arms by the exact comparison-contract identity."""
    if not isinstance(resolved, Mapping):
        return {}
    result: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for item in resolved.get("arms") or []:
        if not isinstance(item, Mapping):
            continue
        role = _text(item.get("role"), 16).lower()
        ref = _commit(item.get("ref"))
        if role in _ROLES and ref:
            result[(role, ref)] = dict(item)
    return result


def source_revision_snapshot(resolved: Any) -> Dict[str, Any]:
    """Return the credential-free, JSON-safe artifact availability snapshot."""
    if not isinstance(resolved, Mapping):
        resolved = {}
    arms: List[Dict[str, Any]] = []
    for item in resolved.get("arms") or []:
        if not isinstance(item, Mapping):
            continue
        try:
            artifact_count = int(item.get("artifact_count", 0) or 0)
        except (TypeError, ValueError):
            artifact_count = 0
        status = _text(item.get("status"), 40)
        if status not in _ALLOWED_STATUSES:
            status = "precondition-unavailable"
        arms.append({
            "role": _text(item.get("role"), 16).lower(),
            "ref": _commit(item.get("ref")),
            "status": status,
            "reason": _safe_reason(item.get("reason")),
            "artifact_count": max(0, min(8, artifact_count)),
            "paths": _safe_relative_paths(item.get("paths")),
            "artifact_digests": _safe_digests(item.get("artifact_digests")),
            "claim_status": CLAIM_STATUS,
        })
        if len(arms) >= MAX_ARMS:
            break
    return {
        "schema_version": SOURCE_REVISION_SCHEMA_VERSION,
        "enabled": bool(resolved.get("enabled")),
        "arms": arms,
        "claim_status": CLAIM_STATUS,
    }


def source_revision_paths(item: Any) -> List[Path]:
    """Return private validated paths for the in-process Java adapter only."""
    if not isinstance(item, Mapping):
        return []
    paths = item.get("_paths")
    return [path for path in paths if isinstance(path, Path)] \
        if isinstance(paths, list) else []
