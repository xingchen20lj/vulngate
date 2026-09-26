"""Small central registry for security-sensitive VulnGate schemas.

Runtime deliberately stays stdlib-only.  The registry therefore implements
the structural checks that must be fail-closed without requiring jsonschema;
development tooling can additionally validate the JSON Schema documents in
``schemas/``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Set

from .security_types import ArtifactEnvelope


SCHEMA_REGISTRY_VERSION = "schema-registry-v1"
SCHEMA_DIR = Path(__file__).resolve().parents[3] / "schemas"


def _unknown_keys(data: Mapping[str, Any], allowed: Iterable[str]) -> Set[str]:
    return set(data) - set(allowed)


def validate_target_config_document(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("target config must be a JSON object")
    from .config import TargetConfig

    allowed = set(TargetConfig.__dataclass_fields__) | {"schema_version"}
    unknown = _unknown_keys(data, allowed)
    if unknown:
        raise ValueError("unknown target config field(s): %s" %
                         ", ".join(sorted(unknown)))
    version = data.get("schema_version", "target-config-v1")
    if version != "target-config-v1":
        raise ValueError("unsupported target config schema_version: %s" % version)
    runtime = data.get("runtime_lab", {})
    if runtime is not None and not isinstance(runtime, dict):
        raise ValueError("runtime_lab must be an object")
    service = runtime.get("service") if isinstance(runtime, dict) else None
    if service is not None:
        if not isinstance(service, dict):
            raise ValueError("runtime_lab.service must be an object")
        allowed_service = {
            "enabled", "run_id", "start_command", "stop_command",
            "healthcheck", "healthcheck_url", "healthcheck_command",
            "expected_status", "healthcheck_status", "working_dir", "env",
            "startup_timeout", "shutdown_timeout", "health_timeout",
            "poll_interval", "stop_external", "allow_unconfined_start",
            "isolation_backend", "isolation_image",
        }
        unknown_service = _unknown_keys(service, allowed_service)
        if unknown_service:
            raise ValueError("unknown runtime_lab.service field(s): %s" %
                             ", ".join(sorted(unknown_service)))
        # A common typo must be visible rather than silently becoming the
        # default false/absent value.
        for key in unknown_service:
            if "allow_unconfined" in key or "isolation" in key:
                raise ValueError("unknown security-critical service field: %s" % key)
    return dict(data)


def validate_artifact_envelope(value: Any, *, schema_version: str,
                               required: Iterable[str] = ()) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("artifact must be an object")
    if value.get("schema_version") != schema_version:
        raise ValueError("artifact schema mismatch: expected %s" % schema_version)
    missing = [key for key in required if key not in value]
    if missing:
        raise ValueError("artifact missing required fields: %s" % ", ".join(missing))
    return ArtifactEnvelope.from_mapping(
        value, schema_version=schema_version).as_dict()


def list_registered_schemas() -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not SCHEMA_DIR.is_dir():
        return out
    for path in sorted(SCHEMA_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and isinstance(data.get("$id"), str):
            out[path.name] = data["$id"]
    return out
