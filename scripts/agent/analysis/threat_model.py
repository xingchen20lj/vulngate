"""Bounded, evidence-linked threat model derived from the coverage ledger.

The inventory already tells VulnGate *what* enters the target and *where* a
dangerous operation may be reached.  This module adds the analyst's missing
middle layer: who is on the other side of each trust boundary, which
assumptions must hold for an attack path to matter, and what experiment should
resolve the uncertainty.

This is deliberately not a finding engine.  Every row is a static research
hypothesis with ``claim_status=not-a-finding``.  In particular:

* an entry is not proof that a route is exposed in the default configuration;
* a control on a call-graph path is not proof of ordering or semantic scope;
* a missing control is not proof that an interceptor or gateway is absent; and
* a capability chain is not proof of data flow or attacker impact.

The artifact is target-scoped and bounded so it can be fed to a model without
turning source text, payloads, credentials, or LLM prose into durable memory.
"""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from datetime import datetime
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence


THREAT_MODEL_INDEX = "threat-model"
THREAT_MODEL_SCHEMA_VERSION = "threat-model-v1"
THREAT_MODEL_CLAIM_STATUS = "not-a-finding"

MAX_BOUNDARIES = 64
MAX_ATTACK_PATHS = 512
MAX_UNRESOLVED = 128
MAX_IDS = 32
MAX_SYMBOLS = 24
MAX_QUESTIONS = 8
MAX_ASSUMPTIONS = 8


_POSTURES = frozenset({
    "guarded", "partial", "uncontrolled", "not-applicable", "unmapped",
})

# These are threat-model labels, not assertions about deployment.  Keeping the
# labels in one table makes it obvious which assumptions are generated for a
# new entry kind and prevents an ad-hoc prompt from silently inventing an
# attacker model.
_BOUNDARY_PROFILES: Dict[str, Dict[str, Any]] = {
    "http": {
        "boundary_type": "network-http",
        "attacker_roles": ["remote-unauthenticated-or-low-privilege"],
        "exposure_assumption": "route exposure and default listener must be confirmed",
    },
    "rpc": {
        "boundary_type": "network-rpc",
        "attacker_roles": ["remote-rpc-caller-or-low-privilege-principal"],
        "exposure_assumption": "RPC registration, transport exposure, and authentication must be confirmed",
    },
    "message": {
        "boundary_type": "message-broker",
        "attacker_roles": ["message-producer-or-compromised-consumer-context"],
        "exposure_assumption": "broker reachability, producer authority, and deserialization boundary must be confirmed",
    },
    "network": {
        "boundary_type": "network-generic",
        "attacker_roles": ["remote-network-caller"],
        "exposure_assumption": "network exposure and default routing must be confirmed",
    },
    "webview": {
        "boundary_type": "webview-content",
        "attacker_roles": ["untrusted-web-content-or-embedded-document"],
        "exposure_assumption": "content origin, navigation policy, and bridge exposure must be confirmed",
    },
    "ipc": {
        "boundary_type": "local-ipc",
        "attacker_roles": ["local-process-or-cross-user-ipc-caller"],
        "exposure_assumption": "endpoint publication, entitlement, and peer identity must be confirmed",
    },
    "url-scheme": {
        "boundary_type": "url-scheme",
        "attacker_roles": ["local-or-remote-url-scheme-caller"],
        "exposure_assumption": "scheme registration, caller context, and OS routing must be confirmed",
    },
    "library-api": {
        "boundary_type": "library-parser-api",
        "attacker_roles": ["application-supplied-parser-input"],
        "exposure_assumption": "calling application, parser configuration, and input provenance must be confirmed",
    },
    "file-input": {
        "boundary_type": "file-or-upload",
        "attacker_roles": ["file-or-upload-supplier"],
        "exposure_assumption": "file acquisition, storage location, and upload policy must be confirmed",
    },
    "config": {
        "boundary_type": "configuration",
        "attacker_roles": ["local-operator-or-deployment-input"],
        "exposure_assumption": "configuration authority and deployment path must be confirmed",
    },
    "cli": {
        "boundary_type": "local-cli",
        "attacker_roles": ["local-command-line-caller"],
        "exposure_assumption": "local execution authority and argument provenance must be confirmed",
    },
}

_DEFAULT_PROFILE: Dict[str, Any] = {
    "boundary_type": "unknown-input",
    "attacker_roles": ["input-source-unknown"],
    "exposure_assumption": "input provenance and exposure must be confirmed",
}

_BASE_ASSUMPTIONS = (
    "static entry detection does not prove default-configuration exposure",
    "heuristic call-graph reachability does not prove runtime data flow",
    "control presence does not prove temporal ordering or subject/object binding",
    "upstream filters, interceptors, gateways, and deployment policy may be outside scope",
    "runtime observation is required before any vulnerability or impact conclusion",
)


def _field(record: Any, name: str, default: Any = None) -> Any:
    if isinstance(record, Mapping):
        return record.get(name, default)
    return getattr(record, name, default)


def _text(value: Any, limit: int = 240) -> str:
    if value is None:
        return ""
    return " ".join(str(value).replace("\x00", "").split())[:limit]


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return default


def _unique(values: Iterable[Any], limit: int = MAX_IDS,
            item_limit: int = 180) -> List[str]:
    out: List[str] = []
    for value in values:
        item = _text(value, item_limit)
        if not item or item in out:
            continue
        out.append(item)
        if len(out) >= max(0, limit):
            break
    return out


def _location(record: Any, file_name: str = "file", line_name: str = "line") -> str:
    file_value = _text(_field(record, file_name, ""), 180)
    line = _int(_field(record, line_name, 0))
    return "%s:%d" % (file_value, line) if file_value and line > 0 else file_value


def _stable_id(prefix: str, *parts: Any) -> str:
    material = "\x1f".join(_text(part, 300) for part in parts)
    digest = hashlib.sha1(material.encode("utf-8", errors="replace")).hexdigest()[:12]
    return "%s-%s" % (prefix, digest)


def _profile(entry: Any) -> Dict[str, Any]:
    kind = _text(_field(entry, "kind", ""), 48).lower()
    profile = _BOUNDARY_PROFILES.get(kind, _DEFAULT_PROFILE)
    return {
        "boundary_type": _text(profile.get("boundary_type"), 80),
        "attacker_roles": _unique(profile.get("attacker_roles") or [], 8, 100),
        "exposure_assumption": _text(profile.get("exposure_assumption"), 240),
    }


def _boundary_key(entry: Any) -> str:
    return "|".join((
        _text(_field(entry, "kind", ""), 48).lower(),
        _text(_field(entry, "framework", ""), 80),
        _text(_field(entry, "target_type", ""), 80),
    ))


def _control_entries(control_map: Any) -> List[Dict[str, Any]]:
    if not isinstance(control_map, Mapping):
        return []
    rows = control_map.get("entries") or []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _capability_paths(capability_graph: Any) -> List[Dict[str, Any]]:
    if not isinstance(capability_graph, Mapping):
        return []
    rows = capability_graph.get("paths") or capability_graph.get("candidates") or []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _path_priority(flow: Any, control: Mapping[str, Any], capabilities: Sequence[Mapping[str, Any]]) -> int:
    priority = {"high": 3, "medium": 2, "low": 1}.get(
        _text(_field(flow, "priority", "medium"), 16).lower(), 1)
    posture = _text(control.get("verdict", "unmapped"), 32)
    if posture in {"partial", "uncontrolled", "unmapped"}:
        priority += 1
    if capabilities:
        priority += 1
    return min(5, max(1, priority))


def _questions(control: Mapping[str, Any], capabilities: Sequence[Mapping[str, Any]],
               coverage_gap: str = "") -> List[str]:
    questions: List[str] = []
    if coverage_gap:
        questions.append("resolve forward/backward reachability gap or dynamic dispatch")
    if control.get("missing_groups"):
        questions.append("test whether an out-of-scope interceptor or gateway supplies the missing control")
        questions.append("verify control ordering and subject/object binding at the sink")
    else:
        questions.append("verify control ordering, branch coverage, and subject/object binding")
    questions.append("confirm entry exposure and input provenance in the target default-configuration state")
    questions.append("trace attacker-controlled data to the sink with typed runtime observations")
    if capabilities:
        questions.append("verify each capability transition independently and observe the typed effect")
    return _unique(questions, MAX_QUESTIONS, 240)


def _capability_summaries(flow_id: str, paths: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    matched: List[Dict[str, Any]] = []
    for path in paths:
        flow_ids = {_text(item, 160) for item in (path.get("flow_ids") or [])}
        if flow_id and flow_id not in flow_ids:
            continue
        candidate_id = _text(path.get("candidate_id"), 160)
        if not candidate_id:
            continue
        matched.append({
            "candidate_id": candidate_id,
            "goal": _text(path.get("goal"), 100),
            "chain_status": _text(path.get("chain_status"), 48),
            "required_capabilities": _unique(path.get("required_capabilities") or [], 16, 64),
            "observed_capabilities": _unique(path.get("observed_capabilities") or [], 16, 64),
            "missing_capabilities": _unique(path.get("missing_capabilities") or [], 16, 64),
            "claim_status": THREAT_MODEL_CLAIM_STATUS,
        })
    matched.sort(key=lambda item: str(item.get("candidate_id")))
    return matched[:8]


def _boundary_rows(entries: Sequence[Any]) -> tuple:
    grouped: Dict[str, Dict[str, Any]] = {}
    for entry in entries:
        entry_id = _text(_field(entry, "entry_id", ""), 160)
        if not entry_id:
            continue
        key = _boundary_key(entry)
        profile = _profile(entry)
        row = grouped.setdefault(key, {
            "boundary_id": _stable_id("boundary", key),
            "boundary_type": profile["boundary_type"],
            "entry_kinds": [],
            "entry_ids": [],
            "attacker_roles": [],
            "trust_assumptions": [],
            "claim_status": THREAT_MODEL_CLAIM_STATUS,
        })
        row["entry_kinds"] = _unique(
            list(row["entry_kinds"]) + [_text(_field(entry, "kind", ""), 48).lower()],
            8, 48)
        row["entry_ids"] = _unique(list(row["entry_ids"]) + [entry_id], MAX_IDS, 160)
        row["attacker_roles"] = _unique(
            list(row["attacker_roles"]) + profile["attacker_roles"], 8, 100)
        row["trust_assumptions"] = _unique(
            list(row["trust_assumptions"]) + [profile["exposure_assumption"]],
            MAX_ASSUMPTIONS, 240)
    rows = sorted(grouped.values(), key=lambda item: str(item.get("boundary_id")))
    return rows[:MAX_BOUNDARIES], grouped


def _safe_control(control: Mapping[str, Any]) -> Dict[str, Any]:
    posture = _text(control.get("verdict", "unmapped"), 32)
    if posture not in _POSTURES:
        posture = "unmapped"
    return {
        "posture": posture,
        "required_groups": [
            _unique(group, 8, 48) for group in (control.get("required_groups") or [])
            if isinstance(group, (list, tuple))
        ][:8],
        "missing_groups": [
            _unique(group, 8, 48) for group in (control.get("missing_groups") or [])
            if isinstance(group, (list, tuple))
        ][:8],
        "present_controls": _unique(control.get("present") or [], 16, 64),
        "control_ids": _unique(control.get("control_ids") or [], MAX_IDS, 160),
    }


def _attack_path(flow: Any, entry: Any, sink: Any, boundary: Mapping[str, Any],
                 control: Mapping[str, Any], capabilities: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    flow_id = _text(_field(flow, "flow_id", ""), 160)
    entry_id = _text(_field(flow, "entry_id", ""), 160)
    sink_id = _text(_field(flow, "sink_id", ""), 160)
    safe_control = _safe_control(control)
    coverage_gap = _text(_field(flow, "coverage_gap", ""), 80)
    profile = _profile(entry)
    questions = _questions(safe_control, capabilities, coverage_gap)
    if coverage_gap:
        state = "reachability-gap"
    elif safe_control["posture"] in {"partial", "uncontrolled", "unmapped"}:
        state = "control-gap-hypothesis"
    else:
        state = "dangerous-operation-path"
    path_id = _stable_id("threat-path", flow_id, entry_id, sink_id)
    return {
        "path_id": path_id,
        "flow_id": flow_id,
        "entry_id": entry_id,
        "sink_id": sink_id,
        "boundary_id": _text(boundary.get("boundary_id"), 160),
        "entry_location": _location(entry),
        "sink_location": _location(sink),
        "sink_category": _text(_field(sink, "category", ""), 64),
        "sink_severity_hint": _text(_field(sink, "severity_hint", "medium"), 16),
        "entry_kind": _text(_field(entry, "kind", ""), 48).lower(),
        "attacker_roles": _unique(profile["attacker_roles"], 8, 100),
        "path_symbols": _unique(_field(flow, "path", []) or [], MAX_SYMBOLS, 180),
        "transforms": _unique(_field(flow, "transforms", []) or [], 16, 100),
        "validations": _unique(_field(flow, "validations", []) or [], 16, 100),
        "authorizations": _unique(_field(flow, "authorizations", []) or [], 16, 100),
        "control_posture": safe_control["posture"],
        "required_control_groups": safe_control["required_groups"],
        "missing_control_groups": safe_control["missing_groups"],
        "present_controls": safe_control["present_controls"],
        "control_ids": safe_control["control_ids"],
        "coverage_gap": coverage_gap,
        "research_state": state,
        "research_priority": _path_priority(flow, control, capabilities),
        "preconditions": _unique([
            profile["exposure_assumption"],
            "call-graph path must be confirmed as runtime data flow",
            "control semantics and ordering must be confirmed at the sink",
        ], MAX_ASSUMPTIONS, 240),
        "research_questions": questions,
        "capability_hypotheses": [dict(item) for item in capabilities][:8],
        "evidence_refs": {
            "entry_id": entry_id,
            "flow_id": flow_id,
            "sink_id": sink_id,
            "locations": _unique([_location(entry), _location(sink)], 4, 180),
        },
        "claim_status": THREAT_MODEL_CLAIM_STATUS,
    }


def _unresolved_rows(entries: Sequence[Any], sinks: Sequence[Any],
                     reachability: Sequence[Any], flows: Sequence[Any]) -> Dict[str, List[Dict[str, Any]]]:
    flow_entry_ids = {_text(_field(flow, "entry_id", ""), 160) for flow in flows}
    flow_sink_ids = {_text(_field(flow, "sink_id", ""), 160) for flow in flows}
    entry_rows = [{
        "entry_id": _text(_field(entry, "entry_id", ""), 160),
        "kind": _text(_field(entry, "kind", ""), 48).lower(),
        "location": _location(entry),
        "reason": "no emitted flow; verify dynamic dispatch, registration, or isolated input",
        "claim_status": THREAT_MODEL_CLAIM_STATUS,
    } for entry in entries if _text(_field(entry, "entry_id", ""), 160)
        not in flow_entry_ids]
    sink_index = {
        _text(_field(sink, "sink_id", ""), 160): sink for sink in sinks
        if _text(_field(sink, "sink_id", ""), 160)
    }
    sink_rows: List[Dict[str, Any]] = []
    for item in reachability:
        gap = _text(_field(item, "coverage_gap", ""), 80)
        sink_id = _text(_field(item, "sink_id", ""), 160)
        if not gap or not sink_id or sink_id in flow_sink_ids:
            continue
        sink = sink_index.get(sink_id)
        sink_rows.append({
            "sink_id": sink_id,
            "category": _text(_field(sink, "category", ""), 64) if sink else "",
            "location": _location(sink) if sink else _text(_field(item, "file", ""), 180),
            "coverage_gap": gap,
            "reason": "sink reachability is unresolved; absence of a flow is not absence of risk",
            "claim_status": THREAT_MODEL_CLAIM_STATUS,
        })
    entry_rows.sort(key=lambda item: str(item.get("entry_id")))
    sink_rows.sort(key=lambda item: str(item.get("sink_id")))
    return {
        "unmapped_entries": entry_rows[:MAX_UNRESOLVED],
        "unmapped_sinks": sink_rows[:MAX_UNRESOLVED],
    }


def build_threat_model(entries: Sequence[Any] = (), sinks: Sequence[Any] = (),
                       flows: Sequence[Any] = (), control_map: Any = None,
                       capability_graph: Any = None,
                       reachability: Sequence[Any] = (), target: str = "",
                       target_type: str = "") -> Dict[str, Any]:
    """Build a bounded threat model from deterministic coverage artifacts."""
    boundaries, boundary_by_key = _boundary_rows(entries)
    control_by_flow = {
        _text(row.get("flow_id"), 160): row
        for row in _control_entries(control_map)
        if _text(row.get("flow_id"), 160)
    }
    capability_paths = _capability_paths(capability_graph)
    entry_by_id = {
        _text(_field(entry, "entry_id", ""), 160): entry
        for entry in entries if _text(_field(entry, "entry_id", ""), 160)
    }
    sink_by_id = {
        _text(_field(sink, "sink_id", ""), 160): sink
        for sink in sinks if _text(_field(sink, "sink_id", ""), 160)
    }
    ordered_flows = sorted(
        [flow for flow in flows if _text(_field(flow, "flow_id", ""), 160)],
        key=lambda flow: (
            {"high": 0, "medium": 1, "low": 2}.get(
                _text(_field(flow, "priority", "medium"), 16).lower(), 3),
            _text(_field(flow, "flow_id", ""), 160),
        ))
    attack_paths: List[Dict[str, Any]] = []
    for flow in ordered_flows[:MAX_ATTACK_PATHS]:
        entry = entry_by_id.get(_text(_field(flow, "entry_id", ""), 160))
        sink = sink_by_id.get(_text(_field(flow, "sink_id", ""), 160))
        if entry is None or sink is None:
            continue
        key = _boundary_key(entry)
        boundary = boundary_by_key.get(key) or {
            "boundary_id": _stable_id("boundary", key),
        }
        control = control_by_flow.get(_text(_field(flow, "flow_id", ""), 160), {})
        capabilities = _capability_summaries(
            _text(_field(flow, "flow_id", ""), 160), capability_paths)
        attack_paths.append(_attack_path(
            flow, entry, sink, boundary, control, capabilities))

    unresolved = _unresolved_rows(entries, sinks, reachability, flows)
    posture_counts = Counter(str(item.get("control_posture")) for item in attack_paths)
    state_counts = Counter(str(item.get("research_state")) for item in attack_paths)
    capability_count = sum(bool(item.get("capability_hypotheses")) for item in attack_paths)
    flow_truncated = len(ordered_flows) > MAX_ATTACK_PATHS
    summary = {
        "boundaries": len(boundaries),
        "attack_paths": len(attack_paths),
        "attack_paths_by_control_posture": dict(sorted(posture_counts.items())),
        "research_states": dict(sorted(state_counts.items())),
        "high_priority_paths": sum(
            1 for item in attack_paths if _int(item.get("research_priority")) >= 4),
        "capability_linked_paths": capability_count,
        "unmapped_entries": len(unresolved["unmapped_entries"]),
        "unmapped_sinks": len(unresolved["unmapped_sinks"]),
        "truncated": flow_truncated,
        "limits": {
            "max_boundaries": MAX_BOUNDARIES,
            "max_attack_paths": MAX_ATTACK_PATHS,
            "max_unresolved": MAX_UNRESOLVED,
        },
        "claim_status": THREAT_MODEL_CLAIM_STATUS,
        "producer": "threat-model",
        "confidence": "heuristic-callgraph",
        "evidence_type": "static-inferred",
    }
    return {
        "schema_version": THREAT_MODEL_SCHEMA_VERSION,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "target": _text(target, 120),
        "target_type": _text(target_type, 80),
        "boundaries": boundaries,
        "attack_paths": attack_paths,
        "unresolved": unresolved,
        "summary": summary,
        "assumptions": list(_BASE_ASSUMPTIONS),
        "provenance": {
            "producer": "threat-model",
            "confidence": "heuristic-callgraph",
            "evidence_type": "static-inferred",
            "claim_status": THREAT_MODEL_CLAIM_STATUS,
        },
        "claim_status": THREAT_MODEL_CLAIM_STATUS,
    }


def _normalize_path(row: Any) -> Dict[str, Any]:
    if not isinstance(row, Mapping):
        return {}
    allowed_scalars = (
        "path_id", "flow_id", "entry_id", "sink_id", "boundary_id",
        "entry_location", "sink_location", "sink_category",
        "sink_severity_hint", "entry_kind", "coverage_gap", "research_state",
    )
    out = {key: _text(row.get(key), 240) for key in allowed_scalars
           if row.get(key) not in (None, "") or key == "coverage_gap"}
    out["attacker_roles"] = _unique(row.get("attacker_roles") or [], 8, 100)
    for key in ("path_symbols", "transforms", "validations", "authorizations",
                "present_controls", "control_ids", "preconditions",
                "research_questions"):
        out[key] = _unique(row.get(key) or [], MAX_QUESTIONS if key == "research_questions"
                           else (MAX_SYMBOLS if key == "path_symbols" else 16), 240)
    out["required_control_groups"] = [
        _unique(group, 8, 48) for group in (row.get("required_control_groups") or [])
        if isinstance(group, (list, tuple))
    ][:8]
    out["missing_control_groups"] = [
        _unique(group, 8, 48) for group in (row.get("missing_control_groups") or [])
        if isinstance(group, (list, tuple))
    ][:8]
    posture = _text(row.get("control_posture", "unmapped"), 32)
    out["control_posture"] = posture if posture in _POSTURES else "unmapped"
    out["research_priority"] = min(5, max(1, _int(row.get("research_priority"), 1)))
    refs = row.get("evidence_refs") if isinstance(row.get("evidence_refs"), Mapping) else {}
    out["evidence_refs"] = {
        "entry_id": _text(refs.get("entry_id"), 160),
        "flow_id": _text(refs.get("flow_id"), 160),
        "sink_id": _text(refs.get("sink_id"), 160),
        "locations": _unique(refs.get("locations") or [], 4, 180),
    }
    hypotheses: List[Dict[str, Any]] = []
    for item in row.get("capability_hypotheses") or []:
        if not isinstance(item, Mapping):
            continue
        hypotheses.append({
            "candidate_id": _text(item.get("candidate_id"), 160),
            "goal": _text(item.get("goal"), 100),
            "chain_status": _text(item.get("chain_status"), 48),
            "required_capabilities": _unique(item.get("required_capabilities") or [], 16, 64),
            "observed_capabilities": _unique(item.get("observed_capabilities") or [], 16, 64),
            "missing_capabilities": _unique(item.get("missing_capabilities") or [], 16, 64),
            "claim_status": THREAT_MODEL_CLAIM_STATUS,
        })
    out["capability_hypotheses"] = hypotheses[:8]
    out["claim_status"] = THREAT_MODEL_CLAIM_STATUS
    return out


def normalize_threat_model(data: Any) -> Dict[str, Any]:
    """Strip untrusted/unknown fields and force research-only claim status."""
    if not isinstance(data, Mapping):
        return {}
    summary = data.get("summary") if isinstance(data.get("summary"), Mapping) else {}
    boundaries: List[Dict[str, Any]] = []
    for row in data.get("boundaries") or []:
        if not isinstance(row, Mapping):
            continue
        boundaries.append({
            "boundary_id": _text(row.get("boundary_id"), 160),
            "boundary_type": _text(row.get("boundary_type"), 80),
            "entry_kinds": _unique(row.get("entry_kinds") or [], 8, 48),
            "entry_ids": _unique(row.get("entry_ids") or [], MAX_IDS, 160),
            "attacker_roles": _unique(row.get("attacker_roles") or [], 8, 100),
            "trust_assumptions": _unique(row.get("trust_assumptions") or [], MAX_ASSUMPTIONS, 240),
            "claim_status": THREAT_MODEL_CLAIM_STATUS,
        })
    normalized_summary = {
        key: (dict(value) if isinstance(value, Mapping) else value)
        for key, value in summary.items()
        if key in {
            "boundaries", "attack_paths", "attack_paths_by_control_posture",
            "research_states", "high_priority_paths", "capability_linked_paths",
            "unmapped_entries", "unmapped_sinks", "truncated", "limits",
        }
    }
    normalized_summary["claim_status"] = THREAT_MODEL_CLAIM_STATUS
    normalized_summary["producer"] = "threat-model"
    normalized_summary["confidence"] = "heuristic-callgraph"
    normalized_summary["evidence_type"] = "static-inferred"
    return {
        "schema_version": THREAT_MODEL_SCHEMA_VERSION,
        "generated_at": _text(data.get("generated_at"), 64),
        "target": _text(data.get("target"), 120),
        "target_type": _text(data.get("target_type"), 80),
        "boundaries": boundaries[:MAX_BOUNDARIES],
        "attack_paths": [_normalize_path(row) for row in (data.get("attack_paths") or [])
                          if isinstance(row, Mapping)][:MAX_ATTACK_PATHS],
        "unresolved": {
            "unmapped_entries": [
                {
                    "entry_id": _text(row.get("entry_id"), 160),
                    "kind": _text(row.get("kind"), 48),
                    "location": _text(row.get("location"), 180),
                    "reason": _text(row.get("reason"), 240),
                    "claim_status": THREAT_MODEL_CLAIM_STATUS,
                }
                for row in (data.get("unresolved", {}).get("unmapped_entries", [])
                            if isinstance(data.get("unresolved"), Mapping) else [])
                if isinstance(row, Mapping)
            ][:MAX_UNRESOLVED],
            "unmapped_sinks": [
                {
                    "sink_id": _text(row.get("sink_id"), 160),
                    "category": _text(row.get("category"), 64),
                    "location": _text(row.get("location"), 180),
                    "coverage_gap": _text(row.get("coverage_gap"), 80),
                    "reason": _text(row.get("reason"), 240),
                    "claim_status": THREAT_MODEL_CLAIM_STATUS,
                }
                for row in (data.get("unresolved", {}).get("unmapped_sinks", [])
                            if isinstance(data.get("unresolved"), Mapping) else [])
                if isinstance(row, Mapping)
            ][:MAX_UNRESOLVED],
        },
        "summary": normalized_summary,
        "assumptions": _unique(data.get("assumptions") or _BASE_ASSUMPTIONS,
                                MAX_ASSUMPTIONS, 240),
        "provenance": {
            "producer": "threat-model",
            "confidence": "heuristic-callgraph",
            "evidence_type": "static-inferred",
            "claim_status": THREAT_MODEL_CLAIM_STATUS,
        },
        "claim_status": THREAT_MODEL_CLAIM_STATUS,
    }


def threat_model_path(workspace: Path, target: str) -> Path:
    return Path(workspace).resolve() / "state" / str(target) / "coverage" / "threat-model.json"


def write_threat_model(workspace: Path, target: str, model: Mapping[str, Any]) -> Path:
    path = threat_model_path(workspace, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(".%s.tmp.%d" % (path.name, __import__("os").getpid()))
    tmp.write_text(json.dumps(normalize_threat_model(model), indent=2,
                              ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)
    return path


def load_threat_model(workspace: Path, target: str) -> Dict[str, Any]:
    path = threat_model_path(workspace, target)
    if not path.exists():
        return {}
    try:
        return normalize_threat_model(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError):
        return {}
