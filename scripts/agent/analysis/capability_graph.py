"""Deterministic capability-primitive and attack-path search.

This module turns the existing entry/sink/flow inventory into a bounded
research graph.  It deliberately models *capabilities*, not vulnerabilities:
``read``/``write``/``ssrf``/``exec`` are observations or hypotheses that still
need source review and runtime evidence.  A composed path is therefore a
candidate for S2, never a finding and never a severity decision.

The search is intentionally conservative in what it persists:

* only ids, categories, file:line locations and bounded metadata are retained;
* every path records observed and missing primitives separately;
* cross-domain composition is labelled heuristic and requires manual data-flow
  plus typed-effect validation;
* limits are explicit in the graph summary, so truncation cannot look like
  absence of a chain.
"""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from itertools import product
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


CAPABILITY_GRAPH_INDEX = "capability-graph"
CAPABILITY_CANDIDATE_INDEX = "capability-candidates"
CAPABILITY_GRAPH_VERSION = "capability-graph-v1"

MAX_NODES = 512
MAX_PATHS = 160
MAX_CHOICES_PER_KIND = 3
MAX_EDGES = 640
MAX_LOCATIONS = 16

# The names are intentionally stable: experiment-planner and downstream
# reports use them as machine-readable chain components.
SINK_CAPABILITIES: Dict[str, Tuple[str, ...]] = {
    "file-read": ("read",),
    "file-mutation": ("write",),
    "command-exec": ("exec",),
    "code-eval": ("eval",),
    "expression-eval": ("eval",),
    "template-render": ("template-eval",),
    "sql-exec": ("sql",),
    "network-egress": ("ssrf",),
    "credential-access": ("credential-read",),
    "privilege": ("privilege",),
    "webview-bridge": ("bridge",),
    "jndi": ("lookup",),
    "dynamic-class-load": ("class-load",),
    "deserialization": ("parse",),
}

# A transition is a research relationship, not a semantic guarantee.  The
# target may be absent; that is exactly what makes a useful next-probe record.
TRANSITIONS: Dict[str, Tuple[str, ...]] = {
    "input": ("eval",),
    "write": ("config-control", "exec"),
    "config-control": ("exec",),
    "read": ("credential-read",),
    "credential-read": ("exec",),
    "ssrf": ("credential-read", "internal-effect"),
    "sql": ("credential-read", "write"),
    "eval": ("exec",),
    "template-eval": ("exec",),
    "bridge": ("exec",),
    "management-access": ("exec",),
}

# Equations from the capability-primitive research method.  The first four
# are common local chains; the rest preserve cross-protocol and data-flow
# hypotheses without asserting that the intermediate service is present.
CHAIN_TEMPLATES: Tuple[Dict[str, Any], ...] = (
    {"kind": "write-to-exec", "equation": "write -> exec",
     "required": ("write", "exec"), "goal": "command-execution"},
    {"kind": "config-to-exec", "equation": "write -> config-control -> exec",
     "required": ("write", "config-control", "exec"), "goal": "command-execution"},
    {"kind": "management-to-exec", "equation": "management-access -> exec",
     "required": ("management-access", "exec"), "goal": "command-execution"},
    {"kind": "credential-to-exec", "equation": "credential-read -> exec",
     "required": ("credential-read", "exec"), "goal": "command-execution"},
    {"kind": "read-to-credential-to-exec",
     "equation": "read -> credential-read -> exec",
     "required": ("read", "credential-read", "exec"),
     "goal": "credential-backed-execution"},
    {"kind": "input-to-eval", "equation": "input -> eval",
     "required": ("input", "eval"), "goal": "typed-evaluation-effect"},
    {"kind": "ssrf-to-credential",
     "equation": "ssrf -> credential-read",
     "required": ("ssrf", "credential-read"),
     "goal": "metadata-credential-access"},
    {"kind": "ssrf-to-internal-effect",
     "equation": "ssrf -> internal-effect",
     "required": ("ssrf", "internal-effect"),
     "goal": "internal-control-plane-effect"},
    {"kind": "sql-to-credential",
     "equation": "sql -> credential-read",
     "required": ("sql", "credential-read"),
     "goal": "credential-access"},
    {"kind": "sql-to-write", "equation": "sql -> write",
     "required": ("sql", "write"), "goal": "file-or-state-mutation"},
    {"kind": "bridge-to-exec", "equation": "bridge -> exec",
     "required": ("bridge", "exec"), "goal": "command-execution"},
    {"kind": "template-to-exec",
     "equation": "template-eval -> exec",
     "required": ("template-eval", "exec"), "goal": "command-execution"},
)

# A single observed high-leverage primitive can justify a *partial* chain
# hypothesis.  It is useful for research planning, but its output is clearly
# marked ``missing`` and remains pending until the next primitive is found.
PARTIAL_SEEDS = frozenset({
    "read", "write", "ssrf", "credential-read", "sql", "bridge",
    "management-access",
})

_ADMIN_MARKERS = ("admin", "manage", "console", "task", "plugin", "webhook",
                  "template", "sql", "shell", "exec", "job")


def _field(record: Any, name: str, default: Any = None) -> Any:
    if isinstance(record, dict):
        return record.get(name, default)
    return getattr(record, name, default)


def _text(value: Any, limit: int = 240) -> str:
    if value is None:
        return ""
    return " ".join(str(value).replace("\x00", "").split())[:limit]


def _location(record: Any) -> str:
    file = _text(_field(record, "file", ""), 180)
    try:
        line = int(_field(record, "line", 0) or 0)
    except (TypeError, ValueError):
        line = 0
    return "%s:%d" % (file, line) if file and line > 0 else file


def _unique(values: Iterable[str], limit: int = MAX_LOCATIONS) -> List[str]:
    out: List[str] = []
    for value in values:
        item = _text(value, 200)
        if item and item not in out:
            out.append(item)
        if len(out) >= limit:
            break
    return out


def _stable_id(prefix: str, *parts: Any) -> str:
    material = "\x1f".join(_text(part, 300) for part in parts)
    return "%s-%s" % (prefix, hashlib.sha1(material.encode("utf-8",
                                                            errors="replace"))
                                  .hexdigest()[:12])


def _entry_kind(entry: Any) -> str:
    return _text(_field(entry, "kind", ""), 40).lower()


def _entry_node(entry: Any) -> Dict[str, Any]:
    entry_id = _text(_field(entry, "entry_id", ""), 160)
    location = _location(entry)
    kind = _entry_kind(entry)
    api = _text(_field(entry, "api", ""), 120)
    nodes = [{
        "node_id": "entry:%s" % entry_id,
        "capability": "input",
        "status": "observed",
        "source_kind": "entry",
        "entry_id": entry_id,
        "locations": [location] if location else [],
        "constraints": {
            "entry_kind": kind,
            "input_shape": _text(_field(entry, "input_shape", ""), 80),
            "untrusted": bool(_field(entry, "untrusted", True)),
        },
        "api": api,
        "confidence": _text(_field(entry, "confidence", "heuristic"), 40)
        or "heuristic",
        "producer": "inventory-entry",
        "evidence_type": "static-observed",
    }]
    # A config/admin-shaped entry is still only a surface clue.  It is kept as
    # a separate primitive so the graph can ask the right next question.
    hay = (api + " " + _text(_field(entry, "input_shape", ""), 80)).lower()
    if kind in {"http", "rpc", "webview", "ipc", "url-scheme"} and \
            any(marker in hay for marker in _ADMIN_MARKERS):
        nodes.append({
            "node_id": _stable_id("entry-cap", entry_id, "management-access"),
            "capability": "management-access",
            "status": "observed",
            "source_kind": "entry",
            "entry_id": entry_id,
            "locations": [location] if location else [],
            "constraints": {"surface_signal": "admin-or-execution-shaped-entry",
                             "untrusted": bool(_field(entry, "untrusted", True))},
            "api": api,
            "confidence": "heuristic-callgraph",
            "producer": "capability-search",
            "evidence_type": "static-inferred",
        })
    if kind == "config":
        nodes.append({
            "node_id": _stable_id("entry-cap", entry_id, "config-control"),
            "capability": "config-control",
            "status": "observed",
            "source_kind": "entry",
            "entry_id": entry_id,
            "locations": [location] if location else [],
            "constraints": {"untrusted": bool(_field(entry, "untrusted", False)),
                             "requires_write_or_deploy_evidence": True},
            "api": api,
            "confidence": "heuristic-callgraph",
            "producer": "capability-search",
            "evidence_type": "static-inferred",
        })
    return nodes


def _sink_capabilities(sink: Any, entry: Any) -> Tuple[str, ...]:
    category = _text(_field(sink, "category", ""), 80).lower()
    mapped = SINK_CAPABILITIES.get(category)
    if mapped:
        return mapped
    # Preserve unknown sinks in the graph without inventing an impact class.
    return ("sink:%s" % category,) if category else ("sink:unknown",)


def _flow_node(flow: Any, entry: Any, sink: Any, capability: str) -> Dict[str, Any]:
    flow_id = _text(_field(flow, "flow_id", ""), 160)
    entry_id = _text(_field(flow, "entry_id", ""), 160)
    sink_id = _text(_field(flow, "sink_id", ""), 160)
    sink_location = _location(sink)
    entry_location = _location(entry)
    locations = _unique([entry_location, sink_location])
    path = [_text(item, 180) for item in (_field(flow, "path", []) or [])]
    constraints = {
        "entry_kind": _entry_kind(entry),
        "input_shape": _text(_field(entry, "input_shape", ""), 80),
        "untrusted": bool(_field(entry, "untrusted", True)),
        "flow_direction": _text(_field(flow, "direction", ""), 40),
        "flow_priority": _text(_field(flow, "priority", ""), 20),
        "path_hops": max(0, len(path) - 1),
        "authorization_present": bool(_field(flow, "authorizations", [])),
        "validation_present": bool(_field(flow, "validations", [])),
    }
    if capability == "ssrf":
        constraints["destination_control_proven"] = False
    if capability in {"exec", "eval", "template-eval"}:
        constraints["typed_effect_required"] = True
    return {
        "node_id": _stable_id("cap", capability, flow_id, sink_id),
        "capability": capability,
        "status": "observed",
        "source_kind": "flow-sink",
        "flow_id": flow_id,
        "entry_id": entry_id,
        "sink_id": sink_id,
        "sink_category": _text(_field(sink, "category", ""), 80),
        "locations": locations,
        "path": path[:MAX_LOCATIONS],
        "constraints": constraints,
        "confidence": "heuristic-callgraph",
        "producer": "capability-search",
        "evidence_type": "static-inferred",
    }


def _node_rank(node: Dict[str, Any]) -> Tuple[int, int, str]:
    priority = {"high": 0, "medium": 1, "low": 2}.get(
        str((node.get("constraints") or {}).get("flow_priority")), 3)
    confidence = {"exact": 0, "ast": 1, "heuristic-callgraph": 2,
                  "heuristic-nearby": 3}.get(str(node.get("confidence")), 9)
    return priority, confidence, str(node.get("node_id"))


def _requirements_reachable(required: Sequence[str], observed: set) -> bool:
    present = [kind for kind in required if kind in observed]
    if len(present) >= 2:
        return True
    return bool(present and present[0] in PARTIAL_SEEDS)


def _path_candidate(template: Mapping[str, Any],
                    choices: Sequence[Optional[Dict[str, Any]]]
                    ) -> Dict[str, Any]:
    required = [str(item) for item in template["required"]]
    observed_nodes = [node for node in choices if node is not None]
    observed_kinds = [str(node.get("capability")) for node in observed_nodes]
    missing = [kind for kind in required if kind not in observed_kinds]
    observed_ids = [str(node.get("node_id")) for node in observed_nodes]
    all_locations = _unique(
        location for node in observed_nodes
        for location in (node.get("locations") or []))
    flow_ids = _unique(str(node.get("flow_id")) for node in observed_nodes
                       if node.get("flow_id"))
    entry_ids = _unique(str(node.get("entry_id")) for node in observed_nodes
                        if node.get("entry_id"))
    sink_ids = _unique(str(node.get("sink_id")) for node in observed_nodes
                       if node.get("sink_id"))
    # Do not include enumeration order in the identity.  The same source
    # inventory must produce the same candidate id when files or flows are
    # discovered in a different order.
    candidate_id = _stable_id("cap", template["kind"], *observed_ids, *missing)
    chain = list(required)
    transition_rules = []
    for left, right in zip(chain, chain[1:]):
        transition_rules.append({
            "from": left,
            "to": right,
            "declared": right in TRANSITIONS.get(left, ()),
        })
    status = "partial-hypothesis" if missing else "composed-hypothesis"
    missing_text = ", ".join(missing) if missing else "none"
    observed_text = ", ".join(_unique(observed_kinds)) or "none"
    goal = str(template["goal"])
    surface = "capability-chain: %s" % template["equation"]
    logic = (
        "Static capability graph observed [%s]; required chain [%s]; missing [%s]. "
        "This is a cross-domain research hypothesis, not proof of data flow or impact."
        % (observed_text, " -> ".join(chain), missing_text)
    )
    hypothesis = (
        "The observed primitive(s) may combine with the missing primitive(s) to reach "
        "%s; verify each transition independently and require typed runtime evidence."
        % goal
    )
    sequence = ["observe-%s" % kind.replace("-", "-") for kind in chain]
    sequence.extend(["verify-transition", "observe-typed-effect"])
    # Keep step identifiers bounded and stable for the existing S4 contract.
    sequence = _unique(sequence, 16)
    preconditions = [
        "每个 observed 原语都必须由对应 file:line/flow 重新核对",
        "missing 原语 [%s] 尚未获得证据，不能按完整攻击链处理" % missing_text,
        "必须在受控矩阵中验证 transition，并记录真实 typed effect",
    ]
    if any((node.get("constraints") or {}).get("authorization_present")
           for node in observed_nodes):
        preconditions.append("授权边界存在静态线索，仍需验证 subject/object binding")
    return {
        "candidate_id": candidate_id,
        "surface": surface,
        "entry": entry_ids[0] if entry_ids else "",
        "input_shape": "capability-composition",
        "logic": logic,
        "hypothesis": hypothesis,
        "attack_class": "capability-chain",
        "precondition_tier_hint": "extra-primitive" if missing else "app-cooperation",
        "preconditions": preconditions,
        "poc_class": "Capability" + candidate_id.replace("-", "").title(),
        "jvm": {},
        "target_classes": [],
        "authz_cases": [],
        "sequence": sequence,
        "concurrency": 1,
        "availability_probe": False,
        "chain_components": chain + [goal, "typed-effect"],
        "transition_rules": transition_rules,
        "novelty_keywords": _unique(["capability-chain", template["kind"],
                                      *chain, goal]),
        "code_location": all_locations,
        "flow_ids": flow_ids,
        "entry_ids": entry_ids,
        "sink_ids": sink_ids,
        "capability_refs": observed_ids,
        "required_capabilities": required,
        "observed_capabilities": _unique(observed_kinds),
        "missing_capabilities": _unique(missing),
        "chain_equation": str(template["equation"]),
        "goal": goal,
        "chain_status": status,
        "source": "capability-graph",
        "producer": "capability-search",
        "confidence": "heuristic-callgraph",
        "evidence_type": "static-inferred",
        "requires_manual_dataflow": True,
        "runtime_required": True,
        "claim_status": "not-a-finding",
    }


def build_capability_graph(entries: Sequence[Any], sinks: Sequence[Any],
                          flows: Sequence[Any],
                          controls: Sequence[Any] = (),
                          max_nodes: int = MAX_NODES,
                          max_paths: int = MAX_PATHS
                          ) -> Dict[str, Any]:
    """Build the graph and deterministic S2 candidates from inventory records."""
    del controls  # flow records already carry the bounded control summary.
    node_limit = max(0, int(max_nodes))
    path_limit = max(0, int(max_paths))
    entry_by_id = {_text(_field(item, "entry_id", ""), 160): item
                   for item in entries if _field(item, "entry_id", "")}
    sink_by_id = {_text(_field(item, "sink_id", ""), 160): item
                  for item in sinks if _field(item, "sink_id", "")}
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []
    flow_count = 0
    for entry in entries:
        for node in _entry_node(entry):
            if len(nodes) >= node_limit:
                break
            nodes.setdefault(str(node["node_id"]), node)

    for flow in flows:
        flow_count += 1
        entry_id = _text(_field(flow, "entry_id", ""), 160)
        sink_id = _text(_field(flow, "sink_id", ""), 160)
        entry = entry_by_id.get(entry_id)
        sink = sink_by_id.get(sink_id)
        if entry is None or sink is None:
            continue
        input_id = "entry:%s" % entry_id
        for capability in _sink_capabilities(sink, entry):
            if len(nodes) >= node_limit:
                break
            node = _flow_node(flow, entry, sink, capability)
            node_id = str(node["node_id"])
            nodes.setdefault(node_id, node)
            if input_id in nodes:
                edges.append({"from": input_id, "to": node_id,
                              "relation": "observed-flow",
                              "flow_id": _text(_field(flow, "flow_id", ""), 160),
                              "confidence": "heuristic-callgraph",
                              "evidence_type": "static-inferred"})

    by_kind: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for node in nodes.values():
        if node.get("status") == "observed":
            by_kind[str(node.get("capability"))].append(node)
    for kind in by_kind:
        by_kind[kind].sort(key=_node_rank)
        del by_kind[kind][MAX_CHOICES_PER_KIND:]

    observed = set(by_kind)
    paths: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    goal_counts: Counter = Counter()
    transition_count = 0
    seen_candidates = set()
    for template in CHAIN_TEMPLATES if path_limit else ():
        required = tuple(str(item) for item in template["required"])
        if not _requirements_reachable(required, observed):
            continue
        choices: List[List[Optional[Dict[str, Any]]]] = [
            by_kind.get(kind, [None]) for kind in required]
        for combo in product(*choices):
            transition_count += max(0, len(required) - 1)
            observed_nodes = [node for node in combo if node is not None]
            if len(observed_nodes) < 1:
                continue
            candidate = _path_candidate(template, combo)
            cid = str(candidate["candidate_id"])
            if cid in seen_candidates:
                continue
            seen_candidates.add(cid)
            candidates.append(candidate)
            goal_counts[str(template["goal"])] += 1
            if len(candidates) >= path_limit:
                break
        if len(candidates) >= path_limit:
            break

    # Add virtual requirement nodes only for capabilities that occur in a
    # generated path.  A missing node is visible in the graph, not silently
    # conflated with an observed primitive.
    for candidate in candidates:
        for kind in candidate.get("missing_capabilities") or []:
            node_id = "need:%s" % kind
            nodes.setdefault(node_id, {
                "node_id": node_id,
                "capability": kind,
                "status": "required",
                "source_kind": "hypothesis",
                "locations": [],
                "constraints": {"runtime_or_source_evidence_required": True},
                "confidence": "unknown",
                "producer": "capability-search",
                "evidence_type": "research-plan",
            })
        ordered_ids = list(candidate.get("capability_refs") or [])
        for kind in candidate.get("missing_capabilities") or []:
            ordered_ids.append("need:%s" % kind)
        for left, right in zip(ordered_ids, ordered_ids[1:]):
            edges.append({
                "from": left, "to": right, "relation": "candidate-transition",
                "candidate_id": candidate["candidate_id"],
                "equation": candidate["chain_equation"],
                "confidence": "heuristic-callgraph",
                "evidence_type": "static-inferred",
            })

    candidates.sort(key=lambda item: (str(item.get("chain_status")),
                                     str(item.get("chain_equation")),
                                     str(item.get("candidate_id"))))
    # Candidate ids were generated before sorting and remain stable; trim edges
    # as a presentation bound while retaining a truthful truncation flag.
    edges_truncated = len(edges) > MAX_EDGES
    edges = sorted(edges, key=lambda item: (
        str(item.get("candidate_id", "")), str(item.get("from")),
        str(item.get("to")), str(item.get("relation"))))[:MAX_EDGES]
    node_values = sorted(nodes.values(), key=lambda item: str(item.get("node_id")))
    nodes_truncated = len(node_values) > node_limit
    node_values = node_values[:node_limit]
    observed_counts = {
        kind: len(items) for kind, items in sorted(by_kind.items())
    }
    summary = {
        "nodes": len(node_values),
        "observed_nodes": sum(1 for node in node_values
                               if node.get("status") == "observed"),
        "required_nodes": sum(1 for node in node_values
                               if node.get("status") == "required"),
        "edges": len(edges),
        "flows_considered": flow_count,
        "observed_capabilities": observed_counts,
        "paths": len(candidates),
        "complete_hypotheses": sum(1 for item in candidates
                                    if not item.get("missing_capabilities")),
        "partial_hypotheses": sum(1 for item in candidates
                                   if item.get("missing_capabilities")),
        "paths_by_goal": dict(sorted(goal_counts.items())),
        "transition_attempts": transition_count,
        "declared_transition_matches": sum(
            1 for item in candidates
            for rule in item.get("transition_rules", [])
            if rule.get("declared")),
        "truncated": bool(edges_truncated or nodes_truncated or
                           (path_limit == 0 and bool(observed)) or
                           len(candidates) >= path_limit),
        "limits": {"max_nodes": node_limit, "max_paths": path_limit,
                   "max_choices_per_kind": MAX_CHOICES_PER_KIND,
                   "max_edges": MAX_EDGES},
        "confidence": "heuristic-callgraph",
        "producer": "capability-search",
        "evidence_type": "static-inferred",
        "claim_status": "not-a-finding",
        "limitations": [
            "capability composition does not prove semantic data flow or temporal order",
            "cross-domain transitions require separately verified intermediate state",
            "missing primitive is a research sub-goal, not negative evidence",
            "typed runtime effect is required before any impact conclusion",
        ],
    }
    return {
        "schema_version": CAPABILITY_GRAPH_VERSION,
        "nodes": node_values,
        "edges": edges,
        "paths": candidates,
        "summary": summary,
        "provenance": {
            "producer": "capability-search",
            "confidence": "heuristic-callgraph",
            "evidence_type": "static-inferred",
            "claim_status": "not-a-finding",
        },
        "candidates": candidates,
    }


def load_capability_graph(store: Any) -> Dict[str, Any]:
    data = store.read(CAPABILITY_GRAPH_INDEX)
    return data if isinstance(data, dict) else {}


def load_capability_candidates(store: Any) -> List[Dict[str, Any]]:
    data = store.read(CAPABILITY_CANDIDATE_INDEX)
    return [item for item in data if isinstance(item, dict)] \
        if isinstance(data, list) else []
