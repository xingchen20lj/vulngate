"""Bounded branch-posture and subject-binding evidence for semantic paths.

``semantic_paths`` answers whether a control is lexically near a sink and
whether an identifier/alias can be followed inside one symbol.  This module
adds the next narrow question an experienced reviewer asks: does the control
look like a guard for the sink's branch, and does it mention the same subject
or object that the sink operates on?

This is still a deterministic heuristic, not a control-flow graph or a type
checker.  It records *posture* (for example ``terminating-guard-likely`` or
``non-branch-check``) and *binding* (``overlap``, ``mismatch``, or
``unresolved``).  It never claims dominance, authorization correctness, or a
vulnerability.  All rows and leads remain ``not-a-finding``.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from . import controls as control_rules
from . import semantic_paths as semantic


SEMANTIC_GUARD_INDEX = "semantic-guard-evidence"
SEMANTIC_GUARD_CANDIDATE_INDEX = "semantic-guard-candidates"
SEMANTIC_GUARD_VERSION = "semantic-guard-evidence-v1"
CLAIM_STATUS = "not-a-finding"
CONFIDENCE = "heuristic-nearby"
EVIDENCE_TYPE = "static-inferred"

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_IDENTIFIER = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b")
_GENERIC_SUBJECT = frozenset({
    "a", "an", "and", "api", "arg", "args", "assert", "auth", "authorization",
    "allow", "check", "checked", "deny", "delete", "does", "ensure", "exec",
    "execute", "false", "get", "has", "if", "input", "is", "object", "open",
    "owner", "permission", "permissions", "read", "request", "return", "role",
    "run", "safe", "sanitize", "system", "tenant", "the", "this", "true",
    "update", "validate", "validation", "value", "write", "id",
})
_NEGATIVE_GUARD = re.compile(
    r"\b(?:not|denied|deny|unauth|unauthorized|forbidden|invalid|failed|fail)\b|!"
)
_BRANCH = re.compile(r"\b(?:if|unless|when)\b")
_TERMINATOR = re.compile(r"\b(?:return|throw|raise|abort|exit|break)\b")

_LIMITATIONS = (
    "branch posture is lexical and does not prove control-flow dominance or path feasibility",
    "subject binding uses bounded identifier overlap and does not prove object identity, tenant equality, or authorization semantics",
    "cross-symbol controls remain unverified because callbacks, DI, reflection and virtual dispatch are not resolved",
    "a mismatch or unresolved binding is a manual review lead, never proof of an authorization bypass",
)


def _field(record: Any, name: str, default: Any = None) -> Any:
    if isinstance(record, dict):
        return record.get(name, default)
    return getattr(record, name, default)


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _text(value: Any, limit: int = 180) -> str:
    return " ".join(str(value or "").replace("\x00", "").split())[:limit]


def _split_identifier(value: Any) -> Set[str]:
    tokens: Set[str] = set()
    for raw in _IDENTIFIER.findall(str(value or "")):
        pieces = _CAMEL_BOUNDARY.sub(" ", raw).replace("$", " ").split("_")
        for piece in pieces:
            word = piece.strip().lower()
            if word and word not in _GENERIC_SUBJECT:
                tokens.add(word)
    return tokens


def _read_lines(root: Path, file_name: str,
                cache: Dict[str, Optional[List[str]]]) -> List[str]:
    if file_name in cache:
        return cache[file_name] or []
    path = Path(file_name)
    if not path.is_absolute():
        path = root / path
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, UnicodeError):
        lines = None
    cache[file_name] = lines
    return lines or []


def _scope_keys(lines: Sequence[str]) -> Dict[int, Tuple[int, int]]:
    return semantic._scope_keys(lines)


def _line(lines: Sequence[str], number: int) -> str:
    return lines[number - 1] if 0 < number <= len(lines) else ""


def _subject_binding(control: Mapping[str, Any], sink: Mapping[str, Any],
                    control_line: str, sink_line: str) -> Tuple[str, List[str], List[str]]:
    control_basis = " ".join([
        str(control.get("category") or ""),
        str(control.get("control_type") or ""),
        str(control.get("api") or ""),
        control_line,
    ])
    sink_basis = " ".join([
        str(sink.get("category") or ""),
        str(sink.get("api") or ""),
        str(sink_line or ""),
    ])
    control_tokens = sorted(_split_identifier(control_basis))[:16]
    sink_tokens = sorted(_split_identifier(sink_basis))[:16]
    if not control_tokens or not sink_tokens:
        return "unresolved", control_tokens, sink_tokens
    if set(control_tokens) & set(sink_tokens):
        return "overlap", control_tokens, sink_tokens
    return "mismatch", control_tokens, sink_tokens


def _has_terminator(lines: Sequence[str], control_line: int, sink_line: int,
                    control_indent: int) -> bool:
    # Inspect only the bounded interval before the sink.  A terminator at the
    # control line handles ``if not check(x): return``; later lines must be
    # indented/nested enough to belong to the apparent guard block.
    for number in range(max(1, control_line), min(len(lines), sink_line - 1) + 1):
        text = _line(lines, number)
        indent = len(text) - len(text.lstrip(" \t"))
        if number == control_line or indent > control_indent:
            if _TERMINATOR.search(semantic._strip_code(text)):
                return True
    return False


def _branch_posture(control: Mapping[str, Any], sink: Mapping[str, Any],
                    lines: Sequence[str], scopes: Mapping[int, Tuple[int, int]]) -> str:
    alignment = str(control.get("alignment") or "")
    if alignment == "cross-symbol-unverified":
        return "cross-symbol-unverified"
    if alignment == "after-sink":
        return "after-sink"
    if alignment == "same-line":
        return "same-line"
    control_line = _int(control.get("line"))
    sink_line = _int(sink.get("line"))
    source = semantic._strip_code(_line(lines, control_line))
    if control_line <= 0 or sink_line <= 0 or sink_line <= control_line:
        return "unresolved"
    control_scope = scopes.get(control_line, (0, 0))
    sink_scope = scopes.get(sink_line, (0, 0))
    if _BRANCH.search(source):
        negative = bool(_NEGATIVE_GUARD.search(source))
        if _has_terminator(lines, control_line, sink_line, control_scope[1]):
            return "terminating-guard-likely" if negative else "branch-unresolved"
        if (sink_scope[0] > control_scope[0]
                or sink_scope[1] > control_scope[1]):
            return "nested-branch-likely"
        return "branch-unresolved"
    # A check call may itself throw or return a denial, but the source shape
    # does not expose that contract.  Keep it separate from a likely guard.
    return "non-branch-check"


def _stable_id(kind: str, flow_id: str, control_id: str) -> str:
    import hashlib
    raw = "%s|%s|%s" % (kind, flow_id, control_id)
    return "guard-%s-%s" % (kind, hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12])


def _location(file_name: Any, line: Any) -> str:
    return "%s:%d" % (str(file_name or ""), _int(line)) if file_name else ""


def _candidate(kind: str, flow: Mapping[str, Any], guard: Mapping[str, Any]
               ) -> Dict[str, Any]:
    flow_id = str(flow.get("flow_id") or "")
    control_id = str(guard.get("control_id") or "")
    candidate_id = _stable_id(kind, flow_id, control_id)
    entry = flow.get("entry") or {}
    sink = flow.get("sink") or {}
    category = "authz" if guard.get("category") in control_rules.AUTHZ_CATEGORIES else "logic"
    if kind == "subject-binding":
        surface = "semantic-subject-binding"
        logic = "subject-binding: %s" % guard.get("subject_binding", "unresolved")
        hypothesis = "控制可能检查了与 sink 不同的 subject/object；需人工验证主体、对象和租户绑定"
        preconditions = [
            "需确认入口在目标默认配置下可达",
            "需验证控制参数与 sink 实际对象的类型、身份和租户关系",
        ]
        authz_cases = control_rules.authz_cases_for()
    else:
        surface = "semantic-branch-posture"
        logic = "branch-posture: %s" % guard.get("branch_posture", "unresolved")
        hypothesis = "控制在源码中出现，但其分支/拒绝路径是否覆盖 sink 仍未被静态证据闭合"
        preconditions = [
            "需确认控制调用的返回/异常语义及 sink 的真实控制流",
            "需验证 sink 是否只位于被保护分支，或存在可绕过的其他分支",
        ]
        authz_cases = control_rules.authz_cases_for() if category == "authz" else []
    locations = []
    for value in (
        _location(entry.get("file"), entry.get("line")),
        _location(sink.get("file"), sink.get("line")),
        _location(guard.get("file"), guard.get("line")),
    ):
        if value and value not in locations:
            locations.append(value)
    return {
        "candidate_id": candidate_id,
        "surface": surface,
        "entry": str(entry.get("api") or entry.get("entry_id") or ""),
        "input_shape": str(entry.get("input_shape") or "unknown"),
        "logic": logic,
        "hypothesis": hypothesis,
        "precondition_tier_hint": "app-cooperation"
        if guard.get("branch_posture") == "cross-symbol-unverified"
        else "single-feature",
        "preconditions": preconditions,
        "poc_class": control_rules.poc_class_for(candidate_id),
        "jvm": {},
        "target_classes": [],
        "authz_cases": authz_cases,
        "chain_components": ["request-input", category,
                             str(sink.get("category") or "sink")],
        "novelty_keywords": sorted(set([surface, kind, category,
                                          str(sink.get("category") or "sink")])),
        "code_location": locations,
        "category": category,
        "flow_id": flow_id,
        "entry_id": str(flow.get("entry_id") or ""),
        "sink_id": str(flow.get("sink_id") or ""),
        "control_id": control_id,
        "path": list(flow.get("path") or []),
        "branch_posture": guard.get("branch_posture", "unresolved"),
        "subject_binding": guard.get("subject_binding", "unresolved"),
        "requires_manual_dataflow": True,
        "source": "semantic-guards",
        "producer": "semantic-guards",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "claim_status": CLAIM_STATUS,
    }


def build_semantic_guard_evidence(root: Path,
                                  semantic_evidence: Mapping[str, Any]
                                  ) -> Dict[str, Any]:
    """Build guard posture/binding evidence from the semantic path artifact."""
    root = Path(root).resolve()
    line_cache: Dict[str, Optional[List[str]]] = {}
    scope_cache: Dict[str, Dict[int, Tuple[int, int]]] = {}
    flow_rows: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    posture_counts: Counter = Counter()
    binding_counts: Counter = Counter()
    flow_branch_gaps = 0
    flow_binding_gaps = 0

    for flow in sorted(semantic_evidence.get("flows") or [],
                       key=lambda item: str(item.get("flow_id") or "")):
        sink = dict(flow.get("sink") or {})
        guards: List[Dict[str, Any]] = []
        required_categories = {
            str(category)
            for group in (flow.get("required_groups") or [])
            for category in (group.get("required") or [])
        }
        for control in flow.get("controls") or []:
            control = dict(control)
            file_name = str(control.get("file") or sink.get("file") or "")
            lines = _read_lines(root, file_name, line_cache)
            if file_name not in scope_cache:
                scope_cache[file_name] = _scope_keys(lines)
            source_line = _line(lines, _int(control.get("line")))
            sink_line = _line(lines, _int(sink.get("line")))
            binding, control_tokens, sink_tokens = _subject_binding(
                control, sink, source_line, sink_line)
            posture = _branch_posture(control, sink, lines,
                                      scope_cache[file_name])
            guard = {
                "control_id": str(control.get("control_id") or ""),
                "category": control_rules.normalize_category(control.get("category")),
                "control_type": _text(control.get("control_type"), 80),
                "api": _text(control.get("api"), 100),
                "file": file_name,
                "line": _int(control.get("line")),
                "symbol_id": str(control.get("symbol_id") or ""),
                "alignment": str(control.get("alignment") or ""),
                "scope": str(control.get("scope") or "unknown"),
                "branch_posture": posture,
                "subject_binding": binding,
                "control_tokens": control_tokens,
                "sink_tokens": sink_tokens,
                "claim_status": CLAIM_STATUS,
                "producer": "semantic-guards",
                "confidence": CONFIDENCE,
                "evidence_type": EVIDENCE_TYPE,
            }
            guard["required_category"] = guard["category"] in required_categories
            guards.append(guard)
            posture_counts[posture] += 1
            binding_counts[binding] += 1

            static_verdict = str(flow.get("static_control_verdict") or "")
            category = guard["category"]
            if static_verdict in (control_rules.VERDICT_GUARDED,
                                  control_rules.VERDICT_PARTIAL):
                if (category in control_rules.AUTHZ_CATEGORIES
                        and binding in {"mismatch", "cross-symbol-unverified"}
                        and guard["required_category"]):
                    candidates.append(_candidate("subject-binding", flow, guard))
                if (guard["required_category"]
                        and posture in {"non-branch-check", "branch-unresolved",
                                         "cross-symbol-unverified", "unresolved"}):
                    candidates.append(_candidate("branch-posture", flow, guard))

        if any(guard.get("subject_binding") in {"mismatch", "cross-symbol-unverified"}
               for guard in guards):
            flow_binding_gaps += 1
        if any(guard.get("branch_posture") in {
                "non-branch-check", "branch-unresolved", "cross-symbol-unverified",
                "unresolved"} for guard in guards):
            flow_branch_gaps += 1
        flow_rows.append({
            "flow_id": str(flow.get("flow_id") or ""),
            "entry_id": str(flow.get("entry_id") or ""),
            "sink_id": str(flow.get("sink_id") or ""),
            "path": list(flow.get("path") or []),
            "entry": dict(flow.get("entry") or {}),
            "sink": sink,
            "static_control_verdict": str(flow.get("static_control_verdict") or ""),
            "guards": guards,
            "required_manual_checks": [
                "verify branch dominance and alternate paths in the real control-flow graph",
                "verify subject/object/tenant identity binding with types and runtime authorization cases",
            ],
            "claim_status": CLAIM_STATUS,
            "producer": "semantic-guards",
            "confidence": CONFIDENCE,
            "evidence_type": EVIDENCE_TYPE,
        })

    candidates.sort(key=lambda item: (str(item.get("surface") or ""),
                                     str(item.get("flow_id") or ""),
                                     str(item.get("control_id") or ""),
                                     str(item.get("candidate_id") or "")))
    summary = {
        "flows": len(flow_rows),
        "flows_with_branch_gaps": flow_branch_gaps,
        "flows_with_subject_binding_gaps": flow_binding_gaps,
        "branch_postures": dict(sorted(posture_counts.items())),
        "subject_binding": dict(sorted(binding_counts.items())),
        "candidates": len(candidates),
        "claim_status": CLAIM_STATUS,
        "producer": "semantic-guards",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "limitations": list(_LIMITATIONS),
    }
    return {
        "schema_version": SEMANTIC_GUARD_VERSION,
        "summary": summary,
        "flows": flow_rows,
        "candidates": candidates,
        "claim_status": CLAIM_STATUS,
        "producer": "semantic-guards",
        "confidence": CONFIDENCE,
        "evidence_type": EVIDENCE_TYPE,
        "limitations": list(_LIMITATIONS),
    }


def load_semantic_guards(store: Any) -> Dict[str, Any]:
    data = store.read(SEMANTIC_GUARD_INDEX)
    return data if isinstance(data, dict) else {}


def load_semantic_guard_candidates(store: Any) -> List[Dict[str, Any]]:
    data = store.read(SEMANTIC_GUARD_CANDIDATE_INDEX)
    return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []


def render_semantic_guards_text(evidence: Mapping[str, Any], lang: str = "zh",
                                limit: int = 20) -> str:
    summary = dict(evidence.get("summary") or {}) if isinstance(evidence, Mapping) else {}
    candidates = list(evidence.get("candidates") or []) if isinstance(evidence, Mapping) else []
    if lang == "en":
        lines = ["Semantic guard evidence (branch posture / subject binding)",
                 "─" * 58,
                 "  flows %s  branch gaps %s  subject gaps %s  candidates %s" % (
                     summary.get("flows", 0), summary.get("flows_with_branch_gaps", 0),
                     summary.get("flows_with_subject_binding_gaps", 0),
                     summary.get("candidates", 0)),
                 "  postures %s" % (summary.get("branch_postures") or {}),
                 "  binding %s" % (summary.get("subject_binding") or {}),
                 "  leads:"]
    else:
        lines = ["语义守卫证据（分支姿态 / 主体绑定）", "─" * 58,
                 "  路径 %s  分支缺口 %s  主体缺口 %s  候选 %s" % (
                     summary.get("flows", 0), summary.get("flows_with_branch_gaps", 0),
                     summary.get("flows_with_subject_binding_gaps", 0),
                     summary.get("candidates", 0)),
                 "  分支姿态 %s" % (summary.get("branch_postures") or {}),
                 "  主体绑定 %s" % (summary.get("subject_binding") or {}),
                 "  待验证线索："]
    for candidate in candidates[:max(0, limit)]:
        lines.append("    %-22s %-28s %s" % (
            candidate.get("candidate_id", ""), candidate.get("surface", ""),
            ",".join(candidate.get("code_location") or []) or "-"))
    if len(candidates) > limit:
        lines.append("    ... %d more" % (len(candidates) - limit))
    return "\n".join(lines)
