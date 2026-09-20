"""Deterministic, falsifiable experiment plans for S2/S3/S4.

The planner does not decide whether a vulnerability exists.  It translates a
candidate's observable research signals into a bounded list of experiments,
each with required observations and explicit falsifiers.  The host agent and
the PoC writer can use the plan to choose the next probe, while G4/G5 still
consume only actual runtime evidence.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence

from ..evaluation.benchmark import normalize_benchmark_feedback
from .authz import normalize_authz_case, normalize_authz_cases
from .experiment import capability_contract_from_candidate
from .redaction import redact_text


PLANNER_VERSION = "experiment-planner-v1"
MAX_PLANS = 6
MAX_VERSIONS = 16
MAX_PRECONDITIONS = 8

_STATE_MARKERS = (
    "race", "竞态", "concurr", "state", "状态", "replay", "重放",
    "double", "重复", "cache", "缓存", "session", "会话", "thread",
    "线程", "toctou", "time-of-check", "lock", "锁",
)
_DOS_MARKERS = (
    "dos", "denial of service", "拒绝服务", "resource exhaustion",
    "资源耗尽", "oom", "outofmemory", "stack overflow", "栈溢出",
    "infinite loop", "死循环", "cpu", "amplification", "放大",
)
_AUTHZ_MARKERS = (
    "authz", "authn", "authoriz", "permission", "权限", "owner",
    "归属", "tenant", "租户", "role", "角色", "idor", "access control",
    "访问控制", "bypass", "绕过", "privilege", "越权",
)
_VARIANT_MARKERS = (
    "fix-completeness", "patch", "修复", "variant", "变体", "residual",
    "残留", "cve", "issue",
)
_EFFECT_MARKERS = (
    "rce", "remote code", "command", "命令", "exec", "执行", "process",
    "进程", "file write", "写文件", "file read", "读文件", "leak",
    "泄露", "ssrf", "xxe", "deserial", "反序列化", "template",
    "模板", "sql", "expression", "表达式",
)


def _text(value: Any, limit: int = 240) -> str:
    if value is None:
        return ""
    return " ".join(str(value).replace("\x00", "").split())[:limit]


def _list(value: Any, limit: int = 16) -> List[str]:
    if not isinstance(value, (list, tuple)):
        return []
    out: List[str] = []
    for item in value:
        text = _text(item, 120)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _contains(text: str, markers: Iterable[str]) -> bool:
    lowered = text.lower()
    return any(marker.lower() in lowered for marker in markers)


def _versions(values: Sequence[Any]) -> List[str]:
    out: List[str] = []
    for value in values:
        version = _text(value, 80)
        if version and version not in out:
            out.append(version)
        if len(out) >= MAX_VERSIONS:
            break
    return sorted(out)


def _authz_case_ids(candidate: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for index, raw in enumerate(normalize_authz_cases(candidate.get("authz_cases"))):
        case = normalize_authz_case(raw, index)
        case_id = _text(case.get("case_id"), 80)
        if case_id and case_id not in out:
            out.append(case_id)
    return out[:16]


def _plan(candidate_id: str, kind: str, objective: str,
          required_observations: List[str], falsifiers: List[str],
          **extra: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "plan_id": "%s:%s" % (candidate_id, kind),
        "kind": kind,
        "status": "planned",
        "objective": objective,
        "required_observations": required_observations,
        "falsifiers": falsifiers,
    }
    result.update(extra)
    return result


def apply_benchmark_feedback(research_plan: Dict[str, Any],
                             benchmark_feedback: Dict[str, Any]) -> Dict[str, Any]:
    """Add bounded benchmark follow-ups to an existing research checklist.

    The feedback can add observations and falsifiers to the baseline plan, and
    tags that help the host choose a probe.  It cannot add a finding, change a
    candidate status, alter a CVSS value, or remove an existing experiment.
    """
    feedback = normalize_benchmark_feedback(benchmark_feedback or {})
    if not feedback or not isinstance(research_plan, dict):
        return research_plan
    result = dict(research_plan)
    result["strategy_tags"] = list(research_plan.get("strategy_tags") or [])
    result["plans"] = []
    for item in research_plan.get("plans") or []:
        if not isinstance(item, dict):
            continue
        copied = dict(item)
        copied["required_observations"] = list(item.get("required_observations") or [])
        copied["falsifiers"] = list(item.get("falsifiers") or [])
        result["plans"].append(copied)

    guidance = feedback.get("planner_guidance") or {}
    tags = [str(item) for item in guidance.get("strategy_tags") or []]
    required = [str(item) for item in guidance.get("required_observations") or []]
    falsifiers = [str(item) for item in guidance.get("falsifiers") or []]
    for tag in tags + (["benchmark-feedback"] if guidance else []):
        if tag and tag not in result["strategy_tags"]:
            result["strategy_tags"].append(tag)
    baseline = next((item for item in result["plans"]
                     if item.get("kind") == "baseline"), None)
    if baseline is not None:
        for observation in required:
            if observation not in baseline["required_observations"]:
                baseline["required_observations"].append(observation)
        for falsifier in falsifiers:
            if falsifier not in baseline["falsifiers"]:
                baseline["falsifiers"].append(falsifier)
        baseline["required_observations"] = baseline["required_observations"][:24]
        baseline["falsifiers"] = baseline["falsifiers"][:24]

    alert_codes = [str(item.get("code")) for item in feedback.get("alerts", [])
                   if isinstance(item, dict) and item.get("code")]
    result["benchmark_guidance"] = {
        "schema_version": feedback.get("schema_version"),
        "source_benchmark_id": feedback.get("benchmark_id", ""),
        "alert_codes": alert_codes[:8],
        "required_observations": required[:12],
        "falsifiers": falsifiers[:12],
        "claim_status": "not-a-finding",
    }
    provenance = dict(result.get("provenance") or {})
    provenance["benchmark_feedback"] = True
    provenance["claim_status"] = "not-a-finding"
    result["provenance"] = provenance
    return result


def plan_candidate_experiments(candidate: Dict[str, Any],
                               versions: Sequence[Any] = (),
                               benchmark_feedback: Optional[Dict[str, Any]] = None
                               ) -> Dict[str, Any]:
    """Return a stable, bounded experiment plan for one candidate.

    The output is a research checklist, not a verdict.  In particular, a plan
    may require an observation that is never produced; that absence remains
    ``unsupported``/pending instead of becoming a negative result.
    """
    candidate_id = _text(candidate.get("candidate_id"), 120) or "candidate"
    text = " ".join(
        _text(candidate.get(key), 400)
        for key in ("surface", "entry", "logic", "hypothesis", "attack_class",
                    "category", "chain_components", "source")
    )
    case_ids = _authz_case_ids(candidate)
    stateful = bool(candidate.get("sequence")) or _contains(text, _STATE_MARKERS)
    dos = _contains(text, _DOS_MARKERS) or bool(candidate.get("availability_probe"))
    authz = bool(case_ids) or str(candidate.get("category", "")).lower() == "authz" \
        or _contains(text, _AUTHZ_MARKERS)
    variant = bool(candidate.get("fix_completeness")) or _contains(text, _VARIANT_MARKERS)
    effect = _contains(text, _EFFECT_MARKERS)
    capability_contract = capability_contract_from_candidate(candidate)
    capability_chain = bool(capability_contract.get("required_capabilities"))

    normalized_versions = _versions(versions)
    preconditions = [
        redact_text(item)
        for item in _list(
            candidate.get("cell_preconditions") or candidate.get("preconditions")
            or ["none"], MAX_PRECONDITIONS)
    ]
    sequence = _list(candidate.get("sequence"), 16)
    if stateful and not sequence:
        sequence = ["baseline", "transition", "probe"]

    tags: List[str] = []
    for tag, enabled in (("stateful", stateful), ("race", stateful and dos),
                         ("authorization", authz), ("variant", variant),
                         ("typed-effect", effect),
                         ("capability-chain", capability_chain)):
        if enabled:
            tags.append(tag)

    plans: List[Dict[str, Any]] = [
        _plan(
            candidate_id,
            "baseline",
            "建立入口可达性、默认/安全态行为和负向基线，避免把 harness 失败当成漏洞不存在。",
            ["one execution-state record", "one target behavior marker or explicit gate"],
            ["unexecuted/run-failed/precondition-unavailable are not negative evidence"],
            matrix_axes={"versions": normalized_versions,
                         "safe_mode": [True, False],
                         "preconditions": preconditions},
        )
    ]

    if capability_chain:
        capability_observations = [
            "CAPABILITY_TRACE for declared primitive ids",
            "CAPABILITY_EVIDENCE for each emitted primitive",
            "TRANSITION_TRACE for each declared transition",
        ]
        if capability_contract.get("typed_effect_required"):
            capability_observations.append("EFFECT_KIND and EFFECT for typed effect")
        plans.append(_plan(
            candidate_id,
            "capability-transition",
            "逐步验证能力原语、相邻 transition 与终点 typed effect；静态链闭合不等于运行时闭合。",
            capability_observations,
            ["missing CAPABILITY_TRACE is unsupported, not proof of absence",
             "missing transition evidence leaves the chain partial",
             "a canary/instantiation without the declared typed effect cannot support impact"],
            required_capabilities=list(
                capability_contract.get("required_capabilities") or []),
            observed_capabilities=list(
                capability_contract.get("observed_capabilities") or []),
            missing_capabilities=list(
                capability_contract.get("missing_capabilities") or []),
            transition_rules=list(
                capability_contract.get("transition_rules") or []),
            typed_effect_required=bool(
                capability_contract.get("typed_effect_required")),
        ))

    if authz:
        plans.append(_plan(
            candidate_id,
            "authorization-boundary",
            "验证入口主体、租户/对象归属与最终 sink 是否绑定到同一安全主体。",
            ["HTTP_CODE or AUTHZ_RESULT", "OBJECT_MUTATED when the case expects deny"],
            ["missing authorization observations => unsupported, not a violation",
             "deny-to-allow or forbidden ownership mutation must be reproduced"],
            cases=case_ids or ["anonymous", "cross-tenant", "other-principal"],
        ))

    if stateful:
        plans.append(_plan(
            candidate_id,
            "state-sequence",
            "验证声明的状态/操作顺序是否真实执行，并记录每一步的状态转移证据。",
            ["STEP_TRACE", "STEP_EVIDENCE or STATE_TRACE", "sequence_status=complete"],
            ["partial/no-trace/out-of-order is insufficient for a complete sequence claim",
             "a timeout without a state observation is not a race proof"],
            sequence=sequence,
        ))

    if stateful and dos:
        plans.append(_plan(
            candidate_id,
            "concurrency-availability",
            "区分单请求变慢与并发饱和导致的服务不可用。",
            ["CONCURRENCY>=2", "SERVICE_UNAVAILABLE=true or equivalent", "probe result"],
            ["declared concurrency alone is not proof",
             "single timeout/OOM/StackOverflow is not complete outage proof"],
            minimum_concurrency=2,
            availability_probe=True,
        ))

    if variant:
        version_pairs = []
        if len(normalized_versions) >= 2:
            version_pairs = [
                {"before": normalized_versions[index],
                 "after": normalized_versions[index + 1]}
                for index in range(len(normalized_versions) - 1)
            ]
        plans.append(_plan(
            candidate_id,
            "fix-variant-comparison",
            "比较修复前后及同族路径，验证补丁是否真正覆盖原始机制和残留变体。",
            ["pre-fix failure/effect observation", "post-fix rejection or safe behavior"],
            ["a fix commit by itself is not runtime evidence",
             "missing old runtime is precondition-unavailable, not fixed"],
            version_pairs=version_pairs,
        ))

    if effect:
        plans.append(_plan(
            candidate_id,
            "typed-effect",
            "只用与候选声明一致的真实 typed effect 支撑最终影响，不把中间能力链升级为终点影响。",
            ["EFFECT_KIND", "corresponding EFFECT detail"],
            ["instantiation/lookup/canary alone cannot prove RCE",
             "a capability-only marker remains safe-equivalent/pending"],
            allowed_effect_kinds=[
                "command-executed", "process-started", "command-marker",
                "file-marker", "content-leak", "object-mutation",
            ],
        ))

    plans = plans[:MAX_PLANS]
    result = {
        "candidate_id": candidate_id,
        "planner_version": PLANNER_VERSION,
        "strategy_tags": tags,
        "matrix_axes": {
            "versions": normalized_versions,
            "safe_mode": [True, False],
            "preconditions": preconditions,
            "authz_cases": case_ids,
        },
        "capability_contract": capability_contract,
        "plans": plans,
        "provenance": {
            "producer": "experiment-planner",
            "confidence": "deterministic-plan",
            "evidence_type": "research-plan",
            "claim_status": "not-a-finding",
        },
    }
    return apply_benchmark_feedback(result, benchmark_feedback or {})
