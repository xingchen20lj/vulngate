"""Hard gates G0-G5 as verifiable decisions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..tools.build import S4_EVIDENCE_POLICY_VERSION
from .security_types import ExecutionState

from ..tools.conclusion import _has_real_effect, _is_runtime_evidence, _requires_real_effect


@dataclass
class GateResult:
    gate_id: str
    passed: bool
    verdict: str
    evidence: List[str] = field(default_factory=list)


def g0_dead_code(entry: Dict[str, Any], reference_count: int) -> GateResult:
    if reference_count == 0:
        return GateResult("G0", False, "dead code (0 external references)",
                          ["reference_count=0 for %s" % entry.get("api")])
    return GateResult("G0", True, "live code", ["reference_count=%d" % reference_count])


def g1_reachable(entry: Dict[str, Any]) -> GateResult:
    untrusted = entry.get("untrusted", False)
    if not untrusted:
        return GateResult("G1", False, "not reachable from untrusted input",
                          ["entry not marked untrusted"])
    return GateResult("G1", True, "reachable from untrusted input", ["untrusted=true"])


def g1b_gate_blocks(audit: Optional[Dict[str, Any]]) -> GateResult:
    if not audit:
        return GateResult("G1b", True, "no audit note - gate status unknown", [])
    gate_status = audit.get("gate_status", "")
    default_reachable = audit.get("default_config_reachable", True)
    if gate_status and not default_reachable:
        return GateResult("G1b", False, "security gate blocks default config: %s" % gate_status,
                          [gate_status, "default_config_reachable=false"])
    if gate_status and default_reachable:
        return GateResult("G1b", True, "gate does not block: %s" % gate_status,
                          [gate_status, "default_config_reachable=true"])
    return GateResult("G1b", True, "no gate recorded", [])


def g3_novelty(novelty: Dict[str, Any]) -> GateResult:
    verdict = novelty.get("verdict", "")
    hits = novelty.get("reason", "")
    if verdict == "candidate-0day":
        # verdict is computed deterministically by NoveltyChecker.evaluate
        # (candidate-0day only when no predating ref/disclosure exists and the
        # query was authoritative). A string match on `reason` is NOT used:
        # the reason text itself contains the words upstream/disclosure
        # ("no upstream open PR/issue and no public disclosure...") which
        # previously caused every genuine candidate-0day to be misjudged.
        return GateResult("G3", True, "candidate-0day: no upstream/public record", [hits])
    if verdict in ("known-family-with-increment", "upstream-fixed"):
        return GateResult("G3", True, "downgraded: %s" % verdict, [hits])
    if verdict == "unknown-query-failed":
        # Baseline #7: query incomplete -> not a 0day claim; human review required.
        return GateResult(
            "G3", True,
            "public-info scan incomplete; needs-human-review (not claimable as 0day)",
            [hits])
    return GateResult("G3", False, "unknown novelty verdict %s" % verdict, [hits])


def g4_runtime(summary: Dict[str, Any], intended: str = "确认",
                candidate: Optional[Dict[str, Any]] = None) -> GateResult:
    instantiated = summary.get("instantiated", [])
    errors = summary.get("errors", [])
    gate_blocked = summary.get("gate_blocked", [])
    leaked = summary.get("leaked", [])
    independent_effects = [
        effect for effect in (summary.get("independent_effect_evidence") or [])
        if isinstance(effect, dict) and effect.get("status") == "observed"
    ]
    if intended == "排除":
        basis = summary.get("exclusion_basis") or {}
        if (isinstance(basis, dict)
                and basis.get("kind") == "g1-unreachable"
                and basis.get("source_refs")):
            return GateResult("G4", True, "source-backed unreachable path",
                              [str(ref) for ref in basis["source_refs"][:8]])
        return GateResult(
            "G4", False, "execution failure or gate block cannot exclude a candidate",
            ["gate_blocked=%d errors=%d" % (len(gate_blocked), len(errors))],
        )
    if intended == "确认":
        if (summary.get("evidence_policy_version") != S4_EVIDENCE_POLICY_VERSION
                or summary.get("execution_state")
                != ExecutionState.EXECUTED_WITH_EFFECT.value):
            return GateResult(
                "G4", False, "no complete harness-observed runtime effect",
                ["execution_state=%s" % summary.get("execution_state", "unknown")],
            )
        if _requires_real_effect(candidate or {}) and not _has_real_effect(summary, candidate):
            return GateResult(
                "G4", False,
                "RCE/code-execution claim lacks real side-effect evidence",
                ["safe-equivalent or capability-only evidence cannot confirm RCE"],
            )
        if instantiated:
            return GateResult("G4", True, "runtime instantiation observed",
                              ["instantiated=%s" % ", ".join(i["class"] for i in instantiated)])
        if leaked:
            return GateResult("G4", True, "runtime content-leakage observed",
                              ["leaked=%s" % ", ".join(i["leaked"][:80] for i in leaked[:3])])
        if independent_effects:
            return GateResult(
                "G4", True, "independent typed runtime effect observed",
                [str(effect.get("kind", "unknown"))
                 for effect in independent_effects[:4]],
            )
        do_s_errors = [e for e in errors if _is_runtime_evidence(e.get("error", ""))]
        if do_s_errors:
            return GateResult("G4", True, "runtime DoS/instantiation-chain error observed",
                              [e["error"] for e in do_s_errors])
        return GateResult("G4", False, "confirmed conclusion without runtime reproduction",
                          ["no instantiated class, no DoS-class error"])
    return GateResult("G4", False, "unknown intended conclusion %s" % intended, [])


def g5_cvss(tier: str, vector: str, implicit_default_on: bool = False) -> GateResult:
    from ..tools.cvss import check_precondition_consistency, base_score
    score, severity = base_score(vector)
    ok, reason = check_precondition_consistency(tier, vector, implicit_default_on)
    return GateResult("G5", ok, reason, ["vector=%s score=%.1f %s" % (vector, score, severity)])


def g5_record_valid(record: Any) -> bool:
    """Validate a persisted S6 record before report/ledger promotion."""
    if not isinstance(record, dict) or record.get("blocked"):
        return False
    vector = record.get("vector")
    score = record.get("score")
    g5 = record.get("g5")
    implicit_default_on = record.get("implicit_default_on", False)
    if not isinstance(vector, str) or not vector.strip() or not isinstance(g5, dict):
        return False
    if not isinstance(implicit_default_on, bool):
        return False
    if g5.get("passed") is not True or isinstance(score, bool):
        return False
    try:
        from ..tools.cvss import (base_score, check_impact_consistency,
                                  check_precondition_consistency)
        computed, severity = base_score(vector)
        if not isinstance(score, (int, float)) or not 0.0 <= float(score) <= 10.0:
            return False
        if abs(float(score) - computed) >= 0.11 or record.get("severity") != severity:
            return False
        ac_ok, _ac_reason = check_precondition_consistency(
            str(record.get("tier") or ""), vector,
            implicit_default_on)
        impact_ok, _impact_reason = check_impact_consistency(
            {key: record.get(key, "") for key in
             ("attack_class", "surface", "logic", "hypothesis", "impact")},
            {"availability_proof": record.get("availability_proof", [])},
            vector)
        return ac_ok and impact_ok
    except (OverflowError, TypeError, ValueError):
        return False
