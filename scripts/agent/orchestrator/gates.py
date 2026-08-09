"""Hard gates G0-G5 as verifiable decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..tools.conclusion import _is_runtime_evidence


@dataclass
class GateResult:
    gate_id: str
    passed: bool
    verdict: str
    evidence: List[str] = None  # type: ignore


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


def g4_runtime(summary: Dict[str, Any], intended: str = "确认") -> GateResult:
    instantiated = summary.get("instantiated", [])
    errors = summary.get("errors", [])
    gate_blocked = summary.get("gate_blocked", [])
    leaked = summary.get("leaked", [])
    if intended == "排除":
        if gate_blocked or errors:
            return GateResult("G4", True, "exclusion backed by runtime", ["gate_blocked=%d errors=%d" % (len(gate_blocked), len(errors))])
        return GateResult("G4", False, "exclusion without runtime evidence", [])
    if intended == "确认":
        if instantiated:
            return GateResult("G4", True, "runtime instantiation observed",
                              ["instantiated=%s" % ", ".join(i["class"] for i in instantiated)])
        if leaked:
            return GateResult("G4", True, "runtime content-leakage observed",
                              ["leaked=%s" % ", ".join(i["leaked"][:80] for i in leaked[:3])])
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
