"""CVSS 3.1 base score computation + precondition-consistency gate (G5)."""

from __future__ import annotations

import math
from typing import Optional, Tuple


AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC = {"L": 0.77, "H": 0.44}
PR = {"N": 0.85, "L": 0.62, "H": 0.27}
UI = {"N": 0.85, "R": 0.62}
IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}

# Precondition tier -> allowed AC values (defensible per methodology §6/G5).
# tier "0"      : default-config reachable -> AC:L is required (AC:H would understate)
# tier "single-feature" / "app-type" / "extra-primitive":
#                requires preconditions -> AC:H unless the enabling feature is
#                implicit-default-on (e.g. annotation-driven), which is still a
#                precondition and must stay AC:H in this baseline.
TIER_AC = {
    "0": ["L"],
    "single-feature": ["H"],
    "app-type": ["H"],
    "extra-primitive": ["H"],
}


def _ceil1(x: float) -> float:
    return math.ceil(x * 10.0) / 10.0


def parse_vector(vector: str) -> dict:
    parts = {}
    for token in vector.split("/"):
        if ":" not in token:
            continue
        k, v = token.split(":", 1)
        parts[k] = v
    return parts


def base_score(vector: str) -> Tuple[float, str]:
    m = parse_vector(vector)
    av, ac, pr, ui = AV[m["AV"]], AC[m["AC"]], PR[m["PR"]], UI[m["UI"]]
    c, i, a = IMPACT[m["C"]], IMPACT[m["I"]], IMPACT[m["A"]]
    iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    scope = m.get("S", "U")
    if scope == "U":
        impact = 6.42 * iss
        base = _ceil1(min(impact + 8.22 * av * ac * pr * ui, 10.0))
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)
        base = _ceil1(min(1.08 * (impact + 8.22 * av * ac * pr * ui), 10.0))
    severity = "None" if base == 0 else "Low" if base < 4.0 else "Medium" if base < 7.0 else "High" if base < 9.0 else "Critical"
    return base, severity


def check_precondition_consistency(tier: str, vector: str, implicit_default_on: bool = False) -> Tuple[bool, str]:
    """G5: CVSS AC must match the precondition tier."""
    m = parse_vector(vector)
    allowed = TIER_AC.get(tier, ["H"])
    if implicit_default_on:
        allowed = allowed + ["L"]
    if m.get("AC") not in allowed:
        return False, (
            "AC:%s inconsistent with precondition tier '%s' (allowed AC %s)"
            % (m.get("AC"), tier, "/".join(allowed))
        )
    return True, "AC:%s consistent with precondition tier '%s'" % (m.get("AC"), tier)
