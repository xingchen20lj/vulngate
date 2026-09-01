"""Structured authorization-context cells and local assertion helpers.

The matrix carries identity *metadata* only.  Credentials, cookies and tokens
are deliberately not accepted by this module; a local PoC may resolve those
through the researcher's own fixture/runtime, but they never enter artifacts.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


_SAFE_FIELDS = (
    "case_id", "principal", "role", "tenant_id", "object_id",
    "object_tenant_id", "expected_http_codes", "expected_object_mutated",
    "expected_authz",
)
_DENY_CODES = {401, 403}


def _text(value: Any, max_len: int = 160) -> str:
    """Return a bounded, single-line metadata value."""
    if value is None:
        return ""
    return " ".join(str(value).replace("\x00", "").split())[:max_len]


def _bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        value = value.strip().lower()
        if value in {"true", "yes", "1", "allow", "allowed"}:
            return True
        if value in {"false", "no", "0", "deny", "denied"}:
            return False
    return None


def normalize_authz_case(case: Any, index: int = 0) -> Dict[str, Any]:
    """Whitelist and normalize one authz case without retaining secrets."""
    if not isinstance(case, dict):
        return {}
    out: Dict[str, Any] = {}
    for key in _SAFE_FIELDS:
        if key not in case:
            continue
        value = case[key]
        if key in {"case_id", "principal", "role", "tenant_id", "object_id",
                   "object_tenant_id"}:
            text = _text(value)
            if text:
                out[key] = text
        elif key == "expected_http_codes":
            values = value if isinstance(value, (list, tuple, set)) else [value]
            codes: List[int] = []
            for item in values:
                try:
                    code = int(item)
                except (TypeError, ValueError):
                    continue
                if 100 <= code <= 599 and code not in codes:
                    codes.append(code)
            if codes:
                out[key] = codes
        elif key == "expected_object_mutated":
            parsed = _bool(value)
            if parsed is not None:
                out[key] = parsed
        elif key == "expected_authz":
            text = _text(value, 24).lower()
            if text in {"allow", "deny"}:
                out[key] = text
    if not out:
        return {}
    if "case_id" not in out:
        out["case_id"] = "authz-%02d" % (index + 1)
    return out


def normalize_authz_cases(cases: Any) -> List[Dict[str, Any]]:
    if not isinstance(cases, list):
        cases = [cases] if isinstance(cases, dict) else []
    normalized = []
    for index, case in enumerate(cases):
        item = normalize_authz_case(case, index)
        if item:
            normalized.append(item)
    return normalized


def authz_env(case: Any) -> Dict[str, str]:
    """Build the non-secret environment contract exposed to a local PoC."""
    item = normalize_authz_case(case)
    mapping = {
        "case_id": "VULNGATE_AUTHZ_CASE",
        "principal": "VULNGATE_AUTHZ_PRINCIPAL",
        "role": "VULNGATE_AUTHZ_ROLE",
        "tenant_id": "VULNGATE_AUTHZ_TENANT",
        "object_id": "VULNGATE_AUTHZ_OBJECT",
        "object_tenant_id": "VULNGATE_AUTHZ_OBJECT_TENANT",
        "expected_authz": "VULNGATE_AUTHZ_EXPECTED",
    }
    out = {env: str(item[key]) for key, env in mapping.items() if item.get(key)}
    if item.get("expected_http_codes"):
        out["VULNGATE_AUTHZ_EXPECTED_HTTP_CODES"] = ",".join(
            str(code) for code in item["expected_http_codes"])
    if "expected_object_mutated" in item:
        out["VULNGATE_AUTHZ_EXPECTED_OBJECT_MUTATED"] = (
            "true" if item["expected_object_mutated"] else "false")
    return out


def authz_jvm_props(case: Any) -> List[str]:
    """Build JVM properties for Java PoCs; values contain no credentials."""
    item = normalize_authz_case(case)
    mapping = {
        "case_id": "case", "principal": "principal", "role": "role",
        "tenant_id": "tenant", "object_id": "object",
        "object_tenant_id": "object-tenant", "expected_authz": "expected",
    }
    out = ["-Dvulngate.authz.%s=%s" % (prop, item[key])
           for key, prop in mapping.items() if item.get(key)]
    if item.get("expected_http_codes"):
        out.append("-Dvulngate.authz.expected-http-codes=" + ",".join(
            str(code) for code in item["expected_http_codes"]))
    if "expected_object_mutated" in item:
        out.append("-Dvulngate.authz.expected-object-mutated=" + (
            "true" if item["expected_object_mutated"] else "false"))
    return out


def _observed_bool(value: Any) -> Optional[bool]:
    return _bool(value)


def assert_authz_observations(case: Any, observations: Dict[str, Any]) -> Dict[str, Any]:
    """Compare observed PoC markers with the declared authorization contract.

    This is a harness assertion, not a vulnerability verdict.  A boundary
    violation is flagged only when a deny/ownership invariant is contradicted
    by an observed allow, successful response, or mutation marker.
    """
    expected = normalize_authz_case(case)
    if not expected:
        return {"status": "not_applicable", "boundary_violation": False}
    obs = observations or {}
    checks: List[Dict[str, Any]] = []
    missing: List[str] = []
    mismatch: List[str] = []
    boundary = False

    codes = expected.get("expected_http_codes")
    if codes:
        raw = str(obs.get("HTTP_CODE", "")).strip()
        if raw.isdigit():
            actual = int(raw)
            ok = actual in codes
            checks.append({"field": "HTTP_CODE", "expected": codes,
                           "observed": actual, "ok": ok})
            if not ok:
                mismatch.append("HTTP_CODE expected %s observed %s" % (codes, actual))
            if any(code in _DENY_CODES for code in codes) and 200 <= actual < 300:
                boundary = True
        else:
            missing.append("HTTP_CODE")

    if "expected_object_mutated" in expected:
        raw = obs.get("OBJECT_MUTATED")
        actual = _observed_bool(raw)
        if actual is None:
            missing.append("OBJECT_MUTATED")
        else:
            want = expected["expected_object_mutated"]
            ok = actual == want
            checks.append({"field": "OBJECT_MUTATED", "expected": want,
                           "observed": actual, "ok": ok})
            if not ok:
                mismatch.append("OBJECT_MUTATED expected %s observed %s" % (want, actual))
            if want is False and actual is True:
                boundary = True

    if expected.get("expected_authz"):
        actual = _text(obs.get("AUTHZ_RESULT"), 24).lower()
        if actual not in {"allow", "deny"}:
            missing.append("AUTHZ_RESULT")
        else:
            want = expected["expected_authz"]
            ok = actual == want
            checks.append({"field": "AUTHZ_RESULT", "expected": want,
                           "observed": actual, "ok": ok})
            if not ok:
                mismatch.append("AUTHZ_RESULT expected %s observed %s" % (want, actual))
            if want == "deny" and actual == "allow":
                boundary = True

    if mismatch:
        status = "failed"
    elif missing:
        status = "unsupported"
    elif checks:
        status = "passed"
    else:
        status = "unsupported"
    return {"case_id": expected.get("case_id"), "status": status,
            "boundary_violation": boundary, "expected": expected,
            "checks": checks, "missing": missing, "mismatch": mismatch}


def authz_case_label(case: Any) -> str:
    item = normalize_authz_case(case)
    if not item:
        return "none"
    return "%s/%s/%s/%s" % (
        item.get("case_id", "case"), item.get("principal", "?"),
        item.get("role", "?"), item.get("tenant_id", "?"))
