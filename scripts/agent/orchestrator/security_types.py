"""Typed values shared by security decision and artifact boundaries."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Mapping, Optional


class ExecutionState(str, Enum):
    UNEXECUTED = "unexecuted"
    EXECUTED_WITH_EFFECT = "executed-with-effect"
    EXECUTED_NO_EFFECT = "executed-no-effect"
    RUN_FAILED = "run-failed"
    GATE_BLOCKED = "gate-blocked"
    TIMED_OUT = "timebox-exhausted"
    PARTIAL_MATRIX = "partial-matrix"
    PRECONDITION_UNAVAILABLE = "precondition-unavailable"
    NEEDS_HARNESS_OBSERVER = "needs-harness-observer"


class StopReason(str, Enum):
    S4_ABORTED = "s4-aborted"
    ROUND_TIMEBOX_EXHAUSTED = "s4-round-timebox-exhausted"
    CANDIDATE_TIMEBOX_EXHAUSTED = "candidate-timebox-exhausted"


@dataclass(frozen=True)
class IsolationState:
    """Serializable backend capability state; never an authorization grant."""

    backend: str
    version: str
    available: bool
    network: str
    filesystem: str
    reason: str = ""
    capabilities: tuple[str, ...] = ()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": "isolation-backend-v1",
            "backend": self.backend,
            "version": self.version,
            "available": self.available,
            "network": self.network,
            "filesystem": self.filesystem,
            "reason": self.reason,
            "capabilities": list(self.capabilities),
        }


@dataclass(frozen=True)
class ArtifactEnvelope:
    """Typed view over an artifact's common envelope fields."""

    schema_version: str
    claim_status: Optional[str] = None
    payload: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any], *, schema_version: str
                     ) -> "ArtifactEnvelope":
        return cls(
            schema_version=schema_version,
            claim_status=(str(value["claim_status"])
                          if "claim_status" in value else None),
            payload=dict(value),
        )

    def as_dict(self) -> Dict[str, Any]:
        result = dict(self.payload)
        result["schema_version"] = self.schema_version
        if self.claim_status is not None:
            result["claim_status"] = self.claim_status
        return result
