"""One parent-owned budget for all finite audit work.

The existing pipeline has several historical timeout objects.  ``WorkBudget``
is the common resource ledger they can share: children may narrow a parent
window and consume parent-owned counters, but cannot mint a new wall-clock,
candidate, process, scan or LLM allowance.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional


RESOURCE_NAMES = (
    "scan_bytes", "scan_files", "process_slots", "llm_calls",
    "candidate_slots", "memory_bytes",
)


class WorkBudgetExceeded(RuntimeError):
    """Raised when a child tries to exceed its own or its parent's budget."""


@dataclass(frozen=True)
class BudgetLimits:
    wall_seconds: Optional[float] = None
    scan_bytes: Optional[int] = None
    scan_files: Optional[int] = None
    process_slots: Optional[int] = None
    llm_calls: Optional[int] = None
    candidate_slots: Optional[int] = None
    memory_bytes: Optional[int] = None

    def as_dict(self) -> Dict[str, Optional[float]]:
        return {
            "wall_seconds": self.wall_seconds,
            "scan_bytes": self.scan_bytes,
            "scan_files": self.scan_files,
            "process_slots": self.process_slots,
            "llm_calls": self.llm_calls,
            "candidate_slots": self.candidate_slots,
            "memory_bytes": self.memory_bytes,
        }


def _counter(value: Any, field: str) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("%s must be a non-negative integer or null" % field)
    return int(value)


class WorkBudget:
    """Thread-safe, monotonic budget with bounded child scopes."""

    def __init__(self, *, wall_seconds: Optional[float] = None,
                 scan_bytes: Optional[int] = None,
                 scan_files: Optional[int] = None,
                 process_slots: Optional[int] = None,
                 llm_calls: Optional[int] = None,
                 candidate_slots: Optional[int] = None,
                 memory_bytes: Optional[int] = None,
                 name: str = "root", parent: Optional["WorkBudget"] = None,
                 clock: Callable[[], float] = time.monotonic):
        if wall_seconds is not None and float(wall_seconds) <= 0:
            raise ValueError("wall_seconds must be positive or null")
        self.name = str(name or "budget")[:120]
        self.parent = parent
        self._clock = clock
        self._lock = threading.RLock()
        self._limits = BudgetLimits(
            wall_seconds=None if wall_seconds is None else float(wall_seconds),
            scan_bytes=_counter(scan_bytes, "scan_bytes"),
            scan_files=_counter(scan_files, "scan_files"),
            process_slots=_counter(process_slots, "process_slots"),
            llm_calls=_counter(llm_calls, "llm_calls"),
            candidate_slots=_counter(candidate_slots, "candidate_slots"),
            memory_bytes=_counter(memory_bytes, "memory_bytes"),
        )
        self._used = {resource: 0 for resource in RESOURCE_NAMES}
        now = self._clock()
        parent_deadline: Optional[float] = (
            parent._deadline if parent is not None else None)
        own_deadline: Optional[float] = (
            None if self._limits.wall_seconds is None
            else now + self._limits.wall_seconds)
        if own_deadline is None:
            self._deadline = parent_deadline
        elif parent_deadline is None:
            self._deadline = own_deadline
        else:
            self._deadline = min(own_deadline, parent_deadline)

    @property
    def limits(self) -> BudgetLimits:
        return self._limits

    def _parent_remaining(self, resource: str) -> Optional[float]:
        if self.parent is None:
            return None
        return self.parent.remaining(resource)

    def remaining(self, resource: str) -> Optional[float]:
        resource = str(resource)
        if resource == "wall_seconds":
            if self._deadline is None:
                return None
            return max(0.0, self._deadline - self._clock())
        if resource not in RESOURCE_NAMES:
            raise ValueError("unknown work-budget resource: %s" % resource)
        limit = getattr(self._limits, resource)
        own = None if limit is None else max(0, limit - self._used[resource])
        parent = self._parent_remaining(resource)
        if own is None:
            return parent
        if parent is None:
            return own
        return min(own, parent)

    def available(self, resource: str, amount: int = 1) -> bool:
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
            raise ValueError("budget amount must be a non-negative integer")
        remaining = self.remaining(resource)
        return remaining is None or remaining >= amount

    def consume(self, resource: str, amount: int = 1) -> None:
        resource = str(resource)
        if resource == "wall_seconds":
            raise ValueError("wall_seconds is elapsed, not a consumable counter")
        if not self.available(resource, amount):
            raise WorkBudgetExceeded(
                "%s budget exhausted for %s (requested=%s remaining=%s)" %
                (self.name, resource, amount, self.remaining(resource)))
        if self.parent is not None:
            self.parent.consume(resource, amount)
        with self._lock:
            self._used[resource] += amount

    def acquire_candidate(self) -> None:
        self.consume("candidate_slots", 1)

    def acquire_process(self) -> None:
        self.consume("process_slots", 1)

    def record_llm_call(self) -> None:
        self.consume("llm_calls", 1)

    def record_scan(self, *, files: int = 0, bytes_read: int = 0) -> None:
        if files:
            self.consume("scan_files", int(files))
        if bytes_read:
            self.consume("scan_bytes", int(bytes_read))

    def child(self, name: str, **requested: Any) -> "WorkBudget":
        unknown = set(requested) - set(BudgetLimits.__dataclass_fields__)
        if unknown:
            raise ValueError("unknown child budget field(s): %s" %
                             ", ".join(sorted(unknown)))
        values: Dict[str, Any] = {}
        for field in BudgetLimits.__dataclass_fields__:
            value = requested.get(field)
            if value is None:
                continue
            if field == "wall_seconds":
                if float(value) <= 0:
                    raise ValueError("wall_seconds must be positive")
                parent_left = self.remaining("wall_seconds")
                values[field] = (float(value) if parent_left is None else
                                 min(float(value), parent_left))
            else:
                value = _counter(value, field)
                parent_left = self.remaining(field)
                values[field] = (value if parent_left is None else
                                 min(value, int(parent_left)))
        return WorkBudget(name=name, parent=self, clock=self._clock, **values)

    def check(self) -> None:
        remaining = self.remaining("wall_seconds")
        if remaining is not None and remaining <= 0:
            raise WorkBudgetExceeded("%s wall budget exhausted" % self.name)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "schema_version": "work-budget-v1",
            "name": self.name,
            "limits": self._limits.as_dict(),
            "used": dict(self._used),
            "remaining": {
                resource: self.remaining(resource)
                for resource in ("wall_seconds",) + RESOURCE_NAMES
            },
            "wall_deadline_monotonic": self._deadline,
            "parent": self.parent.name if self.parent is not None else "",
            "claim_status": "not-a-finding",
        }
