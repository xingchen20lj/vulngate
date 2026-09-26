"""Compatibility facade for the autonomous audit phases.

The implementation is split into preparation, scheduling, execution, and
reporting modules.  This module intentionally keeps the historic import and
module CLI surface stable for integrations and existing audit scripts.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional

from . import common as _common
from . import preparation as _preparation
from . import scheduling as _scheduling
from . import execution as _execution
from . import reporting as _reporting

from .common import *  # noqa: F403,F405
from .preparation import (  # noqa: F401
    TargetPreparationTimeout,
    prepare_target,
    scan_all_entries,
    scan_all_http_entries,
    scan_entries,
    scan_http_entries,
)
from .scheduling import (  # noqa: F401
    _attach_experiment_plans,
    _coverage_prompt_block,
    _current_coverage_scope,
    learn_api_hint,
    propose_candidates,
    schedule_candidates as _schedule_candidates_impl,
    static_candidates as _static_candidates_impl,
)
from .execution import (  # noqa: F401
    audit_candidate,
    build_cells,
    cvss_for_tier,
    extract_java_code,
    extract_shell_code,
    generate_poc,
    generate_shell_poc,
    mechanism_audit,
    novelty_check,
    poc_consistency,
    repair_poc,
    repair_shell_poc,
    verify_candidate,
)
from .reporting import (  # noqa: F401
    _evidence_lines,
    _evidence_text,
    _propose_next,
    _repro_text,
    main,
    run_loop,
    run_round as _run_round_impl,
)

# Compatibility aliases expected by older callers.
ROOT = _common.ROOT
AutoCtx = _common.AutoCtx
scan_s1_source_rules = _common.scan_s1_source_rules
_ensure_capability_inventory_impl = _preparation._ensure_capability_inventory


def _sync_compatibility_patches() -> None:
    """Forward monkeypatches on the legacy facade into phase globals."""
    _scheduling._current_coverage_scope = globals().get(
        "_current_coverage_scope", _scheduling._current_coverage_scope)
    _scheduling._ensure_capability_inventory = globals().get(
        "_ensure_capability_inventory", _preparation._ensure_capability_inventory)
    _reporting._ensure_capability_inventory = globals().get(
        "_ensure_capability_inventory", _preparation._ensure_capability_inventory)
    _reporting.scan_s1_source_rules = globals().get(
        "scan_s1_source_rules", _common.scan_s1_source_rules)


def _ensure_capability_inventory(
        ctx: AutoCtx, *, allow_rebuild: bool = True,
        rebuild_budget_seconds: Optional[int] = None,
        reason: str = "") -> Dict[str, Any]:
    """Legacy entrypoint delegating to the preparation phase."""
    return _ensure_capability_inventory_impl(
        ctx, allow_rebuild=allow_rebuild,
        rebuild_budget_seconds=rebuild_budget_seconds)


def schedule_candidates(ctx: AutoCtx, round_no: int,
                        candidates: List[Dict[str, Any]],
                        pinned: Optional[List[str]] = None):
    _sync_compatibility_patches()
    return _schedule_candidates_impl(ctx, round_no, candidates, pinned)


def static_candidates(ctx: AutoCtx, round_no: Optional[int] = None):
    _sync_compatibility_patches()
    return _static_candidates_impl(ctx, round_no)


def run_round(ctx: AutoCtx, round_no: int):
    _sync_compatibility_patches()
    return _run_round_impl(ctx, round_no)


if __name__ == "__main__":
    sys.exit(main())
