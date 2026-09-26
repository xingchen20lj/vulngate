"""Quota selection, residual sweep, and schedule construction."""

from __future__ import annotations

# Shared scheduler state is centralized in common.py; this keeps phase imports
# explicit at the package boundary while retaining a small compatibility API.
# ruff: noqa: F403,F405
from .common import *
from .common import _coverage_scope_blocker
from .intake import *
from .intake import _research_strategy_snapshot, _threat_model_snapshot
from .scoring import *

@dataclass
class SchedulePlan:
    round_no: int = 0
    slots: int = 0
    selected: List[CandidateScore] = field(default_factory=list)
    deferred: List[CandidateScore] = field(default_factory=list)
    requested_quota: Dict[str, int] = field(default_factory=dict)
    filled_quota: Dict[str, int] = field(default_factory=dict)
    relocated_quota: Dict[str, int] = field(default_factory=dict)
    category_counts: Dict[str, int] = field(default_factory=dict)
    coverage: Dict[str, Any] = field(default_factory=dict)
    residual: Dict[str, Any] = field(default_factory=dict)
    weights: Dict[str, int] = field(default_factory=dict)
    benchmark_feedback: Dict[str, Any] = field(default_factory=dict)
    research_portfolio: Dict[str, Any] = field(default_factory=dict)
    research_strategy: Dict[str, Any] = field(default_factory=dict)
    research_agenda: Dict[str, Any] = field(default_factory=dict)
    threat_model: Dict[str, Any] = field(default_factory=dict)
    weight_adjustments: Dict[str, int] = field(default_factory=dict)
    #: Candidates selected outside the quota because they carry runtime
    #: evidence the static score cannot see (see :func:`stratified_select`).
    pinned: List[str] = field(default_factory=list)
    #: Candidates selected first within the slot budget by explicit operator
    #: priority. They remain subject to the round width and runtime pins.
    priority_candidate_ids: List[str] = field(default_factory=list)
    requested_priority_candidate_ids: List[str] = field(default_factory=list)
    deferred_priority_candidate_ids: List[str] = field(default_factory=list)

    def selected_ids(self) -> List[str]:
        return [s.candidate_id for s in self.selected]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "round": self.round_no,
            "slots": self.slots,
            "weights": dict(self.weights),
            "weight_adjustments": dict(self.weight_adjustments),
            "benchmark_feedback": self.benchmark_feedback,
            "research_portfolio": self.research_portfolio,
            "research_strategy": _research_strategy_snapshot(
                self.research_strategy, item_limit=32),
            "research_agenda": self.research_agenda,
            "threat_model": _threat_model_snapshot(self.threat_model),
            "selected": [s.as_dict() for s in self.selected],
            "deferred": [s.as_dict() for s in self.deferred],
            "pinned": list(self.pinned),
            "priority_candidate_ids": list(self.priority_candidate_ids),
            "requested_priority_candidate_ids": list(
                self.requested_priority_candidate_ids),
            "deferred_priority_candidate_ids": list(
                self.deferred_priority_candidate_ids),
            "quota": {
                "requested": dict(self.requested_quota),
                "filled": dict(self.filled_quota),
                "relocated": {k: v for k, v in self.relocated_quota.items() if v},
            },
            "category_counts": dict(self.category_counts),
            "coverage": self.coverage,
            "residual": self.residual,
            "selected_ids": self.selected_ids(),
            "deferred_ids": [s.candidate_id for s in self.deferred],
            "producer": "scheduler",
            "confidence": "heuristic",
            "evidence_type": "static-inferred",
        }


def stratified_select(scores: Sequence[CandidateScore], slots: int,
                      quota: Optional[Dict[str, int]] = None,
                      pinned: Sequence[str] = (),
                      priority_ids: Sequence[str] = ()
                      ) -> Tuple[List[CandidateScore], List[CandidateScore],
                                 Dict[str, int], Dict[str, int], Dict[str, int]]:
    """Fill per-category quota, then relocate whatever could not be filled.

    Returns ``(selected, deferred, requested, filled, relocated)``.

    Spec §13.3: "如果某类别不存在则动态转移配额".  Relocation means an unfilled
    slot is given to the globally highest-scoring candidate that has not been
    taken yet -- so the round is always ``min(slots, len(scores))`` wide, and the
    relocation is reported per category rather than disappearing.

    ``residual`` is an ordinary bucket here: spec §13.3 reserves a slot for
    candidates derived from the residual sweep, and the residual sweep tags them
    ``category="residual"``.  Treating it as a bucket rather than a special case
    means the reserved slot is filled when such a candidate exists and *reported
    as relocated* when it does not -- the two alternatives are silently spending
    the slot on something else, or losing the round width.

    ``pinned`` ids are selected first, in the order given, outside the quota and
    against the slot budget.  This exists for candidates carrying runtime
    evidence (a fuzz reproducer with a crash dump): the scheduler's factors are
    all static, so letting it drop one in favour of a better-scoring static
    candidate would discard the strongest evidence in the round.  Pinning is
    reported in the plan, and pinning more ids than ``slots`` truncates rather
    than over-filling.

    Explicit operator priorities are selected after runtime pins but before
    category quotas. They consume the same finite slot budget; any remaining
    slots are filled by the ordinary category-stratified scheduler.
    """
    quota = dict(quota if quota is not None else DEFAULT_QUOTA)
    slots = max(0, int(slots))
    by_category: Dict[str, List[CandidateScore]] = {}
    for score in scores:
        by_category.setdefault(score.category, []).append(score)

    taken: set = set()
    selected: List[CandidateScore] = []
    filled: Dict[str, int] = {category: 0 for category in quota}
    by_id = {s.candidate_id: s for s in scores}
    for candidate_id in pinned:
        score = by_id.get(str(candidate_id))
        if score is None or score.candidate_id in taken:
            continue
        if len(selected) >= slots:
            break
        selected.append(score)
        taken.add(score.candidate_id)

    for candidate_id in priority_ids:
        score = by_id.get(str(candidate_id))
        if score is None or score.candidate_id in taken:
            continue
        if len(selected) >= slots:
            break
        selected.append(score)
        taken.add(score.candidate_id)
        if score.category in filled and filled[score.category] < max(
                0, int(quota.get(score.category, 0))):
            filled[score.category] += 1

    # 1. quota categories, in the declared order
    for category in quota:
        want = max(0, int(quota[category]))
        remaining_quota = max(0, want - filled.get(category, 0))
        available = [s for s in by_category.get(category, ())
                     if s.candidate_id not in taken]
        got = 0
        for score in available[:remaining_quota]:
            if len(selected) >= slots:
                break
            selected.append(score)
            taken.add(score.candidate_id)
            got += 1
        filled[category] = filled.get(category, 0) + got

    # 2. relocate unfilled quota, then spend any remaining slots
    remaining = [s for s in scores if s.candidate_id not in taken]
    for score in remaining:
        if len(selected) >= slots:
            break
        selected.append(score)
        taken.add(score.candidate_id)

    relocated: Dict[str, int] = {}
    for category, want in quota.items():
        shortfall = max(0, int(want)) - filled.get(category, 0)
        if shortfall:
            relocated[category] = shortfall

    pinned_order = {str(candidate_id): index
                    for index, candidate_id in enumerate(pinned)}
    priority_order = {str(candidate_id): index
                      for index, candidate_id in enumerate(priority_ids)}
    selected.sort(key=lambda score: (
        0 if score.candidate_id in pinned_order else
        1 if score.candidate_id in priority_order else 2,
        pinned_order.get(score.candidate_id, 0),
        priority_order.get(score.candidate_id, 0),
        -score.total, score.candidate_id))
    deferred = [s for s in scores if s.candidate_id not in taken]
    return selected, deferred, quota, filled, relocated


# ---------------------------------------------------------------------------
# residual sweep (spec §14)
# ---------------------------------------------------------------------------

def residual_sweep(store: CoverageStore, workspace: Path, target: str,
                   round_no: int = 0) -> Dict[str, Any]:
    """Recompute the uncovered regions and coverage summary for the next round.

    Spec §14 requires this after every round.  It goes through
    :func:`agent.analysis.coverage.refresh_candidate_coverage`, so the review
    state is re-derived from the round ledgers (the durable record of what was
    decided) before the gaps are recomputed.
    """
    info = cov.refresh_candidate_coverage(store, workspace, target, round_no or None)
    summary = store.read("coverage-summary") or {}
    regions = summary.get("uncovered_regions") or []
    kinds = Counter(str(r.get("kind")) for r in regions)
    risks = Counter(str(r.get("risk")) for r in regions)
    return {
        "round": round_no,
        "metrics": summary.get("metrics", {}),
        "acceptance": summary.get("acceptance", {}),
        "high_risk_uncovered": summary.get("high_risk_uncovered", 0),
        "stop_condition_met": summary.get("stop_condition_met", False),
        "regions": len(regions),
        "regions_by_kind": dict(sorted(kinds.items())),
        "regions_by_risk": dict(sorted(risks.items())),
        "refresh": info,
    }


# ---------------------------------------------------------------------------
# top level
# ---------------------------------------------------------------------------

class CoverageScopeUnavailable(RuntimeError):
    """Raised when persisted indices cannot support coverage-based ranking."""

def build_schedule(workspace: Path, target: str,
                   candidates: Sequence[Dict[str, Any]],
                   slots: int = DEFAULT_SLOTS,
                   quota: Optional[Dict[str, int]] = None,
                   weights: Optional[Dict[str, int]] = None,
                   round_no: int = 0,
                   refresh: bool = True,
                   pinned: Sequence[str] = (),
                   benchmark_feedback: Optional[Dict[str, Any]] = None,
                   priority_ids: Sequence[str] = ()
                   ) -> SchedulePlan:
    """Score, dedupe and select this round's candidates.

    Writes ``state/<target>/coverage/schedule-round-NN.json`` (and
    ``schedule-latest.json``) so the decision is reproducible and reviewable
    after the fact.  Returns the plan; it never mutates ``candidates``.
    ``pinned`` ids are always selected -- see :func:`stratified_select`.
    """
    workspace = Path(workspace).resolve()
    store = CoverageStore(workspace, target)
    scope_blocker = _coverage_scope_blocker(
        store, check_coverage_summary=not refresh)
    if scope_blocker:
        raise CoverageScopeUnavailable(scope_blocker)
    from ..evidence_provenance import enrich_candidates, load_evidence_provenance

    candidates = enrich_candidates(candidates, load_evidence_provenance(store))
    # Order matters: the sweep must run *before* the context is loaded, or the
    # scores are computed against the previous round's coverage and this round
    # re-picks exactly the same candidates.  The sweep doubles as the scoring
    # input and as spec §14's post-round gap recomputation -- one refresh, and
    # the residual recorded on the plan is the one the scores were based on.
    coverage: Dict[str, Any] = {}
    if refresh:
        coverage = residual_sweep(store, workspace, target, round_no)
    memory = load_research_memory(workspace, target)
    portfolio = load_research_portfolio(workspace, target)
    threat_model = load_threat_model(workspace, target)
    prior_strategy = load_research_strategy(workspace, target)
    research_agenda = load_research_agenda(workspace, target)
    # Replay calibration is an optional, bounded research-only input.  Keep
    # the import local so the scheduler's analysis imports do not create a
    # cycle through the evaluation package during CLI startup.
    from ...evaluation.replay_calibration import load_replay_calibration

    prior_replay_calibration = load_replay_calibration(workspace, target)
    target_type = str(threat_model.get("target_type") or "")
    strategy = build_research_strategy(
        threat_model=threat_model,
        research_portfolio=portfolio,
        research_memory=memory.get("entries") or [],
        benchmark_feedback=benchmark_feedback,
        target=target,
        target_type=target_type,
        round_no=round_no,
        prior_strategy=prior_strategy,
    )
    review_feedback = load_review_feedback(workspace, target)
    if strategy:
        strategy, _research_guidance = apply_research_guidance(
            strategy, portfolio, review_feedback, round_no,
            replay_calibration=prior_replay_calibration)
        write_research_guidance(workspace, target, _research_guidance)
    write_research_strategy(workspace, target, strategy)
    ctx = ScheduleContext.from_store(
        store, weights, research_memory=memory.get("entries") or [],
        benchmark_feedback=benchmark_feedback,
        research_portfolio=portfolio, research_strategy=strategy,
        research_agenda=research_agenda,
        threat_model=threat_model)
    scores = score_candidates(candidates, ctx)
    priority_ids = normalize_candidate_ids(priority_ids)
    selected, deferred, requested, filled, relocated = stratified_select(
        scores, slots, quota, pinned, priority_ids)
    # ``refresh=False`` is used when the caller recomputes coverage itself; the
    # plan then records that the residual was *not* measured rather than
    # reporting ``0`` uncovered -- an absent measurement must not read as "clean".
    residual = {
        "high_risk_uncovered": coverage.get("high_risk_uncovered"),
        "regions_by_kind": coverage.get("regions_by_kind"),
        "stop_condition_met": coverage.get("stop_condition_met"),
        "measured": bool(refresh),
    }
    selected_ids = {s.candidate_id for s in selected}
    pinned_ids = {str(cid) for cid in pinned}
    selected_priority_ids = [
        candidate_id for candidate_id in priority_ids
        if candidate_id in selected_ids and candidate_id not in pinned_ids]
    plan = SchedulePlan(
        round_no=round_no, slots=slots, selected=selected, deferred=deferred,
        requested_quota=requested, filled_quota=filled,
        relocated_quota=relocated,
        category_counts=dict(sorted(Counter(s.category for s in selected).items())),
        coverage=coverage,
        residual=residual,
        weights=dict(ctx.weights),
        benchmark_feedback=dict(ctx.benchmark_feedback),
        research_portfolio=dict(ctx.research_portfolio),
        research_strategy=dict(ctx.research_strategy),
        research_agenda=dict(ctx.research_agenda),
        threat_model=dict(ctx.threat_model),
        weight_adjustments=dict(ctx.weight_adjustments),
        pinned=[str(cid) for cid in pinned if str(cid) in selected_ids],
        priority_candidate_ids=selected_priority_ids,
        requested_priority_candidate_ids=priority_ids,
        deferred_priority_candidate_ids=[
            candidate_id for candidate_id in priority_ids
            if candidate_id not in selected_ids],
    )
    payload = plan.as_dict()
    store.ensure()
    store.write("schedule-round-%02d" % round_no, payload)
    store.write("schedule-latest", payload)
    return plan
