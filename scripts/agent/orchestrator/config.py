"""Target configuration loading (jars, entries, candidates, baselines)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class TargetConfig:
    name: str
    discovery_date: str
    target_type: str = "library"  # library | web-app | middleware | logging | expression | message-rpc | native-app
    target_urls: Dict[str, str] = field(default_factory=dict)  # version -> base URL (web-app S4)
    scope_constraints: str = ""  # project SECURITY.md scope rules, injected into S2/S3 prompts
    upstream_repo: Optional[str] = None
    api_hint: str = ""
    add_exports: List[str] = field(default_factory=list)
    add_opens: List[str] = field(default_factory=list)
    safe_mode_switch: str = "none"  # none | stream-constraints | legacy-jvm-prop
    safe_mode_jvm_prop: str = ""  # if set, matrix emits -D<prop>=true/false
    output_lang: str = "zh"  # "zh" | "en" (ledger/finding output language)
    llm_audit: bool = False  # S5b mechanism audit (LLM) in config-driven pipeline
    fuzzer: Dict[str, Any] = field(default_factory=dict)  # directed fuzz config (plan 2.1)
    # Bounded ordinary-S4 fixture replay/differential evidence.  The adapter
    # is enabled by default and can be disabled per target or candidate when a
    # PoC is intentionally non-repeatable.  An optional ``service`` mapping
    # owns a workspace-local argv-only process with a loopback healthcheck.
    runtime_lab: Dict[str, Any] = field(default_factory=dict)
    # Optional, explicit historical build artifacts for comparison
    # source-revision arms.  This is an artifact adapter only: it never
    # performs checkout or invokes a build command.
    source_revision_artifacts: Dict[str, Any] = field(default_factory=dict)
    public_scan: Dict[str, Any] = field(default_factory=dict)  # internet novelty scan (plan 2.7)
    # Optional, explicitly supplied research-quality feedback.  It only
    # influences S2 prioritisation and experiment checklists; it never changes
    # a candidate conclusion or CVSS value.  A path is resolved relative to the
    # workspace and must contain a benchmark result or feedback artifact.
    benchmark_feedback: Dict[str, Any] = field(default_factory=dict)
    benchmark_feedback_path: Optional[str] = None
    # Optional, explicitly supplied cross-project replay cohort.  It only
    # supplies a bounded research-guidance scheduling policy when the target's
    # own replay history is insufficient; it never changes findings, CVSS, or
    # G4/G5.
    replay_cohort_calibration_path: Optional[str] = None
    jars: List[Dict[str, str]] = field(default_factory=list)
    deps: List[Dict[str, str]] = field(default_factory=list)
    source_dirs: List[str] = field(default_factory=list)
    poc_src_dir: Optional[str] = None
    entry_points: List[Dict[str, Any]] = field(default_factory=list)
    candidates: List[Dict[str, Any]] = field(default_factory=list)
    # Explicit candidate IDs selected before category quotas, within the
    # round's finite slot budget and after runtime-backed pinned candidates.
    priority_candidate_ids: List[str] = field(default_factory=list)
    # Per-round candidate budget (spec §13).  A positive value is the explicit
    # work budget.  ``0`` is accepted as a legacy spelling for the scheduler's
    # finite default; it must never expand into "audit the whole pool" because
    # static evidence inventories can contain tens of thousands of leads.
    max_candidates: int = 8
    # Source-universe enumeration has a bounded wall-clock budget. A timed-out
    # inventory is marked incomplete and prevents later stages from consuming
    # a stale or partial coverage index. Zero disables the limit explicitly.
    coverage_scan_timeout_seconds: int = 600
    # Permit a bounded candidate-only round when S1 coverage is incomplete.
    # Index-derived candidates and coverage-aware scheduling remain disabled,
    # and S8 must keep the coverage closure explicitly incomplete.
    allow_partial_coverage: bool = False
    # Persistent wall-clock cap for the complete config-driven S1-S8 round.
    # Must be between 1 second and 90 minutes; resume never resets the deadline.
    audit_round_timeout_seconds: int = 5400
    # S4 shares a 90-minute round and 15-minute candidate hard maximum across
    # matrix runs and replay/differential lab. These values may lower the caps,
    # never raise them. Expiry preserves completed cells and writes stop-loss rows.
    s4_timeout_seconds: int = 5400
    s4_candidate_timeout_seconds: int = 900
    # Index-derived candidates (spec §11/§12 plus capability paths) enter the
    # round's pool automatically: an unguarded path, sibling control
    # differential, and explicit primitive chain are exactly the "high value
    # candidates" the spec says to promote, and they are
    # derived from persisted indices, not from the model.  Set false to run the
    # pre-PR4 proposal path unchanged -- e.g. to compare a round with and
    # without them.
    static_candidates: bool = True
    exclusions: List[Dict[str, Any]] = field(default_factory=list)
    baselines: List[Dict[str, Any]] = field(default_factory=list)
    notes: str = ""

    @classmethod
    def load(cls, path: Path) -> "TargetConfig":
        data = json.loads(path.read_text(encoding="utf-8"))
        kwargs = {}
        for name, f in cls.__dataclass_fields__.items():
            if name in data:
                kwargs[name] = data[name]
        return cls(**kwargs)

    def resolve_jars(self, workspace: Path) -> Dict[str, List[Path]]:
        out: Dict[str, List[Path]] = {}
        for j in self.jars:
            p = (workspace / j["path"]).resolve()
            out.setdefault(j["version"], []).append(p)
        for dep in self.deps:
            p = (workspace / dep["path"]).resolve()
            if dep.get("version"):
                if dep["version"] in out:
                    out[dep["version"]].append(p)
            else:
                for version_jars in out.values():
                    version_jars.append(p)
        return out

    def resolve_source_revision_artifacts(self, workspace: Path) -> Dict[str, Any]:
        """Validate operator-supplied historical artifacts for S4 only."""
        from ..tools.source_revisions import resolve_source_revision_artifacts

        return resolve_source_revision_artifacts(
            workspace, self.source_revision_artifacts)
