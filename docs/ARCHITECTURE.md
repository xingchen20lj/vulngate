# Architecture

> Codex 1.1.0 adds coverage, call graphs, control gaps, sibling differentials, candidate scheduling and macOS support. See [feature evolution and commands](EVOLUTION.md). Use an independent `--workspace` for audit artifacts.

**Language:** English | [简体中文](ARCHITECTURE.zh-CN.md)

VulnGate is a thin native plugin around a deterministic research framework. The
design principle: **the host Codex agent decides; the bundled code computes.**

## Components

```
┌─────────────────────────────────────────────────────────────┐
│ Codex (CLI or desktop app)                                  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Host agent (main agent)                               │  │
│  │  · owns reasoning: candidates, audit, judgments       │  │
│  │  · owns parallelism: spawns sub-agents (S4/S5)        │  │
│  └───────────────┬───────────────────────────────────────┘  │
│                  │ skill: vulngate-audit (SKILL.md)        │
└──────────────────┼─────────────────────────────────────────┘
                   ▼
        bundled deterministic CLI (scripts/)
        · agent_cli.py: source-map / source-evidence / matrix /
          novelty / cvss / ledger / doctor
        · scripts/agent/: framework (gates, runner, novelty, cvss)
```

## The skill is the contract

`skills/vulngate-audit/SKILL.md` is the execution manual given to the host agent.
It defines:

- the S1→S8 stage sequence and their artifacts;
- the G0–G5 hard gates and what each one blocks;
- the evidence contract (machine-readable observations drive conclusions);
- the safety model (loopback-only, approval logging, no pre-fix disclosure);
- the precondition-tier → CVSS mapping.

The source inventory also persists a semantic path evidence layer. It checks
whether a path control is before the sink in the same lexical scope and runs a
bounded same-symbol parameter/alias walk. `semantic-path-evidence.json`
distinguishes `direct`, `propagated`, `not-traced`, and
`cross-symbol-unresolved` data-flow states; its control rows distinguish
`before-sink`, `after-sink`, `same-line`, and `cross-symbol-unverified`.
This is not branch-dominance, type, virtual-dispatch, DI, reflection,
callback, or sanitizer-semantic proof. It does not copy source text, and all
rows and derived candidates remain `claim_status=not-a-finding` for S2/S3/S4
follow-up.

The next bounded layer is `semantic-guard-evidence-v1`. It derives two review
signals from the same flow: branch posture (`terminating-guard-likely`,
`nested-branch-likely`, `non-branch-check`, or unresolved) and subject/object
binding (`overlap`, `mismatch`, or unresolved). A mismatch is useful when a
permission check appears to inspect one identifier while the sink operates on
another, but it is not proof of an authorization bypass. The layer remains
lexical, does not prove dominance, path feasibility, object identity, tenant
equality, or return/exception semantics, and writes only bounded tokens and
locations. `semantic-guard-candidates.json` is a deterministic S2 research
lead pool; all rows remain `not-a-finding` with
`requires_manual_dataflow=true`.

Inspect it with:

```bash
python3 scripts/agent_cli.py semantic-guards <target> \
  --workspace <audit-dir> --show-candidates --json
```

S8 also emits a bounded `research-strategy-guidance-v1` view. It joins only
strategy observation metadata, the latest review status, and explicit variant
coverage, then maps them to finite next-action classes. Guidance can adjust
research scheduling or recommend replacing a zero-yield experiment, but it is
never evidence, a finding verdict, a CVSS input, or a G4/G5 override.

The S2 planner consumes the same action context through
`surface-variant-plan-v1`. A plan is surface-specific but always symmetric:
each selected variant has positive, negative/safe, and environment-gap lanes.
The lanes are observation requirements and falsifiers, not observations; a
complete plan never implies that any lane executed.

The runtime lab expands the normalized plan into `surface-variant-fixture-v1`
contexts within the configured fixture budget. Each context has an opaque
fixture key, a fixed state-step sequence, and one of the three lanes. S4 clones
the base cell, exposes only bounded `VULNGATE_VARIANT_*` environment variables,
and records the lane context next to redacted replay/differential summaries.
When the budget truncates a plan, the artifact says so explicitly. An
environment-gap lane is still only a request to observe a gap: runner failure,
missing preconditions, and safe-equivalent behavior remain separate runtime
outcomes.

S4 also emits `surface-variant-evidence-v1` from the actual replay and
differential rows. It keeps only an allowlisted signal taxonomy and bounded
state-step identities, classifying each lane as `observed`, `partial`,
`environment-gap`, or `not-executed`. A declared sequence is not a witness:
only a complete observed STEP trace satisfies `state-sequence`, while
typed-effect and safe-equivalent remain separate signals. S8 and S2 reuse this
bounded witness to select the next probe, but it is always
`claim_status=not-a-finding`; raw output, effect details, payloads, commands,
and credentials never enter the artifact, and no gate, CVSS value, or candidate
conclusion is changed.

S8 aggregates those witnesses into `surface-variant-coverage-v1` inside the
project portfolio. It keeps historical signal/status counts alongside the
latest status for each research surface, variant, and lane, including observed
state-sequence, typed-effect, safe-equivalent, and environment-gap coverage.
Only a latest lane that is actually observed is treated as closed; partial,
not-executed, and environment-gap lanes produce bounded next probes linked by
the exact research key. The scheduler may use this view to prioritize the
missing experiment, but the view remains `claim_status=not-a-finding` and
cannot alter a candidate verdict, CVSS, or G4/G5.

For candidates with multiple configured versions or patch metadata, S2 also
emits `comparison-orchestration-v1`. S4 binds the comparison to the same
fixture and lane, classifies actual paired cells as bucket change, signature
drift, same observation, or inconclusive, and keeps source-revision builds and
sibling paths explicitly unexecuted when no operator-supplied artifact exists.
A patch reference is never treated as a runtime result; a missing old or fixed
runtime is an environment gap rather than evidence that the fix works.

An operator can close the source-revision build gap with an explicit,
workspace-local artifact declaration:

```json
{
  "source_revision_artifacts": {
    "enabled": true,
    "arms": [
      {"role": "before", "ref": "<commit-sha>", "jars": ["build/before.jar"]},
      {"role": "after", "ref": "<commit-sha>", "jars": ["build/after.jar"]}
    ]
  }
}
```

The adapter accepts only bounded workspace-local JAR/WAR/ZIP files for the
exact contract refs, fingerprints them, and reuses the isolated Java runner on
the same fixture/lane. It never performs checkout, invokes a build command, or
uses a remote artifact; missing, invalid, non-Java, or mismatched input remains
`precondition-unavailable`/`inconclusive`. Actual source-arm observations are
still research metadata with `claim_status=not-a-finding` and cannot satisfy
G4/G5 by themselves.

S8 also builds `research-replay-calibration-v1` from the target's bounded
round snapshots. It measures whether replacement actions produced new
information, whether environment gaps recovered, and whether fixture budgets
or comparison arms left coverage incomplete. With at least three matched
replays, the result may select only a one- or two-round zero-gain threshold for
future guidance; insufficient history keeps the default. The calibration
artifact contains no raw payloads, commands, output, credentials, or finding
evidence, and changes S2/S8 research scheduling only.

To make a calibration replayable rather than merely copyable, S8 also writes
`research-replay-pack-v1`. The standalone command is:

```bash
python3 scripts/agent_cli.py replay-pack <target> \
  --workspace <audit-dir> --json
```

The pack records only allowlisted workspace-local artifact names, schema
versions, sizes, SHA-256 fingerprints, and bounded per-round lane/comparison
summaries. It carries no source text, payload, command, output, credential, or
finding conclusion. Its provenance status distinguishes complete, partial,
environment-gap, not-executed, and invalid inputs; the embedded calibration
must also match the round-history digest. `verify_replay_pack` can re-hash the
same local workspace after a pack is created. A pack is eligible for cohort
calibration only when the provenance is complete and self-consistent.

When enough independent targets have produced that bounded artifact, an
operator may aggregate them into `research-replay-cohort-v1`:

```bash
python3 scripts/agent_cli.py replay-cohort-calibrate \
  --pack /path/to/project-a/research-replay-pack.json \
  --pack /path/to/project-b/research-replay-pack.json \
  --pack /path/to/project-c/research-replay-pack.json \
  --out state/research-replay-cohort.json --json
```

The cohort recomputes policy from opaque project rows, preserves per-surface
sample sufficiency, and activates the existing two-round replacement threshold
only when at least three distinct projects have sufficient replay history and
the project-level low-yield signal is consistent. With fewer projects it keeps
the default and emits a `collect-more-projects` recommendation. A target may
explicitly set `replay_cohort_calibration_path`; local target calibration wins
over the cohort, and the cohort is never discovered implicitly. Pack inputs
must carry complete, digest-consistent provenance; incomplete packs are
rejected instead of becoming policy samples. The legacy `--artifact` form
remains available for backwards compatibility and is tracked separately from
pack provenance. The pipeline copies only bounded research metadata into S8
and cannot alter candidate status, CVSS, G4, or G5.

### Cross-round evidence consistency

S8 also derives `research-consistency-v1` from bounded, normalized
`research-memory` events. It compares only allowlisted state classes for the
same research key: effect presence, reproduction, comparison outcome, runtime
state, and context digest. It distinguishes `conflicted`, `unstable`,
`insufficient`, `environment-gap`, and `consistent`, and emits a bounded next
action such as `repeat-with-controlled-context`, `isolate-state`, or
`repair-environment`. The standalone command is:

```bash
python3 scripts/agent_cli.py research-consistency <target> \
  --workspace <audit-dir> --json
```

This is a contradiction detector, not a finding detector: environment gaps do
not count as no-effect observations, and every row remains
`claim_status=not-a-finding`. The portfolio and strategy use it only to
schedule controlled re-observation; S8 writes both target and round artifacts,
and replay-pack provenance covers them as well.

The next boundary is `research-consistency-action-v1`. S8 materializes each
non-consistent row as a bounded recheck contract with fixed isolation axes,
positive/negative or environment-gap lanes, a two-run repeat shape, required
observation codes, and falsifier codes. Inspect or rebuild it with:

```bash
python3 scripts/agent_cli.py research-consistency-actions <target> \
  --workspace <audit-dir> --json
```

S2 matches the contract by stable `research_key` and adds a
`consistency-recheck` experiment. S4 carries the normalized contract through
MatrixCell metadata, `VULNGATE_CONSISTENCY_ACTION`, ordinary runtime-lab
fixtures, and replay/differential cells. The contract is still a checklist,
not an observation: missing independent replay, mismatched fixture/context,
unreset state, and signature drift keep the research item pending. The action
artifact, portfolio, strategy, and replay pack remain
`claim_status=not-a-finding` and cannot change candidate status, CVSS, G4, or
G5.

The next boundary is executed closure, `research-consistency-recheck-v1`. S4
now materializes the action's positive/negative or environment-gap lane and
passes only a bounded `VULNGATE_CONSISTENCY_LANE` selector to the PoC. Lane
fixtures have distinct lane identities but retain the same base context
digest. While runner rows are still in memory, S4 extracts only allowlisted
witnesses: execution/environment status, replay count, typed effect or safe
equivalent, explicit state reset, comparison-arm status, and fixture/context
identity. Raw stdout/stderr, commands, payloads, credentials, and source prose
are not copied into the closure artifact.

S8 combines the previous pending action with the current
`S4/runtime-lab.json` and writes `research-consistency-recheck-v1`. It
distinguishes `observed`, `partial`, `environment-gap`, and `not-executed`;
only complete lane, repeat, fixture/context, comparison, and required
observation witnesses stop the duplicate scheduling loop. Inspect it with:

```bash
python3 scripts/agent_cli.py research-consistency-rechecks <target> \
  --workspace <audit-dir> --json
```

Closure remains `claim_status=not-a-finding`; it cannot confirm a vulnerability,
turn an environment gap into negative evidence, or change candidate status,
CVSS, G4, or G5.

Stage 31 adds `research-agenda-v1`, an active finite-budget queue derived only
from normalized strategy and portfolio recheck state. Each item carries a
bounded action, missing/required observations, falsifiers, prerequisites,
expected information gain, estimated cost, and priority score. Selection first
spreads work across explicit research surfaces and attack classes, then uses
remaining slots for the highest information-gain work; environment repair,
residual closure, review follow-up, and evidence debt affect scheduling only.
S8 writes `research-agenda.json` at target and round scope, and it is included
in replay-pack provenance when present:

```bash
python3 scripts/agent_cli.py research-agenda <target> \
  --workspace <audit-dir> [--rebuild] [--slots N] [--max-per-surface N] [--json]
```

The next scheduler round accepts only exact `research_key` or `candidate_id`
matches and applies a small bounded boost, preserving the match in schedule
evidence. Agenda metadata and the scheduler signal remain
`claim_status=not-a-finding`; they cannot confirm a vulnerability or change
candidate status, CVSS, G4, or G5.

Stage 32 adds `research-agenda-outcome-v1`, closing the execution-feedback loop
around the finite queue. Before S8 replaces the previous agenda, it joins its
items by exact `agenda_id`, `strategy_id`, `research_key`, and `candidate_id`
against the actual scheduler snapshot, S4 `verification-matrix`, S4
`runtime-lab`, and S8 strategy feedback. It classifies only bounded outcomes:
`new-information`, `falsifier-observed`, `no-new-information`,
`environment-gap`, `not-executed`, and `not-selected`. Target and round
`research-agenda-outcomes.json` artifacts retain information gain, observed
signals, execution state, cell/fixture counts, and consecutive no-gain counts,
then expose the latest outcome to the next agenda and scheduler prompt. This
is still `claim_status=not-a-finding`; it cannot change candidate status, CVSS,
G4, or G5. Inspect or rebuild it with:

```bash
python3 scripts/agent_cli.py research-agenda-outcomes <target> \
  --workspace <audit-dir> [--round N] [--rebuild] [--json]
```

Stage 33 adds `research-budget-v1`, an outcome-cost adaptive policy for the
finite agenda.  S8 joins the previous agenda and its normalized outcome rows,
then aggregates selected work by explicit research surface, information gain,
estimated cost, environment gaps, and no-information repeats.  It emits only
bounded `recover-environment`, `exploit-high-yield`, `explore-undercovered`,
`continue-balanced`, or `cooldown-low-yield` guidance.  The next agenda
consumes surface priority deltas and cap hints while retaining an exploration
floor; a low-yield surface is cooled down, never deleted, and an environment
gap is never treated as negative security evidence.

S8 writes target and round `research-budget.json` artifacts, and replay packs
include them as optional provenance.  Inspect or rebuild the policy with:

```bash
python3 scripts/agent_cli.py research-budget <target> \
  --workspace <audit-dir> [--round N] [--rebuild] [--slots N] [--json]
```

Budget policy, agenda hints, and their scheduler evidence remain
`claim_status=not-a-finding`; they cannot confirm a vulnerability or change
candidate status, CVSS, G4, or G5.

## Two operating modes

| Mode | Reasoning | Setup | Typical use |
|---|---|---|---|
| A — host-native | The Codex model you already configured | none | Interactive audits, PoC verification, novelty checks |
| B — autonomous | LLM API via `run_pipeline.sh` | `DEEPSEEK_API_KEY` / `OPENAI_API_KEY` | Unattended multi-round sweeps |

Mode A is the default and requires no API key because the host agent itself is the
LLM. Mode B exists for scripted, unattended runs.

## Evidence contract

PoCs must emit machine-readable observation lines, e.g.:

```text
INSTANTIATED=com.sun.rowset.JdbcRowSetImpl
ERROR=java.lang.OutOfMemoryError
GATE_BLOCKED=com.example.Target
NETWORK=ldap://127.0.0.1:389/...
PARSED=true
```

The runner derives facts from these lines only:

- `INSTANTIATED` must be a fully-qualified class name — a bare `true` is not
  evidence of target instantiation.
- `ERROR` distinguishes library behavior (`JSONException`, `OOM`,
  `StackOverflowError`) from environment errors (`ENV_ERROR` family:
  `NoClassDefFoundError`, etc.).
- Cells that fail to compile are harness issues, not verdicts.

## Gates

| Gate | Blocks |
|---|---|
| G0 | claiming reachability for dead code |
| G1 | auditing entries unreachable from untrusted input |
| G1b | treating non-default-feature paths as default-reachable |
| G3 | claiming 0day when any upstream PR/issue/disclosure hits |
| G4 | confirming a finding without runtime PoC evidence |
| G5 | severities whose CVSS `AC` contradicts the precondition tier |

## Safety boundaries

- The matrix runner scans PoC source before compiling and refuses non-loopback
  URLs/IPs.
- Approvals and denials are appended to `state/<target>/round-NN/approval-log.jsonl`.
- No stage publishes anything; S7 writes reports to the local workspace only.
