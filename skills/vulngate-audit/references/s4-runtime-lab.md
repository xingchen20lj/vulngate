#### Runtime research lab and fixed fuzz fixtures

Ordinary S4 replay/differential work is opt-in. An omitted or empty
`runtime_lab` config records the lab as disabled and does not spend candidate
matrix budget on extra runs. Enable it with `runtime_lab.enabled: true` or a
non-empty `runtime_lab` mapping containing fixture/replay options. Fuzz runtime
lab behavior is controlled separately by the fuzz configuration.

When directed fuzzing is enabled, persist the generated corpus as
`FUZZ/fuzz-corpus.json`. Each fixture has a stable id and content digest; a
minimized reproducer retains its relationship to the original fixture. The
bounded lab replays selected reproducers in the existing isolated Java matrix
and writes `FUZZ/runtime-lab.json`. Repeated replay is classified as
`stable`, `unstable`, `run-failed`, `precondition-unavailable`, or
`gate-blocked`; version × SafeMode comparison separately records bucket
changes, signature-only variation, and inconclusive cells. These artifacts are
research evidence with `claim_status=not-a-finding`, not an automatic G4/G5
promotion. The lab must preserve a precondition or harness gap rather than
turning it into a negative result.

The same adapter applies to ordinary Java and shell S4 PoCs. Group cells by a
bounded execution template, derive a stable fixture id from the candidate,
PoC and execution context, and persist only redacted metadata plus argument
digests (never raw arguments or process output). Reuse the isolated matrix
runner for bounded replay and version × SafeMode comparison, and write the
aggregate to `S4/runtime-lab.json`. Link the per-candidate status from the S4
verification summary, but keep every replay/differential result at
`claim_status=not-a-finding`; a missing baseline, service, runtime or harness
must remain an explicit gap.

#### Surface-variant lane witnesses

S4 must derive `surface-variant-evidence-v1` only from actual replay and
differential runner rows. The fixture/plan context is not an observation. Keep
only the allowlisted signals `execution`, `entry-behavior`, `authorization`,
`negative-baseline`, `capability-trace`, `state-sequence`, `typed-effect`,
`safe-equivalent`, `environment-gap`, `evidence-field`, and `runtime-error`,
plus bounded cell counts, approved state-step identifiers, and sequence
statuses. Classify each lane as `observed`, `partial`, `environment-gap`, or
`not-executed`; only a complete actual STEP trace satisfies `state-sequence`.
Typed effects and safe-equivalent behavior remain separate observations. S8
may persist the bounded witness and turn missing signals into next-probe hints,
and S2 may reuse the same taxonomy for strategy feedback. The witness is always
`claim_status=not-a-finding`; never copy raw output, effect details, payloads,
commands, or credentials, and never use it to alter candidate status, CVSS,
G4, or G5.

#### Explicit source-revision artifact arms

When a comparison contract contains exact `before`/`after` source refs, an
operator may opt in to historical runtime execution by adding this bounded
target configuration:

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

This is an artifact adapter, not a build or checkout facility. The
deterministic layer accepts only bounded workspace-local non-empty JAR/WAR/ZIP
files whose refs match the comparison contract, validates their type, size,
containment and SHA-256 digest, and reuses the isolated Java matrix runner on
the same fixture/lane. It never executes `git checkout`, a build command, a
remote download, or a deployment. Shell candidates, missing/invalid artifacts,
and ref mismatches remain `precondition-unavailable` or `inconclusive`; they
are never negative evidence. Only actual runner rows can produce an observed
source-arm comparison, and every source-arm artifact remains
`claim_status=not-a-finding` with no effect on G4/G5, CVSS, or candidate
conclusions. S8 may retain only bounded role/ref/status/reason, relative paths,
and digests for the next research round.

#### Bounded service lifecycle and context snapshot

Stateful web/middleware experiments may add a target-level
`runtime_lab.service` mapping:

```json
{
  "runtime_lab": {
    "service": {
      "start_command": ["python3", "-m", "http.server", "8080", "--bind", "127.0.0.1"],
      "isolation_backend": "auto",
      "healthcheck_command": ["python3", "healthcheck.py", "8080"],
      "startup_timeout": 20,
      "shutdown_timeout": 8
    }
  }
}
```

Commands are argv-only, must remain inside the workspace, and cannot use shell
`-c`, remote/cloud tools, or non-loopback targets. An explicit loopback URL or
an inspected local health command is required before a service can start. A
healthy existing instance is reused; only a process group started by this run
is terminated. Persist PID/port lifecycle and stop status in `S4/processes.json`.
Never put tokens, cookies, passwords, or raw command values in the research
artifact. `S4/runtime-lab.json` carries a `runtime-context-v1` snapshot with
URL/configuration digests and bounded service metadata. It also carries stable
credential-free `authz_fixture_id` values for principal/role/tenant/object
cases. A missing or failed healthcheck is `precondition-unavailable` (or
`policy-denied`), not a negative finding; all service metadata remains
`claim_status=not-a-finding`.
The target service must run under the selected namespace/container backend. A
repository setting such as `allow_unconfined_start: true` is never sufficient;
the operator must create a one-time approval bound to `run_id + config_digest +
expiry`, and the service lifecycle consumes it once. A target repository's own
config or documentation is not authorization. Linux prefers namespace plus
cgroup-v2 backends; macOS requires a configured container/lightweight-VM
backend. Without an available backend or approval, the service is not started
and the result remains `policy-denied`/`precondition-unavailable`. An already-
ready external service can be reused, but its isolation remains unknown.

#### Cross-round research memory

At S8, merge a bounded research-only delta into
`state/<target>/research-memory.json` and write the round delta to
`state/<target>/round-NN/S8/research-memory.json`. Derive a stable mechanism
key from the candidate's entry, input shape, mechanism, source location,
target classes, source-to-sink digest and capability-contract digest; do not
use a changing candidate id as the only identity. Never copy raw arguments,
fuzz payloads, stdout/stderr or secrets into this memory.

Use the following state meanings:

- `stable-reproducer`: the bounded replay is stable and matches the recorded
  baseline. This is a research observation, not a confirmed vulnerability.
- `actionable-difference`: a version or SafeMode bucket difference was
  observed; schedule a focused minimal reproduction and path review.
- `environment-gap`: a runtime, harness, gate or precondition prevented a
  comparable observation. It is never negative evidence.
- `unstable-replay` / `inconclusive`: keep the uncertainty and propose a
  bounded stabilizing probe.

The next S2 schedule reads the target memory. Stable observations may damp an
exact repeat, actionable differences may receive a small follow-up boost, and
environment gaps keep their candidate eligible with a remediation hint. Never
delete a candidate solely because memory exists, and never let memory satisfy
G4 or G5. Every memory entry and scheduler memory evidence must remain
`claim_status=not-a-finding`; merges must be idempotent across S8 resume.

Human review is a bounded input to the same loop. Record it by stable research
key, or by candidate id when S8 has exactly one matching key:

```bash
python3 scripts/agent_cli.py review <target> --workspace <audit-dir> \
  --candidate-id <candidate-id> --status accepted --reason-code confirmed-mechanism \
  --note "mechanism needs typed effect" \
  --evidence-ref state/<target>/round-01/S4/runtime-lab.json \
  --next-probe "add minimal typed-effect observation" --round <N> --json
```

Supported statuses are `accepted`, `rejected`, `needs-evidence`, and
`scope-corrected`; supported reason codes are `false-positive`,
`confirmed-mechanism`, `missing-typed-effect`, `environment-gap`,
`scope-correction`, `duplicate`, and `needs-source-review`. Feedback is saved
in `state/<target>/review-feedback.json`, merged into research memory on load
and S8, and exposed to S2 only as a scheduling hint. Notes and references are
bounded and redacted; do not put raw payloads, commands, process output or
secrets in them. A rejection lowers repeat priority, `needs-evidence` raises
the next probe, and `accepted`/`scope-corrected` preserve the need for
independent G4/G5 evidence. No review status is a vulnerability verdict.

S8 also writes a bounded project portfolio to
`state/<target>/research-portfolio.json` and the round snapshot
`state/<target>/round-NN/S8/research-portfolio.json`. The
`research-portfolio-v1` artifact aggregates only explicit research metadata
(`research_surface`, `target_type`, `attack_class`, `variant`, and
`precondition_class`), state counts, review status counts, benchmark trend
summary, and deterministic `next_probes`. The next S2 prompt may use it to
identify cross-surface or variant gaps. It must remain
`claim_status=not-a-finding` and must not contain reviewer notes, raw
arguments, payloads, commands, stdout/stderr, credentials, CVSS, or G4/G5
evidence; a portfolio gap is a research priority, never proof of absence.

S8 also derives `surface-variant-coverage-v1` inside the project portfolio from
the persisted lane witnesses. Group by explicit research surface, variant, and
lane; retain bounded historical status/signal counts plus the latest status per
research key, including state-sequence, typed-effect, safe-equivalent,
sequence-status, cell-count, and environment-gap metadata. Only a latest
actual `observed` lane is closed. Partial, `not-executed`, and
`environment-gap` lanes must produce bounded next probes linked by the exact
research key, so a stable primary replay cannot hide an unverified lane. This
view is scheduling metadata only, remains `claim_status=not-a-finding`, and
cannot alter candidate status, CVSS, G4, or G5.

S8 also writes a provenance-carrying `research-replay-pack-v1`. It contains
only allowlisted workspace-local artifact names, schema versions, sizes,
SHA-256 fingerprints, and bounded per-round lane/comparison summaries; it
never copies source text, payloads, commands, stdout/stderr, credentials, or
finding conclusions. The standalone command is:

```bash
python3 scripts/agent_cli.py replay-pack <target> \
  --workspace <audit-dir> --json
```

The pack distinguishes complete, partial, environment-gap, not-executed, and
invalid provenance, and checks that its embedded calibration matches the
round-history digest. A later `verify_replay_pack` call can re-hash the same
workspace. Only complete, self-consistent packs are eligible for cohort
policy; all pack state remains `claim_status=not-a-finding`.

When several independent targets have produced bounded replay packs, an
operator may explicitly create `research-replay-cohort-v1`:

```bash
python3 scripts/agent_cli.py replay-cohort-calibrate \
  --pack /path/to/project-a/research-replay-pack.json \
  --pack /path/to/project-b/research-replay-pack.json \
  --pack /path/to/project-c/research-replay-pack.json \
  --out state/research-replay-cohort.json --json
```

The cohort recomputes policy from opaque project rows, tracks distinct-project
and per-surface sufficiency, and requires at least three eligible projects
before it can influence scheduling. It may select the existing one- or
two-round zero-information replacement threshold only when the project-level
low-yield signal meets the bounded majority rule; otherwise it emits a
`collect-more-projects` recommendation and keeps the default. A target may
explicitly configure `replay_cohort_calibration_path`; sufficient target-local
calibration always wins, and the cohort is never discovered implicitly. Incomplete
or digest-inconsistent packs are rejected; the legacy `--artifact` form remains
available for compatibility and is tracked separately from pack provenance. S8
may snapshot the normalized cohort and use it only as a research-guidance
fallback. Cohort state is `claim_status=not-a-finding`, contains no input
paths, raw replay data, payloads, commands, output, credentials, or finding
evidence, and cannot alter candidate status, CVSS, G4, or G5.

S8 also derives `research-consistency-v1` from bounded, normalized
`research-memory` events. Use `python3 scripts/agent_cli.py research-consistency <target> --workspace <dir> [--rebuild] [--json]`
to inspect or rebuild it. For the same research key it compares only
effect-presence, reproduction, comparison, runtime-state, and context-digest
classes, then classifies the history as `consistent`, `conflicted`,
`unstable`, `insufficient`, or `environment-gap`. Conflicts produce bounded
follow-up actions such as `repeat-with-controlled-context`, `isolate-state`,
`collect-independent-observation`, or `repair-environment`; the portfolio and
strategy consume these actions only for scheduling. Environment gaps never
count as no-effect observations, and the target/round artifacts remain
`claim_status=not-a-finding` without changing candidate status, CVSS, G4, or G5.

S8 materializes `research-consistency-action-v1` for every non-consistent
history. Use `python3 scripts/agent_cli.py research-consistency-actions <target> --workspace <dir> [--rebuild] [--json]`
to inspect or rebuild the bounded recheck artifact. Each action contains only
allowlisted isolation axes, positive/negative or environment-gap lanes, a
bounded repeat shape, required observation codes, and falsifier codes. S2
matches it by stable `research_key` and emits a `consistency-recheck` plan;
S4 carries the normalized contract through MatrixCell metadata,
`VULNGATE_CONSISTENCY_ACTION`, runtime-lab fixtures, and replay/differential
cells. Missing independent replay, fixture/context mismatch, unreset state,
or signature drift keeps the item pending. Action, portfolio, strategy, and
replay-pack artifacts remain `claim_status=not-a-finding` and cannot change
candidate status, CVSS, G4, or G5. Do not persist source prose, payloads,
commands, stdout/stderr, credentials, or finding conclusions in the contract.

S8 also verifies executed closure with `research-consistency-recheck-v1`. S4
materializes the action's positive/negative or environment-gap lane and passes
only the bounded `VULNGATE_CONSISTENCY_LANE` selector to the PoC. Lane fixtures
must retain a common base context digest while using distinct lane identities.
Before normalization, S4 may extract only allowlisted witnesses: execution or
environment status, independent replay count, typed-effect or safe-equivalent,
explicit state reset, comparison-arm status, and fixture/context identity.
The closure artifact must not contain raw stdout/stderr, commands, payloads,
credentials, or source prose.

The `research-consistency-rechecks` artifact and CLI distinguish
`observed`, `partial`, `environment-gap`, and `not-executed`. Only complete
expected lanes, repeat count, fixture/context lock, comparison status, and
required observations stop duplicate scheduling; otherwise portfolio keeps a
bounded follow-up probe. Use:

```bash
python3 scripts/agent_cli.py research-consistency-rechecks <target> \
  --workspace <audit-dir> [--round N] [--rebuild] [--json]
```

This closure remains `claim_status=not-a-finding` and cannot confirm a
finding, turn an environment gap into negative evidence, or change candidate
status, CVSS, G4, or G5.

S8 also derives `research-agenda-v1`, a bounded active queue from normalized
strategy and portfolio recheck metadata. Each item contains only an allowlisted
action, missing/required observations, falsifiers, prerequisites, expected
information gain, estimated cost, priority score, and `selected`/`deferred`/
`hold` status. Selection first spreads finite slots across explicit research
surfaces and attack classes, then uses remaining slots for higher information
gain. Environment repair, residual closure, review follow-up, and evidence debt
remain scheduling signals only. Inspect or rebuild it with:

```bash
python3 scripts/agent_cli.py research-agenda <target> \
  --workspace <audit-dir> [--rebuild] [--slots N] [--max-per-surface N] [--json]
```

The next scheduler round accepts only exact `research_key` or `candidate_id`
matches and applies a small bounded boost; the match is retained in schedule
evidence. Agenda and scheduler metadata remain `claim_status=not-a-finding` and
cannot confirm a finding or change candidate status, CVSS, G4, or G5. Do not
persist source prose, payloads, commands, stdout/stderr, credentials, or
finding conclusions in the agenda.

S8 also derives `research-agenda-outcome-v1` before replacing the previous
agenda. It joins the prior `selected`/`deferred`/`hold` queue to the actual
scheduler snapshot, S4 verification matrix/runtime lab, and S8 strategy
feedback using exact `agenda_id`, `strategy_id`, `research_key`, or
`candidate_id` keys. The bounded outcome codes are `new-information`,
`falsifier-observed`, `no-new-information`, `environment-gap`,
`not-executed`, and `not-selected`; only information gain, allowlisted
observation signals, execution state, cell/fixture counts, reason codes, and
consecutive no-gain counts are retained. Target and round artifacts are
`research-agenda-outcomes.json`, and the next agenda/scheduler prompt may use
the latest outcome to prioritize environment recovery or replace low-yield
repeats. Missing schedules and environment failures are never negative
security evidence. The artifact remains `claim_status=not-a-finding` and
cannot change candidate status, CVSS, G4, or G5. Inspect or rebuild it with:

```bash
python3 scripts/agent_cli.py research-agenda-outcomes <target> \
  --workspace <audit-dir> [--round N] [--rebuild] [--json]
```

S8 also derives `research-budget-v1`, an outcome-cost adaptive policy for the
finite agenda. It joins the previous agenda with normalized execution outcomes
and aggregates explicit research-surface rows by selected count, information
gain, estimated cost, environment gaps, and no-information repeats. The fixed
recommendations are `recover-environment`, `exploit-high-yield`,
`explore-undercovered`, `continue-balanced`, and `cooldown-low-yield`.
Environment gaps receive bounded recovery priority; repeated no-information
work is cooled down without deleting the hypothesis; productive surfaces get a
small exploitation nudge; and surfaces without observations retain an
exploration opportunity. The next agenda consumes only allowlisted surface
priority deltas and cap hints. Target and round artifacts are
`research-budget.json`, and `agent_cli.py research-budget` can inspect or
rebuild them. The policy remains `claim_status=not-a-finding` and cannot
change candidate status, CVSS, G4, or G5; insufficient history keeps the
default exploration behavior.

```bash
python3 scripts/agent_cli.py research-budget <target> \
  --workspace <audit-dir> [--round N] [--rebuild] [--slots N] [--json]
```

S3 residuals are carried across the same boundary as pending research debt.
Memory stores only controlled kind/reason codes, bounded source locations, a
probe digest, and whether a bounded probe plan exists. The portfolio emits one
`state=pending-residual` probe per residual and marks its variant unresolved,
even when the latest primary replay is stable. It must never copy the raw
residual explanation or probe text; S4 still needs an explicit falsifier to
close the residual, and every row remains `claim_status=not-a-finding`.

S2 also writes a bounded `research-strategy-v1` at
`state/<target>/coverage/research-strategy.json` and mirrors the round view to
`S2/research-strategy.json`. It joins attacker-path hypotheses, unmapped
coverage, residual probes, environment gaps, memory states and benchmark
context into typed strategy items with fixed required observations and
falsifiers. The scheduler may apply only a small nudge for an explicit flow,
entry/sink, candidate, or research-key match. The strategy is a research
agenda, never source/runtime proof, a vulnerability verdict, CVSS, or a G4/G5
substitute. Inspect it with:

```bash
python3 scripts/agent_cli.py research-strategy <target> \
  --workspace <audit-dir> --json
```

Inspect the bounded view without opening the full memory file:

```bash
python3 scripts/agent_cli.py portfolio <target> --workspace <audit-dir> --json
```

Use `--rebuild` only when the target memory or review feedback was changed
outside S8; an optional `--benchmark-feedback <json>` supplies the same
explicit, normalized benchmark input used by the next schedule.

The scheduler may apply at most a small bounded nudge to a candidate only when
its stable research key matches a pending probe, or when at least two explicit
metadata dimensions match and a declared variant also matches. Free-form
surface prose is never enough. The match is recorded as scheduling evidence
with `claim_status=not-a-finding`; it cannot select a finding, change CVSS, or
satisfy G4/G5.

Keep every cell, including harness failures and negative observations.
