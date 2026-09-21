# Feature evolution

VulnGate 1.2.0 expands the audit engine while keeping the host-agent and
deterministic-executor boundary intact.

## Unreleased semantic path evidence

The next analysis layer closes a specific gap in the earlier heuristic control
map: path membership did not say whether a control occurred before the sink or
whether a same-symbol input token reached the sink argument. S1 now persists
`semantic-path-evidence-v1` and `semantic-path-candidates.json` beside the
existing coverage indices. It records bounded control alignment
(`before-sink`, `after-sink`, `same-line`, or `cross-symbol-unverified`), a
brace/indent lexical-scope relation, and a same-symbol parameter/alias result
(`direct`, `propagated`, `not-traced`, or `cross-symbol-unresolved`).

The layer is deliberately not a compiler or a proof engine. It does not model
branch dominance, types, virtual dispatch, DI, reflection, callbacks, or
sanitizer semantics. Every row is `claim_status=not-a-finding`, every
candidate carries `requires_manual_dataflow=true`, and only S3/S4 can establish
reachability or typed effect. Use:

```bash
python3 scripts/agent_cli.py semantic-paths <target> \
  --workspace <audit-dir> --show-candidates --json
```

The candidate pool consumes these leads after the control, differential, and
capability candidates. The order is deterministic and the raw source text is
not copied into the artifact.

## Unreleased semantic guard evidence

The semantic path layer can show that a control is near a sink, but a senior
reviewer still needs two sharper questions: does the source shape look like a
rejecting guard for the sink's branch, and does the control mention the same
subject/object that the sink operates on? S1 now persists
`semantic-guard-evidence-v1` and `semantic-guard-candidates.json` for those
bounded questions.

The artifact records `terminating-guard-likely`, `nested-branch-likely`,
`non-branch-check`, `branch-unresolved`, and explicit cross-symbol states, plus
`overlap`, `mismatch`, `unresolved`, and `cross-symbol-unverified` subject
binding. It does not prove control-flow dominance, path feasibility, type or
tenant identity, or authorization correctness. Every row remains
`claim_status=not-a-finding`, and each derived lead requires manual data-flow
review. Use:

```bash
python3 scripts/agent_cli.py semantic-guards <target> \
  --workspace <audit-dir> --show-candidates --json
```

The guard candidates are read-only additions to the same deterministic S2
pool. They are intentionally separate from semantic path evidence so later
CFG/type/DI improvements can replace the heuristic layer without changing the
existing artifact contract.

## Analysis coverage

The engine now records the complete production-source universe, explicit skip
reasons, entries, sinks, controls, symbols, heuristic call edges and
forward/backward flow paths. Coverage is derived from durable round ledgers, so
an uncovered high-risk region remains visible until it has evidence.

Control maps judge each path against the controls expected by its sink category.
Sibling differentials compare handlers that should share a security boundary.
Both analyses produce review candidates and retain heuristic confidence labels;
they never replace source review or runtime proof.

Candidate scheduling scores the complete pool, applies category quotas, pins
runtime-backed candidates, and carries deferred work into later rounds. The
pipeline writes the schedule into the same workspace as the evidence ledger.

S2 now also emits a deterministic, bounded experiment plan for every candidate
in the pool. The plan records the observations needed to test baseline,
authorization, stateful/race, availability, fix-variant and typed-effect
hypotheses, plus explicit falsifiers. It is marked `not-a-finding`: the plan
helps S3 choose the next probe but cannot satisfy G4/G5 without persisted
runtime evidence. See [the research roadmap](RESEARCH-ROADMAP.zh-CN.md) for the
next capability layers.

The capability layer is now wired into the same evidence path. S1 derives
`capability-graph.json` from the entry/sink/flow indices and persists bounded
`capability-candidates.json` for explicit primitive equations such as
`read -> credential-read -> exec`, `ssrf -> internal-effect`, and
`write -> config-control -> exec`. Each candidate names its observed and
missing primitives, transition rules, source locations and verification
sequence. These are static research hypotheses (`not-a-finding`) that require
manual data-flow review and runtime typed-effect evidence; a missing primitive
is a next probe, not proof that the chain is absent.

The next link is now deterministic S4 evidence. Capability candidates are
normalized into a bounded `capability_contract` on each matrix cell and exposed
to Java, shell, autonomous, and CLI-manifest PoCs as read-only observation
metadata. The runner preserves `CAPABILITY` / `CAPABILITY_EVIDENCE` and
`TRANSITION` / `TRANSITION_EVIDENCE` traces, and reports `no-trace`, `partial`,
or `complete` capability evidence while keeping `EFFECT_KIND` / `EFFECT` as a
separate typed-effect requirement. Even a complete cell trace remains a
`not-a-finding` research result until the ordinary G1/G4/G5 gates are met.

The directed fuzz path now also has a bounded runtime lab. Generated inputs
are persisted as deterministic fixtures in `FUZZ/fuzz-corpus.json`; minimized
reproducers retain their original fixture relationship, stable identity, and
content digest. Selected reproducers are replayed in the existing isolated
Java matrix and compared across configured versions and SafeMode states.
`FUZZ/runtime-lab.json` distinguishes stable replay, unstable replay, bucket
changes, signature-only drift, and precondition/harness gaps. These records are
research evidence only and remain `claim_status=not-a-finding`.

The same adapter now covers ordinary Java and shell S4 PoCs. It groups cells
into stable execution templates, stores only bounded metadata and argument
digests, and reuses the isolated matrix runners for repeated replay and
version × SafeMode comparison. The result is persisted as
`S4/runtime-lab.json` and linked from the ordinary S4 summary; raw arguments
and process output are not copied into that artifact.

S4 now also has an optional bounded service context for stateful web and
middleware experiments. A target may provide an argv-only `runtime_lab.service`
with a workspace-local working directory and an explicit loopback healthcheck.
The runner reuses a healthy instance, starts only a local process group when
needed, records the PID/port lifecycle in `S4/processes.json`, and tears down
processes it owns. A failed healthcheck is a typed precondition gap, never a
negative result. `S4/runtime-lab.json` carries a `runtime-context-v1` snapshot:
target URL digests, effective runtime-lab options, service configuration
digests, and stable credential-free `authz_fixture_id` records for principal /
role / tenant / object comparisons. Raw commands, URL queries, credentials,
arguments, and process output remain outside the research artifact.

S8 now closes the feedback loop with a target-scoped
`state/<target>/research-memory.json`. A stable, round-independent research key
joins the candidate's bounded mechanism metadata to replay and differential
states. The next schedule lowers the priority of an exact stable repeat,
raises a version/SafeMode difference for a focused follow-up, and preserves a
harness or precondition failure as an environment gap. The memory is
idempotently merged, excludes raw arguments and process output, and remains
`claim_status=not-a-finding`; it improves experiment selection without
changing G4/G5 or asserting that a stable observation proves absence.

The loop now accepts structured human review through `agent_cli.py review`.
Feedback is keyed by the same stable mechanism key, stored separately in
`state/<target>/review-feedback.json`, and replayed into research memory as an
explicit event. S4 context summaries also carry service readiness/config
digests, version/URL digests, authorization fixture IDs, and bounded fix
variant hints. Rejected mechanisms are damped, items marked
`needs-evidence` are promoted for a focused follow-up, and scope corrections
remain visible; none of these signals changes a finding conclusion or satisfies
G4/G5. The round S8 directory snapshots the feedback file for auditability.

The next layer is a deterministic research-quality benchmark. A
`research-benchmark-v1` manifest separates gold truth (`vulnerable`, `negative`,
`environment-gap`) from the claim status the agent is allowed to emit and
declares the evidence fields required for that case. `agent_cli.py benchmark`
then measures observation coverage, confirmed precision/recall, unsafe
confirmation of negative cases, environment-gap fidelity, repeated research
keys with and without new evidence, evidence completeness, decision stability,
and CVSS/severity calibration. The result is deliberately marked
`not-a-finding`; it is a regression signal for the planner, scheduler and
conclusion rules, not a way to promote a real report.

Benchmark results can now be explicitly converted into a bounded
`research-benchmark-feedback-v1` artifact. The feedback contains only numeric
metric snapshots, fixed alert codes, capped signed deltas for the seven
scheduler factors, and planner observations/falsifiers. `agent_cli.py schedule
--benchmark-result` applies it while preserving the original weight scale and
records the actual adjustments in the schedule; S2 experiment plans carry the
same guidance. Config-driven and autonomous runs can opt in with the explicit
`benchmark_feedback_path` or inline `benchmark_feedback` target setting. The
feedback is `not-a-finding`: it cannot confirm/exclude a candidate, synthesize
runtime evidence, change CVSS, or bypass G4/G5. With no feedback, the default
schedule and plan remain byte-for-byte compatible.

The benchmark suite now also includes a cross-surface synthetic manifest and
sample run covering web, protocol, cloud, mobile and native research. Each
surface has a vulnerable, negative and environment-gap variant. Case metadata
is retained in the score, while `research_profile` and
`metrics.coverage_by_surface` expose per-surface observation coverage, negative
result safety, environment-gap fidelity and evidence completeness. The sample
keeps tool/runtime gaps as pending research states and all benchmark artifacts
as `not-a-finding`.

Surface-level benchmark deficits now become bounded `surface_guidance`. The
scheduler applies its small priority delta only when a candidate has an exact
`research_surface` or an explicit supported `target_type`; free-form surface
prose is never substring-matched. The experiment planner adds the matching
surface's fixed observations and falsifiers to its baseline checklist. This
turns a cross-surface score into targeted follow-up work without changing a
candidate status, CVSS, runtime evidence or G4/G5.

Benchmark CLI runs can now take a previous bounded result through
`--baseline`. `research-benchmark-trend-v1` compares fixed aggregate metrics
and common surface metrics, retaining only bounded deltas and regression
signals. A regression becomes the same allowlisted feedback/guidance path as
an absolute deficit; it does not copy case rows, PoC output or conclusions and
does not change G4/G5 or CVSS.

S8 now also produces a bounded `research-portfolio-v1` at
`state/<target>/research-portfolio.json`. It composes the target's research
memory, review feedback and benchmark context into deterministic coverage
views for explicit research surface, target type, attack class, variant and
precondition class. Each variant keeps observed states and unresolved counts,
while `next_probes` exposes only stable research keys, bounded classifications
and probe hints. The round snapshot is written under `S8/`; the next S2 prompt
can reuse the portfolio to choose cross-surface and variant follow-ups. The
deterministic scheduler gives only a stable research-key or multi-dimension
explicit match a small, explainable nudge and records the match in its
schedule evidence. The artifact remains `claim_status=not-a-finding` and never carries reviewer notes,
payloads, commands, process output, CVSS or G4/G5 evidence.

S1 now also emits a bounded `threat-model-v1` under
`state/<target>/coverage/threat-model.json` and mirrors it to
`round-NN/S1/threat-model.json`. It groups entries into explicit trust
boundaries and joins each emitted flow to its sink, static control posture,
reachability gap, attacker-role label, research questions, and any matching
capability-chain hypothesis. Unmapped entries and sinks remain visible as
pending investigation instead of disappearing from the model. The scheduler
includes a bounded snapshot in its prompt and persisted plan, and
`agent_cli.py threat-model` provides a direct report. All rows are static
research hypotheses with `claim_status=not-a-finding`; route exposure, data
flow, control ordering, transitions, and typed effects still require S3/S4
evidence.

S3 residuals now survive the S8 boundary as bounded research metadata. The
memory layer keeps only controlled residual kind/reason codes, source-location
digests, a probe digest and whether a probe plan exists; it never copies the
raw residual explanation or probe. The project portfolio turns each residual
into a `pending-residual` next probe, and marks the related variant unresolved
even when the primary replay is stable. This preserves the expert habit of
closing every residual with a falsifiable probe without weakening G4/G5.

S2 now synthesizes those artifacts into a bounded `research-strategy-v1`.
Control, capability, reachability, coverage, residual, environment and
portfolio follow-up items each carry fixed required observations and
falsifiers. The strategy is persisted at
`state/<target>/coverage/research-strategy.json` and mirrored to
`S2/research-strategy.json`; the scheduler gives only explicit flow,
entry/sink, candidate or research-key matches a small explainable nudge. The
strategy is a research agenda, never a source/runtime conclusion or a G4/G5
substitute.

The next-action layer now produces a bounded `research-strategy-guidance-v1`
snapshot. It joins the strategy item's real S4 observation status, the latest
human review state, and explicit portfolio variant coverage. It maps those
signals to a finite action such as `repair-environment`,
`add-negative-control`, `trace-capability-transition`, `add-typed-effect`,
`replay-residual-variant`, `replay-new-variant`, or `hold-for-new-evidence`.
When a replay yields no new information, the layer can recommend replacing the
experiment class rather than rewarding the same static match again. The target
artifact is `state/<target>/coverage/research-guidance.json` and the round
snapshot is `S8/research-guidance.json`; all fields are bounded metadata with
`claim_status=not-a-finding`, and none can alter a candidate verdict, CVSS,
G4, or G5.

S2 now consumes the action context through a shared
`surface-variant-plan-v1` library. It selects a bounded surface-specific
variant for Web, protocol, cloud, mobile, or native targets and expands it into
three mandatory comparison lanes: `positive`, `negative`, and
`environment-gap`. The lane definitions carry only allowlisted observation
signals and falsifier codes. Config-driven and autonomous planning reuse the
same normalized plan, so a lifecycle, identity-boundary, protocol state
machine, route/parser, or native method-body follow-up is not reduced to a
free-form prompt suggestion. The plan remains a research checklist; only
executed S4 observations can affect gates or conclusions.

The next layer is `surface-variant-fixture-v1`. The runtime lab expands the
normalized lanes into bounded fixture/state-machine contexts, preserving fixed
state-step identifiers and opaque fixture keys. Each replay and version/SafeMode
comparison receives the selected surface, variant, lane, and observation
requirements through controlled `VULNGATE_VARIANT_*` variables; the artifact
records the same context without raw arguments or process output. A configured
fixture budget can truncate work, and that truncation is explicit rather than
silently presenting partial coverage as complete. The lane remains a planning
contract until the PoC emits actual evidence.

Stage 24 closes that distinction with `surface-variant-evidence-v1`. S4
derives the artifact only from actual replay/differential rows and records a
small allowlisted taxonomy: execution, entry behavior, authorization,
negative baseline, capability trace, state sequence, typed effect,
safe-equivalent, environment gap, evidence field, and runtime error. Each lane
is classified as observed, partial, environment-gap, or not-executed; a plan's
declared steps never count, and only a complete observed STEP trace satisfies
the state-sequence signal. S8 stores the bounded witness and turns missing
signals into the next probe, while S2 reuses the same observation taxonomy.
The witness is research metadata with `claim_status=not-a-finding` and never
copies raw output, effect details, payloads, commands, or credentials.

Stage 25 carries the witness across rounds as
`surface-variant-coverage-v1` inside the project portfolio. For each explicit
surface/variant/lane key it retains bounded historical counts and the latest
per-research-key status, observed signals, missing observations, sequence
statuses, cell counts, and environment-gap counts. A lane is closed only when
the latest actual observation is `observed`; partial, not-executed, and
environment-gap states create exact research-key next probes for S2. This is a
coverage and scheduling view, not a finding channel, and remains
`claim_status=not-a-finding`.

For multi-version or fix-completeness candidates, the next deterministic layer
is `comparison-orchestration-v1`. It binds configured before/after version
pairs, read-only parent/fixed revision references, and canonical sibling hints
to the same fixture/lane. S4 classifies only actual paired summaries as bucket
change, signature drift, same observation, or inconclusive; source revision
arms remain explicitly build-required and sibling arms remain pending until
their lane executes. This makes patch-diff reasoning actionable without
pretending that a commit or an unavailable historical build is evidence.

The source-revision gap can now be narrowed by an explicit artifact adapter.
The operator may declare workspace-local JAR/WAR/ZIP files for the exact
`before` and `after` refs in `source_revision_artifacts`. VulnGate validates
paths, size, type, and SHA-256 fingerprints, then aliases those artifacts into
the existing isolated Java matrix on the same fixture/lane. It does not
checkout a revision, invoke a build, or reach a remote artifact service. An
available pair becomes an actual source-arm observation; missing or invalid
artifacts remain `precondition-unavailable`/`inconclusive`, and all source-arm
comparison state remains `not-a-finding` research metadata.

S8 now adds `research-replay-calibration-v1` for the next feedback loop. It
reads only bounded round snapshots of guidance, strategy feedback, and the
runtime lab, then measures replacement hit rate, unproductive repeats,
environment recovery, fixture-budget truncation, and comparison gaps. The
standalone command is:

```bash
python3 scripts/agent_cli.py replay-calibrate <target> \
  --workspace <audit-dir> --json
```

The target artifact is
`state/<target>/coverage/research-replay-calibration.json`; S8 also mirrors a
round snapshot under `S8/`. A calibrated result is accepted only with at least
three matched replay items and can change the zero-information replacement
threshold from one to two consecutive rounds. Insufficient history retains the
default. The calibration is research scheduling metadata only, marked
`not-a-finding`, and cannot alter candidate state, CVSS, G4, or G5.

The next research-loop layer is the explicit cross-project cohort adapter,
`research-replay-cohort-v1`. `agent_cli.py replay-cohort-calibrate` accepts
multiple per-target calibration artifacts and recomputes policy from opaque
project rows rather than averaging untrusted artifact prose. It tracks
distinct-project sufficiency and per-surface replay sufficiency, requires at
least three eligible projects before a cohort can influence scheduling, and
uses a project-level majority of low-yield replacement signals before selecting
the two-round threshold. A target may opt in with
`replay_cohort_calibration_path`; its own calibrated history always wins, while
an insufficient cohort leaves the default unchanged. The pipeline records the
bounded cohort snapshot in S8 only when configured, and all cohort state remains
`not-a-finding` scheduling metadata with no effect on candidate conclusions,
CVSS, G4, or G5.

The following replay layer is `research-replay-pack-v1`. S8 and
`agent_cli.py replay-pack` now package only an allowlisted set of workspace-local
round/target artifacts as relative names, schema versions, sizes, SHA-256
fingerprints, and bounded lane/comparison summaries. The pack embeds the
normalized calibration and checks its history digest against the round
artifacts. Complete, self-consistent provenance is required for a pack to enter
cohort calibration; missing, malformed, changed, and environment-gap inputs
remain distinct states. `verify_replay_pack` can re-hash the original workspace
without emitting its contents. Pack and cohort artifacts remain
`claim_status=not-a-finding`, contain no raw source, payload, command, output,
credential, or finding conclusion, and cannot change candidate status, CVSS,
G4, or G5.

The next layer is `research-consistency-v1`. A latest-state view can hide an
expert-level warning when the same research key produces a typed effect in one
round and a safe-equivalent, reproduction failure, comparison change, or
different runtime context in another. `agent_cli.py research-consistency`
derives a bounded view from normalized `research-memory` events and classifies
the key as `consistent`, `conflicted`, `unstable`, `insufficient`, or
`environment-gap`. It retains only state classes, round references, booleans,
and digests, and turns conflicts into controlled follow-up actions such as
`repeat-with-controlled-context`, `isolate-state`,
`collect-independent-observation`, or `repair-environment`. Portfolio and
strategy consume this view for scheduling only; S8 and replay packs persist it
as provenance-carrying metadata, always `claim_status=not-a-finding`, without
changing candidate status, CVSS, G4, or G5.

The next step is `research-consistency-action-v1`. Detection alone does not
guarantee that the next run will use the same fixture, reset state, or execute
an independent comparison arm. `agent_cli.py research-consistency-actions`
therefore materializes each non-consistent history as a bounded recheck
contract: fixed isolation axes, positive/negative or environment-gap lanes,
repeat count, required observation codes, and falsifier codes. S2 matches the
contract by stable research key and emits a `consistency-recheck` plan. S4
passes the normalized contract through MatrixCell metadata,
`VULNGATE_CONSISTENCY_ACTION`, ordinary runtime-lab fixtures, and replay/
differential cells. Missing replay, fixture/context mismatch, unreset state,
or signature drift keeps the research item pending; it cannot become a
finding, change CVSS, or satisfy G4/G5. The action artifact, portfolio,
strategy, and replay-pack entries remain `claim_status=not-a-finding` and
contain no raw source, payload, command, output, credential, or conclusion.

## Native targets

The macOS adapter turns `.app`, `.dmg` and `.pkg` bundles into an auditable
source view. It handles Mach-O metadata, Swift and Objective-C declarations,
Electron `app.asar` archives with source maps, embedded scripts and JAR views.
The native source view establishes attack surface and file locations; it does
not contain method bodies and cannot by itself establish a vulnerability.

## Operational boundaries

Use an independent `--workspace` for each audit so checkpoints and evidence do
not enter the installed plugin cache. Missing external tools are reported as
precondition gaps. Static coverage, control, differential, capability, and
threat-model output remains a
lead until the S1-S8 evidence gates are satisfied.

The regression suite covers the analysis indexes, scheduler, installer,
workspace isolation, native adaptation and standard Electron archive parsing.
