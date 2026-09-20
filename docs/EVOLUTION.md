# Feature evolution

VulnGate 1.1.0 expands the audit engine while keeping the host-agent and
deterministic-executor boundary intact.

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
artifact remains `claim_status=not-a-finding` and never carries reviewer notes,
payloads, commands, process output, CVSS or G4/G5 evidence.

## Native targets

The macOS adapter turns `.app`, `.dmg` and `.pkg` bundles into an auditable
source view. It handles Mach-O metadata, Swift and Objective-C declarations,
Electron `app.asar` archives with source maps, embedded scripts and JAR views.
The native source view establishes attack surface and file locations; it does
not contain method bodies and cannot by itself establish a vulnerability.

## Operational boundaries

Use an independent `--workspace` for each audit so checkpoints and evidence do
not enter the installed plugin cache. Missing external tools are reported as
precondition gaps. Static coverage, control, differential and capability output remains a
lead until the S1-S8 evidence gates are satisfied.

The regression suite covers the analysis indexes, scheduler, installer,
workspace isolation, native adaptation and standard Electron archive parsing.
