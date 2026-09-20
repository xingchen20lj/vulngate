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
