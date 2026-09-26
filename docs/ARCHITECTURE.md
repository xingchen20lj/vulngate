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
│  │  · uses sub-agents when independent work saves time   │  │
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
- the safety model (source-level egress screening, preflighted macOS Seatbelt
  network confinement and bounded PoC write roots, approval logging, and no
  pre-fix disclosure; PoC filesystem reads/writes use a macOS default-deny profile,
  while runtime-lab services remain outside that OS profile);
- the precondition-tier → CVSS mapping.

Host-native rounds persist a 90-minute S0–S8 budget across assistant turns.
Integrated runners, stage-boundary checks, and the trusted shell hook enforce
that budget for the operations they cover. They cannot preempt host-model
reasoning, an already-running unsupported tool, or specialized paths outside
the hook; the budget is not a hard limit on the assistant's wall-clock turn.
The host must check it before and after long work and stop when it expires. A
three-candidate first wave and an early feasibility check for a matching
target-revision test environment help keep work bounded. A timed-out
whole-repository inventory may continue as a clearly marked partial audit; it
cannot support coverage-complete claims, broad exclusions, or negative
conclusions. One materially narrowed inventory retry is permitted.

Each bundled `CommandRunner` call also has an independent 15-minute wall-clock
cap, including direct build commands that bypass the S4 matrix budget. S4
round and per-candidate budgets are capped at 90 and 15 minutes; configuration
can lower those limits, and snapshots record requested and applied values.
Artifacts record each command's applied timeout and whether the request was
capped.

Host-native audit commands against a target checkout use the `audit-exec` CLI
wrapper, which requires the persisted round deadline and caps execution to the
requested timeout, 15 minutes, or remaining budget. It captures bounded output
and cleanup status in `S0/host-command-runs.jsonl`, and omits ambient
credentials from the child environment. An identical command is blocked after
timeout, failure, or incomplete cleanup unless the caller supplies
`--retry-reason` after confirming the prior process is gone and the scope or
environment changed. It is not an OS network/filesystem sandbox; its output is
`not-a-finding` and cannot validate a PoC. `audit-budget start --root` also
registers the active source root with a bundled Codex `PreToolUse` hook, which
blocks ordinary Bash/Unified Exec calls whose working directory is inside the
root, whose explicit path arguments resolve into it (including relative paths
and symlink aliases), or which recursively inspect/execute from one of its
ancestor directories, unless they invoke VulnGate's bundled deterministic
CLI. Ambiguous shell syntax from an ancestor is blocked. Direct host commands still use
`audit-exec`, and round-control calls must match the active project and round.
If the hook cannot parse an event while an audit registration may exist, it
denies the Bash call instead of silently allowing it.
It also rejects commands above 64 KiB or 2,048 shell tokens before path
inspection, keeping the hook's own work bounded.
The hook must be reviewed and trusted in Codex; specialized tool paths may
bypass it, so the wrapper remains the required path and this is not an OS
enforcement boundary. Release the registration with `audit-budget release`
when the round ends.

For supported shell HTTP cells, a per-run loopback proxy records bounded
response metadata and binds it to a run and cell digest; PoC output markers
remain claims. On macOS, the exact Seatbelt profile is preflighted before the
PoC starts and limits outbound traffic to the proxy's exact port on a
host-owned address. Seatbelt's `localhost` filter is not interface-exact, so
this is not a literal 127.0.0.1-only guarantee. Other
platforms and rejected profiles stop before PoC execution. Offline shell and
Java compile/run commands use a deny-all network profile; Java code that uses
network APIs remains unsupported until a protocol observer exists. Missing
responses are inconclusive. Loopback HTTPS is supported only as a declared
fixture with workspace-local certificate material; non-loopback origins,
chunked requests, and request bodies above 16 MiB are unsupported. PoC writes are confined to
per-run scratch/output roots. Reads from user-home trees, other mounted
volumes, per-user and shared temp trees, keychain stores, local SSH configuration/host
keys, sudoers, and Kerberos keytabs are denied except for explicit
workspace/runtime roots. Reads are default-deny: only standard OS tools, their
required libraries/frameworks, installed Command Line Tools/Xcode/Cryptex runtime
roots, the audit workspace, and explicit runtime roots are readable. The PoC PATH
is limited to `/usr/bin:/bin:/usr/sbin:/sbin`; credential stores remain denied
even when nested under an allowed system root. POSIX runs set hard
per-process CPU, virtual
address-space (4 GiB maximum, or a lower inherited hard cap), per-file size,
open-file and core-dump limits, plus a real-UID process ceiling based on the
startup count +128. Descendants inherit the address-space cap. A separate
process-tree watchdog sums sampled per-process RSS every 100 ms and stops the
run above 2 GiB. This is best-effort, may overshoot between samples, and can
double-count shared pages; monitor failure invalidates the run. It tracks
observed descendants by PID/start-time and signals the original process group
only while a sampled live member still confirms that group identity; detached
children are killed individually when observed. It cannot guarantee cleanup if
a child detaches and reparents between samples. Reads
outside the explicit allowlist are denied; aggregate scratch file count has no
hard quota. The runner samples each configured PoC scratch tree every 250 ms
and stops the tracked process group after it observes more than 256 MiB or 4096
entries. This best-effort stop-loss can overshoot between samples and misses
unlinked-open-file usage. The
Seatbelt profile denies direct `setsid` and `setpgid`
syscalls, blocking the straightforward process-group escape path. The runner
now enforces the wall-clock deadline even if a command closes both output
streams, then attempts to kill the original process group after the leader
exits. Darwin `posix_spawn` attributes can still request another
group/session, and a PoC can ask an external service to launch work, so cleanup
is not guaranteed for every spawn path.
Runtime-lab service processes do not inherit this PoC Seatbelt network/
filesystem profile. VulnGate reuses a healthy external service; a managed start
requires a recorded namespace/container backend, a one-time operator approval
bound to `run_id + config_digest + expiry`, and a successful POSIX resource-limit
preflight. Linux's preferred backend also attaches cgroup-v2 hard limits when
delegation is available; macOS requires a configured container/lightweight-VM
backend. A repository `allow_unconfined_start` boolean is never sufficient.
Managed services inherit the per-process CPU, file-size, descriptor, UID-process,
address-space and core-dump limits recorded in the service result and
`S4/processes.json`. A managed service also gets the sampled 2 GiB process-tree
RSS stop-loss. If the threshold is exceeded or its process-table monitor fails,
VulnGate stops the observed tree and aborts the shared S4 budget; active PoC
commands stop and later pipeline stages are skipped. This remains a best-effort
monitor that can overshoot. External-ready services are not managed
or monitored. The watchdog does not add filesystem-read or network isolation.

Target-specific independent effects are opt-in under a PoC's
`effect_observers` map. The matrix runner supports bounded `filesystem-diff`,
`process-effect`, `jvm-effect`, `jvm-protocol`, `fixture-db`, and
`authorization-state` before/after snapshots in addition to the HTTP semantic
observer. `jvm-protocol` requires a target-declared workspace-local JSON state
file and an allowlist of JSON-pointer paths; it observes protocol state by
digest and never parses PoC stdout/stderr. Paths are resolved under the audit
workspace; only names, counts, predicate outcomes, types, and digests are
persisted. An undeclared or unavailable observer produces `pending` and cannot
satisfy G4.

For example, a target adapter may declare:

```json
{"effect_observers":{"jvm-protocol":{"path":"state/jvm/protocol.json",
  "paths":["/phase","/authorization/status"]}}}
```

The adapter must create that bounded snapshot independently of PoC output; the
runner rejects paths outside the audit workspace.

## Historical CVE benchmark boundary

The deterministic benchmark has a revision-pinned
`historical-cve-benchmark-v1` fixture under `benchmarks/historical/`. It
expands each CVE into vulnerable, fixed, safe-sibling and environment-gap arms,
retains only bounded provenance (official HTTPS references, commits,
entry/sink locations, preconditions and a version matrix), and reports
candidate precision/recall plus discovery-time metrics. The checked-in sample
is static calibration data: vulnerable rows remain candidates and an unavailable
runtime remains an environment gap. Benchmark rows and results are always
`claim_status=not-a-finding`; they cannot satisfy S4/G4/G5 or replace runtime
evidence.

Run it with:

```bash
python3 scripts/agent_cli.py benchmark \
  --manifest benchmarks/historical/historical-cve-v1.json \
  --run benchmarks/historical/historical-cve-sample-run.json --json
```

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

`semantic-call-evidence-v2` adds the bounded interprocedural bridge that the
path and guard layers intentionally leave open. For each call-graph edge on a
flow it records the call-site, argument-to-parameter binding, tainted callee
parameters, and a return-shape hint; it then reports whether those bounded
identifiers reach the sink argument. Java callsites use JDK parse-only facts
and preserve their parser label in provenance; the adapter performs no type
analysis, class loading, annotation processing, or target execution. `bound` is useful positive static
evidence for choosing a trace, while `not-bound` and `unresolved` are manual
review leads, not safety claims. The layer does not resolve overloads, virtual
dispatch, DI, reflection, callbacks, async flow, types, transformations,
dominance, or feasibility, and stores no raw source text. Its
`semantic-call-candidates.json` entries remain `not-a-finding` with
`requires_manual_dataflow=true`.

The same layer performs a bounded multi-edge propagation over the path already
selected by the call graph. It recognizes only simple identifier aliases such
as `local = parameter` before `return local`, reports the alias and
`returned`/`assigned` shape, and leaves transforms, containers, attributes and
unresolved dispatch as gaps. Each row carries call-depth, node, path-count and
wall-clock budgets; a budget hit is an explicit `analysis_gaps` state, never a
negative result. This remains `heuristic-nearby` / `not-a-finding` evidence and
cannot satisfy S4/G4/G5.

```bash
python3 scripts/agent_cli.py semantic-calls <target> \
  --workspace <audit-dir> --show-candidates --json
```

`semantic-controlflow-evidence-v1` adds a bounded structural relation layer on
top of the guard rows. It groups brace/indent branch intervals and records
whether a sink is likely inside the guarded branch, after a terminating
rejection branch, or in an `else`/`except` alternate path. `dominates-likely`
is only a deterministic review signal: the layer does not execute a complete
CFG and does not model loops, short-circuit conditions, exceptions,
fallthrough, macros, or path feasibility. Rows and `cfg-*` candidates remain
`not-a-finding`, with `requires_manual_dataflow=true`.

```bash
python3 scripts/agent_cli.py semantic-controlflow <target> \
  --workspace <audit-dir> --show-candidates --json
```

`semantic-ast-evidence-v2` is the syntax-aware companion for Python and Java
targets. Python uses `ast`; Java consumes only JDK parse-mode facts. It records
branch membership, function or class scope, negative-test shape, direct terminal statements, alternate
`else`/exception paths, and parse failures. This replaces repeated line-range
guessing with a citable AST witness while deliberately stopping short of a
complete CFG, dominance/SSA, type/dispatch or runtime proof. Unsupported languages,
Java parser limits, and
syntax errors remain explicit gaps; `semantic-ast-candidates.json` contains
only `not-a-finding` research leads with `requires_manual_dataflow=true` and
does not store source text or AST dumps.

```bash
python3 scripts/agent_cli.py semantic-ast <target> \
  --workspace <audit-dir> --show-candidates --json
```

`semantic-transform-evidence-v1` follows validation and sanitization control
calls to the value consumed by a sink. It distinguishes a result that is
assigned/used, a discarded validator result, an overwritten transformed value,
and unresolved cross-symbol binding. This is bounded lexical evidence for
choosing the next source/runtime trace; it does not infer API semantics, types,
SSA, complete aliasing, framework filters, or safety. Its rows and
`semantic-transform-candidates.json` remain `not-a-finding` leads.

```bash
python3 scripts/agent_cli.py semantic-transforms <target> \
  --workspace <audit-dir> --show-candidates --json
```

`semantic-python-binding-evidence-v1` is the next language-aware adapter. For
Python files it parses one bounded AST and explores simple assignments,
aliases, guards, exception handlers, and finite loop/branch paths. It records
whether a transformed value is bound to the sink, whether the sink still sees
the raw value, whether paths merge, or whether the adapter cannot resolve the
expression. Java, Go, JavaScript and other unsupported languages are emitted as
explicit adapter gaps rather than being treated as safe. This is still an
abstract syntax witness, not a complete CFG/SSA/type/runtime proof; its rows
and `semantic-python-binding-candidates.json` remain
`claim_status=not-a-finding` with `requires_manual_dataflow=true`.

```bash
python3 scripts/agent_cli.py semantic-bindings <target> \
  --workspace <audit-dir> --show-candidates --json
```

### Shared syntax frontend (Python first)

`SemanticFrontend` provides `parse`, `symbols`, `calls`, `assignments`,
`branches`, `returns`, `parameters` and `arguments`. Python's standard-library
AST implements it locally without executing or importing target code. Syntax
facts have source-bound IDs, spans and lexical scopes; calls remain
`dispatch=unresolved`. These are not resolved types, data-flow edges or a CFG.

One build-local, content-digest-keyed session feeds Python symbol extraction,
AST branch witnesses and Python value binding. No new artifact is introduced:
`symbol-index.json` carries `parser`, `parse_status`, `source_revision`,
`analysis_gaps` and `claim_status`; existing semantic rows carry the same source
revision. `inventory-summary.json` → `counts.semantic_frontend` records files,
LOC, parse requests, cache hits/evictions, nodes, bytes and parser gaps, alongside
existing symbol/edge/flow/path counts and elapsed time. Rebuild existing indices
with `coverage --rebuild` after upgrading.

Bounds are 2,000,000 bytes/file, 100,000 AST nodes/file and depth 128. The shared
LRU retains at most 8 files and 200,000 nodes; each consumer's derived index also
retains at most 8 files. Eviction permits reparsing rather than unbounded memory.
Digest checks detect same-size/same-mtime edits. A symbol's recorded AST revision
that differs from the provenance build's source hash becomes an explicit mismatch
gap; this is not an atomic snapshot guarantee. Oversized prefixes never claim
to be hashes of complete files. Invalid syntax, decoding, source access or budget
failures remain gaps; Python symbol extraction may fall back to explicitly
heuristic regex. Java/JS/TS/Go are still regex fallback pending adapters.

Python declaration ranges include decorators, retain multiline parameter names
and nested scopes, and ignore definitions inside string literals. Repeated
qualified names get occurrence suffixes and `duplicate-definition` gaps rather
than silently merging identities. AST symbol confidence describes syntax only;
the call graph and semantic interpretations remain heuristic and `not-a-finding`.
Dynamic lookup, mutation, decorators, imports and full interprocedural semantics
are not resolved here, and S4/G4/G5 remain unchanged.

### Evidence provenance and correlation

The layered static passes share a deterministic `evidence-provenance-v1`
artifact at `state/<target>/coverage/evidence-provenance.json`. It joins raw
entry/sink/control/symbol facts to flow facts, then to semantic path, call,
guard, control-flow, AST, transform, and Python value-binding rows. Each row
has an `evidence_id`, `source_fact_ids`, `parent_evidence_ids`,
`independence_group`, `file`, `line`, and optional `span`; source text is not
copied.

The static candidate pool uses the same join. A candidate may retain several
derived evidence ids, but the scheduler counts its distinct independence
groups rather than treating each semantic restatement as an independent
witness. Duplicate damping additionally requires a complete lineage, the same
control and category, and a known shared verification question (transform/value
binding, branch/CFG/AST, or subject binding). Different or unknown questions
are not damped merely for occupying the same flow or location. Leads are not
removed. This is provenance and scheduling metadata only: every
record remains `claim_status=not-a-finding`, and it cannot promote a result or
override S4/G4/G5.

IDs incorporate full payload digests and source-file SHA-256 revisions. Nested
control/guard/transform/call/taint records retain their concrete upstream links;
`artifact_row_digest` and `artifact_field` locate them in the producer artifact.
Missing files, facts, upstream rows and unmodeled non-semantic candidate producers
are explicit `provenance_gaps`, not invented independent evidence. A complete
lineage does not mean complete semantics or a validated finding. Files are read
once per build, capped at 8 MiB/file and 64 MiB total; exceeded budgets are gaps.
Peer lists are stored once per group, not copied quadratically per candidate.
The snapshot is not atomic across passes; rerun with `--rebuild` after source
changes. Both configured/autonomous S1 and native CLI scheduling use this index.

```bash
python3 scripts/agent_cli.py evidence-provenance <target> \
  --workspace <audit-dir> --root <source-dir> --rebuild --json --limit 20
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
