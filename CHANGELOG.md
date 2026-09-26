# Changelog

All notable changes to VulnGate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.0] - 2026-09-26

### Changed

- Candidate intake admits prior-agenda and explicit user-priority IDs before
  ordinary category rotation. Runtime-backed candidates remain first; explicit
  user-priority IDs then reserve slots within the same finite round budget
  before category quotas, while prior-agenda candidates remain scoring hints.
  Intake artifacts record requested, admitted, and unmatched IDs, and schedule
  artifacts record selected and deferred explicit priorities.
- Parallel S4/S5 sub-agents are now explicitly optional: use them only when
  independent work is expected to save more time than probe, coordination, and
  review. Quickstart no longer instructs users to spawn one worker per
  candidate.
- S4 parallel receipts now record bounded, challenge-bound progress events and
  expose an `--inspect` snapshot. Five minutes is a liveness check interval;
  each worker keeps one fixed deadline within the shared candidate/round budget,
  so useful work is not discarded at five minutes and stale workers are not
  polled indefinitely. The Chinese skill guidance now matches the English
  execution contract instead of imposing a conflicting five-minute total cap.
- Runtime-lab service and process records now distinguish an unconfined
  VulnGate-managed service, an already-ready external process with unknown
  isolation, and a service that was not started. The lifecycle schema versions
  change so older service snapshots are not mistaken for the new contract.
- The audit skill entrypoint now loads only shared rules and phase routing; S1–S8
  details and optional S4 runtime-lab procedures live in on-demand references.
  The full Chinese mirror moved to `docs/AUDIT-PLAYBOOK.zh-CN.md`, outside the
  runtime skill context, leaving one English execution contract and removing
  duplicated operational rules from each audit's initial context.
- Audit skill examples no longer include `allow_unconfined_start: true` by
  default. The skill now requires explicit user authorization in the audit task
  before adding that setting to operator-controlled configuration.
- The 90-minute audit deadline now applies to all audit work, including host
  reasoning and browsing between commands. The skill requires a deadline check
  at every stage transition and investigation loop; expired source roots stay
  blocked until explicit release.

### Fixed

- Conclusion derivation now rebuilds evidence from raw S4 cells and refuses
  summary-only verdicts. HTTP status/body digests remain transport metadata and
  cannot confirm impact; summary rows retain observer and cell identifiers.
  S4 evidence policy v12 invalidates checkpoints written under the older
  conclusion contract. Executed Java cells without an independent runtime
  observer now record an explicit observer gap.
- The active-audit hook now resolves relative and symlinked path arguments
  against the Bash working directory. Recursive/metadata commands and
  interpreters issued from an ancestor of the registered source root are
  treated as in-scope, and ambiguous shell syntax from that location is
  blocked unless it matches the round's allowed VulnGate CLI contract. The
  ancestor-directory check also detects interpreters/build tools behind common
  command wrappers, not only when they are argv[0].
  While a guard is active, commands over 64 KiB or 2,048 shell tokens are
  rejected before path inspection so the hook cannot spend its timeout
  tokenizing a generated argv list.
  Oversized, malformed, or incomplete hook events also fail closed whenever
  the active-audit registry contains or may contain a registration.
- The English quickstart no longer requires an S4 spawn probe or worker
  creation on every audit; parallelism is chosen only when it is expected to
  save more time than its probe, coordination, and review costs.
- The plugin manifest and current project references now use the maintainer's
  `Zer0Gate` identity and current GitHub repository URL. Security-policy pages
  describe the platform-specific PoC boundary, observer limits, sampled
  stop-losses, and host-side audit deadlines without presenting them as a
  universal sandbox or hard wall-clock limit.
- Conclusion derivation now rebuilds evidence from raw S4 cells and refuses
  summary-only verdicts. HTTP status/body digests remain transport metadata and
  cannot confirm impact; summary rows retain the observer and cell identifiers
  for review.
- `agent_cli.py doctor --json` is now accepted for consistency with the other
  machine-readable commands. `doctor` already emitted JSON, but the rejected
  flag previously wrote argparse usage text into redirected `.json` artifacts.
- The coverage scheduler now rejects missing/invalid inventory scopes, failed
  coverage builds, empty source universes, and missing core index files instead
  of emitting an apparently ranked schedule from empty placeholders. Pipeline
  callers preserve bounded candidates with an explicit degraded note; the
  standalone `schedule` CLI exits without writing a coverage-ranked plan.
- Ordinary S4 replay/differential runtime-lab is now opt-in. An omitted or
  empty `runtime_lab` config no longer reruns every candidate across default
  replay and safe-mode cells; explicit runtime-lab options preserve the bounded
  research workflow. Disabled runs also return before source-revision lookup or
  service lifecycle cleanup, so opting out cannot stop an external service.
  The S4 policy version changes so old checkpoints are reevaluated without
  silently carrying forward implicit lab runs.
- The compatibility manifest no longer sets the unsupported top-level `hooks`
  field. Codex discovers the bundled `hooks/hooks.json` by default when the
  selected manifest does not override hook discovery. The installer now also
  copies the `hooks/` directory into the local plugin source.
- S4 Java and Web PoC prompts no longer require machine-readable stdout markers;
  markers remain optional untrusted claims. Candidate summaries set
  `needs-harness-observer` only when the runner reports that gap, and represent
  a missing captured HTTP response separately. Shell PoC repair is limited to
  one attempt after a concrete nonzero script/request failure, so absent
  evidence alone no longer triggers speculative rewrites. The S4 evidence
  policy version changes so older checkpoints are reevaluated under this rule.
- POSIX PoC resource limits are applied directly through Python's `resource`
  API in a minimal launcher, avoiding shell-specific `ulimit` syntax and unit
  differences. The 64 MiB file cap is set in bytes; the resource-policy version
  changes so older evidence is not reused.
- The command runner keeps enforcing its wall-clock deadline when a child
  closes stdout/stderr and makes a final process-group cleanup attempt after
  the leader exits. Runner policy versions change so older S4 checkpoints are
  not reused under the new cleanup behavior; a child that creates a new
  process group/session can still escape this cleanup boundary.
- Host-side command results now expose PID/start-time process-tree cleanup
  status even outside PoC matrix runs. The new `audit-exec` CLI requires an
  initialized round deadline, caps each source-checkout command at the
  requested timeout, 15 minutes, or remaining budget, and runs with a reduced
  environment. Standalone search/recursive inspection commands (`rg`, `grep`,
  `find`, `fd`, `ack`, `ag`, `du`) and potentially expensive Git metadata
  commands (`git grep`, `status`, `diff`, and `ls-files`) are further capped at
  120 seconds to prevent one broad scan or metadata walk from consuming most of
  the round. Inline-code interpreters (`python -c`/stdin, `perl -e`, `ruby -e`,
  `node -e`, and `osascript -e`) receive the same cap to keep inline scripts
  from bypassing command classification. Run longer scans through dedicated
  tools with their own enumeration deadlines.
  Attempts are recorded in `S0/host-command-runs.jsonl`; identical
  retries after a timeout, failure, or incomplete cleanup require an explicit
  reason after checking that the earlier process is gone and the scope or
  environment changed. `audit-budget start --root` registers the active checkout
  with a bundled Codex `PreToolUse` hook that blocks ordinary Bash/Unified Exec
  calls touching that root unless they use VulnGate's bundled CLI. Direct host
  commands still require the matching audit wrapper; round control commands
  must match the active project and round. Users must review and trust the hook;
  it is a tool guardrail, not an OS enforcement boundary, and specialized tool
  paths may bypass it.
  `audit-budget release` clears the registration at round end.
- Process-tree cleanup no longer discovers descendants through a vanished or
  PID-reused leader; it only retains previously observed children by
  PID/start-time identity. Managed services take their first RSS/process-tree
  sample synchronously before startup code can reap a short-lived leader.
- S4 now preserves stdout/stderr markers as untrusted PoC claims instead of
  treating them as target observations. Legacy cell markers are demoted the
  same way; incomplete, blocked, and failed runs cannot exclude a candidate.
- Shell S4 no longer spends up to two model repair rounds when all cells were
  blocked, timed out, or rejected before a usable execution. It repairs only
  after at least one cell actually launched without a harness stop condition.
- New-target autonomous preparation now starts the persisted round budget
  before type detection, copy, entry scanning, and JAR discovery. These stages
  share one 15-minute preparation slice tied to the original round start, so a
  retry cannot renew it; timeouts leave an S0 status with stage and path, and
  the later audit phases retain the unused round budget.
- Autonomous LLM HTTP requests and retry sleeps now use the remaining persisted
  round deadline instead of multiplying a 180-second per-request timeout
  across retries and JSON fallbacks. A call-budget or deadline stop writes an
  S0 report with completed stages, remaining time, and LLM usage. If S4 reaches
  the LLM budget, it cancels queued candidate work and preserves finished rows
  plus the pending candidate IDs in an S4 partial-results artifact.
- Autonomous CLI now exits with status 2 for explicit round-budget, LLM-budget,
  source-scan, S4-timebox, and active-audit-guard stops so schedulers cannot
  interpret an incomplete run as a successful audit.
- Unhandled round exceptions now preserve completed stages, the last checkpoint,
  budget and LLM usage in `S0/round-error-report.json`, and also return status 2.
- Autonomous library target preparation now scans all ten entry API patterns
  in one labeled source pass across all configured source roots, with one
  shared 10-minute deadline, instead of rescanning the repository once per API
  and source root.
- Full labeled source scans now stream ripgrep records directly into their
  uncapped labeled result groups, avoiding a second in-memory copy of all raw
  matches while preserving complete inventory results and the shared timeout.
- Fresh autonomous target preparation no longer builds the full coverage and
  semantic inventories before the round starts. Candidate-first work reuses a
  valid existing index or defers one bounded rebuild until the first candidate
  wave has been validated.
- Candidate IDs are enforced when S4 fallback cells are merged. S1 and S4–S8
  checkpoints now carry policy versions; a stale or missing earlier checkpoint
  invalidates downstream stages instead of silently reusing them. S8 requires a
  valid G5 record before confirming or attaching CVSS, and S7 skips reports
  without that record and marks superseded generated reports.
- GitHub search hits now flow into Novelty evaluation with issue/PR state,
  creation date, and merge time preserved. Missing query coverage, malformed
  search hits, and NVD channel failures cannot be reported as an authoritative
  empty scan. CVSS 3.1 parsing now validates metrics and uses Scope-specific PR
  weights and the zero-impact rule.
- Large-repository S1 inventory now streams supported source paths, reports
  progress, reads Git worktrees from the index instead of recursively walking
  every path, and stops with an explicit incomplete status at its scan deadline.
- Source-evidence CLI paths are resolved and checked against the authorized
  root before reading. Candidate coverage now persists control IDs and requires
  exact line-backed matches; file-only hints no longer close every region in a
  file, and flows require both their matched entry and sink.
- Matrix CLI input now retains residual, variant, consistency-lane, and
  per-version URL context. Replay cohorts deduplicate by verified pack digest,
  and dependency scanning uses ecosystem-specific Cargo, Composer, and Gradle
  manifest readers plus numeric fixed-version ordering.
- Runner metadata and operator guidance distinguish source-level egress
  screening from OS network isolation. Seatbelt profiles are preflighted before
  shell and Java compile/run commands; shell HTTP cells are limited to the
  observer port, while other Java/shell commands deny network access. Network
  Java PoCs and unsupported platforms fail closed. PoC writes are confined to
  per-run scratch/output roots. PoC filesystem access is now default-deny:
  reads are limited to standard OS tool roots, required system libraries and
  frameworks, installed Command Line Tools/Xcode/Cryptex runtime roots, the audit
  workspace, and explicit runtime roots. System helper execution is granted
  only to tool/runtime roots; library roots are read/map-only. User-home,
  mounted-volume, and temp roots are denied except for scoped workspace/runtime
  subtrees; keychains, local account databases, SSH host-key/config, sudoers,
  and Kerberos keytabs remain denied. PoC PATH is limited to
  `/usr/bin:/bin:/usr/sbin:/sbin`; Java preserves only its explicitly selected
  runtime `JAVA_HOME`. Runtime-lab managed services do
  not use this filesystem profile. Resource use remains partially
  unrestricted; POSIX runners now enforce per-process CPU,
  per-file size, open-file and core-dump limits, and cap the real-UID process
  count at startup baseline +128, and RLIMIT_AS caps each process's virtual
  address space at 4 GiB or a lower inherited hard limit. Java subprocesses get
  a 1 GiB default heap cap. A separate PoC watchdog samples process-tree RSS
  every 100 ms and stops a run above a 2 GiB summed-per-process threshold; this
  is best-effort, may overshoot, and can double-count shared pages. It uses PID
  plus start-time checks to kill observed descendants across process groups,
  but cannot guarantee cleanup if a child escapes and reparents between samples.
  Monitor failure invalidates the run. PoC scratch trees also get a best-effort
  250 ms stop-loss at 256 MiB or 4096 entries; it is not a filesystem quota,
  may overshoot between samples, and misses unlinked-open-file usage.
  Managed runtime-lab services now preflight and inherit those POSIX resource
  caps; they still do not inherit the PoC network/filesystem profile,
  and require `allow_unconfined_start: true` before VulnGate starts one.
  PoC Seatbelt profiles also deny direct `setsid` and `setpgid` syscalls, which
  blocks the straightforward process-group escape path. Darwin `posix_spawn`
  attributes can still request another group/session, so process-tree cleanup
  is not guaranteed against every spawn path or requests to external services.
  Service healthcheck aliases map directly to a numeric loopback address rather
  than relying on mutable host/DNS resolution.
  `0.0.0.0` is no longer classified as a loopback destination; wildcard and
  empty-address listener literals are explicitly rejected.
- S4 Java/shell matrix execution and runtime-lab replays now share hard
  round-wide (90 minute) and per-candidate (15 minute) wall-clock budgets by
  default. Expired cells are persisted as explicit stop-loss rows, completed
  cells remain available, and the S4 budget snapshot records elapsed time and
  exhausted candidate budgets. `TargetConfig` may lower either limit, but the
  round and candidate hard caps remain 90 and 15 minutes.
- The autonomous driver shares those budgets across parallel candidate workers,
  PoC repairs, and runtime-lab replays. An observer gap now ends PoC repair for
  that candidate immediately. Stale S4 policy checkpoints invalidate S5–S8,
  old finding documents are marked superseded, and an exhausted S4 round writes
  a progress report and stops before novelty/CVSS/report generation.
- The config-driven S1–S8 pipeline now creates or reuses a persistent round
  deadline, checks it before and after each stage, writes a stop report when it
  expires, and caps S4 to the remaining time. This is a stage-boundary stop-loss:
  it cannot interrupt a stage or host-model/tool call that is already running.
- The audit-round deadline now has an enforced 90-minute maximum across the
  CLI and both pipeline drivers. Legacy persisted deadlines longer than that
  are clamped from their original start time, so resuming a round cannot restore
  a multi-hour budget.
- Autonomous API-hint learning now runs inside the S0 round deadline instead
  of before the audit loop. S1.5–S4 prompt-source scans are capped by the
  remaining round time, and each round writes source-cache hit/read/timing
  telemetry under its S0 artifacts.
- Managed runtime-lab services now share the preflighted POSIX per-process CPU,
  address-space, file-size, descriptor, UID-process and core-dump limits. The active limits are
  recorded in service results and `S4/processes.json`; missing support blocks
  managed service startup. A sampled 2 GiB process-tree RSS stop-loss now kills
  the observed service tree and cancels the shared S4 budget on threshold or
  monitor failure, stopping active matrix commands and later pipeline stages.
  This is best-effort and may overshoot. External-ready services are not
  monitored. The service process tree still has no filesystem-read or network
  isolation.
- Bundled `CommandRunner` calls now have a 15-minute hard wall-clock cap even
  when a caller requests longer. S4 records the applied timeout and cap status;
  the runner and S4 evidence policy versions invalidate older runtime records.
- S4 round and per-candidate budgets now cap oversized configuration values at
  90 and 15 minutes respectively, and expose requested/applied values in the
  budget snapshot.
- S1 danger and target-rule digests now share one combined `rg` pass while
  preserving per-label caps. Finite S1 and candidate-prompt scans stream rg
  rows and stop when all label caps are met, avoiding an unbounded in-memory
  hit list. Candidate prompts combine up to six keywords into one scan while
  retaining the two-hit-per-keyword display limit; autonomous S1.5/S2/S3/S4
  share bounded source snapshots, and S3/S4 reuse bounded keyword anchors.
  Unchanged anchored files are normally read once per round; source changes or
  LRU eviction can trigger another read.
  Extracted snippets persist in a bounded cache keyed by source-root identity,
  relative path, content SHA-256, anchor, and extraction policy, so source edits
  invalidate prior snippets. Per-round S0 telemetry records source bytes read,
  cache hits, extraction/flush timings, and terminal status. Early-stopped
  ripgrep streams now close both pipe handles as well as terminating the child.
  Autonomous coverage rebuilds use the configured
  source-enumeration deadline and persist running, complete,
  incomplete, or failed status; an incomplete scope with old derived indices
  now withholds those candidates instead of reusing stale artifacts. The
  same-file source/sink digest now uses the bounded Git-index source iterator
  and records a timeout gap instead of recursively walking repository metadata.
- Labeled ripgrep scans now apply one wall-clock budget across all configured
  source directories. Ripgrep failures and malformed structured output raise
  errors instead of becoming empty-hit results. Autonomous S2 scheduling and
  prompt coverage blocks now require a usable current scope, and `--force`
  exposes the already-defined one-retry path for an unchanged failed inventory.
- Autonomous S1 now records incomplete danger/target-rule scans explicitly,
  stops a candidate round cleanly when a later source scan times out, and reuses
  the capability inventory result within the same round instead of refreshing
  coverage again during S2.
- Autonomous rounds now reuse only a complete, scope-matched capability index
  before S2. A missing or stale index no longer blocks the first candidate
  wave: the round validates that wave first, then may make one five-minute
  index attempt only when at least 15 minutes remain. If S2 has no candidates,
  one bounded index attempt may supply a lead. S1 composite-chain candidates
  remain eligible during index deferral because they come from the current
  bounded source-to-sink pass; incomplete or stale index rows stay withheld.
- Large candidate-pool intake now classifies each row once and computes an
  order-independent streaming multiset digest instead of allocating, sorting,
  and serializing a duplicate full-pool manifest. Pinned-candidate lookup also
  indexes only requested IDs.
- Stage-only pipeline runs now require prior checkpoints and current policy
  versions, restore the persisted S2/S3 candidate selection, and mark downstream
  checkpoints for recomputation after a stage is rerun.
- Host-native rounds now use a persistent 90-minute S0–S8 deadline through the
  `audit-budget` CLI, with a three-candidate initial wave and early target-revision
  feasibility checks. A timed-out full-repository inventory may continue as an
  explicitly partial candidate audit; one materially narrower retry is allowed.
  Partial coverage cannot support coverage-complete claims or exclusions.
- The host-native playbook now prioritizes candidate feasibility/review before
  the optional whole-repository index; a full index no longer blocks the first
  candidate wave. Parallel workers are optional, limited to independent tasks,
  and time-boxed; coverage completeness cannot override the round deadline or
  evidence-yield stop-loss.
- Shell matrix cells with a declared loopback HTTP target now route proxy-aware
  clients through a per-run harness observer. Only captured response metadata can
  populate `HTTP_CODE`; PoC stdout remains an untrusted claim. On macOS, a
  preflighted Seatbelt profile restricts the PoC process tree to the observer's
  exact observer port on a host-owned address; Seatbelt's `localhost` filter
  is not interface-exact. Unsupported platforms stop before execution. The observer rejects
  unsupported HTTPS, origins, and oversized/chunked requests; missing captures
  remain inconclusive on all platforms.

### Added

- Added opt-in `allow_partial_coverage` for config-driven rounds. An incomplete
  S1 scope can continue with configured candidates only; index-derived leads,
  coverage-aware scheduling, and stale-index coverage refresh are skipped.
  Old downstream checkpoints are invalidated on entry; partial-mode checkpoints
  can resume after interruption. S8 and the target coverage summary remain
  `scope-incomplete`, with unknown uncovered counts and no coverage-closure
  claim. Default behavior still stops.
- Added scope-bound coverage closure and finite `candidate-intake-v1` scheduling:
  the full static pool is retained, while only a rotating active window reaches
  S2/S3/S4. Legacy `max_candidates: 0` now maps to a finite budget. Static
  evidence remains `not-a-finding` and cannot alter S4/G4.
- Added JDK parse-only Java facts to `semantic-ast-evidence-v2`,
  `semantic-call-evidence-v2`, call-graph edges, and evidence provenance.
  The adapter does not analyze, load, compile, process annotations, or execute
  target code; unresolved types/dispatch and parse limits remain explicit gaps.
- Added challenge-bound S4 delivery controls: `spawn-probe-v2` requires a
  fresh nonce in both heartbeat and reply, and `parallel-receipt-v1` requires a
  matching digest for each candidate's `matrix-runs/<id>/cells.json` before
  runtime artifacts are accepted.
- Added `final-evidence-consistency-v1` at S8. It re-runs G4/G3 before ledger
  rendering, demotes unsupported confirmations, withholds CVSS from unconfirmed
  rows, and labels an unconfirmed `candidate-0day` only as a `not-a-finding`
  novelty hypothesis.
- Historical CVE benchmark validation now requires advisory/source/fix
  references and verifies that vulnerable, fixed, safe-sibling, and
  environment-gap arms remain pinned to their declared baseline commits.

- Added a shared `SemanticFrontend` syntax interface and bounded Python AST
  implementation, consumed by symbol extraction, AST control-flow witnesses
  and Python value binding. Source-digest caching avoids redundant parsing;
  parser gaps and budgets are recorded in existing artifacts, not a new schema.
  Python symbols now retain multiline parameters and nested names, exclude
  string pseudo-definitions, and explicitly mark repeated definitions. Fixed
  file-symbol ties that attributed a whole-file handler to the synthetic file.
  Syntax confidence does not promote flows, effects, findings or S4/G4/G5.
- Added `evidence-provenance-v1` for deterministic lineage from raw source
  facts through semantic layers to static candidates. Related path, guard,
  call, control-flow, AST, transform, and value-binding rows now share an
  `independence_group`, revision-bound IDs and explicit missing-parent gaps;
  S2 keeps the leads and damps only same-control, same-question restatements,
  without counting repeated derived rows as independent evidence. Configured,
  autonomous and native CLI paths share the persisted graph. Fixed missing S1
  imports that prevented semantic/threat-model evidence mirroring.
  All provenance remains `not-a-finding` and
  cannot change S4/G4/G5.
- Added `semantic-python-binding-evidence-v1` and
  `semantic-python-binding-candidates.json`. The bounded Python AST adapter
  follows simple assignments, aliases, guards, exceptions, and finite branch /
  loop paths, preserving raw-at-sink, mixed, derived, unresolved, and
  unsupported-language states as `not-a-finding` research evidence.
- Added `agent_cli.py semantic-bindings` and merged language-aware value-flow
  gaps into the static S2 candidate pool. The adapter does not claim complete
  CFG/SSA, type identity, runtime effect, sanitizer semantics, or safety.
- Added `semantic-transform-evidence-v1` and
  `semantic-transform-candidates.json`. S1 now records bounded evidence for
  whether validation/sanitization results are bound to the same sink input,
  including discarded results, overwritten values, post-sink controls, and
  cross-symbol gaps. All leads remain `not-a-finding` and require manual data
  flow verification.
- Added `agent_cli.py semantic-transforms` and merged transform-binding gaps
  into the static S2 candidate pool without treating a nearby sanitizer call
  as proof that the sink is protected.
- Added deterministic `semantic-path-evidence-v1` and
  `semantic-path-candidates.json`. S1 now records bounded control-order
  evidence and same-symbol parameter/alias reachability, while leaving
  cross-symbol data flow, branch dominance, and all claim promotion to S3/S4.
- Added `agent_cli.py semantic-paths` and merged semantic path leads into the
  static S2 candidate pool.
- Added `semantic-guard-evidence-v1` and `semantic-guard-candidates.json`.
  S1 now records bounded branch posture and subject/object binding evidence for
  semantic flows, including terminating-guard, nested-branch, non-branch-check,
  overlap, mismatch, and unresolved states; all leads remain `not-a-finding`.
- Added `agent_cli.py semantic-guards` and merged guard leads into the static
  S2 candidate pool. The new layer does not claim branch dominance, object
  identity, authorization correctness, or a vulnerability.
- Added `semantic-call-evidence-v1` and `semantic-call-candidates.json`.
  S1 now performs bounded one-hop call-site argument binding, tainted
  parameter propagation, and return-shape hints across source-to-sink flows;
  unresolved dispatch, arity, and sink binding remain explicit research gaps.
- Added `agent_cli.py semantic-calls` and merged interprocedural binding leads
  into the static S2 candidate pool without promoting static data flow to a
  finding or runtime effect.
- Extended semantic call evidence across bounded multi-edge paths. Simple
  `parameter -> local alias -> return` shapes now retain returned aliases and
  `returned`/`assigned` call-site context; call-depth, node, path-count and
  wall-clock budgets produce explicit analysis gaps instead of silently
  dropping work. All rows and candidates remain `not-a-finding` and cannot
  satisfy S4/G4/G5.
- Added `semantic-controlflow-evidence-v1` and
  `semantic-controlflow-candidates.json`. S1 now records bounded structural
  relations for guarded branches, terminating rejection paths, and alternate
  `else`/`except` paths without claiming a complete CFG or dominance proof.
- Added `agent_cli.py semantic-controlflow` and merged control-flow gaps into
  the static S2 candidate pool as `not-a-finding` research leads.
- Added `semantic-ast-evidence-v1` and `semantic-ast-candidates.json`. Python
  files now get bounded AST branch/scope witnesses for terminating guards,
  alternate paths, exception handlers, and parse gaps without storing source
  text or claiming a complete CFG.
- Added `agent_cli.py semantic-ast` and merged AST structural gaps into the
  static S2 candidate pool as `not-a-finding` research leads.

### Fixed

- Loopback service healthchecks now ignore inherited proxy environment
  variables, so a forced host proxy cannot turn a healthy local S4 service into
  a false `precondition-unavailable` result.

## [1.2.0] - 2026-09-21

### Added

- Added `research-budget-v1` outcome-adaptive finite-budget policy. S8 now
  aggregates agenda execution by research surface, cost, and information gain,
  emitting bounded recovery, exploitation, exploration, and low-yield cooldown
  hints for the next agenda. The policy is inspectable through
  `agent_cli.py research-budget`, remains `not-a-finding`, and cannot change
  candidate status, CVSS, G4, or G5.

- Added `research-agenda-outcome-v1` execution feedback. S8 joins the prior
  active queue with the actual schedule and bounded S4/S8 observations, records
  productive information, falsifiers, no-information repeats, environment
  gaps, and not-executed work, and feeds the latest outcome into the next
  agenda. `agent_cli.py research-agenda-outcomes` can inspect or rebuild it;
  all metadata remains `not-a-finding` and cannot change candidate status,
  CVSS, G4, or G5.

- Added `research-agenda-v1` active research budgeting. S8 converts the
  normalized strategy into a bounded selected/deferred/hold queue with
  expected information gain, estimated cost, prerequisites, and per-surface
  diversity; the scheduler consumes only exact agenda matches as a small
  priority signal, and `agent_cli.py research-agenda` can inspect or rebuild
  it. Agenda metadata remains `not-a-finding` and cannot change candidate
  status, CVSS, G4, or G5.

- Added `research-consistency-recheck-v1` execution closure. S4 now expands a
  pending consistency action into bounded positive/negative or environment-gap
  lanes and records replay count, fixture/context identity, comparison status,
  state-reset, typed-effect/safe-equivalent and environment witnesses without
  persisting raw process data. S8, the portfolio, the strategy layer, replay
  packs, and `agent_cli.py research-consistency-rechecks` distinguish observed,
  partial, environment-gap, and not-executed closure; all metadata remains
  `not-a-finding` and cannot change candidate status, CVSS, G4, or G5.

- Added `research-consistency-v1` for bounded cross-round evidence checks.
  `agent_cli.py research-consistency` compares effect, reproduction, comparison,
  runtime-state, and context classifications from `research-memory`, while
  portfolio and strategy convert conflicts into controlled follow-up actions.
  S8 and replay packs persist the target/round artifact; all metadata remains
  `not-a-finding` and cannot affect candidate status, CVSS, G4, or G5.

- Added `research-consistency-action-v1` controlled recheck contracts.
  `agent_cli.py research-consistency-actions` materializes fixed isolation axes,
  paired lanes, required observations, and falsifiers; S2 emits a bounded
  `consistency-recheck` plan and S4 carries the normalized contract through
  MatrixCell, PoC environment, and runtime-lab fixtures. Action artifacts and
  replay-pack provenance remain `not-a-finding` and cannot affect candidate
  status, CVSS, G4, or G5.

- Added `research-replay-pack-v1` provenance packs. S8 and
  `agent_cli.py replay-pack` retain only allowlisted workspace-local artifact
  names, schema versions, sizes, SHA-256 fingerprints, and bounded lane/
  comparison summaries. `replay-cohort-calibrate --pack` rejects incomplete or
  digest-inconsistent packs; all replay provenance remains `not-a-finding` and
  cannot affect candidate status, CVSS, G4, or G5.

- Added bounded cross-project replay calibration, `research-replay-cohort-v1`.
  `agent_cli.py replay-cohort-calibrate` aggregates explicit per-target
  `research-replay-calibration-v1` artifacts by distinct-project sample counts,
  preserves per-surface sufficiency, and activates a one-to-two-round
  zero-information replacement policy only when the cohort is sufficiently
  observed. Target-local calibration takes precedence; insufficient cohorts
  retain the default. The artifact is `not-a-finding` and cannot affect
  candidate status, CVSS, G4, or G5.

- S8/S2 now produce `research-replay-calibration-v1` from bounded real-project
  round history. `agent_cli.py replay-calibrate` measures replacement hit rate,
  unproductive repeats, environment recovery, fixture-budget truncation, and
  comparison gaps; only a validated sample can change the replacement
  zero-gain threshold between one and two rounds. The artifact is
  `not-a-finding` and cannot affect candidate status, CVSS, G4, or G5.

- S2/S4 now carry `comparison-orchestration-v1` for bounded cross-version and
  fix-completeness research. Configured version pairs are compared on the same
  fixture/lane, read-only patch parent/fixed references remain explicit
  build-required arms, and sibling hints remain pending until a matching lane
  runs. S4 distinguishes bucket changes, signature-only drift, missing runtime
  cells, and unexecuted source/sibling arms; S8 retains the bounded comparison
  state as research-only memory; all comparison output remains `not-a-finding`.

- S4 now supports explicit `source_revision_artifacts` arms for exact before/
  after commit references. Workspace-local JAR/WAR/ZIP files are validated and
  fingerprinted, then executed through the existing isolated Java runner on
  the same fixture/lane; VulnGate never performs checkout or builds source.
  Missing, invalid, non-Java, or unavailable artifacts remain explicit
  `precondition-unavailable`/`inconclusive` research gaps, and executed source
  comparisons remain `not-a-finding` metadata.

- S4 runtime research now consumes the shared surface plan through
  `surface-variant-fixture-v1`. Within the configured fixture budget, each
  selected Web/protocol/cloud/mobile/native variant expands into positive,
  negative/safe, and environment-gap runner cells with fixed state-step
  identifiers. PoCs receive only bounded `VULNGATE_VARIANT_*` metadata, and
  `S4/runtime-lab.json` records lane context and truncation explicitly while
  preserving `not-a-finding`; no lane declaration satisfies G4/G5 or changes
  CVSS.

- S4 now emits `surface-variant-evidence-v1` from actual replay/differential
  rows. The bounded witness layer distinguishes observed, partial,
  environment-gap, and not-executed lanes; only a complete observed STEP trace
  satisfies state-sequence, while typed-effect and safe-equivalent remain
  separate signals. S8/S2 reuse missing signals as next-probe hints, without
  persisting raw output or changing candidate status, CVSS, G4, or G5.

- S8 now aggregates persisted lane witnesses as
  `surface-variant-coverage-v1` inside `research-portfolio-v1`. Historical and
  latest status/signal counts stay separate; only a latest actual `observed`
  lane closes, while partial, not-executed, and environment-gap lanes produce
  exact research-key next probes. The coverage view remains
  `not-a-finding` and cannot affect candidate status, CVSS, G4, or G5.

- S2 experiment plans now carry a shared `surface-variant-plan-v1` for Web,
  protocol, cloud, mobile, and native research. Each selected state-machine,
  identity-boundary, lifecycle, route, parser, or method-body variant is
  expanded into positive, negative/safe, and environment-gap lanes with fixed
  observation signals and falsifier codes. Strategy guidance, config-driven
  S2, and autonomous S2 reuse the same bounded plan; it remains
  `not-a-finding` metadata and cannot satisfy G4/G5.

- S8/S2 now produce `research-strategy-guidance-v1`: a bounded next-action layer
  that joins real strategy observations, latest human review status, and
  explicit portfolio variant gaps. It can recommend environment repair,
  negative-control/capability/typed-effect follow-up, residual or new-variant
  replay, scope reframing, or replacing a zero-information experiment. The
  guidance is persisted at `state/<target>/coverage/research-guidance.json` and
  `S8/research-guidance.json`, and only adjusts research scheduling; it never
  changes candidate status, CVSS, G4/G5, or the `not-a-finding` boundary.

- S8 now feeds bounded real S4 observations back into matching research-strategy items. The new `research-strategy-feedback-v1` snapshot records current/history observation status, missing required signals, explicit falsifier observations, and per-round information gain without copying runtime output; complete items with zero new signal no longer receive a strategy scheduling nudge.

- S3 residuals now carry a bounded S2->S4 closure contract. The matrix parser
  records only allowlisted `RESIDUAL_ID` / `RESIDUAL_STATUS` /
  `RESIDUAL_FALSIFIER` observations; S8 advances a residual to
  `residual-falsified` only after a declared contract matches an executed
  no-effect cell. Gate failures, unavailable prerequisites and effect-bearing
  cells remain pending, and `S4/residual-closure.json` plus all memory and
  portfolio views remain `not-a-finding`.

- Composite source-to-sink paths that include an authorization boundary are now
  promoted from S1 hints into deterministic `chain-*` S2 candidates. The
  candidates carry credential-free authorization cases, source locations and
  heuristic provenance, and are scheduled identically by the config-driven and
  autonomous pipelines.
- S4 cells now support a bounded stateful/race experiment contract: declared
  step identifiers, concurrency and availability probes are passed to Java and
  Shell PoCs, while ordered `STEP`/`STEP_EVIDENCE`/`STATE` traces and the
  declaration are persisted. Declarations remain metadata; A:H still requires
  observed concurrent saturation and service unavailability.
- S2 now emits deterministic, bounded `experiment-plans.json` records for the
  complete candidate pool. Plans carry required observations and explicit
  falsifiers for baseline, authorization, state/race, availability, fix
  variants and typed effects, and are explicitly marked `not-a-finding`.
- S1 now builds a bounded capability-primitive graph from the persisted
  entry/sink/flow indices and promotes explicit `read` / `write` / `exec` /
  `ssrf` / credential/evaluation chain hypotheses into S2. Every path records
  observed versus missing primitives, provenance, transition rules and a
  minimal verification sequence; capability paths remain
  `claim_status=not-a-finding` until manual data-flow and runtime typed-effect
  evidence exist.
- Capability-chain candidates now carry a bounded `capability_contract` into
  every S4 Java, shell, autonomous and CLI-manifest cell. PoCs can emit
  ordered `CAPABILITY`/`CAPABILITY_EVIDENCE` and
  `TRANSITION`/`TRANSITION_EVIDENCE` traces; S4 summarizes them as
  `no-trace`/`partial`/`complete` and keeps typed effects separate from
  intermediate capability observations. A complete trace remains
  `claim_status=not-a-finding`.
- The directed fuzz path now persists a deterministic `fuzz-corpus.json`,
  stable fixture ids/content digests, and minimized reproducer metadata. A
  bounded runtime lab replays selected reproducers and compares every
  configured version × SafeMode cell, separating stable reproduction, bucket
  changes, signature-only drift, and precondition/harness gaps in
  `runtime-lab.json`; the lab remains `not-a-finding` evidence.
- Ordinary Java and shell S4 PoCs now have the same bounded fixture adapter.
  It derives a stable identity from the execution context without persisting
  raw arguments, reuses the isolated matrix runners for replay and version ×
  SafeMode comparison, and writes `S4/runtime-lab.json`; replay and
  differential gaps remain `not-a-finding` evidence.
- Stateful S4 runs can now declare a bounded local `runtime_lab.service`.
  Service commands are argv-only and workspace-local, health checks are
  loopback-only, owned process groups are always torn down, and
  `S4/processes.json` records PID/port lifecycle without command or secret
  values. `S4/runtime-lab.json` also records a credential-free configuration
  snapshot and stable `authz_fixture_id` values for tenant/object comparisons.
- S8 now persists target-scoped cross-round research memory. Stable mechanism
  keys, bounded replay/differential states, environment gaps, and next-probe
  hints are merged idempotently into `state/<target>/research-memory.json`;
  the scheduler dampens exact stable repeats and prioritizes actionable
  differences while preserving every candidate and keeping the memory
  `claim_status=not-a-finding`.
- Research memory now absorbs a bounded S4 context view (service readiness and
  config digests, version/URL digests, authorization fixture IDs, and patch
  variant hints) without copying commands, credentials, raw arguments or
  process output. `agent_cli.py review` records accepted, rejected,
  needs-evidence, or scope-corrected feedback in
  `state/<target>/review-feedback.json`; S8 snapshots it and the scheduler
  uses it only to reprioritize follow-up research.
- Added the deterministic `research-benchmark-v1` evaluator and a safe sample
  manifest/run. It measures observation coverage, confirmed precision/recall,
  negative-result safety, environment-gap fidelity, justified versus
  unjustified research-key repeats, evidence completeness, decision stability,
  and CVSS/severity calibration; benchmark output remains
  `claim_status=not-a-finding`.
- Added the first revision-pinned `historical-cve-benchmark-v1` fixture under
  `benchmarks/historical/` for PyYAML CVE-2017-18342, Apache Commons Text
  CVE-2022-42889, and Lodash CVE-2021-23337. Each case has vulnerable/fixed/
  safe-sibling/environment-gap arms, official HTTPS provenance, exact commits,
  entry/sink and precondition metadata, and a four-point version matrix.
  Historical static scoring adds candidate precision/recall, candidate count,
  time-to-first-useful-candidate and time-to-confirm; all rows remain
  `claim_status=not-a-finding` and do not weaken S4/G4/G5.
- Added deterministic `research-benchmark-feedback-v1`: benchmark metrics can
  produce capped alert codes, signed scheduler-factor deltas, and bounded
  experiment observations. CLI scheduling, config-driven S2, and the
  autonomous loop accept the feedback explicitly; plans and schedules record
  the source and actual adjustments while preserving default behavior and
  never changing G4/G5 conclusions or CVSS.
- Added the cross-surface synthetic research benchmark and sample run. Fifteen
  bounded cases cover web, protocol, cloud, mobile and native surfaces, with a
  vulnerable, negative and environment-gap variant per surface. The evaluator
  preserves surface/variant metadata and reports `research_profile` plus
  `coverage_by_surface`; tool or runtime gaps remain pending and the artifact
  remains `claim_status=not-a-finding`.
- Added bounded surface-aware benchmark feedback. Weak per-surface coverage,
  evidence completeness, negative-result safety, or environment-gap fidelity
  produces allowlisted `surface_guidance`; only explicitly matching candidates
  receive a small scheduler priority delta, and matching experiment plans gain
  the corresponding observations/falsifiers. Findings, CVSS and G4/G5 remain
  unchanged.
- Added bounded longitudinal benchmark comparison via `--baseline`. The new
  `research-benchmark-trend-v1` artifact compares fixed aggregate and common
  surface metrics, turns regressions into allowlisted feedback, and preserves
  all benchmark safety boundaries.
- Added the bounded `research-portfolio-v1` project view. S8 aggregates
  research memory, review feedback and benchmark context by research surface,
  target type, attack class, variant and precondition class, and emits
  deterministic `next_probes` without promoting portfolio state to a finding.
- The scheduler now gives only an exact research-key or multi-dimension
  explicit portfolio match a small, recorded priority nudge; broad/free-form
  labels cannot steer a candidate and the nudge never changes G4/G5, CVSS or
  finding status.
- Added bounded `threat-model-v1` attacker-path artifacts. S1 now joins trust
  boundaries, entries, flows, sinks, static control posture, unresolved
  reachability, and matching capability hypotheses; the scheduler prompt and
  `agent_cli.py threat-model` expose the same view. Unmapped regions remain
  pending and every row is forced to `claim_status=not-a-finding`.

### Documentation

- Added the Chinese research-capability roadmap in
  [`docs/RESEARCH-ROADMAP.zh-CN.md`](docs/RESEARCH-ROADMAP.zh-CN.md), including
  acceptance criteria for capability-graph, runtime-lab, memory and evaluation
  stages.
- Documented the `capability` CLI report and the additional S1/S2 coverage
  artifacts in the VulnGate audit skill.
- Documented cross-round research memory, its state taxonomy, and its
  separation from G4/G5 conclusions in the roadmap, README, evolution notes,
  and audit skill.
- Documented the bounded service lifecycle, configuration snapshot, process
  registry, and credential-free authz fixture contract in the roadmap, README,
  quickstart, evolution notes, and audit skill.
- Documented the replayable human-review feedback contract, review CLI, bounded
  statuses/reason codes, and its separation from G4/G5 conclusions.
- Documented the benchmark manifest/run contract and the metrics that constrain
  planner, scheduler and conclusion-rule regressions.
- Documented the benchmark feedback artifact, `--feedback-out`, explicit
  `schedule --benchmark-result` wiring, target-config opt-in, and its strict
  `not-a-finding` boundary.
- Documented the cross-surface benchmark fixture, per-surface coverage metrics,
  and the rule that unavailable runtime or analysis tools remain pending rather
  than becoming negative evidence.
- Documented surface-aware scheduling/planning, exact metadata matching, and
  the bounded `surface_guidance` safety boundary.
- Documented `--baseline`, trend artifacts, fixed comparison metrics, and the
  rule that regressions are research guidance rather than findings.
- Documented the project research portfolio, its S8 artifacts, bounded variant
  coverage and next-probe contract, including its strict `not-a-finding`
  boundary.
- Documented the attacker-path threat model, its target/round artifacts, CLI,
  trust-boundary assumptions, unresolved-region handling, and strict
  separation from vulnerability, CVSS, and G4/G5 conclusions.
- S3 residuals now persist across S8 as bounded research metadata. Research
  memory retains only controlled kind/reason codes, bounded locations, probe
  digests and plan presence; the project portfolio emits `pending-residual`
  next probes even when the primary replay is stable. The residual loop stays
  `claim_status=not-a-finding` and never copies raw probe text.
- S2 now synthesizes a bounded `research-strategy-v1` from the attacker-path
  model, unresolved coverage, residual-aware portfolio probes, cross-round
  memory and benchmark context. Each strategy item carries fixed required
  observations and falsifiers; explicit path/research-key matches can receive
  only a small scheduler nudge and remain `claim_status=not-a-finding`.

## [1.1.0] - 2026-09-16

### Added

- Expanded the deterministic audit layer while preserving the Codex plugin
  identity, manifest, installer and host execution contract.
- Full source inventory and ledger-derived audit coverage; heuristic symbol,
  call and flow indices; per-path security-control gaps and sibling differentials.
- Coverage-aware candidate scoring, category quotas and deferred candidates;
  `coverage`, `schedule`, `controls` and `differential` helper commands.
- macOS `.app`/`.dmg`/`.pkg` adapter, Mach-O metadata reconstruction, Electron
  ASAR/source maps, Java views, native source patterns and `native-app` rules.
- Pipeline `--workspace` for isolated evidence and checkpoints; explicit missing
  external-tool diagnostics; imported regressions and Codex integration tests.

### Fixed

- S3-S8 now consume S2's scheduled selection on both fresh and resumed rounds,
  including an empty selection, rather than the unscheduled configuration pool.
- Native launchers resolve their own Codex plugin and selected Python interpreter;
  no external agent runtime or arbitrary installed-cache lookup is required.
- ASAR parsing reads the actual Chromium Pickle string length, including padding,
  rejects truncated data and prevents extraction through escaping paths/symlinks.
  Unsupported unpacked/link entries remain explicitly counted as skipped.
- External JAR paths sharing the workspace's text prefix no longer crash S1.
- Installer packages runtime/documentation paths explicitly, includes the adapter,
  excludes local research artifacts, and propagates plugin validation failures.
- Correct host instructions for `source-map`, `matrix` and `novelty`, with explicit
  coverage bootstrap and refresh steps for Codex's host-native mode.

See [feature evolution notes](docs/EVOLUTION.md) for the capability map and validation.

## [1.0.1] - 2026-09-03

### Fixed

- **Thread-safe skill cache updates:** the installer preserves compatibility
  aliases for previously installed versioned cache paths, so an audit task that
  was already running does not lose its loaded `SKILL.md` when a newer plugin
  version is installed. A missing thread-bound skill path is now treated as a
  cache error rather than silently switching versions.

## [1.0.0] - 2026-09-03

This is the first formal VulnGate release. It promotes the previously validated 0.2.x development line to a stable plugin release.

### Included

- Complete S1→S8 source-audit workflow for libraries, frameworks, middleware, logging libraries, expression engines, message/RPC stacks, and applications.
- Runtime-backed S4 PoC matrix evidence with version, SafeMode, precondition, authorization, and per-cell JDK tracking.
- Isolated PoC execution environments with explicit network and side-effect boundaries.
- Novelty-query provenance, retry/error recording, upstream issue/PR metadata, CVSS consistency checks, and disclosure-ready ledger/report output.
- Regression coverage for matrix convergence, runtime selection, environment isolation, novelty failures, and conclusion parsing.

## [0.2.29] - 2026-09-03

### Fixed

- **S4 execution convergence:** persisted matrix results and host-sequential fallback evidence now take precedence over agent/probe timeout metadata. Multiple PoCs for the same candidate no longer overwrite one another. Execution states are explicitly separated into `unexecuted`, `run-failed`, `gate-blocked`, `precondition-unavailable`, `executed-no-effect`, and `executed-with-effect`.
- **PoC environment isolation:** PoCs receive only a minimal explicit environment. Agent API URLs, proxies, and credentials no longer affect loopback determination or flow into PoC subprocesses. Novelty uses a separate GitHub API channel.
- **Per-cell JDK selection:** matrix cells support `required_runtime`, `java_bin`, and `java_home`; the actual `java`/`javac` paths and versions are persisted per cell. A cell that declares JDK 8 but cannot access JDK 8 is recorded as `precondition-unavailable` instead of silently using the default JDK.
- **Ledger status parsing:** conclusions such as `确认；High；...` remain recognized as confirmed records, and Novelty persistence now includes authentication source, retries, errors, and issue/PR title/status metadata.

## [0.2.28] - 2026-09-02

### Fixed

- **Novelty query integrity:** ordinary GitHub network failures no longer degrade silently to an empty result. S5 records `query_errors` and marks the query non-authoritative so “query failed” cannot be misreported as “no public record found.”

## [0.2.27] - 2026-09-02

### Added

- **Target-specific S1 rules:** choose entry, authorization, protocol, file-flow, serialization, and dangerous-sink rules by `library`, `web-app`, `middleware`, `message-rpc`, `logging`, or `expression`; persist `S1/target-rules.json`.
- **Composite-chain hints:** heuristic paths that contain both an authorization boundary and a dangerous sink are persisted to `S1/composite-chain-hints.json` to prompt validation of whether transformed objects remain authorization-protected. These hints do not replace data-flow or runtime evidence.

## [0.2.26] - 2026-09-02

### Added

- **Report redaction:** ledger and local finding renderers redact Bearer/Basic credentials, cookies, passwords, tokens, API keys, common GitHub tokens, and sensitive query parameters. Redaction affects presentation only and never changes the conclusion logic.

## [0.2.25] - 2026-09-02

### Added

- **Project value profile:** S1 generates `project-profile.json` and ranks audit priority using signals such as HTTP/RPC exposure, authorization boundaries, parsing/deserialization, files/config/templates, execution/class loading, protocols, and historical security fixes. This score is for prioritization only and is not a vulnerability probability or severity score.
- **Novelty coverage record:** S5 generates `novelty-coverage.json` recording keyword count, per-query limits, public scan channels, errors, and authoritativeness. Candidate-specific keyword/result limits are configurable and defaults were expanded to 12/20 to avoid silent truncation being interpreted as “no public record.”

## [0.2.24] - 2026-09-02

### Added

- **Source→Sink evidence graph:** S1 creates heuristic, file:line-linked `Source→Transform→Validation→Authorization→Sink` paths; S3 injects paths matching candidate entries into audit records. Every path is explicitly marked as requiring manual data-flow review and must not be treated as a vulnerability conclusion by proximity alone.
- Autonomous and config-driven audits now persist the same `S1/source-sink-graph.json` artifact and feed bounded hints into S3.

## [0.2.23] - 2026-09-02

### Added

- **Structured finding schema:** S7 local reports now share fields for entry point, affected/fixed versions, code locations, Source→Sink path, scope, authorization matrix, negative results, Novelty, and CVSS. A report with missing path evidence is explicitly prevented from being promoted to confirmed on schema completeness alone.
- Config-driven and autonomous report generation populate the same fields from candidate and runtime artifacts.

## [0.2.22] - 2026-09-02

### Added

- **Patch-variant analysis:** S1 performs read-only analysis of the latest 30 likely security-fix commits and records parent, changed files, hunks/symbols, security-relevant added/deleted lines, and sibling-path hints. S2 can generate conservative `fix-completeness` candidates with a `probe_plan`.
- Autonomous and config-driven runs persist the same `S1/security-fix-history.json` and `S1/patch-variants.json` artifacts.

### Fixed

- Reduced false remote-host blocks for local macOS/Homebrew paths containing `@`, such as `openjdk@17`.

## [0.2.21] - 2026-09-02

### Added

- **Authorization boundary matrix:** candidates can declare identity, role, tenant, and object-ownership cases. S4 passes non-sensitive context through `VULNGATE_AUTHZ_*` / `-Dvulngate.authz.*`, verifies `HTTP_CODE`, `OBJECT_MUTATED`, and `AUTHZ_RESULT`, and persists `S4/authz-matrix.json`.
- Authorization metadata is allowlisted; tokens, cookies, passwords, and other credential material are never retained in matrix artifacts.

### Fixed

- Web and Java verification cells distinguish missing authorization evidence (`unsupported`) from a failed authorization contract and flag only observed deny-to-allow or ownership-mutation contradictions as `boundary_violation`.

## [0.2.20] - 2026-09-02

### Fixed

- **GitHub CLI authentication discovery:** S5/`doctor` can fall back to the logged-in `gh auth token` keychain when `GITHUB_TOKEN` and `GH_TOKEN` are not exported. The token remains in memory and is never written to audit artifacts.

## [0.2.19] - 2026-09-01

### Added

- **S0 execution boundary:** the PoC runner hard-denies SSH/SCP/SFTP/remote rsync, cloud/container CLIs, Git writes, non-loopback targets, and wildcard public listeners by default. Explicitly authorized owner-controlled staging/ECS can be enabled only through host allowlisting, with policy decisions persisted to approval logs.
- **Evidence fidelity gate:** capability-only instantiation/JNDI traces/memory canaries are separated from real side effects. RCE confirmation requires an explicit `EFFECT_KIND` + `EFFECT` marker; `A:H` DoS requires concurrent saturation and service-unavailable evidence.
- **Process/evidence hygiene:** timeouts terminate complete process groups, matrix artifacts/checkpoints use atomic replacement, and ledgers reject stale safe-equivalent RCE or unsupported full-outage claims.

### Fixed

- Prevented unapproved host-generated remote actions while preserving explicitly authorized staging validation, and prevented single-request slowdown from being promoted silently to High impact.

## [0.2.15] - 2026-08-20

### Added

- **Hard fix-completeness exclusion validation:** `agent_cli.py ledger` performs a second validation pass. A fix-completeness exclusion must include S4 runtime observation lines such as `OBSERVATION=`, `ERROR=`, `GATE_BLOCKED=`, `EXIT_CODE=`, `SIGNAL=`, ASAN, out-of-memory, or SIGABRT evidence. The only exemption is explicit `exclusion_basis=g1-unreachable` with source references showing the fix path is unrelated to untrusted input. The rule also catches unlabelled fix-family surfaces containing UAF/overflow/bypass/race/issue/CVE signals so a model cannot evade the gate by omitting the `fix-completeness` label. Smoke tests cover static-only rejection, unlabelled fix-family rejection, runtime acceptance, and G1-unreachable acceptance.

### Field basis

A Redis audit round using 0.2.13 + deepseek-v4-pro excluded eight fix-completeness candidates with `EXCLUDED_NO_REPRO` plus a one-line “static audit” rationale and zero runtime cells. That violated the 0.2.12 requirement that fix completeness be backed by runtime cells. Because the behavior varied by model, the rule was moved from prose guidance into a deterministic ledger gate.

## [0.2.14] - 2026-08-20

### Changed

- **Language rule promoted to a highest-priority hard instruction:** the user's language now governs all host-agent narrative output—opening, S1–S8 progress, post-tool narration, degraded-mode notes, round summaries, and final reports. Technical originals such as code, class names, exceptions, CVE/GHSA/PR identifiers, search results, and raw sub-agent replies remain unchanged. If the user switches language, the most recent user message becomes authoritative.

### Field basis

In a Redis audit initiated in Chinese, narrative output drifted back to English after S1/S3. The earlier rule was not treated as sufficiently strong, so 0.2.14 moved it to the top of `SKILL.md` and reinforced the final-report rules.

## [0.2.13] - 2026-08-20

### Changed

- **S4 spawn-probe diagnostics:** failed probes persist the sub-agent's actual reply in `spawn-probe.json` as `agent_reply`. Generic greetings such as “ready to help / waiting for task / no task has come through” are classified as environment-level spawn message-delivery failure rather than a probe-protocol problem. One follow-up retry is allowed (≤60s); if no heartbeat appears, degraded mode is recorded with symptom labels such as `no-heartbeat-greeting-only`, `no-heartbeat-timeout`, or `followup-retried-failed`, plus `--followup-retried` when applicable.

### Field basis

Controlled experiments showed that, in some Codex desktop + third-party API gateway environments, both the initial spawn message and follow-up can fail to reach the sub-agent. The sub-agent can start and see its cwd while never receiving the task body. This is a host-environment issue that the plugin cannot repair; VulnGate degrades to host-sequential matrix execution without weakening conclusion requirements.

## [0.2.12] - 2026-08-19

### Added

- **Fix-completeness validation:** S1 converts recent security-fix commits involving UAF, bounds, overflow, bypass, races, or crashes into `surface=fix-completeness` candidates instead of assuming “the fix is already in the tree.” S3 persists residual suspicions to `S3/residuals.json` with a `probe_plan`; S4 must run at least one cell per residual and prefers pre-fix × post-fix comparison cells where possible.

### Field lessons

- Redis blocked-client UAF: CVE-2026-23479 fixed one unblock/eviction UAF path, while a related `handleClientsBlockedOnKey()` reprocessing/list-iterator path required additional upstream work (#15562 / PR #15594). Fix-completeness review must inspect sibling paths.
- fastjson2 JSONB declared-length OOM family: fixes covering BIGINT/BINARY/ARRAY did not justify assuming every string/codec sibling branch was safe; sibling encodings require independent verification.

## [0.2.11] - 2026-08-18

### Changed

- **Narrative language rule:** progress reporting follows the user's language; technical originals such as code, class names, CVE/GHSA/PR references, and search results remain unchanged. Novelty search keywords remain English-first for hit quality.

## [0.2.10] - 2026-08-18

### Fixed

- **Brand naming cleanup:** remaining runtime identifiers using the old `0day-agent` name were changed to `vulngate`, including HTTP User-Agent strings and internal descriptions. No behavior changed.

## [0.2.9] - 2026-08-18

### Added

- **S4 spawn preflight probe:** before candidate-level spawning, S4 spawns one minimal probe using `skills/vulngate-audit/spawn-probe-task.md`. It must write `S4/spawn-probe.heartbeat` and return `PROBE-DONE` within 90 seconds. Probe success enables per-candidate spawning; failure puts the whole round into host-sequential degraded mode and persists `S4/spawn-probe.json`, avoiding repeated per-candidate retries when the channel is already known to be broken.

## [0.2.8] - 2026-08-16

### Added

- **Dependency vulnerability check for developer self-audit:** `agent_cli.py deps --target <dir> [--out report.md]` discovers common dependency manifests, queries OSV, and reports known vulnerabilities plus recommended fixed versions. Query failures are preserved in `query_notes` instead of terminating the run.
- **Quickstart developer self-audit flow:** dependency health check first, then S1→S8 for first-party code; S5 Novelty may be skipped for private code with no meaningful upstream disclosure corpus.

## [0.2.7] - 2026-08-16

### Added

- **Mandatory sub-agent parallelism discipline:** S4/S5 use explicit spawn requests, with one sub-agent per candidate and a maximum of three concurrent sub-agents. Degradation is allowed only after an explicit tool/channel failure and must be recorded; the host must not invent “channel unavailable.”
- **Quickstart explicit authorization prompt:** documentation includes a copyable prompt that explicitly requires S4/S5 spawn parallelism when desired.

## [0.2.6] - 2026-08-16

### Added

- **Target safety-scope injection:** autonomous `prepare_target` reads `scope.md`, `SECURITY-SCOPE.md`, or `SECURITY.md` and injects `TargetConfig.scope_constraints` into S1.5/S2/S3 prompts. Out-of-scope items such as trusted-admin capabilities, operator deployment decisions, pure DoS, or low-impact leakage can be filtered before candidate validation when the project's scope says so.
- **Flask/Flask-AppBuilder route recognition:** the HTTP source-map preset gained `@<name>.route`, `@expose(...)`, method decorators, and `add_url_rule` patterns after a Superset audit showed the previous route regex was too Java/Clojure-centric.

## [0.2.5] - 2026-08-10

### Added

- **Target-type-aware autonomous mode:** S1/S2/S3/S5 prompts switch by target type; web targets use web-security prompts and HTTP route inventories instead of serialization-centric assumptions.
- **Shell/HTTP S4 matrix for web targets:** web PoCs can be bash HTTP scripts emitting `HTTP_CODE`, `RESP_MATCH`, `EVIDENCE`, `GATE_BLOCKED`, and `ERROR`; `VULNGATE_TARGET_URL` carries the target URL and loopback rules remain enforced.
- `env.md` can declare `target_type`, `target_url`, and version-specific URLs; web mode no longer requires a jar.
- **HTTP evidence path in conclusion logic:** `derive_conclusion` can treat bounded response-side `RESP_MATCH` / `EVIDENCE` observations as runtime evidence for web candidates.

### Changed

- `SOURCE_MAP_PRESETS` moved into `agent/tools/source_evidence.py` so CLI and autonomous modes share one entry-pattern definition.

## [0.2.4] - 2026-08-10

### Fixed

- **Ledger renderer robustness:** `novelty` and `cvss` values can be strings or dictionaries without raising an `AttributeError`. This was found during Metabase round-01.

## [0.2.3] - 2026-08-10

### Added

- **Advisory-driven fix-diff reverse analysis:** the playbook gained the advisory → patched tag → diff → old path workflow. A recent security fix is treated as a high-priority attack-surface map, while G3 starts from same-family when the mechanism is already public.
- **Shell/HTTP PoC matrix runner:** `ShellMatrixRunner` executes bash PoCs with the HTTP observation contract and the same loopback restrictions as Java. `agent_cli.py matrix --lang shell` and `stages.run_s4` use the same matrix schema.
- **G4 HTTP evidence dimension:** `summarize_candidate` gained `http_evidence` for status code, response markers, and explicit side-effect evidence.

### Fixed

- **Exact affected/fixed version checking:** affected and fixed ranges must come from the primary GHSA/advisory (`vulnerable_version_range`, `first_patched_version`) instead of a consolidated blog “safe version” that may combine multiple same-day advisories.
- **Fast spawn degradation:** if a candidate-level sub-agent produces no substantive output for about two minutes after a successful probe, the host may degrade to sequential execution and record the reason rather than retry indefinitely.

## [0.2.2] - 2026-08-10

### Fixed

- **Sub-agent false-stall detection:** heartbeat files are required; stall means heartbeat stale >5 min AND no child process AND no workdir growth. Artifacts must be preserved and orphan processes cleaned before fallback.
- **Process registry and deduplication:** reuse matching services after checking `lsof`/`ps`; record PIDs/ports in `S4/processes.json`; perform round-end cleanup.
- **Ledger evidence hard rule:** every ledger row and exclusion requires non-empty evidence.
- **source-map language coverage:** default scanning includes Java, Clojure, Python, Go, JavaScript, and other supported globs; `--globs java` restricts to Java. HTTP presets include non-Java route declarations.
- **env.md discovery:** lookup order is target directory → parent → workspace root, with creation from observable facts when absent.
- **S5 local patched-version diff:** local fixed-version diffs must be cited as fix-boundary Novelty evidence when available.

## [0.2.1] - 2026-08-09

### Fixed

- Hardened the S4 sub-agent boundary: spawn messages must state that sub-agents may only write PoC sources and matrix outputs, must not create S5–S8 artifacts or draw conclusions, and that out-of-scope writes are harness errors to be discarded and redone by the main agent.

## [0.2.0] - 2026-08-09

### Changed

- Scope expanded from parsing/serialization libraries to **any source code**, including web frameworks, middleware/servers, logging libraries, expression engines, message/RPC stacks, and applications.
- S1 entry discovery became target-type-aware through `source-map --preset` (`parsers|http|expression|io|exec|config|all`).
- S2 candidate generation expanded to injection, resource access, exhaustion, logic, and disclosure classes instead of parsing-only hypotheses.
- S4 PoC shape follows target type: Java class, HTTP request, log line, byte stream, CLI invocation, or other bounded form with the same observation contract.

### Added

- `docs/AUDIT-PLAYBOOK.md` as the per-target-type attack-surface checklist with entry patterns and historical vulnerability-family references.

## [0.1.0] - 2026-08-09

Initial release.

### Added

- Codex plugin manifest with `vulngate-audit` skill (S1–S8 pipeline, G0–G5 gates).
- Deterministic CLI (`agent_cli.py`): source-map, source-evidence, matrix, novelty, cvss, ledger, doctor.
- Autonomous mode launcher (`run_pipeline.sh`) with LLM API support.
- Bundled framework (`scripts/agent/`) with hard gates, precondition→CVSS consistency, conservative Novelty judgments, and loopback-only sandboxing.
- Self-contained installer (`install.sh`) for the personal marketplace.
- Smoke test (`scripts/smoke_test.sh`).
- Bilingual README/quickstart/architecture/security/contribution documentation.
- One-command installer with automatic `codex` discovery (`$PATH`, then desktop-bundled CLI), `--no-enable`, and validation fallbacks.

### Fixed

- `novelty` CLI resolves pull requests through the documented `/pulls/{n}` endpoint rather than falling back to fixtures on a normalized 404.
- `INSTANTIATED` is emitted only for non-generic results; JSONObject/HashMap/null-like generic outcomes become `GATE_BLOCKED`.
- S7 finding documents must copy final CVSS/tier values verbatim from S6; intermediate/pre-G5 scores make the report incomplete until reconciled.

---

# 更新日志（中文）

本文件记录 VulnGate 的重要版本变化。格式参考 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)，版本号遵循 [Semantic Versioning](https://semver.org/spec/v2.0.0.html)。

## [1.0.0] - 2026-09-03

VulnGate 首个正式稳定版，将已验证的 0.2.x 开发线提升为稳定插件版本。

### 包含

- 完整 S1→S8 源码审计流程，覆盖库、框架、中间件、日志库、表达式引擎、消息/RPC 栈和应用。
- S4 运行时 PoC 矩阵，记录版本、SafeMode、前置条件、授权上下文以及逐 cell JDK。
- PoC 运行环境隔离，并显式限制网络和副作用边界。
- Novelty 查询来源、重试/错误、上游 issue/PR 元数据、CVSS 一致性检查，以及可用于披露协调的账本/报告产物。
- 覆盖矩阵证据收敛、运行时选择、环境隔离、Novelty 失败和结论解析的回归测试。

## [0.2.29] - 2026-09-03

### 修复

- **S4 执行证据收敛：** 已持久化的矩阵结果与宿主顺序回退证据不再被 Agent/探针超时元数据覆盖；同一候选多个 PoC 不再互相覆盖。状态明确分为 `unexecuted`、`run-failed`、`gate-blocked`、`precondition-unavailable`、`executed-no-effect`、`executed-with-effect`。
- **PoC 环境隔离：** PoC 只接收最小显式环境；Agent API URL、代理和密钥不参与回环判定，也不传入 PoC 子进程。Novelty 使用独立 GitHub API 通道。
- **逐 cell JDK 选择：** 支持 `required_runtime`、`java_bin`、`java_home`，逐 cell 落盘实际 `java`/`javac` 路径和版本；声明 JDK 8 但不可用时记录 `precondition-unavailable`，不静默退回默认 JDK。
- **账本状态解析：** `确认；High；...` 一类带附加字段的记录仍按确认处理；Novelty 持久化认证来源、重试、错误及 issue/PR 标题/状态。

## [0.2.28] - 2026-09-02

### 修复

- **Novelty 查询完整性：** GitHub 普通网络错误不再静默退化为空结果；S5 记录 `query_errors` 并标记查询不具备权威性，避免把“查询失败”误写成“没有公开记录”。

## [0.2.27] - 2026-09-02

### 新增

- **目标类型 S1 规则：** 按 `library`、`web-app`、`middleware`、`message-rpc`、`logging`、`expression` 选择入口、授权、协议、文件流、序列化和危险 Sink 规则，并落盘 `S1/target-rules.json`。
- **组合链提示：** 同时包含授权边界和危险 Sink 的启发式路径写入 `S1/composite-chain-hints.json`，用于提示验证变换后的对象是否仍受授权保护；不替代数据流与运行时证据。

## [0.2.26] - 2026-09-02

### 新增

- **报告脱敏：** 账本与本地发现报告渲染时遮蔽 Bearer/Basic、Cookie、Password、Token、API Key、常见 GitHub Token 与敏感查询参数。脱敏只影响展示，不改变结论判定。

## [0.2.25] - 2026-09-02

### 新增

- **项目价值画像：** S1 生成 `project-profile.json`，根据 HTTP/RPC、鉴权边界、解析/反序列化、文件/配置/模板、执行/类加载、协议和历史安全修复等信号排序审计优先级；该分数不是漏洞概率或严重性。
- **Novelty 覆盖记录：** S5 生成 `novelty-coverage.json`，记录关键词数量、单项查询上限、扫描渠道、错误与权威性；默认关键词/结果限制扩大到 12/20，降低静默截断被误解为“没有公开记录”的风险。

## [0.2.24] - 2026-09-02

### 新增

- **Source→Sink 证据图：** S1 生成带 `file:line` 的启发式 `Source→Transform→Validation→Authorization→Sink` 路径；S3 将匹配候选入口的路径注入审计记录。所有路径都明确要求人工数据流复核，不能把邻近调用直接当成漏洞结论。
- Autonomous 与 config-driven 审计统一落盘 `S1/source-sink-graph.json` 并将受限提示传给 S3。

## [0.2.23] - 2026-09-02

### 新增

- **结构化发现 Schema：** S7 报告统一记录入口、影响/修复版本、代码位置、Source→Sink 路径、范围、授权矩阵、负向结果、Novelty 和 CVSS。缺少路径证据时，不能仅靠字段完整度升级为确认。
- Config-driven 与 autonomous 报告生成使用同一候选/运行时字段。

## [0.2.22] - 2026-09-02

### 新增

- **补丁变体分析：** S1 对最近 30 个疑似安全修复 commit 做只读分析，记录 parent、改动文件、hunk/符号、安全相关增删行与兄弟路径提示；S2 可生成保守的 `fix-completeness` 候选及 `probe_plan`。
- Autonomous 与 config-driven 统一落盘 `S1/security-fix-history.json` 和 `S1/patch-variants.json`。

### 修复

- 减少 macOS/Homebrew 本地路径中 `@`（如 `openjdk@17`）被误判为远程主机的情况。

## [0.2.21] - 2026-09-02

### 新增

- **授权边界矩阵：** 候选可声明身份、角色、租户和对象归属用例；S4 通过 `VULNGATE_AUTHZ_*` / `-Dvulngate.authz.*` 传递非敏感上下文，校验 `HTTP_CODE`、`OBJECT_MUTATED`、`AUTHZ_RESULT`，并落盘 `S4/authz-matrix.json`。
- 授权元数据使用白名单；Token、Cookie、Password 等凭据不会保留在矩阵产物中。

### 修复

- Web/Java 验证 cell 区分授权证据缺失（`unsupported`）和授权契约失败，只把实际观察到的 deny→allow 或对象归属矛盾标为 `boundary_violation`。

## [0.2.20] - 2026-09-02

### 修复

- **GitHub CLI 认证发现：** 当 `GITHUB_TOKEN` / `GH_TOKEN` 未导出时，S5/`doctor` 可回退到已登录的 `gh auth token`；Token 只在内存中使用，不写入审计产物。

## [0.2.19] - 2026-09-01

### 新增

- **S0 执行边界：** 默认硬拒绝 SSH/SCP/SFTP/远程 rsync、云/容器 CLI、Git 写操作、非回环目标和 wildcard 公网监听。用户明确授权自有 staging/ECS 后，只能通过主机白名单启用，并记录审批决策。
- **证据忠实度规则：** 能力级实例化/JNDI 轨迹/内存 Canary 与真实副作用分离。RCE 必须有显式 `EFFECT_KIND` + `EFFECT`；`A:H` DoS 必须有并发饱和与服务不可用证据。
- **进程/证据卫生：** 超时杀完整进程组，矩阵/Checkpoint 原子替换，账本拒绝过期的“安全等价 RCE”或无支撑的完全停服结论。

### 修复

- 阻止未经批准的宿主远程动作，同时保留显式授权 staging；避免单请求变慢被静默提升为 High impact。

## [0.2.15] - 2026-08-20

### 新增

- **fix-completeness 排除硬校验：** `agent_cli.py ledger` 二次校验修复完整性排除记录。证据必须包含 S4 运行时观测（如 `OBSERVATION=`、`ERROR=`、`GATE_BLOCKED=`、`EXIT_CODE=`、`SIGNAL=`、ASAN、OOM、SIGABRT），唯一豁免是带源码引用的 `exclusion_basis=g1-unreachable`。同时覆盖未显式标记但包含 UAF/overflow/bypass/race/issue/CVE 信号的修复族 surface，避免模型通过不写标签绕过。Smoke test 覆盖静态排除拒绝、未标记修复族拒绝、运行时接受和 G1-unreachable 接受。

### 实测依据

Redis 审计中，0.2.13 + deepseek-v4-pro 曾把 8 个 fix-completeness 候选全部以 `EXCLUDED_NO_REPRO` + “static audit” 排除且零运行时 cell，违反 0.2.12 规则。因为不同模型行为不同，该要求被从文本纪律升级为确定性 ledger 闸门。

## [0.2.14] - 2026-08-20

### 变更

- **语言规则升级为最高优先级硬指令：** 用户使用什么语言，宿主 Agent 的开场、S1–S8 进度、工具后叙述、degraded mode、轮次汇总和最终报告都跟随该语言。代码、类名、异常、CVE/GHSA/PR、检索结果、子 Agent 原始回复等技术原文保持不变；用户中途切换语言时，以最近一条用户消息为准。

### 实测依据

Redis 中文审计线程曾在 S1/S3 后漂回英文，说明旧规则没有被模型当作足够强的约束，因此 0.2.14 将其提升到 `SKILL.md` 文首并同步强化最终报告要求。

## [0.2.13] - 2026-08-20

### 变更

- **S4 spawn 探针诊断：** 探针失败时将子 Agent 实际回复写入 `spawn-probe.json` 的 `agent_reply`。通用问候语（如 “ready to help / waiting for task / no task has come through”）判定为环境级消息投递失败，而不是探针协议错误。允许一次 ≤60 秒 follow-up；仍无心跳时按 `no-heartbeat-greeting-only`、`no-heartbeat-timeout`、`followup-retried-failed` 等症状落盘，并记录 `--followup-retried`。

### 实测依据

受控实验确认，在某些 Codex 桌面版 + 第三方 API 网关环境中，子 Agent 能启动并感知 cwd，但初始任务和 follow-up 都可能未投递。插件无法修复宿主通道，因此 VulnGate 自动降级宿主顺序执行，同时保持结论门槛不变。

## [0.2.12] - 2026-08-19

### 新增

- **修复完整性验证：** S1 将近期 UAF、越界、溢出、绕过、竞态、崩溃类安全修复转成 `surface=fix-completeness` 候选，而不是“补丁已在树中 = 已处理”。S3 将残余怀疑点写入 `S3/residuals.json` 并附 `probe_plan`；S4 每条 residual 至少跑一个 cell，并优先做修复前 × 修复后对照。

### 实战教训

- Redis blocked-client UAF：CVE-2026-23479 修复了一条 unblock/eviction UAF 路径，但 `handleClientsBlockedOnKey()` 相关 reprocessing/list-iterator 路径仍需要后续上游修复（#15562 / PR #15594）。修复完整性必须检查兄弟路径。
- fastjson2 JSONB 声明长度 OOM 家族：BIGINT/BINARY/ARRAY 被修不代表字符串/Codec 兄弟分支安全，必须独立验证。

## [0.2.11] - 2026-08-18

### 变更

- **叙述语言规则：** 过程汇报跟随用户语言；代码、类名、CVE/GHSA/PR、检索结果等技术原文保持原样；Novelty 查询关键词优先使用英文以提高命中率。

## [0.2.10] - 2026-08-18

### 修复

- **品牌命名统一：** 将运行时残留的旧 `0day-agent` 标识统一改为 `vulngate`，包括 HTTP User-Agent 和内部描述；功能行为不变。

## [0.2.9] - 2026-08-18

### 新增

- **S4 spawn 预检探针：** 逐候选 spawn 前，先使用 `skills/vulngate-audit/spawn-probe-task.md` 启动极简探针。探针需在 90 秒内写入 `S4/spawn-probe.heartbeat` 并回复 `PROBE-DONE`。成功才继续逐候选 spawn；失败则整轮进入宿主顺序 degraded mode，并落盘 `S4/spawn-probe.json`，避免已知通道故障时反复逐候选重试。

## [0.2.8] - 2026-08-16

### 新增

- **开发者自审计依赖体检：** `agent_cli.py deps --target <dir> [--out report.md]` 自动发现常见依赖清单，查询 OSV，输出已知漏洞和修复版本建议；查询失败记录在 `query_notes`，不中断流程。
- **Quickstart 自审计流程：** 先做依赖体检，再对自研代码跑 S1→S8；私有代码缺少上游公开语料时可按需跳过 S5 Novelty。

## [0.2.7] - 2026-08-16

### 新增

- **子 Agent 并行纪律：** S4/S5 显式要求 spawn，每候选一个、最多 3 个并发。只有明确工具/通道失败才能降级并记录，禁止虚构“通道不可用”。
- **Quickstart 显式授权提示词：** 文档增加可直接粘贴的 S4/S5 并行提示词。

## [0.2.6] - 2026-08-16

### 新增

- **目标安全范围注入：** autonomous `prepare_target` 读取 `scope.md` / `SECURITY-SCOPE.md` / `SECURITY.md`，注入 `TargetConfig.scope_constraints` 到 S1.5/S2/S3。项目官方标记为范围外的 trusted-admin 能力、operator 部署决策、纯 DoS 或低影响泄露可在候选阶段过滤。
- **Flask/Flask-AppBuilder 路由识别：** HTTP source-map preset 增加 `@<name>.route`、`@expose(...)`、HTTP method decorator 和 `add_url_rule` 等模式，修复 Superset 审计中旧正则过度偏向 Java/Clojure 的问题。

## [0.2.5] - 2026-08-10

### 新增

- **autonomous 目标类型感知：** S1/S2/S3/S5 按目标类型切换提示词；Web 目标使用 Web 安全研究员视角与 HTTP 路由清单，不再被反序列化默认假设带偏。
- **Web 目标 Shell/HTTP S4 矩阵：** bash HTTP PoC 输出 `HTTP_CODE`、`RESP_MATCH`、`EVIDENCE`、`GATE_BLOCKED`、`ERROR`，目标 URL 通过 `VULNGATE_TARGET_URL` 注入，仍强制回环策略。
- `env.md` 支持 `target_type`、`target_url` 及逐版本 URL；Web 模式不再要求 jar。
- **HTTP 证据结论路径：** `derive_conclusion` 可将受限的 `RESP_MATCH` / `EVIDENCE` 作为 Web 候选运行时证据。

### 变更

- `SOURCE_MAP_PRESETS` 下沉至 `agent/tools/source_evidence.py`，CLI 与 autonomous 共用同一入口模式定义。

## [0.2.4] - 2026-08-10

### 修复

- **账本渲染容错：** `novelty` / `cvss` 传字符串或字典均可，不再因 `.get` 引发 `AttributeError`；问题由 Metabase round-01 暴露。

## [0.2.3] - 2026-08-10

### 新增

- **通告驱动 fix-diff 反查：** playbook 增加通告 → patched tag → diff → 旧路径流程。近期安全修复被视作高优先攻击面；机制已公开时 G3 从 same-family 起步。
- **Shell/HTTP PoC 矩阵运行器：** `ShellMatrixRunner` 用同一 HTTP 观察契约执行 bash PoC，并继承 Java 的回环限制；`agent_cli.py matrix --lang shell` 与 `stages.run_s4` 使用统一 Schema。
- **G4 HTTP 证据维度：** `summarize_candidate` 增加 `http_evidence`，记录状态码、响应标记与显式副作用证据。

### 修复

- **精确版本区间核对：** affected/fixed range 必须以 GHSA/主通告原文（`vulnerable_version_range`、`first_patched_version`）为准，不使用可能合并多个同日修复的博客“统一安全版本”。
- **spawn 快速降级：** 探针成功后，逐候选子 Agent 若约 2 分钟无实质产出，可降级宿主顺序执行并记录原因，而不是无限重试。

## [0.2.2] - 2026-08-10

### 修复

- **子 Agent 假停滞判断：** 必须有 heartbeat；只有 heartbeat >5 分钟未更新且无子进程且工作目录无增长时才能判定停滞；回退前保留产物并清理孤儿进程。
- **进程注册与去重：** 启动服务前检查 `lsof`/`ps`，复用匹配实例，将 PID/Port 写入 `S4/processes.json`，轮次结束清理。
- **账本证据硬规则：** 每条账本记录和排除项必须有非空证据。
- **source-map 语言覆盖：** 默认扫描 Java、Clojure、Python、Go、JavaScript 等；`--globs java` 才限制为 Java；HTTP preset 覆盖非 Java 路由声明。
- **env.md 发现顺序：** 目标目录 → 父目录 → 工作区根目录，缺失时可根据可观察事实生成。
- **S5 本地修复版 diff：** 有本地 fixed version 时，必须把 diff 作为修复边界 Novelty 证据。

## [0.2.1] - 2026-08-09

### 修复

- 强化 S4 子 Agent 边界：spawn 消息必须明确子 Agent 只能写 PoC 源码和矩阵输出，禁止创建 S5–S8 产物或下结论；越权写入按 harness error 丢弃，由主 Agent 重做。

## [0.2.0] - 2026-08-09

### 变更

- 范围从解析/序列化库扩展到**任意源码**：Web 框架、中间件/服务器、日志库、表达式引擎、消息/RPC 栈和应用。
- S1 使用目标类型感知的 `source-map --preset`：`parsers|http|expression|io|exec|config|all`。
- S2 候选扩展为注入、资源访问、资源耗尽、逻辑和信息泄露等完整攻击类别。
- S4 PoC 形状随目标类型变化：Java 类、HTTP 请求、日志行、字节流、CLI 调用等，统一遵循观察契约。

### 新增

- `docs/AUDIT-PLAYBOOK.md`，提供按目标类型分类的攻击面、入口模式和历史漏洞家族参考。

## [0.1.0] - 2026-08-09

初始版本。

### 新增

- Codex 插件清单与 `vulngate-audit` 技能（S1–S8、G0–G5）。
- 确定性 CLI（`agent_cli.py`）：source-map、source-evidence、matrix、novelty、cvss、ledger、doctor。
- 支持 LLM API 的 autonomous 启动器 `run_pipeline.sh`。
- `scripts/agent/` 捆绑框架：硬闸门、前置条件→CVSS 一致性、保守 Novelty 与回环沙箱。
- 自包含 `install.sh`、Smoke test 与双语 README/Quickstart/Architecture/Security/Contribution 文档。
- 自动发现 `codex` 的一键安装流程，并支持 `--no-enable` 和校验回退。

### 修复

- `novelty` CLI 使用正式 `/pulls/{n}` endpoint 解析 PR，避免规范化 404 后错误回退 fixture。
- `INSTANTIATED` 只对非通用结果输出；JSONObject/HashMap/null 等通用结果改为 `GATE_BLOCKED`。
- S7 报告必须逐字复制 S6 最终 CVSS/tier；存在中间/pre-G5 分数时，报告在与 S6 对齐前视为不完整。
