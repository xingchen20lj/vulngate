# VulnGate

> **Evidence-gated vulnerability research for AI security agents.**

**Language:** English | [简体中文](README.zh-CN.md)

VulnGate is a Codex-native vulnerability research framework that separates **hypothesis generation** from **claim validation**.

The host agent reads code, reasons about attack paths, and proposes vulnerability hypotheses. Deterministic components collect and validate the evidence required to promote those hypotheses into security claims: reachability, runtime effects, exploit preconditions, public-disclosure novelty, severity consistency, and reproducible research artifacts.

The core principle is simple:

> **The model may propose a vulnerability. Evidence decides how far the claim is allowed to go.**

![VulnGate methodology: host-agent reasoning, deterministic evidence collection, S1-S8 research lifecycle, G0-G5 evidence gates, and claim eligibility](docs/assets/vulngate-methodology.svg)

*VulnGate's methodology: host reasoning proposes hypotheses; deterministic evidence and explicit gates constrain how far a security claim may be promoted.*

VulnGate does not treat *plausible*, *triggered*, *confirmed*, *novel*, and *critical* as interchangeable states. Its S1–S8 research lifecycle and G0–G5 evidence-gate family constrain when a candidate may be promoted into a confirmed vulnerability, a novel finding, or a particular severity level.

## Why VulnGate

LLM-assisted vulnerability research can fail in ways that sound convincing:

- a dangerous call site is mistaken for an exploitable path;
- a PoC harness failure is mistaken for evidence that a bug does not exist;
- object instantiation or a lookup trace is overstated as code execution;
- a rate-limited public search is mistaken for evidence of novelty;
- a vulnerability that requires a non-default feature is scored as if it were reachable by default;
- a security patch is assumed complete without testing residual variants.

VulnGate turns these research disciplines into machine-checkable constraints:

- **No confirmation without runtime evidence.** A claim cannot be promoted to confirmed beyond the runtime effect actually observed.
- **No 0day claim on incomplete public-information queries.** A failed or rate-limited novelty scan produces `unknown-query-failed`, not `candidate-0day`.
- **Hard novelty downgrade on upstream evidence.** A predating issue, PR, fix, or public disclosure covering the same mechanism downgrades the novelty claim.
- **Precondition-honest severity.** CVSS and severity must remain consistent with the actual conditions required to reproduce the issue.
- **Negative evidence is typed.** `unexecuted`, `run-failed`, `gate-blocked`, `precondition-unavailable`, `executed-no-effect`, and `executed-with-effect` are different states and are not interchangeable.
- **Fix completeness is testable.** Security-fix history and residual variants can become first-class candidates instead of being dismissed because a patch exists.

## Research positioning

VulnGate does **not** claim to have invented LLM-assisted vulnerability research, runtime PoC verification, variant analysis, or the broader pattern of combining model reasoning with deterministic security tooling. Those directions have prior public work, including Google Project Zero's Project Naptime / Big Sleep and other agentic security systems.

VulnGate focuses on a narrower question:

> **When an AI security agent participates in vulnerability research, what evidence must exist before a hypothesis is eligible to become a stronger security claim?**

This leads to three design themes:

- **Evidence Fidelity** — conclusions must match the strength and semantics of the evidence actually observed.
- **Claim Eligibility** — labels such as *confirmed*, *novel*, or *0day candidate* require explicit eligibility conditions.
- **Precondition Honesty** — environment, configuration, identity, role, runtime, and other prerequisites remain part of the conclusion instead of being optimized away.

See [RELATED_WORK.md](RELATED_WORK.md) for a non-exhaustive comparison with related systems and [PROVENANCE.md](PROVENANCE.md) for the project's development history and design provenance.

## Architecture at a glance

The host Codex agent owns open-ended reasoning. Bundled deterministic helpers own the parts that must be repeatable and auditable.

```text
Source / runtime
      │
      ▼
Host agent: map → hypothesize → audit → interpret
      │
      ▼
Deterministic evidence collection
      │
      ├─ source evidence / patch variants
      ├─ PoC matrix / execution-state convergence
      ├─ novelty queries / coverage
      ├─ CVSS consistency
      └─ ledger / checkpoints / approval logs
      │
      ▼
Evidence gates
      │
      ▼
Confirmed / Excluded / Candidate (pending validation)
```

Current gate identifiers are **G0, G1, G1b, G3, G4, and G5**; G1b is the default-configuration sub-gate.

## Features

- **Host-native orchestration** — uses the model already configured in Codex; no separate API key is required for the recommended mode.
- **S1–S8 research lifecycle** — attack surface → candidates → source audit → PoC matrix → novelty → severity → finding document → evidence ledger.
- **Deterministic helper CLI** — `agent_cli.py` provides source mapping/evidence, matrix execution, novelty checks, CVSS consistency, ledger rendering, dependency checks, research benchmarking, probe diagnostics, and staging helpers.
- **Version × feature × precondition validation** — PoCs are evaluated across explicit cells rather than a single best-effort run.
- **Stateful/race experiment contract** — cells can declare bounded step sequences, concurrency, and an availability probe; ordered `STEP`/`STATE` evidence is retained without treating declarations as proof.
- **Capability-chain runtime contract** — capability candidates carry a bounded `capability_contract` into S4 cells; `CAPABILITY`/`TRANSITION` traces are classified as `no-trace`, `partial`, or `complete`, while typed effects remain a separate evidence requirement.
- **Semantic path evidence** — S1 adds `semantic-path-evidence-v1`: it checks whether path controls are before the sink in the same lexical scope and performs a bounded same-symbol parameter/alias walk; cross-symbol and branch-dominance questions stay explicit research gaps, and every lead remains `not-a-finding`.
- **Semantic guard evidence** — S1 adds `semantic-guard-evidence-v1`: it records bounded branch posture and subject/object binding (`terminating-guard`, `nested-branch`, `non-branch-check`, `overlap`, `mismatch`, `unresolved`) so reviewers can prioritize authorization and logic traces without treating lexical evidence as dominance or object-identity proof.
- **Interprocedural binding evidence** — S1 adds `semantic-call-evidence-v1`: it traces one bounded call hop at a time, records argument-to-parameter binding and return-shape hints, and turns unresolved cross-symbol paths into citable research tasks without claiming complete data flow.
- **Runtime research lab** — directed fuzz inputs become fixed corpus fixtures and minimized reproducers; bounded replay and version × SafeMode comparison preserve stable, differential, signature-drift, and precondition-gap evidence without promoting it to a finding.
- **Ordinary-S4 fixture adapter** — Java and shell PoC cells can be replayed as bounded, redacted execution fixtures; `S4/runtime-lab.json` keeps stable replay, version/SafeMode differences, and harness gaps separate from G4/G5.
- **Bounded service context** — stateful S4 runs may start one workspace-local argv-only service, require a loopback health check, reuse a healthy instance, kill the complete process group, and persist `S4/processes.json`; `runtime-lab.json` includes a credential-free configuration snapshot and stable authz/tenant fixture IDs.
- **Cross-round research memory** — S8 persists stable mechanism keys, replay/differential states, environment gaps, bounded S3 residual metadata, and next-probe hints in `state/<target>/research-memory.json`; S2 reuses that evidence to damp exact repeats and prioritize actionable differences without treating memory as a finding. Residuals remain pending even when the primary replay is stable.
- **Human review feedback loop** — `agent_cli.py review` records bounded accepted/rejected/needs-evidence/scope-corrected feedback by stable research key; S8 replays it into target memory and S2 uses it only to reprioritize follow-up work, never to replace G4/G5 evidence.
- **Research-quality benchmark** — `agent_cli.py benchmark` scores deterministic gold cases and run records for observation coverage, negative-result safety, environment-gap fidelity, repeat rate, evidence completeness, decision stability, and severity calibration; results remain `not-a-finding`.
- **Benchmark-guided research loop** — `research-benchmark-feedback-v1` turns those metrics into capped alert codes, scheduler-factor deltas, and experiment observations; `schedule --benchmark-result` and explicit target-config opt-in feed the next round without changing findings, CVSS, or G4/G5.
- **Cross-surface research benchmark** — `benchmarks/research-benchmark-surfaces-v1.json` exercises web, protocol, cloud, mobile, and native variants with vulnerable, negative, and environment-gap cases; results preserve `research_profile` and `coverage_by_surface` while keeping unresolved cases pending.
- **Surface-aware adaptation** — weak per-surface benchmark metrics become bounded `surface_guidance`; only explicitly tagged matching candidates receive a small scheduling boost and matching experiment plans receive the required observations/falsifiers.
- **Longitudinal benchmark regression** — `benchmark --baseline <result.json>` compares bounded aggregate and per-surface metrics across runs, preserving regression signals as `research-benchmark-trend-v1` without copying case evidence or promoting a finding.
- **Project research portfolio** — S8 composes memory, review feedback, benchmark context, and bounded S3 residuals into `research-portfolio-v1` coverage by surface, attack class, variant, and precondition; it emits prioritized residual-aware `next_probes` and gives only exact matches a tiny scheduler nudge without turning portfolio state into a finding.
- **Attacker-path threat model** — S1 joins entries, trust boundaries, flows, sinks, control posture, unresolved reachability, and capability-chain hypotheses into bounded `threat-model-v1`; the scheduler and `agent_cli.py threat-model` expose it as a research map, never as a finding.
- **Evidence-driven research strategy** — S2 synthesizes the threat model, residuals, cross-round memory, portfolio gaps, and benchmark context into bounded `research-strategy-v1` items with explicit required observations and falsifiers; only explicit path or research-key matches receive a small scheduling nudge, and every item remains `not-a-finding`.
- **Residual falsifier closure** — S2 carries stable residual contracts into S4; only an executed, contract-declared cell with a matching `RESIDUAL_ID`, explicit `RESIDUAL_STATUS=falsified`, an allowlisted falsifier, and no typed effect can move research memory to `residual-falsified`. Gate failures and effects remain pending, and the closure artifact stays `not-a-finding`.
- **Strategy observation feedback** — S8 maps real S4 execution signals back to explicit `research-strategy-v1` items, records missing observations, bounded closure status, and per-round information gain in `research-strategy-feedback-v1`; repeated runs with no new signal lose the strategy nudge without changing candidate or G4/G5 status.
- **Research action guidance** — `research-strategy-guidance-v1` joins strategy observations, latest human review state, and explicit variant coverage into bounded next actions such as environment repair, negative-control addition, capability-transition tracing, typed-effect follow-up, residual replay, or a replacement experiment; it only tunes research scheduling and remains `not-a-finding`.
- **Surface-specific experiment variants** — `surface-variant-plan-v1` turns those actions into bounded Web, protocol, cloud, mobile, and native variant templates; every selected variant carries positive, negative/safe, and environment-gap lanes with required observation signals and falsifiers shared by S2 planning and S4 handoff.
- **Executable surface fixtures** — `surface-variant-fixture-v1` expands each selected lane into a bounded S4 fixture/state-machine context; replay and differential cells receive `VULNGATE_VARIANT_*` metadata, state steps, and lane-specific observation requirements without persisting payloads or treating the plan as evidence.
- **Surface lane witnesses** — `surface-variant-evidence-v1` compares actual S4 runner rows with the lane contract, distinguishes observed/partial/environment-gap/not-executed coverage, and feeds bounded missing-signal hints back to S2/S8 without changing findings, CVSS, or G4/G5.
- **Cross-round surface coverage** — `surface-variant-coverage-v1` aggregates historical and latest lane witnesses in the project portfolio; only latest actual `observed` lanes close, while partial/unexecuted/environment-gap lanes create exact research-key probes for the next round.
- **Cross-version/fix comparison orchestration** — `comparison-orchestration-v1` binds configured version pairs, read-only patch parent/fixed references, and sibling-variant hints to the same fixture/lane; S4 separates bucket changes, signature drift, source-build gaps, and unobserved sibling arms without promoting any difference to a finding.
- **Controlled source-revision arms** — operators may supply workspace-local `.jar`/`.war`/`.zip` artifacts for exact before/after commit refs through `source_revision_artifacts`; VulnGate fingerprints and runs them through the existing isolated Java matrix, never checks out or builds source, and keeps missing/invalid artifacts as explicit inconclusive gaps.
- **Real-project replay calibration** — `agent_cli.py replay-calibrate` and S8 produce `research-replay-calibration-v1` from bounded guidance, strategy-feedback, and runtime-lab history; replacement hit rate, unproductive repeats, environment recovery, fixture truncation, and comparison gaps can adjust only the bounded zero-gain threshold (1–2 rounds), never findings, CVSS, or G4/G5.
- **Cross-project replay cohort calibration** — `agent_cli.py replay-cohort-calibrate` aggregates explicit per-target replay artifacts with distinct-project and per-surface sufficiency checks; an explicitly configured cohort is only a fallback for targets lacking local history, and remains `not-a-finding` scheduling metadata.
- **Provenance-carrying replay packs** — `agent_cli.py replay-pack` and S8 record allowlisted workspace-local artifact hashes plus bounded lane/comparison summaries; `replay-cohort-calibrate --pack` accepts only complete, self-consistent packs, while missing or changed artifacts remain explicit provenance gaps.
- **Cross-round evidence consistency** — `research-consistency-v1` compares bounded research-memory events for the same mechanism, detects effect/reproduction/comparison/context drift, and schedules controlled re-observation without turning contradictions or environment gaps into findings.
- **Controlled consistency rechecks** — `research-consistency-action-v1` turns each non-consistent history into fixed isolation axes, paired lanes, required observations, falsifiers, and a `consistency-recheck` S2 plan; S4 carries the contract through MatrixCell, PoC environment, and runtime-lab fixture metadata while keeping it `not-a-finding`.
- **Executed consistency-recheck closure** — `research-consistency-recheck-v1` makes S4 materialize the action's positive/negative or environment-gap lane, records only bounded lane witnesses, and lets S8 distinguish `observed`, `partial`, `environment-gap`, and `not-executed`; missing repeats, context locks, comparison arms, state resets, or typed/safe-equivalent observations remain pending and never change G4/G5.
- **Active research agenda** — `research-agenda-v1` turns the normalized strategy into a finite, information-gain-oriented queue with explicit prerequisites, cost, surface diversity, selected/deferred/hold status, and a small scheduler boost for exact matches; it remains `not-a-finding` and cannot change candidate status, CVSS, or G4/G5.
- **Agenda execution feedback** — `research-agenda-outcome-v1` compares the prior queue with the actual schedule and bounded S4/S8 observations, distinguishing productive information, falsifiers, no-information repeats, environment gaps, and not-executed work; the next agenda carries that feedback as scheduling metadata only.
- **Outcome-adaptive research budget** — `research-budget-v1` aggregates agenda outcomes by research surface, cost, and information gain; it gives bounded recovery/exploitation/exploration/cooldown hints to the next agenda, without deleting hypotheses or changing candidate, CVSS, G4, or G5 state.
- **Falsifiable experiment planning** — S2 emits bounded plans with required observations and explicit falsifiers for baseline, authz, state, availability, fix variants, and typed effects; plans remain `not-a-finding`.
- **Capability-primitive path search** — S1 derives bounded `read` / `write` / `exec` / `ssrf` and credential/evaluation chains from the entry/sink/flow indices, preserves missing primitives, and emits minimal verification sequences; static chains remain `not-a-finding` until data-flow and runtime typed-effect evidence exist.
- **Authorization-aware matrices** — web/application candidates can include identity × role × tenant × object context.
- **Per-cell runtime requirements** — a required JDK/runtime must actually be available; otherwise the cell is recorded as `precondition-unavailable` instead of silently falling back.
- **Evidence convergence** — persisted matrix evidence is not overwritten by agent/spawn timeout metadata.
- **Conservative novelty** — public-query failures are preserved as uncertainty rather than converted into absence-of-evidence claims.
- **Fix-completeness analysis** — recent security fixes, patch variants, and residuals can feed new validation candidates.
- **Checkpointed evidence ledger** — research state and evidence are persisted so the final report is traceable to artifacts.
- **Safety-first execution** — loopback-first PoC behavior, explicit approval logging, and allowlisted staging support.

## Coverage-driven auditing and native applications

Version 1.2.0 extends the Codex plugin with a broader deterministic analysis
layer, native-application support, and outcome-adaptive research scheduling. The
host uses your configured Codex model; the deterministic commands require no
additional model API key.

- Full production-source inventory with explicit skipped-file reasons and
  ledger-derived review coverage.
- Heuristic symbols, call graphs and forward/backward entry-to-sink paths.
- Per-path control gaps and sibling-handler differentials, with candidates
  retained as leads until verified.
- Source-local semantic path evidence for control order and same-symbol
  parameter/alias reachability, persisted separately from the heuristic call
  graph and surfaced as S2 research candidates.
- Bounded semantic guard evidence for branch posture and subject/object binding,
  persisted separately and surfaced as `not-a-finding` S2 research candidates.
- Bounded one-hop interprocedural argument/return binding evidence for
  source-to-sink flows, with unresolved dispatch and transformations kept as
  explicit research gaps.
- Capability-primitive graphs and explicit attack-chain equations that retain
  missing intermediate capabilities instead of promoting static composition to RCE.
- Candidate scoring and category quotas that preserve deferred work across rounds.
- macOS `.app`/`.dmg`/`.pkg`, Mach-O metadata, Electron ASAR/source maps and JAR views.

```bash
python3 scripts/agent_cli.py coverage demo --root /path/to/source \
  --workspace /path/to/audit --rebuild --show-uncovered
python3 scripts/agent_cli.py controls demo --workspace /path/to/audit --show-candidates
python3 scripts/agent_cli.py differential demo --workspace /path/to/audit --show-candidates
python3 scripts/agent_cli.py capability demo --workspace /path/to/audit --show-candidates
python3 scripts/agent_cli.py semantic-paths demo --workspace /path/to/audit --show-candidates
python3 scripts/agent_cli.py semantic-guards demo --workspace /path/to/audit --show-candidates
python3 scripts/agent_cli.py semantic-calls demo --workspace /path/to/audit --show-candidates
python3 scripts/agent_cli.py benchmark --manifest benchmarks/research-benchmark-v1.json \
  --run benchmarks/research-benchmark-sample-run.json \
  --feedback-out state/research-benchmark-feedback.json --json
bash macos/run-audit.sh /Applications/Target.app /path/to/native-audit
```

Use the same `--workspace` for analysis, scheduling and ledger commands. Rebuild
coverage when source or scope changes. Native reconstruction establishes an
attack-surface view; it does not recover method bodies or prove vulnerabilities.
See [native-target usage](macos/README.md) and
[feature evolution notes](docs/EVOLUTION.md).

## Installation

### Prerequisites

- Codex (CLI or desktop app), version with plugin support
- Python 3.8+
- JDK 8+ for JVM targets (17/21 recommended); native targets require macOS Command Line Tools
- `rg` (ripgrep) for source mapping

### Install from this repository

```bash
git clone https://github.com/xingchen20lj/vulngate.git
cd vulngate
./install.sh
```

`install.sh` copies the plugin to `~/plugins/vulngate`, registers the personal marketplace, and enables it in Codex (`codex plugin add vulngate@personal`). It searches for the `codex` command in `$PATH` and in supported desktop-app locations.

> **Open a new thread after installation.** Plugin skills are loaded at thread start.

For an existing installation, rerun `./install.sh` to update it. The installer
preserves compatibility aliases for older versioned skill-cache paths, so an
audit task that is already running does not lose its `SKILL.md` during the
update. Avoid running a bare `codex plugin add vulngate@personal` while an audit
task is active.

### Manual install

```bash
codex plugin add vulngate@personal
```

If you prefer CLI-only Codex:

```bash
npm install -g @openai/codex
```

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for installation troubleshooting and the full walkthrough.

## Quickstart

Start a new Codex thread and point VulnGate at the authorized source tree:

> Audit this codebase and run the full S1→S8 research pipeline: `/path/to/source`

The host agent maps the attack surface, proposes candidates, audits source, runs evidence-oriented validation cells, checks public novelty, validates severity consistency, and produces local research artifacts.

For an autonomous run using your own compatible LLM API key:

```bash
./scripts/run_pipeline.sh --name <target> --target-dir <path> --round 1
```

## How it works

| Stage | Purpose | Representative outputs | Gate |
|---|---|---|---|
| S1 | Attack-surface mapping, entry inventory, danger sites, fix history/variants, project profile, target rules, composite-chain, capability, semantic path/guard/call evidence, and attacker-path threat-model views | `S1/entry-inventory.json`, `S1/security-fix-history.json`, `S1/patch-variants.json`, `S1/project-profile.json`, `S1/target-rules.json`, `S1/composite-chain-candidates.json`, `S1/capability-graph.json`, `S1/capability-candidates.json`, `S1/semantic-path-evidence.json`, `S1/semantic-path-candidates.json`, `S1/semantic-guard-evidence.json`, `S1/semantic-guard-candidates.json`, `S1/semantic-call-evidence.json`, `S1/semantic-call-candidates.json`, `S1/threat-model.json` | G0 dead code, G1 reachability |
| S2 | Candidate matrix, falsifiable research plans, controlled consistency rechecks, surface-specific variant lanes, and cross-artifact research strategy: surface × entry × input × mechanism | `S2/candidate-matrix.json`, `S2/experiment-plans.json`, `S2/research-strategy.json` | — |
| S3 | Source audit with file:line evidence, source-to-sink hints, residuals | `S3/audit-notes.json`, `S3/residuals.json` | G1b default-config gating |
| S4 | PoC matrix: version × safe mode × precondition; optional authz, bounded state/concurrency, capability-transition context, consistency recheck contract and executed lane closure, residual falsifier contract, replay/differential lab, and loopback service lifecycle | `S4/matrix-runs/<c>/cells.json`, `S4/execution-status.json`, `S4/authz-matrix.json`, `S4/residual-closure.json`, `S4/runtime-lab.json`, `S4/processes.json` | G4 runtime evidence |
| S5 | Novelty: upstream issue/PR/fix + public disclosure search and coverage | `S5/novelty.json`, `S5/novelty-coverage.json` | G3 novelty / downgrade |
| S6 | CVSS + precondition/impact consistency | `S6/severity.json` | G5 consistency |
| S7 | Self-contained local finding document | `reports/<target>/…` | disclosure hold |
| S8 | Evidence ledger, exclusions, round summary, cross-round memory and consistency, controlled recheck actions and execution closure, residual outcomes, strategy observation feedback, review feedback, active research agenda, outcome feedback, adaptive budget policy, variant-aware research actions and project research portfolio | `ledger/<target>/…`, `state/<target>/research-memory.json`, `state/<target>/coverage/research-consistency.json`, `state/<target>/coverage/research-consistency-actions.json`, `state/<target>/coverage/research-consistency-rechecks.json`, `state/<target>/coverage/research-agenda.json`, `state/<target>/coverage/research-agenda-outcomes.json`, `state/<target>/coverage/research-budget.json`, `state/<target>/coverage/research-strategy.json`, `state/<target>/coverage/research-guidance.json`, `state/<target>/research-portfolio.json`, `S8/research-memory.json`, `S8/research-consistency.json`, `S8/research-consistency-actions.json`, `S8/research-consistency-rechecks.json`, `S8/research-agenda.json`, `S8/research-agenda-outcomes.json`, `S8/research-budget.json`, `S8/research-strategy-feedback.json`, `S8/research-guidance.json`, `S8/review-feedback.json`, `S8/research-portfolio.json` | final consistency checks |

The source-to-sink graph is intentionally conservative: heuristic proximity is marked as `heuristic-nearby` and `requires_manual_dataflow=true`; it is not presented as a substitute for sound semantic data-flow analysis.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/AUDIT-PLAYBOOK.md](docs/AUDIT-PLAYBOOK.md) for details.
The implementation roadmap is in [docs/RESEARCH-ROADMAP.zh-CN.md](docs/RESEARCH-ROADMAP.zh-CN.md).

## Safety and disclosure

VulnGate is intended for authorized security research.

- Local PoC side effects are loopback-first (`127.0.0.1`).
- Non-loopback egress, listeners, remote tooling, and staging actions are policy-controlled and logged.
- Explicitly authorized staging requires an allowlisted host; public listeners and third-party targets remain out of scope.
- Staging preparation artifacts are environment records, not vulnerability evidence by themselves.
- Findings are generated locally and are not automatically published.
- Coordinate responsibly with maintainers before public disclosure.

Report vulnerabilities in VulnGate itself through [SECURITY.md](SECURITY.md).

## Development, provenance, and contribution

VulnGate is independently designed and maintained by **xingchen20lj** with AI-assisted development using ChatGPT and Codex. AI tools are used as implementation and design aids; project decisions are tested against real audit behavior and encoded into deterministic rules and regression tests.

The public Git history starts with VulnGate 0.1.0 on 2026-08-09. Subsequent commits record audit-driven changes such as Metabase-run lessons, fix-completeness gates, spawn diagnostics, patch-variant analysis, novelty-query failure preservation, and S4 evidence convergence/runtime isolation.

This history is evidence of project evolution, not a claim that every broad idea used by VulnGate originated here. See [PROVENANCE.md](PROVENANCE.md), [CHANGELOG.md](CHANGELOG.md), and [RELATED_WORK.md](RELATED_WORK.md).

Developer quick reference:

- `scripts/smoke_test.sh` — environment and deterministic-helper smoke tests
- `.codex-plugin/plugin.json` — plugin manifest
- `skills/vulngate-audit/SKILL.md` — host-agent execution contract
- `scripts/agent/` — bundled deterministic framework
- `CHANGELOG.md` — versioned design evolution

Local iteration:

```bash
./install.sh
```

Then start a new thread. Contribution guidance is in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
