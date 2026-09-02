# VulnGate Development Provenance

This document records how VulnGate evolved as a project. It is intended to make design history inspectable, preserve the relationship between observed research failures and implementation changes, and distinguish project-specific evolution from broader prior art in agentic security research.

It is not a legal opinion and does not claim that every broad idea used by VulnGate originated in this repository.

## Maintainer and development model

VulnGate is independently designed and maintained by **xingchen20lj**.

The project has been developed with AI-assisted software engineering using ChatGPT and Codex as design and implementation aids. The maintainer selects the architecture, evaluates behavior, runs audits, reviews generated changes, and iterates on failures observed during real open-source security research.

A recurring development pattern is:

```text
real audit / experiment
        ↓
incorrect, ambiguous, or unsafe agent behavior
        ↓
research lesson
        ↓
deterministic rule / evidence state / gate
        ↓
regression test and documentation
```

This failure-driven evolution is part of VulnGate's engineering methodology.

## Public history boundary

The public Git history begins on **2026-08-09** with commit:

`38486e40f6fa4cd581d5706869d65d3cc05c1fa6` — `feat: initial release of VulnGate 0.1.0 (Codex plugin)`

That initial public snapshot already contained the S1–S8 workflow, G0–G5 gate family, PoC matrix support, Novelty checking, CVSS/precondition consistency, ledger generation, sandbox policy, and the division between host-agent reasoning and deterministic helpers.

Development before that public commit is not represented by Git history. Private ChatGPT/Codex discussions, local files, early experiments, audit artifacts, and other pre-public materials should be retained by the maintainer when available as additional provenance records.

## Selected evolution timeline

The list below highlights commits whose messages preserve the relationship between observed research behavior and later design changes. It is not a complete changelog; see [CHANGELOG.md](CHANGELOG.md) and the Git history for full details.

### 2026-08-09 — Initial public architecture

`38486e40...` — VulnGate 0.1.0

The initial release already described and implemented:

- S1–S8 vulnerability-research lifecycle;
- G0 dead-code and G1 reachability decisions;
- G1b default-configuration security gating;
- G4 runtime evidence for confirmation/exclusion;
- G3 conservative novelty handling;
- G5 CVSS/precondition consistency;
- deterministic helper CLI and evidence ledger;
- loopback-oriented sandbox policy.

This establishes that these project-specific abstractions were part of the first public VulnGate snapshot rather than later documentation-only positioning.

### 2026-08-09 to 2026-08-10 — Early audit-driven corrections

Examples include:

- `62346f92...` — normalize novelty PR endpoint and harden PoC observation contract;
- `e531f89e...` — require S7 to copy CVSS/tier from the S6 final record to prevent report-vs-evidence drift;
- `3fe48b5e...` — "Metabase round-01 lessons": sub-agent heartbeat/stall rules, ledger evidence hard rule, non-Java source mapping, environment discovery, and S5 local-diff behavior;
- `cee0074b...` — advisory-driven fix-diff reverse lookup and shell/HTTP PoC matrix support;
- `19750678...` — ledger renderer tolerance fix explicitly recorded as found during a Metabase run.

These commits show the framework being modified in response to actual audit behavior rather than only from a static upfront specification.

### 2026-08-16 to 2026-08-17 — Scope, target diversity, and agent-execution discipline

Examples include:

- `d4fbd937...` — target-type-aware autonomous behavior and HTTP/Shell matrix support;
- `befc43ea...` — target security-boundary scope injection and Flask/FAB route recognition;
- `c0d9112f...` — explicit sub-agent parallelism discipline;
- `f2d38873...` — developer self-audit dependency CVE checks;
- `6668e4f6...` — S4 spawn preflight probe;
- `e6ff0349...` — classify greeting-only child-agent responses as message-delivery failure and preserve raw diagnostic evidence.

The common theme is that orchestration failures are made explicit instead of being silently converted into research conclusions.

### 2026-08-19 — Fix completeness becomes a first-class evidence problem

- `827f4eba...` — security-fix commits become fix-completeness candidates and S3 residuals must flow into S4;
- `19671c69...` — static-only fix-completeness exclusions are rejected unless backed by runtime evidence or explicit G1-unreachable source evidence.

This extends the evidence contract to negative conclusions about already-patched vulnerability families.

### 2026-09-01 — Research-context and Novelty hardening

Examples include:

- `d92bfab8...` — authorization-boundary matrix;
- `9fd9db8a...` — patch-variant analysis;
- `3b8ebbb8...` — source-to-sink evidence graph;
- `183c5565...` — project profile and novelty coverage;
- `9db5c079...` — sensitive report-evidence redaction;
- `00e825f3...` — target rules and composite-chain hints;
- `460dc70b...` — preserve novelty query failures.

The source-to-sink graph is intentionally labeled as heuristic where appropriate (`heuristic-nearby`, `requires_manual_dataflow=true`) instead of being represented as sound semantic data-flow proof.

### 2026-09-02 — S4 evidence-state convergence and v1.0.0

- `5df9a6be...` — converge matrix evidence and isolate PoC runtimes;
- `513c920c...` — release v1.0.0.

The S4 changes make execution-state semantics explicit, distinguishing states such as:

- `unexecuted`;
- `run-failed`;
- `gate-blocked`;
- `precondition-unavailable`;
- `executed-no-effect`;
- `executed-with-effect`.

The same work adds per-cell runtime/JDK selection and prevents agent environment variables or unrelated proxy/API configuration from contaminating PoC runtime evidence.

## Project-specific design vocabulary

The following terms are used by VulnGate as concrete implementation concepts. Their presence here does not imply legal exclusivity over the words themselves.

### Evidence Fidelity

A conclusion must not be stronger than the actual semantics of the evidence. For example, observing an intermediate behavior does not automatically satisfy the evidence contract for a stronger RCE claim.

### Claim Eligibility

A security label is treated as something that must be earned by explicit evidence conditions. Novelty is one example: an incomplete public-information query cannot establish the absence of prior public evidence.

### Precondition Honesty

Configuration, runtime, feature state, identity, role, tenant, object context, and other prerequisites are retained as part of the vulnerability conclusion and severity assessment.

### Typed Negative Evidence

Failure to reproduce is not one state. VulnGate attempts to distinguish a genuinely executed no-effect result from unexecuted work, harness failure, policy blocking, or unavailable prerequisites.

### Fix-Completeness Evidence

The existence of an upstream security patch is not treated as automatic proof that every related path or variant has been eliminated.

## Relationship to prior work

VulnGate exists in a field with significant prior public work. The project does not claim invention of broad ideas such as:

- LLM-assisted vulnerability research;
- specialized/deterministic security tools used by an LLM agent;
- runtime PoC validation;
- variant analysis;
- static/semantic program analysis;
- persistent security findings or ledgers.

Representative related systems and differences are documented in [RELATED_WORK.md](RELATED_WORK.md).

Acknowledging prior work is part of the project's provenance practice. If future VulnGate development directly adopts implementation code, rules, prompts, datasets, or other protected material from an external project, that source and its license should be recorded explicitly rather than folded into this provenance narrative as independent work.

## Recommended provenance preservation

The maintainer should retain, where practical:

- full Git history and tags;
- `CHANGELOG.md` entries;
- regression tests associated with past failures;
- important ChatGPT/Codex design discussions;
- pre-public local snapshots and timestamps;
- sanitized audit artifacts showing which failure led to which change;
- notes on third-party code or datasets and their licenses.

Sensitive vulnerability material, credentials, private vendor coordination, and undisclosed PoCs should not be committed to this public repository merely for provenance purposes.

## Scope of this document

This file is an engineering provenance record. It does not prove absence of accidental similarity, establish patent rights, or replace a formal source-code/license audit. Its purpose is to make VulnGate's actual development path transparent and reviewable.
