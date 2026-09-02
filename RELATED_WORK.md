# Related Work and Research Positioning

VulnGate is developed in an active area spanning LLM-assisted vulnerability research, program analysis, exploit validation, and autonomous security agents. This document records relevant public work and clarifies where VulnGate overlaps and where its current emphasis differs.

This list is intentionally non-exhaustive. Inclusion does not imply code reuse, architectural derivation, or equivalence.

## Google Project Zero — Project Naptime / Big Sleep

Project Naptime publicly described an LLM-assisted vulnerability research architecture in 2024 with specialized tools, interactive reasoning, and a strong emphasis on verification. Big Sleep continued that line of work on real vulnerability research.

- Project Naptime: https://projectzero.google/2024/06/project-naptime.html
- Big Sleep: https://projectzero.google/2024/10/from-naptime-to-big-sleep.html

**Overlap with VulnGate**

- LLM reasoning is grounded by specialized/deterministic tooling.
- Vulnerability conclusions should be verified rather than accepted from model narration alone.
- Variant-oriented research is valuable.

**Different emphasis in VulnGate**

VulnGate does not position verification as a single terminal step. It treats claim promotion as a lifecycle problem spanning reachability, runtime effect, preconditions, novelty completeness, severity consistency, fix completeness, and persistent evidence records.

## MCPwner

MCPwner is an autonomous vulnerability-discovery system exposed through MCP. Its public design includes deterministic PoC oracles, sandboxed validation, and a persistent findings ledger.

- Repository: https://github.com/nedlir/MCPwner

**Overlap with VulnGate**

- Model reasoning is paired with deterministic security tooling.
- Empirical PoC validation is required before strong findings are reported.
- Persistent research state/ledger is part of the workflow.

**Different emphasis in VulnGate**

MCPwner is primarily organized as a vulnerability-discovery/security-tooling platform. VulnGate is organized around an explicit research-decision protocol: a hypothesis moves through evidence states and gates that govern what can be claimed about confirmation, novelty, preconditions, and severity.

## Prowl

Prowl is an autonomous vulnerability discovery and exploit-validation tool. Its public architecture separates deterministic reconnaissance from LLM hypothesis/triage and later runtime exploit validation.

- Repository: https://github.com/toniantunovi/prowl

**Overlap with VulnGate**

- Deterministic preprocessing/reconnaissance before LLM reasoning.
- Structured hypothesis generation and triage.
- Runtime validation against built or running targets.

**Different emphasis in VulnGate**

Prowl has stronger emphasis on deterministic program-analysis infrastructure and exploit validation. VulnGate's current emphasis is research-claim governance, including novelty-query completeness, typed negative evidence, precondition-to-severity consistency, and fix-completeness decisions.

## Frame

Frame combines LLM reasoning with static/symbolic analysis and solver-backed techniques.

- Repository: https://github.com/lambdasec/frame

**Overlap with VulnGate**

- The model proposes or interprets; a more deterministic core is used to constrain conclusions.
- Security reasoning should not rely on unconstrained natural-language confidence alone.

**Different emphasis in VulnGate**

Frame emphasizes sound/static and symbolic program analysis. VulnGate currently uses conservative source evidence and explicitly labels heuristic source-to-sink hints as `heuristic-nearby` with `requires_manual_dataflow=true`; it does not claim those hints are sound semantic data-flow proofs. VulnGate instead focuses on end-to-end evidence semantics across the vulnerability research lifecycle.

## Broader research direction

Recent research increasingly explores topics such as LLM-generated vulnerability hypotheses, PoC generation, runtime falsification, semantic validation, repository-aware vulnerability assessment, and agentic security workflows. VulnGate should be evaluated as part of this broader verification-first trend rather than as an isolated invention.

## VulnGate's current research question

VulnGate is centered on the following question:

> **When an AI security agent participates in vulnerability research, what evidence must exist before a hypothesis is eligible to become a stronger security claim?**

Three terms summarize the current design focus:

1. **Evidence Fidelity** — the conclusion must not be stronger than the semantics of the evidence.
2. **Claim Eligibility** — labels such as `confirmed` or `candidate-0day` require explicit conditions.
3. **Precondition Honesty** — configuration, runtime, identity, role, tenant, and other prerequisites remain part of the result.

Examples include:

- a public-information query failure remains `unknown-query-failed` rather than becoming evidence for novelty;
- a runtime/environment failure is not silently converted into vulnerability exclusion;
- object instantiation or a lookup trace is not automatically promoted to RCE without the effect required by the RCE claim;
- severity scoring is checked against the conditions required to reproduce the issue;
- a prior security fix can produce fix-completeness/residual candidates instead of automatically closing the research path.

## Originality and provenance note

Similarity at the level of broad research ideas does not by itself imply code or implementation derivation. VulnGate does not claim that LLM-assisted vulnerability research, runtime verification, variant analysis, ledgers, or deterministic tooling originated in this repository.

Project-specific provenance is documented in [PROVENANCE.md](PROVENANCE.md) and the repository Git history. The purpose of these records is to make the project's independent design evolution inspectable while acknowledging public prior work.

## Maintaining this document

When a new system or paper becomes materially relevant to VulnGate:

1. add it here with a primary public source;
2. describe both overlap and differences;
3. avoid unsupported "first" or "unique" claims;
4. if VulnGate adopts a concrete implementation or code from another project, record the source and license explicitly.
