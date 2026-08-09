# Architecture

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
