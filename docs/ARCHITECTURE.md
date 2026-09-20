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
