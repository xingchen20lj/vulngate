# Quickstart

**Language:** English | [简体中文](QUICKSTART.zh-CN.md)

This guide walks through a first VulnGate run.

## 1. Install

```bash
git clone https://github.com/xingchen20lj/vulngate.git
cd vulngate
./install.sh
```

`install.sh` installs the plugin, registers the personal marketplace, and enables
it in Codex automatically. It finds the `codex` command in your `$PATH` or inside
the Codex desktop app bundle — no separate CLI installation needed when you use the
desktop app. Prerequisites: a local Codex client (desktop app or CLI), Python
3.8+, JDK 8+, `rg`.

> **New thread required.** Plugin skills load at thread start — open a new Codex
> thread after installing.

## 2. Prepare a target

Any directory containing source and/or jars works. For Java targets:

```bash
cd /path/to/library
mvn package        # produces target/*.jar if the library ships binaries
```

Record the environment (version, JDK, safe-mode switches, default features) in an
`env.md` next to the source — it anchors the precondition tier for every finding.

## 3. Run the pipeline (host-native mode)

Start a **new** Codex thread and say:

> Audit `/path/to/library` and run the full S1→S8 pipeline.

The host agent will:

1. Map the attack surface (S1) — entries, danger call sites, default features.
2. Propose candidates (S2) with precondition tiers.
3. Audit the source with file:line evidence (S3).
4. Run a mandatory S4 spawn preflight probe, then spawn sub-agents to write,
   compile, and run PoC matrices (S4) across versions × safe-mode ×
   preconditions. If the probe fails (no heartbeat within 90s), the whole
   round degrades to host-sequential execution and records "degraded mode".
5. Sweep upstream issues/PRs and public disclosures (S5) and apply the hard
   novelty downgrade.
6. Compute CVSS with precondition consistency (S6).
7. Render a local finding document (S7) and update the ledger (S8).

Results land under `state/<target>/`, `reports/<target>/`, and
`ledger/<target>/`.

## 4. Run the pipeline (autonomous mode)

When you want a hands-off run with your own LLM API key:

```bash
export DEEPSEEK_API_KEY=...        # or OPENAI_API_KEY
./scripts/run_pipeline.sh \
  --name mytarget \
  --target-dir /path/to/library \
  --round 1 \
  --max-calls 40 --max-candidates 4 --max-rounds 1 \
  --lang zh
```

## 5. Deterministic helpers

The host agent calls these on your behalf; you can also call them directly:

```bash
PYTHONPATH="$PWD/scripts" python3 scripts/agent_cli.py doctor
PYTHONPATH="$PWD/scripts" python3 scripts/agent_cli.py \
  source-map --root /path/to/library-src --pattern "checkAutoType\\("
PYTHONPATH="$PWD/scripts" python3 scripts/agent_cli.py \
  cvss --vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" --tier 0
```

## 6. Troubleshooting

- **GitHub rate limit in S5**: `export GITHUB_TOKEN="$(gh auth token)"` and rerun.
- **No jars found**: build the target first, or point `--target-dir` at a
  directory containing jars.
- **PoC compile errors**: check JDK version, module exports/opens, and classpath;
  record the exact harness error in the cell.
- **Skill not available**: plugin skills load at thread start — always open a new
  thread after installing or updating.
