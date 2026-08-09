# VulnGate

> A Codex-native vulnerability research pipeline for untrusted-input parsing libraries.

**Language:** English | [简体中文](README.zh-CN.md)

VulnGate turns the Codex agent into a structured security research workflow. Given a
target library's source code and runtime, it walks through eight research stages
(S1–S8) — from attack-surface mapping to disclosure-ready findings — and enforces
five hard evidence gates (G0–G5) so that every result is runtime-verified,
novelty-checked, and defensible.

The host Codex agent owns reasoning. Deterministic helpers (bundled with the plugin)
own the parts that must be repeatable: PoC matrix execution, novelty scanning,
CVSS computation, and ledger rendering.

## Why VulnGate

Manual vulnerability research on parsing libraries is slow and easy to get wrong:
entries are guessed at, "it looks reachable" passes for evidence, and a missing
search is treated as a novel finding. VulnGate encodes the disciplines that keep
research honest:

- **No confirmation without runtime evidence.** A finding is confirmed only when a
  PoC cell produced the claimed effect (instantiation, JNDI, OOM, network marker).
- **No 0day claims on incomplete queries.** If the public-information scan failed or
  was rate-limited, the verdict is `unknown-query-failed`, not `candidate-0day`.
- **Hard downgrade on upstream hits.** Any open PR/issue or public disclosure
  covering the mechanism degrades the claim to *same-family + incremental*.
- **Precondition-honest scoring.** CVSS vectors are validated against the actual
  precondition tier (default config vs. single feature vs. app cooperation).
- **Parallel by design.** The pipeline spawns sub-agents for PoC matrices and
  upstream sweeps, so the host agent spends its time judging evidence, not running
  errands.

## Features

- **Host-native orchestration** — runs on the model you already use in Codex; no
  separate API key required.
- **Eight stages, five gates** — S1 attack surface, S2 candidates, S3 source audit,
  S4 PoC matrix, S5 novelty, S6 CVSS, S7 findings, S8 ledger.
- **Bundled deterministic CLI** — `agent_cli.py` with `source-map`,
  `source-evidence`, `matrix`, `novelty`, `cvss`, `ledger`, and `doctor`.
- **Safety first** — JNDI/LDAP/HTTP side effects are loopback-only; non-loopback
  egress is refused at compile time; findings stay local until maintainer
  coordination.
- **Works in Codex CLI and desktop app** — both share the same plugin marketplace
  and configuration.

## Installation

### Prerequisites

- Codex (CLI or desktop app), version with plugin support
- Python 3.8+
- JDK 8+ (17/21 recommended) for PoC compilation
- `rg` (ripgrep) for source mapping

### Install from this repository

```bash
git clone https://github.com/xingchen20lj/vulngate.git
cd vulngate
./install.sh
```

`install.sh` does everything: copies the plugin to `~/plugins/vulngate`, registers
the personal marketplace, and enables it in Codex
(`codex plugin add vulngate@personal`). It finds the `codex` command automatically
— your `$PATH` first, then the CLI bundled inside the Codex desktop app. **If you
use the desktop app, you do not need to install the codex CLI separately.** If
`codex` cannot be found anywhere, the script tells you exactly what to run.

> **New thread required.** Plugin skills load at thread start. Open a new Codex
> thread after installing so the `vulngate-audit` skill becomes available.

### Do I need a local Codex client?

Yes. Plugins run on a local Codex client — the desktop app or the CLI. A
browser-only ChatGPT session cannot load local plugins. The desktop app ships with
its own `codex` binary, so installing the app is sufficient. Prefer CLI-only?

```bash
npm install -g @openai/codex
```

### Manual install / install from the marketplace

```bash
codex plugin add vulngate@personal
```

### Troubleshooting: `codex: command not found`

- You are using the desktop app but the terminal cannot find `codex` — run the
  bundled binary directly:
  - macOS: `/Applications/ChatGPT.app/Contents/Resources/codex`
  - Windows (Git Bash): `"$LOCALAPPDATA/Programs/ChatGPT/Resources/codex"`
- Or add it to your `$PATH` once, then plain `codex` works everywhere.
- `./install.sh` already performs these lookups for you; the manual command is only
  needed when the auto-detection fails.

## Quickstart

1. Start a new Codex thread.
2. Point at a target library:

   > Audit this parsing library and run the full S1→S8 pipeline:
   > `/path/to/library-src`

3. The host agent maps the attack surface, proposes candidates, audits the source,
   runs the PoC matrix (default config × safe mode × preconditions), checks novelty
   against upstream issues/PRs and public disclosures, and produces a
   disclosure-ready finding document.

For a hands-off run with your own LLM API key:

```bash
./scripts/run_pipeline.sh --name <target> --target-dir <path> --round 1
```

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for the full walkthrough.

## How it works

| Stage | What happens | Output | Gate |
|---|---|---|---|
| S1 | Attack-surface map (entries, danger call sites, defaults) | `S1/entry-inventory.json` | G0 dead code, G1 reachability |
| S2 | Candidate matrix (surface × entry × input × logic) | `S2/candidate-matrix.json` | — |
| S3 | Source audit against real code with file:line evidence | `S3/audit-notes.json` | G1b default-config gating |
| S4 | PoC matrix: versions × safe-mode × preconditions | `S4/matrix-runs/<c>/cells.json` | G4 runtime evidence |
| S5 | Novelty: upstream PR/issue + public disclosure scan | `S5/novelty.json` | G3 hard downgrade |
| S6 | CVSS score + precondition consistency | `S6/severity.json` | G5 tier↔AC consistency |
| S7 | Self-contained finding document (local only) | `reports/<target>/…` | disclosure hold |
| S8 | Ledger, exclusions, round summary | `ledger/<target>/…` | — |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details on the two operating
modes (host-native vs. autonomous CLI) and the evidence contract.

## Safety and disclosure

- PoC side effects are loopback-only (`127.0.0.1`); the matrix runner refuses to
  compile sources containing non-loopback URLs or IPs.
- External egress and port listeners require explicit approval and are logged.
- Findings are generated locally and are **not** published before maintainer
  coordination and a public fix.
- Report vulnerabilities in this plugin itself via
  [SECURITY.md](SECURITY.md).

## Development

- `scripts/smoke_test.sh` — environment and deterministic-helper smoke test
- `.codex-plugin/plugin.json` — plugin manifest (name, skills, interface)
- `skills/vulngate-audit/SKILL.md` — the host-agent execution manual
- Framework code lives in `scripts/agent/` (bundled Python package)

Iterating on a local install: `./install.sh && codex plugin add vulngate@personal`,
then start a new thread. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
