---
name: vulngate-audit
description: "Drive the VulnGate S1→S8 vulnerability research pipeline natively in Codex. Use when the user asks to audit a parsing/serialization library (Java/Python/Go/etc.) for RCE/DoS/info-disclosure, verify a PoC across a version×feature×precondition matrix, run the novelty gate against upstream issues/PRs and public disclosures, compute CVSS with precondition consistency, or produce a disclosure-ready finding report. Aliases: 漏洞审计, 0day 挖掘, PoC 验证, Novelty 核验."
---

# VulnGate — S1→S8 漏洞研究管线（宿主驱动）

## 中文速览

- 你是主 Agent，拥有全部推理与结论判定；捆绑 CLI（`scripts/`）只做确定性工作。
- 流程：S1 攻击面 → S2 候选 → S3 源码审计 → S4 PoC 矩阵 → S5 Novelty → S6 CVSS → S7 发现文档 → S8 账本。
- 硬闸门 G0–G5：没有运行时 PoC 输出，不许说“确认”；上游公开命中，一律降级“同族+增量”，严禁声称 0day。
- S4/S5 用宿主原生 spawn 并行（每个候选一个子 Agent 跑矩阵/查上游），子 Agent 只回传原始证据，结论由你定。
- 安全边界：JNDI/HTTP 副作用仅回环 127.0.0.1；修复公开前不发布任何内容；网络外发需用户批准。

## 1. Role model

You (the host Codex agent) are the **main agent** of the research loop. The bundled
Python framework (`scripts/agent/`) is a **deterministic executor**: it compiles and
runs Java PoCs, queries GitHub for novelty, computes CVSS, renders ledgers. It never
decides facts. You decide from its raw runtime observations
(`GATE_BLOCKED` / `INSTANTIATED` / `ERROR` / `NETWORK` / `PARSED` lines) and from
your own source audit.

Two operating modes:

- **Mode A — Host-native (recommended, zero extra setup):** you do S2/S3/S5 reasoning
  yourself using your native tools (exec, search, spawn). Call the bundled CLI only for
  deterministic steps (matrix, novelty fixtures, cvss, ledger). No API key needed.
- **Mode B — Autonomous CLI:** `scripts/run_pipeline.sh --name <target> --target-dir
  <path> --round <N> ...` drives the whole loop with the configured LLM API
  (`DEEPSEEK_API_KEY` or `OPENAI_API_KEY`). Use when the user explicitly wants a
  hands-off run.

## 2. Locating the plugin root

Plugin root is the directory containing `.codex-plugin/plugin.json`. Resolve it with
`codex plugin list`, or locate `skills/vulngate-audit/SKILL.md` inside the plugin
directory. Let `PLUGIN_ROOT` be that directory. All script paths below are relative
to `PLUGIN_ROOT`.

```bash
export PYTHONPATH="$PLUGIN_ROOT/scripts${PYTHONPATH:+:$PYTHONPATH}"
```

## 3. Prerequisites

- Target source and/or jars with an `env.md` recording: version, JDK, safe-mode
  switches, default features, build command.
- JDK (8+; 17/21 recommended), `python3`, and the target's build tool (maven/gradle).
- Network for Novelty (GitHub API; anonymous quota 60/h — set `GITHUB_TOKEN` or
  `GH_TOKEN` when rate-limited, see §10).

Missing tools: do not fake results. Report the gap and install what is needed (ask
user if the install requires system-level changes).

## 4. Workflow S1→S8

Run stages in order. Persist every artifact under the target workspace:
`state/<target>/round-NN/…`, `ledger/<target>/round-NN/…`, `reports/<target>/round-NN/…`.

### S1 — Attack-surface map

- Enumerate modules, entry points (`parse*`, `read*`, `deserialize*`, converters),
  default feature flags, and version diff if a previous version exists.
- Ask the bundled CLI for source evidence:
  `python3 scripts/agent_cli.py source-map --target-dir <path>` (grep-based: entries,
  danger call sites, class instantiation, reflection).
- Gate **G0** (dead code) and **G1** (untrusted input reachable). If the entry is
  unreachable from untrusted input, record `GATE_BLOCKED` and exclude.

### S2 — Candidate matrix

- Generate candidates as `{surface, entry, input_shape, logic, hypothesis,
  precondition_tier, preconditions, entry_feature, target_classes}`.
- Precondition tiers (this drives CVSS later):
  - `0` — default config, no setup.
  - `single-feature` — one library feature flag (e.g. SupportAutoType).
  - `app-cooperation` — requires the application's target type/registration.
  - `extra-primitive` — requires an additional gadget/class on classpath.
- Do not write conclusions yet. Save `S2/candidate-matrix.json`.

### S3 — Source audit

- Audit each candidate against the actual source. Confirm or refute: gate checks,
  default-feature reachability, blacklist/SafeMode coverage, type confusion paths.
- Pull code evidence with `scripts/agent_cli.py source-evidence --file <path>
  --terms <t1,t2>` or grep/ripgrep directly; cite `file:line` in your notes.
- Gate **G1b**: if the path is gated behind a non-default feature, mark it; do not
  silently treat it as default-reachable.
- Save `S3/audit-notes.json`. Drop candidates whose hypothesis is refuted; keep the
  refutation in the exclusions list (S8).

### S4 — PoC matrix (host-native parallelism)

- For each surviving candidate, the minimal PoC must print machine-readable
  observation lines (e.g. `INSTANTIATED com.sun.rowset.JdbcRowSetImpl`,
  `ERROR java.lang.OutOfMemoryError`, `GATE_BLOCKED …`).
- Matrix: `{versions} × {safe-mode on/off} × {precondition tiers}`. At least the
  default-config cell and the claimed-precondition cell.
- **Spawn one sub-agent per candidate** (up to 3 in parallel) with a bounded task:
  write the PoC under the workspace, compile, run the matrix, and return raw cell
  outputs plus any `harness_error`. Sub-agents must not conclude; they return evidence.
- Deterministic runner (also usable directly):
  `python3 scripts/agent_cli.py matrix --workspace <path> --target <name> --round <N>
  --candidate <id>`
  (wraps `agent/tools/build.py`; enforces loopback-only egress via source scan).
- Gate **G4**: a candidate is “confirmed” only when a runtime cell produced the
  claimed effect (instantiation/JNDI/OOM/network marker). Static reasoning alone is
  never confirmation. Record every cell, including failures.

### S5 — Novelty (host-native parallelism)

- For each confirmed candidate, determine whether it is already public:
  - Upstream open/merged PRs and issues on the target repo (GitHub search).
  - Public advisories, CVEs, and security blogs (web search).
  - The bundled checker: `python3 scripts/agent_cli.py novelty --target <name>
    --round <N> --candidate <id>` (GitHub API first, offline fixtures as fallback;
    add `--offline` to force fixtures).
- **Spawn a sub-agent** to collect upstream tracker + web evidence while you audit the
  next candidate; you apply the judgment.
- Gate **G3**: any upstream open PR/issue or public disclosure covering the same
  mechanism → degrade to `same-family+incremental`, never “0day”. If queries failed
  (`unknown-query-failed`), stay conservative: do not upgrade novelty based on absence
  of evidence.

### S6 — CVSS + severity

- Compute the CVSS base score and validate precondition consistency:
  `python3 scripts/agent_cli.py cvss --vector <CVSS:3.1/...> --tier <tier>`
  (wraps `agent/tools/cvss.py`; tier→AC mapping is enforced by G5).
- Gate **G5**: tier `0` → `AC:L`; `single-feature` / `app-cooperation` /
  `extra-primitive` → `AC:H` unless justified and documented. If the vector contradicts
  the tier, fix the vector or downgrade the claim.
- Save `S6/severity.json` with vector, score, tier, and justification.

### S7 — Finding document

- Render a self-contained finding (`reports/<target>/round-NN/挖洞-发现-*.md`) with:
  summary, affected versions, code locations (`file:line`), trigger conditions,
  full PoC + matrix output, novelty judgment, CVSS + tier, and a timeline.
- Gate **disclosure**: before fix/publication, the document stays local. Never create
  public GitHub issues/PRs from this workflow.

### S8 — Ledger

- Append to `ledger/<target>/round-NN/挖洞-候选账本-NN.md`, the exclusions list, and
  the round summary: `python3 scripts/agent_cli.py ledger --workspace <path>
  --target <name> --round <N> --entries <json-file>`.
- Report to the user: confirmed count, excluded count, novelty judgments, and the
  next-step recommendation (verify on more versions, coordinate privately with the
  maintainer, or stop).

## 5. Hard gates summary

| Gate | Check | Blocks |
|---|---|---|
| G0 | Dead code / unused path | claiming reachability |
| G1 | Untrusted-input reachability | auditing unreachable entries |
| G1b | Default-config vs non-default feature | treating non-default as default |
| G3 | Upstream PR/issue/public disclosure | claiming 0day when any hit |
| G4 | Runtime PoC evidence | “confirmed” without cell output |
| G5 | CVSS vector ↔ precondition tier | inconsistent severity |

## 6. Native parallelism (why this plugin exists)

The standalone CLI cannot spawn Codex agents. As a plugin, **you** are the host: use
your native collaboration tools for real parallelism:

- S4: spawn 1 sub-agent per candidate (max 3 concurrent) → each writes+compiles+runs
  its PoC matrix → returns raw `cells.json` + logs. You merge and judge.
- S5: spawn 1 sub-agent for upstream tracker + web disclosure sweep → returns
  structured hits (repo/PR/issue/CVE/blog + URL). You apply G3.
- Keep sub-agent tasks bounded and concrete. They return evidence, never verdicts.
- If spawn is unavailable in the current environment, fall back to sequential
  execution and note it in the round summary.

## 7. Safety and approval model

- JNDI/LDAP/HTTP side effects in PoCs are **loopback only** (127.0.0.1). The bundled
  matrix runner refuses to compile sources that contain non-loopback URLs/IPs.
- Port listeners need approval; external (non-loopback) egress is denied by default.
- Network reads (GitHub API, Maven Central) are allowed for Novelty and version fetch.
- Every approval/denial decision is logged to `state/<target>/round-NN/approval-log.jsonl`.
- Never post findings, PoCs, or partial results to public channels before the
  maintainer has been coordinated with and the fix is public.

## 8. Precondition tiers → CVSS mapping (G5)

| Tier | Meaning | Default AC |
|---|---|---|
| 0 | default config, zero setup | L |
| single-feature | one non-default flag | H (unless documented default-on in some integrations) |
| app-cooperation | app must pass a specific target type / registration | H |
| extra-primitive | extra gadget/class on classpath required | H |

Document any deviation. When in doubt, use the harsher (higher AC / lower severity)
choice.

## 9. Artifacts and conventions

- Machine-readable observations, not prose, drive conclusions.
- Every matrix cell is kept (including failures and harness errors).
- Every excluded candidate is kept in the exclusions list with its reason.
- Findings are bilingual-ready (zh primary, EN summary) so they can be submitted or
  coordinated directly.

## 10. Troubleshooting

- **GitHub rate limit**: symptom `GitHub API rate-limited` in S5. Fix: `export
  GITHUB_TOKEN="$(gh auth token)"` (or classic PAT, no scopes needed for public
  reads) and rerun S5.
- **No jars found**: build the target first (`mvn package` / `gradle build`) or point
  `--target-dir` at a directory containing jars.
- **PoC won't compile**: check JDK version, module exports (`--add-exports` /
  `--add-opens`), and classpath. Record the exact harness error in the cell.
- **Spawn unavailable**: fall back to sequential; note it in the round summary.

## 11. Final response format

End each run with: 结论（确认/排除/待验证 + 数量）、每个确认项的前置条件分级与
CVSS、Novelty 判定与依据、证据落盘路径、下一步建议。Keep it scannable; the full
detail lives in the artifacts.
