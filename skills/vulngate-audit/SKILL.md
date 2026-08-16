---
name: vulngate-audit
description: "Drive the VulnGate S1→S8 source-audit pipeline natively in Codex. Use when the user asks to audit any kind of source code — libraries (parsing/serialization/JSON/XML/YAML), web frameworks (Spring/Struts), middleware/servers (Tomcat/Jetty), logging libraries (Log4j/Logback), expression engines, message/RPC stacks (Dubbo/Netty/Hessian), or applications — for RCE/DoS/info-disclosure/logic flaws; verify a PoC across a version×feature×precondition matrix; run the novelty gate against upstream issues/PRs and public disclosures; compute CVSS with precondition consistency; or produce a disclosure-ready finding report. Aliases: 漏洞审计, 源码审计, 0day 挖掘, PoC 验证, Novelty 核验."
---

# VulnGate — S1→S8 漏洞研究管线（宿主驱动）

## 中文速览

- 你是主 Agent，拥有全部推理与结论判定；捆绑 CLI（`scripts/`）只做确定性工作。
- 流程：S1 攻击面 → S2 候选 → S3 源码审计 → S4 PoC 矩阵 → S5 Novelty → S6 CVSS → S7 发现文档 → S8 账本。
- 适用范围：**任意类型源码**（库 / Web 框架 / 中间件 / 日志库 / 表达式引擎 /
  RPC 消息栈 / 应用）。目标类型对应的攻击面清单见 `docs/AUDIT-PLAYBOOK.md`。
- 硬闸门 G0–G5：没有运行时 PoC 输出，不许说“确认”；上游公开命中，一律降级“同族+增量”，严禁声称 0day。
- S4/S5 用宿主原生 spawn 并行（每个候选一个子 Agent 跑矩阵/查上游），子 Agent 只回传原始证据，结论由你定。
- 安全边界：JNDI/HTTP 副作用仅回环 127.0.0.1；修复公开前不发布任何内容；网络外发需用户批准。

## 0. 子 Agent 并行纪律（强制，非可选项）

Codex 宿主可能注入 `multi_agent_mode=explicitRequestOnly`（"除非用户或技能明确要求，
否则不 spawn 子 Agent"）。**本技能即为明确要求**，因此：

1. **S4 每个候选 spawn 一个子 Agent** 跑 PoC 矩阵；**S5 spawn 一个子 Agent** 收集
   上游 tracker + 公开披露证据。并行上限 3 个（并发槽 = 主 Agent + 3），禁止一次
   spawn 超过 3 个。
2. **S4 开始前先自检**：通过 `list_agents` 确认 spawn 工具可用。可用则**必须使用**，
   不得仅因"保守/省事"而全程顺序执行。
3. 只有 spawn 工具**明确报错**（`agent thread limit reached` / 工具不存在 / 投递失败）
   才允许降级宿主顺序执行，且必须在轮次汇总记录"降级原因 + 尝试次数"。
4. 子 Agent 只回传原始证据，不给结论；按 §4 S4 心跳规则判断停滞，不得仅凭消息静默
   判定"子 Agent 停滞/通道不可用"。
5. 若因用户提示词显式要求而选择不 spawn，在轮次汇总说明原因；**禁止虚构
   "spawn 通道不可用"** 作为不执行的借口。

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
  hands-off run. 目标类型感知（0.2.5）：autonomous 会按目标类型选择提示词与
  S1 扫描（web-app 走 HTTP 路由清单 + Web 研究员提示词 + Shell/HTTP 矩阵）；
  Web 目标需在 env.md 声明 `target_type: web-app` 与
  `target_url: http://127.0.0.1:<port>`（或按版本 `target_url.<version>: ...`），
  web 模式不强制要求 jar。
- **范围约束（0.2.6+）**：目标目录可放 `scope.md`（或 `SECURITY-SCOPE.md`/
  `SECURITY.md`），内容为该项目官方的漏洞范围边界（如 Apache 的 SECURITY.md
  蒸馏版）。autonomous 的 S2/S3 会把它注入候选生成/审计提示词作为硬约束；
  原生 Mode A 也应先读它，把"范围外"（如 Admin 受信能力、operator 部署决策）
  直接排除，不验证、不记录。

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
  switches, default features, build command, and target type (library/framework/
  middleware/...).
- Locate `env.md` by checking, in order: the target source dir, its parent dir,
  and the workspace root. If absent, create one yourself from observable facts
  (git tag/commit, build files, default feature flags) and record where each
  fact came from. Do not skip S1's version/target-type determination because
  no `env.md` was provided.
- `python3`, JDK (8+; 17/21 recommended) for Java targets, and the target's build
  tool (maven/gradle/npm/go/...). For non-Java targets, the host agent runs the
  PoC with the appropriate runtime and still records machine-readable
  observation lines.
- Network for Novelty (GitHub API; anonymous quota 60/h — set `GITHUB_TOKEN` or
  `GH_TOKEN` when rate-limited, see §10).

Missing tools: do not fake results. Report the gap and install what is needed (ask
user if the install requires system-level changes).

## 4. Workflow S1→S8

Run stages in order. Persist every artifact under the target workspace:
`state/<target>/round-NN/…`, `ledger/<target>/round-NN/…`, `reports/<target>/round-NN/…`.

### S1 — Attack-surface map

- Determine the **target type** (library / web framework / middleware / logging /
  expression engine / message-RPC / application) and enumerate its modules and
  entry points according to `docs/AUDIT-PLAYBOOK.md`: parsing, HTTP request
  handling, expression evaluation, configuration loading, file/IO, log
  formatting, protocol decoding, command execution, template rendering, etc.
  Record default feature flags and version diff if a previous version exists.
- **通告驱动反查（优先）**：若目标近期有安全通告（GHSA/CVE/厂商公告），先按
  `docs/AUDIT-PLAYBOOK.md §10` 做 fix-diff 反查——拉 patched tag、diff 受影响
  版本，把修复点对应的旧版代码路径列为最高优先攻击面。修复代码即根因答案；
  反查产物仍必须过 S3 源码审计与 G4 运行时验证，且 G3 按 same-family 起步。
- Ask the bundled CLI for source evidence:
  `python3 scripts/agent_cli.py source-map --target-dir <path> --preset <parsers|http|expression|io|exec|config|all>`
  (grep-based: entries, danger call sites, class instantiation, reflection).
  Pick the preset matching the target type; `--pattern` overrides for custom regex.
- Gate **G0** (dead code) and **G1** (untrusted input reachable). If the entry is
  unreachable from untrusted input, record `GATE_BLOCKED` and exclude.

### S2 — Candidate matrix

- Generate candidates as `{surface, entry, input_shape, logic, hypothesis,
  attack_class, precondition_tier, preconditions, entry_feature, target_classes}`.
- Cover the full attack-class taxonomy from `docs/AUDIT-PLAYBOOK.md`, not only
  parsing: injection (expression/command/SQL/template), resource (path traversal/
  XXE/SSRF/arbitrary file), memory & resource exhaustion (OOM/stack overflow/CPU
  amplification), logic (auth bypass/race/validation bypass), and information
  disclosure (error stack/debug endpoints/log leaks). Do not anchor candidates to
  known advisories; the playbook is a checklist, not a limit.
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
  observation lines (e.g. `INSTANTIATED=<fqcn>`, `ERROR=<exception>`,
  `GATE_BLOCKED=<reason>`, `NETWORK=<url>`, `PARSED=<type>`). PoC shape follows
  the target type: a Java class for libraries, an HTTP request for web frameworks,
  a log line / config file for logging libraries, a byte stream for protocol
  stacks, a CLI invocation for applications.
- Matrix: `{versions} × {safe-mode on/off} × {precondition tiers}`. At least the
  default-config cell and the claimed-precondition cell.
- **Shell/HTTP PoC 契约（Web 应用/服务，Metabase 实战沉淀）**：脚本放
  `poc/<target>/round-NN/src/<candidate>.sh`，以 `bash` 执行（无需执行位）。
  观察行：`HTTP_CODE=<状态码>`、`RESP_MATCH=<响应特征串>`、
  `EVIDENCE=<副作用证据>`（标记文件/数据库行/日志行）、`GATE_BLOCKED=`、
  `ERROR=`。单元环境变量：`VULNGATE_VERSION` / `VULNGATE_SAFE_MODE` /
  `VULNGATE_PRECONDITION` / `VULNGATE_FEATURES`。确定性运行：
  `agent_cli.py matrix --lang shell --manifest <json>`；与 Java 相同，回环强制、
  非回环 URL/IP 静态扫描拒绝。
- **Spawn one sub-agent per candidate** (up to 3 in parallel) with a bounded task:
  write the PoC under the workspace, compile, run the matrix, and return raw cell
  outputs plus any `harness_error`. The spawn message MUST state the boundary
  verbatim: "You may ONLY write PoC sources and matrix outputs. You must NOT
  create any S5–S8 artifacts (novelty, severity, reports, ledger) or draw
  conclusions; return raw evidence only. Writing outside the allowed scope is a
  harness error and will be discarded." Sub-agents return evidence, never
  verdicts. If a sub-agent overstepped, treat its extra writes as harness errors
  and re-do them yourself as main agent.
- **Sub-agent liveness (Metabase lesson, 2026-08-10):** long target operations
  (server boot, large-jar decompile/diff, integration tests) are silent for
  minutes. Never declare a sub-agent "stalled" based only on message silence.
  Require each sub-agent to maintain a heartbeat file
  `state/<target>/round-NN/S4/heartbeat-<candidate>.log` (append one line per
  progress step; touch at least every ~3 minutes). A sub-agent is only stalled
  when BOTH hold for >5 minutes: heartbeat mtime is stale AND no child process
  of the audit is running AND its workdir has not grown. Before falling back,
  inventory its workdir (`ls -la`, `find`), preserve any artifacts under the
  workspace, reuse partial outputs, and kill orphan processes it started
  (record PIDs/ports in `S4/processes.json`).
- **Process registry & dedup:** before starting a service for a PoC, check
  `lsof -nP -iTCP:<port> -sTCP:LISTEN` and `ps aux` for existing instances of
  the same target/version. Reuse an already-running instance when it matches
  the cell's version+config; never boot a second duplicate instance for the
  same matrix cell. Record every started PID+port in `S4/processes.json`.
- Deterministic runner (also usable directly):
  `python3 scripts/agent_cli.py matrix --workspace <path> --target <name> --round <N>
  --candidate <id>`
  (wraps `agent/tools/build.py`; Java-first, enforces loopback-only egress via
  source scan). Shell/HTTP PoCs use `--lang shell` with the same cells.json schema;
  the host can also run them itself and drop observation lines into the same
  structure.
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
- **Local patched-version diff:** if a fixed/patched version's jar or source is
  available locally (e.g. downloaded during the audit), diff the affected
  classes/files and cite it in the novelty evidence. It bounds the fix
  (which versions are affected) and is stronger than a version-range guess.
  (S1 的"通告驱动反查"复用同一 diff，方向相反：S1 用它找攻击面，S5 用它定边界。)
- **版本区间精确核对（Metabase 教训）**：引用受影响/修复版本时，以 GHSA
  原文 `vulnerable_version_range` / `first_patched_version` 为准，逐通告核对；
  厂商博客的"统一安全版清单"可能取同日多个通告修复版的较晚者（如
  reset_password 修在 0.58.23，0.58.24 属同日另一通告 GHSA-r8h2-qpfx-mx59），
  不得混用。
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
- **CVSS/tier must be copied verbatim from `S6/severity.json` (final values).**
  Never re-write intermediate/pre-G5 scores anywhere in S7 (summary, tables, or
  notes). If the finding document contains any vector/tier that differs from the
  S6 final record, the document is NOT complete — reconcile S7 to S6 before
  proceeding. Rejected intermediate values may be listed only as an explicit
  "superseded" note quoting the S6 decision.
- Gate **disclosure**: before fix/publication, the document stays local. Never create
  public GitHub issues/PRs from this workflow.

### S8 — Ledger

- Append to `ledger/<target>/round-NN/挖洞-候选账本-NN.md`, the exclusions list, and
  the round summary: `python3 scripts/agent_cli.py ledger --workspace <path>
  --target <name> --round <N> --entries <json-file>`.
- **Evidence hard rule:** every ledger row and every exclusion must carry
  non-empty evidence (runtime output, source refs, or test results). The CLI
  rejects entries with empty evidence — an exclusion with an empty "basis"
  column is a harness error, not a valid record (Metabase C4 lesson,
  2026-08-10).
- **Round-end cleanup checklist:** before reporting the round as done, verify no
  audit-started processes are still running (`ps aux | grep -iE "<target>|jar
  name"`, `lsof` on used ports) and terminate any that remain. Record cleanup
  in the round summary. A finished round must not leave orphan servers or
  listeners behind.
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
  execution and note it in the round summary. **快速降级（Metabase 教训）**：
  spawn 后子 Agent 在约 2 分钟内无任何实质产出（含空任务 / 仅问候语 /
  心跳文件未出现），即判定 spawn 通道不可用，立即降级宿主顺序执行并记录，
  不反复重试。

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

- **Sub-agent appears stalled**: check its heartbeat file mtime, `ps aux` for
  its child processes, and whether its workdir is growing. Long server
  boots/diffs legitimately take minutes. Only after heartbeat stale >5 min AND
  no children AND no growth may you declare a stall; then preserve its
  artifacts, kill its orphans, and note the fallback in the round summary.
- **Sub-agent 收到空任务 / 只收到问候语**：spawn 通道在当前环境不可用时，
  子 Agent 可能只回问候语或空结果。等待上限 2 分钟（含心跳文件检查），仍无
  实质产出 → 判定通道不可用，立即降级宿主顺序执行并记录，不反复重试。
- **source-map returns nothing for a non-Java target**: the CLI scans
  Java+Clojure+Python+Go+JS etc. by default (`--globs all`). If you restricted
  to Java (`--globs java`) or the project uses an unusual layout, re-run with
  `--preset http --globs all`, or sweep with `rg` directly and record the
  manual sweep in S1.
- **GitHub rate limit**: symptom `GitHub API rate-limited` in S5. Fix: `export
  GITHUB_TOKEN="$(gh auth token)"` (or classic PAT, no scopes needed for public
  reads) and rerun S5.
- **No jars found**: build the target first (`mvn package` / `gradle build`) or point
  `--target-dir` at a directory containing jars.
- **Web 目标报 "no jars found" 或 "web-app 需要 target_url"**：在源码根目录写
  `env.md`，声明 `target_type: web-app` 与 `target_url: http://127.0.0.1:<port>`
  （运行中的目标实例；可按版本加 `target_url.<version>: ...`）。autonomous
  web 模式不需要 jar，S4 用 Shell/HTTP 矩阵直连该 URL。
- **PoC won't compile**: check JDK version, module exports (`--add-exports` /
  `--add-opens`), and classpath. Record the exact harness error in the cell.
- **Spawn unavailable**: fall back to sequential; note it in the round summary.

## 11. Final response format

End each run with: 结论（确认/排除/待验证 + 数量）、每个确认项的前置条件分级与
CVSS、Novelty 判定与依据、证据落盘路径、下一步建议。Keep it scannable; the full
detail lives in the artifacts.
