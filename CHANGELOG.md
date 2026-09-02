# Changelog

All notable changes to VulnGate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
