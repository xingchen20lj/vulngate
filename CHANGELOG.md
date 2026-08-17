# Changelog

All notable changes to VulnGate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.10] - 2026-08-18

### Fixed

- **品牌命名统一（清理旧名残留）**：运行期标识里的 `0day-agent` 旧名全部改为
  `vulngate`——`public_scan.py` / `novelty.py` 的 HTTP User-Agent、
  `scripts/agent/__init__.py` docstring、`orchestrator/pipeline.py` argparse 描述。
  功能无变化，仅对外标识一致（Novelty/公开检索请求不再顶着旧项目名）。

## [0.2.9] - 2026-08-18

### Added

- **S4 spawn 预检探针（把"每轮随机暴露"变成"开跑即暴露"）**：S4 开工前先 spawn 一个
  极简探针子 Agent（任务模板 `skills/vulngate-audit/spawn-probe-task.md`），要求它在
  ≤90 秒内写入 `S4/spawn-probe.heartbeat` 并回 `PROBE-DONE`。探针通过 → 才逐候选
  spawn；探针失败（空任务 / 仅问候语 / 无心跳）→ 判定 degraded mode，整轮宿主顺序
  执行，`agent_cli.py spawn-probe --status degraded` 落盘 `S4/spawn-probe.json`，
  轮次汇总只记一条降级记录，不再逐候选重试。解决多轮实战中 spawn 通道问题"中途才
  暴露、每轮赌一把"的反复现象（2026-08-16/18 Superset、fastjson2 轮次沉淀）。

## [0.2.8] - 2026-08-16

### Added

- **依赖漏洞体检（开发者自审计模式）**：`agent_cli.py deps --target <dir>
  [--out report.md]` —— 自动发现 pom.xml / requirements*.txt / pyproject.toml /
  package.json / go.mod / Gemfile / Cargo.toml / composer.json / build.gradle，
  解析依赖清单，逐条查询 OSV 已知漏洞，输出每条漏洞的严重级与**修复版本建议**
  （优先取语义化版本而非 commit hash）；查询失败如实记录 `query_notes` 不中断。
- **QUICKSTART §1 开发者自审计**：先跑依赖体检、再走 S1→S8 的自查流程说明；
  SKILL.md 中文速览新增自审计模式入口。

## [0.2.7] - 2026-08-16

### Added

- **子 Agent 并行纪律（强制）**：SKILL.md 新增 §0 —— 明确"技能即为
  explicitRequestOnly 的明确要求"：S4/S5 必须 spawn（每候选一个、≤3 并行）、
  spawn 前自检、仅工具明确报错才降级并记录原因、禁止虚构"通道不可用"。
- **QUICKSTART 显式授权提示词**：文档新增 §0，给用户可直接粘贴的提示词模板
  （"S4/S5 必须使用 spawn 子 Agent 并行…"），解决宿主默认保守策略导致的
  子 Agent 不生效问题（08-10 实战暴露）。

## [0.2.6] - 2026-08-16

### Added

- **目标安全边界注入（scope.md）**：autonomous 的 `prepare_target` 自动读取
  目标目录下的 `scope.md` / `SECURITY-SCOPE.md` / `SECURITY.md`，写入
  `TargetConfig.scope_constraints`；S1.5/S2/S3 提示词注入该约束块，把
  "范围外"（Admin 受信能力、operator 部署决策、纯 DoS、低影响泄露等）作为
  候选生成的硬过滤器，防止 LLM 把设计能力当漏洞提出来。
- **Flask/Flask-AppBuilder 路由识别**：`SOURCE_MAP_PRESETS["http"]` 新增
  `@<name>.route`、`@expose(...)`、`@<name>.(get|post|put|delete|patch)`、
  `add_url_rule` 形态（Superset 实战暴露：旧正则只匹配 Clojure/Spring，
  Python 路由入口清单为空）。

## [0.2.5] - 2026-08-10

### Added

- **autonomous 目标类型感知**（Metabase v0.63.2 实战暴露的三大根因修复）：
  - S1/S2/S3/S5 提示词按目标类型切换：web-app 用 Web 安全研究员提示词
    （路由鉴权 / SQLi / SSRF / 模板注入 / 信息泄露 / 业务逻辑），不再被
    "Java 反序列化"人设带偏；
  - S1 攻击面扫描对 web 目标走 HTTP 路由清单（复用 source-map http preset，
    识别 Compojure / Spring / Flask / Express 等）；
  - S4 对 web 目标接入 ShellMatrixRunner：LLM 生成 bash HTTP PoC，观察契约
    HTTP_CODE / RESP_MATCH / EVIDENCE / GATE_BLOCKED，目标 URL 经
    `VULNGATE_TARGET_URL` 注入，含修复轮；
  - `prepare_target` 支持 env.md 声明 `target_type` / `target_url`
    （可按版本），web 目标不再强制要求 jar。
- **结论规则 HTTP 证据路径**：`derive_conclusion` 新增 http_evidence 确认
  （带内容分隔符的 RESP_MATCH / EVIDENCE 视为运行时证据），Web 候选可据此
  判定"确认"。

### Changed

- `SOURCE_MAP_PRESETS` 下沉到 `agent/tools/source_evidence.py`，CLI 与
  autonomous 共用同一份入口清单正则。

## [0.2.4] - 2026-08-10

### Fixed

- **ledger 渲染器容错**：`novelty` / `cvss` 传字符串时不再崩溃（字典与字符串
  均接受）——0.2.3 实战（Metabase round-01）中发现：entries 里写成字符串会抛
  `AttributeError: 'str' object has no attribute 'get'`。

## [0.2.3] - 2026-08-10

### Added

- **通告驱动反查（fix-diff 反查）**：AUDIT-PLAYBOOK 新增 §10——目标近期有安全通告
  时，先拉 patched tag、diff 受影响版本，把修复点对应的旧版路径列为最高优先
  攻击面（Metabase GHSA-vwf4-m7j8-wcjf 实战制胜技）。SKILL S1 同步为优先步骤，
  G3 按 same-family 起步。
- **Shell/HTTP PoC 矩阵运行器**：`build.py` 新增 `ShellMatrixRunner`（bash PoC，
  观察契约 `HTTP_CODE` / `RESP_MATCH` / `EVIDENCE` / `GATE_BLOCKED` / `ERROR`，
  单元环境变量 `VULNGATE_VERSION/SAFE_MODE/PRECONDITION/FEATURES`），
  `agent_cli.py matrix --lang shell` 与 `stages.run_s4` 双运行器接线；
  回环强制与 Java 一致（非回环 URL/IP 静态扫描拒绝）。
- **G4 HTTP 证据维度**：`summarize_candidate` 新增 `http_evidence`
  （http_code / resp_match / evidence），Web 应用候选可直接用响应侧证据判定。

### Fixed

- **版本区间精确核对（Metabase 教训）**：SKILL S5 要求以 GHSA 原文
  `vulnerable_version_range` / `first_patched_version` 为准，逐通告核对；
  博客"统一安全版清单"可能取同日多通告修复版的较晚者（reset_password 修在
  0.58.23，0.58.24 属另一通告），不得混用。
- **spawn 快速降级（Metabase 教训）**：SKILL §6/§10 明确 spawn 后约 2 分钟内
  子 Agent 无实质产出（空任务 / 仅问候语 / 心跳未出现）即判定通道不可用，
  立即降级宿主顺序执行并记录，不反复重试。

## [0.2.2] - 2026-08-10

### Fixed (Metabase round-01 lessons)

- **Sub-agent false-stall detection**: SKILL now requires a heartbeat file
  (`S4/heartbeat-<candidate>.log`), defines stall as heartbeat-stale >5min AND
  no child processes AND no workdir growth, and mandates artifact
  preservation + orphan-process cleanup before fallback.
- **Process registry & dedup**: SKILL requires checking `lsof`/`ps` before
  booting a service, reusing matching instances, and recording PIDs/ports in
  `S4/processes.json`; round-end cleanup checklist added.
- **Ledger evidence hard rule**: `ledger` CLI now rejects any row or exclusion
  with empty evidence (runtime output / source refs / test results).
- **source-map language coverage**: CLI now scans Java+Clojure+Python+Go+JS etc.
  by default (`--globs all`; `--globs java` restricts). `http` preset matches
  compojure `defendpoint/defroutes` and other non-Java route declarations.
- **env.md discovery**: SKILL defines lookup order (target dir → parent →
  workspace root) and self-creation from observable facts when absent.
- **S5 local patched-version diff**: SKILL requires citing local fixed-version
  diffs as fix-boundary novelty evidence.

## [0.2.1] - 2026-08-09

### Fixed

- S4 sub-agent boundary hardened: spawn messages must state verbatim that
  sub-agents may only write PoC sources and matrix outputs, must not create any
  S5–S8 artifacts or draw conclusions, and that out-of-scope writes are harness
  errors to be re-done by the main agent (observed in the first Tomcat run)

## [0.2.0] - 2026-08-09

### Changed

- Scope expanded from parsing/serialization libraries to **any source code**:
  web frameworks (Spring/Struts), middleware/servers (Tomcat/Jetty), logging
  libraries (Log4j/Logback), expression engines, message/RPC stacks, and
  applications
- S1 entry discovery is now target-type aware (`source-map --preset`:
  `parsers|http|expression|io|exec|config|all`)
- S2 candidates cover the full attack-class taxonomy (injection / resource /
  exhaustion / logic / disclosure), not only parsing
- S4 PoC shapes follow the target type (Java class, HTTP request, log line,
  byte stream, CLI invocation); non-Java PoCs are host-run with the same
  observation contract

### Added

- `docs/AUDIT-PLAYBOOK.md` — per-target-type attack-surface checklist with
  entry patterns and historical CVE-family references

## [0.1.0] - 2026-08-09

Initial release.

### Added

- Codex plugin manifest with `vulngate-audit` skill (S1–S8 pipeline, G0–G5 gates)
- Deterministic CLI (`agent_cli.py`): source-map, source-evidence, matrix, novelty,
  cvss, ledger, doctor
- Autonomous mode launcher (`run_pipeline.sh`) with LLM API support
- Bundled framework (`scripts/agent/`) with hard gates, precondition→CVSS
  consistency, conservative novelty judgments, and loopback-only sandboxing
- Self-contained installer (`install.sh`) for the personal marketplace
- Smoke test (`scripts/smoke_test.sh`)
- Bilingual documentation: `README.zh-CN.md`, `docs/QUICKSTART.zh-CN.md`
- Chinese translations: `docs/ARCHITECTURE.zh-CN.md`, `SECURITY.zh-CN.md`,
  `CONTRIBUTING.zh-CN.md` (CHANGELOG and LICENSE remain English by convention)
- One-command installer with automatic `codex` discovery (`$PATH`, then the CLI
  bundled inside the Codex desktop app), with `--no-enable` and inline validation
  fallbacks
- Installation FAQ: no separate codex CLI needed with the desktop app; exact
  commands when `codex` is not on `$PATH`

### Fixed

- `novelty` CLI now resolves pull requests via the documented `/pulls/{n}` GitHub
  endpoint (callers passing `pull_request` are normalized internally instead of
  falling back to fixtures on a 404)
- PoC observation contract hardened: `INSTANTIATED` is only emitted for
  non-generic results (JSONObject/HashMap/null are reported as `GATE_BLOCKED`)
- S7 discipline: finding documents must copy the CVSS/tier verbatim from the S6
  final record — re-writing intermediate/pre-G5 scores marks the document
  incomplete (prevents report-vs-S6 drift seen in first field run)
