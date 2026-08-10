# Changelog

All notable changes to VulnGate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
