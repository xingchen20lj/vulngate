# 当前整改状态

这份状态表记录本轮实际使用中发现、并已纳入回归门禁的补充项。它与
`docs/KNOWN-LIMITATIONS.md` 配合使用：后者只描述仍成立的限制，本文件描述
整改闭环和尚未完成的架构项。

## 本轮已闭环

- [x] `audit-exec` 支持文档约定的 `target options -- argv` 和 `options target -- argv`
      两种写法；`argparse.REMAINDER` 不再吞掉必需参数。
- [x] PreToolUse host guard 与 CLI 使用同一套参数识别规则，支持受信任的
      `PYTHONPATH=<当前插件>/scripts` / `env PYTHONPATH=...` 前缀，同时拒绝外部
      import root。
- [x] Git-index coverage rebuild 初始化 excluded-directory accumulator，覆盖含有
      `vendor`、`node_modules` 等排除目录的真实仓库，不再因 `NameError` 退化为无覆盖率。
- [x] 上述两条都加入 hermetic regression tests，并纳入完整 unittest、Ruff、compileall
      和 secret-scan 门禁。
- [x] 独立 effect collector 已覆盖 HTTP semantic、filesystem diff、process/JVM
      lifecycle、target-declared JVM protocol state、SQLite fixture 和 authorization JSON
      state；原始内容只在内存中处理，
      Java/Shell matrix runner 可按目标声明自动 wiring，结论与 G4 只接受注册
      collector 的独立 effect 行。
- [x] `WorkBudget` 已作为 round/S4/candidate/LLM 的共享父预算接入，子预算只能收窄
      父预算；新增 5k/50k/500k 可选 source-inventory benchmark，CI 执行 5k smoke。
- [x] 关键 conclusion/gate/observer 分支增加 branch-coverage smoke，最低总覆盖门槛为
      50%，并在 CI 中执行。
- [x] Hermetic S0–S8 回归已补上真实 HTTPS fixture；配套 fail-closed 状态回归覆盖
      typed-effect 确认、排除、失败、blocked、precondition-unavailable、timebox recovery，
      以及 Novelty 命中/查询失败和 G5 缺失。
- [x] `agent_cli.py` 已收敛为薄入口；`audit`、`audit_exec`、`runtime`、`research`、
      `analysis`、`evidence` handler 已移入 `scripts/agent/cli/`，并保留旧 CLI 路径兼容。
- [x] autonomous driver 已拆为共享 context、preparation、scheduling、execution、reporting
      phase；`run_agent.py` 仅保留兼容 facade，并转发旧导入与 monkeypatch 入口。
- [x] coverage scheduler 已拆为 `scheduler/{common,intake,scoring,quota,persistence}.py`，
      `agent.analysis.scheduler` 继续提供旧 public API。
- [x] expired audit guard 仅在 workspace 与 source root 均已不存在时自动回收；仍存在的
      expired root 继续保持 fail-closed，避免临时测试目录耗尽 registry 上限。
- [x] Branch governance policy 已作为 `.github/branch-protection.json` 和 schema 纳入 CI，
      并校验 required `test`/`security` checks、CODEOWNERS 覆盖和禁止 force-push；该
      本地 policy 不冒充 GitHub 远端 protection。
- [x] `scripts/apply_branch_governance.py` 提供默认 dry-run、显式 `--apply --confirm-main`
      写入和强制 readback；没有授权时不会触碰远端状态。
- [x] mypy 已纳入 CI，并对 conclusion/evidence/gates、effect observers、HTTP observer
      和 isolation capability 这些安全决策核心模块执行明确的 type gate。
- [x] G4 fail-closed 状态增加 Hypothesis 属性测试：任意 failed/blocked/timed-out/
      precondition-unavailable/observer-gap cell 都不能由 PoC marker 晋升为确认。
- [x] `security_types.py` 集中定义 `ExecutionState`、`StopReason`、`IsolationState` 和
      `ArtifactEnvelope`；schema、G4、隔离能力和预算边界使用 typed values，再在 JSON
      边界序列化。
- [x] 历史审阅已归档到 `docs/reviews/2026-09-23-development-review.zh-CN.md`，旧路径
      保留索引，不再把历史结论混入当前限制说明。

## 仍需后续版本完成

- 具体目标仍需声明其 `jvm-protocol` JSON snapshot 和 allowlisted paths；未声明观测
  scope 的协议类别保持 `pending`，不能自动确认。
- GitHub branch protection/ruleset 的远端启用与 readback 仍需在仓库设置侧完成；代码仓库
  已提供 CI/security/release checks，但不能从本地 checkout 推断远端 required checks。
  本次只读核验结果：`main` 当前返回 `Branch not protected`，仓库 rulesets 为空；启用
  规则前仍需仓库管理员确认 required check 名称和合并策略。
