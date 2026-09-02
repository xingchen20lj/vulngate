# VulnGate

> **面向 AI 安全智能体的证据闸门式漏洞研究框架。**

**语言：** [English](README.md) | 简体中文

VulnGate 是一套 Codex 原生的漏洞研究框架，它将**漏洞假设生成**与**安全结论裁决**明确分离。

宿主 Agent 负责阅读源码、分析攻击路径并提出漏洞假设；确定性组件负责收集和校验能够支撑结论的证据，包括可达性、运行时效果、利用前置条件、公开披露与 Novelty、严重性一致性，以及可复现的研究产物。

VulnGate 的核心原则很简单：

> **模型可以提出漏洞，但证据决定这个结论能够走多远。**

在 VulnGate 中，“看起来可能存在”“触发了某种行为”“漏洞已确认”“属于新漏洞”以及“高危/严重”不是可以相互替代的描述。S1–S8 研究生命周期和 G0–G5 证据闸门体系会约束一个候选在什么条件下才能升级为已确认漏洞、Novel Finding 或特定严重等级。

## 为什么需要 VulnGate

LLM 辅助漏洞研究很容易出现“听起来合理、证据却不够”的结论：

- 看到了危险调用点，就被误认为存在可利用路径；
- PoC harness 或环境失败，被误认为漏洞不存在；
- 仅观察到对象实例化或 lookup 行为，就被夸大成代码执行；
- 公开信息查询被限流，却被误当成“没有公开记录”；
- 漏洞依赖非默认 Feature，却按默认可达路径给出严重等级；
- 看见安全补丁存在，就默认修复已经完整覆盖所有变体。

VulnGate 将这些研究纪律固化为机器可检查的约束：

- **没有运行时证据，不得越级确认。** 安全结论只能升级到实际观察到的运行时效果所能支撑的强度。
- **公开信息查询不完整，不得声称 0day。** 查询失败或被限流时，Novelty 结论为 `unknown-query-failed`，而不是 `candidate-0day`。
- **上游已有同机制证据时强制降级。** 早于发现时间的 issue、PR、修复或公开披露命中同机制时，必须降低 Novelty 声称。
- **前置条件必须诚实保留。** CVSS 与严重等级必须与实际复现条件保持一致。
- **负面证据具有明确语义。** `unexecuted`、`run-failed`、`gate-blocked`、`precondition-unavailable`、`executed-no-effect` 与 `executed-with-effect` 是不同状态，不能相互替代。
- **修复完整性可以被验证。** 安全修复历史、patch variant 与 residual 可以成为一等候选，而不是因为“补丁已经存在”就直接排除。

## 研究定位

VulnGate **不主张** LLM 辅助漏洞研究、运行时 PoC 验证、variant analysis，或“模型推理 + 确定性工具验证”这一广义方向由本项目首创。这些方向已有公开先行工作，包括 Google Project Zero 的 Project Naptime / Big Sleep，以及其他 agentic security research 系统。

VulnGate 更关注一个进一步的问题：

> **当 AI 安全 Agent 自主参与漏洞研究时，在什么证据条件下，它才有资格把一个 hypothesis 升级为更强的安全结论？**

这形成了三个核心设计主题：

- **Evidence Fidelity（证据忠实度）** —— 结论必须与实际证据的强度和语义一致。
- **Claim Eligibility（结论资格）** —— *confirmed*、*novel*、*0day candidate* 等标签必须满足显式资格条件。
- **Precondition Honesty（前置条件诚实性）** —— 环境、配置、身份、角色、运行时等先决条件必须保留在结论中，不能为了得到更强结论而被忽略。

相关系统对比见 [RELATED_WORK.md](RELATED_WORK.md)，项目研发演进与溯源说明见 [PROVENANCE.md](PROVENANCE.md)。

## 架构速览

宿主 Codex Agent 负责开放式推理；插件捆绑的确定性组件负责必须可重复、可审计的步骤。

```text
源码 / 运行环境
      │
      ▼
宿主 Agent：测绘 → 假设 → 审计 → 解释
      │
      ▼
确定性证据收集
      │
      ├─ 源码证据 / patch variants
      ├─ PoC 矩阵 / execution-state convergence
      ├─ Novelty 查询 / coverage
      ├─ CVSS consistency
      └─ ledger / checkpoint / approval log
      │
      ▼
Evidence Gates
      │
      ▼
确认 / 排除 / 候选（待验证）
```

G0–G5 是一套证据闸门体系，其中 G1b 是默认配置安全门控的子闸门。编号代表稳定的研究决策点，而不是“每个数字都必须恰好对应一个同级闸门”的营销计数。

## 功能特性

- **宿主原生编排** —— 推荐模式直接使用 Codex 中已配置的模型，无需额外 API Key。
- **S1–S8 研究生命周期** —— 攻击面 → 候选 → 源码审计 → PoC 矩阵 → Novelty → 严重性 → 发现文档 → Evidence Ledger。
- **确定性助手 CLI** —— `agent_cli.py` 提供 source mapping/evidence、矩阵运行、Novelty、CVSS 一致性、账本、依赖检查、spawn 诊断与 staging helpers。
- **版本 × Feature × 前置条件验证** —— PoC 以显式 cell 矩阵运行，而不是单次 best-effort 测试。
- **授权边界矩阵** —— Web/应用类候选可加入身份 × 角色 × 租户 × 对象维度。
- **逐 cell 运行时前置** —— 声明需要的 JDK/runtime 必须真实可用，否则记录 `precondition-unavailable`，不会静默使用其他运行时替代。
- **S4 证据收敛** —— 已落盘矩阵证据不会被 Agent/spawn 超时元数据覆盖。
- **保守 Novelty** —— 公开查询失败会保留为不确定状态，而不会被转化为“未发现公开记录”。
- **修复完整性分析** —— 近期安全修复、patch variant 与 residual 可继续进入验证流程。
- **Checkpoint + Evidence Ledger** —— 研究状态、证据与最终结论之间保持可追溯关系。
- **安全优先执行边界** —— 回环优先、审批留痕，并支持显式授权且白名单化的 staging。

## 安装

### 前置要求

- Codex（CLI 或桌面客户端），支持插件的版本
- Python 3.8+
- JDK 8+（一般使用推荐 17/21；个别 PoC cell 可声明特定运行时）
- `rg`（ripgrep），用于源码测绘

### 从本仓库安装

```bash
git clone https://github.com/xingchen20lj/vulngate.git
cd vulngate
./install.sh
```

`install.sh` 会把插件复制到 `~/plugins/vulngate`、注册个人 marketplace，并在 Codex 中启用（`codex plugin add vulngate@personal`）。脚本会自动从 `$PATH` 和支持的桌面应用路径中寻找 `codex`。

> **安装后必须新建线程。** 插件技能在线程启动时加载。

### 手动安装

```bash
codex plugin add vulngate@personal
```

如果只想使用 CLI 版 Codex：

```bash
npm install -g @openai/codex
```

完整安装排障与走查见 [docs/QUICKSTART.zh-CN.md](docs/QUICKSTART.zh-CN.md)。

## 快速开始

新建 Codex 线程，并把 VulnGate 指向你有权审计的源码目录：

> 审计这个代码库，跑完整的 S1→S8 研究流程：`/path/to/source`

宿主 Agent 会测绘攻击面、提出候选、审计源码、执行面向证据的验证矩阵、检查公开 Novelty、校验严重性一致性，并生成本地研究产物。

如需使用自己的兼容 LLM API Key 无人值守运行：

```bash
./scripts/run_pipeline.sh --name <target> --target-dir <path> --round 1
```

## 工作原理

| 阶段 | 目的 | 代表性输出 | 闸门 |
|---|---|---|---|
| S1 | 攻击面、入口、危险调用点、修复历史/变体、项目画像、目标类型规则 | `S1/entry-inventory.json`、`S1/security-fix-history.json`、`S1/patch-variants.json`、`S1/project-profile.json`、`S1/target-rules.json`、`S1/composite-chain-hints.json` | G0 死代码、G1 可达性 |
| S2 | 候选矩阵：surface × entry × input × mechanism | `S2/candidate-matrix.json` | — |
| S3 | 带 file:line 证据的源码审计、Source→Sink hints、residuals | `S3/audit-notes.json`、`S3/residuals.json` | G1b 默认配置门控 |
| S4 | PoC 矩阵：版本 × safe mode × 前置条件；可选 authz context | `S4/matrix-runs/<c>/cells.json`、`S4/execution-status.json`、`S4/authz-matrix.json` | G4 运行时证据 |
| S5 | Novelty：上游 issue/PR/fix + 公开披露搜索与覆盖记录 | `S5/novelty.json`、`S5/novelty-coverage.json` | G3 Novelty / 强制降级 |
| S6 | CVSS + 前置条件/影响一致性 | `S6/severity.json` | G5 一致性 |
| S7 | 自包含本地发现文档 | `reports/<target>/…` | 披露冻结 |
| S8 | Evidence Ledger、排除项、轮次汇总 | `ledger/<target>/…` | 最终一致性检查 |

Source→Sink 图刻意保持保守：启发式邻近路径会明确标记为 `heuristic-nearby` 与 `requires_manual_dataflow=true`，不会冒充严格语义数据流证明。

详细设计见 [docs/ARCHITECTURE.zh-CN.md](docs/ARCHITECTURE.zh-CN.md) 与 [docs/AUDIT-PLAYBOOK.md](docs/AUDIT-PLAYBOOK.md)。

## 安全与披露

VulnGate 面向经过授权的安全研究。

- 本地 PoC 副作用以回环（`127.0.0.1`）为默认边界。
- 非回环外联、监听、远程工具与 staging 动作均受策略控制并留痕。
- 显式授权 staging 必须使用主机白名单；公网监听和第三方目标仍不在范围内。
- staging 环境准备记录本身不等于漏洞证据。
- 发现文档只在本地生成，不会自动对外发布。
- 对外披露前应与维护者进行负责任协调。

本插件自身漏洞请按 [SECURITY.zh-CN.md](SECURITY.zh-CN.md) 报告。

## 开发与溯源

VulnGate 由 **xingchen20lj** 独立设计和维护，开发过程中使用 ChatGPT 与 Codex 进行 AI-assisted development。AI 工具作为实现和设计辅助；关键研究决策通过真实审计行为进行验证，并逐步固化为确定性规则与回归测试。

公开 Git 历史从 2026-08-09 的 VulnGate 0.1.0 开始。后续提交持续记录由实际审计暴露的问题，例如 Metabase 审计轮次经验、fix-completeness gate、spawn 诊断、patch variant analysis、Novelty 查询失败保留，以及 S4 evidence convergence/runtime isolation。

这条历史用于说明项目如何演化，并不主张 VulnGate 使用的所有广义思想都起源于本项目。详见 [PROVENANCE.md](PROVENANCE.md) 与 [CHANGELOG.md](CHANGELOG.md)。

## 相关工作

VulnGate 所处的是一个正在快速发展的研究方向。具有代表性的相关系统包括：

- Google Project Zero — **Project Naptime / Big Sleep**：使用专门工具与强验证原则进行 LLM 辅助漏洞研究。
- **MCPwner**：通过 deterministic PoC oracle 与持久化 findings ledger 支撑自主漏洞研究。
- **Prowl**：确定性 reconnaissance、LLM hypothesis/triage，以及针对真实构建/运行目标的 exploit validation。
- **Frame**：将 LLM reasoning 与 sound/static、symbolic analysis 结合。

列出这些工作是为了明确技术背景与重合边界，不代表项目等价。VulnGate 当前更强调跨越运行时效果、Novelty 查询完整性、前置条件、严重性一致性、修复完整性与可复现研究记录的**证据/结论生命周期治理**。

链接、时间、范围和对比说明见 [RELATED_WORK.md](RELATED_WORK.md)。

## 开发

- `scripts/smoke_test.sh` —— 环境与确定性助手冒烟测试
- `.codex-plugin/plugin.json` —— 插件清单
- `skills/vulngate-audit/SKILL.md` —— 宿主 Agent 执行契约
- `scripts/agent/` —— 捆绑的确定性框架
- `CHANGELOG.md` —— 版本化设计演进

本地迭代：

```bash
./install.sh && codex plugin add vulngate@personal
```

然后新建线程。详见 [CONTRIBUTING.zh-CN.md](CONTRIBUTING.zh-CN.md)。

## 许可

MIT —— 见 [LICENSE](LICENSE)。
