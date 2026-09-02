# VulnGate

> 面向任意代码库的 Codex 原生源码审计流水线——库、Web 框架、中间件、日志库、
> 表达式引擎、消息/RPC 栈与应用。

**语言：** [English](README.md) | 简体中文

VulnGate 把 Codex 智能体变成一套结构化的安全研究流程。给定任意代码库的源码与
运行环境——解析库、Web 框架（Spring/Struts）、中间件（Tomcat）、日志库
（Log4j）、表达式引擎、消息/RPC 栈或应用——它会依次推进八个研究阶段（S1–S8）
——从攻击面测绘到可上报的发现文档——
并强制五道证据硬闸门（G0–G5），确保每一条结论都经过运行时验证、过 Novelty
闸门、且可辩护。

推理由宿主 Codex 智能体负责；可重复的部分（PoC 矩阵执行、Novelty 扫描、CVSS
计算、账本落盘）由插件捆绑的确定性助手完成。

## 为什么用 VulnGate

人工审计解析库既慢又容易出错：入口靠猜，"看起来可达"被当成证据，漏掉一次
搜索就被当成新发现。VulnGate 把这些纪律固化成了硬闸门：

- **没有运行时证据，就不算确认。** 只有当 PoC 单元格产生了声称的效果（实例化、
  JNDI、OOM、网络标记）时，发现才算确认。
- **查询不完整，就不许声称 0day。** 若公开信息扫描失败或被限流，结论为
  `unknown-query-failed`，而不是 `candidate-0day`。
- **上游命中即降级。** 只要上游存在覆盖该机制的开 PR/issue 或公开披露，结论
  一律降级为"同族 + 增量清单"。
- **前置条件诚实的定级。** CVSS 向量必须与实际前置分级一致（默认配置 / 单
  Feature / 应用配合）。
- **天然并行。** 管线会派生子 Agent 并行跑 PoC 矩阵和上游检索，让宿主把精力
  花在判断证据上，而不是跑腿。S4 开工前先跑 spawn 探针：探针通过才逐候选并行，
  探针失败整轮自动降级宿主顺序执行并记录 degraded mode——通道问题开跑即暴露，
  不中途赌运气。

## 功能特性

- **宿主原生编排** —— 直接使用你在 Codex 中已配置的模型，无需额外 API Key。
- **八阶段、五闸门** —— S1 攻击面、S2 候选、S3 源码审计、S4 PoC 矩阵、
  S5 Novelty、S6 CVSS、S7 发现文档、S8 账本。
- **捆绑确定性 CLI** —— `agent_cli.py` 提供 `source-map`、`source-evidence`、
  `matrix`、`novelty`、`cvss`、`ledger`、`doctor` 子命令。
- **安全优先** —— JNDI/LDAP/HTTP 副作用仅限回环；非回环外发在编译前即被拒绝；
  在维护者协调完成前，发现文档只留在本地。
- **CLI 与桌面客户端都可用** —— 两者共用同一套插件市场与配置。

## 安装

### 前置要求

- Codex（CLI 或桌面客户端），支持插件的版本
- Python 3.8+
- JDK 8+（推荐 17/21），用于 PoC 编译
- `rg`（ripgrep），用于源码测绘

### 从本仓库安装

```bash
git clone https://github.com/xingchen20lj/vulngate.git
cd vulngate
./install.sh
```

`install.sh` 一步完成全部操作：把插件复制到 `~/plugins/vulngate`、注册个人市场、
并在 Codex 中启用（等价于 `codex plugin add vulngate@personal`）。脚本会自动查找
`codex` 命令——先找 `$PATH`，再找 Codex 桌面应用内置的 CLI。**如果你用的是桌面
应用，不需要单独安装 codex CLI。** 如果实在找不到 `codex`，脚本会明确告诉你
该执行什么命令。

> **必须新建线程。** 插件技能在线程启动时加载。安装后请打开一个新的 Codex
> 线程，`vulngate-audit` 技能才会生效。

### 需要本机 Codex 客户端吗？

需要。插件只能运行在本地 Codex 客户端上（桌面应用或 CLI），纯网页版
ChatGPT 无法加载本地插件。桌面应用自带 `codex` 可执行文件，装好应用即可。
如果只想用 CLI：

```bash
npm install -g @openai/codex
```

### 手动安装 / 从市场安装

```bash
codex plugin add vulngate@personal
```

### 常见问题：提示 `codex: command not found`

- 你装了桌面应用，但终端里找不到 `codex` —— 直接使用应用自带的二进制：
  - macOS：`/Applications/ChatGPT.app/Contents/Resources/codex`
  - Windows（Git Bash）：`"$LOCALAPPDATA/Programs/ChatGPT/Resources/codex"`
- 或者把它加入 `$PATH`，之后直接敲 `codex` 即可。
- `./install.sh` 已经替你做了这些查找；只有当自动检测失败时才需要手动执行
  上面的命令。

## 快速开始

1. 新建一个 Codex 线程。
2. 指向目标库：

   > 审计这个解析库，跑完整的 S1→S8 流程：`/path/to/library-src`

3. 宿主智能体会测绘攻击面、提出候选、审计源码、跑 PoC 矩阵（默认配置 ×
   安全开关 × 前置条件）、对照上游 issue/PR 与公开披露核验 Novelty，并产出
   一份可上报的发现文档。

如需用自己的 LLM API Key 无人值守运行：

```bash
./scripts/run_pipeline.sh --name <target> --target-dir <path> --round 1
```

完整走查见 [docs/QUICKSTART.zh-CN.md](docs/QUICKSTART.zh-CN.md)。

## 工作原理

| 阶段 | 做什么 | 输出 | 闸门 |
|---|---|---|---|
| S1 | 攻击面测绘（入口、危险调用点、默认配置、近期修复变体、项目价值画像、目标类型规则） | `S1/entry-inventory.json`、`S1/security-fix-history.json`、`S1/patch-variants.json`、`S1/project-profile.json`、`S1/target-rules.json`、`S1/composite-chain-hints.json` | G0 死代码、G1 可达性 |
| S2 | 候选矩阵（攻击面 × 入口 × 输入 × 逻辑） | `S2/candidate-matrix.json` | — |
| S3 | 对照真实源码审计（带 file:line 证据） | `S3/audit-notes.json` | G1b 默认配置门控 |
| S4 | PoC 矩阵：版本 × 安全开关 × 前置条件；Web/授权候选增加身份 × 角色 × 租户 × 对象 | `S4/matrix-runs/<c>/cells.json`、`S4/execution-status.json`、`S4/authz-matrix.json` | G4 运行时证据 |
| S5 | Novelty：上游 PR/issue + 公开披露扫描与覆盖记录 | `S5/novelty.json`、`S5/novelty-coverage.json` | G3 硬降级 |
| S6 | CVSS 计算 + 前置一致性校验 | `S6/severity.json` | G5 分级↔AC 一致 |
| S7 | 自包含发现文档（仅本地） | `reports/<target>/…` | 披露冻结 |
| S8 | 账本、已排除清单、轮次汇总 | `ledger/<target>/…` | — |

两种运行模式（宿主原生 / 自主 CLI）与证据契约详见
[docs/ARCHITECTURE.zh-CN.md](docs/ARCHITECTURE.zh-CN.md)。

按目标类型分类的攻击面清单（Web 框架、日志库、中间件、表达式引擎、协议栈、
通用库分别该看什么）见 [docs/AUDIT-PLAYBOOK.md](docs/AUDIT-PLAYBOOK.md)。

## 安全与披露

- PoC 副作用仅限回环（`127.0.0.1`）；矩阵运行器会拒绝编译含非回环 URL/IP 的
  源码。
- 默认模式下运行器硬拒绝非回环外联、SSH/SCP/远程部署、云厂商 CLI 和公网监听；明确授权
  自有 staging/ECS 时，可通过 `--authorized-staging --staging-host <主机>` 启用白名单模式。
  所有远程动作、策略拒绝与审批决定写入日志，第三方目标和 `0.0.0.0/0` 仍不允许。
- staging 环境准备可使用 `agent_cli.py staging-copy` / `staging-exec`；其输出只作为环境
  准备记录，不作为漏洞证据。
- 发现文档只在本地生成，维护者协调完成且修复公开之前，**不会**发布任何内容。
- 本插件自身的漏洞请按 [SECURITY.zh-CN.md](SECURITY.zh-CN.md) 报告。

## 开发

- `scripts/smoke_test.sh` —— 环境与确定性助手冒烟测试
- `.codex-plugin/plugin.json` —— 插件清单（名称、技能、界面）
- `skills/vulngate-audit/SKILL.md` —— 宿主智能体执行手册
- 框架代码位于 `scripts/agent/`（捆绑的 Python 包）

本地迭代：`./install.sh && codex plugin add vulngate@personal`，然后新建线程。
详见 [CONTRIBUTING.zh-CN.md](CONTRIBUTING.zh-CN.md)。

## 许可

MIT —— 见 [LICENSE](LICENSE)。
