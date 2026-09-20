# 架构说明

> Codex 1.1.0 新增：覆盖率、调用图、控制缺口、同族差分、候选调度与 macOS 适配。见 [功能演进与命令说明](EVOLUTION.md)。审计产物使用独立 `--workspace`。

**语言：** [English](ARCHITECTURE.md) | 简体中文

VulnGate 是一个围绕确定性研究框架的轻量原生插件。设计原则：
**宿主 Codex 智能体负责决策；捆绑代码负责计算。**

## 组件

```
┌─────────────────────────────────────────────────────────────┐
│ Codex（CLI 或桌面客户端）                                    │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ 宿主智能体（主 Agent）                                 │  │
│  │  · 负责推理：候选、审计、结论判定                      │  │
│  │  · 负责并行：派生子 Agent（S4/S5）                     │  │
│  └───────────────┬───────────────────────────────────────┘  │
│                  │ 技能：vulngate-audit（SKILL.md）         │
└──────────────────┼─────────────────────────────────────────┘
                   ▼
        捆绑的确定性 CLI（scripts/）
        · agent_cli.py：source-map / source-evidence / matrix /
          novelty / cvss / ledger / doctor
        · scripts/agent/：框架（闸门、运行器、novelty、cvss）
```

## 技能即契约

`skills/vulngate-audit/SKILL.md` 是交给宿主智能体的执行手册，它定义了：

- S1→S8 阶段顺序及各阶段产物；
- G0–G5 硬闸门以及每一道闸门拦截什么；
- 证据契约（由机器可读的观测行驱动结论）；
- 安全模型（仅回环、审批日志、修复前不披露）；
- 前置分级 → CVSS 映射。

S8 还会生成有界的 `research-strategy-guidance-v1` 视图，只汇合策略观测元数据、最新人工复核状态
和显式变体覆盖率，并映射为有限的下一步动作类别。它可以调整研究调度或建议替换零信息增益的实验，
但绝不是证据、漏洞结论、CVSS 输入，也不能覆盖 G4/G5。

S2 复用同一份行动上下文生成 `surface-variant-plan-v1`。计划按 Web、协议、云、移动端和 native
分别选择状态机、身份边界、生命周期、路由、解析器或方法体变体；每个变体始终对称地包含正向、
负向/安全等价和环境缺口三条车道。车道只是观测要求与证伪条件，不是已经执行的观测，完整计划也
不能暗示任一车道已经执行。

S4 runtime lab 会在配置的 fixture 预算内把规范化计划展开为
`surface-variant-fixture-v1`。每个上下文包含不透明的 fixture key、固定的状态步骤序列和一条车道；S4
复制基础 cell，只向 PoC 暴露有界的 `VULNGATE_VARIANT_*` 环境变量，并把车道上下文与脱敏后的重放/差分摘要
一起落盘。预算不足时 artifact 会显式记录截断。environment-gap 仍只是“需要观察缺口”的要求；runner 失败、
前置条件缺失和安全等价行为仍按不同的真实运行结果处理。

S4 还会从真实 replay/differential runner row 生成 `surface-variant-evidence-v1`。它只保留有界的固定信号分类和
状态步骤身份，将每条 lane 区分为 `observed`、`partial`、`environment-gap` 或 `not-executed`。计划声明不是 witness：
只有完整的实际 STEP trace 才能满足 `state-sequence`，typed-effect 与 safe-equivalent 仍是独立信号。S8 与 S2 会复用
这份有界 witness 选择下一步探针，但它始终保持 `claim_status=not-a-finding`；原始输出、effect 细节、payload、命令和
凭据不会进入 artifact，也不会改变任何闸门、CVSS 或 candidate conclusion。

对于存在多个配置版本或修复元数据的候选，S2 还会生成
`comparison-orchestration-v1`。S4 将比较绑定到同一个 fixture 和 lane，并把真实配对 cell 分类为 bucket
变化、仅签名漂移、相同观测或 inconclusive；如果没有操作者提供的构建产物，源码 revision 和同族路径会明确
保持未执行。补丁引用不是运行时结果；旧版本或修复版本缺失时是环境缺口，而不是“修复有效”的证据。

操作者可以显式提供 workspace 内的历史构建产物来补齐 source-revision build gap：

```json
{
  "source_revision_artifacts": {
    "enabled": true,
    "arms": [
      {"role": "before", "ref": "<commit-sha>", "jars": ["build/before.jar"]},
      {"role": "after", "ref": "<commit-sha>", "jars": ["build/after.jar"]}
    ]
  }
}
```

适配器只接受与 comparison contract 精确匹配、位于 workspace 内且类型受限的 JAR/WAR/ZIP，先做大小/路径
校验和指纹，再复用同一 fixture/lane 的隔离 Java runner。它不会 checkout、调用构建命令或使用远程产物；缺失、
损坏、非 Java 或 ref 不匹配仍记录为 `precondition-unavailable`/`inconclusive`。真实 source arm 观测仍是
`claim_status=not-a-finding` 的研究元数据，不能单独满足 G4/G5。

S8 还会从目标的有界轮次快照生成 `research-replay-calibration-v1`。它测量替换动作是否带来新信息、环境
缺口是否恢复，以及 fixture 预算或 comparison arm 是否造成覆盖不完整。只有至少三条匹配回放时，结果才可
将后续 guidance 的零增益阈值在一轮与两轮之间选择；样本不足时保持默认值。校准产物不包含原始 payload、命令、
输出、凭据或漏洞证据，只影响 S2/S8 的研究调度。

S1 中包含授权边界和危险 Sink 的启发式 Source→Sink 路径会写入
`composite-chain-candidates.json`，并在 S2 进入与模型候选、控制图候选、同族差分候选相同的调度池。它们始终保留
`heuristic-nearby` / `requires_manual_dataflow=true`，只能作为审计和 PoC
验证任务，不能直接升级为漏洞结论。

## 两种运行模式

| 模式 | 推理方 | 配置 | 典型用途 |
|---|---|---|---|
| A — 宿主原生 | 你在 Codex 中已配置的模型 | 无 | 交互式审计、PoC 验证、Novelty 核验 |
| B — 自主 | 通过 `run_pipeline.sh` 调用 LLM API | `DEEPSEEK_API_KEY` / `OPENAI_API_KEY` | 无人值守的多轮扫描 |

模式 A 是默认模式，不需要 API Key，因为宿主智能体本身就是 LLM。模式 B 用于
脚本化、无人值守的运行。

## 证据契约

PoC 必须输出机器可读的观测行，例如：

```text
INSTANTIATED=com.sun.rowset.JdbcRowSetImpl
ERROR=java.lang.OutOfMemoryError
GATE_BLOCKED=com.example.Target
NETWORK=ldap://127.0.0.1:389/...
PARSED=true
```

运行器只依据这些行推导事实：

- `INSTANTIATED` 必须是完整类名——单纯的 `true` 不能作为目标类被实例化的证据；
- `ERROR` 区分库行为（`JSONException`、OOM、`StackOverflowError`）与环境错误
  （`ENV_ERROR` 族：`NoClassDefFoundError` 等）；
- 编译失败的单元格属于 harness 问题，不算结论。
- 有状态/竞态候选可以声明有界 `sequence × concurrency × availability_probe`；运行器会保留
  `STEP`、`STEP_EVIDENCE`、`STATE` 的有序 trace，但声明本身不构成漏洞或 `A:H` 证据。

## 闸门

| 闸门 | 拦截什么 |
|---|---|
| G0 | 把死代码判定为可达 |
| G1 | 审计无法从不信任输入到达的入口 |
| G1b | 把非默认 Feature 路径当作默认可达 |
| G3 | 上游有任何 PR/issue/披露命中仍声称 0day |
| G4 | 没有运行时 PoC 证据就确认发现 |
| G5 | CVSS 的 `AC` 与前置分级矛盾 |

## 安全边界

- 矩阵运行器在编译前扫描 PoC 源码，拒绝含非回环 URL/IP 的代码；
- 审批与拒绝均追加写入 `state/<target>/round-NN/approval-log.jsonl`；
- 任何阶段都不会对外发布；S7 只把报告写入本地工作区。
