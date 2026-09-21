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

S8 会把这些 witness 汇聚为 project portfolio 内的 `surface-variant-coverage-v1`。它按研究面、变体和 lane
同时保留历史信号/状态计数与最新状态，包括 state-sequence、typed-effect、safe-equivalent 和 environment-gap
覆盖。只有最新状态确实为 observed 的 lane 才视为闭合；partial、not-executed 和 environment-gap 会生成绑定精确
research key 的有界 next probe。调度器可以用它优先补缺失实验，但该视图始终是 `claim_status=not-a-finding`，不能改变
candidate conclusion、CVSS 或 G4/G5。

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

为了让“真实项目回放”可审计而不只是可复制，S8 还会生成
`research-replay-pack-v1`。也可以单独运行：

```bash
python3 scripts/agent_cli.py replay-pack <target> \
  --workspace <audit-dir> --json
```

pack 只扫描 allowlist 内的 workspace-local 轮次/目标 artifact，保存相对名称、schema version、大小、SHA-256
指纹和有界的每轮 lane/comparison 摘要；不会保存源码、payload、命令、stdout/stderr、凭据或漏洞结论。它区分
complete、partial、environment-gap、not-executed 和 invalid，并校验 pack 内 calibration 与轮次历史的 digest
一致性；本地 `verify_replay_pack` 可以在之后重新哈希核验。只有来源完整且自洽的 pack 才有资格进入 cohort。

当多个独立目标都积累了这类有界 artifact 后，操作者可以显式汇聚为
`research-replay-cohort-v1`：

```bash
python3 scripts/agent_cli.py replay-cohort-calibrate \
  --pack /path/to/project-a/research-replay-pack.json \
  --pack /path/to/project-b/research-replay-pack.json \
  --pack /path/to/project-c/research-replay-pack.json \
  --out state/research-replay-cohort.json --json
```

cohort 会从不透明的 project row 重新计算策略，并保留按研究面的样本充分性；pack 输入必须拥有完整且 digest 自洽的 provenance，缺失或不一致的 pack 会被拒绝，不会成为策略样本。旧的 `--artifact` 仍为兼容入口，但会与 pack provenance 分开统计。只有至少三个不同项目都有足够回放历史，且项目级低收益信号一致时，才会启用已有的两轮 zero-gain replacement threshold。项目数不足时保持默认，并生成 `collect-more-projects` 建议。目标可以显式设置 `replay_cohort_calibration_path`；目标本地校准优先，cohort 不会被隐式发现。管线只保存有界研究元数据，不会复制输入路径、原始回放数据或目标漏洞证据，也不会改变 candidate status、CVSS、G4 或 G5。

### 跨轮证据一致性

S8 还会从有界、归一化的 `research-memory` 事件生成 `research-consistency-v1`。它只比较同一 research key 的固定状态分类：effect 是否出现、是否可复现、comparison 结果、运行状态和 context digest，并区分 `conflicted`、`unstable`、`insufficient`、`environment-gap` 与 `consistent`。独立命令为：

```bash
python3 scripts/agent_cli.py research-consistency <target> \
  --workspace <audit-dir> --json
```

它是矛盾检测器，不是漏洞检测器：环境缺口不会被算作“无 effect”，每条记录保持 `claim_status=not-a-finding`。portfolio 和 strategy 只用它安排受控复核；S8 同时写入 target/round artifact，replay pack 也会覆盖这些 provenance。

阶段 29 将矛盾动作具体化为 `research-consistency-action-v1`。S8 为每个非一致条目生成固定的隔离轴、正/负向或环境缺口 lane、两次独立重复形状、required observation code 和 falsifier code。可用下面命令查看或重建：

```bash
python3 scripts/agent_cli.py research-consistency-actions <target> \
  --workspace <audit-dir> --json
```

S2 按稳定 `research_key` 匹配 action，生成 `consistency-recheck` 计划；S4 将归一化契约传入 MatrixCell、`VULNGATE_CONSISTENCY_ACTION`、普通 runtime-lab fixture 以及 replay/differential cell。它仍只是检查清单，不是观测：缺少独立重放、fixture/context 不一致、状态未重置或只有签名漂移时，研究项继续保持 pending。action、portfolio、strategy 和 replay pack 都保持 `claim_status=not-a-finding`，不能改变 candidate status、CVSS、G4 或 G5。

阶段 30 增加 `research-consistency-recheck-v1` 执行闭合。S4 按 action 的
`matrix_shape` 真正展开 positive/negative 或 environment-gap lane，并通过
`VULNGATE_CONSISTENCY_LANE` 把有界 lane 选择器交给 PoC；每个 lane 使用独立
fixture identity，但保留相同的基础 context digest。runner row 在内存中时只提取
执行/环境状态、独立 replay 次数、typed-effect/safe-equivalent、显式 state reset、
comparison arm 和 fixture/context identity，不能把 raw stdout/stderr、命令、payload、
凭据或 source prose 写进 closure artifact。

S8 使用上一轮 pending action 与本轮 `S4/runtime-lab.json` 生成
`research-consistency-rechecks.json`，严格区分 `observed`、`partial`、
`environment-gap` 和 `not-executed`。只有预期 lane、重复次数、fixture/context 锁、
comparison 和 required observations 全部实际闭合时才停止该条目的重复调度；否则
portfolio 继续给出 bounded probe。可用下面命令检查：

```bash
python3 scripts/agent_cli.py research-consistency-rechecks <target> \
  --workspace <audit-dir> --json
```

该 closure 仍是 `not-a-finding` 研究元数据，不确认漏洞、不降低环境缺口，也不能改变
candidate status、CVSS、G4 或 G5。

阶段 31 增加 `research-agenda-v1` 主动研究议程。它只消费归一化的 strategy 与 portfolio
复核状态，把开放研究项转换为有限的 `selected`、`deferred`、`hold` 队列，并记录
`expected_information_gain`、`estimated_cost`、`prerequisites`、surface diversity 和 bounded
priority score。有限预算先覆盖不同研究面/攻击类别，再用剩余 slots 选择高信息增益项；环境
修复、residual、人工复核和一致性证据债务只影响调度，不是漏洞证据。S8 写入 target/round
`research-agenda.json`，可用：

```bash
python3 scripts/agent_cli.py research-agenda <target> \
  --workspace <audit-dir> [--rebuild] [--slots N] [--max-per-surface N] [--json]
```

下一轮 scheduler 只接受 candidate 与 agenda 的精确 `research_key` 或 `candidate_id` 匹配，
使用有界 boost 并在 schedule evidence 中保留匹配状态；agenda、schedule signal 和 replay pack
仍是 `claim_status=not-a-finding`，不能改变 candidate status、CVSS、G4 或 G5。

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
