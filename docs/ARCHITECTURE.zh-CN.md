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

阶段 32 增加 `research-agenda-outcome-v1` 执行反馈闭环。S8 会在覆盖上一轮 agenda 前，按
`agenda_id`、`strategy_id`、`research_key` 和 `candidate_id` 精确关联实际 schedule、S4
`verification-matrix`、S4 `runtime-lab` 与 S8 strategy feedback，区分
`new-information`、`falsifier-observed`、`no-new-information`、`environment-gap`、
`not-executed` 和 `not-selected`。它只保存有界的信息增益、观测信号、执行状态、cell/fixture
计数和连续无增益计数，写入 target/round `research-agenda-outcomes.json`；下一轮 agenda 和
scheduler prompt 可据此提高环境恢复或低收益替换项的优先级。该反馈仍是
`claim_status=not-a-finding`，不能改变 candidate status、CVSS、G4 或 G5。可用：

```bash
python3 scripts/agent_cli.py research-agenda-outcomes <target> \
  --workspace <audit-dir> [--round N] [--rebuild] [--json]
```

阶段 33 增加 `research-budget-v1` 结果自适应预算策略。S8 将上一轮 agenda 与归一化
outcome 按 research surface 汇总，计算 selected 数、information gain、estimated cost、
environment gap 和 no-information repeat，只产生有界的
`recover-environment`、`exploit-high-yield`、`explore-undercovered`、`continue-balanced` 或
`cooldown-low-yield` 策略码。下一轮 agenda 消费 surface priority delta 与 cap hint，并保留
探索下限；低收益研究面只降温、不删除，环境缺口也绝不会被当成负向安全证据。

S8 写入 target/round `research-budget.json`，replay pack 会在产物存在时记录可选 provenance。
可用下面命令检查或重建：

```bash
python3 scripts/agent_cli.py research-budget <target> \
  --workspace <audit-dir> [--round N] [--rebuild] [--slots N] [--json]
```

budget、agenda hint 和 scheduler evidence 仍是 `claim_status=not-a-finding`，不能确认漏洞、
改变 candidate status、CVSS、G4 或 G5。

S1 中包含授权边界和危险 Sink 的启发式 Source→Sink 路径会写入
`composite-chain-candidates.json`，并在 S2 进入与模型候选、控制图候选、同族差分候选相同的调度池。它们始终保留
`heuristic-nearby` / `requires_manual_dataflow=true`，只能作为审计和 PoC
验证任务，不能直接升级为漏洞结论。

## 语义路径证据层

控制图只能证明控制出现在启发式路径上，不能证明它在 sink 之前、处于同一分支或绑定了正确主体。语义路径层在此基础上增加
`semantic-path-evidence-v1`：记录 `before-sink`、`after-sink`、`same-line`、`cross-symbol-unverified` 控制关系及有限的
brace/indent 语义块关系；当入口与 sink 位于同一符号时，再对参数和简单别名做 `direct` / `propagated` / `not-traced`
追踪，跨符号则明确记为 `cross-symbol-unresolved`。

该层不是编译器或严格证明器，不建模 branch dominance、类型、virtual dispatch、DI、reflection、callback 与 sanitizer
语义；不复制源码原文，所有记录保持 `claim_status=not-a-finding`，候选携带 `requires_manual_dataflow=true`，只能用于
S2 排序和 S3/S4 的下一步验证。产物为 `state/<target>/coverage/semantic-path-evidence.json` 与
`semantic-path-candidates.json`，可用 `python3 scripts/agent_cli.py semantic-paths <target> --workspace <audit-dir> --json`
查看。

在此之上，`semantic-guard-evidence-v1` 增加两个有限的专家复核信号：分支姿态
（`terminating-guard-likely`、`nested-branch-likely`、`non-branch-check` 或 unresolved）以及
subject/object 绑定（`overlap`、`mismatch` 或 unresolved）。例如权限检查看起来检查了一个
标识符，而 sink 实际操作另一个对象时，`mismatch` 可帮助优先安排人工追踪；但它绝不是授权绕过
证明。该层仍是词法启发式，不证明 branch dominance、路径可达性、对象/租户身份或返回/异常语义，
只保存有限 token 和位置；`semantic-guard-candidates.json` 只是确定性的 S2 研究线索，所有行都保持
`not-a-finding` 与 `requires_manual_dataflow=true`。

```bash
python3 scripts/agent_cli.py semantic-guards <target> \
  --workspace <audit-dir> --show-candidates --json
```

`semantic-call-evidence-v1` 补上语义路径/守卫层主动保留的跨符号缺口：对 flow 上每条
call edge 记录调用点、实参到形参的绑定、被污染的 callee 参数和返回形状提示，再比较这些
有限标识符是否到达 sink 参数。`bound` 只是帮助安排下一步追踪的静态证据，`not-bound` 和
`unresolved` 仍是人工复核线索，不是安全结论。该层不解析 overload、virtual dispatch、DI、
reflection、callback、async、类型转换、变换语义、分支支配或路径可行性，也不保存源码原文；
`semantic-call-candidates.json` 保持 `not-a-finding` 与 `requires_manual_dataflow=true`。

在已选定的 bounded flow path 内，该层现在继续传播多条调用边，并识别有限的
`parameter -> local alias -> return` 形状，例如 `local = value; return local`。返回记录同时保留
返回别名以及调用点是 `returned` 还是 `assigned`；变换、容器、属性写入和未解析 dispatch 不会被猜成
别名。每条记录都有 call depth、节点数、路径数和 wall-clock budget；预算耗尽会写入
`analysis_gaps`，不能被解释为无数据流或安全。该层仍是 `heuristic-nearby` / `not-a-finding`，不满足
S4/G4/G5。

```bash
python3 scripts/agent_cli.py semantic-calls <target> \
  --workspace <audit-dir> --show-candidates --json
```

`semantic-controlflow-evidence-v1` 在守卫证据之上增加有界的结构化关系层：按 brace/indent 分支区间记录 sink 是否看起来位于受保护分支、终止拒绝分支之后，或位于 `else`/`except` 备用路径。`dominates-likely` 只是确定性的人工复核信号；该层不执行完整 CFG，也不建模循环、短路、异常、fallthrough、宏或路径可行性。行和 `cfg-*` 候选保持 `not-a-finding` 与 `requires_manual_dataflow=true`。

```bash
python3 scripts/agent_cli.py semantic-controlflow <target> \
  --workspace <audit-dir> --show-candidates --json
```

`semantic-ast-evidence-v1` 是 Python 目标的语法感知补充层：每个有界 Python 文件只解析一次，记录
分支归属、函数/类作用域、负向条件形状、直接终止语句、`else`/异常备用路径和解析失败。它把反复的
行号区间猜测替换为可引用的 AST 结构见证，但仍不声称完整 CFG、dominance/SSA、类型或运行时证明。
不支持的语言和语法错误会作为明确缺口保留；`semantic-ast-candidates.json` 只包含
`not-a-finding`、`requires_manual_dataflow=true` 的研究线索，不保存源码原文或 AST dump。

```bash
python3 scripts/agent_cli.py semantic-ast <target> \
  --workspace <audit-dir> --show-candidates --json
```

`semantic-transform-evidence-v1` 对校验/清洗控制调用到 sink 消费值做有界绑定追踪，区分结果已经赋值并使用、
校验结果被丢弃、变换后的变量被原始值覆盖以及跨符号未解析。它只是帮助选择下一步源码/运行时追踪的静态
证据，不推断 API 语义、类型、SSA、完整别名、框架过滤器或安全性；记录和
`semantic-transform-candidates.json` 始终是 `not-a-finding` 研究线索。

```bash
python3 scripts/agent_cli.py semantic-transforms <target> \
  --workspace <audit-dir> --show-candidates --json
```

`semantic-python-binding-evidence-v1` 是下一层语言感知适配器：对 Python 文件只解析一次有界 AST，探索简单赋值、
别名、守卫、异常处理以及有限分支/循环路径，记录变换后的值是否绑定到 sink、sink 是否仍使用原始值、路径是否
合并，或表达式是否未解析。Java、Go、JavaScript 等未实现适配器的语言会明确记录 adapter gap，不会被当成安全。
它仍然是抽象语法见证，不是完整 CFG/SSA/类型/运行时证明；记录和
`semantic-python-binding-candidates.json` 始终保持 `claim_status=not-a-finding` 与
`requires_manual_dataflow=true`。

```bash
python3 scripts/agent_cli.py semantic-bindings <target> \
  --workspace <audit-dir> --show-candidates --json
```

## 统一语法前端：先接入 Python

`SemanticFrontend` 提供 `parse`、`symbols`、`calls`、`assignments`、`branches`、
`returns`、`parameters` 和 `arguments`。Python 后端使用标准库 AST，在本地解析，
不导入或执行目标代码。语法事实包含绑定源码的 ID、位置和词法作用域；调用仍标记
`dispatch=unresolved`，不代表已解析类型、数据流边或 CFG。

每次 inventory 构建使用一份按内容摘要缓存的 session，供 Python 符号提取、AST
分支见证和值绑定分析复用。不增加新产物：`symbol-index.json` 保存 `parser`、
`parse_status`、`source_revision`、`analysis_gaps` 和 `claim_status`；现有语义
记录携带相同源码版本。`inventory-summary.json` 的 `counts.semantic_frontend`
记录文件、LOC、解析请求、缓存命中/淘汰、节点、读取字节和解析缺口，与已有
符号/边/flow/path 数及耗时一起使用。升级后用 `coverage --rebuild` 重建旧索引。

预算为每文件 2,000,000 字节、100,000 AST 节点、深度 128。共享 LRU 最多保留
8 个文件和 200,000 节点，各消费者的派生索引也最多保留 8 个文件；淘汰后可重解析。
内容摘要能识别大小和 mtime 不变的修改；符号 AST 版本与溯源构建读到的源码哈希
不同时，明确标记版本不一致缺口，但不声称原子快照。超大文件的截断前缀不冒充完整文件版本。
语法、解码、读取和预算失败均为明确缺口，Python 符号可回退为带标记的低置信度
regex。Java/JS/TS/Go 仍为 regex fallback，尚未完成对应 AST 适配器。

Python 声明范围包含装饰器，保留多行参数和嵌套作用域，不把字符串中的伪定义当成
符号。重复限定名使用出现位置后缀并标记 `duplicate-definition`，不静默合并身份。
AST 符号的置信度只描述语法；调用图和语义解释仍是启发式及 `not-a-finding`。
此阶段不解析动态查找、变更、装饰器、导入或完整跨过程语义，不改变 S4/G4/G5。

## 证据溯源与相关性

各个静态语义层现在共享确定性的 `evidence-provenance-v1` 产物：
`state/<target>/coverage/evidence-provenance.json`。它把入口、sink、控制、
符号等原始事实连接到 flow，再连接到语义路径、调用、守卫、控制流、AST、
变换和 Python 值绑定记录。每条记录包含 `evidence_id`、
`source_fact_ids`、`parent_evidence_ids`、`independence_group`、`file`、
`line` 和可选 `span`，不会复制源码原文。

静态候选池复用同一份关联关系。一个候选可以保留多个派生证据 id，但调度器
只统计不同的 independence group，不会把同一条语义流的多层重复解释当成多份
独立证据。重复降权还要求溯源完整、同一控制和类别，以及已知相同验证问题
（变换/值绑定、分支/CFG/AST、主体绑定）。不同或未知问题不会仅因同流或同位置
被一起降权，研究线索不会删除。该机制只是溯源和调度元数据：所有记录仍是 `claim_status=not-a-finding`，
不能升级结论，也不能覆盖 S4/G4/G5。

ID 绑定完整 payload 摘要和源码文件 SHA-256。嵌套的控制/守卫/变换/调用/污点
记录保留具体上游关系，通过 `artifact_row_digest` 和 `artifact_field` 定位原产物。
文件、原始事实、上游记录缺失及尚未建模的非语义候选来源都记为 `provenance_gaps`，
不虚构独立证据。溯源完整不等于语义完整，更不等于漏洞成立。每次构建每个文件
只读一次，限制为每文件 8 MiB、总计 64 MiB，超限明确记缺口。同源候选名单每组
只存一份，避免逐候选复制带来的平方级膨胀。跨分析层不是原子快照，源码变化后
须用 `--rebuild` 重建。配置式/自主式 S1 和原生命令行调度复用同一索引。

```bash
python3 scripts/agent_cli.py evidence-provenance <target> \
  --workspace <audit-dir> --root <source-dir> --rebuild --json --limit 20
```

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
