# VulnGate 研究能力升级路线图

目标不是让模型“更像专家”地生成更长的结论，而是把顶级渗透测试/代码审计中最有价值的能力固化为可重复的研究闭环：完整覆盖、攻击路径推理、可证伪实验、运行时证据、跨轮记忆和严格的结论校准。

## 不变的设计原则

1. 宿主 Agent 负责开放式推理、源码阅读和提出下一步假设。
2. 确定性组件负责边界、归一化、调度、实验契约、证据收集和结论闸门。
3. 静态命中、启发式 Source→Sink、模型判断和“计划中的观测”都不是漏洞结论。
4. 每个重要假设都要有：前置条件、正向观测、负向观测、明确证伪条件和可复现产物。
5. 任何一轮都不能因为“没有新候选”就停止；停止条件仍是覆盖账本和证据闸门满足要求。

## 阶段总览

| 阶段 | 能力目标 | 当前状态 | 主要产物 | 验收标准 |
|---|---|---|---|---|
| 0 | 证据内核与 G0/G1/G1b/G3/G4/G5 | 已完成 | S1–S8、typed effect、execution state、ledger | 结论不能超过真实观测强度 |
| 1 | 全源码覆盖、入口/危险 Sink、控制图、同族差分 | 已完成 | coverage、flow、control、differential、scheduler | 高风险未覆盖区域持续可见 |
| 2 | 复合攻击链和状态/竞态实验契约 | 已完成 | `chain-*`、`sequence`、`STEP/STATE`、可用性证据 | 声明并发不等于 A:H；每一步可追踪 |
| 3 | 可证伪实验规划器 | 本阶段已实现 | `S2/experiment-plans.json`、S3 计划上下文 | 每个候选有必需观测和 falsifier，且 `not-a-finding` |
| 4 | 能力原语与攻击路径图 | 已实现（含 S4 运行时契约） | `capability-graph.json`、`capability-candidates.json`、`capability_contract`、`CAPABILITY/TRANSITION` 证据 | 低危原语只有在链路、transition 和终点 typed effect 均有观测时才允许继续评估 |
| 5 | 运行时研究实验室与差分验证 | 已实现（定向 fuzz + 普通 S4） | `fuzz-corpus.json`、`FUZZ/runtime-lab.json`、`S4/runtime-lab.json`、版本/安全模式差分、缩减 reproducer | 固定输入可重复重放；差分、签名漂移与前置/harness 失败分开记录 |
| 6 | 研究记忆与反馈学习 | 已实现（上下文 + 可回放人工复核） | `state/<target>/research-memory.json`、`state/<target>/review-feedback.json`、`S8/research-memory.json`、`S8/review-feedback.json`、`S4/runtime-lab.json`、`S4/processes.json`、配置快照、authz fixture、修复变体提示 | 新轮次能利用旧证据；服务/配置/授权/修复上下文可复现；人工复核可回放；环境缺口不被当成负证据；重复实验只降权不删除 |
| 7 | 专家级评测基准 | 已实现（核心契约 + 确定性评分器） | `benchmarks/research-benchmark-v1.json`、`benchmarks/research-benchmark-sample-run.json`、`benchmark-result.json` | 同时衡量负向安全、环境缺口保真度、重复率、证据完整度、结论解析和严重性校准 |

## 当前阶段：可证伪实验规划

规划器从候选的可观察信号生成有界计划：

- baseline：入口可达性、默认/安全模式和负向基线；
- authorization-boundary：主体、租户、对象归属和最终 Sink 的绑定；
- state-sequence：步骤顺序、状态检查点和每一步证据；
- concurrency-availability：真实并发度、服务不可用探针和失败边界；
- fix-variant-comparison：修复前后及相邻变体的行为差异；
- typed-effect：只接受与声明影响匹配的 `EFFECT_KIND`/`EFFECT`。

规划器的输出是研究清单，不会生成 confirmed、0day 或严重性结论。S3 可以使用它选择下一步验证，G4/G5 仍只消费实际落盘的矩阵观测。

## 已实现阶段：能力原语与攻击路径图及 S4 运行时契约

现在先将候选拆成可验证的能力原语：输入控制、解析/变换、身份或租户边界、文件读写、网络请求、进程/命令执行、状态修改等；再沿 Source→Transform→Control→Sink 图搜索“能力组合”。S1 会把现有 entry/sink/flow index 转换为有界的 `capability-graph`，并把显式链方程生成到 S2 的候选池。

这一阶段的关键不是把所有低危点拼成 RCE，而是为每条链保存：

- 每个原语的来源、可信边界和证据类型；
- 链路中的必要条件与缺失条件；
- 可单步验证的中间观测；
- 终点效果所需的 typed evidence；
- 被打断时的最小下一步实验。

验收时至少覆盖：`read → leak`、`write → configuration/state change`、`ssrf → internal effect`、`exec → process/file marker`，并保留不能闭合的链作为 pending，而不是误报成高影响漏洞。图中的完整链也只会带 `claim_status=not-a-finding`、`requires_manual_dataflow=true`、`runtime_required=true`，再由现有实验规划器生成最小验证步骤。

能力链现在通过一个有界的 `capability_contract` 进入每个 S4 cell。运行器只把规范化后的
原语、缺失项和 transition 规则作为 PoC 的观察清单，并额外保存：

- `CAPABILITY=` / `CAPABILITY_EVIDENCE=`：实际观察到的能力原语及其安全证据；
- `TRANSITION=` / `TRANSITION_EVIDENCE=`：实际发生的相邻状态转换及其安全证据；
- `EFFECT_KIND=` / `EFFECT=`：需要时用于证明终点 typed effect。

汇总器将能力链标记为 `no-trace`、`partial` 或 `complete`，同时单独记录缺失原语、缺失
transition 证据和 typed effect 状态。`complete` 只表示该 cell 的声明观测清单已满足，仍
不是漏洞结论；所有能力链证据保持 `claim_status=not-a-finding`，环境失败和未观测不能
被解释为能力不存在。

## 阶段 5 初步实现：固定 fixture、重放与版本差分

现有定向 fuzz 不再只输出一批候选：每个生成输入会进入有界的
`FUZZ/fuzz-corpus.json`，由 `entry + group + payload` 生成稳定的 `fixture_id` 和内容
digest。触发器经 ddmin 后会形成独立的缩减 reproducer，原始输入与缩减输入的身份关系
都会保留。

对最多 16 个高价值 reproducer，runtime lab 会复用现有隔离矩阵执行：

- 在原始触发 cell 上重复重放，分类为 `stable`、`unstable`、`run-failed`、
  `precondition-unavailable` 或 `gate-blocked`；
- 在所有配置版本 × SafeMode cell 上执行一次，区分 bucket 变化、仅签名/栈漂移和
  不可比较的环境缺口；
- 将脱敏后的结果写入 `FUZZ/runtime-lab.json`，并在 `fuzz_spec.runtime_lab` 中留下
  artifact 引用；所有实验结果仍是 `claim_status=not-a-finding`。

这一步已经把“定向 fuzz 发现”与“可复现、可差分的研究证据”连接起来；同一套 fixture
adapter 也已扩展到普通 Java/Shell S4 候选：从既有 cell 的参数、前置条件、授权元数据、
有状态声明和能力契约生成稳定身份，但 artifact 只保存参数 digest，不落原始参数或进程输出。
普通 S4 会复用隔离矩阵执行有限重放与版本 × SafeMode 对照，并把 `S4/runtime-lab.json`
关联回 `verification-matrix.json`；所有结果仍保持 `claim_status=not-a-finding`。

本阶段进一步补上了固定服务生命周期和运行上下文快照。`runtime_lab.service` 只接受
workspace 内的 argv 命令，必须配置回环 healthcheck；健康实例可复用，VulnGate 自己启动的
完整进程组会在轮次结束回收，PID/端口状态写入 `S4/processes.json`。服务未就绪时，矩阵
明确记为 `precondition-unavailable`，不把环境失败当作漏洞不存在。`S4/runtime-lab.json`
同时保存脱敏的 `runtime-context-v1`：版本/目标 URL digest、有效 runtime-lab 选项、服务
配置 digest，以及跨 case rename 稳定的 `authz_fixture_id`，用于细粒度租户/对象对照。

## 阶段 6 初步实现：跨轮研究记忆与反馈调度

S8 现在会把本轮候选、稳定研究键和 runtime lab 的有界状态合并到目标级
`state/<target>/research-memory.json`，并在本轮目录留下
`S8/research-memory.json` 与汇总文件。研究键由入口、输入形状、机制、代码位置、目标类、
Source→Sink 摘要和能力契约 digest 组成，不依赖容易变化的 candidate id；原始参数、payload、
stdout/stderr 不写入跨轮记忆。

记忆只表达下一步研究优先级，不改变 G4/G5：

- `stable-reproducer` 表示固定 fixture 的重放与既有基线一致，提示转向授权边界、Source→Sink
  和 typed effect 证据；它不是漏洞确认。
- `actionable-difference` 表示版本或 SafeMode 出现可复核的 bucket 差异，调度器会轻微提高其
  后续最小复现实验优先级；差异仍需定位和验证。
- `environment-gap`、`unstable-replay` 和 `inconclusive` 保留为缺口/不确定性；尤其不能把
  harness、runtime 或前置条件失败解释为“漏洞不存在”。

下一轮 S2 调度会读取这份记忆：稳定观察会降低完全重复探针的分数，差异会提高后续验证优先级，
环境缺口保持原分数并在 prompt 中提示修复。候选不会被自动删除，所有记忆事件都标记
`claim_status=not-a-finding`，且合并操作具备幂等性。

本阶段还把 S4 的 `runtime-context-v1` 压缩为可安全复用的事件上下文：服务状态/配置 digest、
版本与目标 URL digest、运行选项、authz fixture ID、预期授权结果和修复变体提示都可在下一轮
被引用，而原始命令、参数、URL 查询、身份值和进程输出不会复制进研究记忆。人工复核通过：

```bash
python3 scripts/agent_cli.py review <target> --workspace <audit-dir> \
  --candidate-id <candidate-id> --status needs-evidence \
  --reason-code missing-typed-effect --note "补 typed effect" --round <N> --json
```

反馈以 `review-accepted`、`review-rejected`、`review-needs-evidence` 或
`review-scope-corrected` 事件保存到 `state/<target>/review-feedback.json`，并在 S8 快照到本轮
目录。它只影响排序和下一步提示：`rejected` 降低重复，`needs-evidence` 提高补证据优先级，
不能删除候选，也不能替代 G4/G5。

## 阶段 7 初步实现：专家级评测基准

新增 `research-benchmark-v1`，把“专家能力”拆成可以回归的研究质量指标。gold manifest 不保存
漏洞 PoC，而只声明 case 的 truth class、期望 claim status、必需证据字段、机制键和可选期望
严重性；run 记录只包含有界 status、证据字段标记、CVSS 和 research-key 事件。因此评测不会
把 payload、命令、stdout/stderr 复制进结果，也不会成为漏洞账本。

运行方式：

```bash
python3 scripts/agent_cli.py benchmark \
  --manifest benchmarks/research-benchmark-v1.json \
  --run benchmarks/research-benchmark-sample-run.json \
  --out state/benchmark-result.json --json
```

评分器固定输出以下维度：

- 观测覆盖率、期望 status 解析准确率、confirmed precision/recall；
- `unsafe_confirmation_rate`：negative case 被错误确认的比例；
- `environment_gap_fidelity`：不可执行/前置缺口是否保留为缺口，而非排除；
- `repeat_rate` 与 `unjustified_repeat_rate`：同一 research key 的重复，以及没有
  `new_evidence=true` 的重复；
- required/present evidence completeness；
- CVSS 平均绝对误差、1 分以内比例、ordinal error 和严重性夸大率；
- 多次独立 run 的 decision stability。

所有结果标记 `claim_status=not-a-finding`。评测只约束工程改进方向：负向安全、证据完整度或
严重性校准下降时，必须回到候选生成、实验计划、调度或结论规则修正，不能用调高阈值掩盖问题。

## 后续优先级

1. 将 benchmark 结果接入候选生成、实验计划和调度权重，形成可量化的持续改进闭环。
2. 扩展真实/合成变体集，覆盖更多 Web、协议、云、移动端和 native 研究面，同时保持负结果
   与环境缺口分离。

每一阶段都必须同时更新实现、技能契约、回归测试和 CHANGELOG；只有测试、artifact schema 和安全边界一起稳定后，才适合提交为一个独立变更。
