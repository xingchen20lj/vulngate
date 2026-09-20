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
| 6 | 研究记忆与反馈学习 | 后续 | candidate/finding/negative-result 记忆、重复检测、跨轮 next probe | 不重复跑已证伪路径；新轮次能利用旧证据 |
| 7 | 专家级评测基准 | 后续 | 真实/合成案例集、变体集、误报/漏报指标 | 用证据质量、覆盖率、校准度衡量，而不是只看候选数量 |

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

这一步已经把“定向 fuzz 发现”与“可复现、可差分的研究证据”连接起来；下一步是把同一
套 fixture adapter 扩展到了普通 Java/Shell S4 候选：从既有 cell 的参数、前置条件、
授权元数据、有状态声明和能力契约生成稳定身份，但 artifact 只保存参数 digest，不落原始
参数或进程输出。普通 S4 也会复用隔离矩阵执行有限重放与版本 × SafeMode 对照，并把
`S4/runtime-lab.json` 关联回 `verification-matrix.json`；所有结果仍保持
`claim_status=not-a-finding`。下一步是跨轮研究记忆与固定服务生命周期的更细粒度适配。

## 后续优先级

1. 增加跨轮研究记忆和反馈学习，利用稳定负结果和差分结果减少重复实验。
2. 补充固定服务生命周期、配置快照和更细粒度的 authz/tenant fixture adapter。
3. 最后做评测基准，用负结果、重复率、证据完整度和严重性校准反向约束 Agent。

每一阶段都必须同时更新实现、技能契约、回归测试和 CHANGELOG；只有测试、artifact schema 和安全边界一起稳定后，才适合提交为一个独立变更。
