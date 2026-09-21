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
| 8 | 评测驱动的自适应研究闭环 | 已实现（有界反馈接入） | `research-benchmark-feedback-v1`、调度权重快照、`benchmark-guidance` 实验提示 | 评测指标只能改变下一轮研究优先级和必需观测；默认行为可回归，且不改变 G4/G5/CVSS |
| 9 | 跨攻击面变体基准 | 已实现（五类研究面 + 三态契约） | `benchmarks/research-benchmark-surfaces-v1.json`、`benchmarks/research-benchmark-surfaces-sample-run.json`、`research_profile`、`coverage_by_surface` | Web、协议、云、移动端、native 均覆盖 vulnerable/negative/environment-gap；环境缺口不被误判为负向，结果保持 `not-a-finding` |
| 10 | 研究面级自适应调度与规划 | 已实现（有界 surface guidance） | `surface_guidance`、候选级面向证据调度、面级 `benchmark_guidance` | 只对显式匹配研究面的候选加小幅优先级；计划补观测/证伪条件；默认无反馈行为不变，不改变 G4/G5/CVSS |
| 11 | 纵向评测退化检测 | 已实现（bounded trend comparison） | `research-benchmark-trend-v1`、`--baseline`、趋势反馈 | 跨轮只比较固定聚合指标；全局/研究面退化进入有界 guidance；不复制 case、运行时输出或结论 |
| 12 | 项目级研究组合与变体覆盖 | 已实现（bounded research portfolio） | `research-portfolio-v1`、`state/<target>/research-portfolio.json`、S8 组合视图 | 能按研究面/攻击类别/变体/前置条件汇总已观测状态，输出有界 next probes；不把组合统计升级为漏洞结论 |
| 13 | 攻击路径威胁模型与信任边界 | 已实现（bounded attacker-path model） | `threat-model-v1`、`state/<target>/coverage/threat-model.json`、`S1/threat-model.json`、威胁模型 CLI/调度 prompt | 入口、边界、flow、sink、控制姿态、未解析区域和能力链保持可追溯；所有路径仍是 `not-a-finding` |
| 14 | S3 residual 跨轮闭环 | 已实现（bounded residual continuity） | `research-memory-v1` residual metadata、`pending-residual` portfolio probes、调度 prompt | residual 不因主 replay 稳定而消失；只保留受控分类、位置、摘要哈希和计划存在性；不复制原始 probe，也不升级为漏洞结论 |
| 15 | 跨产物证据驱动研究策略 | 已实现（bounded research strategy synthesis） | `research-strategy-v1`、`state/<target>/coverage/research-strategy.json`、`S2/research-strategy.json`、策略 CLI/调度证据 | 威胁路径、coverage gap、residual、跨轮状态和 benchmark 上下文汇聚为带 required observations/falsifiers 的有界议程；策略不能替代 G4/G5 |
| 16 | Residual falsifier 闭合 | 已实现（contract-bound S4 closure） | `S2/experiment-plans.json` residual contracts、`S4/residual-closure.json`、`research-memory-v1` 的 `residual-falsified` | 只有声明过的 residual contract、匹配 ID、显式 allowlisted falsifier、成功执行且无副作用的 cell 才能闭合；环境失败、门控和实际 effect 保持 pending，且不改变 G4/G5 |
| 17 | 策略项真实观测回写与信息增益 | 已实现（bounded S4 strategy feedback） | `research-strategy-feedback-v1`、`S8/research-strategy.json`、`S8/research-strategy-feedback.json`、下一轮策略提示/调度证据 | 只用真实 S4 summary 的有界信号更新匹配策略项；记录缺失观测、最新/历史状态和本轮信息增益；重复且无新信号时取消策略加分，不改变候选、CVSS 或 G4/G5 |
| 18 | 跨轮研究行动与实验替换建议 | 已实现（bounded strategy action guidance） | `research-strategy-guidance-v1`、`state/<target>/coverage/research-guidance.json`、`S8/research-guidance.json`、策略项 `next_action` | 将 S4 观测、人工复核和显式变体覆盖汇合为有限动作；环境缺口优先修复，负向/能力/typed effect 缺口转成定向补证，零信息重复建议换实验；只影响研究调度，不改变候选、CVSS 或 G4/G5 |
| 19 | 研究面专用变体与三车道实验计划 | 已实现（bounded surface variant matrix） | `surface-variant-plan-v1`、`S2/experiment-plans.json`、`S2/candidate-matrix.json`、策略 guidance 中的 `surface_variant_plan` | Web/协议/云/移动/native 按各自状态机、身份边界、生命周期或方法体验证选择变体；每个变体同时保留正向、负向/安全等价、环境缺口车道；计划不等于执行，不改变 G4/G5 |
| 20 | 研究面 fixture 与状态机执行上下文 | 已实现（bounded S4 lane expansion） | `surface-variant-fixture-v1`、`VULNGATE_VARIANT_*`、`S4/runtime-lab.json` lane context | 在 fixture 预算内把每个选中变体展开为三车道 runner cell，向 PoC 提供固定状态步骤和脱敏 lane 元数据；显式记录预算截断；车道仍不是观测，不改变 G4/G5/CVSS |
| 21 | 跨版本与修复变体自动对照编排 | 已实现（bounded comparison orchestration） | `comparison-orchestration-v1`、S2 comparison contract、S4 `comparison` summaries | 将配置版本对、只读 patch parent/fixed 引用和同族变体提示绑定到同一 fixture/lane；区分 bucket 变化、签名漂移、环境缺口和未执行 arm；差异仍不是漏洞结论 |
| 22 | 真实项目回放校准与替换阈值 | 已实现（bounded replay calibration） | `research-replay-calibration-v1`、`state/<target>/coverage/research-replay-calibration.json`、`S8/research-replay-calibration.json`、`replay-calibrate` CLI | 只从有界 guidance/feedback/runtime-lab 快照计算替换命中率、环境恢复、fixture 截断和 comparison gap；样本不足保持默认，样本充分时阈值最多为 1/2 轮；不改变候选、CVSS、G4/G5 |
| 23 | 受控历史构建产物与 source-revision arm 执行 | 已实现（bounded artifact adapter） | `source-revision-artifacts-v1`、`source_revision_artifacts`、S4 source arm records/comparison、S8 research memory | 操作者显式提供 workspace 内匹配 commit ref 的 JAR/WAR/ZIP；校验路径、大小、类型和 digest 后复用隔离 Java runner；不 checkout/构建/远程执行；缺失或损坏产物保持 environment gap/inconclusive，不改变 G4/G5/CVSS |
| 24 | Surface lane 的真实观测见证 | 已实现（bounded lane witness） | `surface-variant-evidence-v1`、S4 lane evidence、S8/S2 bounded signals | 只从真实 runner row 提取 observed/partial/environment-gap/not-executed、state sequence 和 typed effect 信号；计划不等于观测，不改变 G4/G5/CVSS |
| 25 | 跨轮研究面 lane coverage 与闭环调度 | 已实现（bounded surface coverage view） | `surface-variant-coverage-v1`、`research-portfolio-v1.surface_lane_coverage`、lane-specific `next_probes` | 跨轮合并历史/最新 lane 状态，保留信号、序列状态、环境缺口和 research key；未闭合 lane 生成精确下一步 probe，仍不升级为漏洞结论 |
| 26 | 跨项目回放 cohort 校准 | 已实现（bounded cross-project replay cohort） | `research-replay-cohort-v1`、distinct-project/per-surface sufficiency、`replay-cohort-calibrate`、显式 config fallback | 只从多个目标的 bounded calibration 汇聚可重复的调度信号；样本不足保持默认，本地校准优先；不改变候选、CVSS、G4/G5 |
| 27 | 可验证的真实项目回放 pack | 已实现（bounded provenance replay pack） | `research-replay-pack-v1`、文件 SHA-256 provenance、轮次 lane/comparison 摘要、`replay-pack` CLI、S8 自动产物 | 只消费 workspace-local allowlist 文件指纹和有界摘要；完整且自洽的 pack 才能进入 cohort；篡改、缺失和环境缺口保持可区分，不改变候选、CVSS、G4/G5 |
| 28 | 跨轮证据一致性与矛盾复核 | 已实现（bounded evidence consistency） | `research-consistency-v1`、`research-consistency` CLI、portfolio/strategy controlled follow-up、S8 自动产物 | 只从有界 research-memory 事件识别 effect/reproduction/comparison/context 漂移；冲突只生成受控复核动作，环境缺口不变成负证据，不改变候选、CVSS、G4/G5 |
| 29 | 一致性矛盾的受控复核契约 | 已实现（bounded S2→S4 recheck contract） | `research-consistency-action-v1`、`research-consistency-actions` CLI、S2 `consistency-recheck`、S4 MatrixCell/fixture/env、replay pack | 每个非一致条目生成固定隔离轴、正/负向 lane、重复次数、required observations 与 falsifiers；契约可进入 S2→S4 但仍是 `not-a-finding`，不改变候选、CVSS、G4/G5 |
| 30 | 一致性复核的真实执行与闭合 | 已实现（bounded S4→S8 recheck closure） | `research-consistency-recheck-v1`、S4 lane witness、`research-consistency-rechecks` CLI、S8/portfolio closure | 只有正/负向 lane、独立重复、fixture/context 锁、comparison、状态重置和 required observation 都有实际 witness 才标记 `observed`；缺失、部分执行和环境缺口保持可区分并继续 pending，不改变候选、CVSS、G4/G5 |
| 31 | 主动研究议程与有限预算分配 | 已实现（bounded information-gain agenda） | `research-agenda-v1`、`research-agenda` CLI、S8 agenda、scheduler exact-match signal | 将 strategy 的证据债务转成 selected/deferred/hold 队列，显式记录 expected information gain、estimated cost、prerequisites 和 surface diversity；只改变下一轮调度，不改变候选、CVSS、G4/G5 |
| 32 | 主动议程执行反馈与预算闭环 | 已实现（bounded agenda outcome feedback） | `research-agenda-outcome-v1`、`research-agenda-outcomes` CLI、S8 outcome、下一轮 agenda outcome fields | 将上一轮 selected 队列与实际 schedule、S4/S8 观测对齐，区分 new-information、falsifier、no-new-information、environment-gap、not-executed；用收益反馈调整下一轮优先级，不改变候选、CVSS、G4/G5 |
| 33 | 结果自适应研究预算分配 | 已实现（bounded outcome-cost adaptive budget） | `research-budget-v1`、`research-budget` CLI、S8 surface budget、agenda budget hints、replay pack provenance | 按 research surface 汇总成本、信息增益、环境缺口和无信息重复；产生 recovery/exploit/explore/cooldown 策略并影响下一轮有限预算，保留探索与假设，不改变候选、CVSS、G4/G5 |
| 34 | 语义路径证据与有限同符号数据流 | 已实现（bounded semantic path evidence） | `semantic-path-evidence-v1`、`semantic-path-evidence.json`、`semantic-path-candidates.json`、`semantic-paths` CLI | 区分控制在 sink 前/后/同一行及语义块关系；对同符号参数/简单别名给出 direct/propagated/not-traced，跨符号明确 unresolved；不复制源码、不升级 candidate/CVSS/G4/G5 |
| 35 | 语义守卫姿态与主体绑定 | 已实现（bounded semantic guard evidence） | `semantic-guard-evidence-v1`、`semantic-guard-evidence.json`、`semantic-guard-candidates.json`、`semantic-guards` CLI | 区分 terminating/nested/non-branch/未解析分支姿态及 overlap/mismatch/unresolved 主体绑定；只生成 `not-a-finding` 研究线索，不声称 branch dominance、对象身份或授权绕过 |
| 36 | 有界跨符号调用点参数/返回绑定 | 已实现（bounded interprocedural binding evidence；含多边传播与预算） | `semantic-call-evidence-v1`、`semantic-call-evidence.json`、`semantic-call-candidates.json`、`semantic-calls` CLI | 对 bounded flow 的多条调用边绑定实参/形参，识别简单 `parameter -> local alias -> return`，记录 `returned`/`assigned` 与深度/节点/路径/时间预算；超预算显式 gap，静态线索保持 `not-a-finding`，不声称完整数据流或漏洞 |
| 37 | 有界控制流关系与备用路径 | 已实现（bounded control-flow relation evidence） | `semantic-controlflow-evidence-v1`、`semantic-controlflow-evidence.json`、`semantic-controlflow-candidates.json`、`semantic-controlflow` CLI | 区分可能支配、终止拒绝分支之后、`else`/`except` alternate path 和同块未验证检查；不声称完整 CFG、路径可行性或授权绕过 |
| 38 | Python AST 结构见证与解析缺口 | 已实现（bounded Python-AST structural evidence） | `semantic-ast-evidence-v1`、`semantic-ast-evidence.json`、`semantic-ast-candidates.json`、`semantic-ast` CLI | 以语法树确认 Python 作用域、终止守卫、`else`/异常备用路径和解析状态；不声称完整 CFG、SSA、类型/运行时证明，其他语言保留显式降级 |
| 39 | 变换结果绑定与清洗失效线索 | 已实现（bounded transform binding evidence） | `semantic-transform-evidence-v1`、`semantic-transform-evidence.json`、`semantic-transform-candidates.json`、`semantic-transforms` CLI | 区分校验/清洗结果真正绑定、被丢弃、被覆盖、未绑定和跨符号缺口；不声称 sanitizer 语义、SSA、完整别名或漏洞结论 |
| 40 | 语言感知值绑定与混合路径 | 已实现（bounded Python AST value-flow adapter） | `semantic-python-binding-evidence-v1`、`semantic-python-binding-evidence.json`、`semantic-python-binding-candidates.json`、`semantic-bindings` CLI | 对 Python 简单赋值/别名/守卫/异常/有限循环路径区分变换值、原值、派生值、混合路径和未解析状态；其他语言明确 adapter gap，不声称完整 CFG/SSA/类型/运行时或漏洞结论 |
| 41 | 同源证据溯源与相关性 | 已实现首版 | `evidence-provenance-v1`、现有 S1/S2/CLI 消费链 | 源码版本绑定、具体上游引用、显式缺口；仅对同源同控制同问题降权，不把多层解释重复计票 |
| 42 | 统一语法前端 | 已接入 Python，其他语言待实现 | `SemanticFrontend`、既有 symbol/AST/binding/index summary | 三个实际消费者共用有界 AST 缓存；参数、嵌套符号、回退与解析缺口可回归，语法置信度不升级为语义证明 |

当前研发优先级以《VulnGate 后续研发目标（Codex）》为准。上表的已有 synthetic
评分器与回放契约不等于 Historical CVE Benchmark 已完成；Java/JS/TS/Go AST、
有界跨过程传播、最小 CFG、真实历史漏洞四态对照和独立运行时观测仍需逐项验证。
暂停新增非必要平台与 planner，优先检验研究有效性，不以产物数量作为完成标准。

## 已实现基础：可证伪实验规划

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

## 阶段 8 初步实现：评测驱动的自适应研究闭环

评测结果现在可以显式转换为 `research-benchmark-feedback-v1`。反馈只保留有界的指标快照、固定
告警码、最多 6 点的七因子权重微调，以及实验计划需要补齐的观测/证伪条件；不会复制 case、PoC、
命令、stdout/stderr，也不会携带或自动改写 CVSS。

生成反馈并接入下一轮调度：

```bash
python3 scripts/agent_cli.py benchmark \
  --manifest benchmarks/research-benchmark-v1.json \
  --run benchmarks/research-benchmark-sample-run.json \
  --out state/benchmark-result.json \
  --feedback-out state/research-benchmark-feedback.json --json

python3 scripts/agent_cli.py schedule <target> \
  --candidates state/<target>/round-01/S2/candidate-matrix.json \
  --benchmark-result state/research-benchmark-feedback.json \
  --slots 8 --round 2 --json
```

调度计划会落盘 `benchmark_feedback`、实际 `weight_adjustments` 和候选级反馈证据；S2
`experiment-plans.json` 会追加 `benchmark_guidance`。配置驱动/自治管线可在目标配置中显式提供
`benchmark_feedback_path`（或内嵌 `benchmark_feedback`），从而复用同一反馈。反馈只影响排序、
prompt 和研究清单，不会删除候选、确认漏洞、填补运行时证据或绕过 G4/G5。

## 阶段 9 初步实现：跨攻击面变体基准

为了避免“只在解析库样例上表现良好”被误认为具备专家级泛化能力，新增一组脱离真实目标的合成基准：

```bash
python3 scripts/agent_cli.py benchmark \
  --manifest benchmarks/research-benchmark-surfaces-v1.json \
  --run benchmarks/research-benchmark-surfaces-sample-run.json \
  --out state/research-surfaces-result.json --json
```

这组 15 个 case 分布在 Web、协议、云、移动端和 native 五类研究面；每类各包含一个可确认漏洞、一个
应被排除的负向 case 和一个只能保留为候选的环境/工具缺口。manifest 只保存 bounded metadata、truth
class、必需证据和期望 claim status，不保存 payload、命令或进程输出。

评分器会保留 case 的 `surface`、`target_type`、`attack_class`、`variant` 和 `precondition_class`，
并输出 `research_profile` 与按研究面拆分的 `coverage_by_surface`。这使得某一面证据缺失、错误确认
负向 case 或吞掉环境缺口能够独立暴露；所有评测结果仍标记为 `claim_status=not-a-finding`。

## 阶段 10 初步实现：研究面级自适应调度与规划

跨面指标现在会进一步转换成有界 `surface_guidance`。它只保留 allowlist 内的研究面、四类固定指标、
固定观测/证伪文本和最多 6 点的面级优先级增量：

- observation coverage 偏低时，要求该研究面补齐状态或显式执行缺口；
- evidence completeness 偏低时，优先补齐必需证据字段；
- negative case 被错误确认时，优先补 typed effect/确认安全证据；
- environment-gap fidelity 偏低时，优先补 runtime/前置条件探针。

调度器只接受候选中的显式 `research_surface`，或由明确的 `target_type` 映射出的研究面；自由文本
`surface` 不会通过 substring 猜测而获得 boost。规划器只给匹配研究面追加 baseline 观测与 falsifier，
所有结果仍是 `not-a-finding`，不会确认/排除候选，也不会修改 CVSS 或 G4/G5。

## 阶段 11 初步实现：纵向评测退化检测

评测不能只看单轮绝对分数。可以把上一轮的 bounded benchmark result 作为 baseline：

```bash
python3 scripts/agent_cli.py benchmark \
  --manifest benchmarks/research-benchmark-surfaces-v1.json \
  --run benchmarks/research-benchmark-surfaces-sample-run.json \
  --baseline state/previous-research-surfaces-result.json \
  --out state/research-surfaces-result.json \
  --feedback-out state/research-benchmark-feedback.json --json
```

比较器只处理固定的观测覆盖、precision/recall、负向安全、环境缺口保真度、证据完整度、重复率、
决策稳定性和严重性校准指标，并对共同研究面计算独立 delta。退化会形成
`research-benchmark-trend-v1`，进一步转成 `benchmark-regression` 和面级 guidance；baseline/current
case、PoC、stdout/stderr 都不会被复制。趋势仍是 `not-a-finding`，只要求下一轮用独立观测定位回归，
不能改变候选状态、CVSS 或 G4/G5。

## 阶段 12 初步实现：项目级研究组合与变体覆盖

单个 `research-memory` 适合回答“这个机制上一次发生了什么”，但顶级研究员还需要回答“整个项目
哪些面已经被实际验证、哪些变体仍然空白、下一轮最值得做什么”。S8 现在把目标级记忆、人工复核
和显式 benchmark feedback 汇聚成有界 `research-portfolio-v1`：

- 按 `research_surface`、`target_type`、`attack_class`、`variant` 和 `precondition_class` 统计机制数、事件数、稳定观察、可行动差异和环境缺口；
- 为每个变体输出 `observed_states`、`unresolved_entries` 与 `status`，把“未观测”和“稳定观察”分开；
- 生成按缺口优先级排序的 `next_probes`，只保留 research key、受控分类、状态和有界提示，不复制 reviewer note、payload、命令或 stdout/stderr；
- 将纵向 benchmark 的回归面和告警码作为上下文带入组合视图，但仍保持 `claim_status=not-a-finding`。

目标级产物是 `state/<target>/research-portfolio.json`，轮次快照是
`state/<target>/round-NN/S8/research-portfolio.json`。下一轮 S2 prompt 会读取该视图；调度器只对
research key 或至少两个显式维度（含变体）的精确匹配施加很小的优先级增量，并把匹配证据写入
schedule，帮助宿主 Agent 把跨面覆盖和变体缺口转成可证伪实验；它不改变候选状态、CVSS 或 G4/G5。

## 阶段 13 初步实现：攻击路径威胁模型与信任边界

顶级研究员不会只看“某个 API 命中了危险函数”，而会持续维护一张
“谁能够从哪条信任边界、以什么前置条件、经过哪些控制，到达哪个危险操作”的研究地图。
S1 现在把已有 entry/sink/flow、控制图和能力图做成有界的
`threat-model-v1`：

- 按入口类型聚合网络、RPC、消息、WebView、IPC、URL scheme、库解析、文件输入、配置和 CLI 等信任边界，并只记录待确认的 attacker-role 标签；
- 对每条 flow 关联 sink、静态控制姿态、缺失控制组、覆盖缺口、前置条件、证伪问题和能力链假设；
- 对没有生成 flow 的入口、只被 sink 反向看到的区域和其他 reachability gap 单独列为 pending，防止“索引没有路径”被误解成安全；
- 目标级保存到 `state/<target>/coverage/threat-model.json`，轮次镜像保存到 `S1/threat-model.json`；调度 prompt 和 `agent_cli.py threat-model` 使用同一份 bounded 视图。

该模型只表达研究假设，所有记录强制 `claim_status=not-a-finding`，不携带源码原文、payload、命令、stdout/stderr、凭据、CVSS 或 G4/G5 证据。路由暴露、真实数据流、控制顺序、能力 transition 和 typed effect 仍必须由 S3/S4 独立验证。

## 阶段 14 初步实现：S3 residual 跨轮闭环

S3 的 `residuals.json` 代表“尚未正式立项、但不能丢掉的研究怀疑点”。此前它主要停留在单轮 S3/S4 队列；现在 S8 会把 residual 以有界元数据合并进目标级 research memory：

- 只保留受控的 `kind` / `reason_code`、有界 `file:line` 位置、probe 摘要哈希和 `has_probe_plan`，不复制 residual 原文、命令、payload 或 stdout/stderr；
- 即使同一机制的主 replay 是 `stable-reproducer`，相关变体仍会在 portfolio 中标为 unresolved，并生成 `state=pending-residual` 的有界 `next_probe`；
- S2 只把该条目当作下一步研究调度提示，所有 memory、portfolio 和 prompt 记录保持 `claim_status=not-a-finding`，S4 仍必须用明确 falsifier 关闭 residual。

这样可以把顶级研究员常用的“残余怀疑点清单”变成可恢复、可回放、可验证的项目级状态，同时不放宽 G4/G5。

## 阶段 15 初步实现：跨产物证据驱动研究策略

顶级研究员不会把“危险路径”“环境缺口”“已稳定的主样例”和“尚未关闭的变体”混在一个优先级列表里。S2 现在生成 `research-strategy-v1`，把已有 bounded artifact 统一成可回放的研究议程：

- `control-closure`、`capability-closure`、`reachability-closure` 和 `path-closure` 分别对应控制顺序、能力 transition、入口可达性和完整 source→sink 路径的待验证目标；未映射 entry/sink 也单独生成 `coverage-closure`；
- `residual-closure` 与 `environment-recovery` 直接承接 S3 residual 和运行环境缺口，不会因为主 replay 稳定或某轮没有观测就被清掉；
- 每条策略由固定的 required observations 与 falsifiers 构成，并保存 path/research-key/residual 等有界关联；调度器只有在 flow、entry+sink、candidate/research key 等明确证据匹配时才给小幅提示；
- 目标级产物写入 `state/<target>/coverage/research-strategy.json`，S2 快照写入 `S2/research-strategy.json`，也可通过 `python3 scripts/agent_cli.py research-strategy <target> --workspace <audit-dir> --json` 查看。

策略层只是研究计划，不是 source review、运行时观测、漏洞确认、CVSS 或 G4/G5 的替代品；所有记录继续强制 `claim_status=not-a-finding`。

## 阶段 16 初步实现：Residual falsifier 闭合

阶段 14/15 已经能把 residual 保留下来并列入研究议程，但如果没有明确的闭合协议，
同一条残余会无限生成下一步探针。阶段 16 把“何时可以停止追踪这条研究怀疑”固化为
S2→S4→S8 的单向契约：

- S2 根据稳定的 residual identity 生成有界 `residual_contracts`，只暴露 residual ID、
  类型和 allowlisted falsifier；PoC 通过 `VULNGATE_RESIDUAL_CONTRACT` 读取观察清单，
  不能把计划本身当成观测；
- S4 只解析 `RESIDUAL_ID`、`RESIDUAL_STATUS=falsified` 和
  `RESIDUAL_FALSIFIER`，并记录 cell 是否真实执行、是否声明过 contract、是否出现
  typed effect；`S4/residual-closure.json` 只包含这些有界元数据；
- S8 只有在 ID/contract/falsifier 全部匹配、cell 成功执行且没有副作用时才把状态从
  `pending-residual` 单向更新为 `residual-falsified`。缺少 marker、运行失败、前置条件
  不可用、门控阻断或出现 effect 都不能闭合；已闭合状态也不会回退或再次生成 portfolio
  probe；
- 这只是研究记忆和调度状态，始终是 `claim_status=not-a-finding`，不代表漏洞被证伪，
  也不改变 G4/G5、CVSS 或 finding ledger。

## 阶段 17 初步实现：策略项真实观测回写与信息增益

阶段 15/16 已经能生成策略项、执行 residual contract 并把状态写入 memory，但策略项本身仍像
一次性静态清单：S4 跑完后，系统不知道哪些 required observations 已经得到真实信号，也不知道
下一次运行是否只是重复。阶段 17 在 S8 增加一个 bounded feedback loop：

- `apply_strategy_observations` 只按 candidate id、stable research key、residual id 或显式 path
  标识符关联 S4 summary；不会用自由文本、结论或 stdout/stderr 做模糊匹配；
- 汇总器把实际执行、入口行为、授权断言、能力 trace、typed effect、safe-equivalent、residual
  contract 和环境缺口压缩成固定信号，计算 `unobserved`、`execution-only`、`partial`、
  `complete`、`environment-gap` 或 `falsifier-observed` 状态；静态 source→sink 要求不会被
  一次运行的缺失 marker 自动满足；
- `information_gain` 是相对于该策略项历史信号的本轮新增信号数（有界），并保存 missing
  observations、execution states、evidence digest 和 cumulative gain；相同状态重复运行得到 0，
  不会伪造“学习”；
- S8 将反馈写入 `state/<target>/coverage/research-strategy.json` 与轮次的
  `S8/research-strategy-feedback.json`，下一轮重新生成策略时保留该观察历史；策略调度只在有新
  信息或仍未完成时施加小幅提示，已完整/已观察 falsifier 且没有新信息的项不再重复获得加分；
- 所有回写字段继续是 `claim_status=not-a-finding`，只改变研究优先级和下一步提示，不改变
  candidate status、finding ledger、CVSS、G4 或 G5。环境缺口仍然是缺口，而不是负向证据。

## 阶段 18 初步实现：跨轮研究行动与实验替换建议

阶段 17 已经知道“本轮观察到了什么”和“信息增益是多少”，但顶级研究员还会把这些结果与
人工复核、项目级变体覆盖和残余任务合并，决定下一轮到底应该修环境、补哪一种控制证据，还是
彻底换一个实验变体。阶段 18 增加 `research-strategy-guidance-v1`：

- 对每条策略项只输出固定枚举的 `next_action`、有限 `priority_delta`、原因码、来源类别和变体缺口；不复制 reviewer note、payload、命令、stdout/stderr 或自由文本结论；
- `environment-gap` 只能导向 `repair-environment`；S3 residual 导向 `replay-residual-variant`；缺少负向基线、capability transition、typed effect 或 source/dataflow 观测时分别导向定向补证动作；
- `needs-evidence`、`rejected` 和 `scope-corrected` 复核会变成 `review-followup` 或 `reframe-scope`，并与 `variant-coverage` 一起记录来源，避免盲目重复同一条已被否定或范围已修正的路径；
- 当当前状态已经执行但连续轮次 `information_gain=0` 时，输出 `replacement_recommended`；已完整或已观察 falsifier 的重复项进入 `hold-for-new-evidence`，只取消研究加分，不删除候选；
- 目标级和轮次级 guidance 都保持 `claim_status=not-a-finding`。它只是下一步实验编排，不能替代 source review、S4 typed effect、G4/G5 或 CVSS。

## 阶段 20 初步实现：研究面 fixture 与状态机执行上下文

阶段 19 的变体计划已经能告诉宿主 Agent“应该验证什么”，但如果 S4 仍只重放一个没有 lane
身份的基础 cell，PoC 实际执行时就无法区分正向、负向和环境缺口实验，也无法稳定推进研究面特有的
状态机。阶段 20 增加 `surface-variant-fixture-v1`：

- 由规范化的 `surface_variant_plan` 生成最多 9 个有界 fixture context；每个 context 只包含不透明
  `fixture_key`、研究面、变体、lane、固定 `state_steps`、required observations 和 falsifiers；
  原始 payload、命令、凭据和进程输出不会进入计划或跨轮 artifact；
- S4 runtime lab 在 `runtime_lab.max_fixtures` 预算内为每个 context 克隆基础 cell，并将
  `VULNGATE_VARIANT_SURFACE`、`VULNGATE_VARIANT_ID`、`VULNGATE_VARIANT_LANE`、状态步骤、观察要求和
  falsifier 通过受控环境变量交给 PoC；真实执行仍只由 PoC 输出的机器可读证据决定；
- `S4/runtime-lab.json` 将 lane context、每个候选的 lane 计数和预算截断状态与脱敏 replay/differential
  摘要绑定；environment-gap 车道不会被自动标成缺口，runner 失败、前置不可用和安全等价结果仍分开；
- config-driven 与 autonomous S2 都把 fixture plan 暴露在 `candidate-matrix.json`，因此同一份研究计划能从
  调度、PoC 生成到 S4 runtime lab 连贯传递；所有新增字段继续是 `claim_status=not-a-finding`。

## 阶段 21 初步实现：跨版本与修复变体自动对照编排

阶段 20 已经让同一研究面变体的三条 lane 真正进入 S4，但修复完整性候选仍可能把“补丁引用”、
“配置版本差异”和“同族路径”混在一起。阶段 21 增加 `comparison-orchestration-v1`：

- S2 从配置版本、`patch_parent`/`patch_commit` 和 allowlisted `patch_variants` 生成有界 comparison
  contract；源码 revision 只标为 `build-required`，不会由确定性组件自动 checkout 或把 commit 当成证据；
- S4 将 contract 绑定到同一个 fixture/lane，并对真实版本 cell 归纳 `bucket-difference`、
  `signature-drift`、`same-observation` 或 `inconclusive`；缺少旧/新 runtime 明确是环境缺口；
- 没有实际执行的源码 revision 与 sibling arm 会保留 `not-executed` / pending 状态，要求对应的受控构建或
  lane 后才可继续；artifact 不复制 raw diff、payload、命令或 stdout/stderr；
- comparison summary、candidate status 和 S4 merge 都只保存有界身份与状态，不改变 candidate conclusion、
  CVSS、G4 或 G5；S8 会把这些对照状态以白名单形式并入跨轮研究记忆，供下一轮继续补证。

## 阶段 22 初步实现：真实项目回放校准

阶段 18 的 guidance 已经能指出“应该换实验”，但固定阈值可能在不同项目上过早替换，或让无信息重复
持续占用 fixture 预算。阶段 22 增加 `research-replay-calibration-v1`，只使用已经落盘的有界快照：

- 从每轮 `S8/research-guidance.json`、`S8/research-strategy-feedback.json` 和 `S4/runtime-lab.json`
  提取匹配的 guidance/feedback 对，不复制原始 payload、命令、stdout/stderr、凭据或漏洞结论；
- 统计替换建议的实际命中率、无信息重复率、环境缺口恢复率、fixture 预算截断率和 comparison gap 率，
  并保留每轮的有限 outcome 分类，方便审计“建议是否真的改变了信息”；
- `agent_cli.py replay-calibrate <target> --workspace <dir> --json` 可以独立重建目标级校准产物；S8 在写入本轮
  guidance/feedback 后更新 `state/<target>/coverage/` 与 `S8/` 快照，下一轮 S2/S8 复用上一轮已验证的策略；
- 只有至少三条已匹配回放、且替换命中率低并伴随高无信息重复时，才把零增益阈值从 1 调整到 2；fixture
  截断或 comparison gap 只生成恢复/预算告警，不会把计划缺口当成负向证据；所有产物继续保持 `not-a-finding`。

## 阶段 23 初步实现：受控历史构建产物与 source-revision arm 执行

阶段 21 已经能生成 source-revision comparison contract，但“有 patch ref”仍不足以复现修复前后的真实行为。
阶段 23 增加显式的 `source-revision-artifacts-v1` 适配器：

- 配置通过 `source_revision_artifacts.enabled=true` 显式开启，并为 exact `before`/`after` commit ref 提供有限数量的
  workspace-local `.jar`、`.war` 或 `.zip`；路径必须落在 workspace 内，文件必须是非空且不超过大小上限；
- 适配器只做规范化、路径/类型/大小校验和 SHA-256 指纹，不执行 `git checkout`、构建命令、远程下载或部署；
  产物路径只以有界相对路径进入脱敏快照，runner 使用的绝对路径留在进程内；
- Java source arm 复用既有隔离 `JavaMatrixRunner`，沿用同一 fixture/lane、SafeMode 和 comparison 分类；Shell 或
  缺失/损坏/不匹配的 arm 明确保持 `precondition-unavailable`/`inconclusive`；
- 实际 source arm 观测及 before/after pair 只进入 bounded comparison 与 S8 research memory，统一保持
  `claim_status=not-a-finding`，不会改变候选结论、CVSS、G4 或 G5；
- 回归测试同时覆盖 workspace 边界、指纹脱敏、无 checkout/build 副作用、真实 source arm 差异以及记忆归一化后的
  持久化，保证“未执行”“环境缺口”和“已观察差异”不混淆。

## 阶段 24 初步实现：surface lane 的真实观测见证层

阶段 20 已经把研究面 lane 和状态步骤送进 S4，但仅有 fixture context 仍不能说明 PoC 真正执行了哪些步骤。
阶段 24 增加 `surface-variant-evidence-v1`，把 runner 的实际机器可读输出压缩成可回放的 lane witness：

- 只消费真实 replay/differential runner row；计划声明、环境变量和 fixture context 不会单独满足任何观测要求；
- 对每个 cell 仅保留 `execution`、`entry-behavior`、`authorization`、`negative-baseline`、`capability-trace`、
  `state-sequence`、`typed-effect`、`safe-equivalent`、`environment-gap`、`evidence-field` 和 `runtime-error` 等固定信号，
  并严格限制状态步骤、序列状态、cell 数量和缺口码；
- lane 汇总明确区分 `observed`、`partial`、`environment-gap` 与 `not-executed`，只有实际完整的 STEP trace 才能形成
  `state-sequence`，typed effect 与 safe-equivalent 仍是独立观测；
- S8 research memory 只保存归一化 witness 与有界 next-probe hint，S2 strategy observation 读取同一组信号，帮助下一轮
  补状态顺序、负向基线、typed effect 或修复环境；原始输出、effect 细节、payload、命令、凭据不会跨轮持久化；
- witness 始终是 `claim_status=not-a-finding`，不会改变 candidate conclusion、CVSS、G4 或 G5；环境缺口仍不是负向证据。

## 后续优先级

1. 用更多真实项目 lane witness 和细粒度 fixture/state-machine 回放样例校准五类研究面的状态步骤、负向基线、typed-effect 覆盖和一致性冲突阈值，
   保留 runner 的回环、审批和资源上限。
2. 增加更多受控历史产物格式与 project replay 样本，但继续禁止自动 checkout、构建和远程执行，把 artifact provenance 与
   comparison gap 分开统计。
3. 继续积累跨项目回放样本，分别校准 environment recovery、comparison gap 和 fixture budget 的告警边界，避免把样本偏差固化为调度规则；cohort 只有在不同项目样本足够时才应影响调度。

每一阶段都必须同时更新实现、技能契约、回归测试和 CHANGELOG；只有测试、artifact schema 和安全边界一起稳定后，才适合提交为一个独立变更。

## 阶段 26 初步实现：跨项目回放 cohort 校准

阶段 22 的 `research-replay-calibration-v1` 只能回答单个目标上的 guidance 是否产生了新信息。把一个项目的阈值直接迁移到另一个项目，会把产品差异、研究面偏差和环境缺口误当成普遍规律。阶段 26 增加显式的 `research-replay-cohort-v1`：

- `agent_cli.py replay-cohort-calibrate` 接收多个目标已经落盘的 calibration artifact；输入路径、原始回放、payload、命令、stdout/stderr 和漏洞结论不会进入 cohort；project row 只保留不透明 ID、有限计数、比率和 `not-a-finding` 状态。
- cohort 同时检查不同项目数与每个研究面的回放充分性。至少三个独立项目拥有足够的可回放样本后，才允许 cohort policy 影响调度；项目数不足时保留默认阈值并生成 `collect-more-projects`。
- 两轮 zero-gain threshold 只有在项目级低收益 replacement signal 达到有界多数条件时才启用；目标本地已经充分校准时优先使用本地结果，显式 `replay_cohort_calibration_path` 只作为本地历史不足时的 fallback。
- cohort 可以在 S8 复制一份 bounded snapshot，仍只影响 research-guidance scheduling，不会确认/排除候选，不会填补运行时证据，不会改变 CVSS、G4 或 G5；默认未配置时行为保持不变。

## 阶段 27 初步实现：可验证的真实项目回放 pack

阶段 26 的 calibration artifact 能汇聚调度信号，但单独复制一个 JSON 仍无法证明它来自哪些轮次、哪些 S4 lane witness、哪些 comparison gap，容易让“真实项目经验”退化为不可审计的数字。阶段 27 增加 `research-replay-pack-v1`：

- `agent_cli.py replay-pack <target> --workspace <dir> --json` 只扫描显式 allowlist 的 workspace-local 轮次/目标产物，记录相对 artifact 名、文件大小、SHA-256、schema version 和 present/absent/invalid 状态，不复制源码、payload、命令、stdout/stderr、凭据或漏洞结论；
- 每个 round 保留有界的 lane witness 摘要（observed/partial/environment-gap/not-executed、typed-effect、safe-equivalent、state-sequence）以及 comparison 状态/缺口/待执行 arm 计数；环境缺口仍不是负向证据；
- pack 内嵌归一化的 `research-replay-calibration-v1`，并把 target-level calibration 的 history digest 与轮次历史做一致性校验；缺失、篡改、schema 不匹配或 digest 不一致分别保留为 partial/invalid，不静默降级为可信样本；
- S8 的 config-driven 与 autonomous 管线自动写入 `state/<target>/coverage/research-replay-pack.json` 和 round snapshot。`replay-cohort-calibrate --pack ...` 只接受 provenance 完整、自洽且 `valid_for_cohort=true` 的 pack；旧的 `--artifact` 输入仍保留兼容，但不会被伪装成 pack provenance；
- pack/cohort 始终是 `claim_status=not-a-finding` 的研究元数据。它只影响研究调度样本是否可进入 cohort，不改变 candidate status、CVSS、G4 或 G5；文件被修改后可用 `verify_replay_pack` 重新做本地哈希核验。

## 阶段 28 初步实现：跨轮证据一致性与矛盾复核

顶级研究员不会只看同一机制“最新一次”的状态：如果一次回放观察到 typed effect，另一轮却只得到安全等价或不可复现，正确动作是固定上下文、隔离状态并重新观察，而不是把最新结果覆盖历史。阶段 28 增加 `research-consistency-v1`：

- `agent_cli.py research-consistency <target> --workspace <dir> --json` 从已经归一化的 `research-memory` 事件生成有界一致性视图；只保留轮次、状态、effect/reproduction/comparison/context 分类和摘要指纹，不读取或保存源码、payload、命令、stdout/stderr、凭据或漏洞结论；
- 对同一 `research_key` 识别 `effect-presence-drift`、`reproduction-drift`、`comparison-drift`、`state-drift` 和 `context-drift`，区分 `conflicted`、`unstable`、`insufficient`、`environment-gap` 与 `consistent`；环境缺口不参加“无 effect”比较；
- project portfolio 会为非一致条目生成有界 next probe，strategy 将其转成 `repeat-with-controlled-context`，并可继续细化为隔离状态、收集独立观测或修复环境；它只改变下一轮研究优先级，不替代 S4 真实观测；
- S8 的 config-driven 与 autonomous 管线自动写入 target/round consistency artifact，replay pack 也把它纳入 provenance allowlist，确保“矛盾已经被发现”本身可复核；所有状态保持 `claim_status=not-a-finding`，不改变 candidate status、CVSS、G4 或 G5。

## 阶段 29 初步实现：一致性矛盾的受控复核契约

阶段 28 能发现跨轮矛盾，但仅有 `next_action` 仍可能让下一轮重新退化为一次没有对照、没有状态重置或没有独立重复的 best-effort 运行。阶段 29 将动作具体化为 `research-consistency-action-v1`：

- S8 为每个 `conflicted`、`unstable`、`insufficient` 或 `environment-gap` 条目生成一个有界 action entry，固定 `isolation_axes`、`matrix_shape`、`required_observations` 和 `falsifiers`；环境缺口只生成 `environment-repair` 轴和 `environment-status`，不伪造正/负向结果；
- `agent_cli.py research-consistency-actions <target> --workspace <dir> [--rebuild] [--json]` 可查看或重建 action artifact。target/round artifact 与 portfolio 都只保存 allowlist 元数据、状态码和 `claim_status=not-a-finding`，不复制源码、payload、命令、stdout/stderr、凭据或 finding 结论；
- S2 通过稳定 `research_key` 将 action 注入 `experiment-plans.json`，新增 `consistency-recheck` 计划并保留 surface variant 的 positive/negative/environment-gap lane；S4 MatrixCell、PoC 环境变量、普通 runtime-lab fixture 和 replay/differential cell 都携带同一份归一化契约；
- 复核契约把“签名漂移不是 effect”“fixture identity 不一致”“context digest 不一致”“状态未重置”“缺少独立重放”等证伪条件显式化。契约未满足时只保持 pending/环境缺口，不改变 candidate status、CVSS、G4 或 G5；
- replay pack 将 action schema 纳入 round/target provenance allowlist，回归测试验证 action 的重算、脱敏、CLI、portfolio/strategy 传递以及 S2→S4 fixture 环节。

## 阶段 30 初步实现：一致性复核的真实执行与闭合

阶段 29 解决了“下一轮应该怎样复核”，但契约被传到 S4 并不等于复核真的执行过。阶段 30 增加 `research-consistency-recheck-v1`：

- S4 根据 action 的 `matrix_shape` 实际展开 positive/negative 或 environment-gap lane；每个 lane 通过 `VULNGATE_CONSISTENCY_LANE` 接收有界选择器，fixture 使用独立 lane identity，同时保留相同的基础 context digest，避免把 lane 标签误当成上下文差异；
- S4 在原始 runner row 仍位于内存时只提取 allowlist witness：执行/环境状态、独立 replay 次数、typed effect 或 safe-equivalent、显式状态重置、comparison arm 状态，以及 fixture/context 标识。不会把 stdout、stderr、命令、payload、凭据或 source prose 复制进 closure artifact；
- S8 使用上一轮 pending action 与本轮 `S4/runtime-lab.json` 汇合，写出 target/round `research-consistency-rechecks.json`。它严格区分 `observed`、`partial`、`environment-gap` 和 `not-executed`；完整 lane 未闭合时 portfolio 继续生成下一步 probe，完整闭合时停止重复调度但保留历史矛盾供审计；
- `python3 scripts/agent_cli.py research-consistency-rechecks <target> --workspace <audit-dir> [--round N] [--rebuild] [--json]` 只读取有界 runtime-lab artifact，不扫描 raw matrix output。recheck、portfolio、strategy 和 replay pack 全部保持 `claim_status=not-a-finding`，不能满足 G4/G5、确认漏洞或降低环境缺口。

## 阶段 31 初步实现：主动研究议程与有限预算

阶段 30 已经能判断一次受控复核是否真正闭合，但跨攻击面的大型项目仍缺少一个明确的“下一轮先做什么”决策层：策略项可能很多，简单按静态 priority 排序会重复消耗预算，也会让低收益路径挤掉尚未覆盖的研究面。阶段 31 增加 `research-agenda-v1`：

- `build_research_agenda` 只消费归一化的 `research-strategy-v1` 与 portfolio recheck 状态，把每个策略项压缩为有限的 `action`、`missing_observations`、`required_observations`、falsifiers、prerequisites、expected information gain、estimated cost 和 bounded priority score；不复制源码、payload、命令、stdout/stderr、凭据或 finding 结论；
- agenda 在有限 slots 内先按 surface × attack class 做一次多样性选择，再用剩余预算选择高信息增益项，显式区分 `selected`、`deferred` 和已满足证据的 `hold`。环境修复、residual、review follow-up 和 recheck evidence debt 会得到有界加权，但不会改变 G4/G5；
- S8 写入 target/round `research-agenda.json`，replay pack 对其做可选 provenance；`python3 scripts/agent_cli.py research-agenda <target> --workspace <audit-dir> [--rebuild] [--slots N] [--max-per-surface N] [--json]` 可检查或重建；
- 下一轮 scheduler 只在 candidate 与 agenda 的 `research_key` 或 `candidate_id` 精确匹配时使用小幅 boost，并把 agenda 选择证据写入 schedule。agenda 全部保持 `claim_status=not-a-finding`，不能确认漏洞、改变 candidate status、CVSS、G4 或 G5。

## 阶段 32 初步实现：主动议程执行反馈与预算闭环

阶段 31 能选择有限的研究任务，但如果某个 selected 项没有真正进入 schedule、被环境阻断，或连续执行却没有新观测，下一轮仍可能只看到静态 priority。阶段 32 增加 `research-agenda-outcome-v1`：

- S8 在覆盖上一轮 agenda 前，先把上一轮 `selected/deferred/hold` 项与实际 scheduler snapshot、S4 `verification-matrix`、S4 `runtime-lab` 和 S8 strategy feedback 按 `agenda_id`、`strategy_id`、`research_key`、`candidate_id` 的精确键对齐；
- 每项只输出 allowlist outcome：`new-information`、`falsifier-observed`、`no-new-information`、`environment-gap`、`not-executed` 或 `not-selected`，并保留有限的 information gain、observed signals、execution state、cells/fixtures 计数、reason codes 与连续无增益计数；缺少 schedule 或运行环境失败不会被解释成负向安全证据；
- 目标级写入 `state/<target>/coverage/research-agenda-outcomes.json`，轮次写入 `S8/research-agenda-outcomes.json`，同时保留有界 history。下一轮 agenda 将最近 outcome 作为 `last_outcome` 和 recovery/no-information priority signal，scheduler prompt/evidence 也会展示该反馈；
- 可用 `python3 scripts/agent_cli.py research-agenda-outcomes <target> --workspace <audit-dir> [--round N] [--rebuild] [--json]` 检查或重建。outcome、agenda 和 scheduler feedback 都保持 `claim_status=not-a-finding`，不能确认漏洞、改变 candidate status、CVSS、G4 或 G5。

## 阶段 33 初步实现：结果自适应研究预算分配

阶段 32 已经能记录每个议程项是否产生了新信息，但还不能回答“有限预算应该在不同研究面之间如何重新分配”。如果只在单项上加固定 boost，连续低收益实验仍可能消耗大部分轮次，而环境恢复或尚未覆盖的研究面没有明确的预算策略。阶段 33 增加 `research-budget-v1`：

- S8 将上一轮 agenda 与 outcome 按精确键关联，再按 research surface 汇总 selected 数、productive outcome、information gain、estimated cost、environment gap 和 no-information repeat；仅保留受控计数、比率和固定策略码，不复制源码、payload、命令、stdout/stderr、凭据或 reviewer note；
- 策略固定分为 `recover-environment`、`exploit-high-yield`、`explore-undercovered`、`continue-balanced` 和 `cooldown-low-yield`。环境缺口获得有限恢复权重，连续无信息项降温但不删除，生产性研究面得到小幅 exploitation 权重，未观察研究面保留探索机会；
- S8 同时写入 target/round `research-budget.json`，下一轮 `research-agenda-v1` 只消费其中的 surface hint、bounded priority delta 和 cap hint；`agent_cli.py research-budget <target> --workspace <audit-dir> [--round N] [--rebuild] [--slots N] [--json]` 可检查或重建；
- budget、agenda、replay pack 和 scheduler 仍是 `claim_status=not-a-finding`，策略只影响研究顺序和预算，不确认漏洞、不改变 candidate status、CVSS、G4 或 G5。样本不足时保持默认探索策略，策略合并按 round 去重并可重复回放。

## 阶段 34 初步实现：语义路径证据与有限同符号数据流

早期 control map 只能回答“某类控制是否出现在启发式调用路径上”，而 source→sink 图只能回答“入口和危险操作是否被近似连起来”。这两个答案对顶级审计仍不够：控制可能在 sink 之后、处于另一分支，或者只保护了不同的主体；同一 handler 内的输入也可能经过一层简单别名后才进入 sink。阶段 34 增加一个保守的、源码局部的确定性证据层：

- `semantic-path-evidence-v1` 对每条 flow 保存 entry/sink、路径、控制行与 sink 的相对关系：`before-sink`、`after-sink`、`same-line` 或 `cross-symbol-unverified`，并用 brace/indent 计算 `same-lexical-block`、`enclosing-block`、`nested-block` 等有限 scope 关系；
- 当 entry/source symbol 与 sink symbol 相同时，从符号签名提取参数，对简单 `lhs = rhs` / `lhs := rhs` 做有界别名追踪，区分 `direct`、`propagated` 和 `not-traced`；跨符号一律保留为 `cross-symbol-unresolved`，不因为静态图连通就假设参数已传递；
- 对 static control map 已经认为存在控制、但顺序/语义块未对齐的路径，生成 `semantic-control-order`；对中高风险同符号路径未能闭合参数到 sink 的线索，生成 `semantic-dataflow-gap`。这些候选进入 S2 静态候选池，并保持稳定 ID、`requires_manual_dataflow=true` 和明确代码位置；
- 产物不保存源码原文，不建模 branch dominance、类型、virtual dispatch、DI、reflection、callback 或 sanitizer 语义。所有行、summary 和候选保持 `claim_status=not-a-finding`、`confidence=heuristic-nearby`、`evidence_type=static-inferred`，S3/S4 仍必须补真实路径、授权和 typed-effect 证据；
- 可用 `python3 scripts/agent_cli.py semantic-paths <target> --workspace <audit-dir> --show-candidates --json` 查看。覆盖索引发现缺少该 artifact 时会自动重建，autonomous/config-driven 两条管线使用同一份候选源。

## 阶段 35 初步实现：语义守卫姿态与主体绑定

阶段 34 已经能回答控制是否位于 sink 之前、同一有限语义块，以及有限的同符号参数是否接近 sink；但顶级代码审计还需要把“附近的检查”拆成两个更可操作的复核问题：它是否看起来在拒绝路径上保护了 sink 所在分支？它检查的主体或对象是否就是 sink 实际操作的那个？阶段 35 增加独立的 `semantic-guard-evidence-v1`：

- 对每条 semantic flow 记录有限的 branch posture：`terminating-guard-likely`、`nested-branch-likely`、`non-branch-check`、`branch-unresolved`、`after-sink` 与 `cross-symbol-unverified`；这只是源码形状证据，不证明 dominance、路径可行性或返回/异常语义；
- 对控制和 sink 的有限 identifier token 做 subject/object binding：`overlap`、`mismatch`、`unresolved`、`cross-symbol-unverified`。`mismatch` 只表示值得人工追踪“检查了 A、操作了 B”，不表示已经存在越权；
- 对满足基础控制图前置条件的路径生成 `semantic-subject-binding` 与 `semantic-branch-posture` 线索，写入完整静态候选池，同时保留稳定 ID、位置、`requires_manual_dataflow=true` 和 `claim_status=not-a-finding`；
- 产物与 CLI 为 `state/<target>/coverage/semantic-guard-evidence.json`、`semantic-guard-candidates.json` 和 `python3 scripts/agent_cli.py semantic-guards <target> --workspace <audit-dir> --show-candidates --json`。两条 pipeline 共用同一份索引；后续可用 CFG、类型、DI 和运行时授权证据替换启发式层，而不改变既有闸门。

## 阶段 36 增量：多边参数传播与返回别名

在一跳调用绑定基础上，本增量只扩展已经由 call graph 选出的 bounded path，不重新猜测调用目标，也不新增平台抽象层：

- 沿 `A -> B -> C -> Sink` 的已有路径逐边传递有限的 tainted parameter；每条边继续记录实参/形参绑定，最终 sink 只在有限标识符交集存在时记为 `bound`；
- 在 callee 作用域内只识别简单标识符别名，例如 `local = value; return local`，并记录 `alias_map`、`returned_aliases` 和 `tainted_return_aliases`；transform、container、attribute、callback 或未解析 dispatch 保持 unresolved；
- 对每条 flow 设置 `max_call_depth`、`max_propagation_nodes`、`max_propagation_paths` 与 `timeout_seconds`。预算触发会保留 flow 行并写入 `analysis_gaps`，不静默删除，也不转成“无漏洞”；
- 所有新增记录、候选和预算摘要继续保持 `claim_status=not-a-finding`、`confidence=heuristic-nearby`、`requires_manual_dataflow=true`，不影响 S4/G4/G5、CVSS、Novelty 或 confirmed 状态。

验收用例覆盖三段参数传播、局部别名返回和预算耗尽；该测试证明的是静态线索的可追踪性，不是历史 CVE recall/precision 或运行时效果。

## 阶段 36 初步实现：有界跨符号调用点参数/返回绑定

阶段 35 已经能判断“控制看起来是否保护了 sink 所在的分支，以及检查对象是否接近操作对象”，但跨符号路径仍会在调用边处留下 `cross-symbol-unresolved`：模型知道 handler 调用了哪个 helper，却无法从有限证据判断外部输入究竟以哪个参数进入 helper、helper 是否把它传给 sink，或返回值是否把污染重新带回上层。阶段 36 增加独立的 `semantic-call-evidence-v1`，把这段最常见的一跳桥接显式化：

- 对 flow 中相邻的调用边解析有限的调用点实参和被调符号形参，区分 `direct`、`propagated`、`literal`、`unresolved`、`arity-unresolved`、`bound` 与 `not-bound`；污染参数只沿已发现的一跳边传播，不把名字相似当成完整类型或别名证明；
- 在被调符号的有限范围内记录返回语句是否引用污染形参，形成 `tainted-return-likely`、`not-observed` 或 unresolved 的返回形状提示；这只帮助 S3 选择复核点，不声称真实返回值、异常路径、容器元素或异步回调已经被证明；
- 将最终 sink 实参与这条有界绑定链对齐，区分 `bound`、`not-bound`、`unresolved` 和 `not-applicable`，并对未闭合的跨符号路径生成 `semantic-interprocedural-binding` 研究候选，进入 S2 的完整静态候选池；
- 产物与 CLI 为 `state/<target>/coverage/semantic-call-evidence.json`、`semantic-call-candidates.json` 和 `python3 scripts/agent_cli.py semantic-calls <target> --workspace <audit-dir> --show-candidates --json`。实现刻意不建模 CFG、完整类型/别名、virtual dispatch、DI、reflection、callback、async 或 sanitizer 语义；所有记录、摘要和候选仍保持 `claim_status=not-a-finding`、`confidence=heuristic-nearby`、`requires_manual_dataflow=true`，必须由 S3/S4 补真实数据流与效果证据。

## 阶段 37 初步实现：有界控制流关系与备用路径

阶段 35 的 branch posture 和阶段 36 的调用点绑定已经能指出“检查存在”和“输入可能沿调用边传播”，但还不能稳定地区分 sink 位于被保护分支内、位于拒绝分支之后，还是落在 `else`/`except` 备用路径。阶段 37 增加独立的 `semantic-controlflow-evidence-v1`：

- 按源码文件构建有上限的 brace/indent 分支区间和 branch group，记录 `terminating-guard-likely`、`enclosing-branch-likely`、`alternate-path-likely`、`same-block-unverified`、`after-sink`、`same-line` 与 unresolved 关系；`dominates-likely` 只表示结构形状足以安排人工追踪，不是 CFG dominance 证明；
- 对 `if`/`elif`/`else`、`try`/`except`/`finally`、`switch`/`case` 等有限兄弟分支建立可引用的 alternate-path 状态，避免把“同一 handler 出现过授权调用”误认为所有 sink 分支都被保护；
- 对可能的终止拒绝分支记录 sink 是否位于分支体之外，对同块普通检查保留 `same-block-unverified`；不推断返回/异常、循环、短路、fallthrough、宏、路径可行性或对象身份；
- 对满足原有 control-map 前置条件且关系未闭合的路径生成 `semantic-controlflow-gap` 的稳定 `cfg-*` 候选，写入完整 S2 静态候选池。产物不保存源码原文，所有摘要、行和候选保持 `claim_status=not-a-finding`、`confidence=heuristic-nearby`、`requires_manual_dataflow=true`，S3/S4 仍必须补真实 CFG、授权和 typed-effect 证据；
- 产物与 CLI 为 `state/<target>/coverage/semantic-controlflow-evidence.json`、`semantic-controlflow-candidates.json` 和 `python3 scripts/agent_cli.py semantic-controlflow <target> --workspace <audit-dir> --show-candidates --json`。后续可以用 AST/CFG、类型和运行时分支观测替换这一结构启发式，而不改变既有闸门。

## 阶段 38 初步实现：Python AST 结构见证与解析缺口

阶段 37 的 brace/indent 区间已经能跨语言安排控制流人工追踪，但对 Python 仍会把语法树作用域、`else`/异常 handler 和直接 `return`/`raise` 终止形状压缩成行号猜测。阶段 38 增加独立的 `semantic-ast-evidence-v1`：

- 每个有界 Python 文件只解析一次，建立函数/类作用域、`if`、`try`/handler、循环和 `match` 的分支部件索引；对每条已有 guard/sink 关系只保存节点种类、分支 ID、归一化行区间和作用域区间，不保存源码原文或 AST dump；
- 用语法树区分 `ast-terminating-guard`、`ast-enclosing-branch`、`ast-alternate-path`、`ast-same-block-unverified`、`ast-cross-scope-unverified`、`ast-parse-failed` 等结构状态，作为 Stage 37 词法关系的独立交叉证据；
- 直接 `return`/`raise` 只作为终止形状见证；异常、循环、装饰器、动态导入、动态 dispatch、类型/对象身份、sanitizer 和路径可行性仍要求人工与 S4 证据；解析失败、不支持语言和超限文件保持 analysis gap，绝不作为安全负证据；
- 对 guarded/partial 且关系未闭合的路径生成稳定 `ast-*` 候选，加入 S2 静态候选池。记录和候选始终保持 `claim_status=not-a-finding`、`confidence=heuristic-nearby`、`requires_manual_dataflow=true`，不改变候选状态、CVSS、G4/G5；
- 产物与 CLI 为 `state/<target>/coverage/semantic-ast-evidence.json`、`semantic-ast-candidates.json` 和 `python3 scripts/agent_cli.py semantic-ast <target> --workspace <audit-dir> --show-candidates --json`。其他语言继续使用既有通用控制流证据，后续可增加对应的语法/类型适配器。

## 阶段 39 实现：变换结果绑定与清洗失效线索

阶段 34–38 已经逐步回答“控制是否出现、是否在 sink 前、是否看起来位于正确分支以及跨符号输入是否可能传播”，但仍缺少一个直接影响真实漏洞判断的问题：控制调用返回的值是否就是 sink 最终消费的值。很多真实缺陷不是没有调用清洗 API，而是调用结果被丢弃、结果变量后来被原始输入覆盖，或值通过未解析别名进入 sink。阶段 39 增加独立的 `semantic-transform-evidence-v1`：

- 对 semantic path 中属于 validation、sanitization、allowlist、length/depth limit、path/origin/signature check 和 CSRF 的控制，在同一文件/符号内做有界调用识别、赋值识别和一跳别名追踪；只保存变量 token、行号、控制 ID、sink ID 和固定关系枚举，不保存源码原文、payload 或 API 输出；
- 区分 `assignment-bound`、`direct-bound`、`guard-condition`、`not-bound`、`transform-result-discarded`、`validator-result-discarded`、`overwritten-after-transform`、`after-sink`、`cross-symbol-unresolved` 和 `transform-unresolved`。`bound` 只是选择后续 trace 的正向静态信号，gap 是人工复核任务，不是漏洞或安全结论；
- 对 static control map 已判为 guarded/partial 且变换绑定未闭合的路径生成稳定 `xform-*` 候选，候选包含 entry/control/sink 位置、变换关系、需要确认的 API 返回/原地修改/异常语义以及 typed-effect/运行时验证要求，并加入完整 S2 静态候选池；
- S1 coverage、config-driven 和 autonomous 管线共用同一 artifact，`semantic-transforms` CLI 可单独查看或触发覆盖索引重建。记录和候选始终保持 `claim_status=not-a-finding`、`confidence=heuristic-nearby`、`requires_manual_dataflow=true`，不会改变候选状态、CVSS、G4/G5；
- 该层的后续升级顺序是：先用真实项目回放校准误报/漏报，再增加语言 AST/类型/SSA 适配，最后才允许把某些 API 的语义作为显式、可审计的 allowlist 知识输入；绝不把函数名本身当成“已安全”。

## 阶段 40 实现：语言感知值绑定与混合路径

阶段 39 的词法绑定可以指出“清洗结果似乎被丢弃或覆盖”，但它无法可靠处理 Python 的嵌套分支、异常处理、循环和语法作用域。阶段 40 增加 `semantic-python-binding-evidence-v1`，把这一层升级为可审计的语言适配器：

- Python 文件只在有界字节数和 AST 节点数内解析一次；根据已有 transform flow 的 control/sink 位置选择函数作用域，跟踪参数、简单别名、直接赋值、表达式派生和有限分支/异常/循环路径；不保存源码原文、AST dump、payload 或运行时输出；
- 对每条控制记录区分 `ast-bound`、`ast-raw-at-sink`、`ast-guard-condition`、`ast-branch-merged`、`ast-derived-value`、`ast-unresolved`、sink 未到达、解析失败和 `unsupported-language`。路径合并保留原值与变换值的差异，不把某一条安全路径覆盖成整体安全；
- 对 static control map 已判为 guarded/partial 且值流未闭合的路径生成稳定 `pybind-*` 候选，加入完整 S2 静态池；候选保持 `claim_status=not-a-finding`、`confidence=heuristic-nearby`、`requires_manual_dataflow=true`，不改变候选状态、CVSS、G4/G5；
- S1 coverage、config-driven、autonomous 与 `semantic-bindings` CLI 共用同一 artifact。Java、Go、JavaScript 等未实现 AST backend 的语言保留明确 adapter gap，下一步再按语言增加后端；
- 适配器不是完整 CFG、SSA、类型系统或 sanitizer allowlist。下一阶段应先用真实项目/固定样例的正向、负向、混合路径 replay 校准，再增加类型与显式 API 语义证据，不能把函数名直接当作安全证明。
