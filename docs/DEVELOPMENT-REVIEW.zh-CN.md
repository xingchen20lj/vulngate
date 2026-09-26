# VulnGate 代码审阅与后续开发整改路线

审阅基线：`898015d`（2026-09-23）

审阅范围：仓库说明和架构文档、S1–S8 编排与 G0–G5 闸门、PoC 运行与结果归并、Novelty/CVSS、源码覆盖与依赖检查、回放评测、CLI 适配，以及相关测试。
项目定位依据：[README.zh-CN.md](../README.zh-CN.md)：VulnGate 要把漏洞假设生成和安全结论裁决分开，让结论强度受可复现、可追溯证据约束。

## 总体判断

项目的设计目标清晰，已形成较完整的研究流水线：源码线索进入候选，候选经过 PoC 矩阵、Novelty、严重性校准和最终账本；执行状态、证据来源和“不是漏洞结论”的评测元数据也已成为显式概念。相关文档强调环境失败不能当作漏洞不存在、查询失败不能当作没有公开披露，这些原则符合项目定位。

当前主要风险在于，若干关键决策仍把 PoC 自行打印的文本当作独立观测，或在汇总阶段把“没有证据”压成“排除”。这会让项目最重要的证据忠实度、结论资格和前置条件诚实性在少数路径上失效。另有 CVSS 公式错误、Novelty 查询错误状态丢失、最终 G5 检查可缺省、矩阵回放串候选等问题。建议先收紧结论升级和隔离边界，再扩展分析能力或增加新的工作流。

本次验证：仓库测试命令 `PYTHONPATH=scripts python3 -m unittest discover -s tests -t tests -v` 在该基线运行通过，673 项测试通过。另对下列关键边界做了独立的最小化函数级核对；这些核对用于确认代码路径行为，不执行外部 PoC 或网络扫描。测试通过说明现有契约被测试接受，不代表下文列出的语义漏洞已被排除。

## 当前实现中值得保留的基础

- README 对系统边界有明确表述：模型提出假设，确定性组件裁决证据；G0–G5 与 S1–S8 的职责有文档说明。
- 运行时结果已区分编译、环境、闸门和执行状态；存在 `conclusion.py` 作为结论判断入口，并在 S8 再做完整性检查。
- PoC 命令包含超时、进程组回收、有限环境变量和工作目录检查；代码也尝试在执行前扫描外连目标。
- 回放包包含摘要和来源信息，评测结果明确标注 `not-a-finding`，有利于避免把基准分数误写成漏洞结论。
- 测试规模较大且全量通过，适合逐步改为针对结论不变量和端到端状态迁移的测试。

## 问题与风险

优先级含义：**P0** 表示会直接破坏“证据决定结论”的核心保障，应在继续扩大自动确认能力前修复；**P1** 表示可能错误确认、排除、归因或夸大研究有效性；**P2** 表示功能结果不可靠或可维护性不足。

| 优先级 | 问题 | 代码依据与影响 |
| --- | --- | --- |
| P0 | **PoC 自报字符串可被当成实际漏洞效果。** 解析器把 stdout/stderr 中的 `EVIDENCE`、`HTTP_CODE`、`RESP_MATCH`、`LEAKED` 等文本收为 observation；汇总逻辑仅检查字符串是否非空及少量占位符规则，结论逻辑随后可以据此确认。PoC 是被审计模型或用户控制的程序，打印“成功”不能证明响应真实、主体身份变化或副作用发生。最小核对中，PoC 输出 `HTTP_CODE=403`、`EVIDENCE=admin: true` 且退出码为 0 时可走到“确认”；退出码为 1 的相同自报证据也未由结论入口统一拒绝。 | [build.py](../scripts/agent/tools/build.py#L353-L388)、[build.py](../scripts/agent/tools/build.py#L1223-L1238)、[conclusion.py](../scripts/agent/tools/conclusion.py#L191-L208) |
| P0 | **执行失败/被阻断与“已执行但无效果”仍有混淆路径。** `derive_conclusion` 在没有强正证据时把 `gate_blocked` 或任意运行错误映射为“排除”；`pipeline._conclusions` 对 `intended_conclusion=排除` 只要有任意 cell 运行就强制返回“排除”。这与 README 明确区分 `run-failed`、`gate-blocked`、`precondition-unavailable`、`executed-no-effect` 的原则不一致，会把环境不满足或运行器问题误报成反证。相反，PoC 成功输出 marker 时还可能覆盖失败退出状态。 | [conclusion.py](../scripts/agent/tools/conclusion.py#L157-L177)、[conclusion.py](../scripts/agent/tools/conclusion.py#L245-L248)、[pipeline.py](../scripts/agent/orchestrator/pipeline.py#L37-L52) |
| P1 | **Novelty 搜索命中和 NVD 查询失败未可靠传递到最终判定。** CLI 对 `search()` 仅处理 `None`（查询失败），没有把成功搜索的 hits 转成 `UpstreamRef` 交给 `evaluate()`；最小核对中，即使搜索返回一条既有 issue，CLI 仍返回 `candidate-0day` 且 refs 为空。另一个路径中，`scan_nvd()` 将网络失败写入 channel note 而非 `errors`，`run_s5` 的 `query_failed` 又只读取 `pub.errors` 等字段；因此仅 NVD 查询失败时可能被当成“查无公开记录”。 | [agent_cli.py](../scripts/agent_cli.py#L388-L404)、[public_scan.py](../scripts/agent/tools/public_scan.py#L131-L168)、[public_scan.py](../scripts/agent/tools/public_scan.py#L210-L244)、[stages.py](../scripts/agent/orchestrator/stages.py#L1256-L1264) |
| P1 | **CVSS 3.1 计算不符合标准。** 当 C/I/A 都为 `N` 时当前公式仍会仅凭可利用性给出非零分；CVSS 3.1 规定 Impact 为 0 时 Base Score 必须为 0。`PR` 常量只使用未改变 Scope 的权重，Scope 改变时 `PR:L`、`PR:H` 应分别采用 0.68、0.50，而当前仍用 0.62、0.27。最小核对发现全零影响向量得到 3.9，改变 Scope 且 `PR:H` 的向量得到偏低分。向量解析也未校验必需字段、重复字段和非法取值，错误输入可抛异常或被默认接受。 | [cvss.py](../scripts/agent/tools/cvss.py#L9-L13)、[cvss.py](../scripts/agent/tools/cvss.py#L35-L58)。标准：[FIRST CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document) |
| P1 | **最终 S8 没有把 G5 作为必需闸门。** S8 仅在 candidate id 存在于 `severities` 时检查 G5；若 severity 记录缺失，已确认结论不会因缺少 CVSS/G5 而降级。最终边界应对缺失、异常和未执行的闸门一律 fail closed，并将缺失状态写入 ledger。 | [stages.py](../scripts/agent/orchestrator/stages.py#L1516-L1531) |
| P1 | **“loopback-only” 是静态文本策略，不是执行隔离。** `scan_source_egress` 用正则查找 URL/IP 与 `0.0.0.0`/`::` 字面量；最小核对中，`socket.socket().bind(("", 0))` 未被扫描器拒绝，但空地址通常表示绑定所有接口。变量拼接、间接调用和库封装也不由词面扫描提供可靠边界。PoC 仍由当前用户权限直接运行，因此不能把该策略描述成网络沙箱。 | [build.py](../scripts/agent/tools/build.py#L49-L81)、[runner.py](../scripts/agent/sandbox/runner.py#L129-L180)、[build.py](../scripts/agent/tools/build.py#L626-L675) |
| P1 | **候选身份没有贯穿 S4 回放合并。** `_extract_s4_cells()` 收到 `candidate_id`，但对于 `cells`、`fallback_cells`、`matrix_cells` 直接返回全部单元，没有过滤 cell 自带的候选身份。扫描同一 S4 目录下的 fallback 文件后，候选 B 的运行证据可能被合并进候选 A，进而污染结论与 G4。 | [build.py](../scripts/agent/tools/build.py#L967-L981)、[build.py](../scripts/agent/tools/build.py#L984-L1033) |
| P1 | **源码覆盖记录会漏掉安全控制，也可能把文件级线索扩张成整文件覆盖。** `CandidateCoverageRecord` 没有 `controls` 字段；构建阶段虽计算 `matched_controls`，但只用于 categories，应用阶段读取 `record.controls`，所以安全控制不会被候选标记。另一方面，若候选只提供 `entry_file` 或无行号位置，`_touches()` 会把同文件所有入口、sink 等视为命中；这类启发式可能使无关区域被标为 reviewed/excluded。 | [models.py](../scripts/agent/analysis/models.py#L448-L475)、[coverage.py](../scripts/agent/analysis/coverage.py#L438-L457)、[coverage.py](../scripts/agent/analysis/coverage.py#L484-L513)、[coverage.py](../scripts/agent/analysis/coverage.py#L528-L553) |
| P1 | **回放 Cohort 可把同一份研究包重复计算为多个独立项目。** project id 由调用者提供的 label 与 calibration history digest 生成，而不是由 provenance / pack digest 所代表的独立研究来源生成。现有测试用同一个 pack 配三个标签，并断言三个 provenance-eligible 项目和 calibrated 状态；这会让“至少三个项目”的样本门槛被重复输入满足，夸大校准证据。 | [replay_cohort.py](../scripts/agent/evaluation/replay_cohort.py#L194-L201)、[replay_cohort.py](../scripts/agent/evaluation/replay_cohort.py#L232-L249)、[test_replay_pack.py](../tests/test_replay_pack.py#L236-L248) |
| P1 | **source-evidence CLI 未把文件路径限制在指定 root。** `root / args.file` 可以接受绝对路径或 `..` 逃逸；随后会读取文件并回传内容。若模型生成的路径参数越界，可能将审计目标外的本机文件内容带入会话。 | [agent_cli.py](../scripts/agent_cli.py#L172-L184) |
| P2 | **独立 CLI 适配丢失实验契约字段。** `_matrix_cell` 未从输入读取 `residual_contracts`、`variant_context`、`consistency_lane` 等字段，`_shell_poc_spec` 也未保留声明的 URLs 映射。经此 CLI 运行的 cell 与流水线直接构造的 cell 语义不同，残余测试、变体测试或一致性记录可能被静默跳过。 | [agent_cli.py](../scripts/agent_cli.py#L188-L238) |
| P2 | **依赖检查器对部分已声明生态缺少有效解析，修复版本比较也不正确。** `Cargo.toml` 和 Gradle 文件被送入 requirements.txt 风格解析器；`composer.json` 复用 npm parser，但读取的是 `dependencies`/`devDependencies`，而 Composer 常用 `require`/`require-dev`。此外 fixed version 通过字符串 `max()` 选择，`1.9.0` 会胜过较新的 `1.10.0`。依赖扫描会因此漏报或给出不正确修复建议。 | [deps.py](../scripts/agent/tools/deps.py#L78-L143)、[deps.py](../scripts/agent/tools/deps.py#L191-L202) |

## 后续开发顺序

### 阶段一：修复结论可信度边界

1. **把“声明”与“观测”分成不同数据类型。** PoC stdout 中的字段只能代表 PoC 声称发生的事；确认结论必须来自 runner/harness 生成的观测记录。HTTP 结果由测试 harness 发起请求并解析真实响应；文件、数据库、进程等副作用由受控 fixture 或系统观测器核实。每条观测绑定 `run_id`、`candidate_id`、`cell_id`、PoC/source digest、目标 digest、退出状态和采集器版本。
2. **建立单一、穷尽的执行状态机。** 至少保留 `unexecuted`、`run-failed`、`gate-blocked`、`precondition-unavailable`、`executed-no-effect`、`executed-with-effect`。只有矩阵覆盖达到声明要求、正负控制有效且确实执行完毕时，才允许排除；任何未知状态、harness 错误或退出码异常都应是待验证。
3. **统一确认条件。** 不同漏洞类别分别定义可机器验证的 effect contract。通用 marker 不能作为证据；`INSTANTIATED`、`NETWORK` 等只可支撑它们各自语义允许的结论，不能自动升级成 RCE。缺失或相互矛盾的观测应拒绝确认并列明具体原因。
4. **让 S8 对缺失闸门 fail closed。** 对确认候选逐一要求 G3、G4、G5 的明确结果；未运行、缺字段、解析失败都不是通过。S7 报告与最终 ledger 使用同一份经过闸门的结论对象，避免中间报告和收尾账本状态不一致。

### 阶段二：修复 Novelty 与严重性计算

1. **给每个公开信息渠道记录 typed 状态。** 至少区分 `success-with-hits`、`success-empty`、`failed`、`rate-limited`、`offline`；全部要求的渠道成功完成后才能把“未发现公开记录”作为有效 Novelty 证据。将 NVD 失败从 channel note 映射到失败状态。
2. **修复 CLI 搜索闭环。** 将 search hits 规范化为 `UpstreamRef`，连同 issue/PR lookup 结果统一交给 `NoveltyChecker.evaluate()`；CLI 输出中的 refs、查询状态、判断理由必须能从同一输入重现。
3. **按 FIRST 向量测试修复 CVSS。** 在实现中显式区分 Scope U/C 的 PR 权重，处理 Impact 为零的规则，严格校验 v3.1 必需 metric 与允许值。把 FIRST 标准示例作为 golden vectors，并加入属性测试，与独立权威实现逐向量比较。

### 阶段三：收紧执行隔离与身份/路径边界

1. **为 PoC 使用真正的操作系统级隔离。** 默认禁止网络，通过 network namespace 或平台沙箱显式开放 loopback；限制文件系统为只读目标输入和独立临时目录，限制 CPU、内存、进程数、文件数与执行时间。若当前平台不支持所需隔离，停止执行并标记 `environment-unavailable`，不能退回到正则策略后继续声称 loopback-only。
2. **对所有文件读写路径做规范化与 containment 校验。** 对 source path、extra sources、shell script、target、candidate id、fallback artifact 和输出目录 resolve 后检查必须位于授权 root；拒绝绝对路径、路径穿越和符号链接逃逸。source-evidence 返回内容前先做同样校验。
3. **按 candidate id 强校验运行证据。** 每条 S4 cell 都必须有唯一候选身份和稳定 cell id；读取 fallback 时过滤身份不匹配或身份缺失的记录，目录文件名和记录体的身份必须一致，不允许“尽力归并”。

### 阶段四：让覆盖与评测真正代表研究进展

1. 为 coverage record 增加 controls 并端到端持久化；没有精确行号的 file-level 匹配只能写为低置信度 lead，不能据此关闭整文件的所有入口或 sink。展示候选触及区域和覆盖原因，reviewed/excluded 变更需要对应证据。
2. Cohort 的独立性应基于可校验的项目/来源身份和 provenance，而不是用户可重复改变的 label。相同 pack digest 或相同 history digest 不得重复计为独立样本；测试应明确验证相同输入的重复不会达到 cohort 最低样本数。
3. 给 Cargo、Composer、Gradle 使用各自的解析器；版本范围和修复版本使用语义版本/生态专属比较器。无法解析时应显示 unsupported/unknown，而非表现为扫描无依赖。
4. 统一 CLI 与 pipeline 的输入 schema，采用带 `schema_version` 的规范模型；拒绝未知关键字段或至少将未消费字段显式报告，防止实验契约静默丢失。

## 验收标准

以下标准通过前，不建议把自动生成的确认、排除、0day 或 CVSS 标签作为高可信结果输出：

- **反伪造：** PoC 只打印 `HTTP_CODE=200`、`RESP_MATCH`、`EVIDENCE`、`LEAKED`、`INSTANTIATED` 等字符串时，结论保持待验证；harness 独立观察到效果且运行成功后才能升级。
- **失败状态：** 非零退出、编译失败、依赖缺失、前置条件不可用、策略拦截和 harness 异常均不能变成“排除”；完整执行但无效果应有正负控制和覆盖声明。
- **Novelty：** 搜索到既有 issue/PR 必须反映在 refs 和结论中；任何必需渠道失败、离线或限流都不得产出可主张的 `candidate-0day`。
- **CVSS：** FIRST v3.1 示例、Scope U/C 的 PR 权重、全零影响和非法/缺字段向量均有回归覆盖，结果与权威标准一致。
- **最终闸门：** 任一确认候选缺少 G3/G4/G5 记录、闸门结果未知或闸门失败，S8 都只能输出待验证；S7 文档和 ledger 状态一致。
- **归属和隔离：** 同目录混合候选的 fallback 不串证据；路径穿越/符号链接越界被拒绝；无法证明网络隔离时 PoC 不运行。
- **覆盖和 cohort：** 控制项有可追踪的 review state；模糊 file-level 命中不会关闭整文件；重复 pack 不增加独立项目数。
- **端到端闭环：** 至少有一组人工设计的完整案例覆盖“真实确认、真实排除、运行失败、阻断、Novelty 命中、Novelty 查询失败、CVSS 缺失”，逐项检查产出的报告和 ledger，而不只测试独立 helper。

## 建议的研发纪律

- 每个漏洞类别先写 evidence contract 与反例，再扩展 PoC 自动化；用不可信 PoC 作为对抗输入审计结论管线。
- 结论状态只在一个模块中定义和迁移；各阶段产出有版本的结构化证据，不再通过模糊 stdout marker 共享语义。
- 把“未知/不完整”作为正常的最终结果，并在 CLI、报告、账本和评测中保持一致。
- 将静态分析候选、运行时观测、上游公开记录和人工判断分别标注来源、置信度与推导关系，不允许静态启发式悄然成为验证结果。
- 每次修复先加入能失败的回归用例，再调整实现；系统级边界需有端到端验证，不用 helper 单测替代整个证据链的验证。

## 审阅边界

这份文档是对项目设计目标、主要生产路径和相关测试的工程/安全审阅，不是对所有支持语言和每个分支作形式化证明，也没有执行对外目标、真实网络攻击或目标环境中的 PoC。静态分析与正则扫描的覆盖率、第三方 API 实际行为及目标项目差异仍需按具体运行环境补充验证。文中优先级针对 VulnGate 自身结论可靠性和本机执行边界，不是外部漏洞的 CVSS 评估。

## 2026-09-25 整改状态

本轮已落实并验证：

- PoC 的 stdout/stderr marker 统一留在 `poc_claims`，不能直接成为 S4 observation；macOS 本机 HTTP 集成用真实 403 响应对照 PoC 伪造的 `HTTP_CODE=200`，最终只采信 observer 捕获的 403。
- S4 证据策略版本集中定义，汇总器、裁决器、G4 与后续阶段使用同一版本，修复了 v4 产物被 v2 检查拒绝的问题。
- POSIX PoC runner 现将 hard CPU、最高 4 GiB（或更低 inherited cap）的每进程虚拟地址空间、文件大小、打开文件、real-UID 进程数（启动基线 +128）和 core dump 上限直接应用到目标及其继承进程；限额由预检确认，逐 cell 写入 provenance，可信观测要求它与 runner policy 匹配。另有 250 毫秒 scratch 抽样止损（256 MiB / 4096 项），但不是硬配额，无法限制采样间隔内增长或已 unlink 的打开文件；进程树 RSS 有 100 毫秒抽样、2 GiB 阈值的尽力止损（不是内核硬配额，求和可能重复计共享页）。UID 级进程上限不是隔离进程树。
- macOS Seatbelt profile 在执行前预检；HTTP shell cell 限制到对应 observer 端口，其他 shell/Java 编译与运行拒绝网络。Java 网络 PoC 在缺少独立 observer 时停止，不把“无响应”当作反证。
- macOS 实测发现 Seatbelt 的 `localhost` 地址过滤器不等于“仅 127.0.0.1”：同端口的本机其他网卡地址也可连接。网络策略标识和文档已据此修正。runtime-lab 服务需要入站监听，不能安全套用 PoC profile；无 OS 沙箱的托管服务现在默认拒绝启动，只有显式 `allow_unconfined_start: true` 才启动。健康检查将 localhost alias 固定映射到数字 loopback 地址，拒绝依赖系统 DNS/hosts 的任意名字。
- S4 轮次与候选有时间预算；回放 cohort 按 pack/history digest 去重；S4 汇总按候选身份过滤；源文件、脚本、输出和回退产物路径执行 containment 校验。
- 覆盖记录保留安全控制并要求行级位置；文件级命中不会关闭整文件区域。Novelty、CVSS、G5 缺失处理、CLI 契约字段和依赖生态解析也已按审阅项修正。
- 配置驱动管线默认在 S1 范围 incomplete/invalid 时停止；显式启用 `allow_partial_coverage` 后，只验证配置候选并绕过旧索引候选与覆盖调度，S8 不刷新旧索引上的覆盖标记，目标覆盖摘要与本轮闭环都保持 `scope-incomplete`，高风险未覆盖数为未知。进入该模式会让旧下游 checkpoint 失效；带 partial 标记的新 checkpoint 可在中断后恢复。此处覆盖的是候选级验证，不是全仓完整性结论。
- 配置驱动 S1–S8 管线现在会创建或复用持久轮次 deadline，在每个阶段前后检查，到期后保存 `round-timebox-report.json` 并停止后续阶段；S4 时限压到剩余轮次预算。`audit_round_timeout_seconds` 只影响尚未创建 deadline 的新轮次，单轮硬上限为 90 分钟；旧版遗留的更长 deadline 在读取时按 90 分钟截断。S4 配置值也只允许调低 90 分钟轮次/15 分钟候选上限。通用 `CommandRunner` 另将单次命令截断到 15 分钟，并在 S4 保存是否截断的字段。阶段边界检查不能中断宿主模型/未接入工具的执行，需继续配合长操作止损规则。
- S1 危险模式和目标规则摘要现将每组带标签的 regex 合并为一次 `rg` 扫描，保留每个标签各自的截断数量；autonomous coverage 重建使用有界源码枚举，并持久化 running/complete/incomplete/failed。扫描不完整时不再从旧派生索引产生候选。
- 验证结果：最终全量 unittest 678 项通过；插件安装器校验、Python 编译和 `git diff --check` 通过。

此前记录的 678 项 unittest 结果只覆盖当时的运行快照，不覆盖之后新增的轮次 deadline、partial-coverage checkpoint。2026-09-25 续办段落的 691 项结果也只覆盖该段落所述快照，不自动代表后来追加的改动。

### 2026-09-25 续办整改

- 单阶段恢复现在先检查所有前置阶段 checkpoint、覆盖模式和策略版本；S5–S8 还要求关键前序产物存在。S3 保存的候选状态会在恢复时还原。单阶段重跑会记录需要重算的后续阶段，全流程续跑时不会跳过这些旧 checkpoint。
- autonomous 的覆盖提示和调度会核对当前 source scope；scope 失败或不匹配时，不再从旧索引调度候选。`run_agent` 和 `run_multi` 增加 `--force`，可对相同失败 scope 显式重试一次。
- 带标签的 ripgrep 扫描将 timeout 作为所有配置源码目录共享的总预算；ripgrep 非正常退出、结构化输出损坏或缺少匹配行内容时会报错，不会伪装成零命中。
- autonomous 在 S1 保存规则扫描超时状态，在候选源码扫描超时时保存 S0 进度并结束该轮；同一轮的 S2 复用 S1 已刷新的 capability inventory，避免再次刷新覆盖统计。
- 续办整改最终运行 `PYTHONPATH=scripts python3 -m unittest discover -s tests -t tests -v`：691 项全部通过。覆盖范围包括阶段恢复失效、旧覆盖范围拒绝、超时与 rg 错误状态、Seatbelt 多行策略参数解析、S4 回放、轮内候选关键词锚点复用，以及有限标签扫描的流式早停。另在临时源码树上验证真实 ripgrep 流程。尚未用真实目标跑完一轮 S0–S8 并审阅最终报告/ledger，因此测试通过不等于端到端审计结果已验证。插件已刷新至 `1.2.0+codex.local-20260925-054133`，manifest inline validation 通过，130 个待安装文件与 active cache 比对一致（manifest 仅规范化本地版本号）；`git diff --check` 通过。

仍未闭环的边界：

- 当前 Seatbelt profile 将 PoC 写入限制在每次运行的 scratch/output 路径，并采用默认拒绝的读取白名单：只开放标准系统工具、系统运行库/框架、已安装的 CLT/Xcode/Cryptex 运行时、本轮 workspace 和明确配置的 runtime 根目录。用户主目录、挂载卷和临时目录默认拒绝，workspace/runtime 子树按路径例外放行；Keychain、本机账户数据库、SSH 配置/主机密钥、sudoers 和 Kerberos keytab 即使位于允许根目录下也保持拒绝。PoC PATH 限定为 `/usr/bin:/bin:/usr/sbin:/sbin`。POSIX runner 另外限制每进程 CPU 时间、最高 4 GiB 的虚拟地址空间、单文件大小、打开文件数、core dump，并把 real-UID 进程数限制在启动基线 +128。scratch 树每 250 毫秒抽样，超过 256 MiB 或 4096 项时尝试终止被跟踪的进程组；这只是尽力而为的止损，不能限制采样间隔内增长或已 unlink 的打开文件，进程树 RSS 有 100 毫秒抽样、2 GiB 阈值的尽力止损（不是内核硬配额，求和可能重复计共享页）。Seatbelt 拒绝直接 `setsid` / `setpgid` 系统调用，能拦住常见的进程组逃逸方式；runner 在命令关闭 stdout/stderr 时仍执行墙钟截止检查，并在主进程退出后尝试回收原进程组。但 Darwin `posix_spawn` 属性仍能请求新进程组/会话。**PoC 和托管 runtime-lab 服务的 RSS watcher 都是可能 overshoot 的抽样止损，PID/启动时间清理也可能漏掉两次采样间脱离并重新托管的进程；外部已就绪服务不受 VulnGate 管理或监控**。托管服务仍不继承 Seatbelt 网络/文件系统策略，且只在 `allow_unconfined_start: true` 时启动；这不是完整 OS 沙箱。
- 独立运行时采集目前只覆盖受限的 plain-HTTP response metadata。文件/数据库/进程等副作用仍需对应 harness observer；PoC 自报的 marker 会保留为声明，因此缺少独立采集器时结论保持待验证。
- 配置驱动管线在阶段边界检查 90 分钟持久 deadline，并将剩余预算传给 S4；CLI 矩阵也会消费该预算。宿主原生工作流仍依赖技能在长操作前检查；这些机制都不能中断宿主 Agent 的任意推理、正在运行的长阶段或未接入 VulnGate CLI 的工具调用。应按工作流 stop-loss 理解，不能宣传为进程级强制终止器。
- autonomous 每轮仍会刷新若干全仓源码摘要；有限 S1 与候选提示扫描现在流式消费 rg 输出，仅保留各标签上限，满足全部上限后提前停止；S1.5/S2/S3/S4 复用有界文件快照与按内容摘要失效的片段缓存。该缓存仍不覆盖全仓索引/摘要。本轮已把同文件 source/sink 摘要改为 Git-index-aware 源文件遍历，默认最多 120 秒并在超时产物中标记 incomplete；危险模式与目标规则也已合并为一次扫描。后续应让剩余摘要复用同一源文件清单和总预算。

### 2026-09-25 library 入口扫描合并

- 复核发现，autonomous 新 target 准备阶段仍对 10 种 library API 分别运行完整 `rg` 扫描；每次默认 10 分钟，且发生在持久轮次 deadline 创建前，可能让候选验证迟迟无法开始。
- 已改为使用 `scan_all_labeled_hits()` 将所有配置源码根和 API 模式合并为一次扫描，逐模式分类并保留全量入口结果、API 标签、输入形状和危险密度字段。整个源码根集合共享 `scan_all_hits()` 的 10 分钟 deadline，避免按 API 数和源码根数重复遍历。
- 本轮仅做 Python 静态编译、`git diff --check` 和扫描调用路径审阅；未运行测试或真实 target。需要后续用大仓库记录 preparation 扫描耗时，确认真实收益和输出等价。
- 另发现 `prepare_target()` 在轮次 deadline 创建前同步生成完整 coverage/capability inventory，和 candidate-first 设计冲突。已移除这次前置全仓构建：首批候选可先进入 S3/S4，已有 scope 匹配索引仍会复用；缺失索引按既有预算规则在候选波次后最多尝试一次 5 分钟重建。
- 本项只做静态控制流核对、Python 编译和 `git diff --check`；未跑测试或真实 target，仍需用大仓库确认启动耗时及候选调度行为。

### 2026-09-25 Seatbelt PoC 文件读取白名单

- 将 PoC 文件读取改为 Seatbelt 默认拒绝；明确允许标准 OS 工具 `/bin`、`/sbin`、`/usr/bin`、`/usr/sbin`、`/usr/libexec`，动态库/框架 `/usr/lib`、`/System/Library`，以及存在时的 Cryptex、Command Line Tools、Xcode 运行时，再加本轮 workspace 和显式 runtime roots。将可执行 OS 工具 roots 与只读/映射的库 roots 分开，避免为了动态链接而开放任意系统 helper 执行。
- 宽泛用户目录、挂载卷和临时目录仍被拒绝；只重新开放明确配置的 workspace/runtime 子树。Keychain、账户数据库、SSH 密钥/配置、sudoers 和 Kerberos keytab 规则最后生效，即使嵌套在系统 allow root 里也不能读取。PoC PATH 收紧到 `/usr/bin:/bin:/usr/sbin:/sbin`，Java 通过显式 runtime `JAVA_HOME` 运行。
- Seatbelt 网络/文件系统策略 ID、S4 shell/Java runner policy 版本与文档同步更新，旧隔离契约的 checkpoint 不会复用。runtime-lab 服务仍不继承 PoC 的 Seatbelt profile；PoC 与托管服务 RSS watcher 以及跨进程组后代清理都是尽力而为，外部已就绪服务不受监控；真实 S0–S8 端到端闭环仍待解决。
- 本轮不运行测试或目标 PoC；只做静态检查、Python 编译、`git diff --check`、安装器校验和 active cache 内容比对。

### 2026-09-25 候选优先与预算收口

- autonomous 轮次现在在 S1 只复用完整且 scope 匹配的已有 capability index；缺失或过期索引不会阻塞首批候选进入 S3/S4。S1 本轮 source→sink 摘要派生的复合链候选仍会进入首批候选，因为它们不依赖全量索引。首批候选完成后，剩余时间至少 15 分钟时才允许一次最长 5 分钟的补充索引；若 S2 没有候选，也允许一次有界索引尝试提供静态线索。补充线索进入下一轮候选，不覆盖本轮已调度候选；失败/部分索引仍不进入调度。运行时 deadline override 不写入持久化 scope 身份。
- 有限标签 ripgrep 提前停止后会关闭 stdout/stderr 管道并回收子进程；之前真实用例出现的未关闭文件描述符 `ResourceWarning` 已消失。
- 129,477 条合成候选的 intake-only 微基准在本机耗时 0.325 秒，输出 144 条 active window；这是候选 intake 阶段结果，不包含静态候选构造和完整覆盖索引时间，不能与旧审计总耗时直接比较。
- 当前代码快照全量运行 `PYTHONPATH=scripts python3 -m unittest discover -s tests -t tests -v`：697 项全部通过；`python3 -m compileall -q scripts tests` 与 `git diff --check` 通过。插件专用验证器因系统 Python 缺少 PyYAML 未能启动；仓库安装器按设计执行 inline manifest validation 并通过。
- 插件已用仓库 `install.sh` 刷新并启用为 `1.2.0+codex.local-20260925-060900`。将源工作树与 active cache 按安装器发布范围逐文件比较：137 个预期文件全部存在、内容一致（manifest 只比较版本号以外的字段）。尚未用真实目标完整跑一轮 autonomous 或 S0–S8，因此不能据此声称端到端审计质量已验证。

后续应优先为 runtime-lab 服务补齐 OS 级读取/网络隔离，并研究能真正区分 loopback 与本机其他网卡的服务隔离后端；PoC 与托管服务的 RSS watcher 和逃逸后代清理仍是尽力而为，外部已就绪服务不受监控。再逐类实现副作用 observer 和覆盖真实确认、真实排除、失败、阻断、Novelty 与 CVSS 的整条 S0–S8 报告/ledger 集成案例。未完成这些工作前，VulnGate 的安全边界是“macOS 上受限网络、PoC 文件读取白名单和受限写入 + 证据 fail-closed”，不是通用执行沙箱，也不支持把自动确认当成充分证明。

### 2026-09-25 审计时间预算绕过整改

- 只读检查 `Chromium-audit` 任务时，它已是 `notLoaded`，最后一轮已完成；最终任务摘要列出 8 条未验证线索，没有确认的高危/严重发现。S4 产物记录过 `CommandRunner` 接收 14,400 秒（4 小时）的构建请求；另一个 `browser_tests` 构建 1,004 秒仍未进入编译就被中断。本轮 S0 下没有持久 deadline 文件。该案例说明技能的 90 分钟说明和矩阵内预算，不能约束绕过矩阵直接调用通用 runner 的构建命令。
- 已将新轮次 deadline 上限统一收紧到 90 分钟；旧版更长的 persisted deadline 按原开始时间截断。S4 budget 将配置强制限制在 90 分钟/候选 15 分钟，通用 `CommandRunner` 将单次命令限制在 15 分钟；S4 产物记录请求值、实际值和是否截断，并更新 runner/evidence policy 版本使旧 checkpoint 失效。
- 本轮只做 Python 编译检查、`git diff --check`、安装器 inline manifest validation 和 137 个发布文件的源目录/cache 内容比对；未运行测试。active cache 已刷新到 `1.2.0+codex.local-20260925-064138`。这些时限不能强杀宿主模型推理或未接入 VulnGate 的工具。
- autonomous 的 `learn_api_hint()` 原先在 `run_loop` 前运行，未消费 S0 deadline；现移入 S1.5，调用前启动 deadline、调用后立即检查止损。S1.5–S4 的提示源码 `rg` 扫描超时同时限制为配置值与当前轮剩余预算中的较小值。S0 的 source-cache metrics 记录每轮读取、命中和耗时，给后续性能判断提供实际依据。

### 2026-09-25 候选源码片段缓存整改

- autonomous S1.5/S2/S3/S4 现在共用有界源码缓存。每轮未变化且仍在 LRU 中的锚定源码文件通常只读取一次；检测到文件变化或条目被淘汰时会重读。提取后的方法体/类头写入 `state/<target>/cache/` 下的原子 JSON 缓存，最多 512 条、2 MiB；单轮原始文件快照最多 16 MiB，解码行列表最多对应 2 MiB 源码、50,000 行。
- 持久缓存键绑定 source root 身份、相对路径、完整文件 SHA-256、锚点和提取策略版本。每个新轮次第一次访问文件仍会读取并计算 SHA-256，因此文件内容变化会 miss；缓存损坏或无法写入只丢失性能优化，不会改变源码提取结果或审计结论。
- 该优化减少入口摘要与候选阶段反复打开/解码同一文件，并允许跨轮复用提取结果；它仍需每轮至少读取每个被命中文件一次来确认内容摘要。全仓源码摘要尚未统一到这层缓存。
- 每轮遥测写入 `state/<target>/round-NN/S0/source-cache-metrics.json`，记录源码读取/哈希字节数、读取与解码耗时、缓存命中、提取与持久化耗时及终止状态；即使审计中断也会保存最后一次快照。遥测不包含源码内容，写入失败不会影响审计。
- 本轮只做 Python 编译、差异空白检查、安装器校验与 active cache 文件比对；未运行测试或真实目标审计，因此还没有实际命中率或耗时数据。遥测用于后续真实审计核实收益，不能把缓存存在本身当成性能提升证据。

### 2026-09-25 runtime-lab 服务资源限额

- `ServiceLifecycle` 原先在显式 `allow_unconfined_start` 后直接 `Popen`，托管服务绕过了 `CommandRunner` 的 POSIX 资源限额。现复用同一限额包装器并在启动目标前预检；不支持或预检失败时返回 `policy-denied`，不会退回无限制启动。
- 服务进程及其继承子进程收到每进程 CPU 1 小时、单文件 64 MiB、打开文件 512、启动 UID 进程基线 +128、core dump 0 的硬限额。服务结果和 `S4/processes.json` 保存实际限额；生命周期和进程注册 schema 已升级。
- 这些限额将每个服务进程的虚拟地址空间限制在最高 4 GiB，但不限制进程树累计 RSS、累计文件数、可读文件范围或网络；启动仍需显式接受无 OS 网络/文件系统隔离的边界。已就绪的外部服务不由 VulnGate 启动，因此也不享有这些托管进程限额。
- 本轮只做 Python 编译、差异空白检查、安装器校验和 active cache 文件比对；未运行测试或目标服务。真实 runtime-lab 使用兼容性仍待目标级验证。

### 2026-09-25 runner 关闭输出后的进程回收

- CommandRunner 之前只要 stdout/stderr 管道都关闭就退出读取循环；若命令仍在运行，会被过早杀掉，且后台子进程也可能留在原进程组内。现改为即使无打开管道也继续轮询主进程并执行墙钟截止检查；主进程/命令结束后额外向原进程组发送 SIGKILL。
- 因为 runner 对关闭输出的命令行为和收尾策略改变，S4 shell/Java runner policy 版本已递增，旧证据 checkpoint 不会按新策略复用。
- 仅做 Python 编译、差异空白检查、安装器 inline 校验和 active cache 文件比对；未运行测试或 PoC。Darwin `posix_spawn` 仍可请求独立 session/process group，越组进程和外部服务启动的任务仍不保证回收。

### 2026-09-25 Seatbelt 敏感宿主路径拒读（历史策略，后由完整读取白名单补齐）

- PoC 之前可读取用户主目录以外的任意宿主路径。现新增拒读规则：常见挂载根目录（/Volumes、/Network、/net）、每用户及共享临时目录、Keychain、SSH 配置/主机密钥、sudoers、Kerberos keytab 与本地账户数据库；本轮 workspace 和显式 runtime 子目录仍可访问，workspace 或 runtime 位于外接卷时，只重新开放明确配置的对应目录。
- 因网络/文件系统 profile 与 S4 可信观测策略身份变化，Seatbelt 网络/文件系统 policy id 及 shell/Java runner policy 版本递增，旧 checkpoint 不会按旧隔离契约复用。
- 该历史版本仍允许读取其它系统路径，尚未形成完整读取白名单；此边界已由后续“Seatbelt PoC 文件读取白名单”一节补齐。runtime-lab 服务仍不继承 PoC 的 Seatbelt profile。
- 本轮仅做 Python 编译、`git diff --check`、安装器 inline 校验及 active cache 文件比对；未运行测试、PoC 或完整 S0–S8 目标审计。

### 2026-09-25 runtime-lab 进程树 RSS 止损

- 显式启动的托管服务现在复用 PoC 进程树 RSS 采样器：100 毫秒抽样、2 GiB 聚合阈值。超限或进程表监控失败时，会终止已观测服务树、记录 `resource_limits.process_tree_rss` 与清理结果，并中止共享 S4 预算。
- 共享预算中止会让在途 `CommandRunner` 矩阵命令收尾、阻止后续矩阵单元和管线阶段启动；服务/进程 registry schema 与 shell/Java runner policy 版本已递增，使旧策略 checkpoint 失效。
- 这是抽样止损而非内核硬配额，可能 overshoot；PID/启动时间只覆盖已观测的后代。外部已就绪服务不由 VulnGate 管理，也不受此 watcher 监控。托管服务仍没有 Seatbelt 网络和文件读取隔离。
- 本轮仅做 Python 静态编译与 `git diff --check`，未运行测试、PoC 或目标服务；真实 runtime-lab 兼容性和端到端预算中止仍待目标级验证。

### 2026-09-25 进程树 PID 复用与启动采样竞态

- 进程树采样原先在根进程缺席时仍可能从它的 PID 继续遍历；若 PID 已复用，可能把无关进程误纳入并尝试终止。现在只在根 PID 的启动时间身份仍匹配时发现新后代；根进程消失后只保留此前已观察并按 PID/启动时间跟踪的后代。
- 托管服务的第一个进程树样本改为同步取得，发生在启动路径可能调用 `Popen.poll()` 并回收短命根进程之前。该样本建立根 PID 身份并记录可能被重新托管的子进程，随后再由后台 watcher 按 100 毫秒间隔采样。
- 本轮通过相关 Python 文件静态编译与 `git diff --check`；未运行测试、PoC 或目标服务。插件发布目录与活动缓存已更新至 `1.2.0+codex.20260925093836`，这两个改动文件逐字节比对一致。剩余风险是两次采样之间脱离并重新托管的后代可能漏追踪；RSS 仍是可 overshoot 的抽样止损。

### 2026-09-25 宿主审计命令轮次止损

- 新增 `agent_cli.py audit-exec`，要求目标/轮次已有持久 deadline。单命令时限取请求值、15 分钟全局上限和轮次剩余预算中的最小值，工作目录只能位于显式 source root 下；结果返回有限输出、命令摘要、预算前后快照和进程树清理状态，并以 `not-a-finding` 标注。
- 新增审计宿主命令精简环境，避免向目标构建/扫描子进程继承环境里的模型 API token、代理变量等；允许用户显式传递非敏感构建变量。此 wrapper 只约束命令时限与工作目录选择，不提供 OS 文件/网络隔离。
- 每轮命令摘要、运行耗时、退出状态、进程清理结果和 stdout/stderr 摘要哈希写入 `S0/host-command-runs.jsonl`。同一命令超时、失败、运行状态遗留或清理不完整后会拒绝原样重跑，除非调用者先检查旧进程，再说明源码范围或环境已实质变化。runner 的进程清理状态现在也会记录在非 PoC CommandRunner 结果中。
- `audit-exec` 会识别并拒绝 `env bash -c ...` 等常见 shell 包装；命令历史读取最多扫描日志尾部 16 MiB 和 4096 条记录，避免日志增长后读入整份文件。进程清理异常路径会再按 PID/启动时间身份发送终止信号并复核。
- 本轮仅做 Python 静态编译和 `git diff --check`，未运行测试或审计命令。插件已安装为 `1.2.0+codex.20260925101037`，运行时代码、技能和文档与活动缓存逐字节一致；manifest 由 JSON 检查通过。插件完整校验脚本未能启动，因为当前 Python 环境缺少 `PyYAML`。

### 2026-09-25 活动审计源码根工具守卫

- `audit-budget start --root` 和管线轮次启动现在会把 workspace、target、round、源码根及 deadline 登记到 `$CODEX_HOME/vulngate/active-audits.json`。文件更新使用锁和原子替换，并限制记录数量、文件大小和登记时限；轮次结束由 pipeline/autonomous 清理，异常退出后由 deadline 过期回收。
- 新增 Codex `PreToolUse` Bash hook：活动源码根内的工作目录或显式引用源码根的普通 shell 命令会被拒绝；同一 target/workspace/round/root 的 `audit-exec` 和轮次控制命令可继续使用，捆绑 CLI 的确定性操作也保留可用。轮次清理需匹配精确源码根，避免同一轮次 ID 的失败启动移除另一根目录的登记。
- hook 是 Codex 工具层护栏，需用户在 Codex 中审阅并信任；它不提供 OS 级强制隔离，未显式写出绝对源码路径的相对路径、专用工具路径或 hook 未加载时仍可能绕过。不得将其描述为完整命令沙箱。
- 本轮只做 Python 静态编译、JSON 解析、`git diff --check` 和发布目录/活动缓存逐文件对照；未运行测试或真实审计。插件安装版本为 `1.2.0+codex.20260925103746`，42 个变更发布路径与本地插件源及活动缓存逐字节一致。Hook 是否已在桌面端完成信任需用户在新 turn 中确认。

### 2026-09-25 到期止损与并行指引校正

- 发现过期登记会在 hook 读取时被自动清除，导致到期后普通 shell 不再受保护；现保留过期源码根登记，直到显式 release。到期后只允许匹配轮次的 status/release，pipeline/autonomous 发现预算已到期时保留登记，先让宿主报告进度再释放。
- 发现快速上手曾要求每个候选都并行 spawn，与技能中“按收益选择并行”冲突，容易把探针和协调开销强加到审计中。现统一为可选并行：任务独立且预计节省时间高于协调成本时才 spawn。
- 将 90 分钟描述修正为接入 runner、阶段边界和受信任 hook 的操作止损，不再声称能强制限制宿主模型推理或未接入工具的整个 turn。插件无法中断这些路径，宿主必须在长操作前后检查 deadline 并按到期报告停止。
- 本轮新增检查范围仅做静态源码审阅和文档核对；尚未执行测试、模拟过期 hook 事件或真实目标审计。以上 hook 行为的运行时可用性仍取决于 Codex 是否加载并信任插件 hook。

### 2026-09-25 新目标准备纳入轮次预算

- `--target-dir` 之前在 `run_round()` 创建持久 90 分钟 deadline 前，先同步执行类型识别、最长 10 分钟 rsync、入口扫描和无界递归 JAR 查找；因此名义上的 90 分钟预算并未覆盖审计启动阶段。
- 现在先为目标/轮次建立或读取同一持久预算，再进行新目标准备。准备阶段最多占用轮次开始后的 15 分钟，复制、入口扫描、JAR 导入和遍历共享这段时间；重试不会重新获得 15 分钟。入口扫描跨多个源码根共享 deadline。超时写入 `S0/target-preparation-status.json`，包含阶段、路径和进度，并清理失败的本次 rsync 副本。完成后 `run_round()` 复用既有 90 分钟 deadline，不重置时钟，准备阶段未使用的时间留给审计。
- 合并标签的全量 ripgrep 扫描改为逐行流式分类，省掉“原始命中完整列表 + 分类后标签列表”的同时驻留；最终仍保留全部标签命中，不以截断换内存。
- 仅完成 Python 静态编译和 `git diff --check`；未运行测试或真实目标。尚未测量大型仓库的准备速度；同步文件读取/复制调用本身仍可能有单次系统调用延迟，但目标递归遍历和外部扫描不再没有总时间边界。

### 2026-09-25 autonomous 模型请求遵循轮次 deadline

- `LLMClient` 原先按单个 HTTP 请求设置 180 秒超时；一次结构化调用可以依次尝试多档 reasoning effort、重试和 Chat Completions 降级，因此总耗时会远超单次 timeout。autonomous `run_round()` 现在把持久轮次剩余时间提供给 LLM client，每次请求超时和网络重试等待都被 clamp 到同一 deadline；并行 S4 候选共享该 deadline。
- `BudgetExceeded` 原先在 `run_loop()` 只打印后退出，S1–S4 已完成内容没有被聚合到轮次级停止报告。现在写入 `S0/round-stop-report.json`、budget status 和 LLM usage，并列出已完成的 stage；到期时 guard 仍按既有规则保留，给宿主先读取报告的机会。
- 若 S4 并行候选因 LLM 调用/Token 预算耗尽而中断，现在向上传播停止信号，取消尚未启动的候选，等待在途工作收尾，然后保存已完成候选结果和未完成 ID 至 `S4/partial-results.json`。这样不会把预算耗尽降格成单个候选的普通 harness error，也不会丢掉已完成 worker 的结果。
- autonomous CLI 对轮次时间、LLM 额度、源码扫描、S4 timebox 和活动审计守卫的明确中止返回状态码 2；正常完成（包括无新候选后停止）仍返回 0，便于调度器区分“正常收尾”与“未完成审计”。
- `run_loop()` 之前没有捕获预算/扫描以外的异常，错误会在写轮次摘要前直接冒泡。现在普通 `Exception` 会保存类型、有限错误摘要、完成的 checkpoint、最后完成阶段、预算和 LLM 用量到 `S0/round-error-report.json`，并以状态码 2 结束；`KeyboardInterrupt`/`SystemExit` 仍保持进程控制语义。
- 这只约束 VulnGate 自己发出的 LLM HTTP 请求，不能中断 Codex 宿主模型思考或未接入 VulnGate 的工具调用。仅完成静态编译和 `git diff --check`；未运行测试，也未做真实 API 端到端验证。

### 2026-09-25 子 Agent 进度回执与固定截止时间

- 近期审计记录显示，子 Agent 已启动但长时间没有矩阵文件；主线等待后再接管，空等时间远大于候选预算。现将 S4 子 Agent 的 5 分钟要求定义为一次进度检查间隔，而不是整个候选的总截止时间：要求 90 秒内回执接单，5 分钟核验一次有内容的进展；固定总截止时间不超过单候选 15 分钟或轮次剩余预算，不能滚动续期。无新产物/进展时停止并接管缺失工作。
- `parallel-receipt` 新增 `progress` 事件和 `--inspect`；回执保留最多 16 个事件、最多 8 个经过路径/摘要核验的候选矩阵产物。进度只用于判断 worker 是否仍在推进，不能作为漏洞证据；`--verify` 仍只接受同一 challenge 下含有效 `cells.json` 的 completed 回执。
- 本次只做 Python 编译、CLI help 和 `git diff --check`；未运行测试、真实子 Agent 或 S4 矩阵。宿主仍需按固定截止时间中断 worker；CLI 进度回执本身不具备终止 Codex 子 Agent 的能力。

### 2026-09-25 runtime-lab 隔离状态与授权提示

- 技能示例曾直接写入 `allow_unconfined_start: true`，容易让模型把无 OS 网络/文件隔离的目标服务当成默认配置。现已从中英文示例移除，并要求用户明确授权后才在 operator-controlled 配置中加入；目标仓库自身的配置/说明不视为授权。
- 服务生命周期结果及 `S4/processes.json` 现在分别记录 `network_isolation` 和 `filesystem_isolation`：VulnGate 启动的服务标记 `unconfined`，外部已就绪进程标记 `unknown-external-process`，未启动标记 `not-started`。服务和进程 schema 版本递增，旧状态不会冒充新隔离记录。
- 这项修改加强了授权提示和产物可见性，没有新增 runtime-lab OS 沙箱；托管目标服务仍可访问宿主网络/文件。只做 Python 编译和差异检查，未运行测试或启动服务。真实 OS 级服务隔离仍是未完成项。

### 2026-09-25 中文子 Agent 截止语义与英文规范不一致

- 英文规范已把 5 分钟定义为进度检查间隔、S4 worker 固定截止时间限定为单候选 15 分钟或轮次剩余预算，但中文参考段仍写成 worker 总截止时间不超过 5 分钟。这会让中文审计过早中断仍有进展的矩阵工作，抵消固定候选预算修复。
- 中文段现与英文规范统一：90 秒接单 receipt；5 分钟后只检查一次进度事件与产物增长；无变化则接管，若有进展则可持续到原定绝对截止时间；到期后保留有效部分产物并中断，不滚动续期或换 worker 重启同一任务。receipt 只是活性记录，不是漏洞证据。
- 仅做文档静态核对、Python 编译和 `git diff --check`；没有启动子 Agent 或运行 S4。此修复消除技能内的时间盒冲突，但不替代宿主实际执行固定截止时间和中断 worker。

### 2026-09-25 审计技能按阶段渐进加载

- 原 `SKILL.md` 同时包含完整英文规范与完整中文译本，共 2238 行、172 KB；所有审计只需一个模式/一个阶段时，仍要把两种语言及 S1–S8 全部细节一起加载。重复规则也增加了中英文时间盒等内容漂移的机会。
- 现将入口缩至约 6.3 KB：保留语言、模式、审计截止、候选优先、证据与授权硬边界；setup 和 S1–S8 拆入按需 references，S4 runtime-lab 细节只在用到服务、fixture、版本 arm 或研究记忆时加载。完整中文参考移至 `docs/AUDIT-PLAYBOOK.zh-CN.md`，运行时只使用一份英文规范，叙述仍跟随用户语言。
- 原英文规范分段抽取为 references，中文原文保留为文档。Ruby YAML 解析、14 个技能 Markdown 文件的相对链接/名称/占位符检查、相关 Python 静态编译和 `git diff --check` 均通过；官方 `quick_validate.py` 因当前 Python 缺少 `pyyaml` 未能启动。插件安装器已接受并启用 `1.2.0+codex.20260925124426`，17 个相关文件与活动缓存逐字节一致。未运行测试、子 Agent 或审计目标。后续还需观察真实审计是否确实只加载当前阶段材料，并检查 Codex skill loader 对相对 references 的访问行为。

### 2026-09-26 S4 PoC 提示与证据缺口判定自相矛盾

- Java/Web PoC 提示要求模型打印 `HTTP_CODE`、`EVIDENCE`、`ERROR`、能力链和状态步骤等 marker；`summarize_candidate()` 却会因为发现任何 PoC marker 就无条件设置 `needs-harness-observer`。marker 一边被当作必需输出，一边又会触发 observer 缺口路径，造成无效生成/修复工作和错误的缺口分类。
- 现改为 PoC 最小执行、marker 可选且只保留为 `poc_claims`；summary 仅在 runner 明确报告 observer 不可用时设置 `needs-harness-observer`。HTTP observer 已启动但没有捕获响应时单独记录 `no-independent-http-response`，不得解释为候选无影响。Shell PoC 仅在可执行 cell 出现具体非零脚本/请求失败时重写一次；反馈使用退出码和 stderr，不因缺少 marker 或响应反复重写。
- S4 evidence policy 版本已递增，旧 checkpoint 会失效并在新审计轮次重算。插件校验器先因宿主 Python 缺少 `PyYAML` 未能启动；在临时虚拟环境补齐依赖后，校验发现旧 manifest 的顶层 `hooks` 字段不被接受。现已移除此字段并保留 `hooks/hooks.json` 默认布局；Codex 官方打包文档说明，manifest 未声明 hook 时会发现该默认文件。静态编译与 `git diff --check` 通过；本轮未运行测试、PoC、目标服务或真实审计。插件校验、重装和缓存逐文件比对以最终发布记录为准；bundled hook 仍需用户在 Codex 中审阅并信任后才会运行。

### 2026-09-26 普通 S4 runtime-lab 默认重复运行候选

- `runtime_lab` 配置缺省时 `_options()` 默认启用实验室；每个候选最多创建 8 个 fixture，默认每个 fixture 做 3 次 replay 并覆盖两种 SafeMode。这些 cell 会消耗同一候选 15 分钟预算，且 S4 baseline 已执行后还会再次运行 PoC。QUICKSTART 的“有意不可重复时才关闭”文案也把高成本工作流设成默认路径，与技能中的按需指导不一致。
- 现改为普通 S4 replay/differential 仅在明确设置 `runtime_lab.enabled: true` 或提供非空选项时启用；空/缺省配置写入 disabled artifact，不占用候选矩阵预算。显式配置 `runtime_lab.service` 仍会启用该研究路径；fuzz 专用 runtime-lab 规则保持独立。关闭路径现在在源码修订查询和服务生命周期初始化之前返回，避免未启动实验室却执行外部服务清理命令。
- S4 evidence policy 递增以使旧 S4 及下游 checkpoint 重算；QUICKSTART、中英文实验室说明同步为 opt-in。此次仅做代码路径与配置默认值静态审阅、Python 编译和差异检查；未运行测试或目标审计。
- 同步检查还发现安装脚本的发布清单没有包含 `hooks/`，可能导致缓存版本虽然采用默认 hook 发现规则，实际却拿不到当前 bundled hook。现已把 `hooks/` 纳入安装归档；最终缓存核验确认 `hooks/hooks.json` 与 `hooks/pre_tool_use.py` 均已进入活动缓存。
- 最终通过 Python 静态编译、`bash -n install.sh`、`git diff --check` 和官方插件校验器；安装并启用 `1.2.0+codex.local-20260925-203246`。workspace、个人 marketplace 源目录与活动缓存的 153 个发布文件全部一致，manifest 作者为 Zer0Gate / `71823107+Zer0Gate@users.noreply.github.com`。未运行测试、PoC、目标服务或真实审计。

### 2026-09-26 Chromium 审计搜索与元数据遍历耗时失控

- 对近期 Chromium 审计任务 `01a0cc36-21e9-7361-90ea-f2081d19a1bd` 的历史记录复盘：该任务绑定旧技能缓存 `1.2.0+codex.20260922065311`，跨约 24 小时；任务记录累计 2,892 条目标命令，其中 385 条失败或被中断。命令记录累计运行时长约 2,751 分钟（并行命令有重叠，不能当作实际墙钟时间）；多个全仓 `rg` 单次耗时超过 2 小时，`du -sh` 在一次进程快照中已运行 6 分钟以上，另有长时间 `git status` 进程需清理。全仓 coverage 构建也出现 scope 无效/失败，S4 没有形成验证闭环，最终没有确认高危/严重问题。此前新增的 90 分钟轮次预算、15 分钟 `audit-exec` 通用硬上限不覆盖旧技能调用，也不足以阻止一次搜索/元数据命令独占大部分轮次。
- `audit-exec` 现对 `rg`、`grep`、`find`、`fd`、`ack`、`ag`、`du`、`git grep`、`git status`、`git diff`、`git ls-files` 及 `python -c`/stdin、`perl -e`、`ruby -e`、`node -e`、`osascript -e` 施加 120 秒单命令上限。超时仍走现有进程清理与失败重跑拦截；命令记录注明时限策略、上限和触发原因。完整覆盖索引仍由覆盖工具自己的目录枚举预算控制。中英文 S1 规则要求将搜索限定到本轮候选/已调度子系统，并将长扫描交给有独立时限的专用 CLI。
- 旧任务运行时没有加载这次改动，不能据此断言修复已经解决真实审计中的所有拖延。Hook 是否受信任、以及新版本在真实大仓库中的执行效果，仍需在新线程和有界审计中确认；本次未启动目标仓库审计，也未运行测试。

### 2026-09-26 研究议程候选在准入窗口前被过滤

- fastjson2 第 11 轮的审计记录显示，主调度未将明确优先的 `Class` 初始化 RCE 假设带入本轮验证，随后需要另做三候选焦点调度。代码路径也确认了机制原因：autonomous、配置管线和 `schedule` CLI 先调用 `bounded_candidate_intake()`，之后 `build_schedule()` 才加载研究议程并应用候选分数；已选议程候选如果落在准入窗口之外，分数加权无法使它重新出现。
- `selected_candidate_ids()` 让三条调度入口把上一轮议程中仍标记为 selected 的候选 ID 提供给准入器；本次再补充当前轮显式入口：CLI 可重复传 `--priority-candidate <id>`，autonomous/配置管线可在目标配置写 `priority_candidate_ids`。上一轮议程候选只获得评分窗口优先；当前轮显式优先 ID 则在运行时 pinned 候选之后、类别配额之前占用最终轮次名额，超过剩余槽数的请求写入 deferred 列表。不完整覆盖模式忽略旧议程 ID，但显式用户优先 ID 会在可用槽内优先排入候选池。准入 artifact 记录请求、进入窗口和未匹配 ID，schedule artifact 记录最终选入和延后项。
- 用户用自然语言指定攻击类别/代码路径时，宿主先把意图对应到候选 ID；如候选池没有，就补一条带代码位置、前置条件和证伪条件的候选，再通过以上接口调度。候选准入器自身不从自由文本猜 ID。本次仅做 Python 静态编译、`git diff --check` 和调用路径审阅；未运行测试或真实目标审计。

### 2026-09-26 doctor 的 JSON 标志导致审计产物被错误文本覆盖

- fastjson2 的历史轮次曾执行 `agent_cli.py doctor --json > S0/doctor.json`。`doctor` 本身已输出 JSON，但其 argparse 子命令不接受常见的 `--json` 标志，导致 usage/error 文本写进 `.json`；收尾校验才发现并重跑覆盖该文件。
- `doctor` 现在接受 `--json` 并保持 JSON 输出，兼容统一的机器输出调用习惯。此兼容项不能防止其他未知参数/执行失败被 shell 重定向成错误产物，仍应先检查命令状态再把输出认作 artifact。
- 本次做 Python 静态编译和 CLI/parser 源码检查；未运行测试或目标审计。

### 2026-09-26 无效覆盖索引仍生成“覆盖驱动”候选计划

- Chromium 审计产物明确记录 `coverage-summary.audit_status.state=scope-invalid`、`scope_valid=false`、`inventory-scope-missing`，source/entry/sink/flow 索引为空；当时独立 `schedule` 仍将候选池的 8 项全标为 selected。这个计划没有覆盖数据支撑，虽然后续限制文档把它标成 partial。
- `build_schedule()` 现在要求有效且带版本的 inventory scope、非空源码宇宙、成功的 coverage-build 状态和齐全的核心索引。scope 无效时，调度 API 返回有界顺序与明确降级说明；独立 `schedule` CLI 退出并提示重建，不会持久化一份伪装成覆盖评分的计划。显式优先候选仍排在管线降级顺序前部。
- 本次仅做 Python 静态编译、调用路径与历史 artifact 对照、差异检查；未运行测试或新的目标审计。

### 2026-09-26 源码根护栏漏拦父目录相对路径

- 当前 hook 原先只检查 Bash 工作目录是否在源码根内，或命令文本是否包含源码根的绝对路径。若工作目录是源码根的父目录，`rg ... target/src`、符号链接路径和默认递归扫描都可能避开该判断；这会让大范围无界命令继续消耗审计轮次预算。
- hook 现将显式文件/目录参数相对当前工作目录解析并规范化，覆盖相对路径和符号链接；从源码根祖先目录调用递归/元数据工具或解释器会进入受保护路径，shell 复合语法无法可靠解析时也保守拦截。只有与登记的 workspace/target/round/root 相符的 VulnGate CLI 操作才能放行。
- 这仍是 Codex 工具层护栏，不是 OS 沙箱；专用工具、脚本内部动态路径和 hook 未加载仍需通过审计 wrapper 与宿主流程控制。当前只做静态控制流复核、Python 编译和差异检查，未运行测试、目标命令或真实审计。

### 2026-09-26 并行指南与身份/安全说明漂移

- 英文快速上手仍要求每次 S4 都运行 spawn probe 并启动 worker，与技能、中文快速上手和近期整改中的按需并行规则冲突。现已改为先看独立性和净节省时间，只有选并行时才运行探针。
- 仓库 owner 已迁移为 `Zer0Gate`，但 plugin `developerName`、公开文档作者、clone/advisory 链接和本地 Git remote 仍残留旧账号；安全政策也仍将源码检查描述成回环执行边界，并未列出 runtime-lab 与抽样资源止损限制。现已同步当前身份和隔离限制。
- 本项仅做静态文档/manifest/配置核对、Python 编译、JSON 解析和 `git diff --check`；未运行测试或目标审计。

### 2026-09-26 hook 事件异常时默认放行

- 新增的 PreToolUse wrapper 在事件 JSON 损坏或超过 1 MiB 时会进入异常分支并返回 0；如果当时有活动源码根登记，这会把无法检查的 Bash 调用放行，抵消源码根护栏。
- Hook 现限制事件读取大小；Bash 事件字段缺失时，策略层在活动登记存在的情况下拒绝调用。wrapper 捕获解析/导入异常后会检查有界的活动登记文件；若登记存在、文件损坏或状态无法确认，就输出明确 deny，而只有确认没有活动登记时才允许继续。父目录检查还会扫描 argv 中被 `env`、`time` 等包装器隐藏的解释器和构建工具。事件中的命令超过 64 KiB 或 2048 个 shell token 时会在路径解析前拒绝，避免 hook 自身处理超长 argv 耗尽 3 秒 hook 时限。
- 该行为仅覆盖 Codex 调用此 hook 的 Bash 事件。Hook 未加载、未受信任、其他工具类型或 OS 外部进程仍不受此控制。当前只做静态控制流审阅、Python 编译、JSON 解析和差异检查，未运行测试或目标审计。

### 2026-09-26 汇总结论未重新绑定原始 S4 单元，轮次规则弱化了宿主止损

- derive_conclusion 原先信任调用方传入的 summary；HTTP 分支甚至允许 RESP_MATCH/EVIDENCE 文本单独确认。当前汇总器虽已把 PoC marker 降为 claim，但结论入口没有自行从原始 S4 单元重算，旧 checkpoint 或其他调用方仍可把自报字段放进 summary。HTTP observer 只保留状态码和响应体摘要，不能验证内容或目标状态。
- 结论入口现要求提供原始 S4 单元，并重算安全相关字段；确认校验只读取通过 harness provenance 校验的 observations。HTTP 汇总行新增 cell_id、observer run id 和 collector version；状态/摘要只记录为传输证据，不能直接升级为漏洞确认。
- S4 evidence policy 已升至 v12，使旧 S4 及依赖它的下游 checkpoint 失效，避免沿用旧汇总合同。
- 90 分钟技能规则此前明确排除了宿主推理和浏览，容易让长时间开放式分析绕过预算。现在英文入口、S1/S2 参考和中文操作手册要求 deadline 覆盖所有审计工作，在阶段切换及每轮调查前检查；底层工具仍不能强制中断模型生成或未接入的工具，主 Agent 必须在截止时停止。
- Java 执行单元现在会显式记录 needs-harness-observer 缺口，避免把执行成功伪装成已有可用效果证据；独立 JVM 效果采集器本身仍未实现。
- 本轮只做静态控制流审阅、Python 编译、Markdown/链接核查和 git diff --check；未运行测试、PoC、目标服务或真实审计。HTTP 响应内容观测与 Java 独立 JVM 效果观测仍未实现，相关候选应明确保持待验证并继续处理其他已调度工作。
