# WorkBuddy 能力迁回 Codex

本次以 `xingchen20lj/vulngate-workbuddy` 的
`00e92aec9b9b0df35846ba86d86a582dd3511b45` 为固定来源（WorkBuddy 1.2.0），
在本仓库发布为 Codex 1.1.0。保留本仓库历史、MIT 许可和 Codex 原生分发方式。

## 能力对应

| 来源能力 | 本仓库入口 | Codex 适配 |
|---|---|---|
| 全量源码、入口、sink、控制索引 | `scripts/agent/analysis/`、`coverage` | 宿主在 S1 显式初始化；配置管线自动初始化 |
| 符号、调用图、双向 flow | coverage 目录内 JSON 索引 | 保留启发式标签，不作为运行时证明 |
| 控制缺口与同族差分 | `controls`、`differential` | 生成候选后交由 Codex 阅读源码和验证 |
| 覆盖驱动候选调度 | `schedule`、S2 | 配额、延期、运行时候选保留；S3–S8 使用本轮选择 |
| macOS、Electron、内嵌 JVM | `macos/run-audit.sh` | 使用脚本所在 Codex 插件版本，无 WorkBuddy 路径依赖 |
| 独立审计目录 | pipeline `--workspace`、`vg-run.py --audit-root` | 证据写到审计目录，不写入安装缓存 |
| CLI 契约及依赖诊断 | `agent_cli.py`、测试 | 保留 Codex 的根路径和 spawn 协议 |
| 安装与 CI | `install.sh`、`.github/workflows/ci.yml` | `.codex-plugin/plugin.json`、个人 marketplace、独立目录安装测试 |

不迁入 WorkBuddy 的 `.codebuddy-plugin`、设置文件、缓存注册器和安装器。
来源当前版本已经移除的 Web 工作台也不在本次迁移范围内。

## 无额外模型 API Key 的使用方式

安装后，在新的 Codex 任务中调用 `$vulngate-audit`，指定源码或应用路径。
宿主使用当前 Codex 模型，确定性脚本只负责分析、验证和落盘。
插件结构遵循 [OpenAI 插件文档](https://learn.chatgpt.com/docs/plugins)。

也可手动查看确定性分析结果。以下命令从本仓库执行，所有命令使用相同审计目录：

```bash
python3 scripts/agent_cli.py coverage demo --workspace /path/to/audit \
  --root /path/to/source --rebuild --json
python3 scripts/agent_cli.py controls demo --workspace /path/to/audit --show-candidates
python3 scripts/agent_cli.py differential demo --workspace /path/to/audit --show-candidates
python3 scripts/agent_cli.py schedule demo --workspace /path/to/audit \
  --candidates /path/to/candidate-pool.json --round 1 --slots 8 --json
python3 scripts/agent_cli.py coverage demo --workspace /path/to/audit --show-uncovered --schedule
```

`candidate-pool.json` 是完整候选列表，包含宿主候选及 coverage 目录中的
`control-candidates.json`、`differential-candidates.json`。选择结果中的
`selected_ids` 用于本轮；延期候选保留到后续轮次。源码或扫描范围变更后执行
`coverage --rebuild`；账本写入后执行 `coverage` 刷新状态。

原生目标：

```bash
bash macos/run-audit.sh /Applications/Target.app /path/to/audit
# 在审计目录完成候选、PoC 与配置后运行：
python3 macos/bin/vg-run.py --audit-root /path/to/audit \
  --target target --round 1 --config targets/target.json
```

支持 `VULNGATE_PY=/absolute/path/to/python3` 选择解释器；`VULNGATE_PLUGIN`
或 `vg-run.py --plugin` 可显式选择另一个 Codex 插件根。无显式选择时使用当前
脚本所属版本，不搜索其他宿主或旧缓存。`run_pipeline.sh` 仍是可选的独立 API
模式，与上述 Codex 宿主模式不同。

## 验证范围与限制

迁入全套分析层回归测试，另加 Codex 安装/更新、调度跨阶段传递、独立 workspace、
标准 ASAR/source map 解包测试。所有 fixture 使用临时目录，不需要模型 API Key。
ASAR 格式按 [Electron 官方实现](https://github.com/electron/asar/blob/main/src/disk.ts)
读取两层 Pickle；未支持的 unpacked/link 条目计入 `skipped`，不能把部分提取称为完整源码。

Mach-O 输出是元数据声明视图，不含方法体；真实 macOS 工具链、DMG/PKG 挂载、
目标特定 PoC 和外部模型 API 仍需在相应环境单独验证。`macos/README.md` 的
历史实测数据来自迁移来源，并非本次重新执行的结果。覆盖率和控制缺口均为审计
辅助信息，不能替代 G0–G5 证据闸门，也不能证明目标不存在漏洞。


本次本机验证（2026-09-16）：422 项 unittest 全部通过，原有 smoke test、
Codex plugin-creator 清单验证、skill-creator 技能验证与 8/8 原生适配检查通过。
另以临时 Swift 源码 fixture 离线运行 S1→S8，并读取 coverage / controls /
differential JSON，确认调度产生的候选进入账本，未运行的候选没有被升级为已确认。
实际第三方应用、外部 LLM API 和 GitHub CI 运行不包含在此结果中。
