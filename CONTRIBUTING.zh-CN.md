# 参与贡献

**语言：** [English](CONTRIBUTING.md) | 简体中文

感谢你考虑为 VulnGate 贡献代码。VulnGate 是一个安全研究工具，因为管线产出的
发现可能被上报给厂商或用于协调，所以对变更的把关标准刻意较高。

## 基本规则

- **不公开披露发现。** PoC、报告和协调消息在目标库维护者介入、修复公开之前，
  一律只留在本地。
- **证据优先于断言。** 任何影响结论的管线改动都必须守住这条规则：确认发现
  必须有运行时 PoC 输出。
- **保守的 Novelty。** 上游命中必须降级；不完整的查询不得当作权威结论。
- **本仓库禁止敏感材料。** 不要提交尚未披露的目标身份、私有厂商协调记录、
  披露草稿、真实凭据或其他机密研究产物。

## 开发流程

1. Fork 仓库并创建功能分支。
2. 修改代码，保持插件清单有效：

   ```bash
   python3 scripts/validate_plugin.py .   # 当 Codex plugin-creator 工具可用时
   ```

3. 运行冒烟测试：

   ```bash
   ./scripts/smoke_test.sh
   ```

4. 涉及安装脚本时，用隔离路径测试：

   ```bash
   PLUGIN_HOME=/tmp/vg-home VULNGATE_MARKETPLACE=/tmp/vg-market/marketplace.json ./install.sh
   ```

5. 提交 Pull Request，说明变更内容及其对证据契约的影响。

## 项目结构

- `.codex-plugin/plugin.json` —— 插件清单
- `skills/vulngate-audit/SKILL.md` —— 宿主智能体执行手册（S1–S8、G0–G5）
- `scripts/agent_cli.py` —— 确定性助手 CLI
- `scripts/agent/` —— 捆绑的确定性执行框架；框架行为变更时，需同步更新插件契约、文档与回归测试
- `scripts/run_pipeline.sh` —— 自主模式启动器
- `docs/` —— 用户与架构文档

## 发布流程

- 在 `.codex-plugin/plugin.json` 和 `CHANGELOG.md` 中升级版本号（语义化版本）。
- 以 `vX.Y.Z` 打 tag 发布。
- 本地迭代不需要升版本号：`./install.sh` 会自动设置带时间戳的 `codex.*`
  cachebuster，Codex 会把它当作新安装。
