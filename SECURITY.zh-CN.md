# 安全政策

**语言：** [English](SECURITY.md) | 简体中文

VulnGate 本身是一个安全工具。本页说明插件自身的安全姿态，以及如何报告插件
中的问题。

## 报告 VulnGate 自身的安全漏洞

如果你在插件本身（而非用它审计的目标库）中发现了漏洞，请私下报告：

- 在 GitHub 上打开 **私有安全通告**：
  `https://github.com/Zer0Gate/vulngate/security/advisories/new`
- 或发送邮件给维护者（见仓库元数据），主题为
  `[VulnGate security] <简要描述>`

请附上：

- 受影响版本
- 复现步骤（最小化）
- 影响评估
- 建议修复方案（如有）

我们承诺在 5 个工作日内确认报告，并在公开披露前协调修复。

## 管线安全姿态

- **PoC 隔离取决于平台。** 在受支持的 macOS 主机上，Shell 和 Java PoC 命令
  必须通过 Seatbelt 预检。网络默认拒绝；受支持的 HTTP cell 仅允许连接对应
  observer 端口。源码级外连检查只是补充措施，不是执行沙箱。
- **文件与资源限制有明确边界。** 支持的 macOS 主机上，PoC 文件读取使用
  Seatbelt 默认拒绝策略。POSIX 资源限额按单进程计算；RSS 和 scratch 大小监控
  是抽样尽力止损，不是聚合硬配额。不支持所需隔离时，PoC 执行会失败关闭。
- **托管 runtime-lab 服务使用明确的隔离 backend。** Linux 使用 namespace/container
  backend，并在可用时启用 cgroup-v2；macOS 必须配置容器/轻量 VM backend。
  仓库中的 `allow_unconfined_start: true` 绝不是充分授权；启动前必须消费绑定
  `run_id + config_digest + expiry` 的一次性操作员授权。backend 或授权缺失时 fail closed。
- **证据必须独立采集。** PoC stdout/stderr marker 属于不可信声明。捆绑的 HTTP
  observer 可采集响应元数据；其他副作用需要对应 observer。observer 缺失或运行
  失败都意味着结论待验证，不能作为候选无害的证据。
- **审计时限是操作护栏。** 90 分钟轮次预算、`audit-exec` wrapper 和受信任的
  Codex hook 只覆盖已接入路径；它们无法中断宿主模型推理或所有专用工具路径。
  Hook 不是操作系统级安全边界。
- **审批留痕与本地报告。** 受策略约束的操作会记录到审批日志；发现报告在本地
  生成，管线不会自动发布。
- **保守的 Novelty。** `unknown-query-failed` 是一等结论；“没查到”不等于
  “不存在”。
- **凭据处理。** API Key 从环境变量读取，不得写入审计产物。公开信息查询可从
  `GITHUB_TOKEN` / `GH_TOKEN` 读取 GitHub token。

## 范围

- 范围内：插件清单、`skills/`、`scripts/`、安装脚本、文档。
- 范围外：被审计目标库的漏洞（请向对应维护者报告），以及 Codex 平台本身的
  问题。
