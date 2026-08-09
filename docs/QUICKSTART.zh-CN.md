# 快速上手

本指南带您完成 VulnGate 的第一次运行。

## 1. 安装

```bash
git clone https://github.com/xingchen20lj/vulngate.git
cd vulngate
./install.sh
codex plugin add vulngate@personal
```

前置要求：Codex（CLI 或桌面客户端）、Python 3.8+、JDK 8+、`rg`。

## 2. 准备目标

任何包含源码和/或 jar 的目录都可以。以 Java 目标为例：

```bash
cd /path/to/library
mvn package        # 若库发布二进制，生成 target/*.jar
```

建议在源码旁写一份 `env.md` 记录环境信息（版本、JDK、安全开关、默认
Feature）——它决定了每一条发现的前置分级。

## 3. 运行管线（宿主原生模式）

新建一个 **新** Codex 线程，然后说：

> 审计 `/path/to/library`，跑完整的 S1→S8 流程。

宿主智能体会：

1. 测绘攻击面（S1）——入口、危险调用点、默认 Feature。
2. 提出候选（S2），并标注前置分级。
3. 带 file:line 证据审计源码（S3）。
4. 派生子 Agent 编写、编译并运行 PoC 矩阵（S4），覆盖版本 × 安全开关 ×
   前置条件。
5. 扫描上游 issue/PR 与公开披露（S5），执行 Novelty 硬降级。
6. 计算 CVSS 并校验前置一致性（S6）。
7. 生成本地发现文档（S7）并更新账本（S8）。

结果落在 `state/<target>/`、`reports/<target>/`、`ledger/<target>/` 下。

## 4. 运行管线（自主模式）

需要无人值守运行，并愿意使用自己的 LLM API Key 时：

```bash
export DEEPSEEK_API_KEY=...        # 或 OPENAI_API_KEY
./scripts/run_pipeline.sh \
  --name mytarget \
  --target-dir /path/to/library \
  --round 1 \
  --max-calls 40 --max-candidates 4 --max-rounds 1 \
  --lang zh
```

## 5. 确定性助手

宿主智能体会代为调用这些命令，您也可以直接使用：

```bash
PYTHONPATH="$PWD/scripts" python3 scripts/agent_cli.py doctor
PYTHONPATH="$PWD/scripts" python3 scripts/agent_cli.py \
  source-map --root /path/to/library-src --pattern "checkAutoType\\("
PYTHONPATH="$PWD/scripts" python3 scripts/agent_cli.py \
  cvss --vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" --tier 0
```

## 6. 常见问题

- **S5 遇到 GitHub 限流**：`export GITHUB_TOKEN="$(gh auth token)"` 后重跑。
- **找不到 jar**：先构建目标，或把 `--target-dir` 指向包含 jar 的目录。
- **PoC 编译失败**：检查 JDK 版本、模块 exports/opens 与 classpath，并把确切的
  环境错误记入单元格。
- **技能不可用**：插件技能在线程启动时加载——安装或更新后务必新建线程。
