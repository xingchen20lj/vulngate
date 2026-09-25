# 快速上手

> Codex 1.1.0 新增：覆盖率、调用图、控制缺口、同族差分、候选调度与 macOS 适配。见 [功能演进与命令说明](EVOLUTION.md)。审计产物使用独立 `--workspace`。

本指南带您完成 VulnGate 的第一次运行。

## 0. 子 Agent 并行按需启用

并行是加速手段，不是每轮必做项。只有任务彼此独立、输出路径隔离，且预计节省时间
大于探针、协调和复核成本时才 spawn；最多同时 3 个 worker。候选共享构建/测试环境、
存在磁盘争用、时间预算不足或当前宿主没有可用的 spawn 工具时，按顺序执行，不要为了
满足并行要求反复探针或重试。选择并行时先跑一次 spawn-probe，失败后记录实际错误并
顺序降级。worker 只回原始证据，主 Agent 负责复核和结论。

## 1. 开发者自审计（先查依赖，再查代码）

写产品代码想自查安全，两步：

```bash
# 1) 依赖体检：已知漏洞 + 修复版本（支持 pom.xml / requirements*.txt /
#    pyproject.toml / package.json / go.mod / Gemfile / Cargo.toml 等）
python3 scripts/agent_cli.py deps --target ./my-project --out deps-report.md

# 2) 让插件对自研代码跑 S1→S8（可让主 Agent 跳过 S5 Novelty）
```

`deps` 数据源为 OSV（api.osv.dev），查询失败会如实标注 `query_notes` 而不中断。

## 2. 安装

```bash
git clone https://github.com/Zer0Gate/vulngate.git
cd vulngate
./install.sh
```

`install.sh` 会自动完成：安装插件、注册个人市场、并在 Codex 中启用。它会先在
`$PATH` 中查找 `codex` 命令，再查找桌面应用内置的 CLI——用桌面应用的话不需要
单独安装 CLI。前置要求：本机 Codex 客户端（桌面应用或 CLI）、Python 3.8+、
JDK 8+、`rg`。

> **必须新建线程。** 插件技能在线程启动时加载——安装后请打开新的 Codex 线程。

## 3. 准备目标

任何包含源码和/或 jar 的目录都可以。以 Java 目标为例：

```bash
cd /path/to/library
mvn package        # 若库发布二进制，生成 target/*.jar
```

建议在源码旁写一份 `env.md` 记录环境信息（版本、JDK、安全开关、默认
Feature）——它决定了每一条发现的前置分级。

## 4. 运行管线（宿主原生模式）

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

### S4 运行状态与 JDK 前置

`S4/execution-status.json` 以实际 `cells.json` 为准，状态包括：
`unexecuted`（没有 cell）、`run-failed`（运行失败）、`gate-blocked`（门禁阻断）、
`precondition-unavailable`（声明的运行时不可用）、`executed-no-effect`（已执行但没有漏洞效果）
和 `executed-with-effect`。宿主代理或 spawn 通道超时不会覆盖已经落盘的矩阵结果。

需要 JDK8 时，在矩阵 cell 中显式写 `required_runtime: "jdk8"` 与 `java_home: "/path/to/jdk8"`
（也可写 `java_bin`）。VulnGate 会用该 cell 的 `java` 和同一 JDK 的 `javac`，并在
`cells.json` 记录实际路径与版本；找不到或版本不匹配时只记录前置不可用，不会假装用默认 JDK。

普通 S4 的重放/差分默认关闭，因为它会重复运行 PoC 并占用同一候选预算。确实需要稳定性
或版本 × SafeMode 对照时，在目标配置中设置 `runtime_lab.enabled=true`；结果仍与
G4/G5 结论分开保存。未提供 `runtime_lab` 配置或配置为空时，不会额外重放。

有状态 Web/中间件 PoC 可以让 VulnGate 管理一个本地服务。命令必须是 argv 数组，工作目录
必须在 workspace 内，并且必须提供回环健康检查；不要把 Token、Cookie 或 Password 放入配置：

```json
{
  "runtime_lab": {
    "service": {
      "start_command": ["python3", "-m", "http.server", "8080", "--bind", "127.0.0.1"],
      "allow_unconfined_start": true,
      "healthcheck_url": "http://127.0.0.1:8080/",
      "startup_timeout": 20,
      "shutdown_timeout": 8
    }
  }
}
```

运行时会复用已健康的本地实例，只回收本轮自己启动的进程组；PID/端口生命周期写入
`S4/processes.json`。`S4/runtime-lab.json` 的 `configuration` 是脱敏快照，授权/租户/对象
用例会生成稳定的 `authz_fixture_id`；服务未就绪只记录为
`precondition-unavailable`，不会被解释成漏洞不存在。禁止使用 shell `-c`、远程命令或非回环
健康地址。托管服务没有 OS 网络/文件系统沙箱；启动前会预检并使用 POSIX CPU、单文件大小、文件描述符、UID 进程数和 core dump 限额，但不限制内存、文件读取范围或网络。只有明确接受该边界并设置 `allow_unconfined_start: true` 后才会启动。

## 5. 运行管线（自主模式）

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

## 6. 确定性助手

宿主智能体会代为调用这些命令，您也可以直接使用：

```bash
PYTHONPATH="$PWD/scripts" python3 scripts/agent_cli.py doctor
PYTHONPATH="$PWD/scripts" python3 scripts/agent_cli.py \
  source-map --root /path/to/library-src --pattern "checkAutoType\\("
PYTHONPATH="$PWD/scripts" python3 scripts/agent_cli.py \
  cvss --vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" --tier 0
```

## 7. 常见问题

- **S5 遇到 GitHub 限流**：`export GITHUB_TOKEN="$(gh auth token)"` 后重跑。
- **找不到 jar**：先构建目标，或把 `--target-dir` 指向包含 jar 的目录。
- **PoC 编译失败**：检查 JDK 版本、模块 exports/opens 与 classpath，并把确切的
  环境错误记入单元格。
- **技能不可用**：插件技能在线程启动时加载——安装或更新后务必新建线程。
