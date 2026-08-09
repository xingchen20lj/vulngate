# 架构说明

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
