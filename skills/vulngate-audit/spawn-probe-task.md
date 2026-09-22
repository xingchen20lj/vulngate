# VulnGate S4 Spawn Probe Task (challenge-bound v2)

The host agent sends this exact task to a single probe sub-agent before starting S4 candidate-level spawning.

Before spawning, the host must run `agent_cli.py spawn-probe --prepare` and
replace both placeholders with values from that command. The host must not
create the heartbeat itself.

Replace `<HEARTBEAT_FILE>` with the emitted absolute path and
`<PROBE_TOKEN>` with the emitted token.

```text
state/<target>/round-NN/S4/spawn-probe-<token>.heartbeat
```

## Probe objective

Verify only that the spawned sub-agent:

1. receives the task body; and
2. can write to the shared VulnGate workspace.

This is a transport/workspace probe, not a vulnerability-research task.

## Probe instructions

1. Append exactly one line to `<HEARTBEAT_FILE>` in the following form:

   ```text
   PROBE <PROBE_TOKEN>
   ```

2. After the file write succeeds, reply with exactly:

   ```text
   PROBE-DONE <PROBE_TOKEN>
   ```

3. Do not audit source code, run PoCs, access the network, create any other files, or draw conclusions.
4. Any write outside `<HEARTBEAT_FILE>` is a harness error and must be discarded by the host.

---

# 中文版 — VulnGate S4 Spawn 探针任务（challenge-bound v2）

宿主 Agent 在 S4 开始逐候选 spawn 之前，必须先把本任务原样发送给一个探针子 Agent。

宿主必须先运行 `agent_cli.py spawn-probe --prepare`，并用其输出替换两个
占位符；宿主不得自行创建心跳文件。

将 `<HEARTBEAT_FILE>` 替换为输出的绝对路径，将 `<PROBE_TOKEN>` 替换为输出 token：

```text
state/<target>/round-NN/S4/spawn-probe-<token>.heartbeat
```

## 探针目标

探针只验证两件事：

1. 被 spawn 的子 Agent 能收到任务正文；
2. 子 Agent 能写入 VulnGate 的共享工作区。

这是消息投递/共享工作区探针，不是漏洞研究任务。

## 探针指令

1. 向 `<HEARTBEAT_FILE>` 追加且只追加一行：

   ```text
   PROBE <PROBE_TOKEN>
   ```

2. 文件写入成功后，只回复：

   ```text
   PROBE-DONE <PROBE_TOKEN>
   ```

3. 禁止审计源码、运行 PoC、访问网络、创建其他文件或给出任何漏洞结论。
4. 如果子 Agent 写入了 `<HEARTBEAT_FILE>` 以外的文件，按 harness error 处理，宿主必须丢弃该越权产物。
