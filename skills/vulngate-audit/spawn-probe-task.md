# VulnGate S4 spawn 探针任务（0.2.9+）

宿主在 S4 开工前把**下面的任务消息原样** spawn 给一个探针子 Agent，并把
`<HEARTBEAT_FILE>` 替换为 `state/<target>/round-NN/S4/spawn-probe.heartbeat`
的绝对路径。探针只验证一件事：子 Agent 能否收到任务正文并写入共享工作区。
探针不做任何审计工作，不产出任何 S5–S8 产物。

## 任务消息（原样发送，替换 <HEARTBEAT_FILE>）

你是 VulnGate S4 spawn 探针。你的唯一任务是：

1. 立即把下面这一行追加写入文件 `<HEARTBEAT_FILE>`（文件不存在就创建）：
   `PROBE <你的 agent 名称或当前时间戳>`
2. 完成后只回复一行：`PROBE-DONE`

禁止做任何其他事情：不运行审计、不写其他文件、不调用网络、不产生任何结论。
除上述心跳文件外，任何写入都是 harness error，会被宿主丢弃。
