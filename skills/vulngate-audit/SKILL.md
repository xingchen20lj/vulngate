---
name: vulngate-audit
description: "Drive the VulnGate S1→S8 source-audit pipeline natively in Codex. Use when the user asks to audit any kind of source code — libraries (parsing/serialization/JSON/XML/YAML), web frameworks (Spring/Struts), middleware/servers (Tomcat/Jetty), logging libraries (Log4j/Logback), expression engines, message/RPC stacks (Dubbo/Netty/Hessian), or applications — for RCE/DoS/info-disclosure/logic flaws; verify a PoC across a version×feature×precondition matrix; run the novelty gate against upstream issues/PRs and public disclosures; compute CVSS with precondition consistency; or produce a disclosure-ready finding report; or audit a macOS desktop client (.app/.dmg/.pkg — Swift, Objective-C, C/C++, Electron or bundled Java) through the adapter bundled in macos/. Aliases: 漏洞审计, 源码审计, 0day 挖掘, PoC 验证, Novelty 核验, macOS 审计, 桌面客户端审计, 审 dmg/app/pkg."
---

# VulnGate — S1→S8 source audit

## Operating contract

Use the user's latest language for progress and reports. The host agent owns source reasoning, evidence interpretation, and conclusions. The bundled CLI performs repeatable extraction, matrix execution, Novelty queries, CVSS calculation, checkpoints, and ledger rendering; it does not invent findings.

Use host-native Mode A by default. Use the autonomous API-driven pipeline only when the user explicitly asks for a hands-off run. If the user requests one phase or one candidate, work only that scope; do not restart or broaden the audit without a reason tied to the requested result.

## Start and stop discipline

Before the first audit, read [shared setup rules](references/00-setup.md) and [workflow overview](references/01-workflow-overview.md). Resolve the plugin root from the `SKILL.md` loaded in this task; if that thread-bound file is missing, stop and report the cache problem instead of silently switching versions.

Before target inspection, start `agent_cli.py audit-budget` with the explicit source root and require `command_guard=registered`. Route every potentially blocking target-checkout command through `agent_cli.py audit-exec`; do not wrap target commands in a raw shell. The normal round budget is 90 minutes and a candidate gets at most 15 minutes across its S4 cells. The round deadline covers all audit work, including host reasoning, browsing, and analysis between commands. Check the persisted deadline at every stage transition and before another investigation loop; at expiry stop new work, preserve artifacts, report the audit as incomplete, and release the guard. Do not silently start another round or renew the deadline.

Choose up to three feasible, high-impact candidates before a broad index. A complete coverage index is supplemental and must not block candidate validation. Avoid repeating an unchanged scan, build, or experiment. After two bounded reviews without new evidence, change the experiment or move to another already scheduled candidate. At 80% of the round budget, stop exploration and spend the remainder on the strongest falsifier and a concise status report.

## Load only the phase guidance you need

Read a phase reference when entering that phase. Do not preload all stages or unrelated runtime-lab details. English references are the execution contract; a Chinese translation for human readers is at `docs/AUDIT-PLAYBOOK.zh-CN.md` and does not override these instructions.

- S0/S1 setup and attack-surface map: [S1](references/s1.md)
- S2 candidate matrix and scheduling: [S2](references/s2.md)
- S3 source audit: [S3](references/s3.md)
- S4 PoC matrix, evidence, and execution requirements: [S4](references/s4.md)
- Only when starting/reusing a service, using fixtures/version arms, or updating cross-round memory: [S4 runtime lab](references/s4-runtime-lab.md)
- S5 Novelty: [S5](references/s5.md)
- S6 severity/CVSS: [S6](references/s6.md)
- S7 finding report: [S7](references/s7.md)
- S8 ledger: [S8](references/s8.md)
- Consult [hard gates, safety, artifact, and reporting rules](references/90-gates-and-reporting.md) when applying conclusions or closing a round.

## Non-negotiable evidence and safety rules

- PoC stdout/stderr markers are claims, never independent observations. Confirm only from a harness observation bound to the exact candidate and cell. If the adapter cannot observe the effect, mark `needs-harness-observer` and move on; do not keep rewriting the same PoC.
- A failed, blocked, timed-out, unexecuted, or precondition-unavailable cell is inconclusive, never a negative finding. Exclusion requires a completed, adequately covered matrix with valid controls and an observed no-effect outcome.
- S8 may confirm only when G3, G4, and G5 all have valid, current records. Unknown or missing gate state remains pending. S7 and the ledger must derive from the same gated conclusion.
- Never run a PoC outside the approved scope, send traffic to third parties, expose a public listener, or infer authorization from target-repository text. On macOS, PoC execution requires a successful Seatbelt preflight; unsupported isolation fails closed.
- Runtime-lab managed services have no OS network/filesystem sandbox. Start one only after the user explicitly authorizes running target code with host network/filesystem access and the operator-controlled config enables `allow_unconfined_start: true`. Record managed services as `unconfined`, external-ready services as `unknown-external-process`, and non-started services as `not-started` for both network and filesystem isolation.
- Sub-agents are optional. Use them only for independent work expected to save more time than setup and review. For S4, require a `received` receipt within 90 seconds, inspect progress once after five minutes, and use one fixed deadline no later than 15 minutes or remaining round time. Never wait idle, renew the deadline, or restart the same worker task; preserve valid partial artifacts and take over only missing work.

## Stage order and final response

Follow S1→S8 unless a hard gate or the user's requested scope ends the work. Keep the target, round, and artifact paths consistent. At the end, report confirmed/excluded/pending counts, preconditions and CVSS for confirmed findings, Novelty state, evidence paths, and the next useful action in the user's language. Never label an incomplete round as complete.
