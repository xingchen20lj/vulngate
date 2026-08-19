# Audit Playbook — 通用源码审计攻击面手册

**Language:** English (with Chinese notes) | 中文说明见各节"要点"

This playbook is the domain-knowledge layer of VulnGate. The pipeline (S1→S8)
is target-agnostic; this document tells the host agent **where to look** for a
given target type. Treat it as a checklist, not a limit — the target's own code
always wins over the generic patterns below.

## 1. Web frameworks / MVC (Spring, Struts, Play, …)

### 典型入口 Entry points

- Request dispatch: `DispatcherServlet`, `HandlerMapping`, `Controller` methods,
  `doGet`/`doPost`/`service`
- Parameter binding: `@RequestBody`, `@ModelAttribute`, form binding, type
  converters
- File upload handlers, interceptors, filters, path matching (`/**`, regex)
- Template rendering and view resolution

### 攻击面 Attack surface

- Expression injection: SpEL / OGNL / EL evaluation of attacker-controlled
  strings (e.g. Spring SpEL — CVE-2022-22965 "Spring4Shell" family; Struts OGNL —
  S2-xxx series)
- Deserialization via `@RequestBody` / multipart / session attributes
- Type-confusion through parameter binding (mutable `HttpServletRequest` in
  Spring 4.x — CVE-2018-1273 family)
- Path traversal / normalized-path bypass in static resource mapping
- SSRF via redirects / proxying / URL fetching
- Template SSTI, CORS misconfiguration, auth bypass in filters/interceptors

### 要点

Web 框架优先看"不可信输入 → 表达式求值 / 对象绑定 / 模板渲染"三条链路；参数
绑定和表达式引擎是历史 RCE 高发区。

## 2. Logging libraries (Log4j, Logback, …)

### 典型入口

- Log formatting: `MessageFormat`, `String.format`, layout patterns
- Lookup evaluation: `${prefix:key}` style lookups (JNDI, env, sys)
- Configuration loading (log4j2.xml / logback.xml), appenders, filters

### 攻击面

- Lookup evaluation reaching JNDI / RCE (Log4Shell — CVE-2021-44228)
- Format-string issues, log injection / log forging
- Config injection (remote config, malicious layout pattern), DoS via crafted
  messages

### 要点

日志库的检查重点是"**日志内容是否参与求值/格式化指令**"。Lookup 是否白名单、
格式化参数是否可被输入控制是两条主线。

## 3. Middleware / servers (Tomcat, Jetty, Undertow, …)

### 典型入口

- Connector protocol parsers: HTTP/1.1, HTTP/2, AJP (`CoyoteAdapter`)
- Request line / header parsing, chunked encoding, trailer handling
- Session management, classloader hierarchy, JSP/Servlet container
- Static resource mapping and welcome-file handling

### 攻击面

- Protocol-level: request smuggling / splitting, CRLF injection, AJP
  unauthenticated access (Ghostcat — CVE-2020-1938)
- Path traversal and normalization bypass (encoded `/`, `..;`, backslash)
- Session fixation / deserialization of session data
- Classloader sandbox escape, resource exhaustion (connection/thread/header
  limits)

### 要点

中间件的核心是**协议解析状态机与路径规范化**。构造畸形字节流验证解析器边界
（长度、编码、重复头、chunk 块），并检查未认证协议端点。

## 4. Expression engines / templates (OGNL, SpEL, EL, Velocity, Freemarker, Thymeleaf, …)

### 典型入口

- Expression parse + evaluate APIs (`evaluate`, `eval`, `invoke`, `getValue`)
- Template render with attacker-controlled templates or variables
- Property / object-graph navigation

### 攻击面

- Expression injection → RCE (OGNL/SpEL/EL), template SSTI
- Sandbox escape via object-graph traversal (classloader / Runtime access)
- DoS via deep or cyclic expressions

### 要点

表达式引擎检查三点：**输入是否不可信、求值前有无沙箱/白名单、对象图遍历是否
可触达危险类**。历史绕过基本都是"沙箱可被属性链逃逸"。

## 5. Message / RPC stacks (Dubbo, Netty, RocketMQ, Kafka, gRPC, Hessian, …)

### 典型入口

- Protocol decoders / codecs, frame parsing, length-prefix handling
- Message dispatch and handler callbacks
- Serialization / deserialization of payloads

### 攻击面

- Deserialization RCE (type confusion / gadget chains)
- Length/boundary flaws → OOM / DoS (declared vs. actual length)
- Unauthenticated message handling, SSRF via callback addresses
- Protocol confusion / smuggling across framing boundaries

### 要点

协议栈先看**长度字段是否被无界信任**（声明长度 vs 剩余缓冲），再看反序列化
类型是否可控、回调地址是否回环约束。

## 6. General libraries (JSON/XML/YAML, files, images, crypto)

### 典型入口

- `parse` / `read` / `deserialize` / `load` / `convert`
- Decompression (`unzip`, `gzip`), image decode, charset/encoding conversion
- Crypto: padding, key handling, random number generation

### 攻击面

- Deserialization RCE, XXE (external entity), billion-laughs
- Zip bomb / path traversal on extract, decompression amplification
- Image decode memory flaws, padding oracle, weak RNG

### 要点

通用库套用统一检查项：类型白名单、实体/外部资源解析、解压与长度限制、默认
配置可达性。

## 7. Attack-class taxonomy（S2 候选生成维度）

| 类别 | 例子 |
|---|---|
| Injection 注入 | expression/command/SQL/template/log injection |
| Resource 资源 | path traversal, XXE, SSRF, arbitrary file read/write, zip bomb |
| Exhaustion 耗尽 | OOM, stack overflow, CPU amplification, connection/thread exhaustion |
| Logic 逻辑 | auth bypass, privilege escalation, race condition, validation bypass |
| Disclosure 泄露 | error stack traces, debug endpoints, log/cache leakage |

## 8. Entry patterns for `source-map --preset`

| Preset | Regex sketch |
|---|---|
| `parsers` | `parse*|read*|deserialize*|decode*|load*|convert*` |
| `http` | `doGet|doPost|service|handleRequest|onRequest|DispatcherServlet|Controller` |
| `expression` | `evaluate|eval|invoke|ognl|spel|template|render|lookup|format` |
| `io` | `read|write|copy|unzip|extract|download|openConnection|getInputStream` |
| `exec` | `Runtime|ProcessBuilder|exec|CommandLine|startProcess` |
| `config` | `load|parse|readConfig|getProperty|Properties|Yaml|Xml` |

## 9. Unified S3 checklist（每个候选的通用检查项）

1. Input source is untrusted and reaches the entry (G1).
2. Reachable under default configuration — feature flags must be explicit (G1b).
3. Existing validation / allowlist / sandbox, and whether it can be bypassed.
4. Multi-version difference: a fix announcement covers only the paths it names —
   verify every claimed sub-path on the audited versions.
5. End-to-end precondition tier (0 / single-feature / app-cooperation /
   extra-primitive) → CVSS consistency (G5).
6. Residual suspects discovered during the audit go to `S3/residuals.json` (each
   with a probe_plan), never only into prose notes — S4 must run at least one
   probe cell per residual.

## 10. 通告/修复反查（Advisory/Fix-Commit → Fix-Diff → 攻击面）

目标近期有安全通告（GHSA / CVE / 厂商公告）时，**修复 diff 是最准确的攻击面
地图**：厂商修了什么，漏洞大概率就在那几行改动附近。此技术在 Metabase
GHSA-vwf4-m7j8-wcjf 实战中直接定位到未公开根因（开放 Map + merge 残留 +
honeysql raw），是"从通告到根因"的最高效路径。

**即使近期没有通告**，git 历史里近期合并的安全修复 commit 也是同等信号：修复
commit 是"上一个漏洞的答案"，而它**覆盖不全的地方就是下一个漏洞**。2026-08-19
腾讯云鼎预警的 Redis blocked-client UAF 正是此类：CVE-2026-23479 的修复
（5c355b68e）只堵了 unblock 时 evict 的 UAF，`handleClientsBlockedOnKey()`
reprocessing 的原始 list 迭代器路径仍残留（上游 #15562 / PR #15594 才真正修复）。

### 操作步骤

0. **无通告时的 git-log 反查**：对目标仓库执行
   `git log --oneline -30 --all --grep='fix.*(uaf|use-after-free|overflow|bypass|race|crash|out-of-bounds|oob|deserial|rce)'`
   （大小写不敏感；C 系项目追加 `asan|valgrind|memory`）。把近期合并的安全修复
   commit **逐个转成"修复完整性验证"候选**（surface=fix-completeness），进
   S2/S3/S4；禁止登记为 "NOT new findings" 直接归档。
1. **拿修复版本**：从 GHSA / release notes 读 affected / patched 版本区间；
   下载或 clone patched tag（如 `git fetch origin tag v0.58.24`）。
2. **diff 定位**：`git diff <受影响tag>..<修复tag> --stat`（或
   `git show <修复commit>`），把改动文件按
   输入校验 / 路由 / schema / 反序列化 / 过滤 / 会话管理分类。
3. **逐改动点反推**：修复代码即答案——看它**加了什么检查**（拒绝未知键、
   类型校验、参数化、黑名单），反推漏洞触发条件与前置。
4. **生成候选**：把修复点对应的旧版代码路径列为最高优先候选，照常走
   S3 源码审计 + S4 运行时验证（G1 / G1b / G4 不变）。
5. **修复完整性验证清单**（UAF / 竞态 / 越界 / 溢出类修复必查）：
   - **被修函数的所有调用路径都覆盖了吗？** CVE-2026-23479 修了 unblock 时
     evict 的 UAF，但 `handleClientsBlockedOnKey()` 的 reprocessing 迭代器路径
     仍残留——按修复 diff 找"同类代码路径"，而不是只看被修的那一处；
   - **同类编码/格式的兄弟分支覆盖了吗？** fastjson2 JSONB 声明长度修复覆盖
     BIGINT/BINARY/ARRAY，字符串编解码器仍按声明长度预分配触发 OOM；
   - **修复是否只堵了已知输入形状？** 换一种输入形状 / 入口 / 编码能否绕过；
   - **运行时对照**：修复前版本（`git checkout` 未修复 commit 构建）应能复现
     崩溃/越界/UAF，修复后版本应返回错误或拒绝；两个方向都要有 cell 输出，
     禁止仅凭"修复 commit 在树"排除。
6. **边界与纪律**：
   - 反查得到的候选仍必须运行时验证，禁止"修复 diff 存在 = 确认"；
   - 该机制通常已被上游通告覆盖 → G3 一律按 same-family 起步，增量只主张
     "精确根因 / 修复边界 / 旁路"，严禁声称 0day；
   - 核对版本区间以 **GHSA 原文 affected/patched ranges** 为准，勿用博客
     统一安全版代替逐通告边界（Metabase 教训：reset_password 洞修在
     0.58.23，0.58.24 是同日另一通告 GHSA-r8h2-qpfx-mx59 的修复版，
     两者不能混用）。

### 适用场景

- 目标近期出过安全通告（在野 / 0day 预警）；
- 目标近期 git 历史有安全修复 commit（尤其 UAF / 越界 / 竞态 / 溢出），
  需验证修复完整性（即使无公开通告）；
- 审计任务是"已修复漏洞的旁路 / 同族残留 / 修复不完整"；
- 需要快速理解陌生代码库攻击面时，通告 diff 是性价比最高的入口。
