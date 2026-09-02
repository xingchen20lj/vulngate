# Audit Playbook — General Source-Audit Attack-Surface Guide

This playbook is the domain-knowledge layer of VulnGate. The S1→S8 pipeline is target-agnostic; this document tells the host agent **where to look** for a given target type. Treat it as a checklist, not a limit. The target's actual code and runtime behavior always take precedence over the generic patterns below.

## 1. Web frameworks / MVC

Typical targets include Spring, Struts, Play, and similar frameworks.

### Entry points

- Request dispatch: `DispatcherServlet`, `HandlerMapping`, controller methods, `doGet`, `doPost`, `service`.
- Parameter binding: `@RequestBody`, `@ModelAttribute`, form binding, type converters.
- File upload handlers, interceptors, filters, path matching (`/**`, regex).
- Template rendering and view resolution.

### Attack surface

- Expression injection: SpEL / OGNL / EL evaluation of attacker-controlled strings, including Spring4Shell- and Struts-OGNL-family mechanisms.
- Deserialization through request bodies, multipart data, or session attributes.
- Type confusion through parameter binding.
- Path traversal or normalized-path bypass in static-resource mappings.
- SSRF through redirects, proxying, or URL fetching.
- Template injection, CORS mistakes, and authentication/authorization bypass in filters or interceptors.

### Review focus

Prioritize the chains **untrusted input → expression evaluation**, **untrusted input → object binding**, and **untrusted input → template rendering**. Parameter binding and expression engines have historically been high-value RCE surfaces.

## 2. Logging libraries

Typical targets include Log4j, Logback, and similar logging stacks.

### Entry points

- Log formatting: `MessageFormat`, `String.format`, layout patterns.
- Lookup evaluation: `${prefix:key}`-style lookups such as JNDI, environment, or system properties.
- Configuration loading, appenders, layouts, and filters.

### Attack surface

- Lookup evaluation reaching JNDI or other dangerous mechanisms.
- Format-string problems, log injection, and log forging.
- Configuration injection, remote configuration, malicious layout patterns, or message-driven DoS.

### Review focus

Ask whether **log content itself can become an instruction to the formatter or lookup engine**. The two main lines are lookup allowlisting and attacker control over formatting directives or arguments.

## 3. Middleware / servers

Typical targets include Tomcat, Jetty, Undertow, and similar containers or servers.

### Entry points

- Connector protocol parsers: HTTP/1.1, HTTP/2, AJP, and adapter layers such as `CoyoteAdapter`.
- Request-line and header parsing, chunked encoding, trailers.
- Session management, classloader hierarchy, JSP/Servlet container paths.
- Static-resource mapping and welcome-file handling.

### Attack surface

- Request smuggling or splitting, CRLF injection, unauthenticated protocol endpoints.
- Path traversal and normalization bypass using encoded separators, semicolons, backslashes, or dot segments.
- Session fixation or session deserialization.
- Classloader or sandbox escape.
- Connection, thread, header, or parser resource exhaustion.

### Review focus

Focus on **protocol parser state machines** and **path normalization**. Exercise malformed byte streams, length fields, encodings, duplicate headers, chunk boundaries, and unauthenticated protocol endpoints.

## 4. Expression engines / templates

Typical targets include OGNL, SpEL, EL, Velocity, Freemarker, Thymeleaf, and similar engines.

### Entry points

- Expression parse/evaluate APIs such as `evaluate`, `eval`, `invoke`, and `getValue`.
- Template rendering with attacker-controlled templates or variables.
- Property and object-graph navigation.

### Attack surface

- Expression injection and server-side template injection.
- Sandbox escape through object-graph traversal, classloader access, or runtime/process primitives.
- Resource exhaustion through deep, cyclic, or adversarial expressions.

### Review focus

Check three questions: **Is the input untrusted? Is there a sandbox/allowlist before evaluation? Can object-graph navigation reach dangerous capabilities?** Many historical bypasses are sandbox escapes through property chains.

## 5. Message / RPC stacks

Typical targets include Dubbo, Netty, RocketMQ, Kafka, gRPC, Hessian, and similar protocol stacks.

### Entry points

- Protocol decoders, codecs, frame parsing, and length-prefix handling.
- Message dispatch and handler callbacks.
- Payload serialization and deserialization.

### Attack surface

- Deserialization and type-confusion mechanisms.
- Declared-length versus actual-buffer flaws leading to OOM or other resource exhaustion.
- Unauthenticated message handling and callback-address SSRF.
- Protocol confusion or smuggling across frame boundaries.

### Review focus

Start with **whether length fields are trusted without bounds**, then examine controllable deserialization types and callback/network destinations.

## 6. General libraries

Typical targets include JSON/XML/YAML libraries, file/archive utilities, image decoders, and crypto helpers.

### Entry points

- `parse`, `read`, `deserialize`, `load`, `convert`.
- Decompression, image decoding, charset and encoding conversion.
- Crypto padding, key handling, and random-number generation.

### Attack surface

- Deserialization, XXE/external entities, entity-expansion DoS.
- Archive bombs, path traversal on extraction, decompression amplification.
- Image-decoder memory flaws, padding oracles, weak randomness.

### Review focus

Apply the common checks: type allowlists, external-resource/entity resolution, length and decompression limits, and default-configuration reachability.

## 7. Attack-class taxonomy for S2

| Class | Examples |
|---|---|
| Injection | expression, command, SQL, template, log injection |
| Resource | path traversal, XXE, SSRF, arbitrary file read/write, archive bomb |
| Exhaustion | OOM, stack overflow, CPU amplification, connection/thread exhaustion |
| Logic | authentication bypass, privilege escalation, race condition, validation bypass |
| Disclosure | stack traces, debug endpoints, log/cache leakage |

## 8. Entry patterns for `source-map --preset`

| Preset | Regex sketch |
|---|---|
| `parsers` | `parse*|read*|deserialize*|decode*|load*|convert*` |
| `http` | `doGet|doPost|service|handleRequest|onRequest|DispatcherServlet|Controller` |
| `expression` | `evaluate|eval|invoke|ognl|spel|template|render|lookup|format` |
| `io` | `read|write|copy|unzip|extract|download|openConnection|getInputStream` |
| `exec` | `Runtime|ProcessBuilder|exec|CommandLine|startProcess` |
| `config` | `load|parse|readConfig|getProperty|Properties|Yaml|Xml` |

## 9. Unified S3 checklist

For every candidate:

1. Confirm that the input source is untrusted and reaches the entry (G1).
2. Determine whether the path is reachable under default configuration; feature flags and non-default setup must remain explicit (G1b).
3. Identify validation, allowlists, security gates, or sandboxes and test whether they can be bypassed.
4. Compare versions carefully. A fix announcement only proves the paths it actually fixes; verify every claimed sub-path on the audited versions.
5. Assign an end-to-end precondition tier (`0`, `single-feature`, `app-cooperation`, `extra-primitive`) and preserve it through CVSS consistency checks (G5).
6. Persist residual suspects in `S3/residuals.json`, each with a `probe_plan`. S4 must execute at least one probe cell for every residual.

## 10. Advisory / fix-commit reverse analysis

When a target has a recent security advisory, **the fix diff is often the most precise attack-surface map available**. The code changed by the maintainer identifies the mechanism and its trust boundary more reliably than a generic vulnerability description.

The same reasoning applies even without a public advisory: recent security-related commits are strong signals. A fix commit is an answer to the previous bug; **sibling paths or uncovered variants around that fix can become candidates for fix-completeness validation**.

Examples that motivated this rule include:

- A Metabase advisory analysis where the patched diff exposed the root-cause path and made the affected mechanism much easier to localize.
- Redis blocked-client UAF analysis around CVE-2026-23479, where a fix covered one UAF path while a related reprocessing/list-iterator path required additional upstream work.
- fastjson2 JSONB declared-length fixes where sibling encoding branches needed separate verification rather than assuming the first patch covered the whole family.

### Procedure

0. **Git-history reverse scan when no advisory exists.** Run a bounded search such as:

   ```bash
   git log --oneline -30 --all --grep='fix.*(uaf|use-after-free|overflow|bypass|race|crash|out-of-bounds|oob|deserial|rce)'
   ```

   For C/C++ projects, consider additional terms such as `asan`, `valgrind`, or `memory`. Convert each credible recent security fix into a `surface=fix-completeness` candidate that proceeds through S2/S3/S4. Do not archive it merely as “not a new finding.”

1. **Obtain the fix boundary.** Read affected/patched ranges from the primary advisory or release metadata and obtain the patched tag or commit.
2. **Diff the fix.** Use `git diff <affected>..<patched> --stat` or `git show <fix-commit>`. Classify changed files by validation, routing, schema, deserialization, filtering, session handling, and similar trust boundaries.
3. **Reverse the change.** Ask what check was added, what dangerous behavior was removed, and what exact precondition existed before the fix.
4. **Create candidates.** Treat the old code paths corresponding to the fix as high-priority candidates, but still require S3 source audit and S4 runtime evidence. G1, G1b, and G4 do not disappear because a patch exists.
5. **Test fix completeness.** For UAF, race, bounds, overflow, parser, and similar fixes:
   - enumerate all callers and sibling paths of the changed function;
   - inspect sibling encodings/formats, not just the patched branch;
   - vary the input shape and entry point instead of testing only the known trigger;
   - when feasible, compare pre-fix and post-fix runtime cells. The pre-fix cell should reproduce the original failure/effect and the fixed cell should reject or safely handle it. A fix commit being present in the tree is not runtime evidence.
6. **Preserve novelty discipline.** If the mechanism is already covered by a public advisory, start from a same-family/known-family position. Any incremental claim must be about a distinct residual, precise root cause, bypass, or fix boundary supported by evidence. Do not call it a 0day merely because the analysis is deeper.
7. **Use primary version ranges.** Prefer the advisory's own affected/patched ranges over a blog's consolidated “safe version” list, which may combine several fixes released on the same day.

### When to use this method

- A target has a recent security advisory or active security fix.
- Git history contains recent UAF, bounds, race, overflow, bypass, or parser/security fixes.
- The research question is specifically about bypasses, sibling variants, or incomplete fixes.
- The codebase is unfamiliar and a fix diff offers the fastest reliable path to a concrete trust boundary.

---

# 中文版 — 通用源码审计攻击面手册

本手册是 VulnGate 的领域知识层。S1→S8 管线本身与目标类型无关；本文件用于告诉宿主 Agent：面对不同类型的代码库，**应该优先看哪里**。它是检查清单，不是边界；任何时候都以目标真实源码和运行时行为为准。

## 1. Web 框架 / MVC

典型目标包括 Spring、Struts、Play 等。

### 典型入口

- 请求分发：`DispatcherServlet`、`HandlerMapping`、Controller 方法、`doGet`、`doPost`、`service`。
- 参数绑定：`@RequestBody`、`@ModelAttribute`、表单绑定、类型转换器。
- 文件上传、拦截器、过滤器、路径匹配（`/**`、正则）。
- 模板渲染与视图解析。

### 攻击面

- SpEL / OGNL / EL 等表达式对不可信字符串求值。
- Request body、multipart、session attribute 进入反序列化或对象绑定链。
- 参数绑定造成的类型混淆。
- 静态资源路径遍历与规范化绕过。
- Redirect、代理、URL 获取带来的 SSRF。
- 模板注入、CORS 错误、过滤器或拦截器中的认证/授权绕过。

### 检查重点

优先检查 **不可信输入 → 表达式求值**、**不可信输入 → 对象绑定**、**不可信输入 → 模板渲染** 三条链。参数绑定与表达式引擎长期属于高价值 RCE 攻击面。

## 2. 日志库

典型目标包括 Log4j、Logback 等。

### 典型入口

- 日志格式化：`MessageFormat`、`String.format`、layout pattern。
- `${prefix:key}` 一类 Lookup，例如 JNDI、环境变量、系统属性。
- 配置加载、Appender、Layout、Filter。

### 攻击面

- Lookup 到达 JNDI 或其他危险能力。
- 格式化问题、日志注入与日志伪造。
- 配置注入、远程配置、恶意 Layout pattern、消息驱动 DoS。

### 检查重点

核心问题是：**日志内容本身是否会成为格式化器或 Lookup 引擎的指令**。重点检查 Lookup 白名单以及攻击者能否控制格式化指令或参数。

## 3. 中间件 / 服务器

典型目标包括 Tomcat、Jetty、Undertow 等。

### 典型入口

- HTTP/1.1、HTTP/2、AJP 等协议解析器及 `CoyoteAdapter` 一类适配层。
- Request line、Header、chunked encoding、trailer 解析。
- Session 管理、ClassLoader 层次、JSP/Servlet 容器路径。
- 静态资源映射与 welcome-file 处理。

### 攻击面

- Request smuggling/splitting、CRLF、未认证协议端点。
- 编码分隔符、分号、反斜杠、dot segment 带来的路径规范化绕过。
- Session fixation 或 session 反序列化。
- ClassLoader / sandbox escape。
- 连接、线程、Header 或解析器资源耗尽。

### 检查重点

核心是**协议解析状态机**与**路径规范化**。构造畸形字节流、长度字段、编码、重复 Header、chunk 边界和未认证协议端点进行验证。

## 4. 表达式引擎 / 模板引擎

典型目标包括 OGNL、SpEL、EL、Velocity、Freemarker、Thymeleaf 等。

### 典型入口

- `evaluate`、`eval`、`invoke`、`getValue` 等表达式解析/求值 API。
- 攻击者可控模板或变量进入模板渲染。
- 属性和对象图遍历。

### 攻击面

- 表达式注入与 SSTI。
- 通过对象图、ClassLoader、Runtime/进程能力逃逸沙箱。
- 深层、循环或对抗性表达式造成资源耗尽。

### 检查重点

检查三个问题：**输入是否不可信？求值前是否有沙箱/白名单？对象图能否触达危险能力？** 历史上的大量绕过都属于属性链导致的沙箱逃逸。

## 5. 消息 / RPC 协议栈

典型目标包括 Dubbo、Netty、RocketMQ、Kafka、gRPC、Hessian 等。

### 典型入口

- 协议 Decoder、Codec、Frame parser、长度前缀处理。
- 消息分发与 Handler callback。
- Payload 序列化/反序列化。

### 攻击面

- 反序列化与类型混淆。
- 声明长度与实际缓冲不一致导致 OOM 或资源耗尽。
- 未认证消息处理与 callback 地址 SSRF。
- Frame 边界之间的协议混淆或 smuggling。

### 检查重点

先检查**长度字段是否被无界信任**，再检查可控反序列化类型和 callback / 网络目的地址。

## 6. 通用库

典型目标包括 JSON/XML/YAML、文件/压缩工具、图片解码、密码学辅助库。

### 典型入口

- `parse`、`read`、`deserialize`、`load`、`convert`。
- 解压、图片解码、字符集/编码转换。
- Padding、密钥处理、随机数生成。

### 攻击面

- 反序列化、XXE/外部实体、实体扩展 DoS。
- Zip bomb、解压路径遍历、解压放大。
- 图片解码内存问题、Padding oracle、弱随机数。

### 检查重点

统一检查类型白名单、外部资源/实体解析、长度与解压限制，以及默认配置下是否可达。

## 7. S2 攻击类别

| 类别 | 例子 |
|---|---|
| 注入 | expression、command、SQL、template、log injection |
| 资源访问 | path traversal、XXE、SSRF、任意文件读写、archive bomb |
| 资源耗尽 | OOM、stack overflow、CPU amplification、连接/线程耗尽 |
| 逻辑问题 | 认证绕过、权限提升、竞态、校验绕过 |
| 信息泄露 | stack trace、debug endpoint、日志/缓存泄露 |

## 8. `source-map --preset` 入口模式

| Preset | Regex 示意 |
|---|---|
| `parsers` | `parse*|read*|deserialize*|decode*|load*|convert*` |
| `http` | `doGet|doPost|service|handleRequest|onRequest|DispatcherServlet|Controller` |
| `expression` | `evaluate|eval|invoke|ognl|spel|template|render|lookup|format` |
| `io` | `read|write|copy|unzip|extract|download|openConnection|getInputStream` |
| `exec` | `Runtime|ProcessBuilder|exec|CommandLine|startProcess` |
| `config` | `load|parse|readConfig|getProperty|Properties|Yaml|Xml` |

## 9. S3 通用检查清单

每个候选都要检查：

1. 输入来源确实不可信，并可达入口（G1）。
2. 默认配置是否可达；Feature flag 和非默认前置必须显式保留（G1b）。
3. 是否存在校验、白名单、安全门或沙箱，以及能否绕过。
4. 精确比较版本。修复公告只证明实际修复的路径，不能自动覆盖所有同族分支。
5. 明确端到端前置等级（`0`、`single-feature`、`app-cooperation`、`extra-primitive`），并保持到 CVSS 一致性校验（G5）。
6. 残余怀疑点必须写入 `S3/residuals.json`，每条包含 `probe_plan`；S4 每条至少运行一个 probe cell。

## 10. 通告 / 修复提交反查

目标近期存在安全通告时，**修复 diff 往往是最精确的攻击面地图**。维护者修改的代码通常比泛化漏洞描述更直接地暴露机制和信任边界。

即使没有公开通告，近期安全修复 commit 也具有同样价值：一个 fix commit 是“上一个漏洞的答案”；其**兄弟路径、遗漏变体或修复边界**可以转化为 fix-completeness 候选。

推动该规则形成的实际经验包括：

- Metabase 通告分析中，修复 diff 能快速定位根因路径。
- Redis blocked-client UAF / CVE-2026-23479 周边分析中，一个修复覆盖了某条 UAF 路径，但相关 reprocessing/list-iterator 路径还需要额外上游修复。
- fastjson2 JSONB 声明长度家族中，兄弟编码分支需要逐项验证，不能假设首次修复已经覆盖全部家族。

### 操作步骤

0. **无通告时做 git 历史反查。** 运行有界查询，例如：

   ```bash
   git log --oneline -30 --all --grep='fix.*(uaf|use-after-free|overflow|bypass|race|crash|out-of-bounds|oob|deserial|rce)'
   ```

   C/C++ 项目可增加 `asan`、`valgrind`、`memory` 等关键词。每个可信安全修复都转成 `surface=fix-completeness` 候选，继续进入 S2/S3/S4，不能只标成“不是新发现”后归档。

1. **确定修复边界。** 从主通告或 Release metadata 获取 affected/patched range，并取得 patched tag/commit。
2. **Diff 修复。** 使用 `git diff <affected>..<patched> --stat` 或 `git show <fix-commit>`，按输入校验、路由、Schema、反序列化、过滤、Session 等信任边界分类。
3. **反推变更。** 看新增了什么检查、移除了什么危险行为、修复前到底需要什么前置条件。
4. **生成候选。** 将修复对应的旧路径设为高优先级候选，但仍必须经过 S3 源码审计与 S4 运行时验证；G1/G1b/G4 不因“存在补丁”而消失。
5. **验证修复完整性。** 对 UAF、竞态、越界、溢出、解析器等修复：
   - 枚举被修函数的所有调用者与兄弟路径；
   - 检查兄弟编码/格式分支，而不是只测补丁所在分支；
   - 改变输入形状和入口，避免只重放已知触发器；
   - 能构建旧版时，优先做修复前/修复后运行时对照。旧版应复现原问题，修复版应拒绝或安全处理。“修复 commit 已在树中”本身不是运行时证据。
6. **保持 Novelty 纪律。** 机制已有公开通告时，从 same-family / known-family 起步。增量只能主张有证据支撑的残余、精确根因、旁路或修复边界，不能因为分析更深就称为 0day。
7. **使用一手版本区间。** 以通告自身的 affected/patched range 为准，不要用博客的统一“安全版本”代替逐通告边界，因为同一天可能同时发布多个不同修复。

### 适用场景

- 目标近期存在安全通告或活跃安全修复。
- Git 历史存在近期 UAF、越界、竞态、溢出、绕过或解析器安全修复。
- 研究问题本身就是旁路、同族变体或修复不完整。
- 面对陌生代码库，需要通过 fix diff 快速定位可信攻击面。
