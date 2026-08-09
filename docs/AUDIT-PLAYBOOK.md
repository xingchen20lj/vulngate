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
