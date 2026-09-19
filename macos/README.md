# macOS / native 目标适配层

让 **任意 macOS 应用**（`.dmg` / `.pkg` / `.app`）都能被 VulnGate 审计，且 S1→S8 全线可用。

> **补丁已内置。** 本目录随 Codex 原生 `vulngate` 仓库分发，8 处补丁已直接固化在
> `scripts/agent/**` 源码中，`install.sh` 装出来的插件默认具备原生/macOS 能力 ——
> **不需要再手工给插件打补丁**。`bin/patch-vulngate.py` 保留下来做两件事：
> 回归校验（`--verify`，确认 8 处改动仍在）与回滚（`--restore`）。

---

## 一句话结论

**可行，但不是靠"换工具"，而是靠两层适配：把目标"源码化"，再补上 8 处消除 JVM 假设的改动（本仓库已内置）。**

vulngate 的 S1/S2/S3 是**扫源码**的（`rg` + 白名单扩展名）。macOS 应用里逻辑
是编译后的 Mach-O，白名单命中不了 → S1 出空、S3 拿不到 `file:line`、整条链断。
本工具把二进制的**客观元数据**还原成 `.h`/`.c` 声明树（白名单内），让确定性扫描
与 LLM 证据提取重新有素材。

---

## 目录

```
bin/
  macho2source.py     Mach-O → .h/.c 声明树（原生应用源码化，纯标准库）
  asar_tool.py        Electron app.asar 解包 + sourcemap 还原原始 TS
  asar_stats.py       app.asar 内容统计（侦察期用）
  jar2source.py       jar → .java 视图（javap 签名/字节码，或 CFR 真反编译）
  app2source.sh       归一化(DMG/PKG/app) + 按语言栈分派
  gen-config.py       生成 TargetConfig（含入口候选抽取）
  patch-vulngate.py   8 处补丁的校验/回滚器（补丁本身已内置在插件源码里）
  vg-run.py           使用 pipeline --workspace 将证据写到审计目录
templates/
  poc-native.sh       S4 原生 PoC 骨架（严守观测契约）
macos-app-recon.sh    审计前侦察：语言栈识别 + 适用性判定 + 下一步命令
run-audit.sh          一键编排
```

---

## 快速开始

```bash
# 从仓库根执行。一条命令走完：侦察 → 源码化 → 生成配置 → 落 PoC
bash macos/run-audit.sh "/Applications/Target.app" ./audit

# 想直接连跑管线（S1→S8）：
bash macos/run-audit.sh "/Applications/Target.app" ./audit --run
```

> `--apply-patch` 选项保留但已无必要：补丁在插件源码里，脚本会直接报
> `ALREADY-APPLIED`。它现在的用途是在 8 处中任何一处丢失时把它补回去。

手动分步：

```bash
S=macos   # 本目录；装好后也可用 <插件根>/macos

# 0. 回归校验：确认 8 处补丁在位（补丁已内置，纯检查）
python3 $S/bin/patch-vulngate.py --plugin <vulngate插件根> --verify

# 1. 源码化
bash $S/bin/app2source.sh "/Applications/Target.app" -o ./audit

# 2. 配置
python3 $S/bin/gen-config.py --recon ./audit/recon.json \
        --audit-root ./audit --plugin <插件根> --name target \
        -o ./audit/targets/target.json

# 3. 跑 S1 确认扫到了东西，再跑全流程
python3 $S/bin/vg-run.py --plugin <插件根> --audit-root ./audit \
        --target target --round 1 --config targets/target.json --stage S1 --force
python3 $S/bin/vg-run.py --plugin <插件根> --audit-root ./audit \
        --target target --round 1 --config targets/target.json
```

---

## 三类目标，三种源码化策略

| 语言栈 | 识别特征 | 源码化手段 | 落到白名单的扩展名 | 实测样本 |
|---|---|---|---|---|
| **Electron / Web** | `Contents/Resources/app.asar` | asar 解包；有 `.map` 时**还原原始 TS** | `.js` `.ts` `.jsx` `.tsx` | Obsidian、Electron desktop client |
| **Java** | `Contents/**/*.jar` | jar 清单喂 S1；`javap` 出 `.java` 视图 | `.java` | Burp Suite |
| **内嵌脚本** | `*.py` | 直接复制 | `.py` | LibreOffice、企业微信 |
| **原生 Mach-O** | 主可执行是 Mach-O | `otool -ov` / `nm` / `swift-demangle` / `c++filt` 重建 | `.h` `.c` | WireGuard、KeePassXC |

一个应用可以同时命中多类（如 Burp = Java + Chromium 原生壳），会全部处理。

---

## macOS 应用接入 vulngate 的四个真实约束

这几条都是实测踩出来的，不解决就会"看着配好了但扫出来是空的"。

### 1. `source_dirs` 必须是**相对** WORKSPACE 的路径

`source_evidence._safe_resolve()` 会这样校验：

```python
p = (root / str(rel)).resolve()
if str(p) == str(root) or str(p).startswith(str(root) + "/"):
    return p
return None          # ← 越界直接返回 None，扫描出空且不报错
```

扫描根之外的路径会被拒绝；建议使用相对路径。因此：

- `app2source.sh -o` 指向的目录必须包含 `reconstructed/`
- `gen-config.py --audit-root` 指向同一目录，配置里写 `"source_dirs": ["reconstructed"]`

### 2. 使用独立审计目录

管线现在支持 `--workspace <审计目录>`。`vg-run.py --audit-root` 将该路径传给
管线，并从审计目录解析相对配置路径；不再改写模块全局变量。旧调用未提供
`--workspace` 时仍保留 `<插件>/scripts` 默认值，新审计应显式使用独立目录。

插件根默认为正在执行的脚本所属 Codex 插件，可用 `--plugin`（vg-run）或
`VULNGATE_PLUGIN` 显式覆盖；不搜索任意缓存版本。Python 默认取 PATH 的
`python3`，可通过 `VULNGATE_PY` 指定。

### 3. jar 也必须能被 `relative_to(workspace)`

S1 里有这样一行：

```python
"path": str(p.relative_to(ctx.workspace)),
```

而 macOS 应用的 jar 天然在 `/Applications/...` 下 → 抛 `ValueError` → **S1 直接崩**。
这是 vulngate 自身的缺陷（`TargetConfig.resolve_jars` 明明允许任意路径）。
由补丁 #8 修掉。

### 4. `matrix --lang` 只有 `java` 和 `shell`

原生应用的 PoC 走 `--lang shell`，**无需改插件**。但必须按观测契约输出，
否则 `parse_observations` 解析不到 → G4 判"缺运行时证据"→ 拒绝确认。

---

## 8 处核心改动（已内置在插件源码里）

| # | 文件 | 改动 | 不改的后果 |
|---|---|---|---|
| 1 | `source_evidence.py` | `DEFAULT_SOURCE_GLOBS` 补 `.swift/.m/.mm/.hpp/.mjs/.cjs` | Swift/ObjC 产物不被扫描 |
| 2 | `source_evidence.py` | `DANGER_PATTERNS` 加 11 组 macOS sink | S1 危险面 10→21，原生 sink 扫不出来 |
| 3 | `source_evidence.py` | `SOURCE_MAP_PRESETS` 加 `native` 预设 | — |
| 4 | `target_rules.py` | `TARGET_RULES` 加 `native-app` | 只能退到 `library` 规则，命中 28→1 |
| 5 | `stages.py` | `_gate_scan` 去掉 `globs=["*.java"]` | 非 Java 项目 gate-scan 恒为 0 |
| 6 | `stages.py` | S2 entry 匹配去掉 `endswith(".java")` | 非 `.java` 入口 `danger_hits` 恒为 0 |
| 7 | `project_profile.py` | 后缀集补 `.h/.swift/.m/.mm` | 只影响打分 |
| 8 | `stages.py` | S1 jar 报告行容忍 workspace 外路径 | **S1 崩溃** |

**落地方式（v1.1.0 起）：** 这 8 处改动**已经直接写进仓库的 `scripts/agent/**`
源码**，`install.sh` 装出来的插件天生带这些能力 —— 无需运行时打补丁，也不会因为
插件升级而丢失。`bin/patch-vulngate.py` 因此降级为工具：

- `--verify`：回归校验。一条命令确认 8 处都还在（CI 与 `install.sh` 都会跑）。
- `--restore`：从 `<插件>/.vulngate-macos-backup/` 回滚（仅当确实 `--apply` 写过）。
- `--apply`：仅当某处意外丢失时补回去（幂等，靠 sentinel 判定，不叠加）。

`tests/test_macos_adaptation.py` 每次跑测试都会断言这 8 处仍然生效；CI 也会跑，
防止后续改动静默回退。

> ⚠️ 请改**仓库源码**再跑 `install.sh`，不要手工补**插件缓存目录**
> （`~/.codex/plugins/cache/personal/vulngate/...`）—— 那份补丁会被下次插件升级覆盖。

### 补丁前后对照（WireGuard，同一目标同一配置）

| 指标 | 原版 | 已打补丁 |
|---|---|---|
| 目标规则命中 | 1 | **28** |
| 危险调用点 | 0 | **9** |
| 命中分类 | `parser-entry:1` | `ui-entry:2, deserialization:8, command-exec:2, credential-boundary:8, dangerous-sink:8` |

---

## 原生应用的重建保真度（`macho2source.py` 会自评并写进 MANIFEST）

| 情形 | 可恢复内容 | 评级 |
|---|---|---|
| **ObjC / Cocoa 应用**（含 strip） | 类名、方法名、选择器——ObjC 元数据是**数据段**，strip 不影响 | `high` |
| **Swift 应用** | demangle 后的类型/协议/方法签名（`__swift5_*` 段） | `medium` |
| **C/C++ 未 strip** | `c++filt` 还原的 `类::方法` 签名 | `high` |
| **C/C++ 已 strip** | 只剩**外部导入 API 面** + 字符串常量 + 依赖 | `low`，需 Ghidra |
| 任意情形 | 导入 API 面、entitlements、动态库依赖 | — |

实测：WireGuard 主二进制 `objc=39` → `high`；KeePassXC（已 strip：48 定义 /
3041 未定义）→ `low`，如实报告"自有函数名已丢失，方法级结构需 Ghidra"。

**诚实的边界**：产出物是**重建视图**，不是原始源码。每个文件头都写了 provenance：

```
VULNGATE-RECONSTRUCTED  --  二进制元数据重建视图，非原始源码
注意：行号与本文件对应，**不对应原始工程行号**。方法体为空，
      因此只能断言"该符号/该 API 被引用"，不能断言"某行存在某逻辑"。
```

同理，配置的 `scope_constraints` 会把这句话注入 S2/S3 的提示词。

---

## S4：原生应用的运行时验证

`matrix --lang` 只认 `java|shell`，所以原生 PoC 走 shell。关键在观测契约
（`build.py::summarize_candidate` → `gates.py::g4_runtime`）：

```
EFFECT_KIND=command-executed|command-marker|process-started|code-execution|file-marker
EFFECT=<具体副作用描述>
```

`_has_real_effect()` **只承认这 5 种 kind**。缺 `EFFECT_KIND`、或被打成
`canary/simulat/shape-only/in-memory`，就只能停在"能力证明"，G4 会拒绝确认。

其余可用观测行：`HTTP_CODE` `RESP_MATCH` `EVIDENCE` `INSTANTIATED`(必须含点)
`LEAKED`(需含分隔符) `ERROR` `GATE_BLOCKED` `ENV_ERROR` `NETWORK` `PARSED`
`INPUT_BYTES`(OOM 放大判定必需) `CONCURRENCY`+`SERVICE_UNAVAILABLE`。

`templates/poc-native.sh` 是覆盖这五类候选面（URL Scheme / 命令执行 /
反序列化 / 本地服务 / DoS）的骨架，含"未复现就如实报 ERROR，不伪造"的写法。

> 注意：`ShellMatrixRunner` 会静态扫描脚本，**含非回环 URL/IP 会被拒跑**
> （`EGRESS_DENIED`）。本地服务测试用 `127.0.0.1`。

---

## 历史实测记录（2026-09-14）

以下记录用于说明适配层的实测边界；具体目标仍需在授权环境中重新验证。

| 样本 | 语言栈 | 源码化结果 | S1 结果 |
|---|---|---|---|
| **WireGuard** | Swift + ObjC | 3 二进制 → 29 `.h`，39 个 ObjC 类，保真度 `high` | 28 规则命中 / 9 危险点 |
| **Burp Suite** | Java + Chromium | 4 jar（55139 类）+ 8 Mach-O → 63 文件 | 16 规则命中 / **107 危险点** |
| **Obsidian** | Electron + 8 原生 | asar 15 文件 + 8 Mach-O → 92 文件 | 符号链接解析生效 |
| **KeePassXC** | C++/Qt（已 strip） | 4 自有 + 50 vendored → 44 文件 | 如实判 `low`，建议 Ghidra |
| **Large Electron asar** | Electron | 20334 文件 / 821MB / **6461 sourcemap** | 抽样 6 个 map → **还原 301 个原始源文件** |

sourcemap 还原效果（这是 Electron 审计最值钱的入口）：

```
压缩产物:  minified 单行 JS
还原产物:  'use strict';
           import CanceledError from './CanceledError.js';
           /** @param {Function} executor ... */
           class CancelToken { constructor(executor) { ... } }
```

即从打包产物里**拿回原始工程结构与行号**，S3 的 `file:line` 证据链质量直接跃升。

---

## 来源记录的工具链情况（非本次验证）

- `otool` `nm` `dyld_info` `lipo` `codesign` `strings` `hdiutil` `pkgutil` `xar` `objdump` —
  CommandLineTools 自带，齐备
- `swift-demangle` `c++filt` — **在 CLT 里**（`/Library/Developer/CommandLineTools/usr/bin/`），
  `xcrun -f` 能找到；**不需要装 Xcode**
- `nm` 的坑：`-U` 是"**不**显示未定义符号"，取外部导入面要用 `nm -u`
- `nm` 未定义符号是 2 字段格式（`U _sym`），定义符号是 3 字段 —— 判定 strip 就靠这个
- 未安装但可装：`ipsw`（brew core）、`radare2`、`ghidra`（cask 已下架，需手动下 NSA Release）
- 可选升级：把 `cfr.jar` 放到 `~/.vulngate/cfr.jar`，`jar2source.py` 会自动切到真反编译

---

## 已知限制

1. **方法体没有内容**。原生产物是声明级视图，不能据此断言"某行存在某逻辑"。
   要方法级证据需 Ghidra headless（`analyzeHeadless` 产 `.c` 伪代码，同样落在白名单内）。
2. **已 strip 的纯 C/C++ 应用**重建质量低，只有 API 面 + 字符串。
3. **8 处改动随仓库源码分发**，因此跨插件升级存活（`install.sh` 整树拷贝）。
   只有手工改插件缓存目录的那种做法会被升级覆盖 —— 请改源码仓库。
4. **目标类型需人工确认**。`gen-config.py` 的 auto 推断是保守的（Electron→`web-app`、
   Java→`library`、原生→`native-app`）。像 Burp 这种本质是代理服务的，应手动改
   `target_type` 为 `web-app` 才会命中 HTTP 规则集。
5. **S4 仍是人工活**。骨架只提供契约与候选面，具体 payload 要按目标写。

ASAR 解包对未支持的 `unpacked` / `link` 条目计入 `skipped`，需另行审阅；部分提取不等于完整源码。
