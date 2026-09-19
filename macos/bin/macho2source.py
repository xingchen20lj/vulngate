#!/usr/bin/env python3
"""macho2source.py -- Mach-O 二进制 -> vulngate 可扫描的 "源码化" 视图。

为什么要这一步
--------------
VulnGate 的 S1/S2/S3 靠 `rg` 扫源码，白名单见
`source_evidence.DEFAULT_SOURCE_GLOBS`。原生 macOS 应用里逻辑是编译后的
Mach-O，白名单一个都命中不了 -> S1 出空，S3 拿不到 file:line，整条链断掉。

本工具不解包成"原始源码"（做不到，也不该假装做到），而是把二进制里
**客观存在的元数据**还原成 C 声明形态的文本，落在白名单已有的扩展名
(`.h` / `.c`) 里，让 vulngate 的确定性扫描与 LLM 证据提取有真实素材。

提取来源（全部是 Apple 自带工具，零第三方依赖）
------------------------------------------------
  otool -ov       ObjC 类 / 方法 / 属性 / ivar 元数据  -> .h 接口声明
  nm -u           外部导入符号（=应用真正调用的系统 API 面）-> .h 声明
  nm / nm -g     应用自身定义的函数，Swift 符号做 demangle -> .c 函数骨架
  otool -L       动态库依赖清单 -> .h + deps 清单（喂 S5 依赖 CVE 扫描）
  strings -a     高价值字符串常量（URL / 路径 / SQL / 秘钥线索）-> .h 常量
  codesign -d    签名与 entitlements -> .h 注释

**诚实的边界**：产出物是"重建视图"，不是原始工程源码。
每个文件头部都写了 provenance 头，明确标注这一点。因此
  * 它可以支撑 攻击面测绘(S1) / 候选定位(S2) / 证据引用(S3)
  * 它 **不能** 支撑 "行号等于原始工程行号" 这类断言
真要做指令级反编译，需要 Ghidra headless（见 --ghidra 说明）。

用法
----
  macho2source.py <macho|app|dir> -o <outdir> [--arch arm64|x86_64]
                  [--max-strings 4000] [--jobs 4]
"""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

VERSION = "1.0.0"

# --------------------------------------------------------------------------- #
# 外部 API 分类表：native 攻击面的判定依据。
# 命中即写入对应分类的 .h，并在 MANIFEST 里给出 vulngate 危险模式标签，
# 便于 S1 的 danger-call-site 扫描与 S2 的候选排序。
# --------------------------------------------------------------------------- #
API_BUCKETS: List[Tuple[str, str, str]] = [
    # (bucket, vulngate 标签, 正则 -- 匹配 nm 导入符号去掉前导下划线后的名字)
    ("process-exec", "native-command-exec",
     r"^(?:posix_spawn|posix_spawnp|execve|execv|execl|execle|execvp|system|popen|fork|vfork|"
     r"NSTask|NSLaunch|SMJobSubmit)$"),
    ("credential", "native-credential",
     r"^(?:SecItem[A-Za-z]*|SecKeychain[A-Za-z]*|SecKey[A-Za-z]*|SecIdentity[A-Za-z]*|"
     r"SecTrust[A-Za-z]*|SecAccess[A-Za-z]*|SecRandomCopyBytes|SecCode[A-Za-z]*)$"),
    ("crypto", "native-crypto-weak",
     r"^(?:CCCrypt[A-Za-z]*|CCHmac|CC_MD[245]|CC_SHA1|CCRC4|CCDES|MD5|SHA1|EVP_[A-Za-z_]+|"
     r"DES_[a-z]+|RC4)$"),
    ("deserialization", "native-deserialization",
     r"^(?:NSKeyedUnarchiver|NSKeyedArchiver|CFPropertyListCreate[A-Za-z]*|"
     r"NSPropertyListSerialization|propertyListWithData|unarchiv[A-Za-z]*|"
     r"xmlReadMemory|xmlParseMemory|sqlite3_open[A-Za-z0-9]*|sqlite3_exec)$"),
    ("dynamic-load", "native-dynamic-load",
     r"^(?:dlopen|dlsym|dlclose|NSAddImage|NSLookupSymbolInImage|NSCreateObjectFileImageFromFile)$"),
    ("file-io", "native-file-io",
     r"^(?:fopen|open|openat|freopen|unlink|remove|rename|mkdir|rmdir|chmod|chown|chflags|"
     r"NSFileManager|NSData|write|pwrite|truncate|ftruncate|mkstemp|realpath|readlink)$"),
    ("unsafe-c", "native-unsafe-c",
     r"^(?:strcpy|strcat|sprintf|vsprintf|gets|alloca|memcpy|memmove|strncpy|strncat|snprintf|"
     r"scanf|sscanf|realpath)$"),
    ("webview-bridge", "native-webview-bridge",
     r"^(?:WKWebView|WKUserContentController|WKScriptMessageHandler|JSContext|JSValue|"
     r"evaluateJavaScript|WKWebViewConfiguration|WKPreferences|JSGlobalContextRef)$"),
    ("ipc", "native-ipc",
     r"^(?:xpc_[a-z_]+|NSXPC[A-Za-z]*|mach_msg[a-z_]*|bootstrap_[a-z_]+|CFMessagePort[A-Za-z]*|"
     r"CFNotificationCenter[A-Za-z]*|NSDistributedNotification[A-Za-z]*|"
     r"NSMachPort|NSPort|NSConnection)$"),
    ("applescript", "native-applescript",
     r"^(?:NSAppleScript|OSAScript[A-Za-z]*|AEDesc|AESend|AECreateDesc|OSACompileExecute|"
     r"executeAppleEvent|NSAppleEventDescriptor)$"),
    ("privilege", "native-privilege",
     r"^(?:AuthorizationCreate|AuthorizationExecuteWithPrivileges|AuthorizationCopyRights|"
     r"setuid|setgid|seteuid|setegid|SMJobBless|SMCopyEngineResult)$"),
    ("network", "native-network",
     r"^(?:socket|connect|bind|listen|accept|socketpair|sendto|recvfrom|getaddrinfo|"
     r"NSURLSession|CFStreamCreate[A-Za-z]*|CFReadStream[A-Za-z]*|CFWriteStream[A-Za-z]*|"
     r"curl_easy_[a-z]+|SCNetwork[A-Za-z]*)$"),
    ("memory", "native-memory",
     r"^(?:malloc|calloc|realloc|free|mmap|mprotect|vm_allocate|vm_protect|vm_deallocate|"
     r"vm_map|mach_vm_[a-z_]+)$"),
    ("logging", "native-logging",
     r"^(?:asl_[a-z_]+|os_log[a-z_]*|NSLog|CFLog|syslog)$"),
    ("ui-entry", "native-ui-entry",
     r"^(?:NSApplicationMain|NSApplication|UIApplication|RunApplicationEventLoop|"
     r"NSApp|NSWindow|NSViewController|NSView)$"),
]
API_BUCKETS_C = [(b, t, re.compile(p)) for b, t, p in API_BUCKETS]

# 进入源码视图的字符串常量筛选
INTERESTING_STRING_PATTERNS: List[Tuple[str, str]] = [
    ("url", r"^(?:https?|ftp|ws|wss|file|smb|ssh)://\S+$"),
    ("url-scheme", r"^[a-z][a-z0-9+.\-]{2,40}$"),
    ("path", r"^(?:/|~)[\w\-./%@ ]{2,200}$"),
    ("sql", r"(?i)\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.{0,180}"),
    ("format", r"^.{0,120}%(?:@|n|s|d|lu|x)\b.{0,120}$"),
    ("secret-ish", r"(?i)\b(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|"
                   r"authorization|bearer|client[_-]?secret)\b.{0,120}"),
    ("xpc-service", r"^[a-z0-9]+(?:[.-][a-z0-9]+){2,}$"),
    ("shell-cmd", r"(?i)\b(?:/bin/|/usr/bin/|/usr/sbin/|/sbin/|bash|sh -c|osascript|"
                  r"defaults write|launchctl|networksetup)\b.{0,120}"),
    ("keychain-attr", r"(?i)\b(?:kSecAttr|kSecClass|kSecValue|kSecReturn)\w+"),
    ("entitlement", r"(?i)\b(?:com\.apple\.security|application-identifier|"
                    r"get-task-allow|disable-library-validation)\b"),
]

# ObjC 里值得单独成节的入口/危险方法名
OBJC_INTERESTING = re.compile(
    r"(?i)(openURL|openFile|handleOpen|application:open|applicationDidFinish|"
    r"handleGetURL|executeShell|runCommand|launch|spawn|exec|performSelector|"
    r"evaluateJavaScript|addScriptMessageHandler|userContentController|"
    r"unarchiv|valueForKey|setValue:forKey|initWithCoder|encodeWithCoder|"
    r"keychain|credential|password|token|decrypt|encrypt|verify|authoriz|"
    r"loadRequest|loadHTMLString|openDocument|readFrom|writeTo|deleteFile)"
)

PROVENANCE = """/* ==========================================================================
 * VULNGATE-RECONSTRUCTED  --  二进制元数据重建视图，非原始源码
 * --------------------------------------------------------------------------
 * 目标      : {target}
 * 产物来源  : {sources}
 * 生成工具  : macho2source.py v{version}
 * 生成时间  : {ts}
 * --------------------------------------------------------------------------
 * 注意：本文件不是原始工程源码，行号与本文件对应，**不对应原始工程行号**。
 *      内容由 Mach-O 元数据（符号表 / ObjC 运行时结构 / 依赖表 / 常量池）
 *      还原而来，用于攻击面测绘与证据定位；方法体为空（未做指令级反编译），
 *      因此不能据此断言"某行存在某逻辑"，只能断言"该符号/该 API 被引用"。
 *      需要方法体级证据时，请用 Ghidra headless 产出真正的 .c 伪代码。
 * ========================================================================== */
"""  # noqa: E501


# --------------------------------------------------------------------------- #
# 子进程工具
# --------------------------------------------------------------------------- #
def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run(cmd: Sequence[str], timeout: int = 300) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""
    if p.returncode != 0 and not p.stdout:
        return ""
    return p.stdout or ""


def _tool_path(name: str, fallback: str) -> Optional[str]:
    """定位 CLT 工具（无 Xcode 时 xcrun -f 仍可用）。"""
    p = shutil.which(name)
    if p:
        return p
    out = run(["xcrun", "-f", name], timeout=20).strip()
    if out and Path(out).exists():
        return out
    return fallback if Path(fallback).exists() else None


def demangle(symbols: List[str]) -> Dict[str, str]:
    """Swift 与 C++ 符号一起 demangle，返回 mangled -> 可读签名。

    Swift: `swift-demangle`，输出 `input ---> output`。
    C++  : `c++filt`，输出为输入（未变）或还原后的签名。
    只有真正发生变化（即可还原）的条目才进入结果。
    """
    if not symbols:
        return {}
    out: Dict[str, str] = {}
    chunk = 400

    swift_exe = _tool_path("swift-demangle",
                           "/Library/Developer/CommandLineTools/usr/bin/swift-demangle")
    cxx_exe = _tool_path("c++filt", "/usr/bin/c++filt")
    swift_syms = [s for s in symbols if s.startswith(("$s", "$S", "$s", "_$s")) or
                  s.startswith("$s") or "$s" in s[:3] or s.startswith("_T")]
    cxx_syms = [s for s in symbols if s.startswith("_Z")]

    for i in range(0, len(swift_syms), chunk):
        batch = swift_syms[i:i + chunk]
        if not swift_exe:
            break
        p = subprocess.run([swift_exe] + batch, capture_output=True, text=True,
                           errors="replace")
        for line in (p.stdout or "").splitlines():
            if " ---> " in line:
                src, _, dst = line.partition(" ---> ")
                src, dst = src.strip(), dst.strip()
                if src and dst and src != dst:
                    out[src] = dst

    for i in range(0, len(cxx_syms), chunk):
        batch = cxx_syms[i:i + chunk]
        if not cxx_exe:
            break
        p = subprocess.run([cxx_exe] + batch, capture_output=True, text=True,
                           errors="replace")
        outs = [ln.strip() for ln in (p.stdout or "").splitlines() if ln.strip()]
        for src, dst in zip(batch, outs):
            if dst and dst != src:
                out[src] = dst
    return out


# --------------------------------------------------------------------------- #
# Mach-O 解析
# --------------------------------------------------------------------------- #
def is_macho(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            magic = fh.read(4)
    except OSError:
        return False
    return magic in (
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",   # MH_MAGIC / MH_CIGAM
        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",   # 64-bit
        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",   # FAT
        b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",   # FAT_64
    )


def archs_of(path: Path) -> List[str]:
    out = run(["lipo", "-archs", str(path)], timeout=60).strip()
    return out.split() if out else []


def pick_arch(path: Path, want: Optional[str]) -> Optional[str]:
    archs = archs_of(path)
    if not archs:
        return None
    if want and want in archs:
        return want
    host = "arm64" if os.uname().machine == "arm64" else "x86_64"
    if host in archs:
        return host
    return archs[0]


def parse_imports(path: Path, arch: Optional[str]) -> List[str]:
    cmd = ["nm", "-u"]
    if arch:
        cmd += ["-arch", arch]
    cmd.append(str(path))
    syms = []
    for line in run(cmd, timeout=180).splitlines():
        parts = line.split()
        if not parts:
            continue
        s = parts[-1]
        if s.startswith("_"):
            s = s[1:]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s):
            syms.append(s)
    return sorted(set(syms))


def parse_defined(path: Path, arch: Optional[str]) -> List[str]:
    cmd = ["nm"]
    if arch:
        cmd += ["-arch", arch]
    cmd.append(str(path))
    syms = []
    for line in run(cmd, timeout=180).splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        kind, name = parts[-2], parts[-1]
        if kind not in ("T", "t", "S", "s", "D", "d"):
            continue
        if name.startswith("_"):
            name = name[1:]
        if name and not name.startswith("__"):
            syms.append(name)
    return sorted(set(syms))


def symbol_stats(path: Path, arch: Optional[str]) -> Dict[str, int]:
    """统计定义/未定义符号数，用于判定是否被 strip 以及重建质量。"""
    cmd = ["nm"]
    if arch:
        cmd += ["-arch", arch]
    cmd.append(str(path))
    defined = undefined = 0
    for line in run(cmd, timeout=180).splitlines():
        parts = line.split()
        if len(parts) >= 3:
            defined += 1
        elif len(parts) == 2:
            undefined += 1
    return {"defined": defined, "undefined": undefined}


def reconstruction_quality(stats: Dict[str, int], objc_classes: int,
                           demangled: int, swift_meta: bool) -> Tuple[str, str]:
    """给出"重建保真度"评级与原因。诚实标注，避免高估产物能力。

    Returns (grade, reason)，grade ∈ {high, medium, low}。
    """
    d, u = stats.get("defined", 0), stats.get("undefined", 0)
    stripped = d < 50 and u > 500
    # ObjC 运行时元数据优先级最高：它是数据段，strip 不影响，可完整还原类/方法
    if objc_classes >= 5:
        return "high", ("ObjC 运行时元数据存活（%d 个类）：类名/方法名/选择器可完整还原，"
                        "strip 不影响%s" % (objc_classes,
                                             "；叠加 Swift 元数据" if swift_meta else ""))
    if swift_meta:
        return "medium", ("Swift 元数据段存在：类型/协议/方法签名可还原，"
                          "但方法体需反编译（%s）" % ("已 strip" if stripped else "未 strip"))
    if stripped:
        return "low", ("已 strip：自有函数名丢失（定义 %d / 未定义 %d）。"
                       "仅可还原外部 API 调用面、字符串常量与依赖；"
                       "方法级结构需 Ghidra headless" % (d, u))
    if demangled >= 100:
        return "high", "未 strip：%d 个 C++/Swift 符号已还原为可读签名" % demangled
    return "medium", "符号量有限（定义 %d / 反解 %d）：以导入面与字符串为主" % (d, demangled)


def parse_objc(path: Path, arch: Optional[str]) -> Dict[str, Dict[str, List[str]]]:
    """解析 `otool -ov`，还原 ObjC 类 -> {methods, properties, ivars}。

    otool -ov 的缩进即语义层级：
      4 空格  isa / superclass
      8 空格  name(类名) / baseMethods / baseProperties / ivars
     12 空格  name(成员名) / types / imp
    """
    cmd = ["otool", "-ov"]
    if arch:
        cmd += ["-arch", arch]
    cmd.append(str(path))
    text = run(cmd, timeout=420)
    if not text:
        return {}

    classes: Dict[str, Dict[str, List[str]]] = {}
    in_classlist = False
    cur_class: Optional[str] = None
    bucket: Optional[str] = None

    for line in text.splitlines():
        m = re.match(r"^Contents of \((.+?)\) section", line)
        if m:
            in_classlist = "__objc_classlist" in m.group(1)
            continue
        if not in_classlist:
            continue
        m = re.match(r"^ {8}name\s+0x[0-9a-fA-F]+\s+(\S+)\s*$", line)
        if m:
            cur_class = m.group(1)
            classes.setdefault(cur_class, {"methods": [], "properties": [], "ivars": []})
            bucket = None
            continue
        m = re.match(r"^ {8}(baseMethods|baseProperties|ivars)\b", line)
        if m:
            bucket = {"baseMethods": "methods", "baseProperties": "properties",
                      "ivars": "ivars"}[m.group(1)]
            continue
        m = re.match(r"^ {12}name\s+0x[0-9a-fA-F]+\s+(\S+)\s*$", line)
        if m and cur_class and bucket:
            classes[cur_class][bucket].append(m.group(1))
    return {k: v for k, v in classes.items() if any(v.values())}


def parse_deps(path: Path, arch: Optional[str]) -> List[str]:
    cmd = ["otool", "-L"]
    if arch:
        cmd += ["-arch", arch]
    cmd.append(str(path))
    out = []
    for i, line in enumerate(run(cmd, timeout=120).splitlines()):
        if i == 0:
            continue
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^(\S+)\s+\(", line)
        if not m:
            m = re.match(r"^(\S+)", line)
        if m:
            out.append(m.group(1))
    return out


def parse_strings(path: Path, limit: int) -> Dict[str, List[str]]:
    text = run(["strings", "-a", "-n", "6", str(path)], timeout=300)
    buckets: Dict[str, List[str]] = {}
    seen = set()
    for raw in text.splitlines():
        s = raw.strip()
        if not s or len(s) > 220 or s in seen:
            continue
        for label, pat in INTERESTING_STRING_PATTERNS:
            if re.search(pat, s):
                if label == "url-scheme" and not re.fullmatch(
                        r"[a-z][a-z0-9+.\-]{2,40}", s):
                    continue
                seen.add(s)
                b = buckets.setdefault(label, [])
                if len(b) < limit:
                    b.append(s)
                break
    return buckets


def parse_entitlements(path: Path) -> List[str]:
    out = run(["codesign", "-d", "--entitlements", ":-", str(path)], timeout=60)
    return [ln.strip() for ln in out.splitlines() if ln.strip()][:80]


def parse_info_plist(app: Path) -> Dict[str, object]:
    p = app / "Contents" / "Info.plist"
    if not p.exists():
        return {}
    try:
        with p.open("rb") as fh:
            return plistlib.load(fh)
    except Exception:
        return {}


# --------------------------------------------------------------------------- #
# 输出：把提取结果写成 .h / .c
# --------------------------------------------------------------------------- #
def _cstr(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def write_objc_header(out: Path, name: str, classes, target: str, ts: str) -> int:
    lines = [PROVENANCE.format(target=target, version=VERSION, ts=ts,
                               sources="otool -ov (__objc_classlist 元数据)")]
    lines.append("#ifndef VULNGATE_RECON_OBJC_H")
    lines.append("#define VULNGATE_RECON_OBJC_H")
    lines.append("")
    for cls in sorted(classes):
        info = classes[cls]
        lines.append("/* [objc-class] %s */" % cls)
        lines.append("@interface %s : NSObject" % cls)
        for prop in info.get("properties", []):
            lines.append("- (id)%s;  /* [objc-property] */" % prop)
        for meth in info.get("methods", []):
            tag = " [entry-candidate]" if OBJC_INTERESTING.search(meth) else ""
            lines.append("- (id)%s;  /* [objc-method]%s */" % (meth, tag))
        for ivar in info.get("ivars", []):
            lines.append("    /* [objc-ivar] %s */" % ivar)
        lines.append("@end")
        lines.append("")
    lines.append("#endif")
    (out / (name + "_objc.h")).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return sum(len(v.get("methods", [])) for v in classes.values())


def write_api_headers(out: Path, imports: List[str], target: str, ts: str,
                      deps: List[str], ents: List[str]) -> Dict[str, int]:
    by_bucket: Dict[str, List[str]] = {}
    label_of: Dict[str, str] = {}
    for sym in imports:
        for bucket, label, rx in API_BUCKETS_C:
            if rx.match(sym):
                by_bucket.setdefault(bucket, []).append(sym)
                label_of[bucket] = label
                break
    for bucket in sorted(by_bucket):
        syms = sorted(set(by_bucket[bucket]))
        lines = [PROVENANCE.format(
            target=target, version=VERSION, ts=ts,
            sources="nm -u (外部导入符号 = 应用实际调用的系统 API)")]
        lines.append("/* vulngate danger-label: %s  --  命中 %d 个符号 */"
                     % (label_of.get(bucket, "native-api"), len(syms)))
        lines.append("")
        for s in syms:
            lines.append("extern void *%s(void);  /* [%s] */" % (s, label_of.get(bucket)))
        (out / ("api_%s.h" % bucket.replace("-", "_"))).write_text(
            "\n".join(lines) + "\n", encoding="utf-8")

    # 未归类的导入：整体落一个文件，保证 API 面不丢（超出上限则截断并注明）
    unclassified = [s for s in imports
                    if not any(rx.match(s) for _, _, rx in API_BUCKETS_C)]
    if unclassified:
        cap = 1500
        unclassified = sorted(set(unclassified))
        shown = unclassified[:cap]
        lines = [PROVENANCE.format(
            target=target, version=VERSION, ts=ts, sources="nm -u (未归类导入符号)")]
        if len(unclassified) > cap:
            lines.append("/* 共 %d 条，此处截断展示前 %d 条；完整清单见 MANIFEST.json */"
                         % (len(unclassified), cap))
        for s in shown:
            lines.append("extern void *%s(void);  /* [native-api-other] */" % s)
        (out / "api_other.h").write_text("\n".join(lines) + "\n", encoding="utf-8")

    if deps:
        lines = [PROVENANCE.format(
            target=target, version=VERSION, ts=ts, sources="otool -L (动态库依赖)")]
        lines.append("/* 这些依赖用于 S5 的依赖 CVE 扫描（OSV 查询） */")
        for d in deps:
            lines.append('extern const char *dep_%s;  /* [native-dep] %s */'
                         % (re.sub(r"\W", "_", Path(d).stem), d))
        (out / "api_deps.h").write_text("\n".join(lines) + "\n", encoding="utf-8")

    if ents:
        lines = [PROVENANCE.format(
            target=target, version=VERSION, ts=ts,
            sources="codesign -d --entitlements (签名授权)")]
        for e in ents:
            lines.append("/* [entitlement] %s */" % e)
        (out / "api_entitlements.h").write_text("\n".join(lines) + "\n",
                                                encoding="utf-8")
    return {k: len(set(v)) for k, v in by_bucket.items()}


def write_symbol_header(out: Path, defined: List[str], demangled: Dict[str, str],
                        strings: Dict[str, List[str]], target: str, ts: str) -> None:
    swift = [(s, demangled.get(s)) for s in defined if s in demangled]
    plain = [s for s in defined if s not in demangled]
    swift.sort(key=lambda kv: (len(kv[0]), kv[0]))

    lines = [PROVENANCE.format(
        target=target, version=VERSION, ts=ts,
        sources="nm + swift-demangle (应用自身定义的函数符号)")]
    lines.append("/* Swift 符号 demangle 后共 %d 条（按 mangled 长度截断展示） */"
                 % len(swift))
    lines.append("")
    for mangled, dem in swift[:6000]:
        body = (dem or "").replace("*/", "*_/").replace("\n", " ")
        flag = " [entry-candidate]" if re.search(
            r"(?i)(shell|exec|command|launch|spawn|keychain|credential|password|"
            r"token|unarchiv|parse|decode|read|write|open|url|file|path|script|"
            r"evaluate|authoriz|privilege|install|update)", body) else ""
        lines.append('void %s(void);  /* [swift] %s%s */'
                     % (re.sub(r"\W", "_", mangled)[:120] or "sym", body, flag))
    for s in plain[:3000]:
        lines.append("void %s(void);  /* [symbol] */" % re.sub(r"\W", "_", s)[:120])
    (out / "symbols.h").write_text("\n".join(lines) + "\n", encoding="utf-8")

    if strings:
        lines = [PROVENANCE.format(
            target=target, version=VERSION, ts=ts,
            sources="strings -a (常量池筛选)")]
        for label in sorted(strings):
            lines.append("/* ---- %s ---- */" % label)
            for s in sorted(set(strings[label])):
                lines.append('const char *k_%s = "%s";  /* [%s] */'
                             % (re.sub(r"\W", "_", Path(s).stem)[:40] or "s",
                                _cstr(s)[:200], label))
            lines.append("")
        (out / "strings.h").write_text("\n".join(lines) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- #
# 单文件处理
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# 自有代码 vs 第三方库的划分
#
# 实测动机（KeePassXC）：一个 .app 里能扫出 54 个 Mach-O，其中 50 个是
# vendored 的 Qt/openssl/botan。若全部塞进 source_dirs，S1 的攻击面会被
# 第三方库淹没，候选排序失真。所以：
#   primary  -> 进入 source_dirs，参与 S1/S2/S3
#   vendor   -> 不进 source_dirs，只产出依赖清单与轻量符号索引（喂 S5 OSV）
# --------------------------------------------------------------------------- #
VENDOR_NAME_RE = re.compile(
    r"^(?:lib|Qt|Electron|Squirrel|Sparkle|ReactiveCocoa|Mantle|AFNetworking|"
    r"SDWebImage|CocoaLumberjack|Protobuf|gRPC|abseil|boringssl|openssl|"
    r"chrome_crashpad|Mono|node|v8|ffmpeg|libav|sqlite|zlib|libusb)")


def _norm_name(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def classify_binary(path: Path, app: Path, main_exe: Optional[str]) -> str:
    """返回 'primary' | 'vendor'。保守优先：拿不准就归 primary（宁可多扫不可漏审）。

    关键用例（实测）：KeePassXC 的主可执行是个瘦启动器，自有实现在
    `libkeepassxc-*.dylib` 里 —— 名字带 `lib` 前缀也不能算 vendored。
    因此先做"库名是否含应用名"的匹配，再退到 lib*/已知厂商前缀规则。
    """
    try:
        rel = path.resolve().relative_to(app.resolve())
    except ValueError:
        return "primary"
    parts = rel.parts
    app_norm = _norm_name(app.stem)
    stem_norm = _norm_name(path.stem)

    # 1) 应用自有库：名字里含应用名（libkeepassxc-core / libobsidian-helpers ...）
    if app_norm and app_norm in stem_norm and stem_norm != app_norm:
        return "primary"

    # 主可执行 / Contents/MacOS 下的自有工具（CLI、代理、插件 .so）-> 自有
    if len(parts) >= 3 and parts[0] == "Contents" and parts[1] == "MacOS":
        if main_exe and path.name == main_exe:
            return "primary"
        # MacOS 下带 libxxx 前缀的才是 vendored
        return "vendor" if (path.suffix in (".dylib", ".so")
                            or VENDOR_NAME_RE.match(path.name)) else "primary"

    # 嵌套 .app / .appex / XPCServices -> 自有代码（helper 与扩展常承载解析逻辑）
    if any(p.endswith((".app", ".appex", ".xpc")) for p in parts):
        return "primary"

    # Frameworks / PlugIns 下的 .framework -> 名称像产品名的算自有，lib* 算 vendored
    if "Frameworks" in parts or "PlugIns" in parts:
        if path.suffix in (".dylib", ".so") or VENDOR_NAME_RE.match(path.stem):
            return "vendor"
        return "primary"

    if path.suffix in (".dylib", ".so"):
        return "vendor"
    return "primary"


def collect_binaries(target: Path, scope: str = "main") -> List[Tuple[Path, str]]:
    """找出目标里的所有 Mach-O，并标注 primary / vendor。

    返回 [(path, bucket)]，bucket ∈ {primary, vendor}。
    scope='main' 时仅返回 primary；'all' 时两者都返回。
    """
    if target.is_file():
        if not is_macho(target):
            return []
        return [(target, "primary")]

    app = target
    info = parse_info_plist(app)
    main_exe = str(info.get("CFBundleExecutable")) if info.get("CFBundleExecutable") else None

    found: List[Path] = []
    if main_exe:
        p = app / "Contents" / "MacOS" / main_exe
        if p.exists() and is_macho(p):
            found.append(p)
    macos_dir = app / "Contents" / "MacOS"
    if macos_dir.is_dir():
        for p in sorted(macos_dir.iterdir()):
            if p.is_file() and is_macho(p):
                found.append(p)
    for sub in ("Frameworks", "PlugIns", "XPCServices", "Helpers",
                "Library/LoginItems", "Library/XPCServices"):
        root = app / "Contents" / sub
        if not root.is_dir():
            continue
        for p in sorted(root.rglob("*")):
            if p.is_file() and is_macho(p):
                found.append(p)
    for p in sorted((app / "Contents").rglob("*.app")):
        info2 = parse_info_plist(p)
        e2 = info2.get("CFBundleExecutable")
        if e2:
            q = p / "Contents" / "MacOS" / str(e2)
            if q.exists() and is_macho(q):
                found.append(q)

    seen, uniq = set(), []
    for p in found:
        rp = p.resolve()
        if rp not in seen:
            seen.add(rp)
            uniq.append(p)

    tagged = [(p, classify_binary(p, app, main_exe)) for p in uniq]
    if scope == "main":
        tagged = [(p, b) for p, b in tagged if b == "primary"]
    return tagged


def process_binary(path: Path, out_root: Path, target_label: str, arch: Optional[str],
                   max_strings: int, ts: str, bucket: str = "primary") -> Dict[str, object]:
    rel = re.sub(r"[^\w.\-]+", "_", str(path.name))
    out = out_root / bucket / rel
    out.mkdir(parents=True, exist_ok=True)
    chosen = pick_arch(path, arch)

    imports = parse_imports(path, chosen)
    defined = parse_defined(path, chosen)
    demangled = demangle(defined)
    objc = parse_objc(path, chosen)
    deps = parse_deps(path, chosen)
    strings = parse_strings(path, max_strings)
    ents = parse_entitlements(path)
    stats = symbol_stats(path, chosen)

    load_cmds = run(["otool", "-l", str(path)], timeout=180)
    swift_meta = "__swift5_proto" in load_cmds or "__swift5_typeref" in load_cmds
    grade, reason = reconstruction_quality(stats, len(objc), len(demangled), swift_meta)

    buckets = write_api_headers(out, imports, str(path), ts, deps, ents)
    meth_count = write_objc_header(out, rel, objc, str(path), ts)
    write_symbol_header(out, defined, demangled, strings, str(path), ts)

    return {
        "binary": str(path),
        "bucket": bucket,
        "arch": chosen,
        "archs": archs_of(path),
        "defined_symbols": stats.get("defined", 0),
        "undefined_symbols": stats.get("undefined", 0),
        "stripped": stats.get("defined", 0) < 50 and stats.get("undefined", 0) > 500,
        "swift_metadata": swift_meta,
        "reconstruction_grade": grade,
        "reconstruction_reason": reason,
        "imports": len(imports),
        "demangled": len(demangled),
        "objc_classes": len(objc),
        "objc_methods": meth_count,
        "deps": deps,
        "entitlements": ents,
        "string_buckets": {k: len(v) for k, v in strings.items()},
        "api_buckets": buckets,
        "out_dir": str(out),
        "files": sorted(p.name for p in out.iterdir()),
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Mach-O -> vulngate 可扫描的源码化视图（.h/.c 声明树）")
    ap.add_argument("target", help="Mach-O 文件 / .app / 含 .app 的目录")
    ap.add_argument("-o", "--out", required=True, help="输出去（会成为 source_dirs）")
    ap.add_argument("--arch", default=None, help="优先架构（默认跟随宿主）")
    ap.add_argument("--max-strings", type=int, default=3000,
                    help="每个字符串分类的上限")
    ap.add_argument("--scope", choices=["main", "all"], default="main",
                    help="main=只源码化自有代码（recommended）；all=连 vendored 库一起")
    ap.add_argument("--jobs", type=int, default=4)
    args = ap.parse_args(argv)

    for tool in ("otool", "nm", "strings", "lipo"):
        if not have(tool):
            print("ERROR: 缺少必需工具 %s（需安装 Xcode Command Line Tools）" % tool,
                  file=sys.stderr)
            return 2

    target = Path(args.target).expanduser().resolve()
    if not target.exists():
        print("ERROR: 目标不存在: %s" % target, file=sys.stderr)
        return 2

    import datetime
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    out_root = Path(args.out).expanduser().resolve()
    out_root.mkdir(parents=True, exist_ok=True)

    # 先全量枚举以便统计 vendor，再按 scope 决定实际处理哪些
    every = collect_binaries(target, scope="all")
    binaries = collect_binaries(target, scope=args.scope)
    if not binaries:
        print("WARN: 未找到任何可处理的 Mach-O（目标可能是纯脚本/资源包）",
              file=sys.stderr)
        return 1

    primary_n = sum(1 for _, b in every if b == "primary")
    vendor_n = sum(1 for _, b in every if b == "vendor")
    print("[macho2source] 目标: %s" % target)
    print("[macho2source] 枚举到 %d 个 Mach-O（自有 %d / 第三方 %d），本次处理 %d 个（scope=%s）"
          % (len(every), primary_n, vendor_n, len(binaries), args.scope))

    results = []
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futs = [pool.submit(process_binary, b, out_root, str(target), args.arch,
                            args.max_strings, ts, bucket) for b, bucket in binaries]
        for f in futs:
            try:
                results.append(f.result())
            except Exception as exc:  # 单个二进制失败不拖垮整体
                print("  ! 处理失败: %s" % exc, file=sys.stderr)

    # vendored 依赖汇总：即使 scope=main 也要产出，供 S5 做 OSV 依赖 CVE 扫描
    vendor_deps = sorted({d for p, b in every if b == "vendor"
                          for d in parse_deps(p, pick_arch(p, None))})

    manifest = {
        "tool": "macho2source.py",
        "version": VERSION,
        "generated_at": ts,
        "target": str(target),
        "scope": args.scope,
        "binary_count": len(binaries),
        "enumerated": {"primary": primary_n, "vendor": vendor_n},
        "note": "重建视图（二进制元数据），非原始源码；行号仅对应生成文件。",
        "vendor_deps": vendor_deps,
        "binaries": results,
    }
    (out_root / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    total_files = sum(len(r["files"]) for r in results)
    print("[macho2source] 完成: %d 个二进制 -> %d 个声明文件" % (len(results), total_files))
    for r in results:
        print("  [%s] %-28s arch=%-7s 导入=%-5d 反解=%-5d objc=%-4d 保真度=%s%s"
              % (r["bucket"], Path(r["binary"]).name, r["arch"], r["imports"],
                 r["demangled"], r["objc_classes"], r["reconstruction_grade"],
                 " (strip)" if r["stripped"] else ""))
    print()
    print("[macho2source] 重建保真度说明:")
    for r in results:
        print("  %-28s %s" % (Path(r["binary"]).name, r["reconstruction_reason"]))
    print("[macho2source] 清单: %s" % (out_root / "MANIFEST.json"))
    if vendor_deps:
        print("[macho2source] vendored 依赖 %d 条（已写入 MANIFEST 供 S5 扫描）"
              % len(vendor_deps))
    return 0


if __name__ == "__main__":
    sys.exit(main())
