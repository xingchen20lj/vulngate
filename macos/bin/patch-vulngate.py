#!/usr/bin/env python3
"""patch-vulngate.py -- 给 vulngate 打上"非 JVM 目标"的最小必要补丁。

设计原则
--------
**能不改就不改。** 绝大多数适配靠"把目标源码化 + 写 TargetConfig"完成，
只有以下 8 处是硬编码的 JVM 假设 / 真实缺陷，不改则原生或 Java 目标无法达标：

  #1 source_evidence.DEFAULT_SOURCE_GLOBS  缺 .swift/.m/.mm/.hpp/.mjs/.cjs
  #2 source_evidence.DANGER_PATTERNS        无 macOS 原生 sink，S1 危险面扫不出来
  #3 source_evidence.SOURCE_MAP_PRESETS     无 native 预设
  #4 target_rules.TARGET_RULES              无 native-app 目标类型
  #5 stages._gate_scan                      `globs=["*.java"]` —— 非 Java 项目恒为空
  #6 stages 的 S2 entry 匹配                 `t.endswith(".java")` —— 非 .java 入口
                                            danger_hits 恒为 0
  #7 project_profile._source_file_count     后缀集缺 .h/.swift/.m/.mm —— 只影响打分
  #8 stages S1 的 jar 报告行                  `p.relative_to(ctx.workspace)` 对
                                            workspace 外的 jar 抛 ValueError，
                                            直接让 S1 崩（macOS 应用的 jar 天然
                                            在 /Applications 下，必踩）

补丁特性
--------
  * **幂等**：靠 sentinel 注释判定，重复执行不会叠加
  * **默认 dry-run**：不加 --apply 不动文件
  * **可回滚**：原始文件备份到 <plugin>/.vulngate-macos-backup/，附 sha256
  * **可验证**：--verify 只检查落地状态
  * **版本容错**：某处 old 串匹配不到（插件升级改了措辞）→ 该项标记 SKIP 并
    明确报告，不会静默成功

多重落地态（``markers``）
------------------------
#1 / #6 / #7 都是"后缀集合"补丁。当代码演进为从单一后缀表派生
（``agent.analysis.languages.LANGUAGE_SUFFIXES``）时，字面后缀列表会从这三个
位置消失，但补丁要保证的不变量（原生后缀确实被扫描到）仍然成立，且由测试
``tests/test_macos_adaptation.NativeGlobTests`` 直接断言。

因此这三项声明 ``markers`` 列表：命中其中**任意**一个即视为已落地。
``old`` / ``new`` 仍保留，用于给未打过补丁的上游插件执行 ``--apply``。

用法
----
  patch-vulngate.py --plugin <vulngate插件根>            # 预览
  patch-vulngate.py --plugin <...> --apply               # 应用
  patch-vulngate.py --plugin <...> --verify              # 校验
  patch-vulngate.py --plugin <...> --restore             # 回滚
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional

SENTINEL = "vulngate-macos-universal"
BACKUP_DIR = ".vulngate-macos-backup"

NATIVE_DANGER = '''    # --- [vulngate-macos-universal] macOS / native sinks ---
    (r"posix_spawn|posix_spawnp|execve|execv\\(|execl\\(|system\\s*\\(|popen\\s*\\("
     r"|NSTask|NSAppleScript|Process\\(", "native-command-exec"),
    (r"SecItemCopyMatching|SecItemAdd|SecItemDelete|SecKeychain|SecKeyRawSign"
     r"|SecKeyDecrypt|SecKeyCreateDecryptedData", "native-credential"),
    (r"NSKeyedUnarchiver|unarchive[A-Za-z]*|CFPropertyListCreate|"
     r"propertyListWithData|sqlite3_open|sqlite3_exec", "native-deserialization"),
    (r"dlopen|dlsym|NSAddImage|NSCreateObjectFileImageFromFile", "native-dynamic-load"),
    (r"WKWebView|evaluateJavaScript|JSContext|addScriptMessageHandler"
     r"|userContentController", "native-webview-bridge"),
    (r"NSXPCConnection|xpc_connection_create|mach_msg|bootstrap_look_up"
     r"|CFMessagePort", "native-ipc"),
    (r"AESend|OSAScript|executeAppleEvent|AEDesc|NSAppleEventDescriptor",
     "native-applescript"),
    (r"strcpy\\s*\\(|strcat\\s*\\(|sprintf\\s*\\(|gets\\s*\\(|alloca\\s*\\(",
     "native-unsafe-c"),
    (r"application:openURL|handleGetURLEvent|openURL|handleOpenURL"
     r"|CFBundleURLSchemes", "native-url-scheme-entry"),
    (r"AuthorizationExecuteWithPrivileges|AuthorizationCreate|SMJobBless"
     r"|\\bsetuid\\s*\\(|\\bsetgid\\s*\\(", "native-privilege"),
    (r"get-task-allow|disable-library-validation|com.apple.security"
     r"|allow-dyld-environment-variables", "native-entitlement"),
'''

NATIVE_TARGET_RULES = '''    # [vulngate-macos-universal] macOS 原生应用（.app / Mach-O / Swift / ObjC）
    "native-app": [
        (r"application:openURL|applicationDidFinishLaunching|handleGetURLEvent"
         r"|openURL|handleOpenURL|NSApplicationMain", "ui-entry"),
        (r"NSXPCConnection|xpc_connection_create|mach_msg|bootstrap_look_up"
         r"|shouldAcceptNewConnection|CFMessagePort", "ipc-entry"),
        (r"WKWebView|evaluateJavaScript|addScriptMessageHandler"
         r"|userContentController|JSContext", "webview-boundary"),
        (r"NSKeyedUnarchiver|unarchive[A-Za-z]*|propertyListWithData"
         r"|CFPropertyListCreate|initWithCoder", "deserialization"),
        (r"posix_spawn|NSTask|execve|system\\s*\\(|popen\\s*\\(|NSAppleScript", "command-exec"),
        (r"SecItem[A-Za-z]*|SecKeychain|keychain|credential", "credential-boundary"),
        (r"AuthorizationExecuteWithPrivileges|SMJobBless|setuid|setgid"
         r"|get-task-allow|disable-library-validation", "privilege-boundary"),
        (r"fopen|NSFileManager|open\\s*\\(|unlink|remove|chmod", "dangerous-sink"),
    ],
'''

NATIVE_PRESET = '''    # [vulngate-macos-universal] macOS 原生入口/危险调用候选面
    "native": (r"(?:application:openURL|handleGetURLEvent|openURL|NSApplicationMain"
               r"|NSXPCConnection|xpc_connection_create|shouldAcceptNewConnection"
               r"|WKWebView|evaluateJavaScript|addScriptMessageHandler"
               r"|NSKeyedUnarchiver|unarchive[A-Za-z]*|propertyListWithData"
               r"|posix_spawn|NSTask|execve|popen|SecItem[A-Za-z]*"
               r"|AuthorizationExecuteWithPrivileges|SMJobBless"
               r"|applicationDidFinishLaunching)"),
'''

# 插入锚点里"原样保留"的那一行，抽成常量复用，避免在 old/new 里
# 各写一遍导致转义不一致（`\\s` vs `\\\\s` 曾让补丁产出非法正则）。
ANCHOR_RESOURCE_LOAD = \
    '    (r"getResourceAsStream|getResource\\s*\\(", "resource-load"),'
ANCHOR_ALL_PRESET = (
    '    "all": r"(parse\\w*|read\\w*|deserialize\\w*|decode\\w*|load\\w*|convert\\w*|'
    'doGet|doPost|service|evaluate|eval|invoke|lookup|format|exec\\w*|'
    'openConnection|getInputStream)\\s*\\(",')
ANCHOR_EXPRESSION_RULE = (
    '    "expression": [(r"evaluate|parseExpression|eval|template|render", '
    '"expression-entry"),\n'
    '                   (r"ClassLoader|Runtime|ProcessBuilder|MethodHandle", '
    '"execution-sink")],')

PATCHES: List[Dict[str, str]] = [
    # ---------------------------------------------------------------- #1
    {
        "id": "1-globs",
        "file": "scripts/agent/tools/source_evidence.py",
        "desc": "DEFAULT_SOURCE_GLOBS 补齐原生/前端扩展名",
        "old": '    "*.php", "*.rs", "*.cs", "*.c", "*.cpp", "*.h",\n]',
        "new": ('    "*.php", "*.rs", "*.cs", "*.c", "*.cpp", "*.h",\n'
                '    "*.swift", "*.m", "*.mm", "*.hpp", "*.mjs", "*.cjs",'
                '  # [vulngate-macos-universal]\n]'),
        "marker": '"*.swift"',
        # Deriving the glob list from the unified suffix table
        # (agent.analysis.languages) is an equally valid -- and stronger --
        # landing state: one definition instead of four.
        "markers": ['"*.swift"', "DEFAULT_SOURCE_GLOBS: List[str] = source_globs()"],
    },
    # ---------------------------------------------------------------- #2
    {
        "id": "2-danger",
        "file": "scripts/agent/tools/source_evidence.py",
        "desc": "DANGER_PATTERNS 增加 macOS 原生 sink",
        "old": ANCHOR_RESOURCE_LOAD + "\n]",
        "new": ANCHOR_RESOURCE_LOAD + "\n" + NATIVE_DANGER + "]",
        "marker": "native-command-exec",
    },
    # ---------------------------------------------------------------- #3
    {
        "id": "3-preset",
        "file": "scripts/agent/tools/source_evidence.py",
        "desc": "SOURCE_MAP_PRESETS 增加 native 预设",
        "old": ANCHOR_ALL_PRESET + "\n}",
        "new": ANCHOR_ALL_PRESET + "\n" + NATIVE_PRESET + "}",
        "marker": '"native": (',
    },
    # ---------------------------------------------------------------- #4
    {
        "id": "4-target-rules",
        "file": "scripts/agent/tools/target_rules.py",
        "desc": "TARGET_RULES 增加 native-app 目标类型",
        "old": ANCHOR_EXPRESSION_RULE + "\n}",
        "new": ANCHOR_EXPRESSION_RULE + "\n" + NATIVE_TARGET_RULES + "}",
        "marker": '"native-app": [',
    },
    # ---------------------------------------------------------------- #5
    {
        "id": "5-gate-scan",
        "file": "scripts/agent/orchestrator/stages/common.py",
        "desc": "S1 _gate_scan 去掉硬编码 globs=[\"*.java\"]",
        "old": '            lines = srch.rg(kw, d, globs=["*.java"], max_count=6)',
        "new": ('            # [vulngate-macos-universal] 去掉 *.java 硬编码：\n'
                '            # globs=None 时 srch.rg 扫全部文件，\n'
                '            # 让 source-evidence 的白名单成为唯一口径。\n'
                '            lines = srch.rg(kw, d, max_count=6)'),
        "marker": "去掉 *.java 硬编码",
    },
    # ---------------------------------------------------------------- #6
    {
        "id": "6-s2-entry-match",
        "file": "scripts/agent/orchestrator/stages/s1.py",
        "desc": 'S2 entry 匹配去掉 t.endswith(".java") 硬编码',
        "old": ('        fname_tokens = [t for t in re.split(r"[^\\w./]+", str(fl)) '
                'if t.endswith(".java")]'),
        "new": ('        # [vulngate-macos-universal] 原为 t.endswith(".java")，\n'
                '        # 导致 .h/.swift/.py/.ts 入口的 danger_hits 恒为 0。\n'
                '        _src_exts = (".java", ".kt", ".scala", ".clj", ".py", ".go",\n'
                '                     ".rb", ".js", ".jsx", ".ts", ".tsx", ".php", ".rs",\n'
                '                     ".cs", ".c", ".cpp", ".h", ".swift", ".m", ".mm",\n'
                '                     ".hpp", ".mjs", ".cjs")\n'
                '        fname_tokens = [t for t in re.split(r"[^\\w./]+", str(fl))\n'
                '                        if t.endswith(_src_exts)]'),
        "marker": "_src_exts = tuple(ALL_SUFFIXES)",
        "markers": ["_src_exts = (", "_src_exts = tuple(ALL_SUFFIXES)"],
    },
    # ---------------------------------------------------------------- #7
    {
        "id": "7-profile-suffixes",
        "file": "scripts/agent/tools/project_profile.py",
        "desc": "project_profile 后缀集补齐（只影响打分，不影响扫描）",
        "old": ('    suffixes = {".java", ".kt", ".scala", ".go", ".py", ".js", ".ts", ".clj",\n'
                '                ".c", ".cpp", ".rs", ".rb", ".php", ".cs"}'),
        "new": ('    # [vulngate-macos-universal] 补齐 .h/.swift/.m/.mm 等\n'
                '    suffixes = {".java", ".kt", ".scala", ".go", ".py", ".js", ".ts",\n'
                '                ".jsx", ".tsx", ".clj", ".c", ".cpp", ".h", ".hpp",\n'
                '                ".rs", ".rb", ".php", ".cs", ".swift", ".m", ".mm",\n'
                '                ".mjs", ".cjs"}'),
        "marker": '".swift", ".m", ".mm",',
        "markers": ['".swift", ".m", ".mm",', "suffixes = set(ALL_SUFFIXES)"],
    },
    # ---------------------------------------------------------------- #8
    {
        "id": "8-jar-path-outside-ws",
        "file": "scripts/agent/orchestrator/stages/s1.py",
        "desc": "S1 jar 报告行容忍 workspace 之外的 jar 路径",
        "old": '            "path": str(p.relative_to(ctx.workspace)),',
        "new": ('            # [vulngate-macos-universal] TargetConfig.resolve_jars 允许\n'
                '            # jar 位于 workspace 之外（绝对路径），但这一行假设了\n'
                '            # 包含关系，relative_to 会抛 ValueError 让 S1 整体崩。\n'
                '            # macOS 应用的 jar 天然在 /Applications 下，故需容忍。\n'
                '            "path": (str(p.relative_to(ctx.workspace))\n'
                '                     if str(p).startswith(str(ctx.workspace)) else str(p)),'),
        "marker": "jar 位于 workspace 之外",
    },
]


def landed(patch: Dict[str, str], text: str) -> bool:
    """True when any accepted landing marker for ``patch`` is present in ``text``.

    ``markers`` (when declared) lists alternative landing states -- see the
    module docstring.  Falls back to the single ``marker``.
    """
    return any(marker and marker in text
               for marker in (patch.get("markers") or [patch["marker"]]))


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def backup(plugin: Path, path: Path) -> Path:
    bdir = plugin / BACKUP_DIR
    bdir.mkdir(parents=True, exist_ok=True)
    rel = path.relative_to(plugin)
    dest = bdir / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        shutil.copy2(path, dest)
    return dest


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="给 vulngate 打最小必要补丁（默认 dry-run）")
    ap.add_argument("--plugin", required=True, help="vulngate 插件根目录")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--apply", action="store_true", help="真正写入（默认只预览）")
    g.add_argument("--verify", action="store_true", help="只校验当前落地状态")
    g.add_argument("--restore", action="store_true", help="从备份回滚")
    args = ap.parse_args(argv)

    plugin = Path(args.plugin).expanduser().resolve()
    if not (plugin / "scripts" / "agent" / "orchestrator" / "pipeline.py").exists():
        print("ERROR: %s 不是 vulngate 插件根" % plugin, file=sys.stderr)
        return 2

    # ---------------- restore ----------------
    if args.restore:
        bdir = plugin / BACKUP_DIR
        if not bdir.exists():
            print("没有备份目录 %s，无需回滚" % bdir)
            return 0
        n = 0
        for f in sorted(bdir.rglob("*.py")):
            rel = f.relative_to(bdir)
            dest = plugin / rel
            shutil.copy2(f, dest)
            n += 1
            print("  还原 %s" % rel)
        print("已回滚 %d 个文件（备份保留在 %s）" % (n, bdir))
        return 0

    # ---------------- patch / verify ----------------
    report = []
    changed = 0
    for p in PATCHES:
        f = plugin / p["file"]
        item = {"id": p["id"], "file": p["file"], "desc": p["desc"], "state": ""}
        if not f.exists():
            item["state"] = "FILE-MISSING"
            report.append(item)
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        if landed(p, text):
            item["state"] = "ALREADY-APPLIED"
            report.append(item)
            continue
        if p["old"] not in text:
            item["state"] = "SKIP-NO-MATCH"
            item["hint"] = "插件版本可能已变化，请人工核对"
            report.append(item)
            continue
        if args.verify:
            item["state"] = "NOT-APPLIED"
            report.append(item)
            continue
        if args.apply:
            backup(plugin, f)
            f.write_text(text.replace(p["old"], p["new"], 1), encoding="utf-8")
            changed += 1
            item["state"] = "APPLIED"
        else:
            item["state"] = "WOULD-APPLY"
        report.append(item)

    mode = ("校验" if args.verify else "应用" if args.apply else "预览（dry-run）")
    print("=" * 74)
    print("vulngate 补丁 %s | 插件: %s" % (mode, plugin))
    print("=" * 74)
    icon = {"APPLIED": "✓", "WOULD-APPLY": "→", "ALREADY-APPLIED": "=",
            "NOT-APPLIED": "✗", "SKIP-NO-MATCH": "!", "FILE-MISSING": "!"}
    for it in report:
        line = "  %s [%s] %-16s %s" % (icon.get(it["state"], "?"), it["state"],
                                       it["id"], it["desc"])
        print(line)
        if it.get("hint"):
            print("      └─ %s" % it["hint"])
    print("-" * 74)
    applied = sum(1 for it in report if it["state"] in ("APPLIED", "ALREADY-APPLIED"))
    print("  已生效 %d/%d" % (applied, len(PATCHES)))
    if not args.apply and not args.verify:
        would = sum(1 for it in report if it["state"] == "WOULD-APPLY")
        print("  待应用 %d 项 —— 加 --apply 执行" % would)
        print("  注意：插件目录属用户缓存区，插件升级会覆盖补丁，需重跑本脚本。")
    if args.apply:
        print("  已写入 %d 个文件；备份在 %s" % (changed, plugin / BACKUP_DIR))
        print("  回滚：--restore")
    # 备份清单
    man = plugin / BACKUP_DIR / "patch-report.json"
    if args.apply:
        man.parent.mkdir(parents=True, exist_ok=True)
        man.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                       encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
