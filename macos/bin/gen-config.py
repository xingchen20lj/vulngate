#!/usr/bin/env python3
"""gen-config.py -- 由 recon.json / MANIFEST.json 生成 vulngate 的 TargetConfig。

配置里每一项都对应 vulngate 代码里的真实字段（`orchestrator/config.py`
的 `TargetConfig` dataclass）：

  name / discovery_date / target_type      -> 决定 S1 的 TARGET_RULES 分支
  jars[{version,path}]                     -> S1 的类级拓扑与版本 diff
  deps[{path,version}]                     -> S5 的 OSV 依赖 CVE 扫描
  source_dirs[]                            -> 所有 grep 扫描的根
  entry_points[{api,input_shape,file_line,untrusted,text}]
                                           -> S2 的候选来源；untrusted=true 才能过 G1
  candidates[]                             -> S4 矩阵的输入（可留空，交给 S2）
  target_urls{}                            -> S4 web-app 模式的 base URL
  scope_constraints                        -> 注入 S2/S3 的提示词

用法:
  gen-config.py --recon <out>/recon.json -o <workspace>/targets/<name>.json
                [--name NAME] [--target-type auto|web-app|library|middleware|native-app]
                [--entry-limit 60]
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# 各语言栈的入口候选模式（与 vulngate 的 SOURCE_MAP_PRESETS 思路一致，
# 但这里额外覆盖 macOS 原生与 Electron 的入口形态）
ENTRY_PATTERNS: List[tuple] = [
    # (label, input_shape, 正则)
    ("http-route", "http-request",
     r"(?:@[\w.]+\.route|@[\w.]+\.(?:get|post|put|delete|patch))\s*\(|"
     r"\b(?:router\.(?:GET|POST|PUT|DELETE|PATCH|ANY)|app\.(?:get|post|put|delete|patch)|"
     r"doGet|doPost|RequestMapping|GetMapping|PostMapping|add_url_rule)\s*\("),
    ("ipc-bridge", "ipc-message",
     r"(?:ipcMain\.(?:handle|on)|ipcRenderer\.(?:invoke|send)|contextBridge\.expose|"
     r"require\(['\"]electron['\"]\))"),
    ("native-url-scheme", "url-scheme",
     r"application:openURL|handleGetURLEvent|openURL|handleOpenURL|CFBundleURLSchemes"),
    ("native-xpc", "xpc-message",
     r"NSXPCConnection|xpc_connection_create|mach_msg|bootstrap_look_up|"
     r"NSXPCListener|shouldAcceptNewConnection"),
    ("native-applescript", "apple-event",
     r"NSAppleScript|OSAScript|executeAppleEvent|AEDesc|AESend"),
    ("native-webview", "web-content",
     r"WKWebView|evaluateJavaScript|addScriptMessageHandler|JSContext|loadRequest"),
    ("native-delegate", "application-lifecycle",
     r"applicationDidFinishLaunching|application:didFinishLaunching|"
     r"applicationWillFinishLaunching|RunApplicationEventLoop"),
    ("cli-arg", "argv",
     r"NSProcessInfo\.processInfo|CommandLine\.arguments|getopt|parse_args|"
     r"NSArgumentDomain"),
    ("java-servlet", "http-request",
     r"\b(?:Filter|Servlet|Interceptor|Controller|Endpoint)\b"),
    ("python-entry", "function-call",
     r"^(?:def|class)\s+(?:handle|process|parse|load|main|run|serve|dispatch)\w*"),
]

MARKER_RE = re.compile(r"/\*\s*\[(entry-candidate|swift|objc-method|native-dep)\]")
NATIVE_LABEL_RE = re.compile(r"\[((?:native|objc|swift|entitlement)[\w-]*)\]")


def read_json(p: Path) -> Dict[str, Any]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def collect_source_files(src_dirs: List[Path]) -> List[Path]:
    exts = (".java", ".kt", ".scala", ".clj", ".py", ".go", ".rb", ".js", ".jsx",
            ".ts", ".tsx", ".php", ".rs", ".cs", ".c", ".cpp", ".h", ".swift",
            ".m", ".mm", ".hpp", ".mjs", ".cjs")
    out: List[Path] = []
    for d in src_dirs:
        if not d.exists():
            continue
        for p in d.rglob("*"):
            if p.is_file() and p.suffix.lower() in exts:
                out.append(p)
    return out


def sniff_target_type(recon: Dict[str, Any]) -> str:
    kinds = set(recon.get("kinds") or [])
    if "electron" in kinds:
        return "web-app"
    if "java" in kinds and "native" not in kinds:
        return "library"
    if "java" in kinds:
        return "library"
    if "python" in kinds and "native" not in kinds:
        return "library"
    return "native-app"


def patch_applied(plugin: Optional[Path]) -> bool:
    if not plugin:
        return False
    tr = plugin / "scripts" / "agent" / "tools" / "target_rules.py"
    try:
        return "native-app" in tr.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False


def harvest_entries(files: List[Path], limit: int,
                    root: Optional[Path] = None) -> List[Dict[str, Any]]:
    """从源码化视图里抽取入口候选。

    两个来源：
      1. macho2source / jar2source 打的语义标记（[entry-candidate] / [native-*]）
         —— 这是原生应用唯一可靠的入口线索
      2. 各语言栈的入口正则

    file_line 必须是**相对 audit_root** 的路径：vulngate 的 S1/S3 用
    `Path(...).resolve().relative_to(root.resolve())` 产出相对路径，
    S2 的 entry 匹配再用 `fl in dfile` 比较 —— 给绝对路径会导致匹配失效。
    """
    entries: List[Dict[str, Any]] = []
    seen = set()

    def add(api: str, shape: str, rel: str, line: int, text: str) -> None:
        key = (rel, line)
        if key in seen or len(entries) >= limit:
            return
        seen.add(key)
        entries.append({
            "api": api, "input_shape": shape, "file_line": f"{rel}:{line}",
            "untrusted": True, "text": text[:200],
        })

    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if root is not None:
            try:
                rel = f.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                rel = f.name
        else:
            rel = f.as_posix()
        for i, line in enumerate(text.splitlines(), 1):
            if len(entries) >= limit:
                break
            # 来源 1：语义标记
            if "[entry-candidate]" in line:
                m = NATIVE_LABEL_RE.search(line)
                label = m.group(1) if m else "native-entry"
                shape = ("url-scheme" if "url" in line.lower() else
                         "xpc-message" if "xpc" in label else
                         "ipc-message" if "ipc" in label else
                         "web-content" if "webview" in label else "native-call")
                add(label, shape, rel, i, line.strip())
                continue
            # 来源 2：入口正则
            for api, shape, rx in ENTRY_PATTERNS:
                if re.search(rx, line, re.I):
                    add(api, shape, rel, i, line.strip())
                    break
    return entries


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="生成 vulngate TargetConfig")
    ap.add_argument("--recon", required=True, help="app2source.sh 产出的 recon.json")
    ap.add_argument("-o", "--out", required=True, help="配置文件输出路径")
    ap.add_argument("--name", default="")
    ap.add_argument("--target-type", default="auto")
    ap.add_argument("--plugin", default="", help="vulngate 插件根（用于探测补丁）")
    ap.add_argument("--entry-limit", type=int, default=60)
    ap.add_argument("--audit-root", default="",
                    help="作为 vulngate WORKSPACE 的目录（vg-run.py 会把 WORKSPACE "
                         "指向它）。source_dirs 必须相对它，因为 "
                         "source_evidence._safe_resolve 会丢弃越界的绝对路径。"
                         "默认取 recon.json 所在目录。")
    args = ap.parse_args(argv)

    recon_path = Path(args.recon).expanduser().resolve()
    recon = read_json(recon_path)
    if not recon:
        print("ERROR: 无法读取 %s" % recon_path, file=sys.stderr)
        return 2

    target = Path(str(recon.get("target") or "")).stem or "target"
    name = args.name or re.sub(r"[^\w.\-]+", "-", target).strip("-").lower() or "app"

    recon_dir = Path(str(recon.get("reconstructed_dir") or recon_path.parent / "reconstructed"))
    audit_root = (Path(args.audit_root).expanduser().resolve()
                  if args.audit_root else recon_path.parent.resolve())

    # source_dirs 必须是相对 WORKSPACE 的路径，否则 _safe_resolve 直接返回 None
    try:
        src_rel = recon_dir.resolve().relative_to(audit_root).as_posix()
    except ValueError:
        print("ERROR: 源码化目录 %s 不在审计根 %s 之内。\n"
              "       vulngate 的 _safe_resolve 会丢弃越界路径，扫描将静默返回空。\n"
              "       请让 app2source.sh 的 -o 指向审计根内部。"
              % (recon_dir, audit_root), file=sys.stderr)
        return 3

    src_dirs = [recon_dir]
    files = collect_source_files(src_dirs)

    plugin = Path(args.plugin).expanduser().resolve() if args.plugin else None
    has_patch = patch_applied(plugin)

    ttype = args.target_type
    if ttype == "auto":
        ttype = sniff_target_type(recon)
        if ttype == "native-app" and not has_patch:
            # 未打补丁时 vulngate 没有 native-app 规则，退到语义最接近的 middleware
            ttype = "middleware"

    entries = harvest_entries(files, args.entry_limit, root=audit_root)

    # jars：来自侦察结果里的 java 步骤
    jars: List[Dict[str, str]] = []
    deps: List[Dict[str, str]] = []
    for step in recon.get("steps") or []:
        if step.get("kind") == "java":
            jars_json = recon_dir / "java" / "jars.json"
            jd = read_json(jars_json)
            for j in jd.get("jars") or []:
                jars.append({"version": str(j.get("version") or "unknown"),
                             "path": str(j.get("jar"))})
    # 原生依赖：取自 MANIFEST 的 vendor_deps（喂 S5）
    for mf in recon_dir.rglob("MANIFEST.json"):
        m = read_json(mf)
        for d in (m.get("vendor_deps") or []):
            base = Path(str(d)).name
            if not base:
                continue
            deps.append({"path": str(d), "version": ""})

    file_counts = recon.get("file_counts_by_ext") or {}
    covered = [e for e in file_counts
               if e in (".java", ".kt", ".scala", ".clj", ".py", ".go", ".rb", ".js",
                        ".jsx", ".ts", ".tsx", ".php", ".rs", ".cs", ".c", ".cpp", ".h")]
    need_patch = [e for e in file_counts if e in (".swift", ".m", ".mm", ".hpp",
                                                  ".mjs", ".cjs")]

    scope_note = (
        "目标为 macOS 应用（{kinds}）。源码视图由二进制元数据重建（macho2source.py）"
        "或 asar/jar 解包得到，**不是原始工程源码**："
        "file:line 指向重建视图的行号，不得当作原始工程行号引用。"
        "方法体为空，因此只能断言“符号/API 被引用”，不能断言“某行存在某逻辑”。"
    ).format(kinds=",".join(recon.get("kinds") or ["unknown"]))

    config: Dict[str, Any] = {
        "name": name,
        "discovery_date": datetime.date.today().isoformat(),
        "target_type": ttype,
        "target_urls": {},
        "upstream_repo": "",
        "api_hint": "",
        "scope_constraints": scope_note,
        "output_lang": "zh",
        "llm_audit": False,
        "safe_mode_switch": "none",
        "runtime_lab": {},
        "jars": jars,
        "deps": deps,
        "source_dirs": [src_rel],
        "poc_src_dir": None,
        "entry_points": entries,
        "candidates": [],
        "exclusions": [],
        "baselines": [],
        "notes": (
            "由 vulngate-macos-universal/gen-config.py 生成。"
            "audit_root=%s；target_type=%s；源码化文件 %d 个；入口候选 %d 条；"
            "白名单覆盖扩展名=%s；需补丁覆盖=%s；补丁已应用=%s"
            % (audit_root, ttype, len(files), len(entries), covered, need_patch, has_patch)
        ),
    }

    out = Path(args.out).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")

    print("[gen-config] 配置: %s" % out)
    print("[gen-config] name=%s target_type=%s" % (name, ttype))
    print("[gen-config] source_dirs=%s" % config["source_dirs"])
    print("[gen-config] 源码化文件 %d 个 | 入口候选 %d 条 | jar %d | deps %d"
          % (len(files), len(entries), len(jars), len(deps)))
    print("[gen-config] 白名单已覆盖: %s" % (covered or "无"))
    if need_patch:
        print("[gen-config] 需打补丁才纳入扫描: %s" % need_patch)
    if not has_patch and ttype == "middleware":
        print("[gen-config] 提示：打上补丁后 target_type 可升级为 native-app")
    if not entries:
        print("[gen-config] 警告：入口候选为 0 —— S2 将没有候选来源，"
              "建议检查源码化产物或手工补 entry_points")
    return 0


if __name__ == "__main__":
    sys.exit(main())
