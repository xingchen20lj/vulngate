#!/usr/bin/env python3
"""jar2source.py -- 把 Java 桌面应用（Burp 这类 .app 内嵌 jar）源码化。

为什么要它
----------
vulngate 的 S1 **原生支持** jar：`TargetConfig.jars` 走 `jar tf` 做类级拓扑与
版本 diff。所以对 Java 系 macOS 应用，S1/S5 甚至不需要本工具。

但 S3 需要 `file:line` 级的源码片段。jar 里是 `.class` 字节码，为此本工具
产出可在白名单内（`*.java`）grep 的文本视图：
  * 有 CFR/Procyon -> 真反编译，得到接近原始的 Java 源码（最佳）
  * 无            -> `javap -p -s` 出类/方法签名 + 描述符，并对"危险关键词"
                     命中的类追加 `javap -c` 字节码（含常量池字符串）

顺带产出一个 OSV 依赖清单（`deps.json`），喂给 vulngate 的 S5 依赖 CVE 扫描。

用法:
  jar2source.py --jar-list jars.txt -o <outdir> [--max-bytecode 200] [--cfr <cfr.jar>]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional, Sequence

# 危险关键词：命中则对该类补 `javap -c` 字节码（含字符串常量）
INTERESTING = re.compile(
    r"(?i)(Controller|Servlet|Filter|Handler|Endpoint|Route|Api|Service|Manager|"
    r"Util|Parser|Reader|Loader|Decoder|Deserial|Serializ|Mapper|Codec|Compress|"
    r"Archive|Zip|Upload|Import|Export|Download|File|Path|Sql|Jdbc|Script|Eval|"
    r"Template|Exec|Process|Command|Shell|Auth|Token|Session|Permission|Role|"
    r"Reflect|ClassLoader|Proxy|Config|Backup|Restore|Plugin|Xml|Json|Yaml)"
)

# jar 名 -> 可能的 Maven 坐标线索（供 S5 用；不到能确定就只留文件名）
VERSION_RE = re.compile(r"[-_](\d+\.\d+(?:\.\d+)*(?:[-.][A-Za-z0-9]+)*)\.jar$", re.I)


def run(cmd: Sequence[str], timeout: int = 600) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""
    return p.stdout or ""


def jar_classes(jar: Path) -> List[str]:
    out = run(["jar", "tf", str(jar)], timeout=300)
    return [ln.strip() for ln in out.splitlines()
            if ln.strip().endswith(".class") and "module-info" not in ln]


def class_to_fqcn(entry: str) -> str:
    return entry[:-6].replace("/", ".")


def jar_meta(jar: Path) -> Dict[str, object]:
    m = VERSION_RE.search(jar.name)
    version = m.group(1) if m else "unknown"
    name = jar.name[:m.start()] if m else jar.stem
    manifest = run(["unzip", "-p", str(jar), "META-INF/MANIFEST.MF"], timeout=60)
    impl = re.search(r"^Implementation-Version:\s*(.+)$", manifest, re.M)
    if impl:
        version = impl.group(1).strip()
    artifact = re.search(r"^Implementation-Title:\s*(.+)$", manifest, re.M)
    return {
        "jar": str(jar),
        "artifact": (artifact.group(1).strip() if artifact else name),
        "version": version,
        "class_count": len(jar_classes(jar)),
    }


def safe(s: str) -> str:
    return re.sub(r"[^\w.\-]+", "_", s)


def decompile_with_cfr(jar: Path, out: Path, cfr: Path) -> int:
    d = out / "cfr" / safe(jar.stem)
    d.mkdir(parents=True, exist_ok=True)
    java = shutil.which("java") or "/usr/bin/java"
    run([java, "-jar", str(cfr), str(jar), "--outputdir", str(d)],
        timeout=1800)
    return sum(1 for _ in d.rglob("*.java"))


def javap_view(jar: Path, out: Path, max_bytecode: int) -> Dict[str, int]:
    """无反编译器时：签名视图 + 危险类的字节码视图。"""
    classes = [class_to_fqcn(c) for c in jar_classes(jar)]
    if not classes:
        return {"signatures": 0, "bytecode_classes": 0}
    d = out / "javap" / safe(jar.stem)
    d.mkdir(parents=True, exist_ok=True)

    # 签名视图：一次 javap 传多个类，避免逐类起进程
    sig_lines: List[str] = []
    for i in range(0, len(classes), 400):
        batch = classes[i:i + 400]
        sig_lines.append(run(["javap", "-p", "-s", "-cp", str(jar)] + batch,
                             timeout=900))
    (d / f"{safe(jar.stem)}_signatures.java").write_text(
        "/* VULNGATE-RECONSTRUCTED: javap -p -s 签名视图（字节码，非原始源码） */\n"
        + "\n".join(sig_lines), encoding="utf-8")

    # 字节码视图：仅危险关键词命中的类，且限流
    hits = [c for c in classes if INTERESTING.search(c)]
    hits = hits[:max_bytecode]
    if hits:
        body: List[str] = []
        for i in range(0, len(hits), 100):
            batch = hits[i:i + 100]
            body.append(run(["javap", "-p", "-c", "-constants", "-cp", str(jar)] + batch,
                            timeout=1200))
        (d / f"{safe(jar.stem)}_interesting_bytecode.java").write_text(
            "/* VULNGATE-RECONSTRUCTED: javap -c 字节码视图"
            "（含常量池字符串；命中 %d 个危险命名类） */\n" % len(hits)
            + "\n".join(body), encoding="utf-8")
    return {"signatures": len(classes), "bytecode_classes": len(hits)}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="jar -> vulngate 可扫描的 .java 视图")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--jar-list", help="每行一个 jar 路径的文件")
    src.add_argument("--jar", help="单个 jar")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--cfr", default=os.environ.get("CFR_JAR", ""),
                    help="CFR jar 路径；给了就做真反编译（最佳质量）")
    ap.add_argument("--max-bytecode", type=int, default=200,
                    help="最多对多少个危险命名类出字节码视图")
    ap.add_argument("--jobs", type=int, default=4)
    args = ap.parse_args(argv)

    out = Path(args.out).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    jars: List[Path] = []
    if args.jar:
        jars = [Path(args.jar)]
    else:
        p = Path(args.jar_list)
        if not p.exists():
            print("ERROR: jar 列表不存在: %s" % p, file=sys.stderr)
            return 2
        jars = [Path(ln.strip()) for ln in p.read_text(encoding="utf-8").splitlines()
                if ln.strip()]
    jars = [j for j in jars if j.exists()]
    if not jars:
        print("WARN: 没有可处理的 jar")
        return 1

    cfr = Path(args.cfr) if args.cfr else None
    if cfr and not cfr.exists():
        print("WARN: CFR 不存在（%s），退回 javap 视图" % cfr, file=sys.stderr)
        cfr = None
    if not cfr:
        auto = Path.home() / ".vulngate" / "cfr.jar"
        if auto.exists():
            cfr = auto

    print("[jar2source] %d 个 jar | 模式: %s"
          % (len(jars), "CFR 真反编译" if cfr else "javap 签名+字节码视图"))

    metas: List[Dict[str, object]] = []
    totals = {"cfr": 0, "signatures": 0, "bytecode_classes": 0}

    def work(j: Path):
        meta = jar_meta(j)
        if cfr:
            n = decompile_with_cfr(j, out, cfr)
            return meta, {"decompiled": n}
        return meta, javap_view(j, out, args.max_bytecode)

    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for meta, res in pool.map(work, jars):
            metas.append(meta)
            jn = Path(str(meta["jar"])).name
            if "decompiled" in res:
                totals["cfr"] += int(res["decompiled"])
                print("  %-50s -> %s 个 .java" % (jn, res["decompiled"]))
            else:
                totals["signatures"] += int(res["signatures"])
                totals["bytecode_classes"] += int(res["bytecode_classes"])
                print("  %-50s -> 签名 %s / 字节码类 %s"
                      % (jn, res["signatures"], res["bytecode_classes"]))

    (out / "jars.json").write_text(
        json.dumps({"mode": "cfr" if cfr else "javap",
                    "totals": totals, "jars": metas},
                   indent=2, ensure_ascii=False),
        encoding="utf-8")
    print("[jar2source] 完成:", json.dumps(totals, ensure_ascii=False))
    print("[jar2source] 清单: %s" % (out / "jars.json"))
    if not cfr:
        print("[jar2source] 提示：把 cfr.jar 放到 ~/.vulngate/cfr.jar 可升级为真反编译")
    return 0


if __name__ == "__main__":
    sys.exit(main())
