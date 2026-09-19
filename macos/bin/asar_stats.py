#!/usr/bin/env python3
"""统计 Electron app.asar 内的文件构成，判断是否有明文 JS/TS 可审。

asar 布局: [0:4]=4  [4:8]=headerLen  [8:8+headerLen]=pickle(len + JSON header)
不依赖 @electron/asar，纯标准库。
"""
import json
import struct
import sys


def read_header(path):
    with open(path, "rb") as fh:
        size_buf = fh.read(8)
        if len(size_buf) < 8:
            return None
        header_size = struct.unpack("<I", size_buf[4:8])[0]
        if header_size <= 0 or header_size > 200 * 1024 * 1024:
            return None
        hb = fh.read(header_size)
    text = hb.decode("utf-8", "replace")
    start = text.find('{"files"')
    if start < 0:
        return None
    depth = 0
    in_str = False
    esc = False
    for j in range(start, len(text)):
        c = text[j]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:j + 1])
    return None


def walk(node, counts, acc):
    for key, val in (node.get("files") or {}).items():
        if isinstance(val, dict) and "files" in val:
            walk(val, counts, acc)
            continue
        acc["files"] += 1
        acc["bytes"] += val.get("size", 0) if isinstance(val, dict) else 0
        ext = "." + key.rsplit(".", 1)[1].lower() if "." in key else "(noext)"
        counts[ext] = counts.get(ext, 0) + 1


def main():
    if len(sys.argv) < 2:
        print("usage: asar_stats.py <app.asar>")
        return 2
    header = read_header(sys.argv[1])
    if header is None:
        print("  [!!] 无法解析 asar 头（可能不是标准 asar）")
        return 0

    counts = {}
    acc = {"files": 0, "bytes": 0}
    walk(header, counts, acc)

    ordered = sorted(counts.items(), key=lambda kv: -kv[1])
    top = "  ".join("%s:%d" % (e, c) for e, c in ordered[:5])
    src = sum(counts.get(e, 0) for e in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"))
    maps = counts.get(".map", 0)

    print("  文件数=%d  解包后≈%.1fMB" % (acc["files"], acc["bytes"] / 1048576.0))
    print("  明文 JS/TS = %d" % src)
    if maps:
        print("  source map = %d 个  ▸ 可还原原始 TS 源码" % maps)
    print("  分布: %s" % top)
    return 0


if __name__ == "__main__":
    sys.exit(main())
