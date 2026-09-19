#!/usr/bin/env python3
"""asar_tool.py -- Electron `app.asar` 的解包 / 统计 / source map 还原。

背景
----
App Store 之外的 macOS 应用里，Electron 系占比很高。它们的核心业务逻辑
以**明文 JS/TS** 打进 `Contents/Resources/app.asar`，这正好落在 vulngate
的扫描白名单内（`*.js` / `*.ts` / `*.jsx` / `*.tsx`）—— 这是 macOS 应用
里对 vulngate 最友好的一类，S1/S2/S3 几乎可以当普通 Web 项目审。

两个关键增强
------------
1. **不依赖 @electron/asar**：纯标准库读 asar 头（8 字节 header + JSON 索引），
   按 offset 切片导出，避免装 node 依赖。
2. **source map 还原**：若打包时带了 `.js.map`，说明可以把压缩后的 JS 反解回
   原始 TypeScript。这一步让 S3 的 `file:line` 指向**原始工程行号**而不是
   压缩产物 —— 证据链质量跃升一个档次。若存在 sourcesContent 字段，
   则原始 TS 源码可直接落盘。

用法
----
  asar_tool.py list    <app.asar>
  asar_tool.py stats   <app.asar>
  asar_tool.py extract <app.asar> -o <outdir> [--restore-maps]
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import struct
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ASAR_HEADER_PROBE = 16
MAX_INDEX_BYTES = 64 * 1024 * 1024


def read_index(asar: Path) -> Tuple[Dict[str, Any], int]:
    """返回 (索引 JSON, 数据区起始偏移)。"""
    with asar.open("rb") as fh:
        first = fh.read(16)
        if len(first) < 16:
            raise ValueError("文件过小，不是有效的 asar")
        # Two Chromium pickles: [4, header_size], then
        # [payload_size, string_length, JSON, padding]. See electron/asar disk.ts.
        size_payload, hdr_size, payload_size, json_len = struct.unpack("<IIII", first)
        if (size_payload != 4 or hdr_size < 8 or hdr_size > MAX_INDEX_BYTES
                or payload_size != hdr_size - 4 or json_len > payload_size - 4):
            raise ValueError("invalid asar pickle header")
        fh.seek(8)
        header = fh.read(hdr_size)
        if len(header) != hdr_size:
            raise ValueError("truncated asar header")
        idx = json.loads(header[8:8 + json_len].decode("utf-8"))
        if not isinstance(idx, dict) or not isinstance(idx.get("files"), dict):
            raise ValueError("asar header must contain files")
        return idx, 8 + hdr_size


def walk(node: Dict[str, Any], prefix: str = "") -> List[Tuple[str, Dict[str, Any]]]:
    out = []
    for name, meta in (node.get("files") or {}).items():
        if name in ("", ".", "..") or "/" in name or "\\" in name:
            raise ValueError("invalid asar entry name: %r" % name)
        p = f"{prefix}/{name}" if prefix else name
        if "files" in meta:
            out.extend(walk(meta, p))
        else:
            out.append((p, meta))
    return out


def stats(asar: Path) -> Dict[str, Any]:
    idx, _ = read_index(asar)
    files = walk(idx)
    total = 0
    ext: Counter = Counter()
    for p, meta in files:
        total += int(meta.get("size") or 0)
        m = re.search(r"(\.[A-Za-z0-9]+)$", p)
        ext[m.group(1).lower() if m else "(noext)"] += 1
    maps = sum(1 for p, _ in files if p.endswith(".map"))
    return {
        "path": str(asar),
        "file_count": len(files),
        "unpacked_bytes": total,
        "extensions": dict(ext.most_common(15)),
        "source_maps": maps,
        "js_ts_count": sum(c for e, c in ext.items()
                           if e in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")),
    }


def _read_slice(fh, base: int, offset: str, size: int) -> bytes:
    off = int(offset)
    size = int(size)
    if off < 0 or size < 0 or base + off + size > os.fstat(fh.fileno()).st_size:
        raise ValueError("asar entry outside archive")
    fh.seek(base + off)
    data = fh.read(size)
    if len(data) != size:
        raise ValueError("truncated asar entry")
    return data


def extract(asar: Path, outdir: Path, restore_maps: bool,
            only_interesting: bool = True) -> Dict[str, Any]:
    idx, base = read_index(asar)
    files = walk(idx)
    outdir.mkdir(parents=True, exist_ok=True)

    KEEP = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".map", ".json",
            ".py", ".rb", ".html", ".htm", ".vue", ".svelte", ".java", ".kt")
    written = 0
    skipped = 0
    total_bytes = 0
    dedup: Dict[str, int] = {}

    with asar.open("rb") as fh:
        for p, meta in files:
            if meta.get("unpacked") or meta.get("link"):
                skipped += 1
                continue
            if only_interesting and not p.lower().endswith(KEEP):
                skipped += 1
                continue
            # 防目录穿越
            parts = [x for x in p.split("/") if x not in ("", ".", "..")]
            if not parts:
                skipped += 1
                continue
            dest = outdir.joinpath(*parts)
            if outdir.resolve() not in dest.resolve().parents:
                raise ValueError("asar output escapes destination: %s" % p)
            dest.parent.mkdir(parents=True, exist_ok=True)
            data = _read_slice(fh, base, meta.get("offset", "0"), meta.get("size", 0))
            dest.write_bytes(data)
            written += 1
            total_bytes += len(data)
            if p.endswith(".js") and restore_maps:
                m = re.search(rb"sourceMappingURL=([^\s'\"]+)", data[-4096:])
                if m:
                    dedup[p] = 1

    restored = 0
    if restore_maps:
        restored = restore_sourcemaps(outdir)

    return {
        "path": str(asar),
        "outdir": str(outdir),
        "written": written,
        "skipped": skipped,
        "bytes": total_bytes,
        "js_with_sourcemap": len(dedup),
        "restored_sources": restored,
    }


def restore_sourcemaps(root: Path) -> int:
    """从 .map 里还原原始源码（sourcesContent 存在时直接落盘）。

    还原出的文件放在 `<map 所在目录>/../__sources__/<source path>`，
    让 vulngate 的 file:line 指向原始工程结构。
    """
    count = 0
    for mp in root.rglob("*.map"):
        try:
            data = json.loads(mp.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        contents = data.get("sourcesContent")
        sources = data.get("sources") or []
        if not contents or not sources:
            continue
        base = mp.parent / "__sources__"
        for src, content in zip(sources, contents):
            if content is None:
                continue
            rel = src
            if rel.startswith("webpack://"):
                rel = rel.split("webpack://", 1)[1]
            if rel.startswith("file://"):
                rel = rel[len("file://"):]
            parts = [x for x in re.split(r"[/\\]+", rel) if x not in ("", ".", "..")]
            if not parts:
                continue
            dest = base.joinpath(*parts)
            if dest.suffix not in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
                                   ".vue", ".svelte"):
                dest = dest.with_suffix(dest.suffix + ".txt" if dest.suffix else ".txt")
            if root.resolve() not in dest.resolve().parents:
                raise ValueError("source map output escapes destination: %s" % src)
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content, encoding="utf-8")
                count += 1
            except Exception:
                continue
    return count


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Electron app.asar 解包/统计/sourcemap 还原")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("list", "stats", "extract"):
        sp = sub.add_parser(name)
        sp.add_argument("asar")
        if name == "extract":
            sp.add_argument("-o", "--out", required=True)
            sp.add_argument("--restore-maps", action="store_true")
            sp.add_argument("--all", action="store_true",
                            help="导出全部文件（默认只导源码/配置类）")
    args = ap.parse_args(argv)
    asar = Path(args.asar).expanduser().resolve()
    if not asar.exists():
        print("ERROR: 不存在: %s" % asar, file=sys.stderr)
        return 2

    if args.cmd == "list":
        idx, _ = read_index(asar)
        for p, meta in walk(idx):
            print("%10s  %s" % (meta.get("size", "?"), p))
        return 0
    if args.cmd == "stats":
        s = stats(asar)
        print(json.dumps(s, indent=2, ensure_ascii=False))
        return 0
    r = extract(asar, Path(args.out).expanduser().resolve(),
                args.restore_maps, only_interesting=not args.all)
    print(json.dumps(r, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
