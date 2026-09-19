#!/usr/bin/env bash
# =============================================================================
# app2source.sh -- 把任意 macOS 应用（.dmg / .pkg / .app）源码化成
#                 VulnGate 能扫的目录树。
#
# 这是让 vulngate "S1→S8 全通" 的第一块地基：先解决"没有源码可扫"。
#
# 分派逻辑（按 .app 内部的语言栈，可叠加）：
#   Electron (app.asar)      -> asar 解包 + sourcemap 还原原始 TS   [白名单 *.ts]
#   Java (Contents/Java)     -> jar 清单（S1 原生支持）+ javap 反汇编 [白名单 *.java]
#   Python (*.py)            -> 直接复制                               [白名单 *.py]
#   原生 Mach-O              -> macho2source.py 元数据重建            [白名单 *.h/*.c]
#
# 用法:
#   app2source.sh <target> -o <outdir> [--scope main|all] [--no-maps] [--keep-mount]
#
# 产出:
#   <outdir>/reconstructed/...   源码化视图（直接作为 vulngate 的 source_dirs）
#   <outdir>/recon.json          侦察结果，交给 gen-config.py 生成 TargetConfig
# =============================================================================
set -uo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Codex uses the selected interpreter or python3 from PATH, without another host's runtime.
PY="${VULNGATE_PY:-python3}"
command -v "$PY" >/dev/null 2>&1 || { echo "Python not found: $PY" >&2; exit 2; }
export VULNGATE_PY="$PY"
MACHO2SRC="$SELF_DIR/macho2source.py"
ASAR_TOOL="$SELF_DIR/asar_tool.py"

TARGET=""; OUT=""; SCOPE="main"; RESTORE_MAPS=1; KEEP_MOUNT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -o|--out)      OUT="$2"; shift 2 ;;
    --scope)       SCOPE="$2"; shift 2 ;;
    --no-maps)     RESTORE_MAPS=0; shift ;;
    --keep-mount)  KEEP_MOUNT=1; shift ;;
    -h|--help)     sed -n '2,30p' "$0"; exit 0 ;;
    *)             TARGET="$1"; shift ;;
  esac
done

if [ -z "$TARGET" ] || [ -z "$OUT" ]; then
  echo "用法: app2source.sh <target.dmg|.pkg|.app|目录> -o <outdir>" >&2
  exit 2
fi

[ -f "$MACHO2SRC" ] || { echo "缺少 $MACHO2SRC" >&2; exit 2; }

TARGET="$(cd "$(dirname "$TARGET")" 2>/dev/null && pwd)/$(basename "$TARGET")"
[ -e "$TARGET" ] || { echo "目标不存在: $TARGET" >&2; exit 2; }
OUT="$(mkdir -p "$OUT" && cd "$OUT" && pwd)"
RECON="$OUT/reconstructed"
mkdir -p "$RECON"

MOUNT=""
TMPX=""
cleanup() {
  if [ -n "$MOUNT" ] && [ "$KEEP_MOUNT" -eq 0 ]; then
    hdiutil detach "$MOUNT" -quiet 2>/dev/null || hdiutil detach "$MOUNT" -force -quiet 2>/dev/null
  fi
  [ -n "$TMPX" ] && rm -rf "$TMPX"
  return 0
}
trap cleanup EXIT INT TERM

log() { printf '\033[36m[app2source]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[app2source] ! \033[0m%s\n' "$*" >&2; }

# --------------------------------------------------------------------------- #
# 1. 归一化：DMG / PKG -> 落在磁盘上的 .app
# --------------------------------------------------------------------------- #
ROOT="$TARGET"
case "$TARGET" in
  *.dmg)
    MOUNT="$(mktemp -d /tmp/vg-mnt.XXXXXX)"
    log "挂载 DMG（只读）: $TARGET"
    if ! hdiutil attach "$TARGET" -readonly -nobrowse -mountpoint "$MOUNT" -quiet; then
      echo "ERROR: DMG 挂载失败" >&2; exit 3
    fi
    ROOT="$MOUNT"
    ;;
  *.pkg)
    TMPX="$(mktemp -d /tmp/vg-pkg.XXXXXX)"
    log "展开 PKG: $TARGET"
    if ! pkgutil --expand-full "$TARGET" "$TMPX/expanded" 2>/dev/null; then
      # 某些 pkg 不支持 --expand-full，退回 payload 抽取
      pkgutil --expand "$TARGET" "$TMPX/expanded" 2>/dev/null || true
      for pl in "$TMPX"/expanded/*.pkg/Payload; do
        [ -f "$pl" ] || continue
        d="$TMPX/payload/$(basename "$(dirname "$pl")")"
        mkdir -p "$d"
        (cd "$d" && gunzip -dc "$pl" 2>/dev/null | cpio -i --quiet 2>/dev/null) || \
          (cd "$d" && xar -xf "$pl" 2>/dev/null) || warn "payload 抽取失败: $pl"
      done
    fi
    ROOT="$TMPX"
    ;;
esac

# 解析符号链接应用（如 JetBrains Toolbox 装在 ~/Applications，
# /Applications 下只是 symlink；find 默认不跟随会漏掉真身）
# 注意：macOS 的 BSD readlink 不支持 -f，用 python 兜底解析。
if [ -L "$ROOT" ]; then
  REAL="$("$PY" -c "import os,sys;print(os.path.realpath(sys.argv[1]))" "$ROOT" 2>/dev/null || true)"
  [ -n "$REAL" ] && [ -e "$REAL" ] && ROOT="$REAL" && log "符号链接解析 -> $ROOT"
fi

# 找到 .app
APPS=()
if [ -d "$ROOT" ] && [ "${ROOT##*.}" = "app" ]; then
  APPS=("$ROOT")
elif [ -d "$ROOT" ]; then
  while IFS= read -r -d '' a; do APPS+=("$a"); done \
    < <(find "$ROOT" -maxdepth 3 -name "*.app" -type d -print0 2>/dev/null)
fi

if [ "${#APPS[@]}" -eq 0 ]; then
  warn "未在 $ROOT 下找到 .app（可能是裸二进制或资源包），尝试直接当 Mach-O 处理"
  APPS=("")
fi

# --------------------------------------------------------------------------- #
# 2. 分派
# --------------------------------------------------------------------------- #
SUMMARY="$OUT/.summary.tsv"
: > "$SUMMARY"
printf 'kind\tpath\tdetail\n' >> "$SUMMARY"

for APP in "${APPS[@]}"; do
  # ---- 2a. Electron / asar ----
  while IFS= read -r -d '' ASAR; do
    REL="$(echo "${ASAR#$ROOT/}" | tr '/' '_')"
    DEST="$RECON/electron/${REL%.asar}"
    mkdir -p "$DEST"
    log "asar 解包: $(basename "$ASAR")"
    ARGS=(extract "$ASAR" -o "$DEST")
    [ "$RESTORE_MAPS" -eq 1 ] && ARGS+=(--restore-maps)
    JRES="$OUT/.asar.$$.json"
    "$PY" "$ASAR_TOOL" "${ARGS[@]}" > "$JRES" 2>/dev/null || warn "asar 解包失败: $ASAR"
    if [ -s "$JRES" ]; then
      W="$("$PY" -c "import json,sys;d=json.load(open(sys.argv[1]));print(d.get('written',0))" "$JRES" 2>/dev/null || echo 0)"
      R="$("$PY" -c "import json,sys;d=json.load(open(sys.argv[1]));print(d.get('restored_sources',0))" "$JRES" 2>/dev/null || echo 0)"
      printf 'electron\t%s\t导出 %s 文件, 还原 %s 个原始源文件\n' "$ASAR" "$W" "$R" >> "$SUMMARY"
      log "  -> $W 个文件（sourcemap 还原 $R 个原始源文件）"
    fi
    rm -f "$JRES"
  done < <(find "$ROOT" -name "app.asar" -type f -print0 2>/dev/null)

  # ---- 2b. Java（jar）----
  JARS=()
  while IFS= read -r -d '' J; do JARS+=("$J"); done \
    < <(find "$ROOT" -maxdepth 6 -name "*.jar" -type f -print0 2>/dev/null)
  if [ "${#JARS[@]}" -gt 0 ]; then
    log "发现 ${#JARS[@]} 个 jar（S1 原生支持 jar 级扫描）"
    DEST="$RECON/java"
    mkdir -p "$DEST"
    : > "$OUT/.jars.txt"
    for J in "${JARS[@]}"; do echo "$J" >> "$OUT/.jars.txt"; done
    # javap 反汇编，给 S3 提供可 grep 的 .java 文本（方法签名 + 常量池）
    if command -v javap >/dev/null 2>&1; then
      "$PY" "$SELF_DIR/jar2source.py" --jar-list "$OUT/.jars.txt" -o "$DEST" \
        2>/dev/null | tail -3
    fi
    printf 'java\t%s\t%s 个 jar\n' "$ROOT" "${#JARS[@]}" >> "$SUMMARY"
  fi

  # ---- 2c. Python ----
  PYN=0; DEST="$RECON/python"
  while IFS= read -r -d '' P; do
    R="${P#$ROOT/}"
    mkdir -p "$DEST/$(dirname "$R")"
    cp "$P" "$DEST/$R" 2>/dev/null && PYN=$((PYN+1))
  done < <(find "$ROOT" -maxdepth 6 -name "*.py" -type f -print0 2>/dev/null)
  [ "$PYN" -gt 0 ] && { log "发现 $PYN 个 .py（明文脚本）"; \
    printf 'python\t%s\t%s 个 .py\n' "$ROOT" "$PYN" >> "$SUMMARY"; }

  # ---- 2d. 原生 Mach-O ----
  if [ -n "$APP" ]; then
    log "Mach-O 元数据重建: $(basename "$APP") (scope=${SCOPE})"
    DEST="$RECON/native"
    mkdir -p "$DEST"
    "$PY" "$MACHO2SRC" "$APP" -o "$DEST" --scope "$SCOPE" 2>&1 | \
      grep -E "枚举到|完成:|保真度=|清单:" | sed 's/^/  /'
    printf 'native\t%s\tscope=%s\n' "$APP" "$SCOPE" >> "$SUMMARY"
  fi
done

# --------------------------------------------------------------------------- #
# 3. 汇总 recon.json
# --------------------------------------------------------------------------- #
"$PY" - "$OUT" "$SUMMARY" "$TARGET" "$SCOPE" <<'PYEOF'
import json, sys, os
from pathlib import Path
out, summary, target, scope = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
rows = []
for line in Path(summary).read_text(encoding="utf-8").splitlines()[1:]:
    parts = line.split("\t")
    if len(parts) >= 3:
        rows.append({"kind": parts[0], "path": parts[1], "detail": parts[2]})
recon = Path(out) / "reconstructed"
counts = {}
for p in recon.rglob("*"):
    if p.is_file():
        counts[p.suffix.lower()] = counts.get(p.suffix.lower(), 0) + 1
kinds = sorted({r["kind"] for r in rows})
data = {
    "target": target, "scope": scope,
    "kinds": kinds,
    "reconstructed_dir": str(recon),
    "file_counts_by_ext": dict(sorted(counts.items(), key=lambda kv: -kv[1])),
    "total_files": sum(counts.values()),
    "steps": rows,
    "vulngate_source_glob_coverage": {
        "覆盖的扩展名（在白名单内）": [e for e in counts
                                    if e in (".java", ".kt", ".scala", ".clj", ".py",
                                             ".go", ".rb", ".js", ".jsx", ".ts", ".tsx",
                                             ".php", ".rs", ".cs", ".c", ".cpp", ".h")],
        "需补丁才覆盖的扩展名": [e for e in counts
                               if e in (".swift", ".m", ".mm", ".hpp", ".mjs", ".cjs")],
    },
}
(Path(out) / "recon.json").write_text(json.dumps(data, indent=2, ensure_ascii=False),
                                     encoding="utf-8")
print()
print("[app2source] 语言栈:", ", ".join(kinds) or "无")
print("[app2source] 源码化文件总数:", data["total_files"])
top = list(data["file_counts_by_ext"].items())[:8]
print("[app2source] 主要扩展名:", ", ".join(f"{e}×{c}" for e, c in top))
print("[app2source] 侦察结果:", Path(out) / "recon.json")
PYEOF
