#!/usr/bin/env bash
# =============================================================================
# run-audit.sh -- 一键把"任意 macOS 应用"接入 vulngate。
#
# 流程：
#   1. 侦察   ：识别语言栈（复用 macos-app-recon.sh，若在同目录）
#   2. 源码化 ：app2source.sh -> <audit>/reconstructed/
#   3. 校验   ：确认 8 处原生支持已内置（--apply-patch 只在意外丢失时补回）
#   4. 配置   ：gen-config.py -> <audit>/targets/<name>.json
#   5. 落 PoC ：拷 templates/poc-native.sh 进审计目录
#   6. 跑管线 ：vg-run.py --stage S1..S8（--run 才执行）
#
# 用法:
#   run-audit.sh <目标.app|.dmg|.pkg> <审计目录> [选项]
#
# 选项:
#   --apply-patch        仅在 8 处内置改动意外丢失时补回（会写插件目录）
#   --run                执行管线（默认到编排完就停，由你检查后再跑）
#   --stage S1|...|S8    只跑某个阶段
#   --scope main|all     源码化范围（默认 main=仅自有代码）
#   --offline            不访问 GitHub API
#   --target-name NAME   覆盖 target 名
# =============================================================================
set -uo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SELF_DIR/bin"
# Codex uses the selected interpreter or python3 from PATH, without another host's runtime.
PY="${VULNGATE_PY:-python3}"
command -v "$PY" >/dev/null 2>&1 || { echo "Python not found: $PY" >&2; exit 2; }
export VULNGATE_PY="$PY"
# Bind to this script's plugin version, never an arbitrary installed cache.
PLUGIN="${VULNGATE_PLUGIN:-$(cd "$SELF_DIR/.." && pwd)}"
[ -f "$PLUGIN/.codex-plugin/plugin.json" ] || {
  echo "Codex plugin manifest not found: $PLUGIN/.codex-plugin/plugin.json" >&2; exit 2;
}

TARGET=""; AUDIT=""; APPLY_PATCH=0; DO_RUN=0
STAGE=""; SCOPE="main"; OFFLINE=""; TNAME=""
while [ $# -gt 0 ]; do
  case "$1" in
    --apply-patch) APPLY_PATCH=1; shift ;;
    --run)         DO_RUN=1; shift ;;
    --stage)       STAGE="$2"; shift 2 ;;
    --scope)       SCOPE="$2"; shift 2 ;;
    --offline)     OFFLINE="--offline"; shift ;;
    --target-name) TNAME="$2"; shift 2 ;;
    -h|--help)     sed -n '2,26p' "$0"; exit 0 ;;
    *)             if [ -z "$TARGET" ]; then TARGET="$1"; else AUDIT="$1"; fi; shift ;;
  esac
done

if [ -z "$TARGET" ] || [ -z "$AUDIT" ]; then
  echo "用法: run-audit.sh <目标.app|.dmg|.pkg> <审计目录> [--apply-patch] [--run]" >&2
  exit 2
fi
[ -e "$TARGET" ] || { echo "目标不存在: $TARGET" >&2; exit 2; }
AUDIT="$(mkdir -p "$AUDIT" && cd "$AUDIT" && pwd)"

hr() { printf '\n\033[1;36m========== %s ==========\033[0m\n' "$*"; }
ok() { printf '\033[32m  ✓\033[0m %s\n' "$*"; }
warn() { printf '\033[33m  ! \033[0m%s\n' "$*" >&2; }

echo "审计目录 : $AUDIT"
echo "目标     : $TARGET"
echo "插件     : ${PLUGIN:-<未找到>}"

# --------------------------------------------------------------------------- #
hr "1/6 侦察：识别语言栈"
if [ -x "$SELF_DIR/../macos-app-recon.sh" ]; then
  bash "$SELF_DIR/../macos-app-recon.sh" "$TARGET" 2>&1 | \
    sed -n '/A. 归一化/,/^====/p' | head -40
elif [ -x "$SELF_DIR/macos-app-recon.sh" ]; then
  bash "$SELF_DIR/macos-app-recon.sh" "$TARGET" 2>&1 | head -40
else
  warn "未找到 macos-app-recon.sh，跳过（不影响后续）"
fi

# --------------------------------------------------------------------------- #
hr "2/6 源码化：转成 vulngate 可扫的目录树"
bash "$BIN/app2source.sh" "$TARGET" -o "$AUDIT" --scope "$SCOPE" || {
  echo "源码化失败" >&2; exit 4; }

# --------------------------------------------------------------------------- #
hr "3/6 校验：vulngate 的原生支持"
if [ -n "$PLUGIN" ]; then
  if [ "$APPLY_PATCH" -eq 1 ]; then
    "$PY" "$BIN/patch-vulngate.py" --plugin "$PLUGIN" --apply
  else
    # The eight changes ship inside the plugin source, so a normal install needs
    # no patching at all: verify, and only warn when something is actually gone.
    VERIFY_RAW="$("$PY" "$BIN/patch-vulngate.py" --plugin "$PLUGIN" --verify 2>&1)"
    printf '%s\n' "$VERIFY_RAW"
    if printf '%s\n' "$VERIFY_RAW" | grep -q '已生效 8/8'; then
      ok "8 处原生支持已内置在插件源码里 —— 不需要打补丁"
    else
      warn "有改动未生效（见上方清单）：用 --apply-patch 补回，或改仓库源码后重装"
    fi
  fi
else
  warn "未定位到 vulngate 插件，跳过校验（用 VULNGATE_PLUGIN 指定）"
fi

# --------------------------------------------------------------------------- #
hr "4/6 配置：生成 TargetConfig"
NAME="$TNAME"
if [ -z "$NAME" ]; then
  NAME="$(basename "$TARGET" | sed 's/\.[^.]*$//' | tr 'A-Z' 'a-z' | tr -c 'a-z0-9' '-' | sed 's/-*$//')"
fi
mkdir -p "$AUDIT/targets"
CFG="$AUDIT/targets/$NAME.json"
"$PY" "$BIN/gen-config.py" \
  --recon "$AUDIT/recon.json" \
  --audit-root "$AUDIT" \
  --plugin "$PLUGIN" \
  --name "$NAME" \
  -o "$CFG" || { echo "配置生成失败" >&2; exit 5; }

# --------------------------------------------------------------------------- #
hr "5/6 落 PoC 模板"
POCDIR="$AUDIT/poc/$NAME/round-01/src"
mkdir -p "$POCDIR"
cp "$SELF_DIR/templates/poc-native.sh" "$POCDIR/poc-01.sh" 2>/dev/null && \
  ok "PoC 骨架 -> $POCDIR/poc-01.sh"
mkdir -p "$AUDIT/agent/regression/configs"
ln -sf "$CFG" "$AUDIT/agent/regression/configs/$NAME.json" 2>/dev/null

# --------------------------------------------------------------------------- #
hr "6/6 运行管线"
if [ "$DO_RUN" -eq 1 ]; then
  [ -n "$PLUGIN" ] || { echo "缺插件，无法运行" >&2; exit 6; }
  ARGS=(--plugin "$PLUGIN" --audit-root "$AUDIT"
        --target "$NAME" --round 1 --config "targets/$NAME.json" $OFFLINE)
  [ -n "$STAGE" ] && ARGS+=(--stage "$STAGE")
  "$PY" "$BIN/vg-run.py" "${ARGS[@]}"
else
  cat <<EOT
  已编排完毕，但未执行管线（默认安全停点）。检查无误后手动跑：

    # 先只跑 S1，确认扫描真的扫到了东西
    $PY $BIN/vg-run.py --plugin "$PLUGIN" --audit-root "$AUDIT" \\
        --target "$NAME" --round 1 --config "targets/$NAME.json" --stage S1 --force

    # 再整条跑
    $PY $BIN/vg-run.py --plugin "$PLUGIN" --audit-root "$AUDIT" \\
        --target "$NAME" --round 1 --config "targets/$NAME.json" $OFFLINE

  产物位置：
    源码视图   $AUDIT/reconstructed/
    配置       $CFG
    管线状态   $AUDIT/state/$NAME/
    发现       $AUDIT/ledger/$NAME/
EOT
fi
