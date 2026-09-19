#!/usr/bin/env bash
# ==============================================================================
#  macOS 应用审计前侦察 —— 判定 vulngate 能否接手
#
#  用法：
#     bash macos-app-recon.sh <path>              # .dmg / .pkg / .app 均可
#     bash macos-app-recon.sh <path> --extract DIR  # 顺带把 .app 复制出来
#
#  输出：语言栈识别 + 明文源码规模 + vulngate 适用性判定 + 下一步命令
#
#  背景：vulngate 自带白名单覆盖
#        .java .kt .scala .clj .py .go .rb .js .jsx .ts .tsx .php .rs .cs .c .cpp .h
#        本项目已内置 macOS 适配层，把白名单补到 .swift/.m/.mm/.hpp/.mjs/.cjs，
#        并加入 native sink 规则与 native-app 目标类型 —— 纯原生 app 因此也在射程内，
#        前提是先用 app2source.sh 把 Mach-O 转成可扫的声明树。详见 macos/README.md。
# ==============================================================================
set -uo pipefail

SRC="${1:-}"
shift || true
EXTRACT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --extract) EXTRACT="${2:-}"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ -n "$SRC" ] || { sed -n '2,14p' "$0"; exit 2; }
[ -e "$SRC" ] || { echo "路径不存在: $SRC" >&2; exit 2; }

HERE="$(cd "$(dirname "$0")" && pwd)"
ASAR_STATS="$HERE/bin/asar_stats.py"
# Codex uses the selected interpreter or python3 from PATH, without another host's runtime.
PY_BIN="${VULNGATE_PY:-python3}"
command -v "$PY_BIN" >/dev/null 2>&1 || { echo "Python not found: $PY_BIN" >&2; exit 2; }
export VULNGATE_PY="$PY_BIN"

hdr()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
kv()   { printf '  %s: %s\n' "$1" "$2"; }

MOUNTED=""
cleanup() {
  if [ -n "$MOUNTED" ]; then
    hdiutil detach "$MOUNTED" -quiet 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ==============================================================================
hdr "A. 归一化输入"
# ==============================================================================
APP=""
case "$SRC" in
  *.dmg|*.DMG)
    MOUNTPOINT="$(mktemp -d /tmp/recon-dmg.XXXXXX)"
    echo "  挂载 DMG（只读，不自动打开）..."
    if hdiutil attach "$SRC" -nobrowse -readonly -mountpoint "$MOUNTPOINT" -quiet; then
      MOUNTED="$MOUNTPOINT"
      APP="$(find "$MOUNTPOINT" -maxdepth 2 -name '*.app' -type d 2>/dev/null | head -1)"
      if [ -z "$APP" ]; then
        PKG="$(find "$MOUNTPOINT" -maxdepth 2 -name '*.pkg' 2>/dev/null | head -1)"
        [ -n "$PKG" ] && echo "  DMG 内是 .pkg，不是 .app：$PKG"
      fi
      echo "  挂载点: $MOUNTPOINT"
    else
      echo "  挂载失败" >&2; exit 1
    fi
    ;;
  *.pkg|*.PKG)
    DEST="${EXTRACT:-$(mktemp -d /tmp/recon-pkg.XXXXXX)}"
    mkdir -p "$DEST"
    echo "  展开 pkg → $DEST"
    pkgutil --expand-full "$SRC" "$DEST" >/dev/null 2>&1
    APP="$(find "$DEST" -maxdepth 4 -name '*.app' -type d 2>/dev/null | head -1)"
    ;;
  *.app|*.APP)
    APP="$SRC"
    ;;
  *)
    APPDIR="$SRC/Applications"
    [ -d "$APPDIR" ] && APP="$(find "$APPDIR" -maxdepth 1 -name '*.app' -type d 2>/dev/null | head -1)"
    [ -z "$APP" ] && { echo "无法识别输入类型（需 .dmg/.pkg/.app）" >&2; exit 2; }
    ;;
esac

if [ -z "$APP" ]; then
  echo "  未在输入中找到 .app" >&2
  exit 1
fi

REAL="$(cd "$APP" 2>/dev/null && pwd -P)"
NAME="$(basename "$APP" .app)"
kv "app 包" "$APP"
[ "$REAL" != "$APP" ] && kv "真实路径" "$REAL (符号链接已解析)"
kv "bundle 大小" "$(du -sh "$REAL" 2>/dev/null | cut -f1)"

# --extract：把 app 复制到工作目录
if [ -n "$EXTRACT" ]; then
  mkdir -p "$EXTRACT"
  echo "  复制到 $EXTRACT/$NAME.app ..."
  cp -R "$APP" "$EXTRACT/" 2>/dev/null && echo "  完成"
fi

# ==============================================================================
hdr "B. 语言栈识别"
# ==============================================================================
IS_ELECTRON=0; IS_ASAR=0; JAR_N=0; PY_N=0; JS_DIR=""

[ -d "$APP/Contents/Frameworks/Electron Framework.framework" ] && IS_ELECTRON=1
[ -f "$APP/Contents/Resources/app.asar" ] && IS_ASAR=1
[ -d "$APP/Contents/Resources/app" ] && JS_DIR="$APP/Contents/Resources/app"

JAR_N=$(find "$APP" -name '*.jar' 2>/dev/null | wc -l | tr -d ' ')
PY_N=$(find "$APP" -maxdepth 4 -name '*.py' 2>/dev/null | wc -l | tr -d ' ')

CORE_BIN="$APP/Contents/MacOS/$(defaults read "$REAL/Contents/Info" CFBundleExecutable 2>/dev/null || echo "$NAME")"
kv "Electron 框架" "$([ "$IS_ELECTRON" = 1 ] && echo '是' || echo '否')"
kv "app.asar" "$([ "$IS_ASAR" = 1 ] && echo '是' || echo '否')"
kv "Resources/app 目录" "$([ -n "$JS_DIR" ] && echo '存在（见 C 段统计）' || echo '否')"
kv "jar 数量" "$JAR_N"
kv "py 脚本数量" "$PY_N"
if [ -f "$CORE_BIN" ]; then
  kv "主二进制架构" "$(lipo -archs "$CORE_BIN" 2>/dev/null || echo '?')"
fi

# ==============================================================================
hdr "C. asar 内容统计"
# ==============================================================================
if [ "$IS_ASAR" = 1 ]; then
  "$PY_BIN" "$ASAR_STATS" "$APP/Contents/Resources/app.asar" 2>&1 | sed 's/^/  /'
else
  echo "  无 app.asar，跳过"
fi

if [ -n "$JS_DIR" ]; then
  echo ""
  echo "  Resources/app 目录（未打包 JS）："
  n=$(find "$JS_DIR" -name '*.js' 2>/dev/null | wc -l | tr -d ' ')
  nm=$(find "$JS_DIR" -name '*.map' 2>/dev/null | wc -l | tr -d ' ')
  echo "    .js = $n    .map = $nm"
fi

# ==============================================================================
hdr "D. vulngate 适用性判定"
# ==============================================================================
VERDICT=""
if [ "$JAR_N" -gt 0 ]; then
  VERDICT="JAVA"
elif [ "$IS_ASAR" = 1 ] || [ "$IS_ELECTRON" = 1 ] || [ -n "$JS_DIR" ]; then
  VERDICT="ELECTRON"
elif [ "$PY_N" -gt 0 ]; then
  VERDICT="PYTHON"
else
  VERDICT="NATIVE"
fi

LBL_FULL="$(printf '\033[32m%s\033[0m' '[vulngate: 可全通]')"
LBL_PART="$(printf '\033[33m%s\033[0m' '[vulngate: 部分可用]')"
LBL_ADAPT="$(printf '\033[32m%s\033[0m' '[vulngate: 可全通（需适配层）]')"
LBL_NONE="$(printf '\033[31m%s\033[0m' '[vulngate: 不适用]')"

case "$VERDICT" in
  JAVA)
    cat <<EOT
  $LBL_FULL 这是 Java 应用（$JAR_N 个 jar）
  vulngate 是 JVM 生态审计工具，这是它的原生主场 —— S1→S8 全部可跑，
  包括 S4 的 java PoC 矩阵（本机 JDK 8/17/21 齐全）。

  下一步：
    1) 反编译 jar 得到可审源码（任选其一，需自行安装）：
         jadx   ~/tools/jadx/bin/jadx -d src/ $APP/Contents/**/*.jar
         cfr    java -jar cfr.jar <jar> --outputdir src/
         procyon / fernflower 同理
    2) 建工作区并指向反编译后的源码目录：
         state/ledger/reports 由 vulngate 自动创建
    3) 起一轮：目标目录 = src/，env.md 记 JVM 版本与 jar 清单
EOT
    ;;
  ELECTRON)
    cat <<EOT
  $LBL_PART 这是 Web/Electron 系应用
  明文 JS/TS 在 asar 或 Resources/app 里，vulngate 的 glob 白名单含 .js/.ts/.jsx/.tsx
  → S1 攻击面、S2 候选、S3 源码审计（file:line）都能做。
  典型案例面：ipcMain/ipcRenderer 通道、contextIsolation/nodeIntegration、
  preload 暴露面、shell.openExternal、自定义协议 handler、asar 路径穿越。

  下一步：
    1) 解包 asar（需 npx：npx --yes @electron/asar extract app.asar ./src）
       若有 .map，用 source-map 工具还原原始 TS，更容易出 file:line
    2) 目标目录 = 解包后的目录（含 package.json 的那一层）
    3) S4 只能用 --lang shell 跑 node 做单函数级验证；
       Electron 原生模块依赖缺位时记 precondition-unavailable，不要当负证据
EOT
    ;;
  PYTHON)
    cat <<EOT
  $LBL_PART 包里带明文 Python 脚本（$PY_N 个）
  .py 在 vulngate 白名单内，源码级审计可做；S4 走 --lang shell 调 python3。
EOT
    ;;
  NATIVE)
    cat <<EOT
  $LBL_ADAPT 没有明文 jar / JS / Python —— 是编译后的 Mach-O（Swift/ObjC/C/C++）
  本项目已内置 native 支持（白名单含 .swift/.m/.mm/.h，DANGER_PATTERNS 含 11 组
  macOS sink，TARGET_RULES 含 native-app）。**但 Mach-O 不能直接扫**，先源码化：

  下一步：
    1) 一键编排（侦察→源码化→配置→跑管线）：
         bash macos/run-audit.sh "$APP" ./audit
      只做源码化时：
         bash macos/bin/app2source.sh "$APP" -o ./audit --scope main
      产出 ./audit/reconstructed/ 为可扫声明树（.h/.c），S1→S8 全程可用。
    2) 源码化是元数据重建（符号/字符串/Objective-C 运行时方法、Selector、类结构、
       entitlements、URL scheme、XPC 服务名），**不是反编译**。要拿真实伪代码仍需
       Ghidra / Hopper / radare2 / ipsw class-dump，可把产物一并放进 reconstructed/，
       两条证据链互补：重建树给 S1/S2 定面，伪代码给 S3 落 file:line。
    3) 附带工具（系统自带，立即可用）：
         otool -L / nm / strings / codesign -d --entitlements -   ← 二进制面
         ipsw macho info / ipsw class-dump                        ← brew install ipsw
EOT
    ;;
esac

# ==============================================================================
hdr "E. 签名与加固信息（对所有类型都有用）"
# ==============================================================================
echo "  --- codesign ---"
codesign -dvvv "$APP" 2>&1 | grep -E "Identifier|TeamIdentifier|Authority|flags|Runtime" | sed 's/^/    /' | head -8
echo "  --- entitlements ---"
codesign -d --entitlements - "$APP" 2>/dev/null | head -20 | sed 's/^/    /'
echo "  --- Gatekeeper ---"
spctl -a -vv "$APP" 2>&1 | sed 's/^/    /' | head -3

# ==============================================================================
hdr "完成"
# ==============================================================================
echo "  提醒：DMG 挂载点已自动卸载。若复制了 .app，注意它是别人的版权物，"
echo "        审计行为需在授权范围内，发现不要自动公开。"
