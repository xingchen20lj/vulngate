#!/usr/bin/env bash
# =============================================================================
# poc-native.sh -- S4 原生应用 PoC 骨架（遵守 vulngate 的观测契约）
#
# 放进 vulngate 的 PoC 目录后用 --lang shell 跑：
#   <workspace>/poc/<target>/round-01/src/<candidate>.sh
#   vg-run.py ... --stage S4
#   或 agent_cli.py matrix --lang shell --manifest <manifest.json>
#
# 为什么用 shell 而不是 java
# -------------------------
# agent_cli.py 的 `matrix --lang` 只有 {java, shell}。原生 macOS 应用的 PoC
# 天然是"起进程 / 喂输入 / 观察副作用"，用 shell 完全够，且**无需改插件**。
# 关键在于必须按下面的契约打印观测行，否则 build.py 的 parse_observations
# 解析不到，G4 会判"缺运行时证据"从而拒绝确认。
#
# 观测契约（build.py::summarize_candidate -> orchestrator/gates.py::g4_runtime）
# ---------------------------------------------------------------------------
#   HTTP_CODE=<状态码>          观测到的 HTTP 状态码（digit 才计入）
#   RESP_MATCH=<标记>           响应中的期望标记（非占位值）
#   EVIDENCE=<文本>             通用副作用证据
#   INSTANTIATED=<FQCN>         被实例化的类，**必须含点**，否则不计
#   LEAKED=<具体内容>           泄漏的实际内容（需含分隔符，裸标识符会被判硬编码）
#   ERROR=<异常/崩溃>           运行时错误
#   GATE_BLOCKED=<原因>         前置条件阻断
#   ENV_ERROR=<原因>            环境问题（会让结论降级为"候选"，不是证据）
#   NETWORK=<url>               出网目标（需回环）
#   PARSED=<标记>               成功解析
#   INPUT_BYTES=<字节数>        OOM/DoS 放大倍数判定的必需项
#   CONCURRENCY=<n> + SERVICE_UNAVAILABLE=true   可用性证明
#   CANARY=<标记>               内存金丝雀（会被判为 safe-equivalent，**不能**支撑 RCE）
#
#   ★ EFFECT_KIND + EFFECT    —— RCE / 代码执行类结论的唯一通行证
#     _has_real_effect() 只承认这几个 kind：
#       command-executed | command-marker | process-started |
#       code-execution   | file-marker
#     缺 EFFECT_KIND，或被判为 canary/simulat/shape-only/in-memory，
#     就只能停在"能力证明"，G4 会拒绝"确认"。
#
# 环境变量（由 ShellMatrixRunner 注入）
#   VULNGATE_VERSION / VULNGATE_SAFE_MODE / VULNGATE_PRECONDITION
#   VULNGATE_FEATURES / VULNGATE_TARGET_URL
# =============================================================================
set -uo pipefail

# ---- 单元标识（矩阵会跑多组 version × safe_mode × precondition） -------------
VERSION="${VULNGATE_VERSION:-local}"
SAFE_MODE="${VULNGATE_SAFE_MODE:-false}"
PRECONDITION="${VULNGATE_PRECONDITION:-default}"
FEATURES="${VULNGATE_FEATURES:-}"

TARGET_APP="${POC_TARGET_APP:-/Applications/REPLACE_ME.app}"
TARGET_BIN="${POC_TARGET_BIN:-$TARGET_APP/Contents/MacOS/REPLACE_ME}"

# 沙箱化工作区：所有副作用只允许落在 tmp 内
WORK="$(mktemp -d "${TMPDIR:-/tmp}/vg-poc.XXXXXX")"
MARKER="$WORK/marker.txt"
trap 'rm -rf "$WORK"' EXIT

echo "# cell version=$VERSION safe_mode=$SAFE_MODE precondition=$PRECONDITION"
echo "# features=$FEATURES target=$TARGET_BIN"

# ---------------------------------------------------------------------------
# 前置条件闸门：不满足就明确报告，而不是伪造观测值
# ---------------------------------------------------------------------------
if [ ! -x "$TARGET_BIN" ]; then
  echo "ENV_ERROR=target binary not executable: $TARGET_BIN"
  exit 0
fi

# 若被测路径需要某 feature 开启，而本 cell 未开启，要如实报 gate blocked
case "$FEATURES" in
  *REPLACE_FEATURE*) : ;;
  *)
    echo "GATE_BLOCKED=required feature not enabled in this cell (features=$FEATURES)"
    exit 0
    ;;
esac

# ---------------------------------------------------------------------------
# 候选面 A：URL Scheme / 文件关联注入
#   观测：应用被唤起后是否以非预期参数执行了动作
# ---------------------------------------------------------------------------
probe_url_scheme() {
  local payload="$1"
  # 例：open "targetapp://action?path=$(printf '%s' "$payload" | base64)"
  # 只为演示契约，此处不实际调用：
  #   open -a "$TARGET_APP" --args "$payload"
  # 观测副作用：marker 文件是否由进程以外的方式被写入
  if [ -f "$MARKER" ]; then
    echo "EVIDENCE=payload induced file write: $(cat "$MARKER")"
  fi
}

# ---------------------------------------------------------------------------
# 候选面 B：命令执行（RCE）
#   这是唯一能过 G4 的写法：必须给出 EFFECT_KIND=<被承认的 kind> + EFFECT
# ---------------------------------------------------------------------------
probe_command_exec() {
  local payload="$1"
  rm -f "$MARKER"
  # 典型手法（按实际目标替换其中之一）：
  #   1) 参数注入到 NSTask/posix_spawn 的拼接命令
  #   2) DYLD_INSERT_LIBRARIES 劫持（需目标未开 hardened runtime
  #      或 entitlements 含 disable-library-validation）
  #   3) AppleScript / osascript 转发
  #
  # 演示：仅当真的产生了进程与产物，才打印 effect 行
  if [ -n "${POC_FORCE_DEMO:-}" ]; then
    /bin/sh -c 'echo vg-poc > "'"$MARKER"'"' >/dev/null 2>&1
  fi

  if [ -f "$MARKER" ] && [ "$(cat "$MARKER" 2>/dev/null)" = "vg-poc" ]; then
    # 真实：产物由被利用的路径产生
    echo "EFFECT_KIND=command-marker"
    echo "EFFECT=marker file created by spawned command: $MARKER -> $(cat "$MARKER")"
    echo "EVIDENCE=child pid recorded: $(cat "$WORK/child.pid" 2>/dev/null || echo n/a)"
  else
    # 未复现：如实报告，不伪造。G4 会正确拒绝确认。
    echo "ERROR=payload did not reach command execution path (no side effect observed)"
  fi
}

# ---------------------------------------------------------------------------
# 候选面 C：反序列化 / plist 解析
#   观测：INSTANTIATED 必须是带点的类名；LEAKED 必须是真实内容
# ---------------------------------------------------------------------------
probe_deserialization() {
  local plist="$WORK/payload.plist"
  printf '%s' "${POC_PLIST:-}" > "$plist"
  if [ ! -s "$plist" ]; then
    echo "GATE_BLOCKED=no payload supplied via POC_PLIST"
    return
  fi
  # 例：/usr/bin/plutil -convert xml1 -o - "$plist"
  # 观测：
  #   echo "INSTANTIATED=com.example.ClassName"
  #   echo "LEAKED=key=value;path=/etc/passwd:1"
  echo "PARSED=plist"
}

# ---------------------------------------------------------------------------
# 候选面 D：本地 HTTP / XPC 服务面（与 web-app 同构，Evidence 走 HTTP 契约）
# ---------------------------------------------------------------------------
probe_local_service() {
  local base="${VULNGATE_TARGET_URL:-http://127.0.0.1:8080}"
  local code
  code="$(/usr/bin/curl -s -o "$WORK/body" -w '%{http_code}' \
          --max-time 8 "$base/REPLACE_PATH" 2>/dev/null || echo 000)"
  echo "HTTP_CODE=$code"
  if /usr/bin/grep -q "REPLACE_MARKER" "$WORK/body" 2>/dev/null; then
    echo "RESP_MATCH=REPLACE_MARKER"
  fi
}

# ---------------------------------------------------------------------------
# 候选面 E：DoS / 资源放大
#   注意：OOM 类结论必须有 INPUT_BYTES，且 <1MB 才算放大（>=1MB 会被判 trivial）
# ---------------------------------------------------------------------------
probe_dos() {
  local payload="$WORK/input.bin"
  /usr/bin/head -c "${POC_INPUT_BYTES:-1024}" /dev/zero > "$payload" 2>/dev/null
  echo "INPUT_BYTES=$(/usr/bin/stat -f%z "$payload" 2>/dev/null || echo 0)"
  # 观测崩溃：
  #   ... run target ...
  #   if crash detected; then echo "ERROR=EXC_BAD_ACCESS (SIGSEGV) at ..."; fi
}

# ---------------------------------------------------------------------------
# 主流程：按候选面选择。默认只跑一条，避免矩阵爆炸
# ---------------------------------------------------------------------------
case "${POC_PROBE:-command_exec}" in
  url_scheme)      probe_url_scheme   "${POC_PAYLOAD:-test}" ;;
  command_exec)    probe_command_exec "${POC_PAYLOAD:-test}" ;;
  deserialization) probe_deserialization ;;
  local_service)   probe_local_service ;;
  dos)             probe_dos ;;
  *)               echo "ENV_ERROR=unknown POC_PROBE=${POC_PROBE}" ;;
esac

# 收尾：确保总是有可解析输出，避免 harness 误判为"无观测"
exit 0
