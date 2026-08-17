#!/usr/bin/env bash
# VulnGate installer — installs the plugin into the Codex personal marketplace.
#
# Usage:
#   ./install.sh                      # installs, registers marketplace AND enables in Codex
#   ./install.sh --no-enable          # install only; you run `codex plugin add` yourself
#
# The script finds the `codex` command automatically: $PATH first, then the CLI
# bundled inside the Codex desktop app. You do NOT need to install codex CLI
# separately when you use the desktop app.
#
# Env overrides: PLUGIN_HOME, VULNGATE_MARKETPLACE, CODEX_BIN
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DEST="${PLUGIN_HOME:-$HOME/plugins}/vulngate"
MARKETPLACE="${VULNGATE_MARKETPLACE:-$HOME/.agents/plugins/marketplace.json}"
ENABLE=1
if [ "${1:-}" = "--no-enable" ]; then
  ENABLE=0
fi

if [ ! -f "$ROOT/.codex-plugin/plugin.json" ]; then
  echo "error: plugin manifest not found at $ROOT/.codex-plugin/plugin.json" >&2
  exit 1
fi

echo "[1/4] Copying plugin -> $DEST"
mkdir -p "$DEST"
tar -C "$ROOT" -cf - \
  --exclude '.git' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  . | tar -C "$DEST" -xf -

echo "[2/4] Updating local cachebuster (iteration-aware reinstall)"
CACHEBUSTER="$(date -u +%Y%m%d-%H%M%S)"
python3 - "$DEST" "local-$CACHEBUSTER" <<'PYEOF'
import json, sys
from pathlib import Path
dest = Path(sys.argv[1])
manifest = dest / ".codex-plugin" / "plugin.json"
data = json.loads(manifest.read_text(encoding="utf-8"))
base = data.get("version", "0.1.0").split("+")[0]
data["version"] = "%s+codex.%s" % (base, sys.argv[2])
manifest.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print("    version ->", data["version"])
PYEOF

echo "[3/4] Registering personal marketplace entry"
python3 - "$MARKETPLACE" <<'PYEOF'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
data = {}
if path.exists():
    data = json.loads(path.read_text(encoding="utf-8"))
data.setdefault("name", "personal")
data.setdefault("interface", {}).setdefault("displayName", "Personal")
data.setdefault("plugins", [])
entry = {
    "name": "vulngate",
    "source": {"source": "local", "path": "./plugins/vulngate"},
    "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
    "category": "Engineering",
}
plugins = data["plugins"]
for i, p in enumerate(plugins):
    if p.get("name") == "vulngate":
        plugins[i] = entry
        break
else:
    plugins.append(entry)
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print("    entry ready at", path)
PYEOF

validate_inline() {
  python3 - "$DEST" <<'PYEOF'
import json, re, sys
from pathlib import Path
dest = Path(sys.argv[1])
data = json.loads((dest / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
req = ("name", "version", "description", "skills", "interface")
missing = [k for k in req if k not in data]
if missing or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+.*", data.get("version", "")):
  print("!! inline validation failed: missing=%s version=%s" % (missing, data.get("version")))
  sys.exit(1)
for icon in ("composerIcon", "logo"):
  p = data.get("interface", {}).get(icon)
  if p and not (dest / p).exists():
    print("!! missing asset:", p)
    sys.exit(1)
print("    inline validation OK")
PYEOF
}

echo "[4/4] Validating"
VALIDATOR="$HOME/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py"
if [ -f "$VALIDATOR" ] && python3 -c 'import yaml' >/dev/null 2>&1; then
  if python3 "$VALIDATOR" "$DEST"; then
    :
  else
    echo "    full validator unavailable; falling back to inline check"
    validate_inline
  fi
else
  validate_inline
fi

find_codex() {
  if [ -n "${CODEX_BIN:-}" ] && [ -x "$CODEX_BIN" ]; then
    echo "$CODEX_BIN"
    return 0
  fi
  local c
  c="$(command -v codex 2>/dev/null || true)"
  if [ -n "$c" ]; then
    echo "$c"
    return 0
  fi
  # macOS: CLI bundled inside the Codex desktop app
  if [ -x "/Applications/ChatGPT.app/Contents/Resources/codex" ]; then
    echo "/Applications/ChatGPT.app/Contents/Resources/codex"
    return 0
  fi
  # Windows (Git Bash / WSL) common locations
  for p in \
    "$LOCALAPPDATA/Programs/ChatGPT/Resources/codex" \
    "/c/Program Files/ChatGPT/Resources/codex"; do
    if [ -x "$p" ]; then
      echo "$p"
      return 0
    fi
  done
  return 1
}

if [ "$ENABLE" = "1" ]; then
  CODEX="$(find_codex || true)"
  if [ -n "$CODEX" ]; then
    echo "[5/5] Enabling plugin in Codex (via $CODEX)"
    "$CODEX" plugin add vulngate@personal
  else
    echo
    echo "!! 未找到 codex 命令，插件已安装但未启用。"
    echo "   如果你在用 Codex 桌面应用，它自带 CLI："
    echo "     macOS:  /Applications/ChatGPT.app/Contents/Resources/codex"
    echo "   请在你的终端里执行："
    echo "     codex plugin add vulngate@personal"
    echo "   然后新建一个线程即可（插件技能在线程启动时加载）。"
  fi
else
  echo
  echo "已安装（未启用）。请手动执行："
  echo "  codex plugin add vulngate@personal"
fi

echo
echo "完成。请新建一个 Codex 线程后开始使用（技能在线程启动时加载）。"
