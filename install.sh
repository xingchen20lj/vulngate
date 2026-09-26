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
case "${1:-}" in
  --no-enable) ENABLE=0 ;;
  "") ;;
  *) echo "usage: $0 [--no-enable]" >&2; exit 2 ;;
esac

if [ ! -f "$ROOT/.codex-plugin/plugin.json" ]; then
  echo "error: plugin manifest not found at $ROOT/.codex-plugin/plugin.json" >&2
  exit 1
fi

echo "[1/4] Copying plugin -> $DEST"
DEST_PARENT="$(dirname "$DEST")"
mkdir -p "$DEST_PARENT"
CACHEBUSTER="$(date -u +%Y%m%d-%H%M%S)-$$"
STAGING="$(mktemp -d "$DEST_PARENT/.vulngate-staging.XXXXXX")"
BACKUP="${DEST}.previous.${CACHEBUSTER}"
FAILED="${DEST}.failed.${CACHEBUSTER}"
OLD_DEST_PRESENT=0
[ -e "$DEST" ] && OLD_DEST_PRESENT=1
SWAPPED=0

rollback_install() {
  status=$?
  trap - EXIT ERR INT TERM
  if [ "$SWAPPED" = "1" ] && [ -e "$DEST" ]; then
    mv "$DEST" "$FAILED" 2>/dev/null || true
  fi
  if [ "$OLD_DEST_PRESENT" = "1" ] && [ -e "$BACKUP" ]; then
    mv "$BACKUP" "$DEST" 2>/dev/null || true
    echo "!! installation failed; previous plugin restored at $DEST" >&2
  fi
  if [ -d "$STAGING" ]; then
    rm -rf -- "$STAGING"
  fi
  exit "$status"
}
trap rollback_install EXIT ERR INT TERM

sync_directory() {
  python3 - "$1" <<'PYEOF'
import os
import sys
fd = os.open(sys.argv[1], os.O_RDONLY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PYEOF
}
tar -C "$ROOT" -cf - \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude '.DS_Store' \
  --exclude 'docs/DEVELOPMENT-REVIEW.zh-CN.md' \
  .codex-plugin hooks skills scripts macos assets docs benchmarks schemas pyproject.toml \
  README.md README.zh-CN.md LICENSE CHANGELOG.md PROVENANCE.md RELATED_WORK.md \
  SECURITY.md SECURITY.zh-CN.md CONTRIBUTING.md CONTRIBUTING.zh-CN.md \
  | tar -C "$STAGING" -xf -
echo "[2/4] Updating local cachebuster (iteration-aware reinstall)"
python3 - "$STAGING" "local-$CACHEBUSTER" <<'PYEOF'
import json, sys
from pathlib import Path
import os
dest = Path(sys.argv[1])
manifest = dest / ".codex-plugin" / "plugin.json"
data = json.loads(manifest.read_text(encoding="utf-8"))
base = data.get("version", "0.1.0").split("+")[0]
data["version"] = "%s+codex.%s" % (base, sys.argv[2])
tmp = manifest.with_name(manifest.name + ".tmp")
with tmp.open("w", encoding="utf-8") as handle:
    handle.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    handle.flush()
    os.fsync(handle.fileno())
tmp.replace(manifest)
print("    version ->", data["version"])
PYEOF

# Validate the complete staged tree before changing the active installation.
python3 - "$STAGING" <<'PYEOF'
import json, re, sys
from pathlib import Path
root = Path(sys.argv[1])
manifest = root / ".codex-plugin" / "plugin.json"
data = json.loads(manifest.read_text(encoding="utf-8"))
required = ("name", "version", "description", "skills", "interface")
missing = [key for key in required if key not in data]
if missing or data.get("name") != "vulngate" or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+.*", data.get("version", "")):
    raise SystemExit("staged plugin manifest validation failed: %s" % missing)
for icon in ("composerIcon", "logo"):
    path = data.get("interface", {}).get(icon)
    if path and not (root / path).exists():
        raise SystemExit("staged plugin asset missing: %s" % path)
print("    staged plugin validation OK")
PYEOF

# Publish only runtime files and documentation. In particular, never copy
# state/, ledger/, reports/, poc/, credentials or .vulngate-macos-backup/.
# The rename is the only point at which the active directory changes.
if [ "$OLD_DEST_PRESENT" = "1" ]; then
  mv "$DEST" "$BACKUP"
fi
mv "$STAGING" "$DEST"
SWAPPED=1
sync_directory "$DEST_PARENT"

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
import os, tempfile
fd, temp_name = tempfile.mkstemp(prefix=path.name + ".tmp.", dir=str(path.parent))
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    Path(temp_name).replace(path)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
except Exception:
    try:
        Path(temp_name).unlink()
    except OSError:
        pass
    raise
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
  python3 "$VALIDATOR" "$DEST"
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
  if [ -x "/Applications/Codex.app/Contents/Resources/codex" ]; then
    echo "/Applications/Codex.app/Contents/Resources/codex"
    return 0
  fi
  if [ -x "/Applications/ChatGPT.app/Contents/Resources/codex" ]; then
    echo "/Applications/ChatGPT.app/Contents/Resources/codex"
    return 0
  fi
  # Windows (Git Bash / WSL) common locations
  for p in \
    "${LOCALAPPDATA:-}/Programs/ChatGPT/Resources/codex" \
    "/c/Program Files/ChatGPT/Resources/codex"; do
    if [ -x "$p" ]; then
      echo "$p"
      return 0
    fi
  done
  return 1
}

# Codex binds a skill path when a thread starts. A reinstall changes the
# versioned cache directory, so preserve aliases for all cache versions that
# existed before the reinstall. This lets in-progress threads keep resolving
# their original path while new threads use the new version.
CODEX_HOME_DIR="${CODEX_HOME:-$HOME/.codex}"
CACHE_ROOT="$CODEX_HOME_DIR/plugins/cache/personal/vulngate"
OLD_CACHE_VERSIONS="$(mktemp "${TMPDIR:-/tmp}/vulngate-cache-versions.XXXXXX")"
cleanup_cache_versions() {
  rm -f "$OLD_CACHE_VERSIONS"
}
trap cleanup_cache_versions EXIT

capture_cache_versions() {
  : > "$OLD_CACHE_VERSIONS"
  if [ -d "$CACHE_ROOT" ]; then
    find "$CACHE_ROOT" -mindepth 1 -maxdepth 1 \
      \( -type d -o -type l \) -exec basename {} \; \
      | sort -u > "$OLD_CACHE_VERSIONS"
  fi
}

restore_cache_aliases() {
  local active_version="$1"
  local old_version
  if [ ! -d "$CACHE_ROOT/$active_version" ]; then
    return 0
  fi
  while IFS= read -r old_version; do
    [ -n "$old_version" ] || continue
    [ "$old_version" = "$active_version" ] && continue
    if [ -L "$CACHE_ROOT/$old_version" ]; then
      rm -f "$CACHE_ROOT/$old_version"
      ln -s "$CACHE_ROOT/$active_version" "$CACHE_ROOT/$old_version"
      echo "    refreshed cache path: $old_version -> $active_version"
    elif [ ! -e "$CACHE_ROOT/$old_version" ]; then
      ln -s "$CACHE_ROOT/$active_version" "$CACHE_ROOT/$old_version"
      echo "    preserved cache path: $old_version -> $active_version"
    fi
  done < "$OLD_CACHE_VERSIONS"
}

if [ "$ENABLE" = "1" ]; then
  CODEX="$(find_codex || true)"
  if [ -n "$CODEX" ]; then
    ACTIVE_VERSION="$(python3 - "$DEST" <<'PYEOF'
import json, sys
from pathlib import Path
print(json.loads((Path(sys.argv[1]) / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))["version"])
PYEOF
)"
    capture_cache_versions
    echo "[5/5] Enabling plugin in Codex (via $CODEX)"
    "$CODEX" plugin add vulngate@personal
    restore_cache_aliases "$ACTIVE_VERSION"
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

# A successful install keeps the previous version for rollback.  Stop the
# failure trap only after all validation and optional enablement completed.
cleanup_cache_versions
trap - EXIT ERR INT TERM
