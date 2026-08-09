#!/usr/bin/env bash
# VulnGate installer — installs the plugin into the Codex personal marketplace.
#
# Usage:
#   ./install.sh                      # install to ~/plugins/vulngate + register marketplace
#   codex plugin add vulngate@personal
#
# Env overrides (testing): PLUGIN_HOME, VULNGATE_MARKETPLACE
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DEST="${PLUGIN_HOME:-$HOME/plugins}/vulngate"
MARKETPLACE="${VULNGATE_MARKETPLACE:-$HOME/.agents/plugins/marketplace.json}"

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

echo "[4/4] Validating"
if [ -f "$ROOT/.codex-plugin/plugin.json" ]; then
  VALIDATOR="/Users/cyber/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py"
  if [ -f "$VALIDATOR" ]; then
    python3 "$VALIDATOR" "$DEST"
  else
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
  fi
fi

echo
echo "Installed. Enable in Codex:"
echo "  codex plugin add vulngate@personal"
echo "Then start a NEW thread — the vulngate-audit skill loads at thread start."
