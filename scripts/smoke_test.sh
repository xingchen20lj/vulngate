#!/usr/bin/env bash
# VulnGate plugin — smoke test (env + deterministic helpers).
set -euo pipefail

PLUGIN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$PLUGIN_ROOT/scripts${PYTHONPATH:+:$PYTHONPATH}"

echo "[1/4] doctor"
python3 "$PLUGIN_ROOT/scripts/agent_cli.py" doctor | python3 -c \
  'import json,sys; d=json.load(sys.stdin); print("  status:", d["status"], "| missing:", d["missing"])'

echo "[2/4] cvss (G5)"
python3 "$PLUGIN_ROOT/scripts/agent_cli.py" cvss \
  --vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" --tier 0

echo "[3/4] novelty (offline evidence, conservative)"
cat > /tmp/zda-novelty-evidence.json <<'EOF'
{"refs": [], "disclosures": [], "discovery_date": "2026-08-09",
 "query_failed": true, "increments": []}
EOF
python3 "$PLUGIN_ROOT/scripts/agent_cli.py" novelty --evidence /tmp/zda-novelty-evidence.json

echo "[4/4] done"
