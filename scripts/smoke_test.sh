#!/usr/bin/env bash
# VulnGate plugin — smoke test (env + deterministic helpers).
set -euo pipefail

PLUGIN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$PLUGIN_ROOT/scripts${PYTHONPATH:+:$PYTHONPATH}"

echo "[1/6] doctor"
python3 "$PLUGIN_ROOT/scripts/agent_cli.py" doctor | python3 -c \
  'import json,sys; d=json.load(sys.stdin); print("  status:", d["status"], "| missing:", d["missing"])'

echo "[2/6] cvss (G5)"
python3 "$PLUGIN_ROOT/scripts/agent_cli.py" cvss \
  --vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" --tier 0

echo "[3/6] novelty (offline evidence, conservative)"
cat > /tmp/zda-novelty-evidence.json <<'EOF'
{"refs": [], "disclosures": [], "discovery_date": "2026-08-09",
 "query_failed": true, "increments": []}
EOF
python3 "$PLUGIN_ROOT/scripts/agent_cli.py" novelty --evidence /tmp/zda-novelty-evidence.json

echo "[4/6] source-map on a non-Java target (Clojure routes, --globs all)"
SMOKE_SRC="$(mktemp -d)"
mkdir -p "$SMOKE_SRC/src/demo"
cat > "$SMOKE_SRC/src/demo/routes.clj" <<'CLJ'
(ns demo.routes)
(api.macros/defendpoint :post "/reset_password" [_ _ {:keys [token]}]
  (do-reset token))
(defroutes app (GET "/api/x" [] (ok)))
CLJ
python3 "$PLUGIN_ROOT/scripts/agent_cli.py" source-map --root "$SMOKE_SRC" \
  --preset http --globs all --max-hits 10 | python3 -c '
import json,sys
d=json.load(sys.stdin)
hits=[e for e in d["entries"] if "defendpoint" in e["text"] or "defroutes" in e["text"]]
print("  count:", d["count"], "| route hits:", len(hits))
assert len(hits) >= 2, "expected defendpoint+defroutes hits, got %s" % d["entries"]
'
rm -rf "$SMOKE_SRC"

echo "[5/6] ledger evidence hard rule (reject empty evidence)"
cat > /tmp/zda-ledger-empty.json <<'EOF'
{"rows": [], "excluded": [{"surface": "X1 test", "conclusion": "excluded", "evidence": ""}]}
EOF
if python3 "$PLUGIN_ROOT/scripts/agent_cli.py" ledger \
  --workspace "$(mktemp -d)" --target smoke --round 1 \
  --entries /tmp/zda-ledger-empty.json >/dev/null 2>&1; then
  echo "  FAIL: ledger accepted empty evidence"; exit 1
fi
echo "  ok: empty-evidence entry rejected (exit != 0)"

echo "[6/6] done"
