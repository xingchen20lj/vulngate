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

echo "[6/7] fix-completeness static-only exclusion rejected (0.2.15)"
cat > /tmp/zda-ledger-static.json <<'EOF'
{"rows": [], "excluded": [{"candidate_id": "C5",
  "surface": "fix-completeness", "conclusion": "excluded",
  "evidence": "static audit: listFirst + listRotateHeadToTail complete"}]}
EOF
if python3 "$PLUGIN_ROOT/scripts/agent_cli.py" ledger \
  --workspace "$(mktemp -d)" --target smoke --round 1 \
  --entries /tmp/zda-ledger-static.json >/dev/null 2>&1; then
  echo "  FAIL: ledger accepted static-only fix-completeness exclusion"; exit 1
fi
echo "  ok: static-only fix-completeness exclusion rejected (exit != 0)"

cat > /tmp/zda-ledger-untagged.json <<'EOF'
{"rows": [], "excluded": [{"surface": "handleClientsBlockedOnKey UAF (#15594 / CVE-2026-23479)",
  "conclusion": "excluded", "evidence": "static audit: listFirst + listRotateHeadToTail complete"}]}
EOF
if python3 "$PLUGIN_ROOT/scripts/agent_cli.py" ledger \
  --workspace "$(mktemp -d)" --target smoke --round 1 \
  --entries /tmp/zda-ledger-untagged.json >/dev/null 2>&1; then
  echo "  FAIL: ledger accepted untagged fix-family static exclusion"; exit 1
fi
echo "  ok: untagged fix-family (UAF #CVE) static exclusion rejected (exit != 0)"

cat > /tmp/zda-ledger-runtime.json <<'EOF'
{"rows": [], "excluded": [{"candidate_id": "C5",
  "surface": "fix-completeness", "conclusion": "excluded",
  "evidence": "OBSERVATION=GATE_BLOCKED(fixed) ERROR=none"}]}
EOF
python3 "$PLUGIN_ROOT/scripts/agent_cli.py" ledger \
  --workspace "$(mktemp -d)" --target smoke --round 1 \
  --entries /tmp/zda-ledger-runtime.json >/dev/null 2>&1 || {
  echo "  FAIL: runtime-evidenced exclusion should be accepted"; exit 1; }
echo "  ok: runtime-evidenced exclusion accepted"

cat > /tmp/zda-ledger-g1.json <<'EOF'
{"rows": [], "excluded": [{"candidate_id": "C9",
  "surface": "fix-completeness", "conclusion": "excluded",
  "evidence": "src/x.c:100 reachable only via admin-only RPC",
  "exclusion_basis": "g1-unreachable"}]}
EOF
python3 "$PLUGIN_ROOT/scripts/agent_cli.py" ledger \
  --workspace "$(mktemp -d)" --target smoke --round 1 \
  --entries /tmp/zda-ledger-g1.json >/dev/null 2>&1 || {
  echo "  FAIL: G1-unreachable exclusion should be accepted"; exit 1; }
echo "  ok: G1-unreachable exclusion accepted"

echo "[7/7] done"
