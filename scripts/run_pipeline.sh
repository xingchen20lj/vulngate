#!/usr/bin/env bash
# VulnGate plugin — autonomous mode (Mode B) launcher.
#
# Usage:
#   run_pipeline.sh --name <target> --target-dir <src-or-jar-dir> \
#     --round <N> [--max-calls N] [--max-candidates N] [--max-rounds N] \
#     [--reasoning-effort low|high|none] [--lang zh|en] [--offline]
#
# Mode A (host-native) does NOT need this script: the host Codex agent calls
# `agent_cli.py` for deterministic steps and reasons itself.
set -euo pipefail

PLUGIN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$PLUGIN_ROOT/scripts${PYTHONPATH:+:$PYTHONPATH}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 not found" >&2
  exit 2
fi

exec python3 -m agent.autonomous.run_agent "$@"
