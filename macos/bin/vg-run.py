#!/usr/bin/env python3
"""Run the bundled Codex pipeline with evidence in a separate audit directory.

Usage:
  vg-run.py --plugin <plugin-root> --audit-root <audit-dir> \
            --target NAME --round 1 --config targets/NAME.json [--stage S1]

The loaded script's plugin is authoritative unless --plugin or VULNGATE_PLUGIN
explicitly selects another Codex plugin. No installed cache is searched.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def find_plugin(explicit: str) -> Path:
    """定位 vulngate 插件根（含 scripts/agent/orchestrator/pipeline.py 的那个目录）。"""
    selected = explicit or os.environ.get("VULNGATE_PLUGIN")
    plugin = Path(selected).expanduser().resolve() if selected else Path(__file__).resolve().parents[2]
    if ((plugin / ".codex-plugin/plugin.json").is_file()
            and (plugin / "scripts/agent/orchestrator/pipeline.py").is_file()):
        return plugin
    raise SystemExit("ERROR: invalid Codex VulnGate plugin: %s" % plugin)



def main(argv: list) -> int:
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--plugin", default="")
    ap.add_argument("--audit-root", default="")
    ap.add_argument("-h", "--help", action="store_true")
    known, rest = ap.parse_known_args(argv)
    if known.help:
        print(__doc__)
        return 0

    plugin = find_plugin(known.plugin)
    audit_root = Path(known.audit_root).expanduser().resolve() if known.audit_root else Path.cwd()
    audit_root.mkdir(parents=True, exist_ok=True)

    scripts = plugin / "scripts"
    sys.path.insert(0, str(scripts))

    from agent.orchestrator import pipeline  # noqa: E402

    original = pipeline.WORKSPACE
    original_cwd = Path.cwd()

    # 切到审计根：vulngate 的 --config 是相对 CWD 解析的，
    # 而它的正常用法是"在 workspace 里跑"。不 chdir 的话
    # `--config targets/x.json` 会解析到调用者目录而报 FileNotFoundError。
    try:
        os.chdir(audit_root)
    except OSError as exc:
        print("ERROR: 无法切换到审计根 %s: %s" % (audit_root, exc), file=sys.stderr)
        return 2

    print("[vg-run] 插件      : %s" % plugin)
    print("[vg-run] WORKSPACE : %s  (插件默认值: %s)" % (audit_root, original))
    print("[vg-run] 产物将落在: %s/{state,poc,ledger,findings}/"
          % audit_root)

    try:
        # --audit-root owns the workspace; last option wins in argparse.
        rc = pipeline.main(rest + ["--workspace", str(audit_root)])
        return int(rc or 0)
    finally:
        os.chdir(original_cwd)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
