#!/usr/bin/env python3
"""Benchmark the bounded source-universe enumeration path.

Examples:
  python3 scripts/benchmark_source_inventory.py --sizes 5000 --max-seconds 30
  python3 scripts/benchmark_source_inventory.py --sizes 5000,50000,500000 \
      --generate --output benchmark-source-inventory.json

The large sizes are opt-in because creating half a million fixtures is a real
workload.  The output is JSON so CI can compare files/sec and elapsed time
without making the benchmark part of the security evidence path.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent.analysis.inventory import enumerate_source_universe  # noqa: E402


def _sizes(value: str) -> List[int]:
    result = []
    for item in str(value).split(","):
        count = int(item.strip())
        if count < 1 or count > 1_000_000:
            raise ValueError("sizes must be in [1, 1000000]")
        result.append(count)
    return sorted(set(result))


def _build_fixture(root: Path, count: int) -> int:
    """Create small Python files in a two-level layout and return bytes written."""
    total = 0
    for index in range(count):
        directory = root / ("src%03d" % (index % 256))
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / ("module_%06d.py" % index)
        content = "def value_%d():\n    return %d\n" % (index, index)
        path.write_text(content, encoding="utf-8")
        total += len(content.encode("utf-8"))
    return total


def _measure(root: Path, count: int, expected_bytes: int) -> Dict[str, Any]:
    started = time.perf_counter()
    universe = enumerate_source_universe(root, source_dirs=["."])
    elapsed = max(0.000001, time.perf_counter() - started)
    files = int(universe.scanned_files)
    bytes_seen = int((universe.enumeration or {}).get(
        "bytes_seen", expected_bytes) or 0)
    return {
        "requested_files": count,
        "scanned_files": files,
        "source_files": len(universe.records),
        "excluded_dirs": len(universe.excluded_dirs),
        "bytes_written_fixture": expected_bytes,
        "bytes_seen": bytes_seen,
        "files_per_second": round(files / elapsed, 2),
        "bytes_per_second": round(bytes_seen / elapsed, 2),
        "elapsed_seconds": round(elapsed, 4),
        "enumeration": dict(universe.enumeration),
        "cache_hit": False,
    }


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", default="5000", help="comma-separated file counts")
    parser.add_argument("--root", type=Path,
                        help="existing fixture root; without --generate only one size is allowed")
    parser.add_argument("--generate", action="store_true",
                        help="generate deterministic fixtures in a temporary directory")
    parser.add_argument("--output", type=Path, help="write JSON metrics to this path")
    parser.add_argument("--max-seconds", type=float,
                        help="fail if any requested size exceeds this elapsed time")
    args = parser.parse_args(argv)
    sizes = _sizes(args.sizes)
    if args.root is not None and len(sizes) != 1:
        parser.error("--root requires exactly one --sizes value")
    if args.root is not None and args.generate:
        parser.error("--root and --generate are mutually exclusive")

    owned = None
    try:
        if args.root is not None:
            roots = [(args.root.expanduser().resolve(), sizes[0], 0)]
        else:
            owned = tempfile.TemporaryDirectory(prefix="vulngate-source-bench-")
            roots = []
            for count in sizes:
                root = Path(owned.name) / ("fixture-%d" % count)
                root.mkdir(parents=True)
                written = _build_fixture(root, count)
                roots.append((root, count, written))
        rows = [_measure(root, count, written) for root, count, written in roots]
    finally:
        if owned is not None:
            owned.cleanup()

    payload = {
        "schema_version": "source-inventory-benchmark-v1",
        "policy": "git-index-bounded-v1",
        "results": rows,
        "threshold_seconds": args.max_seconds,
        "claim_status": "not-a-finding",
    }
    encoded = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    if args.max_seconds is not None and any(
            row["elapsed_seconds"] > args.max_seconds for row in rows):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
