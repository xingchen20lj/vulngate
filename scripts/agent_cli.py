#!/usr/bin/env python3
"""Thin VulnGate CLI entrypoint.

Command implementations live under ``agent.cli``.  Keeping this file to
bootstrap/dispatch logic preserves the documented executable path while
preventing new command logic from accumulating in the repository root.
"""

from agent.cli.legacy import build_parser, main

__all__ = ["build_parser", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
