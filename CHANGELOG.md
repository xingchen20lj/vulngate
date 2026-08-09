# Changelog

All notable changes to VulnGate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-09

Initial release.

### Added

- Codex plugin manifest with `vulngate-audit` skill (S1–S8 pipeline, G0–G5 gates)
- Deterministic CLI (`agent_cli.py`): source-map, source-evidence, matrix, novelty,
  cvss, ledger, doctor
- Autonomous mode launcher (`run_pipeline.sh`) with LLM API support
- Bundled framework (`scripts/agent/`) with hard gates, precondition→CVSS
  consistency, conservative novelty judgments, and loopback-only sandboxing
- Self-contained installer (`install.sh`) for the personal marketplace
- Smoke test (`scripts/smoke_test.sh`)
