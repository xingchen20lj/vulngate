# Contributing to VulnGate

Thanks for considering a contribution. VulnGate is a security research tool; the
bar for changes is deliberately high because findings produced by this pipeline
may be reported to vendors or used in coordination.

## Ground rules

- **No public disclosure of findings.** PoCs, reports, and coordination messages
  stay local until the maintainer of the target library has been engaged and a
  fix is public.
- **Evidence over assertion.** Any change to the pipeline that affects conclusions
  must preserve the rule: a "confirmed" finding requires runtime PoC output.
- **Conservative novelty.** Upstream hits degrade claims. Incomplete queries must
  not be treated as authoritative.
- **No sensitive material in this repository.** Do not commit real target names,
  vendor coordination threads, disclosure drafts, or credentials.

## Development workflow

1. Fork the repository and create a feature branch.
2. Make changes; keep the plugin manifest valid:

   ```bash
   python3 scripts/validate_plugin.py .   # when the Codex plugin-creator tooling is available
   ```

3. Run the smoke test:

   ```bash
   ./scripts/smoke_test.sh
   ```

4. For installer changes, test with isolated paths:

   ```bash
   PLUGIN_HOME=/tmp/vg-home VULNGATE_MARKETPLACE=/tmp/vg-market/marketplace.json ./install.sh
   ```

5. Open a pull request describing the change and its effect on the evidence
   contract.

## Project layout

- `.codex-plugin/plugin.json` — plugin manifest
- `skills/vulngate-audit/SKILL.md` — host-agent execution manual (S1–S8, G0–G5)
- `scripts/agent_cli.py` — deterministic helper CLI
- `scripts/agent/` — bundled framework (mirrored from the parent project; keep in
  sync when framework logic changes)
- `scripts/run_pipeline.sh` — autonomous mode launcher
- `docs/` — user and architecture documentation

## Release process

- Bump the version in `.codex-plugin/plugin.json` and `CHANGELOG.md`
  (semantic versioning).
- Tag releases as `vX.Y.Z`.
- Local iteration does not require a version bump: `./install.sh` sets a
  timestamped `codex.*` cachebuster that Codex treats as a new install.
