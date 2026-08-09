# Security Policy

VulnGate is itself a security tool. This page describes the security posture of
the plugin and how to report issues in the plugin.

## Reporting a vulnerability in VulnGate

If you find a vulnerability in the plugin itself (not in a library audited with
it), please report it privately:

- Open a **private advisory** on GitHub:
  `https://github.com/xingchen20lj/vulngate/security/advisories/new`
- Or email the maintainer (see repository metadata) with the subject
  `[VulnGate security] <short description>`.

Please include:

- Affected version
- Steps to reproduce (minimal)
- Impact assessment
- Suggested fix, if any

We aim to acknowledge reports within 5 business days and to coordinate a fix
before any public disclosure.

## Security posture of the pipeline

- **Loopback-only side effects.** PoC code that references non-loopback URLs or IPs
  is refused at compile time by the matrix runner.
- **Approval logging.** Port listeners and external network operations require
  explicit approval; every decision is recorded to an approval log.
- **Local-first findings.** Reports are generated in the local workspace and are
  never published by the pipeline.
- **Conservative novelty.** `unknown-query-failed` is a first-class verdict;
  absence of evidence is not treated as evidence of absence.
- **No credential handling.** The plugin reads API keys from the environment only
  and never logs them. GitHub tokens are read from `GITHUB_TOKEN` / `GH_TOKEN`.

## Scope

- In scope: plugin manifest, `skills/`, `scripts/`, installer, documentation.
- Out of scope: vulnerabilities in target libraries being audited (report those to
  the respective maintainers), and general Codex platform issues.
