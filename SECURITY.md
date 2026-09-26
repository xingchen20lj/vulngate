# Security Policy

**Language:** English | [简体中文](SECURITY.zh-CN.md)

VulnGate is itself a security tool. This page describes the security posture of
the plugin and how to report issues in the plugin.

## Reporting a vulnerability in VulnGate

If you find a vulnerability in the plugin itself (not in a library audited with
it), please report it privately:

- Open a **private advisory** on GitHub:
  `https://github.com/Zer0Gate/vulngate/security/advisories/new`
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

- **PoC isolation is platform-specific.** On supported macOS hosts, shell and
  Java PoC commands require a successful Seatbelt preflight. Network access is
  denied by default; supported HTTP cells are limited to their observer port.
  Source-level egress screening is supplemental and is not an execution sandbox.
- **Filesystem and resource limits have stated bounds.** PoC reads use a
  default-deny Seatbelt policy on supported macOS hosts. POSIX process limits
  are per process; RSS and scratch-size watchdogs are sampled best-effort
  stop-losses, not hard aggregate quotas. Unsupported isolation fails closed.
- **Managed runtime-lab services have an explicit backend boundary.** Linux uses
  a namespace/container backend with cgroup-v2 where available; macOS requires
  a configured container/lightweight-VM backend. A repository boolean such as
  `allow_unconfined_start: true` is never sufficient. A one-time operator
  approval bound to `run_id + config_digest + expiry` must be consumed before
  launch; missing backend or approval fails closed.
- **Evidence must be independently observed.** PoC stdout/stderr markers are
  untrusted claims. The bundled HTTP observer captures response metadata, but
  other effects need a matching observer. A missing observer or failed run is
  inconclusive, not evidence that a candidate is harmless.
- **Audit deadlines are operational guardrails.** The 90-minute round budget,
  `audit-exec` wrapper, and trusted Codex hook cover integrated paths only; they
  do not preempt host-model reasoning or every specialized tool path. The hook
  is not an operating-system security boundary.
- **Approval logging and local reports.** Scope-sensitive operations are
  recorded, and findings are generated locally rather than published by the
  pipeline.
- **Conservative novelty.** `unknown-query-failed` is a first-class verdict;
  absence of evidence is not treated as evidence of absence.
- **Credential handling.** API keys are read from the environment and must not
  be written to audit artifacts. GitHub tokens may be read from
  `GITHUB_TOKEN` / `GH_TOKEN` for public-information queries.

## Scope

- In scope: plugin manifest, `skills/`, `scripts/`, installer, documentation.
- Out of scope: vulnerabilities in target libraries being audited (report those to
  the respective maintainers), and general Codex platform issues.
