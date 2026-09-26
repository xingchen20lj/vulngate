# Known limitations

This file lists limitations that are true for the current release. Historical
review notes, including `docs/reviews/2026-09-23-development-review.zh-CN.md`, do not silently
redefine the current runtime contract.

- Runtime-lab managed services require a concrete isolation backend. Linux
  prefers bubblewrap namespaces with delegated cgroup v2; macOS requires a
  configured container or lightweight VM. A missing backend fails closed.
- An already-running external service is not sandboxed or monitored by
  VulnGate; its network and filesystem access are recorded as unknown.
- HTTP semantic predicates are bounded and run in memory. Only predicate IDs,
  results and response digests are persisted; raw response bodies are not
  evidence artifacts.
- The JVM process collector observes only an explicitly scoped lifecycle.
  Target-specific protocol state can use the `jvm-protocol` collector with a
  workspace-local JSON snapshot and allowlisted JSON-pointer paths; undeclared,
  unavailable, and stdout/stderr-only protocol state remains pending/claims.
- PoC RSS and scratch watchers remain sampled stop-losses. They are not a
  substitute for kernel-enforced limits; supported runtime-lab backends use
  cgroup/container limits where available.
- The hook is an import-trust check and policy guard, not an operating-system
  security boundary.
