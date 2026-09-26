## 7. Hard gates summary

| Gate | Check | Prevents |
|---|---|---|
| G0 | dead/unused path | claiming reachability for dead code |
| G1 | untrusted-input reachability | treating unreachable code as attack surface |
| G1b | default config vs non-default feature | hiding configuration preconditions |
| G3 | public/upstream Novelty state | unsupported 0day/novelty claims |
| G4 | runtime evidence and effect semantics | confirmation beyond observed behavior |
| G5 | CVSS ↔ precondition/effect consistency | inflated or inconsistent severity |

Fix-completeness is not a separate gate; it is a mandatory application of G1/G4 to security-fix-derived candidates.

## 8. Safety and approval model

- PoC network side effects are loopback-first (`127.0.0.1`).
- Known literal non-loopback targets, remote-execution primitives, and wildcard listeners are blocked by source screening unless the explicit authorized-staging path applies. This is not an OS sandbox; unknown dynamic network destinations remain an isolation gap.
- Public-information reads such as GitHub API queries and dependency/version retrieval are separate from PoC egress and may be allowed by policy.
- Approval/denial decisions are persisted to `state/<target>/round-NN/approval-log.jsonl`.
- Never publish findings, PoCs, or partial results automatically.

## 9. Artifacts and conventions

- Machine-readable observations drive conclusions; prose does not override them.
- Keep every matrix cell, including failures and harness errors.
- Keep every excluded candidate with its evidence and reason.
- `S3/residuals.json` is part of the S4 mandatory probe queue.
- Narrative output follows the user's language; technical originals remain unchanged.
- Novelty search terms may remain English-first when that improves public-search hit quality.
- Local report renderers should redact credentials and sensitive query parameters without changing the underlying conclusion semantics.

## 10. Troubleshooting

### Spawn/sub-agent problems

- Check heartbeat mtime, child processes, and workdir growth before declaring a stall.
- A no-heartbeat generic greeting after spawn indicates likely message-delivery failure. Retry follow-up once, then persist degraded mode if still unsuccessful.
- A known host-environment failure may allow a sub-agent to start but prevent both initial and follow-up task bodies from arriving. VulnGate cannot repair the host channel; host-sequential execution is the correct degraded mode.

### Source-map returns nothing

The default source map covers multiple languages. If an unusual layout or an overly narrow `--globs` was used, rerun with the appropriate preset/`--globs all` or perform a bounded `rg` sweep and record it in S1.

### GitHub rate limit

If S5 reports rate limiting, provide `GITHUB_TOKEN` / `GH_TOKEN` or use an authenticated `gh` session. Record query failure rather than interpreting it as no disclosure.

### No jars / build artifacts

Build the target or point the target directory at the required artifacts. For web mode, use `target_type: web-app` plus a bounded `target_url`; a jar is not required.

### PoC compile/runtime failure

Check the required JDK/runtime, module exports/opens, classpath, build tool, and environment. Persist the exact harness/runtime error and classify the cell appropriately.

## 11. Final response format

End a run with a concise summary in the user's language:

- confirmed / excluded / pending counts;
- each confirmed item's precondition tier and final CVSS;
- Novelty state and supporting query evidence;
- evidence artifact paths;
- recommended next step, such as more-version verification, private maintainer coordination, or stopping.

The detailed technical record lives in the artifacts.

---
