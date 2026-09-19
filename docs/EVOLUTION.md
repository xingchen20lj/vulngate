# Feature evolution

VulnGate 1.1.0 expands the audit engine while keeping the host-agent and
deterministic-executor boundary intact.

## Analysis coverage

The engine now records the complete production-source universe, explicit skip
reasons, entries, sinks, controls, symbols, heuristic call edges and
forward/backward flow paths. Coverage is derived from durable round ledgers, so
an uncovered high-risk region remains visible until it has evidence.

Control maps judge each path against the controls expected by its sink category.
Sibling differentials compare handlers that should share a security boundary.
Both analyses produce review candidates and retain heuristic confidence labels;
they never replace source review or runtime proof.

Candidate scheduling scores the complete pool, applies category quotas, pins
runtime-backed candidates, and carries deferred work into later rounds. The
pipeline writes the schedule into the same workspace as the evidence ledger.

## Native targets

The macOS adapter turns `.app`, `.dmg` and `.pkg` bundles into an auditable
source view. It handles Mach-O metadata, Swift and Objective-C declarations,
Electron `app.asar` archives with source maps, embedded scripts and JAR views.
The native source view establishes attack surface and file locations; it does
not contain method bodies and cannot by itself establish a vulnerability.

## Operational boundaries

Use an independent `--workspace` for each audit so checkpoints and evidence do
not enter the installed plugin cache. Missing external tools are reported as
precondition gaps. Static coverage, control and differential output remains a
lead until the S1-S8 evidence gates are satisfied.

The regression suite covers the analysis indexes, scheduler, installer,
workspace isolation, native adaptation and standard Electron archive parsing.
