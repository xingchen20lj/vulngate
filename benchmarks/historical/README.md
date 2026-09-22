# Historical CVE Benchmark

This directory contains a small, revision-pinned research benchmark for
calibrating VulnGate's static semantic analysis. It is not a vulnerability
ledger and its output is never a finding: every result carries
`claim_status=not-a-finding`.

Each CVE case declares four independent arms:

- `vulnerable`: the affected revision; a static run may emit only a candidate;
- `fixed`: the vendor-fixed revision;
- `safe-sibling`: a nearby safe API or control path in the affected revision;
- `environment-gap`: the same mechanism with an unavailable runtime
  precondition, which must remain a typed gap rather than become `excluded`.

The case metadata records the project, CVE, exact revision commits, expected
entry/sink locations, preconditions, effect class, severity range, official
references, safe sibling, and a four-point version matrix. Raw exploit payloads
and source snippets are intentionally absent.

Manifest validation requires advisory, source, and fix references; it also
requires the vulnerable, fixed, safe-sibling, and environment-gap arms to stay
anchored to the declared vulnerable/fixed commits and to appear in the version
matrix. This prevents an apparently complete benchmark from comparing unrelated
revisions.

The sample run is a static calibration fixture. It demonstrates candidate
precision/recall, time-to-candidate, and gap preservation; it does not claim
that any CVE has been confirmed. A future runtime harness may submit a second
run against the same arm IDs, but it must preserve the S4/G4 Evidence Gate and
the `not-a-finding` status until the normal disclosure pipeline completes.
