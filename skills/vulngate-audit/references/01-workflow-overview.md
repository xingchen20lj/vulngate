# Workflow overview

## 6. Workflow S1→S8

Persist artifacts under:

```text
state/<target>/round-NN/...
ledger/<target>/round-NN/...
reports/<target>/round-NN/...
```

Run stages in order unless a hard gate or explicit scope rule ends a candidate.
