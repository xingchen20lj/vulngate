"""Coverage-driven security audit layer.

This package is a *new analysis layer* bolted onto the existing S1-S8 pipeline
rather than a rewrite of it (spec §21.3).  It answers a question the pipeline
could not previously answer:

    how much of the target's production source has actually been audited?

Design contract (spec §2.1, §21.1):

* **Discovery is unbounded, presentation is bounded.**  Every scan in here is
  full-scan.  ``max_items`` / ``max_chars`` style parameters exist only where a
  *summary* is being rendered for a prompt or a report, and they never truncate
  an index.
* **Deterministic.**  No LLM participates in building coverage numbers.  Every
  record carries ``file`` / ``line`` / ``symbol`` / ``producer`` / ``confidence``
  / ``evidence_type`` provenance (spec §21.2).

Module map:

``languages``   unified language/suffix definition + exclusion rules (§6.2/§6.3)
``models``      record dataclasses and audit-state enums (§4)
``inventory``   full source/entry/sink/control inventory + on-disk store (§3)
``coverage``    coverage metrics and the ``coverage`` CLI renderer (§5/§16)
``symbols``     symbol index (§4.2)
``callgraph``   heuristic cross-function call graph (§8)
``dataflow``    forward + backward cross-procedural flow records (§9/§10)
``controls``    security-control index + control map, Entry->Sink verdicts (§11)
``scheduler``   coverage-aware candidate scheduling (§13/§14)
``differential`` sibling/differential analysis: where a family disagrees (§12)
``capability_graph`` bounded capability-primitive composition and research paths
``semantic_paths`` bounded source-local control-order and same-symbol data-flow evidence
``semantic_guards`` bounded branch-posture and subject/object binding evidence
``semantic_calls`` bounded one-hop interprocedural argument/return evidence
``semantic_controlflow`` bounded branch-dominance and alternate-path evidence
``semantic_ast`` bounded Python-AST branch and scope evidence
"""

from __future__ import annotations

__all__ = [
    "capability_graph",
    "callgraph",
    "coverage",
    "controls",
    "dataflow",
    "differential",
    "inventory",
    "languages",
    "models",
    "scheduler",
    "semantic_guards",
    "semantic_calls",
    "semantic_controlflow",
    "semantic_ast",
    "semantic_paths",
    "symbols",
]
