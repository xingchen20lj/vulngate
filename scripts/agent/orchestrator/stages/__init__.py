"""S1→S8 stage package.

The public wrappers preserve the historic agent.orchestrator.stages import
surface while dispatching each stage to its independently testable module.
"""

from . import common as _common
from . import s1 as _s1
from . import s2 as _s2
from . import s3 as _s3
from . import s4 as _s4
from . import s5 as _s5
from . import s6 as _s6
from . import s7 as _s7
from . import s8 as _s8

# Compatibility exports used by existing integrations/tests that patch the
# historic module namespace before invoking a stage.
StageContext = _common.StageContext
JavaMatrixRunner = _common.JavaMatrixRunner
ShellMatrixRunner = _common.ShellMatrixRunner
analyze_patch_history = _common.analyze_patch_history
_coverage_scope_incomplete = _common._coverage_scope_incomplete
_derive_conclusion = _s5._derive_conclusion


def _sync_patches(module):
    for name in ("JavaMatrixRunner", "ShellMatrixRunner",
                 "analyze_patch_history"):
        setattr(module, name, globals()[name])


def run_s1(ctx):
    _sync_patches(_s1)
    return _s1.run_s1(ctx)


def run_s2(ctx):
    _sync_patches(_s2)
    return _s2.run_s2(ctx)


def run_s3(ctx):
    _sync_patches(_s3)
    return _s3.run_s3(ctx)


def run_s4(ctx):
    _sync_patches(_s4)
    return _s4.run_s4(ctx)


def run_s5(ctx):
    _sync_patches(_s5)
    return _s5.run_s5(ctx)


def run_s6(ctx, summaries, conclusions):
    _sync_patches(_s6)
    return _s6.run_s6(ctx, summaries, conclusions)


def run_s7(ctx, rows, summaries, severities):
    _sync_patches(_s7)
    return _s7.run_s7(ctx, rows, summaries, severities)


def run_s8(ctx, summaries, conclusions, novelties, severities):
    _sync_patches(_s8)
    return _s8.run_s8(ctx, summaries, conclusions, novelties, severities)


__all__ = [
    "StageContext", "run_s1", "run_s2", "run_s3", "run_s4",
    "run_s5", "run_s6", "run_s7", "run_s8",
]

