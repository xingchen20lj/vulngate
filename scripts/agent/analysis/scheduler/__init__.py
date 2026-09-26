"""Compatibility package for coverage-aware candidate scheduling.

The implementation is split into intake, scoring, quota, and persistence
modules.  Public names remain available from agent.analysis.scheduler.
"""

# Re-exporting is intentional: this module preserves the historic API surface.
# ruff: noqa: F403,F405

from .common import *
from .intake import *
from .scoring import *
from .quota import *
from .persistence import *

# Historic tests and integrations used these private implementation seams for
# deterministic linkage/threshold checks; retain them while the code lives in
# the scoring phase.
from .scoring import _band, _symbols_at
