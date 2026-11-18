"""The Runtime's one implementation of the occurrence window rule (`source_offset` = window origin).

An occurrence shows the window [offset, offset + length] of its shot's internal timeline, starting at its
placement; a child at internal time tau appears at `start - offset + tau` and is visible only inside the window.
Every Runtime reader asks this module. It is pinned to the Agent's astrid/core/timeline/occurrence_window.py and the
App's occurrenceWindow.ts by the shared conformance fixture (tests/fixtures/occurrence-window/).
"""
from __future__ import annotations

import math
from collections.abc import Mapping

from .errors import ValidationError

_EPS = 1e-6


def source_offset(value) -> float:
    """The offset in the stored unit (absent/None is 0; a {start, end} mapping reads `start`). Raises
    ValidationError when it is not a finite number >= 0; a valid offset is never clamped."""
    if isinstance(value, Mapping):
        value = value.get("start", value.get("start_ms", 0))
    if value is None:
        return 0.0
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValidationError("occurrence source_offset must be a finite number")
    if value < 0:
        raise ValidationError("occurrence source_offset must not be negative")
    return float(value)


def visible_span(start, end, offset, length):
    """A child span [start, end] cut to the window [offset, offset + length], in any one unit; None when none shows."""
    low, high = max(start, offset), min(end, offset + length)
    return (low, high) if high > low + _EPS else None
