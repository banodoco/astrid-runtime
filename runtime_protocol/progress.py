"""One wire validator for renewed and terminal progress checkpoints."""
import math
from collections.abc import Mapping

from .errors import ValidationError


def normalize_progress(progress):
    if progress is None:
        return None
    if not isinstance(progress, Mapping):
        raise ValidationError("progress must be an object")
    unexpected = set(progress) - {"phase", "percent", "current", "total"}
    if unexpected:
        raise ValidationError("progress contains unsupported fields", details={"fields": sorted(unexpected)})
    normalized = {}
    if "phase" in progress:
        phase = progress["phase"]
        if not isinstance(phase, str) or not phase.strip() or len(phase) > 128:
            raise ValidationError("progress.phase must be a non-empty string of at most 128 characters")
        normalized["phase"] = phase.strip()
    for key in ("percent", "current", "total"):
        if key not in progress:
            continue
        value = progress[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
            raise ValidationError(f"progress.{key} must be a finite number")
        if key == "percent" and not 0 <= float(value) <= 100:
            raise ValidationError("progress.percent must be between 0 and 100")
        if key == "total" and float(value) < 1:
            raise ValidationError("progress.total must be at least 1")
        if key == "current" and float(value) < 0:
            raise ValidationError("progress.current must be non-negative")
        normalized[key] = value
    if not normalized:
        raise ValidationError("progress must contain phase, percent, current, or total")
    return normalized
