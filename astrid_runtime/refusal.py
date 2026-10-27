"""Shared extraction of operator-facing lifecycle refusal details."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def refusal_from(exc: BaseException) -> tuple[str, Mapping[str, Any] | None]:
    """Return an exception's preferred refusal message and structured details."""
    value = getattr(exc, "details", None)
    details = value if isinstance(value, Mapping) else None
    message = (details.get("message") or details.get("headline")) if details else None
    return str(message or exc), details
