"""The fixed authoring-provider seam used by the Runtime door.

The neutral Runtime deliberately has no dependency on Agent. This module only
knows the small startup ABI; importing the selected provider is deferred until
a daemon explicitly opts into the trusted ``astrid`` profile.
"""

from __future__ import annotations

import importlib
import inspect

from .contract_metadata import SCHEMA_DIGEST
from .errors import RuntimeErrorBase, ValidationError

PROVIDER_ID = "astrid-v1"
INTERFACE_VERSION = 1
PROVIDER_FACTORY = "astrid.sdk.timeline.commit.create_runtime_commit_service"


class TimelineCommitUnavailable(RuntimeErrorBase):
    """The neutral runtime has no semantic commit provider installed."""

    code = "not_ready"
    status = 503

    def __init__(self):
        super().__init__(
            "timeline commit provider is unavailable",
            details={"reason": "runtime_unavailable"},
        )


def _synchronous_commit_signature(provider) -> bool:
    method = getattr(provider, "commit", None)
    if not callable(method) or inspect.iscoroutinefunction(method):
        return False
    try:
        signature = inspect.signature(method)
    except (TypeError, ValueError):
        return False
    parameters = tuple(signature.parameters.values())
    if len(parameters) != 2:
        return False
    return all(
        parameter.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        and parameter.default is inspect.Parameter.empty
        for parameter in parameters
    )


def validate_timeline_commit_provider(provider):
    """Validate the exact trusted ABI before authoring readiness is published."""
    if (
        type(getattr(provider, "provider_id", None)) is not str
        or provider.provider_id != PROVIDER_ID
        or type(getattr(provider, "interface_version", None)) is not int
        or provider.interface_version != INTERFACE_VERSION
        or type(getattr(provider, "contract_digest", None)) is not str
        or provider.contract_digest != SCHEMA_DIGEST
        or not _synchronous_commit_signature(provider)
    ):
        raise ValidationError("timeline commit provider interface/contract mismatch")
    return provider


def load_timeline_commit_provider(authoring_profile):
    """Load the one trusted provider, or return ``None`` for neutral startup."""
    if authoring_profile in (None, "neutral"):
        return None
    if authoring_profile != "astrid":
        raise ValueError("unsupported authoring profile")

    # Keep this import entirely behind the explicit profile choice. In
    # particular, a neutral Runtime process must not import Agent transitively.
    module = importlib.import_module("astrid.sdk.timeline.commit")
    factory = getattr(module, "create_runtime_commit_service", None)
    if not callable(factory) or inspect.iscoroutinefunction(factory):
        raise ValidationError(f"authoring provider factory is unavailable: {PROVIDER_FACTORY}")
    try:
        factory_signature = inspect.signature(factory)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"authoring provider factory signature is unavailable: {PROVIDER_FACTORY}") from exc
    if factory_signature.parameters:
        raise ValidationError("authoring provider factory must be zero-argument")
    try:
        provider = factory()
    except TypeError as exc:
        raise ValidationError("authoring provider factory must be zero-argument") from exc
    return validate_timeline_commit_provider(provider)
