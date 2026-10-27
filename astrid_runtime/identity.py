"""Validation and comparison for the Runtime owner's captured identity."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from runtime_protocol.startup_identity import capture_startup_identity


IDENTITY_REFUSAL_MESSAGE = (
    "An older Astrid is still running. Restart it after its running tasks finish."
)


class StartupIdentityError(ValueError):
    """An identity is incomplete, malformed, or not bound to its live owner."""


def normalize_startup_identity(value: Any) -> dict[str, Any]:
    """Validate and return the canonical installed or source identity shape."""
    if not isinstance(value, Mapping):
        raise StartupIdentityError("startup identity must be an object")

    managed_by = value.get("managed_by")
    if managed_by == "source":
        expected = {"release", "managed_by", "runtime_head", "agent_head", "dirty", "dirty_hash"}
        if set(value) != expected or type(value.get("release")) is not int or value["release"] != 0:
            raise StartupIdentityError("source startup identity has invalid fields")
        runtime_head = value.get("runtime_head")
        agent_head = value.get("agent_head")
        dirty_hash = value.get("dirty_hash")
        if not _valid_head(runtime_head) or not _valid_head(agent_head):
            raise StartupIdentityError("source startup identity has invalid checkout heads")
        if type(value.get("dirty")) is not bool:
            raise StartupIdentityError("source startup identity has invalid dirty state")
        if not isinstance(dirty_hash, str) or len(dirty_hash) != 64 or not _lower_hex(dirty_hash):
            raise StartupIdentityError("source startup identity has an invalid dirty hash")
        return {
            "release": 0,
            "managed_by": "source",
            "runtime_head": runtime_head,
            "agent_head": agent_head,
            "dirty": value["dirty"],
            "dirty_hash": dirty_hash,
        }

    expected = {"release", "managed_by"}
    if set(value) != expected:
        raise StartupIdentityError("installed startup identity has invalid fields")
    release = value.get("release")
    if type(release) is not int or release < 0:
        raise StartupIdentityError("installed startup identity has invalid release")
    if managed_by not in (None, "pinokio"):
        raise StartupIdentityError("installed startup identity has invalid management mode")
    return {"release": release, "managed_by": managed_by}


def requested_startup_identity(source: Any) -> dict[str, Any]:
    """Capture the caller identity through the same env/source interface as the daemon."""
    return normalize_startup_identity(capture_startup_identity(
        runtime_checkout=Path(source.runtime_checkout),
        agent_checkout=Path(source.source_checkout),
    ))


def validate_live_owner_identity(
    health: Any,
    *,
    instance_id: str,
) -> dict[str, Any]:
    """Validate identity fields from canonical health and their owner binding."""
    if not isinstance(health, Mapping):
        raise StartupIdentityError("live health is unavailable")
    if health.get("runtime_instance_id") != instance_id or not instance_id:
        raise StartupIdentityError("live health belongs to a different owner instance")
    return normalize_startup_identity(health.get("identity"))


def identities_match(expected: Any, observed: Any) -> bool:
    try:
        return normalize_startup_identity(expected) == normalize_startup_identity(observed)
    except StartupIdentityError:
        return False


def _valid_head(value: Any) -> bool:
    return isinstance(value, str) and len(value) in (40, 64) and _lower_hex(value)


def _lower_hex(value: str) -> bool:
    return all(character in "0123456789abcdef" for character in value)
