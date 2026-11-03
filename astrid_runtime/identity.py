"""Validation and comparison for the Runtime owner's captured identity."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from runtime_protocol.startup_identity import capture_startup_identity
from .owner_diagnostics import outcome, predicate_chain

IDENTITY_REFUSAL_MESSAGE = (
    "An older Astrid is still running. Restart it after its running tasks finish."
)


class StartupIdentityError(ValueError):
    """An identity is incomplete, malformed, or not bound to its live owner."""


@predicate_chain(
    "identity_object",
    "identity_fields",
    "identity_release_integer",
    "identity_release_valid",
    "identity_runtime_head",
    "identity_agent_head",
    "identity_dirty_boolean",
    "identity_dirty_hash",
    "identity_management",
)
def normalize_startup_identity(value: Any) -> dict[str, Any]:
    """Validate and return the canonical installed or source identity shape."""
    if not outcome("identity_object", isinstance(value, Mapping)):
        raise StartupIdentityError("startup identity must be an object")

    managed_by = value.get("managed_by")
    if managed_by == "source":
        expected = {"release", "managed_by", "runtime_head", "agent_head", "dirty", "dirty_hash"}
        if (
            not outcome(
                "identity_fields",
                set(value) == expected,
            )
            or not outcome(
                "identity_release_integer",
                type(value.get("release")) is int,
            )
            or not outcome("identity_release_valid", value["release"] == 0)
        ):
            raise StartupIdentityError("source startup identity has invalid fields")
        runtime_head = value.get("runtime_head")
        agent_head = value.get("agent_head")
        dirty_hash = value.get("dirty_hash")
        if not outcome(
            "identity_runtime_head",
            _valid_head(runtime_head),
        ) or not outcome("identity_agent_head", _valid_head(agent_head)):
            raise StartupIdentityError("source startup identity has invalid checkout heads")
        if not outcome("identity_dirty_boolean", type(value.get("dirty")) is bool):
            raise StartupIdentityError("source startup identity has invalid dirty state")
        if not outcome(
            "identity_dirty_hash",
            outcome(
                "identity_dirty_hash_string",
                isinstance(dirty_hash, str),
                blocked=("identity_dirty_hash_length", "identity_dirty_hash_hex"),
            )
            and outcome("identity_dirty_hash_length", len(dirty_hash) == 64, blocked=("identity_dirty_hash_hex",))
            and outcome("identity_dirty_hash_hex", _lower_hex(dirty_hash)),
        ):
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
    if not outcome("identity_fields", set(value) == expected):
        raise StartupIdentityError("installed startup identity has invalid fields")
    release = value.get("release")
    if not outcome(
        "identity_release_integer",
        type(release) is int,
    ) or not outcome("identity_release_valid", release >= 0):
        raise StartupIdentityError("installed startup identity has invalid release")
    if not outcome("identity_management", managed_by in (None, "pinokio")):
        raise StartupIdentityError("installed startup identity has invalid management mode")
    return {"release": release, "managed_by": managed_by}


def requested_startup_identity(source: Any) -> dict[str, Any]:
    """Capture the caller identity through the same env/source interface as the daemon."""
    return normalize_startup_identity(capture_startup_identity(
        runtime_checkout=Path(source.runtime_checkout),
        agent_checkout=Path(source.source_checkout),
    ))


@predicate_chain(
    "identity_health_object",
    "identity_health_instance",
    "identity_instance_present",
    "identity_wire_present",
)
def validate_live_owner_identity(
    health: Any,
    *,
    instance_id: str,
) -> dict[str, Any]:
    """Validate identity fields from canonical health and their owner binding."""
    if not outcome("identity_health_object", isinstance(health, Mapping)):
        raise StartupIdentityError("live health is unavailable")
    if not outcome(
        "identity_health_instance",
        health.get("runtime_instance_id") == instance_id,
    ) or not outcome("identity_instance_present", bool(instance_id)):
        raise StartupIdentityError("live health belongs to a different owner instance")
    # R0 attached its owner instance to health but predated startup identity
    # publication altogether.  Preserve that one predecessor wire shape only:
    # current low-level R1 health explicitly says ``identity: null`` and must
    # continue to fail closed through normalize_startup_identity.
    if not outcome("identity_wire_present", "identity" in health):
        return {"release": 0, "managed_by": None}
    return normalize_startup_identity(health.get("identity"))


def _valid_head(value: Any) -> bool:
    return (
        outcome("identity_head_string", isinstance(value, str), blocked=("identity_head_length", "identity_head_hex"))
        and outcome("identity_head_length", len(value) in (40, 64), blocked=("identity_head_hex",))
        and outcome("identity_head_hex", _lower_hex(value))
    )


def _lower_hex(value: str) -> bool:
    return all(character in "0123456789abcdef" for character in value)
