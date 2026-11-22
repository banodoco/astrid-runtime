"""Neutral, process-owned local workspace runtime.

This package intentionally has no dependency on Astrid, Astrid App, or worker
checkouts.  Clients communicate through the versioned HTTP protocol.
"""

from importlib import import_module
from typing import TYPE_CHECKING

from .timeline_replay_identity import capture_replay_installation as _capture_replay_installation

_capture_replay_installation(__file__)

from .errors import RuntimeErrorBase, AuthorizationError, ConflictError, NotFoundError

if TYPE_CHECKING:
    from .service import RuntimeService
    from .daemon import RuntimeDaemon

__all__ = ["RuntimeDaemon", "RuntimeService", "RuntimeErrorBase", "AuthorizationError", "ConflictError", "NotFoundError"]


def __getattr__(name: str):
    # Native platform clients must not import the workspace storage authority.
    modules = {"RuntimeService": ".service", "RuntimeDaemon": ".daemon"}
    if name not in modules:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(modules[name], __name__), name)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(__all__))
