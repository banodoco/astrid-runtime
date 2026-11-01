"""Runtime-owned context for the admitted render-observation path.

The descriptor is minted by the retained Runtime host launcher.  It is never
read from a task, profile overlay, or ambient ``ASTRID_*`` environment value.
The installed host is the only child that receives the write end; its admitted
render action is responsible for forwarding that exact descriptor to the real
renderer.
"""
from __future__ import annotations

import os
import re

from .errors import ConflictError


TIMELINE_OBSERVER_FD_ENV = "ASTRID_TIMELINE_OBSERVER_FD"
RUN_ID_RE = re.compile(r"[0-9a-f]{32}\Z")


def admitted_run_id(task_run_id, run_id) -> str:
    """Return only the Runtime-owned run identity for an admitted action."""
    if type(run_id) is not str or RUN_ID_RE.fullmatch(run_id) is None:
        raise ConflictError("admitted render run_id is missing or invalid")
    if task_run_id != run_id:
        raise ConflictError("admitted render run_id disagrees with task ownership")
    return run_id


def open_host_observer() -> tuple[int, int]:
    """Create a nonblocking Runtime-retained FIFO and host-only write end."""
    if os.name == "nt":
        raise ConflictError("render observer descriptor transport is unavailable on Windows")
    flags = os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        read_fd, write_fd = os.pipe2(flags)
    except AttributeError:
        read_fd, write_fd = os.pipe()
        for descriptor in (read_fd, write_fd):
            os.set_blocking(descriptor, False)
            os.set_inheritable(descriptor, False)
    return read_fd, write_fd


def close_observer(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass
