"""The one place that chooses a process-binding provider by operating system.

custody_broker asks LINUX only; Darwin and Windows keep their existing code paths
there, unchanged. Linux identity is pid + uid + /proc start ticks + PID namespace,
signalled through a pidfd (see linux_process_binding). ROTATES_ON_EXEC is False
on Linux: exec keeps pid and start ticks, so the post-exec wait is not needed.
"""
from __future__ import annotations

import sys

from . import linux_process_binding

LINUX = sys.platform.startswith("linux")
ROTATES_ON_EXEC = not LINUX
PRIMITIVE = linux_process_binding.PRIMITIVE if LINUX else "proc_signal_with_audittoken"


def supported() -> bool:
    """Linux custody needs proven pidfd signalling (no ENOSYS fallback); Darwin and Windows unchanged."""
    if LINUX:
        return linux_process_binding.pidfd_available()
    return sys.platform in ("darwin", "win32")
