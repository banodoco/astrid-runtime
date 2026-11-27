"""Stdlib-only process observations and retained native authority dispatch.

Token dictionaries are serializable observations. Native custody requires
the live object returned by retain_peer/retain_child on every backend. OS
modules are imported on use; this module never imports the Runtime application.
"""
from __future__ import annotations

import sys

LINUX = sys.platform.startswith("linux")
ROTATES_ON_EXEC = not LINUX
PRIMITIVE = "proc_signal_with_pidfd_identity" if LINUX else "proc_signal_with_audittoken"


class ProcessBindingError(RuntimeError):
    """A process observation or retained authority cannot be verified."""


class ProcessBindingUnavailable(ProcessBindingError):
    """The selected native authority is unavailable on this platform."""


def _platform() -> str:
    return sys.platform


def backend() -> str:
    value = _platform()
    if value.startswith("linux"):
        return "linux"
    return {"darwin": "darwin", "win32": "windows"}.get(value, "other")


def _linux_call(name, *args, **kwargs):
    from . import linux_process_binding
    try:
        return getattr(linux_process_binding, name)(*args, **kwargs)
    except linux_process_binding.LinuxBindingError as exc:
        raise ProcessBindingError(str(exc)) from exc


def _native_backend():
    selected = backend()
    if selected == "windows":
        from . import windows_handoff
        return windows_handoff
    if selected == "darwin":
        try:
            from . import darwin_process_binding
        except ImportError as exc:
            raise ProcessBindingUnavailable("Darwin process binding provider is unavailable") from exc
        return darwin_process_binding
    raise ProcessBindingUnavailable("process binding provider is unavailable on this OS")


def _native_call(name, *args, **kwargs):
    provider = _native_backend()
    function = getattr(provider, name, None)
    if function is None:
        raise ProcessBindingUnavailable(f"native process binding {name} is unavailable on this OS")
    try:
        return function(*args, **kwargs)
    except getattr(provider, "WindowsBindingError", ()) as exc:
        # The Windows provider also serves pre-import transport callers and
        # retains its ConflictError ABI. Normalize only its named native error.
        raise ProcessBindingError(str(exc)) from exc
    except getattr(provider, "DarwinBindingError", ()) as exc:
        # Preserve the precise native cause, including acquisition versus
        # acquired-port failure. Do not swallow unrelated RuntimeError values.
        raise ProcessBindingError(str(exc)) from exc


def supported() -> bool:
    """Probe signalling support; each channel must still establish its origin."""
    if backend() == "linux":
        return _linux_call("pidfd_available")
    return backend() in ("darwin", "windows")


def identity(pid, *, timeout=1.0):
    from . import platform
    return platform.process_identity(pid, timeout=timeout)


def birth_matches(expected, actual):
    from . import platform
    return platform.process_birth_matches(expected, actual)


def token(pid):
    if backend() == "linux":
        return _linux_call("token", pid)
    if backend() == "windows":
        from . import platform
        return platform.handoff_token(pid)
    return _native_call("token", pid)


def details(words):
    if backend() == "linux":
        return _linux_call("details", words)
    if backend() == "windows":
        from . import platform
        return platform.handoff_token_details(list(words))
    return _native_call("details", words)


def peer_token(connection):
    """Return compatible details; possession of the result grants no custody."""
    if backend() == "linux":
        return _linux_call("peer_token", connection)
    return _native_call("peer_token", connection)


def retain_peer(connection, *, expected=None):
    if backend() == "linux":
        return _linux_call("retain_peer", connection, expected=expected)
    return _native_call("retain_peer", connection, expected=expected)


def retain_child(child, *, reap_guard, expected=None):
    if backend() == "linux":
        return _linux_call("retain_child", child, reap_guard=reap_guard, expected=expected)
    return _native_call("retain_child", child, reap_guard=reap_guard, expected=expected)


def signal(words, signum, *, authority=None):
    from . import platform
    admitted = {platform.TERM, platform.KILL}
    if platform.USER1 is not None:
        admitted.add(platform.USER1)
    if isinstance(signum, bool) or not isinstance(signum, int) or signum not in admitted:
        raise ProcessBindingError("custody signal is outside the admitted set")
    if backend() == "linux":
        return _linux_call("signal", words, signum, authority=authority)
    # Other native providers must retain/check their own process reference;
    # there is deliberately no cached-PID or token-only fallback here.
    return _native_call("signal", words, signum, authority=authority)


def resume_once(authority):
    if backend() != "darwin":
        raise ProcessBindingUnavailable("one-shot resume exists only for a suspended Darwin launch")
    return _native_call("resume_once", authority)

def census():
    """Linux proc observations with explicit partial/unavailable status."""
    if not sys.platform.startswith("linux"):
        raise NotImplementedError("Linux proc census is unavailable on this OS")
    from . import linux_process_binding
    return linux_process_binding.census()


def zombie_birth(pid):
    """Observe a fully scoped Linux unreaped zombie birth, never custody."""
    if not sys.platform.startswith("linux"):
        raise NotImplementedError("Linux zombie birth is unavailable on this OS")
    from . import linux_process_binding
    return linux_process_binding.zombie_birth(pid)


def birth_ticks(pid):
    """Observe live Linux start ticks for the legacy Vibe registry only."""
    if not sys.platform.startswith("linux"):
        raise NotImplementedError("Linux start ticks are unavailable on this OS")
    from . import linux_process_binding
    return linux_process_binding.birth_ticks(pid)
