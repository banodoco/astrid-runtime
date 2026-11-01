"""Linux provider for the platform-neutral process-binding token.

Linux has no kernel audit token, so the token is built from the exact
identity the Runtime already observes: pid, uid, /proc start ticks (birth),
and the PID namespace inode. The token is refused whenever any of those
differs from a fresh observation of the same pid, and signals go through a
pidfd opened before the identity re-check, so a reused pid cannot be hit.

Exec does not change pid or start ticks, so ROTATES_ON_EXEC is False here.
A sealed, held child is the one the parent reaps; see custody_broker
AuthenticatedCleanupActor.retained_child.

Limitation: /proc start ticks have roughly 10 ms resolution. Two live processes
always differ by pid, so a token cannot be confused across pids. The real risk
is reuse of the SAME pid within one tick. That is covered by the parent holding
the child unreaped until the broker is done (AuthenticatedCleanupActor.retained_child,
sole reaper RetainedProcess); an exited-but-unreaped child keeps its pid, and the
broker refuses it before any signal.
"""
from __future__ import annotations

import errno
import hashlib
import json
from typing import Mapping, Sequence

from . import platform

TOKEN_TAG = 0x4153544C  # "ASTL": Astrid Linux process token
PRIMITIVE = "proc_signal_with_pidfd_identity"
ROTATES_ON_EXEC = False
_WORD_LIMIT = 0xFFFFFFFF


class LinuxBindingError(RuntimeError):
    """Raised when a Linux process token cannot be proven exactly."""


def _split64(value: int) -> tuple[int, int]:
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise LinuxBindingError("linux process token field is out of range")
    return value & _WORD_LIMIT, value >> 32


def _parse_birth(birth_id: object) -> tuple[int, int]:
    """Return (start_ticks, pidns_inode) from platform.process_identity birth_id."""
    if not isinstance(birth_id, str) or not birth_id.startswith("proc-start-ticks:"):
        raise LinuxBindingError("linux process birth identity is unavailable")
    parts = birth_id.split(";")
    try:
        ticks = int(parts[0].split(":", 1)[1])
    except (IndexError, ValueError) as exc:
        raise LinuxBindingError("linux process start ticks are malformed") from exc
    namespace = 0
    for part in parts[1:]:
        if part.startswith("pidns:"):
            try:
                namespace = int(part.split(":", 1)[1])
            except ValueError as exc:
                raise LinuxBindingError("linux pid namespace is malformed") from exc
    if namespace == 0:
        raise LinuxBindingError("linux pid namespace is unavailable; refusing")
    return ticks, namespace


def _observe(pid: int) -> dict[str, object]:
    identity = platform.process_identity(pid)
    if identity is None:
        raise LinuxBindingError("linux process is absent or exited")
    if identity.get("pid") != pid:
        raise LinuxBindingError("linux process identity names another pid")
    ticks, namespace = _parse_birth(identity.get("birth_id"))
    uid = identity.get("uid")
    if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
        raise LinuxBindingError("linux process uid is malformed")
    return {"pid": pid, "uid": uid, "ticks": ticks, "namespace": namespace}


def _words(observed: Mapping[str, object]) -> list[int]:
    ticks_lo, ticks_hi = _split64(int(observed["ticks"]))
    ns_lo, ns_hi = _split64(int(observed["namespace"]))
    uid_lo, uid_hi = _split64(int(observed["uid"]))
    return [TOKEN_TAG, int(observed["pid"]), uid_lo, uid_hi, ticks_lo, ticks_hi, ns_lo, ns_hi]


def token(pid: int) -> dict[str, object]:
    """Capture the live Linux token for a pid, with its digest and birth."""
    observed = _observe(pid)
    words = _words(observed)
    return {**details(words), "words": words}


def details(words: Sequence[int]) -> dict[str, object]:
    """Public token details, with the same keys as the Darwin audit token."""
    decoded = _decode(words)
    return {key: decoded[key] for key in ("pid", "uid", "pidversion", "sha256")}


def _decode(words: Sequence[int]) -> dict[str, object]:
    """Decode and validate a Linux token; never trusts a frame's own pid."""
    if len(words) != 8 or any(isinstance(v, bool) or not isinstance(v, int) or v < 0 or v > _WORD_LIMIT for v in words):
        raise LinuxBindingError("linux process token is invalid")
    if words[0] != TOKEN_TAG:
        raise LinuxBindingError("linux process token tag is wrong")
    pid = words[1]
    uid = words[2] | (words[3] << 32)
    ticks = words[4] | (words[5] << 32)
    namespace = words[6] | (words[7] << 32)
    if pid <= 0 or namespace == 0:
        raise LinuxBindingError("linux process token has no pid or namespace")
    canonical = json.dumps(list(words), separators=(",", ":")).encode("utf-8")
    return {"pid": pid, "uid": uid, "pidversion": ticks, "namespace": namespace,
            "sha256": "sha256:" + hashlib.sha256(canonical).hexdigest()}


def _matches(words: Sequence[int]) -> dict[str, object]:
    decoded = _decode(words)
    observed = _observe(int(decoded["pid"]))
    if (observed["uid"] != decoded["uid"] or observed["ticks"] != decoded["pidversion"]
            or observed["namespace"] != decoded["namespace"]):
        raise LinuxBindingError("linux process identity changed or was reused")
    return decoded


def peer_token(connection) -> dict[str, object]:
    """Read the connected peer's pid and uid with SO_PEERCRED, before and after the /proc read."""
    import socket
    import struct

    raw_before = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, _gid = struct.unpack("3i", raw_before)
    observed = token(pid)
    raw_after = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    if raw_after != raw_before:
        raise LinuxBindingError("linux peer credentials changed during the read")
    if observed["uid"] != uid:
        raise LinuxBindingError("linux peer uid does not match its process identity")
    return observed


def signal(words: Sequence[int], signum: int) -> None:
    """Signal the exact process named by the token, or refuse without signalling."""
    decoded = _decode(words)
    pid = int(decoded["pid"])
    if signum not in (platform.TERM, platform.KILL) and signum != platform.USER1:
        raise LinuxBindingError("linux process signal is not admitted")
    try:
        fd = platform.pidfd_open(pid)
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            raise LinuxBindingError("linux process is absent") from exc
        raise
    try:
        _matches(words)
        platform.pidfd_send_signal(fd, signum)
    finally:
        import os

        os.close(fd)
