"""POSIX worker transport primitives, behind platform.py."""
from __future__ import annotations
import array
import os
import socket
import struct
import subprocess
import sys
from .errors import ConflictError
from typing import Any


def peer_token(channel):
    """Observe the native peer; a returned token does not grant custody."""
    from . import process_binding
    return process_binding.peer_token(channel)


def retain_peer(channel, *, expected=None):
    """The caller keeps and closes this native reference around its operation."""
    from . import process_binding
    return process_binding.retain_peer(channel, expected=expected)


def peer_uid(channel: socket.socket) -> int:
    """Return the kernel-authenticated UID of a connected Unix peer."""

    if channel.family != socket.AF_UNIX:
        raise ConflictError("handoff transfer channel must be a Unix socket")
    if os.name == "nt":
        raise ConflictError("handoff peer authentication is unavailable on Windows")
    getpeereid = getattr(channel, "getpeereid", None)
    if callable(getpeereid):
        try:
            uid, _ = getpeereid()
            return int(uid)
        except OSError as exc:
            raise ConflictError("cannot authenticate handoff transfer peer") from exc
    local_peercred = getattr(socket, "LOCAL_PEERCRED", None)
    if local_peercred is not None:
        # Darwin exposes struct xucred through SOL_LOCAL (numeric level 0) but
        # does not expose getpeereid(3) through every Python build.  Its first
        # two unsigned fields are the ABI version and authenticated UID.
        try:
            credentials = channel.getsockopt(
                getattr(socket, "SOL_LOCAL", 0), local_peercred, struct.calcsize("2I")
            )
            version, uid = struct.unpack("2I", credentials)
            if version != 0:
                raise ConflictError("handoff transfer peer credentials have an invalid version")
            return int(uid)
        except OSError as exc:
            raise ConflictError("cannot authenticate handoff transfer peer") from exc
    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        raise ConflictError("platform cannot authenticate handoff transfer peer")
    try:
        credentials = channel.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("3i"))
        _, uid, _ = struct.unpack("3i", credentials)
        return int(uid)
    except (OSError, struct.error) as exc:
        raise ConflictError("cannot authenticate handoff transfer peer") from exc


def peer_pid(channel: socket.socket) -> int:
    """Return the kernel-authenticated PID of a connected Unix peer."""

    if channel.family != socket.AF_UNIX:
        raise ConflictError("handoff transfer channel must be a Unix socket")
    if os.name == "nt":
        raise ConflictError("handoff peer authentication is unavailable on Windows")
    if sys.platform == "darwin":
        from .darwin_process_binding import DarwinBindingError, peer_pid as darwin_peer_pid
        try:
            return darwin_peer_pid(channel)
        except DarwinBindingError as exc:
            raise ConflictError("cannot authenticate handoff transfer peer PID") from exc
    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        raise ConflictError("platform cannot authenticate handoff transfer peer PID")
    try:
        credentials = channel.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("3i"))
        pid, _, _ = struct.unpack("3i", credentials)
        return int(pid)
    except (OSError, struct.error) as exc:
        raise ConflictError("cannot authenticate handoff transfer peer PID") from exc


def _all_rights_descriptors(ancillary: list[tuple[int, int, bytes]]) -> list[int]:
    """Extract every complete received SCM_RIGHTS integer for cleanup."""

    descriptors: list[int] = []
    itemsize = array.array("i").itemsize
    for level, kind, payload in ancillary:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            continue
        usable = len(payload) - (len(payload) % itemsize)
        if usable:
            values = array.array("i")
            values.frombytes(payload[:usable])
            descriptors.extend(values)
    return descriptors


def _received_descriptors(ancillary: list[tuple[int, int, bytes]]) -> list[int]:
    if len(ancillary) != 1:
        raise ConflictError("handoff transfer must carry one descriptor record")
    level, kind, payload = ancillary[0]
    itemsize = array.array("i").itemsize
    if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS or len(payload) % itemsize:
        raise ConflictError("handoff transfer descriptor record is invalid")
    descriptors = array.array("i")
    descriptors.frombytes(payload)
    return list(descriptors)


def send(channel, payload, descriptors=()):
    if not descriptors:
        channel.sendall(payload)
        return
    rights = array.array("i", descriptors)
    sent = channel.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes())])
    if sent <= 0:
        raise ConflictError("handoff authority transfer was incomplete")
    if sent < len(payload):
        channel.sendall(payload[sent:])


class ReceivedDescriptors(list):
    """Retain record validity until the protocol selects control or authority."""
    def __init__(self, ancillary):
        super().__init__(_all_rights_descriptors(ancillary))
        self.authority_present = bool(ancillary)
        self.record_error = None
        if ancillary:
            try:
                if _received_descriptors(ancillary) != self:
                    raise ConflictError("handoff transfer descriptor record is invalid")
            except ConflictError as exc:
                self.record_error = exc


def receive(channel, limit):
    payload, ancillary, flags, _ = channel.recvmsg(limit, socket.CMSG_SPACE(2 * array.array("i").itemsize))
    descriptors = ReceivedDescriptors(ancillary)
    try:
        if flags & getattr(socket, "MSG_CTRUNC", 0):
            raise ConflictError("handoff authority descriptors were truncated")
        if flags & getattr(socket, "MSG_TRUNC", 0):
            raise ConflictError("handoff authority frame was truncated")
        return payload, descriptors
    except BaseException:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def inspect_socket(descriptor: int, *, listener: bool) -> tuple[int, int, Any]:
    duplicate = os.dup(descriptor)
    try:
        inspected = socket.socket(fileno=duplicate)
        family = inspected.family
        kind = inspected.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        address = inspected.getsockname()
        if listener:
            try:
                accepting = inspected.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
            except OSError as exc:
                if sys.platform != "darwin":
                    raise
                # Darwin does not implement SO_ACCEPTCONN.  Observe the exact
                # descriptor's kernel LISTEN state without calling accept(2)
                # (which could consume a queued client during transfer).
                observed = subprocess.run(
                    [
                        "/usr/sbin/lsof",
                        "-a",
                        "-p",
                        str(os.getpid()),
                        "-d",
                        str(duplicate),
                        "-n",
                        "-P",
                        "-iTCP",
                        "-sTCP:LISTEN",
                        "-Ff",
                    ],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if observed.returncode not in (0, 1):
                    raise ConflictError("cannot observe inherited listener state") from exc
                accepting = int(f"f{duplicate}" in observed.stdout.splitlines())
            detail = (accepting, address)
        else:
            # A connected Unix socketpair is the only valid Worker-control
            # authority.  SO_ACCEPTCONN is unavailable for AF_UNIX on Darwin,
            # so connected-peer observation supplies the stronger role check.
            detail = (inspected.getpeername(), address)
        inspected.close()
        duplicate = -1
        return family, kind, detail
    except OSError as exc:
        raise ConflictError("handoff authority descriptor is not an observable socket") from exc
    finally:
        if duplicate >= 0:
            os.close(duplicate)


