"""Pinned Linux endpoints for the existing typed, close-only FD transport.

These are private transport objects, not native admission evidence. No endpoint
is unlinked on close: an old or replaced name requires explicit recovery.
"""
from __future__ import annotations

import os
from pathlib import Path
import socket
import stat
import time

from astrid_runtime import lifecycle_transfer_broker as _transport

LinuxPeer = _transport.LinuxPeer
TransferError = _transport.TransferError
CloseOnlyAliases = _transport.CloseOnlyAliases
linux_peer_identity = _transport.linux_peer_identity
receive_aliases = _transport.receive_aliases
authenticate = _transport._authenticate
object_id = _transport._object
ProvisionalOriginal = _transport.ProvisionalOriginal


def _identity(info):
    return info.st_dev, info.st_ino


class PrivateEndpoint:
    """Retain a no-follow parent handle and check both parent and socket IDs."""

    def __init__(self, path):
        self.path = Path(path)
        self._parent = _transport._open_root(self.path.parent)
        self._closed = False
        try:
            self._parent_id = _identity(os.fstat(self._parent))
            self._check_parent()
        except BaseException:
            os.close(self._parent)
            raise
        self._socket_id = None

    @property
    def address(self):
        # AF_UNIX has a small pathname limit. The pinned Linux handle also
        # avoids a path traversal during bind/connect, including long roots.
        return f"/proc/self/fd/{self._parent}/{self.path.name}"

    def _check_parent(self):
        held = os.fstat(self._parent)
        current = _transport._open_root(self.path.parent)
        try:
            if (_identity(held) != self._parent_id
                    or _identity(os.fstat(current)) != self._parent_id
                    or held.st_uid != os.geteuid() or held.st_mode & 0o077):
                raise TransferError("socket parent is not owner-only or changed")
        finally:
            os.close(current)

    def check(self):
        if self._closed:
            raise TransferError("endpoint closed")
        self._check_parent()
        info = os.stat(self.path.name, dir_fd=self._parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1
                or (self._socket_id is not None and _identity(info) != self._socket_id)):
            raise TransferError("socket is not owner-only or changed")
        self._socket_id = _identity(info)

    def close(self):
        if not self._closed:
            self._closed = True
            os.close(self._parent)


class PrivateListener(PrivateEndpoint):
    def __init__(self, path):
        super().__init__(path)
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self._socket.settimeout(_transport.TIMEOUT)
            self._socket.bind(self.address)
            os.chmod(self.path.name, 0o600, dir_fd=self._parent, follow_symlinks=False)
            self.check()
            self._socket.listen(1)
        except BaseException:
            self.close()
            raise

    def fileno(self):
        return self._socket.fileno()

    def accept(self):
        self.check()
        conn, address = self._socket.accept()
        try:
            self.check()
            return conn, address
        except BaseException:
            conn.close()
            raise

    def close(self):
        self._socket.close()
        super().close()


def connect(path, expected_peer):
    endpoint = PrivateEndpoint(path)
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        endpoint.check()
        conn.settimeout(_transport.TIMEOUT)
        conn.connect(endpoint.address)
        endpoint.check()
        authenticate(conn, expected_peer)
        return conn
    except BaseException:
        conn.close()
        raise
    finally:
        endpoint.close()


def listen(path):
    return PrivateListener(path)


class _DeadlineSocket:
    """Clamp the existing typed sender's timeout to the enclosing RPC budget."""
    def __init__(self, conn, deadline):
        self._conn, self._deadline = conn, deadline

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def settimeout(self, timeout):
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TransferError("transfer deadline expired")
        self._conn.settimeout(min(timeout, remaining))


def send_aliases(conn, *, deadline=None, **binding):
    if deadline is not None:
        conn = _DeadlineSocket(conn, deadline)
    return _transport.send_aliases(conn, **binding)
