"""Linux daemon-origin rendezvous for retained Runtime owner authority.

The name selects a channel, not a process capability. The connecting controller
must authenticate the original listening process using the native provider and
compare its full expected identity. No request data, bearer, or PID is trusted
by the listener; it offers no RPC and performs no action on the peer's behalf.
"""
from __future__ import annotations

import hashlib
import socket
import threading

from . import process_binding


def _address(instance_id: str) -> bytes:
    if not isinstance(instance_id, str) or not instance_id:
        raise process_binding.ProcessBindingError("native Runtime owner instance is unavailable")
    # Linux abstract names avoid Unix pathname length limits and stale files.
    # A name collision fails closed; an impostor must still pass kernel identity.
    return b"\0astrid-runtime-owner-" + hashlib.sha256(instance_id.encode("utf-8")).hexdigest().encode("ascii")


class OwnerPeerListener:
    """The Runtime owner itself creates this listener; never inherit it."""
    def __init__(self, instance_id: str):
        self._closed = threading.Event()
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self._socket.settimeout(0.2)
            self._socket.bind(_address(instance_id))
            self._socket.listen(16)
            self._thread = threading.Thread(target=self._serve, name="runtime-owner-peer", daemon=True)
            self._thread.start()
        except BaseException:
            self._socket.close()
            raise

    def _serve(self):
        while not self._closed.is_set():
            try:
                connection, _ = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            # Keep the original peer credentials on the client's socket.
            # No protocol input or server-side signalling operation exists.
            connection.close()

    def close(self):
        self._closed.set()
        self._socket.close()
        self._thread.join(timeout=1.0)
        if self._thread.is_alive():
            raise process_binding.ProcessBindingError("native Runtime owner listener did not close")


def retain_owner_peer(instance_id: str, *, expected):
    """Capture and verify the actual daemon peer before closing the transport."""
    handle = None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2.0)
            connection.connect(_address(instance_id))
            handle = process_binding.retain_peer(connection, expected=expected)
            handle.verify(expected)
        return handle
    except (OSError, process_binding.ProcessBindingError) as exc:
        if handle is not None:
            handle.close()
        raise process_binding.ProcessBindingError(
            f"native Linux Runtime owner authority unavailable: {exc}"
        ) from exc
    except BaseException:
        if handle is not None:
            handle.close()
        raise
