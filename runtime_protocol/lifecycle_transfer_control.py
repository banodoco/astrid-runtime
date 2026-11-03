"""Refusal-only Linux control endpoint for a live provisional transfer session.

This is an internal, provisional control protocol, not the proposed native
wire contract. It cannot arm or deliver a writer. The owner must keep the
session alive until recovery; socket loss is not evidence of native closure.
"""
from __future__ import annotations

import array
import hashlib
import hmac
import json
import os
from pathlib import Path
import select
import socket
import struct
import threading
import time
import weakref

from astrid_runtime._realm_fence import FenceUnavailable
from astrid_runtime import lifecycle_transfer_broker as transport
from runtime_protocol.lifecycle_transfer_transport import PrivateListener

_VERSION = "astrid.provisional-control/v1"
_MAX = 16 * 1024
_TIMEOUT = 10.0
_FIELDS = {"version", "capability", "operation_id", "generation", "binding_digest",
           "request_id", "expected_phase", "sequence", "action", "target_phase"}
_CONTROLS = weakref.WeakKeyDictionary()
_CONTROLS_LOCK = threading.Lock()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _close_rights(ancillary):
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            fds = array.array("i")
            fds.frombytes(data[:len(data) - len(data) % fds.itemsize])
            for fd in fds:
                os.close(fd)


class ProvisionalControl:
    """Own one endpoint and serve one authenticated request per connection.

    The session is created and retained in this process. No wire input can
    establish admission or supply native evidence; writer requests are recorded
    as refusals by the existing durable session ledger.
    """

    version = _VERSION
    fields = _FIELDS

    def __init__(self, path, *, session, binding, controller, capability):
        if (not transport._hex(capability) or controller.uid != os.geteuid()
                or type(binding) is not dict):
            raise transport.TransferError("invalid control binding")
        try:
            raw = json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            identity = binding["controller"]
            if (hashlib.sha256(raw).hexdigest() != session.binding_digest
                    or identity != {"pid": controller.pid, "uid": controller.uid, "birth": controller.birth}):
                raise transport.TransferError("control binding differs")
            self._operation = binding["operation_id"]
            self._generation = binding["generation"]
        except (KeyError, TypeError, ValueError) as exc:
            raise transport.TransferError("invalid control binding") from exc
        self._session = session
        self._controller = controller
        self._capability = capability
        self._pid = os.getpid()
        self._serving = threading.Lock()
        self._listener = None
        self._unavailable = False
        # Acquire the actual provisional locks before advertising the endpoint.
        # This does not admit a stopped owner or authorize a writer.
        session.pin_and_acquire_original().revalidate()
        with _CONTROLS_LOCK:
            if session in _CONTROLS:
                raise transport.TransferError("controller already bound to session")
            # Never let close/disconnect create a new controller lifetime.
            _CONTROLS[session] = True
        self._listener = PrivateListener(Path(path))

    def close(self):
        if os.getpid() != self._pid:
            raise transport.TransferError("control belongs to another process")
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        # Do not close the session: its owner controls custody and recovery.
        # Do not unlink a pathname that may have been replaced.

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def serve_once(self, *, timeout=_TIMEOUT):
        """Serve at most one connection. Concurrent connections are rejected."""
        if not self._serving.acquire(blocking=False):
            raise transport.TransferError("controller already active")
        try:
            return self._serve_once(timeout)
        finally:
            self._serving.release()

    def serve_forever(self, stop):
        """Run in the custody-holder process until its owner requests a stop.

        Peer errors never terminate custody. Stopping this loop closes no locks
        and is not a release, detach, or terminal lifecycle decision.
        """
        while not stop.is_set():
            if self._unavailable:
                stop.wait(0.1)
                continue
            try:
                self.serve_once(timeout=0.1)
            except (OSError, ValueError, FenceUnavailable, transport.TransferError):
                # A replaced endpoint must not unwind the holder's session and
                # close its original locks. Keep custody for explicit recovery.
                self._unavailable = True

    def _serve_once(self, timeout):
        if os.getpid() != self._pid or self._listener is None:
            raise transport.TransferError("control unavailable")
        self._listener.check()
        ready, _, _ = select.select([self._listener], [], [], timeout)
        if not ready:
            return False
        conn, _ = self._listener.accept()
        try:
            self._deadline = time.monotonic() + _TIMEOUT
            transport._authenticate(conn, self._controller)
            request = self._receive(conn, deadline=self._deadline)
            transport._authenticate(conn, self._controller)
            result = self._dispatch(request)
            data = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            if len(data) > _MAX:
                raise transport.TransferError("control reply too large")
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise transport.TransferError("control deadline")
            conn.settimeout(remaining)
            conn.sendall(struct.pack("!I", len(data)) + data)
        except (OSError, ValueError, TypeError, UnicodeError, RecursionError,
                FenceUnavailable, transport.TransferError):
            # Invalid, disconnected and uncertain requests get no positive reply.
            pass
        finally:
            conn.close()
        return True

    def _receive(self, conn, *, listener=None, deadline=None):
        data = bytearray()
        deadline = time.monotonic() + _TIMEOUT if deadline is None else deadline
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise transport.TransferError("control deadline")
            active = self._listener if listener is None else listener
            readable, _, _ = select.select([active, conn], [], [], remaining)
            if not readable:
                raise transport.TransferError("control deadline")
            if active in readable:
                extra, _ = active.accept()
                extra.close()
            if conn not in readable:
                continue
            chunk, ancillary, flags, _ = conn.recvmsg(_MAX + 5 - len(data), socket.CMSG_SPACE(16 * array.array("i").itemsize), getattr(socket, "MSG_CMSG_CLOEXEC", 0))
            _close_rights(ancillary)
            if ancillary or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC):
                raise transport.TransferError("unexpected ancillary data")
            data.extend(chunk)
            if len(data) > _MAX + 4:
                raise transport.TransferError("oversized control frame")
            if len(data) >= 4:
                size = struct.unpack("!I", data[:4])[0]
                if size == 0 or size > _MAX or len(data) > size + 4:
                    raise transport.TransferError("invalid control frame")
            if not chunk:
                break
        if len(data) < 5 or struct.unpack("!I", data[:4])[0] != len(data) - 4:
            raise transport.TransferError("incomplete control frame")
        value = json.loads(data[4:].decode("utf-8"), object_pairs_hook=_unique)
        if type(value) is not dict or set(value) != self.fields:
            raise transport.TransferError("invalid control fields")
        return value

    def _validate(self, req):
        if (req["version"] != self.version or not transport._hex(req["capability"])
                or not hmac.compare_digest(req["capability"], self._capability)
                or req["operation_id"] != self._operation or req["generation"] != self._generation
                or req["binding_digest"] != self._session.binding_digest
                or type(req["sequence"]) is not int or req["sequence"] < 1
                or type(req["request_id"]) is not str or not 0 < len(req["request_id"]) <= 256
                or type(req["action"]) is not str
                or type(req["expected_phase"]) is not str or not 0 < len(req["expected_phase"]) <= 256
                or type(req["target_phase"]) is not str or len(req["target_phase"]) > 256):
            raise transport.TransferError("control binding differs")

    def _dispatch(self, req):
        self._validate(req)
        self._session.pin_and_acquire_original().revalidate()
        status = self._session.query()
        if req["action"] == "query":
            if req["target_phase"] != "" or req["expected_phase"] != status["phase"] or req["sequence"] != len(status["requests"]) + 1:
                raise transport.TransferError("stale query")
            return {"code": "observed", "phase": status["phase"], "request_count": len(status["requests"])}
        if req["action"] != "transition" or not req["target_phase"]:
            raise transport.TransferError("unsupported control action")
        previous = next((index for index, item in enumerate(status["requests"], 1)
                         if item["request"]["request_id"] == req["request_id"]), None)
        if req["sequence"] != (previous if previous is not None else len(status["requests"]) + 1):
            raise transport.TransferError("stale sequence")
        return self._session.request_transition(operation_id=req["operation_id"], generation=req["generation"],
            request_id=req["request_id"], expected_phase=req["expected_phase"],
            binding_digest=req["binding_digest"], target_phase=req["target_phase"])
