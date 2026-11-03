"""Connected Linux broker for provisional, close-only descriptor transport.

The holder owns a real TransferSession, with one frozen controller and at most
one frozen recipient. This implements transport, not arm_writer or stopped-R0
admission. A provisional recipient must not open a database or publish ready.
Native selection/containment, Agent enrollment, adoption and settlement remain
unavailable; no message in this protocol supplies those authorities.

Every attempted export permanently occupies this broker lifetime. Tombstones
and the existing session recovery ledger survive process loss; reconnect, ACK,
EOF, recipient death and changed request IDs cannot clear them. Missing ALL
local records is not recoverable authority: there is no recovery/enrollment API
here. Installation authority remains a precondition for creating a session.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import hmac
import json
import os
from pathlib import Path
import select
import stat
import time

from astrid_runtime._realm_fence import FenceUnavailable
from runtime_protocol.lifecycle_transfer_control import ProvisionalControl
from runtime_protocol import lifecycle_transfer_transport as transport

VERSION = "astrid.provisional-broker/v2"
_CONTROL_RECORD = "lifecycle-transfer-control.json"
_DELIVERY = "lifecycle-transfer-delivery.json"


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def request_binding(request):
    """Commit to all nonsecret control fields, including phase and sequence."""
    return hashlib.sha256(_encode({k: v for k, v in request.items() if k != "capability"})).hexdigest()


def _create_only(directory, name, value):
    data = _encode(value)
    if not data or len(data) > 16384:
        raise transport.TransferError("oversized broker record")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory)
    try:
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(data):
            count = os.write(fd, data[offset:])
            if count <= 0:
                raise OSError("short broker record write")
            offset += count
        os.fsync(fd)
        held = os.fstat(fd)
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (not stat.S_ISREG(held.st_mode) or held.st_uid != os.geteuid()
                or held.st_mode & 0o077 or held.st_nlink != 1
                or (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)):
            raise transport.TransferError("broker record replaced")
        os.fsync(directory)
    finally:
        os.close(fd)
    # Partial files and failed fsyncs are intentionally never removed.


class TransferBroker(ProvisionalControl):
    """Serve a controller and one separately authenticated provisional recipient.

    Recipient identity and secret are installed locally before serving, never
    nominated by a control message. They authenticate transport only. There is
    deliberately no API to arm a lifecycle writer or resolve an export.
    """

    version = VERSION

    def __init__(self, path, *, session, binding, controller, capability,
                 recipient_path, recipient, recipient_capability):
        if (type(recipient) is not transport.LinuxPeer or recipient.uid != os.geteuid()
                or type(capability) is not str or type(recipient_capability) is not str
                or len(recipient_capability) != 64
                or any(c not in "0123456789abcdef" for c in recipient_capability)
                or hmac.compare_digest(capability, recipient_capability)
                or transport.linux_peer_identity(recipient.pid) != recipient):
            raise transport.TransferError("invalid provisional recipient")
        self._recipient = recipient
        self._recipient_capability = recipient_capability
        self._recipient_listener = None
        self._spent = False
        self._delivery_request = None
        self._delivery_result = None
        self._role = binding["role"]
        super().__init__(path, session=session, binding=binding, controller=controller, capability=capability)
        try:
            directory = session._ledger_directory()
            try:
                # A re-created endpoint or new generation cannot recover this
                # initial exchange. Existing, corrupt and partial files refuse.
                for name in (_CONTROL_RECORD, _DELIVERY):
                    try:
                        os.stat(name, dir_fd=directory, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    raise transport.TransferError("recovery_required: occupied broker")
                # This local tombstone is not Agent installation enrollment.
                _create_only(directory, _CONTROL_RECORD, {
                    "version": VERSION, "operation_id": self._operation,
                    "generation": self._generation, "binding_digest": session.binding_digest,
                    "broker": asdict(transport.linux_peer_identity(os.getpid())),
                    "controller": asdict(controller), "recipient": asdict(recipient),
                })
                session._verify_ledger_directory(directory)
            finally:
                os.close(directory)
            # Any prior recovery entry also disables a fresh transport send.
            if session.query()["phase"] != "observed":
                raise transport.TransferError("recovery_required")
            self._recipient_listener = transport.PrivateListener(Path(recipient_path))
        except BaseException:
            self.close()
            raise

    def close(self):
        super().close()
        if self._recipient_listener is not None:
            self._recipient_listener.close()
            self._recipient_listener = None

    def _status(self, code="lease_uncertain"):
        return {"code": code, "stage": "provisional_delivery", "phase": "recovery_required",
                "side_effects": "uncertain", "writer_occupancy": "uncertain"}

    def _dispatch(self, request):
        self._validate(request)
        if request["action"] != "deliver-provisional":
            result = super()._dispatch(request)
            if request["action"] == "query":
                result["writer_occupancy"] = "uncertain" if self._spent else "none"
            return result
        if request["target_phase"]:
            raise transport.TransferError("invalid provisional delivery action")
        # This mutex is the existing session's custody exclusion. No SQLite
        # work fence or callback into Agent/bootstrap is held across the RPC.
        with self._session._mutex:
            self._session.pin_and_acquire_original().revalidate()
            digest = request_binding(request)
            if self._spent:
                return dict(self._delivery_result) if digest == self._delivery_request else self._status("binding_changed")
            status = self._session.query()
            if (request["expected_phase"] != "observed" or status["phase"] != "observed"
                    or request["sequence"] != len(status["requests"]) + 1
                    or any(e["request"]["request_id"] == request["request_id"] for e in status["requests"])):
                raise transport.TransferError("stale delivery request")
            # Consume before any fallible persistence, accept, receive or send.
            self._spent, self._delivery_request = True, digest
            self._delivery_result = self._status()
            try:
                directory = self._session._ledger_directory()
                try:
                    _create_only(directory, _DELIVERY, {
                        "version": VERSION, "request_digest": digest,
                        "request": {k: v for k, v in request.items() if k != "capability"},
                        "recipient": asdict(self._recipient), "role": self._role,
                        "disposition": "may_have_delivered",
                    })
                    self._session._verify_ledger_directory(directory)
                finally:
                    os.close(directory)
                self._session.require_recovery(
                    operation_id=self._operation, generation=self._generation,
                    binding_digest=self._session.binding_digest, request_id=request["request_id"],
                    expected_phase="observed", reason="lease_uncertain")
            except (OSError, FenceUnavailable, transport.TransferError):
                self._delivery_result = self._status("durability_failed")
                return dict(self._delivery_result)
            try:
                self._send_to_recipient(request, digest)
            except (OSError, ValueError, TypeError, UnicodeError, RecursionError,
                    FenceUnavailable, transport.TransferError):
                pass
            # Even successful sendmsg/receive/close acknowledgments cannot
            # establish native adoption, descendant closure or settlement.
            return dict(self._delivery_result)

    def _send_to_recipient(self, request, digest):
        listener = self._recipient_listener
        listener.check()
        while True:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise transport.TransferError("recipient deadline")
            ready, _, _ = select.select([listener, self._listener], [], [], remaining)
            if self._listener in ready:
                extra, _ = self._listener.accept()
                extra.close()
            if listener in ready:
                break
        conn, _ = listener.accept()
        with conn:
            transport.authenticate(conn, self._recipient)
            claim = self._receive(conn, listener=listener, deadline=self._deadline)
            if (type(claim["capability"]) is not str
                    or not hmac.compare_digest(claim["capability"], self._recipient_capability)
                    or request_binding(claim) != digest):
                raise transport.TransferError("recipient request differs")
            transport.authenticate(conn, self._recipient)
            self._listener.check()
            listener.check()
            self._session.pin_and_acquire_original().revalidate()
            realm = self._session._custody._realm
            # The typed transport sends the actual held open descriptions.
            # It never reopens the owner path, relocks, or retries sendmsg.
            transport.send_aliases(conn, expected_peer=self._recipient,
                deadline=self._deadline,
                capability=self._recipient_capability, binding_digest=digest,
                sequence=request["sequence"], role=self._role,
                directory_fd=realm._directory_fd, owner_fd=realm._owner_fd)


def receive_provisional(path, *, broker, request, role, expected_objects):
    """Claim close-only aliases. This is not AdoptedCustody or DB admission."""
    with transport.connect(path, broker) as conn:
        data = _encode(request)
        if len(data) > 16384:
            raise transport.TransferError("oversized recipient request")
        import struct
        conn.sendall(struct.pack("!I", len(data)) + data)
        conn.shutdown(1)
        return transport.receive_aliases(conn, expected_peer=broker,
            capability=request["capability"], binding_digest=request_binding(request),
            sequence=request["sequence"], role=role, expected_objects=expected_objects)


def run_transfer_broker(path, *, session, binding, controller, capability,
                        recipient_path, recipient, recipient_capability, stop):
    """Host the connected loop in the process retaining the original locks.

    The owner supplies secrets through private process-local storage/IPC, never
    argv or public references. Stop closes endpoints and leaves the caller's
    session and original locks held for recovery. There is no automatic release,
    restart, takeover, native verification or admission.
    """
    with TransferBroker(path, session=session, binding=binding, controller=controller,
            capability=capability, recipient_path=recipient_path, recipient=recipient,
            recipient_capability=recipient_capability) as broker:
        broker.serve_forever(stop)
