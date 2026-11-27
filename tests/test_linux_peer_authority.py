"""Linux channel origin, retained custody, refusal, and descriptor lifetime."""
from __future__ import annotations

import array
from contextlib import contextmanager
import errno
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace

import pytest

from runtime_protocol import linux_process_binding as linux
from runtime_protocol import platform, process_binding
from tests.lanes import requires_linux_tree_custody

pytestmark = [requires_linux_tree_custody, pytest.mark.needs_real_pidfd]


def _reap(child):
    if child is not None:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)


@contextmanager
def _child():
    child = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(30)"])
    try:
        yield child
    finally:
        _reap(child)


@contextmanager
def _connected_child():
    """The child creates the connection; parent retains spawn independently."""
    with tempfile.TemporaryDirectory(prefix="p38-peer-", dir="/tmp") as root:
        os.chmod(root, 0o700)
        path = root + "/s"
        child = accepted = spawned = None
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.settimeout(5)
            listener.bind(path)
            os.chmod(path, 0o600)
            listener.listen(1)
            try:
                code = """import socket, sys
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.settimeout(10)
    connection.connect(sys.argv[1])
    connection.sendall(b'ready')
    connection.recv(1)
"""
                child = subprocess.Popen([sys.executable, "-I", "-c", code, path])
                spawned = linux.retain_child(child, reap_guard=threading.RLock())
                accepted, _ = listener.accept()
                accepted.settimeout(5)
                # Readiness and all waits are bounded; no sleep establishes origin.
                ready = b""
                while len(ready) < 5:
                    part = accepted.recv(5 - len(ready))
                    if not part:
                        raise AssertionError("child closed before readiness")
                    ready += part
                assert ready == b"ready"
                yield child, accepted, spawned
            finally:
                if accepted is not None:
                    accepted.close()
                if spawned is not None:
                    spawned.close()
                _reap(child)


def _closed(fd):
    with pytest.raises(OSError) as exc:
        os.fstat(fd)
    assert exc.value.errno == errno.EBADF


class FakeConnection:
    """Only scripted credential/provenance failure paths; pidfds remain real."""
    def __init__(self, pid, uid, *, fd=None, failure=None, second=None):
        self.credentials = struct.pack("3i", pid, uid, os.getgid())
        self.second = second
        self.fd = fd
        self.failure = failure
        self.reads = 0
        self.issued = []

    def getsockopt(self, level, option, size):
        assert level == socket.SOL_SOCKET
        if option == socket.SO_PEERCRED:
            assert size == struct.calcsize("3i")
            self.reads += 1
            return self.second if self.reads > 1 and self.second is not None else self.credentials
        assert option == linux.SO_PEERPIDFD and size == struct.calcsize("i")
        if self.failure is not None:
            raise OSError(self.failure, "scripted socket option refusal")
        descriptor = os.dup(self.fd)
        self.issued.append(descriptor)
        return struct.pack("i", descriptor)


def test_socketpair_observes_its_creator_and_closes_native_reference():
    left, right = socket.socketpair()
    try:
        with linux.retain_peer(left, expected=platform.process_identity(os.getpid())) as authority:
            assert authority.token == linux.token(os.getpid())
            assert process_binding.peer_token(left) == authority.token
            if authority.authority == "pidfd":
                fd = authority._fd
                assert authority.verify() == authority.token
                assert not os.get_inheritable(fd)
            else:
                fd = None
                with pytest.raises(linux.LinuxBindingError, match="no retained native authority"):
                    authority.verify()
        authority.close()
        if fd is not None:
            _closed(fd)
        with pytest.raises(linux.LinuxBindingError, match="closed"):
            authority.verify()
    finally:
        left.close()
        right.close()


def test_child_originated_connection_matches_independently_retained_spawn():
    with _connected_child() as (child, accepted, spawned):
        with process_binding.retain_peer(accepted, expected=spawned.identity) as authority:
            assert authority.authority == "pidfd"
            assert authority.identity == spawned.identity
            assert authority.verify() == spawned.verify()
            assert authority.token == process_binding.token(child.pid)
            fd = authority._fd
        _closed(fd)


def test_child_originated_connection_rejects_expected_birth_mismatch_without_leak():
    with _connected_child() as (child, accepted, spawned):
        expected = spawned.identity
        expected["birth_id"] += ";mismatch:yes"
        before = len(os.listdir("/proc/self/fd"))
        with pytest.raises(process_binding.ProcessBindingError, match="expected incarnation"):
            process_binding.retain_peer(accepted, expected=expected)
        assert len(os.listdir("/proc/self/fd")) == before
        assert child.poll() is None


def test_inherited_parent_socketpair_cannot_authenticate_child():
    parent, inherited = socket.socketpair()
    child = None
    try:
        child = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(30)"],
                                 pass_fds=(inherited.fileno(),))
        inherited.close()
        with linux.retain_child(child, reap_guard=threading.RLock()) as spawned:
            before = len(os.listdir("/proc/self/fd"))
            with pytest.raises(linux.LinuxBindingError, match="expected incarnation"):
                linux.retain_peer(parent, expected=spawned.identity)
            assert len(os.listdir("/proc/self/fd")) == before
            with linux.retain_peer(parent) as origin:
                assert origin.token["pid"] == os.getpid()
                assert origin.token["pid"] != child.pid
                assert origin.token == linux.token(os.getpid())
    finally:
        parent.close()
        inherited.close()
        _reap(child)


def test_real_host_child_authenticates_original_runtime_parent():
    parent, inherited = socket.socketpair()
    child = None
    expected = platform.process_identity(os.getpid())
    code = """import errno, json, os, socket, sys
from runtime_protocol import process_binding
channel = socket.socket(fileno=int(sys.argv[1]))
try:
    with process_binding.retain_peer(channel, expected=json.loads(sys.argv[2])) as authority:
        token = authority.verify()
        identity = authority.identity
        descriptor = authority._fd
    try:
        os.fstat(descriptor)
    except OSError as error:
        assert error.errno == errno.EBADF
    else:
        raise AssertionError('native descriptor leaked')
    print(json.dumps({'token': token, 'identity': identity}))
finally:
    channel.close()
"""
    try:
        child = subprocess.Popen([sys.executable, "-I", "-c", code,
                                  str(inherited.fileno()), json.dumps(expected)],
                                 pass_fds=(inherited.fileno(),), stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        inherited.close()
        stdout, stderr = child.communicate(timeout=10)
        assert child.returncode == 0, stderr
        result = json.loads(stdout)
        assert result["token"] == linux.token(os.getpid())
        assert result["identity"] == {key: expected[key] for key in ("pid", "uid", "birth_id")}
        assert result["token"]["pid"] != child.pid
    finally:
        parent.close()
        inherited.close()
        _reap(child)


def test_carried_socket_refuses_exited_original_creator_even_with_replayed_observation(monkeypatch):
    control, inherited = socket.socketpair()
    child = None
    carried = []
    code = """import array, socket, sys, time
transfer = socket.socket(fileno=int(sys.argv[1]))
left, right = socket.socketpair()
transfer.sendmsg([b'r'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                         array.array('i', [left.fileno(), right.fileno()]))])
time.sleep(30)
"""
    try:
        control.settimeout(5)
        child = subprocess.Popen([sys.executable, "-I", "-c", code, str(inherited.fileno())],
                                 pass_fds=(inherited.fileno(),))
        inherited.close()
        payload, ancillary, flags, _ = control.recvmsg(1, socket.CMSG_SPACE(2 * array.array("i").itemsize))
        assert payload == b"r" and not flags & socket.MSG_CTRUNC
        descriptors = array.array("i")
        assert len(ancillary) == 1 and ancillary[0][:2] == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
        descriptors.frombytes(ancillary[0][2])
        carried = [socket.socket(fileno=fd) for fd in descriptors]
        assert len(carried) == 2
        with linux.retain_child(child, reap_guard=threading.RLock()) as spawned:
            with linux.retain_peer(carried[0], expected=spawned.identity) as authority:
                saved = linux._observe(child.pid)
                assert authority.verify()["pid"] == child.pid
                child.kill()
                child.wait(timeout=5)
                # Keep both original socket endpoints alive in this process.
                carried[0].sendall(b"x")
                carried[1].settimeout(5)
                assert carried[1].recv(1) == b"x"
                monkeypatch.setattr(linux, "_observe", lambda pid: dict(saved))
                monkeypatch.setattr(platform, "pidfd_open", lambda *a: pytest.fail("cached PID reopened"))
                with pytest.raises(linux.LinuxBindingError, match="exited|absent"):
                    authority.verify()
                with pytest.raises(linux.LinuxBindingError, match="exited|absent"):
                    linux.retain_peer(carried[0], expected=spawned.identity)
                with pytest.raises(linux.LinuxBindingError, match="exited|absent"):
                    authority.signal(platform.TERM)
    finally:
        for channel in carried:
            channel.close()
        control.close()
        inherited.close()
        _reap(child)


@pytest.mark.parametrize("failure", [errno.ENOPROTOOPT, errno.EINVAL, errno.EOPNOTSUPP])
def test_peercred_fallback_is_observation_only_and_cannot_be_promoted(monkeypatch, failure):
    with _child() as child:
        connection = FakeConnection(child.pid, os.getuid(), failure=failure)
        monkeypatch.setattr(platform, "pidfd_open", lambda *a: pytest.fail("observation promoted through PID"))
        with linux.retain_peer(connection) as authority:
            assert authority.authority == "peercred"
            assert authority.token == linux.token(child.pid)
            with pytest.raises(linux.LinuxBindingError, match="no retained native authority"):
                authority.verify()
            with pytest.raises(linux.LinuxBindingError, match="no retained native authority"):
                linux.signal(authority.token["words"], platform.TERM, authority=authority)
            assert child.poll() is None


@pytest.mark.parametrize("failure", [errno.EPERM, errno.EACCES, errno.EBADF])
def test_denied_native_peer_lookup_is_not_a_diagnostic_fallback(failure):
    connection = FakeConnection(os.getpid(), os.getuid(), failure=failure)
    with pytest.raises(linux.LinuxBindingError, match="pidfd is unavailable"):
        linux.retain_peer(connection)


def test_pidfd_for_another_process_is_refused_and_closed():
    with _child() as child:
        fd = platform.pidfd_open(os.getpid())
        connection = FakeConnection(child.pid, os.getuid(), fd=fd)
        try:
            with pytest.raises(linux.LinuxBindingError, match="names another process"):
                linux.retain_peer(connection)
            assert len(connection.issued) == 1
            _closed(connection.issued[0])
        finally:
            os.close(fd)


@pytest.mark.parametrize("mismatch", ["credentials", "uid", "birth"])
def test_capture_refusals_close_acquired_descriptors(mismatch):
    with _child() as child:
        fd = platform.pidfd_open(child.pid)
        uid = os.getuid()
        second = struct.pack("3i", child.pid, uid, os.getgid() + 1) if mismatch == "credentials" else None
        connection = FakeConnection(child.pid, uid + 1 if mismatch == "uid" else uid,
                                    fd=fd, second=second)
        expected = platform.process_identity(child.pid)
        if mismatch == "birth":
            expected["birth_id"] += ";mismatch:yes"
        try:
            with pytest.raises(linux.LinuxBindingError):
                linux.retain_peer(connection, expected=expected)
            assert len(connection.issued) == 1
            _closed(connection.issued[0])
            assert child.poll() is None
        finally:
            os.close(fd)


def test_token_snapshots_cannot_modify_a_retained_pin():
    with _child() as child:
        with linux.retain_child(child, reap_guard=threading.RLock()) as authority:
            token, identity = authority.token, authority.identity
            token["words"][4] ^= 1
            identity["birth_id"] = "forged"
            assert authority.verify() == linux.token(child.pid)
            assert authority.identity == {key: platform.process_identity(child.pid)[key]
                                          for key in ("pid", "uid", "birth_id")}


def test_default_child_authority_refuses_a_synthetic_process(monkeypatch):
    synthetic = SimpleNamespace(pid=os.getpid(), returncode=None, _waitpid_lock=threading.Lock())
    monkeypatch.setattr(platform, "pidfd_open", lambda *a: pytest.fail("synthetic child promoted"))
    with pytest.raises(process_binding.ProcessBindingError, match="retained Popen"):
        process_binding.retain_child(synthetic, reap_guard=threading.RLock())


@pytest.mark.parametrize("field", ["pid", "uid", "birth_id"])
def test_retained_identity_change_refuses_without_a_signal(monkeypatch, field):
    with _child() as child:
        with linux.retain_child(child, reap_guard=threading.RLock()) as authority:
            real_identity = platform.process_identity
            real_send = platform.pidfd_send_signal
            delivered = []
            def changed(pid, **kwargs):
                value = dict(real_identity(pid, **kwargs))
                value[field] = value[field] + 1 if field != "birth_id" else value[field] + ";mismatch:yes"
                return value
            def send(fd, signum):
                if signum:
                    delivered.append(signum)
                return real_send(fd, signum)
            monkeypatch.setattr(platform, "process_identity", changed)
            monkeypatch.setattr(platform, "pidfd_send_signal", send)
            with pytest.raises(linux.LinuxBindingError):
                authority.signal(platform.TERM)
            assert delivered == [] and child.poll() is None


def test_unsupported_signal_is_denied_before_native_action(monkeypatch):
    with _child() as child:
        with linux.retain_child(child, reap_guard=threading.RLock()) as authority:
            monkeypatch.setattr(platform, "pidfd_send_signal", lambda *a: pytest.fail("denied signal reached kernel"))
            for signum in (signal.SIGHUP, True, 0, "15"):
                with pytest.raises(linux.LinuxBindingError, match="not admitted"):
                    authority.signal(signum)
            assert child.poll() is None


def test_close_cannot_recycle_descriptor_during_authorized_signal(monkeypatch):
    with _child() as child:
        authority = linux.retain_child(child, reap_guard=threading.RLock())
        descriptor = authority._fd
        entered, release, closing, closed = (threading.Event() for _ in range(4))
        failures = []
        real_send = platform.pidfd_send_signal
        def send(fd, signum):
            if signum:
                entered.set()
                assert release.wait(5)
                os.fstat(descriptor)
            return real_send(fd, signum)
        def signal_child():
            try:
                authority.signal(platform.TERM)
            except BaseException as exc:
                failures.append(exc)
        def close():
            closing.set()
            authority.close()
            closed.set()
        monkeypatch.setattr(platform, "pidfd_send_signal", send)
        sender = threading.Thread(target=signal_child)
        closer = threading.Thread(target=close)
        try:
            sender.start()
            assert entered.wait(5)
            closer.start()
            assert closing.wait(5)
            assert not closed.wait(0.05)
        finally:
            release.set()
            sender.join(timeout=5)
            if closer.ident is not None:
                closer.join(timeout=5)
            authority.close()
        assert not sender.is_alive() and not closer.is_alive()
        assert not failures
        assert child.wait(timeout=5) == -platform.TERM
        _closed(descriptor)


def test_private_actor_keeps_native_authority_until_explicit_close():
    from astrid_runtime import custody_broker as custody
    left, right = socket.socketpair()
    before = len(os.listdir("/proc/self/fd"))
    try:
        with custody.AuthenticatedCleanupActor.private_peer(left) as actor:
            expected = actor.verify()
            assert expected["pid"] == os.getpid()
            left.close()
            assert actor.verify() == expected
        actor.close()
        with pytest.raises(custody.CustodyError):
            actor.verify()
        assert len(os.listdir("/proc/self/fd")) == before - 1
    finally:
        left.close()
        right.close()
