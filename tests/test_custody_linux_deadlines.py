from __future__ import annotations

import errno
import os
import socket
import subprocess
import sys
import threading
import time

import pytest

from astrid_runtime import custody_broker as custody
from runtime_protocol import platform, process_binding

pytestmark = pytest.mark.skipif(not process_binding.LINUX, reason="Linux custody")


@pytest.fixture
def child():
    process = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(60)"])
    try:
        yield process
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()


def test_native_publish_refuses_missing_boot_scope(tmp_path, monkeypatch, child):
    real_identity = platform.process_identity
    def without_boot(pid, **kwargs):
        identity = real_identity(pid, **kwargs)
        if identity is not None:
            identity = dict(identity)
            identity["birth_id"] = identity["birth_id"].split(";boot:")[0] + ";pidns:" + identity["birth_id"].split(";pidns:")[1]
        return identity
    monkeypatch.setattr(platform, "process_identity", without_boot)
    monkeypatch.setattr(platform, "signal_process", lambda *args: pytest.fail("fallback reached"))
    instance = custody.NativeProcessCustody(tmp_path, without_boot(child.pid))
    with pytest.raises(custody.CustodyError, match="boot_id"):
        instance.publish()
    assert not instance.path.exists()
    assert child.poll() is None


@pytest.mark.parametrize("missing", ["open", "send"])
def test_native_publish_refuses_unproven_pidfd(tmp_path, monkeypatch, child, missing):
    identity = platform.process_identity(child.pid)
    def enosys(*args):
        raise OSError(errno.ENOSYS, "unsupported")
    monkeypatch.setattr(platform, "pidfd_open" if missing == "open" else "pidfd_send_signal", enosys)
    monkeypatch.setattr(platform, "signal_process", lambda *args: pytest.fail("fallback reached"))
    instance = custody.NativeProcessCustody(tmp_path, identity)
    with pytest.raises(custody.CustodyError, match="pidfd"):
        instance.publish()
    assert not instance.path.exists()
    assert child.poll() is None


def test_native_signal_uses_pidfd_and_refuses_enosys_without_fallback(tmp_path, monkeypatch, child):
    instance = custody.NativeProcessCustody(tmp_path, platform.process_identity(child.pid))
    instance.publish()
    monkeypatch.setattr(platform, "signal_process", lambda *args: pytest.fail("fallback reached"))
    monkeypatch.setattr(platform, "_signal_checked_pid", lambda *args: pytest.fail("bare PID reached"))
    original_open = platform.pidfd_open
    def enosys(*args):
        raise OSError(errno.ENOSYS, "unsupported")
    monkeypatch.setattr(platform, "pidfd_open", enosys)
    with pytest.raises(custody.CustodyError, match="unsupported"):
        instance.signal(platform.TERM)
    assert child.poll() is None
    monkeypatch.setattr(platform, "pidfd_open", original_open)
    instance.signal(platform.TERM)
    assert child.wait(timeout=5) == -int(platform.TERM)


def test_frame_read_uses_one_deadline_for_trickled_bytes():
    reader, writer = socket.socketpair()
    reader.settimeout(0.15)
    def trickle():
        try:
            for byte in b'{"a":1}\n':
                writer.sendall(bytes([byte]))
                time.sleep(0.04)
        except OSError:
            pass
        finally:
            writer.close()
    thread = threading.Thread(target=trickle)
    thread.start()
    try:
        start = time.monotonic()
        with pytest.raises((custody.CustodyError, TimeoutError)):
            custody._read_frame(reader)
        assert time.monotonic() - start < 0.5
    finally:
        reader.close()
        thread.join()


def test_complete_frame_received_after_deadline_is_refused(monkeypatch):
    class LateSocket:
        def settimeout(self, value):
            pass
        def recv(self, count):
            return b'{}\n'
    clock = iter([0.0, 2.0])
    monkeypatch.setattr(custody.time, "monotonic", lambda: next(clock))
    with pytest.raises(custody.CustodyError, match="timed out"):
        custody._read_frame(LateSocket(), deadline=1.0)


def test_registration_expiring_during_identity_check_never_binds(tmp_path):
    scope = tmp_path / "scope"
    platform.private_directory(scope)
    def slow_identity(pid):
        time.sleep(0.25)
        return {**platform.process_identity(pid), "parent_pid": os.getpid()}
    broker = custody.RoleBoundCustodyBroker(role="host", identity_provider=slow_identity,
        ledger_root=scope / "admission", timeout=0.15)
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        peer.connect(str(broker.socket_path))
        custody._send_frame(peer, {"version": custody.PROTOCOL_VERSION, "command": "register_pre_exec",
            "run_id": broker.run_id, "role": broker.role, "pid": os.getpid(), "ppid": os.getpid(),
            "argv_digest": "sha256:" + "0" * 64})
        broker._thread.join(timeout=3)
        assert not broker._thread.is_alive()
        assert isinstance(broker.error, custody.CustodyError)
        assert "timed out" in str(broker.error)
        assert broker.registration is None
        assert broker.sequence == 0
        assert not broker.journal_path.exists()
    finally:
        peer.close()
        broker.abort_before_spawn()
