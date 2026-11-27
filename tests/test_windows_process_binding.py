"""Retained Windows authority: portable refusal tests and real native lifetimes.

Portable injections exercise ordering only. The registered Windows nodes below
must execute on Windows before this backend can be qualified.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from runtime_protocol import platform, windows_handoff as windows
from tests.lanes import requires_windows_process_and_lock_apis


PEER = {"pid": 52, "uid": 17, "birth_id": "windows-creation:123456789"}


class Channel:
    family = socket.AF_INET

    def __init__(self):
        self.closed = False
        self.local = ("127.0.0.1", 3141)
        self.remote = ("127.0.0.1", 2718)

    def fileno(self): return -1 if self.closed else 901
    def getsockname(self): return self.local
    def getpeername(self): return self.remote
    def set_inheritable(self, value): pass
    def close(self): self.closed = True


@pytest.fixture
def handles(monkeypatch):
    state = SimpleNamespace(handles={}, opened=[], closed=[], duplicated=[], terminated=[],
                            next_handle=100, observed=dict(PEER), alive=True,
                            access=windows._ACTION_ACCESS, tcp_pid=PEER["pid"])
    def allocate(pid, access):
        state.next_handle += 1
        handle = state.next_handle
        state.handles[handle] = (pid, access)
        return handle
    def opened(pid):
        state.opened.append(pid)
        return allocate(pid, state.access), state.access
    def duplicate(handle, *, access=None):
        pid, original_access = state.handles[handle]
        assert access is None or access & original_access == access
        state.duplicated.append((handle, access))
        return allocate(pid, original_access if access is None else access)
    def close(handle):
        assert handle in state.handles, "handle closed twice"
        del state.handles[handle]
        state.closed.append(handle)
    def read(handle):
        assert handle in state.handles, "verified a closed handle"
        if not state.alive:
            raise windows.WindowsBindingError("Windows retained process owner exited")
        return dict(state.observed)
    def terminate(handle):
        assert handle in state.handles, "acted through a closed handle"
        assert state.handles[handle][1] & windows._TERMINATE
        state.terminated.append(handle)
    monkeypatch.setattr(windows, "_open_process", opened)
    monkeypatch.setattr(windows, "_duplicate_process", duplicate)
    monkeypatch.setattr(windows, "_close_process", close)
    monkeypatch.setattr(windows, "_handle_identity", read)
    monkeypatch.setattr(windows, "_terminate_process", terminate)
    monkeypatch.setattr(windows, "tcp_peer_pid", lambda channel: state.tcp_pid)
    monkeypatch.setattr(platform, "current_user", lambda: PEER["uid"])
    monkeypatch.setattr(platform, "process_identity", lambda *args, **kwargs: pytest.fail("retained authority reopened PID"))
    monkeypatch.setattr(platform, "handoff_token", lambda *args: pytest.fail("retained authority reopened token PID"))
    yield state
    for peer, _ in list(windows._pins.values()):
        if peer._handle in state.handles:
            peer.close()
    assert not state.handles, "retained native handle leaked"


def test_windows_retained_handle_survives_transport_close_without_reopening(handles):
    channel = Channel()
    assert windows.pin_peer(channel, PEER) == PEER
    pin = windows._pins[channel][0]
    with windows.retain_peer(channel, expected=PEER) as retained:
        assert retained._handle != pin._handle
        assert handles.duplicated == [(pin._handle, None)]
        captured = retained._handle
        windows._close_channel(channel)
        assert channel.closed and pin._handle is None
        assert retained.verify()["pid"] == PEER["pid"]
        windows.signal(retained.token["words"], platform.TERM, authority=retained)
        assert handles.terminated == [captured]
        assert handles.opened == [PEER["pid"]]
    retained.close()
    assert handles.closed.count(captured) == 1
    with pytest.raises(windows.WindowsBindingError, match="closed"):
        retained.verify()


def test_windows_retained_snapshots_cannot_change_authority(handles):
    channel = Channel()
    windows.pin_peer(channel, PEER)
    with windows.retain_peer(channel) as retained:
        observed, token = retained.identity, retained.token
        observed["pid"] = 999
        token["words"][1] = 999
        assert retained.identity == PEER and retained.verify()["pid"] == PEER["pid"]
        assert retained.authority == "windows-process-handle"
        with pytest.raises(windows.WindowsBindingError, match="differs"):
            windows.signal(token["words"], platform.KILL, authority=retained)
        assert not handles.terminated


@pytest.mark.parametrize("change", ["pid", "uid", "birth", "exit", "endpoint", "tcp_pid"])
def test_windows_original_pin_refuses_replaced_or_exited_owner(handles, change):
    channel = Channel()
    windows.pin_peer(channel, PEER)
    if change == "pid": handles.observed["pid"] += 1
    if change == "uid": handles.observed["uid"] += 1
    if change == "birth": handles.observed["birth_id"] = "windows-creation:999"
    if change == "exit": handles.alive = False
    if change == "endpoint": channel.remote = ("127.0.0.1", 2719)
    if change == "tcp_pid": handles.tcp_pid += 1
    with pytest.raises(windows.WindowsBindingError):
        windows.retain_peer(channel)
    with pytest.raises(windows.WindowsBindingError):
        windows.pin_peer(channel, PEER)  # Must not discard the old pin and reopen.
    assert handles.opened == [PEER["pid"]] and not handles.terminated


def test_windows_read_only_pin_cannot_upgrade_or_terminate(handles):
    handles.access = windows._OBSERVE_ACCESS
    channel = Channel()
    windows.pin_peer(channel, PEER)
    with windows.retain_peer(channel) as retained:
        assert retained.access == windows._OBSERVE_ACCESS
        assert retained.verify()["pid"] == PEER["pid"]
        with pytest.raises(windows.WindowsBindingError, match="no termination access"):
            retained.signal(platform.KILL)
    assert handles.duplicated[0][1] is None
    assert handles.opened == [PEER["pid"]] and not handles.terminated


@pytest.mark.parametrize("signum", [0, False, True, -1, 2, 10])
def test_windows_unsupported_signals_do_not_act(handles, signum):
    channel = Channel()
    windows.pin_peer(channel, PEER)
    with windows.retain_peer(channel) as retained:
        with pytest.raises(windows.WindowsBindingError, match="outside the admitted set"):
            retained.signal(signum)
        with pytest.raises(windows.WindowsBindingError, match="outside the admitted set"):
            windows.signal(retained.token["words"], signum, authority=retained)
    assert not handles.terminated


def test_windows_unbound_socket_token_or_popen_shaped_object_has_no_authority(handles):
    with pytest.raises(windows.WindowsBindingError, match="no retained process authority"):
        windows.retain_peer(Channel(), expected=PEER)
    with pytest.raises(windows.WindowsBindingError, match="requires retained native authority"):
        windows.signal(windows._identity_token(PEER)["words"], platform.TERM)
    with pytest.raises(windows.WindowsBindingError, match="retained Popen"):
        windows.retain_child(SimpleNamespace(pid=52, _handle=100), reap_guard=threading.RLock())
    assert not handles.opened and not handles.terminated


def test_windows_failed_capture_closes_native_handle(handles):
    handles.observed["birth_id"] = "windows-creation:999"
    with pytest.raises(windows.WindowsBindingError, match="incarnation"):
        windows.pin_peer(Channel(), PEER)
    assert len(handles.closed) == 1 and not handles.handles


def test_windows_failed_context_entry_closes_retained_handle(handles):
    channel = Channel()
    windows.pin_peer(channel, PEER)
    retained = windows.retain_peer(channel)
    captured = retained._handle
    handles.alive = False
    with pytest.raises(windows.WindowsBindingError, match="exited"):
        with retained:
            pytest.fail("exited owner entered custody context")
    assert retained._handle is None and handles.closed.count(captured) == 1


def test_windows_close_is_serialized_with_verification_and_termination(handles, monkeypatch):
    channel = Channel()
    windows.pin_peer(channel, PEER)
    retained = windows.retain_peer(channel)
    captured = retained._handle
    entered, release, closed = threading.Event(), threading.Event(), threading.Event()
    errors = []
    def terminate(handle):
        assert handle == captured and handle in handles.handles
        entered.set()
        assert release.wait(5)
        assert handle in handles.handles
        handles.terminated.append(handle)
    monkeypatch.setattr(windows, "_terminate_process", terminate)
    def signal():
        try: retained.signal(platform.TERM)
        except BaseException as exc: errors.append(exc)
    def close():
        try: retained.close()
        except BaseException as exc: errors.append(exc)
        finally: closed.set()
    actor, closer = threading.Thread(target=signal), threading.Thread(target=close)
    try:
        actor.start()
        assert entered.wait(5)
        closer.start()
        assert not closed.wait(0.05)
        assert captured in handles.handles
    finally:
        release.set()
        actor.join(5)
        if closer.ident is not None: closer.join(5)
        retained.close()
    assert not actor.is_alive() and not closer.is_alive() and not errors
    assert handles.terminated == [captured] and handles.closed.count(captured) == 1


@pytest.mark.parametrize("failure", [None, "exit", "endpoint", "unbound", "construct", "inherit"])
def test_windows_inherited_adoption_uses_original_handle_and_releases_it(handles, monkeypatch, failure):
    bootstrap = Channel()
    windows.pin_peer(bootstrap, PEER)
    original = windows.retain_peer(bootstrap)
    original_handle = original._handle
    windows._close_channel(bootstrap)
    inherited = Channel()
    monkeypatch.setattr(windows.socket, "socket", lambda *, fileno: inherited)
    def fail(*args, **kwargs):
        raise OSError("native socket failure")
    if failure == "construct": monkeypatch.setattr(windows.socket, "socket", fail)
    if failure == "inherit": inherited.set_inheritable = fail
    monkeypatch.setattr(windows, "_inherited_peer", None if failure == "unbound" else original)
    monkeypatch.setattr(windows, "_inherited_owner", dict(PEER))
    endpoint = (inherited.local, inherited.remote)
    monkeypatch.setattr(windows, "_inherited_sockets", {901: endpoint if failure != "endpoint" else ()})
    if failure == "exit": handles.alive = False
    try:
        if failure is None:
            assert windows.adopt_socket(901) is inherited
            assert windows.verify_peer(inherited) == PEER
        else:
            error = OSError if failure in ("construct", "inherit") else windows.ConflictError
            with pytest.raises(error):
                windows.adopt_socket(901)
            assert inherited.closed == (failure != "construct")
        assert windows._inherited_peer is None and not windows._inherited_sockets
        if failure != "unbound": assert original_handle in handles.closed
        assert handles.opened == [PEER["pid"]]
    finally:
        original.close()
        windows._close_channel(inherited)


def test_windows_failed_worker_module_entry_releases_pending_owner_handle(handles, monkeypatch):
    bootstrap, inherited = Channel(), Channel()
    bootstrap.sendall = lambda data: None
    inherited.detach = lambda: 901
    windows.pin_peer(bootstrap, PEER)
    monkeypatch.setattr(windows, "connect", lambda *args, **kwargs: bootstrap)
    monkeypatch.setattr(windows.socket, "socket", lambda *, fileno: inherited)
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace())
    monkeypatch.setattr(os, "set_handle_inheritable", lambda *args: None, raising=False)
    monkeypatch.setattr(windows, "_inherited_peer", None)
    monkeypatch.setattr(windows, "_inherited_owner", None)
    monkeypatch.setattr(windows, "_inherited_sockets", {})
    monkeypatch.setenv("ASTRID_RUNTIME_WORKER_BOOTSTRAP", json.dumps({
        "endpoint": "fixture", "files": {}, "sockets": [901], "argv": [],
    }))
    def fail(argv):
        assert windows._inherited_peer is not None and 901 in windows._inherited_sockets
        raise RuntimeError("worker entry failed")
    monkeypatch.setattr(windows, "enter_module", fail)
    with pytest.raises(RuntimeError, match="worker entry failed"):
        windows.run_worker()
    assert bootstrap.closed and not handles.handles
    assert windows._inherited_peer is None and not windows._inherited_sockets


def _native_process(command="import time; time.sleep(60)", *arguments):
    return subprocess.Popen([windows.python_executable(sys.executable), "-u", "-c", command, *arguments],
                            cwd=Path(__file__).resolve().parents[1],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)


def _reap(child):
    if child.poll() is None:
        child.kill()
    child.communicate(timeout=10)


@pytest.fixture
def native_child():
    child = _native_process()
    try:
        yield child
    finally:
        _reap(child)


_CONNECTING_CHILD = r'''
import struct, sys, time
from runtime_protocol import windows_handoff as windows
channel = windows.connect(sys.argv[1], timeout=10)
try:
    channel.sendall(b"R")
    command = channel.recv(1)
    if command == b"S":
        shared = channel.share(int(sys.argv[2]))
        channel.sendall(struct.pack("!I", len(shared)) + shared)
        channel.recv(1)
    elif not command:
        # Closing the transport must not revoke a separately retained process
        # handle. Stay alive so the parent can prove allowed action afterward.
        time.sleep(60)
finally:
    channel.close()
'''


@pytest.fixture
def native_channel():
    listener = windows.Listener(timeout=10)
    child = channel = None
    try:
        child = _native_process(_CONNECTING_CHILD, listener.endpoint, str(os.getpid()))
        expected = platform.handoff_child_identity(child)
        channel = listener.accept(expected)
        assert windows.read_exact(channel, 1, deadline=time.monotonic() + 10) == b"R"
        yield channel, child, windows.identity(expected)
    finally:
        if channel is not None: channel.close()
        listener.close()
        if child is not None: _reap(child)


def _no_reopen(monkeypatch):
    monkeypatch.setattr(windows, "_open_process", lambda pid: pytest.fail("retained operation opened PID"))
    monkeypatch.setattr(platform, "process_identity", lambda *args, **kwargs: pytest.fail("retained operation observed PID"))
    monkeypatch.setattr(platform, "handoff_token", lambda *args: pytest.fail("retained operation reopened token"))


@requires_windows_process_and_lock_apis
def test_windows_native_self_and_child_birth_match_captured_handles(native_child, monkeypatch):
    observed_self = windows.identity(platform.process_identity(os.getpid()))
    handle, access = windows._open_process(os.getpid())
    with windows.PeerHandle(handle, windows._handle_identity(handle), access) as self_peer:
        assert self_peer.identity == observed_self
        assert self_peer.token["words"] == platform.handoff_token(os.getpid())["words"]
    expected = windows.identity(platform.handoff_child_identity(native_child))
    original = int(native_child._handle)
    with windows.retain_child(native_child, reap_guard=threading.RLock(), expected=expected) as retained:
        assert retained._handle != original
        assert not os.get_handle_inheritable(retained._handle)
        assert retained.identity == expected
        assert retained.token["words"] == platform.handoff_token(native_child.pid)["words"]
        _no_reopen(monkeypatch)
        assert retained.verify()["pid"] == native_child.pid
    assert platform._windows_process_active(original), "closing duplicate closed Popen's handle"


@requires_windows_process_and_lock_apis
def test_windows_native_retained_peer_outlives_channel_and_terminates_owned_child(native_channel, monkeypatch):
    channel, child, expected = native_channel
    with windows.retain_peer(channel, expected=expected) as retained:
        _no_reopen(monkeypatch)
        assert windows.peer_token(channel) == retained.token
        # Keep the channel object referenced: pin cleanup must occur on close,
        # independently of Python collection and independent retained authority.
        pin = windows._pins[channel][0]
        channel.close()
        assert pin._handle is None and retained._handle is not None
        assert retained.verify(expected)["pid"] == child.pid
        windows.signal(retained.token["words"], platform.TERM, authority=retained)
        child.wait(timeout=10)
        with pytest.raises(windows.WindowsBindingError, match="exited"):
            retained.verify()
    retained.close()
    with pytest.raises(windows.WindowsBindingError, match="closed"):
        retained.signal(platform.KILL)


@requires_windows_process_and_lock_apis
def test_windows_native_signal_refusals_leave_original_child_alive(native_child, monkeypatch):
    with windows.retain_child(native_child, reap_guard=threading.RLock()) as retained:
        _no_reopen(monkeypatch)
        for signum in (0, False, True, -1, 2, 10):
            with pytest.raises(windows.WindowsBindingError, match="outside the admitted set"):
                windows.signal(retained.token["words"], signum, authority=retained)
        for field, value in (("pid", native_child.pid + 1), ("uid", retained.identity["uid"] ^ 1),
                             ("birth_id", "windows-creation:1")):
            wrong = {**retained.identity, field: value}
            with pytest.raises(windows.WindowsBindingError, match="incarnation"):
                retained.verify(wrong)
            with pytest.raises(windows.WindowsBindingError, match="incarnation"):
                windows.signal(windows._identity_token(wrong)["words"], platform.KILL, authority=retained)
        with pytest.raises(windows.WindowsBindingError, match="requires retained native authority"):
            windows.signal(retained.token["words"], platform.TERM)
        assert native_child.poll() is None


@requires_windows_process_and_lock_apis
def test_windows_native_read_only_duplicate_preserves_actual_access(native_child, monkeypatch):
    kernel = windows._handle_api()
    handle = kernel.OpenProcess(windows._OBSERVE_ACCESS, False, native_child.pid)
    assert handle
    with windows.PeerHandle(handle, windows._handle_identity(handle), windows._OBSERVE_ACCESS) as source:
        with source._duplicate() as retained:
            _no_reopen(monkeypatch)
            assert retained.access == windows._OBSERVE_ACCESS
            assert not os.get_handle_inheritable(retained._handle)
            with pytest.raises(windows.WindowsBindingError, match="no termination access"):
                retained.signal(platform.TERM)
            assert not kernel.TerminateProcess(retained._handle, 1)
            assert ctypes.get_last_error() == 5  # actual OS permission, not a mocked mask
            assert native_child.poll() is None


@requires_windows_process_and_lock_apis
def test_windows_native_exited_owner_with_exit_code_259_is_refused():
    child = _native_process("import sys; sys.stdin.buffer.read(1); raise SystemExit(259)")
    try:
        with windows.retain_child(child, reap_guard=threading.RLock()) as retained:
            child.stdin.write(b"X")
            child.stdin.flush()
            assert child.wait(timeout=10) == 259
            with pytest.raises(windows.WindowsBindingError, match="exited"):
                retained.verify()
            with pytest.raises(windows.WindowsBindingError, match="exited"):
                retained.signal(platform.KILL)
    finally:
        _reap(child)


@requires_windows_process_and_lock_apis
def test_windows_native_carried_socket_does_not_replace_exited_original_owner(native_channel, monkeypatch):
    channel, child, expected = native_channel
    carried = None
    try:
        with windows.retain_peer(channel, expected=expected) as retained:
            channel.sendall(b"S")
            size, = struct.unpack("!I", windows.read_exact(channel, 4, deadline=time.monotonic() + 10))
            assert 0 < size <= 4096
            carried = socket.fromshare(windows.read_exact(channel, size, deadline=time.monotonic() + 10))
            carried.set_inheritable(False)
            channel.sendall(b"X")
            assert child.wait(timeout=10) == 0
            assert carried.fileno() >= 0
            _no_reopen(monkeypatch)
            with pytest.raises(windows.WindowsBindingError, match="exited"):
                retained.verify(expected)
            with pytest.raises(windows.WindowsBindingError, match="exited"):
                windows.signal(retained.token["words"], platform.TERM, authority=retained)
    finally:
        if carried is not None: carried.close()


@requires_windows_process_and_lock_apis
def test_windows_native_inherited_adoption_preserves_original_handle(monkeypatch):
    # The socket creator is this process. Its captured process handle must be
    # carried through adoption even though the bootstrap transport has closed.
    left, right = socket.socketpair(socket.AF_INET)
    handle, access = windows._open_process(os.getpid())
    source = windows.PeerHandle(handle, windows._handle_identity(handle), access)
    adopted = None
    try:
        descriptor = right.fileno()
        endpoints = right.getsockname(), right.getpeername()
        monkeypatch.setattr(windows, "_inherited_owner", source.identity)
        monkeypatch.setattr(windows, "_inherited_peer", source)
        monkeypatch.setattr(windows, "_inherited_sockets", {descriptor: endpoints})
        _no_reopen(monkeypatch)
        adopted = windows.adopt_socket(right.detach())
        assert source._handle is None
        with windows.retain_peer(adopted) as retained:
            assert retained.identity["pid"] == os.getpid()
            adopted.close()
            assert retained.verify()["pid"] == os.getpid()
    finally:
        source.close()
        left.close()
        right.close()
        if adopted is not None: adopted.close()


@requires_windows_process_and_lock_apis
def test_windows_native_worker_bootstrap_carries_owner_handle_through_real_adoption():
    parent, inherited = socket.socketpair(socket.AF_INET)
    process = None
    expected = windows.identity(platform.process_identity(os.getpid()))
    code = r'''
import json, sys
from runtime_protocol import platform, windows_handoff as windows
expected = json.loads(sys.argv[2])
original = windows._inherited_peer
assert original is not None
def no_reopen(*args, **kwargs):
    raise AssertionError("bootstrap owner PID was reopened during adoption")
windows._open_process = no_reopen
platform.process_identity = no_reopen
control = platform.handoff_adopt_socket(int(sys.argv[1]))
with windows.retain_peer(control, expected=expected) as retained:
    assert original._handle is None and windows._inherited_peer is None
    control.sendall(b"R")
    assert control.recv(1) == b"X"
    control.close()
    report = {"identity": retained.identity, "token_pid": retained.verify(expected)["pid"],
              "pin_closed": windows._pins[control][0]._handle is None}
    print(json.dumps(report), flush=True)
'''
    try:
        process = platform.spawn_tree([sys.executable, "-u", "-c", code,
                                      str(inherited.fileno()), json.dumps(expected)],
                                     pass_fds=(inherited.fileno(),), close_fds=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        inherited.close()
        parent.settimeout(10)
        assert parent.recv(1) == b"R"
        parent.sendall(b"X")
        output, errors = process.communicate(timeout=10)
        assert process.returncode == 0, (output, errors)
        assert json.loads(output) == {"identity": expected, "token_pid": os.getpid(), "pin_closed": True}
    finally:
        parent.close()
        inherited.close()
        if process is not None:
            try:
                _reap(process)
            finally:
                process._runtime_job.close()


@requires_windows_process_and_lock_apis
def test_windows_native_close_signal_race_keeps_original_handle_custody(native_child):
    retained = windows.retain_child(native_child, reap_guard=threading.RLock())
    start = threading.Barrier(2, timeout=5)
    outcomes = []
    def signal():
        try:
            start.wait()
            retained.signal(platform.TERM)
            outcomes.append("terminated")
        except windows.WindowsBindingError as exc:
            outcomes.append(str(exc))
    def close():
        start.wait()
        retained.close()
    actor, closer = threading.Thread(target=signal), threading.Thread(target=close)
    try:
        actor.start()
        closer.start()
        actor.join(10)
        closer.join(10)
        assert not actor.is_alive() and not closer.is_alive()
        assert len(outcomes) == 1
        assert outcomes[0] == "terminated" or "authority is closed" in outcomes[0]
        if outcomes[0] == "terminated":
            native_child.wait(timeout=10)
        else:
            assert native_child.poll() is None
        assert retained._handle is None
        # Popen still owns its own valid native reference, live or signaled.
        assert platform._windows_process_active(native_child._handle) == (outcomes[0] != "terminated")
    finally:
        retained.close()


@requires_windows_process_and_lock_apis
def test_windows_native_repeated_retention_and_channel_close_release_handles(native_channel):
    from ctypes import wintypes

    channel, child, expected = native_channel
    kernel = windows._handle_api()
    kernel.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetProcessHandleCount.restype = wintypes.BOOL
    def count():
        value = wintypes.DWORD()
        assert kernel.GetProcessHandleCount(kernel.GetCurrentProcess(), ctypes.byref(value))
        return value.value
    # Warm native library/token observations before comparing handle counts.
    windows.verify_peer(channel, expected)
    before = count()
    for _ in range(20):
        with windows.retain_peer(channel, expected=expected) as retained:
            assert retained.verify()["pid"] == child.pid
    assert count() == before
    pin = windows._pins[channel][0]
    channel.close()
    assert pin._handle is None
    assert count() <= before - 2  # socket and captured process handle, with object still referenced
