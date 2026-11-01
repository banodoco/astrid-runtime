"""Cross-platform transport logic and native Windows launch/transfer proof."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from runtime_protocol import platform, posix_handoff, windows_handoff as windows
from runtime_protocol import local_worker_handoff as handoff
from runtime_protocol.errors import ConflictError
from tests.lanes import requires_windows_process_and_lock_apis


PEER = {"pid": 52, "uid": 17, "birth_id": "windows-creation:123456789"}


class Channel:
    family = socket.AF_INET

    def __init__(self, data=b""):
        self.data = bytearray(data)
        self.sent = b""
        self.closed = False

    def fileno(self): return 901
    def getsockname(self): return ("127.0.0.1", 3141)
    def getpeername(self): return ("127.0.0.1", 2718)
    def sendall(self, data): self.sent += data
    def recv(self, count):
        result = bytes(self.data[:count])
        del self.data[:count]
        return result
    def close(self): self.closed = True
    def settimeout(self, timeout):
        self.timeouts = [*getattr(self, "timeouts", []), timeout]
    def set_inheritable(self, value): pass


@pytest.fixture
def native_peer(monkeypatch):
    monkeypatch.setattr(windows, "tcp_peer_pid", lambda channel: PEER["pid"])
    monkeypatch.setattr(platform, "process_identity", lambda pid: dict(PEER))
    monkeypatch.setattr(platform, "current_user", lambda: PEER["uid"])
    return dict(PEER)


@pytest.mark.parametrize("field,value", [("pid", 53), ("uid", 18), ("birth_id", "windows-creation:999")])
def test_windows_peer_rejects_wrong_pid_user_and_creation(native_peer, field, value):
    expected = {**native_peer, field: value}
    with pytest.raises(ConflictError, match="incarnation"):
        windows.pin_peer(Channel(), expected)


def test_windows_peer_revalidates_pid_reuse_on_every_use(native_peer, monkeypatch):
    channel = Channel()
    assert windows.pin_peer(channel, native_peer) == native_peer
    monkeypatch.setattr(platform, "process_identity", lambda pid: {**PEER, "birth_id": "windows-creation:999"})
    with pytest.raises(ConflictError, match="incarnation"):
        windows.verify_peer(channel)


def test_windows_peer_rejects_process_exit_and_pid_change(native_peer, monkeypatch):
    monkeypatch.setattr(platform, "process_identity", lambda pid: None)
    with pytest.raises(ConflictError, match="unavailable"):
        windows.pin_peer(Channel(), native_peer)
    monkeypatch.setattr(platform, "process_identity", lambda pid: PEER)
    pids = iter([52, 53])
    monkeypatch.setattr(windows, "tcp_peer_pid", lambda channel: next(pids))
    with pytest.raises(ConflictError, match="changed"):
        windows.pin_peer(Channel(), native_peer)


def _table(rows):
    address = struct.unpack("=I", socket.inet_aton("127.0.0.1"))[0]
    return struct.pack("=I", len(rows)) + b"".join(
        struct.pack("=6I", state, address, socket.htons(local), address, socket.htons(remote), pid)
        for state, local, remote, pid in rows)


@pytest.mark.parametrize("rows,accepted", [
    ([(5, 2718, 3141, 52)], True),
    ([(5, 3141, 2718, 99), (5, 2718, 3141, 52)], True),
    ([(5, 3141, 2718, 99)], False),
    ([(8, 2718, 3141, 52)], False),
    ([(5, 2718, 3141, 52), (5, 2718, 3141, 53)], False),
    ([(5, 2718, 3141, 0)], False),
])
def test_windows_tcp_table_uses_exact_reverse_established_tuple(rows, accepted):
    invoke = lambda: windows.tcp_peer_from_table(_table(rows), ("127.0.0.1", 3141), ("127.0.0.1", 2718))
    if accepted:
        assert invoke() == 52
    else:
        with pytest.raises(ConflictError): invoke()


@pytest.mark.parametrize("data", [b"", b"\0", struct.pack("=I", 100), _table([(5, 2718, 3141, 52)])[:-1]])
def test_windows_tcp_table_rejects_truncation(data):
    with pytest.raises(ConflictError, match="malformed"):
        windows.tcp_peer_from_table(data, ("127.0.0.1", 3141), ("127.0.0.1", 2718))


def _listener(channel, *following, token="a" * 64):
    listener = windows.Listener.__new__(windows.Listener)
    listener.expected = PEER
    listener.token = token
    listener.used = False
    listener._token_lock = threading.Lock()
    listener.timeout = 1
    channels = iter((channel, *following))
    def accept():
        value = next(channels, None)
        if value is None:
            raise TimeoutError("no authenticated client arrived")
        return value, None
    listener.socket = SimpleNamespace(accept=accept, settimeout=lambda timeout: None)
    listener.socket.close = lambda: setattr(listener.socket, "closed", True)
    return listener


def test_windows_token_is_one_time_and_only_consumed_after_authentication(native_peer):
    channel = Channel(b"a" * 64)
    listener = _listener(channel)
    assert listener.accept() is channel
    assert listener.used and channel.sent == b"\x01"
    with pytest.raises(ConflictError, match="already consumed"):
        listener.accept()
    assert not channel.closed


@pytest.mark.parametrize("token", [b"b" * 64, b"a" * 63])
def test_windows_bad_or_truncated_token_closes_connection(native_peer, token):
    channel = Channel(token)
    listener = _listener(channel)
    with pytest.raises(TimeoutError): listener.accept()
    assert channel.closed and not listener.used and not channel.sent


@pytest.mark.parametrize("failure", ["identity", "token", "truncated", "reset", "ack"])
def test_windows_listener_discards_rogue_before_accepting_selected_child(native_peer, monkeypatch, failure):
    rogue = Channel(b"b" * 64 if failure == "token" else b"a" * (63 if failure == "truncated" else 64))
    child = Channel(b"a" * 64)
    listener = _listener(rogue, child)
    if failure == "identity":
        monkeypatch.setattr(windows, "tcp_peer_pid", lambda channel: 53 if channel is rogue else PEER["pid"])
        monkeypatch.setattr(platform, "process_identity", lambda pid: {**PEER, "pid": pid})
    if failure in ("reset", "ack"):
        def reset(*args):
            raise ConnectionResetError("rogue disconnected")
        if failure == "reset":
            rogue.recv = reset
        else:
            rogue.sendall = reset
    assert listener.accept() is child
    assert rogue.closed and not rogue.sent
    assert listener.used and child.sent == b"\x01" and not child.closed


def test_windows_rejected_connections_share_accept_and_read_deadline(native_peer, monkeypatch):
    moments = iter([0.0, 0.1, 0.7, 1.05])
    monkeypatch.setattr(windows.time, "monotonic", lambda: next(moments))
    rogue, child = Channel(b"b" * 64), Channel(b"a" * 64)
    listener = _listener(rogue, child)
    timeouts = []
    listener.socket.settimeout = timeouts.append
    with pytest.raises(TimeoutError, match="authentication timed out"):
        listener.accept()
    assert timeouts == pytest.approx([0.9])
    assert rogue.timeouts == pytest.approx([0.3])
    assert rogue.closed and not child.closed and child.data == b"a" * 64
    assert not listener.used


def test_windows_accept_wait_and_final_ack_use_the_same_deadline(native_peer, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(windows.time, "monotonic", lambda: now[0])
    channel = Channel(b"a" * 64)
    listener = _listener(channel)
    def accept():
        now[0] = 0.8
        return channel, None
    listener.socket.accept = accept
    read = channel.recv
    def recv(count):
        now[0] = 1.1
        return read(count)
    channel.recv = recv
    with pytest.raises(TimeoutError, match="authentication timed out"):
        listener.accept()
    assert channel.timeouts == pytest.approx([0.2])
    assert channel.closed and not listener.used and not channel.sent


def test_windows_worker_authentication_retries_without_resetting_bootstrap_ack_budget(native_peer, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(windows.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(platform, "handoff_child_identity", lambda process: PEER)
    rogue, child = Channel(b"b" * 64), Channel(b"a" * 64 + b"\x02")
    launch = windows.InheritedHandles.__new__(windows.InheritedHandles)
    launch.listener = _listener(rogue, child)
    accept = launch.listener.socket.accept
    def delayed_accept():
        now[0] += 0.35
        return accept()
    launch.listener.socket.accept = delayed_accept
    launch.authenticate(SimpleNamespace(pid=PEER["pid"]))
    assert rogue.closed and child.closed and launch.listener.used
    assert child.timeouts[-1] == pytest.approx(0.3)
    assert child.data == b""


@pytest.mark.parametrize("failure", ["token", "lineage"])
def test_windows_role_broker_rejects_rogue_then_seals_real_child(native_peer, monkeypatch, failure):
    from astrid_runtime import custody_broker as custody
    parent = {**PEER, "pid": 99}
    selected = {**PEER, "parent_pid": parent["pid"]}
    monkeypatch.setattr(platform, "process_identity", lambda pid: selected if pid == PEER["pid"] else {
        **selected, "pid": pid, "parent_pid": 100,
    })
    monkeypatch.setattr(custody, "sys", SimpleNamespace(platform="win32"))
    token = {"pid": PEER["pid"], "uid": PEER["uid"], "pidversion": 1,
             "sha256": "token-digest", "words": [1] * 8}
    monkeypatch.setattr(custody, "_peer_token", lambda channel: token)
    frame = {"version": custody.PROTOCOL_VERSION, "command": "register_pre_exec",
             "run_id": "run", "role": "relay", "pid": PEER["pid"],
             "ppid": parent["pid"], "argv_digest": "argv-digest"}
    rogue = Channel(b"b" * 64 if failure == "token" else b"a" * 64)
    child = Channel(b"a" * 64 + custody._canonical(frame) + b"\n")
    if failure == "lineage":
        monkeypatch.setattr(windows, "tcp_peer_pid", lambda channel: 53 if channel is rogue else PEER["pid"])
    events = []
    broker = SimpleNamespace(
        listener=_listener(rogue, child), timeout=1, error=None, state="accepting",
        run_id="run", role="relay", launch_parent=SimpleNamespace(verify=lambda: parent),
        identity_provider=lambda pid: selected, cleanup_actor=object(), custody_generation=1,
        role_authority=SimpleNamespace(bind_pending=lambda **kwargs: None, bind_target=lambda **kwargs: None),
        chain_head="chain", authority_journal=None, _persist=events.append,
        _ready=threading.Event(), socket_path=SimpleNamespace(unlink=lambda **kwargs: None),
        socket_root=SimpleNamespace(rmdir=lambda: None), _release_authority_scope=lambda: None,
        _retain_post_exec_connection=False, _post_exec_connection=None,
    )
    custody.RoleBoundCustodyBroker._serve(broker)
    assert broker.error is None and broker.state == "sealed"
    assert events == ["registration_pre_exec", "registration_ack_checkpoint", "registration_post_exec", "admission_sealed"]
    assert broker.registration["identity"] == selected
    assert broker.listener.used and broker.listener.socket.closed
    assert rogue.closed and child.closed and broker._ready.is_set()


class SharedSocket:
    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.closed = False
        self.inheritable = True
    def share(self, pid):
        assert pid == PEER["pid"]
        return struct.pack("!I", self.descriptor)
    def detach(self): return self.descriptor
    def close(self): self.closed = True
    def set_inheritable(self, value): self.inheritable = value


@pytest.mark.parametrize("transport", ["posix", "windows"])
def test_both_transports_keep_protocol_frame_and_exact_authority_order(monkeypatch, transport):
    payload = handoff._canonical_frame({"version": handoff.TRANSFER_VERSION, "deadline_unix_ms": 1000})
    if transport == "windows":
        channel = Channel()
        monkeypatch.setattr(windows, "verify_peer", lambda *args: PEER)
        monkeypatch.setattr(windows.socket, "socket", lambda *, fileno: SharedSocket(fileno))
        received = []
        def fromshare(value):
            result = SharedSocket(struct.unpack("!I", value)[0])
            received.append(result)
            return result
        monkeypatch.setattr(windows.socket, "fromshare", fromshare, raising=False)
        windows.send(channel, payload, (101, 102))
        channel.data = bytearray(channel.sent)
        assert windows.receive(channel, 1024) == (payload, [101, 102])
        assert all(not value.inheritable for value in received)
    else:
        # Mock the Unix syscall too: both OS backends run in every default leg.
        monkeypatch.setattr(posix_handoff.socket, "SCM_RIGHTS", 1, raising=False)
        monkeypatch.setattr(posix_handoff.socket, "CMSG_SPACE", lambda n: n + 16, raising=False)
        channel = Channel()
        def sendmsg(parts, ancillary):
            channel.packet = (b"".join(parts), ancillary, 0, None)
            return len(channel.packet[0])
        channel.sendmsg = sendmsg
        channel.recvmsg = lambda *args: channel.packet
        posix_handoff.send(channel, payload, (101, 102))
        assert posix_handoff.receive(channel, 1024) == (payload, [101, 102])


@pytest.mark.parametrize("fault", ["bad_share", "truncated_payload", "peer_changed"])
def test_windows_transfer_closes_every_imported_socket_on_failure(monkeypatch, fault):
    monkeypatch.setattr(windows, "verify_peer", lambda *args: PEER)
    imported = []
    def fromshare(value):
        if fault == "bad_share" and imported: raise OSError("invalid share")
        result = SharedSocket(100 + len(imported))
        imported.append(result)
        return result
    monkeypatch.setattr(windows.socket, "fromshare", fromshare, raising=False)
    data = b"\0" + struct.pack("!II", 3, 2) + struct.pack("!I", 1) + b"a" + struct.pack("!I", 1) + b"b"
    data += b"{}\n" if fault != "truncated_payload" else b"{"
    if fault == "peer_changed":
        calls = []
        def verify(channel):
            calls.append(1)
            if len(calls) == 2: raise ConflictError("peer changed")
            return PEER
        monkeypatch.setattr(windows, "verify_peer", verify)
    with pytest.raises((ConflictError, OSError)): windows.receive(Channel(data), 1024)
    assert imported and all(value.closed for value in imported)


@pytest.mark.parametrize("length,count", [(1025, 2), (3, 1), (3, 3), (3, 0)])
def test_windows_transfer_bounds_precede_handle_import(monkeypatch, length, count):
    monkeypatch.setattr(windows, "verify_peer", lambda *args: PEER)
    with pytest.raises(ConflictError, match="boundary"):
        windows.receive(Channel(b"\0" + struct.pack("!II", length, count)), 1024)


@pytest.mark.parametrize("transport", ["posix", "windows"])
@pytest.mark.parametrize("payload", [b'{"a":1,"a":2}\n', b'[]\n', b'{}\n{}\n', b'{"a":NaN}\n'])
def test_protocol_rejections_apply_to_both_transports(monkeypatch, transport, payload):
    module = windows if transport == "windows" else posix_handoff
    monkeypatch.setattr(platform, "_handoff_transport", lambda: module)
    channel = Channel(payload)
    if transport == "windows":
        monkeypatch.setattr(windows, "verify_peer", lambda *args: PEER)
    else:
        channel.recvmsg = lambda *args: (payload, [], 0, None)
        monkeypatch.setattr(posix_handoff.socket, "CMSG_SPACE", lambda n: n + 16, raising=False)
    with pytest.raises(ConflictError): handoff.receive_frame(channel)


@pytest.mark.parametrize("system,suffix", [("win32", "Scripts/python.exe"), ("linux", "bin/python"), ("darwin", "bin/python")])
def test_one_venv_locator_preserves_lexical_environment(monkeypatch, tmp_path, system, suffix):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform=system))
    assert platform.venv_python(tmp_path) == tmp_path / suffix


def test_windows_creation_token_roundtrip_and_safe_signal(monkeypatch):
    monkeypatch.setattr(platform, "process_identity", lambda pid: PEER)
    token = platform.handoff_token(PEER["pid"])
    assert platform.handoff_token_details(token["words"]) == {key: token[key] for key in ("pid", "uid", "pidversion", "sha256")}
    seen = []
    monkeypatch.setattr(platform, "signal_process", lambda expected, signum: seen.append((expected, signum)))
    platform.handoff_signal_token(token["words"], platform.TERM)
    assert seen == [(PEER, platform.TERM)]


WINDOWS_CHILD = r'''
import json, socket, sys
from astrid_runtime.custody_broker import AuthenticatedCleanupActor
from runtime_protocol import platform
from runtime_protocol.local_worker_composition import _frame_send, _frame_receive
from runtime_protocol.local_worker_handoff import (
    connect_fresh_successor, send_frame, receive_frame, receive_bound_authority_transfer,
)
control = platform.handoff_adopt_socket(int(sys.argv[1]))
control.settimeout(10)
_frame_send(control, AuthenticatedCleanupActor.current().verify())
data = _frame_receive(control)
channel, relay = connect_fresh_successor(data['binding'], data['seal'], timeout=10)
send_frame(channel, data['request'])
transfer = receive_bound_authority_transfer(channel, binding=data['binding'],
    sealed_record_digest=data['seal'], expected_listener=tuple(data['listener']))
assert not platform.handoff_get_inheritable(transfer.worker_control_fd)
assert not platform.handoff_get_inheritable(transfer.listener_fd)
worker = socket.socket(fileno=transfer.worker_control_fd)
_frame_send(worker, {'transferred': True})
worker.detach()
send_frame(channel, {'adopted': True})
assert receive_frame(channel) == {'release': True}
transfer.close()
channel.close()
control.close()
'''


@pytest.mark.integration
@requires_windows_process_and_lock_apis
def test_windows_launch_fresh_authenticated_exchange_and_socket_transfer(tmp_path):
    from astrid_runtime.custody_broker import AuthenticatedCleanupActor
    from runtime_protocol.local_execution_handoff import digest
    from runtime_protocol.local_worker_composition import _frame_send, _frame_receive
    from test_local_execution_supervisor import _handoff_case
    from test_local_worker_handoff import _adoption

    parent, inherited = socket.socketpair()
    control, control_peer = socket.socketpair()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    listener.bind(("127.0.0.1", 0)); listener.listen(1)
    process = successor = channel = None
    try:
        process = platform.spawn_tree([sys.executable, "-c", WINDOWS_CHILD, str(inherited.fileno())],
            close_fds=True, pass_fds=(inherited.fileno(),), stdin=subprocess.DEVNULL)
        inherited.close()
        parent.settimeout(10); control_peer.settimeout(10)
        child_actor = _frame_receive(parent)
        source = AuthenticatedCleanupActor.current().verify()
        request, _ = _handoff_case(tmp_path)
        binding = request["binding"]
        binding.update(source_owner=source, new_owner=child_actor)
        binding["source_relay_reference"]["target"] = source
        binding["intent_digest"] = digest({"version": request["version"], "binding": {k: v for k, v in binding.items() if k != "intent_digest"}})
        scope = Path(binding["custody_scope"])
        platform.owner_only(scope, directory=True)
        seal = "sha256:" + "2" * 64
        successor = handoff.HandoffSuccessorListener(binding, seal, timeout=10)
        adoption = _adoption(binding, seal=seal)
        wrapped = {"version": "runtime.local-execution-control/v1", "command": "handoff", "request": adoption}
        _frame_send(parent, {"binding": binding, "seal": seal, "request": wrapped, "listener": list(listener.getsockname())})
        peer, frame = successor.accept()
        channel = peer.channel
        assert frame == wrapped and peer.actor.verify() == child_actor
        transfer_frame = {"version": handoff.TRANSFER_VERSION, "deadline_unix_ms": binding["deadline_unix_ms"],
                          "binding_digest": digest(binding), "sealed_record_digest": seal}
        handoff.send_authority_transfer(channel, transfer_frame,
            worker_control_fd=control.fileno(), listener_fd=listener.fileno())
        assert _frame_receive(control_peer) == {"transferred": True}
        assert handoff.receive_frame(channel) == {"adopted": True}
        handoff.send_frame(channel, {"release": True})
        assert process.wait(timeout=15) == 0
    finally:
        for value in (parent, inherited, control, control_peer, listener, channel, successor):
            if value is not None: value.close()
        if process is not None:
            try:
                if process.poll() is None: platform.stop_tree(process, grace=1)
            finally:
                process._runtime_job.close()


@pytest.mark.integration
@requires_windows_process_and_lock_apis
@pytest.mark.parametrize("wrong", ["pid", "uid", "birth_id"])
def test_windows_real_connection_refuses_unselected_process_identity(wrong):
    # A real native TCP peer, with a deliberately wrong selected binding. The
    # UID case tests refusal without requiring credentials for a second account.
    source = windows.Listener(timeout=10)
    process = None
    try:
        code = (
            "import os; from runtime_protocol.windows_handoff import connect; "
            "channel=connect(os.environ['ASTRID_TEST_HANDOFF_ENDPOINT'], timeout=10)"
        )
        environment = {**os.environ, "ASTRID_TEST_HANDOFF_ENDPOINT": source.endpoint}
        process = subprocess.Popen([sys.executable, "-c", code], env=environment,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        expected = windows.identity(platform.process_identity(process.pid))
        expected[wrong] = expected[wrong] + 1 if wrong != "birth_id" else "windows-creation:0"
        with pytest.raises(TimeoutError):
            source.accept(expected)
        assert not source.used
        assert process.wait(timeout=15) != 0
    finally:
        source.close()
        if process is not None and process.poll() is None:
            process.kill(); process.wait(timeout=10)


@pytest.mark.parametrize("fail", [False, True])
def test_windows_handle_list_is_explicit_and_inheritance_is_restored(monkeypatch, fail):
    listener = SimpleNamespace(endpoint="private-endpoint", closed=False)
    listener.close = lambda: setattr(listener, "closed", True)
    monkeypatch.setattr(windows, "Listener", lambda **kwargs: listener)
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(get_osfhandle=lambda fd: 202))
    monkeypatch.setattr(subprocess, "STARTUPINFO", lambda: SimpleNamespace(lpAttributeList={"handle_list": [999]}), raising=False)
    flags = {101: False, 202: False}
    monkeypatch.setattr(os, "get_handle_inheritable", lambda handle: flags[handle], raising=False)
    def set_flag(handle, value):
        if fail and handle == 202 and value: raise OSError("cannot inherit")
        flags[handle] = value
    monkeypatch.setattr(os, "set_handle_inheritable", set_flag, raising=False)
    def borrowed(*, fileno):
        if fileno == 3: raise OSError("not a socket")
        return SharedSocket(fileno)
    monkeypatch.setattr(windows.socket, "socket", borrowed)
    environment = {"PATH": "selected"}
    kwargs = {"env": environment}
    if fail:
        with pytest.raises(OSError, match="cannot inherit"):
            windows.InheritedHandles([sys.executable, "-I", "-m", "target"], kwargs, (101, 3))
    else:
        launch = windows.InheritedHandles([sys.executable, "-I", "-m", "target"], kwargs, (101, 3))
        assert kwargs["close_fds"] is True
        assert kwargs["startupinfo"].lpAttributeList == {"handle_list": [999, 101, 202]}
        bootstrap = json.loads(kwargs["env"]["ASTRID_RUNTIME_WORKER_BOOTSTRAP"])
        assert bootstrap["sockets"] == [101] and bootstrap["files"] == {"3": 202}
        assert bootstrap["endpoint"] == "private-endpoint"
        assert environment == {"PATH": "selected"}
        assert flags == {101: True, 202: True}
        launch.restore()
        launch.close()
    assert flags == {101: False, 202: False} and listener.closed


@pytest.mark.parametrize("mode", ["-c", "-m"])
@pytest.mark.parametrize(
    "flags",
    [["-I", "-S"], ["-S", "-I"], ["-u", "-B", "-I", "-S", "-s", "-E"], ["-X", "utf8", "-I", "-S"]],
)
def test_windows_module_entry_accepts_no_site_and_preserves_worker_arguments(monkeypatch, mode, flags):
    import runpy
    received = []
    monkeypatch.setattr(sys, "argv", [])
    if "-X" in flags:
        monkeypatch.setattr(sys, "flags", SimpleNamespace(utf8_mode=1))
    monkeypatch.setattr(sys, "path", list(sys.path))
    original_path = list(sys.path)
    monkeypatch.setenv("PYTHONPATH", "unadmitted-import-root")
    monkeypatch.setitem(sys.modules, "worker_probe", SimpleNamespace(record=lambda: received.append(list(sys.argv))))
    def run_module(name, **kwargs):
        assert name == "worker_probe" and kwargs == {"run_name": "__main__", "alter_sys": True}
        received.append(list(sys.argv))
    monkeypatch.setattr(runpy, "run_module", run_module)
    target = "import worker_probe; worker_probe.record()" if mode == "-c" else "worker_probe"
    windows.enter_module([sys.executable, *flags, mode, target, "request.json", "--child-bridge", "101", "-S"])
    assert received == [["-c" if mode == "-c" else target, "request.json", "--child-bridge", "101", "-S"]]
    assert sys.path == original_path


def test_windows_module_entry_refuses_unrecognized_or_inactive_utf8_option(monkeypatch):
    monkeypatch.setattr(sys, "flags", SimpleNamespace(utf8_mode=0))
    with pytest.raises(ConflictError, match="UTF-8 flag was not active"):
        windows.enter_module([sys.executable, "-X", "utf8", "-m", "worker_probe"])
    monkeypatch.setattr(sys, "flags", SimpleNamespace(utf8_mode=1))
    with pytest.raises(ConflictError, match="requires a Python module or command"):
        windows.enter_module([sys.executable, "-X", "utf8=0", "-m", "worker_probe"])


def test_windows_no_site_bootstrap_authenticates_then_enters_network_site_and_channel(monkeypatch):
    events = []
    listener = SimpleNamespace(endpoint="private-endpoint", close=lambda: None)
    monkeypatch.setattr(windows, "Listener", lambda **kwargs: listener)
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace())
    monkeypatch.setattr(subprocess, "STARTUPINFO", lambda: SimpleNamespace(lpAttributeList=None), raising=False)
    monkeypatch.setattr(os, "get_handle_inheritable", lambda handle: False, raising=False)
    monkeypatch.setattr(os, "set_handle_inheritable", lambda handle, value: events.append(("inherit", handle, value)), raising=False)
    inherited = Channel()
    inherited.detach = lambda: 101
    inherited.sendall = lambda data: events.append(("worker-send", data))
    monkeypatch.setattr(windows.socket, "socket", lambda *, fileno: inherited)
    authenticated = Channel()
    authenticated.sendall = lambda data: events.append(("bootstrap-ack", data))
    authenticated.close = lambda: events.append("bootstrap-close")
    def connect(endpoint, **kwargs):
        assert endpoint == listener.endpoint
        events.append("authenticate")
        return authenticated
    monkeypatch.setattr(windows, "connect", connect)
    monkeypatch.setattr(windows, "verify_peer", lambda channel: events.append("verify-owner") or PEER)
    monkeypatch.setattr(windows, "pin_peer", lambda channel, owner: events.append(("adopt-owner", owner)) or owner)
    monkeypatch.setattr(windows, "_inherited_owner", None)
    monkeypatch.setattr(windows, "_inherited_sockets", {})
    monkeypatch.setattr(sys, "argv", [])
    monkeypatch.setattr(sys, "flags", SimpleNamespace(utf8_mode=1))
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setitem(sys.modules, "startup_probe", SimpleNamespace(install_network=lambda: events.append("network")))
    def worker():
        assert sys.argv == ["-c", "request.json", "--child-bridge", "101"]
        events.append("worker")
        windows.adopt_socket(int(sys.argv[3])).sendall(b"ready")
    dependency = SimpleNamespace(run=worker)
    def site_main():
        assert events[-1] == "network"
        events.append("site")
        monkeypatch.setitem(sys.modules, "worker_dependency", dependency)
        site.execsitecustomize()
        site.execusercustomize()
    site = SimpleNamespace(main=site_main, execsitecustomize=lambda: pytest.fail("unexpected site hook"),
                           execusercustomize=lambda: pytest.fail("unexpected user hook"))
    monkeypatch.setitem(sys.modules, "site", site)
    monkeypatch.delitem(sys.modules, "worker_dependency", raising=False)
    command = (
        "import startup_probe; startup_probe.install_network(); import site; "
        "site.execsitecustomize=lambda: None; site.execusercustomize=lambda: None; site.main(); "
        "import worker_dependency; worker_dependency.run()"
    )
    argv = [sys.executable, "-X", "utf8", "-u", "-B", "-I", "-S", "-c", command, "request.json", "--child-bridge", "101"]
    kwargs = {"env": {"PYTHONPATH": "unadmitted-import-root"}}
    launch = windows.InheritedHandles(argv, kwargs, (101,))
    try:
        assert launch.argv == [windows.python_executable(sys.executable), "-X", "utf8", "-u", "-B", "-I", "-S",
                               str(Path(windows.__file__).with_name("windows_worker_bootstrap.py"))]
        monkeypatch.setenv("ASTRID_RUNTIME_WORKER_BOOTSTRAP", kwargs["env"]["ASTRID_RUNTIME_WORKER_BOOTSTRAP"])
        events.clear()
        windows.run_worker()
        assert events == ["authenticate", "verify-owner", ("bootstrap-ack", b"\x02"), "bootstrap-close",
                          ("inherit", 101, False), "network", "site", "worker", ("adopt-owner", PEER),
                          ("worker-send", b"ready")]
        assert "unadmitted-import-root" not in sys.path
    finally:
        launch.close()


@pytest.mark.parametrize("failure", [None, "job", "spawn", "assign", "resume", "authenticate"])
def test_windows_worker_launch_authenticates_after_job_assignment_and_cleans_failure(monkeypatch, failure):
    events = []
    def step(name):
        events.append(name)
        if name == failure: raise OSError(name)
    class Inheritance:
        def __init__(self, argv, kwargs, descriptors):
            assert descriptors == (101,)
            self.argv = ["worker-bootstrap"]
            kwargs.update(close_fds=True, startupinfo=SimpleNamespace(lpAttributeList={"handle_list": [101]}))
        def restore(self): step("restore")
        def authenticate(self, process): step("authenticate")
        def close(self): step("inheritance-close")
    class Job:
        handle = 333
        def __init__(self): step("job")
        def assign(self, process): step("assign")
        def close(self): step("job-close"); self.handle = None
    process = SimpleNamespace(pid=PEER["pid"], kill=lambda: step("kill"), wait=lambda: step("wait"))
    def popen(argv, **kwargs):
        assert argv == ["worker-bootstrap"] and "pass_fds" not in kwargs
        assert kwargs["close_fds"] is True
        assert kwargs["startupinfo"].lpAttributeList["handle_list"] == [101, 333]
        assert kwargs["env"]["ASTRID_RUNTIME_JOB_HANDLE"] == "333"
        step("spawn")
        return process
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(platform, "_inherited_job_handle", None)
    monkeypatch.setattr(platform, "_inherited_ancestor_jobs", [])
    monkeypatch.setattr(windows, "InheritedHandles", Inheritance)
    monkeypatch.setattr(platform, "_Job", Job)
    monkeypatch.setattr(subprocess, "Popen", popen)
    monkeypatch.setattr(subprocess, "STARTUPINFO", lambda: SimpleNamespace(lpAttributeList=None), raising=False)
    monkeypatch.setattr(platform, "_resume_process", lambda pid: step("resume"))
    monkeypatch.setattr(os, "set_handle_inheritable", lambda handle, value: None, raising=False)
    if failure:
        with pytest.raises(OSError, match=failure): platform.spawn_tree([sys.executable, "-m", "target"], pass_fds=(101,))
        if failure not in ("job", "spawn"):
            assert events.index("kill") < events.index("wait") < events.index("job-close")
    else:
        assert platform.spawn_tree([sys.executable, "-m", "target"], pass_fds=(101,)) is process
        assert events.index("assign") < events.index("resume") < events.index("authenticate")
        assert events.index("spawn") < events.index("restore") < events.index("resume")
    assert events[-1] == "inheritance-close"


@pytest.mark.integration
@requires_windows_process_and_lock_apis
def test_windows_worker_launch_ignores_a_rogue_first_connection(tmp_path, monkeypatch):
    listeners, rogues = [], []
    original = windows.Listener
    class AttackedListener(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            listeners.append(self)
            rogues.append(socket.create_connection(("127.0.0.1", json.loads(self.endpoint)["port"]), timeout=10))
    monkeypatch.setattr(windows, "Listener", AttackedListener)
    process = None
    try:
        with (tmp_path / "binding").open("w+b") as binding:
            binding.write(b"worker-binding"); binding.flush(); binding.seek(0)
            code = "import os,sys; assert os.read(int(sys.argv[1]),64)==b'worker-binding'"
            process = platform.spawn_tree([sys.executable, "-c", code, str(binding.fileno())],
                                         pass_fds=(binding.fileno(),), close_fds=True)
            assert process.wait(timeout=15) == 0
        assert len(listeners) == 1 and listeners[0].used
        assert rogues[0].recv(1) == b""
    finally:
        for rogue in rogues:
            rogue.close()
        if process is not None:
            try:
                if process.poll() is None: platform.stop_tree(process, grace=1)
            finally:
                process._runtime_job.close()


@pytest.mark.integration
@requires_windows_process_and_lock_apis
def test_windows_strict_network_startup_with_inherited_channel(tmp_path):
    import venv
    from runtime_protocol.local_worker_composition import _frame_receive
    root = tmp_path / "strict-worker-venv"
    venv.EnvBuilder(with_pip=False).create(root)
    packages = root / "Lib" / "site-packages"
    unexpected_site = tmp_path / "unexpected-site"
    guarded_site = tmp_path / "guarded-site"
    # Both automatic .pth execution and a customizable hook must stay out of
    # bootstrap startup. The worker explicitly restores dependencies only once
    # its network guard is installed, matching strict host startup ordering.
    (packages / "startup-order.pth").write_text(
        "import pathlib, socket; assert socket.socket.connect.__name__ == 'deny_network'; "
        f"pathlib.Path({str(guarded_site)!r}).write_text('guarded')\n", encoding="utf-8")
    (packages / "sitecustomize.py").write_text(
        f"from pathlib import Path; Path({str(unexpected_site)!r}).touch()\n", encoding="utf-8")
    (packages / "worker_dependency.py").write_text(
        "import socket\nassert socket.socket.connect.__name__ == 'deny_network'\nVALUE = 'admitted'\n",
        encoding="utf-8")
    code = r'''
import importlib.util, json, os, pathlib, socket, sys
config = json.loads(sys.argv[1])
assert sys.flags.isolated and sys.flags.no_site
assert 'site' not in sys.modules
assert not pathlib.Path(config['unexpected_site']).exists()
assert importlib.util.find_spec('worker_dependency') is None
events = ['network']
def deny_network(self, address):
    raise PermissionError('strict worker network guard')
socket.socket.connect = deny_network
import site
site.execsitecustomize = lambda: None
site.execusercustomize = lambda: None
site.main()
events.append('site')
assert pathlib.Path(config['guarded_site']).read_text() == 'guarded'
assert not pathlib.Path(config['unexpected_site']).exists()
import worker_dependency
events.append('worker')
try:
    with socket.socket() as denied:
        denied.connect(('127.0.0.1', 17480))
except PermissionError:
    pass
else:
    raise AssertionError('network guard did not remain installed')
from runtime_protocol import platform
assert sys.argv[2:4] == ['request.json', '--child-bridge']
channel = platform.handoff_adopt_socket(int(sys.argv[4]))
channel.sendall((json.dumps({'events': events, 'pid': os.getpid(), 'prefix': sys.prefix,
    'dependency': worker_dependency.VALUE, 'inheritable': channel.get_inheritable()}) + '\n').encode())
assert channel.recv(1) == b'x'
channel.close()
'''
    config = json.dumps({"unexpected_site": str(unexpected_site), "guarded_site": str(guarded_site)})
    parent, inherited = socket.socketpair()
    process = None
    try:
        process = platform.spawn_tree([str(platform.venv_python(root)), "-I", "-S", "-c", code,
                                      config, "request.json", "--child-bridge", str(inherited.fileno())],
                                     pass_fds=(inherited.fileno(),), close_fds=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        inherited.close(); parent.settimeout(15)
        report = _frame_receive(parent)
        assert report == {"events": ["network", "site", "worker"], "pid": process.pid,
                          "prefix": str(root), "dependency": "admitted", "inheritable": False}
        parent.sendall(b"x")
        output, errors = process.communicate(timeout=15)
        assert process.returncode == 0, (output, errors)
        assert not unexpected_site.exists()
    finally:
        parent.close(); inherited.close()
        if process is not None:
            try:
                if process.poll() is None: platform.stop_tree(process, grace=1)
            finally:
                process._runtime_job.close()
                process.communicate(timeout=15)


@pytest.mark.integration
@requires_windows_process_and_lock_apis
def test_windows_role_broker_seals_the_same_child_creation_identity(tmp_path):
    from astrid_runtime import custody_broker as custody
    control, inherited = socket.socketpair()
    scope = tmp_path / "scope"
    platform.private_directory(scope)
    broker = custody.RoleBoundCustodyBroker(role="relay", identity_provider=custody.default_process_identity,
        ledger_root=scope / "admission", authority_scope_root=scope,
        authority_journal=scope / "admissions.jsonl", owner_epoch="owner", timeout=10)
    target = [sys.executable, "-I", "-c",
        "import socket,sys; s=socket.socket(fileno=int(sys.argv[1])); s.sendall(b'ready'); assert s.recv(1)==b'x'", str(inherited.fileno())]
    environment = {**os.environ, **broker.child_environment(target, start_new_session=True)}
    process = rogue = None
    try:
        port = json.loads(broker.listener.endpoint)["port"]
        rogue = socket.create_connection(("127.0.0.1", port), timeout=10)
        assert rogue.recv(1) == b""
        assert not broker.listener.used
        process = platform.spawn_tree(custody.custody_wrapper_argv(sys.executable), env=environment,
                                     close_fds=True, pass_fds=(inherited.fileno(),))
        inherited.close(); control.settimeout(15)
        broker.wait_until_sealed()
        actor = custody.AuthenticatedCleanupActor.retained_child(process, reap_guard=threading.RLock())
        assert actor.verify()["birth_id"] == platform.process_identity(process.pid)["birth_id"]
        assert broker.role_authority.reference()["target"] == actor.verify()
        assert control.recv(5) == b"ready"
        control.sendall(b"x")
        assert process.wait(timeout=15) == 0
    finally:
        if rogue is not None:
            rogue.close()
        control.close(); inherited.close()
        if process is None:
            broker.abort_before_spawn()
        else:
            try:
                if process.poll() is None: platform.stop_tree(process, grace=1)
            finally:
                process._runtime_job.close()


def test_windows_peer_token_brackets_creation_time_observation(monkeypatch):
    observations = []
    def verify(channel):
        observations.append("verify")
        return PEER
    def token(pid):
        observations.append("token")
        return {"uid": PEER["uid"], "pidversion": 123456789}
    monkeypatch.setattr(windows, "verify_peer", verify)
    monkeypatch.setattr(platform, "handoff_token", token)
    assert windows.peer_token(Channel())["pidversion"] == 123456789
    assert observations == ["verify", "token", "verify"]
    monkeypatch.setattr(platform, "handoff_token", lambda pid: {"uid": PEER["uid"], "pidversion": 999})
    with pytest.raises(ConflictError, match="incarnation changed"):
        windows.peer_token(Channel())


@pytest.mark.parametrize("alive", [[True, True], [False], [True, False]])
def test_windows_launch_identity_uses_retained_handle_and_refuses_exit(monkeypatch, alive):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="win32"))
    states = iter(alive)
    handles = []
    monkeypatch.setattr(platform, "_windows_process_active", lambda handle: handles.append(handle) or next(states))
    monkeypatch.setattr(platform, "_windows_identity", lambda pid, handle: dict(PEER))
    monkeypatch.setattr(platform, "process_identity", lambda pid: pytest.fail("numeric PID lookup cannot pin a launch"))
    process = SimpleNamespace(pid=PEER["pid"], _handle=888)
    if all(alive):
        assert platform.handoff_child_identity(process) == PEER
    else:
        with pytest.raises(ProcessLookupError): platform.handoff_child_identity(process)
    assert handles == [888] * len(alive)


def test_windows_retained_workers_explicitly_keep_ancestor_jobs(monkeypatch):
    captured = {}
    class Inheritance:
        def __init__(self, argv, kwargs, descriptors):
            self.argv = argv
            kwargs["startupinfo"] = SimpleNamespace(lpAttributeList={"handle_list": [101]})
        def restore(self): pass
        def authenticate(self, process): pass
        def close(self): pass
    class Job:
        handle = 333
        def assign(self, process): pass
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(platform, "_inherited_job_handle", 444)
    monkeypatch.setattr(platform, "_inherited_ancestor_jobs", [555])
    monkeypatch.setattr(platform, "_Job", Job)
    monkeypatch.setattr(windows, "InheritedHandles", Inheritance)
    monkeypatch.setattr(subprocess, "STARTUPINFO", lambda: SimpleNamespace(lpAttributeList=None), raising=False)
    flags = {333: False, 444: False, 555: False}
    monkeypatch.setattr(os, "get_handle_inheritable", lambda handle: flags[handle], raising=False)
    monkeypatch.setattr(os, "set_handle_inheritable", lambda handle, value: flags.update({handle: value}), raising=False)
    process = SimpleNamespace(pid=52)
    def popen(argv, **kwargs):
        captured.update(kwargs)
        assert all(flags.values())
        return process
    monkeypatch.setattr(subprocess, "Popen", popen)
    monkeypatch.setattr(platform, "_resume_process", lambda pid: None)
    assert platform.spawn_tree([sys.executable, "-m", "target"], pass_fds=(101,)) is process
    assert captured["startupinfo"].lpAttributeList["handle_list"] == [101, 333, 555, 444]
    assert captured["env"]["ASTRID_RUNTIME_ANCESTOR_JOB_HANDLES"] == "555,444"
    assert not any(flags.values())


@pytest.mark.integration
@requires_windows_process_and_lock_apis
def test_windows_retained_worker_survives_original_owner_job_close(tmp_path):
    import time
    marker = tmp_path / "release"
    done = tmp_path / "done"
    worker_code = (
        "import pathlib,sys,time; from runtime_protocol import platform; "
        "s=platform.handoff_adopt_socket(int(sys.argv[1])); s.sendall(b'ready'); "
        "deadline=time.monotonic()+25; marker=pathlib.Path(sys.argv[2]); "
        "\nwhile not marker.exists() and time.monotonic()<deadline: time.sleep(.05)"
        "\npathlib.Path(sys.argv[3]).write_text('exited'); s.close()"
    )
    owner_code = (
        "import json,socket,subprocess,sys; from runtime_protocol import platform; "
        "parent,child=socket.socketpair(); "
        "worker=platform.spawn_tree([sys.executable,'-c',sys.argv[1],str(child.fileno()),sys.argv[2],sys.argv[3]], "
        "pass_fds=(child.fileno(),),close_fds=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
        "child.close(); parent.settimeout(15); assert parent.recv(5)==b'ready'; "
        "print(json.dumps(platform.process_identity(worker.pid)),flush=True); parent.close()"
    )
    owner = platform.spawn_tree([sys.executable, "-c", owner_code, worker_code, str(marker), str(done)],
                               detached=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        output, errors = owner.communicate(timeout=20)
        assert owner.returncode == 0, errors
        expected = json.loads(output)
        owner._runtime_job.close()
        observed = platform.process_identity(expected["pid"])
        assert observed is not None
        assert all(observed[key] == expected[key] for key in windows.IDENTITY_FIELDS)
    finally:
        marker.touch()
        if owner.poll() is None: platform.stop_tree(owner, grace=1)
        owner._runtime_job.close()
    deadline = time.monotonic() + 10
    while not done.exists() and time.monotonic() < deadline:
        time.sleep(.05)
    assert done.read_text() == "exited"


def test_windows_authentication_uses_one_absolute_budget(monkeypatch):
    moments = iter([0.2, 0.8, 1.1])
    monkeypatch.setattr(windows.time, "monotonic", lambda: next(moments))
    channel = Channel(b"abc")
    read = channel.recv
    channel.recv = lambda count: read(1)
    with pytest.raises(TimeoutError, match="authentication timed out"):
        windows.read_exact(channel, 3, deadline=1)
    assert channel.data == b"c"


@pytest.mark.integration
@requires_windows_process_and_lock_apis
def test_windows_launch_reconstructs_inherited_crt_file(tmp_path):
    import tempfile
    with tempfile.TemporaryFile() as binding:
        binding.write(b"sealed-launch-binding"); binding.flush(); binding.seek(0)
        code = "import os,sys; assert os.read(int(sys.argv[1]),64)==b'sealed-launch-binding'"
        process = platform.spawn_tree([sys.executable, "-c", code, str(binding.fileno())],
                                     pass_fds=(binding.fileno(),), close_fds=True)
        try:
            assert process.wait(timeout=15) == 0
        finally:
            try:
                if process.poll() is None: platform.stop_tree(process, grace=1)
            finally:
                process._runtime_job.close()


def test_posix_control_preserves_unexpected_authority_refusal_and_closes_fd(monkeypatch, tmp_path):
    import array
    descriptor = os.open(tmp_path / "authority", os.O_CREAT | os.O_RDWR, 0o600)
    channel = Channel()
    monkeypatch.setattr(platform, "_handoff_transport", lambda: posix_handoff)
    monkeypatch.setattr(platform, "handoff_close", os.close)
    monkeypatch.setattr(socket, "SCM_RIGHTS", 1, raising=False)
    monkeypatch.setattr(socket, "CMSG_SPACE", lambda size: size + 16, raising=False)
    channel.recvmsg = lambda *args: (b"{}\n", [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [descriptor]).tobytes())], 0, None)
    try:
        with pytest.raises(ConflictError, match="unexpected authority"):
            handoff.receive_frame(channel)
        with pytest.raises(OSError): os.fstat(descriptor)
    finally:
        try: os.close(descriptor)
        except OSError: pass


def test_windows_deadline_wrapper_retains_the_authenticated_socket_pin(native_peer):
    channel = Channel()
    windows.pin_peer(channel, native_peer)
    class Deadline:
        _handoff_channel = channel
        def __getattr__(self, name): return getattr(channel, name)
    assert windows.verify_peer(Deadline()) == native_peer


def test_windows_current_venv_uses_the_base_interpreter(monkeypatch):
    monkeypatch.setattr(windows, "sys", SimpleNamespace(executable="selected-python", _base_executable="base-python"))
    assert windows.python_executable("selected-python") == "base-python"


@pytest.mark.parametrize("valid", [True, False])
def test_windows_configured_venv_resolves_base_without_running_redirector(tmp_path, monkeypatch, valid):
    monkeypatch.setattr(windows, "sys", SimpleNamespace(executable="other-python"))
    root = tmp_path / "worker"
    scripts = root / "Scripts"; scripts.mkdir(parents=True)
    base = tmp_path / "base"; base.mkdir()
    if valid: (base / "python.exe").touch()
    (root / "pyvenv.cfg").write_text("home = " + str(base) + "\n", encoding="utf-8")
    if valid:
        assert windows.python_executable(str(scripts / "python.exe")) == str(base / "python.exe")
    else:
        with pytest.raises(ConflictError, match="base Python"):
            windows.python_executable(str(scripts / "python.exe"))


@pytest.mark.integration
@requires_windows_process_and_lock_apis
def test_windows_venv_launch_retains_actual_pid_and_selected_environment(tmp_path):
    import venv
    from runtime_protocol.local_worker_composition import _frame_receive
    root = tmp_path / "worker-venv"
    venv.EnvBuilder(with_pip=False).create(root)
    parent, inherited = socket.socketpair()
    code = (
        "import json,os,socket,sys; s=socket.socket(fileno=int(sys.argv[1])); "
        "s.sendall((json.dumps({'pid':os.getpid(),'prefix':sys.prefix})+'\\n').encode()); "
        "assert s.recv(1)==b'x'"
    )
    process = None
    try:
        process = platform.spawn_tree([str(platform.venv_python(root)), "-c", code, str(inherited.fileno())],
                                     pass_fds=(inherited.fileno(),), close_fds=True)
        inherited.close(); parent.settimeout(15)
        report = _frame_receive(parent)
        assert report["pid"] == process.pid
        assert Path(report["prefix"]) == root
        parent.sendall(b"x")
        assert process.wait(timeout=15) == 0
    finally:
        parent.close(); inherited.close()
        if process is not None:
            try:
                if process.poll() is None: platform.stop_tree(process, grace=1)
            finally:
                process._runtime_job.close()
