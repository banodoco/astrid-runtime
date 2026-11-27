"""Portable failure-path checks and real Darwin provider qualification.

Tests marked darwin_native use actual processes, Mach rights and libproc.
Unmarked fake-native tests check Python cleanup/control flow only and are not
evidence that a Darwin kernel accepted an operation.
"""
from __future__ import annotations

import ctypes
import errno
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

import pytest

from runtime_protocol import darwin_process_binding as darwin
from runtime_protocol import platform


class Function:
    def __init__(self, function):
        self.function = function

    def __call__(self, *args):
        return self.function(*args)


def fake_mach(monkeypatch, *, acquisition=0, port=77, failure=None, release=0):
    """Portable fake, used only to inspect cleanup after each native error."""
    calls = []
    words = [0, 501, 0, 0, 0, 123, 0, 9]
    reads = 0

    def acquire(_self, pid, result):
        calls.append(("acquire", pid))
        result._obj.value = port
        return acquisition

    def info(_port, flavor, output, count):
        nonlocal reads
        reads += 1
        calls.append(("read", reads))
        assert flavor == 15
        if failure == "first" and reads == 1 or failure == "second" and reads == 2:
            return 5
        count._obj.value = 7 if failure == "count" else 8
        result = list(words)
        if failure == "rotation" and reads == 2:
            result[7] += 1
        ctypes.cast(output, ctypes.POINTER(darwin._AuditToken)).contents.value[:] = result
        return 0

    def pid_for_task(_port, output):
        output._obj.value = 124 if failure == "pid" else 123
        return 0

    def deallocate(task, name):
        calls.append(("release", task, name))
        return release

    library = SimpleNamespace(
        task_name_for_pid=Function(acquire), task_info=Function(info),
        pid_for_task=Function(pid_for_task), mach_port_deallocate=Function(deallocate),
    )
    monkeypatch.setattr(darwin, "sys", SimpleNamespace(platform="darwin", byteorder=sys.byteorder))
    monkeypatch.setattr(darwin, "_mach_library", lambda: (library, 1))
    monkeypatch.setattr(darwin, "details", lambda values: {
        "pid": values[5], "uid": values[1], "pidversion": values[7], "sha256": str(values),
    })
    return calls


def test_provider_import_is_stdlib_only():
    root = Path(__file__).resolve().parents[1]
    code = (
        "import sys; sys.path.insert(0, " + repr(str(root)) + "); "
        "from runtime_protocol import darwin_process_binding; "
        "assert not any(n == 'astrid_runtime' or n.startswith('astrid_runtime.') "
        "or n == 'astrid' or n.startswith('astrid.') for n in sys.modules)"
    )
    result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_original_darwin_constants_and_checked_abi(monkeypatch):
    assert (darwin.SOL_LOCAL, darwin.LOCAL_PEERTOKEN, darwin.TOKEN_BYTES) == (0, 6, 32)
    assert (darwin.TASK_AUDIT_TOKEN, darwin.TASK_AUDIT_TOKEN_COUNT) == (15, 8)
    assert (darwin.DARWIN_POSIX_SPAWN_SETEXEC, darwin.DARWIN_POSIX_SPAWN_START_SUSPENDED) == (0x40, 0x80)
    assert darwin.DARWIN_SIGCONT == 19 and darwin.DARWIN_SIGUSR1 == 30
    assert darwin.ROTATES_ON_EXEC is True
    assert darwin.PRIMITIVE == "proc_signal_with_audittoken"
    assert ctypes.sizeof(darwin._DarwinBSDInfo) == 136
    monkeypatch.setattr(darwin, "sys", SimpleNamespace(platform="darwin", byteorder=sys.byteorder))
    darwin._check_darwin_census_abi()
    monkeypatch.setattr(darwin, "sys", SimpleNamespace(platform="darwin", byteorder="big"))
    with pytest.raises(darwin.DarwinBindingError, match="ABI"):
        darwin._check_darwin_census_abi()


@pytest.mark.parametrize("words", [[], [1] * 7, [1] * 9, [True] * 8, [-1] * 8, [2**32] * 8, ["1"] * 8])
def test_malformed_token_words_are_rejected(words):
    with pytest.raises(darwin.DarwinBindingError, match="token"):
        darwin._token_from_words(words)


@pytest.mark.parametrize("failure", ["first", "second", "count", "pid", "rotation"])
def test_capture_failure_releases_exactly_one_right(monkeypatch, failure):
    calls = fake_mach(monkeypatch, failure=failure)
    with pytest.raises(darwin.NativeTokenCaptureError) as caught:
        darwin.token(123)
    assert caught.value.capture_failure["port_acquired"] is True
    assert caught.value.capture_failure["port_release_succeeded"] is True
    assert [item for item in calls if item[0] == "release"] == [("release", 1, 77)]


@pytest.mark.parametrize("result,port,narrow", [(5, 0, True), (0, 0, False), (5, 77, False)])
def test_task_name_denial_is_distinct_from_failure_after_acquisition(monkeypatch, result, port, narrow):
    calls = fake_mach(monkeypatch, acquisition=result, port=port)
    with pytest.raises(darwin.NativeTokenCaptureError) as caught:
        darwin.token(123)
    assert isinstance(caught.value, darwin.TaskNameUnavailable) is narrow
    assert [item for item in calls if item[0] == "release"] == ([] if not port else [("release", 1, port)])


def test_primary_capture_error_preserves_release_failure(monkeypatch):
    calls = fake_mach(monkeypatch, failure="first", release=17)
    with pytest.raises(darwin.NativeTokenCaptureError) as caught:
        darwin.token(123)
    assert caught.value.capture_failure["substage"] == "task_info_first"
    assert caught.value.capture_failure["port_release_succeeded"] is False
    assert caught.value.port_release_error.capture_failure["substage"] == "mach_port_deallocate"
    assert [item[0] for item in calls].count("release") == 1


def test_successful_observation_does_not_hide_release_failure(monkeypatch):
    fake_mach(monkeypatch, release=17)
    with pytest.raises(darwin.NativeTokenCaptureError) as caught:
        darwin.token(123)
    assert caught.value.capture_failure["substage"] == "mach_port_deallocate"


@pytest.mark.parametrize("used", [1, 100000000])
def test_census_refuses_partial_or_over_capacity_native_result(monkeypatch, used):
    monkeypatch.setattr(darwin, "sys", SimpleNamespace(platform="darwin", byteorder=sys.byteorder))

    def sysctl(_mib, _length, output, size, _new, _new_size):
        size._obj.value = ctypes.sizeof(darwin._DarwinKInfoProc) if output is None else used
        return 0

    monkeypatch.setattr(darwin.ctypes, "CDLL", lambda *_a, **_kw: SimpleNamespace(sysctl=Function(sysctl)))
    with pytest.raises(darwin.DarwinBindingError, match="truncated"):
        darwin._darwin_process_records()


@pytest.mark.parametrize("signum", [0, 1, 19, -1, True, "15", 15.0])
def test_disallowed_signal_never_reaches_native_syscall(monkeypatch, signum):
    monkeypatch.setattr(darwin, "_send_signal", lambda *_: pytest.fail("unexpected native signal"))
    with pytest.raises(darwin.DarwinBindingError, match="admitted"):
        darwin.signal([0] * 8, signum)


def test_words_alone_never_create_signal_or_resume_authority(monkeypatch):
    monkeypatch.setattr(darwin, "_send_signal", lambda *_: pytest.fail("unexpected native signal"))
    with pytest.raises(darwin.DarwinBindingError, match="retained native authority"):
        darwin.signal([0] * 8, 15)
    with pytest.raises(darwin.DarwinBindingError, match="owned child"):
        darwin.resume_once({"words": [0] * 8})


def test_signal_enum_uses_the_same_admission_contract():
    with pytest.raises(darwin.DarwinBindingError, match="retained native authority"):
        darwin.signal([0] * 8, signal.SIGTERM)


def test_same_task_token_rotation_never_silently_refreshes_peer(monkeypatch):
    row = {"pid": 123, "uid": 501, "parent_pid": 1, "start_sec": 12345, "start_usec": 6, "status": 2}
    before = {"pid": 123, "uid": 501, "pidversion": 7, "sha256": "before", "words": [7] * 8}
    after = {**before, "pidversion": 8, "sha256": "after", "words": [8] * 8}
    native = SimpleNamespace(read=lambda: after, close=lambda: None)
    monkeypatch.setattr(darwin, "_live", lambda _pid: dict(row))
    handle = darwin.PeerHandle(native, row, before, _factory=darwin._FACTORY)
    try:
        with pytest.raises(darwin.DarwinBindingError, match="rotated"):
            handle.verify()
        assert handle.token == before
        copy = handle.token
        copy["words"][0] = 999
        assert handle.token["words"][0] == 7
    finally:
        handle.close()


def test_failed_resume_attempt_is_consumed_before_call(monkeypatch):
    handle = object.__new__(darwin.OwnedChildHandle)
    handle._lock = threading.RLock()
    handle._reap_guard, handle._wait_guard = threading.Lock(), threading.Lock()
    handle._resume_consumed = False
    handle._check_child_locked = lambda: {"status": 4}
    handle._verify_locked = lambda: {"words": [0] * 8}
    sent = []

    def refuse(words, signum):
        sent.append(signum)
        assert handle._resume_consumed
        raise darwin.AuditTokenSignalError(errno.ESRCH, 0)

    monkeypatch.setattr(darwin, "_send_signal", refuse)
    with pytest.raises(darwin.AuditTokenSignalError):
        darwin.resume_once(handle)
    with pytest.raises(darwin.DarwinBindingError, match="already consumed"):
        darwin.resume_once(handle)
    assert sent == [19]


@pytest.mark.parametrize("failure", ["init", "flags", "spawn", "return", "destroy"])
def test_suspended_setexec_releases_initialized_attributes(monkeypatch, failure):
    calls = []
    monkeypatch.setattr(darwin, "sys", SimpleNamespace(platform="darwin", byteorder=sys.byteorder))

    def flags(_attr, value):
        calls.append(("flags", value.value))
        return errno.EINVAL if failure == "flags" else 0

    library = SimpleNamespace(
        posix_spawnattr_init=Function(lambda _attr: errno.ENOMEM if failure == "init" else 0),
        posix_spawnattr_setflags=Function(flags),
        posix_spawnattr_destroy=Function(lambda _attr: calls.append(("destroy",)) or (errno.EINVAL if failure == "destroy" else 0)),
        posix_spawn=Function(lambda *_args: errno.ENOENT if failure == "spawn" else 0),
    )
    monkeypatch.setattr(darwin.ctypes, "CDLL", lambda *_a, **_kw: library)
    with pytest.raises((OSError, darwin.DarwinBindingError)) as caught:
        darwin.setexec_suspended(["/missing"], {"A": "B"})
    assert [item for item in calls if item[0] == "destroy"] == ([] if failure == "init" else [("destroy",)])
    if failure != "init":
        assert ("flags", 0x40 | 0x80) in calls
    if failure == "destroy":
        assert caught.value.spawnattr_release_error.errno == errno.EINVAL


def _recv_exact(channel, count):
    result = bytearray()
    while len(result) < count:
        part = channel.recv(count - len(result))
        assert part, "native socket closed before complete readiness"
        result.extend(part)
    return bytes(result)


def _line(child, timeout=8):
    assert select.select([child.stdout], [], [], timeout)[0], "native child readiness timed out"
    line = child.stdout.readline()
    if not line:
        child.wait(timeout=timeout)
        pytest.fail("native child exited before readiness: " + child.stderr.read())
    return line.strip()


def _finish(child):
    if child.poll() is None:
        try:
            child.stdin.write("finish\n")
            child.stdin.flush()
            child.wait(timeout=8)
        except (BrokenPipeError, subprocess.TimeoutExpired):
            # Fixture cleanup targets only this directly owned, unreaped child.
            child.kill()
            child.wait(timeout=8)
    for stream in (child.stdin, child.stdout, child.stderr):
        stream.close()


def _child(code, *arguments):
    return subprocess.Popen([sys.executable, "-c", code, *map(str, arguments)],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True)


def _send(child, text):
    child.stdin.write(text + "\n")
    child.stdin.flush()


def _right_refs(native):
    reader = native.library.mach_port_get_refs
    reader.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int, ctypes.POINTER(ctypes.c_uint32)]
    reader.restype = ctypes.c_int
    count = ctypes.c_uint32()
    assert reader(native.task_self, native.port, 0, ctypes.byref(count)) == 0  # MACH_PORT_RIGHT_SEND
    return count.value


@pytest.mark.darwin_native
def test_native_token_identity_census_and_port_release():
    from astrid_runtime import custody_broker
    actual = darwin.identity(os.getpid())
    assert actual == platform.process_identity(os.getpid())
    assert actual["parent_pid"] == os.getppid()
    rows = darwin._darwin_process_records(os.getpid())
    assert len(rows) == 1
    assert rows[0]["uid"] == os.getuid()
    assert darwin._ps_lstart_birth(rows[0]["start_sec"]) == actual["birth_id"]
    census = darwin._darwin_process_records()
    assert any(row["pid"] == os.getpid() for row in census)
    with darwin._MachTask(os.getpid()) as retained:
        count = _right_refs(retained)
        for _ in range(16):
            observed = darwin.token(os.getpid())
            assert observed == custody_broker.current_process_audit_token(os.getpid())
            assert darwin.details(observed["words"]) == {key: observed[key] for key in ("pid", "uid", "pidversion", "sha256")}
        assert _right_refs(retained) == count


@pytest.mark.darwin_native
def test_native_child_origin_peer_mismatch_signal_and_close():
    with tempfile.TemporaryDirectory(prefix="p38-d-", dir="/private/tmp") as root:
        path = Path(root) / "s"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path)); listener.listen(1); listener.settimeout(8)
            child = _child("import socket,sys; s=socket.socket(socket.AF_UNIX); "
                           "s.connect(sys.argv[1]); s.sendall(b'ready'); sys.stdin.readline()", path)
            handle = None
            try:
                accepted, _ = listener.accept()
                with accepted:
                    assert _recv_exact(accepted, 5) == b"ready"
                    expected = darwin.identity(child.pid)
                    with darwin._MachTask(child.pid) as anchor:
                        count = _right_refs(anchor)
                        for field, value in (("pid", os.getpid()), ("uid", expected["uid"] + 1),
                                             ("birth_id", expected["birth_id"] + "-wrong")):
                            with pytest.raises(darwin.DarwinBindingError, match="expected"):
                                darwin.retain_peer(accepted, expected={**expected, field: value})
                            assert _right_refs(anchor) == count
                    handle = darwin.retain_peer(accepted, expected=expected)
                assert handle.verify(expected)["pid"] == child.pid
                with pytest.raises(darwin.DarwinBindingError, match="admitted"):
                    handle.signal(19)
                handle.signal(15)
                assert child.wait(timeout=8) == -signal.SIGTERM
                with pytest.raises(darwin.DarwinBindingError, match="absent|exited|unavailable"):
                    handle.verify(expected)
                handle.close(); handle.close()
                with pytest.raises(darwin.DarwinBindingError, match="closed"):
                    handle.signal(15)
            finally:
                if handle is not None:
                    handle.close()
                _finish(child)


@pytest.mark.darwin_native
def test_native_peer_exec_refuses_while_owned_child_can_explicitly_refresh():
    with tempfile.TemporaryDirectory(prefix="p38-d-", dir="/private/tmp") as root:
        path = Path(root) / "s"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path)); listener.listen(1); listener.settimeout(8)
            second = ("import socket,sys; s=socket.socket(fileno=int(sys.argv[1])); "
                      "s.sendall(b'exec'); print('exec-ready',flush=True); sys.stdin.readline()")
            code = ("import os,socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); "
                    "s.set_inheritable(True); s.sendall(b'ready'); print('ready',flush=True); "
                    "sys.stdin.readline(); os.execv(sys.executable,[sys.executable,'-c',"
                    + repr(second) + ",str(s.fileno())])")
            child = _child(code, path)
            owned = peer = accepted = None
            try:
                accepted, _ = listener.accept()
                accepted.settimeout(8)
                assert _recv_exact(accepted, 5) == b"ready" and _line(child) == "ready"
                expected = darwin.identity(child.pid)
                owned = darwin.retain_child(child, reap_guard=threading.Lock(), expected=expected)
                peer = darwin.retain_peer(accepted, expected=expected)
                before = owned.token
                with pytest.raises(darwin.DarwinBindingError, match="not suspended"):
                    darwin.resume_once(owned)
                _send(child, "exec")
                assert _recv_exact(accepted, 4) == b"exec" and _line(child) == "exec-ready"
                assert darwin.peer_token(accepted)["pidversion"] != before["pidversion"]
                with pytest.raises(darwin.DarwinBindingError):
                    peer.verify(expected)
                with pytest.raises(darwin.DarwinBindingError):
                    peer.signal(15)
                after = owned.refresh_after_exec()
                assert after["pid"] == before["pid"] and after["uid"] == before["uid"]
                assert after["pidversion"] != before["pidversion"]
                assert owned.identity == expected
                with pytest.raises(darwin.DarwinBindingError, match="differs"):
                    darwin.signal(before["words"], 15, authority=owned)
                owned.signal(15)
                assert child.wait(timeout=8) == -signal.SIGTERM
                with pytest.raises(darwin.DarwinBindingError):
                    owned.refresh_after_exec()
                with pytest.raises(darwin.DarwinBindingError, match="absent|exited"):
                    darwin.retain_child(child, reap_guard=threading.Lock())
            finally:
                for handle in (owned, peer):
                    if handle is not None:
                        handle.close()
                if accepted is not None:
                    accepted.close()
                _finish(child)


@pytest.mark.darwin_native
def test_native_carried_endpoint_changes_observation_but_not_retained_peer():
    source, other = socket.socketpair()
    child = handle = None
    try:
        other.sendall(b"parent")
        assert _recv_exact(source, 6) == b"parent"
        expected = darwin.identity(os.getpid())
        handle = darwin.retain_peer(source, expected=expected)
        original = handle.token
        child = subprocess.Popen(
            [sys.executable, "-c", "import socket,sys; s=socket.socket(fileno=int(sys.argv[1])); "
             "s.sendall(b'child'); print('ready',flush=True); sys.stdin.readline()", str(other.fileno())],
            pass_fds=(other.fileno(),), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        source.settimeout(8)
        assert _recv_exact(source, 5) == b"child" and _line(child) == "ready"
        assert darwin.peer_token(source)["pid"] == child.pid
        assert handle.verify(expected) == original
        with pytest.raises(darwin.DarwinBindingError, match="expected"):
            handle.verify(darwin.identity(child.pid))
        assert handle.token == original
    finally:
        if handle is not None:
            handle.close()
        source.close(); other.close()
        if child is not None:
            _finish(child)


@pytest.mark.darwin_native
def test_native_suspended_setexec_executes_user_code_only_after_one_resume(tmp_path):
    marker = tmp_path / "user-code-ran"
    target = ("from pathlib import Path; import sys; Path(" + repr(str(marker)) + ").write_text('ran'); "
              "print('running',flush=True); sys.stdin.readline()")
    wrapper = ("import os,sys; from runtime_protocol.darwin_process_binding import setexec_suspended; "
               "print('wrapper',flush=True); sys.stdin.readline(); "
               "setexec_suspended([sys.executable,'-c'," + repr(target) + "],dict(os.environ))")
    child = _child(wrapper)
    owned = None
    try:
        assert _line(child) == "wrapper"
        owned = darwin.retain_child(child, reap_guard=threading.Lock())
        old = owned.token
        _send(child, "launch")
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            row = darwin.read_process_info(child.pid, include_exit=True)
            if row is not None and row["status"] == 4:
                break
            time.sleep(0.01)
        else:
            pytest.fail("SETEXEC child did not reach the native stopped state")
        assert not marker.exists()
        current = owned.refresh_after_exec()
        assert current["pidversion"] != old["pidversion"]
        assert not marker.exists()
        darwin.resume_once(owned)
        assert _line(child) == "running"
        assert marker.read_text() == "ran"
        with pytest.raises(darwin.DarwinBindingError, match="already consumed"):
            darwin.resume_once(owned)
    finally:
        if owned is not None:
            owned.close()
        _finish(child)

