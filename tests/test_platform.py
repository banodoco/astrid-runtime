from __future__ import annotations

import ast
import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.lanes import (
    requires_posix_private_modes,
    requires_posix_process_groups,
    requires_windows_job_object,
    requires_windows_token_process_times,
)

from runtime_protocol import platform


@pytest.mark.parametrize("stdin", ["omitted", None])
def test_spawn_tree_defaults_missing_stdin_to_devnull(monkeypatch, stdin):
    calls = []

    def popen(_argv, **kwargs):
        calls.append(kwargs)
        return object()

    monkeypatch.setattr(platform.sys, "platform", "linux")
    monkeypatch.setattr(platform.subprocess, "Popen", popen)
    kwargs = {} if stdin == "omitted" else {"stdin": stdin}
    platform.spawn_tree(["child"], **kwargs)
    assert calls[0]["stdin"] == subprocess.DEVNULL


@pytest.mark.parametrize("stdin", [subprocess.PIPE, subprocess.DEVNULL])
def test_spawn_tree_preserves_explicit_stdin(monkeypatch, stdin):
    calls = []

    def popen(_argv, **kwargs):
        calls.append(kwargs)
        return object()

    monkeypatch.setattr(platform.sys, "platform", "linux")
    monkeypatch.setattr(platform.subprocess, "Popen", popen)
    platform.spawn_tree(["child"], stdin=stdin)
    assert calls[0]["stdin"] == stdin


@pytest.mark.parametrize("stdin", ["omitted", None, subprocess.PIPE])
def test_spawn_tree_windows_dispatch_applies_or_preserves_stdin(monkeypatch, stdin):
    calls = []
    process = object()

    def spawn(_argv, **kwargs):
        calls.append(kwargs)
        return process

    monkeypatch.setattr(platform.sys, "platform", "win32")
    monkeypatch.setattr(platform, "_spawn_windows_tree", spawn)
    kwargs = {} if stdin == "omitted" else {"stdin": stdin}
    assert platform.spawn_tree(["child"], **kwargs) is process
    expected = subprocess.DEVNULL if stdin in ("omitted", None) else stdin
    assert calls[0]["stdin"] == expected


def test_spawn_tree_preserves_explicit_stdin_file_and_descriptor(monkeypatch, tmp_path):
    calls = []

    def popen(_argv, **kwargs):
        calls.append(kwargs)
        return object()

    monkeypatch.setattr(platform.sys, "platform", "linux")
    monkeypatch.setattr(platform.subprocess, "Popen", popen)
    path = tmp_path / "stdin.txt"
    path.write_text("input")
    with path.open("rb") as stream:
        platform.spawn_tree(["child"], stdin=stream)
        assert calls[-1]["stdin"] is stream
        platform.spawn_tree(["child"], stdin=stream.fileno())
        assert calls[-1]["stdin"] == stream.fileno()


def test_runtime_direct_subprocess_runs_do_not_inherit_stdin():
    from pathlib import Path

    root = Path(__file__).parents[1] / "runtime_protocol"
    unsafe = []
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "run" and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "subprocess"):
                continue
            keywords = {item.arg: item.value for item in node.keywords if item.arg is not None}
            if "input" in keywords:
                continue
            stdin = keywords.get("stdin")
            is_none = isinstance(stdin, ast.Constant) and stdin.value is None
            if stdin is None or is_none:
                unsafe.append(f"{path.relative_to(root)}:{node.lineno}")
    assert unsafe == []


def test_windows_durable_replace_retries_only_transient_sharing_failures(monkeypatch):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="win32"))
    attempts = []
    failures = iter((5, 32, None))

    def move(source, destination):
        attempts.append((source, destination))
        code = next(failures)
        if code is not None:
            error = OSError("transient Windows replace failure")
            error.winerror = code
            raise error

    monkeypatch.setattr(platform, "_move_file_write_through", move)
    monkeypatch.setattr(platform.time, "sleep", lambda _delay: None)
    assert platform.durable_replace("temporary", "destination") is None
    assert attempts == [("temporary", "destination")] * 3


def test_windows_durable_replace_does_not_retry_permanent_errors(monkeypatch):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="win32"))
    attempts = []

    def move(_source, _destination):
        attempts.append(1)
        raise PermissionError("permanent failure")

    monkeypatch.setattr(platform, "_move_file_write_through", move)
    with pytest.raises(PermissionError):
        platform.durable_replace("temporary", "destination")
    assert attempts == [1]


def test_windows_move_uses_write_through_replace_flags(monkeypatch):
    calls = []

    class Move:
        argtypes = None
        restype = None

        def __call__(self, source, destination, flags):
            calls.append((source, destination, flags))
            return 1

    class Kernel:
        MoveFileExW = Move()

    monkeypatch.setattr(platform.ctypes, "WinDLL", lambda *_args, **_kwargs: Kernel(), raising=False)
    platform._move_file_write_through("source", "destination")
    assert calls == [("source", "destination", 0x1 | 0x8)]


def test_posix_durable_replace_fsyncs_both_parent_directories(monkeypatch, tmp_path):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="linux"))
    calls = []
    monkeypatch.setattr(platform.os, "replace", lambda _source, _destination: None)
    monkeypatch.setattr(platform, "fsync_directory", calls.append)
    platform.durable_replace(tmp_path / "source" / "file", tmp_path / "destination" / "file")
    assert set(calls) == {tmp_path / "source", tmp_path / "destination"}


def test_windows_directory_durability_helper_is_best_effort_noop(monkeypatch, tmp_path):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="win32"))
    with monkeypatch.context() as patch:
        patch.setattr(platform.os, "open", lambda *_a, **_k: pytest.fail("Windows must not open directory for fsync"))
        platform.fsync_directory(tmp_path)


@pytest.mark.parametrize("os_name", ["darwin", "linux", "win32"])
def test_native_data_and_log_roots_use_os_default_and_injected_home(monkeypatch, tmp_path, os_name):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform=os_name))
    home = tmp_path / "home"
    local_app_data = tmp_path / "user-local"
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg-state"))
    if os_name == "darwin":
        assert platform.data_root(home) == home / "Library/Application Support/Astrid Runtime"
        assert platform.log_dir(home) == home / "Library/Logs/Astrid Runtime"
    elif os_name == "linux":
        assert platform.data_root(home) == tmp_path / "xdg-data/astrid-runtime"
        assert platform.log_dir(home) == tmp_path / "xdg-state/astrid-runtime/logs"
    else:
        assert platform.data_root(home) == local_app_data / "Astrid Runtime"
        assert platform.log_dir(home) == local_app_data / "Astrid Runtime/logs"


def test_linux_data_and_log_roots_fall_back_to_injected_home(monkeypatch, tmp_path):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    home = tmp_path / "home"
    assert platform.data_root(home) == home / ".local/share/astrid-runtime"
    assert platform.log_dir(home) == home / ".local/state/astrid-runtime/logs"


def test_windows_roots_fall_back_to_injected_home(monkeypatch, tmp_path):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    home = tmp_path / "home"
    assert platform.data_root(home) == home / "AppData/Local/Astrid Runtime"
    assert platform.log_dir(home) == home / "AppData/Local/Astrid Runtime/logs"


@requires_posix_private_modes
def test_owner_only_applies_and_checks_private_file_and_directory_modes(tmp_path):
    file_path = tmp_path / "secret"
    file_path.write_text("secret")
    directory = tmp_path / "private"
    directory.mkdir()
    platform.owner_only(file_path)
    platform.owner_only(directory, directory=True)
    assert platform.is_owner_only(file_path)
    assert platform.is_owner_only(file_path.stat())
    assert platform.is_owner_only(directory, directory=True)
    if sys.platform != "win32":
        assert file_path.stat().st_mode & 0o777 == 0o600
        assert directory.stat().st_mode & 0o777 == 0o700
    file_path.chmod(0o640)
    assert not platform.is_owner_only(file_path)


def test_file_lock_excludes_contender_and_releases(tmp_path):
    lock_path = tmp_path / "owner.lock"
    with platform.file_lock(lock_path, blocking=True):
        with pytest.raises(BlockingIOError):
            with platform.file_lock(lock_path, blocking=False):
                pytest.fail("contender acquired a held lock")
    with platform.file_lock(lock_path, blocking=False):
        pass


def test_current_process_identity_is_stable_and_has_native_fields():
    identity = platform.process_identity(os.getpid())
    assert identity is not None
    assert identity["pid"] == os.getpid()
    assert identity["uid"] == platform.current_user()
    assert identity["birth_id"]


def test_linux_proc_identity_parser_uses_stat_and_brackets_start_tick(monkeypatch):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="linux"))
    reads = []
    start_ticks = ["4242", "4242"]

    class FakePath:
        def __init__(self, value):
            self.value = str(value)
        def __truediv__(self, part):
            return FakePath(self.value.rstrip("/") + "/" + str(part))
        def read_text(self):
            if self.value.endswith("boot_id"):
                return "test-boot"
            reads.append(self.value)
            if self.value == "/proc/sys/kernel/random/boot_id":
                return "b38142f7-84c5-487d-95a4-8180cbff3972\n"
            tick = start_ticks[min(len(reads) - 1, 1)]
            fields = ["S", "23", "24", "25"] + ["0"] * 15 + [tick, "0"]
            return "77 (worker ) with parens) " + " ".join(fields)
        def stat(self):
            return SimpleNamespace(st_uid=501, st_ino=1234)

    monkeypatch.setattr(platform, "Path", FakePath)
    value = platform.process_identity(77)
    assert value["pid"] == 77
    assert value["uid"] == 501
    assert value["parent_pid"] == 23
    assert value["process_group"] == 24
    assert value["session_id"] == 25
    assert value["birth_id"] == "proc-start-ticks:4242;boot:test-boot;pidns:1234"
    assert len(reads) == 2


def test_linux_proc_identity_rejects_pid_reuse_during_observation(monkeypatch):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="linux"))
    ticks = iter(("4242", "4243"))

    class FakePath:
        def __init__(self, value): self.value = str(value)
        def __truediv__(self, part): return FakePath(self.value.rstrip("/") + "/" + str(part))
        def read_text(self):
            if self.value.endswith("boot_id"):
                return "test-boot"
            fields = ["S", "23", "24", "25"] + ["0"] * 15 + [next(ticks), "0"]
            return "77 (worker) " + " ".join(fields)
        def stat(self): return SimpleNamespace(st_uid=501, st_ino=1234)

    monkeypatch.setattr(platform, "Path", FakePath)
    with pytest.raises(OSError, match="changed"):
        platform.process_identity(77)


@pytest.mark.parametrize("boot_id,tick", [
    (None, "4242"), ("", "4242"), ("corrupt", "4242"),
    ("b38142f7-84c5-487d-95a4-8180cbff3972", "corrupt"),
])
def test_linux_proc_identity_refuses_unknown_boot_or_start_tick(tmp_path, monkeypatch, boot_id, tick):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="linux"))
    proc = tmp_path / "proc"
    (proc / "77").mkdir(parents=True)
    fields = ["S", "23", "24", "25"] + ["0"] * 15 + [tick, "0"]
    (proc / "77" / "stat").write_text("77 (worker) " + " ".join(fields))
    boot = tmp_path / "boot_id"
    if boot_id is not None:
        boot.write_text(boot_id)
    monkeypatch.setattr(platform, "Path", lambda path: boot if str(path).endswith("boot_id") else proc)
    if tick == "corrupt":
        with pytest.raises(OSError):
            platform.process_identity(77)
    else:
        identity = platform.process_identity(77)
        assert platform.process_birth_matches(identity["birth_id"], identity["birth_id"]) is None


@pytest.mark.parametrize("birth_id", [
    "e1a239c5-fbdb-4c06-b924-6f0479e69568:4242",  # Same PID/tick, prior boot.
    "b38142f7-84c5-487d-95a4-8180cbff3972:4243",  # Reused PID.
    "proc-start-ticks:4242", "corrupt",
])
def test_linux_signal_refuses_mismatched_birth_before_kernel_signal(monkeypatch, birth_id):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="linux"))
    observed = {"pid": 77, "uid": 501, "birth_id": "b38142f7-84c5-487d-95a4-8180cbff3972:4242"}
    opened, closed = [], []
    monkeypatch.setattr(platform.os, "pidfd_open", lambda pid: opened.append(pid) or 99, raising=False)
    monkeypatch.setattr(platform.os, "close", closed.append)
    monkeypatch.setattr(platform.signal, "pidfd_send_signal", lambda *_: pytest.fail("mismatched birth signaled"), raising=False)
    monkeypatch.setattr(platform, "process_identity", lambda pid: observed)
    with pytest.raises(OSError, match="incarnation changed"):
        platform.signal_process({**observed, "birth_id": birth_id}, platform.TERM)
    assert opened == [77]
    assert closed == [99]


def test_darwin_identity_keeps_legacy_birth_marker_and_brackets_native_observation(monkeypatch):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="darwin"))
    seconds = int(time.mktime((2026, 10, 9, 18, 21, 21, 0, 0, -1)))
    observation = {"pid": 123, "uid": 501, "parent_pid": 41, "start_sec": seconds, "start_usec": 123456}
    rows = iter((observation, dict(observation)))
    monkeypatch.setattr(platform, "_read_darwin_process_info", lambda _pid: next(rows))
    value = platform.process_identity(123)
    assert value == {
        "pid": 123, "uid": 501, "parent_pid": 41,
        "birth_id": "ps-lstart:Fri Oct  9 18:21:21 2026",
    }


def test_darwin_identity_only_proves_absence_from_native_esrch(monkeypatch):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(platform, "_read_darwin_process_info", lambda _pid: None)
    assert platform.process_identity(123) is None
    monkeypatch.setattr(platform, "_read_darwin_process_info", lambda _pid: (_ for _ in ()).throw(PermissionError("denied")))
    with pytest.raises(PermissionError):
        platform.process_identity(123)


@requires_windows_token_process_times
def test_windows_current_user_and_get_process_times_identity():
    assert platform.current_user() > 0
    identity = platform.process_identity(os.getpid())
    assert identity["uid"] == platform.current_user()
    assert identity["birth_id"].startswith("windows-creation:")


@pytest.mark.integration
@requires_posix_process_groups
def test_stop_tree_cleans_up_grandchild(tmp_path):
    from runtime_protocol.platform import spawn_tree, stop_tree
    pid_file = tmp_path / "grandchild.pid"
    child_code = "import time; time.sleep(60)"
    parent_code = (
        "import subprocess,sys,time,pathlib; "
        f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
        f"pathlib.Path({str(pid_file)!r}).write_text(str(p.pid)); time.sleep(60)"
    )
    process = spawn_tree([sys.executable, "-c", parent_code], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 5
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(.02)
        assert pid_file.exists()
        grandchild = int(pid_file.read_text())
    finally:
        stop_tree(process, grace=.1)
    _wait_absent(grandchild)


@pytest.mark.integration
@requires_windows_job_object
def test_windows_job_close_kills_grandchild(tmp_path):
    from runtime_protocol.platform import spawn_tree
    pid_file = tmp_path / "grandchild.pid"
    child_code = "import time; time.sleep(60)"
    parent_code = (
        "import subprocess,sys,time,pathlib; "
        f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
        f"pathlib.Path({str(pid_file)!r}).write_text(str(p.pid)); time.sleep(60)"
    )
    process = spawn_tree([sys.executable, "-c", parent_code], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 5
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(.02)
        assert pid_file.exists()
        grandchild = int(pid_file.read_text())
    finally:
        process._runtime_job.close()
        process.wait(timeout=5)
    _wait_absent(grandchild)


def _wait_absent(pid):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if platform.process_identity(pid) is None:
            return
        time.sleep(.02)
    pytest.fail(f"process {pid} outlived its owned tree")


def test_windows_service_stop_uses_stdin_eof_then_job_cleanup(monkeypatch):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="win32"))
    job = SimpleNamespace(handle=1, close=Mock(), active_processes=lambda: 0)
    channel = Mock()
    process = SimpleNamespace(pid=1234, args=["service"], stdin=channel, _runtime_job=job,
        poll=Mock(return_value=None),
        wait=Mock(side_effect=[subprocess.TimeoutExpired("service", 1), None]))
    events = []
    monkeypatch.setattr(platform, "signal_tree", lambda _process, signum: events.append(signum))
    monkeypatch.setattr(platform.time, "monotonic", lambda: 10.0)
    monkeypatch.setattr(platform.time, "sleep", lambda delay: events.append(("grace", delay)))
    platform.stop_tree(process, grace=1, stop_channel=True)
    channel.close.assert_called_once_with()
    assert events == [("grace", 1.0), platform.KILL]
    assert process.wait.call_count == 2
    job.close.assert_called_once_with()


@pytest.mark.parametrize("leader_exited", [False, True])
def test_linux_service_grace_expires_before_forcing_remaining_group(monkeypatch, leader_exited):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="linux"))
    now, events = [0.0], []
    process = SimpleNamespace(pid=1234, returncode=None,
        stdin=SimpleNamespace(close=lambda: events.append("eof")), wait=Mock())
    monkeypatch.setattr(platform, "os", SimpleNamespace(
        waitid=lambda *args: object() if leader_exited else None,
        P_PID=1, WEXITED=4, WNOHANG=1, WNOWAIT=16))
    monkeypatch.setattr(platform, "_signal_linux_group", lambda child, sig: events.append((sig, now[0])))
    monkeypatch.setattr(platform.time, "monotonic", lambda: now[0])
    def sleep(delay):
        assert delay > 0, "shutdown must escalate when its grace deadline expires"
        now[0] += delay
    monkeypatch.setattr(platform.time, "sleep", sleep)
    platform.stop_tree(process, grace=0.15, stop_channel=True)
    assert events[0] == "eof"
    assert events[1] == (platform.TERM, 0.0)
    assert events[2][0] == platform.KILL
    assert events[2][1] == pytest.approx(0.15)
    process.wait.assert_called_once_with(timeout=2.0)


def test_darwin_service_stop_signals_group_after_leader_exit(monkeypatch):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="darwin"))
    events = []
    process = SimpleNamespace(pid=1234, returncode=None,
        stdin=SimpleNamespace(close=lambda: events.append("eof")), wait=Mock())
    monkeypatch.setattr(platform, "_darwin_tree_exited", lambda child: True)
    monkeypatch.setattr(platform, "signal_tree", lambda child, sig: events.append(sig))
    monkeypatch.setattr(platform.time, "sleep", lambda delay: events.append(("grace", delay)))
    platform.stop_tree(process, grace=0.15, stop_channel=True)
    assert events == ["eof", platform.TERM, ("grace", 0.15), platform.KILL]
    process.wait.assert_called_once_with(timeout=2.0)


def _spawn_group_leader(code):
    from runtime_protocol.platform import spawn_tree
    return spawn_tree([sys.executable, "-c", code], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _deny_killpg(monkeypatch):
    def deny(_pgid, _signum):
        raise PermissionError(1, "Operation not permitted")
    monkeypatch.setattr(platform.os, "killpg", deny)


@requires_posix_process_groups
def test_eperm_from_group_holding_only_a_zombie_leader_means_group_gone(monkeypatch):
    process = _spawn_group_leader("pass")
    try:
        while not platform.tree_exited(process):  # leader exited, left unreaped
            time.sleep(.01)
        _deny_killpg(monkeypatch)
        with pytest.raises(ProcessLookupError):
            platform._signal_posix_group(process.pid, signal.SIGKILL)
    finally:
        monkeypatch.undo()
        platform.stop_tree(process, grace=.1)


def _fake_ps(monkeypatch, stdout):
    monkeypatch.setattr(platform.subprocess, "run", lambda *_a, **_k: SimpleNamespace(stdout=stdout))


@requires_posix_process_groups
def test_eperm_from_group_with_empty_ps_listing_is_a_real_failure(monkeypatch):
    _deny_killpg(monkeypatch)
    _fake_ps(monkeypatch, "")
    try:
        with pytest.raises(PermissionError) as raised:
            platform._signal_posix_group(4242, signal.SIGKILL)
        assert not isinstance(raised.value, ProcessLookupError)
    finally:
        monkeypatch.undo()


@requires_posix_process_groups
def test_eperm_from_group_with_all_zombie_rows_means_group_gone(monkeypatch):
    _deny_killpg(monkeypatch)
    _fake_ps(monkeypatch, "4242 Z\n")
    try:
        with pytest.raises(ProcessLookupError):
            platform._signal_posix_group(4242, signal.SIGKILL)
    finally:
        monkeypatch.undo()


@requires_posix_process_groups
def test_eperm_from_group_with_zombie_and_live_rows_is_a_real_failure(monkeypatch):
    _deny_killpg(monkeypatch)
    _fake_ps(monkeypatch, "4242 Z\n4242 S\n")
    try:
        with pytest.raises(PermissionError) as raised:
            platform._signal_posix_group(4242, signal.SIGKILL)
        assert not isinstance(raised.value, ProcessLookupError)
    finally:
        monkeypatch.undo()


@requires_posix_process_groups
def test_eperm_from_group_with_a_live_member_is_a_real_failure(monkeypatch):
    process = _spawn_group_leader("import time; time.sleep(60)")
    try:
        _deny_killpg(monkeypatch)
        with pytest.raises(PermissionError):
            platform._signal_posix_group(process.pid, signal.SIGKILL)
    finally:
        monkeypatch.undo()
        platform.stop_tree(process, grace=.1)


@pytest.mark.parametrize("active_processes, drained", [(0, True), (1, False)])
def test_windows_tree_drained_queries_job_and_closes_only_when_empty(monkeypatch, active_processes, drained):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="win32"))
    calls = []

    class Function:
        def __init__(self, callback):
            self.callback = callback
        def __call__(self, *args):
            return self.callback(*args)

    def query(handle, info_class, info, size, _returned):
        calls.append((handle, info_class, size))
        fields = ctypes.cast(info, ctypes.POINTER(ctypes.c_uint32))
        fields[10] = active_processes
        return 1

    kernel = SimpleNamespace(
        QueryInformationJobObject=Function(query),
        CloseHandle=Function(lambda handle: calls.append(("close", handle)) or 1),
    )
    monkeypatch.setattr(platform, "_kernel", lambda: kernel)
    job = object.__new__(platform._Job)
    job.handle = 77
    process = SimpleNamespace(_runtime_job=job)

    assert platform.tree_drained(process) is drained
    assert calls[0] == (77, 1, 48)
    assert (("close", 77) in calls) is drained
    assert job.handle == (None if drained else 77)


def test_windows_tree_drained_requires_a_job(monkeypatch):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="win32"))
    with pytest.raises(ProcessLookupError, match="no Windows Job Object"):
        platform.tree_drained(SimpleNamespace())


def test_windows_tree_drained_accepts_retained_closed_job_without_query(monkeypatch):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="win32"))
    job = SimpleNamespace(handle=None, active_processes=lambda: pytest.fail("queried a closed Job"))

    assert platform.tree_drained(SimpleNamespace(_runtime_job=job)) is True


def test_windows_tree_drained_preserves_query_errors(monkeypatch):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="win32"))
    job = SimpleNamespace(handle=77, active_processes=lambda: (_ for _ in ()).throw(OSError("query failed")))

    with pytest.raises(OSError, match="query failed"):
        platform.tree_drained(SimpleNamespace(_runtime_job=job))
    assert job.handle == 77


@pytest.mark.parametrize("expected,actual,result", [
    ("b38142f7-84c5-487d-95a4-8180cbff3972:42", "b38142f7-84c5-487d-95a4-8180cbff3972:42", None),
    ("b38142f7-84c5-487d-95a4-8180cbff3972:42", "de2e05aa-6956-451e-9dd9-521955212d27:42", None),
    ("proc-start-ticks:42;boot:a", "proc-start-ticks:43;boot:a", None),
    ("proc-start-ticks:1", "proc-start-ticks:1;boot:a;pidns:2", None),
    ("proc-start-ticks:1", "proc-start-ticks:2;boot:a;pidns:2", None),
    ("proc-start-ticks:1;boot:a;pidns:2", "proc-start-ticks:1;boot:b;pidns:2", False),
    ("proc-start-ticks:1;boot:a;pidns:2", "proc-start-ticks:1;boot:a;pidns:3", None),
    ("proc-start-ticks:1;boot:a;pidns:2", "proc-start-ticks:1", None),
    ("proc-start-ticks:1;boot:a;pidns:2", "proc-start-ticks:1;pidns:2", None),
    ("proc-start-ticks:1;boot:a;pidns:2", "proc-start-ticks:1;pidns:3", None),
    ("proc-start-ticks:1;boot:a;pidns:2", "proc-start-ticks:2", None),
    ("proc-start-ticks:1;boot:a;pidns:2", "proc-start-ticks:1;boot:a;pidns:2", True),
])
def test_process_birth_comparison_handles_reboot_namespace_and_legacy(expected, actual, result):
    assert platform.process_birth_matches(expected, actual) is result


def test_linux_identity_includes_incarnation_scope():
    if sys.platform != "linux":
        return  # Linux-specific fields; generic native identity is tested above.
    identity = platform.process_identity(os.getpid())
    assert ";boot:" in identity["birth_id"]
    assert f";pidns:{Path('/proc/self/ns/pid').stat().st_ino}" in identity["birth_id"]


@pytest.mark.parametrize("unavailable", ["boot", "namespace", "both"])
def test_linux_identity_keeps_working_when_optional_scope_is_denied(monkeypatch, unavailable):
    if sys.platform != "linux":
        return
    real_read = Path.read_text
    real_stat = Path.stat

    def read(path, *args, **kwargs):
        if path.name == "boot_id" and unavailable in {"boot", "both"}:
            raise PermissionError("restricted proc mount")
        return real_read(path, *args, **kwargs)

    def stat(path, *args, **kwargs):
        if str(path).endswith("/ns/pid") and unavailable in {"namespace", "both"}:
            raise PermissionError("restricted proc mount")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(Path, "stat", stat)
    identity = platform.process_identity(os.getpid())
    assert identity is not None
    assert (";boot:" in identity["birth_id"]) is (unavailable == "namespace")
    assert (";pidns:" in identity["birth_id"]) is (unavailable == "boot")


@pytest.mark.parametrize("expected,actual,result", [
    ("b38142f7-84c5-487d-95a4-8180cbff3972:42", "proc-start-ticks:42;boot:b38142f7-84c5-487d-95a4-8180cbff3972;pidns:7", None),
    ("b38142f7-84c5-487d-95a4-8180cbff3972:42", "proc-start-ticks:43;boot:b38142f7-84c5-487d-95a4-8180cbff3972;pidns:7", None),
    ("b38142f7-84c5-487d-95a4-8180cbff3972:42", "proc-start-ticks:42;pidns:7", None),
    ("proc-start-ticks:42;boot:b38142f7-84c5-487d-95a4-8180cbff3972;pidns:7", "b38142f7-84c5-487d-95a4-8180cbff3972:42", None),
    ("proc-start-ticks:42;boot:a;pidns:7", "proc-start-ticks:42;boot:a;pidns:8", None),
    ("proc-start-ticks:bad", "proc-start-ticks:bad", None),
])
def test_cross_format_birth_comparison_is_conservative(expected, actual, result):
    assert platform.process_birth_matches(expected, actual) is result
