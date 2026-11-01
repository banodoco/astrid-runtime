"""Review regressions; unit cases never bind ports or send real signals."""
import os
import socket
import signal
import subprocess
import sys
import threading
import time
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from runtime_protocol import platform, server
from tests.lanes import requires_linux_tree_custody, requires_windows_security, requires_posix_process_groups


@pytest.mark.parametrize("host", ["win32", "darwin", "linux"])
def test_listener_sets_exclusive_windows_option_before_bind(monkeypatch, host):
    monkeypatch.setattr(server, "sys", SimpleNamespace(platform=host), raising=False)
    monkeypatch.setattr(socket, "SO_EXCLUSIVEADDRUSE", -5, raising=False)
    events = []
    listener = object.__new__(server.RuntimeHTTPServer)
    listener.socket = SimpleNamespace(setsockopt=lambda *args: events.append(args))
    listener.server_address = ("127.0.0.1", 4321)
    monkeypatch.setattr(server.TCPServer, "server_bind", lambda self: events.append("bind"))
    listener.server_bind()
    if host == "win32":
        assert listener.allow_reuse_address is False
        assert events == [(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1), "bind"]
    else:
        assert listener.allow_reuse_address is True
        assert events == ["bind"]
    assert listener.server_name == "127.0.0.1"
    assert listener.server_port == 4321


@pytest.mark.parametrize("killpg_missing", [False, True])
def test_linux_cleanup_refuses_group_after_leader_reaped(monkeypatch, killpg_missing):
    if killpg_missing:
        monkeypatch.delattr(os, "killpg", raising=False)
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="linux"))
    signal_group = Mock()
    monkeypatch.setattr(os, "killpg", signal_group, raising=False)
    process = SimpleNamespace(pid=4321, returncode=0, poll=lambda: 0)
    platform.stop_tree(process)
    signal_group.assert_not_called()


@pytest.mark.parametrize("killpg_missing", [False, True])
def test_linux_cleanup_refuses_externally_reaped_child(monkeypatch, killpg_missing):
    if killpg_missing:
        monkeypatch.delattr(os, "killpg", raising=False)
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="linux"))
    for name, value in {"P_PID": 1, "WEXITED": 4, "WNOHANG": 1, "WNOWAIT": 0x1000000}.items():
        monkeypatch.setattr(os, name, value, raising=False)
    def already_reaped(*_):
        raise ChildProcessError("no child")
    monkeypatch.setattr(os, "waitid", already_reaped, raising=False)
    killpg = Mock()
    monkeypatch.setattr(os, "killpg", killpg, raising=False)
    platform.stop_tree(SimpleNamespace(pid=4321, returncode=None))
    killpg.assert_not_called()


def test_windows_stat_metadata_cannot_authorize_a_credential(monkeypatch, tmp_path):
    metadata = tmp_path.stat()
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="win32"))
    assert not platform.is_owner_only(metadata)


@pytest.mark.parametrize("killpg_missing", [False, True])
def test_linux_cleanup_kills_group_before_reaping_leader(monkeypatch, killpg_missing):
    if killpg_missing:
        monkeypatch.delattr(os, "killpg", raising=False)
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="linux"))
    for name, value in {"P_PID": 1, "WEXITED": 4, "WNOHANG": 1, "WNOWAIT": 0x1000000}.items():
        monkeypatch.setattr(os, name, value, raising=False)
    events = []
    monkeypatch.setattr(os, "waitid", lambda *_: SimpleNamespace(si_pid=4321), raising=False)
    process = SimpleNamespace(pid=4321, returncode=None,
        poll=lambda: events.append("poll") or 0,
        wait=lambda **_: events.append("reap"))
    monkeypatch.setattr(os, "killpg", lambda _, sig: events.append(sig), raising=False)
    platform.stop_tree(process)
    assert events == [platform.KILL, "reap"]


@pytest.mark.parametrize("target", [4321, SimpleNamespace(pid=4321, returncode=0)])
@pytest.mark.parametrize("killpg_missing", [False, True])
def test_linux_group_signalling_refuses_missing_custody(monkeypatch, target, killpg_missing):
    if killpg_missing:
        monkeypatch.delattr(os, "killpg", raising=False)
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="linux"))
    killpg = Mock()
    monkeypatch.setattr(os, "killpg", killpg, raising=False)
    with pytest.raises(ProcessLookupError, match="custody"):
        platform.signal_tree(target, platform.KILL)
    killpg.assert_not_called()


def test_startup_lock_wait_cancels_without_acquiring_or_unlocking(monkeypatch, tmp_path):
    from runtime_protocol import cancellation
    from astrid_runtime.bootstrap import _bootstrap_mutex
    from astrid_runtime.paths import RuntimePaths
    event = threading.Event()
    attempts = []
    def busy(fd, *, exclusive=True, blocking=True):
        attempts.append(blocking)
        event.set()
        raise BlockingIOError("another launcher owns the lock")
    monkeypatch.setattr(platform, "_lock_file", busy)
    unlock = Mock()
    monkeypatch.setattr(platform, "unlock_file", unlock)
    with cancellation.startup_scope(event), pytest.raises(cancellation.StartupCancelled, match="cancelled"):
        with _bootstrap_mutex(RuntimePaths.sandbox(tmp_path)):
            pytest.fail("cancelled launcher acquired the mutex")
    assert attempts == [False]
    unlock.assert_not_called()


def test_endpoint_readiness_cancels_before_poll_or_network(monkeypatch, tmp_path):
    from runtime_protocol import cancellation
    from astrid_runtime.runtime_boundary import LocalRuntimeBoundary
    event = threading.Event()
    boundary = LocalRuntimeBoundary()
    process = SimpleNamespace(poll=lambda: pytest.fail("cancel before polling"))
    with cancellation.startup_scope(event), pytest.raises(cancellation.StartupCancelled):
        event.set()
        boundary._wait_endpoint(tmp_path, process)


def test_run_cancellation_during_bootstrap_cleans_up_and_exits_nonzero(monkeypatch, tmp_path, capsys):
    from astrid_runtime import cli
    from astrid_runtime.paths import RuntimePaths
    handlers = []
    stopped = Mock()
    boundary = SimpleNamespace(stop=stopped, check_running=lambda: pytest.fail("cancel before readiness"))
    monkeypatch.setattr(cli, "ForegroundRuntimeBoundary", lambda: boundary)
    monkeypatch.setattr(cli.platform, "log_dir", lambda _: tmp_path / "logs")
    monkeypatch.setattr(cli.platform, "install_stop_handlers", lambda callback: handlers.append(callback) or (lambda: None))
    def bootstrap(*_):
        handlers[0]()  # Invoke the handler directly; never send a signal.
        return None
    monkeypatch.setattr(cli, "bootstrap", bootstrap)
    assert cli._run_foreground(RuntimePaths.sandbox(tmp_path), cli.BootstrapConfig(), json_mode=True) == 1
    stopped.assert_called_once()
    assert "cancelled" in capsys.readouterr().out


def test_door_wait_cancels_between_health_and_realm_reads(monkeypatch, tmp_path):
    from runtime_protocol import cancellation
    from astrid_runtime import cli
    from astrid_runtime.paths import RuntimePaths
    from tests.test_foreground import _result, _discovery
    paths = RuntimePaths.sandbox(tmp_path)
    result = _result()
    _discovery(paths, result)
    event = threading.Event()
    routes = []
    def read(_endpoint, _origin, route):
        routes.append(route)
        event.set()
        return {"status": "ok", "runtime_instance_id": result.runtime_instance_id}
    monkeypatch.setattr(cli, "_door_json", read)
    with cancellation.startup_scope(event), pytest.raises(cancellation.StartupCancelled):
        cli._wait_for_door(paths, result, SimpleNamespace(wait_seconds=30))
    assert routes == ["/api/runtime/v1/health"]


def test_startup_transport_retains_original_timeout_budget(monkeypatch):
    from runtime_protocol import cancellation
    event = threading.Event()
    attempts = []
    elapsed = [0.0]
    monkeypatch.setattr(cancellation, "time", SimpleNamespace(monotonic=lambda: elapsed[0]))
    def read(timeout):
        attempts.append(timeout)
        elapsed[0] += 1.25
        if len(attempts) < 3:
            raise TimeoutError("temporarily busy")
        return "ready"
    with cancellation.startup_scope(event):
        assert cancellation.retry_timeouts(read, 5.0) == "ready"
    assert attempts == [5.0, 3.75, 2.5]


def test_startup_transport_checks_cancel_after_socket_timeout():
    from runtime_protocol import cancellation
    event = threading.Event()
    def read(timeout):
        event.set()
        raise TimeoutError("still busy")
    with cancellation.startup_scope(event), pytest.raises(cancellation.StartupCancelled):
        cancellation.retry_timeouts(read, 5.0)


def test_admission_copy_cancels_before_copying_bytes(tmp_path):
    from runtime_protocol import cancellation
    from runtime_protocol.store import RealmStore
    source, destination = tmp_path / "db", tmp_path / "snapshot"
    source.write_bytes(b"untouched")
    event = threading.Event()
    with cancellation.startup_scope(event), pytest.raises(cancellation.StartupCancelled):
        event.set()
        RealmStore._copy_admission_file(source, destination, time.monotonic() + 60)
    assert not destination.exists()


def test_admission_sqlite_progress_cancels_and_removes_callback(monkeypatch, tmp_path):
    from runtime_protocol import cancellation
    from runtime_protocol.store import RealmStore
    event = threading.Event()
    with RealmStore.initialize(tmp_path / "realm") as store:
        def slow_inspect(**_):
            event.set()
            store.conn.execute("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<1000000) SELECT sum(x) FROM n").fetchone()
            pytest.fail("SQLite did not interrupt the admission query")
        monkeypatch.setattr(store, "_integrity_report", slow_inspect)
        with cancellation.startup_scope(event), pytest.raises(cancellation.StartupCancelled):
            store.integrity_report()
        # The progress callback must be cleared even after interruption.
        assert store.conn.execute("SELECT 1").fetchone()[0] == 1


@requires_windows_security
def test_windows_owner_only_rejects_public_dacl_and_stat_only_check(tmp_path):
    from astrid_runtime.io import atomic_write_json
    from runtime_protocol import windows_security
    path = tmp_path / "owned" / "secret"
    atomic_write_json(path, {"token": "secret"})
    windows_security.set_sddl(path, "D:P(A;;FA;;;WD)")
    assert not platform.is_owner_only(path)
    assert not platform.is_owner_only(path.stat())
    platform.owner_only(path)
    assert platform.is_owner_only(path)
    with path.open("rb") as handle:
        assert platform.is_owner_only(handle.fileno())


@requires_windows_security
def test_windows_credential_rejects_public_file_before_read(tmp_path):
    from astrid_runtime.bootstrap import BootstrapError, _credential
    from astrid_runtime.io import atomic_write_json
    from astrid_runtime.paths import RuntimePaths
    from runtime_protocol import windows_security
    paths = RuntimePaths.current(data_root=tmp_path / "shared-root")
    paths.ensure_support_dirs()
    path = paths.credentials_dir / "astrid.json"
    atomic_write_json(path, {"scope": "astrid", "token": "a" * 64})
    windows_security.set_sddl(path, "D:P(A;;FA;;;WD)")
    with pytest.raises(BootstrapError, match="unsafe.*DACL|DACL.*unsafe"):
        _credential(paths)


@requires_windows_security
def test_windows_discovery_and_credentials_are_private_from_creation(tmp_path):
    from astrid_runtime.bootstrap import _credential
    from astrid_runtime.paths import RuntimePaths
    from runtime_protocol.auth import CredentialStore
    from runtime_protocol.catalog import LiveDiscovery
    from runtime_protocol import windows_security
    paths = RuntimePaths.current(data_root=tmp_path / "data")
    paths.ensure_support_dirs()
    _actor, token = _credential(paths)
    assert token.encode() in windows_security.read_private(paths.credentials_dir / "astrid.json")
    credentials = CredentialStore(paths.runtime_support / "credentials")
    bearer, path = credentials.provision("owner", ["admin"])
    assert windows_security.read_private(path).decode() == bearer
    assert credentials.require(bearer, "admin")["actor"] == "owner"
    discovery = LiveDiscovery(paths.discovery_path)
    discovery.publish(pid=123, runtime_instance_id="test")
    assert discovery.read()["runtime_instance_id"] == "test"
    for directory in (paths.credentials_dir, paths.runtime_support, credentials.root):
        assert platform.is_owner_only(directory, directory=True)
    windows_security.set_sddl(paths.discovery_path, "D:P(A;;FA;;;WD)")
    with pytest.raises(PermissionError, match="unsafe.*DACL"):
        discovery.read()


@requires_windows_security
def test_windows_rejects_shared_credential_directory(tmp_path):
    from runtime_protocol import windows_security
    root = tmp_path / "credentials"
    platform.private_directory(root)
    windows_security.set_sddl(root, "D:P(A;OICI;FA;;;WD)")
    with pytest.raises(PermissionError, match="unsafe.*DACL"):
        platform.private_directory(root)


@requires_windows_security
def test_windows_rejects_owner_mismatch_with_private_dacl(tmp_path, monkeypatch):
    import ctypes
    from astrid_runtime.io import atomic_write_json
    from runtime_protocol import windows_security
    path = tmp_path / "owned" / "private"
    atomic_write_json(path, {"token": "secret"})
    # Model a different token user without requiring owner-changing privileges.
    null_sid = ctypes.create_string_buffer(bytes([1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
    monkeypatch.setattr(windows_security, "_user_sid", lambda: null_sid)
    monkeypatch.setattr(windows_security, "_default_owner_sid", lambda: null_sid)
    with pytest.raises(PermissionError, match="owner is not the current token user"):
        windows_security.validate(path)


@requires_windows_security
@pytest.mark.integration
def test_windows_listener_cannot_be_rebound():
    from http.server import BaseHTTPRequestHandler
    with server.RuntimeHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler) as listener:
        with socket.socket() as contender:
            contender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            with pytest.raises(OSError):
                contender.bind(listener.server_address)


@requires_linux_tree_custody
@pytest.mark.integration
def test_linux_cleanup_retains_exited_child_until_group_teardown():
    process = platform.spawn_tree([sys.executable, "-c", "pass"])
    # WNOWAIT observes exit without letting the numeric group ID be reused.
    os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT)
    platform.stop_tree(process)
    assert process.returncode == 0


@pytest.mark.integration
@requires_posix_process_groups
@pytest.mark.parametrize("stop_signal", [signal.SIGTERM, signal.SIGINT])
@pytest.mark.parametrize("stage", ["lock", "door", "provision", "handshake"])
def test_run_native_startup_signal_cancels_promptly_and_cleans_up(tmp_path, stage, stop_signal):
    from astrid_runtime.paths import RuntimePaths
    paths = RuntimePaths.current(data_root=tmp_path / "data")
    paths.ensure_support_dirs()
    script = r'''
import json, sys, threading
from pathlib import Path
from astrid_runtime import cli
from astrid_runtime.bootstrap import _bootstrap_mutex, _provision_connection
from astrid_runtime.runtime_boundary import LocalRuntimeBoundary
from astrid_runtime_client import generated
from astrid_runtime import runtime_boundary
from astrid_runtime.paths import RuntimePaths
root, stage = Path(sys.argv[1]), sys.argv[2]
paths = RuntimePaths.current(data_root=root)
cli.platform.log_dir = lambda _: root / "logs"
class Boundary:
    wait_seconds = 60
    def check_running(self): pass
    def is_pid_alive(self, _pid): return True
    def stop(self): (root / "cleaned").write_text("yes")
cli.ForegroundRuntimeBoundary = Boundary
def pending(*_):
    if stage in {"provision", "handshake"}:
        def blocked(request, *, timeout):
            if request.full_url.endswith("/credentials") and stage == "handshake":
                class Response:
                    def __enter__(self): return self
                    def __exit__(self, *_): return False
                    def read(self): return b'{"scope":"astrid"}'
                return Response()
            (root / "waiting").write_text("yes")
            threading.Event().wait(timeout)
            raise TimeoutError("handoff timed out")
        runtime_boundary.urlopen_loopback = blocked
        generated._urlopen_loopback = blocked
        boundary = LocalRuntimeBoundary()
        boundary._bootstrap_credential = "bootstrap-token"
        connection = boundary.connect(endpoint="http://127.0.0.1:1", credential="token")
        _provision_connection(connection, "actor", "token", "realm")
        raise RuntimeError("handoff unexpectedly completed")
    (root / "waiting").write_text("yes")
    if stage == "lock":
        with _bootstrap_mutex(paths): raise RuntimeError("lock unexpectedly acquired")
    result = cli.BootstrapResult(status="started", realm_id="realm", display_name="test",
        endpoint="http://127.0.0.1:1", actor_id="test", source_profile="astrid",
        door_endpoint="http://127.0.0.1:1", door_origin="https://hosted.test", runtime_instance_id="test")
    paths.discovery_path.write_text(json.dumps({"pid": 123, "active_realm": "realm", "runtime_instance_id": "test"}))
    return result
cli.bootstrap = pending
def unavailable(*_): raise OSError("still starting")
cli._door_json = unavailable
raise SystemExit(cli._run_foreground(paths, cli.BootstrapConfig(), json_mode=True))
'''
    # pytest's pythonpath setting applies only to this interpreter. The child
    # exercises the generated client too, so give it the same SDK source root.
    client_root = str(Path(__file__).resolve().parents[1] / "packages" / "python")
    child_environment = dict(os.environ)
    child_environment["PYTHONPATH"] = os.pathsep.join(
        filter(None, (client_root, child_environment.get("PYTHONPATH")))
    )
    with platform.file_lock(paths.bootstrap_lock_path):
        process = platform.spawn_tree([sys.executable, "-c", script, str(paths.app_support), stage],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=child_environment)
        try:
            deadline = time.monotonic() + 10
            while not (paths.app_support / "waiting").exists() and time.monotonic() < deadline:
                if process.poll() is not None:
                    output, errors = process.communicate(timeout=3)
                    pytest.fail(f"Runtime exited before waiting at {stage}:\n{output}\n{errors}")
                time.sleep(0.02)
            assert (paths.app_support / "waiting").exists()
            process.send_signal(stop_signal)
            output, errors = process.communicate(timeout=3)
            assert process.returncode == 1, errors
            assert "cancelled" in json.loads(output)["error"]
            assert (paths.app_support / "cleaned").read_text() == "yes"
        finally:
            if process.poll() is None:
                platform.stop_tree(process, grace=0.1)
