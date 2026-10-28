"""Startup cancellation regressions without sockets, processes, or signals."""
import json
import signal
import threading
import time
from types import SimpleNamespace

import pytest

from astrid_runtime import cli, runtime_boundary
from astrid_runtime.bootstrap import BootstrapConfig, _provision_connection
from astrid_runtime.paths import RuntimePaths
from astrid_runtime_client import generated
from runtime_protocol import cancellation
from tests.test_bootstrap import FakeBoundary, PROFILE


class Response:
    status = 200
    headers = {}

    def __init__(self, value):
        self.body = json.dumps(value).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, *_):
        return self.body


HANDSHAKE = {
    "protocol": "workspace.v1", "schema_digest": "schema", "session_id": "session",
    "actor_id": "actor", "realm_id": "realm", "scopes": [],
}


@pytest.mark.parametrize("route,budget", [("health", 5.0), ("door", 2.0)])
def test_readiness_accepts_300ms_response_in_foreground(monkeypatch, route, budget):
    timeouts = []

    def respond(_request, *, timeout):
        timeouts.append(timeout)
        time.sleep(min(0.3, timeout))
        if timeout < 0.3:
            raise TimeoutError("response needs 300 ms")
        return Response({"status": "ok", "protocol": "workspace.v1"})

    monkeypatch.setattr(runtime_boundary, "urlopen_loopback", respond)
    monkeypatch.setattr(cli, "urlopen_loopback", respond)
    with cancellation.startup_scope(threading.Event()):
        if route == "health":
            assert runtime_boundary.LocalRuntimeBoundary._http_health("http://127.0.0.1:1")
        else:
            assert cli._door_json("http://127.0.0.1:1", "https://hosted.test", "/health")["status"] == "ok"
    assert len(timeouts) == 1
    assert budget - 0.1 < timeouts[0] <= budget


def test_readiness_cancels_while_request_is_still_pending():
    stop, entered, release, finished = (threading.Event() for _ in range(4))
    calls = []

    def read(timeout):
        calls.append(timeout)
        entered.set()
        try:
            release.wait(1.5)  # Bounds failure on the old blocking implementation.
            return "ready"
        finally:
            finished.set()

    def cancel():
        assert entered.wait(2)
        stop.set()

    canceller = threading.Thread(target=cancel)
    canceller.start()
    started = time.monotonic()
    try:
        with cancellation.startup_scope(stop), pytest.raises(cancellation.StartupCancelled):
            cancellation.retry_timeouts(read, 5.0)
        assert time.monotonic() - started < 0.75
        assert not finished.is_set()
        assert len(calls) == 1 and 4.9 < calls[0] <= 5.0
    finally:
        release.set()
        canceller.join(2)
        assert finished.wait(2)


@pytest.mark.parametrize("stage", ["provision", "handshake"])
@pytest.mark.parametrize("stop_signal", [signal.SIGTERM, signal.SIGINT])
def test_run_cancels_pending_handoff_and_rolls_back(monkeypatch, tmp_path, capsys, stage, stop_signal):
    import importlib

    bootstrap_module = importlib.import_module("astrid_runtime.bootstrap")
    monkeypatch.setattr(bootstrap_module, "_capture_requested_identity", lambda _source: {"release": 0, "managed_by": None})
    paths = RuntimePaths.sandbox(tmp_path)
    paths.ensure_support_dirs()
    root = paths.realms_dir / "realm"
    root.mkdir(parents=True)
    catalog = {"version": 1, "selected_realm_id": "realm", "realms": [
        {"realm_id": "realm", "display_name": "Test", "data_root": str(root)},
    ], "source_profiles": {}}
    paths.catalog_path.write_text(json.dumps(catalog))
    catalog_before = paths.catalog_path.read_bytes()
    entered, release, finished = (threading.Event() for _ in range(3))
    requests, handlers, cleanups, scopes = [], [], [], []
    requester = []

    def respond(request, *, timeout):
        current = "provision" if request.full_url.endswith("/credentials") else "handshake"
        requests.append((current, timeout))
        if current == stage:
            requester.append(threading.current_thread())
            scopes.append(cancellation.active())
            entered.set()
            try:
                release.wait(1.5)
            finally:
                finished.set()
        return Response({"scope": "astrid"} if current == "provision" else HANDSHAKE)

    monkeypatch.setattr(runtime_boundary, "urlopen_loopback", respond)
    monkeypatch.setattr(generated, "_urlopen_loopback", respond)
    boundary = FakeBoundary()
    local = runtime_boundary.LocalRuntimeBoundary()
    local._bootstrap_credential = "bootstrap-token"
    boundary.connect = local.connect

    def cleanup():
        cancellation.check()  # Cleanup must run outside the cancelled scope.
        cleanups.append(True)
        boundary.alive.clear()

    boundary.stop = cleanup
    boundary.check_running = lambda: pytest.fail("must cancel before readiness")
    monkeypatch.setattr(cli, "ForegroundRuntimeBoundary", lambda: boundary)
    monkeypatch.setattr(cli.platform, "log_dir", lambda _: tmp_path / "logs")
    monkeypatch.setattr(cli.platform, "install_stop_handlers", lambda callback: handlers.append(callback) or (lambda: None))

    def cancel():
        assert entered.wait(2)
        handlers[0](stop_signal, None)  # Exercise the handler; never send a signal.

    canceller = threading.Thread(target=cancel)
    canceller.start()
    started = time.monotonic()
    try:
        assert cli._run_foreground(paths, BootstrapConfig(source_profile=PROFILE), json_mode=True) == 1
        assert time.monotonic() - started < 0.75
        assert not finished.is_set()
        assert "cancelled" in json.loads(capsys.readouterr().out)["error"]
        assert cleanups and not boundary.alive
        assert not paths.discovery_path.exists()
        assert not paths.instance_lock_path.exists()
        assert not (paths.credentials_dir / "astrid.json").exists()
        assert not (paths.source_profiles_dir / "astrid.json").exists()
        assert paths.catalog_path.read_bytes() == catalog_before
        assert root.is_dir()
        assert requests == ([("provision", 5)] if stage == "provision" else [("provision", 5), ("handshake", 30.0)])
        assert scopes == [True]
    finally:
        release.set()
        canceller.join(2)
        assert finished.wait(2)
        if requester[0] is not threading.current_thread():
            requester[0].join(2)
    # A late provisioning response must not resume realm selection/handshake.
    assert len(requests) == (1 if stage == "provision" else 2)


@pytest.mark.parametrize("stage", ["provision_actor", "select_realm", "handshake"])
def test_handoff_checks_stop_between_calls(stage):
    stop = threading.Event()
    calls = []

    def invoke(name, **_):
        calls.append(name)
        if name == stage:
            stop.set()

    connection = SimpleNamespace(**{
        name: lambda name=name, **kwargs: invoke(name, **kwargs)
        for name in ("provision_actor", "select_realm", "handshake")
    })
    with cancellation.startup_scope(stop), pytest.raises(cancellation.StartupCancelled):
        _provision_connection(connection, "actor", "token", "realm")
    assert calls[-1] == stage


def test_background_handoff_keeps_timeouts_and_calling_thread(monkeypatch):
    timeouts, threads = [], []

    def respond(request, *, timeout):
        timeouts.append(timeout)
        threads.append(threading.current_thread())
        return Response({"scope": "astrid"} if request.full_url.endswith("/credentials") else HANDSHAKE)

    monkeypatch.setattr(runtime_boundary, "urlopen_loopback", respond)
    monkeypatch.setattr(generated, "_urlopen_loopback", respond)
    boundary = runtime_boundary.LocalRuntimeBoundary()
    boundary._bootstrap_credential = "bootstrap-token"
    connection = boundary.connect(endpoint="http://127.0.0.1:1", credential="token")
    _provision_connection(connection, "actor", "token", "realm")
    assert timeouts == [5, 30.0]
    assert threads == [threading.current_thread()] * 2
