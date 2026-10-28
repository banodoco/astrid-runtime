from __future__ import annotations

import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from astrid_runtime import cli
from astrid_runtime.bootstrap import BootstrapError, BootstrapResult, DoorSettings
from astrid_runtime.io import atomic_write_json
from astrid_runtime.paths import RuntimePaths


ORIGIN = "https://astrid.haus"
ENDPOINT = "http://127.0.0.1:17340"


def _result(*, realm="realm-a", instance="instance-a", endpoint=ENDPOINT, origin=ORIGIN):
    return BootstrapResult(
        status="started", realm_id=realm, display_name="Workspace", endpoint="http://127.0.0.1:61217",
        actor_id="actor", source_profile="astrid", door_origin=origin, door_endpoint=endpoint,
        runtime_instance_id=instance,
    )


def _discovery(paths, result, *, instance="instance-a", realm="realm-a"):
    atomic_write_json(paths.discovery_path, {
        "pid": 42, "process_birth_id": "birth-a", "runtime_instance_id": instance,
        "active_realm": realm, "door_endpoint": result.door_endpoint, "door_origin": result.door_origin,
    })


class _Boundary:
    def __init__(self, *, wait_seconds=1.0, check_error=None):
        self.wait_seconds = wait_seconds
        self.check_error = check_error
        self.checks = 0
        self.stops = 0

    def check_running(self):
        self.checks += 1
        if self.check_error:
            raise self.check_error

    def stop(self):
        self.stops += 1


def test_parser_accepts_up_wait_and_foreground_run(tmp_path):
    up = cli.parser().parse_args(["up", "--wait", "--data-root", str(tmp_path / "data")])
    assert up.command == "up" and up.wait
    run = cli.parser().parse_args(["run", "--data-root", str(tmp_path / "data")])
    assert run.command == "run"
    offline_run = cli.parser().parse_args([
        "run", "--data-root", str(tmp_path / "offline-data"), "--hosted-origin", "off",
    ])
    assert cli._config(offline_run, RuntimePaths.sandbox(tmp_path / "offline-support")).door is None


def test_wait_for_door_accepts_matching_runtime_and_realm(tmp_path, monkeypatch):
    paths = RuntimePaths.sandbox(tmp_path / "support")
    result = _result()
    _discovery(paths, result)
    calls = []
    def read(_endpoint, _origin, route):
        calls.append(route)
        if route.endswith("health"):
            return {"status": "ok", "runtime_instance_id": "instance-a"}
        return {"realm_id": "realm-a"}
    monkeypatch.setattr(cli, "_door_json", read)
    cli._wait_for_door(paths, result, _Boundary())
    assert calls == ["/api/runtime/v1/health", "/api/runtime/v1/realm"]


@pytest.mark.parametrize(
    "health,realm,match",
    [
        ({"status": "ok", "runtime_instance_id": "different"}, {"realm_id": "realm-a"}, "different Runtime"),
        ({"status": "ok", "runtime_instance_id": "instance-a"}, {"realm_id": "realm-b"}, "different Runtime"),
    ],
)
def test_wait_for_door_rejects_instance_or_realm_mismatch(tmp_path, monkeypatch, health, realm, match):
    paths = RuntimePaths.sandbox(tmp_path / "support")
    result = _result()
    _discovery(paths, result)
    monkeypatch.setattr(cli, "_door_json", lambda _endpoint, _origin, route: health if route.endswith("health") else realm)
    with pytest.raises(BootstrapError, match=match):
        cli._wait_for_door(paths, result, _Boundary())


def test_wait_for_door_refuses_disabled_or_missing_door(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path / "support")
    with pytest.raises(BootstrapError, match="no browser door"):
        cli._wait_for_door(paths, _result(endpoint=None, origin=None), _Boundary())


def test_wait_for_door_detects_discovery_owner_change(tmp_path, monkeypatch):
    paths = RuntimePaths.sandbox(tmp_path / "support")
    result = _result()
    _discovery(paths, result)
    original = paths.discovery_path.read_text()
    changed = json.loads(original)
    changed["runtime_instance_id"] = "replacement"
    reads = iter((json.loads(original), changed))
    monkeypatch.setattr(cli, "_read_support_json", lambda _path: next(reads))
    with pytest.raises(BootstrapError, match="identity changed"):
        cli._wait_for_door(paths, result, _Boundary())


def test_wait_for_door_rejects_replacement_already_present_before_first_read(tmp_path, monkeypatch):
    paths = RuntimePaths.sandbox(tmp_path / "support")
    result = _result(instance="original-instance")
    _discovery(paths, result, instance="replacement-instance")
    monkeypatch.setattr(cli, "_door_json", lambda *_: pytest.fail("must reject before contacting a replacement door"))
    with pytest.raises(BootstrapError, match="discovery changed"):
        cli._wait_for_door(paths, result, _Boundary())


def test_wait_for_door_reports_early_process_exit(tmp_path, monkeypatch):
    paths = RuntimePaths.sandbox(tmp_path / "support")
    result = _result()
    _discovery(paths, result)
    monkeypatch.setattr(cli, "_door_json", lambda *_: (_ for _ in ()).throw(OSError("connection refused")))
    with pytest.raises(BootstrapError, match="Runtime exited.*connection refused"):
        cli._wait_for_door(paths, result, SimpleNamespace(wait_seconds=1, is_pid_alive=lambda _pid: False))


def test_wait_for_door_reports_deadline_and_last_reason(tmp_path, monkeypatch):
    paths = RuntimePaths.sandbox(tmp_path / "support")
    result = _result()
    _discovery(paths, result)
    clock = iter((0.0, 0.1, 1.1))
    monkeypatch.setattr(cli, "time", SimpleNamespace(monotonic=lambda: next(clock), sleep=lambda _seconds: None))
    monkeypatch.setattr(cli, "_door_json", lambda *_: (_ for _ in ()).throw(OSError("door refused connection")))
    with pytest.raises(BootstrapError, match="deadline.*door refused connection"):
        cli._wait_for_door(paths, result, SimpleNamespace(wait_seconds=1, is_pid_alive=lambda _pid: True))


def test_up_wait_requires_browser_door_and_emits_refusal(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_paths", lambda _args: RuntimePaths.sandbox(tmp_path / "support"))
    monkeypatch.setattr(cli, "_config", lambda *_: cli.BootstrapConfig(door=None))
    assert cli.main(["up", "--wait", "--hosted-origin", "off", "--json"]) == 1
    assert "requires the browser door" in capsys.readouterr().out


def test_up_wait_returns_only_after_matching_door_is_ready(tmp_path, monkeypatch, capsys):
    paths = RuntimePaths.sandbox(tmp_path / "support")
    result = _result()
    _discovery(paths, result)
    boundary = _Boundary()
    monkeypatch.setattr(cli, "_paths", lambda _args: paths)
    monkeypatch.setattr(cli, "_config", lambda *_: cli.BootstrapConfig(door=DoorSettings(ORIGIN, 17340)))
    monkeypatch.setattr(cli, "LocalRuntimeBoundary", lambda: boundary)
    monkeypatch.setattr(cli, "bootstrap", lambda *_: result)
    monkeypatch.setattr(cli, "_wait_for_door", lambda *_: boundary.check_running())
    assert cli.main(["up", "--wait", "--json"]) == 0
    assert boundary.checks == 1
    assert json.loads(capsys.readouterr().out)["realm_id"] == "realm-a"


@pytest.mark.parametrize("failure", ["startup", "listener"])
def test_run_foreground_reports_failure_log_and_stops_owner_in_same_process(tmp_path, monkeypatch, capsys, failure):
    paths = RuntimePaths.sandbox(tmp_path / "support")
    boundary = _Boundary(check_error=RuntimeError("listener stopped"))
    registrations = []
    monkeypatch.setattr(cli, "platform", SimpleNamespace(
        log_dir=lambda home: tmp_path / "logs",
        owner_only=lambda _path: None,
        install_stop_handlers=lambda callback: (registrations.append(callback) or (lambda: None)),
    ))
    monkeypatch.setattr(cli, "ForegroundRuntimeBoundary", lambda: boundary)
    if failure == "startup":
        monkeypatch.setattr(cli, "bootstrap", lambda *_: (_ for _ in ()).throw(OSError("listener bind denied")))
        boundary.check_error = None
    else:
        monkeypatch.setattr(cli, "bootstrap", lambda *_: _result())
        monkeypatch.setattr(cli, "_wait_for_door", lambda *_: None)
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_k: pytest.fail("foreground run must not spawn a daemon process"))
    code = cli._run_foreground(paths, cli.BootstrapConfig(door=DoorSettings(ORIGIN, 17340)), json_mode=True)
    assert code == 1
    assert boundary.stops == 1
    output = json.loads(capsys.readouterr().out)
    assert output["ok"] is False
    assert str(tmp_path / "logs" / "runtime.log") == output["log"]
    assert ("listener bind denied" if failure == "startup" else "listener stopped") in output["error"]
    log_path = Path(output["log"])
    assert log_path.is_file()
    assert ("listener bind denied" if failure == "startup" else "listener stopped") in log_path.read_text()


def test_run_foreground_stops_only_when_handler_event_is_set(tmp_path, monkeypatch):
    paths = RuntimePaths.sandbox(tmp_path / "support")
    boundary = _Boundary()
    registration = {}
    class FakeEvent:
        def __init__(self): self.stopped = False
        def is_set(self): return self.stopped
        def wait(self, _timeout):
            if not self.stopped:
                registration["handler"]()
                return False
            return True
        def set(self): self.stopped = True
    monkeypatch.setattr(cli.threading, "Event", FakeEvent)
    monkeypatch.setattr(cli, "platform", SimpleNamespace(
        log_dir=lambda _home: tmp_path / "logs",
        owner_only=lambda _path: None,
        install_stop_handlers=lambda callback: (registration.update(handler=callback) or (lambda: None)),
    ))
    monkeypatch.setattr(cli, "ForegroundRuntimeBoundary", lambda: boundary)
    monkeypatch.setattr(cli, "bootstrap", lambda *_: _result())
    monkeypatch.setattr(cli, "_wait_for_door", lambda *_: None)
    assert cli._run_foreground(paths, cli.BootstrapConfig(door=DoorSettings(ORIGIN, 17340)), json_mode=True) == 0
    assert boundary.checks == 2
    assert boundary.stops == 1


def test_run_foreground_treats_stop_after_readiness_as_orderly(tmp_path, monkeypatch, capsys):
    paths = RuntimePaths.sandbox(tmp_path / "support")
    boundary = _Boundary()
    registration = {}
    monkeypatch.setattr(cli, "platform", SimpleNamespace(
        log_dir=lambda _home: tmp_path / "logs",
        owner_only=lambda _path: None,
        install_stop_handlers=lambda callback: (registration.update(handler=callback) or (lambda: None)),
    ))
    monkeypatch.setattr(cli, "ForegroundRuntimeBoundary", lambda: boundary)
    monkeypatch.setattr(cli, "bootstrap", lambda *_: _result())

    def ready_then_stop(*_):
        registration["handler"](None, None)

    monkeypatch.setattr(cli, "_wait_for_door", ready_then_stop)
    assert cli._run_foreground(paths, cli.BootstrapConfig(door=DoorSettings(ORIGIN, 17340)), json_mode=True) == 0
    assert boundary.stops == 1
    assert capsys.readouterr().out == ""


def test_run_command_routes_to_in_process_foreground_owner(tmp_path, monkeypatch):
    paths = RuntimePaths.sandbox(tmp_path / "support")
    config = cli.BootstrapConfig(door=DoorSettings(ORIGIN, 17340))
    boundary = _Boundary()
    registration = {}
    class FakeEvent:
        def __init__(self): self.stopped = False
        def is_set(self): return self.stopped
        def wait(self, _timeout):
            if not self.stopped:
                registration["handler"]()
                return False
            return True
        def set(self): self.stopped = True
    monkeypatch.setattr(cli, "_paths", lambda _args: paths)
    monkeypatch.setattr(cli, "_config", lambda *_: config)
    monkeypatch.setattr(cli.threading, "Event", FakeEvent)
    monkeypatch.setattr(cli, "ForegroundRuntimeBoundary", lambda: boundary)
    monkeypatch.setattr(cli, "bootstrap", lambda *_: _result())
    monkeypatch.setattr(cli, "_wait_for_door", lambda *_: None)
    monkeypatch.setattr(cli, "platform", SimpleNamespace(
        log_dir=lambda _home: tmp_path / "logs",
        owner_only=lambda _path: None,
        install_stop_handlers=lambda callback: (registration.update(handler=callback) or (lambda: None)),
    ))
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_k: pytest.fail("run must own its daemon in this process"))
    assert cli.main(["run", "--data-root", str(tmp_path / "data"), "--json"]) == 0
    assert boundary.stops == 1


def test_run_command_accepts_disabled_hosted_door_and_stays_foreground(tmp_path, monkeypatch):
    paths = RuntimePaths.sandbox(tmp_path / "support")
    config = cli.BootstrapConfig(door=None)
    boundary = _Boundary()
    registration = {}

    class FakeEvent:
        def __init__(self):
            self.stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, _timeout):
            if not self.stopped:
                registration["handler"]()
                return False
            return True

        def set(self):
            self.stopped = True

    monkeypatch.setattr(cli, "_paths", lambda _args: paths)
    monkeypatch.setattr(cli, "_config", lambda *_: config)
    monkeypatch.setattr(cli.process_control, "configure_from", lambda _support: None)
    monkeypatch.setattr(cli.threading, "Event", FakeEvent)
    monkeypatch.setattr(cli, "ForegroundRuntimeBoundary", lambda: boundary)
    monkeypatch.setattr(cli, "bootstrap", lambda *_: _result(endpoint=None, origin=None))
    monkeypatch.setattr(cli, "_wait_for_door", lambda *_: pytest.fail("door-off foreground run must not wait for a door"))
    monkeypatch.setattr(cli, "platform", SimpleNamespace(
        log_dir=lambda _home: tmp_path / "logs",
        owner_only=lambda _path: None,
        install_stop_handlers=lambda callback: (registration.update(handler=callback) or (lambda: None)),
    ))

    assert cli.main(["run", "--hosted-origin", "off", "--json"]) == 0
    assert boundary.stops == 1


def test_foreground_boundary_requires_door_thread_only_when_door_is_configured():
    from astrid_runtime.runtime_boundary import ForegroundRuntimeBoundary

    alive = SimpleNamespace(is_alive=lambda: True)
    boundary = ForegroundRuntimeBoundary()
    boundary.daemon = SimpleNamespace(
        thread=alive,
        door=None,
        door_thread=None,
        service=SimpleNamespace(_verified=True),
    )
    boundary.check_running()

    boundary.daemon.door = object()
    with pytest.raises(BootstrapError, match="browser door stopped unexpectedly"):
        boundary.check_running()


def test_foreground_boundary_retains_daemon_until_stop_succeeds():
    from astrid_runtime.runtime_boundary import ForegroundRuntimeBoundary

    boundary = ForegroundRuntimeBoundary()
    failure = RuntimeError("injected daemon stop failure")
    daemon = SimpleNamespace(stop=lambda: (_ for _ in ()).throw(failure))
    boundary.daemon = daemon
    with pytest.raises(RuntimeError, match="injected daemon stop failure"):
        boundary.stop()
    assert boundary.daemon is daemon

    daemon.stop = lambda: None
    assert boundary.stop() == {"children_stopped": True}
    assert boundary.daemon is None


def test_foreground_constructor_failure_removes_private_bootstrap_token(tmp_path, monkeypatch):
    from astrid_runtime.runtime_boundary import ForegroundRuntimeBoundary
    from runtime_protocol import daemon
    boundary = ForegroundRuntimeBoundary()
    monkeypatch.setattr(boundary, "_validate_source", lambda _source: None)
    monkeypatch.setattr(daemon, "RuntimeDaemon", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("bad daemon config")))
    support = tmp_path / "support"
    source = SimpleNamespace(runtime_command=None, runtime_environment=None, worker_profile=None)
    with pytest.raises(OSError, match="bad daemon config"):
        boundary.start(realm_id="realm", realm_root=tmp_path / "realm", owner_lock=support / "instance.lock", source_profile=source)
    assert not list(support.glob(".bootstrap-token-*"))
    assert boundary.daemon is None


def test_run_reports_invalid_data_root_without_traceback(capsys):
    assert cli.main(["run", "--data-root", "relative"]) == 1
    assert "absolute" in json.loads(capsys.readouterr().out)["error"]
