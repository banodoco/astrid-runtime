from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from jsonschema import Draft202012Validator

from astrid_runtime.bootstrap import BootstrapError, SourceProfile
from astrid_runtime.runtime_boundary import LocalRuntimeBoundary
from astrid_runtime import cli as operator_cli
from astrid_runtime_client.generated import Health
from runtime_protocol import platform
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ValidationError
from runtime_protocol.logs import RotatingLog
from runtime_protocol.server import RuntimeHandler
from runtime_protocol.services import ServiceConfiguration, ServiceSpec, ServiceSupervisor, load_service_configuration, parse_services
import runtime_protocol.services as services_module


ROOT = Path(__file__).resolve().parents[1]


def _document(**fields):
    return {"version": 1, "services": [{"name": "example", "argv": ["{python}", "-m", "example"],
        "restart": "always", **fields}]}


def _supervisor(tmp_path, specs=None, **kwargs):
    support = tmp_path / "support"
    platform.private_directory(support)
    config = ServiceConfiguration(tuple(specs or parse_services(_document())), sys.executable, tmp_path)
    return ServiceSupervisor(config, support_root=support, realm_root=tmp_path / "realm",
        realm_id="realm", runtime_endpoint="http://127.0.0.1:1234", log_directory=tmp_path / "logs", **kwargs)


def test_declaration_schema_and_parser_agree_on_portable_example():
    value = _document(env={"HANDSHAKE_ROOT": "{support_root}"}, ready={"file": "chat.json"})
    schema = json.loads((ROOT / "contract/schemas/services.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(value)
    spec, = parse_services(value)
    assert spec.argv == ("{python}", "-m", "example")
    assert spec.ready_file == "chat.json" and spec.ready_timeout == 30


@pytest.mark.parametrize("document", [
    None, [], {}, {"version": 2, "services": []}, {"version": True, "services": []},
    {"version": 1, "services": "example"}, {"version": 1, "services": [], "unknown": True},
    _document(argv="python -m example"), _document(argv=[]), _document(argv=[1]),
    _document(argv=["bad\0argument"]), _document(name="../escape"), _document(name="Example"),
    _document(restart="never"), _document(shell=True), _document(env={"BAD=KEY": "value"}),
    _document(env={"KEY": None}), _document(env={"ASTRID_RUNTIME_JOB_HANDLE": "123"}),
    _document(env={"ASTRID_RUNTIME_SERVICE_NAME": "pack-host"}),
    _document(env={"ASTRID_RUNTIME_SERVICE_LAUNCH_ID": "a" * 32}),
    _document(ready={"file": "../chat.json"}), _document(ready={"file": "catalog.json"}),
    _document(ready={"file": "chat.json", "timeout_seconds": 0}),
    _document(ready={"file": "chat.json", "timeout_seconds": float("inf")}),
    _document(ready={"file": "chat.json", "extra": True}),
    {"version": 1, "services": _document()["services"] * 2},
    {"version": 1, "services": [_document(ready={"file": "chat.json"})["services"][0],
        _document(name="other", ready={"file": "CHAT.json"})["services"][0]]},
])
def test_invalid_declaration_is_refused(document):
    with pytest.raises(ValidationError, match="Invalid service declaration"):
        parse_services(document)


@pytest.mark.parametrize("contents", [None, "{", "[]", " " * (256 * 1024 + 1)])
def test_missing_or_invalid_selected_declaration_is_not_silently_ignored(tmp_path, contents):
    path = tmp_path / "services.json"
    if contents is not None:
        path.write_text(contents, encoding="utf-8")
    with pytest.raises(ValidationError):
        load_service_configuration(path, python=sys.executable, source_checkout=tmp_path)


def test_unconfigured_services_do_not_read_any_paths_or_spawn(tmp_path, monkeypatch):
    spawn = Mock()
    monkeypatch.setattr(platform, "spawn_tree", spawn)
    assert load_service_configuration(None, python=None, source_checkout=None) is None
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support")
    assert daemon.services is None and daemon.service_status() == []
    spawn.assert_not_called()


def test_supervisor_marks_runtime_owned_service_name_after_configured_env(tmp_path, monkeypatch):
    spec = ServiceSpec("pack-host", (sys.executable,), "always", {"SERVICE_SETTING": "configured"})
    supervisor = _supervisor(tmp_path, [spec])
    monkeypatch.setenv("ASTRID_RUNTIME_SERVICE_NAME", "ambient-spoof")
    env = supervisor._environment(spec)
    assert env["ASTRID_RUNTIME_SERVICE_NAME"] == "pack-host"
    assert env["SERVICE_SETTING"] == "configured"
    assert "ASTRID_RUNTIME_SERVICE_LAUNCH_ID" not in env


def test_pack_host_cleanup_receipts_are_bounded_owner_only_and_preserved(tmp_path):
    supervisor = _supervisor(tmp_path, [ServiceSpec("pack-host", (sys.executable,), "always")])
    supervisor._record_service_cleanup("pack-host", 321, "windows-creation:10", "a" * 32)
    supervisor._record_service_cleanup("pack-host", 654, "windows-creation:20", "b" * 32)
    receipt = supervisor.support / "pack-host-job-cleanup.json"
    value = json.loads(receipt.read_text(encoding="utf-8"))
    assert value == {"version": 1, "service_name": "pack-host", "support_root": str(supervisor.support.resolve()),
        "receipts": [
            {"pid": 321, "process_birth_id": "windows-creation:10", "runtime_service_launch_id": "a" * 32,
                "job_drained": True},
            {"pid": 654, "process_birth_id": "windows-creation:20", "runtime_service_launch_id": "b" * 32,
                "job_drained": True},
        ]}


def test_service_cleanup_receipt_history_keeps_latest_64_attempts(tmp_path):
    supervisor = _supervisor(tmp_path, [ServiceSpec("pack-host", (sys.executable,), "always")])
    for index in range(65):
        supervisor._record_service_cleanup("pack-host", index + 1, f"birth:{index}", f"{index:032x}")
    value = json.loads((supervisor.support / "pack-host-job-cleanup.json").read_text(encoding="utf-8"))
    assert len(value["receipts"]) == 64
    assert value["receipts"][0]["runtime_service_launch_id"] == f"{1:032x}"
    assert value["receipts"][-1]["runtime_service_launch_id"] == f"{64:032x}"


def test_pack_host_cleanup_receipt_refuses_corrupt_history_without_overwriting(tmp_path):
    supervisor = _supervisor(tmp_path, [ServiceSpec("pack-host", (sys.executable,), "always")])
    receipt = supervisor.support / "pack-host-job-cleanup.json"
    receipt.write_text("{}", encoding="utf-8")
    platform.owner_only(receipt)
    with pytest.raises(OSError, match="unsupported schema"):
        supervisor._record_service_cleanup("pack-host", 321, "windows-creation:10", "a" * 32)
    assert receipt.read_text(encoding="utf-8") == "{}"


def test_shutdown_retry_publishes_pack_host_cleanup_receipt(tmp_path, monkeypatch):
    supervisor = _supervisor(tmp_path, [ServiceSpec("pack-host", (sys.executable,), "always")])
    item = supervisor._services[0]
    item.process = object()
    item.cleanup_identity = (321, "windows-creation:10", "a" * 32)
    monkeypatch.setattr(services_module, "sys", SimpleNamespace(platform="win32"))
    stopped = []
    monkeypatch.setattr(platform, "stop_tree", lambda process, **kwargs: stopped.append(process))

    supervisor.stop()

    assert len(stopped) == 1
    value = json.loads((supervisor.support / "pack-host-job-cleanup.json").read_text(encoding="utf-8"))
    assert value["receipts"] == [{"pid": 321, "process_birth_id": "windows-creation:10",
        "runtime_service_launch_id": "a" * 32, "job_drained": True}]
    assert item.process is None and item.cleanup_identity is None


def test_source_profile_selects_one_file_and_preserves_old_profile_digest(tmp_path):
    mapping = {"profile": "astrid", "runtime_checkout": str(ROOT), "source_checkout": str(tmp_path)}
    old = SourceProfile.from_mapping(mapping)
    assert "service_declaration" not in old.as_dict()
    assert SourceProfile.from_mapping(old.as_dict()).digest == old.digest
    profile = SourceProfile.from_mapping({**mapping, "service_declaration": str(tmp_path / "services.json")})
    assert profile.service_declaration == str(tmp_path / "services.json")
    assert SourceProfile.from_mapping(profile.as_dict()).digest == profile.digest != old.digest
    for path in (False, "", "relative/services.json"):
        with pytest.raises(BootstrapError, match="service_declaration"):
            SourceProfile.from_mapping({**mapping, "service_declaration": path})


def test_daemon_launch_passes_selected_declaration_and_environment_interpreter(tmp_path):
    declaration = tmp_path / "services.json"
    declaration.write_text(json.dumps(_document()), encoding="utf-8")
    profile = SourceProfile("astrid", str(ROOT), str(tmp_path), runtime_environment=sys.prefix,
        service_declaration=str(declaration))
    boundary = LocalRuntimeBoundary()
    argv = boundary._argv(profile, realm_id="realm", realm_root=tmp_path / "realm",
        support_root=tmp_path, display_name="Example", owner_lock=tmp_path / "instance.lock",
        token_file=tmp_path / "bootstrap.token")
    selected_python = str(Path(sys.prefix) / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
    assert argv[argv.index("--service-python") + 1] == selected_python == argv[0]
    assert argv[argv.index("--service-declaration") + 1] == str(declaration)
    assert argv[argv.index("--service-source-checkout") + 1] == str(tmp_path)
    assert "--log-file" in argv


@pytest.mark.parametrize("declared,grace", [(False, 5.0), (True, 20.0)])
def test_runtime_stop_allows_declared_trees_to_finish_their_shutdown(tmp_path, monkeypatch, declared, grace):
    from astrid_runtime import runtime_boundary as boundary_module
    monkeypatch.setattr(boundary_module, "sys", SimpleNamespace(platform="linux", exc_info=sys.exc_info))
    process = SimpleNamespace(pid=1234)
    monkeypatch.setattr(platform, "spawn_tree", lambda *_, **__: process)
    stop = Mock()
    monkeypatch.setattr(platform, "stop_tree", stop)
    argv = [sys.executable, "-m", "runtime_protocol", "start"]
    if declared:
        argv += ["--service-declaration", str(tmp_path / "services.json")]
    boundary = LocalRuntimeBoundary()
    boundary._spawn_runtime(argv, support_root=tmp_path, stdout=subprocess.DEVNULL)
    boundary._terminate(process)
    stop.assert_called_once_with(process, grace=grace)


def test_service_environment_and_argv_keep_spaces_and_literal_shell_syntax(tmp_path, monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "/unexpected")
    monkeypatch.setenv("ASTRID_RUNTIME_JOB_HANDLE", "123")
    monkeypatch.setenv("ASTRID_RUNTIME_CUSTODY_OWNER", "secret")
    monkeypatch.setenv("USERPROFILE", "user home with spaces")
    spec = ServiceSpec("example", ("{python}", "literal $HOME ; echo bad", "{support_root}"), "always",
        {"VALUE": "{support_root}", "EMPTY": ""})
    supervisor = _supervisor(tmp_path, [spec])
    process = SimpleNamespace(stdout=io.BytesIO(b"first\nsecond\n"), returncode=None)
    calls = []
    monkeypatch.setattr(platform, "spawn_tree", lambda argv, **kwargs: calls.append((argv, kwargs)) or process)
    monkeypatch.setattr(platform, "tree_exited", lambda _process: True)
    monkeypatch.setattr(platform, "stop_tree", lambda proc, **_: setattr(proc, "returncode", 9))
    with RotatingLog(tmp_path / "logs/service-example.log") as log:
        code, _, _ = supervisor._attempt(supervisor._services[0], log)
    argv, options = calls[0]
    assert argv == [sys.executable, "literal $HOME ; echo bad", str(tmp_path / "support")]
    assert "shell" not in options and options["cwd"] == tmp_path and options["hidden"] is True
    assert options["stdin"] == subprocess.PIPE and options["stderr"] == subprocess.STDOUT
    assert options["env"]["VALUE"] == str(tmp_path / "support")
    assert options["env"]["EMPTY"] == "" and options["env"]["USERPROFILE"] == "user home with spaces"
    assert options["env"]["PATH"].split(os.pathsep)[0] == str(Path(sys.executable).parent)
    assert not {"PYTHONPATH", "ASTRID_RUNTIME_JOB_HANDLE", "ASTRID_RUNTIME_CUSTODY_OWNER"} & options["env"].keys()
    assert code == 9 and supervisor.snapshot()[0]["last_exit"] == 9
    assert (tmp_path / "logs/service-example.log").read_text() == "first\nsecond\n"


def test_windows_service_environment_uses_userprofile_when_home_is_absent(tmp_path, monkeypatch):
    from runtime_protocol import services
    monkeypatch.setattr(services, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.setenv("USERPROFILE", "user home with spaces")
    supervisor = _supervisor(tmp_path)

    assert supervisor._environment(supervisor._services[0].spec)["HOME"] == "user home with spaces"


def test_restart_backoff_caps_and_resets_only_after_stable_running(tmp_path, monkeypatch):
    supervisor = _supervisor(tmp_path)
    delays, observed = [], []
    class Stop:
        stopped = False
        def is_set(self): return self.stopped
        def wait(self, delay):
            delays.append(delay)
            observed.append(supervisor.snapshot()[0])
            self.stopped = len(delays) == 8
            return self.stopped
    supervisor._stop = Stop()
    attempts = iter([(4, 0, None)] * 7 + [(4, 60, None)])
    monkeypatch.setattr(supervisor, "_attempt", lambda *_: next(attempts))
    supervisor._run(supervisor._services[0])
    assert delays == [1, 2, 4, 8, 16, 30, 30, 1]
    assert [row["state"] for row in observed] == ["restarting", "restarting", "failed", "failed", "failed", "failed", "failed", "restarting"]
    assert all(row["reason"] == "exited" for row in observed)
    assert supervisor.snapshot()[0]["restart_count"] == 7


def test_restart_starting_state_preserves_last_reason_and_exit(tmp_path, monkeypatch):
    supervisor = _supervisor(tmp_path, [ServiceSpec("example", (sys.executable,), "on-failure")])
    starts, retry_states = [], []

    def attempt(item, _log):
        starts.append(supervisor.snapshot()[0])
        if len(starts) == 1:
            supervisor._update(item, last_exit=7)
            return 7, 0.0, "readiness_timeout"
        return 0, 0.0, None

    def wait(_delay):
        retry_states.append(supervisor.snapshot()[0])
        return False

    monkeypatch.setattr(supervisor, "_attempt", attempt)
    monkeypatch.setattr(supervisor._stop, "wait", wait)
    supervisor._run(supervisor._services[0])

    assert retry_states == [{"name": "example", "state": "restarting", "last_exit": 7,
        "restart_count": 0, "reason": "readiness_timeout"}]
    assert starts[1] == {"name": "example", "state": "starting", "last_exit": 7,
        "restart_count": 1, "reason": "readiness_timeout"}


@pytest.mark.parametrize("policy,restarts", [("always", True), ("on-failure", False)])
def test_clean_exit_obeys_restart_policy(tmp_path, monkeypatch, policy, restarts):
    supervisor = _supervisor(tmp_path, [ServiceSpec("example", (sys.executable,), policy)])
    def attempt(item, _log):
        supervisor._update(item, last_exit=0)
        return 0, 0, None
    monkeypatch.setattr(supervisor, "_attempt", attempt)
    delays = []
    def stop_during_backoff(delay):
        delays.append(delay)
        supervisor._stop.set()
        return True
    monkeypatch.setattr(supervisor._stop, "wait", stop_during_backoff)
    supervisor._run(supervisor._services[0])
    row, = supervisor.snapshot()
    assert row["last_exit"] == 0
    assert row["state"] == ("restarting" if restarts else "failed")
    assert delays == ([1] if restarts else [])


def test_fast_launch_failures_keep_safe_reason_when_marked_failed(tmp_path, monkeypatch):
    supervisor = _supervisor(tmp_path)
    attempt = Mock(side_effect=FileNotFoundError("sensitive argv"))
    monkeypatch.setattr(supervisor, "_attempt", attempt)
    observed = []

    def stop(delay):
        row, = supervisor.snapshot()
        observed.append(row)
        if row["state"] == "failed":
            supervisor._stop.set()
            return True
        return False

    monkeypatch.setattr(supervisor._stop, "wait", stop)
    supervisor._run(supervisor._services[0])
    assert attempt.call_count == 3
    assert all(row["reason"] == "launch_failed" for row in observed)
    assert supervisor.snapshot()[0]["state"] == "failed"
    assert supervisor.snapshot()[0]["reason"] == "launch_failed"
    assert "sensitive argv" not in json.dumps(supervisor.snapshot())


def test_ready_timeout_removes_stale_hint_and_cleans_tree(tmp_path, monkeypatch):
    spec = ServiceSpec("example", (sys.executable,), "on-failure", ready_file="chat.json", ready_timeout=0.01)
    supervisor = _supervisor(tmp_path, [spec], grace=0.1)
    ready = tmp_path / "support/chat.json"
    ready.write_text("stale", encoding="utf-8")
    process = SimpleNamespace(stdout=io.BytesIO(b""), returncode=None)
    def spawn(*_, **__):
        assert not ready.exists()
        return process
    monkeypatch.setattr(platform, "spawn_tree", spawn)
    monkeypatch.setattr(platform, "tree_exited", lambda _: False)
    stop = Mock(side_effect=lambda proc, **_: setattr(proc, "returncode", -15))
    monkeypatch.setattr(platform, "stop_tree", stop)
    with RotatingLog(tmp_path / "logs/service-example.log") as log:
        code, stable_for, reason = supervisor._attempt(supervisor._services[0], log)
    assert (code, stable_for, reason) == (-15, 0, "readiness_timeout")
    assert not ready.exists()
    stop.assert_called_once_with(process, grace=0.1, stop_channel=True)


def test_stability_window_excludes_tree_and_log_cleanup_time(tmp_path, monkeypatch):
    from runtime_protocol import services
    supervisor = _supervisor(tmp_path)
    process = SimpleNamespace(stdout=io.BytesIO(b""), returncode=None)
    clock = iter([0.0, 2.0, 3.0, 60.0])
    monkeypatch.setattr(services, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    monkeypatch.setattr(platform, "spawn_tree", lambda *_, **__: process)
    monkeypatch.setattr(platform, "tree_exited", Mock(side_effect=[False, False, True]))
    monkeypatch.setattr(platform, "stop_tree", lambda proc, **_: setattr(proc, "returncode", 7))
    monkeypatch.setattr(supervisor._stop, "wait", lambda _: False)
    with RotatingLog(tmp_path / "logs/service-example.log") as log:
        code, stable_for, reason = supervisor._attempt(supervisor._services[0], log)
    assert (code, stable_for, reason) == (7, 60.0, None)


def test_fast_exit_never_reports_running_with_mocked_process(tmp_path, monkeypatch):
    from runtime_protocol import services
    supervisor = _supervisor(tmp_path)
    process = SimpleNamespace(stdout=io.BytesIO(b""), returncode=None)
    clock = iter([0.0, 0.0, 0.1])
    monkeypatch.setattr(services, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    monkeypatch.setattr(platform, "spawn_tree", lambda *_, **__: process)
    monkeypatch.setattr(platform, "tree_exited", Mock(side_effect=[False, True]))
    monkeypatch.setattr(platform, "stop_tree", lambda proc, **_: setattr(proc, "returncode", 1))
    observed = []
    monkeypatch.setattr(supervisor._stop, "wait", lambda _: observed.append(supervisor.snapshot()[0]["state"]))
    with RotatingLog(tmp_path / "logs/service-example.log") as log:
        result = supervisor._attempt(supervisor._services[0], log)
    assert result == (1, 0.0, None)
    assert observed == ["starting"]


@pytest.mark.parametrize("declares_ready", [False, True])
def test_running_waits_for_stability_or_declared_readiness(tmp_path, monkeypatch, declares_ready):
    from runtime_protocol import services
    spec = ServiceSpec("example", (sys.executable,), "always", ready_file="service.ready" if declares_ready else None)
    supervisor = _supervisor(tmp_path, [spec])
    process = SimpleNamespace(stdout=io.BytesIO(b""), returncode=None)
    now, states = [0.0], []
    observed = []
    supervisor._update(supervisor._services[0], last_exit=7, reason="readiness_timeout")
    monkeypatch.setattr(services, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr(platform, "spawn_tree", lambda *_, **__: process)
    monkeypatch.setattr(platform, "tree_exited", lambda _: now[0] >= 3.0)
    monkeypatch.setattr(platform, "stop_tree", lambda proc, **_: setattr(proc, "returncode", 1))
    def wait(delay):
        states.append(supervisor.snapshot()[0]["state"])
        observed.append(supervisor.snapshot()[0])
        now[0] += 1.0
        if declares_ready and now[0] == 1.0:
            (tmp_path / "support/service.ready").write_text("ready", encoding="utf-8")
    monkeypatch.setattr(supervisor._stop, "wait", wait)
    with RotatingLog(tmp_path / "logs/service-example.log") as log:
        code, stable_for, reason = supervisor._attempt(supervisor._services[0], log)
    assert code == 1 and reason is None
    assert states == (["starting", "running", "running"] if declares_ready else ["starting", "starting", "running"])
    assert stable_for == (2.0 if declares_ready else 3.0)
    running_rows = [row for row in observed if row["state"] == "running"]
    assert running_rows and all(row["last_exit"] == 7 and row["reason"] == "readiness_timeout"
        for row in running_rows)


@pytest.mark.parametrize("state,code", [("starting", None), ("running", None), ("restarting", 7), ("failed", 0)])
def test_health_and_typed_operator_status_preserve_service_state(state, code):
    rows = [{"name": "example", "state": state, "last_exit": code, "restart_count": 2, "reason": "exited"}]
    base = {"status": "ok", "protocol": "workspace.v1", "schema_digest": "sha256:" + "a" * 64,
        "runtime_epoch": 1, "runtime_session_id": "session"}
    handler = object.__new__(RuntimeHandler)
    handler.path, handler.command = "/v1/health", "GET"
    handler.server = SimpleNamespace(runtime=SimpleNamespace(health=lambda: base),
        daemon_runtime=SimpleNamespace(startup_identity_instance_id="instance",
            startup_identity={"release": 0, "managed_by": None}, service_status=lambda: rows))
    handler._send = lambda status, body: (status, body)
    status, value = handler._route()
    assert status == 200 and value == {**base, "runtime_instance_id": "instance",
        "identity": {"release": 0, "managed_by": None}, "services": rows}
    schema = json.loads((ROOT / "contract/schemas/health.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(value)
    assert operator_cli._json_value(Health.from_json(value))["services"] == rows
    assert Health.from_json({**base, "runtime_instance_id": "instance", "identity": None}).services == ()


def test_typed_service_status_accepts_future_response_fields():
    from astrid_runtime_client import ServiceStatus
    row = {"name": "example", "state": "running", "last_exit": None, "restart_count": 0, "future": "value"}
    assert ServiceStatus.from_json(row) == ServiceStatus("example", "running", None, 0)


def test_typed_service_status_states_match_health_contract():
    from typing import get_args, get_type_hints
    from astrid_runtime_client import ServiceStatus
    schema = json.loads((ROOT / "contract/schemas/health.json").read_text(encoding="utf-8"))
    states = schema["properties"]["services"]["items"]["properties"]["state"]["enum"]
    assert set(get_args(get_type_hints(ServiceStatus)["state"])) == set(states)


def test_runtime_and_service_logs_close_before_rotation_and_bound_backups(tmp_path):
    for name in ("runtime.log", "service-example.log"):
        path = tmp_path / name
        with RotatingLog(path, max_bytes=5, backups=3) as log:
            for index in range(7):
                log.write(f"{index}abc\n")
        assert path.read_text() == "6abc\n"
        assert [(tmp_path / f"{name}.{index}").read_text() for index in range(1, 4)] == ["5abc\n", "4abc\n", "3abc\n"]
        assert not (tmp_path / f"{name}.4").exists()


def test_linux_exit_observation_preserves_waitable_group_anchor(monkeypatch):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="linux"))
    for name, value in {"P_PID": 1, "WEXITED": 4, "WNOHANG": 1, "WNOWAIT": 0x1000000}.items():
        monkeypatch.setattr(os, name, value, raising=False)
    observed = Mock(return_value=SimpleNamespace(si_status=3))
    monkeypatch.setattr(os, "waitid", observed, raising=False)
    child = SimpleNamespace(pid=1234, returncode=None, poll=Mock(side_effect=AssertionError("must not reap")))
    assert platform.tree_exited(child)
    observed.assert_called_once_with(os.P_PID, 1234, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    child.poll.assert_not_called()


def test_darwin_tree_cleanup_observes_zombie_before_group_kill_and_wait(monkeypatch):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="darwin"))
    calls = []
    child = SimpleNamespace(pid=1234, returncode=None, _waitpid_lock=threading.Lock(),
        wait=lambda **_: calls.append("wait"))
    monkeypatch.setattr(platform, "_read_darwin_process_info", lambda _pid, **_: {"status": 5})
    monkeypatch.setattr(platform, "signal_tree", lambda proc, sig: calls.append(sig))
    assert platform.tree_exited(child)
    platform.stop_tree(child, grace=0.01)
    assert calls == [platform.KILL, "wait"]


def test_windows_exit_observation_keeps_job_for_cleanup(monkeypatch):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="win32"))
    job = SimpleNamespace(handle=1, close=Mock(), active_processes=lambda: 0)
    child = SimpleNamespace(pid=1234, args=["worker"], returncode=7, poll=lambda: 7,
        wait=Mock(), _runtime_job=job)
    monkeypatch.setattr(platform, "signal_tree", Mock())
    assert platform.tree_exited(child)
    platform.stop_tree(child)
    job.close.assert_called_once()


def test_windows_service_spawn_assigns_job_before_resuming_and_hides_console(monkeypatch):
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="win32"))
    events = []
    job = SimpleNamespace(handle=123, assign=lambda process: events.append("assigned"), close=Mock())
    process = SimpleNamespace(pid=1234)
    monkeypatch.setattr(platform, "_Job", lambda: job)
    monkeypatch.setattr(platform, "_resume_process", lambda _pid: events.append("resumed"))
    popen = Mock(return_value=process)
    monkeypatch.setattr(platform.subprocess, "Popen", popen)
    assert platform.spawn_tree(["python.exe", "service.py"], hidden=True) is process
    assert popen.call_args.kwargs["creationflags"] & 0x08000000
    assert popen.call_args.kwargs["creationflags"] & 0x4
    assert process._runtime_job is job and events == ["assigned", "resumed"]
    job.close.assert_not_called()


@pytest.mark.parametrize("winerror", [5, 32, 33])
def test_rotation_retries_windows_sharing_violation_after_closing_log(tmp_path, monkeypatch, winerror):
    from runtime_protocol import logs
    monkeypatch.setattr(logs, "sys", SimpleNamespace(platform="win32"))
    real_replace = Path.replace
    attempts = []
    with RotatingLog(tmp_path / "runtime.log", max_bytes=5) as log:
        def replace(path, target):
            assert log._file.closed
            attempts.append(path)
            if len(attempts) == 1:
                error = PermissionError("sharing violation")
                error.winerror = winerror
                raise error
            return real_replace(path, target)
        monkeypatch.setattr(Path, "replace", replace)
        log.write("12345")
        log.write("next")
    assert len(attempts) == 2
    assert (tmp_path / "runtime.log.1").read_text() == "12345"
    assert (tmp_path / "runtime.log").read_text() == "next"


@pytest.mark.parametrize("declared", [False, True])
def test_daemon_starts_services_after_readiness_and_stops_before_realm_close(tmp_path, monkeypatch, declared):
    from runtime_protocol import daemon as daemon_module, services as services_module
    events = []
    service = Mock(realm={"id": "realm", "display_name": "Example"})
    service.catalog_admission.return_value = {"runtime_epoch": 1}
    service.close.side_effect = lambda: events.append("realm_closed")
    monkeypatch.setattr(daemon_module, "RuntimeService", lambda *_, **__: service)
    class Listener:
        server_port = 1234
        accepting_authenticated_requests = True
        def __init__(self, *_): pass
        def serve_forever(self): pass
        def shutdown(self): events.append("listener_shutdown")
        def server_close(self): pass
    class Thread:
        def __init__(self, **_): self.started = False
        def start(self): self.started = True; events.append("listener_started")
        def is_alive(self): return self.started
    monkeypatch.setattr(daemon_module, "RuntimeHTTPServer", Listener)
    monkeypatch.setattr(daemon_module.threading, "Thread", Thread)
    config = ServiceConfiguration(parse_services(_document()), sys.executable, tmp_path) if declared else None
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support", services=config, log_directory=tmp_path / "logs")
    daemon._provision_credentials = lambda **_: None
    daemon.catalog = Mock()
    class Supervisor:
        def __init__(self, selected, **kwargs):
            assert selected is config and kwargs["log_directory"] == tmp_path / "logs"
        def start(self):
            assert daemon.thread.is_alive()
            assert json.loads((tmp_path / "support/discovery.json").read_text())["endpoint"] == daemon.endpoint
            events.append("services_started")
        def begin_shutdown(self): events.append("services_fenced")
        def stop(self): events.append("services_stopped")
        def snapshot(self): return [{"name": "example", "state": "running", "last_exit": None, "restart_count": 0}]
    monkeypatch.setattr(services_module, "ServiceSupervisor", Supervisor)
    daemon.start()
    assert bool(daemon.service_status()) == declared
    daemon.stop()
    if declared:
        assert events.index("listener_started") < events.index("services_started")
        assert events.index("services_fenced") < events.index("services_stopped") < events.index("realm_closed")
    else:
        assert events == ["listener_started", "listener_shutdown", "realm_closed"]


def test_foreground_passes_the_same_declaration_and_log_directory(tmp_path, monkeypatch):
    from astrid_runtime import runtime_boundary as boundary_module
    from runtime_protocol import daemon as daemon_module
    path = tmp_path / "services.json"
    path.write_text(json.dumps(_document()), encoding="utf-8")
    source = SourceProfile("astrid", str(ROOT), str(tmp_path), runtime_environment=sys.prefix, service_declaration=str(path))
    observed = []
    daemon = Mock()
    def construct(*args, **kwargs):
        observed.append(kwargs)
        return daemon
    monkeypatch.setattr(daemon_module, "RuntimeDaemon", construct)
    monkeypatch.setattr(boundary_module, "NativeProcessCustody", Mock())
    boundary = boundary_module.ForegroundRuntimeBoundary()
    boundary._log_directory = tmp_path / "logs"
    boundary.start(realm_id="realm", realm_root=tmp_path / "realm", owner_lock=tmp_path / "support/instance.lock", source_profile=source)
    try:
        options, = observed
        assert options["services"].python == sys.executable
        assert options["services"].services == parse_services(_document())
        assert options["services"].source_checkout == tmp_path
        assert options["log_directory"] == tmp_path / "logs"
        daemon.start.assert_called_once()
    finally:
        boundary.stop()


def _wait(check, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError("Service did not reach expected state")


@pytest.mark.integration
def test_real_service_starts_logs_and_publishes_running_status(tmp_path):
    script = tmp_path / "service.py"
    script.write_text("import os,time\nprint(os.environ['SERVICE_VALUE'], flush=True)\ntime.sleep(120)\n", encoding="utf-8")
    spec = ServiceSpec("example", (sys.executable, "-u", str(script)), "always", {"SERVICE_VALUE": "service started"})
    supervisor = _supervisor(tmp_path, [spec], grace=0.1)
    try:
        supervisor.start()
        _wait(lambda: supervisor.snapshot()[0]["state"] == "running")
        log = tmp_path / "logs/service-example.log"
        _wait(lambda: log.exists() and "service started" in log.read_text())
        assert supervisor.snapshot() == [{"name": "example", "state": "running", "last_exit": None, "restart_count": 0}]
    finally:
        supervisor.stop()
    assert supervisor._services[0].process is None


@pytest.mark.integration
def test_real_crash_restarts_after_backoff_and_preserves_last_exit(tmp_path):
    attempts = tmp_path / "attempts.txt"
    script = tmp_path / "service.py"
    script.write_text("import pathlib,sys,time\np=pathlib.Path(sys.argv[1])\n"
        "previous=p.read_text() if p.exists() else ''\nt=p.with_suffix('.tmp')\n"
        "t.write_text(previous+str(time.monotonic())+'\\n')\nt.replace(p)\n"
        "if not previous: sys.exit(7)\ntime.sleep(120)\n", encoding="utf-8")
    supervisor = _supervisor(tmp_path, [ServiceSpec("example", (sys.executable, str(script), str(attempts)), "on-failure")],
        initial_backoff=0.3, max_backoff=0.6, grace=0.1)
    try:
        supervisor.start()
        _wait(lambda: supervisor.snapshot()[0]["last_exit"] == 7)
        _wait(lambda: supervisor.snapshot()[0]["restart_count"] == 1 and supervisor.snapshot()[0]["state"] == "running")
        _wait(lambda: len(attempts.read_text().splitlines()) == 2)
        first, second = map(float, attempts.read_text().splitlines())
        assert second - first >= 0.3
        assert supervisor.snapshot()[0]["last_exit"] == 7
        assert "retrying in 0.3s" in (tmp_path / "logs/service-example.log").read_text()
    finally:
        supervisor.stop()


@pytest.mark.integration
def test_immediate_exit_service_never_reports_running_and_marks_startup_failure(tmp_path):
    script = tmp_path / "service.py"
    script.write_text("raise SystemExit(1)\n", encoding="utf-8")
    supervisor = _supervisor(tmp_path, [ServiceSpec("example", (sys.executable, str(script),), "always")],
        initial_backoff=0.2, max_backoff=0.2, grace=0.05)
    observed = []
    try:
        supervisor.start()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            row, = supervisor.snapshot()
            observed.append(row)
            if row["state"] == "failed" and row["restart_count"] >= 2:
                break
            time.sleep(0.005)
        else:
            pytest.fail("immediate-exit service did not reach repeated-startup-failure state")
        assert all(row["state"] != "running" for row in observed)
        assert row["last_exit"] == 1
        assert row["reason"] == "exited"
    finally:
        supervisor.stop()


@pytest.mark.integration
@pytest.mark.parametrize("crash", [False, True])
def test_real_shutdown_and_crash_cleanup_kill_stubborn_descendant(tmp_path, crash):
    script = tmp_path / "tree.py"
    pid_file = tmp_path / "child.pid"
    ready = tmp_path / "support/tree.ready"
    script.write_text(
        "import os,pathlib,signal,subprocess,sys,time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "if hasattr(signal, 'SIGBREAK'): signal.signal(signal.SIGBREAK, signal.SIG_IGN)\n"
        "if sys.argv[1] == 'child':\n"
        " p=pathlib.Path(sys.argv[2]); t=p.with_suffix('.tmp')\n"
        " t.write_text(str(os.getpid())); t.replace(p)\n"
        "else:\n"
        " subprocess.Popen([sys.executable, __file__, 'child', sys.argv[2]])\n"
        " while not pathlib.Path(sys.argv[2]).exists(): time.sleep(0.01)\n"
        " pathlib.Path(sys.argv[3]).write_text('ready')\n"
        " if sys.argv[1] == 'crash': sys.exit(9)\n"
        "time.sleep(120)\n", encoding="utf-8")
    spec = ServiceSpec("example", (sys.executable, str(script), "crash" if crash else "parent", str(pid_file), str(ready)),
        "always", ready_file="tree.ready")
    supervisor = _supervisor(tmp_path, [spec], initial_backoff=30, grace=0.1)
    child_pid = None
    try:
        supervisor.start()
        _wait(lambda: pid_file.exists())
        child_pid = int(pid_file.read_text())
        if crash:
            _wait(lambda: supervisor.snapshot()[0]["last_exit"] == 9)
            _wait(lambda: platform.process_identity(child_pid) is None)
        else:
            _wait(lambda: supervisor.snapshot()[0]["state"] == "running")
            assert platform.process_identity(child_pid) is not None
    finally:
        supervisor.stop()
    assert child_pid is not None
    _wait(lambda: platform.process_identity(child_pid) is None)
    assert not ready.exists()


@pytest.mark.integration
@pytest.mark.parametrize("command", ["run", "up"])
def test_installed_run_and_up_supervise_declared_service_and_report_status(tmp_path, stage1_runtime_environment, command):
    from tests.test_portable_lifecycle import (
        _command, _environment, _manifest, _prepare_workspace, _python, _stop_foreground, _wait_for_discovery,
    )
    manifest = _manifest(tmp_path)
    env = _environment(tmp_path)
    declaration = tmp_path / "services.json"
    script = tmp_path / "service.py"
    observed = tmp_path / "observed.json"
    script.write_text("import json,os,pathlib,signal,sys,time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "if hasattr(signal, 'SIGBREAK'): signal.signal(signal.SIGBREAK, signal.SIG_IGN)\n"
        "support=pathlib.Path(sys.argv[2])\n"
        "d=json.loads((support/'discovery.json').read_text())\n"
        "p=pathlib.Path(sys.argv[1]); t=p.with_suffix('.tmp')\n"
        "t.write_text(json.dumps({'python':sys.executable,'endpoint':d['endpoint'],'pid':os.getpid()})); t.replace(p)\n"
        "time.sleep(120)\n", encoding="utf-8")
    declaration.write_text(json.dumps(_document(argv=["{python}", str(script), str(observed), "{support_root}"])), encoding="utf-8")
    profile = json.loads(manifest.read_text())
    profile.update(service_declaration=str(declaration), runtime_environment=str(stage1_runtime_environment))
    manifest.write_text(json.dumps(profile), encoding="utf-8")
    created = _prepare_workspace(stage1_runtime_environment, manifest, env)
    assert created.returncode == 0, created.stdout + created.stderr
    process = None
    up_started = False
    service_pid = None
    try:
        argv = _command(stage1_runtime_environment, manifest, command, "--door-port", "0")
        if command == "run":
            process = platform.spawn_tree(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            discovery = _wait_for_discovery(tmp_path / "support/runtime/discovery.json", process)
        else:
            started = subprocess.run([*argv, "--wait"], env=env, capture_output=True, text=True, timeout=90)
            assert started.returncode == 0, started.stdout + started.stderr
            up_started = True
            discovery = json.loads((tmp_path / "support/runtime/discovery.json").read_text())
        _wait(lambda: observed.exists())
        launched = json.loads(observed.read_text())
        service_pid = launched["pid"]
        assert launched == {"python": str(_python(stage1_runtime_environment)), "endpoint": discovery["endpoint"], "pid": service_pid}
        assert platform.process_identity(service_pid) is not None
        status_command = [str(_python(stage1_runtime_environment)), "-m", "astrid_runtime.cli", "status",
            "--data-root", str(tmp_path / "support"), "--json"]
        status = subprocess.run(status_command, env=env, capture_output=True, text=True, timeout=30)
        assert status.returncode == 0, status.stdout + status.stderr
        rows = json.loads(status.stdout)["health"]["services"]
        assert rows[0]["name"] == "example"
        states = [rows[0]["state"]]
        assert rows[0]["state"] in {"starting", "running"}
        deadline = time.monotonic() + 15
        while rows[0]["state"] != "running" and time.monotonic() < deadline:
            time.sleep(0.1)
            status = subprocess.run(status_command, env=env, capture_output=True, text=True, timeout=30)
            assert status.returncode == 0, status.stdout + status.stderr
            rows = json.loads(status.stdout)["health"]["services"]
            states.append(rows[0]["state"])
        assert rows[0]["state"] == "running", f"service did not become running before deadline: {rows}"
        if "starting" in states:
            assert states.index("starting") < states.index("running")
        assert rows[0]["name"] == "example" and rows[0]["state"] == "running" and rows[0]["last_exit"] is None
    finally:
        if process is not None:
            _stop_foreground(process)
        elif up_started:
            stopped = subprocess.run(_command(stage1_runtime_environment, manifest, "down"), env=env,
                capture_output=True, text=True, timeout=45)
            assert stopped.returncode == 0, stopped.stdout + stopped.stderr
    assert service_pid is not None
    _wait(lambda: platform.process_identity(service_pid) is None)
