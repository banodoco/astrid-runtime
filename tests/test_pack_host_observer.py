from __future__ import annotations

import json

import pytest

from astrid_runtime import cli
from astrid_runtime_client import ApiError, WorkspaceClient
from tests.runtime_credentials import provision_executor_token
from tests.test_tasks_clear import _live_owner


@pytest.fixture
def live(tmp_path, monkeypatch):
    paths, daemon = _live_owner(tmp_path, monkeypatch)
    try:
        owner = WorkspaceClient(daemon.endpoint, daemon.token)
        owner.register_executor({
            "executor_id": "astrid-pack-host", "max_concurrency": 1,
            "resource_keys": [], "capabilities": ["render.basic"],
            "protocol": "workspace.v1", "source_digest": "sha256:" + "a" * 64,
            "dependency_digest": "sha256:" + "b" * 64, "source_epoch": "source-1",
        }, idempotency_key="register-pack-host")
        health = owner.health()
        args = ["observe-pack-host", "--json", "--endpoint", daemon.endpoint,
                "--runtime-instance-id", health.runtime_instance_id,
                "--runtime-session-id", health.runtime_session_id,
                "--runtime-epoch", str(health.runtime_epoch)]
        yield paths, daemon, owner, args
    finally:
        daemon.stop()


def test_observer_uses_owner_after_scoped_worker_handshake(live, capsys):
    _, daemon, owner, args = live
    worker_token = provision_executor_token(daemon, "astrid-pack-host")
    worker = WorkspaceClient(daemon.endpoint, worker_token)
    assert worker.handshake("astrid-generic-host", "1", ["worker:execute"]).actor_id == "astrid-pack-host"
    with pytest.raises(ApiError) as denied:
        worker.get_executor("astrid-pack-host")
    assert denied.value.status in (401, 403)
    foreign_token, _ = daemon.credentials.provision("foreign", ["handshake", "admin"])
    with pytest.raises(ApiError) as denied:
        WorkspaceClient(daemon.endpoint, foreign_token).get_executor("astrid-pack-host")
    assert denied.value.status in (401, 403)
    assert cli.main(args) == 0
    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["executor_id"] == "astrid-pack-host"
    assert result["readiness"] == "ready"
    assert result["runtime_epoch"] == owner.health().runtime_epoch
    assert result["runtime_session_id"] == owner.health().runtime_session_id
    assert result["source_epoch"] == "source-1"
    assert daemon.token not in output and worker_token not in output and foreign_token not in output
    assert set(result) == {"executor_id", "readiness", "runtime_epoch", "runtime_session_id", "source_epoch", "source_digest", "dependency_digest", "capabilities"}


@pytest.mark.parametrize("flag,value", [("--endpoint", "http://127.0.0.1:1"), ("--runtime-instance-id", "foreign"), ("--runtime-session-id", "foreign"), ("--runtime-epoch", "99999")])
def test_foreign_identity_fails_closed(live, capsys, flag, value):
    _, daemon, _, args = live
    args[args.index(flag) + 1] = value
    assert cli.main(args) == 1
    output = capsys.readouterr().out
    assert json.loads(output) == {"ok": False, "error": "pack host observation unavailable"}
    assert daemon.token not in output


def test_unavailable_owner_and_untrusted_errors_are_not_exposed(live, capsys, monkeypatch):
    _, daemon, _, args = live
    def fail(*_args, **_kwargs):
        raise RuntimeError("untrusted " + daemon.token)
    monkeypatch.setattr(cli, "_credential", fail)
    assert cli.main(args) == 1
    assert daemon.token not in capsys.readouterr().out


@pytest.mark.parametrize("actor,scopes", [("astrid-pack-host", ["handshake", "worker:execute"]), ("foreign", ["handshake", "admin"])])
def test_observer_rejects_non_owner_credentials(live, capsys, monkeypatch, actor, scopes):
    _, daemon, _, args = live
    token, _ = daemon.credentials.provision(actor, scopes)
    monkeypatch.setattr(cli, "_credential", lambda *_args, **_kwargs: token)
    assert cli.main(args) == 1
    output = capsys.readouterr().out
    assert json.loads(output)["ok"] is False
    assert token not in output


def test_observer_rejects_replaced_discovery(live, capsys, monkeypatch):
    paths, daemon, _, args = live
    original = cli._read_support_json
    count = 0
    def changed(path):
        nonlocal count
        value = original(path)
        if path == paths.discovery_path:
            count += 1
            if count == 2:
                return {**value, "endpoint": "http://127.0.0.1:1"}
        return value
    monkeypatch.setattr(cli, "_read_support_json", changed)
    assert cli.main(args) == 1
    assert daemon.token not in capsys.readouterr().out


@pytest.mark.parametrize("change", ["executor_session", "executor_epoch", "health_session", "credential_in_result", "oversized", "malformed"])
def test_observer_rejects_changed_evidence(live, capsys, monkeypatch, change):
    from dataclasses import replace
    import astrid_runtime_client
    _, daemon, _, args = live
    real_client = astrid_runtime_client.WorkspaceClient

    class AlteredClient:
        def __init__(self, *args, **kwargs):
            self.client = real_client(*args, **kwargs)
            self.health_calls = 0
        def health(self):
            self.health_calls += 1
            value = self.client.health()
            if change == "health_session" and self.health_calls == 2:
                return replace(value, runtime_session_id="replaced")
            return value
        def get_executor(self, executor_id):
            value = self.client.get_executor(executor_id)
            if change == "executor_session":
                return replace(value, runtime_session_id="replaced")
            if change == "executor_epoch":
                return replace(value, runtime_epoch=value.runtime_epoch + 1)
            if change == "credential_in_result":
                return replace(value, source_epoch=daemon.token)
            if change == "oversized":
                return replace(value, source_epoch="x" * 4097)
            if change == "malformed":
                return None
            return value

    monkeypatch.setattr(astrid_runtime_client, "WorkspaceClient", AlteredClient)
    assert cli.main(args) == 1
    output = capsys.readouterr().out
    assert json.loads(output)["ok"] is False
    assert daemon.token not in output


def test_many_capabilities_have_bounded_output(live, capsys, monkeypatch):
    from dataclasses import replace
    import astrid_runtime_client
    _, _, _, args = live
    real_client = astrid_runtime_client.WorkspaceClient
    class ManyCapabilities:
        def __init__(self, *args, **kwargs):
            self.client = real_client(*args, **kwargs)
        def health(self):
            return self.client.health()
        def get_executor(self, executor_id):
            value = self.client.get_executor(executor_id)
            return replace(value, capabilities=value.capabilities * 10000)
    monkeypatch.setattr(astrid_runtime_client, "WorkspaceClient", ManyCapabilities)
    assert cli.main(args) == 0
    output = capsys.readouterr().out
    assert len(output.encode()) < 65536
    assert len(json.loads(output)["capabilities"]) <= 1


def test_cli_data_root_is_parent_of_runtime(live, capsys, monkeypatch):
    from astrid_runtime.paths import RuntimePaths
    paths, daemon, _, args = live
    monkeypatch.setattr(cli, "_paths", lambda parsed: RuntimePaths.current(paths.home, data_root=parsed.data_root))
    assert cli.main(args + ["--data-root", str(paths.app_support)]) == 0
    assert json.loads(capsys.readouterr().out)["executor_id"] == "astrid-pack-host"
    assert cli.main(args + ["--data-root", str(paths.runtime_support)]) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False


def test_observer_never_follows_cross_port_redirect(live, capsys, monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    paths, daemon, _, args = live
    received = []
    origin_received = []
    class Sink(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.end_headers()
        def log_message(self, *args):
            pass
    sink = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self):
            origin_received.append(self.headers.get("Authorization"))
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{sink.server_port}/capture")
            self.end_headers()
        def log_message(self, *args):
            pass
    origin = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    threads = [Thread(target=server.serve_forever, daemon=True) for server in (sink, origin)]
    for thread in threads:
        thread.start()
    try:
        endpoint = f"http://127.0.0.1:{origin.server_port}"
        args[args.index("--endpoint") + 1] = endpoint
        original = cli._read_support_json
        def discovery(path):
            value = original(path)
            if path == paths.discovery_path:
                return {**value, "endpoint": endpoint}
            return value
        monkeypatch.setattr(cli, "_read_support_json", discovery)
        assert cli.main(args) == 1
        output = capsys.readouterr().out
        assert json.loads(output) == {"ok": False, "error": "pack host observation unavailable"}
        assert daemon.token not in output
        assert origin_received == ["Bearer " + daemon.token]
        assert received == []
    finally:
        for server in (origin, sink):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join()
