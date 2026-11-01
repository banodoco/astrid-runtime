from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from runtime_protocol.daemon import RuntimeDaemon


def _git(path: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(path), *args], check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()


def _repo(path: Path) -> Path:
    path.mkdir()
    _git(path, "init", "-q")
    _git(path, "config", "user.email", "test@example.invalid")
    _git(path, "config", "user.name", "Test")
    (path / "tracked").write_text("initial")
    _git(path, "add", "tracked")
    _git(path, "commit", "-qm", "initial")
    return path


def _owner(runtime: Path, agent: Path) -> RuntimeDaemon:
    daemon = RuntimeDaemon.__new__(RuntimeDaemon)
    daemon.instance_id = "first-owner"
    daemon._identity_runtime_checkout = runtime
    daemon._identity_agent_checkout = agent
    daemon._startup_identity = None
    daemon._startup_identity_instance_id = None
    return daemon


def test_source_identity_is_snapshotted_and_defensively_copied(tmp_path, monkeypatch):
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    owner = _owner(runtime, agent)
    monkeypatch.delenv("ASTRID_INSTALL_RELEASE", raising=False)
    monkeypatch.delenv("ASTRID_INSTALL_MANAGED_BY", raising=False)
    owner._bind_startup_identity()
    captured = owner.startup_identity
    assert captured["managed_by"] == "source" and captured["dirty"] is False
    captured["dirty"] = True
    monkeypatch.setenv("ASTRID_INSTALL_RELEASE", "17")
    monkeypatch.setenv("ASTRID_INSTALL_MANAGED_BY", "pinokio")
    (runtime / "tracked").write_text("changed while owner lives")
    assert owner.startup_identity["dirty"] is False
    assert owner.startup_identity["runtime_head"] == _git(runtime, "rev-parse", "HEAD")
    assert owner.startup_identity_instance_id == "first-owner"

    owner.instance_id = "replacement-owner"
    monkeypatch.delenv("ASTRID_INSTALL_RELEASE")
    monkeypatch.delenv("ASTRID_INSTALL_MANAGED_BY")
    owner._bind_startup_identity()
    assert owner.startup_identity_instance_id == "replacement-owner"
    assert owner.startup_identity["dirty"] is True


def test_installed_identity_uses_decimal_release_and_null_native(tmp_path, monkeypatch):
    owner = _owner(_repo(tmp_path / "runtime"), _repo(tmp_path / "agent"))
    monkeypatch.setenv("ASTRID_INSTALL_RELEASE", "23")
    monkeypatch.setenv("ASTRID_INSTALL_MANAGED_BY", "")
    owner._bind_startup_identity()
    assert owner.startup_identity == {"release": 23, "managed_by": None}


def test_direct_neutral_daemon_uses_legacy_identity(monkeypatch):
    owner = _owner(None, None)
    monkeypatch.delenv("ASTRID_INSTALL_RELEASE", raising=False)
    monkeypatch.delenv("ASTRID_INSTALL_MANAGED_BY", raising=False)
    owner._bind_startup_identity()
    assert owner.startup_identity == {"release": 0, "managed_by": None}


def test_actual_owner_restart_captures_new_snapshot_without_publication(tmp_path, monkeypatch):
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    realm, support = tmp_path / "realm", tmp_path / "support"
    from runtime_protocol.store import RealmStore
    RealmStore.initialize(realm, display_name="Test", realm_id="test").close()
    monkeypatch.delenv("ASTRID_INSTALL_RELEASE", raising=False)
    monkeypatch.delenv("ASTRID_INSTALL_MANAGED_BY", raising=False)
    daemon = RuntimeDaemon(realm, support_root=support, runtime_checkout=runtime,
                          agent_checkout=agent, realm_id="test")
    try:
        daemon.start()
        first_id = daemon.instance_id
        first_identity = daemon.startup_identity
        assert daemon.startup_identity_instance_id == first_id
        assert "startup_identity" not in daemon.service.health()
        assert "startup_identity" not in daemon.discovery.read()
        (runtime / "tracked").write_text("live edit")
        monkeypatch.setenv("ASTRID_INSTALL_RELEASE", "99")
        assert daemon.startup_identity == first_identity
        daemon.stop()
        _git(runtime, "add", "tracked")
        _git(runtime, "commit", "-qm", "next")
        monkeypatch.delenv("ASTRID_INSTALL_RELEASE")
        daemon.start()
        assert daemon.instance_id != first_id
        assert daemon.startup_identity_instance_id == daemon.instance_id
        assert daemon.startup_identity["runtime_head"] != first_identity["runtime_head"]
        assert "startup_identity" not in daemon.service.health()
        assert "startup_identity" not in daemon.discovery.read()
    finally:
        daemon.stop()


def test_actual_owner_installed_env_overrides_archive_source_paths(tmp_path, monkeypatch):
    runtime, agent = tmp_path / "runtime-archive", tmp_path / "agent-archive"
    runtime.mkdir()
    agent.mkdir()
    realm, support = tmp_path / "realm", tmp_path / "support"
    from runtime_protocol.store import RealmStore
    RealmStore.initialize(realm, display_name="Test", realm_id="test").close()
    monkeypatch.setenv("ASTRID_INSTALL_RELEASE", "31")
    monkeypatch.setenv("ASTRID_INSTALL_MANAGED_BY", "pinokio")
    daemon = RuntimeDaemon(realm, support_root=support, runtime_checkout=runtime,
                          agent_checkout=agent, realm_id="test")
    try:
        daemon.start()
        assert daemon.startup_identity == {"release": 31, "managed_by": "pinokio"}
    finally:
        daemon.stop()


def test_unstamped_installed_roots_and_mixed_roots(tmp_path):
    from runtime_protocol.startup_identity import capture_startup_identity
    from runtime_protocol.source_identity import SourceIdentityError

    runtime, agent = tmp_path / "runtime", tmp_path / "agent"
    runtime.mkdir()
    agent.mkdir()
    assert capture_startup_identity(runtime_checkout=runtime, agent_checkout=agent, environ={}) == {
        "release": 0, "managed_by": None,
    }
    assert capture_startup_identity(runtime_checkout=runtime, agent_checkout=agent,
                                    environ={"ASTRID_INSTALL_RELEASE": "7", "ASTRID_INSTALL_MANAGED_BY": "pinokio"}) == {
        "release": 7, "managed_by": "pinokio",
    }
    (runtime / ".git").mkdir()
    with pytest.raises(SourceIdentityError):
        capture_startup_identity(runtime_checkout=runtime, agent_checkout=agent, environ={})


def test_local_boundary_argv_carries_exact_profile_checkouts(tmp_path):
    from astrid_runtime.bootstrap import SourceProfile
    from astrid_runtime.runtime_boundary import LocalRuntimeBoundary

    runtime, agent = tmp_path / "runtime checkout", tmp_path / "agent checkout"
    runtime.mkdir()
    agent.mkdir()
    profile = SourceProfile("astrid", str(runtime), str(agent))
    argv = LocalRuntimeBoundary()._argv(
        profile, realm_id="r", realm_root=tmp_path / "realm", support_root=tmp_path / "support",
        display_name="test", owner_lock=tmp_path / "support/instance.lock",
        token_file=tmp_path / "support/token")
    assert argv[argv.index("--runtime-checkout") + 1] == str(runtime)
    assert argv[argv.index("--agent-checkout") + 1] == str(agent)


def test_runtime_cli_passes_selected_checkouts_to_owner(tmp_path, monkeypatch, capsys):
    from runtime_protocol import cli

    captured = {}

    class FakeDaemon:
        def __init__(self, *_args, **kwargs):
            captured.update(kwargs)
            captured["root_arg"] = _args[0]
            self.endpoint = "http://127.0.0.1:1234"
            self.service = SimpleNamespace(realm={"id": "realm"})
            self.credential_path = Path("credential")
            self.worker_credential_path = Path("worker-credential")
            self.local_worker_profiles = None
            self.door_endpoint = None

        def start(self):
            return self

        def stop(self):
            pass

    monkeypatch.setattr(cli, "RuntimeDaemon", FakeDaemon)
    monkeypatch.setattr(cli.platform, "install_stop_handlers", lambda _handler: lambda: None)
    monkeypatch.setattr(cli.time, "sleep", lambda _seconds: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        cli.main(["start", "--root", str(tmp_path / "realm"),
                  "--runtime-checkout", str(tmp_path / "runtime"),
                  "--agent-checkout", str(tmp_path / "agent")])
    capsys.readouterr()
    assert captured["runtime_checkout"] == str(tmp_path / "runtime")
    assert captured["agent_checkout"] == str(tmp_path / "agent")


def test_foreground_boundary_passes_selected_checkouts_to_owner(tmp_path, monkeypatch):
    from astrid_runtime.bootstrap import SourceProfile
    from astrid_runtime.runtime_boundary import ForegroundRuntimeBoundary

    runtime, agent = tmp_path / "runtime", tmp_path / "agent"
    runtime.mkdir()
    agent.mkdir()
    captured = {}

    class FailingDaemon:
        def __init__(self, *_args, **kwargs):
            captured.update(kwargs)
            raise OSError("stop after constructor arguments")

    import runtime_protocol.daemon as daemon_module
    monkeypatch.setattr(daemon_module, "RuntimeDaemon", FailingDaemon)
    boundary = ForegroundRuntimeBoundary()
    source = SourceProfile("astrid", str(runtime), str(agent))
    with pytest.raises(OSError, match="stop after constructor"):
        boundary.start(realm_id="realm", realm_root=tmp_path / "realm",
                       owner_lock=tmp_path / "support/instance.lock", source_profile=source)
    assert captured["runtime_checkout"] == str(runtime)
    assert captured["agent_checkout"] == str(agent)


def test_startup_identity_fails_closed_for_bad_installed_context_and_partial_source(monkeypatch, tmp_path):
    from runtime_protocol.startup_identity import capture_startup_identity
    from runtime_protocol.source_identity import SourceIdentityError

    monkeypatch.setenv("ASTRID_INSTALL_RELEASE", "-1")
    monkeypatch.setenv("ASTRID_INSTALL_MANAGED_BY", "")
    with pytest.raises(ValueError, match="nonnegative"):
        capture_startup_identity()
    monkeypatch.setenv("ASTRID_INSTALL_RELEASE", "1.5")
    with pytest.raises(ValueError, match="decimal"):
        capture_startup_identity()
    monkeypatch.setenv("ASTRID_INSTALL_RELEASE", "1")
    monkeypatch.setenv("ASTRID_INSTALL_MANAGED_BY", "other")
    with pytest.raises(ValueError, match="empty or pinokio"):
        capture_startup_identity()
    monkeypatch.delenv("ASTRID_INSTALL_RELEASE")
    monkeypatch.delenv("ASTRID_INSTALL_MANAGED_BY")
    with pytest.raises(ValueError, match="both Runtime and agent"):
        capture_startup_identity(runtime_checkout=tmp_path)
    with pytest.raises(SourceIdentityError, match="source checkout is not a directory"):
        capture_startup_identity(runtime_checkout=tmp_path / "missing-runtime",
                                 agent_checkout=tmp_path / "missing-agent")


def test_installed_environment_is_copied_once_before_field_reads():
    from runtime_protocol.startup_identity import capture_startup_identity

    class MutatingEnvironment(dict):
        def __getitem__(self, key):
            value = super().__getitem__(key)
            if key == "ASTRID_INSTALL_RELEASE":
                self["ASTRID_INSTALL_MANAGED_BY"] = "pinokio"
            return value

    env = MutatingEnvironment(ASTRID_INSTALL_RELEASE="7", ASTRID_INSTALL_MANAGED_BY="")
    assert capture_startup_identity(environ=env) == {"release": 7, "managed_by": None}
