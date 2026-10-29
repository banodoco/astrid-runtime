"""Private owner selection transport; no producer, worker, or engine execution."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import json

import pytest

from astrid_runtime.bootstrap import SourceProfile
from astrid_runtime.runtime_boundary import ForegroundRuntimeBoundary
from runtime_protocol import cli, daemon as daemon_module, local_worker_composition as module
from runtime_protocol import service as service_module, verified_host_launch
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ValidationError
from runtime_protocol.local_worker_composition import (
    CrossProcessWorkerPreparer, LocalWorkerComposition, OSProcessInspector,
)
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from test_local_worker import host_only_profile_case


@pytest.fixture
def composition():
    profile = host_only_profile_case()
    preparer = CrossProcessWorkerPreparer(profile=profile,
        config={"source_checkout": "/installed", "environment": {"OWNER": "selected"}}, environment={})
    return LocalWorkerComposition({profile.profile_id: profile}, preparer, OSProcessInspector(profile))


def _forbid(*_args, **_kwargs):
    pytest.fail("retention must not resolve, load, prepare, or launch")


class _StartupCaptured(Exception):
    pass


@pytest.mark.parametrize("entrypoint", ["cli", "foreground"])
def test_startup_paths_retain_owner_selection_before_lifecycle(tmp_path, monkeypatch, capsys, composition, entrypoint):
    root, support = tmp_path / "realm", tmp_path / "support"
    RealmStore.initialize(root, realm_id="realm").close()
    selected = composition.profiles.copy()
    expected_config = json.loads(json.dumps(composition.preparer.config))
    loaded, owners, services = [], [], []

    def load(path, **kwargs):
        loaded.append((path, kwargs))
        return composition

    def owner(*args, **kwargs):
        value = RuntimeDaemon(*args, **kwargs)
        owners.append(value)
        # The owner constructor must retain selection before callers can edit
        # the original object, including while startup has not opened its store.
        composition.profiles.clear()
        composition.preparer.config["source_checkout"] = "/caller-mutation"
        return value

    def credentials_fence(owner, **_kwargs):
        services.append(owner.service)
        raise _StartupCaptured("fenced before credential or worker lifecycle")

    monkeypatch.setattr(module, "load_local_worker_composition", load)
    monkeypatch.setattr(cli, "load_local_worker_composition", load)
    monkeypatch.setattr(module, "_installed_host_release", _forbid)
    monkeypatch.setattr(verified_host_launch, "_SourceLoader", _forbid)
    monkeypatch.setattr(CrossProcessWorkerPreparer, "prepare", _forbid)
    monkeypatch.setattr(RuntimeDaemon, "_bind_startup_identity", lambda _self: None)
    monkeypatch.setattr(RuntimeDaemon, "_provision_credentials", credentials_fence)
    monkeypatch.setattr(daemon_module.process_control, "configure_from", lambda _root: None)
    monkeypatch.setattr(daemon_module.platform, "process_control_probe", lambda: {})
    monkeypatch.setattr(daemon_module.process_control, "announce", lambda _value: None)

    try:
        if entrypoint == "cli":
            monkeypatch.setattr(cli, "RuntimeDaemon", owner)
            assert cli.main(["start", "--root", str(root), "--support-root", str(support),
                "--realm-id", "realm", "--worker-profile", "owner-selected.json"]) == 1
            assert "fenced before credential" in capsys.readouterr().out
        else:
            monkeypatch.setattr(daemon_module, "RuntimeDaemon", owner)
            boundary = ForegroundRuntimeBoundary()
            monkeypatch.setattr(boundary, "_validate_source", lambda _source: None)
            # Leave the captured service open for assertions; no custody or
            # listener was obtained and the test closes the store below.
            monkeypatch.setattr(boundary, "stop", lambda: None)
            source = SourceProfile("astrid", str(tmp_path), str(tmp_path), worker_profile="owner-selected.json")
            with pytest.raises(_StartupCaptured):
                boundary.start(realm_id="realm", realm_root=root,
                    owner_lock=support / "instance.lock", source_profile=source)
        assert len(loaded) == len(owners) == len(services) == 1
        assert loaded[0][1] == {"workspace_uuid": "realm", "realm_root": root,
            "support_root": support, "runtime_instance_id": "pending-startup"}
        owner, service = owners[0], services[0]
        retained = service._local_worker_composition
        assert retained is owner._local_worker_composition
        assert retained.profiles == selected and retained.config == expected_config
        assert retained._installed_release_loader is _forbid
        assert retained._verified_source_loader is _forbid
        assert owner.local_worker_launcher is None and owner.credentials is None
        assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0
        assert service.store.conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0
        assert service.store.realm_lifecycle()["state"] == "active"
    finally:
        for service in services:
            service.close()


@pytest.mark.parametrize("entrypoint", ["cli", "foreground"])
@pytest.mark.parametrize("missing", [True, False])
def test_selected_startup_paths_fail_closed_before_owner_start(tmp_path, monkeypatch, capsys, composition, entrypoint, missing):
    value = None if missing else LocalWorkerComposition({}, composition.preparer, composition.inspector)
    monkeypatch.setattr(module, "load_local_worker_composition", lambda *_args, **_kwargs: value)
    monkeypatch.setattr(cli, "load_local_worker_composition", lambda *_args, **_kwargs: value)
    monkeypatch.setattr(RuntimeDaemon, "start", _forbid)
    monkeypatch.setattr(service_module, "RealmStore", _forbid)
    monkeypatch.setattr(daemon_module, "_authority_path", _forbid)
    monkeypatch.setattr(CrossProcessWorkerPreparer, "prepare", _forbid)
    if entrypoint == "cli":
        assert cli.main(["start", "--root", str(tmp_path / "realm"), "--realm-id", "realm",
            "--worker-profile", "owner-selected.json"]) == 1
        output = json.loads(capsys.readouterr().out)
        assert output["ok"] is False
        assert "composition" in output["error"]["message"]
    else:
        boundary = ForegroundRuntimeBoundary()
        monkeypatch.setattr(boundary, "_validate_source", lambda _source: None)
        source = SourceProfile("astrid", str(tmp_path), str(tmp_path), worker_profile="owner-selected.json")
        with pytest.raises(ValidationError, match="composition"):
            boundary.start(realm_id="realm", realm_root=tmp_path / "realm",
                owner_lock=tmp_path / "support/instance.lock", source_profile=source)
    assert not (tmp_path / "realm").exists()


def test_service_selection_is_read_only_isolated_and_keeps_fixed_lazy_loaders(tmp_path, monkeypatch, composition):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    release = {"source_components": {"sdk": "owner-pinned"}}
    calls = []

    def installed_release(profile, config):
        calls.append((profile, config))
        return release

    original_loader = verified_host_launch._SourceLoader
    monkeypatch.setattr(module, "_installed_host_release", installed_release)
    monkeypatch.setattr(CrossProcessWorkerPreparer, "prepare", _forbid)
    service = RuntimeService(root, _local_worker_composition=composition, _local_worker_composition_required=True)
    try:
        retained = service._local_worker_composition
        assert calls == []
        assert retained._installed_release_loader is installed_release
        assert retained._verified_source_loader is original_loader
        assert not hasattr(retained, "preparer") and not hasattr(retained, "inspector")
        profile_id = next(iter(composition.profiles))
        composition.profiles[profile_id].host_launch["environment"]["CALLER"] = "changed"
        composition.profiles.clear()
        composition.preparer.config["environment"]["OWNER"] = "changed"
        composition.preparer.config["source_checkout"] = "/caller"
        with pytest.raises(FrozenInstanceError):
            retained._config_json = b"{}"
        profiles, config = retained.profiles, retained.config
        with pytest.raises(FrozenInstanceError):
            profiles[profile_id].profile_id = "changed"
        profiles[profile_id].host_launch["environment"]["READ"] = "changed"
        profiles.clear()
        config["environment"]["OWNER"] = "changed"
        assert retained.profiles[profile_id].host_launch["environment"] == {}
        assert retained.config["environment"] == {"OWNER": "selected"}
        monkeypatch.setattr(module, "_installed_host_release", _forbid)
        monkeypatch.setattr(verified_host_launch, "_SourceLoader", _forbid)
        first = retained._installed_release(profile_id)
        first["source_components"]["sdk"] = "changed"
        assert retained._installed_release(profile_id) == release
        assert calls[0][1]["source_checkout"] == "/installed"
        calls[0][1]["environment"]["OWNER"] = "loader-mutation"
        assert retained.config["environment"] == {"OWNER": "selected"}
        assert retained._verified_source_loader is original_loader
        with pytest.raises(ValidationError, match="owner-selected"):
            retained._installed_release("caller-profile")
        assert len(calls) == 2
    finally:
        service.close()


@pytest.mark.parametrize("constructor", [RuntimeDaemon, RuntimeService])
@pytest.mark.parametrize("invalid", ["missing", "wrong_type", "empty", "missing_source", "broken_retention"])
def test_expected_selection_fails_before_owner_or_store(tmp_path, monkeypatch, composition, constructor, invalid):
    if invalid == "missing":
        value = None
    elif invalid == "wrong_type":
        value = {"profile": "caller-selected", "source_checkout": "/caller"}
    elif invalid == "empty":
        value = LocalWorkerComposition({}, composition.preparer, composition.inspector)
    elif invalid == "missing_source":
        value = composition
        value.preparer.config.pop("source_checkout")
    else:
        value = composition
        monkeypatch.setattr(value, "_retain", lambda: None)
    monkeypatch.setattr(service_module, "RealmStore", _forbid)
    monkeypatch.setattr(daemon_module, "_authority_path", _forbid)
    with pytest.raises(ValidationError, match="composition"):
        constructor(tmp_path / "absent", _local_worker_composition=value, _local_worker_composition_required=True)
    assert not (tmp_path / "absent").exists()


@pytest.mark.parametrize("profiles,config", [(b"{}", b"{}"), (b"invalid", b"{}"), (b"[]", b"{}")])
def test_malformed_retained_selection_is_rejected(profiles, config):
    with pytest.raises(ValidationError, match="invalid retained"):
        module._RetainedLocalWorkerComposition(profiles, config)


@pytest.mark.parametrize("with_selection", [False, True])
def test_ordinary_admission_keeps_caller_metadata_opaque_and_lifecycle_unchanged(tmp_path, monkeypatch, composition, with_selection):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    monkeypatch.setattr(module, "_installed_host_release", _forbid)
    monkeypatch.setattr(verified_host_launch, "_SourceLoader", _forbid)
    monkeypatch.setattr(CrossProcessWorkerPreparer, "prepare", _forbid)
    service = RuntimeService(root, _local_worker_composition=composition if with_selection else None)
    try:
        retained = service._local_worker_composition
        before_selection = retained.config if retained else None
        lifecycle = service.store.realm_lifecycle()
        epoch = service.store._current_runtime_epoch()
        forged = {"source_checkout": "/caller", "profile": {"profile_id": "caller"},
            "hash": "caller-digest", "verified": True, "signature": "caller-signature"}
        body = {"capability_id": "render.basic", "spec": {"local_worker_composition": forged,
            "installed_release": forged}, "generation_intent": forged, "idempotency_key": "opaque"}
        admitted = service.create_task(body)
        replay = service.create_task(body)
        assert admitted["task"]["id"] == replay["task"]["id"]
        assert admitted["task"]["status"] == "queued"
        assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
        assert service.store.conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0
        assert service.store.conn.execute("SELECT COUNT(*) FROM execution_bindings").fetchone()[0] == 0
        events = service.store.conn.execute("SELECT payload_json FROM events WHERE kind='task.admitted'").fetchall()
        assert len(events) == 1
        assert json.loads(events[0][0]) == {"capability": "render.basic",
            "classification": {"version": 1, "is_root": True, "is_generation": False}}
        assert service.store.realm_lifecycle() == lifecycle
        assert service.store._current_runtime_epoch() == epoch
        assert service._local_worker_composition is retained
        assert (retained.config if retained else None) == before_selection
    finally:
        service.close()


def test_component_only_daemon_retains_no_selection_authority(tmp_path, composition):
    owner = RuntimeDaemon(tmp_path / "realm", local_worker_profiles=composition.profiles,
        local_worker_preparer=composition.preparer, local_worker_inspector=composition.inspector)
    assert owner._local_worker_composition is None


def test_legacy_loaded_composition_retention_preserves_supported_startup(tmp_path):
    from test_local_worker_composition import _profile_document
    document, _source, support, _packs = _profile_document(tmp_path)
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document))
    composition = module.load_local_worker_composition(path, workspace_uuid="realm",
        realm_root=tmp_path / "realm", support_root=support, runtime_instance_id="pending-startup")
    retained = composition._retain()
    assert retained.profiles == composition.profiles
    assert retained.config == composition.preparer.config
    assert next(iter(retained.profiles.values())).engine_launch is None
