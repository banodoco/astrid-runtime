from __future__ import annotations

import json
from pathlib import Path

import pytest

from astrid_runtime.bootstrap import BootstrapConfig, BootstrapError, SourceProfile, bootstrap
from astrid_runtime.paths import RuntimePaths
from astrid_runtime.workspace import configure_workspace, inspect_workspace
from runtime_protocol.store import RealmStore


class _Boundary:
    def __init__(self):
        self.calls = []

    def create(self, *, realm_id, realm_root, display_name, source_profile):
        self.calls.append(("create", realm_id, Path(realm_root)))
        RealmStore.initialize(realm_root, realm_id=realm_id, display_name=display_name).close()
        return {"state": "created", "realm_id": realm_id}

    def inspect(self, *, realm_root):
        self.calls.append(("inspect", Path(realm_root)))
        return RealmStore.inspect_realm(realm_root)

    def start(self, **_kwargs):
        self.calls.append(("start",))
        raise AssertionError("observation/setup test must not launch")


def _config(tmp_path):
    profile = SourceProfile("astrid", str(tmp_path), str(tmp_path))
    return BootstrapConfig(source_profile=profile)


def test_up_refuses_missing_selection_without_creating_support_state(tmp_path):
    support = tmp_path / "support"
    paths = RuntimePaths.current(data_root=support)
    boundary = _Boundary()
    with pytest.raises(BootstrapError, match="No workspace is configured"):
        bootstrap(paths, boundary, _config(tmp_path))
    assert not support.exists()
    assert boundary.calls == []


def test_explicit_create_preserves_omitted_vs_explicit_empty_identity(tmp_path):
    paths = RuntimePaths.current(data_root=tmp_path / "support")
    boundary = _Boundary()
    with pytest.raises(BootstrapError, match="opaque identifier"):
        configure_workspace(
            paths,
            boundary,
            _config(tmp_path),
            mode="create",
            realm_root=tmp_path / "empty-id",
            realm_id="",
        )
    assert not paths.app_support.exists()

    result = configure_workspace(
        paths,
        boundary,
        _config(tmp_path),
        mode="create",
        realm_root=tmp_path / "generated-id",
        realm_id=None,
    )
    assert result["status"] == "configured_create"
    assert result["realm_id"]
    catalog = json.loads(paths.catalog_path.read_text())
    assert catalog["selected_realm_id"] == result["realm_id"]


def test_attach_accepts_bounded_opaque_identity_and_fences_mismatch(tmp_path):
    root = tmp_path / "existing"
    RealmStore.initialize(root, realm_id="realm:opaque-01").close()
    paths = RuntimePaths.current(data_root=tmp_path / "support")
    boundary = _Boundary()
    with pytest.raises(BootstrapError, match="identity mismatch"):
        configure_workspace(
            paths,
            boundary,
            _config(tmp_path),
            mode="attach",
            realm_root=root,
            realm_id="wrong",
        )
    assert not paths.app_support.exists()

    result = configure_workspace(
        paths,
        boundary,
        _config(tmp_path),
        mode="attach",
        realm_root=root,
        realm_id="realm:opaque-01",
    )
    assert result["realm_id"] == "realm:opaque-01"


def test_candidate_inspection_is_nonstarting_and_does_not_create_support(tmp_path):
    root = tmp_path / "candidate"
    RealmStore.initialize(root, realm_id="candidate-id").close()
    files_before = {
        path.relative_to(root): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }
    directories_before = sorted(
        path.relative_to(root) for path in root.rglob("*") if path.is_dir()
    )
    paths = RuntimePaths.current(data_root=tmp_path / "support")
    boundary = _Boundary()
    result = inspect_workspace(
        paths,
        boundary,
        realm_root=root,
        expected_realm_id="candidate-id",
    )
    assert result["state"] == "inspectable"
    assert not paths.app_support.exists()
    assert [call[0] for call in boundary.calls] == ["inspect"]
    assert {
        path.relative_to(root): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    } == files_before
    assert sorted(path.relative_to(root) for path in root.rglob("*") if path.is_dir()) == directories_before


def _configured_live_owner(tmp_path):
    paths = RuntimePaths.current(data_root=tmp_path / "support")
    root = tmp_path / "realm"
    boundary = _Boundary()
    configure_workspace(paths, boundary, _config(tmp_path), mode="create", realm_root=root, realm_id="film")
    discovery = {"active_realm": "film", "realm_root": str(root), "runtime_instance_id": "instance-a",
                 "pid": 12345, "process_birth_id": "birth-a", "endpoint": "http://127.0.0.1:12345"}
    paths.discovery_path.write_text(json.dumps(discovery))
    boundary.is_pid_alive = lambda pid: pid == discovery["pid"]
    # Doctor verifies authenticated endpoint metadata. Keep that response
    # independent of subsequent discovery-file mutations.
    metadata = {"status": "ok", "runtime_instance_id": discovery["runtime_instance_id"],
                "realm_id": discovery["active_realm"]}
    def endpoint_metadata(*, endpoint, credential_file):
        assert endpoint == discovery["endpoint"]
        assert credential_file == paths.runtime_support / "credentials" / "owner.token"
        return dict(metadata)
    boundary.endpoint_metadata = endpoint_metadata
    boundary.calls.clear()
    return paths, root, boundary, discovery


def test_configured_inspection_reuses_same_verified_discovery_snapshot(tmp_path, monkeypatch):
    import importlib
    bootstrap_module = importlib.import_module("astrid_runtime.bootstrap")

    paths, root, boundary, discovery = _configured_live_owner(tmp_path)
    original = bootstrap_module._read_support_json
    reads = []
    def read(path):
        if path == paths.discovery_path:
            reads.append(path)
        return original(path)
    monkeypatch.setattr(bootstrap_module, "_read_support_json", read)
    result = inspect_workspace(paths, boundary)
    assert result["inspection"]["source"] == "live_owner"
    assert result["inspection"]["runtime_instance_id"] == discovery["runtime_instance_id"]
    assert reads == [paths.discovery_path]
    assert boundary.calls == []  # No full DB/CAS doctor and no process launch.
    # Public doctor remains a report-only API with the same validation contract.
    assert bootstrap_module.doctor(paths, boundary)["healthy"] is True


def test_replaced_discovery_is_not_returned_as_the_verified_instance(tmp_path):
    paths, root, boundary, verified = _configured_live_owner(tmp_path)
    replacement = {**verified, "runtime_instance_id": "unverified-new-instance", "pid": 23456, "process_birth_id": "new-birth"}
    endpoint_metadata = boundary.endpoint_metadata
    probes = []
    def replace_during_probe(**kw):
        metadata = endpoint_metadata(**kw)
        probes.append(metadata)
        paths.discovery_path.write_text(json.dumps(replacement))
        return metadata
    boundary.endpoint_metadata = replace_during_probe
    result = inspect_workspace(paths, boundary)
    assert len(probes) == 1
    assert probes[0]["runtime_instance_id"] == verified["runtime_instance_id"]
    assert json.loads(paths.discovery_path.read_text()) == replacement
    assert result["inspection"]["source"] == "live_owner"
    assert result["inspection"]["runtime_instance_id"] == verified["runtime_instance_id"]
    assert result["inspection"]["runtime_instance_id"] != replacement["runtime_instance_id"]
    assert boundary.calls == []


@pytest.mark.parametrize("failure", ["dead", "changed_instance", "unhealthy", "other_realm", "other_root"])
def test_unverified_or_mismatched_live_owner_falls_back_to_full_inspection(tmp_path, failure):
    paths, root, boundary, discovery = _configured_live_owner(tmp_path)
    if failure == "dead":
        boundary.is_pid_alive = lambda _pid: False
    elif failure == "changed_instance":
        endpoint_metadata = boundary.endpoint_metadata
        boundary.endpoint_metadata = lambda **kw: {
            **endpoint_metadata(**kw), "runtime_instance_id": "another-instance"}
    elif failure == "unhealthy":
        endpoint_metadata = boundary.endpoint_metadata
        boundary.endpoint_metadata = lambda **kw: {
            **endpoint_metadata(**kw), "status": "degraded"}
    else:
        discovery["active_realm" if failure == "other_realm" else "realm_root"] = "other" if failure == "other_realm" else str(tmp_path / "other")
        paths.discovery_path.write_text(json.dumps(discovery))
    result = inspect_workspace(paths, boundary)
    assert result["realm_id"] == "film"
    assert "source" not in result["inspection"]
    assert [call[0] for call in boundary.calls] == ["inspect"]


def test_explicit_candidate_still_gets_full_inspection_even_with_live_owner(tmp_path):
    paths, root, boundary, _discovery = _configured_live_owner(tmp_path)
    result = inspect_workspace(paths, boundary, realm_root=root, expected_realm_id="film")
    assert result["realm_id"] == "film" and "source" not in result["inspection"]
    assert [call[0] for call in boundary.calls] == ["inspect"]


def test_missing_boundary_cannot_promote_pid_only_doctor_to_live_inspection(tmp_path, monkeypatch):
    import importlib
    bootstrap_module = importlib.import_module("astrid_runtime.bootstrap")
    paths, _root, _boundary, _discovery = _configured_live_owner(tmp_path)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("PID-only support diagnostics cannot authorize the fast path")
    monkeypatch.setattr(bootstrap_module, "_doctor_observation", forbidden)
    with pytest.raises(BootstrapError, match="cannot inspect a canonical realm"):
        inspect_workspace(paths, None)
