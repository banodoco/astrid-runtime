from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import shutil
import sys
import pytest
import subprocess

sys.path.insert(0, str(Path(__file__).parents[1] / "packages" / "python"))

from astrid_runtime import BootstrapConfig, BootstrapError, LocalRuntimeBoundary, RuntimePaths, SourceProfile, bootstrap, configure_workspace, connect
from astrid_runtime.bootstrap import restart
from astrid_runtime_client import WorkspaceClient


def _config() -> BootstrapConfig:
    checkout = Path(__file__).parents[1].resolve()
    profile = SourceProfile(profile="astrid", runtime_checkout=str(checkout), source_checkout=str(checkout))
    return BootstrapConfig(source_profile=profile)


def _configure(paths, boundary):
    config = _config()
    configure_workspace(
        paths, boundary, config, mode="create",
        realm_root=paths.realms_dir / "explicit-realm", realm_id="explicit-realm",
    )
    return config


def _stop_unfinished(boundary):
    process = getattr(boundary, "_process", None)
    if process is not None and getattr(process, "_runtime_cleanup_error", None) is None:
        boundary.stop()


def _git_checkout(
    root: Path, source_root: Path | None = None, trees: tuple[str, ...] = (),
) -> None:
    root.mkdir(parents=True)
    if source_root is not None:
        for tree in trees:
            source = source_root / tree
            target = root / tree
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(
                source, target,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"),
            )
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
    (root / "tracked.txt").write_text("baseline", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "baseline"], check=True)


def _authority_files(paths):
    return (
        paths.catalog_path,
        paths.source_profiles_dir / "astrid.json",
        paths.discovery_path,
        paths.instance_lock_path,
        paths.credentials_dir / "astrid.json",
    )


@pytest.mark.darwin_native
def test_real_subprocess_fresh_launch_reconnect_and_scoped_generated_client(tmp_path, owned_process_groups):
    paths = RuntimePaths.sandbox(tmp_path)
    boundary = LocalRuntimeBoundary()
    owned_process_groups.add_cleanup(lambda: _stop_unfinished(boundary))
    try:
        config = _configure(paths, boundary)
        first = bootstrap(paths, boundary, config)
        discovery = json.loads(paths.discovery_path.read_text())
        assert first.status == "started"
        assert discovery["protocol_version"] == "workspace.v1"
        assert discovery["schema_version"] == "workspace-schema-v1"
        assert discovery["active_realm"] == first.realm_id
        assert discovery["runtime_instance_id"]

        credential = json.loads((paths.credentials_dir / "astrid.json").read_text())
        serialized_discovery = json.dumps(discovery)
        # Discovery may advertise owner-only credential paths so the pack
        # host can start, but neither bearer value may cross that boundary.
        assert credential["token"] not in serialized_discovery
        worker_credential = Path(discovery["worker_credential_file"]).read_text(encoding="utf-8").strip()
        assert worker_credential not in serialized_discovery
        client = WorkspaceClient(first.endpoint, credential["token"])
        assert client.health()["protocol"] == "workspace.v1"
        assert client.get_realm().realm_id == first.realm_id
        project = client.create_project("real-bootstrap", idempotency_key="real-bootstrap-project")

        second = bootstrap(paths, LocalRuntimeBoundary(), _config())
        assert second.status == "reconnected"
        assert second.realm_id == first.realm_id
        assert client.get_project(project.project_id).name == "real-bootstrap"
    finally:
        boundary.stop()


@pytest.mark.darwin_native
def test_concurrent_reconnect_survives_restricted_pid_identity_probe(tmp_path, monkeypatch, owned_process_groups):
    paths = RuntimePaths.sandbox(tmp_path)
    boundary = LocalRuntimeBoundary()
    owned_process_groups.add_cleanup(lambda: _stop_unfinished(boundary))
    try:
        config = _configure(paths, boundary)
        first = bootstrap(paths, boundary, config)

        def deny_signal(_pid, _signal):
            raise PermissionError("operation not permitted")

        monkeypatch.setattr(os, "kill", deny_signal)
        monkeypatch.setattr(LocalRuntimeBoundary, "process_birth_identity", staticmethod(lambda _pid: None))
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _index: bootstrap(paths, LocalRuntimeBoundary(), _config()), range(2)))

        assert first.ready
        assert [result.status for result in results] == ["reconnected", "reconnected"]
        assert {result.endpoint for result in results} == {first.endpoint}
    finally:
        boundary.stop()


@pytest.mark.darwin_native
def test_real_subprocess_restart_preserves_realm_and_credential(tmp_path, owned_process_groups):
    paths = RuntimePaths.sandbox(tmp_path)
    boundary = LocalRuntimeBoundary()
    owned_process_groups.add_cleanup(lambda: _stop_unfinished(boundary))
    try:
        config = _configure(paths, boundary)
        first = bootstrap(paths, boundary, config)
        token_before = json.loads((paths.credentials_dir / "astrid.json").read_text())["token"]
        result = restart(paths, boundary, _config())
        assert result.status == "restarted"
        assert result.realm_id == first.realm_id
        token_after = json.loads((paths.credentials_dir / "astrid.json").read_text())["token"]
        assert token_after == token_before
        assert WorkspaceClient(result.endpoint, token_after).get_realm().realm_id == first.realm_id
    finally:
        boundary.stop()


@pytest.mark.darwin_native
def test_real_subprocess_stale_discovery_recovers_without_new_realm(tmp_path, owned_process_groups):
    paths = RuntimePaths.sandbox(tmp_path)
    boundary = LocalRuntimeBoundary()
    owned_process_groups.add_cleanup(lambda: _stop_unfinished(boundary))
    try:
        config = _configure(paths, boundary)
        first = bootstrap(paths, boundary, config)
        assert boundary._process is not None
        os.kill(boundary._process.pid, 9)
        boundary._process.wait(timeout=3)
        recovered = bootstrap(paths, boundary, _config())
        assert recovered.status == "started"
        assert recovered.realm_id == first.realm_id
    finally:
        boundary.stop()


def test_linux_loopback_identity_refusal_and_idle_dirty_restart(tmp_path, monkeypatch):
    """Both live-owner entrypoints refuse an edited source tree before writes."""
    monkeypatch.delenv("ASTRID_INSTALL_RELEASE", raising=False)
    monkeypatch.delenv("ASTRID_INSTALL_MANAGED_BY", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    runtime_root = Path(__file__).resolve().parents[1]
    runtime_checkout = tmp_path / "source-runtime"
    product_checkout = tmp_path / "source-product"
    _git_checkout(
        runtime_checkout, runtime_root,
        ("runtime_protocol", "astrid_runtime", "packages/python/astrid_runtime_client"),
    )
    _git_checkout(product_checkout)
    profile = SourceProfile(
        profile="astrid", runtime_checkout=str(runtime_checkout),
        source_checkout=str(product_checkout), capability_digest="caps-v1",
    )
    config = BootstrapConfig(source_profile=profile)
    paths = RuntimePaths.sandbox(tmp_path / "support")
    first_boundary = LocalRuntimeBoundary()
    restart_boundary = None
    try:
        configure_workspace(
            paths, first_boundary, config, mode="create",
            realm_root=paths.realms_dir / "explicit-realm", realm_id="explicit-realm",
        )
        first = bootstrap(paths, first_boundary, config)
        original_discovery = json.loads(paths.discovery_path.read_text(encoding="utf-8"))
        original_identity = original_discovery["identity"]
        assert original_discovery["runtime_instance_id"] == first.runtime_instance_id
        assert original_identity["dirty"] is False

        (product_checkout / "tracked.txt").write_text("edited product checkout", encoding="utf-8")
        authority_before = {path: path.read_bytes() for path in _authority_files(paths)}
        with pytest.raises(BootstrapError) as caught:
            bootstrap(paths, LocalRuntimeBoundary(), config)
        assert str(caught.value) == (
            "An older Astrid is still running. Restart it after its running tasks finish."
        )
        assert authority_before == {path: path.read_bytes() for path in _authority_files(paths)}
        assert first_boundary._process is not None and first_boundary._process.poll() is None
        live = first_boundary.owner_startup_identity(
            endpoint=first.endpoint, instance_id=first.runtime_instance_id,
        )
        assert live["runtime_instance_id"] == first.runtime_instance_id
        assert live["identity"] == original_identity

        with pytest.raises(BootstrapError) as caught:
            connect(paths, LocalRuntimeBoundary(), config)
        assert str(caught.value) == (
            "An older Astrid is still running. Restart it after its running tasks finish."
        )
        assert authority_before == {path: path.read_bytes() for path in _authority_files(paths)}
        assert first_boundary._process is not None and first_boundary._process.poll() is None

        restart_boundary = LocalRuntimeBoundary()
        restart_boundary.prepare_restart(
            source_profile=profile,
            realm_id=first.realm_id,
            realm_root=paths.realms_dir / "explicit-realm",
            support_root=paths.runtime_support,
            pid=int(original_discovery["pid"]),
        )
        restarted = restart(paths, restart_boundary, config)
        assert restarted.status == "restarted"
        assert restarted.runtime_instance_id != first.runtime_instance_id
        updated = json.loads(paths.discovery_path.read_text(encoding="utf-8"))
        assert updated["runtime_instance_id"] == restarted.runtime_instance_id
        assert updated["identity"]["dirty"] is True
        assert updated["identity"]["dirty_hash"] != original_identity["dirty_hash"]
        health = restart_boundary.owner_startup_identity(
            endpoint=restarted.endpoint, instance_id=restarted.runtime_instance_id,
        )
        assert health["runtime_instance_id"] == restarted.runtime_instance_id
        assert health["identity"] == updated["identity"]

        connected = connect(paths, LocalRuntimeBoundary(), config)
        assert connected.status == "reconnected"
        assert connected.runtime_instance_id == restarted.runtime_instance_id
    finally:
        if restart_boundary is not None:
            _stop_unfinished(restart_boundary)
        _stop_unfinished(first_boundary)
