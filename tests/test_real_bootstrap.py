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
from astrid_runtime import cli
from astrid_runtime_client import WorkspaceClient
from runtime_protocol.source_identity import SourceIdentityError, capture_source_identity


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


@pytest.mark.parametrize("clean_filter", [False, True])
def test_linux_loopback_identity_refusal_and_idle_dirty_restart(tmp_path, monkeypatch, clean_filter):
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
    if clean_filter:
        def git(*args):
            return subprocess.run(["git", "-C", str(product_checkout), *args],
                                  check=True, capture_output=True, text=True).stdout.strip()

        (product_checkout / ".gitattributes").write_text("tracked.txt filter=canonical\n")
        (product_checkout / "tracked.txt").write_text("x\n")
        git("config", "filter.canonical.clean", "tr ab x")
        git("config", "filter.canonical.smudge", "cat")
        git("add", ".gitattributes", "tracked.txt")
        git("commit", "-qm", "configure clean filter")
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

        (product_checkout / "tracked.txt").write_text(
            "a\n" if clean_filter else "edited product checkout", encoding="utf-8",
        )
        if clean_filter:
            assert git("status", "--porcelain") == ""
        authority_before = {path: path.read_bytes() for path in _authority_files(paths)}
        def unexpected_operation(*_args, **_kwargs):
            pytest.fail("identity refusal attempted an owner operation or actor connection")

        with monkeypatch.context() as refusal:
            for method in ("start", "connect", "stop_owner", "restart"):
                refusal.setattr(LocalRuntimeBoundary, method, unexpected_operation)
            for entrypoint in (bootstrap, connect):
                with pytest.raises(BootstrapError) as caught:
                    entrypoint(paths, LocalRuntimeBoundary(), config)
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


@pytest.mark.parametrize("checkout", ["runtime", "agent"])
def test_linux_loopback_untracked_nested_checkout_refuses_up_and_connect(tmp_path, monkeypatch, checkout):
    """Unsupported nested checkouts refuse both callers before any owner work."""
    monkeypatch.delenv("ASTRID_INSTALL_RELEASE", raising=False)
    monkeypatch.delenv("ASTRID_INSTALL_MANAGED_BY", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    runtime_checkout = tmp_path / "source-runtime"
    product_checkout = tmp_path / "source-product"
    _git_checkout(
        runtime_checkout, Path(__file__).resolve().parents[1],
        ("runtime_protocol", "astrid_runtime", "packages/python/astrid_runtime_client"),
    )
    _git_checkout(product_checkout)
    profile = SourceProfile(
        profile="astrid", runtime_checkout=str(runtime_checkout),
        source_checkout=str(product_checkout), capability_digest="caps-v1",
    )
    config = BootstrapConfig(source_profile=profile)
    paths = RuntimePaths.sandbox(tmp_path / "support")
    boundary = LocalRuntimeBoundary()
    try:
        configure_workspace(
            paths, boundary, config, mode="create",
            realm_root=paths.realms_dir / "explicit-realm", realm_id="explicit-realm",
        )
        first = bootstrap(paths, boundary, config)
        original_identity = json.loads(paths.discovery_path.read_text())["identity"]
        authority_before = {path: path.read_bytes() for path in _authority_files(paths)}
        root = runtime_checkout if checkout == "runtime" else product_checkout
        nested = root / "local-plugin"
        _git_checkout(nested)
        assert subprocess.check_output([
            "git", "-C", str(root), "ls-files", "--others", "--exclude-standard", "-z",
        ]) == b"local-plugin/\0"

        def unexpected_operation(*_args, **_kwargs):
            pytest.fail("unverified source identity attempted an owner operation or actor connection")

        with monkeypatch.context() as refusal:
            for method in ("start", "connect", "stop_owner", "restart"):
                refusal.setattr(LocalRuntimeBoundary, method, unexpected_operation)
            for content in ("baseline", "edited plugin source\n"):
                (nested / "tracked.txt").write_text(content, encoding="utf-8")
                for entrypoint in (bootstrap, connect):
                    with pytest.raises(BootstrapError, match="Requested Runtime identity could not be verified") as caught:
                        entrypoint(paths, LocalRuntimeBoundary(), config)
                    assert isinstance(caught.value.__cause__, SourceIdentityError)
                    assert "untracked source directory" in str(caught.value.__cause__)
                    assert authority_before == {path: path.read_bytes() for path in _authority_files(paths)}
                    assert boundary._process is not None and boundary._process.poll() is None
                    live = boundary.owner_startup_identity(
                        endpoint=first.endpoint, instance_id=first.runtime_instance_id,
                    )
                    assert live["runtime_instance_id"] == first.runtime_instance_id
                    assert live["identity"] == original_identity
    finally:
        _stop_unfinished(boundary)


@pytest.mark.parametrize("checkout", ["runtime", "agent"])
@pytest.mark.parametrize("nested_kind", ["ordinary", "linked"])
def test_cli_indexed_file_replaced_by_checkout_refuses_live_owner(
    tmp_path, monkeypatch, capsys, checkout, nested_kind,
):
    for name in ("ASTRID_INSTALL_RELEASE", "ASTRID_INSTALL_MANAGED_BY", "ASTRID_RUNTIME_SOURCE_MANIFEST"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    runtime, agent = tmp_path / "runtime", tmp_path / "agent"
    _git_checkout(runtime, Path(__file__).resolve().parents[1],
                  ("runtime_protocol", "astrid_runtime", "packages/python/astrid_runtime_client"))
    _git_checkout(agent)
    paths = RuntimePaths.current(data_root=tmp_path / "support")
    config = BootstrapConfig(source_profile=SourceProfile(
        profile="astrid", runtime_checkout=str(runtime), source_checkout=str(agent), capability_digest="caps-v1",
    ))
    boundary = LocalRuntimeBoundary()
    try:
        configure_workspace(paths, boundary, config, mode="create", realm_root=paths.realms_dir / "realm", realm_id="realm")
        first = bootstrap(paths, boundary, config)
        identity = json.loads(paths.discovery_path.read_text())["identity"]
        before = {p: p.read_bytes() for p in _authority_files(paths)}
        root = runtime if checkout == "runtime" else agent
        nested = root / "tracked.txt"
        nested.unlink()
        if nested_kind == "ordinary":
            _git_checkout(nested)
        else:
            other = tmp_path / "other"
            _git_checkout(other)
            subprocess.run(["git", "-C", str(other), "worktree", "add", "-qb", "nested", str(nested), "HEAD"], check=True)
        assert subprocess.check_output(["git", "-C", str(root), "ls-files", "--others", "--exclude-standard", "-z"]) == b""
        for content in ("baseline", "edited nested source"):
            (nested / "tracked.txt").write_text(content)
            with pytest.raises(SourceIdentityError, match="nested source checkout"):
                capture_source_identity(runtime, agent)
            for command in ("up", "connect"):
                assert cli.main([command, "--data-root", str(paths.app_support), "--hosted-origin", "off", "--json"]) == 1
                payload = json.loads(capsys.readouterr().out)
                assert payload["error"] == "Requested Runtime identity could not be verified."
                assert before == {p: p.read_bytes() for p in _authority_files(paths)}
                assert boundary._process is not None and boundary._process.poll() is None
                assert boundary.owner_startup_identity(endpoint=first.endpoint, instance_id=first.runtime_instance_id)["identity"] == identity
    finally:
        _stop_unfinished(boundary)
