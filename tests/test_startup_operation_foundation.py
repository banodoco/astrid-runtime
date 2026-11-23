"""Focused regression tests for Runtime startup-operation identity and custody."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

from astrid_runtime.bootstrap import BootstrapConfig, SourceProfile, _startup_scope
from astrid_runtime.identity import requested_startup_identity
from astrid_runtime.paths import RuntimePaths
from astrid_runtime.workspace import inspect_workspace, startup_status
from runtime_protocol import platform, startup_operation
from runtime_protocol.store import RealmStore


def _source_profile():
    checkout = Path(__file__).resolve().parents[1]
    return SourceProfile(
        "astrid", str(checkout), str(checkout), runtime_environment=str(Path(sys.prefix).resolve()),
    )


def _write_catalog(paths, realm_root, realm_id):
    paths.ensure_support_dirs()
    paths.catalog_path.write_text(json.dumps({
        "version": 1,
        "selected_realm_id": realm_id,
        "source_profiles": {},
        "realms": [{"realm_id": realm_id, "data_root": str(realm_root), "display_name": "Startup test"}],
    }))


def test_startup_status_does_not_reattach_operation_after_install_identity_changes(tmp_path, monkeypatch):
    """The same profile and paths under a new captured install stamp is a new scope."""
    paths = RuntimePaths.current(data_root=tmp_path / "support")
    paths.ensure_support_dirs()
    realm_root = tmp_path / "realm"
    RealmStore.initialize(realm_root, realm_id="scope-realm").close()
    source = _source_profile()
    config = BootstrapConfig(source_profile=source)
    operation_id = "a" * 32

    monkeypatch.setenv("ASTRID_INSTALL_RELEASE", "15")
    identity_a = requested_startup_identity(source)
    scope_a = _startup_scope(source, "scope-realm", realm_root)
    StartupOperation = startup_operation.StartupOperation
    StartupOperation.assign(
        paths.runtime_support.resolve(), scope_a, operation_id=operation_id, pid=os.getpid(),
    )

    monkeypatch.setenv("ASTRID_INSTALL_RELEASE", "16")
    identity_b = requested_startup_identity(source)
    assert identity_a != identity_b
    assert source.digest == config.source_profile.digest
    scope_b = _startup_scope(source, "scope-realm", realm_root)
    assert scope_b != scope_a

    observed = startup_status(
        paths,
        realm_root=realm_root,
        expected_realm_id="scope-realm",
        config=config,
        operation_id=operation_id,
    )
    assert observed["state"] == "unavailable", observed


def test_managed_inspection_does_not_trust_health_shaped_discovery_without_current_custody(tmp_path):
    """A same-realm healthy endpoint cannot replace the missing current owner fence."""
    realm_root = tmp_path / "realm"
    realm_id = "custody-realm"
    RealmStore.initialize(realm_root, realm_id=realm_id).close()
    paths = RuntimePaths.current(data_root=tmp_path / "support")
    _write_catalog(paths, realm_root, realm_id)
    from astrid_runtime.bootstrap import _realm_owner_present

    # RealmStore initialization leaves its lock file behind but releases it;
    # there is no current Runtime custody represented by that marker.
    assert not _realm_owner_present(realm_root)
    assert not paths.instance_lock_path.exists()

    endpoint = "http://127.0.0.1:43127"
    instance_id = "incumbent-instance"
    paths.discovery_path.write_text(json.dumps({
        "version": 1,
        "endpoint": endpoint,
        "pid": os.getpid(),
        # This discovery is intentionally stale even though the injected health
        # response below looks authenticated and agrees on the realm/instance.
        "process_birth_id": "stale-birth-marker",
        "runtime_instance_id": instance_id,
        "active_realm": realm_id,
        "realm_root": str(realm_root),
        "protocol_version": "workspace.v1",
        "schema_version": "workspace-schema-v1",
    }))

    class Boundary:
        startup_inspections = 0

        def is_pid_alive(self, pid):
            return pid == os.getpid()

        def endpoint_metadata(self, *, endpoint, credential_file):
            assert endpoint == "http://127.0.0.1:43127"
            return {
                "status": "ok",
                "runtime_instance_id": instance_id,
                "realm_id": realm_id,
            }

        def inspect_startup(self, *, realm_root):
            self.startup_inspections += 1
            return RealmStore.inspect_realm(realm_root, timeout_seconds=120)

    boundary = Boundary()
    config = BootstrapConfig(source_profile=_source_profile())
    result = inspect_workspace(paths, boundary, startup_operation=True, config=config)

    assert boundary.startup_inspections == 1
    assert result["ok"] is True
    assert result["inspection"]["checks"]["realm_identity"]["realm_id"] == realm_id
    assert result["inspection"]["checks"]["sqlite_integrity"]["ok"] is True
    assert not paths.instance_lock_path.exists()
