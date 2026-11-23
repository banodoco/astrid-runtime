"""Focused regression tests for Runtime startup-operation identity and custody."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import threading

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


def test_simultaneous_initial_startup_inspections_share_one_scan_and_operation(
    tmp_path, monkeypatch,
):
    """Two no-record first observations must not queue duplicate full scans."""
    import astrid_runtime.workspace as workspace_module

    realm_root = tmp_path / "realm"
    realm_id = "simultaneous-realm"
    RealmStore.initialize(realm_root, realm_id=realm_id).close()
    paths = RuntimePaths.current(data_root=tmp_path / "support")
    _write_catalog(paths, realm_root, realm_id)
    source = _source_profile()
    config = BootstrapConfig(source_profile=source)
    paths.bootstrap_lock_path.touch()
    platform.owner_only(paths.bootstrap_lock_path)

    initial_reads = threading.Barrier(2)
    first_scan_started = threading.Event()
    release_first_scan = threading.Event()
    second_lock_contended = threading.Event()
    permit_queued_lock = threading.Event()
    counts_lock = threading.Lock()
    seen_threads = set()
    scan_count = 0
    lock_holder = None
    outcomes = {}
    errors = {}
    original_pending = workspace_module._pending_inspection
    original_lock_file = platform.lock_file
    original_unlock_file = platform.unlock_file
    original_copy = RealmStore._copy_admission_file

    def synchronize_initial_pending(paths_arg, scope):
        result = original_pending(paths_arg, scope)
        thread_name = threading.current_thread().name
        with counts_lock:
            first_read = thread_name not in seen_threads
            if first_read:
                seen_threads.add(thread_name)
        if first_read:
            assert result is None
            initial_reads.wait(timeout=5)
        return result

    bootstrap_lock_stat = paths.bootstrap_lock_path.stat()

    def observed_lock(fd, *, exclusive=True, blocking=True):
        nonlocal lock_holder
        observed = os.fstat(fd)
        if ((observed.st_dev, observed.st_ino)
                != (bootstrap_lock_stat.st_dev, bootstrap_lock_stat.st_ino)):
            return original_lock_file(fd, exclusive=exclusive, blocking=blocking)

        thread_name = threading.current_thread().name
        with counts_lock:
            if lock_holder is None:
                lock_holder = thread_name
                return original_lock_file(fd, exclusive=exclusive, blocking=blocking)
            second_attempt = thread_name != lock_holder
        if not second_attempt:
            return original_lock_file(fd, exclusive=exclusive, blocking=blocking)

        # Prove the second caller reached the same real bootstrap lock while it
        # was held by the first. Candidate nonblocking acquisition reports this
        # contention directly; baseline blocking acquisition waits for the
        # test to release the first scan, then proceeds through the real lock.
        try:
            original_lock_file(fd, exclusive=exclusive, blocking=False)
        except BlockingIOError:
            second_lock_contended.set()
            if not blocking:
                raise
            if not permit_queued_lock.wait(timeout=5):
                raise TimeoutError("test did not release queued bootstrap lock")
            return original_lock_file(fd, exclusive=exclusive, blocking=True)
        else:
            original_unlock_file(fd)
            second_lock_contended.set()
            return original_lock_file(fd, exclusive=exclusive, blocking=blocking)

    monkeypatch.setattr(workspace_module, "_pending_inspection", synchronize_initial_pending)
    monkeypatch.setattr(platform, "lock_file", observed_lock)

    held_copy_threads = set()

    def hold_first_real_admission_copy(source_path, destination_path, deadline):
        original_copy(source_path, destination_path, deadline)
        thread_name = threading.current_thread().name
        with counts_lock:
            hold = thread_name not in held_copy_threads
            held_copy_threads.add(thread_name)
        if hold:
            first_scan_started.set()
            if not release_first_scan.wait(timeout=5):
                raise TimeoutError("test did not release first cold integrity copy")

    monkeypatch.setattr(
        RealmStore, "_copy_admission_file", staticmethod(hold_first_real_admission_copy),
    )

    class Boundary:
        def inspect_startup(self, *, realm_root):
            nonlocal scan_count
            with counts_lock:
                scan_count += 1
            return RealmStore.inspect_realm(realm_root, timeout_seconds=120)

    def inspect(name):
        try:
            outcomes[name] = inspect_workspace(
                paths, Boundary(), startup_operation=True, config=config,
            )
        except BaseException as exc:
            errors[name] = exc

    threads = [
        threading.Thread(target=inspect, args=(f"arrival-{index}",), name=f"arrival-{index}")
        for index in (1, 2)
    ]
    for thread in threads:
        thread.start()

    operation_id = None
    try:
        assert first_scan_started.wait(timeout=5), "neither caller entered the first integrity scan"
        assert second_lock_contended.wait(timeout=5), "second caller did not reach the bootstrap lock"
        observed = startup_operation.read_operation(paths.runtime_support.resolve(), fresh=False)
        assert observed is not None and observed.state == "pending"
        operation_id = observed.operation_id
    finally:
        # Release the queued baseline caller and the held verifier together;
        # all waits in workers/barriers are bounded above.
        permit_queued_lock.set()
        release_first_scan.set()
        for thread in threads:
            thread.join(timeout=6)

    assert all(not thread.is_alive() for thread in threads), "inspection worker exceeded its bounded join"
    assert not errors, errors
    assert scan_count == 1, f"simultaneous inspection repeated the full verifier {scan_count} times"
    assert len(outcomes) == 2

    winners = [result for result in outcomes.values() if result.get("ok") is True]
    losers = [result for result in outcomes.values() if result.get("ok") is False]
    assert len(winners) == 1
    assert len(losers) == 1
    loser = losers[0]
    assert loser.get("state") in {"startup_busy", "startup_pending"}, loser
    if loser["state"] == "startup_pending":
        assert loser["startup_operation"]["operation_id"] == operation_id
