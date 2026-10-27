from __future__ import annotations

import sqlite3
import threading

import pytest
from http_helpers import Api

from astrid_runtime.runtime_boundary import LocalRuntimeBoundary
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError, RealmAdmissionError
from runtime_protocol.lifecycle import inspect_interruption_state, interruption_fence
from runtime_protocol.store import RealmStore


def _realm(tmp_path):
    root = tmp_path / "realm"
    store = RealmStore.initialize(root, realm_id="realm-lifecycle")
    spec_digest = store._store_spec({})
    store.close()
    timestamp = "2026-09-24T00:00:00Z"
    connection = sqlite3.connect(root / "realm.sqlite3")
    connection.execute(
        "INSERT INTO projects(id, realm_id, slug, name, metadata_json, created_at, updated_at) "
        "VALUES ('project', 'realm-lifecycle', 'project', 'Project', '{}', ?, ?)",
        (timestamp, timestamp),
    )
    connection.execute(
        "INSERT INTO runs(id, project_id, capability, spec_digest, status, created_at, updated_at) "
        "VALUES ('run', 'project', 'test', ?, 'running', ?, ?)",
        (spec_digest, timestamp, timestamp),
    )
    connection.execute(
        "INSERT INTO tasks(id, run_id, capability, spec_digest, status, created_at, updated_at) "
        "VALUES ('task', 'run', 'test', ?, 'queued', ?, ?)",
        (spec_digest, timestamp, timestamp),
    )
    connection.commit()
    connection.close()
    return root


@pytest.mark.parametrize(
    "lease_expires_at, expected_expired",
    [
        ("2000-01-01T00:00:00Z", True),
        ("not-a-time", None),
    ],
)
def test_unsettled_attempt_blocks_even_when_expired_or_uncertain(
    tmp_path, lease_expires_at, expected_expired
):
    root = _realm(tmp_path)
    connection = sqlite3.connect(root / "realm.sqlite3")
    connection.execute(
        "INSERT INTO attempts(id, task_id, lease_id, fence, executor_id, lease_expires_at, settled, runtime_epoch) "
        "VALUES ('attempt', 'task', 'lease', 1, 'executor', ?, 0, 1)",
        (lease_expires_at,),
    )
    connection.commit()
    connection.close()

    report = inspect_interruption_state(root)
    assert report["safe"] is False
    assert report["unreconciled_attempts"][0]["lease_expired"] is expected_expired
    with pytest.raises(ConflictError, match="Astrid is busy"):
        with interruption_fence(root):
            pass


@pytest.mark.parametrize("binding_status", ["claimed", "stale"])
def test_claimed_or_stale_execution_binding_blocks_interruption(tmp_path, binding_status):
    root = _realm(tmp_path)
    timestamp = "2026-09-24T00:00:00Z"
    connection = sqlite3.connect(root / "realm.sqlite3")
    connection.execute(
        "INSERT INTO execution_bindings("
        "binding_id, task_id, run_id, session_id, runtime_epoch, capability_id, "
        "target_kind, resolved_target_json, status, created_at, updated_at"
        ") VALUES ('binding', 'task', 'run', 'session', 1, 'test', 'local', '{}', ?, ?, ?)",
        (binding_status, timestamp, timestamp),
    )
    connection.commit()
    connection.close()
    report = inspect_interruption_state(root)
    assert report["safe"] is False
    assert report["claimed_or_stale_bindings"][0]["status"] == binding_status


def test_interruption_fence_serializes_with_admission_and_claim_writes(tmp_path):
    root = _realm(tmp_path)
    database = root / "realm.sqlite3"
    with interruption_fence(root, timeout_seconds=0.05) as report:
        assert report["safe"] is True
        contender = sqlite3.connect(database, timeout=0.01)
        try:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                contender.execute("BEGIN IMMEDIATE")
        finally:
            contender.close()

    contender = sqlite3.connect(database, timeout=0.05)
    try:
        contender.execute("BEGIN IMMEDIATE")
        contender.rollback()
    finally:
        contender.close()


def test_interruption_fence_keeps_http_owner_identity_reachable_during_claim(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
    service = daemon.service
    service.register_executor({"executor_id": "render-worker", "capabilities": ["rendering.render"]})
    epoch = service.health()["runtime_epoch"]
    restricted_token, _ = daemon.credentials.provision("restricted", ["handshake"])
    claim_started = threading.Event()
    claim_done = threading.Event()
    results, failures = [], []

    def trace(statement):
        if statement == "BEGIN IMMEDIATE":
            claim_started.set()

    service.store.conn.set_trace_callback(trace)

    def claim():
        try:
            results.append(service.claim_next({
                "executor_id": "render-worker", "capability_ids": ["rendering.render"],
                "runtime_epoch": epoch,
            }, idempotency_key="claim-during-stop"))
        except Exception as error:
            failures.append(error)
        finally:
            claim_done.set()

    worker = threading.Thread(target=claim, name="claim-during-stop")
    try:
        with interruption_fence(root) as report:
            assert report["safe"] is True
            worker.start()
            assert claim_started.wait(2), "claim did not reach the SQLite write fence"
            metadata = LocalRuntimeBoundary().endpoint_metadata(
                endpoint=daemon.endpoint, credential_file=daemon.credential_path,
            )
            assert metadata.get("runtime_instance_id") == daemon.instance_id
            assert metadata.get("realm_id") == service.realm["id"]
            assert metadata.get("status") == "ok"
            for token in (None, restricted_token):
                with pytest.raises(RuntimeError) as denied:
                    Api(daemon.endpoint, token).request("GET", "/v1/realm",
                                                       headers={"X-Astrid-Owner-Identity": "1"})
                assert denied.value.status == 401
            assert not claim_done.is_set(), "claim crossed the held interruption fence"
        worker.join(12)
        assert not worker.is_alive()
        assert not failures
        assert results == [None]
    finally:
        if worker.ident is not None:
            worker.join(12)
        service.store.conn.set_trace_callback(None)
        daemon.stop()


@pytest.mark.parametrize("failure", ["closed-store", "closed-primary", "missing-database", "corrupt-database"])
def test_identity_snapshot_preserves_closed_or_broken_store_degradation(tmp_path, failure):
    from runtime_protocol.service import RuntimeService

    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    database = service.store.db_path
    try:
        assert service.health()["status"] == "ok"
        if failure == "closed-store":
            service.close()
        elif failure == "closed-primary":
            service.store.conn.close()
        elif failure == "missing-database":
            service.store.db_path = tmp_path / "missing.sqlite3"
        else:
            from runtime_protocol import platform
            service.store.db_path = tmp_path / "corrupt.sqlite3"
            service.store.db_path.write_bytes(b"not a database")
            platform.owner_only(service.store.db_path)
        assert service.health(identity_probe=True)["status"] == "degraded"
        assert service._admission_failure == {"reason": "runtime_liveness_failed"}
        if failure == "missing-database":
            assert not service.store.db_path.exists()
            service.store.db_path = database
            assert service.health(identity_probe=True)["status"] == "degraded"
            with pytest.raises(RealmAdmissionError):
                service.create_project({"slug": "after-failure", "name": "After failure"})
    finally:
        service.store.db_path = database
        service.store.close(orderly=False)


def test_identity_snapshot_reads_exact_committed_realm_and_is_read_only(tmp_path):
    from runtime_protocol.service import RuntimeService

    root = tmp_path / "realm space % # ünicode"
    RealmStore.initialize(root, realm_id="selected-realm").close()
    service = RuntimeService(root)
    try:
        assert service.health(identity_probe=True)["status"] == "ok"
        assert service.realm_resource(identity_probe=True)["realm_id"] == "selected-realm"
        service.tombstone({"expected_version": 1})
        resource = service.realm_resource(identity_probe=True)
        assert resource["state"] == "tombstoned"
        assert resource["lifecycle_version"] == 2
        with service.store._read_snapshot() as reader:
            with pytest.raises(sqlite3.OperationalError, match="readonly"):
                reader.execute("UPDATE realm SET display_name='uncommitted'")
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            reader.execute("SELECT 1")
        assert service.realm_resource(identity_probe=True)["display_name"] == "Workspace"
    finally:
        service.close()


def test_failed_health_snapshot_serializes_admission_loss_with_mutation(tmp_path, monkeypatch):
    from runtime_protocol.service import RuntimeService

    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    writer_entered, release_writer, health_failed, health_done = (threading.Event() for _ in range(4))
    admission_waiting = threading.Event()
    results, failures = {}, []
    create_project = service.store.create_project
    mutex = service.store._mutex

    class AdmissionMutex:
        def __enter__(self):
            if threading.current_thread().name == "health-failure":
                admission_waiting.set()
            return mutex.__enter__()

        def __exit__(self, *args):
            return mutex.__exit__(*args)

    service.store._mutex = AdmissionMutex()

    def paused_write(*args, **kwargs):
        writer_entered.set()
        assert release_writer.wait(2), "writer was not released"
        return create_project(*args, **kwargs)

    def broken_snapshot():
        health_failed.set()
        raise sqlite3.DatabaseError("identity read failed")

    def write():
        try:
            results["project"] = service.create_project({"slug": "admitted", "name": "Admitted"})
        except Exception as error:
            failures.append(error)

    def health():
        try:
            results["health"] = service.health(identity_probe=True)
        except Exception as error:
            failures.append(error)
        finally:
            health_done.set()

    monkeypatch.setattr(service.store, "create_project", paused_write)
    monkeypatch.setattr(service.store, "_read_snapshot", broken_snapshot)
    writer = threading.Thread(target=write)
    probe = threading.Thread(target=health, name="health-failure")
    try:
        writer.start()
        assert writer_entered.wait(2)
        probe.start()
        assert health_failed.wait(2)
        assert admission_waiting.wait(2), "health did not serialize its admission failure"
        assert not health_done.is_set()
        assert service._verified is True
        release_writer.set()
        writer.join(2)
        probe.join(2)
        assert not writer.is_alive() and not probe.is_alive()
        assert not failures
        assert results["project"]["slug"] == "admitted"
        assert results["health"]["status"] == "degraded"
        with pytest.raises(RealmAdmissionError):
            service.create_project({"slug": "after-failure", "name": "After failure"})
        assert service.store.conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == 1
    finally:
        release_writer.set()
        writer.join(2)
        if probe.ident is not None:
            probe.join(2)
        service.close()


def test_interruption_observation_rejects_symlink_realm_alias(tmp_path):
    root = _realm(tmp_path)
    alias = tmp_path / "realm-alias"
    alias.symlink_to(root, target_is_directory=True)
    before = (root / "realm.sqlite3").read_bytes()
    with pytest.raises(RealmAdmissionError, match="symlink"):
        inspect_interruption_state(alias)
    assert (root / "realm.sqlite3").read_bytes() == before
