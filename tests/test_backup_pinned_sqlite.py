import hashlib
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

import runtime_protocol.backup as backup_module
from runtime_protocol.errors import ConflictError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_store import TimelineCommitStore


@pytest.fixture
def darwin_verifier(tmp_path, monkeypatch):
    """Exercise macOS verification on every host, rejecting descriptor aliases."""
    monkeypatch.setattr(backup_module, "sys", SimpleNamespace(platform="darwin"), raising=False)
    original_connect = sqlite3.connect
    original_stat = os.stat
    original_temporary_directory = backup_module.tempfile.TemporaryDirectory
    snapshots = []

    def connect(database, *args, **kwargs):
        assert "/dev/fd/" not in str(database), "macOS cannot reopen SQLite through /dev/fd"
        return original_connect(database, *args, **kwargs)

    def stat(path, *args, **kwargs):
        assert not str(path).startswith("/dev/fd/"), "macOS cannot traverse a directory fd alias"
        return original_stat(path, *args, **kwargs)

    def temporary_directory(*args, **kwargs):
        directory = original_temporary_directory(*args, dir=tmp_path, **kwargs)
        snapshots.append(Path(directory.name))
        return directory

    monkeypatch.setattr(backup_module.sqlite3, "connect", connect)
    monkeypatch.setattr(backup_module.os, "stat", stat)
    monkeypatch.setattr(backup_module.tempfile, "TemporaryDirectory", temporary_directory)
    yield snapshots
    assert all(not path.exists() for path in snapshots)


def _database(path, value):
    connection = sqlite3.connect(path)
    try:
        with connection:
            connection.execute("CREATE TABLE evidence(value TEXT)")
            connection.execute("INSERT INTO evidence VALUES (?)", (value,))
    finally:
        connection.close()


def test_backup_darwin_snapshot_is_pinned_readonly_and_cleaned(tmp_path, monkeypatch, darwin_verifier):
    root = tmp_path / "source"
    root.mkdir()
    database = root / "realm.sqlite3"
    _database(database, "pinned")
    before = database.read_bytes()
    root_fd = backup_module.open_directory_chain(root)
    original_read = backup_module.os.read
    moved = tmp_path / "moved-source"

    def replace_directory(fd, size):
        if not moved.exists():
            root.rename(moved)
            root.mkdir()
            _database(database, "replacement")
        return original_read(fd, size)

    monkeypatch.setattr(backup_module.os, "read", replace_directory)
    try:
        connection = backup_module._connection_from_fd(root_fd, "realm.sqlite3")
        try:
            assert connection.execute("SELECT value FROM evidence").fetchone() == ("pinned",)
            assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
            with pytest.raises(sqlite3.OperationalError, match="readonly"):
                connection.execute("INSERT INTO evidence VALUES ('mutation')")
            assert connection._snapshot_path.read_bytes() == before
        finally:
            connection.close()
        assert (moved / "realm.sqlite3").read_bytes() == before
        assert {path.name for path in moved.iterdir()} == {"realm.sqlite3"}
        assert darwin_verifier and all(not path.exists() for path in darwin_verifier)
    finally:
        os.close(root_fd)


def test_backup_darwin_snapshot_rejects_inflight_change(tmp_path, monkeypatch, darwin_verifier):
    database = tmp_path / "realm.sqlite3"
    _database(database, "original")
    root_fd = backup_module.open_directory_chain(tmp_path)
    original_read = backup_module.os.read
    changed = False

    def change_database(fd, size):
        nonlocal changed
        data = original_read(fd, size)
        if not changed:
            changed = True
            with database.open("ab") as output:
                output.write(b"injected concurrent change")
        return data

    monkeypatch.setattr(backup_module.os, "read", change_database)
    try:
        with pytest.raises(ConflictError, match="changed while being snapshotted"):
            backup_module._connection_from_fd(root_fd, "realm.sqlite3")
        assert changed
        assert darwin_verifier and all(not path.exists() for path in darwin_verifier)
    finally:
        os.close(root_fd)


def test_backup_darwin_snapshot_cleans_up_failed_open(tmp_path, monkeypatch, darwin_verifier):
    _database(tmp_path / "realm.sqlite3", "original")
    root_fd = backup_module.open_directory_chain(tmp_path)

    def reject_snapshot(*args, **kwargs):
        raise sqlite3.OperationalError("injected snapshot open failure")

    monkeypatch.setattr(backup_module.sqlite3, "connect", reject_snapshot)
    try:
        with pytest.raises(sqlite3.OperationalError, match="snapshot open failure"):
            backup_module._connection_from_fd(root_fd, "realm.sqlite3")
        assert darwin_verifier and all(not path.exists() for path in darwin_verifier)
    finally:
        os.close(root_fd)


def test_backup_darwin_snapshot_cleans_up_failed_inspector_setup(tmp_path, monkeypatch, darwin_verifier):
    _database(tmp_path / "realm.sqlite3", "original")
    root_fd = backup_module.open_directory_chain(tmp_path)
    original_open = backup_module._open_relative
    original_connection = backup_module._connection_from_fd
    connections = []

    def deny_cas(root_fd, name, **kwargs):
        if name == "cas/sha256":
            raise PermissionError("injected CAS open failure")
        return original_open(root_fd, name, **kwargs)

    def retain_connection(*args, **kwargs):
        connection = original_connection(*args, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(backup_module, "_open_relative", deny_cas)
    monkeypatch.setattr(backup_module, "_connection_from_fd", retain_connection)
    try:
        with pytest.raises(PermissionError, match="CAS open failure"):
            backup_module._inspect_consolidated_realm(root_fd)
        assert darwin_verifier and all(not path.exists() for path in darwin_verifier)
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connections[0].execute("SELECT 1")
    finally:
        for connection in connections:
            connection.close()
        os.close(root_fd)


def test_backup_darwin_roundtrip_and_adoption_copy(tmp_path, darwin_verifier):
    from astrid_runtime.workspace_adopt import _materialize_backup, _pinned_backup_source

    root = tmp_path / "realm"
    RealmStore.initialize(root, realm_id="pinned-realm").close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "fixture", "name": "Fixture"}, idempotency_key="fixture")
        service.ingest(project["id"], b"temporary fixture media", media_type="application/octet-stream", idempotency_key="media")
        backup = tmp_path / "backup"
        service.backup(backup)
        assert backup_module.verify_backup(backup)["doctor"]["ok"]
        candidate = tmp_path / "candidate"
        service.restore(backup, candidate)
        assert backup_module.verify_restore_candidate(candidate)["doctor"]["ok"]
        adopted = tmp_path / "adopted"
        adopted.mkdir(mode=0o700)
        with _pinned_backup_source(backup, service.realm["id"]) as pinned:
            assert _materialize_backup(backup, adopted, pinned)["bytes_copied"] > 0
        assert (adopted / "realm.sqlite3").read_bytes() == (backup / "realm.sqlite3").read_bytes()
    finally:
        service.close()
    assert darwin_verifier and all(not path.exists() for path in darwin_verifier)


def test_backup_darwin_timeline_cas_reads_stay_pinned(tmp_path, monkeypatch, darwin_verifier):
    root = tmp_path / "realm"
    store = RealmStore.initialize(tmp_path / "live")
    data = b"pinned timeline input"
    digest = hashlib.sha256(data).hexdigest()
    obj = store.cas_root / digest[:2] / digest[2:]
    obj.parent.mkdir()
    obj.write_bytes(data)
    store.record_object(digest, len(data), "application/octet-stream")
    try:
        backup_module.create_backup(store, root, key_path=tmp_path / "backup-auth.key")
    finally:
        store.close()
    original_report = RealmStore.integrity_report

    def inspect_with_timeline_inputs(inspector, **kwargs):
        root.rename(tmp_path / "moved-realm")
        root.mkdir()
        # All reads and retained-input rechecks must still see the pinned CAS.
        history = TimelineCommitStore(inspector, validate_prepared=None)
        with history.verification_scope(), history.history_read_scope():
            assert history._read_history_object(digest) == data
        report = original_report(inspector, **kwargs)
        assert report["ok"], json.dumps(report)
        return report

    monkeypatch.setattr(RealmStore, "integrity_report", inspect_with_timeline_inputs)
    root_fd = backup_module.open_directory_chain(root)
    try:
        report, realm = backup_module._inspect_consolidated_realm(root_fd)
        assert report["ok"]
        assert realm["id"]
    finally:
        os.close(root_fd)
