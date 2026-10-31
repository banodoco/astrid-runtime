from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3
import shutil
from types import SimpleNamespace

import pytest

from astrid_runtime.bootstrap import BootstrapConfig, SourceProfile
from astrid_runtime.paths import RuntimePaths
from astrid_runtime.workspace_adopt import WorkspaceAdoptError, adopt_workspace
from runtime_protocol.store import RealmStore
from runtime_protocol.upgrade import inspect_canonical_schema
from runtime_protocol.store import SCHEMA_VERSION
from runtime_protocol import platform as runtime_platform


@pytest.fixture(autouse=True)
def _adoption_capacity(monkeypatch):
    # Adoption budgets a 4 GiB reserve plus copy and migration space; give these
    # filesystem-isolated tests a stable capacity observation.
    from collections import namedtuple
    from astrid_runtime import workspace_adopt

    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(
        workspace_adopt,
        "shutil",
        SimpleNamespace(disk_usage=lambda *_: usage(16 * 1024**3, 0, 16 * 1024**3), rmtree=shutil.rmtree),
    )


class _Boundary:
    def inspect(self, *, realm_root):
        return RealmStore.inspect_realm(realm_root)


def _setup(tmp_path):
    root = tmp_path / "old" / "runtime" / "realms" / "film"
    RealmStore.initialize(root, realm_id="film").close()
    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        # A fresh realm is the current schema; walk it back to a genuine v26 layout:
        # v28 -> v27 (inline specs, no task_specs) then v27 -> v26 (no user_preferences).
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("ALTER TABLE timelines DROP COLUMN name")  # v30 -> v29: timelines.name is the only v30 change
        connection.execute("DROP TABLE user_app_state")
        connection.execute("DROP INDEX idx_generations_gen")
        connection.execute("DROP INDEX IF EXISTS idx_tasks_retention")
        for table in ("runs", "tasks"):
            connection.execute(f"ALTER TABLE {table} ADD COLUMN spec_json TEXT")
            connection.execute(f"ALTER TABLE {table} DROP COLUMN spec_digest")
        connection.execute("DROP TABLE task_specs")
        connection.execute("DROP TABLE user_preferences")
        connection.execute("UPDATE runtime_schema SET version=26 WHERE id=1")
        connection.commit()
    finally:
        connection.close()
    (root / "cas" / "sha256" / "aa").mkdir(parents=True)
    (root / "cas" / "sha256" / "aa" / "sample").write_bytes(b"sample-media")
    paths = RuntimePaths.current(data_root=tmp_path / "new")
    profile = SourceProfile("astrid", str(tmp_path), str(tmp_path))
    config = BootstrapConfig(source_profile=profile)
    return root, paths, config


def _fingerprints(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*") if path.is_file()}


def _adopt(root, paths, config, monkeypatch):
    monkeypatch.setattr("astrid_runtime.workspace_adopt.bootstrap", lambda *_: object())
    monkeypatch.setattr("astrid_runtime.workspace_adopt._verify_running", lambda *_: {"health": True})
    return adopt_workspace(paths, _Boundary(), config, source=root.parent.parent.parent, realm_id="film")


def test_adopts_v26_without_modifying_source(tmp_path, monkeypatch):
    root, paths, config = _setup(tmp_path)
    before = _fingerprints(root)
    result = _adopt(root, paths, config, monkeypatch)
    assert result["source_version"] == 26
    assert result["target_version"] == SCHEMA_VERSION
    assert inspect_canonical_schema(paths.realms_dir / "film")["version"] == SCHEMA_VERSION
    assert _fingerprints(root) == before
    assert result["bytes_cloned"] + result["bytes_copied"] >= (root / "realm.sqlite3").stat().st_size


def test_refuses_live_source_with_stop_instruction(tmp_path, monkeypatch):
    root, paths, config = _setup(tmp_path)
    with (root / "owner.lock").open("r+") as lock:
        runtime_platform.lock_file(lock.fileno(), exclusive=True, blocking=False)
        with pytest.raises(WorkspaceAdoptError, match="stop the old runtime first"):
            _adopt(root, paths, config, monkeypatch)
    assert not (paths.realms_dir / "film").exists()


def test_copy_fallback_and_interrupted_retry(tmp_path, monkeypatch):
    root, paths, config = _setup(tmp_path)
    monkeypatch.setattr("runtime_protocol.fsclone.clone_file", lambda *_: False)
    monkeypatch.setattr("astrid_runtime.workspace_adopt.clone_file", lambda *_: False)
    from astrid_runtime import workspace_adopt
    original = workspace_adopt._materialize
    calls = 0
    def fail_once(*args):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("interrupted")
        return original(*args)
    monkeypatch.setattr(workspace_adopt, "_materialize", fail_once)
    with pytest.raises(RuntimeError, match="interrupted"):
        _adopt(root, paths, config, monkeypatch)
    assert not (paths.realms_dir / "film").exists()
    result = _adopt(root, paths, config, monkeypatch)
    assert result["bytes_cloned"] == 0
    assert result["bytes_copied"] > 0
    assert inspect_canonical_schema(paths.realms_dir / "film")["version"] == SCHEMA_VERSION


def test_retries_launch_after_published_attach(tmp_path, monkeypatch):
    root, paths, config = _setup(tmp_path)
    monkeypatch.setattr("astrid_runtime.workspace_adopt.bootstrap", lambda *_: (_ for _ in ()).throw(RuntimeError("launch failed")))
    with pytest.raises(WorkspaceAdoptError, match="finish with astrid-runtime up"):
        adopt_workspace(paths, _Boundary(), config, source=root, realm_id="film")
    assert (paths.realms_dir / "film").is_dir()
    monkeypatch.setattr("astrid_runtime.workspace_adopt.bootstrap", lambda *_: object())
    monkeypatch.setattr("astrid_runtime.workspace_adopt._verify_running", lambda *_: {"health": True})
    result = adopt_workspace(paths, _Boundary(), config, source=root, realm_id="film")
    assert result["ok"]
    assert result["target_version"] == SCHEMA_VERSION


def test_mirror_directories_keeps_empty_storage_roots_and_modes(tmp_path):
    # Real realms have an empty staging/ and 0700 storage roots; admission
    # refuses a realm without them ("realm storage roots are incomplete").
    from astrid_runtime.workspace_adopt import _mirror_directories

    source = tmp_path / "source"
    for relative in ("cas/sha256/ab", "staging", "presentations"):
        (source / relative).mkdir(parents=True)
    for relative in ("cas", "cas/sha256", "staging"):
        (source / relative).chmod(0o700)
    target = tmp_path / "target"
    target.mkdir()
    _mirror_directories(source, target)
    for relative in ("cas", "cas/sha256", "cas/sha256/ab", "staging", "presentations"):
        assert (target / relative).is_dir()
    assert (target / "staging").stat().st_mode & 0o777 == 0o700
    assert (target / "cas/sha256").stat().st_mode & 0o777 == 0o700


def test_completed_adoption_rerun_reuses_destination_without_clone_or_migration(tmp_path, monkeypatch):
    root, paths, config = _setup(tmp_path)
    before = _fingerprints(root)
    first = _adopt(root, paths, config, monkeypatch)
    destination = paths.realms_dir / "film"
    database = (destination / "realm.sqlite3").read_bytes()
    journal = paths.runtime_support / "adopt-journal.json"
    import json
    assert json.loads(journal.read_text())["state"] == "complete"
    def unexpected(*args, **kwargs):
        pytest.fail("completed adoption must not reclone or remigrate the destination")
    monkeypatch.setattr("astrid_runtime.workspace_adopt._materialize", unexpected)
    monkeypatch.setattr("astrid_runtime.workspace_adopt.migrate_canonical_to_current", unexpected)
    second = _adopt(root, paths, config, monkeypatch)
    assert second["destination"] == first["destination"]
    assert second["migration"] == first["migration"]
    assert (destination / "realm.sqlite3").read_bytes() == database
    assert _fingerprints(root) == before
    assert json.loads(journal.read_text())["state"] == "complete"


def _live_backup(tmp_path):
    """The source owner retains its lock throughout backup adoption."""
    from runtime_protocol.backup import create_backup

    store = RealmStore.initialize(tmp_path / "live" / "film", realm_id="film")
    media = b"authenticated-backup-media"
    digest = hashlib.sha256(media).hexdigest()
    obj = store.cas_root / digest[:2] / digest[2:]
    obj.parent.mkdir(parents=True, exist_ok=True)
    obj.write_bytes(media)
    store.record_object(digest, len(media), "application/octet-stream")
    backup = tmp_path / "backup"
    create_backup(store, backup, key_path=tmp_path / "backup-auth.key")
    paths = RuntimePaths.current(data_root=tmp_path / "new")
    config = BootstrapConfig(source_profile=SourceProfile("astrid", str(tmp_path), str(tmp_path)))
    return store, backup, paths, config


def _adopt_from(source, paths, config, monkeypatch, realm_id="film"):
    monkeypatch.setattr("astrid_runtime.workspace_adopt.bootstrap", lambda *_: object())
    monkeypatch.setattr("astrid_runtime.workspace_adopt._verify_running", lambda *_: {"health": True})
    return adopt_workspace(paths, _Boundary(), config, source=source, realm_id=realm_id)


def _rewrite_backup_database(backup, sql):
    """Model an authenticated backup emitted by a historical canonical runtime."""
    import json
    from runtime_protocol.backup import _authenticated_digest, _manifest_digest_payload, _manifest_mac
    from runtime_protocol.util import canonical_json

    connection = sqlite3.connect(backup / "realm.sqlite3")
    try:
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA foreign_keys=OFF")
        for statement in sql:
            connection.execute(statement)
        version = connection.execute("SELECT version FROM runtime_schema WHERE id=1").fetchone()[0]
        connection.commit()
    finally:
        connection.close()
    manifest_path = backup / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    database = (backup / "realm.sqlite3").read_bytes()
    manifest["files"]["realm.sqlite3"] = {"sha256": hashlib.sha256(database).hexdigest(), "size": len(database)}
    manifest["database_sha256"] = hashlib.sha256(database).hexdigest()
    manifest["schema"]["version"] = version
    manifest["manifest_sha256"] = _authenticated_digest(_manifest_digest_payload(manifest))
    key = Path(manifest["authentication"]["key_path"]).read_bytes()
    manifest["manifest_hmac"] = _manifest_mac(manifest, key)
    manifest_path.write_text(canonical_json(manifest) + "\n")


def _historical_backup(backup, version):
    sql = []
    if version < 32:
        sql += ["DROP INDEX idx_generations_gen"]
    if version < 31:  # v31 -> v30: user_app_state is the only v31 change
        sql += ["DROP TABLE user_app_state"]
    if version < 30:  # v30 -> v29: timelines.name is the only v30 change
        sql += ["ALTER TABLE timelines DROP COLUMN name"]
    if version < 28:
        sql += ["DROP INDEX IF EXISTS idx_tasks_retention"]
        for table in ("runs", "tasks"):
            sql += [f"ALTER TABLE {table} ADD COLUMN spec_json TEXT", f"ALTER TABLE {table} DROP COLUMN spec_digest"]
        sql += ["DROP TABLE task_specs"]
    if version < 27:
        sql += ["DROP TABLE user_preferences"]
    _rewrite_backup_database(backup, sql + [f"UPDATE runtime_schema SET version={version} WHERE id=1"])
    # Version alone is insufficient fixture evidence.
    assert inspect_canonical_schema(backup)["version"] == version


@pytest.mark.parametrize("version", [26, 28, SCHEMA_VERSION])
def test_adopts_authenticated_backup_with_live_source_owner(tmp_path, monkeypatch, version):
    store, backup, paths, config = _live_backup(tmp_path)
    try:
        if version != SCHEMA_VERSION:
            _historical_backup(backup, version)
        before = _fingerprints(backup)
        source_before = _fingerprints(store.root)
        result = _adopt_from(backup, paths, config, monkeypatch)
        with pytest.raises(BlockingIOError):
            with (store.root / "owner.lock").open("r+") as contender:
                runtime_platform.lock_file(contender.fileno(), exclusive=True, blocking=False)
        assert _fingerprints(store.root) == source_before
        assert _fingerprints(backup) == before
    finally:
        store.close()
    destination = paths.realms_dir / "film"
    assert result["source_kind"] == "backup"
    assert result["source_version"] == version
    assert inspect_canonical_schema(destination)["version"] == SCHEMA_VERSION
    assert RealmStore.inspect_realm(destination, deep=True)["ok"]
    for relative in ("cas", "cas/sha256", "staging"):
        assert (destination / relative).stat().st_mode & 0o777 == 0o700
    assert not (destination / "manifest.json").exists()


def test_backup_wrong_realm_authentication_and_database_refused(tmp_path, monkeypatch):
    import json
    store, backup, paths, config = _live_backup(tmp_path)
    try:
        with pytest.raises(WorkspaceAdoptError, match="different realm"):
            _adopt_from(backup, paths, config, monkeypatch, realm_id="other")
        manifest_path = backup / "manifest.json"
        original = manifest_path.read_bytes()
        manifest = json.loads(original)
        manifest["realm"]["id"] = "forged-realm"
        manifest_path.write_text(json.dumps(manifest))
        with pytest.raises(WorkspaceAdoptError, match="authentication"):
            _adopt_from(backup, paths, config, monkeypatch)
        manifest_path.write_bytes(original)
        with (backup / "realm.sqlite3").open("r+b") as database:
            database.seek(200)
            database.write(b"tampered")
        with pytest.raises(WorkspaceAdoptError, match="backup did not verify"):
            _adopt_from(backup, paths, config, monkeypatch)
    finally:
        store.close()
    assert not (paths.realms_dir / "film").exists()


@pytest.mark.parametrize("mutation", ["database", "cas", "extra", "missing", "symlink", "manifest", "cas_manifest", "directory"])
def test_backup_changed_between_verification_and_copy_never_migrates(tmp_path, monkeypatch, mutation):
    import shutil
    from astrid_runtime import workspace_adopt
    store, backup, paths, config = _live_backup(tmp_path)
    original = workspace_adopt._materialize_backup
    obj = next((backup / "cas" / "sha256").glob("*/*"))

    def mutate_then_copy(root, temporary, evidence):
        if mutation == "database":
            with (root / "realm.sqlite3").open("r+b") as database:
                database.seek(200)
                database.write(b"changed")
        elif mutation == "cas":
            obj.write_bytes(b"changed-after-verify")
        elif mutation == "extra":
            (obj.parent / ("0" * 62)).write_bytes(b"extra")
        elif mutation == "missing":
            obj.unlink()
        elif mutation == "symlink":
            obj.unlink()
            obj.symlink_to(tmp_path / "outside")
        elif mutation in {"manifest", "cas_manifest"}:
            name = "manifest.json" if mutation == "manifest" else "cas-manifest.json"
            (root / name).write_bytes((root / name).read_bytes() + b" ")
        else:
            root.rename(root.with_name("retained-backup"))
            shutil.copytree(root.with_name("retained-backup"), root)
        return original(root, temporary, evidence)

    def unexpected(*args, **kwargs):
        pytest.fail("unverified backup bytes must not reach migration or attachment")

    monkeypatch.setattr(workspace_adopt, "_materialize_backup", mutate_then_copy)
    monkeypatch.setattr(workspace_adopt, "migrate_canonical_to_current", unexpected)
    monkeypatch.setattr(workspace_adopt, "configure_workspace", unexpected)
    try:
        with pytest.raises(WorkspaceAdoptError):
            _adopt_from(backup, paths, config, monkeypatch)
    finally:
        store.close()
    assert not (paths.realms_dir / "film").exists()
    assert not list(paths.realms_dir.glob(".film.adopt-*"))


@pytest.mark.parametrize("component", ["database", "cas"])
def test_copy_bytes_are_checked_against_retained_evidence_before_migration(tmp_path, monkeypatch, component):
    import os
    from astrid_runtime import workspace_adopt
    store, backup, paths, config = _live_backup(tmp_path)
    original = workspace_adopt.copy_file_at
    changed = False

    def corrupt_copy(source_fd, name, destination_fd, target_name, **kwargs):
        nonlocal changed
        original(source_fd, name, destination_fd, target_name, **kwargs)
        if (component == "database" and name == "realm.sqlite3") or (component == "cas" and name != "realm.sqlite3"):
            fd = os.open(target_name, os.O_WRONLY, dir_fd=destination_fd)
            try:
                os.lseek(fd, 200 if component == "database" else 0, os.SEEK_SET)
                os.write(fd, b"tampered-copy")
                changed = True
            finally:
                os.close(fd)

    monkeypatch.setattr(workspace_adopt, "copy_file_at", corrupt_copy)
    monkeypatch.setattr(workspace_adopt, "migrate_canonical_to_current", lambda *a, **k: pytest.fail("copy integrity must precede migration"))
    try:
        with pytest.raises(WorkspaceAdoptError, match="verification"):
            _adopt_from(backup, paths, config, monkeypatch)
        assert changed
    finally:
        store.close()
    assert not (paths.realms_dir / "film").exists()


@pytest.mark.parametrize("issue", ["unsupported", "extra_table", "missing_column", "foreign_key"])
def test_authenticated_older_backup_with_unsupported_shape_or_second_issue_is_refused(tmp_path, monkeypatch, issue):
    from runtime_protocol.errors import RuntimeErrorBase
    store, backup, paths, config = _live_backup(tmp_path)
    try:
        _historical_backup(backup, 26)
        statements = {
            "unsupported": ["UPDATE runtime_schema SET version=23 WHERE id=1"],
            "extra_table": ["CREATE TABLE alternate_runtime(value TEXT)"],
            "missing_column": ["ALTER TABLE attempts DROP COLUMN lease_id"],
            "foreign_key": ["INSERT INTO project_objects(project_id, digest, relation, created_at) VALUES ('missing', 'missing', 'managed', 'now')"],
        }
        _rewrite_backup_database(backup, statements[issue])
        monkeypatch.setattr("astrid_runtime.workspace_adopt.migrate_canonical_to_current", lambda *a, **k: pytest.fail("unsafe old backup must not migrate"))
        with pytest.raises((WorkspaceAdoptError, RuntimeErrorBase)):
            _adopt_from(backup, paths, config, monkeypatch)
    finally:
        store.close()
    assert not (paths.realms_dir / "film").exists()


def test_backup_interrupted_copy_can_retry_and_completed_evolved_destination_is_reused(tmp_path, monkeypatch):
    from astrid_runtime import workspace_adopt
    store, backup, paths, config = _live_backup(tmp_path)
    original = workspace_adopt._materialize_backup
    calls = 0

    def interrupt_once(*args):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("interrupted backup copy")
        return original(*args)

    monkeypatch.setattr(workspace_adopt, "_materialize_backup", interrupt_once)
    try:
        with pytest.raises(RuntimeError, match="interrupted backup"):
            _adopt_from(backup, paths, config, monkeypatch)
        result = _adopt_from(backup, paths, config, monkeypatch)
        destination = paths.realms_dir / "film"
        evolved = RealmStore(destination)
        evolved.create_project("after-adopt", "Legitimate destination evolution")
        evolved.close()
        before = _fingerprints(destination)
        monkeypatch.setattr(workspace_adopt, "_materialize_backup", lambda *a: pytest.fail("completed adoption must not recopy"))
        monkeypatch.setattr(workspace_adopt, "migrate_canonical_to_current", lambda *a, **k: pytest.fail("completed adoption must not remigrate"))
        repeated = _adopt_from(backup, paths, config, monkeypatch)
        assert repeated["migration"] == result["migration"]
        after = _fingerprints(destination)
        # Canonical inspection uses SQLite mode=ro, which may create WAL read
        # coordination files for a WAL-mode database. Every original file,
        # including the authoritative DB/CAS, must retain identical bytes.
        assert {name: after[name] for name in before} == before
        added = set(after) - set(before)
        assert added <= {"realm.sqlite3-wal", "realm.sqlite3-shm"}
        if "realm.sqlite3-wal" in added:
            assert (destination / "realm.sqlite3-wal").read_bytes() == b""
        if "realm.sqlite3-shm" in added:
            import struct
            shm = (destination / "realm.sqlite3-shm").read_bytes()
            assert len(shm) == 32768
            # Both native-endian WAL-index headers must describe zero frames;
            # the shared-memory file cannot hide any committed WAL content.
            assert struct.unpack_from("=I", shm, 16)[0] == 0
            assert struct.unpack_from("=I", shm, 64)[0] == 0
        connection = sqlite3.connect(f"file:{destination / 'realm.sqlite3'}?immutable=1", uri=True)
        try:
            assert connection.execute("SELECT slug, name FROM projects WHERE slug='after-adopt'").fetchall() == [
                ("after-adopt", "Legitimate destination evolution")
            ]
        finally:
            connection.close()
    finally:
        store.close()


def test_different_authenticated_backup_at_same_path_cannot_resume(tmp_path, monkeypatch):
    from runtime_protocol.backup import create_backup, verify_backup
    store, backup, paths, config = _live_backup(tmp_path)
    try:
        _adopt_from(backup, paths, config, monkeypatch)
        destination_before = _fingerprints(paths.realms_dir / "film")
        backup.rename(backup.with_name("original-backup"))
        store.create_project("new-source-state", "A different valid backup")
        create_backup(store, backup, key_path=tmp_path / "backup-auth.key")
        assert verify_backup(backup)["doctor"]["ok"]
        with pytest.raises(WorkspaceAdoptError, match="backup identity differs"):
            _adopt_from(backup, paths, config, monkeypatch)
        assert _fingerprints(paths.realms_dir / "film") == destination_before
    finally:
        store.close()


@pytest.mark.parametrize("clone_capable", [False, True])
def test_space_budget_preserves_floor_and_admits_migration_scratch_before_copy(tmp_path, monkeypatch, clone_capable):
    from collections import namedtuple
    from astrid_runtime import workspace_adopt
    root, paths, config = _setup(tmp_path)
    monkeypatch.setattr(workspace_adopt, "clone_file", lambda *_: clone_capable)
    # Above the free floor but below fallback + migration scratch admission.
    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(workspace_adopt.shutil, "disk_usage", lambda *_: usage(10**10, 0, 4 * 1024**3 + 1024))
    monkeypatch.setattr(workspace_adopt, "_materialize", lambda *a: pytest.fail("space admission must precede copying"))
    with pytest.raises(WorkspaceAdoptError, match="migration.*4 GiB floor"):
        _adopt(root, paths, config, monkeypatch)
    assert not (paths.realms_dir / "film").exists()


def test_final_private_integrity_failure_prevents_publication_and_attachment(tmp_path, monkeypatch):
    from astrid_runtime import workspace_adopt
    store, backup, paths, config = _live_backup(tmp_path)
    original = workspace_adopt.migrate_canonical_to_current

    def corrupt_private_candidate(root, **kwargs):
        result = original(root, **kwargs)
        # Current-schema migration is a no-op. An extra authenticated-looking
        # schema marker cannot stand in for final relational/foreign-key checks.
        connection = sqlite3.connect(root / "realm.sqlite3")
        try:
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute("INSERT INTO project_objects(project_id, digest, relation, created_at) VALUES ('missing', 'missing', 'managed', 'now')")
            connection.commit()
        finally:
            connection.close()
        return result

    monkeypatch.setattr(workspace_adopt, "migrate_canonical_to_current", corrupt_private_candidate)
    monkeypatch.setattr(workspace_adopt, "configure_workspace", lambda *a, **k: pytest.fail("unhealthy candidate must not attach"))
    try:
        with pytest.raises(WorkspaceAdoptError, match="final integrity checks"):
            _adopt_from(backup, paths, config, monkeypatch)
    finally:
        store.close()
    assert not (paths.realms_dir / "film").exists()
    assert not list(paths.realms_dir.glob(".film.adopt-*"))
