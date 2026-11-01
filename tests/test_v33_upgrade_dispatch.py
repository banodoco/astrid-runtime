"""Focused empty-realm DDL dispatch and side-effect refusal checks."""
import sqlite3

import pytest

from runtime_protocol.errors import ValidationError
from runtime_protocol.store import SCHEMA_VERSION
from runtime_protocol.upgrade import inspect_realm_schema, migrate_canonical_to_current, upgrade_realm
from runtime_protocol.v33_manifest import canonical_manifest
from test_v33_manifest import database, legacy_database


def write_realm(root, connection):
    root.mkdir()
    target = sqlite3.connect(root / "realm.sqlite3")
    connection.commit()
    connection.backup(target)
    target.close()
    connection.close()


@pytest.mark.parametrize("family", ["C24", "C24-nullable", "C25", "C25-nullable", "C26", "C26-nullable", "C27", "C27-nullable", "C28", "C29", "C30", "C31", "H31", "M32", "TL32", "U33"])
def test_empty_canonical_dispatch(tmp_path, family):
    root = tmp_path / "realm"
    write_realm(root, database(family))
    assert inspect_realm_schema(root)["kind"] == family
    result = migrate_canonical_to_current(root, confirmation="MIGRATE CANONICAL r")
    assert result["target_schema_version"] == SCHEMA_VERSION == 33
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        assert canonical_manifest(connection)["kind"] == "U33"
    assert result["changed"] == (family != "U33")


@pytest.mark.parametrize("mutation", ["DROP INDEX idx_generations_gen", "CREATE INDEX unexpected ON generations(id)", "DROP TABLE timeline_document_input_links"])
def test_refusal_precedes_source_or_lock_writes(tmp_path, mutation):
    root = tmp_path / "realm"
    connection = database("U33")
    connection.execute(mutation)
    write_realm(root, connection)
    before = (root / "realm.sqlite3").read_bytes()
    with pytest.raises(ValidationError):
        migrate_canonical_to_current(root, confirmation="MIGRATE CANONICAL r")
    assert (root / "realm.sqlite3").read_bytes() == before
    assert sorted(p.name for p in root.iterdir()) == ["realm.sqlite3"]


@pytest.mark.parametrize("nullable", [False, True])
def test_empty_legacy_rebuild(tmp_path, nullable):
    root = tmp_path / "realm"
    source = legacy_database(nullable)
    source.execute("INSERT INTO realm_lifecycle(realm_id, state, version) VALUES ('r', 'active', 1)")
    write_realm(root, source)
    result = upgrade_realm(root, confirmation="UPGRADE r", retain_backup=True, archive_root=tmp_path / "backups")
    assert result["target_schema_version"] == 33
    assert inspect_realm_schema(root)["kind"] == "U33"


@pytest.mark.parametrize("nullable", [False, True])
def test_legacy_retired_workers_are_retained_in_archive(tmp_path, nullable):
    root = tmp_path / "realm"
    source = legacy_database(nullable)
    source.execute("INSERT INTO realm_lifecycle(realm_id, state, version) VALUES ('r', 'active', 1)")
    source.execute("""CREATE TABLE workers (
        id TEXT PRIMARY KEY, capabilities_json TEXT NOT NULL, max_concurrency INTEGER NOT NULL,
        resource_keys_json TEXT NOT NULL, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
        readiness TEXT NOT NULL DEFAULT 'ready', readiness_reason TEXT,
        runtime_epoch INTEGER NOT NULL DEFAULT 1
    )""")
    source.execute("INSERT INTO workers(id, capabilities_json, max_concurrency, resource_keys_json, created_at, last_seen_at) VALUES ('w', '[]', 1, '[]', 't', 't')")
    write_realm(root, source)
    before = (root / "realm.sqlite3").read_bytes()
    result = upgrade_realm(root, confirmation="UPGRADE r", retain_backup=True, archive_root=tmp_path / "backups")
    from pathlib import Path
    archived = Path(result["archive"]) / "realm.sqlite3"
    assert archived.read_bytes() == before
    with sqlite3.connect(archived) as connection:
        assert connection.execute("SELECT id FROM workers").fetchone()[0] == "w"


def test_legacy_locked_reclassification_precedes_archive(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from runtime_protocol import upgrade
    root = tmp_path / "realm"
    write_realm(root, legacy_database())
    @contextmanager
    def change_before_lock(path):
        with sqlite3.connect(path / "realm.sqlite3") as connection:
            connection.execute("CREATE INDEX injected ON generations(id)")
        yield
    monkeypatch.setattr(upgrade, "_owner_fence", change_before_lock)
    with pytest.raises(ValidationError, match="unsupported legacy"):
        upgrade_realm(root, confirmation="UPGRADE r", retain_backup=True, archive_root=tmp_path / "backups")
    assert not (tmp_path / "backups").exists()


def test_owner_fence_holds_admission_custody_for_operation(tmp_path):
    from runtime_protocol.store import realm_admission_fence
    from runtime_protocol.upgrade import _owner_fence
    root = tmp_path / "realm"
    write_realm(root, database("C31"))
    with _owner_fence(root):
        with pytest.raises((BlockingIOError, OSError)):
            with realm_admission_fence(root, blocking=False):
                pass


def test_unknown_workers_refused_before_lock(tmp_path):
    root = tmp_path / "realm"
    connection = legacy_database()
    connection.execute("CREATE TABLE workers (id TEXT PRIMARY KEY)")
    write_realm(root, connection)
    with pytest.raises(ValidationError, match="workers.*preserve"):
        upgrade_realm(root, confirmation="UPGRADE r", retain_backup=True, archive_root=tmp_path / "backups")
    assert sorted(p.name for p in root.iterdir()) == ["realm.sqlite3"]


def test_orphan_generation_refuses_before_migration(tmp_path):
    root = tmp_path / "realm"
    connection = database("C31")
    connection.execute("INSERT INTO generations(id, project_id, type, status, metadata_json, version, created_at, updated_at) VALUES ('g', 'p', 'generation', 'succeeded', '{}', 1, 't', 't')")
    write_realm(root, connection)
    from runtime_protocol.errors import ConflictError
    before = (root / "realm.sqlite3").read_bytes()
    with pytest.raises(ConflictError, match="integrity checks"):
        migrate_canonical_to_current(root, confirmation="MIGRATE CANONICAL r")
    assert (root / "realm.sqlite3").read_bytes() == before
    assert not (root / ".v33-activation.json").exists()


def test_locked_reclassification_refuses_schema_change(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from runtime_protocol import upgrade
    root = tmp_path / "realm"
    write_realm(root, database("C31"))
    @contextmanager
    def change_before_lock(path):
        with sqlite3.connect(path / "realm.sqlite3") as connection:
            connection.execute("CREATE INDEX injected ON generations(id)")
        yield
    monkeypatch.setattr(upgrade, "_owner_fence", change_before_lock)
    with pytest.raises(ValidationError, match="unsupported canonical"):
        migrate_canonical_to_current(root, confirmation="MIGRATE CANONICAL r")
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        assert connection.execute("SELECT version FROM runtime_schema").fetchone()[0] == 31


@pytest.mark.parametrize("family, migrate, target, confirmation", [
    ("C24", "migrate_canonical_v24_to_v25", "C25", "MIGRATE VARIANT STATE r"),
    ("C25", "migrate_canonical_v25_to_v26", "C26", "MIGRATE EXECUTION BINDING r"),
])
def test_named_historical_migrations(tmp_path, family, migrate, target, confirmation):
    from runtime_protocol import upgrade
    root = tmp_path / "realm"
    write_realm(root, database(family))
    getattr(upgrade, migrate)(root, confirmation=confirmation)
    assert inspect_realm_schema(root)["kind"] == target


def test_canonical_chain_rolls_back_interrupted_ddl(tmp_path, monkeypatch):
    from runtime_protocol import upgrade
    root = tmp_path / "realm"
    write_realm(root, database("C24"))
    def interrupt(connection):
        connection.execute("CREATE TABLE interrupted (id INTEGER)")
        raise RuntimeError("interrupted migration")
    monkeypatch.setattr(upgrade, "_apply_v25_to_v26", interrupt)
    with pytest.raises(RuntimeError, match="interrupted migration"):
        migrate_canonical_to_current(root, confirmation="MIGRATE CANONICAL r")
    assert inspect_realm_schema(root)["kind"] == "C24"


def test_preflight_reads_live_wal_without_modifying_source(tmp_path):
    root = tmp_path / "realm"
    write_realm(root, database("C31"))
    connection = sqlite3.connect(root / "realm.sqlite3")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("CREATE INDEX injected ON generations(id)")
    connection.commit()
    paths = sorted(root.iterdir())
    before = {path.name: path.read_bytes() for path in paths}
    with pytest.raises(ValidationError, match="unsupported canonical"):
        inspect_realm_schema(root)
    assert {path.name: path.read_bytes() for path in root.iterdir()} == before
    connection.close()


def test_shape_derivation_selects_both_ambiguous_families():
    from runtime_protocol.upgrade import _canonical_shape_for
    with pytest.raises(ValidationError, match="requires the classified"):
        _canonical_shape_for(32)
    m_tables, m_columns = _canonical_shape_for(32, family="M32")
    tl_tables, tl_columns = _canonical_shape_for(32, family="TL32")
    h_tables, h_columns = _canonical_shape_for(31, family="H31")
    assert "user_app_state" in m_tables and "timeline_commit_history" not in m_tables
    assert "timeline_commit_history" in tl_tables and "publication_id" in tl_columns["parent_composition_heads"]
    assert "user_app_state" not in h_tables and "timeline_commit_history" in h_tables
    assert "publication_id" not in m_columns["parent_composition_heads"]


def test_empty_legacy_additive_tables_use_existing_rebuild(tmp_path):
    root = tmp_path / "realm"
    source = legacy_database(components=("user_app_state",))
    source.execute("INSERT INTO realm_lifecycle(realm_id, state, version) VALUES ('r', 'active', 1)")
    write_realm(root, source)
    result = upgrade_realm(root, confirmation="UPGRADE r", retain_backup=True, archive_root=tmp_path / "backups")
    assert result["target_schema_version"] == 33


def test_populated_legacy_additive_table_is_preserved(tmp_path):
    root = tmp_path / "realm"
    source = legacy_database(components=("user_app_state",))
    source.execute("INSERT INTO realm_lifecycle(realm_id,state,version) VALUES ('r','active',1)")
    source.execute("INSERT INTO user_app_state VALUES ('a', 'k', '{}', 1, 't', 't')")
    write_realm(root, source)
    upgrade_realm(root, confirmation="UPGRADE r", retain_backup=True, archive_root=tmp_path / "backups")
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        assert connection.execute("SELECT actor_id,key,content_json FROM user_app_state").fetchone() == ("a","k","{}")


def test_legacy_task_specs_preserved_by_rebuild(tmp_path):
    import hashlib
    root = tmp_path / "realm"
    source = legacy_database(components=("task_specs",))
    source.execute("INSERT INTO realm_lifecycle(realm_id,state,version) VALUES ('r','active',1)")
    body = '{"retained":true}'
    checksum = hashlib.sha256(body.encode()).hexdigest()
    source.execute("INSERT INTO task_specs VALUES (?,?,?)", (checksum, body, 't'))
    write_realm(root, source)
    upgrade_realm(root, confirmation="UPGRADE r", retain_backup=True, archive_root=tmp_path / "backups")
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        assert connection.execute("SELECT digest,body_json FROM task_specs").fetchone() == (checksum,body)
