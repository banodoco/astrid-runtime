from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys

import pytest

from runtime_protocol import platform, upgrade
from runtime_protocol.errors import OwnerBusyError, RealmAdmissionError, ValidationError
from runtime_protocol.store import SCHEMA_VERSION, RealmStore
from runtime_protocol.upgrade import (
    inspect_canonical_schema,
    migrate_canonical_to_current,
    migrate_canonical_v24_to_v25,
    migrate_canonical_v25_to_v26,
    repair_generic_media_types,
    upgrade_realm,
)


def _remove_timeline_commit_schema(connection):
    # C24-C31 predate the complete Timeline v32 bundle.
    for table in ("timeline_document_input_links", "timeline_document_input_bindings",
                  "timeline_document_input_contents", "timeline_commit_history"):
        connection.execute(f"DROP TABLE {table}")
    connection.execute("ALTER TABLE parent_composition_heads DROP COLUMN publication_id")
    connection.execute("ALTER TABLE parent_composition_revisions DROP COLUMN commit_manifest_json")


def _walk_back_to_v27(connection):
    # A fresh realm is the current schema; v31 -> v30 drops user_app_state, v30 -> v29 drops timelines.name
    # (the only v30 change), and v28 -> v27 restores inline specs and drops task_specs.
    connection.execute("PRAGMA foreign_keys=OFF")
    _remove_timeline_commit_schema(connection)
    connection.execute("DROP INDEX IF EXISTS idx_generations_gen")
    connection.execute("DROP TABLE user_app_state")
    connection.execute("ALTER TABLE timelines DROP COLUMN name")
    connection.execute("DROP INDEX IF EXISTS idx_tasks_retention")
    for table in ("runs", "tasks"):
        connection.execute(f"ALTER TABLE {table} ADD COLUMN spec_json TEXT")
        connection.execute(f"ALTER TABLE {table} DROP COLUMN spec_digest")
    connection.execute("DROP TABLE task_specs")
    connection.execute("UPDATE runtime_schema SET version=27 WHERE id=1")
    connection.commit()


def _legacy_realm(root, *, register_indexes=True):
    store = RealmStore.initialize(root)
    realm_id = store.realm["id"]
    timestamp = "2026-09-15T00:00:00Z"
    store.close()
    payload = b"legacy-video"
    digest = hashlib.sha256(payload).hexdigest()
    cas = root / "cas" / "sha256" / digest[:2]
    cas.mkdir(parents=True, exist_ok=True)
    (cas / digest[2:]).write_bytes(payload)
    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        _walk_back_to_v27(connection)
        connection.executescript(
            """
            DROP INDEX idx_managed_output_task;
            DROP INDEX idx_managed_output_manifest;
            DROP TABLE managed_output_lifecycle;
            DROP TABLE managed_output_associations;
            DROP TABLE runtime_schema;
            DROP TABLE user_preferences;
            CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
            CREATE TABLE canonical_receipt_backfills(id INTEGER PRIMARY KEY, detail TEXT);
            CREATE TABLE lost_and_found(id INTEGER PRIMARY KEY, payload BLOB);
            CREATE TABLE migration_event_streams(id TEXT PRIMARY KEY, payload TEXT);
            CREATE TABLE migration_events(id TEXT PRIMARY KEY, payload TEXT);
            CREATE TABLE migration_owner_records(id TEXT PRIMARY KEY, payload TEXT);
            """
        )
        connection.executemany(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            [(version, f"2026-09-15T00:00:{version:02d}Z") for version in range(1, 24)],
        )
        connection.execute("INSERT INTO lost_and_found(id, payload) VALUES (1, ?)", (b"legacy-bytes",))
        connection.execute(
            "INSERT INTO projects(id, realm_id, slug, name, metadata_json, version, created_at, updated_at, idempotency_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("project-1", realm_id, "kept-project", "Kept project", "{}", 1, timestamp, timestamp, None),
        )
        connection.execute(
            "INSERT INTO runs(id, project_id, capability, spec_json, status, idempotency_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("run-1", "project-1", "rendering.render", "{}", "completed", None, timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO tasks(id, run_id, capability, spec_json, status, attempt, lease_fence, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("task-1", "run-1", "test-capability", json.dumps({"inputs": {"output_name": "legacy.mp4"}}), "completed", 1, 1, timestamp, timestamp),
        )
        connection.execute(
            "UPDATE tasks SET attempt_id=?, result_json=? WHERE id=?",
            (
                "attempt-1",
                json.dumps({"outputs": [{"kind": "object", "name": "video", "digest": "sha256:" + digest, "media_type": "clip/visual", "size": len(payload), "ordinal": 0, "role": "result"}]}),
                "task-1",
            ),
        )
        connection.execute(
            "INSERT INTO attempts(id, task_id, lease_id, fence, executor_id, lease_expires_at, settled, runtime_epoch) VALUES (?, ?, ?, 1, ?, ?, 1, 1)",
            ("attempt-1", "task-1", "lease-1", "fixture", timestamp),
        )
        if register_indexes:
            connection.execute(
                "INSERT INTO objects(digest, size, media_type, original_name, created_at) VALUES (?, ?, ?, ?, ?)",
                (digest, len(payload), "clip/visual", "video", timestamp),
            )
            connection.execute(
                "INSERT INTO project_objects(project_id, digest, relation, created_at) VALUES (?, ?, ?, ?)",
                ("project-1", digest, "managed", timestamp),
            )
        connection.execute(
            "INSERT INTO generations(id, project_id, source_task_id, type, status, metadata_json, version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("generation-1", "project-1", "task-1", "generation", "succeeded", "{}", 1, timestamp, timestamp),
        )
        connection.commit()
    finally:
        connection.close()
    return realm_id


@pytest.mark.parametrize("retain_backup", [False, True])
def test_upgrade_preserves_canonical_rows_and_retains_backup_only_when_requested(tmp_path, retain_backup):
    root = tmp_path / "realm"
    realm_id = _legacy_realm(root)

    result = upgrade_realm(root, retain_backup=retain_backup, timeout_seconds=30, confirmation=f"UPGRADE {realm_id}")
    assert result["ok"] is True
    assert result["backup_retained"] is retain_backup
    assert not list(tmp_path.glob(".realm-upgrade-transaction-*"))
    if retain_backup:
        archive = tmp_path / "realm" / "realm-upgrade-backups" / result["archive"].split("/")[-1]
        manifest = json.loads((archive / "manifest.json").read_text())
        assert manifest["source_schema_version"] == 23
        assert manifest["target_schema_version"] == SCHEMA_VERSION
        assert manifest["historical_managed_outputs"]["migrated"] == 1
        assert set(manifest["legacy_tables"]) >= {"schema_migrations", "lost_and_found"}
        assert (archive / "realm.sqlite3").is_file()
        archived = sqlite3.connect(archive / "realm.sqlite3")
        try:
            assert archived.execute("SELECT payload FROM lost_and_found WHERE id=1").fetchone()[0] == b"legacy-bytes"
        finally:
            archived.close()
    else:
        assert result["archive"] is None
        assert not (root / "realm-upgrade-backups").exists()

    reopened = RealmStore(root)
    try:
        row = reopened.conn.execute("SELECT format_id, version FROM runtime_schema WHERE id=1").fetchone()
        assert tuple(row) == ("astrid-runtime-sqlite-v1", SCHEMA_VERSION)
        assert reopened.conn.execute("SELECT id FROM realm").fetchone()[0] == realm_id
        assert reopened.conn.execute("SELECT id FROM generations").fetchone()[0] == "generation-1"
        migrated_output = reopened.list_managed_outputs("task-1")
        assert migrated_output[0]["filename"] == "legacy.mp4"
        tables = {row[0] for row in reopened.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "schema_migrations" not in tables
        assert {"managed_output_associations", "managed_output_lifecycle"}.issubset(tables)
    finally:
        reopened.close()


def test_canonical_v24_variant_state_migration_is_additive_and_refuses_repeat(tmp_path):
    root = tmp_path / "realm"
    store = RealmStore.initialize(root, realm_id="realm-v24")
    project = store.create_project("v24", "V24", idempotency_key="project-v24")
    timestamp = "2026-09-22T00:00:00Z"
    store.conn.execute(
        "INSERT INTO generations(id, project_id, source_task_id, type, status, metadata_json, version, created_at, updated_at) VALUES (?, ?, NULL, ?, ?, ?, 1, ?, ?)",
        ("generation-v24", project["id"], "video", "succeeded", "{}", timestamp, timestamp),
    )
    store.conn.execute(
        "INSERT INTO generation_variants(id, generation_id, object_id, variant_type, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("variant-v24", "generation-v24", None, "original", "{}", timestamp),
    )
    store.conn.commit()
    store.close()

    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        _walk_back_to_v27(connection)
        connection.execute("PRAGMA foreign_keys=OFF")
        for column in ("thumbnail_object_id", "thumbnail_source_object_id", "thumbnail_recipe_version", "viewed_at"):
            connection.execute(f"ALTER TABLE generation_variants DROP COLUMN {column}")
        connection.execute("ALTER TABLE tasks DROP COLUMN execution_request_json")
        connection.execute("DROP TABLE execution_bindings")
        connection.execute("DROP TABLE user_preferences")
        connection.execute("UPDATE runtime_schema SET version=24 WHERE id=1")
        connection.commit()
    finally:
        connection.close()

    assert inspect_canonical_schema(root, expected_realm_id="realm-v24")["kind"] == "C24-nullable"
    result = migrate_canonical_v24_to_v25(
        root,
        confirmation="MIGRATE VARIANT STATE realm-v24",
    )
    assert result["target_schema_version"] == 25
    reopened = sqlite3.connect(root / "realm.sqlite3")
    try:
        assert reopened.execute("SELECT version FROM runtime_schema WHERE id=1").fetchone()[0] == 25
        columns = {row[1] for row in reopened.execute("PRAGMA table_info(generation_variants)")}
        assert {"thumbnail_object_id", "thumbnail_source_object_id", "thumbnail_recipe_version", "viewed_at"} <= columns
        foreign_keys = {row[3] for row in reopened.execute("PRAGMA foreign_key_list(generation_variants)")}
        assert {"thumbnail_object_id", "thumbnail_source_object_id"} <= foreign_keys
        assert reopened.execute("SELECT viewed_at FROM generation_variants WHERE id='variant-v24'").fetchone()[0] is None
    finally:
        reopened.close()

    with pytest.raises(ValidationError, match="canonical schema v24"):
        migrate_canonical_v24_to_v25(root, confirmation="MIGRATE VARIANT STATE realm-v24")


def test_upgrade_refuses_unknown_shape_without_touching_source(tmp_path):
    root = tmp_path / "realm"
    realm_id = _legacy_realm(root)
    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        connection.execute("CREATE TABLE unexpected_data(id INTEGER PRIMARY KEY, payload BLOB)")
        connection.execute("INSERT INTO unexpected_data(payload) VALUES (?)", (b"must-preserve",))
        connection.commit()
    finally:
        connection.close()
    before = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ("realm.sqlite3", "realm.sqlite3-wal", "realm.sqlite3-shm", "realm.sqlite3-journal")
        if (root / name).exists()
    }

    with pytest.raises(ValidationError, match="unsupported legacy v23 manifest"):
        upgrade_realm(root, timeout_seconds=30, confirmation=f"UPGRADE {realm_id}",
                      retain_backup=True, archive_root=tmp_path / "backups")
    after = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ("realm.sqlite3", "realm.sqlite3-wal", "realm.sqlite3-shm", "realm.sqlite3-journal")
        if (root / name).exists()
    }
    assert after == before


def test_execution_binding_migration_adds_only_the_targeted_contract(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        _walk_back_to_v27(connection)
        connection.execute("ALTER TABLE tasks DROP COLUMN execution_request_json")
        connection.execute("DROP TABLE execution_bindings")
        connection.execute("DROP TABLE user_preferences")
        connection.execute("UPDATE runtime_schema SET version=25 WHERE id=1")
        realm_id = connection.execute("SELECT id FROM realm LIMIT 1").fetchone()[0]
        connection.commit()
    finally:
        connection.close()

    assert inspect_canonical_schema(root, expected_realm_id=realm_id)["kind"] == "C25-nullable"
    result = migrate_canonical_v25_to_v26(
        root,
        confirmation=f"MIGRATE EXECUTION BINDING {realm_id}",
    )
    assert result["target_schema_version"] == 26
    reopened = sqlite3.connect(root / "realm.sqlite3")
    try:
        assert reopened.execute("SELECT version FROM runtime_schema WHERE id=1").fetchone()[0] == 26
        task_columns = {row[1] for row in reopened.execute("PRAGMA table_info(tasks)")}
        binding_columns = {row[1] for row in reopened.execute("PRAGMA table_info(execution_bindings)")}
        assert "execution_request_json" in task_columns
        assert {"binding_id", "session_id", "profile_digest", "storage_json", "resolved_target_json"} <= binding_columns
    finally:
        reopened.close()


def _canonical_fixture(root, version):
    store = RealmStore.initialize(root, realm_id=f"realm-v{version}")
    project = store.create_project("kept", "Kept project", idempotency_key="fixture-project")
    timestamp = "2026-10-02T00:00:00Z"
    store.conn.execute(
        "INSERT INTO project_documents(id, project_id, kind, content_json, version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("kept-doc", project["id"], "markdown", json.dumps("# Kept\n\nDocument"), 3, timestamp, timestamp),
    )
    store.conn.commit()
    store.close()
    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        if version < 32:
            connection.execute("DROP INDEX IF EXISTS idx_generations_gen")
        if version < 28:
            _walk_back_to_v27(connection)  # also drops user_app_state and timelines.name
        else:
            if version < 32:
                _remove_timeline_commit_schema(connection)
            if version < 31:
                connection.execute("DROP TABLE user_app_state")
            if version < 30:
                connection.execute("ALTER TABLE timelines DROP COLUMN name")
        if version < 27:
            connection.execute("DROP TABLE user_preferences")
        if version <= 25:
            connection.execute("ALTER TABLE tasks DROP COLUMN execution_request_json")
            connection.execute("DROP TABLE execution_bindings")
        if version == 24:
            for column in ("thumbnail_object_id", "thumbnail_source_object_id", "thumbnail_recipe_version", "viewed_at"):
                connection.execute(f"ALTER TABLE generation_variants DROP COLUMN {column}")
        connection.execute("UPDATE runtime_schema SET version=? WHERE id=1", (version,))
        connection.commit()
    finally:
        connection.close()
    family = "U33" if version == 33 else f"C{version}" + ("-nullable" if version < 28 else "")
    assert inspect_canonical_schema(root, expected_realm_id=f"realm-v{version}")["kind"] == family
    return f"realm-v{version}"


@pytest.mark.parametrize("source_version, expected_steps", [(24, 9), (25, 8), (26, 7), (29, 4), (30, 3), (31, 2)])
def test_complete_canonical_migration_chain_reaches_current_schema(tmp_path, source_version, expected_steps):
    root = tmp_path / f"realm-{source_version}"
    realm_id = _canonical_fixture(root, source_version)
    assert inspect_canonical_schema(root)["kind"] == f"C{source_version}" + ("-nullable" if source_version < 28 else "")
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        projects_before = connection.execute("SELECT * FROM projects ORDER BY id").fetchall()
        documents_before = connection.execute("SELECT * FROM project_documents ORDER BY id").fetchall()
    result = migrate_canonical_to_current(
        root,
        confirmation=f"MIGRATE CANONICAL {realm_id}",
        expected_realm_id=realm_id,
    )
    assert result["source_schema_version"] == source_version
    assert result["target_schema_version"] == SCHEMA_VERSION
    assert len(result["steps"]) == expected_steps
    assert inspect_canonical_schema(root, expected_realm_id=realm_id)["version"] == SCHEMA_VERSION

    with sqlite3.connect(root / "realm.sqlite3") as connection:
        assert connection.execute("SELECT * FROM projects ORDER BY id").fetchall() == projects_before
        assert connection.execute("SELECT * FROM project_documents ORDER BY id").fetchall() == documents_before
        assert connection.execute("SELECT COUNT(*) FROM user_preferences").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM user_app_state").fetchone()[0] == 0
    reopened = RealmStore(root)
    try:
        assert reopened.integrity_report()["ok"] is True
    finally:
        reopened.close()


def test_current_canonical_migration_is_read_only_idempotent(tmp_path):
    root = tmp_path / "realm-current"
    realm_id = _canonical_fixture(root, SCHEMA_VERSION)
    database = root / "realm.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO user_preferences VALUES (?, ?, ?, ?, ?, ?)",
            ("actor-a", "preferences-a", "# Saved preferences", 4, "created", "updated"),
        )
    before = database.read_bytes()
    first = migrate_canonical_to_current(
        root,
        confirmation=f"MIGRATE CANONICAL {realm_id}",
        expected_realm_id=realm_id,
    )
    second = migrate_canonical_to_current(
        root,
        confirmation=f"MIGRATE CANONICAL {realm_id}",
        expected_realm_id=realm_id,
    )
    assert first["changed"] is False
    assert second["changed"] is False
    assert database.read_bytes() == before
    assert not (root / ".runtime-owner.lock").exists()


@pytest.mark.parametrize("mutation, message", [("newer", "unsupported canonical v34 manifest"), ("alternate", "unsupported canonical v33 manifest")])
def test_unknown_canonical_layout_is_rejected_without_mutation(tmp_path, mutation, message):
    root = tmp_path / mutation
    realm_id = _canonical_fixture(root, SCHEMA_VERSION)
    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        if mutation == "newer":
            connection.execute("UPDATE runtime_schema SET version=? WHERE id=1", (SCHEMA_VERSION + 1,))
        else:
            connection.execute("ALTER TABLE tasks ADD COLUMN distributed_binding_json TEXT")
        connection.commit()
    finally:
        connection.close()
    database = root / "realm.sqlite3"
    before = database.read_bytes()
    with pytest.raises(ValidationError, match=message):
        migrate_canonical_to_current(
            root,
            confirmation=f"MIGRATE CANONICAL {realm_id}",
            expected_realm_id=realm_id,
        )
    assert database.read_bytes() == before
    assert not (root / ".runtime-owner.lock").exists()


@pytest.mark.parametrize("source_version", [24, 25, 26])
def test_historical_canonical_version_rejects_preferences_table(tmp_path, source_version):
    root = tmp_path / "wrong-historical-shape"
    realm_id = _canonical_fixture(root, source_version)
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        connection.execute("CREATE TABLE user_preferences(actor_id TEXT PRIMARY KEY, content TEXT)")
    before = (root / "realm.sqlite3").read_bytes()
    with pytest.raises(ValidationError, match=f"unsupported canonical v{source_version} manifest"):
        migrate_canonical_to_current(root, confirmation=f"MIGRATE CANONICAL {realm_id}")
    assert (root / "realm.sqlite3").read_bytes() == before


def test_canonical_identity_fence_precedes_mutation(tmp_path):
    root = tmp_path / "identity"
    realm_id = _canonical_fixture(root, 25)
    database = root / "realm.sqlite3"
    before = database.read_bytes()
    with pytest.raises(ValidationError, match="identity mismatch"):
        migrate_canonical_to_current(
            root,
            confirmation=f"MIGRATE CANONICAL {realm_id}",
            expected_realm_id="different-realm",
        )
    assert database.read_bytes() == before


def test_complete_chain_rolls_back_if_second_step_is_interrupted(tmp_path, monkeypatch):
    import runtime_protocol.upgrade as upgrade_module

    root = tmp_path / "interrupted"
    realm_id = _canonical_fixture(root, 24)
    original = upgrade_module._apply_v25_to_v26

    def interrupted(connection):
        original(connection)
        raise RuntimeError("injected interruption")

    monkeypatch.setattr(upgrade_module, "_apply_v25_to_v26", interrupted)
    with pytest.raises(RuntimeError, match="injected interruption"):
        migrate_canonical_to_current(
            root,
            confirmation=f"MIGRATE CANONICAL {realm_id}",
            expected_realm_id=realm_id,
        )
    assert inspect_canonical_schema(root, expected_realm_id=realm_id)["version"] == 24


@pytest.mark.parametrize("source_version", [24, 25, 26])
def test_preferences_migration_rolls_back_entire_chain_on_interruption(tmp_path, monkeypatch, source_version):
    import runtime_protocol.upgrade as upgrade_module

    root = tmp_path / "interrupted-preferences"
    realm_id = _canonical_fixture(root, source_version)
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        documents_before = connection.execute("SELECT * FROM project_documents ORDER BY id").fetchall()
    original = upgrade_module._apply_v26_to_v27

    def interrupted(connection):
        original(connection)
        raise RuntimeError("injected preferences interruption")

    monkeypatch.setattr(upgrade_module, "_apply_v26_to_v27", interrupted)
    with pytest.raises(RuntimeError, match="injected preferences interruption"):
        migrate_canonical_to_current(root, confirmation=f"MIGRATE CANONICAL {realm_id}")
    assert inspect_canonical_schema(root)["version"] == source_version
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        assert connection.execute("SELECT * FROM project_documents ORDER BY id").fetchall() == documents_before
        assert not connection.execute("SELECT name FROM sqlite_master WHERE name='user_preferences'").fetchall()


def test_preferences_table_actor_key_and_stable_id_constraints(tmp_path):
    root = tmp_path / "preferences-constraints"
    store = RealmStore.initialize(root)
    try:
        row = ("actor-a", "preferences-a", "# Preferences", 1, "created", "updated")
        store.conn.execute("INSERT INTO user_preferences VALUES (?, ?, ?, ?, ?, ?)", row)
        store.conn.commit()
        assert store.conn.execute("SELECT content FROM user_preferences WHERE actor_id=?", ("actor-a",)).fetchone()[0] == "# Preferences"
        for conflicting in (
            ("actor-a", "preferences-b", "other", 1, "created", "updated"),
            ("actor-b", "preferences-a", "other", 1, "created", "updated"),
            (None, "preferences-b", "other", 1, "created", "updated"),
            ("actor-b", "preferences-b", "other", 0, "created", "updated"),
        ):
            with pytest.raises(sqlite3.IntegrityError):
                store.conn.execute("INSERT INTO user_preferences VALUES (?, ?, ?, ?, ?, ?)", conflicting)
            store.conn.rollback()
    finally:
        store.close()


def test_current_inspection_and_noop_reject_symlink_alias_without_mutation(tmp_path):
    root = tmp_path / "canonical"
    realm_id = _canonical_fixture(root, SCHEMA_VERSION)
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    before = (root / "realm.sqlite3").read_bytes()
    owner_before = (root / "owner.lock").read_bytes() if (root / "owner.lock").exists() else None
    with pytest.raises(RealmAdmissionError, match="symlink"):
        inspect_canonical_schema(alias, expected_realm_id=realm_id)
    with pytest.raises(RealmAdmissionError, match="symlink"):
        migrate_canonical_to_current(
            alias,
            confirmation=f"MIGRATE CANONICAL {realm_id}",
            expected_realm_id=realm_id,
        )
    assert (root / "realm.sqlite3").read_bytes() == before
    owner_after = (root / "owner.lock").read_bytes() if (root / "owner.lock").exists() else None
    assert owner_after == owner_before


def test_upgrade_repairs_missing_historical_object_indexes(tmp_path):
    root = tmp_path / "realm"
    realm_id = _legacy_realm(root, register_indexes=False)
    result = upgrade_realm(root, timeout_seconds=30, confirmation=f"UPGRADE {realm_id}")
    assert result["historical_managed_outputs"]["migrated"] == 1
    reopened = RealmStore(root)
    try:
        digest = reopened.conn.execute("SELECT object_digest FROM managed_output_associations").fetchone()[0]
        assert reopened.conn.execute("SELECT size FROM objects WHERE digest=?", (digest,)).fetchone()[0] == len(b"legacy-video")
        assert reopened.conn.execute(
            "SELECT relation FROM project_objects WHERE project_id='project-1' AND digest=?", (digest,)
        ).fetchone()[0] == "managed"
    finally:
        reopened.close()


def test_repair_generic_media_types_updates_object_association_and_variant(tmp_path):
    root = tmp_path / "realm"
    store = RealmStore.initialize(root, realm_id="realm-repair")
    store.close()
    timestamp = "2026-09-22T00:00:00Z"
    payload = b"not-a-real-video-but-a-digest-checked-fixture"
    digest = hashlib.sha256(payload).hexdigest()
    cas = root / "cas" / "sha256" / digest[:2]
    cas.mkdir(parents=True, exist_ok=True)
    (cas / digest[2:]).write_bytes(payload)

    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        # Schema v28+ stores specs once in task_specs; runs and tasks reference them by digest.
        empty_spec = hashlib.sha256(b"{}").hexdigest()
        connection.execute(
            "INSERT INTO task_specs(digest, body_json, created_at) VALUES (?, '{}', ?)",
            (empty_spec, timestamp),
        )
        connection.execute(
            "INSERT INTO projects(id, realm_id, slug, name, metadata_json, version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("project-repair", "realm-repair", "repair", "Repair", "{}", 1, timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO runs(id, project_id, capability, spec_digest, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("run-repair", "project-repair", "vibecomfy.run", empty_spec, "completed", timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO tasks(id, run_id, capability, spec_digest, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("task-repair", "run-repair", "vibecomfy.run", empty_spec, "completed", timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO attempts(id, task_id, lease_id, fence, executor_id, lease_expires_at, settled, runtime_epoch) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("attempt-repair", "task-repair", "lease-repair", 1, "fixture", timestamp, 1, 1),
        )
        connection.execute(
            "INSERT INTO objects(digest, size, media_type, original_name, created_at) VALUES (?, ?, ?, ?, ?)",
            (digest, len(payload), "application/octet-stream", "vibecomfy_run", timestamp),
        )
        connection.execute(
            "INSERT INTO project_objects(project_id, digest, relation, created_at) VALUES (?, ?, ?, ?)",
            ("project-repair", digest, "managed", timestamp),
        )
        connection.execute(
            "INSERT INTO generations(id, project_id, source_task_id, type, status, metadata_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("generation-repair", "project-repair", "task-repair", "vibecomfy.run", "completed", "{}", timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO generation_variants(id, generation_id, object_id, variant_type, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                "variant-repair",
                "generation-repair",
                digest,
                "original",
                json.dumps({"filename": "render.mp4", "media_type": "application/octet-stream"}),
                timestamp,
            ),
        )
        connection.execute(
            "INSERT INTO managed_output_associations(association_id, task_id, attempt_id, project_id, output_port, group_key, generation_id, variant_key, object_digest, size, filename, media_type, ordinal, role, producer_json, provenance_json, durability, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "association-repair", "task-repair", "attempt-repair", "project-repair",
                "vibecomfy_run", "main", "generation-repair", "original", digest,
                len(payload), "render.mp4", "application/octet-stream", 0, "result", "{}", "{}", "durable", timestamp,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    result = repair_generic_media_types(
        root,
        task_id="task-repair",
        confirmation="REPAIR GENERIC MEDIA TYPES realm-repair",
    )
    assert result["repaired"] == {"objects": 1, "associations": 1, "variants": 1}
    assert result["skipped_count"] == 0

    reopened = sqlite3.connect(root / "realm.sqlite3")
    try:
        assert reopened.execute("SELECT media_type FROM objects WHERE digest=?", (digest,)).fetchone()[0] == "video/mp4"
        assert reopened.execute("SELECT media_type FROM managed_output_associations WHERE association_id='association-repair'").fetchone()[0] == "video/mp4"
        metadata = json.loads(reopened.execute("SELECT metadata_json FROM generation_variants WHERE id='variant-repair'").fetchone()[0])
        assert metadata["media_type"] == "video/mp4"
    finally:
        reopened.close()


def test_upgrade_is_not_repeatable_and_refuses_live_owner(tmp_path):
    root = tmp_path / "realm"
    realm_id = _legacy_realm(root)
    upgrade_realm(root, timeout_seconds=30, confirmation=f"UPGRADE {realm_id}")
    active_names = ("realm.sqlite3", "realm.sqlite3-wal", "realm.sqlite3-shm", "realm.sqlite3-journal")
    after = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in active_names
        if (root / name).exists()
    }
    with pytest.raises(ValidationError, match="schema_migrations"):
        upgrade_realm(root, timeout_seconds=30, confirmation=f"UPGRADE {realm_id}")
    assert {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in active_names
        if (root / name).exists()
    } == after

    lock = (root / "owner.lock").open("a+")
    try:
        from runtime_protocol import platform as runtime_platform
        runtime_platform.lock_file(lock.fileno(), exclusive=True, blocking=False)
        with pytest.raises(OwnerBusyError):
            upgrade_realm(root, timeout_seconds=30, confirmation=f"UPGRADE {realm_id}")
    finally:
        runtime_platform.unlock_file(lock.fileno())
        lock.close()


def test_upgrade_archives_wal_before_activation(tmp_path):
    root = tmp_path / "realm"
    realm_id = _legacy_realm(root)
    # Simulate an interrupted owner: a normal final connection.close() may
    # checkpoint and delete the WAL, depending on the SQLite build.
    subprocess.run(
        [sys.executable, "-c", """
import os, sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
connection.execute("PRAGMA journal_mode=WAL")
connection.execute("PRAGMA wal_autocheckpoint=0")
connection.execute("UPDATE realm SET display_name=?", ("WAL realm",))
connection.commit()
os._exit(0)
""", str(root / "realm.sqlite3")],
        check=True,
    )
    assert (root / "realm.sqlite3-wal").is_file()
    original_components = {
        path.name: path.read_bytes() for path in root.glob("realm.sqlite3*") if path.is_file()
    }

    result = upgrade_realm(root, retain_backup=True, timeout_seconds=30, confirmation=f"UPGRADE {realm_id}")
    archive = root / "realm-upgrade-backups" / result["archive"].split("/")[-1]
    manifest = json.loads((archive / "manifest.json").read_text())
    assert "realm.sqlite3-wal" in manifest["components"]
    assert (archive / "realm.sqlite3-wal").is_file()
    for name, payload in original_components.items():
        assert (archive / name).read_bytes() == payload
        assert manifest["components"][name]["sha256"] == hashlib.sha256(payload).hexdigest()
    assert not any((root / f"realm.sqlite3{suffix}").exists() for suffix in ("-wal", "-shm", "-journal"))
    reopened = RealmStore(root)
    try:
        assert reopened.realm["display_name"] == "WAL realm"
    finally:
        reopened.close()


@pytest.mark.parametrize("failure_phase", ["checkpoint", "publication_flush"])
@pytest.mark.parametrize("rollback_failure", [None, "before_publication", "after_publication"])
def test_upgrade_restores_after_publication_and_preserves_uncertain_rollback(
    tmp_path, monkeypatch, failure_phase, rollback_failure,
):
    root = tmp_path / "realm"
    realm_id = _legacy_realm(root)
    source_db = root / "realm.sqlite3"
    original = source_db.read_bytes()
    real_replace = platform.replace_path
    real_flush = platform.flush_replace
    failed_forward = []
    failed_rollback = []

    def rollback_source(source):
        return Path(source).name.startswith(".realm.sqlite3.rollback-")

    def publish(source, destination):
        if rollback_failure == "before_publication" and rollback_source(source):
            failed_rollback.append("before")
            raise OSError("injected rollback rename failure")
        return real_replace(source, destination)

    def flush(source, destination):
        source, destination = Path(source), Path(destination)
        if (failure_phase == "publication_flush" and source.name == "realm.sqlite3"
                and source.parent.name.startswith(".realm-upgrade-") and destination == source_db):
            assert not source.exists()
            activated = sqlite3.connect(source_db)
            try:
                assert activated.execute("SELECT version FROM runtime_schema").fetchone()[0] == SCHEMA_VERSION
            finally:
                activated.close()
            failed_forward.append("after rename")
            raise OSError("injected activation flush failure")
        if rollback_failure == "after_publication" and rollback_source(source):
            assert not source.exists()
            assert source_db.read_bytes() == original
            failed_rollback.append("after")
            raise OSError("injected rollback flush failure")
        return real_flush(source, destination)

    def fail_checkpoint(source):
        source.write_bytes(b"partially checkpointed")
        failed_forward.append("checkpoint")
        raise OSError("injected checkpoint failure")

    monkeypatch.setattr(platform, "replace_path", publish)
    monkeypatch.setattr(platform, "flush_replace", flush)
    if failure_phase == "checkpoint":
        monkeypatch.setattr(upgrade, "_checkpoint_source_wal", fail_checkpoint)

    error_type = OSError if rollback_failure is None else RuntimeError
    message = "injected" if rollback_failure is None else "rollback failed; recovery snapshot preserved at"
    with pytest.raises(error_type, match=message) as error:
        upgrade_realm(root, timeout_seconds=30, confirmation=f"UPGRADE {realm_id}")

    assert len(failed_forward) == 1
    assert bool(failed_rollback) == (rollback_failure is not None)
    snapshots = list(tmp_path.glob(".realm-upgrade-transaction-*/v23-*/realm.sqlite3"))
    if rollback_failure is None:
        assert source_db.read_bytes() == original
        assert snapshots == []
    else:
        assert len(snapshots) == 1
        assert snapshots[0].read_bytes() == original
        assert str(snapshots[0].parent) in str(error.value)
        if rollback_failure == "after_publication":
            assert source_db.read_bytes() == original


@pytest.mark.parametrize("operation", ["upgrade", "compaction"])
def test_upgrade_and_compaction_flush_owned_files_through_writable_handles(tmp_path, monkeypatch, operation):
    root = tmp_path / "realm"
    if operation == "upgrade":
        realm_id = _legacy_realm(root)
    else:
        store = RealmStore.initialize(root)
        realm_id = store.realm["id"]
        store.close()
    real_fsync = upgrade.os.fsync
    flushed_files = []

    def writable_fsync(fd):
        if stat.S_ISREG(os.fstat(fd).st_mode):
            # A zero-byte write verifies access without changing file contents
            # or offset. POSIX and Windows CRT reject read-only descriptors.
            os.write(fd, b"")
            flushed_files.append(fd)
        return real_fsync(fd)

    monkeypatch.setattr(upgrade.os, "fsync", writable_fsync)
    if operation == "upgrade":
        assert upgrade_realm(root, confirmation=f"UPGRADE {realm_id}")["ok"]
    else:
        assert upgrade.compact_idempotency_ledger(root, confirmation=f"COMPACT IDEMPOTENCY {realm_id}")["ok"]
    assert flushed_files


def test_upgrade_post_publication_failure_restores_archived_sqlite_sidecars(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    realm_id = _legacy_realm(root)
    subprocess.run([sys.executable, "-c", """
import os, sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
connection.execute("PRAGMA journal_mode=WAL")
connection.execute("PRAGMA wal_autocheckpoint=0")
connection.execute("UPDATE realm SET display_name='pending WAL'")
connection.commit()
os._exit(0)
""", str(root / "realm.sqlite3")], check=True)
    original = {
        path.name: path.read_bytes() for path in root.glob("realm.sqlite3*")
        if path.is_file()
    }
    assert "realm.sqlite3-wal" in original
    real_flush = platform.flush_replace
    publications = []

    def flush(source, destination):
        source = Path(source)
        if source.name == "realm.sqlite3" and source.parent.name.startswith(".realm-upgrade-"):
            publications.append(source)
            raise OSError("injected post-publication failure")
        return real_flush(source, destination)

    monkeypatch.setattr(platform, "flush_replace", flush)
    with pytest.raises(OSError, match="injected post-publication failure"):
        upgrade_realm(root, confirmation=f"UPGRADE {realm_id}")
    assert len(publications) == 1
    assert {path.name: path.read_bytes() for path in root.glob("realm.sqlite3*") if path.is_file()} == original
    assert not list(tmp_path.glob(".realm-upgrade-transaction-*"))
