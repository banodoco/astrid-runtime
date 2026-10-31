from __future__ import annotations

import shutil
import sqlite3
import json
from datetime import datetime, timedelta, timezone

import pytest

from runtime_protocol.errors import ConflictError
from runtime_protocol.cli import main as runtime_cli
from runtime_protocol.store import IdempotencyWindowExpired, RealmStore, SCHEMA_VERSION
from runtime_protocol.upgrade import compact_idempotency_ledger


def _v27_copy(source, target):
    """Materialize a v27 realm from a fresh realm for the offline migration journey."""
    connection = sqlite3.connect(source / "realm.sqlite3")
    try:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("ALTER TABLE timelines DROP COLUMN name")  # v30 -> v29: timelines.name is the only v30 change
        connection.execute("DROP TABLE user_app_state")
        connection.execute("DROP INDEX idx_generations_gen")
        connection.execute("DROP INDEX idx_tasks_retention")
        for table in ("runs", "tasks"):
            connection.execute(f"ALTER TABLE {table} ADD COLUMN spec_json TEXT")
            connection.execute(
                f"UPDATE {table} SET spec_json=(SELECT body_json FROM task_specs "
                f"WHERE digest={table}.spec_digest)"
            )
            connection.execute(f"ALTER TABLE {table} DROP COLUMN spec_digest")
        connection.execute("DROP TABLE task_specs")
        connection.execute("UPDATE runtime_schema SET version=27")
        connection.commit()
    finally:
        connection.close()
    shutil.copytree(source, target)


def test_offline_migration_and_compaction_of_duplicate_render_specs(tmp_path, capsys):
    source = tmp_path / "source"
    clone = tmp_path / "clone"
    store = RealmStore.initialize(source)
    realm_id = store.realm["id"]
    spec = {"spec": {"timeline_snapshot": {"cuts": "x" * 128_000}}, "input_object_ids": []}
    first = None
    try:
        for index in range(32):
            value = store.create_task("synthetic.render", spec, idempotency_key="replay" if index == 0 else None)
            first = first or value
    finally:
        store.close()
    _v27_copy(source, clone)
    before = (clone / "realm.sqlite3").stat().st_size
    assert (source / "realm.sqlite3").read_bytes() == (clone / "realm.sqlite3").read_bytes()

    assert runtime_cli(["migrate-canonical", "--root", str(clone),
                        "--confirm", f"MIGRATE CANONICAL {realm_id}"]) == 0
    migrated = json.loads(capsys.readouterr().out)
    steps = {step["target_schema_version"]: step for step in migrated["steps"]}
    assert steps[28]["row_count"] == 64
    assert steps[28]["unique_specs"] == 1
    # Steps run in order and end at the current schema.
    assert [step["target_schema_version"] for step in migrated["steps"]] == [28, 29, 30, 31, 32]
    assert migrated["target_schema_version"] == SCHEMA_VERSION
    compacted = compact_idempotency_ledger(clone, confirmation=f"COMPACT IDEMPOTENCY {realm_id}")
    assert compacted["after_bytes"] < before * 0.25
    assert compacted["retired_tasks"] == 0

    reopened = RealmStore(clone)
    try:
        assert reopened.integrity_report()["ok"] is True
        assert reopened.create_task("synthetic.render", spec, idempotency_key="replay")["task"]["id"] == first["task"]["id"]
        assert reopened.get_task(first["task"]["id"])["task"]["spec"] == spec
        assert reopened.conn.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        reopened.close()
    assert (source / "realm.sqlite3").stat().st_size == before


def test_compaction_retires_old_terminal_spec_and_refuses_retry(tmp_path):
    root = tmp_path / "realm"
    store = RealmStore.initialize(root)
    realm_id = store.realm["id"]
    value = store.create_task("synthetic.render", {"spec": {"payload": "x" * 100_000}})
    task_id, run_id = value["task"]["id"], value["run"]["id"]
    old = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat(timespec="milliseconds")
    store.conn.execute(
        "UPDATE tasks SET status='failed', result_json=?, expected_effect_json=?, "
        "execution_request_json=?, updated_at=? WHERE id=?",
        ('{"error":"finished"}', '{"effect_type":"old"}', '{"target":"old"}', old, task_id),
    )
    store.conn.execute("UPDATE runs SET status='failed', updated_at=? WHERE id=?", (old, run_id))
    store.close()

    compacted = compact_idempotency_ledger(root, confirmation=f"COMPACT IDEMPOTENCY {realm_id}")
    assert (compacted["retired_tasks"], compacted["retired_runs"], compacted["removed_specs"]) == (1, 1, 1)
    reopened = RealmStore(root)
    try:
        assert reopened.integrity_report()["ok"] is True
        summary = reopened.get_task(task_id)["task"]
        assert summary["spec_retired"] is True
        assert summary["result"] == {"error": "finished"}
        assert "expected_effect" not in summary
        assert reopened.conn.execute("SELECT execution_request_json FROM tasks WHERE id=?", (task_id,)).fetchone()[0] is None
        with pytest.raises(ConflictError, match="retention window"):
            reopened.retry_run(run_id)
    finally:
        reopened.close()


def test_recent_admission_receipt_preserves_old_terminal_spec(tmp_path):
    root = tmp_path / "realm"
    store = RealmStore.initialize(root)
    realm_id = store.realm["id"]
    spec = {"spec": {"payload": "x" * 20_000}}
    value = store.create_task("synthetic.render", spec, idempotency_key="keep-replay")
    task_id, run_id = value["task"]["id"], value["run"]["id"]
    old = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat(timespec="milliseconds")
    store.conn.execute("UPDATE tasks SET status='completed', updated_at=? WHERE id=?", (old, task_id))
    store.conn.execute("UPDATE runs SET status='completed', updated_at=? WHERE id=?", (old, run_id))
    store.close()

    first = compact_idempotency_ledger(root, confirmation=f"COMPACT IDEMPOTENCY {realm_id}")
    assert first["retired_tasks"] == 0
    reopened = RealmStore(root)
    try:
        assert reopened.create_task("synthetic.render", spec, idempotency_key="keep-replay")["task"]["id"] == task_id
        expired = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(timespec="milliseconds")
        reopened.conn.execute(
            "UPDATE command_idempotency SET created_at=? WHERE command_kind='task.create' AND idempotency_key='keep-replay'",
            (expired,),
        )
    finally:
        reopened.close()
    second = compact_idempotency_ledger(root, confirmation=f"COMPACT IDEMPOTENCY {realm_id}")
    assert second["retired_tasks"] == 1
    reopened = RealmStore(root)
    try:
        with pytest.raises(IdempotencyWindowExpired):
            reopened.create_task("synthetic.render", spec, idempotency_key="keep-replay")
        assert reopened.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
    finally:
        reopened.close()


def test_new_admission_reuses_space_from_expired_terminal_spec(tmp_path):
    root = tmp_path / "realm"
    store = RealmStore.initialize(root)
    try:
        old_task = store.create_task("synthetic.render", {"spec": {"old": "x" * 100_000}})
        task_id, run_id = old_task["task"]["id"], old_task["run"]["id"]
        old = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat(timespec="milliseconds")
        store.conn.execute("UPDATE tasks SET status='completed', updated_at=? WHERE id=?", (old, task_id))
        store.conn.execute("UPDATE runs SET status='completed', updated_at=? WHERE id=?", (old, run_id))
        assert store.conn.execute("SELECT COUNT(*) FROM task_specs").fetchone()[0] == 1
        store.create_task("synthetic.render", {"spec": {"new": "small"}})
        assert store.conn.execute("SELECT spec_digest FROM tasks WHERE id=?", (task_id,)).fetchone()[0] is None
        assert store.conn.execute("SELECT COUNT(*) FROM task_specs").fetchone()[0] == 1
        assert store.integrity_report()["ok"] is True
    finally:
        store.close()


def test_configured_retention_window_applies_to_admission_and_compaction(tmp_path, monkeypatch):
    monkeypatch.setenv("ASTRID_RUNTIME_SPEC_RETENTION_DAYS", "60")
    root = tmp_path / "realm"
    store = RealmStore.initialize(root)
    realm_id = store.realm["id"]
    try:
        value = store.create_task("synthetic.render", {"spec": {"old": True}})
        task_id, run_id = value["task"]["id"], value["run"]["id"]
        old = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat(timespec="milliseconds")
        store.conn.execute("UPDATE tasks SET status='completed', updated_at=? WHERE id=?", (old, task_id))
        store.conn.execute("UPDATE runs SET status='completed', updated_at=? WHERE id=?", (old, run_id))
        store.create_task("synthetic.render", {"spec": {"new": True}})
        assert store.conn.execute("SELECT spec_digest FROM tasks WHERE id=?", (task_id,)).fetchone()[0]
    finally:
        store.close()
    default = compact_idempotency_ledger(root, confirmation=f"COMPACT IDEMPOTENCY {realm_id}")
    assert default["retention_days"] == 60
    assert default["retired_tasks"] == 0
    overridden = compact_idempotency_ledger(root, confirmation=f"COMPACT IDEMPOTENCY {realm_id}", retention_days=30)
    assert overridden["retired_tasks"] == 1
