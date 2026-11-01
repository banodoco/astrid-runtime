import sqlite3

import pytest

from runtime_protocol.errors import ConflictError, ValidationError
from runtime_protocol.v33_backfill_plan import freeze_generation_plan, reconcile_generation_plan


def database():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("CREATE TABLE generations (id TEXT PRIMARY KEY, project_id TEXT, source_task_id TEXT, type TEXT, metadata_json TEXT, version INTEGER, updated_at TEXT)")
    db.executemany("INSERT INTO generations VALUES (?, 'p', NULL, ?, '{}', 1, 'old')", [("a", "image"), ("b", "video")])
    db.commit()
    return db


def plan_for(db):
    db.execute("BEGIN")
    plan = freeze_generation_plan(db, realm_id="realm", backup_id="backup", schema_fingerprint="schema", applied_at="fixed")
    db.rollback()
    return plan


def test_frozen_plan_applies_once_and_recognizes_lost_ack():
    db = database()
    plan = plan_for(db)
    assert reconcile_generation_plan(db, plan)["state"] == "applied"
    committed = list(map(tuple, db.execute("SELECT * FROM generations ORDER BY id")))
    assert reconcile_generation_plan(db, plan)["state"] == "already_applied"
    assert list(map(tuple, db.execute("SELECT * FROM generations ORDER BY id"))) == committed
    assert [row["version"] for row in db.execute("SELECT * FROM generations")] == [2, 2]


def test_mixed_state_and_changed_scope_refuse_without_mutation():
    db = database()
    plan = plan_for(db)
    after = plan["entries"][0]["after"]
    db.execute("UPDATE generations SET metadata_json=?, version=?, updated_at=? WHERE id=?", (after["metadata_json"], after["version"], after["updated_at"], after["id"]))
    db.commit()
    before = list(map(tuple, db.execute("SELECT * FROM generations ORDER BY id")))
    with pytest.raises(ConflictError, match="mixed or changed"):
        reconcile_generation_plan(db, plan)
    assert list(map(tuple, db.execute("SELECT * FROM generations ORDER BY id"))) == before
    db.execute("DELETE FROM generations")
    db.commit()
    with pytest.raises(ConflictError, match="mixed or changed"):
        reconcile_generation_plan(db, plan)


def test_tampered_plan_refuses_before_transaction():
    db = database()
    plan = plan_for(db)
    plan["applied_at"] = "changed"
    with pytest.raises(ValidationError, match="digest mismatch"):
        reconcile_generation_plan(db, plan)
    assert not db.in_transaction


@pytest.mark.parametrize("mutation", [
    "UPDATE generations SET type='audio' WHERE id='a'",
    "UPDATE tasks SET expected_effect_json='{}' WHERE id='task'",
    "UPDATE runs SET project_id='other' WHERE id='run'",
    "UPDATE task_specs SET body_json='{}' WHERE digest='spec'",
    "UPDATE execution_bindings SET target_id='other' WHERE task_id='task'",
])
@pytest.mark.parametrize("after_apply", [False, True])
def test_changed_sql_evidence_refuses_before_apply_or_lost_ack(mutation, after_apply):
    db = database()
    db.execute("CREATE TABLE tasks (id TEXT PRIMARY KEY, run_id TEXT, expected_effect_json TEXT, spec_digest TEXT)")
    db.execute("CREATE TABLE runs (id TEXT PRIMARY KEY, project_id TEXT, spec_digest TEXT)")
    db.execute("CREATE TABLE task_specs (digest TEXT PRIMARY KEY, body_json TEXT)")
    db.execute("CREATE TABLE execution_bindings (task_id TEXT PRIMARY KEY, target_kind TEXT, target_id TEXT)")
    db.execute("INSERT INTO tasks VALUES ('task', 'run', NULL, 'spec')")
    db.execute("INSERT INTO runs VALUES ('run', 'p', NULL)")
    db.execute("INSERT INTO task_specs VALUES ('spec', '{\"inputs\":{\"model\":\"m\"}}')")
    db.execute("INSERT INTO execution_bindings VALUES ('task', 'machine', 'host')")
    db.execute("UPDATE generations SET source_task_id='task' WHERE id='a'")
    db.commit()
    plan = plan_for(db)
    if after_apply:
        reconcile_generation_plan(db, plan)
    db.execute(mutation)
    db.commit()
    before = list(map(tuple, db.execute("SELECT * FROM generations ORDER BY id")))
    with pytest.raises(ConflictError, match="source evidence changed"):
        reconcile_generation_plan(db, plan)
    assert list(map(tuple, db.execute("SELECT * FROM generations ORDER BY id"))) == before
