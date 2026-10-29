from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

import pytest

import runtime_protocol.lifecycle as lifecycle
from runtime_protocol.errors import ConflictError, ValidationError
from runtime_protocol.lifecycle import inspect_interruption_state, interruption_fence
from runtime_protocol.store import RealmStore


NOW = datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone.utc)
CREATED = "2026-10-27T11:59:00Z"


class FrozenDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW if tz else NOW.replace(tzinfo=None)


def _realm(tmp_path):
    root = tmp_path / "realm"
    store = RealmStore.initialize(root, realm_id="refusal-tests")
    spec_digest = store._store_spec({})
    store.close()
    db = sqlite3.connect(root / "realm.sqlite3")
    db.execute(
        "INSERT INTO projects(id, realm_id, slug, name, metadata_json, created_at, updated_at) "
        "VALUES ('p', 'refusal-tests', 'p', 'P', '{}', ?, ?)", (CREATED, CREATED),
    )
    db.execute(
        "INSERT INTO runs(id, project_id, capability, spec_digest, status, created_at, updated_at) "
        "VALUES ('r', 'p', 'render', ?, 'running', ?, ?)", (spec_digest, CREATED, CREATED),
    )
    db.commit()
    db.close()
    return root


def _task(db, task_id, *, status="queued", capability="rendering.render", created_at=CREATED):
    db.execute(
        "INSERT INTO tasks(id, run_id, capability, status, created_at, updated_at) "
        "VALUES (?, 'r', ?, ?, ?, ?)", (task_id, capability, status, created_at, CREATED),
    )


def test_blocker_report_normalizes_all_categories_and_keeps_structured_arrays(tmp_path, monkeypatch):
    monkeypatch.setattr(lifecycle, "datetime", FrozenDateTime)
    root = _realm(tmp_path)
    db = sqlite3.connect(root / "realm.sqlite3")
    _task(db, "running", status="running")
    _task(db, "cancel", status="cancel_requested", created_at="invalid")
    _task(db, "attempt", created_at="2026-10-27T12:05:00Z")
    _task(db, "binding")
    _task(db, "reservation")
    db.execute(
        "INSERT INTO attempts(id, task_id, lease_id, fence, executor_id, lease_expires_at, settled, runtime_epoch) "
        "VALUES ('a-expired', 'attempt', 'lease', 1, 'worker', '2000-01-01T00:00:00Z', 0, 1)"
    )
    db.execute(
        "INSERT INTO execution_bindings(binding_id, task_id, run_id, session_id, runtime_epoch, capability_id, "
        "target_kind, resolved_target_json, status, created_at, updated_at) "
        "VALUES ('b-stale', 'binding', 'r', 'session', 1, 'rendering.render', 'local', '{}', 'stale', ?, ?)",
        (CREATED, CREATED),
    )
    db.execute(
        "INSERT INTO reservations(task_id, resource_key, lease_token, created_at) VALUES ('reservation', 'gpu:0', 'lease-r', ?) "
        "ON CONFLICT(task_id, resource_key) DO UPDATE SET released_at=NULL", (CREATED,),
    )
    # The same task can be present in several blocker categories; count it once.
    db.execute(
        "INSERT INTO reservations(task_id, resource_key, lease_token, created_at) VALUES ('attempt', 'gpu:1', 'lease-a', ?)",
        (CREATED,),
    )
    db.commit()
    db.close()

    report = inspect_interruption_state(root)
    assert report["safe"] is False
    assert report["task_count"] == 5
    assert report["headline"] == "Astrid is busy (5 tasks running). Try again when they finish."
    assert report["message"] == "\n".join([
        report["headline"],
        "attempt [unreleased_reservation; rendering.render; queued; age 0s]",
        "attempt [unsettled_attempt; rendering.render; queued; age 0s]",
        "binding [claimed_or_stale_binding; rendering.render; queued; age 60s]",
        "cancel [cancel_requested_task; rendering.render; cancel_requested; age unknown]",
        "reservation [unreleased_reservation; rendering.render; queued; age 60s]",
        "running [running_task; rendering.render; running; age 60s]",
    ])
    assert json.loads(json.dumps(report, sort_keys=True))["blockers"] == report["blockers"]
    assert len(report["active_tasks"]) == 2
    assert len(report["unreconciled_attempts"]) == 1
    assert report["unreconciled_attempts"][0]["lease_expired"] is True
    assert report["blockers"] == [
        {
            "task_id": "attempt", "kind": "rendering.render", "state": "queued",
            "created_at": "2026-10-27T12:05:00Z", "age_seconds": 0,
            "blocker_kind": "unreleased_reservation", "resource_key": "gpu:1",
            "lease_token": "lease-a", "executor_id": None, "fence": 0,
            "lease_expires_at": None, "lease_expired": None, "runtime_epoch": 1,
        },
        {
            "task_id": "attempt", "kind": "rendering.render", "state": "queued",
            "created_at": "2026-10-27T12:05:00Z", "age_seconds": 0,
            "blocker_kind": "unsettled_attempt", "attempt_id": "a-expired", "lease_id": "lease",
            "lease_expires_at": "2000-01-01T00:00:00Z", "lease_expired": True, "runtime_epoch": 1,
        },
        {
            "task_id": "binding", "kind": "rendering.render", "state": "queued",
            "created_at": CREATED, "age_seconds": 60, "blocker_kind": "claimed_or_stale_binding",
            "binding_id": "b-stale", "binding_status": "stale",
        },
        {
            "task_id": "cancel", "kind": "rendering.render", "state": "cancel_requested",
            "created_at": "invalid", "age_seconds": None, "blocker_kind": "cancel_requested_task",
        },
        {
            "task_id": "reservation", "kind": "rendering.render", "state": "queued",
            "created_at": CREATED, "age_seconds": 60, "blocker_kind": "unreleased_reservation",
            "resource_key": "gpu:0", "lease_token": "lease-r", "executor_id": None,
            "fence": 0, "lease_expires_at": None, "lease_expired": None, "runtime_epoch": 1,
        },
        {
            "task_id": "running", "kind": "rendering.render", "state": "running",
            "created_at": CREATED, "age_seconds": 60, "blocker_kind": "running_task",
        },
    ]
    with pytest.raises(ConflictError) as refusal:
        with interruption_fence(root):
            pytest.fail("blocked realm must not enter the fence")
    assert refusal.value.details == report
    assert str(refusal.value) == report["message"]


@pytest.mark.parametrize("created_at,expected_age", [
    ("", None), ("bad-date", None), ("2026-10-27T12:01:00Z", 0),
    ("2026-10-27T11:59:30+00:00", 30),
])
def test_running_task_timestamp_normalization(tmp_path, monkeypatch, created_at, expected_age):
    monkeypatch.setattr(lifecycle, "datetime", FrozenDateTime)
    root = _realm(tmp_path)
    db = sqlite3.connect(root / "realm.sqlite3")
    _task(db, "task", status="running", created_at=created_at)
    db.commit()
    db.close()
    row = inspect_interruption_state(root)["blockers"][0]
    assert row["created_at"] == created_at
    assert row["age_seconds"] == expected_age


def test_orphaned_blocker_metadata_is_reported_as_unknown_not_idle(tmp_path):
    root = _realm(tmp_path)
    db = sqlite3.connect(root / "realm.sqlite3")
    db.execute("PRAGMA foreign_keys=OFF")
    db.execute(
        "INSERT INTO attempts(id, task_id, lease_id, fence, executor_id, lease_expires_at, settled, runtime_epoch) "
        "VALUES ('orphan-attempt', 'missing-task', 'lease', 1, 'worker', 'invalid', 0, 1)"
    )
    db.commit()
    db.close()
    report = inspect_interruption_state(root)
    assert not report["safe"]
    assert report["task_count"] == 1
    assert report["blockers"] == [{
        "task_id": "missing-task", "kind": "unknown", "state": "unknown", "created_at": None,
        "age_seconds": None, "blocker_kind": "unsettled_attempt",
        "attempt_id": "orphan-attempt", "lease_id": "lease",
        "lease_expires_at": "invalid", "lease_expired": None, "runtime_epoch": 1,
    }]


def test_legacy_tasks_table_without_optional_kind_or_created_at_uses_unknowns():
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(
        "CREATE TABLE tasks (id TEXT PRIMARY KEY, status TEXT NOT NULL);"
        "CREATE TABLE attempts (id TEXT, task_id TEXT, lease_id TEXT, lease_expires_at TEXT, "
        "runtime_epoch INTEGER, settled INTEGER);"
        "INSERT INTO tasks VALUES ('legacy-task', 'running');"
        "INSERT INTO attempts VALUES ('settled', 'legacy-task', 'lease', 'invalid', 1, 1);"
    )
    try:
        report = lifecycle._interruption_report(connection)
    finally:
        connection.close()
    assert report["blockers"] == [{
        "task_id": "legacy-task", "kind": "unknown", "state": "running", "created_at": None,
        "age_seconds": None, "blocker_kind": "running_task",
    }]


@pytest.mark.parametrize("category", [
    "running_task", "cancel_requested_task", "unsettled_attempt",
    "claimed_binding", "stale_binding", "unreleased_reservation",
])
def test_each_blocker_category_refuses_individually(tmp_path, monkeypatch, category):
    monkeypatch.setattr(lifecycle, "datetime", FrozenDateTime)
    root = _realm(tmp_path)
    db = sqlite3.connect(root / "realm.sqlite3")
    status = {
        "running_task": "running",
        "cancel_requested_task": "cancel_requested",
    }.get(category, "queued")
    _task(db, "blocked", status=status)
    if category == "unsettled_attempt":
        db.execute(
            "INSERT INTO attempts(id, task_id, lease_id, fence, executor_id, lease_expires_at, settled, runtime_epoch) "
            "VALUES ('attempt', 'blocked', 'lease', 1, 'worker', 'invalid', 0, 1)"
        )
    elif category in {"claimed_binding", "stale_binding"}:
        binding_status = "claimed" if category == "claimed_binding" else "stale"
        db.execute(
            "INSERT INTO execution_bindings(binding_id, task_id, run_id, session_id, runtime_epoch, capability_id, "
            "target_kind, resolved_target_json, status, created_at, updated_at) "
            "VALUES ('binding', 'blocked', 'r', 'session', 1, 'rendering.render', 'local', '{}', ?, ?, ?)",
            (binding_status, CREATED, CREATED),
        )
    elif category == "unreleased_reservation":
        db.execute(
            "INSERT INTO reservations(task_id, resource_key, lease_token, created_at) "
            "VALUES ('blocked', 'gpu:0', 'lease', ?) ON CONFLICT(task_id, resource_key) "
            "DO UPDATE SET released_at=NULL",
            (CREATED,),
        )
    db.commit()
    db.close()

    report = inspect_interruption_state(root)
    assert report["safe"] is False
    assert report["task_count"] == 1
    expected_kind = "claimed_or_stale_binding" if category in {"claimed_binding", "stale_binding"} else category
    assert report["blockers"][0]["blocker_kind"] == expected_kind
    assert report["blockers"][0]["task_id"] == "blocked"
    assert report["headline"] == "Astrid is busy (1 tasks running). Try again when they finish."
    with pytest.raises(ConflictError) as refusal:
        with interruption_fence(root):
            pytest.fail("an individual blocker category must refuse the fence")
    assert refusal.value.details["blockers"] == report["blockers"]


def _committed_data(root):
    with closing(sqlite3.connect(root / "realm.sqlite3")) as db:
        return tuple(db.iterdump())


def test_refusal_on_clean_wal_database_does_not_change_committed_data(tmp_path):
    root = _realm(tmp_path)
    with closing(sqlite3.connect(root / "realm.sqlite3")) as db:
        _task(db, "busy", status="running")
        db.commit()
    before = _committed_data(root)

    report = inspect_interruption_state(root)

    assert report["safe"] is False
    assert _committed_data(root) == before


def test_read_only_observer_includes_live_wal_work_without_data_mutation(tmp_path):
    root = _realm(tmp_path)
    writer = sqlite3.connect(root / "realm.sqlite3")
    writer.execute("PRAGMA wal_autocheckpoint=0")
    _task(writer, "live-wal", status="running")
    writer.commit()
    assert (root / "realm.sqlite3-wal").stat().st_size > 0
    before = _committed_data(root)
    try:
        report = inspect_interruption_state(root)
        assert report["safe"] is False
        assert report["blockers"][0]["task_id"] == "live-wal"
        assert _committed_data(root) == before
    finally:
        writer.close()


def test_read_only_observation_stays_consistent_when_writer_commits(tmp_path, monkeypatch):
    root = _realm(tmp_path)
    original_report = lifecycle._interruption_report

    def report_with_writer(connection):
        before = original_report(connection)
        with sqlite3.connect(root / "realm.sqlite3") as writer:
            _task(writer, "raced-writer", status="running")
        # All queries in one advisory observation see the same SQLite snapshot.
        assert original_report(connection) == before
        return before

    with monkeypatch.context() as patch:
        patch.setattr(lifecycle, "_interruption_report", report_with_writer)
        assert inspect_interruption_state(root)["safe"] is True
    report = inspect_interruption_state(root)
    assert report["safe"] is False
    assert report["blockers"][0]["task_id"] == "raced-writer"


def test_read_only_observer_sees_work_after_wal_checkpoint(tmp_path, monkeypatch):
    root = _realm(tmp_path)
    writer = sqlite3.connect(root / "realm.sqlite3")
    writer.execute("PRAGMA wal_autocheckpoint=0")
    _task(writer, "checkpointed", status="running")
    writer.commit()
    assert (root / "realm.sqlite3-wal").stat().st_size > 0
    original_report = lifecycle._interruption_report

    def report_after_checkpoint(connection):
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return original_report(connection)

    monkeypatch.setattr(lifecycle, "_interruption_report", report_after_checkpoint)
    try:
        report = inspect_interruption_state(root)
        assert report["safe"] is False
        assert report["blockers"][0]["task_id"] == "checkpointed"
    finally:
        writer.close()


def test_read_only_observer_uses_query_only_without_file_copies(tmp_path, monkeypatch):
    root = _realm(tmp_path)
    original_report = lifecycle._interruption_report
    original_connect = sqlite3.connect
    opened = []

    def observe_connect(database, **kwargs):
        opened.append((database, kwargs))
        return original_connect(database, **kwargs)

    def read_only_report(connection):
        assert connection.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            connection.execute("DELETE FROM tasks")
        return original_report(connection)

    monkeypatch.setattr(lifecycle.sqlite3, "connect", observe_connect)
    monkeypatch.setattr(lifecycle, "_interruption_report", read_only_report)
    monkeypatch.setattr(Path, "read_bytes", lambda *_: pytest.fail("preflight copied a whole file"))
    assert inspect_interruption_state(root)["safe"] is True
    assert opened == [(lifecycle.sqlite_file_uri(root / "realm.sqlite3", mode="ro"), {"uri": True})]


def test_read_only_refusal_does_not_mutate_committed_data(tmp_path):
    root = _realm(tmp_path)
    with closing(sqlite3.connect(root / "realm.sqlite3")) as db:
        _task(db, "busy", status="running")
        db.commit()
    before = _committed_data(root)
    with pytest.raises(ConflictError):
        with interruption_fence(root):
            pytest.fail("busy realm was admitted")
    assert _committed_data(root) == before


def test_preflight_to_final_check_race_is_refused(tmp_path, monkeypatch):
    root = _realm(tmp_path)
    original = lifecycle.assert_interruption_safe
    injected = False

    def preflight_then_claim(path):
        nonlocal injected
        report = original(path)
        if not injected:
            injected = True
            db = sqlite3.connect(root / "realm.sqlite3")
            _task(db, "claimed-after-preflight", status="running")
            db.commit()
            db.close()
        return report

    monkeypatch.setattr(lifecycle, "assert_interruption_safe", preflight_then_claim)
    with pytest.raises(ConflictError) as refusal:
        with interruption_fence(root):
            pytest.fail("final serialized check missed a newly running task")
    assert refusal.value.details["task_count"] == 1
    assert refusal.value.details["blockers"][0]["task_id"] == "claimed-after-preflight"


def test_missing_required_metadata_schema_refuses_instead_of_reporting_idle(tmp_path):
    root = _realm(tmp_path)
    db = sqlite3.connect(root / "realm.sqlite3")
    db.execute("ALTER TABLE tasks RENAME TO damaged_tasks")
    db.commit()
    db.close()
    with pytest.raises(ValidationError, match="tables are missing"):
        inspect_interruption_state(root)


def test_missing_task_identity_metadata_refuses_instead_of_reporting_idle(tmp_path):
    root = _realm(tmp_path)
    db = sqlite3.connect(root / "realm.sqlite3")
    db.execute("ALTER TABLE tasks RENAME TO damaged_tasks")
    db.execute("CREATE TABLE tasks (status TEXT)")
    db.commit()
    db.close()
    with pytest.raises(ValidationError, match="identity/status metadata is missing"):
        inspect_interruption_state(root)
