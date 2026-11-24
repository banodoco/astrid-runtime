"""SV-L5: accepted timeline publications are append-only in SQLite."""
import sqlite3

import pytest

import test_timeline_commit_authentication as auth
from test_timeline_commit_port import commit

service = auth.service


@pytest.mark.parametrize("statement", [
    "UPDATE timeline_commit_history SET intent=intent WHERE publication_id=?",
    "DELETE FROM timeline_commit_history WHERE publication_id=?",
    "INSERT OR REPLACE INTO timeline_commit_history SELECT * FROM timeline_commit_history WHERE publication_id=?",
])
def test_accepted_publication_is_immutable(service, statement):
    auth.provider(service)
    publication = commit(service, auth.body(service))["receipt"]["receipt_id"]
    connection = service.store.conn
    read = "SELECT * FROM timeline_commit_history WHERE publication_id=?"
    original = tuple(connection.execute(read, (publication,)).fetchone())

    with pytest.raises(sqlite3.IntegrityError, match="accepted timeline history is immutable"):
        connection.execute(statement, (publication,))

    assert tuple(connection.execute(read, (publication,)).fetchone()) == original


def test_replace_cannot_bypass_guards_on_an_external_connection(service):
    from contextlib import closing

    auth.provider(service)
    publication = commit(service, auth.body(service))["receipt"]["receipt_id"]
    with closing(sqlite3.connect(service.store.db_path)) as connection, connection:
        connection.execute("PRAGMA recursive_triggers=OFF")
        row = connection.execute(
            "SELECT rowid, * FROM timeline_commit_history WHERE publication_id=?", (publication,)
        ).fetchone()
        assert row is not None
        values = list(row[1:])
        marks = ",".join("?" for _ in values)
        # Unique publication ID (different sequence), scoped sequence
        # (different publication ID), and explicit rowid (both keys different).
        by_id = [*values[:-1], values[-1] + 1000]
        by_sequence = ["forged-publication", *values[1:]]
        by_rowid = ["forged-publication", *values[1:-1], values[-1] + 1000]
        for sql, args in (
            (f"INSERT OR REPLACE INTO timeline_commit_history VALUES ({marks})", by_id),
            (f"INSERT OR REPLACE INTO timeline_commit_history VALUES ({marks})", by_sequence),
            (f"INSERT OR REPLACE INTO timeline_commit_history(rowid, publication_id, project_id, timeline_id, "
             "revision_id, previous_publication_id, previous_revision_id, intent, records_json, metadata_json, "
             f"provider_version, compiler_version, publisher, project_seq) VALUES (?,{marks})", [row[0], *by_rowid]),
        ):
            with pytest.raises(sqlite3.IntegrityError, match="accepted timeline history is immutable"):
                connection.execute(sql, args)
            assert connection.execute(
                "SELECT rowid, * FROM timeline_commit_history WHERE publication_id=?", (publication,)
            ).fetchone() == row


def test_forge_restores_guard_inside_outer_transaction(service):
    from runtime_protocol.v33_manifest import canonical_manifest
    from tests.history_forgery import forge_history_row

    auth.provider(service)
    publication = commit(service, auth.body(service))["receipt"]["receipt_id"]
    connection = service.store.conn
    change = "UPDATE timeline_commit_history SET metadata_json=metadata_json || ' ' WHERE publication_id=?"
    read = "SELECT metadata_json FROM timeline_commit_history WHERE publication_id=?"
    original = connection.execute(read, (publication,)).fetchone()[0]
    connection.execute("SAVEPOINT outer_forge")
    try:
        assert forge_history_row(connection, change, (publication,)).rowcount == 1
        assert connection.in_transaction
        assert connection.execute(read, (publication,)).fetchone()[0] == original + " "
        assert canonical_manifest(connection)["history_guarded"]
        with pytest.raises(sqlite3.IntegrityError, match="accepted timeline history is immutable"):
            connection.execute(change, (publication,))
        with pytest.raises(sqlite3.IntegrityError):
            forge_history_row(connection, "UPDATE timeline_commit_history SET intent='bad' WHERE publication_id=?", (publication,))
        with pytest.raises(sqlite3.IntegrityError, match="accepted timeline history is immutable"):
            connection.execute(change, (publication,))
    finally:
        connection.execute("ROLLBACK TO outer_forge")
        connection.execute("RELEASE outer_forge")
    assert connection.execute(read, (publication,)).fetchone()[0] == original
    assert canonical_manifest(connection)["history_guarded"]


def test_append_and_restore_preserve_accepted_edges(service):
    from runtime_protocol.timeline_commit_port import route_path
    from test_timeline_commit_port import PreparedProvider, request, use_provider

    use_provider(service, PreparedProvider())
    original = request(service)
    source = original["base_revision_id"]
    connection = service.store.conn

    def history():
        return {row[0]: tuple(row) for row in connection.execute("SELECT * FROM timeline_commit_history")}

    before = history()
    accepted = commit(service, original)
    appended = history()
    assert appended.keys() == before.keys() | {accepted["receipt"]["receipt_id"]}
    assert all(appended[key] == value for key, value in before.items())
    current = service.get_project_timeline(service.test_project, "main")
    body = {"expected_head": current["head_revision_id"], "expected_publication_id": current["head_publication_id"]}
    restored = service.restore_project_parent_composition_revision(
        service.test_project, "main", source, body, idempotency_key="immutable-restore",
        publisher="editor", invocation_path=route_path(service.test_project, "main", f"composition-revisions/{source}/restore"),
        authorize=lambda: None,
    )
    after = history()
    assert after.keys() == appended.keys() | {restored["receipt"]["receipt_id"]}
    assert all(after[key] == value for key, value in appended.items())
    assert service.store.integrity_report()["ok"]


@pytest.mark.parametrize("corrupt", [False, True])
def test_offline_unguarded_v33_migration_preserves_history_and_doctor_refuses_corruption(service, corrupt):
    from contextlib import closing

    from runtime_protocol.canonical_schema import TIMELINE_HISTORY_TRIGGER_SQL
    from runtime_protocol.errors import RealmAdmissionError
    from runtime_protocol.store import RealmStore
    from runtime_protocol.upgrade import inspect_canonical_schema, migrate_canonical_to_current

    auth.provider(service)
    publication = commit(service, auth.body(service))["receipt"]["receipt_id"]
    root = service.store.root
    service.close()
    with closing(sqlite3.connect(root / "realm.sqlite3")) as connection, connection:
        for name in TIMELINE_HISTORY_TRIGGER_SQL:
            connection.execute(f"DROP TRIGGER {name}")
        if corrupt:
            connection.execute("UPDATE timeline_commit_history SET records_json='{}' WHERE publication_id=?", (publication,))
        original = connection.execute("SELECT * FROM timeline_commit_history ORDER BY publication_id").fetchall()

    prior = inspect_canonical_schema(root)
    assert prior["version"] == 33 and not prior["history_guarded"]
    result = migrate_canonical_to_current(root, confirmation=f"MIGRATE CANONICAL {prior['realm_id']}")
    assert result["changed"]
    migrated = inspect_canonical_schema(root)
    assert migrated["history_guarded"] and migrated["fingerprint"] != prior["fingerprint"]
    with closing(sqlite3.connect(root / "realm.sqlite3")) as connection, connection:
        assert connection.execute("SELECT * FROM timeline_commit_history ORDER BY publication_id").fetchall() == original
        with pytest.raises(sqlite3.IntegrityError, match="accepted timeline history is immutable"):
            connection.execute("UPDATE timeline_commit_history SET intent=intent WHERE publication_id=?", (publication,))
    if corrupt:
        with pytest.raises(RealmAdmissionError) as refusal:
            RealmStore(root)
        assert any(item["table"] == "timeline_commit_history" and item["id"] == publication
                   for item in refusal.value.details["checks"]["revisions"]["errors"])
    else:
        with closing(RealmStore(root)) as reopened:
            assert reopened.integrity_report()["ok"]


def test_missing_or_modified_guard_is_not_a_current_manifest(service):
    from runtime_protocol.errors import ValidationError
    from runtime_protocol.v33_manifest import canonical_manifest

    connection = service.store.conn
    connection.execute("SAVEPOINT guard_tamper")
    try:
        connection.execute("DROP TRIGGER timeline_history_no_update")
        with pytest.raises(ValidationError, match="unsupported canonical"):
            canonical_manifest(connection)
        connection.execute("CREATE TRIGGER timeline_history_no_update BEFORE UPDATE ON timeline_commit_history BEGIN SELECT 1; END")
        with pytest.raises(ValidationError, match="unsupported SQLite schema object"):
            canonical_manifest(connection)
    finally:
        connection.execute("ROLLBACK TO guard_tamper")
        connection.execute("RELEASE guard_tamper")
    assert canonical_manifest(connection)["history_guarded"]
