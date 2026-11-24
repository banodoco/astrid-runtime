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
    from runtime_protocol.history_guards import history_guard_manifest
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
        assert history_guard_manifest(connection)["version"] == 1
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
    assert history_guard_manifest(connection)["version"] == 1


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
def test_unguarded_u33_admission_installs_only_after_existing_verification(service, corrupt):
    from contextlib import closing

    from runtime_protocol.history_guards import history_guard_manifest, remove_history_guards
    from runtime_protocol.errors import RealmAdmissionError
    from runtime_protocol.store import RealmStore
    from runtime_protocol.upgrade import inspect_canonical_schema

    auth.provider(service)
    publication = commit(service, auth.body(service))["receipt"]["receipt_id"]
    root = service.store.root
    before = inspect_canonical_schema(root)
    service.close()
    with closing(sqlite3.connect(root / "realm.sqlite3", isolation_level=None)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        assert remove_history_guards(connection)
        if corrupt:
            connection.execute("UPDATE timeline_commit_history SET records_json='{}' WHERE publication_id=?", (publication,))
        connection.commit()
        original = connection.execute("SELECT * FROM timeline_commit_history ORDER BY publication_id").fetchall()
        assert history_guard_manifest(connection)["version"] == 0

    prior = inspect_canonical_schema(root)
    assert prior["version"] == 33 and prior["kind"] == "U33"
    assert prior["fingerprint"] == before["fingerprint"]
    report = RealmStore.inspect_realm(root, timeout_seconds=120)
    assert report["checks"]["history_guards"]["version"] == 0
    if corrupt:
        with pytest.raises(RealmAdmissionError) as refusal:
            RealmStore(root, admission_timeout=120)
        assert any(item["table"] == "timeline_commit_history" and item["id"] == publication
                   for item in refusal.value.details["checks"]["revisions"]["errors"])
        with closing(sqlite3.connect(root / "realm.sqlite3")) as connection:
            assert history_guard_manifest(connection)["version"] == 0
    else:
        assert report["ok"]
        with closing(RealmStore(root, admission_timeout=120)) as reopened:
            assert reopened.admission_report["checks"]["history_guards"]["version"] == 1
            assert history_guard_manifest(reopened.conn)["version"] == 1
            assert reopened.integrity_report()["ok"]
        with closing(RealmStore(root, admission_timeout=120)) as reopened:
            assert history_guard_manifest(reopened.conn)["version"] == 1
    with closing(sqlite3.connect(root / "realm.sqlite3")) as connection:
        assert connection.execute("SELECT * FROM timeline_commit_history ORDER BY publication_id").fetchall() == original
    assert inspect_canonical_schema(root)["fingerprint"] == prior["fingerprint"]


@pytest.mark.parametrize("mutation", ["missing_update", "missing_delete", "missing_collision", "when_zero", "ignore", "extra"])
def test_partial_or_modified_guard_layer_refused_without_repair(service, mutation):
    from contextlib import closing

    from runtime_protocol.errors import RealmAdmissionError
    from runtime_protocol.history_guards import HISTORY_GUARD_RECOVERY, TIMELINE_HISTORY_TRIGGER_SQL
    from runtime_protocol.store import RealmStore

    root = service.store.root
    service.close()
    name = {"missing_update": "timeline_history_no_update", "missing_delete": "timeline_history_no_delete",
            "missing_collision": "timeline_history_no_replace"}.get(mutation, "timeline_history_no_update")
    with closing(sqlite3.connect(root / "realm.sqlite3")) as connection, connection:
        if mutation != "extra":
            connection.execute(f"DROP TRIGGER {name}")
        if mutation == "when_zero":
            connection.execute(TIMELINE_HISTORY_TRIGGER_SQL[name].replace(
                "ON timeline_commit_history\nBEGIN", "ON timeline_commit_history\nWHEN 0\nBEGIN"))
        elif mutation == "ignore":
            connection.execute(TIMELINE_HISTORY_TRIGGER_SQL[name].replace(
                "RAISE(ABORT, 'accepted timeline history is immutable')", "RAISE(IGNORE)"))
        elif mutation == "extra":
            connection.execute("CREATE TRIGGER unexpected_history_guard BEFORE UPDATE ON timeline_commit_history BEGIN SELECT 1; END")

    database = root / "realm.sqlite3"
    before = database.read_bytes()
    report = RealmStore.inspect_realm(root, timeout_seconds=120)
    assert not report["ok"]
    assert "history_guards" in report["issues"]
    assert not report["checks"]["history_guards"]["ok"]
    assert report["recovery_action"] == HISTORY_GUARD_RECOVERY
    with pytest.raises(RealmAdmissionError, match="history_guards"):
        RealmStore(root, admission_timeout=120)
    assert database.read_bytes() == before


def test_layer_has_separate_manifest_and_u33_fingerprint_is_unchanged():
    from runtime_protocol.history_guards import history_guard_manifest, install_history_guards, remove_history_guards
    from runtime_protocol.v33_manifest import canonical_manifest
    from test_v33_manifest import database

    connection = database("U33")
    before = canonical_manifest(connection)
    assert before["fingerprint"] == "6ed4d1f145aa5fd8d9691b8b7d072f4e176ad857d4dda586f72b4a64c0e09ff3"
    assert history_guard_manifest(connection)["version"] == 0
    assert install_history_guards(connection)
    assert not install_history_guards(connection)
    assert canonical_manifest(connection) == before
    layer = history_guard_manifest(connection)
    assert layer["version"] == 1 and layer["fingerprint"]
    assert remove_history_guards(connection)
    assert not remove_history_guards(connection)
    assert canonical_manifest(connection) == before
    assert history_guard_manifest(connection)["version"] == 0
    connection.rollback()
    connection.close()


def test_delete_forgery_restores_guard_in_same_transaction():
    from runtime_protocol.history_guards import history_guard_manifest, install_history_guards
    from test_v33_manifest import database
    from tests.history_forgery import forge_history_row

    connection = database("U33")
    # Deliberately minimal rows in an isolated SQLite control; no production
    # history or real service fixture is fabricated.
    connection.execute("INSERT INTO timeline_commit_history VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       ("p", "project", "timeline", "revision", None, None, "bootstrap", None, "{}", None, None, None, 1))
    install_history_guards(connection)
    delete = "DELETE FROM timeline_commit_history WHERE publication_id=?"
    connection.execute("SAVEPOINT delete_control")
    try:
        assert forge_history_row(connection, delete, ("p",)).rowcount == 1
        assert history_guard_manifest(connection)["version"] == 1
        connection.execute("INSERT INTO timeline_commit_history VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           ("q", "project", "timeline", "revision", None, None, "bootstrap", None, "{}", None, None, None, 2))
        with pytest.raises(sqlite3.IntegrityError, match="accepted timeline history is immutable"):
            connection.execute(delete, ("q",))
        with pytest.raises(sqlite3.OperationalError):
            forge_history_row(connection, "DELETE FROM timeline_commit_history WHERE missing_column=?", ("q",))
        with pytest.raises(sqlite3.IntegrityError, match="accepted timeline history is immutable"):
            connection.execute(delete, ("q",))
    finally:
        connection.execute("ROLLBACK TO delete_control")
        connection.execute("RELEASE delete_control")
    assert history_guard_manifest(connection)["version"] == 1
    assert connection.execute("SELECT publication_id FROM timeline_commit_history").fetchall() == [("p",)]
    connection.close()


def test_rollback_backup_is_unguarded_signed_u33_without_live_history_change(service, tmp_path):
    from contextlib import closing

    from runtime_protocol.backup import create_backup, restore_backup, verify_backup
    from runtime_protocol.history_guards import history_guard_manifest
    from runtime_protocol.store import RealmStore
    from runtime_protocol.v33_manifest import canonical_manifest

    auth.provider(service)
    commit(service, auth.body(service))
    conn = service.store.conn
    manifest = canonical_manifest(conn)
    rows = [tuple(row) for row in conn.execute("SELECT * FROM timeline_commit_history ORDER BY publication_id")]
    backup = tmp_path / "rollback-backup"
    key = b"history-layer-rollback-proof-key" * 2
    create_backup(service.store, backup, key=key)
    assert verify_backup(backup, key=key)["manifest"]["schema"]["version"] == 33
    assert history_guard_manifest(conn)["version"] == 1
    assert [tuple(row) for row in conn.execute("SELECT * FROM timeline_commit_history ORDER BY publication_id")] == rows
    with closing(sqlite3.connect(backup / "realm.sqlite3")) as copy:
        assert history_guard_manifest(copy)["version"] == 0
        assert canonical_manifest(copy) == manifest
        assert copy.execute("SELECT * FROM timeline_commit_history ORDER BY publication_id").fetchall() == rows
    restored = tmp_path / "rollback-restored"
    restore_backup(backup, restored, key=key)
    with closing(sqlite3.connect(restored / "realm.sqlite3")) as copy:
        assert history_guard_manifest(copy)["version"] == 0
        assert canonical_manifest(copy) == manifest
        assert copy.execute("SELECT * FROM timeline_commit_history ORDER BY publication_id").fetchall() == rows
    with closing(RealmStore(restored, admission_timeout=120)) as reopened:
        assert history_guard_manifest(reopened.conn)["version"] == 1
        assert [tuple(row) for row in reopened.conn.execute("SELECT * FROM timeline_commit_history ORDER BY publication_id")] == rows


def test_explicit_rollback_removal_is_fenced_and_idempotent(service):
    from contextlib import closing

    from runtime_protocol.errors import OwnerBusyError
    from runtime_protocol.history_guards import history_guard_manifest, prepare_history_guard_rollback
    from runtime_protocol.store import RealmStore
    from runtime_protocol.v33_manifest import canonical_manifest

    auth.provider(service)
    commit(service, auth.body(service))
    root = service.store.root
    conn = service.store.conn
    before = canonical_manifest(conn)
    rows = [tuple(row) for row in conn.execute("SELECT * FROM timeline_commit_history ORDER BY publication_id")]
    confirmation = f"REMOVE HISTORY GUARDS {before['realm_id']}"
    with pytest.raises(OwnerBusyError):
        prepare_history_guard_rollback(root, confirmation=confirmation)
    service.close()
    assert prepare_history_guard_rollback(root, confirmation=confirmation)["changed"]
    assert not prepare_history_guard_rollback(root, confirmation=confirmation)["changed"]
    with closing(sqlite3.connect(root / "realm.sqlite3")) as copy:
        assert history_guard_manifest(copy)["version"] == 0
        assert canonical_manifest(copy) == before
        assert copy.execute("SELECT * FROM timeline_commit_history ORDER BY publication_id").fetchall() == rows
    with closing(RealmStore(root, admission_timeout=120)) as reopened:
        assert history_guard_manifest(reopened.conn)["version"] == 1
        assert [tuple(row) for row in reopened.conn.execute("SELECT * FROM timeline_commit_history ORDER BY publication_id")] == rows
