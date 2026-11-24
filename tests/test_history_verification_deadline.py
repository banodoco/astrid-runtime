"""SV-L9a: timeout classification, without treating unscanned rows as corrupt."""
import sqlite3
from types import SimpleNamespace

import pytest

from runtime_protocol import timeline_commit_store as history_module
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_store import TimelineCommitStore


@pytest.mark.parametrize("bad_first", [False, True])
def test_history_scan_stops_on_sqlite_deadline_and_keeps_real_errors(bad_first):
    # Use the scan body directly with a minimal SQLite history. The doctor
    # installs its progress handler on the same connection in production.
    with sqlite3.connect(":memory:") as connection:
        connection.row_factory = sqlite3.Row
        connection.executescript("""
            CREATE TABLE timeline_commit_history(
                project_id, timeline_id, project_seq, previous_publication_id,
                previous_revision_id, publication_id, revision_id, intent, records_json
            );
            CREATE TABLE command_idempotency(txn_id, first_project_seq, command_kind);
            CREATE TABLE parent_composition_heads(project_id, timeline_id, publication_id, revision_id);
            CREATE TABLE timeline_document_input_contents(content_digest, content_json, content_size);
            CREATE TABLE timeline_document_input_links(publication_id, project_id, timeline_id, revision_id);
            INSERT INTO timeline_commit_history VALUES ('p','t',1,NULL,NULL,'a','ra','legacy',NULL);
            INSERT INTO timeline_commit_history VALUES ('p','t',2,'a','ra','b','rb','legacy',NULL);
            INSERT INTO timeline_commit_history VALUES ('p','t',3,'b','rb','c','rc','legacy',NULL);
            INSERT INTO command_idempotency VALUES ('a',1,'parent_composition.publish');
            INSERT INTO command_idempotency VALUES ('b',2,'parent_composition.publish');
            INSERT INTO command_idempotency VALUES ('c',3,'parent_composition.publish');
        """)
        if bad_first:
            connection.execute("DELETE FROM command_idempotency WHERE txn_id='a'")
        seen = []

        class Reader:
            def execute(self, query, parameters=()):
                if query.startswith("SELECT * FROM command_idempotency"):
                    seen.append(parameters[0])
                    if parameters == ("b",):
                        # A real SQLite progress-handler interruption, not an
                        # exception with a forged message.
                        connection.set_progress_handler(lambda: 1, 1)
                try:
                    return connection.execute(query, parameters)
                finally:
                    connection.set_progress_handler(None, 0)

        errors = []
        with pytest.raises(sqlite3.OperationalError) as exc:
            TimelineCommitStore.integrity_errors.__wrapped__(SimpleNamespace(conn=Reader()), errors=errors)
        assert exc.value.sqlite_errorcode == sqlite3.SQLITE_INTERRUPT
        assert seen == ["a", "b"]
        assert [error["id"] for error in errors] == (["a"] if bad_first else [])


@pytest.mark.parametrize("bad_first", [False, True])
def test_doctor_preserves_known_failure_on_incomplete_history(tmp_path, monkeypatch, bad_first):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()

    def interrupted(self, *, deadline, errors):
        if bad_first:
            errors.append({"table": "timeline_commit_history", "id": "bad", "reason": "history receipt missing or ambiguous"})
        raise TimeoutError("history verification incomplete")

    monkeypatch.setattr(history_module.TimelineCommitStore, "integrity_errors", interrupted)
    report = RealmStore.inspect_realm(root, deep=True)
    assert report["ok"] is False
    assert report["verification_incomplete"] is True
    assert report["checks"]["deep_verification"]["verified_at"] is None
    if bad_first:
        assert report["state"] == "unhealthy"
        assert report["issues"] == ["revisions"]
        assert report["checks"]["revisions"]["ok"] is False
        assert report["checks"]["revisions"]["errors"][0]["id"] == "bad"
        assert "verified backup" in report["recovery_action"]
    else:
        assert report["state"] == "not_checked"
        assert report["issues"] == []
        assert report["checks"]["revisions"]["ok"] is None
        assert report["checks"]["revisions"]["errors"] == []
        assert "Verification incomplete" in report["recovery_action"]
        assert "backup" not in report["recovery_action"]
