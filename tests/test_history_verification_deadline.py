"""SV-L9a: timeout classification, without treating unscanned rows as corrupt."""
import sqlite3
import threading
from types import SimpleNamespace

import pytest

from astrid_runtime.bootstrap import BootstrapError
from astrid_runtime.workspace import _inspect
from runtime_protocol import cancellation, timeline_commit_store as history_module
from runtime_protocol.errors import IntegrityDeadlineExceeded, RealmAdmissionError
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_store import TimelineCommitStore
from test_timeline_commit_authentication import body, provider
from test_timeline_commit_port import commit, service  # noqa: F401 (shared fixture)
from test_timeline_verified_reads import next_request


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
        raise IntegrityDeadlineExceeded("history verification incomplete")

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


def test_real_history_deadline_after_first_record_is_one_incomplete_report(service, monkeypatch):
    provider(service)
    first = commit(service, body(service))
    second = commit(service, next_request(service), key="second")
    root = service.store.root
    first_id = first["receipt"]["receipt_id"]
    second_id = second["receipt"]["receipt_id"]
    service.close()
    assert RealmStore.inspect_realm(root, deep=True)["ok"] is True

    original = TimelineCommitStore._verify_accepted
    expired = False
    seen = []

    def verify(self, receipt, edge, *args, **kwargs):
        nonlocal expired
        result = original(self, receipt, edge, *args, **kwargs)
        seen.append(edge["publication_id"])
        if edge["publication_id"] == first_id:
            expired = True
        return result

    def monotonic():
        # The doctor keeps its genuine SQLite deadline; force this traversal
        # to observe that deadline immediately after one complete recorded row.
        return float("inf") if expired else 0.0

    monkeypatch.setattr(history_module, "time", SimpleNamespace(monotonic=monotonic))
    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted", verify)
    report = RealmStore.inspect_realm(root, deep=True)
    assert first_id in seen
    assert second_id not in seen
    assert report["ok"] is False
    assert report["state"] == "not_checked"
    assert report["verification_incomplete"] is True
    assert report["issues"] == []
    assert report["checks"]["revisions"]["errors"] == []
    assert "Verification incomplete" in report["recovery_action"]
    assert "backup" not in report["recovery_action"]

    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted", original)
    expired = False
    assert RealmStore.inspect_realm(root, deep=True)["ok"] is True


def test_cancelled_scan_propagates_cancellation(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    cancelled = threading.Event()

    def interrupted(self, *, deadline, errors):
        cancelled.set()
        cancellation.check()

    monkeypatch.setattr(TimelineCommitStore, "integrity_errors", interrupted)
    with cancellation.startup_scope(cancelled):
        with pytest.raises(cancellation.StartupCancelled):
            RealmStore.inspect_realm(root, deep=True)


def test_named_check_and_recovery_survive_startup_refusal(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()

    def damaged(self, *, deadline, errors):
        errors.append({"table": "timeline_commit_history", "id": "bad", "reason": "history receipt missing or ambiguous"})
        return errors

    monkeypatch.setattr(TimelineCommitStore, "integrity_errors", damaged)
    with pytest.raises(RealmAdmissionError, match="revisions") as refusal:
        RealmStore(root)
    assert "verified backup" in str(refusal.value)
    assert refusal.value.details["checks"]["revisions"]["errors"][0]["id"] == "bad"
    boundary = SimpleNamespace(inspect=lambda *, realm_root: RealmStore.inspect_realm(realm_root))
    with pytest.raises(BootstrapError, match="revisions") as workspace_refusal:
        _inspect(boundary, root)
    assert "verified backup" in str(workspace_refusal.value)


def test_premature_row_timeout_is_a_named_revision_error(service, monkeypatch):
    """An I/O timeout inside one row is not expiry of the scan's own budget."""
    provider(service)
    accepted = commit(service, body(service))
    publication = accepted["receipt"]["receipt_id"]
    root = service.store.root
    service.close()
    original = TimelineCommitStore._verify_accepted

    def timed_out(self, receipt, edge, *args, **kwargs):
        if edge["publication_id"] == publication:
            raise TimeoutError("storage read timed out before the verification deadline")
        return original(self, receipt, edge, *args, **kwargs)

    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted", timed_out)
    report = RealmStore.inspect_realm(root, deep=True, timeout_seconds=120)
    assert report["state"] == "unhealthy"
    assert report["ok"] is False
    assert report["issues"] == ["revisions"]
    assert not report.get("history_deferral_eligible", False)
    assert not report.get("verification_incomplete", False)
    assert any(row["id"] == publication and "storage read timed out" in row["reason"]
               for row in report["checks"]["revisions"]["errors"])
    with pytest.raises(RealmAdmissionError, match="revisions"):
        RealmStore(root, admission_timeout=120)


def test_premature_traversal_timeout_refuses_with_named_check(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()

    def timed_out(self, *, deadline, errors):
        raise TimeoutError("history query I/O timed out")

    monkeypatch.setattr(TimelineCommitStore, "integrity_errors", timed_out)
    report = RealmStore.inspect_realm(root, deep=True, timeout_seconds=120)
    assert report["state"] == "unhealthy"
    assert report["issues"] == ["revisions"]
    assert report["checks"]["revisions"]["errors"] == [
        {"table": "timeline_commit_history", "reason": "history query I/O timed out"}
    ]
    assert not report.get("history_deferral_eligible", False)


def test_premature_cas_timeout_names_cas_check(service, monkeypatch):
    root = service.store.root
    service.ingest(service.test_project, b"retained test object", media_type="application/octet-stream",
                   idempotency_key="timeout-fixture")
    service.close()

    def timed_out(self, digest, *, deadline=None):
        raise TimeoutError("CAS storage I/O timed out")

    monkeypatch.setattr(RealmStore, "_cas_digest", timed_out)
    report = RealmStore.inspect_realm(root, deep=True, timeout_seconds=120)
    assert report["state"] == "unhealthy"
    assert report["issues"] == ["reachable_cas"]
    assert report["checks"]["reachable_cas"]["errors"][0]["reason"] == "read_timeout"
    assert "CAS storage read timeout" in report["recovery_action"]
    assert not report.get("history_deferral_eligible", False)


def test_premature_snapshot_copy_timeout_is_not_deadline(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()

    def timed_out(*args, **kwargs):
        raise TimeoutError("source file I/O timed out")

    monkeypatch.setattr(RealmStore, "_copy_admission_file", staticmethod(timed_out))
    report = RealmStore.inspect_realm(root, timeout_seconds=120)
    assert report["state"] == "unhealthy"
    assert report["issues"] == ["sqlite_integrity"]
    assert "source file I/O timed out" in report["checks"]["sqlite_integrity"]["result"]
