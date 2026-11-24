"""SV-L9a: exercise real persisted histories through deferred owner admission."""
from __future__ import annotations

import copy
import json
import multiprocessing
import sqlite3
import threading
import time
import traceback
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest

from astrid_runtime.bootstrap import BootstrapError
from astrid_runtime.workspace import _inspect
from runtime_protocol.cli import main as runtime_main
from runtime_protocol.errors import RealmAdmissionError
from runtime_protocol.history_guards import history_guard_manifest, remove_history_guards
from runtime_protocol.history_verification import may_defer_history
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_store import TimelineCommitStore
from test_timeline_commit_authentication import body, provider
from test_timeline_commit_port import PreparedProvider, commit, service  # noqa: F401 (shared fixture)
from tests.history_forgery import forge_history_row


_PENDING = "verification in progress, retry in a moment"


def _wait_state(runtime, expected, timeout=120):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        status = runtime.store.history_verification_status()
        if status and status["state"] in ("complete", "failed"):
            assert status["state"] == expected, runtime.store.admission_report
            return status
        time.sleep(0.02)
    pytest.fail(f"verification never reached {expected}: {runtime.store.history_verification_status()}")


def _late_deadline(original, on_progress):
    def scan(self, *, deadline=None, errors=None, progress=None):
        if progress is None:
            # Exhaust only the final history traversal's deadline. All other
            # startup checks still execute the production path.
            return original(self, deadline=0, errors=errors)

        def observe(checked, total):
            progress(checked, total)
            on_progress(checked, total)

        return original(self, deadline=deadline, errors=errors, progress=observe)
    return scan


def _register(runtime, project):
    runtime.test_project = project
    runtime.test_provider = PreparedProvider()
    runtime.register_timeline_commit_provider(runtime.test_provider)
    provider(runtime)


def _next(runtime, note):
    request = body(runtime)
    head = runtime.get_timeline_verified_head(runtime.test_project, "main", authorize=lambda: None)
    previous = head["canonical_document"]["parent_revision"]["payload"].get("meta")
    change = request["commands"][0]["args"]["changes"][0]
    if previous is not None:
        change["before"] = {"state": "present", "value": previous}
    change["value"] = {"org.example.timeline": {"note": note}}
    request["steps"][0]["patch"] = [copy.deepcopy(change)]
    return request


def _history_fixture(service, edits=2):
    provider(service)
    accepted = None
    for number in range(edits):
        accepted = commit(service, _next(service, f"note-{number}"), key=f"edit-{number}")
    head = service.get_timeline_verified_head(service.test_project, "main", authorize=lambda: None)
    root, project = service.store.root, service.test_project
    publication = accepted["receipt"]["receipt_id"]
    return root, project, head, publication


def _pending_owner(root, project, monkeypatch, *, pause_at=1):
    reached = threading.Event()
    release = threading.Event()

    def progress(checked, total):
        if checked == pause_at and not reached.is_set():
            reached.set()
            if not release.wait(120):
                raise TimeoutError("test failed to release background verification")

    original = TimelineCommitStore.integrity_errors
    monkeypatch.setattr(TimelineCommitStore, "integrity_errors", _late_deadline(original, progress))
    runtime = RuntimeService(root, admission_timeout=120)
    try:
        _register(runtime, project)
        assert reached.wait(120), runtime.store.history_verification_status()
    except BaseException:
        release.set()
        runtime.close()
        raise
    return runtime, release


def test_pending_owner_reads_guarded_history_then_accepts_writes(service, monkeypatch):
    root, project, head, publication = _history_fixture(service)
    service.close()

    # Recreate a real guard-free U33 image, as an older release may leave it.
    with closing(sqlite3.connect(root / "realm.sqlite3", isolation_level=None)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        assert remove_history_guards(connection)
        connection.commit()
        assert history_guard_manifest(connection)["version"] == 0

    runtime, release = _pending_owner(root, project, monkeypatch)
    try:
        assert runtime.health()["status"] == "ok"
        assert runtime.get_project(project)["id"] == project
        assert runtime.get_timeline_verified_head(project, "main", authorize=lambda: None) == head
        assert runtime.store.conn.execute("PRAGMA query_only").fetchone()[0] == 1
        assert history_guard_manifest(runtime.store.conn)["version"] == 1
        with closing(sqlite3.connect(root / "realm.sqlite3", isolation_level=None)) as writer:
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                writer.execute("UPDATE timeline_commit_history SET records_json=records_json WHERE publication_id=?", (publication,))
        report = runtime.doctor()
        assert report["verification"]["state"] == "pending"
        assert report["verification"]["history_rows_checked"] == 1
        assert report["verification"]["history_rows_total"] >= 3
        assert _PENDING in report["message"]
        assert report["issues"] == []
        with pytest.raises(RealmAdmissionError, match=_PENDING):
            runtime.create_project({"slug": "blocked", "name": "Blocked"})
        request = _next(runtime, "after-verification")
        with pytest.raises(RealmAdmissionError, match=_PENDING):
            commit(runtime, request, key="after")
        with pytest.raises(RealmAdmissionError, match=_PENDING):
            runtime.stage_object([b"blocked"])
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            runtime.store.conn.execute("UPDATE projects SET name='blocked' WHERE id=?", (project,))
        release.set()
        complete = _wait_state(runtime, "complete")
        assert complete["history_rows_checked"] == complete["history_rows_total"]
        assert runtime.store.admission_report["ok"] is True
        assert runtime.store.conn.execute("PRAGMA query_only").fetchone()[0] == 0
        assert commit(runtime, request, key="after")["data"]["status"] == "accepted"
        assert runtime.create_project({"slug": "allowed", "name": "Allowed"})["name"] == "Allowed"
    finally:
        release.set()
        runtime.close()


def test_changed_live_authority_restarts_without_lifting_gate(service, monkeypatch):
    root, project, _, _ = _history_fixture(service)
    service.close()
    entered = [threading.Event(), threading.Event()]
    release = [threading.Event(), threading.Event()]
    attempts = 0

    def progress(checked, total):
        nonlocal attempts
        if checked == 0:
            attempts += 1
        if checked == 1 and attempts <= 2:
            entered[attempts - 1].set()
            if not release[attempts - 1].wait(120):
                raise TimeoutError("test failed to release scan")

    monkeypatch.setattr(TimelineCommitStore, "integrity_errors",
                        _late_deadline(TimelineCommitStore.integrity_errors, progress))
    runtime = RuntimeService(root, admission_timeout=120)
    try:
        assert entered[0].wait(120), runtime.store.history_verification_status()
        # A non-cooperating SQLite writer moves the data_version but not the
        # history heads/sequence. An older successful detached scan is stale.
        with closing(sqlite3.connect(root / "realm.sqlite3", isolation_level=None)) as writer:
            writer.execute("UPDATE projects SET name='Moved during scan' WHERE id=?", (project,))
        release[0].set()
        assert entered[1].wait(120), runtime.store.history_verification_status()
        assert runtime.store.history_verification_status()["state"] == "pending"
        with pytest.raises(RealmAdmissionError, match=_PENDING):
            runtime.create_project({"slug": "not-yet", "name": "Not yet"})
        release[1].set()
        _wait_state(runtime, "complete")
        assert runtime.get_project(project)["name"] == "Moved during scan"
        assert runtime.create_project({"slug": "after", "name": "After"})["name"] == "After"
    finally:
        for gate in release:
            gate.set()
        runtime.close()


def test_late_real_corruption_keeps_unaffected_reads_and_named_write_refusal(service, monkeypatch):
    root, project, _, publication = _history_fixture(service)
    service.create_timeline(project, "unaffected", name="Unaffected", idempotency_key="other")
    unaffected = service.get_timeline_verified_head(project, "unaffected", authorize=lambda: None)
    service.close()
    with closing(sqlite3.connect(root / "realm.sqlite3", isolation_level=None)) as writer:
        forge_history_row(writer, "UPDATE timeline_commit_history SET records_json='{}' WHERE publication_id=?", (publication,))
        assert history_guard_manifest(writer)["version"] == 1
    runtime, release = _pending_owner(root, project, monkeypatch)
    try:
        assert runtime.get_timeline_verified_head(project, "unaffected", authorize=lambda: None) == unaffected
        release.set()
        _wait_state(runtime, "failed")
        report = runtime.doctor()
        assert report["issues"] == ["revisions"]
        assert any(row["id"] == publication for row in report["checks"]["revisions"]["errors"])
        assert "verified backup" in report["recovery_action"]
        with pytest.raises(RealmAdmissionError, match="revisions") as refusal:
            runtime.create_project({"slug": "not-writable", "name": "Not writable"})
        assert "verified backup" in str(refusal.value)
        assert runtime.store.conn.execute("PRAGMA query_only").fetchone()[0] == 1
        assert runtime.get_timeline_verified_head(project, "unaffected", authorize=lambda: None) == unaffected
    finally:
        release.set()
        runtime.close()
    assert json.loads((root / "admission-state.json").read_text())["clean_shutdown"] is False


def test_only_late_history_incomplete_is_eligible(service, monkeypatch):
    root, _, _, _ = _history_fixture(service)
    service.close()
    monkeypatch.setattr(TimelineCommitStore, "integrity_errors",
                        _late_deadline(TimelineCommitStore.integrity_errors, lambda *_: None))
    report = RealmStore.inspect_realm(root, deep=True, timeout_seconds=120)
    assert may_defer_history(report, root)
    boundary = SimpleNamespace(inspect=lambda *, realm_root: report)
    # Candidate attach is not read-only owner startup.
    with pytest.raises(BootstrapError, match="Verification incomplete"):
        _inspect(boundary, root)
    assert _inspect(boundary, root, allow_deferred=True)[0] == report["checks"]["realm_identity"]["realm_id"]
    for name in ("schema", "realm_identity", "history_guards", "reachable_cas", "relational", "activation"):
        damaged = copy.deepcopy(report)
        damaged["checks"][name]["ok"] = False
        assert not may_defer_history(damaged, root), name
    legacy = copy.deepcopy(report)
    legacy["history_deferral_eligible"] = False
    assert not may_defer_history(legacy, root)
    mixed = copy.deepcopy(report)
    mixed["issues"] = ["revisions"]
    assert not may_defer_history(mixed, root)
    assert not may_defer_history(RealmStore.inspect_realm(root, timeout_seconds=0), root)
    with pytest.raises(RealmAdmissionError, match="Verification incomplete"):
        RealmStore(root, acquire_owner=False, admission_timeout=120)
    store = RealmStore(root, admission_timeout=120, _start_history_verification=False)
    try:
        with store._verification_boot_writes():
            with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
                store.conn.execute("UPDATE command_idempotency SET result_json='{}'")
        assert store.conn.execute("PRAGMA query_only").fetchone()[0] == 1
    finally:
        store.close()
    assert json.loads((root / "admission-state.json").read_text())["clean_shutdown"] is False


def _kill_scan_child(root, project, release, messages):
    original = TimelineCommitStore.integrity_errors
    reached = threading.Event()

    def progress(checked, total):
        if checked == 2 and not reached.is_set():
            reached.set()
            if not release.wait(180):
                raise TimeoutError("test failed to release child scan")

    TimelineCommitStore.integrity_errors = _late_deadline(original, progress)
    runtime = None
    try:
        runtime = RuntimeService(root, admission_timeout=120)
        _register(runtime, project)
        assert reached.wait(120)
        head = runtime.get_timeline_verified_head(project, "main", authorize=lambda: None)
        request = _next(runtime, "after-kill")
        with pytest.raises(RealmAdmissionError, match=_PENDING):
            commit(runtime, request, key="after-kill")
        progress_report = runtime.doctor()["verification"]
        messages.put(("readable", head["head"], progress_report, runtime.runtime_lifecycle()["runtime_epoch"]))
        assert release.wait(180)
        _wait_state(runtime, "complete")
        assert commit(runtime, request, key="after-kill")["data"]["status"] == "accepted"
        messages.put(("writable", runtime.store.history_verification_status()))
    except BaseException:
        messages.put(("error", traceback.format_exc()))
        raise
    finally:
        if runtime is not None:
            runtime.close()


def test_kill_mid_scan_restarts_large_history_and_enables_writes_only_after_proof(service):
    root, project, head, _ = _history_fixture(service, edits=60)
    service.close()
    context = multiprocessing.get_context("spawn")
    first_epoch = None
    for killed in (True, False):
        release = context.Event()
        messages = context.Queue()
        child = context.Process(target=_kill_scan_child, args=(str(root), project, release, messages))
        child.start()
        try:
            result = messages.get(timeout=180)
            assert result[0] == "readable", result
            assert result[1] == head["head"]
            assert result[2]["state"] == "pending"
            assert result[2]["history_rows_checked"] == 2
            assert result[2]["history_rows_total"] >= 60
            if killed:
                first_epoch = result[3]
                child.kill()
                child.join(30)
                assert child.exitcode is not None and child.exitcode != 0
                assert json.loads((Path(root) / "admission-state.json").read_text())["clean_shutdown"] is False
            else:
                assert result[3] > first_epoch
                release.set()
                result = messages.get(timeout=180)
                assert result[0] == "writable", result
                assert result[1]["state"] == "complete"
                child.join(30)
                assert child.exitcode == 0
        finally:
            release.set()
            if child.is_alive():
                child.kill()
                child.join(30)
            messages.close()
            messages.join_thread()
    assert json.loads((Path(root) / "admission-state.json").read_text())["clean_shutdown"] is True


def test_repeated_incomplete_background_scans_end_in_named_refusal(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    original = TimelineCommitStore.integrity_errors
    background_attempts = []

    def expired(self, *, deadline=None, errors=None, progress=None):
        if progress is not None:
            background_attempts.append(deadline)
        # Exercise the real traversal's deadline signal, not a generic
        # TimeoutError raised by an unrelated row or storage operation.
        return original(self, deadline=0, errors=errors, progress=progress)

    monkeypatch.setattr(TimelineCommitStore, "integrity_errors", expired)
    runtime = RuntimeService(root, admission_timeout=120)
    try:
        status = _wait_state(runtime, "failed")
        assert len(background_attempts) == 3
        assert status["attempt"] == 3
        report = runtime.doctor()
        assert report["issues"] == ["history_verification"]
        check = report["checks"]["history_verification"]
        assert check["reason"] == "verification_retry_limit_exhausted"
        assert check["attempts"] == 3
        assert "rerun doctor" in report["recovery_action"]
        assert "restore" not in report["recovery_action"].lower()
        assert runtime.store.conn.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(RealmAdmissionError, match="history_verification"):
            runtime.create_project({"slug": "blocked", "name": "Blocked"})
    finally:
        runtime.close()
    assert json.loads((root / "admission-state.json").read_text())["clean_shutdown"] is False


@pytest.mark.parametrize("command", ["backup", "export", "purge"])
def test_offline_cli_refuses_even_eligible_incomplete_history(tmp_path, monkeypatch, command):
    root = tmp_path / "realm"
    destination = tmp_path / "output"
    with RealmStore.initialize(root, realm_id="offline-strict") as store:
        store.tombstone_realm()
    original = TimelineCommitStore.integrity_errors
    monkeypatch.setattr(TimelineCommitStore, "integrity_errors",
                        _late_deadline(original, lambda *_: None))
    report = RealmStore.inspect_realm(root, deep=True, timeout_seconds=120)
    assert may_defer_history(report, root)
    before = (root / "admission-state.json").read_bytes()

    from runtime_protocol.history_verification import DeferredHistoryVerification

    def unexpected_background(self):
        pytest.fail("offline command attempted to start deferred verification")

    monkeypatch.setattr(DeferredHistoryVerification, "start", unexpected_background)
    arguments = ["--confirm", "PURGE offline-strict"] if command == "purge" else [
        "--destination", str(destination)
    ]
    with pytest.raises(RealmAdmissionError, match="Verification incomplete") as refused:
        runtime_main([command, "--root", str(root), *arguments])
    assert refused.value.details["history_deferral_eligible"] is True
    assert (root / "realm.sqlite3").is_file()
    assert (root / "admission-state.json").read_bytes() == before
    assert not destination.exists()
