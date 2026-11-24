"""SV-L9a real-realm regression: SQLite bookkeeping is not commit authority."""
from __future__ import annotations

import os
import shutil
import sqlite3
import threading
from contextlib import closing

import pytest

from runtime_protocol.errors import RealmAdmissionError
from runtime_protocol.history_verification import DeferredHistoryVerification, history_boundary
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_store import TimelineCommitStore
from test_deferred_history_verification import (
    _history_fixture, _late_deadline, _pending_owner, _wait_state,
)
from test_timeline_commit_port import service  # noqa: F401 (shared fixture)


_PENDING = "verification in progress, retry in a moment"


def _sqlite_paths(root):
    return root / "realm.sqlite3", root / "realm.sqlite3-wal"


def _touch(path):
    """Change mtime (and usually ctime), not inode or contents."""
    before = path.stat()
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 2_000_000_000))
    after = path.stat()
    assert (before.st_dev, before.st_ino, before.st_size) == (
        after.st_dev, after.st_ino, after.st_size
    )
    assert after.st_mtime_ns != before.st_mtime_ns


def _live_commit_authority(runtime):
    with runtime.store._mutex:
        connection = runtime.store.conn
        return (connection.execute("PRAGMA data_version").fetchone()[0],
                connection.total_changes, history_boundary(connection))


@pytest.mark.timeout(120)
def test_metadata_touch_during_60_edit_history_scan_completes_once(service, monkeypatch):
    """Same real history, same owner, no new commit: no second scan."""
    root, project, head, _ = _history_fixture(service, edits=60)
    service.close()
    runtime, release = _pending_owner(root, project, monkeypatch, pause_at=2)
    try:
        assert runtime.get_timeline_verified_head(project, "main", authorize=lambda: None) == head
        pending = runtime.store.history_verification_status()
        assert pending["attempt"] == 1
        assert pending["history_rows_checked"] == 2
        assert pending["history_rows_total"] >= 60
        before = _live_commit_authority(runtime)
        for path in _sqlite_paths(root):
            _touch(path)
        assert _live_commit_authority(runtime) == before
        with pytest.raises(RealmAdmissionError, match=_PENDING):
            runtime.create_project({"slug": "before-touch-proof", "name": "Blocked"})
        release.set()
        complete = _wait_state(runtime, "complete", timeout=60)
        # This fails on e30d4374: the same verified snapshot is discarded
        # solely because the live DB/WAL stat metadata changed.
        assert complete["attempt"] == 1, complete
        assert complete["history_rows_checked"] == complete["history_rows_total"]
        assert runtime.store.admission_report["ok"] is True
        assert runtime.create_project({"slug": "after-touch-proof", "name": "Allowed"})["name"] == "Allowed"
    finally:
        release.set()
        runtime.close()


def test_metadata_touches_during_snapshot_copy_and_writer_fence_do_not_retry(service, monkeypatch):
    root, _, _, _ = _history_fixture(service)
    service.close()
    authority_paths = _sqlite_paths(root)
    copied = []
    at_fence = []
    original_copy = RealmStore._copy_admission_file
    original_authority = DeferredHistoryVerification._authority

    def copy_with_touch(source, destination, deadline, *, _expected_identity=None):
        # Only the actual background detached source copy, not initial
        # admission. Change metadata before the FD check and again before
        # inspect_realm's post-copy path check.
        if _expected_identity is not None and source in authority_paths:
            _touch(source)
            original_copy(source, destination, deadline, _expected_identity=_expected_identity)
            _touch(source)
            copied.append(source)
        else:
            original_copy(source, destination, deadline, _expected_identity=_expected_identity)

    def authority_with_touch(self):
        # Exercise the actual final BEGIN IMMEDIATE fence, not a fabricated
        # equality tuple. The write transaction is held during this sample.
        if self.store.conn.in_transaction:
            for path in authority_paths:
                _touch(path)
                at_fence.append(path)
        return original_authority(self)

    monkeypatch.setattr(RealmStore, "_copy_admission_file", staticmethod(copy_with_touch))
    monkeypatch.setattr(DeferredHistoryVerification, "_authority", authority_with_touch)
    monkeypatch.setattr(TimelineCommitStore, "integrity_errors",
                        _late_deadline(TimelineCommitStore.integrity_errors, lambda *_: None))
    runtime = RuntimeService(root, admission_timeout=120)
    try:
        complete = _wait_state(runtime, "complete", timeout=30)
        assert copied == list(authority_paths)
        assert at_fence == list(authority_paths)
        assert complete["attempt"] == 1
        assert runtime.store.conn.execute("PRAGMA query_only").fetchone()[0] == 0
    finally:
        runtime.close()


@pytest.mark.parametrize("changes", [1, 3], ids=["rescan-once", "exhaust-real-changes"])
def test_other_connection_commits_consume_retry_attempts(service, monkeypatch, changes):
    root, project, _, _ = _history_fixture(service)
    service.close()
    entered = [threading.Event() for _ in range(changes)]
    release = [threading.Event() for _ in range(changes)]
    scans = []

    def progress(checked, total):
        if checked == 0:
            scans.append(total)
        if checked == 1 and len(scans) <= changes:
            index = len(scans) - 1
            entered[index].set()
            if not release[index].wait(30):
                raise TimeoutError("test did not release scan")

    monkeypatch.setattr(TimelineCommitStore, "integrity_errors",
                        _late_deadline(TimelineCommitStore.integrity_errors, progress))
    runtime = RuntimeService(root, admission_timeout=120)
    try:
        for index in range(changes):
            assert entered[index].wait(30), runtime.store.history_verification_status()
            status = runtime.store.history_verification_status()
            assert status["state"] == "pending"
            assert status["attempt"] == index + 1
            before = _live_commit_authority(runtime)
            # A committed update from a distinct SQLite connection: no
            # change to the history heads or to the owner's total_changes.
            with closing(sqlite3.connect(root / "realm.sqlite3", timeout=5)) as writer:
                writer.execute("UPDATE projects SET name=? WHERE id=?", (f"Other writer {index}", project))
                writer.commit()
            after = _live_commit_authority(runtime)
            assert after[0] != before[0]
            assert after[1:] == before[1:]
            with pytest.raises(RealmAdmissionError, match=_PENDING):
                runtime.create_project({"slug": "while-stale", "name": "Blocked"})
            release[index].set()

        if changes == 1:
            complete = _wait_state(runtime, "complete", timeout=30)
            assert len(scans) == complete["attempt"] == 2
            assert runtime.get_project(project)["name"] == "Other writer 0"
            assert runtime.create_project({"slug": "after-rescan", "name": "Allowed"})["name"] == "Allowed"
        else:
            failed = _wait_state(runtime, "failed", timeout=30)
            assert len(scans) == failed["attempt"] == 3
            check = runtime.doctor()["checks"]["history_verification"]
            assert check["reason"] == "verification_retry_limit_exhausted"
            assert check["attempts"] == 3
            assert runtime.store.conn.execute("PRAGMA query_only").fetchone()[0] == 1
            with pytest.raises(RealmAdmissionError, match="history_verification"):
                runtime.create_project({"slug": "after-exhaustion", "name": "Blocked"})
    finally:
        for gate in release:
            gate.set()
        runtime.close()


@pytest.mark.parametrize("suffix", ["", "-wal"], ids=["db-inode", "wal-inode"])
def test_deferred_verification_fails_boot_on_inode_replacement(service, tmp_path, monkeypatch, suffix):
    root, project, _, _ = _history_fixture(service)
    service.close()
    runtime, release = _pending_owner(root, project, monkeypatch)
    try:
        path = root / ("realm.sqlite3" + suffix)
        before = path.stat()
        replacement = tmp_path / "replacement"
        # Byte-identical replacement isolates inode custody from logical
        # changes; do not edit accepted history or change a guard trigger.
        shutil.copyfile(path, replacement)
        try:
            os.replace(replacement, path)
        except PermissionError:
            if os.name != "nt":
                raise
            # Windows can refuse the swap at the OS boundary.
            current = path.stat()
            assert (current.st_dev, current.st_ino) == (before.st_dev, before.st_ino)
            pytest.skip("Windows refused replacement of the open SQLite file")
        after = path.stat()
        assert (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        release.set()
        failed = _wait_state(runtime, "failed", timeout=30)
        assert failed["attempt"] == 1
        report = runtime.doctor()
        assert report["issues"] == ["history_verification"]
        assert "identity changed" in report["checks"]["history_verification"]["reason"]
        assert "restart" in report["recovery_action"].lower()
        with pytest.raises(RealmAdmissionError, match="history_verification"):
            runtime.create_project({"slug": "swapped", "name": "Blocked"})
    finally:
        release.set()
        runtime.close()


def test_offline_inspection_still_refuses_changed_copy_metadata(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    original = RealmStore._copy_admission_file

    def changed_copy(source, destination, deadline, **kwargs):
        original(source, destination, deadline, **kwargs)
        if source == root / "realm.sqlite3":
            _touch(source)

    monkeypatch.setattr(RealmStore, "_copy_admission_file", staticmethod(changed_copy))
    report = RealmStore.inspect_realm(root, timeout_seconds=120, deep=True)
    assert report["state"] == "unhealthy"
    assert report["checks"]["sqlite_integrity"]["reason"] == "unreadable"
    assert "component changed during inspection" in report["checks"]["sqlite_integrity"]["result"]
