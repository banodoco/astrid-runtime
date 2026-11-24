"""Owner-local, non-durable continuation of an incomplete startup history scan.

The normal detached doctor still decides integrity. This coordinator only
permits a tightly classified read-only owner and publishes write admission
after comparing the exact verified detached image with the live authority.
"""
from __future__ import annotations

import copy
import logging
import sqlite3
import stat
import threading
from contextlib import contextmanager

from . import cancellation
from .errors import RealmAdmissionError
from .history_guards import history_guard_manifest

_LOG = logging.getLogger(__name__)
_PENDING = "verification in progress, retry in a moment"


def may_defer_history(report, root):
    """Never treat a generic timeout, failed check or legacy activation as safe."""
    if not (report.get("state") == "not_checked"
            and report.get("verification_incomplete") is True
            and report.get("history_deferral_eligible") is True
            and report.get("issues") == []
            and report.get("ok") is False):
        return False
    checks = report.get("checks", {})
    if not all(checks.get(key, {}).get("ok") is True for key in (
        "sqlite_integrity", "foreign_keys", "schema", "realm_identity",
        "reachable_cas", "event_chain", "relational", "catalog", "activation",
        "history_guards",
    )):
        return False
    guard = checks["history_guards"]
    if (guard.get("version"), guard.get("state")) not in ((0, "absent"), (1, "installed")):
        return False
    revisions = checks.get("revisions", {})
    if not (revisions.get("reason") == "timeout" and revisions.get("ok") is None
            and revisions.get("errors") == []):
        return False
    from .v33_lifecycle import MARKER, activation

    marker = root / MARKER
    if marker.is_symlink():
        return False
    state = activation(root)
    return state is None or state[1].get("state") == "ready"


def history_boundary(connection):
    """Logical authority of the exact SQLite image inspected, not a watermark."""
    return (
        tuple(tuple(row) for row in connection.execute(
            "SELECT id FROM realm ORDER BY id")),
        tuple(tuple(row) for row in connection.execute(
            "SELECT project_id, timeline_id, publication_id, revision_id "
            "FROM parent_composition_heads ORDER BY project_id, timeline_id")),
        tuple(tuple(row) for row in connection.execute(
            "SELECT project_id, next_seq FROM project_sequences ORDER BY project_id")),
        history_guard_manifest(connection),
    )


def _file_identity(path):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError("SQLite authority component is not a regular file")
    return (metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


class DeferredHistoryVerification:
    def __init__(self, store):
        self.store = store
        self._stop = threading.Event()
        self._thread = None
        self._status = {"state": "pending", "message": _PENDING,
                        "history_rows_checked": 0, "history_rows_total": None,
                        "phase": "waiting_for_boot"}

    @property
    def status(self):
        # Publish immutable replacement dictionaries, never mutable scan state.
        return dict(self._status)

    def assert_writable(self):
        state = self._status["state"]
        if state == "complete":
            return
        if state == "pending":
            raise RealmAdmissionError(_PENDING, details={"verification": self.status})
        report = self.store.admission_report
        checks = ", ".join(report.get("issues", [])) or "history_verification"
        raise RealmAdmissionError(
            f"realm failed {checks} check: {report.get('recovery_action', '')}",
            details=report,
        )

    def doctor(self):
        result = copy.deepcopy(self.store.admission_report)
        result["verification"] = self.status
        if self._status["state"] == "pending":
            result["message"] = _PENDING
            result["next_action"] = result["recovery_action"] = _PENDING
        return result

    @contextmanager
    def boot_writes(self):
        """Permit only the internal startup transaction, never history/receipts."""
        store = self.store
        with store._mutex:
            if self._thread is not None or self._status["state"] != "pending":
                raise RealmAdmissionError("deferred verification boot scope is closed")
            if getattr(store, "_history_boot_writes", False):
                raise RealmAdmissionError("nested verification boot scope")
            connection = store.conn

            def authorize(action, table, column, database, source):
                if action in (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE):
                    if database == "main" and (
                        table in {"command_idempotency", "project_sequences",
                                  "shot_revisions", "internal_timeline_revisions"}
                        or table.startswith(("timeline_", "parent_composition_", "composition_revision_"))
                    ):
                        return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            connection.execute("PRAGMA query_only=OFF")
            connection.set_authorizer(authorize)
            store._history_boot_writes = True
            try:
                yield
            finally:
                store._history_boot_writes = False
                connection.set_authorizer(None)
                connection.execute("PRAGMA query_only=ON")

    def start(self):
        with self.store._mutex:
            if self._thread is not None or self._stop.is_set():
                return
            self._thread = threading.Thread(target=self._run, daemon=True,
                                            name="astrid-history-verification")
            self._thread.start()

    def stop(self):
        self._stop.set()
        # The scan owns only a detached connection. If cancellation is inside a
        # long Python validation, it must never publish after close begins.
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)

    def _authority(self):
        store = self.store
        root = store.root.lstat()
        if not stat.S_ISDIR(root.st_mode):
            raise OSError("realm directory authority changed")
        connection = store.conn
        return (
            (root.st_dev, root.st_ino), id(connection),
            _file_identity(store.db_path),
            _file_identity(store.db_path.with_name(store.db_path.name + "-wal")),
            connection.execute("PRAGMA data_version").fetchone()[0],
            connection.total_changes, history_boundary(connection),
        )

    def _progress(self, checked, total):
        cancellation.check()
        self._status = {**self._status, "phase": "history",
                        "history_rows_checked": checked, "history_rows_total": total}

    def _failure(self, reason, recovery):
        return {"ok": False, "state": "unhealthy", "status": "failed",
                "issues": ["history_verification"],
                "checks": {"history_verification": {"ok": False, "reason": reason}},
                "recovery_action": recovery, "next_action": recovery}

    def _publish_failure(self, report):
        with self.store._mutex:
            if self._stop.is_set() or self.store.conn is None:
                return
            self.store.conn.execute("PRAGMA query_only=ON")
            self.store.admission_report = report
            self._status = {**self._status, "state": "failed", "phase": "failed",
                            "message": "realm failed " + (", ".join(report.get("issues", [])) or "history_verification") + " check"}

    def _run(self):
        store = self.store
        budget = max(3600.0, store.admission_timeout * 2)
        try:
            with cancellation.startup_scope(self._stop):
                while not self._stop.is_set():
                    self._status = {**self._status, "phase": "snapshot",
                                    "history_rows_checked": 0, "history_rows_total": None}
                    with store._mutex:
                        cancellation.check()
                        before = self._authority()
                    # No primary mutex while copying and checking the isolated
                    # query-only image, including all history and CAS checks.
                    report = store.inspect_realm(
                        store.root, deep=True, timeout_seconds=budget,
                        allow_active_marker=False, _history_progress=self._progress,
                    )
                    observed = report.pop("_snapshot_history_authority", None)
                    with store._mutex:
                        cancellation.check()
                        if self._authority() != before:
                            continue  # Re-scan, never certify a moved store.
                        if report.get("state") == "not_checked":
                            budget = min(budget * 2, 86400.0)
                            continue
                        if not report.get("ok"):
                            self._publish_failure(report)
                            return
                        if observed != before[-1] or observed[-1]["version"] != 1:
                            self._publish_failure(self._failure(
                                "verified_snapshot_authority_mismatch",
                                "Restart Runtime and rerun doctor against the current realm.",
                            ))
                            return
                        # Exclude even a concurrent SQLite writer while
                        # rechecking the authority and opening the write gate.
                        # The normal lifetime owner fence stays held throughout.
                        connection = store.conn
                        connection.execute("PRAGMA query_only=OFF")
                        try:
                            connection.execute("BEGIN IMMEDIATE")
                            try:
                                if self._authority() != before:
                                    continue
                                cancellation.check()
                                store.admission_report = report
                                store._write_admission_state(clean=False)
                                cancellation.check()
                            finally:
                                connection.rollback()
                            cancellation.check()
                            self._status = {**self._status, "state": "complete",
                                            "phase": "complete", "message": "verification complete"}
                        finally:
                            if self._status["state"] != "complete":
                                connection.execute("PRAGMA query_only=ON")
                        if self._status["state"] == "complete":
                            return
        except cancellation.StartupCancelled:
            return
        except Exception as exc:
            _LOG.exception("Deferred startup history verification failed")
            self._publish_failure(self._failure(
                type(exc).__name__ + ": " + str(exc),
                "Restart Runtime and rerun doctor; verification did not complete.",
            ))
