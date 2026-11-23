"""Opt-in, bounded provenance for timeline replay-memo diagnostics.

This diagnostic records SQL *attempt shapes* only. It never stores SQL text,
parameters, exception messages, filesystem paths, or database identities. The
acceptance wrapper supplies the actual transaction outcome separately.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
import traceback

_SQL_WRITE = re.compile(r"^\s*(INSERT(?:\s+OR\s+\w+)?\s+INTO|REPLACE\s+INTO|UPDATE(?:\s+OR\s+\w+)?|DELETE\s+FROM)\s+([A-Za-z_][A-Za-z0-9_]*)", re.I)
_SQL_TX = re.compile(r"^\s*(BEGIN|COMMIT|END|ROLLBACK|SAVEPOINT|RELEASE)\b", re.I)
_KNOWN_TABLES = frozenset({
    "tasks", "reservations", "executors", "attempts", "events", "command_idempotency",
    "timeline_commits", "timeline_commit_events", "timeline_commit_objects",
    "timeline_commit_materializations", "timeline_composition_revisions",
    "timeline_shot_revisions", "timeline_internal_revisions", "timeline_head",
    "timeline_heads", "objects", "projects", "timelines", "clips", "media",
})
_MAX_EVENTS = 384
_MAX_BYTES = 2 * 1024 * 1024


def _caller():
    for frame in reversed(traceback.extract_stack(limit=24)[:-2]):
        filename = frame.filename.replace("\\", "/").rsplit("/", 1)[-1]
        if filename != "_timeline_memo_trace.py":
            return {"file": filename[:80], "function": frame.name[:80], "line": frame.lineno}
    return {"unknown": True}


def _route(handler):
    """Return a fixed route label; never retain user-supplied path components."""
    method = getattr(handler, "command", "?")
    try:
        from urllib.parse import urlsplit
        pieces = [part for part in urlsplit(getattr(handler, "path", "")).path.split("/") if part]
    except Exception:
        return "unknown"
    if len(pieces) == 6 and pieces[:2] == ["v1", "projects"] and pieces[2] and pieces[3] == "timelines":
        if pieces[5] == "commit" and method == "POST":
            return "timeline_commit_post"
        if pieces[5] in ("commits", "verified-head") and method == "GET":
            return "timeline_history_get"
    return "other_http_route"


class TimelineMemoTrace:
    def __init__(self, connection: sqlite3.Connection, path: str):
        self.connection = connection
        self.path = path
        self.lock = threading.Lock()
        self.events = []
        self.sequence = 0
        self.flushed_sequence = 0
        self.overflow = False
        self.unknown_seen = False
        self.bytes_written = 0
        self.disabled = False
        self.closed = False
        self.connection_replaced = False
        self.transaction_sequence = 0
        self.transaction_local = threading.local()
        self.request_sequence = 0
        # Exclusive creation avoids appending to stale evidence or following a
        # symlink. Operators must choose a fresh evidence path for each run.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        self.fd = fd
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        connection.set_trace_callback(self._trace)

    def _append(self, event):
        with self.lock:
            if self.disabled:
                return
            self.sequence += 1
            if len(self.events) >= _MAX_EVENTS:
                self.events.pop(0)
                self.overflow = True
            event = {"seq": self.sequence, "monotonic_ns": time.monotonic_ns(), **event}
            self.events.append(event)

    @property
    def current_transaction_id(self):
        stack = getattr(self.transaction_local, "stack", ())
        return stack[-1]["id"] if stack else None

    def transaction_started(self, kind):
        with self.lock:
            self.transaction_sequence += 1
            transaction_id = self.transaction_sequence
        stack = list(getattr(self.transaction_local, "stack", ()))
        parent_id = stack[-1]["id"] if stack else None
        stack.append({"id": transaction_id, "parent_id": parent_id})
        self.transaction_local.stack = stack
        self._append({"kind": "transaction_scope_started", "transaction_id": transaction_id,
                      "parent_transaction_id": parent_id, "scope": kind})
        return transaction_id

    @property
    def current_request_id(self):
        return getattr(self.transaction_local, "request_id", None)

    def request_started(self, handler):
        with self.lock:
            self.request_sequence += 1
            request_id = self.request_sequence
        self.transaction_local.request_id = request_id
        self._append({"kind": "request_scope_started", "request_id": request_id,
                      "route": _route(handler)})
        return request_id

    def request_finished(self, request_id):
        self._append({"kind": "request_scope_finished", "request_id": request_id})
        if self.current_request_id == request_id:
            self.transaction_local.request_id = None

    def transaction_finished(self, transaction_id, outcome, *, exception_class=None):
        stack = list(getattr(self.transaction_local, "stack", ()))
        if not stack or stack[-1]["id"] != transaction_id:
            self.unknown_seen = True
            self._append({"kind": "transaction_scope_mismatch", "transaction_id": transaction_id,
                          "unknown": True})
        else:
            stack.pop()
            self.transaction_local.stack = stack
        if outcome in ("rollback_failed", "savepoint_rollback_failed"):
            self.unknown_seen = True
        self._append({"kind": "transaction_outcome", "transaction_id": transaction_id,
                      "outcome": outcome, "exception_class": exception_class,
                      "connection_in_transaction": bool(self.connection.in_transaction)})

    def rebind_connection(self, connection):
        self.connection_replaced = True
        self.unknown_seen = True
        self.connection = connection
        connection.set_trace_callback(self._trace)
        self._append({"kind": "trace_connection_rebound", "coverage_gap": True,
                      "unknown": True})
        self.flush()

    def _trace(self, sql):
        # SQLite passes expanded SQL here. Parse only a fixed verb/table shape;
        # expanded text is intentionally never copied, logged, or formatted.
        try:
            write = _SQL_WRITE.match(sql)
            tx = _SQL_TX.match(sql)
            if write:
                raw_table = write.group(2).lower()
                kind = write.group(1).split()[0].upper()
                table = raw_table if raw_table in _KNOWN_TABLES else "other_or_unknown"
                transaction_id = self.current_transaction_id
                if transaction_id is None:
                    self.unknown_seen = True
                request_id = self.current_request_id
                if request_id is None:
                    self.unknown_seen = True
                self._append({"kind": "sql_attempt", "verb": kind, "table": table,
                              "caller": _caller(), "transaction_id": transaction_id,
                              "request_id": request_id,
                              "transaction_correlation": "observed" if transaction_id is not None else "unknown",
                              "request_correlation": "observed" if request_id is not None else "unknown"})
            elif tx:
                self._append({"kind": "transaction_statement_attempt", "verb": tx.group(1).upper(),
                              "caller": _caller(), "transaction_id": self.current_transaction_id,
                              "request_id": self.current_request_id})
            elif re.match(r"^\s*(SELECT|PRAGMA|EXPLAIN)\b", sql, re.I):
                return
            else:
                self.unknown_seen = True
                self._append({"kind": "unknown_sql_attempt", "caller": _caller()})
        except Exception:
            self.unknown_seen = True
            self._append({"kind": "unknown_trace_event", "unknown": True})

    def _version_delta(self, before, after):
        fields = ("connection", "total_changes", "data_version", "files", "package_owner")
        if before is None or after is None:
            return {"unknown": True, "reason": "version_sample_unavailable"}
        return {"changed": [field for field, old, new in zip(fields, before, after) if old != new],
                "total_changes_delta": after[1] - before[1],
                "data_version_delta": after[2] - before[2],
                "unknown": False}

    def boundary(self, event, *, before=None, after=None, **fields):
        self._append({"kind": event, "cause": _caller(), "version": self._version_delta(before, after), **fields})

    def memo_invalidation(self, *, before, after, reason, generation, proofs_before):
        """Record the exact version comparison that caused a memo clear."""
        allowed = {"memo_premise_failed", "store_version_changed"}
        if reason not in allowed:
            reason = "unknown"
            self.unknown_seen = True
        self.boundary("memo_invalidation_detected", before=before, after=after,
                      reason=reason, generation=generation, proofs_before=proofs_before)

    def http_error(self, handler, exc):
        self._append({"kind": "http_error", "route": _route(handler),
                      "request_id": self.current_request_id,
                      "exception_class": type(exc).__name__, "message_recorded": False})

    def acceptance_transaction_outcome(self, transaction_id, outcome, *, exception_class=None):
        self._append({"kind": "acceptance_transaction_outcome", "transaction_id": transaction_id,
                      "outcome": outcome,
                      "request_id": self.current_request_id,
                      "exception_class": exception_class, "connection_in_transaction": bool(self.connection.in_transaction)})
        self.flush()

    def flush(self):
        with self.lock:
            if self.disabled:
                return
            events = [event for event in self.events if event["seq"] > self.flushed_sequence]
            payload = {"schema": "timeline-memo-provenance-v1", "overflow": self.overflow,
                       "unknown": self.unknown_seen, "events": events}
            data = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
            if self.bytes_written + len(data) > _MAX_BYTES:
                self.overflow = True
                payload = {"schema": "timeline-memo-provenance-v1", "overflow": True,
                           "unknown": True, "events": [{"kind": "bounded_output_overflow"}]}
                data = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
                self.disabled = True
            start = self.bytes_written
            try:
                view = memoryview(data)
                while view:
                    written = os.write(self.fd, view)
                    if written <= 0:
                        raise OSError("trace write made no progress")
                    view = view[written:]
                os.fsync(self.fd)
            except OSError:
                self.disabled = True
                self.unknown_seen = True
                try:
                    os.ftruncate(self.fd, start)
                    os.lseek(self.fd, start, os.SEEK_SET)
                    failure = b'{"schema":"timeline-memo-provenance-v1","overflow":true,"unknown":true,"events":[{"kind":"trace_output_failure"}]}\n'
                    os.write(self.fd, failure)
                    os.fsync(self.fd)
                    self.bytes_written = start + len(failure)
                except OSError:
                    pass
                return
            self.bytes_written += len(data)
            if events:
                self.flushed_sequence = events[-1]["seq"]

    def close(self):
        if self.closed:
            return
        try:
            self.flush()
        finally:
            try:
                self.connection.set_trace_callback(None)
            except sqlite3.Error:
                pass
            try:
                os.close(self.fd)
            finally:
                self.closed = True
