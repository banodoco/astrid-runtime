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
                self._append({"kind": "sql_attempt", "verb": kind, "table": table, "caller": _caller()})
            elif tx:
                self._append({"kind": "transaction_statement_attempt", "verb": tx.group(1).upper(), "caller": _caller()})
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
                      "exception_class": type(exc).__name__, "message_recorded": False})

    def transaction_outcome(self, outcome, *, exception_class=None):
        self._append({"kind": "acceptance_transaction_outcome", "outcome": outcome,
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
            os.write(self.fd, data)
            os.fsync(self.fd)
            self.bytes_written += len(data)
            if events:
                self.flushed_sequence = events[-1]["seq"]

    def close(self):
        try:
            self.flush()
        finally:
            self.connection.set_trace_callback(None)
            os.close(self.fd)
