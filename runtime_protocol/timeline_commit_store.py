"""Renderer-free persistence for the frozen timeline commit contract.

Callers supply schema/event validation and request-private input captures. Only
this module owns the acceptance transaction; provider execution belongs outside
RealmStore's mutex.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
from collections import deque
from contextlib import contextmanager
from functools import wraps
from typing import cast

from .errors import ConflictError, ProtocolError, ValidationError
from .idempotency import command_result
from .timeline_commit_validation import detached, digest
from .timeline_materialization import has_materialization, item_identity, materialization_join, root_identity
from .timeline_commit_types import CommitFailure
from .util import canonical_json, new_id, now

_METADATA = ("source", "label", "rationale", "group_id")
_PRIVATE_EXECUTION = "_sequential_execution"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TEXT_BINDING_REF = re.compile(r"occurrence:([^/]+)/text-binding:(prompt|voiceover_script|transcript)(?::([a-z][a-z0-9-]{0,63}))?\Z")
_LOGGER = logging.getLogger(__name__)


def reject(reason, message=None, *, status=409, diagnostic_reason=None, safe_details=None):
    from .timeline_commit import CommitRejected

    details = {"status": "refused", "reason": reason,
               "base": None, "current": None, "conflicts": []}
    if safe_details is not None:
        details["safe_diagnostic"] = safe_details
    failure = cast(CommitFailure, {
        "http_status": status, "code": "conflict" if status == 409 else "validation_error",
        "message": message or reason, "details": details
    })
    error = CommitRejected(failure)
    if diagnostic_reason is not None:
        error.__dict__["_diagnostic_reason"] = diagnostic_reason
    raise error


def request_identity(context):
    invocation = context["invocation"]
    return hashlib.sha256(canonical_json({"operation": invocation["operation"], "path": invocation["path"],
                          "publisher": context["publisher"], "request": invocation["body"]}).encode()).hexdigest()


def scope(context):
    request = context["request"]
    return canonical_json([request["project_id"], request["timeline_id"]])


def _effective_merge_mode(request):
    """Return the contract's requested mode after the conservative patch rule."""
    requested = request.get("merge", "fields")
    if requested == "atomic":
        return "atomic"

    def contains_document_patch(commands):
        for command in commands:
            if command.get("op") == "doc.patch":
                return True
            if command.get("op") == "timeline.batch" and contains_document_patch(command.get("args", {}).get("commands", [])):
                return True
        return False

    if "reads" not in request and contains_document_patch(request.get("commands", [])):
        return "atomic"
    return requested


def _is_v2_request(request, records=None):
    """Return whether the caller opted into the v2 request annotations.

    ABI-1 requests are intentionally left byte-for-byte compatible: their
    result and legacy history metadata must not acquire synthetic v2 fields.
    Once any v2 control is present, the provider's authoritative step records
    and the effective merge mode are part of the durable result.
    """
    return any(key in request for key in ("label", "steps", "merge", "reads")) or (
        records is not None and "steps" in records
    ) or any(command.get("op") == "doc.patch" for command in request.get("commands", []))


def _history_metadata(request, data):
    """Project request annotations and effective commit facts into one JSON value.

    The value is stored in the existing history row.  In particular, no actor
    value is accepted from the request: ``publisher`` is added to the result and
    history edge from the authenticated execution context by the caller.
    """
    metadata = {key: request[key] for key in _METADATA if key in request}
    if _is_v2_request(request) or "steps" in data:
        metadata["label"] = data["label"]
        metadata["merge"] = request.get("merge", "fields")
        metadata["merge_mode"] = data["merge_mode"]
        if "reads" in request:
            metadata["reads"] = request["reads"]
    return metadata


def _validate_record_metadata(request, records):
    """Require the provider's authoritative v2 metadata, while leaving ABI-1 untouched."""
    if not _is_v2_request(request, records):
        return
    if records.get("label") != request.get("label", "Timeline edit"):
        reject("invalid_records", "provider label differs from the request", status=422)
    if records.get("merge_mode") != _effective_merge_mode(request):
        reject("invalid_records", "provider merge mode differs from the effective request mode", status=422)
    if "steps" not in records:
        reject("invalid_records", "provider did not return authoritative step records", status=422)
    if any("dependencies" not in step for step in records["steps"]):
        reject("invalid_records", "provider step dependencies are missing", status=422)


_SHELL_SCOPE_TABLES = ("timeline_shots", "timeline_references", "timeline_render_publications",
                       "timeline_document_input_links", "timeline_commit_history")


def has_authored_content(value):
    if isinstance(value, dict):
        return any(has_authored_content(item) for item in value.values())
    if isinstance(value, list):
        return any(has_authored_content(item) for item in value)
    return value is not None


def timeline_scope_is_empty(conn, timeline_id, *, project_id=None):
    """True when nothing is authored under the timeline or its legacy document."""
    if project_id is not None:
        document = conn.execute("SELECT content_json FROM project_documents WHERE id=? AND project_id=?",
                                (f"timeline:{timeline_id}", project_id)).fetchone()
        if document is not None:
            # Baseline verification already rejects duplicate/non-finite JSON.
            # Use the same parser here so corrupt legacy bytes cannot hide
            # authored content behind a last-key-wins decode.
            from .timeline_commit_baseline import _json
            try:
                content = _json(document["content_json"])
            except (TypeError, ValueError):
                return False
            if has_authored_content(content):
                return False
    # Any row keyed to the timeline is authored data.
    for table in _SHELL_SCOPE_TABLES:
        if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() and \
                conn.execute(f"SELECT 1 FROM {table} WHERE timeline_id=? LIMIT 1", (timeline_id,)).fetchone():
            return False
    # create_timeline snapshots the empty shell as timeline_revisions v1; only a non-empty snapshot is authored.
    if conn.execute("SELECT 1 FROM timeline_revisions WHERE timeline_id=? AND (shots_json!='[]' OR references_json!='[]') LIMIT 1",
                    (timeline_id,)).fetchone():
        return False
    for child in ("composition_revision_occurrences", "composition_revision_dependencies"):
        if conn.execute(f"SELECT 1 FROM {child} c JOIN parent_composition_revisions r ON r.id=c.parent_revision_id "
                        "WHERE r.timeline_id=? LIMIT 1", (timeline_id,)).fetchone():
            return False
    return True


def _evaluation(method):
    @wraps(method)
    def evaluate(self, *args, **kwargs):
        try:
            with self.store._mutex:
                if getattr(self._verification, "current", None) is None:
                    with self.verification_scope():
                        return evaluate(self, *args, **kwargs)
                if method.__name__ != "accept" and not self._reading:
                    with self._read_transaction():
                        return evaluate(self, *args, **kwargs)
                self._sync_replay_memo()
                version = self._replay_store_version
                boundary = self._history_inputs is None
                result = method(self, *args, **kwargs)
                if boundary:
                    self._check_history_objects()
                self._check_history_version()
                if method.__name__ != "accept" and version != self._replay_store_version:
                    raise ProtocolError("accepted commit inputs changed during verification")
                return result
        except BaseException:
            self.clear_replay_memo()
            raise
    return evaluate


class _HistoryReadCursor:
    def __init__(self, inputs, query, parameters):
        self.inputs, self.query, self.parameters = inputs, query, parameters
        self.cursor = inputs.connection.execute(query, parameters)

    def _read(self, method):
        value = getattr(self.cursor, method)()
        rows = [value] if method == "fetchone" else value
        snapshot = tuple(None if row is None else tuple(row) for row in rows)
        key = (self.query, self.parameters, method)
        if key in self.inputs.rows and self.inputs.rows[key] != snapshot:
            raise ProtocolError("accepted commit inputs changed during verification")
        self.inputs.rows[key] = snapshot
        return value

    def fetchone(self):
        return self._read("fetchone")

    def fetchall(self):
        return self._read("fetchall")

    def __iter__(self):
        return iter(self.fetchall())


class _HistoryReadInputs:
    """Exact consumed SQL results and CAS bytes for one authoritative read."""
    def __init__(self, connection, cas_root):
        self.connection, self.cas_root = connection, cas_root
        self.rows, self.objects = {}, {}

    def execute(self, query, parameters=()):
        return _HistoryReadCursor(self, query, tuple(parameters))

    def check(self):
        from .cas import ContentAddressedStore

        for object_id, expected in self.objects.items():
            data = ContentAddressedStore(self.cas_root).read(object_id)
            if (len(data), hashlib.sha256(data).digest()) != expected:
                raise ProtocolError("accepted commit object changed during verification")
        for (query, parameters, method), expected in self.rows.items():
            value = getattr(self.connection.execute(query, parameters), method)()
            rows = [value] if method == "fetchone" else value
            if tuple(None if row is None else tuple(row) for row in rows) != expected:
                raise ProtocolError("accepted commit inputs changed during verification")


class TimelineCommitStore:
    def __init__(self, store, *, validate_prepared, validate_event=None):
        self.store = store
        # Validation uses the wire worker's authoritative schema, including
        # Agent-owned leaves. It must raise on invalid data, never normalize it.
        self.validate_prepared = validate_prepared
        self.validate_event = validate_event
        self._verification = threading.local()
        self._replay_memo = set()
        self._replay_generation = 0
        self._replay_store_version = None
        self._history_state = {}
        self._connection = self.store.conn
        self._reading = False
        self._acceptance_transaction = False
        value = os.stat(self.store.db_path)
        self._database_identity = (value.st_dev, value.st_ino)
        self._wal_identity = None
        self.clear_replay_memo()

    def clear_replay_memo(self):
        with self.store._mutex:
            self._replay_memo.clear()
            self._history_state = {key: {} for key in
                                   ("records", "entries", "closures", "heads", "chains", "chain_tails", "events", "objects")}
            self._replay_generation += 1

    def _physical_version(self):
        files = []
        for index, path in enumerate((self.store.db_path, str(self.store.db_path) + "-wal",
                                      str(self.store.db_path) + "-shm", self.store.db_path.parent)):
            try:
                value = os.stat(path)
                # SQLite updates SHM during ordinary reads. Only its identity
                # and protection, and the directory's, affect retained trust.
                content = (value.st_size, value.st_mtime_ns, value.st_ctime_ns) if index < 2 else (None, None, None)
                files.append((value.st_dev, value.st_ino, *content, value.st_uid, value.st_mode))
            except FileNotFoundError:
                files.append(None)
        try:
            package_owner = os.stat(os.path.dirname(os.path.realpath(__file__))).st_uid
        except OSError:
            package_owner = None
        return tuple(files), package_owner

    def _replacement_connection_is_current(self, connection):
        """Check that an externally supplied handle names this realm DB."""
        try:
            database = connection.execute("PRAGMA database_list").fetchone()
            journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
        except (AttributeError, sqlite3.Error) as exc:
            raise ProtocolError("accepted commit connection replacement is unusable") from exc
        if database is None or len(database) < 3 or not database[2]:
            raise ProtocolError("accepted commit connection replacement is not the realm database")
        try:
            current_path = os.path.realpath(database[2])
            expected_path = os.path.realpath(self.store.db_path)
        except OSError as exc:
            raise ProtocolError("accepted commit connection replacement path is unavailable") from exc
        if current_path != expected_path:
            raise ProtocolError("accepted commit connection replacement is not the realm database")
        if journal_mode is None or str(journal_mode[0]).lower() != "wal":
            raise ProtocolError("realm storage requires SQLite WAL journal mode")

    def _reestablish_connection(self):
        """Replace stale storage handles before any authenticated read.

        A handle replacement can be adopted after checking its database path;
        a changed DB/WAL path is reopened through RealmStore's existing open
        lifecycle. Both routes discard all retained proofs and establish a
        new physical identity baseline before verification resumes.
        """
        with self.store._mutex:
            current = self.store.conn
            if current is None or getattr(self.store, "_lock_file", None) is None:
                raise ProtocolError("accepted commit storage is closed; reopen required")
            if getattr(current, "in_transaction", False) or getattr(self._connection, "in_transaction", False):
                raise ProtocolError("accepted commit storage identity changed during a transaction; reopen required")
            files, _ = self._physical_version()
            if files[0] is None:
                raise ProtocolError("accepted commit database is missing; reopen required")

            if current is not self._connection:
                self._replacement_connection_is_current(current)
                current.row_factory = sqlite3.Row
                current.execute("PRAGMA foreign_keys=ON")
                current.execute("PRAGMA busy_timeout=10000")
            else:
                # Closing the old handle is essential: SQLite may otherwise
                # continue serving the disconnected inode after DB/WAL swap.
                current.close()
                self.store.conn = None
                try:
                    self.store._open(fresh=False)
                except FileNotFoundError as exc:
                    raise ProtocolError("accepted commit database is missing; reopen required") from exc

            self._connection = self.store.conn
            files, _ = self._physical_version()
            if files[0] is None:
                raise ProtocolError("accepted commit database is missing; reopen required")
            self._database_identity = files[0][:2]
            self._wal_identity = None if files[1] is None else files[1][:2]
            self._replay_store_version = None
            self.clear_replay_memo()

    def _store_version(self):
        # data_version is meaningful only on the same live connection. The
        # RealmStore mutex also serializes its use across request threads.
        files, package_owner = self._physical_version()
        connection_changed = self.store.conn is not self._connection
        database_changed = files[0] is None or files[0][:2] != self._database_identity
        wal_changed = self._wal_identity is not None and (files[1] is None or files[1][:2] != self._wal_identity)
        if connection_changed or database_changed or wal_changed:
            self._reestablish_connection()
            files, package_owner = self._physical_version()
        if files[0] is None:
            raise ProtocolError("accepted commit database is missing; reopen required")
        if self._wal_identity is None and files[1] is not None:
            self._wal_identity = files[1][:2]
        connection = cast(sqlite3.Connection, self._connection)
        return (id(connection), connection.total_changes,
                connection.execute("PRAGMA data_version").fetchone()[0], tuple(files), package_owner)

    def _memo_failure(self, version):
        if version[4] is None:
            return "installed runtime package directory owner is unavailable"
        for name, value in zip(("DB", "WAL", "SHM", "store directory"), version[3]):
            if value is None:
                if name in ("WAL", "SHM"):
                    continue
                return f"{name} is missing"
            if value[-1] & 0o022:
                return f"{name} is group/world-writable"
            if value[-2] not in (0, version[4]):
                return f"{name} owner uid {value[-2]} differs from root and installed runtime package owner uid {version[4]}"
        return None

    @contextmanager
    def _read_transaction(self):
        with self.store._mutex:
            try:
                self._store_version()
                connection = cast(sqlite3.Connection, self._connection)
                owned = not connection.in_transaction
                if owned:
                    connection.execute("BEGIN")
                self._reading = True
                try:
                    # Compare after entering the snapshot, before any cache hit.
                    self._sync_replay_memo()
                    yield
                    self._check_history_version()
                finally:
                    self._reading = False
                    if owned:
                        connection.rollback()
                    elif not self._acceptance_transaction:
                        # An unrelated caller transaction may still roll back.
                        # Its provisional rows cannot become retained proofs.
                        self.clear_replay_memo()
                # data_version can stay at the snapshot's value until it ends.
                self._check_history_version()
            except BaseException:
                self.clear_replay_memo()
                raise

    def _check_history_version(self):
        if self._store_version() != self._replay_store_version:
            raise ProtocolError("accepted commit inputs changed during verification")

    def _check_history_objects(self):
        # CAS is outside SQLite's change boundary. Keep the existing physical
        # byte verification, including for objects consumed by cached ancestry.
        from .cas import ContentAddressedStore

        for object_id, expected in self._history_state["objects"].items():
            data = ContentAddressedStore(self.store.cas_root).read(object_id)
            if (len(data), hashlib.sha256(data).digest()) != expected:
                raise ProtocolError("accepted commit object changed during verification")

    def _sync_replay_memo(self):
        version = self._store_version()
        current = self._verification.current
        failure = self._memo_failure(version)
        if failure is not None and not current["memo_fallback"]:
            # Keep request-local verification, but never inherit proofs from a
            # previous request when the approved data/code premise fails.
            self.clear_replay_memo()
            current["memo_fallback"] = True
            _LOGGER.warning("timeline history memo disabled; full verification for this request: %s", failure)
        if version != self._replay_store_version:
            previous = self._replay_store_version
            if (current["accepting"] and self.store.conn.in_transaction and previous is not None
                    and version[0] == previous[0] and version[2] == previous[2] and version[4] == previous[4]
                    and all(old is None or (new is not None and old[:2] == new[:2] and old[-2:] == new[-2:])
                            for old, new in zip(previous[3], version[3]))):
                # Only the validated acceptance's write phase may retain old
                # immutable proofs while its own projections/links are added.
                # The mutex and SQLite write transaction fence this phase;
                # rollback or any exception discards every provisional value.
                self._history_state["heads"].clear()
            else:
                self.clear_replay_memo()
            self._replay_store_version = version
        if current["generation"] != self._replay_generation:
            current["verified"].clear()
            current["generation"] = self._replay_generation

    @contextmanager
    def _accepting(self):
        try:
            with self.store._transaction():
                # BEGIN IMMEDIATE excludes other SQLite writers. A change
                # before that fence must invalidate all earlier proofs.
                self._acceptance_transaction = True
                self._sync_replay_memo()
                before = self._replay_store_version
                assert before is not None
                yield
                after = self._store_version()
                if after[2] != before[2]:
                    raise ProtocolError("accepted commit inputs changed during acceptance")
            # Sample once after COMMIT and retain that exact sample. Comparing
            # its external-write counter prevents absorbing a writer that won
            # the lock immediately after our own commit. A later writer is
            # detected against this sample at the next boundary.
            committed = self._store_version()
            if committed[2] != after[2]:
                raise ProtocolError("accepted commit inputs changed during acceptance")
        except BaseException:
            self.clear_replay_memo()
            raise
        else:
            # Only the successful acceptance transaction may extend history
            # without discarding earlier full replay proofs.
            if self._memo_failure(committed) is not None or before[4] != committed[4] or any(
                    old is not None and new is not None and old[-2:] != new[-2:]
                    for old, new in zip(before[3], committed[3])):
                # Our SQLite write cannot account for chmod/chown. Do not
                # absorb those changes into the post-commit baseline either.
                self.clear_replay_memo()
            self._replay_store_version = committed
            self._history_state["heads"].clear()
        finally:
            self._acceptance_transaction = False
            self._verification.current["accepting"] = False

    @contextmanager
    def verification_scope(self):
        """Start an independent evaluation, including when another is nested."""
        previous = getattr(self._verification, "current", None)
        current = {"verified": set(), "active": set(), "traversal": None, "inputs": None,
                   "generation": self._replay_generation, "accepting": False, "memo_fallback": False}
        self._verification.current = current
        try:
            yield
        except BaseException:
            self.clear_replay_memo()
            raise
        finally:
            current["verified"].clear()
            current["active"].clear()
            self._verification.current = previous

    @contextmanager
    def history_read_scope(self):
        """Keep graph inputs live through the provider's final dependent reads."""
        current = getattr(self._verification, "current", None)
        if current is None:
            with self.verification_scope(), self.history_read_scope():
                yield
            return
        if not self._reading:
            with self._read_transaction(), self.history_read_scope():
                yield
            return
        previous = current["inputs"]
        inputs = previous if previous is not None else _HistoryReadInputs(self.store.conn, self.store.cas_root)
        current["inputs"] = inputs
        try:
            self._sync_replay_memo()
            version = self._replay_store_version
            self._check_history_objects()
            yield
            inputs.check()
            self._check_history_objects()
            if self._store_version() != version:
                raise ProtocolError("accepted commit inputs changed during verification")
        except BaseException:
            self.clear_replay_memo()
            raise
        finally:
            current["inputs"] = previous

    @property
    def _history_read_identity(self):
        assert self._history_inputs is not None
        return self._replay_generation, self._replay_store_version

    @property
    def _history_inputs(self):
        current = getattr(self._verification, "current", None)
        traversal = current["traversal"] if current else None
        if traversal is not None:
            return traversal["inputs"]
        return current["inputs"] if current else None

    @property
    def conn(self):
        inputs = self._history_inputs
        return inputs if inputs is not None else self.store.conn

    def _read_history_object(self, object_id):
        from .cas import ContentAddressedStore

        data = ContentAddressedStore(self.store.cas_root).read(object_id)
        value = (len(data), hashlib.sha256(data).digest())
        previous = self._history_state["objects"].get(object_id)
        if previous is not None and previous != value:
            raise ProtocolError("accepted commit object changed during verification")
        self._history_state["objects"][object_id] = value
        inputs = self._history_inputs
        if inputs is not None:
            objects = inputs.objects
            if object_id in objects and objects[object_id] != value:
                raise ProtocolError("accepted commit object changed during verification")
            objects[object_id] = value
        return data

    def _membership(self, project_id, timeline_id):
        row = self.conn.execute("SELECT p.realm_id FROM timelines t JOIN projects p ON p.id=t.project_id "
                                "WHERE t.id=? AND t.project_id=? AND t.archived_at IS NULL",
                                (timeline_id, project_id)).fetchone()
        if row is None:
            reject("history_unavailable", diagnostic_reason="store_membership_missing")
        return row["realm_id"]

    @_evaluation
    def lookup(self, context, *, authorize):
        with self.store._mutex:
            authorize()
            request = context["request"]
            # Lookup is the only path allowed to inspect an archived scope:
            # it must first authenticate the current actor, then prove the
            # project/timeline row exists, and only then read the exact key.
            # New writes continue through _membership's active-row guard.
            row = self.conn.execute(
                "SELECT p.realm_id FROM timelines t JOIN projects p ON p.id=t.project_id "
                "WHERE t.id=? AND t.project_id=?",
                (request["timeline_id"], request["project_id"]),
            ).fetchone()
            if row is None or row["realm_id"] != context["realm_id"]:
                reject("authority_changed")
            return self._lookup(context)

    def _lookup(self, context):
        row = self.conn.execute("SELECT * FROM command_idempotency WHERE command_kind='timeline.commit' "
                                "AND aggregate_id=? AND idempotency_key=?", (scope(context), context["idempotency_key"])).fetchone()
        if row is None:
            return None
        if row["request_hash"] != context["request_hash"]:
            reject("idempotency_mismatch")
        edge = self.conn.execute("SELECT * FROM timeline_commit_history WHERE publication_id=?", (row["txn_id"],)).fetchone()
        if edge is None or edge["project_id"] != context["request"]["project_id"] or edge["timeline_id"] != context["request"]["timeline_id"]:
            raise ProtocolError("accepted commit history is missing or corrupt")
        self._verify_accepted(row, edge, allow_archived=True)
        return self._envelope(row, edge["project_id"])

    @_evaluation
    def _verify_accepted(self, row, edge, *, allow_archived=False):
        from .timeline_commit import CommitRejected

        self._sync_replay_memo()
        current = self._verification.current
        active = current["active"]
        identity = (edge["project_id"], edge["timeline_id"], edge["publication_id"])
        cached = self._history_state["records"].get(identity)
        if cached is not None:
            if cached != (dict(row), dict(edge)):
                raise ProtocolError("accepted commit history changed during verification")
            return
        if identity in active:
            raise ProtocolError("accepted commit history contains a cycle")
        traversal = current["traversal"]
        if traversal is not None:
            traversal["dependencies"][traversal["current"]].add(identity)
            existing = traversal["nodes"].get(identity)
            if existing is not None:
                if dict(row) != dict(existing[0]) or dict(edge) != dict(existing[1]):
                    raise ProtocolError("accepted commit history changed during verification")
            else:
                traversal["nodes"][identity] = (row, edge, allow_archived)
                traversal["dependencies"][identity] = set()
                traversal["pending"].append(identity)
            return
        # Build one dependency graph for this lookup, not for the request. No
        # internal history entry escapes until every node's live predicates and
        # replay proof pass. Later lookups rebuild it, even in the same scope.
        traversal = {"nodes": {identity: (row, edge, allow_archived)},
                     "dependencies": {identity: set()}, "pending": deque([identity]),
                     "replays": {}, "current": identity,
                     "inputs": current["inputs"] if current["inputs"] is not None else
                               _HistoryReadInputs(self.store.conn, self.store.cas_root)}
        current["traversal"] = traversal
        try:
            while traversal["pending"]:
                node = traversal["pending"].popleft()
                traversal["current"] = node
                ledger, history, archived = traversal["nodes"][node]
                live_ledger = self.conn.execute("SELECT * FROM command_idempotency WHERE txn_id=?", (node[2],)).fetchone()
                live_history = self.conn.execute("SELECT * FROM timeline_commit_history WHERE publication_id=?", (node[2],)).fetchone()
                if (live_ledger is None or live_history is None
                        or dict(live_ledger) != dict(ledger) or dict(live_history) != dict(history)):
                    raise ProtocolError("accepted commit history changed during verification")
                active.add(node)
                try:
                    self._verify_accepted_record(ledger, history, allow_archived=archived)
                finally:
                    active.remove(node)
            # Authenticate dependencies before their consumers; reject indirect
            # cycles as well as the direct recursion caught by active above.
            remaining = {node: len(deps) for node, deps in traversal["dependencies"].items()}
            consumers = {node: [] for node in remaining}
            for node, deps in traversal["dependencies"].items():
                for dependency in deps:
                    consumers[dependency].append(node)
            ready = deque(node for node, count in remaining.items() if not count)
            ordered = []
            while ready:
                node = ready.popleft()
                ordered.append(node)
                for consumer in consumers[node]:
                    remaining[consumer] -= 1
                    if not remaining[consumer]:
                        ready.append(consumer)
            if len(ordered) != len(remaining):
                raise ProtocolError("accepted commit history contains a cycle")
            # Callbacks during collection may have changed an already checked
            # dependency. Re-read every consumed result, including empty SQL
            # results and physical object bytes, before using queued proofs.
            traversal["inputs"].check()
            proofs = set()
            generation = self._replay_generation
            for node in ordered:
                replay = traversal["replays"].get(node)
                if replay is not None:
                    key, arguments = replay
                    self._sync_replay_memo()
                    if key not in current["verified"] and key not in self._replay_memo:
                        self._verify_accepted_replay(*arguments)
                        proofs.add(key)
            # Replay/capture validation can also call back into the runtime.
            # Publish no proofs or history until all inputs still match.
            traversal["inputs"].check()
            self._sync_replay_memo()
            if generation == self._replay_generation:
                current["verified"].update(proofs)
                self._replay_memo.update(proofs)
                for node, (ledger, history, _) in traversal["nodes"].items():
                    self._history_state["records"][node] = (dict(ledger), dict(history))
        except (KeyError, TypeError, ValueError, IndexError, ValidationError, CommitRejected) as exc:
            raise ProtocolError("accepted commit record is corrupt") from exc
        finally:
            current["traversal"] = None

    def _verify_accepted_record(self, row, edge, *, allow_archived=False):
        from .timeline_commit import CommitRejected
        try:
            data, records = json.loads(row["result_json"]), json.loads(edge["records_json"])
            metadata = json.loads(edge["metadata_json"])
            previous = {"revision_id": edge["previous_revision_id"], "publication_id": edge["previous_publication_id"]}
            document = data["canonical_document"]
            valid = (edge["intent"] == "recorded" and row["command_kind"] == "timeline.commit"
                     and row["txn_id"] == edge["publication_id"]
                     and row["aggregate_id"] == canonical_json([edge["project_id"], edge["timeline_id"]])
                     and row["primary_stream_id"] == edge["timeline_id"]
                     and row["first_project_seq"] == row["last_project_seq"] == edge["project_seq"]
                     and data["accepted_revision_id"] == document["parent_revision"]["revision_id"] == edge["revision_id"]
                     and document["project_id"] == edge["project_id"] and document["timeline_id"] == edge["timeline_id"]
                     and data["document_digest"] == digest(document)
                     and canonical_json(data["commands"]) == canonical_json([r["command"] for r in records["commands"]])
                     and data["previous_revision_id"] == previous["revision_id"]
                     and data["previous_publication_id"] == previous["publication_id"]
                     and data["publisher"] == edge["publisher"]
                     and all(data[k] == edge[k] for k in ("provider_version", "compiler_version"))
                     and {k: data[k] for k in metadata
                          if k in data and k in _METADATA} == {
                         k: metadata[k] for k in metadata
                         if k in _METADATA
                     })
            base = {"revision_id": data["base_revision_id"], "publication_id": data["base_publication_id"]}
            historical_status = "accepted" if previous == base else "rebased"
            modern_status = "accepted" if previous == base else "merged"
            valid = valid and data["status"] in {historical_status, modern_status}
            valid = valid and data["rebased_onto"] == (None if previous == base else previous)
            if "merge_mode" in metadata:
                valid = valid and data.get("merge_mode") == metadata["merge_mode"]
            if "merge" in metadata:
                valid = valid and metadata["merge"] in {"fields", "atomic"}
            if "reads" in metadata:
                valid = valid and data.get("reads", metadata["reads"]) == metadata["reads"]
            if "steps" in records:
                valid = valid and data.get("steps") == records["steps"]
            if "label" in records:
                valid = valid and data.get("label") == records["label"]
            if "merge_mode" in records:
                valid = valid and data.get("merge_mode") == records["merge_mode"]
            ids = json.loads(row["event_ids_json"])
            seq = row["resulting_stream_seq"]
            # Replay verifies the accepted prefix, independent of later writes.
            prefix = self._event_prefix(edge["project_id"], edge["timeline_id"], through=seq)
            valid = valid and isinstance(ids, list) and 0 < len(ids) <= seq <= len(prefix)
            project_seq = self.conn.execute("SELECT next_seq FROM project_sequences WHERE project_id=?",
                                            (edge["project_id"],)).fetchone()
            valid = valid and project_seq is not None and 0 < edge["project_seq"] < project_seq[0]
            valid = valid and ids == [str(e["id"]) for e in prefix[seq - len(ids):seq]]
            event = self.conn.execute("SELECT * FROM timeline_events WHERE id=? AND timeline_id=?",
                                      (ids[-1], edge["timeline_id"])).fetchone()
            valid = valid and event is not None and event["kind"] == "timeline.commit.accepted"
            if valid:
                payload = json.loads(event["payload_json"])
                expected = {"project_id": edge["project_id"], "timeline_id": edge["timeline_id"],
                            "previous": previous, "revision_id": edge["revision_id"],
                            "publisher": edge["publisher"], "intent": "recorded",
                            "records_digest": digest(records)}
                # Only historical events and metadata that both lack the mode
                # are ABI1. Never reclassify mutable record shapes on replay.
                if "recorder_abi" in metadata or "recorder_abi" in payload:
                    abi = metadata.get("recorder_abi")
                    valid = (type(abi) is int and abi in (1, 2)
                             and type(payload.get("recorder_abi")) is int) and valid
                    expected.update(recorder_abi=abi, request_hash=row["request_hash"],
                                    metadata_digest=digest(metadata))
                valid = valid and payload == expected
            if not valid:
                raise ValueError()
            prepared = {**data, "records": records, "expected_head": previous}
            if has_materialization(prepared):
                project, timeline = edge["project_id"], edge["timeline_id"]
                allocations = materialization_join(prepared, project, timeline,
                    lambda revision: self.revision_closure(project, timeline, revision,
                                                           allow_archived=allow_archived))
                if canonical_json(document) != canonical_json(self.revision_closure(
                        project, timeline, edge["revision_id"], allow_archived=allow_archived)):
                    raise ValueError()
                self._check_inherited_allocations(project, timeline, records, allocations, edge["project_seq"],
                                                   allow_archived=allow_archived)
            if "steps" in records:
                self._accepted_replay(row, edge, data, metadata, records, previous, prefix[seq - 1]["event_hash"],
                                      allow_archived=allow_archived)
        except (KeyError, TypeError, ValueError, IndexError, ValidationError, ConflictError, CommitRejected) as exc:
            raise ProtocolError("accepted commit record is corrupt") from exc

    def _event_prefix(self, project_id, timeline_id, *, through=None):
        from .timeline_commit_baseline import _json, _require

        prefix = self._history_state["events"].setdefault((project_id, timeline_id), [])
        query = "SELECT * FROM timeline_events WHERE timeline_id=? AND id>? ORDER BY id"
        parameters = (timeline_id, prefix[-1]["id"] if prefix else 0)
        if through is not None:
            query += " LIMIT ?"
            parameters += (max(0, through - len(prefix)),)
        events = self.conn.execute(query, parameters).fetchall()
        previous = prefix[-1]["event_hash"] if prefix else ""
        for event in events:
            payload = _json(event["payload_json"])
            _require(isinstance(payload, dict), "timeline_event_payload_mismatch")
            hashed = {"timeline_id": timeline_id, "kind": event["kind"], "payload": payload,
                      "previous_hash": previous, "created_at": event["created_at"]}
            _require(event["previous_hash"] == previous and event["event_hash"] == digest(hashed)[7:],
                     "timeline_event_chain_mismatch")
            _require(payload.get("project_id") == project_id, "event_project_mismatch")
            previous = event["event_hash"]
        prefix.extend(dict(event) for event in events)
        return prefix

    def _accepted_replay(self, row, edge, data, metadata, records, previous, events, *, allow_archived):
        base = {"revision_id": data["base_revision_id"], "publication_id": data["base_publication_id"]}
        replay_request = {**metadata, "commands": data["commands"],
                          "base_revision_id": base["revision_id"], "base_publication_id": base["publication_id"]}
        source = self.revision_closure(edge["project_id"], edge["timeline_id"], previous["revision_id"],
                                       allow_archived=allow_archived)
        continuations = self._binding_continuations(
            edge["project_id"], edge["timeline_id"], base["publication_id"], previous,
            allow_archived=allow_archived,
        )
        history = self._inverse_stage_history(edge["project_id"], edge["timeline_id"], records,
                                              allow_archived=allow_archived)
        prepared = {"records": records, "expected_head": previous, "canonical_document": data["canonical_document"]}
        original = self.revision_closure(edge["project_id"], edge["timeline_id"], base["revision_id"],
                                         allow_archived=allow_archived)
        realm = self.conn.execute("SELECT realm_id FROM projects WHERE id=?", (edge["project_id"],)).fetchone()
        # Entry bytes alone do not cover mutable source rows or event prefixes.
        # Resolve those afresh before reusing the pure recorder/capture checks.
        traversal = self._verification.current["traversal"]
        key = (edge["project_seq"], digest({"ledger": dict(row), "edge": dict(edge),
               "source": source, "base": original, "continuations": {key: sorted(value) for key, value in continuations.items()}, "history": history,
               "events": events, "realm": list(realm) if realm else None}),
               self._history_chain(edge))
        verified = self._verification.current["verified"]
        arguments = (row, edge, data, metadata, replay_request, prepared,
                     original, source, continuations, history)
        if traversal is not None:
            traversal["replays"][traversal["current"]] = (key, arguments)
        elif key not in verified and key not in self._replay_memo:
            self._verify_accepted_replay(row, edge, data, metadata, replay_request, prepared,
                                         original, source, continuations, history)
            verified.add(key)

    def _history_chain(self, edge):
        chains = self._history_state["chains"]
        scope = (edge["project_id"], edge["timeline_id"])
        ordinal = edge["project_seq"]
        if (*scope, ordinal) not in chains:
            low, previous = self._history_state["chain_tails"].get(scope, (0, ""))
            rows = self.conn.execute(
                "SELECT * FROM timeline_commit_history WHERE project_id=? AND timeline_id=? "
                "AND project_seq>? AND project_seq<=? ORDER BY project_seq", (*scope, low, ordinal)).fetchall()
            ledgers = {row["txn_id"]: dict(row) for row in self.conn.execute(
                "SELECT * FROM command_idempotency WHERE txn_id IN (SELECT publication_id "
                "FROM timeline_commit_history WHERE project_id=? AND timeline_id=? AND project_seq>? AND project_seq<=?)",
                (*scope, low, ordinal)).fetchall()}
            for row in rows:
                chains[(*scope, row["project_seq"])] = previous
                # Hash the actual stored JSON strings, including legacy rows;
                # no persisted digest or verification claim is authoritative.
                previous = digest([previous, dict(row), ledgers.get(row["publication_id"])])
            self._history_state["chain_tails"][scope] = (ordinal, previous)
        return chains[(*scope, ordinal)]

    def _verify_accepted_replay(self, row, edge, data, metadata, replay_request, prepared,
                                original, source, continuations, history):
        from .timeline_commit_auth import validate
        sequential = None
        if _PRIVATE_EXECUTION in metadata:
            replay_request, prepared, sequential = self._historical_sequential(
                metadata[_PRIVATE_EXECUTION], row, edge, data, prepared, original, source,
                continuations, history,
            )
        else:
            from .timeline_commit_auth import sequential_proof_required
            if sequential_proof_required(prepared, source, continuations):
                raise ValueError("historical sequential proof is missing")
        validate(replay_request, prepared, source, original, continuations, history, sequential=sequential)

    def _historical_sequential(self, execution, row, edge, data, accepted, base, source, continuations, history):
        from .timeline_commit_auth import validate_sequential_capture
        from .timeline_commit_port import route_path
        from .timeline_commit_validation import validate_commit_value

        if set(execution) != {"capture", "prepared"}:
            raise ValueError("historical sequential execution is malformed")
        capture, prepared = execution["capture"], execution["prepared"]
        context = capture["context"]
        validate_commit_value(context, "CommitContext")
        validate_commit_value(prepared, "PreparedCommit")
        request = context["request"]
        realm = self.conn.execute("SELECT realm_id FROM projects WHERE id=?", (edge["project_id"],)).fetchone()
        if (realm is None or context["realm_id"] != realm[0]
                or context["publisher"] != edge["publisher"]
                or context["idempotency_key"] != row["idempotency_key"]
                or context["request_hash"] != row["request_hash"]
                or request_identity(context) != row["request_hash"]
                or request["project_id"] != edge["project_id"] or request["timeline_id"] != edge["timeline_id"]
                or request["base_revision_id"] != data["base_revision_id"]
                or request["base_publication_id"] != data["base_publication_id"]
                or context["invocation"]["operation"] != "commitTimeline"
                or context["invocation"]["path"] != route_path(edge["project_id"], edge["timeline_id"])
                or context["invocation"]["body"] != request or request.get("dry_run", False)
                or any(prepared[key] != value for key, value in accepted.items())
                or any(prepared[key] != data[key] for key in
                       ("document_digest", "id_map", "provider_version", "compiler_version"))
                or any(data.get(key) != request.get(key) for key in _METADATA if key != "label")
                or data["label"] != request.get("label", "Timeline edit")
                or data["merge_mode"] != _effective_merge_mode(request)):
            raise ValueError("historical sequential execution differs from acceptance")
        event_ids = json.loads(row["event_ids_json"])
        if len(event_ids) != len(prepared["semantic_events"]) + 1:
            raise ValueError("historical sequential events differ from acceptance")
        for event_id, semantic in zip(event_ids, prepared["semantic_events"]):
            event = self.conn.execute("SELECT kind, payload_json FROM timeline_events WHERE id=? AND timeline_id=?",
                                      (event_id, edge["timeline_id"])).fetchone()
            if event is None or event["kind"] != semantic["kind"] or json.loads(event["payload_json"]) != {
                    "project_id": edge["project_id"], "timeline_id": edge["timeline_id"],
                    "publisher": edge["publisher"], **semantic}:
                raise ValueError("historical sequential events differ from acceptance")
        return request, prepared, validate_sequential_capture(
            request, prepared, capture, source, base, continuations, history,
        )

    def _check_inherited_allocations(self, project, timeline, records, allocations, before_seq=None,
                                     *, allow_archived=False):
        inverse_refs = {d["key"].removeprefix("materialization.source:")
                        for r in records["commands"] if r["command"]["op"] == "timeline.inverse"
                        for d in r["dependencies"] if d["key"].startswith("materialization.source:")}
        if not inverse_refs:
            return
        inherited = {}
        for publication in records["undo_of"]:
            if before_seq is not None:
                row = self.conn.execute("SELECT project_seq FROM timeline_commit_history WHERE publication_id=?",
                                        (publication,)).fetchone()
                if row is None or row[0] >= before_seq:
                    reject("invalid_records")
            entry = self.history_entry(project, timeline, publication, allow_archived=allow_archived)
            data = entry["receipt"]["result"]
            target = {**data, "records": entry["records"], "expected_head": entry["previous"]}
            if has_materialization(target):
                for shot, allocation in materialization_join(target, project, timeline,
                        lambda revision: self.revision_closure(project, timeline, revision,
                                                               allow_archived=allow_archived)).items():
                    if shot in inherited and canonical_json(inherited[shot]) != canonical_json(allocation):
                        reject("invalid_records")
                    inherited[shot] = allocation
        if any(canonical_json(allocations.get(ref.removeprefix("shot:"))) !=
               canonical_json(inherited.get(ref.removeprefix("shot:"))) for ref in inverse_refs):
            reject("invalid_records", "inverse allocation lacks authenticated provenance")

    @staticmethod
    def _envelope(row, project_id):
        data = (json.loads(row["result_json"]) if row["command_kind"] == "parent_composition.publish" else
                command_result(row["result_json"], kind="timeline.commit", created_at=row["created_at"]))
        receipt = {"receipt_id": row["txn_id"], "command_kind": row["command_kind"],
                   "idempotency_key": row["idempotency_key"], "request_hash": row["request_hash"],
                   "project_id": project_id, "project_seq": [row["first_project_seq"], row["last_project_seq"]],
                   "event_ids": json.loads(row["event_ids_json"]), "result": data, "created_at": row["created_at"]}
        return detached({"data": data, "receipt": receipt})

    @_evaluation
    def head(self, project_id, timeline_id):
        return self._head_entry(project_id, timeline_id)[0]

    def _head_entry(self, project_id, timeline_id):
        with self.store._mutex:
            self._membership(project_id, timeline_id)
            cached = self._history_state["heads"].get((project_id, timeline_id))
            if cached is not None:
                return detached(cached), self._history_entry_view(project_id, timeline_id, cached["publication_id"])
            row = self.conn.execute("SELECT revision_id, publication_id FROM parent_composition_heads "
                                    "WHERE project_id=? AND timeline_id=?", (project_id, timeline_id)).fetchone()
            if row is None or not row["revision_id"] or not row["publication_id"]:
                reject("history_unavailable", diagnostic_reason="store_head_missing")
            assert row is not None
            entry = self._history_entry_view(project_id, timeline_id, row["publication_id"])
            if entry["revision_id"] != row["revision_id"]:
                reject("history_unavailable", diagnostic_reason="store_head_revision_mismatch")
            from .timeline_catalog import verify_catalog_tail
            from .timeline_commit_baseline import _shot_projection, _text_bindings
            ledger = self.conn.execute("SELECT resulting_stream_seq, last_project_seq FROM command_idempotency WHERE txn_id=?",
                                       (row["publication_id"],)).fetchone()
            try:
                events = self._event_prefix(project_id, timeline_id)
                catalog = verify_catalog_tail(self.conn, project_id, timeline_id, events, ledger[0], ledger[1],
                                              legacy=entry["intent"] == "legacy_unknown")
                if catalog:
                    document = self.revision_closure(project_id, timeline_id, row["revision_id"])
                    if entry["intent"] == "recorded" and document != entry["receipt"]["result"]["canonical_document"]:
                        reject("history_unavailable", "canonical film differs from accepted publication",
                               diagnostic_reason="store_head_canonical_mismatch")
                    for shot in document["shot_revisions"]:
                        _shot_projection(self.conn, project_id, shot["shot_id"])
                        _text_bindings(self.conn, project_id, shot, self._read_history_object)
            except ConflictError as exc:
                from .timeline_commit import CommitRejected
                raise CommitRejected({"http_status": 409, "code": "conflict",
                                      "message": "timeline has untracked writes",
                                      "details": {"base": None, "current": None, "conflicts": [], **exc.details}}) from exc
            except (KeyError, TypeError, ValueError, IndexError):
                reject("history_unavailable", "timeline catalog facts are corrupt",
                       diagnostic_reason="store_head_catalog_corrupt")
            self._history_state["heads"][(project_id, timeline_id)] = dict(row)
            return dict(row), entry

    @_evaluation
    def history_entry(self, project_id, timeline_id, publication_id, *, allow_archived=False):
        return detached(self._history_entry_view(project_id, timeline_id, publication_id,
                                                 allow_archived=allow_archived))

    @_evaluation
    def _history_entry_view(self, project_id, timeline_id, publication_id, *, allow_archived=False):
        # Internal readers must not mutate this authenticated value. The public
        # store API and RequestCommitPort detach before handing it to a caller.
        with self.store._mutex:
            if allow_archived:
                row = self.conn.execute(
                    "SELECT p.realm_id FROM timelines t JOIN projects p ON p.id=t.project_id "
                    "WHERE t.id=? AND t.project_id=?", (timeline_id, project_id)).fetchone()
                if row is None:
                    reject("history_unavailable", diagnostic_reason="store_archived_scope_missing")
            else:
                self._membership(project_id, timeline_id)
            identity = (project_id, timeline_id, publication_id)
            cached = self._history_state["entries"].get(identity)
            if cached is not None:
                row, ledger, entry = cached
                if row["intent"] == "recorded" or ledger["command_kind"] == "timeline.commit":
                    self._verify_accepted(ledger, row, allow_archived=allow_archived)
                return entry
            row = self.conn.execute("SELECT * FROM timeline_commit_history WHERE publication_id=? "
                                    "AND project_id=? AND timeline_id=?", (publication_id, project_id, timeline_id)).fetchone()
            if row is None:
                reject("history_unavailable", diagnostic_reason="store_history_entry_missing")
            assert row is not None
            ledger = self.conn.execute("SELECT * FROM command_idempotency WHERE txn_id=?", (publication_id,)).fetchone()
            if ledger is None or ledger["first_project_seq"] != row["project_seq"]:
                reject("history_unavailable", diagnostic_reason="store_history_ledger_mismatch")
            assert ledger is not None
            if row["intent"] == "recorded" or ledger["command_kind"] == "timeline.commit":
                self._verify_accepted(ledger, row, allow_archived=allow_archived)
            previous = None if row["previous_publication_id"] is None else {
                "revision_id": row["previous_revision_id"], "publication_id": row["previous_publication_id"]}
            records = json.loads(row["records_json"]) if row["records_json"] is not None else None
            entry = {"publication_id": publication_id, "revision_id": row["revision_id"], "previous": previous,
                     "receipt": self._envelope(ledger, project_id)["receipt"], "intent": row["intent"],
                     "records": records, "provider_version": row["provider_version"],
                     "compiler_version": row["compiler_version"], "publisher": row["publisher"],
                     **json.loads(row["metadata_json"])}
            entry.pop(_PRIVATE_EXECUTION, None)
            # Modern records carry the authenticated provider projection.  A
            # legacy edge has no recorder and must remain null/absent rather
            # than receiving invented step or undo authority.
            if records is not None and "steps" in records:
                entry["steps"] = records["steps"]
            if self._verification.current["traversal"] is None:
                self._history_state["entries"][identity] = (dict(row), dict(ledger), detached(entry))
            return entry

    @_evaluation
    def _read_history(self, project_id, timeline_id, *, cursor, limit):
        # The bound is detached from the process's verified state and remains
        # fixed for pagination, including after our own next accepted commit.
        with self.store._mutex:
            if cursor is None:
                through, bound = self._head_entry(project_id, timeline_id)
                bound = detached(bound)
            else:
                try:
                    decoded = json.loads(base64.urlsafe_b64decode(cursor.encode()))
                    scope = decoded["scope"]
                    if scope[:2] != [project_id, timeline_id] or scope[3] is not None:
                        raise ValueError()
                    through = scope[2]
                except (ValueError, KeyError, TypeError, IndexError) as exc:
                    raise ValidationError("invalid commit history cursor") from exc
                bound = self.history_entry(project_id, timeline_id, through["publication_id"])
            return self._history_page(project_id, timeline_id, through, bound, cursor=cursor, limit=limit)

    @_evaluation
    def history(self, project_id, timeline_id, through, after_publication_id=None, cursor=None, limit=100):
        return detached(self._history_view(project_id, timeline_id, through,
                                           after_publication_id=after_publication_id, cursor=cursor, limit=limit))

    @_evaluation
    def _history_view(self, project_id, timeline_id, through, after_publication_id=None, cursor=None, limit=100):
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValidationError("history limit must be 1–200")
        with self.store._mutex:
            bound = self._history_entry_view(project_id, timeline_id, through["publication_id"])
            return self._history_page(project_id, timeline_id, through, bound,
                                      after_publication_id=after_publication_id, cursor=cursor, limit=limit, _entry_views=True)

    def _history_page(self, project_id, timeline_id, through, bound, *,
                      after_publication_id=None, cursor=None, limit, _entry_views=False):
        if bound["revision_id"] != through["revision_id"]:
            reject("history_unavailable", diagnostic_reason="store_history_bound_revision_mismatch")
        read_entry = self._history_entry_view if _entry_views else self.history_entry
        after = read_entry(project_id, timeline_id, after_publication_id) if after_publication_id else None
        low = after["receipt"]["project_seq"][0] if after else 0
        high = bound["receipt"]["project_seq"][0]
        cursor_scope = [project_id, timeline_id, through, after_publication_id]
        start = low
        if cursor is not None:
            try:
                decoded = json.loads(base64.urlsafe_b64decode(cursor.encode()))
                if decoded["scope"] != cursor_scope or type(decoded["seq"]) is not int or not low < decoded["seq"] <= high:
                    raise ValueError()
                start = decoded["seq"]
            except (ValueError, KeyError, TypeError) as exc:
                raise ValidationError("invalid history cursor") from exc
        if low > high:
            reject("history_unavailable", diagnostic_reason="store_history_bound_order_invalid")
        rows = self.conn.execute("SELECT publication_id FROM timeline_commit_history WHERE project_id=? AND timeline_id=? "
                                 "AND project_seq>? AND project_seq<=? ORDER BY project_seq LIMIT ?",
                                 (project_id, timeline_id, start, high, limit + 1)).fetchall()
        # The bound is the exact entry authenticated in this locked read, not
        # another publication or closure with coincidentally equal bytes.
        items = [bound if row[0] == bound["publication_id"] else
                 read_entry(project_id, timeline_id, row[0]) for row in rows[:limit]]
        previous = self.conn.execute("SELECT publication_id, revision_id FROM timeline_commit_history WHERE project_id=? "
                                    "AND timeline_id=? AND project_seq<=? ORDER BY project_seq DESC LIMIT 1",
                                    (project_id, timeline_id, start)).fetchone()
        expected = dict(previous) if previous else None
        for entry in items:
            if entry["previous"] != expected:
                reject("history_unavailable", diagnostic_reason="store_history_chain_break")
            expected = {"publication_id": entry["publication_id"], "revision_id": entry["revision_id"]}
        if len(rows) <= limit and expected != through:
            reject("history_unavailable", diagnostic_reason="store_history_through_mismatch")
        next_cursor = None
        if len(rows) > limit:
            next_cursor = base64.urlsafe_b64encode(canonical_json({"scope": cursor_scope,
                "seq": items[-1]["receipt"]["project_seq"][0]}).encode()).decode()
        return {"items": items, "next_cursor": next_cursor, "head": detached(through)}

    @_evaluation
    def revision_closure(self, project_id, timeline_id, revision_id, *, allow_archived=False):
        with self.store._mutex:
            if allow_archived:
                row = self.conn.execute(
                    "SELECT 1 FROM timelines WHERE id=? AND project_id=?",
                    (timeline_id, project_id),
                ).fetchone()
                if row is None:
                    reject("history_unavailable", diagnostic_reason="store_revision_scope_missing")
            else:
                self._membership(project_id, timeline_id)
            identity = (project_id, timeline_id, revision_id)
            cached = self._history_state["closures"].get(identity)
            if cached is not None:
                return detached(cached)
            parent = self.conn.execute("SELECT * FROM parent_composition_revisions WHERE id=? AND project_id=? AND timeline_id=?",
                                       (revision_id, project_id, timeline_id)).fetchone()
            if parent is None:
                reject("history_unavailable", diagnostic_reason="store_revision_missing")
            if parent["commit_manifest_json"] is None:
                from .timeline_commit_baseline import verify_revision_source
                document = verify_revision_source(self.conn, project_id, timeline_id, revision_id,
                                                   read_object=self._read_history_object)
                self._validate_closure(document, allow_archived=allow_archived)
                self._history_state["closures"][identity] = detached(document)
                return document
            manifest = json.loads(parent["commit_manifest_json"])
            document = {"schema_version": 1, "project_id": project_id, "timeline_id": timeline_id,
                        "parent_revision": self._image(parent), "shot_revisions": [],
                        "internal_timeline_revisions": [], "dependency_manifest": manifest}
            for family, table in (("shot_revisions", "shot_revisions"), ("internal_timeline_revisions", "internal_timeline_revisions")):
                pins = manifest["shots" if family == "shot_revisions" else "internal_timelines"]
                for pin in pins:
                    row = self.conn.execute(f"SELECT * FROM {table} WHERE id=? AND project_id=?", (pin["revision_id"], project_id)).fetchone()
                    if row is None:
                        reject("history_unavailable", diagnostic_reason="store_revision_dependency_missing")
                    image = self._image(row)
                    image.update({key: row[key] for key in ("shot_id", "internal_timeline_revision_id") if key in row.keys()})
                    if family == "internal_timeline_revisions":
                        image["timeline_id"] = row["timeline_id"]
                    document[family].append(image)
            self._validate_closure(document, allow_archived=allow_archived)
            self._verify_inputs(document)
            self._history_state["closures"][identity] = detached(document)
            return document

    @_evaluation
    def source_revision_closure(self, project_id, timeline_id, revision_id, publication_id,
                                content_digest):
        """Return one authenticated historical source closure.

        The source pair is deliberately checked separately from the request's
        destination head.  A revision ID alone is not a source authority: the
        accepted publication edge and the immutable parent digest must agree
        with the caller's exact reference.
        """
        with self.store._mutex:
            entry = self.history_entry(project_id, timeline_id, publication_id)
            if entry["revision_id"] != revision_id:
                reject("dependency_unavailable", "source publication and revision pins disagree")
            document = self.revision_closure(project_id, timeline_id, revision_id)
            if document is not None:
                parent = document.get("parent_revision")
                if not isinstance(parent, dict) or parent.get("content_digest") != content_digest:
                    reject("dependency_unavailable", "source revision content digest disagrees")
                return document
            reject("dependency_unavailable", "source revision closure is unavailable")

    def _verify_inputs(self, document):
        for pin in document["dependency_manifest"]["documents"]:
            row = self.conn.execute("SELECT c.content_json, c.content_size, b.kind FROM timeline_document_input_contents c "
                "JOIN timeline_document_input_bindings b ON b.content_digest=c.content_digest "
                "JOIN timeline_document_input_links l ON l.project_id=b.project_id AND l.document_id=b.document_id "
                "AND l.document_version=b.document_version AND l.content_digest=b.content_digest "
                "WHERE l.project_id=? AND l.timeline_id=? AND l.revision_id=? AND b.document_id=? "
                "AND b.document_version=? AND b.content_digest=? LIMIT 1",
                (document["project_id"], document["timeline_id"], document["parent_revision"]["revision_id"],
                 pin["document_id"], pin["version"], pin["content_digest"])).fetchone()
            if row is None or digest(json.loads(row["content_json"])) != pin["content_digest"] or len(row["content_json"].encode()) != row["content_size"]:
                reject("dependency_unavailable", "retained input is missing or corrupt")
            from .timeline_commit_inputs import PROJECT_PACK_KIND, validate_pack_snapshot_objects
            if row["kind"] == PROJECT_PACK_KIND:
                validate_pack_snapshot_objects(self.conn, document["project_id"], json.loads(row["content_json"]))

    @_evaluation
    def integrity_errors(self):
        errors = []
        previous = {}
        for edge in self.conn.execute("SELECT * FROM timeline_commit_history ORDER BY project_id, timeline_id, project_seq"):
            try:
                key = (edge["project_id"], edge["timeline_id"])
                expected = previous.get(key)
                actual = (edge["previous_publication_id"], edge["previous_revision_id"])
                if actual != (expected if expected else (None, None)):
                    raise ValueError("history ancestry mismatch")
                previous[key] = (edge["publication_id"], edge["revision_id"])
                ledger = self.conn.execute("SELECT * FROM command_idempotency WHERE txn_id=?", (edge["publication_id"],)).fetchall()
                if len(ledger) != 1 or ledger[0]["first_project_seq"] != edge["project_seq"]:
                    raise ValueError("history receipt missing or ambiguous")
                if edge["intent"] == "recorded":
                    self._verify_accepted(ledger[0], edge)
                    self._verify_inputs(json.loads(ledger[0]["result_json"])["canonical_document"])
                elif edge["records_json"] is not None or ledger[0]["command_kind"] != "parent_composition.publish":
                    raise ValueError("invented legacy provenance")
            except Exception as exc:
                errors.append({"table": "timeline_commit_history", "id": edge["publication_id"], "reason": str(exc)})
        for key, expected in previous.items():
            head = self.conn.execute("SELECT publication_id, revision_id FROM parent_composition_heads WHERE project_id=? AND timeline_id=?", key).fetchone()
            if head is None or tuple(head) != expected:
                errors.append({"table": "parent_composition_heads", "id": key[1], "reason": "publication head mismatch"})
        for row in self.conn.execute("SELECT * FROM timeline_document_input_contents"):
            try:
                value = detached(json.loads(row["content_json"]))
                if digest(value) != row["content_digest"] or canonical_json(value) != row["content_json"] or len(row["content_json"].encode()) != row["content_size"]:
                    raise ValueError("retained input digest mismatch")
            except Exception as exc:
                errors.append({"table": "timeline_document_input_contents", "id": row["content_digest"], "reason": str(exc)})
        for row in self.conn.execute("SELECT l.* FROM timeline_document_input_links l LEFT JOIN timeline_commit_history h "
                                     "ON h.publication_id=l.publication_id AND h.project_id=l.project_id "
                                     "AND h.timeline_id=l.timeline_id AND h.revision_id=l.revision_id WHERE h.publication_id IS NULL"):
            errors.append({"table": "timeline_document_input_links", "id": row["publication_id"], "reason": "orphan retained input link"})
        return errors

    def shot_closure(self, project_id, shot_id, revision_id):
        with self.store._mutex:
            row = self.conn.execute("SELECT * FROM shot_revisions WHERE id=? AND project_id=? AND shot_id=?",
                                    (revision_id, project_id, shot_id)).fetchone()
            if row is None:
                reject("dependency_unavailable")
            internal = self.conn.execute("SELECT * FROM internal_timeline_revisions WHERE id=? AND project_id=?",
                                         (row["internal_timeline_revision_id"], project_id)).fetchone()
            if internal is None:
                reject("dependency_unavailable")
            shot = {**self._image(row), "shot_id": shot_id, "internal_timeline_revision_id": internal["id"]}
            image = {**self._image(internal), "timeline_id": internal["timeline_id"]}
            if digest(shot["payload"]) != shot["content_digest"] or digest(image["payload"]) != image["content_digest"]:
                reject("dependency_unavailable")
            if shot["payload"].get("internal_timeline_revision_id") != internal["id"]:
                reject("dependency_unavailable")
            manifests = self.conn.execute("SELECT DISTINCT json_extract(p.commit_manifest_json, '$.media'), "
                "json_extract(p.commit_manifest_json, '$.documents') FROM parent_composition_revisions p "
                "JOIN composition_revision_occurrences o ON o.parent_revision_id=p.id "
                "WHERE p.project_id=? AND o.shot_id=? AND o.shot_revision_id=? AND p.commit_manifest_json IS NOT NULL LIMIT 2",
                (project_id, shot_id, revision_id)).fetchall()
            if len(manifests) != 1:
                reject("history_unavailable", "shot input closure is unavailable or ambiguous",
                       diagnostic_reason="store_shot_input_closure_ambiguous")
            parent = self.conn.execute("SELECT p.timeline_id, p.id FROM parent_composition_revisions p "
                "JOIN composition_revision_occurrences o ON o.parent_revision_id=p.id "
                "WHERE p.project_id=? AND o.shot_id=? AND o.shot_revision_id=? AND p.commit_manifest_json IS NOT NULL ORDER BY p.id LIMIT 1",
                (project_id, shot_id, revision_id)).fetchone()
            if parent is None:
                reject("history_unavailable", diagnostic_reason="store_shot_parent_missing")
            document = self.revision_closure(project_id, parent["timeline_id"], parent["id"])
            return {"shot_revision": shot, "internal_timeline_revision": image,
                    "media": document["dependency_manifest"]["media"], "documents": document["dependency_manifest"]["documents"]}

    def _verify_parent_rows(self, document):
        parent_id = document["parent_revision"]["revision_id"]
        occurrences = document["parent_revision"]["payload"]["occurrences"]
        rows = self.conn.execute("SELECT * FROM composition_revision_occurrences WHERE parent_revision_id=? ORDER BY ordinal", (parent_id,)).fetchall()
        if len(rows) != len(occurrences):
            reject("history_unavailable", diagnostic_reason="store_occurrence_rows_mismatch")
        for ordinal, (row, occurrence) in enumerate(zip(rows, occurrences)):
            expected = {"parent_revision_id": parent_id, "project_id": document["project_id"], "ordinal": ordinal,
                        **{k: occurrence[k] for k in ("occurrence_id", "shot_id", "shot_revision_id", "duration_ms", "track")},
                        "gain": occurrence.get("gain", 1),
                        "muted": int(occurrence.get("muted", occurrence.get("mute", False))),
                        "placement_json": canonical_json(occurrence["placement"]),
                        **{k + "_json": canonical_json(occurrence.get(k, default)) for k, default in
                           (("source_offset", 0), ("speed", 1), ("transform", {}), ("provenance", {}))}}
            if dict(row) != expected:
                reject("history_unavailable", diagnostic_reason="store_occurrence_row_mismatch")
        manifest = document["dependency_manifest"]
        expected = [("shot_revision", p["revision_id"], p["content_digest"]) for p in manifest["shots"]]
        expected += [("internal_timeline_revision", p["revision_id"], p["content_digest"]) for p in manifest["internal_timelines"]]
        expected += [("media", p["media_id"], p["content_digest"]) for p in manifest["media"]]
        rows = self.conn.execute("SELECT dependency_kind, dependency_id, content_digest, ordinal FROM composition_revision_dependencies "
                                 "WHERE parent_revision_id=? ORDER BY ordinal", (parent_id,)).fetchall()
        if [tuple(row) for row in rows] != [(*pin, ordinal) for ordinal, pin in enumerate(expected)]:
            reject("history_unavailable", diagnostic_reason="store_dependency_rows_mismatch")

    @staticmethod
    def _image(row):
        return {"revision_id": row["id"], "content_digest": row["content_digest"], "payload": json.loads(row["payload_json"])}

    def _validate_closure(self, document, *, allow_archived=False):
        from .visual_seam import parent_clips

        project_id, timeline_id = document["project_id"], document["timeline_id"]
        if allow_archived:
            row = self.conn.execute(
                "SELECT 1 FROM timelines WHERE id=? AND project_id=?",
                (timeline_id, project_id),
            ).fetchone()
            if row is None:
                reject("history_unavailable", diagnostic_reason="store_shot_revision_scope_missing")
        else:
            self._membership(project_id, timeline_id)
        parent = document["parent_revision"]
        try:
            parent_clips(parent["payload"])
        except (ConflictError, ValidationError) as exc:
            reject("invalid_closure", str(exc), status=422)
        shots, internals = document["shot_revisions"], document["internal_timeline_revisions"]
        manifest = document["dependency_manifest"]
        for clip in parent["payload"]["clips"]:
            if not isinstance(clip, dict) or set(clip) & {"occurrence_id", "shot_revision_id", "parent_revision_id", "composition_revision_id"}:
                reject("invalid_closure", "ordinary clips cannot contain nested compositions", status=422)
        for images, table, identity in (([parent], "parent_composition_revisions", "timeline_id"),
                                        (shots, "shot_revisions", "shot_id"), (internals, "internal_timeline_revisions", "timeline_id")):
            if len({image["revision_id"] for image in images}) != len(images):
                reject("invalid_closure", status=422)
            for image in images:
                if digest(image["payload"]) != image["content_digest"]:
                    reject("invalid_closure", "revision content digest mismatch", status=422)
                owner_id = image.get(identity, timeline_id)
                existing = self.conn.execute(f"SELECT * FROM {table} WHERE id=?", (image["revision_id"],)).fetchone()
                if existing is not None and (existing["project_id"] != project_id or existing[identity] != owner_id
                        or existing["payload_json"] != canonical_json(image["payload"]) or existing["content_digest"] != image["content_digest"]):
                    reject("revision_identity_mismatch")
                if table == "parent_composition_revisions" and existing is not None and existing["commit_manifest_json"] is not None:
                    if existing["commit_manifest_json"] != canonical_json(manifest):
                        reject("revision_identity_mismatch", "revision dependency closure changed")
                if table == "internal_timeline_revisions":
                    payload = image["payload"]
                    nested_fields = {"occurrences", "occurrence_records", "parent_composition", "nested_composition",
                                     "occurrence_id", "shot_revision_id", "parent_revision_id", "composition_revision_id"}
                    # Only authored structure is reserved; params and provenance remain opaque.
                    if set(payload) & nested_fields or any(set(clip) & nested_fields for clip in payload.get("clips", [])):
                        reject("invalid_closure", "internal timeline cannot contain a nested composition", status=422)
                    owner = self.conn.execute("SELECT project_id FROM timelines WHERE id=?", (owner_id,)).fetchone()
                    shot_id = owner_id.removeprefix("shot:") if owner_id.startswith("shot:") else None
                    if owner is None and shot_id:
                        owner = self.conn.execute("SELECT project_id FROM project_shots WHERE id=?", (shot_id,)).fetchone()
                        if owner is None and any(s["shot_id"] == shot_id for s in shots):
                            owner = {"project_id": project_id}
                    if owner is None or owner["project_id"] != project_id:
                        reject("invalid_closure", "internal timeline scope mismatch")
                if table == "shot_revisions":
                    if existing is not None and existing["internal_timeline_revision_id"] != image["internal_timeline_revision_id"]:
                        reject("revision_identity_mismatch")
                    owner = self.conn.execute("SELECT project_id FROM project_shots WHERE id=?", (owner_id,)).fetchone()
                    if owner is not None and owner["project_id"] != project_id:
                        reject("invalid_closure", "shot scope mismatch")
                    if image["payload"].get("internal_timeline_revision_id") != image["internal_timeline_revision_id"]:
                        reject("invalid_closure", status=422)
                    payload = image["payload"]
                    if set(payload) & {"occurrences", "occurrence_records", "parent_composition", "parent_revision_id", "composition_revision_id"}:
                        reject("invalid_closure", "nested shot composition", status=422)
                    if not isinstance(payload.get("items", []), list) or any(not isinstance(item, dict)
                            or not isinstance(item.get("item_id", item.get("id")), str) or not item.get("media_id")
                            for item in payload.get("items", [])):
                        reject("invalid_closure", "shot items cannot be projected", status=422)
        shot_keys = {(s["shot_id"], s["revision_id"]) for s in shots}
        occurrences = parent["payload"]["occurrences"]
        for occurrence in occurrences:
            speed = occurrence.get("speed", 1)
            valid_speed = (type(speed) in (int, float) and speed > 0) or (isinstance(speed, dict)
                and set(speed) == {"numerator", "denominator"} and all(type(v) is int and v > 0 for v in speed.values()))
            if not valid_speed or not occurrence["placement"] or not isinstance(occurrence.get("muted", occurrence.get("mute", False)), bool):
                reject("invalid_closure", "invalid occurrence timing or placement", status=422)
            if "muted" in occurrence and "mute" in occurrence and occurrence["muted"] != occurrence["mute"]:
                reject("invalid_closure", "ambiguous occurrence mute", status=422)
        if shot_keys != {(o["shot_id"], o["shot_revision_id"]) for o in occurrences}:
            reject("invalid_closure", "incomplete or extraneous shot closure", status=422)
        if len({o["occurrence_id"] for o in occurrences}) != len(occurrences):
            reject("invalid_closure", "duplicate occurrences", status=422)
        if {s["internal_timeline_revision_id"] for s in shots} != {i["revision_id"] for i in internals}:
            reject("invalid_closure", "incomplete or extraneous internal closure", status=422)
        for images, key, fields, sort_keys in ((shots, "shots", ("shot_id", "revision_id", "internal_timeline_revision_id", "content_digest"), ("shot_id", "revision_id")),
                (internals, "internal_timelines", ("timeline_id", "revision_id", "content_digest"), ("timeline_id", "revision_id"))):
            ordered = sorted(images, key=lambda image: tuple(image[k] for k in sort_keys))
            if images != ordered or manifest[key] != [{k: image[k] for k in fields} for image in ordered]:
                reject("invalid_closure", "manifest does not equal complete closure", status=422)
        media = manifest["media"]
        if media != sorted(media, key=lambda item: item["media_id"]) or len({m["media_id"] for m in media}) != len(media):
            reject("invalid_closure", status=422)
        for pin in media:
            if not _DIGEST.fullmatch(pin["media_id"]) or pin["content_digest"] != pin["media_id"]:
                reject("invalid_closure", status=422)
            row = self.conn.execute("SELECT o.size FROM objects o JOIN project_objects p ON p.digest=o.digest "
                                    "WHERE p.project_id=? AND p.relation='managed' AND o.digest=?", (project_id, pin["media_id"][7:])).fetchone()
            if row is None:
                reject("dependency_unavailable")
            data = self._read_history_object(pin["media_id"][7:])
            if len(data) != row["size"] or "sha256:" + hashlib.sha256(data).hexdigest() != pin["media_id"]:
                reject("dependency_unavailable")
        payload_media = set()
        def collect(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key in {"media_id", "object_id"} and isinstance(child, str):
                        normalized = child if child.startswith("sha256:") else "sha256:" + child
                        if _DIGEST.fullmatch(normalized):
                            payload_media.add(normalized)
                    collect(child)
            elif isinstance(value, list):
                for child in value:
                    collect(child)
        for image in [parent, *shots, *internals]:
            collect(image["payload"])
        if not payload_media <= {m["media_id"] for m in media}:
            reject("invalid_closure", "unaccounted media", status=422)
        pins = manifest["documents"]
        if pins != sorted(pins, key=lambda p: (p["document_id"], p["version"], p["content_digest"])) or len({canonical_json(p) for p in pins}) != len(pins):
            reject("invalid_closure", status=422)
        existing = self.conn.execute("SELECT 1 FROM parent_composition_revisions WHERE id=?", (parent["revision_id"],)).fetchone()
        if existing is not None:
            self._verify_parent_rows(document)

    def _binding_continuations(self, project, timeline, base_publication, expected, *, allow_archived=False):
        continuations, cursor, seen = {}, expected, set()
        while cursor is not None and cursor["publication_id"] != base_publication:
            if cursor["publication_id"] in seen:
                reject("history_unavailable", "history ancestry contains a cycle",
                       diagnostic_reason="store_history_ancestry_cycle")
            seen.add(cursor["publication_id"])
            entry = self.history_entry(project, timeline, cursor["publication_id"], allow_archived=allow_archived)
            if entry["records"]:
                for record in entry["records"]["commands"]:
                    for binding in record["bindings"]:
                        if binding.get("key") == "commit.materialization":
                            continuations.setdefault(binding["physical_ref"], set()).add(binding["successor"])
            cursor = entry["previous"]
        if cursor is None:
            reject("history_unavailable", "base is outside evaluated head ancestry",
                   diagnostic_reason="store_history_base_outside_ancestry")
        return continuations

    def _inverse_stage_history(self, project, timeline, records, *, allow_archived=False):
        """Pass only store-authenticated undo sources to inverse-stage auth."""
        if not any(binding.get("key") == "inverse.stage"
                   for record in records.get("commands", []) for binding in record.get("bindings", [])):
            return None
        publications = records.get("undo_of")
        if not isinstance(publications, list):
            reject("history_unavailable", "inverse stage history targets are unavailable",
                   diagnostic_reason="store_inverse_stage_targets_unavailable")
        return {publication: self.history_entry(project, timeline, publication, allow_archived=allow_archived)
                for publication in publications}

    def _validate(self, context, prepared, inputs):
        # Callers run _check_shot_destinations first, which validates the schema.
        request = context["request"]
        document = prepared["canonical_document"]
        if (document["project_id"], document["timeline_id"]) != (request["project_id"], request["timeline_id"]):
            reject("invalid_closure", status=422)
        if prepared["document_digest"] != digest(document):
            reject("invalid_closure", "whole-document digest mismatch", status=422)
        self._validate_closure(document)
        records = prepared["records"]
        commands = records["commands"]
        if not commands or [r["ordinal"] for r in commands] != list(range(len(commands))):
            reject("invalid_records", status=422)
        recorded_steps = records.get("steps")
        requested_steps = request.get("steps")
        execution = None
        _validate_record_metadata(request, records)
        if _is_v2_request(request) and recorded_steps is None:
            reject("invalid_records", "provider did not return authoritative step records", status=422)
        if recorded_steps is not None:
            ordinals = [ordinal for step in recorded_steps for ordinal in step["command_ordinals"]]
            if ordinals != list(range(len(commands))) or len({step["id"] for step in recorded_steps}) != len(recorded_steps):
                reject("invalid_records", "step records do not partition commands", status=422)
            if requested_steps is not None and [
                    {key: step[key] for key in ("id", "label", "intent", "tags", "command_ordinals")}
                    for step in recorded_steps
                ] != [
                    {key: step[key] for key in ("id", "label", "intent", "tags", "command_ordinals")}
                    for step in requested_steps
                ]:
                reject("invalid_records", "provider step boundaries disagree with the request", status=422)
            from .timeline_commit_auth import validate
            source = self.revision_closure(request["project_id"], request["timeline_id"], prepared["expected_head"]["revision_id"])
            base = self.revision_closure(request["project_id"], request["timeline_id"], request["base_revision_id"])
            continuations = self._binding_continuations(request["project_id"], request["timeline_id"],
                                                       request["base_publication_id"], prepared["expected_head"])
            history = self._inverse_stage_history(request["project_id"], request["timeline_id"], records)
            sequential = None
            if inputs is not None and hasattr(inputs, "_validate_sequential_execution"):
                sequential = inputs._validate_sequential_execution(
                    prepared, source, base, continuations, history,
                )
            from .timeline_commit_auth import sequential_proof_required
            if sequential is None and sequential_proof_required(prepared, source, continuations):
                reject("sequential_proof_unavailable", "moved-head staged physical input requires private sequential proof")
            validate(request, prepared, source, base, continuations, history, sequential=sequential)
            if sequential is not None:
                execution = {"capture": sequential["retained_capture"], "prepared": prepared}
        elif any("physical_ref" in binding for record in commands for binding in record["bindings"]):
            reject("invalid_records", "physical bindings require authoritative steps", status=422)
        for record in commands:
            if any(write["cause"] >= len(commands) for write in record["derived_writes"]):
                reject("invalid_records", status=422)
        undo_seqs = [self.history_entry(request["project_id"], request["timeline_id"], publication_id)["receipt"]["project_seq"][0]
                     for publication_id in records["undo_of"]]
        if undo_seqs != sorted(set(undo_seqs)):
            reject("invalid_records", "undo targets must follow acceptance order", status=422)
        restored = records["restored_from"]
        if restored is not None:
            source = self.revision_closure(request["project_id"], request["timeline_id"], restored["revision_id"])
            if source["parent_revision"]["content_digest"] != restored["content_digest"]:
                reject("invalid_records", status=422)
        for event in prepared["semantic_events"]:
            if event["command_ordinal"] >= len(commands) or self.validate_event is None:
                reject("invalid_event", status=422)
            self.validate_event(event)
        if inputs is not None and not has_materialization(prepared):
            inputs.validate(prepared)
        elif inputs is None and (document["dependency_manifest"]["documents"] or any(r["dependencies"] for r in commands)):
            reject("dependency_unavailable", "request-private dependency captures required")
        allocations = self._materializations(context, prepared, inputs)
        self._check_inherited_allocations(request["project_id"], request["timeline_id"], records, allocations)
        return {"canonical_document": document, "document_digest": prepared["document_digest"],
                "commands": [r["command"] for r in commands], "id_map": prepared["id_map"],
                "provider_version": prepared["provider_version"], "compiler_version": prepared["compiler_version"]}, execution

    def _materializations(self, context, prepared, inputs):
        if has_materialization(prepared):
            from .timeline_commit_port import RequestCommitPort
            if not isinstance(inputs, RequestCommitPort) or canonical_json(inputs._provider_context()) != canonical_json(context):
                reject("dependency_unavailable", "request-private materialization captures required")
            return inputs.validate(prepared)
        return materialization_join(prepared, context["request"]["project_id"], context["request"]["timeline_id"],
                                    lambda _: reject("dependency_unavailable"))

    @staticmethod
    def _same_materialization_slot(shot, owner, allocation, prior_allocation, before, after):
        if allocation is None or allocation[0] != owner:
            return False
        pin = allocation[1]
        source = pin["source"]
        edge = [(o["shot_id"], o["shot_revision_id"]) for o in before["parent_revision"]["payload"]["occurrences"]
                if o["occurrence_id"] == owner]
        if edge != [(source["shot_id"], source["revision_id"])]:
            return False
        output = [o["shot_id"] for o in after["parent_revision"]["payload"]["occurrences"] if o["occurrence_id"] == owner]
        members = {i.get("item_id", i.get("id")) for s in after["shot_revisions"]
                   if s["shot_id"] == shot for i in s["payload"].get("items", [])}
        if output != [shot]:
            return False
        if prior_allocation is not None:
            return canonical_json(allocation) == canonical_json(prior_allocation)
        # Frozen M1 edges have no new allocation facts. Their already verified
        # source/binding/read proof remains usable only with this exact closure.
        return (canonical_json(pin["parent"]) == canonical_json({k: before["parent_revision"][k]
                                                                for k in ("revision_id", "content_digest")})
                and members == set(source["item_id_map"].values()))

    def _check_shot_destinations(self, context, prepared, inputs=None):
        # Check the wire shape before inspecting destinations. This preflight
        # precedes closure validation so foreign occupants get the same refusal.
        try:
            self.validate_prepared(prepared)
        except Exception:
            reject("invalid_prepared", "prepared commit does not satisfy the frozen schema", status=422)
        document, records = prepared["canonical_document"], prepared["records"]
        project, timeline = context["request"]["project_id"], context["request"]["timeline_id"]
        # Exact immutable reuse does not write the mutable shot projection.
        writes = [s for s in document["shot_revisions"] if self.conn.execute(
            "SELECT 1 FROM shot_revisions WHERE id=?", (s["revision_id"],)).fetchone() is None]
        if len({s["shot_id"] for s in writes}) != len(writes):
            reject("identity_collision")
        # Agent owns command.created consistency. Reserve the exact recorded
        # reference without interpreting command arguments or inventing ID forms.
        claims = [(item["kind"], item["ref"]) for record in records["commands"]
                  if record["command"]["op"] != "timeline.inverse" for item in record["created"]]
        claims = [(kind, self._reservation_identity(kind, ref)) for kind, ref in claims]
        if len(set(claims)) != len(claims):
            reject("identity_collision")
        self._check_birth_destinations(claims)
        occupied = set()
        for image in writes:
            row = self.conn.execute("SELECT project_id FROM project_shots WHERE id=?", (image["shot_id"],)).fetchone()
            if row is not None:
                if row["project_id"] != project:
                    reject("destination_occupied")
                occupied.add(image["shot_id"])
        allocations = self._materializations(context, prepared, inputs)
        if not writes and not claims:
            return
        current = self.revision_closure(project, timeline, prepared["expected_head"]["revision_id"])
        owned = {s["shot_id"] for s in current["shot_revisions"]}
        fresh = {s["shot_id"] for s in writes} - owned
        for shot in fresh:
            for row in self.conn.execute("SELECT project_id FROM shot_revisions WHERE shot_id=?", (shot,)):
                if row["project_id"] != project:
                    reject("destination_occupied")
                occupied.add(shot)
        heads = {shot: self.conn.execute("SELECT revision_id FROM shot_revision_heads WHERE shot_id=? AND project_id=?",
                                        (shot, project)).fetchone() for shot in occupied}

        def unchanged(shot, revision):
            return heads[shot] is not None and heads[shot]["revision_id"] == revision

        authorized = set()
        for image in current["shot_revisions"]:
            shot = image["shot_id"]
            if shot in occupied and unchanged(shot, image["revision_id"]):
                # A film pin authorizes its own projection, not a newer catalog
                # head written since that pin was accepted.
                occupied.remove(shot)
                authorized.add(shot)
        restored_items = set()
        if occupied:
            from .timeline_commit_port import command_leaves

            requested = [p for c in command_leaves(context["request"]["commands"])
                         if c["op"] == "timeline.inverse" for p in c["args"]["publications"]]
            if requested != prepared["records"]["undo_of"]:
                reject("destination_occupied")

            def edges(value):
                return {o["occurrence_id"]: (o["shot_id"], o["shot_revision_id"])
                        for o in value["parent_revision"]["payload"]["occurrences"]}

            active, output = edges(current), edges(document)
            cursor, remaining = prepared["expected_head"], set(requested)
            while cursor and (occupied or remaining):
                # history_entry authenticates the records against the receipt/event.
                entry = self.history_entry(project, timeline, cursor["publication_id"])
                previous = entry["previous"]
                if entry["intent"] == "recorded":
                    before = self.revision_closure(project, timeline, previous["revision_id"])
                    prior = edges(before)
                    if entry["publication_id"] in remaining:
                        for o, (shot, _) in prior.items():
                            owner, source = "occurrence:" + o, before["parent_revision"]
                            if (shot in occupied and unchanged(shot, prior[o][1])
                                    and output.get(o, (None,))[0] == shot) and any(
                                    w["ref"] == "shot:" + shot or w["ref"] == owner or w["ref"].startswith(owner + "/")
                                    or (w["ref"] == "timeline" and not w["path"] and w["before"] == {
                                        "state": "present", "value": {k: source[k] for k in ("revision_id", "content_digest")}})
                                    for r in entry["records"]["commands"] for w in r["writes"]):
                                occupied.discard(shot)
                                authorized.add(shot)
                                restored_items.update(i.get("item_id", i.get("id"))
                                    for s in before["shot_revisions"] if s["shot_id"] == shot
                                    for i in s["payload"].get("items", []))
                        remaining.remove(entry["publication_id"])
                    accepted_document = self.revision_closure(project, timeline, entry["revision_id"])
                    after = edges(accepted_document)
                    historical = {**entry["receipt"]["result"], "records": entry["records"], "expected_head": previous}
                    prior_allocations = (materialization_join(historical, project, timeline,
                        lambda revision: self.revision_closure(project, timeline, revision))
                        if has_materialization(historical) else {})
                    for o, (shot, _) in after.items():
                        owner = "occurrence:" + o
                        if shot in allocations or shot in prior_allocations:
                            if not self._same_materialization_slot(shot, o, allocations.get(shot),
                                    prior_allocations.get(shot), before, accepted_document):
                                continue
                        if (shot in occupied and unchanged(shot, after[o][1])
                                and output.get(o, (None,))[0] == shot and o in prior
                                and active.get(o) == prior[o]
                                and any(any(b["ref"] == owner for b in r["bindings"])
                                        and any(read["ref"] == owner + "/shot" and read["path"] == ["shot_id"]
                                                and read["state"] == {"state": "present", "value": prior[o][0]}
                                                for read in r["reads"]) for r in entry["records"]["commands"])):
                            occupied.remove(shot)
                            authorized.add(shot)
                cursor = previous
            if occupied or remaining:
                reject("destination_occupied")
        destinations, fresh_items = {}, set()
        old_items = {s["shot_id"]: {i.get("item_id", i.get("id")) for i in s["payload"].get("items", [])}
                     for s in current["shot_revisions"]}
        for image in writes:
            shot = image["shot_id"]
            for item in image["payload"].get("items", []):
                identity = item.get("item_id", item.get("id"))
                if not identity or identity in destinations:
                    reject("identity_collision")
                destinations[identity] = shot
                if identity not in old_items.get(shot, set()):
                    fresh_items.add(identity)
        for identity, shot in destinations.items():
            row = self.conn.execute("SELECT shot_id FROM shot_items WHERE id=?", (identity,)).fetchone()
            if row is not None and (row["shot_id"] != shot or shot not in authorized):
                reject("identity_collision")
            for retained in self.conn.execute(
                    "SELECT DISTINCT s.* FROM shot_revisions s, json_each(s.payload_json, '$.items') i "
                    "WHERE COALESCE(json_extract(i.value, '$.item_id'), json_extract(i.value, '$.id'))=?", (identity,)):
                if (digest(json.loads(retained["payload_json"])) != retained["content_digest"]
                        or retained["project_id"] != project or retained["shot_id"] != shot or shot not in authorized):
                    reject("identity_collision")
        if not fresh and not fresh_items and not claims:
            return
        # Missing history cannot prove that a free ID was never reserved. Exact
        # matching records are authenticated against their durable receipt/event.
        if self.conn.execute("SELECT 1 FROM command_idempotency c LEFT JOIN timeline_commit_history h ON h.publication_id=c.txn_id "
                             "WHERE c.command_kind='timeline.commit' AND h.publication_id IS NULL LIMIT 1").fetchone():
            reject("identity_collision")
        reservations = set(claims) | {("shot", "shot:" + shot) for shot in fresh - authorized}
        reservations.update(("item", identity) for identity in fresh_items - restored_items)
        for kind, ref in reservations:
            rows = self.conn.execute(
                "SELECT DISTINCT h.* FROM timeline_commit_history h, "
                "json_each(h.records_json, '$.commands') r, json_each(r.value, '$.created') i "
                "WHERE json_extract(i.value, '$.kind')=? AND (json_extract(i.value, '$.ref')=? OR ?='item') "
                "AND (h.project_id=? OR ?='item') AND (h.timeline_id=? OR ? IN ('shot', 'item'))",
                (kind, ref, kind, project, kind, timeline, kind)).fetchall()
            for entry in rows:
                if kind == "item" and not any(i["kind"] == "item" and self._reservation_identity("item", i["ref"]) == ref
                        for r in json.loads(entry["records_json"])["commands"]
                        if r["command"]["op"] != "timeline.inverse" for i in r["created"]):
                    continue
                ledger = self.conn.execute("SELECT * FROM command_idempotency WHERE txn_id=?", (entry["publication_id"],)).fetchone()
                if ledger is None:
                    reject("identity_collision")
                self._verify_accepted(ledger, entry)
                reject("identity_collision")

    @staticmethod
    def _reservation_identity(kind, ref):
        if kind == "item":
            member = item_identity(ref)
            if member is None:
                reject("invalid_records", "item reservation requires a canonical item ref", status=422)
            return member[1]
        if kind == "shot" and (root_identity(ref) is None or root_identity(ref)[0] != "shot"):
            reject("invalid_records", "shot reservation requires a canonical shot ref", status=422)
        return ref

    def _check_birth_destinations(self, claims):
        # Native births reserve even if a later command removes the new root.
        # Derived allocations never supply these claims; inverses were excluded.
        for kind, ref in claims:
            if kind == "shot":
                shot = root_identity(ref)[1]
                if (self.conn.execute("SELECT 1 FROM project_shots WHERE id=?", (shot,)).fetchone()
                        or self.conn.execute("SELECT 1 FROM shot_revisions WHERE shot_id=?", (shot,)).fetchone()):
                    reject("destination_occupied")
            elif kind == "item":
                if (self.conn.execute("SELECT 1 FROM shot_items WHERE id=?", (ref,)).fetchone()
                        or self.conn.execute("SELECT 1 FROM shot_revisions s, json_each(s.payload_json, '$.items') i "
                            "WHERE COALESCE(json_extract(i.value, '$.item_id'), json_extract(i.value, '$.id'))=? LIMIT 1", (ref,)).fetchone()):
                    reject("identity_collision")

    @_evaluation
    def preview(self, context, prepared, *, authorize, inputs=None):
        context, prepared = detached(context), detached(prepared)
        with self.store._mutex:
            authorize()
            if not context["request"].get("dry_run", False):
                reject("preview_requires_dry_run", status=422)
            self._check_context(context)
            self._check_head(context, prepared["expected_head"])
            self._check_shot_destinations(context, prepared, inputs)
            candidate, _ = self._validate(context, prepared, inputs)
            request = context["request"]
            candidate["merge_mode"] = _effective_merge_mode(request)
            if "steps" in prepared["records"]:
                candidate["steps"] = prepared["records"]["steps"]
            base = {"revision_id": request["base_revision_id"], "publication_id": request["base_publication_id"]}
            return {"data": {"status": "preview", "would_status": "accepted" if prepared["expected_head"] == base else "merged",
                            "base_revision_id": request["base_revision_id"],
                            "base_publication_id": request["base_publication_id"],
                            "evaluated_head": prepared["expected_head"], **candidate}, "receipt": None}

    def _check_context(self, context):
        request = context["request"]
        realm = self._membership(request["project_id"], request["timeline_id"])
        if realm != context["realm_id"] or request_identity(context) != context["request_hash"]:
            reject("invocation_mismatch", status=422)
        if context["invocation"]["operation"] == "commitTimeline" and request != context["invocation"]["body"]:
            reject("invocation_mismatch", status=422)
        if self.history_entry(request["project_id"], request["timeline_id"], request["base_publication_id"])["revision_id"] != request["base_revision_id"]:
            reject("history_unavailable", diagnostic_reason="store_request_base_mismatch")

    def _check_head(self, context, expected):
        from .timeline_commit import StaleHead

        request = context["request"]
        current = self.head(request["project_id"], request["timeline_id"])
        if current != expected:
            raise StaleHead(current)
        base = {"revision_id": request["base_revision_id"], "publication_id": request["base_publication_id"]}
        if any(c["op"] == "timeline.restore" for c in request["commands"]) and expected != base:
            reject("stale_head")

    @_evaluation
    def accept(self, context, prepared, *, authorize, inputs=None):
        context, prepared = detached(context), detached(prepared)
        with self.store._mutex:
            if self.conn.in_transaction:
                raise ProtocolError("commit acceptance requires the outer transaction")
            with self._accepting():
                authorize()
                replay = self._lookup(context)
                if replay is not None:
                    return replay
                if context["request"].get("dry_run", False):
                    reject("dry_run_accept", status=422)
                self._check_context(context)
                self._check_head(context, prepared["expected_head"])
                self._check_shot_destinations(context, prepared, inputs)
                candidate, execution = self._validate(context, prepared, inputs)
                # Validation has accepted these exact records. Physical bindings
                # identify the v2 recorder; native coverage completeness is not
                # a separate submit-time obligation.
                recorder_abi = 2 if any("physical_ref" in binding
                                       for record in prepared["records"]["commands"]
                                       for binding in record["bindings"]) else 1
                request, previous = context["request"], prepared["expected_head"]
                from .timeline_commit_reference_projection import (
                    ReferenceProjectionError,
                    prepare_reference_projection,
                )
                reference_projection = None
                try:
                    previous_document = self.revision_closure(
                        request["project_id"], request["timeline_id"], previous["revision_id"]
                    )
                    timeline = self.conn.execute(
                        "SELECT version FROM timelines WHERE id=? AND project_id=?",
                        (request["timeline_id"], request["project_id"]),
                    ).fetchone()
                    reference_projection = prepare_reference_projection(
                        self.conn, candidate["canonical_document"], previous_document,
                        next_version=int(timeline["version"]) + 1,
                    )
                except ReferenceProjectionError as exc:
                    reject(exc.reason, exc.message, status=exc.status,
                           diagnostic_reason=(
                               "store_reference_projection_prepare_history"
                               if exc.reason == "history_unavailable" else None
                           ))
                base = {"revision_id": request["base_revision_id"], "publication_id": request["base_publication_id"]}
                modern = _is_v2_request(request, prepared["records"])
                data = {"status": ("accepted" if previous == base else ("merged" if modern else "rebased")),
                        "base_revision_id": base["revision_id"],
                        "base_publication_id": base["publication_id"], "previous_revision_id": previous["revision_id"],
                        "previous_publication_id": previous["publication_id"],
                        "accepted_revision_id": candidate["canonical_document"]["parent_revision"]["revision_id"],
                        "rebased_onto": None if previous == base else previous, **candidate,
                        "publisher": context["publisher"],
                        **{k: request[k] for k in _METADATA if k in request}}
                if modern:
                    data["merge_mode"] = _effective_merge_mode(request)
                    data.setdefault("label", "Timeline edit")
                if modern and "steps" in prepared["records"]:
                    data["steps"] = prepared["records"]["steps"]
                self._verification.current["accepting"] = True
                self._persist_closure(candidate["canonical_document"])
                result = self._publish(context, data, previous, prepared["records"], prepared["semantic_events"],
                                       recorder_abi=recorder_abi, execution=execution)
                from .timeline_commit_reference_projection import (
                    apply_reference_projection,
                )
                if reference_projection is not None:
                    try:
                        apply_reference_projection(self.conn, reference_projection)
                    except ReferenceProjectionError as exc:
                        if exc.reason == "history_unavailable":
                            raise
                        reject(exc.reason, exc.message, status=exc.status,
                               diagnostic_reason=(
                                   "store_reference_projection_apply_history"
                                   if exc.reason == "history_unavailable" else None
                               ))
                self._project_text_bindings(candidate["canonical_document"], prepared["records"], result["receipt"]["receipt_id"])
                if inputs is not None:
                    inputs.persist(prepared, result["receipt"]["receipt_id"], data["accepted_revision_id"])
                self._check_history_objects()
                return result

    def _project_text_bindings(self, document, records, publication_id):
        """Derive live text-binding rows and events from the accepted recorder's writes.

        Runs in the acceptance transaction after _persist_closure; only this commit's
        writes are projected, so historical reuse never repoints a live row.
        """
        project_id = document["project_id"]
        shots = {o["occurrence_id"]: o["shot_id"] for o in document["parent_revision"]["payload"]["occurrences"]}
        for record in records["commands"]:
            for write in record["writes"]:
                if "/text-binding:" not in write["ref"]:
                    continue
                match = _TEXT_BINDING_REF.fullmatch(write["ref"])
                if match is None or write["path"]:
                    reject("invalid_records", "malformed text binding write", status=422)
                occurrence, kind, slot = match.groups()
                owner = "occurrence:" + occurrence
                read = next((r for r in record["reads"] if r["ref"] == owner + "/shot" and r["path"] == ["shot_id"]), None)
                shot_id = shots.get(occurrence)
                if shot_id is None or read is None or read["state"] != {"state": "present", "value": shot_id}:
                    reject("text_binding_owner_changed", "text binding owner differs from the accepted shot")
                self._project_text_binding(project_id, shot_id, kind, slot, write["before"], write["after"], publication_id)

    def _project_text_binding(self, project_id, shot_id, kind, slot, before, after, publication_id,
                              *, allow_import_text_plain=False):
        from .service import RuntimeService
        from .timeline_commit_port import _verify_text_object, verify_retained_text_object, verify_text_object
        from .cas import ContentAddressedStore

        owner = self.conn.execute("SELECT project_id FROM project_shots WHERE id=?", (shot_id,)).fetchone()
        if owner is None or owner["project_id"] != project_id:
            reject("dependency_unavailable", "text binding shot is not in this project")
        binding_id = RuntimeService._text_binding_id(project_id, shot_id, kind, slot)
        row = self.conn.execute("SELECT * FROM shot_text_bindings WHERE id=? AND project_id=?", (binding_id, project_id)).fetchone()
        latest = None
        if row is not None:
            events = RuntimeService._text_binding_events(self.conn, row)
            latest = json.loads(events[-1]["payload_json"])
        live = latest is not None and latest.get("state", "present") == "present"
        current = None
        if live:
            media = self.conn.execute("SELECT size, media_type FROM objects WHERE digest=?", (row["media_digest"],)).fetchone()
            if media is None:
                reject("dependency_unavailable", "bound text media is missing")
            current = {"kind": row["kind"], "slot": row["slot"], "media_id": "sha256:" + row["media_digest"],
                       "content_hash": "sha256:" + row["media_digest"], "byte_size": media["size"], "mime_type": media["media_type"]}
        fields = ("kind", "slot", "media_id", "content_hash", "byte_size", "mime_type")
        if (before["state"] == "present") != live or (live and any(
                before["value"].get(field) != current[field] for field in fields)):
            reject("text_binding_mismatch", "recorded text binding state differs from the live binding")
        clearing = after["state"] == "absent"
        if clearing and not live:
            reject("text_binding_mismatch", "cannot clear an absent text binding")
        value = current if clearing else after["value"]
        for descriptor in ([current] if live else []) + ([] if clearing else [value]):
            selection = {"object_id": descriptor.get("media_id"), "digest": descriptor.get("content_hash"),
                         "size": descriptor.get("byte_size"), "media_type": descriptor.get("mime_type")}
            if (descriptor.get("kind"), descriptor.get("slot")) != (kind, slot):
                reject("invalid_records", "text binding row differs from its key", status=422)
            cas = ContentAddressedStore(self.store.cas_root)
            if selection["media_type"] == "text/plain" and row is not None:
                verify_retained_text_object(self.conn, cas, row, selection)
            elif selection["media_type"] == "text/plain" and allow_import_text_plain:
                _verify_text_object(self.conn, cas, project_id, selection, "text/plain")
            else:
                verify_text_object(self.conn, cas, project_id, selection)
        object_digest = value["media_id"][7:]
        timestamp = now()
        if row is None:
            self.conn.execute("INSERT INTO shot_text_bindings(id, project_id, shot_id, kind, slot, media_digest, event_stream_id, head_seq, created_at, updated_at) "
                              "VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
                              (binding_id, project_id, shot_id, kind, slot, object_digest, binding_id + ":shot.text_binding", timestamp, timestamp))
            head, previous_hash = 0, ""
        elif live and not clearing and row["media_digest"] == object_digest:
            return
        else:
            head = row["head_seq"]
            previous_hash = self.conn.execute("SELECT event_hash FROM shot_text_binding_events WHERE binding_id=? AND seq=?",
                                              (binding_id, head)).fetchone()["event_hash"]
        event_id, seq = new_id(), head + 1
        event_kind = "shot.text_binding.created" if seq == 1 else "shot.text_binding.rebound"
        payload = {"binding_id": binding_id, "project_id": project_id, "shot_id": shot_id, "kind": kind, "slot": slot,
                   "media_id": value["media_id"], "content_hash": value["content_hash"], "byte_size": value["byte_size"],
                   "mime_type": value["mime_type"], "publication_id": publication_id,
                   "state": "absent" if clearing else "present"}
        event_hash = hashlib.sha256(canonical_json({"event_id": event_id, "binding_id": binding_id, "seq": seq,
                                                    "kind": event_kind, "payload": payload,
                                                    "previous_hash": previous_hash}).encode()).hexdigest()
        self.conn.execute("INSERT INTO shot_text_binding_events(event_id, binding_id, project_id, seq, kind, payload_json, previous_hash, event_hash, created_at) "
                          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                          (event_id, binding_id, project_id, seq, event_kind, canonical_json(payload), previous_hash, event_hash, timestamp))
        self.conn.execute("UPDATE shot_text_bindings SET media_digest=?, head_seq=?, updated_at=? WHERE id=?",
                          (object_digest, seq, timestamp, binding_id))

    def _persist_closure(self, document):
        project_id, timestamp = document["project_id"], now()
        for image in document["internal_timeline_revisions"]:
            self.conn.execute("INSERT OR IGNORE INTO internal_timeline_revisions(id, project_id, timeline_id, payload_json, content_digest, created_at) "
                              "VALUES (?, ?, ?, ?, ?, ?)", (image["revision_id"], project_id, image["timeline_id"], canonical_json(image["payload"]), image["content_digest"], timestamp))
        for image in document["shot_revisions"]:
            existing = self.conn.execute("SELECT 1 FROM shot_revisions WHERE id=?", (image["revision_id"],)).fetchone()
            if existing:
                continue
            payload, shot_id = image["payload"], image["shot_id"]
            self.conn.execute("INSERT INTO project_shots(id, project_id, name, metadata_json, version, created_at, updated_at, archived_at) "
                              "VALUES (?, ?, ?, ?, 1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, metadata_json=excluded.metadata_json, "
                              "version=project_shots.version+1, updated_at=excluded.updated_at, archived_at=excluded.archived_at",
                              (shot_id, project_id, payload.get("name") or shot_id, canonical_json(payload.get("metadata", {})), timestamp, timestamp,
                               timestamp if payload.get("archived", False) else None))
            self.conn.execute("DELETE FROM shot_items WHERE shot_id=?", (shot_id,))
            for ordinal, item in enumerate(payload.get("items", [])):
                self.conn.execute("INSERT INTO shot_items(id, shot_id, media_id, sort_key, source_frame, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                  (item.get("item_id", item.get("id")), shot_id, item["media_id"].removeprefix("sha256:"), f"{ordinal:08d}",
                                   item.get("source_frame"), canonical_json(item.get("metadata", {})), timestamp))
            self.conn.execute("INSERT INTO shot_revisions(id, project_id, shot_id, internal_timeline_revision_id, payload_json, content_digest, created_at) "
                              "VALUES (?, ?, ?, ?, ?, ?, ?)", (image["revision_id"], project_id, shot_id, image["internal_timeline_revision_id"],
                                                             canonical_json(payload), image["content_digest"], timestamp))
            self.conn.execute("INSERT INTO shot_revision_heads(shot_id, project_id, revision_id, updated_at) VALUES (?, ?, ?, ?) "
                              "ON CONFLICT(shot_id) DO UPDATE SET revision_id=excluded.revision_id, updated_at=excluded.updated_at",
                              (shot_id, project_id, image["revision_id"], timestamp))
        parent, manifest = document["parent_revision"], document["dependency_manifest"]
        existing = self.conn.execute("SELECT 1 FROM parent_composition_revisions WHERE id=?", (parent["revision_id"],)).fetchone()
        if existing is None:
            self.conn.execute("INSERT INTO parent_composition_revisions(id, project_id, timeline_id, payload_json, content_digest, commit_manifest_json, created_at) "
                              "VALUES (?, ?, ?, ?, ?, ?, ?)", (parent["revision_id"], project_id, document["timeline_id"], canonical_json(parent["payload"]),
                                                             parent["content_digest"], canonical_json(manifest), timestamp))
            for ordinal, occurrence in enumerate(parent["payload"]["occurrences"]):
                self.conn.execute("INSERT INTO composition_revision_occurrences(parent_revision_id, occurrence_id, ordinal, project_id, shot_id, shot_revision_id, "
                                  "placement_json, source_offset_json, duration_ms, speed_json, track, transform_json, gain, muted, provenance_json) "
                                  "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                  (parent["revision_id"], occurrence["occurrence_id"], ordinal, project_id, occurrence["shot_id"], occurrence["shot_revision_id"],
                                   canonical_json(occurrence["placement"]), canonical_json(occurrence.get("source_offset", 0)), occurrence["duration_ms"],
                                   canonical_json(occurrence.get("speed", 1)), occurrence["track"], canonical_json(occurrence.get("transform", {})), occurrence.get("gain", 1),
                                   int(occurrence.get("muted", occurrence.get("mute", False))), canonical_json(occurrence.get("provenance", {}))))
            dependencies = [("shot_revision", p["revision_id"], p["content_digest"]) for p in manifest["shots"]]
            dependencies += [("internal_timeline_revision", p["revision_id"], p["content_digest"]) for p in manifest["internal_timelines"]]
            dependencies += [("media", p["media_id"], p["content_digest"]) for p in manifest["media"]]
            for ordinal, (kind, identity, content_digest) in enumerate(dependencies):
                self.conn.execute("INSERT INTO composition_revision_dependencies VALUES (?, ?, ?, ?, ?)",
                                  (parent["revision_id"], kind, identity, content_digest, ordinal))
        else:
            self.conn.execute("UPDATE parent_composition_revisions SET commit_manifest_json=? WHERE id=? AND commit_manifest_json IS NULL",
                              (canonical_json(manifest), parent["revision_id"]))

    def _publish(self, context, data, previous, records, semantic_events, *, recorder_abi, execution=None):
        request = context["request"]
        project_id, timeline_id = request["project_id"], request["timeline_id"]
        revision_id = data["canonical_document"]["parent_revision"]["revision_id"]
        metadata = {**_history_metadata(request, data), "recorder_abi": recorder_abi}
        if execution is not None:
            metadata[_PRIVATE_EXECUTION] = execution
        event_ids = []
        for event in semantic_events:
            event_ids.append(self.store._append_timeline_event(timeline_id, event["kind"],
                {"project_id": project_id, "timeline_id": timeline_id, "publisher": context["publisher"], **event}))
        event_ids.append(self.store._append_timeline_event(timeline_id, "timeline.commit.accepted",
            {"project_id": project_id, "timeline_id": timeline_id, "previous": previous, "revision_id": revision_id,
             "publisher": context["publisher"], "intent": "recorded", "records_digest": digest(records),
             "recorder_abi": recorder_abi, "request_hash": context["request_hash"],
             "metadata_digest": digest(metadata)}))
        seq = self.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE timeline_id=?", (timeline_id,)).fetchone()[0]
        publication_id = self.store._record_command_receipt("timeline.commit", scope(context), context["idempotency_key"], context["request_hash"],
            data, project_id=project_id, event_ids=event_ids, primary_stream_id=timeline_id, resulting_stream_seq=seq)
        ledger = self.conn.execute("SELECT * FROM command_idempotency WHERE txn_id=?", (publication_id,)).fetchone()
        self.conn.execute("INSERT INTO timeline_commit_history VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (publication_id, project_id, timeline_id, revision_id, previous["publication_id"] if previous else None,
             previous["revision_id"], "recorded", canonical_json(records),
             canonical_json(metadata), data.get("provider_version"), data.get("compiler_version"),
             context["publisher"], ledger["first_project_seq"]))
        changed = self.conn.execute("UPDATE parent_composition_heads SET revision_id=?, publication_id=?, updated_at=? "
            "WHERE project_id=? AND timeline_id=? AND revision_id=? AND publication_id=?", (revision_id, publication_id, now(), project_id, timeline_id,
            previous["revision_id"], previous["publication_id"])).rowcount
        if changed != 1:
            raise ProtocolError("head changed inside acceptance transaction")
        self.conn.execute("UPDATE timelines SET version=version+1 WHERE id=? AND project_id=?", (timeline_id, project_id))
        return self._envelope(ledger, project_id)

    def _install_entries(self, project_id, timeline_id, plan):
        for entry in plan["entries"]:
            previous = entry["previous"]
            self.conn.execute("INSERT INTO timeline_commit_history VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (entry["publication_id"], project_id, timeline_id, entry["revision_id"],
                 previous["publication_id"] if previous else None, previous["revision_id"] if previous else None,
                 entry["intent"], None, canonical_json({k: entry[k] for k in _METADATA if k in entry}),
                 entry["provider_version"], entry["compiler_version"], entry["publisher"], entry["receipt"]["project_seq"][0]))
        changed = self.conn.execute("UPDATE parent_composition_heads SET publication_id=? WHERE project_id=? AND timeline_id=? "
                                   "AND revision_id=? AND publication_id IS NULL", (plan["head"]["publication_id"], project_id,
                                   timeline_id, plan["head"]["revision_id"])).rowcount
        if changed != 1:
            reject("stale_head")

    def install_verified_baseline(self, project_id, timeline_id, *, authorize, verify_inputs=None):
        from .cas import ContentAddressedStore
        from .timeline_commit_baseline import baseline_install_plan, verify_baseline

        with self.store._mutex, self.store._transaction():
            authorize()
            self._membership(project_id, timeline_id)
            current = self.conn.execute("SELECT revision_id, publication_id FROM parent_composition_heads WHERE project_id=? AND timeline_id=?",
                                        (project_id, timeline_id)).fetchone()
            if current is not None and current["publication_id"]:
                return self.head(project_id, timeline_id)
            read_object = ContentAddressedStore(self.store.cas_root).read
            facts = verify_baseline(self.conn, project_id, timeline_id, read_object=read_object)
            plan = baseline_install_plan(self.conn, facts, read_object=read_object)
            document = facts["canonical_document"]
            if verify_inputs is not None:
                verify_inputs(document)
            self._validate_closure(document)
            for entry in plan["entries"]:
                event = self.conn.execute("SELECT payload_json FROM timeline_events WHERE id=? AND timeline_id=?",
                                          (entry["receipt"]["event_ids"][0], timeline_id)).fetchone()
                manifest = {**json.loads(event[0])["dependency_manifest"], "documents": []}
                self.conn.execute("UPDATE parent_composition_revisions SET commit_manifest_json=? WHERE id=? AND commit_manifest_json IS NULL",
                                  (canonical_json(manifest), entry["revision_id"]))
            self._install_entries(project_id, timeline_id, plan)
            return detached(plan["head"])

    def adopt_empty_shell(self, project_id, timeline_id, *, authorize):
        """Bootstrap an empty headless shell or adopt its verified publication.

        A shell without a parent must have no retained parent or publication.
        Returns the publication event installed by the existing bootstrap path.
        """
        from .cas import ContentAddressedStore
        from .timeline_commit_baseline import bootstrap_install_plan

        with self.store._mutex, self.store._transaction():
            authorize()
            self._membership(project_id, timeline_id)
            current = self.conn.execute("SELECT project_id, revision_id, publication_id FROM parent_composition_heads WHERE timeline_id=?",
                                        (timeline_id,)).fetchone()
            if current is not None and (current["project_id"] != project_id or current["publication_id"] is not None):
                reject("history_unavailable", diagnostic_reason="store_adopt_existing_head")
            if not timeline_scope_is_empty(self.conn, timeline_id, project_id=project_id):
                reject("history_unavailable", diagnostic_reason="store_adopt_nonempty_scope")
            if current is None or current["revision_id"] is None:
                if self.conn.execute("SELECT 1 FROM parent_composition_revisions WHERE timeline_id=? LIMIT 1", (timeline_id,)).fetchone():
                    reject("history_unavailable", diagnostic_reason="store_adopt_existing_parent")
                # Normal create retains its empty legacy projection as well.
                empty_legacy = {"shots": [], "references": []}
                for row in self.conn.execute("SELECT * FROM internal_timeline_revisions WHERE timeline_id=?", (timeline_id,)):
                    if row["project_id"] != project_id or row["payload_json"] != canonical_json(empty_legacy) or row["content_digest"] != digest(empty_legacy):
                        reject("history_unavailable", diagnostic_reason="store_adopt_legacy_shell_mismatch")
                if self.conn.execute("SELECT 1 FROM command_idempotency WHERE command_kind='parent_composition.publish' AND aggregate_id=? LIMIT 1",
                                     (timeline_id,)).fetchone() or self.conn.execute(
                        "SELECT 1 FROM timeline_events WHERE timeline_id=? AND kind='parent.composition.published' LIMIT 1", (timeline_id,)).fetchone():
                    reject("history_unavailable", diagnostic_reason="store_adopt_prior_publication")
                head = self.bootstrap(project_id, timeline_id, authorize=authorize)
                entry = self.history_entry(project_id, timeline_id, head["publication_id"])
                return entry["receipt"]["event_ids"][0]
            plan = bootstrap_install_plan(self.conn, project_id, timeline_id,
                                          read_object=ContentAddressedStore(self.store.cas_root).read)
            self._install_entries(project_id, timeline_id, plan)
            return plan["entries"][0]["receipt"]["event_ids"][0]

    def bootstrap(self, project_id, timeline_id, *, authorize, document=None, source=None,
                  idempotency_key=None, request_hash=None):
        """Install one initial publication, optionally from a validated import closure.

        Timeline creation and import share the same transaction, publication
        event, receipt, head and history path. An imported closure is therefore
        the first editable revision, with no intermediate empty timeline.
        """
        from .timeline_commit_baseline import default_bootstrap_document

        # May compose with main's atomic create transaction. This is the sole
        # exception to accept's outer-transaction requirement.
        with self.store._mutex, self.store._transaction():
            authorize()
            self._membership(project_id, timeline_id)
            current = self.conn.execute("SELECT revision_id, publication_id FROM parent_composition_heads WHERE project_id=? AND timeline_id=?",
                                        (project_id, timeline_id)).fetchone()
            if current is not None and current["revision_id"]:
                if current["publication_id"]:
                    return self.head(project_id, timeline_id)
                reject("history_unavailable", diagnostic_reason="store_bootstrap_unpublished_head")
            if source is not None and (
                not isinstance(source, dict)
                or set(source) - {"via", "detail"}
                or source.get("via") not in {"cli", "python", "app", "script", "sheet"}
                or ("detail" in source and not isinstance(source["detail"], str))
            ):
                raise ValidationError("source must be a supported timeline provenance object")
            imported = document is not None
            if document is None:
                document = default_bootstrap_document(project_id, timeline_id, "bootstrap-" + new_id())
            elif (document.get("project_id"), document.get("timeline_id")) != (project_id, timeline_id):
                reject("invalid_closure", "import closure scope does not match the new timeline", status=422)
            self._validate_closure(document)
            self._persist_closure(document)
            parent, timestamp = document["parent_revision"], now()
            manifest = {k: v for k, v in document["dependency_manifest"].items() if k != "documents"}
            self.conn.execute("INSERT INTO parent_composition_heads(timeline_id, project_id, revision_id, updated_at) VALUES (?, ?, ?, ?) "
                              "ON CONFLICT(timeline_id) DO UPDATE SET revision_id=excluded.revision_id, updated_at=excluded.updated_at",
                              (timeline_id, project_id, parent["revision_id"], timestamp))
            event_payload = {"project_id": project_id, "timeline_id": timeline_id,
                             "old_head": None, "new_head": parent["revision_id"],
                             "content_digest": parent["content_digest"], "dependency_manifest": manifest}
            if source is not None:
                event_payload["source"] = source
            event = self.store._append_timeline_event(timeline_id, "parent.composition.published", event_payload)
            result = {"project_id": project_id, "timeline_id": timeline_id, "revision_id": parent["revision_id"],
                      "parent_revision_id": parent["revision_id"], "content_digest": parent["content_digest"], "payload": parent["payload"],
                      "old_head": None, "new_head": parent["revision_id"], "dependency_manifest": manifest,
                      "content_digests": {"parent": parent["content_digest"],
                          **{item["revision_id"]: item["content_digest"] for item in document["shot_revisions"] + document["internal_timeline_revisions"]},
                          **{item["media_id"]: item["content_digest"] for item in manifest["media"]}},
                      "event_id": event, "created_at": timestamp}
            if imported and source is not None:
                result["source"] = source
            event_seq = self.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE timeline_id=?", (timeline_id,)).fetchone()[0]
            publication_key = idempotency_key or ("bootstrap:" + timeline_id)
            publication_hash = request_hash or digest({"project_id": project_id, "timeline_id": timeline_id, "bootstrap": True})[7:]
            publication_id = self.store._record_command_receipt("parent_composition.publish", timeline_id,
                publication_key, publication_hash, result,
                project_id=project_id, event_ids=[event], primary_stream_id=timeline_id, resulting_stream_seq=event_seq, created_at=timestamp)
            if imported:
                for shot in document["shot_revisions"]:
                    for descriptor in shot["payload"].get("text_bindings", []):
                        from .service import RuntimeService
                        expected_binding_id = RuntimeService._text_binding_id(
                            project_id, shot["shot_id"], descriptor.get("kind"), descriptor.get("slot")
                        )
                        if (descriptor.get("binding_id") != expected_binding_id
                                or descriptor.get("project_id", project_id) != project_id
                                or descriptor.get("shot_id", shot["shot_id"]) != shot["shot_id"]
                                or descriptor.get("event_stream_id", expected_binding_id + ":shot.text_binding")
                                != expected_binding_id + ":shot.text_binding"):
                            reject("invalid_closure", "import text binding identity does not match its shot", status=422)
                        self._project_text_binding(
                            project_id, shot["shot_id"], descriptor["kind"], descriptor.get("slot"),
                            {"state": "absent"}, {"state": "present", "value": descriptor}, publication_id,
                            allow_import_text_plain=True,
                        )
                entry = {
                    "publication_id": publication_id,
                    "revision_id": parent["revision_id"],
                    "previous": None,
                    "intent": "bootstrap",
                    "receipt": {"project_seq": [
                        self.conn.execute("SELECT first_project_seq FROM command_idempotency WHERE txn_id=?", (publication_id,)).fetchone()[0],
                        self.conn.execute("SELECT last_project_seq FROM command_idempotency WHERE txn_id=?", (publication_id,)).fetchone()[0],
                    ]},
                    "provider_version": None,
                    "compiler_version": None,
                    "publisher": None,
                    **({"source": source, "label": "Imported timeline"} if source is not None else {"label": "Imported timeline"}),
                }
                plan = {"head": {"revision_id": parent["revision_id"], "publication_id": publication_id}, "entries": [entry]}
            else:
                from .cas import ContentAddressedStore
                from .timeline_commit_baseline import bootstrap_install_plan
                plan = bootstrap_install_plan(self.conn, project_id, timeline_id,
                                              read_object=ContentAddressedStore(self.store.cas_root).read)
            self._install_entries(project_id, timeline_id, plan)
            return detached(plan["head"])
