"""Explicit offline upgrade from retired/current formats to the canonical format.

Opening a realm never upgrades it. This module is an operator-only boundary:
it acquires the same owner fence as the daemon, stages a temporary copy of the
source SQLite state for rollback, builds a fresh canonical database, and
replaces the database only after lossless row and integrity checks pass. A
persistent source archive is opt-in.
"""

from __future__ import annotations

import hashlib
import json
import math
import mimetypes
from runtime_protocol.dirfd import filesystem as os
from runtime_protocol import platform
import re
import shutil
import sqlite3
import stat
import tempfile
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .canonical_schema import (CANONICAL_FORMAT_ID, CANONICAL_SCHEMA_SQL,
                               GENERATION_TAG_INDEX_SQL, generation_tag_index_is_current)
from .cas import ContentAddressedStore
from .catalog import _safe_path
from .errors import ConflictError, OwnerBusyError, RealmAdmissionError, ValidationError
from .store import (REQUIRED_SCHEMA_COLUMNS, REQUIRED_SCHEMA_TABLES, SCHEMA_VERSION, RealmStore,
                    realm_admission_fence,
                    IDEMPOTENCY_RESULT_MARKER_PREFIX, IDEMPOTENCY_RESULT_WINDOW_SECONDS,
                    EXPIRABLE_RESULT_SQL, expired_command_result, expired_publication_result,
                    retire_terminal_specs, configured_spec_retention_days)
from .util import canonical_json, now
from .snapshot_refs import publish_snapshot, rewrite_spec_snapshots, restore_spec_snapshots
from .sqlite_uri import sqlite_file_uri

LEGACY_TABLES = frozenset(
    {
        "schema_migrations",
        "canonical_receipt_backfills",
        "lost_and_found",
        "migration_event_streams",
        "migration_events",
        "migration_owner_records",
        "workers",
    }
)
NEW_TABLES = frozenset({
    "runtime_schema", "managed_output_associations", "managed_output_lifecycle", "user_preferences", "user_app_state", "task_specs",
    "internal_timeline_revisions", "shot_revisions", "parent_composition_revisions",
    "shot_revision_heads", "parent_composition_heads", "composition_revision_occurrences",
    "composition_revision_dependencies",
})
REVISION_TABLES = frozenset({
    "internal_timeline_revisions", "shot_revisions", "parent_composition_revisions",
    "shot_revision_heads", "parent_composition_heads", "composition_revision_occurrences",
    "composition_revision_dependencies",
})
DEFAULT_UPGRADE_TIMEOUT_SECONDS = 120.0
CANONICAL_PREVIOUS_SCHEMA_VERSION = 24
VARIANT_STATE_TARGET_SCHEMA_VERSION = 25
EXECUTION_BINDING_PREVIOUS_SCHEMA_VERSION = 25
EXECUTION_BINDING_TARGET_SCHEMA_VERSION = 26
USER_PREFERENCES_PREVIOUS_SCHEMA_VERSION = 26
USER_PREFERENCES_TARGET_SCHEMA_VERSION = 27
SPEC_DEDUP_TARGET_SCHEMA_VERSION = 28
SPEC_REFERENCE_TARGET_SCHEMA_VERSION = 29
TIMELINE_NAME_TARGET_SCHEMA_VERSION = 30
USER_APP_STATE_TARGET_SCHEMA_VERSION = 31
GENERATION_TAG_TARGET_SCHEMA_VERSION = 32
GENERATION_TAG_MIGRATION_CONFIRMATION = "MIGRATE GENERATION TAGS"
HISTORICAL_OUTPUT_MIGRATION_CONFIRMATION = "MIGRATE MANAGED OUTPUTS"
GENERIC_MEDIA_TYPE_REPAIR_CONFIRMATION = "REPAIR GENERIC MEDIA TYPES"
_VIDEO_SUFFIXES = frozenset({".mp4", ".mov", ".webm", ".mkv"})
_VIDEO_MEDIA_TYPES = frozenset({
    "video/mp4", "video/quicktime", "video/webm", "video/x-matroska", "clip/visual",
})
_VIDEO_SUFFIX_MEDIA_TYPES = {
    ".mp4": "video/mp4",
    ".mov": "video/quicktime",
    ".webm": "video/webm",
    ".mkv": "video/x-matroska",
}
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_HISTORICAL_ASSOCIATION_COLUMNS = (
    "association_id", "task_id", "attempt_id", "project_id", "output_port", "group_key",
    "generation_id", "variant_key", "object_digest", "manifest_digest", "size", "filename",
    "media_type", "ordinal", "role", "producer_json", "provenance_json", "durability",
    "regeneration_json", "coverage_json", "created_at",
)


def _retained_idempotency_digest(connection: sqlite3.Connection) -> tuple[int, str]:
    """Fingerprint every ledger fact other than the compactable response body."""
    columns = [column for column in _table_columns(connection, "command_idempotency") if column != "result_json"]
    selected = ", ".join(_quote(column) for column in columns)
    rows = connection.execute(
        f"SELECT {selected} FROM command_idempotency "
        "ORDER BY command_kind, aggregate_id, idempotency_key"
    )
    digest = hashlib.sha256()
    count = 0
    for row in rows:
        encoded = canonical_json(list(row)).encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        count += 1
    return count, digest.hexdigest()


def _retained_task_run_digest(connection: sqlite3.Connection) -> dict[str, tuple[int, str]]:
    return {
        table: _row_digest(
            connection, table,
            [name for name in _table_columns(connection, table)
             if name not in {"spec_digest", "expected_effect_json", "execution_request_json"}],
        )
        for table in ("runs", "tasks")
    }


def _validate_spec_records(connection: sqlite3.Connection) -> int:
    count = 0
    for digest, body in connection.execute("SELECT digest, body_json FROM task_specs"):
        if hashlib.sha256(body.encode("utf-8")).hexdigest() != digest:
            raise ValidationError("task spec digest changed or is corrupt")
        count += 1
    return count


def compact_idempotency_ledger(root: str | Path, *, confirmation: str | None = None,
                               retention_days: int | None = None) -> dict:
    """Offline compaction of expired replays and terminal task specs."""
    if retention_days is None:
        retention_days = configured_spec_retention_days()
    if isinstance(retention_days, bool) or not isinstance(retention_days, int) or retention_days < 2:
        raise ValidationError("retention_days must be an integer of at least 2 (receipt replay lasts 24 hours)")
    root = _safe_realm_root(root)
    identity = inspect_canonical_schema(root)
    if int(identity["version"]) != SCHEMA_VERSION:
        raise ValidationError(f"idempotency compaction requires canonical schema v{SCHEMA_VERSION}")
    realm_id = str(identity["realm_id"])
    expected = f"COMPACT IDEMPOTENCY {realm_id}"
    if confirmation != expected:
        raise ValidationError(f"compaction requires confirmation exactly '{expected}'")
    db = root / "realm.sqlite3"
    _regular(db, "realm database")
    if shutil.disk_usage(root).free < db.stat().st_size:
        raise ValidationError("compaction needs at least one realm database size of free disk for VACUUM INTO")
    output = root / f"realm.sqlite3.compact-{uuid.uuid4().hex}"
    started = time.monotonic()
    with _owner_fence(root):
        connection = sqlite3.connect(db, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = _canonical_schema_identity(connection, expected_realm_id=realm_id)
            if int(current["version"]) != SCHEMA_VERSION:
                raise ConflictError("realm schema changed before compaction")
            before_count, before_digest = _retained_idempotency_digest(connection)
            retained_summaries = _retained_task_run_digest(connection)
            # Historical command/transaction facts remain permanent. New session
            # replays use the service's temporary table, not this ledger.
            removed = 0
            cutoff = (datetime.now(timezone.utc) - timedelta(seconds=IDEMPOTENCY_RESULT_WINDOW_SECONDS)).isoformat(timespec="milliseconds")
            changed = 0
            cursor = 0
            while True:
                batch = connection.execute(
                    "SELECT rowid, command_kind, result_json FROM command_idempotency WHERE rowid > ? "
                    "AND created_at < ? AND substr(result_json, 1, ?) <> ? "
                    "AND " + EXPIRABLE_RESULT_SQL + "ORDER BY rowid LIMIT 500",
                    (cursor, cutoff, len(IDEMPOTENCY_RESULT_MARKER_PREFIX), IDEMPOTENCY_RESULT_MARKER_PREFIX),
                ).fetchall()
                if not batch:
                    break
                for row in batch:
                    connection.execute(
                        "UPDATE command_idempotency SET result_json=? WHERE rowid=?",
                        ((expired_publication_result(row["result_json"])
                          if row["command_kind"] == "parent_composition.publish"
                          else expired_command_result(row["result_json"])), row["rowid"]),
                    )
                    changed += 1
                cursor = batch[-1]["rowid"]
            retired = retire_terminal_specs(connection, retention_days=retention_days)
            after_count, after_digest = _retained_idempotency_digest(connection)
            if (before_count, before_digest) != (after_count, after_digest):
                raise ValidationError("idempotency retained-column digest changed during compaction")
            if _retained_task_run_digest(connection) != retained_summaries:
                raise ValidationError("task/run retained-column digest changed during compaction")
            _validate_spec_records(connection)
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise ValidationError("compacted database failed foreign-key validation")
            if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValidationError("compacted database failed SQLite integrity check")
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("VACUUM INTO ?", (str(output),))
            platform.owner_only(output)
            verified = sqlite3.connect(sqlite_file_uri(output), uri=True)
            try:
                if _retained_idempotency_digest(verified) != (after_count, after_digest):
                    raise ValidationError("VACUUM output changed retained idempotency facts")
                if _retained_task_run_digest(verified) != retained_summaries:
                    raise ValidationError("VACUUM output changed retained task/run summaries")
                _validate_spec_records(verified)
                if verified.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValidationError("VACUUM output failed SQLite integrity check")
                if verified.execute("PRAGMA foreign_key_check").fetchone() is not None:
                    raise ValidationError("VACUUM output failed foreign-key validation")
            finally:
                verified.close()
        except Exception:
            connection.rollback()
            output.unlink(missing_ok=True)
            raise
        finally:
            connection.close()
        before_bytes = db.stat().st_size
        after_bytes = output.stat().st_size
        _fsync_file(output)
        try:
            platform.durable_replace(output, db)
        finally:
            output.unlink(missing_ok=True)
    return {"ok": True, "realm_id": realm_id, "removed_session_rows": removed,
            **retired,
            "expired_results": changed, "retained_rows": after_count,
            "retained_columns_sha256": after_digest, "before_bytes": before_bytes,
            "after_bytes": after_bytes, "elapsed_seconds": time.monotonic() - started}


def _regular(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as exc:
        raise RealmAdmissionError(f"{label} is missing") from exc
    if not stat.S_ISREG(mode) or path.is_symlink():
        raise RealmAdmissionError(f"{label} must be an ordinary file")


def _safe_realm_root(root: str | Path) -> Path:
    try:
        return _safe_path(root, "realm root").resolve()
    except ValueError as exc:
        raise RealmAdmissionError(str(exc)) from exc


def _quote(identifier: str) -> str:
    if not identifier or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for ch in identifier):
        raise ValidationError("invalid SQLite identifier")
    return '"' + identifier + '"'


def _file_digest(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
    return size, digest.hexdigest()


def _row_digest(connection: sqlite3.Connection, table: str, columns: list[str], *, deadline: float | None = None) -> tuple[int, str]:
    digest = hashlib.sha256()
    count = 0
    selected = ", ".join(_quote(column) for column in columns)
    ordering = _row_ordering(connection, table, columns)
    select = f"SELECT {selected} FROM {_quote(table)} ORDER BY {ordering}"
    for row in connection.execute(select):
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("SQLite row verification timed out")
        for value in row:
            if value is None:
                encoded = b"N"
            elif isinstance(value, bool):
                encoded = b"B" + (b"1" if value else b"0")
            elif isinstance(value, int):
                encoded = b"I" + str(value).encode("ascii")
            elif isinstance(value, float):
                encoded = b"F" + repr(value).encode("ascii")
            elif isinstance(value, bytes):
                encoded = b"B" + len(value).to_bytes(8, "big") + value
            else:
                encoded = b"T" + str(value).encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        count += 1
    return count, digest.hexdigest()


def _row_ordering(connection: sqlite3.Connection, table: str, columns: list[str]) -> str:
    """Return a stable ordering for both rowid and WITHOUT ROWID tables."""
    table_sql = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()[0] or ""
    # Every current canonical table is rowid-backed.  Keep the fallback for a
    # historical WITHOUT ROWID table so fingerprints remain deterministic
    # without loading an entire large table into memory.
    if "WITHOUT ROWID" in str(table_sql).upper():
        return ", ".join(_quote(column) for column in columns)
    return "rowid"


def _table_columns(connection: sqlite3.Connection, table: str) -> list[str]:
    return [str(row[1]) for row in connection.execute(f"PRAGMA table_info({_quote(table)})")]


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    }


def _canonical_shape_for(version: int) -> tuple[set[str], dict[str, set[str]]]:
    """Return the exact supported canonical layout for one historical version.

    Historical targets are deliberately pinned.  A future current schema must
    not silently change what v24, v25 or v26 means, and a database carrying a known
    version number with an alternate (for example distributed-binding) layout
    is not accepted as that version.
    """
    if version not in {
        CANONICAL_PREVIOUS_SCHEMA_VERSION,
        VARIANT_STATE_TARGET_SCHEMA_VERSION,
        EXECUTION_BINDING_TARGET_SCHEMA_VERSION,
        USER_PREFERENCES_TARGET_SCHEMA_VERSION,
        SPEC_DEDUP_TARGET_SCHEMA_VERSION,
        SPEC_REFERENCE_TARGET_SCHEMA_VERSION,
        TIMELINE_NAME_TARGET_SCHEMA_VERSION,
        USER_APP_STATE_TARGET_SCHEMA_VERSION,
        GENERATION_TAG_TARGET_SCHEMA_VERSION,
    }:
        raise ValidationError(f"canonical schema version {version} is not supported")
    tables = set(REQUIRED_SCHEMA_TABLES)
    columns = {table: set(values) for table, values in REQUIRED_SCHEMA_COLUMNS.items()}
    if version < USER_APP_STATE_TARGET_SCHEMA_VERSION:
        tables.remove("user_app_state")
        columns.pop("user_app_state")
    if version < TIMELINE_NAME_TARGET_SCHEMA_VERSION:
        columns["timelines"].remove("name")
    if version < SPEC_DEDUP_TARGET_SCHEMA_VERSION:
        tables.remove("task_specs")
        columns.pop("task_specs")
        for table in ("tasks", "runs"):
            columns[table].remove("spec_digest")
            columns[table].add("spec_json")
    if version < USER_PREFERENCES_TARGET_SCHEMA_VERSION:
        tables.remove("user_preferences")
        columns.pop("user_preferences")
    if version < EXECUTION_BINDING_TARGET_SCHEMA_VERSION:
        tables.remove("execution_bindings")
        columns.pop("execution_bindings")
        columns["tasks"].remove("execution_request_json")
    if version < VARIANT_STATE_TARGET_SCHEMA_VERSION:
        columns["generation_variants"] -= {
            "thumbnail_object_id",
            "thumbnail_source_object_id",
            "thumbnail_recipe_version",
            "viewed_at",
        }
    return tables, columns


def _canonical_schema_identity(
    connection: sqlite3.Connection,
    *,
    expected_realm_id: str | None = None,
) -> dict[str, object]:
    """Classify a supported v24/v25/v26/current database by version *and* shape."""
    tables = _tables(connection)
    if "runtime_schema" not in tables:
        raise ValidationError("canonical runtime_schema table is missing")
    rows = connection.execute(
        "SELECT id, format_id, version FROM runtime_schema ORDER BY id"
    ).fetchall()
    if len(rows) != 1 or int(rows[0][0]) != 1:
        raise ValidationError("canonical runtime schema identity is ambiguous")
    format_id, version = str(rows[0][1]), int(rows[0][2])
    if format_id != CANONICAL_FORMAT_ID:
        raise ValidationError(f"unsupported canonical format {format_id!r}")
    if version > GENERATION_TAG_TARGET_SCHEMA_VERSION:
        raise ValidationError(
            f"canonical schema v{version} is newer than supported v{GENERATION_TAG_TARGET_SCHEMA_VERSION}"
        )
    if version < CANONICAL_PREVIOUS_SCHEMA_VERSION:
        raise ValidationError(f"canonical schema v{version} is not a supported migration source")
    expected_tables, expected_columns = _canonical_shape_for(version)
    unknown = tables - expected_tables
    missing = expected_tables - tables
    if unknown or missing:
        details = []
        if unknown:
            details.append("unexpected tables: " + ", ".join(sorted(unknown)))
        if missing:
            details.append("missing tables: " + ", ".join(sorted(missing)))
        raise ValidationError(
            f"canonical schema v{version} layout is not the supported layout ({'; '.join(details)})"
        )
    for table in sorted(expected_tables):
        actual = set(_table_columns(connection, table))
        expected = expected_columns[table]
        if actual != expected:
            raise ValidationError(
                f"canonical schema v{version} layout differs for table {table}"
            )
    if version == GENERATION_TAG_TARGET_SCHEMA_VERSION and not generation_tag_index_is_current(connection):
        raise ValidationError("canonical schema v32 generation tag index is missing or differs")
    realm_rows = connection.execute("SELECT id FROM realm ORDER BY id").fetchall()
    if len(realm_rows) != 1 or not str(realm_rows[0][0]):
        raise ValidationError("canonical realm identity is missing or ambiguous")
    realm_id = str(realm_rows[0][0])
    if expected_realm_id is not None and realm_id != str(expected_realm_id):
        raise ValidationError(
            f"canonical realm identity mismatch: expected {expected_realm_id}, found {realm_id}"
        )
    return {
        "format_id": format_id,
        "version": version,
        "kind": f"v{version}",
        "realm_id": realm_id,
    }


def inspect_canonical_schema(
    root: str | Path,
    *,
    expected_realm_id: str | None = None,
) -> dict[str, object]:
    """Read-only exact schema/realm classification used before lifecycle effects."""
    root = _safe_realm_root(root)
    if not root.exists() or not root.is_dir() or root.is_symlink():
        raise RealmAdmissionError("realm root is missing or invalid")
    connection = _open_readonly(root / "realm.sqlite3")
    try:
        return _canonical_schema_identity(connection, expected_realm_id=expected_realm_id)
    finally:
        connection.close()


@contextmanager
def _sqlite_deadline(connection: sqlite3.Connection, deadline: float | None):
    if deadline is None:
        yield
        return
    def progress() -> int:
        return 1 if time.monotonic() >= deadline else 0

    connection.set_progress_handler(progress, 1000)
    try:
        yield
    finally:
        connection.set_progress_handler(None, 0)


def _quick_check(connection: sqlite3.Connection, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    try:
        with _sqlite_deadline(connection, deadline):
            rows = [str(row[0]) for row in connection.execute("PRAGMA quick_check").fetchall()]
            return "ok" if rows == ["ok"] else "\n".join(rows)
    except sqlite3.DatabaseError as exc:
        if time.monotonic() >= deadline:
            raise TimeoutError("SQLite integrity check timed out") from exc
        raise


def _foreign_key_errors(connection: sqlite3.Connection, timeout: float) -> list:
    deadline = time.monotonic() + timeout
    try:
        with _sqlite_deadline(connection, deadline):
            return connection.execute("PRAGMA foreign_key_check").fetchall()
    except sqlite3.DatabaseError as exc:
        if time.monotonic() >= deadline:
            raise TimeoutError("SQLite foreign-key check timed out") from exc
        raise


@contextmanager
def _owner_fence(root: Path):
    lock_path = root / "owner.lock"
    if lock_path.is_symlink():
        raise ValidationError("owner lock must not be a symlink")
    handle = None
    try:
        try:
            # Replacement can temporarily close owner.lock on Windows while
            # retaining directory custody. Maintenance must join that fence
            # before acquiring the lifetime owner lock, just like startup.
            with realm_admission_fence(root, blocking=False):
                handle = lock_path.open("a+")
                platform.owner_only(lock_path)
                platform.lock_file(handle.fileno(), blocking=False)
        except (BlockingIOError, OSError) as exc:
            raise OwnerBusyError("another runtime daemon owns this realm") from exc
        yield
    finally:
        if handle is not None:
            try:
                platform.unlock_file(handle.fileno())
            except OSError:
                pass
            handle.close()



def _open_readonly(db: Path) -> sqlite3.Connection:
    _regular(db, "realm database")
    connection = sqlite3.connect(sqlite_file_uri(db), uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _apply_v24_to_v25(connection: sqlite3.Connection) -> dict[str, object]:
    columns = set(_table_columns(connection, "generation_variants"))
    _, expected_columns = _canonical_shape_for(CANONICAL_PREVIOUS_SCHEMA_VERSION)
    if columns != expected_columns["generation_variants"]:
        raise ValidationError("v24 generation_variants shape is not recognized")
    connection.execute(
        "ALTER TABLE generation_variants ADD COLUMN thumbnail_object_id TEXT REFERENCES objects(digest)"
    )
    connection.execute(
        "ALTER TABLE generation_variants ADD COLUMN thumbnail_source_object_id TEXT REFERENCES objects(digest)"
    )
    connection.execute("ALTER TABLE generation_variants ADD COLUMN thumbnail_recipe_version INTEGER")
    connection.execute("ALTER TABLE generation_variants ADD COLUMN viewed_at TEXT")
    connection.execute(
        "UPDATE runtime_schema SET version=? WHERE id=1",
        (VARIANT_STATE_TARGET_SCHEMA_VERSION,),
    )
    return {
        "source_schema_version": CANONICAL_PREVIOUS_SCHEMA_VERSION,
        "target_schema_version": VARIANT_STATE_TARGET_SCHEMA_VERSION,
        "added_columns": [
            "generation_variants.thumbnail_object_id",
            "generation_variants.thumbnail_source_object_id",
            "generation_variants.thumbnail_recipe_version",
            "generation_variants.viewed_at",
        ],
    }


def _apply_v25_to_v26(connection: sqlite3.Connection) -> dict[str, object]:
    task_columns = set(_table_columns(connection, "tasks"))
    _, expected_columns = _canonical_shape_for(EXECUTION_BINDING_PREVIOUS_SCHEMA_VERSION)
    if task_columns != expected_columns["tasks"]:
        raise ValidationError("v25 tasks shape is not recognized")
    if "execution_bindings" in _tables(connection):
        raise ValidationError("v25 execution binding table is already present")
    connection.execute("ALTER TABLE tasks ADD COLUMN execution_request_json TEXT")
    connection.execute(
        """
        CREATE TABLE execution_bindings (
            binding_id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL UNIQUE REFERENCES tasks(id),
            run_id TEXT NOT NULL REFERENCES runs(id),
            attempt_id TEXT REFERENCES attempts(id),
            lease_id TEXT,
            fence INTEGER NOT NULL DEFAULT 0,
            executor_id TEXT,
            session_id TEXT NOT NULL,
            runtime_epoch INTEGER NOT NULL,
            capability_id TEXT NOT NULL,
            profile_revision TEXT,
            profile_digest TEXT,
            release_digest TEXT,
            target_kind TEXT NOT NULL,
            target_id TEXT,
            provider_account_ref TEXT,
            pod_id TEXT,
            storage_json TEXT,
            mounts_json TEXT,
            resolved_target_json TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('prepared', 'claimed', 'released', 'stale')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        "UPDATE runtime_schema SET version=? WHERE id=1",
        (EXECUTION_BINDING_TARGET_SCHEMA_VERSION,),
    )
    return {
        "source_schema_version": EXECUTION_BINDING_PREVIOUS_SCHEMA_VERSION,
        "target_schema_version": EXECUTION_BINDING_TARGET_SCHEMA_VERSION,
        "added_columns": ["tasks.execution_request_json"],
        "added_tables": ["execution_bindings"],
    }


def _apply_v26_to_v27(connection: sqlite3.Connection) -> dict[str, object]:
    if "user_preferences" in _tables(connection):
        raise ValidationError("v26 user preferences table is already present")
    connection.execute(
        """
        CREATE TABLE user_preferences (
            actor_id TEXT PRIMARY KEY NOT NULL, id TEXT NOT NULL UNIQUE,
            content TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        "UPDATE runtime_schema SET version=? WHERE id=1",
        (USER_PREFERENCES_TARGET_SCHEMA_VERSION,),
    )
    return {
        "source_schema_version": USER_PREFERENCES_PREVIOUS_SCHEMA_VERSION,
        "target_schema_version": USER_PREFERENCES_TARGET_SCHEMA_VERSION,
        "added_tables": ["user_preferences"],
    }


def _spec_row_digest(connection: sqlite3.Connection, *, deduplicated: bool) -> tuple[int, str]:
    """Fingerprint retained row columns and the exact bytes of each spec."""
    digest = hashlib.sha256()
    count = 0
    for table in ("runs", "tasks"):
        for row in connection.execute(f"SELECT * FROM {table} ORDER BY id"):
            values = dict(row)
            if deduplicated:
                spec_digest = values.pop("spec_digest")
                if spec_digest is not None:
                    body = connection.execute(
                        "SELECT body_json FROM task_specs WHERE digest=?", (spec_digest,)
                    ).fetchone()
                    if body is None or hashlib.sha256(body[0].encode("utf-8")).hexdigest() != spec_digest:
                        raise ValidationError("migrated task spec reference is missing or corrupt")
            else:
                spec_digest = hashlib.sha256(values.pop("spec_json").encode("utf-8")).hexdigest()
            digest.update(canonical_json([table, values, spec_digest]).encode("utf-8"))
            count += 1
    return count, digest.hexdigest()


def _apply_v27_to_v28(connection: sqlite3.Connection) -> dict[str, object]:
    _, expected = _canonical_shape_for(USER_PREFERENCES_TARGET_SCHEMA_VERSION)
    for table in ("runs", "tasks"):
        if set(_table_columns(connection, table)) != expected[table]:
            raise ValidationError(f"v27 {table} shape is not recognized")
    before_count, before_digest = _spec_row_digest(connection, deduplicated=False)
    connection.execute(
        "CREATE TABLE task_specs (digest TEXT PRIMARY KEY, body_json TEXT NOT NULL, created_at TEXT NOT NULL)"
    )
    for table in ("runs", "tasks"):
        connection.execute(
            f"ALTER TABLE {table} ADD COLUMN spec_digest TEXT REFERENCES task_specs(digest)"
        )
        cursor = ""
        while True:
            batch = connection.execute(
                f"SELECT id, spec_json FROM {table} WHERE id > ? ORDER BY id LIMIT 20", (cursor,)
            ).fetchall()
            if not batch:
                break
            for row in batch:
                body = row["spec_json"]
                try:
                    if not isinstance(json.loads(body), dict):
                        raise ValueError("spec must be an object")
                except (ValueError, TypeError) as exc:
                    raise ValidationError(f"{table} spec is malformed: {row['id']}") from exc
                digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
                connection.execute(
                    "INSERT OR IGNORE INTO task_specs(digest, body_json, created_at) VALUES (?, ?, ?)",
                    (digest, body, now()),
                )
                connection.execute(
                    f"UPDATE {table} SET spec_digest=? WHERE id=?", (digest, row["id"])
                )
            cursor = batch[-1]["id"]
        connection.execute(f"ALTER TABLE {table} DROP COLUMN spec_json")
    after_count, after_digest = _spec_row_digest(connection, deduplicated=True)
    if (before_count, before_digest) != (after_count, after_digest):
        raise ValidationError("task/run retained-column digest changed during spec migration")
    connection.execute(
        "CREATE INDEX idx_tasks_retention ON tasks(updated_at) "
        "WHERE spec_digest IS NOT NULL AND status IN ('completed','failed','cancelled')"
    )
    connection.execute("UPDATE runtime_schema SET version=? WHERE id=1", (SPEC_DEDUP_TARGET_SCHEMA_VERSION,))
    return {"source_schema_version": USER_PREFERENCES_TARGET_SCHEMA_VERSION,
            "target_schema_version": SPEC_DEDUP_TARGET_SCHEMA_VERSION,
            "row_count": after_count, "retained_columns_sha256": after_digest,
            "unique_specs": connection.execute("SELECT COUNT(*) FROM task_specs").fetchone()[0]}


def _apply_v28_to_v29(connection: sqlite3.Connection, root: Path) -> dict[str, object]:
    """Move exact legacy projections to CAS, then repoint paired task specs."""
    cas = ContentAddressedStore(root / "cas" / "sha256")
    before = _retained_task_run_digest(connection)
    changed = 0
    inline_bytes = 0
    referenced_bytes = 0
    cursor = ""
    while True:
        rows = connection.execute(
            "SELECT r.id, r.project_id, r.spec_digest, t.id AS task_id, "
            "t.spec_digest AS task_spec_digest FROM runs r "
            "JOIN tasks t ON t.run_id=r.id WHERE r.id>? ORDER BY r.id LIMIT 20", (cursor,)
        ).fetchall()
        if not rows:
            break
        for row in rows:
            cursor = row["id"]
            if row["spec_digest"] is None:
                continue  # Retired terminal bodies have no replay source.
            if row["spec_digest"] != row["task_spec_digest"]:
                raise ValidationError("v28 task/run spec pair differs; refusing reference migration")
            source = connection.execute(
                "SELECT body_json FROM task_specs WHERE digest=?", (row["spec_digest"],)
            ).fetchone()
            if source is None or hashlib.sha256(source[0].encode()).hexdigest() != row["spec_digest"]:
                raise ValidationError("v28 task spec reference is missing or corrupt")
            original = json.loads(source[0])
            if not isinstance(original, dict):
                raise ValidationError("v28 task spec must be an object")
            published: list[str] = []

            def publish(snapshot, provenance):
                ref = publish_snapshot(connection, root / "cas" / "sha256", root / "staging",
                                       snapshot, provenance, row["project_id"])
                published.append(ref["digest"].removeprefix("sha256:"))
                return ref

            rewritten, count = rewrite_spec_snapshots(original, publish)
            if not count:
                continue
            def read(ref):
                digest = ref["digest"].removeprefix("sha256:")
                payload = cas.read(digest)
                if hashlib.sha256(payload).hexdigest() != digest:
                    raise ValidationError("migrated snapshot CAS digest mismatch")
                return json.loads(payload)
            for digest in published:
                object_id = "sha256:" + digest
                if object_id not in rewritten.get("input_object_ids", []):
                    rewritten.setdefault("input_object_ids", []).append(object_id)
            replay = restore_spec_snapshots(rewritten, read)
            replay["input_object_ids"] = original.get("input_object_ids", [])
            if canonical_json(replay) != canonical_json(original):
                raise ValidationError("v29 snapshot reference replay differs from legacy spec")
            body = canonical_json(rewritten)
            spec_digest = hashlib.sha256(body.encode()).hexdigest()
            connection.execute(
                "INSERT OR IGNORE INTO task_specs(digest,body_json,created_at) VALUES (?,?,?)",
                (spec_digest, body, now()),
            )
            connection.execute("UPDATE runs SET spec_digest=? WHERE id=?", (spec_digest, row["id"]))
            connection.execute("UPDATE tasks SET spec_digest=? WHERE id=?", (spec_digest, row["task_id"]))
            changed += 1
            inline_bytes += len(source[0].encode())
            referenced_bytes += len(body.encode())
    connection.execute(
        "DELETE FROM task_specs WHERE digest NOT IN "
        "(SELECT spec_digest FROM runs WHERE spec_digest IS NOT NULL UNION "
        "SELECT spec_digest FROM tasks WHERE spec_digest IS NOT NULL)"
    )
    if _retained_task_run_digest(connection) != before:
        raise ValidationError("task/run retained-column digest changed during reference migration")
    _validate_spec_records(connection)
    connection.execute("UPDATE runtime_schema SET version=29 WHERE id=1")
    return {"source_schema_version": 28, "target_schema_version": 29,
            "referenced_pairs": changed, "old_spec_bytes": inline_bytes,
            "new_spec_bytes": referenced_bytes}


def _apply_v29_to_v30(connection: sqlite3.Connection) -> dict[str, object]:
    connection.execute("ALTER TABLE timelines ADD COLUMN name TEXT")
    connection.execute("UPDATE runtime_schema SET version=30 WHERE id=1")
    return {"source_schema_version": 29, "target_schema_version": 30,
            "timeline_count": connection.execute("SELECT COUNT(*) FROM timelines").fetchone()[0]}


def _apply_v30_to_v31(connection: sqlite3.Connection) -> dict[str, object]:
    if "user_app_state" in _tables(connection):
        raise ValidationError("v30 user app state table is already present")
    connection.execute(
        """
        CREATE TABLE user_app_state (
            actor_id TEXT NOT NULL, key TEXT NOT NULL,
            content_json TEXT NOT NULL CHECK (json_valid(content_json)),
            version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            PRIMARY KEY (actor_id, key)
        )
        """
    )
    connection.execute("UPDATE runtime_schema SET version=31 WHERE id=1")
    return {"source_schema_version": 30, "target_schema_version": 31, "added_tables": ["user_app_state"]}


def _apply_v31_to_v32(connection: sqlite3.Connection) -> dict[str, object]:
    if connection.execute(
        "SELECT 1 FROM sqlite_master WHERE name='idx_generations_gen'"
    ).fetchone():
        raise ValidationError("v31 generation tag index is already present")
    connection.execute(GENERATION_TAG_INDEX_SQL)
    connection.execute("UPDATE runtime_schema SET version=32 WHERE id=1")
    return {"source_schema_version": 31, "target_schema_version": 32,
            "added_indexes": ["idx_generations_gen"]}


def migrate_canonical_v24_to_v25(
    root: str | Path,
    *,
    timeout_seconds: float = DEFAULT_UPGRADE_TIMEOUT_SECONDS,
    confirmation: str | None = None,
) -> dict:
    """Add variant poster/read-state columns to a stopped canonical v24 realm."""
    root = _safe_realm_root(root)
    if not root.exists() or not root.is_dir() or root.is_symlink():
        raise RealmAdmissionError("realm root is missing or invalid")
    if not math.isfinite(float(timeout_seconds)) or timeout_seconds <= 0:
        raise ValidationError("timeout_seconds must be positive")
    identity = inspect_canonical_schema(root)
    if identity["version"] != CANONICAL_PREVIOUS_SCHEMA_VERSION:
        raise ValidationError(
            f"variant state migration requires canonical schema v{CANONICAL_PREVIOUS_SCHEMA_VERSION}"
        )
    realm_id = str(identity["realm_id"])
    expected_confirmation = f"MIGRATE VARIANT STATE {realm_id}"
    if confirmation != expected_confirmation:
        raise ValidationError(f"migration requires confirmation exactly '{expected_confirmation}'")
    with _owner_fence(root):
        db = root / "realm.sqlite3"
        _regular(db, "realm database")
        connection = sqlite3.connect(db)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            started = time.monotonic()
            connection.execute("BEGIN IMMEDIATE")
            current = _canonical_schema_identity(connection, expected_realm_id=realm_id)
            if current["version"] != CANONICAL_PREVIOUS_SCHEMA_VERSION:
                raise ConflictError("realm schema changed before v24 migration")
            step = _apply_v24_to_v25(connection)
            connection.commit()
            elapsed = time.monotonic() - started
            return {
                "ok": True,
                "realm_id": realm_id,
                **step,
                "elapsed_seconds": elapsed,
            }
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def migrate_canonical_v25_to_v26(
    root: str | Path,
    *,
    timeout_seconds: float = DEFAULT_UPGRADE_TIMEOUT_SECONDS,
    confirmation: str | None = None,
) -> dict:
    """Add the durable targeted-execution binding contract to a stopped realm."""
    root = _safe_realm_root(root)
    if not root.exists() or not root.is_dir() or root.is_symlink():
        raise RealmAdmissionError("realm root is missing or invalid")
    if not math.isfinite(float(timeout_seconds)) or timeout_seconds <= 0:
        raise ValidationError("timeout_seconds must be positive")
    identity = inspect_canonical_schema(root)
    if identity["version"] != EXECUTION_BINDING_PREVIOUS_SCHEMA_VERSION:
        raise ValidationError(
            f"execution binding migration requires canonical schema v{EXECUTION_BINDING_PREVIOUS_SCHEMA_VERSION}"
        )
    realm_id = str(identity["realm_id"])
    expected_confirmation = f"MIGRATE EXECUTION BINDING {realm_id}"
    if confirmation != expected_confirmation:
        raise ValidationError(f"migration requires confirmation exactly '{expected_confirmation}'")
    with _owner_fence(root):
        db = root / "realm.sqlite3"
        _regular(db, "realm database")
        connection = sqlite3.connect(db)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            started = time.monotonic()
            connection.execute("BEGIN IMMEDIATE")
            current = _canonical_schema_identity(connection, expected_realm_id=realm_id)
            if current["version"] != EXECUTION_BINDING_PREVIOUS_SCHEMA_VERSION:
                raise ConflictError("realm schema changed before v25 migration")
            step = _apply_v25_to_v26(connection)
            connection.commit()
            return {
                "ok": True,
                "realm_id": realm_id,
                **step,
                "elapsed_seconds": time.monotonic() - started,
            }
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


MIGRATION_VACUUM_MIN_FREE_BYTES = 64 * 1024 * 1024


def _reclaim_after_migration(connection: sqlite3.Connection) -> dict[str, object]:
    """Give the pages a migration freed back to the disk.

    Spec deduplication (v28/v29) frees most of a long-lived realm (the film's
    1.1 GB database was 77% free pages). The schema change is already
    committed, so a VACUUM that cannot run (e.g. low disk) is reported, not fatal;
    ``astrid-runtime-protocol compact`` can reclaim the space later.
    """
    page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
    free_bytes = page_size * int(connection.execute("PRAGMA freelist_count").fetchone()[0])
    if free_bytes < MIGRATION_VACUUM_MIN_FREE_BYTES:
        return {"performed": False, "free_bytes": free_bytes}
    try:
        connection.execute("VACUUM")
    except sqlite3.Error as exc:
        return {"performed": False, "free_bytes": free_bytes, "error": str(exc)}
    return {"performed": True, "reclaimed_bytes": free_bytes}


def migrate_canonical_to_current(
    root: str | Path,
    *,
    timeout_seconds: float = DEFAULT_UPGRADE_TIMEOUT_SECONDS,
    confirmation: str | None = None,
    expected_realm_id: str | None = None,
) -> dict:
    """Atomically run every supported canonical step through pinned v32.

    Current v32 is a read-only idempotent result.  Unknown, alternate, and
    newer layouts are rejected by the read-only preflight before an owner-lock
    marker, SQLite sidecar, journal, process signal, or schema mutation occurs.
    """
    root = _safe_realm_root(root)
    if not math.isfinite(float(timeout_seconds)) or timeout_seconds <= 0:
        raise ValidationError("timeout_seconds must be positive")
    identity = inspect_canonical_schema(root, expected_realm_id=expected_realm_id)
    realm_id = str(identity["realm_id"])
    expected_confirmation = f"MIGRATE CANONICAL {realm_id}"
    if confirmation != expected_confirmation:
        raise ValidationError(f"migration requires confirmation exactly '{expected_confirmation}'")
    source_version = int(identity["version"])
    if source_version == GENERATION_TAG_TARGET_SCHEMA_VERSION:
        return {
            "ok": True,
            "realm_id": realm_id,
            "source_schema_version": source_version,
            "target_schema_version": GENERATION_TAG_TARGET_SCHEMA_VERSION,
            "steps": [],
            "changed": False,
        }
    started = time.monotonic()
    with _owner_fence(root):
        connection = sqlite3.connect(root / "realm.sqlite3", timeout=float(timeout_seconds))
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = _canonical_schema_identity(connection, expected_realm_id=realm_id)
            if int(current["version"]) != source_version:
                raise ConflictError("realm schema changed before canonical migration")
            steps: list[dict[str, object]] = []
            if source_version == CANONICAL_PREVIOUS_SCHEMA_VERSION:
                steps.append(_apply_v24_to_v25(connection))
                current = _canonical_schema_identity(connection, expected_realm_id=realm_id)
                if int(current["version"]) != VARIANT_STATE_TARGET_SCHEMA_VERSION:
                    raise ValidationError("v24 to v25 migration did not produce the pinned v25 layout")
            if int(current["version"]) == EXECUTION_BINDING_PREVIOUS_SCHEMA_VERSION:
                steps.append(_apply_v25_to_v26(connection))
                current = _canonical_schema_identity(connection, expected_realm_id=realm_id)
                if int(current["version"]) != EXECUTION_BINDING_TARGET_SCHEMA_VERSION:
                    raise ValidationError("v25 to v26 migration did not produce the pinned v26 layout")
            if int(current["version"]) == USER_PREFERENCES_PREVIOUS_SCHEMA_VERSION:
                steps.append(_apply_v26_to_v27(connection))
                current = _canonical_schema_identity(connection, expected_realm_id=realm_id)
            if int(current["version"]) == USER_PREFERENCES_TARGET_SCHEMA_VERSION:
                steps.append(_apply_v27_to_v28(connection))
                current = _canonical_schema_identity(connection, expected_realm_id=realm_id)
            if int(current["version"]) == SPEC_DEDUP_TARGET_SCHEMA_VERSION:
                steps.append(_apply_v28_to_v29(connection, root))
                current = _canonical_schema_identity(connection, expected_realm_id=realm_id)
            if int(current["version"]) == SPEC_REFERENCE_TARGET_SCHEMA_VERSION:
                steps.append(_apply_v29_to_v30(connection))
                current = _canonical_schema_identity(connection, expected_realm_id=realm_id)
            if int(current["version"]) == TIMELINE_NAME_TARGET_SCHEMA_VERSION:
                steps.append(_apply_v30_to_v31(connection))
                current = _canonical_schema_identity(connection, expected_realm_id=realm_id)
            if int(current["version"]) == USER_APP_STATE_TARGET_SCHEMA_VERSION:
                steps.append(_apply_v31_to_v32(connection))
            final = _canonical_schema_identity(connection, expected_realm_id=realm_id)
            if int(final["version"]) != GENERATION_TAG_TARGET_SCHEMA_VERSION:
                raise ValidationError("canonical migration did not produce the pinned v32 layout")
            if _quick_check(connection, float(timeout_seconds)) != "ok":
                raise ValidationError("migrated database failed SQLite integrity check")
            foreign_keys = _foreign_key_errors(connection, float(timeout_seconds))
            if foreign_keys:
                raise ValidationError("migrated database failed foreign-key validation")
            connection.commit()
            return {
                "ok": True,
                "realm_id": realm_id,
                "source_schema_version": source_version,
                "target_schema_version": GENERATION_TAG_TARGET_SCHEMA_VERSION,
                "steps": steps,
                "changed": True,
                "vacuum": _reclaim_after_migration(connection),
                "elapsed_seconds": time.monotonic() - started,
            }
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def _source_shape(connection: sqlite3.Connection) -> tuple[set[str], dict[str, list[str]], str]:
    tables = _tables(connection)
    if "schema_migrations" not in tables and "runtime_schema" in tables:
        schema = connection.execute("SELECT format_id, version FROM runtime_schema WHERE id=1").fetchone()
        if not schema or schema[0] != CANONICAL_FORMAT_ID or int(schema[1]) != SCHEMA_VERSION:
            raise ValidationError("upgrade requires the current canonical schema")
        if REVISION_TABLES.issubset(tables):
            raise ValidationError("upgrade source already contains the canonical revision tables; schema_migrations is absent")
        unknown = tables - set(REQUIRED_SCHEMA_TABLES)
        if unknown:
            raise ValidationError("upgrade refuses unknown source tables: " + ", ".join(sorted(unknown)))
        excluded = {"runtime_schema", *REVISION_TABLES}
        columns: dict[str, list[str]] = {}
        for table in sorted(REQUIRED_SCHEMA_TABLES - excluded):
            actual = _table_columns(connection, table)
            expected = list(REQUIRED_SCHEMA_COLUMNS[table])
            if set(actual) != set(expected) or len(actual) != len(expected):
                raise ValidationError(f"upgrade source shape differs for table {table}")
            columns[table] = actual
        return tables, columns, str(schema[1])
    if "schema_migrations" not in tables:
        raise ValidationError("upgrade requires a legacy schema_migrations table")
    version = connection.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()[0]
    if int(version) != 23:
        raise ValidationError(f"upgrade requires schema version 23, found {version}")
    # A legacy fixture may have been opened once by a newer Runtime before it
    # was returned to the retired migration shape.  The revision tables are
    # additive and are intentionally empty in that source; the original v24
    # marker/output tables remain the repeatability fence.
    if tables & {"runtime_schema", "managed_output_associations", "managed_output_lifecycle"}:
        raise ValidationError("upgrade source already contains v24 tables")
    unknown = tables - set(REQUIRED_SCHEMA_TABLES) - LEGACY_TABLES
    if unknown:
        raise ValidationError("upgrade refuses unknown source tables: " + ", ".join(sorted(unknown)))
    missing = set(REQUIRED_SCHEMA_TABLES) - NEW_TABLES - tables
    if missing:
        raise ValidationError("upgrade source is missing shared canonical tables: " + ", ".join(sorted(missing)))
    columns: dict[str, list[str]] = {}
    shared_tables = (REQUIRED_SCHEMA_TABLES - NEW_TABLES) | (tables & {"user_preferences"})
    _, legacy_columns = _canonical_shape_for(USER_PREFERENCES_TARGET_SCHEMA_VERSION)
    for table in sorted(shared_tables):
        actual = _table_columns(connection, table)
        expected = list(legacy_columns[table])
        if set(actual) != set(expected) or len(actual) != len(expected):
            raise ValidationError(f"upgrade source shape differs for table {table}")
        columns[table] = actual
    return tables, columns, str(version)


def _archive_source(root: Path, archive: Path) -> dict:
    archive.mkdir(parents=True, exist_ok=False)
    components = {}
    for suffix in ("", "-wal", "-shm", "-journal"):
        source_path = root / f"realm.sqlite3{suffix}"
        if source_path.exists() or source_path.is_symlink():
            _regular(source_path, f"realm.sqlite3{suffix}")
            target = archive / source_path.name
            shutil.copy2(source_path, target)
            _fsync_file(target)
            size, digest = _file_digest(target)
            components[source_path.name] = {"size": size, "sha256": digest}
    _fsync_directory(archive)
    _fsync_directory(archive.parent)
    return {"components": components}


def _assert_snapshot_unchanged(root: Path, metadata: dict) -> None:
    """Refuse to activate if anything changed after the archive was taken."""
    for name, expected in metadata.get("components", {}).items():
        current = root / name
        _regular(current, name)
        size, digest = _file_digest(current)
        if size != expected["size"] or digest != expected["sha256"]:
            raise ConflictError(f"realm changed while preparing upgrade: {name}")
    archived = set(metadata.get("components", {}))
    current = {f"realm.sqlite3{suffix}" for suffix in ("", "-wal", "-shm", "-journal") if (root / f"realm.sqlite3{suffix}").exists()}
    if current != archived:
        raise ConflictError("realm SQLite sidecars changed while preparing upgrade")


def _checkpoint_source_wal(source_db: Path) -> None:
    """Merge any old WAL into the old DB before the canonical DB is swapped in."""
    connection = sqlite3.connect(source_db, isolation_level=None, timeout=5.0)
    try:
        result = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if result is not None and int(result[0]) != 0:
            raise ConflictError("source SQLite WAL is busy; upgrade was not activated")
    finally:
        connection.close()
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = source_db.with_name(source_db.name + suffix)
        if sidecar.exists() or sidecar.is_symlink():
            sidecar.unlink()
    _fsync_directory(source_db.parent)


def _fsync_file(path: Path) -> None:
    # FlushFileBuffers (and consequently Windows os.fsync) needs write access.
    with path.open("r+b") as handle:
        os.fsync(handle.fileno())


def _fsync_directory(path: Path) -> None:
    platform.fsync_directory(path)


def _copy_shared(source: sqlite3.Connection, target: sqlite3.Connection, columns: dict[str, list[str]], *, deadline: float | None = None) -> dict[str, dict[str, object]]:
    with _sqlite_deadline(source, deadline), _sqlite_deadline(target, deadline):
        target.execute("PRAGMA foreign_keys=OFF")
        fingerprints = {}
        try:
            for table in sorted(columns):
                names = columns[table]
                source_count, source_digest = _row_digest(source, table, names, deadline=deadline)
                quoted = ", ".join(_quote(name) for name in names)
                rows = source.execute(
                    f"SELECT {quoted} FROM {_quote(table)} ORDER BY {_row_ordering(source, table, names)}"
                )
                if table in {"runs", "tasks"} and "spec_json" in names:
                    target_names = ["spec_digest" if name == "spec_json" else name for name in names]
                    target_quoted = ", ".join(_quote(name) for name in target_names)
                    placeholders = ", ".join("?" for _ in target_names)
                    spec_index = names.index("spec_json")
                    for row in rows:
                        values = list(row)
                        body = values[spec_index]
                        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
                        target.execute(
                            "INSERT OR IGNORE INTO task_specs(digest, body_json, created_at) VALUES (?, ?, ?)",
                            (digest, body, now()),
                        )
                        values[spec_index] = digest
                        target.execute(f"INSERT INTO {_quote(table)} ({target_quoted}) VALUES ({placeholders})", values)
                    count = target.execute(f"SELECT COUNT(*) FROM {_quote(table)}").fetchone()[0]
                    if source_count != count:
                        raise ValidationError(f"source and staged rows differ for table {table}")
                    fingerprints[table] = {"rows": count, "sha256": source_digest}
                else:
                    placeholders = ", ".join("?" for _ in names)
                    target.executemany(f"INSERT INTO {_quote(table)} ({quoted}) VALUES ({placeholders})", rows)
                    count, digest = _row_digest(target, table, names, deadline=deadline)
                    if (source_count, source_digest) != (count, digest):
                        raise ValidationError(f"source and staged rows differ for table {table}")
                    fingerprints[table] = {"rows": count, "sha256": digest}
            target.execute(
                "INSERT INTO runtime_schema(id, format_id, version, created_at) VALUES (1, ?, ?, ?)",
                (CANONICAL_FORMAT_ID, SCHEMA_VERSION, now()),
            )
            target.commit()
            target.execute("PRAGMA foreign_keys=ON")
            if "runs" in columns and "tasks" in columns and "spec_json" in columns["runs"]:
                target.row_factory = sqlite3.Row
                if _spec_row_digest(source, deduplicated=False) != _spec_row_digest(target, deduplicated=True):
                    raise ValidationError("source and staged task/run facts differ")
            return fingerprints
        except sqlite3.DatabaseError as exc:
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("SQLite row copy timed out") from exc
            raise


def _validate_candidate(target: sqlite3.Connection, root: Path, timeout: float) -> dict:
    target.row_factory = sqlite3.Row
    target.execute("PRAGMA query_only=ON")
    quick = _quick_check(target, timeout)
    if quick != "ok":
        raise ValidationError("staged database failed SQLite integrity check")
    foreign_keys = _foreign_key_errors(target, timeout)
    if foreign_keys:
        raise ValidationError("staged database failed foreign-key validation")
    inspector = object.__new__(RealmStore)
    inspector.root = root
    inspector.cas_root = root / "cas" / "sha256"
    inspector.conn = target
    inspector._mutex = None
    report = inspector._integrity_report(deadline=time.monotonic() + timeout)
    if not report.get("ok"):
        raise ValidationError("staged database failed canonical validation", details=report)
    return report


def _write_manifest(archive: Path, metadata: dict) -> None:
    """Write a self-authenticating manifest through a same-directory rename."""
    payload = dict(metadata)
    payload.pop("manifest_sha256", None)
    payload["manifest_sha256"] = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
    temporary = archive / ".manifest.json.tmp"
    temporary.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    platform.owner_only(temporary)
    _fsync_file(temporary)
    platform.durable_replace(temporary, archive / "manifest.json")


def upgrade_realm(
    root: str | Path,
    *,
    archive_root: str | Path | None = None,
    retain_backup: bool = False,
    timeout_seconds: float = DEFAULT_UPGRADE_TIMEOUT_SECONDS,
    confirmation: str | None = None,
) -> dict:
    """Upgrade one stopped v23 realm with a temporary rollback snapshot.

    A durable source archive is created only when ``retain_backup`` is
    explicitly requested. The transaction always takes a same-filesystem
    temporary copy so it can verify and roll back the swap; that copy is
    removed after success or successful rollback.
    """
    root = _safe_realm_root(root)
    if not root.exists() or not root.is_dir() or root.is_symlink():
        raise RealmAdmissionError("realm root is missing or invalid")
    if not math.isfinite(float(timeout_seconds)) or timeout_seconds <= 0:
        raise ValidationError("timeout_seconds must be positive")
    if archive_root is not None and not retain_backup:
        raise ValidationError("archive_root requires retain_backup=True")
    archive_parent = None
    if retain_backup:
        archive_parent = Path(archive_root).expanduser().resolve() if archive_root else root / "realm-upgrade-backups"
        try:
            archive_parent.relative_to(root.parent)
        except ValueError as exc:
            raise ValidationError("archive_root must share the realm's filesystem parent") from exc
    with _owner_fence(root):
        source_db = root / "realm.sqlite3"
        source = None
        stage_dir = None
        target = None
        restore_required = False
        archive = None
        temporary_archive_parent = None
        preserve_temporary_archive = False
        try:
            operation_id = uuid.uuid4().hex
            if archive_parent is None:
                temporary_archive_parent = Path(
                    tempfile.mkdtemp(prefix=".realm-upgrade-transaction-", dir=root.parent)
                )
                archive = temporary_archive_parent / f"v23-{operation_id}"
            else:
                archive_parent.mkdir(parents=True, exist_ok=True)
                archive = archive_parent / f"v23-{operation_id}"
            # Archive before opening SQLite.  Even a read-only SQLite
            # connection may create/update a WAL shared-memory sidecar; the
            # source tree must remain byte-identical on every rejected plan.
            archive_meta = _archive_source(root, archive)
            # Read from a disposable copy as SQLite may modify its SHM even
            # in read-only mode. The recovery image and its hashes stay exact.
            stage_dir = Path(tempfile.mkdtemp(prefix=".realm-upgrade-", dir=root.parent))
            source_copy = stage_dir / "source"
            source_copy.mkdir()
            for name in archive_meta["components"]:
                shutil.copy2(archive / name, source_copy / name)
            source = _open_readonly(source_copy / "realm.sqlite3")
            tables, columns, source_version = _source_shape(source)
            source_check = _quick_check(source, timeout_seconds)
            if source_check != "ok":
                raise ValidationError("archived source failed SQLite integrity check")
            if _foreign_key_errors(source, timeout_seconds):
                raise ValidationError("archived source failed foreign-key validation")
            realm_row = source.execute("SELECT id FROM realm LIMIT 1").fetchone()
            realm_id = str(realm_row[0]) if realm_row else ""
            if not realm_id:
                raise ValidationError("upgrade source has no realm identity")
            if confirmation != f"UPGRADE {realm_id}":
                raise ValidationError(f"upgrade requires confirmation exactly 'UPGRADE {realm_id}'")
            legacy = {}
            for table in sorted(tables & LEGACY_TABLES):
                table_columns = _table_columns(source, table)
                count, digest = _row_digest(source, table, table_columns, deadline=time.monotonic() + timeout_seconds)
                legacy[table] = {"columns": table_columns, "rows": count, "sha256": digest}
            archive_meta["legacy_tables"] = legacy
            stage_db = stage_dir / "realm.sqlite3"
            target = sqlite3.connect(stage_db)
            target.executescript(CANONICAL_SCHEMA_SQL)
            fingerprints = _copy_shared(source, target, columns, deadline=time.monotonic() + timeout_seconds)
            historical_candidates, historical_skipped = _collect_historical_candidates(
                source, root, timeout_seconds, verify_cas=False
            )
            historical_inserted = _insert_historical_candidates(target, historical_candidates)
            target.commit()
            report = _validate_candidate(target, root, timeout_seconds)
            target.close()
            target = None
            source.close()
            source = None
            _assert_snapshot_unchanged(root, archive_meta)
            # The source WAL is part of the archived evidence.  Checkpoint it
            # before replacing the DB so a crash cannot make SQLite apply an
            # old WAL to the newly activated canonical file.
            restore_required = True
            _checkpoint_source_wal(source_db)
            archive_meta.update({
                "format": "runtime-realm-upgrade/v1",
                "state": "validated",
                "operation_id": archive.name.removeprefix("v23-"),
                "source_schema_version": int(source_version),
                "target_schema_version": SCHEMA_VERSION,
                "source_realm_id": realm_id,
                "shared_tables": fingerprints,
                "historical_managed_outputs": {
                    "migrated": historical_inserted,
                    "skipped": historical_skipped,
                    "skipped_count": len(historical_skipped),
                },
                "target_integrity": report,
                "created_at": now(),
            })
            _write_manifest(archive, archive_meta)
            platform.owner_only(stage_db)
            _fsync_file(stage_db)
            _fsync_directory(stage_dir)
            platform.replace_path(stage_db, source_db)
            # The completed publication is now covered by restore_required;
            # a failed directory flush must take the rollback path too.
            platform.flush_replace(stage_db, source_db)
            archive_meta.update({"state": "activated", "activated_at": now()})
            _write_manifest(archive, archive_meta)
            return {
                "ok": True,
                "realm_id": realm_id,
                "archive": str(archive) if retain_backup else None,
                "backup_retained": bool(retain_backup),
                "root": str(root),
                "source_schema_version": int(source_version),
                "target_schema_version": SCHEMA_VERSION,
                "shared_tables": fingerprints,
                "historical_managed_outputs": {
                    "migrated": historical_inserted,
                    "skipped": historical_skipped,
                    "skipped_count": len(historical_skipped),
                },
            }
        except Exception:
            if target is not None:
                target.close()
            if restore_required and archive is not None:
                # A post-swap sidecar or manifest failure must not strand a
                # half-activated realm. Restore the archived byte snapshot;
                # the archive remains available for operator inspection.
                try:
                    rollback = root.parent / f".{source_db.name}.rollback-{uuid.uuid4().hex}"
                    shutil.copy2(archive / source_db.name, rollback)
                    platform.owner_only(rollback)
                    _fsync_file(rollback)
                    platform.durable_replace(rollback, source_db)
                    for suffix in ("-wal", "-shm", "-journal"):
                        archived_sidecar = archive / f"{source_db.name}{suffix}"
                        restored_sidecar = root / f"{source_db.name}{suffix}"
                        if archived_sidecar.exists():
                            rollback_sidecar = root / f".{restored_sidecar.name}.rollback-{uuid.uuid4().hex}"
                            shutil.copy2(archived_sidecar, rollback_sidecar)
                            platform.owner_only(rollback_sidecar)
                            _fsync_file(rollback_sidecar)
                            platform.durable_replace(rollback_sidecar, restored_sidecar)
                        elif restored_sidecar.exists() or restored_sidecar.is_symlink():
                            restored_sidecar.unlink()
                    _fsync_directory(root)
                except Exception as rollback_error:
                    # Keep the only rollback image if restoration itself
                    # fails. Its path is deterministic from this exception's
                    # operation id and the operator can recover it manually.
                    preserve_temporary_archive = temporary_archive_parent is not None
                    raise RuntimeError(
                        "realm upgrade rollback failed; recovery snapshot preserved at "
                        f"{archive}"
                    ) from rollback_error
            if stage_dir is not None:
                staged = stage_dir / "realm.sqlite3"
                if staged.exists():
                    staged.unlink()
            if temporary_archive_parent is not None and not preserve_temporary_archive:
                shutil.rmtree(temporary_archive_parent, ignore_errors=True)
            raise
        finally:
            if source is not None:
                source.close()
            if stage_dir is not None:
                shutil.rmtree(stage_dir, ignore_errors=True)
            if temporary_archive_parent is not None and not preserve_temporary_archive:
                shutil.rmtree(temporary_archive_parent, ignore_errors=True)


def _historical_filename(spec: object, output: dict) -> str | None:
    """Resolve a historical name only from the settled task's own spec."""
    value = output.get("filename")
    if not isinstance(value, str) or not value:
        value = None
    if value is None and isinstance(spec, dict):
        pending = [spec]
        while pending:
            current = pending.pop(0)
            if not isinstance(current, dict):
                continue
            candidate = current.get("output_name")
            if isinstance(candidate, str) and candidate:
                value = candidate
                break
            snapshot = current.get("timeline_snapshot")
            config = snapshot.get("config") if isinstance(snapshot, dict) else None
            declared_output = config.get("output") if isinstance(config, dict) else None
            candidate = declared_output.get("file") if isinstance(declared_output, dict) else None
            if isinstance(candidate, str) and candidate:
                value = candidate
                break
            pending.extend(child for child in current.values() if isinstance(child, dict))
    if not isinstance(value, str) or Path(value).name != value or not _SAFE_FILENAME.fullmatch(value):
        return None
    return value if Path(value).suffix.lower() in _VIDEO_SUFFIXES else None


def _historical_video_media_type(value: object, filename: str) -> str | None:
    if not isinstance(value, str):
        return None
    media_type = value.strip().lower()
    if media_type in _VIDEO_MEDIA_TYPES:
        return media_type
    # A historical artifact type is retained as-is in the object row.  The
    # extension is used only to reject non-video outputs during reconciliation.
    if media_type == "clip/visual" and Path(filename).suffix.lower() in _VIDEO_SUFFIXES:
        return media_type
    return None


def _verified_cas_object(root: Path, digest: str, expected_size: int, deadline: float) -> None:
    path = root / "cas" / "sha256" / digest[:2] / digest[2:]
    _regular(path, f"CAS object {digest}")
    actual_size, actual_digest = _file_digest_until(path, deadline)
    if actual_size != expected_size or actual_digest != digest:
        raise ValidationError(f"historical output CAS verification failed for {digest}")


def _media_type_from_filename(filename: object) -> str | None:
    """Infer a display MIME only from a safe direct output filename."""
    if not isinstance(filename, str) or not filename or Path(filename).name != filename:
        return None
    media_type = _VIDEO_SUFFIX_MEDIA_TYPES.get(Path(filename).suffix.lower())
    if media_type is not None:
        return media_type
    media_type = mimetypes.guess_type(filename)[0]
    if not media_type or media_type.lower() == "application/octet-stream":
        return None
    return media_type


def repair_generic_media_types(
    root: str | Path,
    *,
    project_id: str | None = None,
    task_id: str | None = None,
    generation_id: str | None = None,
    timeout_seconds: float = DEFAULT_UPGRADE_TIMEOUT_SECONDS,
    confirmation: str | None = None,
) -> dict:
    """Repair generic published MIME values using the managed filename contract.

    This is an explicit, stopped-runtime migration for rows published before
    producers consistently supplied MIME types. It changes metadata only when
    every reference to an object agrees with the filename-derived type and the
    CAS bytes still verify against the stored digest and size.
    """
    root = _safe_realm_root(root)
    if not root.exists() or not root.is_dir() or root.is_symlink():
        raise RealmAdmissionError("realm root is missing or invalid")
    if not math.isfinite(float(timeout_seconds)) or timeout_seconds <= 0:
        raise ValidationError("timeout_seconds must be positive")
    with _owner_fence(root):
        db = root / "realm.sqlite3"
        _regular(db, "realm database")
        connection = sqlite3.connect(db)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            schema = connection.execute("SELECT format_id, version FROM runtime_schema WHERE id=1").fetchone()
            if not schema or schema[0] != CANONICAL_FORMAT_ID or int(schema[1]) != SCHEMA_VERSION:
                raise ValidationError(f"generic MIME repair requires canonical schema v{SCHEMA_VERSION}")
            realm_id = str(connection.execute("SELECT id FROM realm LIMIT 1").fetchone()[0])
            expected_confirmation = f"{GENERIC_MEDIA_TYPE_REPAIR_CONFIRMATION} {realm_id}"
            if confirmation != expected_confirmation:
                raise ValidationError(f"repair requires confirmation exactly '{expected_confirmation}'")

            filters: list[str] = []
            association_params: list[object] = ["application/octet-stream"]
            variant_params: list[object] = ["application/octet-stream"]
            if project_id:
                filters.append("project_id=?")
                association_params.append(project_id)
            if task_id:
                filters.append("task_id=?")
                association_params.append(task_id)
            if generation_id:
                filters.append("generation_id=?")
                association_params.append(generation_id)
            association_where = " AND ".join(["media_type=?", *filters])
            associations = connection.execute(
                f"SELECT * FROM managed_output_associations WHERE {association_where} ORDER BY association_id",
                tuple(association_params),
            ).fetchall()

            variant_filters: list[str] = ["json_extract(gv.metadata_json, '$.media_type')=?"]
            if project_id:
                variant_filters.append("g.project_id=?")
                variant_params.append(project_id)
            if task_id:
                variant_filters.append("g.source_task_id=?")
                variant_params.append(task_id)
            if generation_id:
                variant_filters.append("gv.generation_id=?")
                variant_params.append(generation_id)
            variants = connection.execute(
                "SELECT gv.*, g.project_id, g.source_task_id FROM generation_variants gv "
                "JOIN generations g ON g.id=gv.generation_id WHERE "
                + " AND ".join(variant_filters)
                + " ORDER BY gv.id",
                tuple(variant_params),
            ).fetchall()

            skipped: list[dict[str, object]] = []
            association_plan: list[tuple[str, str, str]] = []
            variant_plan: list[tuple[str, str, str]] = []
            digest_targets: dict[str, set[str]] = {}

            for row in associations:
                media_type = _media_type_from_filename(row["filename"])
                if media_type is None:
                    skipped.append({"kind": "association", "id": row["association_id"], "reason": "filename_has_no_supported_mime"})
                    continue
                digest_targets.setdefault(str(row["object_digest"]), set()).add(media_type)
                association_plan.append((str(row["association_id"]), str(row["object_digest"]), media_type))

            for row in variants:
                try:
                    metadata = json.loads(row["metadata_json"])
                except (TypeError, json.JSONDecodeError):
                    skipped.append({"kind": "variant", "id": row["id"], "reason": "malformed_metadata"})
                    continue
                media_type = _media_type_from_filename(metadata.get("filename"))
                if media_type is None or not row["object_id"]:
                    skipped.append({"kind": "variant", "id": row["id"], "reason": "filename_has_no_supported_mime"})
                    continue
                digest = str(row["object_id"])
                digest_targets.setdefault(digest, set()).add(media_type)
                variant_plan.append((str(row["id"]), digest, media_type))

            target_by_digest: dict[str, str] = {}
            for digest, targets in digest_targets.items():
                if len(targets) != 1:
                    skipped.append({"kind": "object", "id": digest, "reason": "conflicting_filename_mimes"})
                    continue
                target_by_digest[digest] = next(iter(targets))

            deadline = time.monotonic() + float(timeout_seconds)
            for digest, target in list(target_by_digest.items()):
                object_row = connection.execute(
                    "SELECT size, media_type FROM objects WHERE digest=?", (digest,)
                ).fetchone()
                if object_row is None:
                    skipped.append({"kind": "object", "id": digest, "reason": "object_missing"})
                    target_by_digest.pop(digest)
                    continue
                _verified_cas_object(root, digest, int(object_row["size"]), deadline)
                existing_object_type = str(object_row["media_type"] or "").strip().lower()
                if existing_object_type not in {"", "application/octet-stream", target}:
                    skipped.append({"kind": "object", "id": digest, "reason": "object_media_type_conflict"})
                    target_by_digest.pop(digest)
                    continue
                for reference in connection.execute(
                    "SELECT media_type, filename FROM managed_output_associations WHERE object_digest=?",
                    (digest,),
                ):
                    reference_type = str(reference["media_type"] or "").strip().lower()
                    inferred = _media_type_from_filename(reference["filename"])
                    resolved = inferred if reference_type in {"", "application/octet-stream", "clip/visual"} else reference_type
                    if resolved != target:
                        skipped.append({"kind": "object", "id": digest, "reason": "association_media_type_conflict"})
                        target_by_digest.pop(digest)
                        break
                if digest not in target_by_digest:
                    continue
                for reference in connection.execute(
                    "SELECT metadata_json FROM generation_variants WHERE object_id=?",
                    (digest,),
                ):
                    try:
                        metadata = json.loads(reference["metadata_json"])
                    except (TypeError, json.JSONDecodeError):
                        resolved = None
                    else:
                        reference_type = str(metadata.get("media_type") or "").strip().lower()
                        inferred = _media_type_from_filename(metadata.get("filename"))
                        resolved = inferred if reference_type in {"", "application/octet-stream", "clip/visual"} else reference_type
                    if resolved != target:
                        skipped.append({"kind": "object", "id": digest, "reason": "variant_media_type_conflict"})
                        target_by_digest.pop(digest)
                        break

            # An object can be shared by several settled attempts. Once the
            # object-level type is proven, repair every generic reference to
            # it, including references outside the optional scope filters, so
            # Runtime's object and association contracts remain consistent.
            for digest, target in target_by_digest.items():
                for reference in connection.execute(
                    "SELECT association_id, media_type, filename FROM managed_output_associations WHERE object_digest=?",
                    (digest,),
                ):
                    if str(reference["media_type"] or "").strip().lower() != "application/octet-stream":
                        continue
                    if _media_type_from_filename(reference["filename"]) == target:
                        association_plan.append((str(reference["association_id"]), digest, target))
                for reference in connection.execute(
                    "SELECT id, metadata_json FROM generation_variants WHERE object_id=?",
                    (digest,),
                ):
                    try:
                        metadata = json.loads(reference["metadata_json"])
                    except (TypeError, json.JSONDecodeError):
                        continue
                    if str(metadata.get("media_type") or "").strip().lower() != "application/octet-stream":
                        continue
                    if _media_type_from_filename(metadata.get("filename")) == target:
                        variant_plan.append((str(reference["id"]), digest, target))

            association_plan = list(dict.fromkeys(association_plan))
            variant_plan = list(dict.fromkeys(variant_plan))
            connection.execute("BEGIN")
            repaired_objects = 0
            repaired_associations = 0
            repaired_variants = 0
            for digest, target in target_by_digest.items():
                cursor = connection.execute(
                    "UPDATE objects SET media_type=? WHERE digest=? AND media_type=?",
                    (target, digest, "application/octet-stream"),
                )
                repaired_objects += cursor.rowcount
            for association_id, digest, target in association_plan:
                if digest not in target_by_digest:
                    continue
                cursor = connection.execute(
                    "UPDATE managed_output_associations SET media_type=? WHERE association_id=? AND media_type=?",
                    (target, association_id, "application/octet-stream"),
                )
                repaired_associations += cursor.rowcount
            for variant_id, digest, target in variant_plan:
                if digest not in target_by_digest:
                    continue
                row = connection.execute("SELECT metadata_json FROM generation_variants WHERE id=?", (variant_id,)).fetchone()
                if row is None:
                    continue
                metadata = json.loads(row["metadata_json"])
                metadata["media_type"] = target
                connection.execute(
                    "UPDATE generation_variants SET metadata_json=? WHERE id=?",
                    (canonical_json(metadata), variant_id),
                )
                repaired_variants += 1
            connection.commit()
            return {
                "ok": True,
                "realm_id": realm_id,
                "project_id": project_id,
                "task_id": task_id,
                "generation_id": generation_id,
                "repaired": {
                    "objects": repaired_objects,
                    "associations": repaired_associations,
                    "variants": repaired_variants,
                },
                "skipped": skipped,
                "skipped_count": len(skipped),
            }
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def _file_digest_until(path: Path, deadline: float) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("historical output verification timed out")
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
    return size, digest.hexdigest()


def _historical_output_identity(task_id: str, output: dict) -> tuple[str, str, str, int]:
    output_port = output.get("output_port", output.get("name", "output"))
    group_key = output.get("group_key", "default")
    ordinal = int(output.get("ordinal", 0))
    variant_key = output.get("variant_key", str(ordinal))
    if not all(isinstance(value, str) and value for value in (output_port, group_key, variant_key)):
        raise ValidationError(f"historical output identity is invalid for task {task_id}")
    return str(output_port), str(group_key), str(variant_key), ordinal


def _collect_historical_candidates(
    connection: sqlite3.Connection,
    root: Path,
    timeout_seconds: float,
    *,
    project_id: str | None = None,
    task_id: str | None = None,
    verify_cas: bool = True,
) -> tuple[list[dict], list[dict]]:
    """Collect only verifiable old render associations, with skip evidence."""
    params: list[object] = []
    where = ["t.status='completed'", "r.capability='rendering.render'"]
    if project_id:
        where.append("r.project_id=?")
        params.append(project_id)
    if task_id:
        where.append("t.id=?")
        params.append(task_id)
    spec_join = (
        "LEFT JOIN task_specs s ON s.digest=t.spec_digest "
        if "task_specs" in _tables(connection) else ""
    )
    spec_select = "s.body_json AS spec_json" if spec_join else "t.spec_json"
    tasks = connection.execute(
        f"SELECT t.*, {spec_select}, r.project_id, r.id AS run_id "
        f"FROM tasks t JOIN runs r ON r.id=t.run_id {spec_join} WHERE "
        + " AND ".join(where) + " ORDER BY t.id",
        params,
    ).fetchall()
    has_associations = "managed_output_associations" in _tables(connection)
    candidates: list[dict] = []
    skipped: list[dict] = []

    def skip(task, reason, **details):
        skipped.append({"task_id": str(task["id"]), "reason": reason, **details})

    for task in tasks:
        if not task["attempt_id"]:
            skip(task, "missing_settled_attempt")
            continue
        attempt = connection.execute("SELECT task_id FROM attempts WHERE id=?", (task["attempt_id"],)).fetchone()
        if not attempt or attempt["task_id"] != task["id"]:
            if task_id:
                raise ValidationError(f"historical output task {task['id']} has an unrelated attempt")
            skip(task, "attempt_task_mismatch")
            continue
        project = connection.execute(
            "SELECT id FROM projects WHERE id=?", (task["project_id"],)
        ).fetchone()
        if not project:
            skip(task, "project_missing")
            continue
        try:
            result = json.loads(task["result_json"] or "{}")
            spec = json.loads(task["spec_json"] or "{}")
        except json.JSONDecodeError:
            skip(task, "malformed_task_json")
            continue
        outputs = result.get("outputs") if isinstance(result, dict) else None
        if not isinstance(outputs, list):
            skip(task, "no_settled_outputs")
            continue
        for output in outputs:
            if not isinstance(output, dict) or output.get("kind") != "object":
                continue
            try:
                output_port, group_key, variant_key, ordinal = _historical_output_identity(task["id"], output)
            except (TypeError, ValueError, ValidationError):
                skip(task, "invalid_output_identity")
                continue
            if output_port != "video":
                continue
            identity = {
                "task_id": str(task["id"]), "output_port": output_port,
                "group_key": group_key, "generation_id": None,
                "variant_key": variant_key, "ordinal": ordinal,
            }
            association_id = "managed-output-" + hashlib.sha256(canonical_json(identity).encode()).hexdigest()
            if has_associations:
                existing = connection.execute(
                    "SELECT task_id, attempt_id, project_id FROM managed_output_associations WHERE association_id=?",
                    (association_id,),
                ).fetchone()
                if existing:
                    if (existing["task_id"], existing["attempt_id"], existing["project_id"]) != (task["id"], task["attempt_id"], task["project_id"]):
                        raise ConflictError(f"historical association conflicts: {association_id}")
                    skip(task, "association_already_materialized", association_id=association_id)
                    continue
            raw_digest = output.get("digest")
            digest = str(raw_digest).removeprefix("sha256:") if isinstance(raw_digest, str) else ""
            raw_size = output.get("size")
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                skip(task, "invalid_output_digest", ordinal=ordinal)
                continue
            if isinstance(raw_size, bool) or not isinstance(raw_size, int) or raw_size < 0:
                skip(task, "invalid_output_size", ordinal=ordinal)
                continue
            filename = _historical_filename(spec, output)
            media_type = _historical_video_media_type(output.get("media_type"), filename or "") if filename else None
            if filename is None or media_type is None:
                skip(task, "missing_verified_filename_or_media_type", ordinal=ordinal)
                continue
            object_row = connection.execute("SELECT size, media_type FROM objects WHERE digest=?", (digest,)).fetchone()
            if object_row and (int(object_row["size"]) != raw_size or object_row["media_type"] != media_type):
                skip(task, "object_metadata_conflict", ordinal=ordinal)
                continue
            project_object = connection.execute(
                "SELECT 1 FROM project_objects WHERE project_id=? AND digest=? AND relation='managed'",
                (task["project_id"], digest),
            ).fetchone()
            if verify_cas:
                try:
                    _verified_cas_object(root, digest, raw_size, time.monotonic() + timeout_seconds)
                except (OSError, ValidationError, TimeoutError):
                    skip(task, "cas_verification_failed", ordinal=ordinal)
                    continue
            candidates.append({
                "association_id": association_id, "task_id": str(task["id"]),
                "attempt_id": str(task["attempt_id"]), "project_id": str(task["project_id"]),
                "output_port": output_port, "group_key": group_key, "generation_id": None,
                "variant_key": variant_key, "object_digest": digest, "manifest_digest": None,
                "size": raw_size, "filename": filename, "media_type": media_type,
                "ordinal": ordinal, "role": output.get("role") or "output",
                "producer_json": canonical_json({"capability_id": task["capability"], "historical_migration": "runtime-managed-output-reconciliation/v1"}),
                "provenance_json": canonical_json({"task_id": str(task["id"]), "run_id": str(task["run_id"]), "attempt_id": str(task["attempt_id"]), "historical_migration": "runtime-managed-output-reconciliation/v1"}),
                "durability": output.get("durability", "durable"),
                "regeneration_json": None, "coverage_json": None,
                "created_at": task["updated_at"],
                "_object_missing": object_row is None,
                "_project_object_missing": project_object is None,
            })
    return candidates, skipped


def _insert_historical_candidates(connection: sqlite3.Connection, candidates: list[dict]) -> int:
    inserted = 0
    for item in candidates:
        if item.get("_object_missing"):
            existing = connection.execute(
                "SELECT size, media_type FROM objects WHERE digest=?", (item["object_digest"],)
            ).fetchone()
            if existing and (int(existing["size"]) != int(item["size"]) or existing["media_type"] != item["media_type"]):
                raise ConflictError(f"historical object metadata conflicts: {item['object_digest']}")
            if existing is None:
                connection.execute(
                    "INSERT INTO objects(digest, size, media_type, original_name, created_at) VALUES (?, ?, ?, ?, ?)",
                    (item["object_digest"], item["size"], item["media_type"], item["filename"], item["created_at"]),
                )
        if item.get("_project_object_missing"):
            connection.execute(
                "INSERT OR IGNORE INTO project_objects(project_id, digest, relation, created_at) VALUES (?, ?, 'managed', ?)",
                (item["project_id"], item["object_digest"], item["created_at"]),
            )
        columns = ", ".join(_HISTORICAL_ASSOCIATION_COLUMNS)
        placeholders = ", ".join("?" for _ in _HISTORICAL_ASSOCIATION_COLUMNS)
        connection.execute(
            f"INSERT INTO managed_output_associations ({columns}) VALUES ({placeholders})",
            tuple(item[column] for column in _HISTORICAL_ASSOCIATION_COLUMNS),
        )
        connection.execute(
            "INSERT INTO managed_output_lifecycle(association_id, state, version, expires_at, pinned_at, lease_id, lease_owner, lease_expires_at, updated_at, created_at) VALUES (?, ?, 1, NULL, NULL, NULL, NULL, NULL, ?, ?)",
            (item["association_id"], "available", item["created_at"], item["created_at"]),
        )
        inserted += 1
    return inserted


def migrate_historical_managed_outputs(
    root: str | Path,
    *,
    project_id: str | None = None,
    task_id: str | None = None,
    timeout_seconds: float = DEFAULT_UPGRADE_TIMEOUT_SECONDS,
    confirmation: str | None = None,
) -> dict:
    """Materialize verified historical associations for old settled video outputs.

    This is an explicit, stopped-runtime migration. It reads only task result
    JSON, the task's own output name, project ownership, and the Runtime CAS;
    it never guesses from filesystem names or creates a reader fallback.
    """
    root = _safe_realm_root(root)
    if not root.exists() or not root.is_dir() or root.is_symlink():
        raise RealmAdmissionError("realm root is missing or invalid")
    if not math.isfinite(float(timeout_seconds)) or timeout_seconds <= 0:
        raise ValidationError("timeout_seconds must be positive")
    with _owner_fence(root):
        db = root / "realm.sqlite3"
        _regular(db, "realm database")
        connection = sqlite3.connect(db)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            schema = connection.execute("SELECT format_id, version FROM runtime_schema WHERE id=1").fetchone()
            if not schema or schema[0] != CANONICAL_FORMAT_ID or int(schema[1]) != SCHEMA_VERSION:
                raise ValidationError(f"historical output migration requires canonical schema v{SCHEMA_VERSION}")
            realm_id = str(connection.execute("SELECT id FROM realm LIMIT 1").fetchone()[0])
            expected_confirmation = f"{HISTORICAL_OUTPUT_MIGRATION_CONFIRMATION} {realm_id}"
            if confirmation != expected_confirmation:
                raise ValidationError(f"migration requires confirmation exactly '{expected_confirmation}'")
            candidates, skipped = _collect_historical_candidates(
                connection, root, timeout_seconds, project_id=project_id, task_id=task_id
            )
            connection.execute("BEGIN")
            inserted = _insert_historical_candidates(connection, candidates)
            connection.commit()
            return {"ok": True, "realm_id": realm_id, "project_id": project_id, "task_id": task_id, "migrated": inserted, "skipped": skipped, "skipped_count": len(skipped)}
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def _generation_tag_object(value, *, reason: str) -> dict:
    """Reject ambiguous evidence rather than treating malformed JSON as empty."""
    try:
        parsed = json.loads(value) if isinstance(value, str) else value
    except (TypeError, ValueError) as exc:
        raise ValueError(reason) from exc
    if not isinstance(parsed, dict):
        raise ValueError(reason)
    return parsed


_GENERATION_TAG_FIELDS = frozenset({
    "kind", "origin", "generator", "model", "mode", "backend", "target", "machine",
    "workflow_digest", "task_id", "run_id", "seed", "cost_usd", "duration_ms", "tags",
})


def _generation_tag_inputs(roots, *, deadline):
    """Read only JSON below operator-selected roots; never follow links."""
    records, skipped = [], []
    for supplied in roots:
        root = Path(supplied)
        if not root.is_absolute() or root.is_symlink() or not root.exists():
            raise ValidationError("generation evidence roots must be existing absolute non-symlink paths")
        paths = []
        if root.is_file():
            paths.append(root)
        elif root.is_dir():
            for directory, directories, files in os.walk(root, followlinks=False):
                if time.monotonic() >= deadline:
                    raise TimeoutError("generation tag migration timed out")
                directories[:] = sorted(name for name in directories if not (Path(directory) / name).is_symlink())
                paths.extend(Path(directory) / name for name in sorted(files) if name.endswith(".json"))
        else:
            raise ValidationError("generation evidence root must be a JSON file or directory")
        for path in sorted(paths):
            if time.monotonic() >= deadline:
                raise TimeoutError("generation tag migration timed out")
            try:
                if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
                    raise ValueError("unsafe_or_oversized_evidence_file")
                value = json.loads(path.read_text(encoding="utf-8"))
                values = value.get("generations", [value]) if isinstance(value, dict) else value
                if not isinstance(values, list) or not all(isinstance(item, dict) for item in values):
                    raise ValueError("malformed_evidence_file")
                for index, item in enumerate(values):
                    locator = item.get("locator")
                    identity = locator if isinstance(locator, dict) else item
                    if not any(isinstance(identity.get(key), str) and identity[key]
                               for key in ("generation_id", "task_id", "kernel_task_id")):
                        skipped.append({"source": str(path), "row": index, "reason": "missing_generation_or_task_identity"})
                        continue
                    records.append((str(path), index, item))
            except (OSError, UnicodeError, ValueError) as exc:
                reason = str(exc) if isinstance(exc, ValueError) and not isinstance(exc, json.JSONDecodeError) else "malformed_evidence_file"
                skipped.append({"source": str(path), "reason": reason})
    return records, skipped


def _generation_tag_template_models(path):
    if path is None:
        return {}
    path = Path(path)
    if not path.is_absolute() or path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValidationError("template model map must be an explicit absolute regular JSON file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise ValidationError("template model map must contain a JSON object") from exc
    if not isinstance(value, dict) or not all(isinstance(key, str) and key and isinstance(item, str) and item
                                              for key, item in value.items()):
        raise ValidationError("template model map must map non-empty template ids to model strings")
    return value


def _generation_tag_evidence(connection, generation, *, version: int,
                             external=(), template_models=None, realm_id=None) -> dict:
    metadata = _generation_tag_object(generation["metadata_json"], reason="malformed_metadata")
    current = metadata.get("gen", {})
    if not isinstance(current, dict):
        raise ValueError("malformed_gen")
    evidence = dict(current)
    template_models = template_models or {}
    imported = isinstance(metadata.get("provenance"), dict) and metadata["provenance"].get("origin") == "imported"
    if imported:
        evidence.setdefault("origin", "imported")

    def merge(tags):
        for key, item in tags.items():
            if key not in _GENERATION_TAG_FIELDS or key in current or (key == "origin" and imported):
                continue
            if key == "tags":
                valid = isinstance(item, list) and all(isinstance(tag, str) and tag for tag in item)
            elif key in {"seed", "duration_ms"}:
                valid = isinstance(item, int) and not isinstance(item, bool) and (key == "seed" or item >= 0)
            elif key == "cost_usd":
                valid = isinstance(item, (int, float)) and not isinstance(item, bool) and math.isfinite(item) and item >= 0
            else:
                valid = isinstance(item, str) and bool(item)
            if not valid:
                raise ValueError("malformed_generation_field:" + key)
            if key in evidence and evidence[key] != item:
                raise ValueError("conflicting_evidence")
            evidence[key] = item

    def merge_legacy(value):
        """Use named historical fields, never filenames or model-name guesses."""
        value = _generation_tag_object(value, reason="malformed_source_metadata")
        tags = {key: value[key] for key in _GENERATION_TAG_FIELDS if key in value and value[key] is not None and key != "kind"}
        for source, target in (("modality", "kind"), ("content_type", "kind"),
                               ("mode_used", "mode"), ("execution", "backend")):
            if source in value and value[source] is not None:
                if target == "kind" and value[source] not in ("image", "video", "audio"):
                    continue
                tags.setdefault(target, value[source])
        if isinstance(value.get("kind"), str) and value["kind"] in {"image", "video", "audio"}:
            tags.setdefault("kind", value["kind"])
        template = value.get("template_id", value.get("template"))
        if isinstance(template, str) and template in template_models:
            tags.setdefault("model", template_models[template])
        merge(tags)
        h3 = value.get("h3_av")
        if h3 is not None:
            h3 = _generation_tag_object(h3, reason="malformed_h3_av")
            merge({"generator": "h3_av.transform"})
            merge_legacy({key: item for key, item in h3.items() if key != "h3_av"})
            graph = h3.get("graph")
            if isinstance(graph, dict):
                profile = graph.get("profile")
                if isinstance(profile, str) and profile in template_models:
                    merge({"model": template_models[profile]})
                workflow = graph.get("workflow")
                if isinstance(workflow, dict) and isinstance(workflow.get("sha256"), str):
                    merge({"workflow_digest": "sha256:" + workflow["sha256"].removeprefix("sha256:")})

    def merge_metadata(value):
        value = _generation_tag_object(value, reason="malformed_source_metadata")
        tags = value.get("gen", {})
        if not isinstance(tags, dict):
            raise ValueError("malformed_source_gen")
        merge(tags)
        merge_legacy(value)
        params = value.get("params")
        if isinstance(params, dict):
            merge_legacy(params)

    def merge_spec(value):
        spec = _generation_tag_object(value, reason="malformed_source_spec")
        intent = spec.get("__runtime_generation_intent", spec.get("generation_intent"))
        if intent is not None:
            if not isinstance(intent, dict):
                raise ValueError("malformed_generation_intent")
            merge_metadata(intent.get("metadata", {}))
            if isinstance(intent.get("modality"), str) and intent["modality"] in {"image", "video", "audio"}:
                merge({"kind": intent["modality"]})
        inputs = spec.get("inputs")
        if isinstance(inputs, dict):
            merge_legacy(inputs)
            if isinstance(inputs.get("generation_intent"), dict):
                merge_spec({"generation_intent": inputs["generation_intent"]})

    def stored_spec(row):
        if version < SPEC_DEDUP_TARGET_SCHEMA_VERSION:
            return row["spec_json"]
        if row["spec_digest"] is None:
            return None
        spec = connection.execute(
            "SELECT body_json FROM task_specs WHERE digest=?", (row["spec_digest"],)
        ).fetchone()
        if spec is None:
            raise ValueError("missing_source_spec")
        return spec[0]

    merge_metadata(metadata)
    if generation["type"] in {"image", "video", "audio"}:
        merge({"kind": generation["type"]})
    task = None
    if generation["source_task_id"]:
        task = connection.execute("SELECT * FROM tasks WHERE id=?", (generation["source_task_id"],)).fetchone()
        if task is None:
            raise ValueError("missing_source_task")
        run = connection.execute("SELECT * FROM runs WHERE id=?", (task["run_id"],)).fetchone()
        if run is None or run["project_id"] != generation["project_id"]:
            raise ValueError("source_project_mismatch")
        effect = task["expected_effect_json"]
        if effect is not None:
            effect = _generation_tag_object(effect, reason="malformed_source_effect")
            if effect.get("effect_type") in {"generation.publish_v1", "generation.create_with_variant"}:
                payload = _generation_tag_object(effect.get("payload", {}), reason="malformed_source_effect")
                merge_metadata(payload.get("metadata", {}))
        for row in (task, run):
            spec = stored_spec(row)
            if spec is not None:
                merge_spec(spec)
        if version >= EXECUTION_BINDING_TARGET_SCHEMA_VERSION:
            binding = connection.execute("SELECT target_kind, target_id FROM execution_bindings WHERE task_id=?", (task["id"],)).fetchone()
            if binding:
                merge({"target": binding["target_kind"]})
                if binding["target_kind"] == "machine" and binding["target_id"]:
                    merge({"machine": binding["target_id"]})
    for source, index, value in external:
        identity = value.get("locator") if isinstance(value.get("locator"), dict) else value
        generation_id = identity.get("generation_id")
        task_id = identity.get("task_id", identity.get("kernel_task_id"))
        if generation_id != generation["id"] and (not task_id or task_id != generation["source_task_id"]):
            continue
        if ((generation_id is not None and generation_id != generation["id"])
                or (task_id is not None and task_id != generation["source_task_id"])
                or (identity.get("run_id") is not None and task is not None and identity["run_id"] != task["run_id"])
                or (value.get("project_id") is not None and value["project_id"] != generation["project_id"])
                or (value.get("realm_id") is not None and value["realm_id"] != realm_id)):
            raise ValueError("external_source_identity_mismatch")
        merge_metadata(value)
        admission = value.get("admission")
        if isinstance(admission, dict):
            if admission.get("project_id") not in {None, generation["project_id"]}:
                raise ValueError("external_source_identity_mismatch")
            merge_spec(admission)
            merge_spec(admission.get("spec", {}))
            effect = admission.get("settlement_effect", admission.get("expected_effect"))
            if isinstance(effect, dict) and isinstance(effect.get("payload"), dict):
                merge_metadata(effect["payload"].get("metadata", {}))
        if "metadata" in value:
            merge_metadata(value["metadata"])
    provenance = metadata.get("provenance")
    if isinstance(provenance, dict) and provenance.get("origin") == "imported":
        evidence.setdefault("origin", "imported")
        params = metadata.get("params")
        if isinstance(params, dict) and isinstance(params.get("content_type"), str) and params["content_type"] in {"image", "video", "audio"}:
            evidence.setdefault("kind", params["content_type"])
    semantic_fields = {"kind", "origin", "generator", "model", "mode", "backend", "target", "machine",
                       "workflow_digest", "seed", "cost_usd", "duration_ms", "tags"}
    if not any(key in evidence and evidence[key] not in (None, "", [], {}) for key in semantic_fields):
        raise ValueError("insufficient_evidence")
    if task is not None:
        evidence.setdefault("task_id", task["id"])
        evidence.setdefault("run_id", task["run_id"])
    updated = dict(metadata)
    updated["gen"] = evidence
    return updated


def migrate_generation_tags(
    root: str | Path,
    *,
    project_id: str | None = None,
    dry_run: bool = True,
    manifest_roots=(),
    receipt_roots=(),
    template_model_map: str | Path | None = None,
    timeout_seconds: float = DEFAULT_UPGRADE_TIMEOUT_SECONDS,
    confirmation: str | None = None,
) -> dict:
    """Backfill explicit Runtime generation evidence while the owner is stopped.

    Runtime SQL and explicitly supplied JSON evidence are the only inputs.
    The idempotency ledger and CAS contents are never read or changed. Dry-run
    is the default and works on old canonical schemas without upgrading them.
    """
    root = _safe_realm_root(root)
    if not math.isfinite(float(timeout_seconds)) or timeout_seconds <= 0:
        raise ValidationError("timeout_seconds must be positive")
    started = time.monotonic()
    deadline = started + float(timeout_seconds)
    template_models = _generation_tag_template_models(template_model_map)
    external, source_skipped = _generation_tag_inputs((*manifest_roots, *receipt_roots), deadline=deadline)
    external_by_generation, external_by_task = {}, {}
    for record in external:
        identity = record[2].get("locator") if isinstance(record[2].get("locator"), dict) else record[2]
        if isinstance(identity.get("generation_id"), str):
            external_by_generation.setdefault(identity["generation_id"], []).append(record)
        task_id = identity.get("task_id", identity.get("kernel_task_id"))
        if isinstance(task_id, str):
            external_by_task.setdefault(task_id, []).append(record)
    identity = inspect_canonical_schema(root)
    realm_id = str(identity["realm_id"])
    version = int(identity["version"])
    expected_confirmation = f"{GENERATION_TAG_MIGRATION_CONFIRMATION} {realm_id}"
    if not dry_run and confirmation != expected_confirmation:
        raise ValidationError(f"migration requires confirmation exactly '{expected_confirmation}'")
    with _owner_fence(root):
        connection = (_open_readonly(root / "realm.sqlite3") if dry_run else
                      sqlite3.connect(root / "realm.sqlite3", timeout=float(timeout_seconds)))
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN" if dry_run else "BEGIN IMMEDIATE")
            current = _canonical_schema_identity(connection, expected_realm_id=realm_id)
            if int(current["version"]) != version:
                raise ConflictError("realm schema changed before generation tag migration")
            skipped = []
            candidates = []
            query = "SELECT * FROM generations"
            args = ()
            if project_id is not None:
                query += " WHERE project_id=?"
                args = (project_id,)
            query += " ORDER BY id"
            with _sqlite_deadline(connection, deadline):
                for generation in connection.execute(query, args):
                    if time.monotonic() >= deadline:
                        raise TimeoutError("generation tag migration timed out")
                    try:
                        selected = external_by_generation.get(generation["id"], []) + external_by_task.get(generation["source_task_id"], [])
                        kwargs = {"external": selected, "template_models": template_models, "realm_id": realm_id} if selected or template_models else {}
                        metadata = _generation_tag_evidence(connection, generation, version=version, **kwargs)
                    except ValueError as exc:
                        skipped.append({"generation_id": generation["id"], "reason": str(exc)})
                        continue
                    before = json.loads(generation["metadata_json"])
                    if metadata == before:
                        skipped.append({"generation_id": generation["id"], "reason": "already_current"})
                        continue
                    candidates.append({"generation_id": generation["id"],
                                       "fields": sorted(set(metadata["gen"]) - set(before.get("gen", {}))),
                                       "gen": metadata["gen"]})
                    if not dry_run:
                        connection.execute(
                            "UPDATE generations SET metadata_json=?, version=version+1, updated_at=? WHERE id=?",
                            (canonical_json(metadata), now(), generation["id"]),
                        )
            if dry_run:
                connection.rollback()
            else:
                connection.commit()
            return {"ok": True, "realm_id": realm_id, "project_id": project_id,
                    "schema_version": version, "dry_run": dry_run, "skip_ledger": True,
                    "candidate_count": len(candidates), "candidates": candidates,
                    "migrated": 0 if dry_run else len(candidates),
                    "skipped_count": len(skipped), "skipped": skipped,
                    "source_skipped": source_skipped, "source_skipped_count": len(source_skipped),
                    "elapsed_seconds": time.monotonic() - started}
        except sqlite3.OperationalError as exc:
            connection.rollback()
            if time.monotonic() >= deadline:
                raise TimeoutError("generation tag migration timed out") from exc
            raise
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
