"""History guard layer 1, separately versioned from pinned canonical U33.

Only the exact three triggers below belong to this layer. Absence is a
supported historical/backup shape; partial or changed definitions are not.
Installation/removal is schema-only under a caller-owned transaction and
never rewrites accepted history. A previous Runtime may need an unguarded
backup or explicit stopped-realm rollback preparation before it can open.
"""
from __future__ import annotations

import hashlib
import json

from .errors import ValidationError

HISTORY_GUARD_LAYER_VERSION = 1
HISTORY_GUARD_RECOVERY = (
    "History guard layer 1 is incomplete or altered. Stop Runtime and restore "
    "from a verified backup; do not repair individual triggers or start the previous Runtime."
)


class HistoryGuardManifestError(ValidationError):
    """The additive history guard layer is neither absent nor exact."""


# Guard the two declared unique keys AND SQLite's implicit rowid. REPLACE
# bypasses DELETE triggers on connections with recursive_triggers=OFF; the
# BEFORE INSERT guard refuses its collisions independently of that setting.
# Normal publication appends use three indexed probes, not a history scan.
TIMELINE_HISTORY_TRIGGER_SQL = {
    "timeline_history_no_update": """
CREATE TRIGGER timeline_history_no_update BEFORE UPDATE ON timeline_commit_history
BEGIN
    SELECT RAISE(ABORT, 'accepted timeline history is immutable');
END
""".strip(),
    "timeline_history_no_delete": """
CREATE TRIGGER timeline_history_no_delete BEFORE DELETE ON timeline_commit_history
BEGIN
    SELECT RAISE(ABORT, 'accepted timeline history is immutable');
END
""".strip(),
    "timeline_history_no_replace": """
CREATE TRIGGER timeline_history_no_replace BEFORE INSERT ON timeline_commit_history
WHEN EXISTS (SELECT 1 FROM timeline_commit_history WHERE publication_id=NEW.publication_id)
  OR EXISTS (SELECT 1 FROM timeline_commit_history
             WHERE project_id=NEW.project_id AND timeline_id=NEW.timeline_id AND project_seq=NEW.project_seq)
  OR EXISTS (SELECT 1 FROM timeline_commit_history WHERE rowid=NEW.rowid)
BEGIN
    SELECT RAISE(ABORT, 'accepted timeline history is immutable');
END
""".strip(),
}

def history_guard_manifest(connection):
    """Classify the exact persistent layer; no history data is read."""
    from .v33_manifest import _tokens

    names = tuple(TIMELINE_HISTORY_TRIGGER_SQL)
    rows = connection.execute(
        "SELECT type, name, tbl_name, sql FROM main.sqlite_master "
        "WHERE name IN (?, ?, ?) OR (type='trigger' AND tbl_name='timeline_commit_history') "
        "ORDER BY name", names,
    ).fetchall()
    if not rows:
        return {"version": 0, "state": "absent", "fingerprint": None}
    actual = {}
    for kind, name, owner, sql in rows:
        expected = TIMELINE_HISTORY_TRIGGER_SQL.get(name)
        if (kind != "trigger" or owner != "timeline_commit_history" or expected is None
                or not isinstance(sql, str) or _tokens(sql) != _tokens(expected)):
            raise HistoryGuardManifestError("history guard layer 1 contains an altered or unexpected object: " + name)
        actual[name] = _tokens(sql)
    if set(actual) != set(names):
        raise HistoryGuardManifestError("history guard layer 1 is incomplete; missing: " + ", ".join(sorted(set(names) - set(actual))))
    fingerprint = hashlib.sha256(json.dumps(
        {"version": HISTORY_GUARD_LAYER_VERSION, "triggers": actual},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()
    return {"version": HISTORY_GUARD_LAYER_VERSION, "state": "installed", "fingerprint": fingerprint}


def _require_u33(connection):
    from .v33_manifest import canonical_manifest

    if not connection.in_transaction:
        raise ValidationError("history guard layer changes require a caller-owned transaction")
    identity = canonical_manifest(connection)
    if identity["kind"] != "U33":
        raise ValidationError("history guard layer 1 requires exact canonical U33")
    return identity


def install_history_guards(connection):
    """Install layer 1 only on exact U33, idempotently, before owner admission."""
    from .v33_manifest import canonical_manifest

    before = _require_u33(connection)
    if history_guard_manifest(connection)["version"] == HISTORY_GUARD_LAYER_VERSION:
        return False
    for statement in TIMELINE_HISTORY_TRIGGER_SQL.values():
        connection.execute(statement)
    if (canonical_manifest(connection) != before
            or history_guard_manifest(connection)["version"] != HISTORY_GUARD_LAYER_VERSION):
        raise HistoryGuardManifestError("history guard layer 1 installation did not verify")
    return True


def remove_history_guards(connection):
    """Remove only a verified layer 1 from exact U33, inside one transaction.

    Used on a private, not-yet-authenticated backup image for previous Runtime
    compatibility. No signed or live backup is rewritten.
    """
    from .v33_manifest import canonical_manifest

    before = _require_u33(connection)
    if history_guard_manifest(connection)["version"] == 0:
        return False
    for name in TIMELINE_HISTORY_TRIGGER_SQL:
        connection.execute(f"DROP TRIGGER main.{name}")
    if canonical_manifest(connection) != before or history_guard_manifest(connection)["version"] != 0:
        raise HistoryGuardManifestError("history guard layer 1 removal did not verify")
    return True


def prepare_history_guard_rollback(root, *, confirmation):
    """Prepare a stopped realm/clone for a guard-unaware previous Runtime.

    Only an exact U33 image with absent or exact layer 1 is eligible. The
    existing admission and lifetime fences prevent removing live protection.
    Incomplete v33 activation must use its existing recovery route first.
    """
    import sqlite3
    from .errors import ConflictError
    from .sqlite_uri import sqlite_file_uri
    from .upgrade import _owner_fence, _safe_realm_root, inspect_canonical_schema
    from .v33_lifecycle import activation
    from .v33_manifest import canonical_manifest

    root = _safe_realm_root(root)
    identity = inspect_canonical_schema(root)
    if identity["kind"] != "U33":
        raise ValidationError("history guard rollback requires exact canonical U33")
    if confirmation != f"REMOVE HISTORY GUARDS {identity['realm_id']}":
        raise ValidationError("history guard rollback requires confirmation for the exact realm id")
    with _owner_fence(root):
        pending = activation(root)
        if pending is not None and pending[1]["state"] != "ready":
            raise ConflictError("complete or restore the existing v33 activation before history guard rollback")
        db = root / "realm.sqlite3"
        source = db.lstat()
        if (source.st_dev, source.st_ino) != tuple(identity["source_file_identity"][:2]):
            raise ConflictError("realm database changed before history guard rollback")
        connection = sqlite3.connect(sqlite_file_uri(db, mode="rw"), uri=True, isolation_level=None)
        try:
            connection.execute("BEGIN IMMEDIATE")
            live = canonical_manifest(connection, expected_realm_id=identity["realm_id"])
            if any(live[key] != identity[key] for key in ("version", "kind", "fingerprint", "realm_id")):
                raise ConflictError("realm schema changed before history guard rollback")
            changed = remove_history_guards(connection)
            if changed:
                connection.commit()
            else:
                connection.rollback()
            return {"ok": True, "changed": changed, "realm_id": live["realm_id"],
                    "schema_version": live["version"], "fingerprint": live["fingerprint"],
                    "history_guard_layer": 0}
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
