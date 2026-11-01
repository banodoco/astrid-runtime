"""Durable offline v33 recovery and SQL-only backfill coordination.

No schema tables are added. Recovery images are immutable inactive inputs; the
small realm marker fences startup until the journal proves backfill completion.
Only explicit offline recovery may restore an image, before request admission.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import uuid
from contextlib import contextmanager

from . import platform
from .errors import ConflictError, ValidationError
from .util import canonical_json, now

MARKER = ".v33-activation.json"


def digest(value):
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def write_record(path, value):
    from astrid_runtime.io import atomic_write_json
    body = {k: v for k, v in value.items() if k != "record_digest"}
    atomic_write_json(Path(path), {**body, "record_digest": digest(body)})


def read_record(path):
    try:
        if Path(path).is_symlink():
            raise ValueError("symbolic recovery record")
        value = json.loads(Path(path).read_text())
        body = {k: v for k, v in value.items() if k != "record_digest"}
        if value.get("record_digest") != digest(body):
            raise ValueError("digest mismatch")
        return body
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        raise ConflictError(f"v33 recovery evidence is unreadable or corrupt: {path}") from exc


def _files(root, *, exclude=()):
    root = Path(root)
    for directory, folders, files in os.walk(root, followlinks=False):
        base = Path(directory)
        def included(name):
            relative = (base / name).relative_to(root).as_posix()
            return not any(relative == e or relative.startswith(e + "/") for e in exclude)
        folders[:] = sorted(name for name in folders if included(name))
        for name in sorted(folders + [n for n in files if included(n)]):
            path = base / name
            if path.is_symlink():
                raise ValidationError(f"recovery scope contains a symlink: {path}")
            if path.is_file():
                yield path
            elif not path.is_dir():
                raise ValidationError(f"recovery scope contains a special file: {path}")


def _file_fact(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return {"size": path.stat().st_size, "sha256": h.hexdigest()}


def snapshot_tree(source, destination, *, exclude=()):
    source, destination = Path(source), Path(destination)
    platform.private_directory(destination)
    inventory = {}
    for directory, folders, files in os.walk(source, followlinks=False):
        relative = Path(directory).relative_to(source).as_posix()
        folders[:] = [name for name in folders if not any((Path(directory) / name).relative_to(source).as_posix() == e or (Path(directory) / name).relative_to(source).as_posix().startswith(e + "/") for e in exclude)]
        if relative != ".":
            platform.private_directory(destination / relative)
    for path in _files(source, exclude=exclude):
        name = path.relative_to(source).as_posix()
        if any(name == e or name.startswith(e + "/") for e in exclude):
            continue
        target = destination / name
        platform.private_directory(target.parent)
        shutil.copy2(path, target)
        platform.owner_only(target)
        with target.open("r+b") as handle:
            os.fsync(handle.fileno())
        inventory[name] = _file_fact(target)
        if inventory[name] != _file_fact(path):
            raise ConflictError("recovery source changed while snapshotting")
    for directory in sorted((p for p in destination.rglob("*") if p.is_dir()), reverse=True):
        platform.fsync_directory(directory)
    platform.fsync_directory(destination)
    return inventory


def verify_tree(root, inventory):
    found = {p.relative_to(root).as_posix(): _file_fact(p) for p in _files(root)}
    if found != inventory:
        raise ConflictError("recovery image inventory/hash mismatch")


def verify_sqlite_image(image, *, realm_id, fingerprint):
    """Open only a disposable WAL-aware copy, preserving the archived bytes."""
    from .v33_manifest import canonical_manifest, legacy_manifest
    with tempfile.TemporaryDirectory(prefix="verify-v33-") as temporary:
        copy = Path(temporary)
        for suffix in ("", "-wal", "-shm", "-journal"):
            source = Path(image) / ("realm.sqlite3" + suffix)
            if source.exists():
                shutil.copy2(source, copy / source.name)
        connection = sqlite3.connect(copy / "realm.sqlite3")
        try:
            connection.row_factory = sqlite3.Row
            tables = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            manifest = (canonical_manifest if "runtime_schema" in tables else legacy_manifest)(connection, expected_realm_id=realm_id)
            if manifest["fingerprint"] != fingerprint:
                raise ConflictError("recovery source schema/realm binding mismatch")
            if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok" or connection.execute("PRAGMA foreign_key_check").fetchone():
                raise ConflictError("recovery database failed integrity checks")
            if "objects" in tables:
                for row in connection.execute("SELECT digest, size FROM objects"):
                    path = Path(image) / "cas" / "sha256" / row[0][:2] / row[0][2:]
                    if not path.is_file() or _file_fact(path) != {"size": row[1], "sha256": row[0]}:
                        raise ConflictError("recovery image has missing or corrupt CAS")
        finally:
            connection.close()


@contextmanager
def sqlite_observation(root):
    """Retain original DB/WAL/SHM bytes before acquiring SQLite's writer lock.

    Ownership already excludes cooperative writers. Recheck both copies to
    detect an uncooperative writer; the observation itself is not a backup.
    """
    with tempfile.TemporaryDirectory(prefix="v33-observation-") as temporary:
        copy = Path(temporary)
        def source_identity():
            result = {}
            for suffix in ("", "-wal", "-shm", "-journal"):
                path = Path(root) / ("realm.sqlite3" + suffix)
                if path.is_symlink():
                    raise ValidationError("SQLite recovery component must be a regular file")
                if path.exists():
                    st = path.stat()
                    result[path.name] = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
            return result
        observed_identity = source_identity()
        for suffix in ("", "-wal", "-shm", "-journal"):
            source = Path(root) / ("realm.sqlite3" + suffix)
            if source.exists():
                shutil.copy2(source, copy / source.name)
                if _file_fact(source) != _file_fact(copy / source.name):
                    raise ConflictError("SQLite changed during offline observation")
        if observed_identity != source_identity():
            raise ConflictError("SQLite files changed during detached observation")
        yield copy


def check_root_binding(root, identity):
    from .catalog import _safe_path
    root = _safe_path(root, "recovery realm root")
    current = root.stat()
    if [current.st_dev, current.st_ino] != identity:
        raise ConflictError("realm directory identity changed; recovery is required")


def begin(root, identity, *, recovery_root=None, sqlite_image=None):
    root = Path(root)
    if (root / MARKER).exists() and activation(root)[1]["state"] != "ready":
        raise ConflictError("v33 activation already exists; use explicit recovery")
    check_root_binding(root, identity["source_root_identity"])
    operation_id = uuid.uuid4().hex
    archive = Path(recovery_root) if recovery_root else root.parent / ".v33-recovery" / operation_id
    if archive == root or root in archive.parents:
        raise ValidationError("recovery set must be outside the realm")
    platform.private_directory(archive)
    if archive.stat().st_dev != root.stat().st_dev:
        raise ValidationError("recovery directory must be on the realm filesystem")
    inventory = snapshot_tree(root, archive / "realm", exclude=("owner.lock",))
    if sqlite_image is not None:
        for name in list(inventory):
            if name in {"realm.sqlite3" + suffix for suffix in ("", "-wal", "-shm", "-journal")}:
                (archive / "realm" / name).unlink()
                del inventory[name]
        for original in Path(sqlite_image).iterdir():
            target = archive / "realm" / original.name
            shutil.copy2(original, target)
            with target.open("r+b") as handle:
                os.fsync(handle.fileno())
            inventory[original.name] = _file_fact(target)
        platform.fsync_directory(archive / "realm")
    verify_tree(archive / "realm", inventory)
    verify_sqlite_image(archive / "realm", realm_id=identity["realm_id"], fingerprint=identity["fingerprint"])
    check_root_binding(root, identity["source_root_identity"])
    record = {"format": "astrid-v33-activation/v1", "operation_id": operation_id,
              "backup_id": operation_id, "realm_id": identity["realm_id"], "realm_root": str(root),
              "source": identity, "root_identity": identity["source_root_identity"], "inventory": inventory, "state": "backup_verified", "created_at": now(),
              "retention": "at least 30 days after activation AND operator acknowledgement after a verified replacement backup; indefinite while recovery is unresolved",
              "scope": "realm DB/sidecars, all CAS and realm files; offline input, no disconnected App state"}
    write_record(archive / "activation.json", record)
    write_record(root / MARKER, {"archive": str(archive), "operation_id": operation_id, "realm_id": identity["realm_id"], "state": "backup_verified"})
    return archive, record


def activation(root):
    marker = Path(root) / MARKER
    if not marker.exists():
        return None
    binding = read_record(marker)
    archive = Path(binding["archive"])
    record = read_record(archive / "activation.json")
    if (record["operation_id"] != binding["operation_id"] or record["realm_id"] != binding["realm_id"]
            or record["realm_root"] != str(Path(root))):
        raise ConflictError("v33 activation binding mismatch")
    check_root_binding(root, record["root_identity"])
    return archive, record


def phase(archive, record, state, **facts):
    check_root_binding(Path(record["realm_root"]), record["root_identity"])
    record.update(state=state, **facts)
    write_record(Path(archive) / "activation.json", record)
    marker = Path(record["realm_root"]) / MARKER
    if marker.exists():
        binding = read_record(marker)
        if binding.get("operation_id") == record["operation_id"] and binding.get("archive") == str(archive):
            write_record(marker, {**binding, "state": state})


def complete_backfill(root, connection, archive, record):
    from .v33_backfill_plan import freeze_generation_plan, reconcile_generation_plan
    from .v33_manifest import canonical_manifest
    current = canonical_manifest(connection, expected_realm_id=record["realm_id"])
    if current["kind"] != "U33":
        raise ConflictError("backfill requires the verified U33 schema")
    plan_path = Path(archive) / "backfill-plan.json"
    if plan_path.exists():
        plan = read_record(plan_path)
    else:
        connection.execute("BEGIN IMMEDIATE")
        try:
            plan = freeze_generation_plan(connection, realm_id=record["realm_id"], backup_id=record["backup_id"],
                                          schema_fingerprint=current["fingerprint"], applied_at=now())
            write_record(plan_path, plan)
        finally:
            connection.rollback()
    if (plan["realm_id"] != record["realm_id"] or plan["backup_id"] != record["backup_id"]
            or plan["schema_fingerprint"] != current["fingerprint"]):
        raise ConflictError("backfill plan is not bound to this recovery set")
    phase(archive, record, "plan_persisted", plan_digest=plan["digest"])
    result = reconcile_generation_plan(connection, plan)
    # Faults here deliberately leave the frozen plan and committed post-state.
    phase(archive, record, "backfill_committed")
    completion = {**result, "realm_id": record["realm_id"], "schema_fingerprint": current["fingerprint"],
                  "inventory": [{"id": e["before"]["id"], "reason": e["reason"]} for e in plan["entries"]]}
    write_record(Path(archive) / "backfill-complete.json", completion)
    phase(archive, record, "backfill_complete")
    return completion


def check_startup(root):
    state = activation(root)
    if state is None:
        return
    archive, record = state
    if record["state"] not in {"backfill_complete", "provider_verified", "ready"}:
        raise ConflictError("v33 activation incomplete; run offline upgrade recovery before startup")
    if record.get("operator_owned") and record["state"] != "ready" and os.environ.get("ASTRID_V33_ACTIVATION") != record["operation_id"]:
        raise ConflictError("v33 activation is exclusively owned by the upgrade coordinator")
    completion = read_record(archive / "backfill-complete.json")
    if completion["plan_digest"] != record.get("plan_digest") or completion["backup_id"] != record["backup_id"]:
        raise ConflictError("v33 completion does not match activation")
    # Once ready, normal authorized writes may legitimately change old witnesses.
    if record["state"] != "ready":
        from .v33_backfill_plan import reconcile_generation_plan
        connection = sqlite3.connect(Path(root) / "realm.sqlite3")
        connection.row_factory = sqlite3.Row
        try:
            if reconcile_generation_plan(connection, read_record(archive / "backfill-plan.json"), verify_only=True)["state"] != "already_applied":
                raise ConflictError("backfill completion does not match database")
        finally:
            connection.close()


def require_ready(root):
    marker = Path(root) / MARKER
    if marker.exists() and read_record(marker).get("state") != "ready":
        raise ConflictError("v33 provider/baseline verification is pending; requests and fresh pins are fenced")


def provider_ready(root, inventory):
    state = activation(root)
    if state:
        archive, record = state
        check_startup(root)
        phase(archive, record, "provider_verified" if record.get("operator_owned") and record["state"] != "ready" else "ready",
              baseline_inventory=inventory, ready_at=record.get("ready_at", now()))


def restore(root, archive):
    """Restore a matching full realm image, retaining failed state for diagnosis.

    Caller owns admission and lifetime locks and has positively stopped the
    candidate. This operation is restricted to the pre-readiness window.
    """
    root, archive = Path(root), Path(archive)
    record = read_record(archive / "activation.json")
    if record.get("format") == "astrid-v34-activation/v1":
        raise ConflictError("v34 rollback is refused; resume custody activation and preserve admitted writes")
    if record["realm_root"] != str(root) or record["state"] == "ready" or record.get("prior_launch_started"):
        raise ConflictError("automatic restore is confined to the fenced pre-admission window")
    check_root_binding(root, record["root_identity"])
    verify_tree(archive / "realm", record["inventory"])
    verify_sqlite_image(archive / "realm", realm_id=record["realm_id"], fingerprint=record["source"]["fingerprint"])
    phase(archive, record, "restoring")
    failed = archive / ("failed-" + uuid.uuid4().hex)
    snapshot_tree(root, failed, exclude=("owner.lock",))
    # Keep owner.lock's inode and the realm directory fence throughout restore.
    for path in list(root.iterdir()):
        if path.name in {"owner.lock", MARKER}:
            continue
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
    snapshot_tree(archive / "realm", root, exclude=(MARKER,))
    verify_sqlite_image(root, realm_id=record["realm_id"], fingerprint=record["source"]["fingerprint"])
    phase(archive, record, "restored", restored_at=now(), failed_image=str(failed))
    finish_restore_marker(root, archive, record)
    return record


def finish_restore_marker(root, archive, record):
    """Finish a lost restore acknowledgement after full-image verification."""
    root, archive = Path(root), Path(archive)
    if record["state"] != "restored":
        raise ConflictError("restore marker cannot be released before verified restoration")
    if MARKER in record["inventory"]:
        write_record(root / MARKER, read_record(archive / "realm" / MARKER))
    else:
        (root / MARKER).unlink(missing_ok=True)
        platform.fsync_directory(root)


def inspect_recovery_set(archive, *, destination=None):
    """Verify and export the retained original, including archival-only rows."""
    archive = Path(archive).expanduser().resolve()
    record = read_record(archive / "activation.json")
    verify_tree(archive / "realm", record["inventory"])
    verify_sqlite_image(archive / "realm", realm_id=record["realm_id"], fingerprint=record["source"]["fingerprint"])
    tables = {}
    with sqlite_observation(archive / "realm") as copy:
        connection = sqlite3.connect(copy / "realm.sqlite3")
        try:
            from .upgrade import _row_digest, _table_columns
            names = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
            for name in names:
                count, checksum = _row_digest(connection, name, _table_columns(connection, name))
                tables[name] = {"rows": count, "sha256": checksum}
        finally:
            connection.close()
    result = {"format": "astrid-recovery-inspection/v1", "backup_id": record["backup_id"],
              "realm_id": record["realm_id"], "source": record["source"], "state": record["state"],
              "tables": tables, "inventory": record["inventory"], "retention": record["retention"], "verified": True}
    if destination is not None:
        destination = Path(destination).expanduser().resolve()
        if destination.exists() or destination == archive or archive in destination.parents or destination in archive.parents:
            raise ValidationError("recovery export requires a new directory outside the archive")
        snapshot_tree(archive / "realm", destination / "realm")
        write_record(destination / "inventory.json", result)
    return result


def restore_observation(root, observed):
    """Undo SQLite's own bookkeeping when backup fails before any DDL/data.

    Compare the complete logical images first, so a changed source is never
    overwritten. Prepare and fsync every replacement before removing sidecars;
    a failed replacement retains its prepared set for explicit recovery.
    """
    from .upgrade import _row_digest, _table_columns, _tables
    def facts(image):
        with sqlite_observation(image) as copy:
            connection = sqlite3.connect(copy / "realm.sqlite3")
            try:
                schema = list(connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"))
                rows = {name: _row_digest(connection, name, _table_columns(connection, name)) for name in sorted(_tables(connection))}
                return schema, rows
            finally:
                connection.close()
    root, observed = Path(root), Path(observed)
    if facts(root) != facts(observed):
        raise ConflictError("source changed before backup completed; preserve current data and retry offline")
    prepared = root.parent / (".v33-observation-restore-" + uuid.uuid4().hex)
    platform.private_directory(prepared)
    for source in observed.iterdir():
        target = prepared / source.name
        shutil.copy2(source, target)
        with target.open("r+b") as handle:
            os.fsync(handle.fileno())
    platform.fsync_directory(prepared)
    try:
        # Publish retained WAL before the matching main image, without an
        # unlink gap for a WAL carrying the only committed copy of a row.
        for suffix in ("-wal", "-journal", "-shm", ""):
            source = prepared / ("realm.sqlite3" + suffix)
            if source.exists():
                platform.durable_replace(source, root / source.name)
            elif suffix:
                (root / source.name).unlink(missing_ok=True)
        platform.fsync_directory(root)
    except Exception as exc:
        raise ConflictError(f"pre-mutation SQLite bookkeeping restoration is uncertain; prepared image retained at {prepared}") from exc
    shutil.rmtree(prepared)


def rebind_after_relocation(root, previous_root):
    """Carry a completed activation across an authorized support-root move."""
    root, previous_root = Path(root), Path(previous_root)
    if not (root / MARKER).exists():
        return
    binding = read_record(root / MARKER)
    archive = Path(binding["archive"])
    record = read_record(archive / "activation.json")
    if record["realm_root"] == str(root):
        return
    if (record["realm_root"] != str(previous_root) or record["state"] != "ready"
            or binding["operation_id"] != record["operation_id"]):
        raise ConflictError("only a completed matching activation may be relocated")
    from .upgrade import inspect_realm_schema
    current = inspect_realm_schema(root, expected_realm_id=record["realm_id"])
    if current["kind"] != "U33":
        raise ConflictError("relocated activation is not U33")
    record["realm_root"] = str(root)
    record["root_identity"] = current["source_root_identity"]
    phase(archive, record, "ready", relocations=[*record.get("relocations", []),
          {"from": str(previous_root), "to": str(root), "at": now()}])
