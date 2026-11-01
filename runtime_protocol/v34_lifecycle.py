"""Offline U33 -> V34 activation, bound to a verified full recovery set.

The v33 archive/marker remain owned by the round-1b coordinator. An admitted
v34 realm is never automatically replaced by an old snapshot.
"""
from __future__ import annotations

import shutil
import sqlite3
import time
import uuid
from pathlib import Path

from . import platform, v33_lifecycle as old
from .custody_schema import CUSTODY_SCHEMA_SQL
from .errors import ConflictError, ValidationError
from .util import now
from .v33_manifest import canonical_manifest

MARKER = '.v34-activation.json'


def activation(root):
    root = Path(root)
    if not (root / MARKER).exists():
        return None
    binding = old.read_record(root / MARKER)
    archive = Path(binding['archive'])
    record = old.read_record(archive / 'activation.json')
    if (record['format'] != 'astrid-v34-activation/v1' or record['realm_root'] != str(root)
            or any(record[k] != binding[k] for k in ('operation_id','realm_id','recovery_digest'))
            or record['recovery_digest'] != old.digest(record['inventory'])):
        raise ConflictError('v34 activation is not bound to its full recovery set')
    old.check_root_binding(root, record['root_identity'])
    return archive, record


def verify_recovery(archive, record):
    old.verify_tree(archive / 'realm', record['inventory'])
    old.verify_sqlite_image(archive / 'realm', realm_id=record['realm_id'], fingerprint=record['source']['fingerprint'])


def phase(root, archive, record, state):
    old.check_root_binding(root, record['root_identity'])
    record['state'] = state
    old.write_record(archive / 'activation.json', record)
    old.write_record(Path(root) / MARKER, {k: record[k] for k in ('operation_id','realm_id','recovery_digest','state')} | {'archive': str(archive)})


def begin(root, identity, observation):
    pending = activation(root)
    if pending and pending[1]["state"] != "ready":
        raise ConflictError("v34 activation already exists; resume its verified recovery set")
    archive = root.parent / '.v34-recovery' / uuid.uuid4().hex
    platform.private_directory(archive)
    if archive.stat().st_dev != root.stat().st_dev:
        raise ValidationError('custody recovery set must share the realm filesystem')
    inventory = old.snapshot_tree(root, archive / 'realm', exclude=('owner.lock',))
    for name in list(inventory):
        if name in {'realm.sqlite3' + s for s in ('','-wal','-shm','-journal')}:
            (archive / 'realm' / name).unlink()
            del inventory[name]
    for source in Path(observation).iterdir():
        destination = archive / 'realm' / source.name
        shutil.copy2(source, destination)
        with destination.open('r+b') as stream:
            import os
            os.fsync(stream.fileno())
        inventory[source.name] = old._file_fact(destination)
    platform.fsync_directory(archive / 'realm')
    record = {'format': 'astrid-v34-activation/v1', 'operation_id': archive.name,
              'realm_id': identity['realm_id'], 'realm_root': str(root),
              'root_identity': identity['source_root_identity'], 'source': identity,
              'inventory': inventory, 'recovery_digest': old.digest(inventory),
              'state': 'backup_verified', 'created_at': now(),
              'retention': 'indefinite while unresolved; at least 30 days and operator acknowledgement'}
    verify_recovery(archive, record)
    phase(root, archive, record, 'backup_verified')
    return archive, record


def apply(connection):
    if canonical_manifest(connection)['kind'] != 'U33':
        raise ValidationError('custody migration requires pinned U33')
    # executescript would implicitly commit; execute the fixed DDL statements
    # separately to retain the single schema/version transaction.
    for statement in CUSTODY_SCHEMA_SQL.split(';'):
        if statement.strip():
            connection.execute(statement)
    # Historical in-flight work is uncertainty, never fabricated stop evidence.
    for task in connection.execute('SELECT * FROM tasks WHERE attempt_id IN (SELECT id FROM attempts WHERE settled=0)').fetchall():
        connection.execute("UPDATE tasks SET waiting_reason='legacy_install_custody_unknown' WHERE id=?", (task['id'],))
        if task['spec_digest']:
            import json
            spec = connection.execute('SELECT body_json FROM task_specs WHERE digest=?', (task['spec_digest'],)).fetchone()
            from .custody import declared_binding
            binding = declared_binding(json.loads(spec[0])) if spec else None
            if isinstance(binding, dict) and binding.get('installation_id'):
                connection.execute('INSERT OR IGNORE INTO custody_installations(installation_id,realm_id,quarantined,created_at) VALUES (?,?,1,?)', (binding['installation_id'], connection.execute('SELECT id FROM realm').fetchone()[0], now()))
    connection.execute('UPDATE runtime_schema SET version=34 WHERE id=1')
    if canonical_manifest(connection)['kind'] != 'V34':
        raise ValidationError('migration did not produce pinned V34')


def migrate(root, *, confirmation, expected_realm_id=None, timeout_seconds=120):
    from .upgrade import inspect_realm_schema, _owner_fence
    root = Path(root).resolve()
    # Detached classification precedes every marker, owner lock and DB write.
    identity = inspect_realm_schema(root, expected_realm_id=expected_realm_id)
    if identity['kind'] not in {'U33','V34'}:
        raise ValidationError('custody activation requires completed canonical v33 migration')
    if confirmation != f"MIGRATE CANONICAL {identity['realm_id']}":
        raise ValidationError('custody migration confirmation differs')
    previous = old.activation(root)
    if previous and previous[1]['state'] != 'ready':
        raise ConflictError('finish or explicitly recover the round-1b v33 activation first')
    pending = activation(root)
    if identity['kind'] == 'V34':
        if pending:
            verify_recovery(*pending)
            if pending[1]['state'] != 'ready':
                return {'ok': True, 'changed': False, 'source_schema_version': 34, 'target_schema_version': 34,
                        'admission_closed': True, 'recovery_set': str(pending[0]), 'next_action': 'activate_v34'}
        return {'ok': True, 'changed': False, 'source_schema_version': 34, 'target_schema_version': 34, 'admission_closed': False}
    if pending:
        if pending[1]['state'] != 'backup_verified' or pending[1]['source']['fingerprint'] != identity['fingerprint']:
            raise ConflictError('v34 activation journal conflicts with intact U33')
        verify_recovery(*pending)
    with _owner_fence(root), old.sqlite_observation(root) as observation:
        connection = sqlite3.connect(root / 'realm.sqlite3', timeout=timeout_seconds)
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA foreign_keys=ON')
        connection.execute('PRAGMA synchronous=FULL')
        try:
            connection.execute('BEGIN IMMEDIATE')
            locked = canonical_manifest(connection, expected_realm_id=identity['realm_id'])
            if locked['fingerprint'] != identity['fingerprint']:
                raise ConflictError('schema changed before v34 writer exclusion')
            source_stat = (root / 'realm.sqlite3').stat()
            if (source_stat.st_dev, source_stat.st_ino) != tuple(identity['source_file_identity'][:2]):
                raise ConflictError('database identity changed before migration')
            archive, record = pending or begin(root, identity, observation)
            if pending:
                # Intact v33 may retry only if the entire pre-activation image
                # still agrees with its recovery set (including admitted data).
                def logical_facts(image):
                    from .upgrade import _row_digest, _table_columns, _tables
                    with old.sqlite_observation(image) as copy:
                        db = sqlite3.connect(copy / 'realm.sqlite3')
                        try:
                            return {t: _row_digest(db, t, _table_columns(db,t)) for t in _tables(db)}
                        finally:
                            db.close()
                current_files = {p.relative_to(root).as_posix(): old._file_fact(p) for p in old._files(root, exclude=('owner.lock', MARKER)) if not p.name.startswith('realm.sqlite3')}
                archived_files = {k:v for k,v in record['inventory'].items() if not k.startswith('realm.sqlite3') and k != MARKER}
                if current_files != archived_files or logical_facts(root) != logical_facts(archive / 'realm'):
                    raise ConflictError('intact U33 data differs from the verified recovery set')
            apply(connection)
            boundary('before_schema_commit')
            if connection.execute('PRAGMA integrity_check').fetchone()[0] != 'ok' or connection.execute('PRAGMA foreign_key_check').fetchone():
                raise ValidationError('V34 integrity or foreign-key check failed')
            connection.commit()
            boundary('schema_committed')
            phase(root, archive, record, 'schema_committed')
        except BaseException:
            connection.rollback()
            # Never replace a possibly committed schema or erase admitted work.
            raise
        finally:
            connection.close()
    return {'ok': True, 'changed': True, 'source_schema_version': 33, 'target_schema_version': 34,
            'admission_closed': True, 'recovery_set': str(archive), 'next_action': 'activate_v34'}


def activate(root, *, admit=True):
    """Offline acknowledgement after complete V34 and archive verification."""
    from .upgrade import inspect_realm_schema, _owner_fence
    root = Path(root).resolve()
    identity = inspect_realm_schema(root)
    if identity['kind'] != 'V34':
        raise ConflictError('activation requires committed V34')
    pending = activation(root)
    if pending is None:
        raise ConflictError('activation requires its verified full recovery set')
    with _owner_fence(root):
        archive, record = pending
        verify_recovery(archive, record)
        with old.sqlite_observation(root) as observation:
            connection = sqlite3.connect(Path(observation) / 'realm.sqlite3')
            try:
                if canonical_manifest(connection)['kind'] != 'V34' or connection.execute('PRAGMA integrity_check').fetchone()[0] != 'ok' or connection.execute('PRAGMA foreign_key_check').fetchone():
                    raise ConflictError('v34 activation integrity failed')
            finally:
                connection.close()
        if not admit:
            record['provider_verified'] = False
        phase(root, archive, record, 'ready' if admit else 'activation_verified')
    return {'ok': True, 'admission_closed': not admit, 'schema_version': 34}


def check_startup(root):
    pending = activation(root)
    if pending and pending[1]['state'] == 'activation_verified' and pending[1].get('operator_owned'):
        import os
        if os.environ.get('ASTRID_V33_ACTIVATION') == pending[1]['operation_id']:
            return
    require_ready(root)


def require_ready(root):
    pending = activation(root)
    if pending and pending[1]['state'] != 'ready':
        raise ConflictError('v34 activation incomplete; admission is closed; resume offline activation')


def rollback(root, archive):
    """Conservatively refuse destructive rollback, preserving all v34 writes.

    An old binary cannot represent custody. Snapshot age or an apparently idle
    supervisor is insufficient independent quiescence authority.
    """
    record = old.read_record(Path(archive) / 'activation.json')
    if record['realm_root'] != str(Path(root).resolve()):
        raise ConflictError('rollback recovery set belongs to another realm')
    raise ConflictError('v34 rollback refused: preserve custody and admitted writes; independently establish quiescence before an older Runtime')


def boundary(name):
    """Crash injection seam."""


def assert_replacement_preserves_custody(active, candidate):
    """A snapshot cannot erase custody, keys, quarantine or replay history.

    Call under owner/admission exclusion immediately before publication too.
    Unreadable active authority is uncertainty and is refused, not guessed away.
    """
    from .custody_schema import CUSTODY_TABLES
    from .upgrade import _row_digest, _table_columns, _tables
    def facts(root):
        with old.sqlite_observation(root) as observation:
            db = sqlite3.connect(observation / 'realm.sqlite3')
            db.row_factory = sqlite3.Row
            try:
                tables = _tables(db)
                schema = db.execute('SELECT version FROM runtime_schema WHERE id=1').fetchone()
                if not schema:
                    raise ConflictError('replacement cannot establish the active custody schema')
                if schema[0] < 34:
                    canonical_manifest(db)
                    return {}
                if not CUSTODY_TABLES.issubset(tables):
                    raise ConflictError('replacement cannot exclude damaged custody authority')
                result = {t:_row_digest(db,t,_table_columns(db,t)) for t in CUSTODY_TABLES}
                legacy = list(db.execute("SELECT id AS task_id,attempt_id FROM tasks WHERE waiting_reason='legacy_install_custody_unknown'"))
                # An empty fresh domain has no old authority to preserve.
                if not legacy and not any(count for count, _ in result.values()):
                    return {}
                rows = list(db.execute('SELECT task_id,attempt_id FROM attempt_custody')) + legacy
                for task in rows:
                    for table,field,value in [('tasks','id',task['task_id']),('attempts','id',task['attempt_id']),('reservations','task_id',task['task_id'])]:
                        entries = [dict(r) for r in db.execute(f'SELECT * FROM {table} WHERE {field}=? ORDER BY rowid',(value,))]
                        result[(table,value)] = old.digest(entries)
                return result
            except sqlite3.DatabaseError as exc:
                raise ConflictError('replacement cannot exclude surviving custody in an unreadable realm') from exc
            finally:
                db.close()
    before = facts(active)
    if before and before != facts(candidate):
        raise ConflictError('replacement would erase or change custody, reservations, quarantine or replay state')


def provider_ready(root, inventory):
    pending = activation(root)
    if pending and pending[1]['state'] == 'activation_verified':
        archive, record = pending
        record['provider_verified'] = True
        record['baseline_inventory'] = inventory
        phase(Path(root), archive, record, 'activation_verified')
