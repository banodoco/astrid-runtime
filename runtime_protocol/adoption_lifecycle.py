"""Admission fence for a copied realm inside journaled workspace adoption.

The copy reaches its final directory before migration. Activation archives are
therefore born at that directory and are never rebound by adoption or relocation.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3

from .errors import ConflictError
from . import v33_lifecycle as history

MARKER = '.adoption-activation.json'
TOKEN = 'ASTRID_ADOPTION_ACTIVATION'


def begin(temporary, destination, journal_path, operation_id, realm_id):
    temporary, destination = Path(temporary), Path(destination)
    stat = temporary.stat()
    history.write_record(temporary / MARKER, {
        'format': 'astrid-adoption-activation/v1', 'operation_id': operation_id,
        'realm_id': realm_id, 'realm_root': str(destination),
        'root_identity': [stat.st_dev, stat.st_ino], 'journal': str(journal_path),
    })


def activation(root):
    root = Path(root)
    marker = root / MARKER
    if not marker.exists() and not marker.is_symlink():
        return None
    record = history.read_record(marker)
    try:
        journal_path = Path(record['journal'])
        if journal_path.is_symlink():
            raise ValueError('symbolic adoption journal')
        journal = json.loads(journal_path.read_text())
        if (record['format'] != 'astrid-adoption-activation/v1'
                or record['realm_root'] != str(root)
                or any(journal[k] != record[k] for k in ('operation_id', 'realm_id'))
                or journal['destination'] != str(root)):
            raise ValueError('adoption journal binding differs')
        history.check_root_binding(root, record['root_identity'])
    except (KeyError, OSError, ValueError, TypeError) as exc:
        raise ConflictError('adoption activation is not bound to this journal and directory') from exc
    return record


def verify_historical_gate(root):
    """Verify the completed SQL/backfill gate without opening the live DB.

    Fresh provider/baseline registration remains pending until V34 startup.
    This exception belongs only to the same journaled, unadmitted adoption.
    """
    record = activation(root)
    if record is None:
        raise ConflictError('pending U33 activation requires its adoption journal')
    pending = history.activation(root)
    if pending is None or pending[1]['state'] == 'ready':
        return record
    archive, old = pending
    if (old['state'] != 'backfill_complete' or
            (old.get('operator_owned') and old.get('adoption_operation') != record['operation_id'])):
        raise ConflictError('adoption requires completed round-1b SQL/backfill activation')
    history.verify_tree(archive / 'realm', old['inventory'])
    history.verify_sqlite_image(archive / 'realm', realm_id=old['realm_id'],
                                fingerprint=old['source']['fingerprint'])
    completion = history.read_record(archive / 'backfill-complete.json')
    if completion['plan_digest'] != old.get('plan_digest') or completion['backup_id'] != old['backup_id']:
        raise ConflictError('adoption backfill completion differs from its recovery set')
    from .v33_backfill_plan import reconcile_generation_plan
    with history.sqlite_observation(root) as observation:
        connection = sqlite3.connect(observation / 'realm.sqlite3')
        connection.row_factory = sqlite3.Row
        try:
            reconcile_generation_plan(connection, history.read_record(archive / 'backfill-plan.json'), verify_only=True)
        finally:
            connection.close()
    return record


def check_startup(root):
    record = activation(root)
    if record is None:
        return
    if os.environ.get(TOKEN) == record['operation_id']:
        return
    from .v34_lifecycle import activation as custody_activation
    pending = custody_activation(root)
    if pending and pending[1]['state'] == 'ready':
        return
    raise ConflictError('workspace adoption is incomplete; admission is closed; resume adoption')
