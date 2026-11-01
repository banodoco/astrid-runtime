"""Authentic historical fixtures and the separate offline U33/V34 gates."""
from __future__ import annotations

import hashlib
from contextlib import closing
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
import shutil

from runtime_protocol.canonical_schema import CANONICAL_SCHEMA_SQL
from runtime_protocol.v33_manifest import canonical_manifest

BASE = '1a275bb339ae897e52a5be5e1da99e846e402037'
U33_SQL_DIGEST = 'afca19543e320894339b42af8015abf183b8b17e576e082707a9b854291d364c'
U33_FINGERPRINT = '6ed4d1f145aa5fd8d9691b8b7d072f4e176ad857d4dda586f72b4a64c0e09ff3'
# This inventory is pinned independently of the current fresh-schema declaration.
V34_ONLY = ('custody_nonces', 'custody_evidence_pins', 'custody_receipts',
            'custody_creates', 'custody_evidence', 'attempt_custody',
            'custody_keys', 'custody_installations')


def to_u33(connection):
    """Rewind an empty fresh custody domain before historical fixture edits."""
    assert hashlib.sha256(CANONICAL_SCHEMA_SQL.encode()).hexdigest() == U33_SQL_DIGEST
    version = connection.execute('SELECT version FROM runtime_schema').fetchone()[0]
    if version <= 33:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert not tables.intersection(V34_ONLY)
        return
    assert version == 34
    assert canonical_manifest(connection)['kind'] == 'V34'
    for table in V34_ONLY:
        assert connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] == 0
        connection.execute(f'DROP TABLE {table}')
    connection.execute('UPDATE runtime_schema SET version=33')
    assert canonical_manifest(connection)['fingerprint'] == U33_FINGERPRINT


def v33_executable(root):
    root = Path(root)
    executable = root.parent / '_v33_fixture_executable'
    if not executable.exists():
        executable.mkdir()
        raw = subprocess.check_output(['git', 'archive', BASE, 'runtime_protocol', 'astrid_runtime'],
                                      cwd=Path(__file__).resolve().parents[1])
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            archive.extractall(executable, filter='data')
    return executable


def finish_v33_offline(root):
    """Use the pinned owning binary to finish its real provider/baseline gate."""
    from runtime_protocol import v33_lifecycle
    root = Path(root)
    with closing(sqlite3.connect(root / 'realm.sqlite3')) as connection:
        assert canonical_manifest(connection)['kind'] == 'U33'
        assert connection.execute('SELECT COUNT(*) FROM attempts WHERE settled=0').fetchone()[0] == 0
    state = v33_lifecycle.activation(root)
    if not state or state[1]['state'] == 'ready':
        return
    assert state[1]['state'] == 'backfill_complete'
    assert not state[1].get('operator_owned')
    (root / 'cas/sha256').mkdir(parents=True, exist_ok=True)
    (root / 'staging').mkdir(exist_ok=True)
    executable = v33_executable(root)
    script = '''
import sys
from runtime_protocol.service import RuntimeService
from runtime_protocol.contract_metadata import SCHEMA_DIGEST
class OfflineFixtureProvider:
    provider_id = 'astrid-v1'
    interface_version = 1
    contract_digest = SCHEMA_DIGEST
    def commit(self, context, port):
        raise AssertionError('offline fixture activation must not dispatch edits')
try:
    service = RuntimeService(sys.argv[1])
except Exception as exc:
    print(getattr(exc, 'details', None), file=sys.stderr)
    raise
try:
    service.register_timeline_commit_provider(OfflineFixtureProvider())
finally:
    service.close()
'''
    result = subprocess.run(['env', '-u', 'RUNPOD_API_KEY', f'PYTHONPATH={executable}',
                             'PYTHONDONTWRITEBYTECODE=1', sys.executable, '-B', '-c', script, str(root)],
                            cwd=executable, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert v33_lifecycle.activation(root)[1]['state'] == 'ready'


def activate_fixture_to_current(root):
    """Complete the historical gate before admitting the current destination."""
    from runtime_protocol.store import SCHEMA_VERSION
    from runtime_protocol.upgrade import inspect_realm_schema, migrate_canonical_to_current
    identity = inspect_realm_schema(root)
    if SCHEMA_VERSION == 33:
        # The reference comparison changes fixtures only, never the base Runtime.
        assert identity['kind'] == 'U33'
        finish_v33_offline(root)
        return {'target_schema_version': 33}
    assert SCHEMA_VERSION == 34
    from runtime_protocol import v34_lifecycle
    if identity['kind'] == 'U33':
        finish_v33_offline(root)
        result = migrate_canonical_to_current(root, confirmation=f"MIGRATE CANONICAL {identity['realm_id']}")
        assert result['target_schema_version'] == 34 and result['admission_closed']
    else:
        assert identity['kind'] == 'V34'
        result = migrate_canonical_to_current(root, confirmation=f"MIGRATE CANONICAL {identity['realm_id']}")
    if v34_lifecycle.activation(root):
        v34_lifecycle.activate(root)
    assert inspect_realm_schema(root)['kind'] == 'V34'
    return result


def historical_case(tmp_path, node):
    """Retain a protected U33-only journey on its immutable owning binary."""
    project = Path(__file__).resolve().parents[1]
    target = Path(tmp_path) / '_historical_round1b'
    target.mkdir()
    raw = subprocess.check_output(['git', 'archive', BASE], cwd=project)
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        archive.extractall(target, filter='data')
    common = subprocess.check_output(['git', 'rev-parse', '--git-common-dir'], cwd=project, text=True).strip()
    common = (project / common).resolve()
    meta = target / '.git'
    (meta / 'objects/info').mkdir(parents=True)
    (meta / 'refs').mkdir()
    (meta / 'HEAD').write_text(BASE + '\n')
    (meta / 'config').write_text('[core]\nrepositoryformatversion=0\nbare=false\n')
    (meta / 'objects/info/alternates').write_text(str(common / 'objects') + '\n')
    subprocess.run(['git', 'read-tree', BASE], cwd=target, check=True)
    temporary = Path(tmp_path) / '_historical_basetemp'
    command = ['env', '-u', 'RUNPOD_API_KEY', f'PYTHONPATH={target}:{target / "tests"}',
               'PYTHONDONTWRITEBYTECODE=1', sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider',
               f'--basetemp={temporary}', 'tests/test_v33_protected_acceptance.py::' + node]
    result = subprocess.run(command, cwd=target, capture_output=True, text=True, timeout=180)
    (Path(tmp_path) / 'historical-result.json').write_text(json.dumps({
        'command': command, 'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}, indent=2))
    shutil.rmtree(temporary, ignore_errors=True)
    assert result.returncode == 0, result.stdout + result.stderr
