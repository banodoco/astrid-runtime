"""Journaled adoption owns the U33/V34 boundary without relocating activation."""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys

import pytest

from astrid_runtime import workspace_adopt
from runtime_protocol import adoption_lifecycle as adoption, v33_lifecycle as old, v34_lifecycle as custody
from runtime_protocol.errors import ConflictError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.upgrade import inspect_realm_schema
from test_workspace_adopt import _adoption_capacity, _adopt, _fingerprints, _setup


def interrupt(tmp_path, monkeypatch, boundary):
    root, paths, config = _setup(tmp_path)
    source_before = _fingerprints(root)
    copies = []
    materialize = workspace_adopt._materialize

    def copy_once(*args):
        copies.append(args[1])
        return materialize(*args)

    def crash(name):
        if name == boundary:
            raise OSError('interrupted adoption boundary')

    monkeypatch.setattr(workspace_adopt, '_materialize', copy_once)
    with monkeypatch.context() as fault:
        fault.setattr(custody, 'boundary', crash)
        with pytest.raises(OSError, match='interrupted adoption boundary'):
            _adopt(root, paths, config, monkeypatch)
    destination = paths.realms_dir / 'film'
    assert destination.is_dir()
    assert _fingerprints(root) == source_before
    assert len(copies) == 1
    assert not workspace_adopt._read_catalog(paths).get('realms')
    return root, paths, config, destination, copies, source_before


@pytest.mark.parametrize('boundary,kind', [('before_schema_commit', 'U33'), ('schema_committed', 'V34')])
def test_adoption_resumes_v33_v34_boundary_with_two_restarts(tmp_path, monkeypatch, boundary, kind):
    root, paths, config, destination, copies, source_before = interrupt(tmp_path, monkeypatch, boundary)
    assert inspect_realm_schema(destination)['kind'] == kind
    archive, record = custody.activation(destination)
    historical_archive, historical_record = old.activation(destination)
    recovery_image = _fingerprints(archive / 'realm')
    old_image = _fingerprints(historical_archive / 'realm')
    assert record['recovery_digest'] == old.digest(record['inventory'])
    assert historical_record['state'] == 'backfill_complete'
    assert historical_record['operator_owned']
    assert historical_record['realm_root'] == record['realm_root'] == str(destination)
    assert historical_record['root_identity'] == record['root_identity'] == adoption.activation(destination)['root_identity']
    for _ in range(2):
        with pytest.raises(ConflictError, match='admission is closed'):
            RealmStore(destination)
        result = _adopt(root, paths, config, monkeypatch)
        assert result['target_version'] == 34
        assert inspect_realm_schema(destination)['kind'] == 'V34'
        assert custody.activation(destination)[0] == archive
        assert custody.activation(destination)[1]['state'] == 'activation_verified'
        assert _fingerprints(archive / 'realm') == recovery_image
        assert _fingerprints(historical_archive / 'realm') == old_image
        assert len(copies) == 1
        assert _fingerprints(root) == source_before
        # The bootstrap/health doubles do not constitute provider verification.
        assert old.activation(destination)[1]['state'] == 'backfill_complete'
    journal = json.loads((paths.runtime_support / 'adopt-journal.json').read_text())
    assert journal['migration']['source_schema_version'] == 26
    assert journal['migration']['target_schema_version'] == 34
    assert journal['migration']['steps'][-1] == {'source_schema_version': 33, 'target_schema_version': 34}
    assert journal['migration']['historical_recovery_set'] == str(historical_archive)


@pytest.mark.parametrize('boundary', ['before_schema_commit', 'schema_committed'])
def test_adoption_hybrid_refuses_without_any_recovery_writes(tmp_path, monkeypatch, boundary):
    root, paths, config, destination, copies, _ = interrupt(tmp_path, monkeypatch, boundary)
    with sqlite3.connect(destination / 'realm.sqlite3') as db:
        db.execute('PRAGMA foreign_keys=OFF')
        if boundary == 'before_schema_commit':
            db.execute('CREATE TABLE custody_keys(hybrid INTEGER)')
        else:
            db.execute('DROP TABLE custody_nonces')
    before = _fingerprints(tmp_path)
    for _ in range(2):
        with pytest.raises(ValidationError):
            _adopt(root, paths, config, monkeypatch)
        assert _fingerprints(tmp_path) == before
        assert len(copies) == 1


def test_adoption_corrupt_full_recovery_set_refuses_without_writes(tmp_path, monkeypatch):
    root, paths, config, destination, copies, _ = interrupt(tmp_path, monkeypatch, 'before_schema_commit')
    archive, _ = custody.activation(destination)
    (archive / 'realm' / 'realm.sqlite3').write_bytes(b'corrupt recovery set')
    before = _fingerprints(tmp_path)
    with pytest.raises(ConflictError, match='inventory/hash mismatch'):
        _adopt(root, paths, config, monkeypatch)
    assert _fingerprints(tmp_path) == before
    assert len(copies) == 1


def test_adoption_opens_only_after_fresh_real_provider_registration(tmp_path, monkeypatch):
    from runtime_protocol.contract_metadata import SCHEMA_DIGEST

    class Provider:
        provider_id = 'astrid-v1'
        interface_version = 1
        contract_digest = SCHEMA_DIGEST

        def commit(self, context, port):
            pytest.fail('offline adoption must not invoke an edit or installer')

    root, paths, config = _setup(tmp_path)
    _adopt(root, paths, config, monkeypatch)
    destination = paths.realms_dir / 'film'
    operation = adoption.activation(destination)['operation_id']
    with pytest.raises(ConflictError, match='admission is closed'):
        RuntimeService(destination)
    with monkeypatch.context() as startup:
        startup.setenv(adoption.TOKEN, operation)
        service = RuntimeService(destination)
        try:
            with pytest.raises(ConflictError):
                service._assert_mutation_admitted()
            service.register_timeline_commit_provider(Provider())
            service._assert_mutation_admitted()
            assert old.activation(destination)[1]['state'] == 'ready'
            assert custody.activation(destination)[1]['state'] == 'ready'
            assert service.store.conn.execute('SELECT COUNT(*) FROM attempt_custody').fetchone()[0] == 0
        finally:
            service.close()
    # A real subsequent startup needs no inherited coordinator token.
    for _ in range(2):
        with RealmStore(destination) as store:
            assert store.integrity_report()['ok']
            assert inspect_realm_schema(destination)['kind'] == 'V34'


def test_adoption_journal_identity_cannot_be_replaced(tmp_path, monkeypatch):
    root, paths, config, destination, copies, _ = interrupt(tmp_path, monkeypatch, 'schema_committed')
    journal_path = paths.runtime_support / 'adopt-journal.json'
    journal = json.loads(journal_path.read_text())
    journal['operation_id'] = 'another-adoption'
    journal_path.write_text(json.dumps(journal))
    before = _fingerprints(tmp_path)
    with pytest.raises(ConflictError, match='journal and directory'):
        _adopt(root, paths, config, monkeypatch)
    assert _fingerprints(tmp_path) == before
    assert len(copies) == 1


def test_adoption_old_binary_cannot_admit_u33_crash_boundary(tmp_path, monkeypatch):
    from tests.custody_schema_fixtures import v33_executable

    _, _, _, destination, _, _ = interrupt(tmp_path, monkeypatch, 'before_schema_commit')
    executable = v33_executable(destination)
    before = _fingerprints(destination)
    script = '''
import sys
from runtime_protocol.store import RealmStore
from runtime_protocol.errors import ConflictError
try:
    RealmStore(sys.argv[1])
except ConflictError as exc:
    assert 'exclusively owned' in str(exc)
else:
    raise AssertionError('the old binary admitted the uncommitted adoption')
'''
    result = subprocess.run(['env', '-u', 'RUNPOD_API_KEY', '-u', 'ASTRID_V33_ACTIVATION',
                             f'PYTHONPATH={executable}', 'PYTHONDONTWRITEBYTECODE=1',
                             sys.executable, '-c', script, str(destination)],
                            cwd=executable, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert _fingerprints(destination) == before
