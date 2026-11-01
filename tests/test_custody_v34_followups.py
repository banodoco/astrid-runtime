"""Fail-closed outcomes from the supplied round-2 recovery decisions."""
import base64
from contextlib import contextmanager
import hashlib
import json
import shutil
import sqlite3

import pytest

from astrid_runtime import relocation
from astrid_runtime.bootstrap import BootstrapConfig
from astrid_runtime.paths import RuntimePaths
from runtime_protocol.backup import create_backup, restore_backup
from runtime_protocol.custody_schema import CUSTODY_TABLES
from runtime_protocol.errors import ConflictError, RealmAdmissionError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.util import canonical_json
from runtime_protocol import v34_lifecycle as life
from runtime_protocol.upgrade import migrate_canonical_to_current
from test_attempt_custody_v34 import world, arm, body, reconcile, retained, restart, SupervisorDouble
from test_custody_v34_migration import u33, tree


class NoOwnerCalls:
    def __init__(self):
        self.calls = 0

    def __getattr__(self, name):
        self.calls += 1
        raise AssertionError('relocation must refuse before an owner handoff: ' + name)


def test_older_coordinator_input_refuses_before_journal_or_owner_calls(tmp_path):
    from astrid_runtime.operator_upgrade import upgrade_workspace, OperatorUpgradeError
    from test_operator_upgrade import _fixture, _Boundary
    paths, profile, root = _fixture(tmp_path, version=25)
    boundary = _Boundary(paths)
    before = tree(paths.app_support)
    with pytest.raises(OperatorUpgradeError) as error:
        upgrade_workspace(paths, boundary, BootstrapConfig(source_profile=profile))
    assert error.value.details['reason'] == 'round1b_activation_required'
    assert error.value.details['next_action'] == 'finish_v33_activation_then_migrate_v34'
    assert tree(paths.app_support) == before and not boundary.calls


def relocation_fixture(tmp_path, *, migrated=True, secondary=False):
    paths = RuntimePaths.sandbox(tmp_path / 'support')
    paths.ensure_support_dirs()
    root = paths.realms_dir / 'old'
    realm = u33(root)
    if migrated:
        migrate_canonical_to_current(root, confirmation=f'MIGRATE CANONICAL {realm}')
        life.activate(root)
    rows = [{'realm_id': realm, 'data_root': str(root), 'display_name': 'Old'}]
    selected = realm
    if secondary:
        selected = 'selected'
        fresh = paths.realms_dir / selected
        RealmStore.initialize(fresh, realm_id=selected).close()
        rows.append({'realm_id': selected, 'data_root': str(fresh), 'display_name': 'Selected'})
    paths.catalog_path.write_text(json.dumps({'version': 1, 'realms': rows, 'selected_realm_id': selected}))
    paths.discovery_path.write_text(json.dumps({'pid': 1234, 'active_realm': selected}))
    return paths, root, realm


@pytest.mark.parametrize('secondary', [False, True])
def test_activated_v34_relocation_refuses_before_any_mutation(tmp_path, secondary):
    paths, root, _ = relocation_fixture(tmp_path, secondary=secondary)
    destination = tmp_path / 'destination'
    destination.mkdir()
    (destination / 'retained').write_bytes(b'untouched destination')
    archive = life.activation(root)[0]
    before = tree(paths.app_support), tree(destination), tree(archive)
    owner = NoOwnerCalls()
    for operation in (
        lambda: relocation.plan_relocation(paths, destination),
        lambda: relocation.relocate(paths, owner, BootstrapConfig(), None,
                                    destination=destination, confirmation='RELOCATE old'),
    ):
        with pytest.raises(relocation.RelocationError, match='A03B-V34-RELOCATION-HANDOFF'):
            operation()
        assert (tree(paths.app_support), tree(destination), tree(archive)) == before
        assert owner.calls == 0


def test_relocation_revalidates_v34_refusal_under_launcher_exclusion(tmp_path, monkeypatch):
    paths, root, realm = relocation_fixture(tmp_path, migrated=False)
    destination = tmp_path / 'destination'
    owner = NoOwnerCalls()
    original = relocation._bootstrap_mutex
    observed = {}

    @contextmanager
    def migration_before_exclusion(target):
        with original(target):
            migrate_canonical_to_current(root, confirmation=f'MIGRATE CANONICAL {realm}')
            life.activate(root)
            observed['source'] = tree(paths.app_support)
            observed['archive'] = tree(life.activation(root)[0])
            yield

    monkeypatch.setattr(relocation, '_bootstrap_mutex', migration_before_exclusion)
    with pytest.raises(relocation.RelocationError, match='A03B-V34-RELOCATION-HANDOFF'):
        relocation.relocate(paths, owner, BootstrapConfig(), None,
                            destination=destination, confirmation=f'RELOCATE {realm}')
    assert owner.calls == 0 and not destination.exists()
    assert tree(paths.app_support) == observed['source']
    assert tree(life.activation(root)[0]) == observed['archive']


@pytest.mark.parametrize('method', ['copy', 'move'])
def test_copied_or_moved_v34_root_cannot_bypass_startup_binding(tmp_path, method):
    root = tmp_path / 'root'
    realm = u33(root)
    migrate_canonical_to_current(root, confirmation=f'MIGRATE CANONICAL {realm}')
    life.activate(root)
    archive = life.activation(root)[0]
    target = tmp_path / 'other'
    shutil.copytree(root, target) if method == 'copy' else root.rename(target)
    before, recovery = tree(target), tree(archive)
    with pytest.raises((ConflictError, RealmAdmissionError)):
        RuntimeService(target)
    assert tree(target) == before and tree(archive) == recovery


def legacy_world(w, *, attributed):
    service, root = w['service'], w['root']
    if not attributed:
        task = service.store.conn.execute('SELECT * FROM tasks WHERE id=?', (w['attempt']['task_id'],)).fetchone()
        spec = service.store._spec(task)
        del spec.get('spec', spec)['install_binding']
        encoded = canonical_json(spec)
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        service.store.conn.execute("INSERT INTO task_specs VALUES (?,?,'t')", (digest, encoded))
        service.store.conn.execute('UPDATE tasks SET spec_digest=? WHERE id=?', (digest, task['id']))
    service.close()
    with sqlite3.connect(root / 'realm.sqlite3') as db:
        db.execute('PRAGMA foreign_keys=OFF')
        for table in CUSTODY_TABLES:
            db.execute('DROP TABLE ' + table)
        db.execute('UPDATE runtime_schema SET version=33')
    migrate_canonical_to_current(root, confirmation=f"MIGRATE CANONICAL {w['request']['realm_id']}")
    life.activate(root)
    w['service'] = RuntimeService(root)


def assert_legacy_retained(w):
    db = w['service'].store.conn
    attempt = db.execute('SELECT * FROM attempts WHERE id=?', (w['attempt']['attempt_id'],)).fetchone()
    task = db.execute('SELECT * FROM tasks WHERE id=?', (w['attempt']['task_id'],)).fetchone()
    assert attempt['settled'] == 0 and task['waiting_reason'] == 'legacy_install_custody_unknown'
    for key in ('lease_id', 'fence', 'executor_id', 'runtime_epoch'):
        assert attempt[key] == w['request'][key]
    assert task['attempt_id'] == attempt['id']
    assert db.execute('SELECT COUNT(*) FROM attempt_custody').fetchone()[0] == 0
    assert db.execute('SELECT COUNT(*) FROM reservations WHERE released_at IS NULL').fetchone()[0] == 1
    assert db.execute("SELECT COUNT(*) FROM events WHERE kind LIKE 'task.custody_%'").fetchone()[0] == 0


def test_terminal_legacy_installer_boolean_is_not_migration_stop_authority(world):
    w = world
    supervisor = SupervisorDouble()
    supervisor.dispatch({'dispatch_intent_id': 'old-untracked-intent', 'launch_permit_id': 'old-permit',
                         'launch_permit_expires_at': w['request']['launch_permit_expires_at']})
    w['service'].store.cancel_task(w['attempt']['task_id'], stop_observed=True)
    legacy_world(w, attributed=True)
    db = w['service'].store.conn
    spec_digest = db.execute('SELECT spec_digest FROM tasks').fetchone()[0]
    db.execute("UPDATE tasks SET updated_at='2000-01-01T00:00:00Z'")
    db.execute("UPDATE runs SET updated_at='2000-01-01T00:00:00Z'")
    db.execute("UPDATE command_idempotency SET created_at='2000-01-01T00:00:00Z'")
    from runtime_protocol.store import retire_terminal_specs
    with w['service'].store._transaction():
        retired = retire_terminal_specs(db, retention_days=30)
    assert retired['retired_tasks'] == retired['retired_runs'] == retired['removed_specs'] == 0
    assert db.execute('SELECT spec_digest FROM tasks').fetchone()[0] == spec_digest
    for _ in range(2):
        db = w['service'].store.conn
        task = db.execute('SELECT * FROM tasks WHERE id=?', (w['attempt']['task_id'],)).fetchone()
        attempt = db.execute('SELECT * FROM attempts WHERE id=?', (w['attempt']['attempt_id'],)).fetchone()
        assert task['status'] == 'cancelled' and attempt['settled'] == 1
        assert task['waiting_reason'] == 'legacy_install_custody_unknown'
        assert db.execute('SELECT quarantined FROM custody_installations WHERE installation_id=?',
                          (w['request']['installation_id'],)).fetchone()[0] == 1
        assert db.execute('SELECT COUNT(*) FROM attempt_custody').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM reservations WHERE released_at IS NULL').fetchone()[0] == 0
        with pytest.raises(ConflictError):
            w['service'].store.create_task('custody.test', {'install_binding': w['request']['install_binding']})
        assert supervisor.invoked == 1
        assert not supervisor.revoked
        restart(w)


@pytest.mark.parametrize('attributed', [False, True])
@pytest.mark.parametrize('damage', ['attempt', 'run', 'event'])
def test_legacy_attempt_lost_from_task_projection_remains_quarantined(world, attributed, damage):
    w = world
    db = w['service'].store.conn
    db.execute("UPDATE tasks SET status='failed',attempt_id=NULL WHERE id=?", (w['attempt']['task_id'],))
    legacy_world(w, attributed=attributed)
    candidate = w['root'].parent / 'erased-lineage'
    shutil.copytree(w['root'], candidate)
    life.assert_replacement_preserves_custody(w['root'], candidate)
    with sqlite3.connect(candidate / 'realm.sqlite3') as db:
        if damage == 'attempt':
            db.execute('DELETE FROM attempts')
        elif damage == 'run':
            db.execute("UPDATE runs SET status='queued'")
        else:
            db.execute('DELETE FROM events WHERE id=(SELECT MAX(id) FROM events)')
    with pytest.raises(ConflictError, match='erase or change custody'):
        life.assert_replacement_preserves_custody(w['root'], candidate)
    for _ in range(2):
        db = w['service'].store.conn
        task = db.execute('SELECT * FROM tasks WHERE id=?', (w['attempt']['task_id'],)).fetchone()
        assert task['attempt_id'] is None and task['waiting_reason'] == 'legacy_install_custody_unknown'
        attempt = db.execute('SELECT * FROM attempts WHERE id=?', (w['attempt']['attempt_id'],)).fetchone()
        assert attempt['settled'] == 0
        for key in ('lease_id','fence','runtime_epoch','executor_id'):
            assert attempt[key] == w['request'][key]
        assert db.execute('SELECT COUNT(*) FROM reservations WHERE released_at IS NULL').fetchone()[0] == 1
        assert db.execute('SELECT COUNT(*) FROM attempt_custody').fetchone()[0] == 0
        with pytest.raises(ConflictError):
            w['service'].store.create_task('custody.test', {'install_binding': w['request']['install_binding']})
        restart(w)


@pytest.mark.parametrize('attributed', [False, True])
@pytest.mark.parametrize('path', ['claim', 'claim_replay', 'task_retry', 'run_retry', 'resume', 'reset', 'release', 'new_task', 'bare_stop'])
def test_legacy_quarantine_blocks_every_admission_and_release_path(world, attributed, path):
    w = world
    legacy_world(w, attributed=attributed)
    restart(w)
    restart(w)
    s, a = w['service'], w['attempt']
    db = s.store.conn
    if path == 'claim':
        db.execute("UPDATE tasks SET status='queued' WHERE id=?", (a['task_id'],))
        call = lambda: s.store._claim_task(a['task_id'], w['request']['executor_id'], 'new', runtime_epoch=s.health()['runtime_epoch'])
    elif path == 'claim_replay':
        call = lambda: s.claim_next({'executor_id': w['request']['executor_id'], 'capability_ids': ['custody.test'],
                                    'runtime_epoch': a['runtime_epoch']}, idempotency_key='claim')
    elif path in {'task_retry', 'run_retry'}:
        db.execute("UPDATE tasks SET status='failed' WHERE id=?", (a['task_id'],))
        run = db.execute('SELECT run_id FROM tasks WHERE id=?', (a['task_id'],)).fetchone()[0]
        db.execute("UPDATE runs SET status='failed' WHERE id=?", (run,))
        call = (lambda: s.retry_task(a['task_id'], idempotency_key='retry')) if path == 'task_retry' else lambda: s.store.retry_run(run)
    elif path == 'resume':
        s._checkpoint_row = lambda *args: {'task_id': a['task_id']}
        call = lambda: s.resume_attempt({'nonce': 'n', 'authorization': 'a', 'attempt_id': a['attempt_id'],
                                         'runtime_epoch': s.health()['runtime_epoch']})
    elif path == 'reset':
        call = lambda: s.store.reset_execution_attempt(a['task_id'])
    elif path == 'release':
        call = lambda: s.store._release_reservations(a['task_id'])
    elif path == 'bare_stop':
        call = lambda: s.store.cancel_task(a['task_id'], stop_observed=True)
    else:
        binding = dict(w['request']['install_binding'])
        if not attributed:
            binding['installation_id'] = 'a-different-installation'
        call = lambda: s.store.create_task('custody.test', {'install_binding': binding})
    def facts():
        return {table: [tuple(row) for row in db.execute('SELECT * FROM ' + table + ' ORDER BY rowid')]
                for table in ('tasks', 'attempts', 'reservations', 'events')}
    before = facts()
    with pytest.raises(ConflictError):
        call()
    assert facts() == before
    assert_legacy_retained(w)


@pytest.mark.parametrize('attributed', [False, True])
def test_legacy_quarantine_survives_backup_and_refuses_reservation_erasure(world, tmp_path, attributed):
    w = world
    legacy_world(w, attributed=attributed)
    candidate = tmp_path / 'candidate'
    shutil.copytree(w['root'], candidate)
    with sqlite3.connect(candidate / 'realm.sqlite3') as db:
        db.execute("UPDATE reservations SET released_at='erased by candidate'")
    before = tree(w['root'])
    with pytest.raises(ConflictError, match='erase or change custody'):
        life.assert_replacement_preserves_custody(w['root'], candidate)
    assert tree(w['root']) == before
    backup, target = tmp_path / 'backup', tmp_path / 'restored'
    key = b'test-only-legacy-quarantine-backup-key'
    create_backup(w['service'].store, backup, key=key)
    w['service'].close()
    restore_backup(backup, target, key=key)
    with sqlite3.connect(target / 'realm.sqlite3') as db:
        assert db.execute("SELECT COUNT(*) FROM tasks WHERE waiting_reason='legacy_install_custody_unknown'").fetchone()[0] == 1
        assert db.execute('SELECT COUNT(*) FROM reservations WHERE released_at IS NULL').fetchone()[0] == 1
        assert db.execute('SELECT COUNT(*) FROM attempt_custody').fetchone()[0] == 0
    w['service'] = RuntimeService(target)
    w['root'] = target
    assert w['service'].health()['runtime_epoch'] > w['request']['runtime_epoch']
    restart(w)
    restart(w)
    assert_legacy_retained(w)


@pytest.mark.parametrize('mode', ['reconcile', 'repair'])
def test_pending_success_has_typed_hold_and_cannot_be_replaced_by_recovery(world, mode):
    w = world
    row = arm(w)
    supervisor = SupervisorDouble()
    w['service'].store.custody.dispatch(row['custody_id'], supervisor)
    data = b'exact successful publication before a manifest'
    publication = {'lease_id': row['lease_id'], 'fence': row['fence'], 'runtime_epoch': row['runtime_epoch'],
                   'outputs': [{'kind': 'object', 'name': 'output', 'digest': 'sha256:' + hashlib.sha256(data).hexdigest(),
                                'size': len(data), 'media_type': 'application/octet-stream',
                                'data_base64': base64.b64encode(data).decode()}],
                   'result': {'pending_journal_identity': 'original-job-and-journal', 'actual_install_outcome': 'success'}}
    w['service'].settle_attempt(row['attempt_id'], publication, idempotency_key='pending-success')
    pending = retained(w)['pending_publication_json']
    with pytest.raises(ConflictError) as error:
        reconcile(w, body(w, mode=mode))
    assert error.value.details['reason'] == 'custody_pending_success'
    assert error.value.details['next_action'] == 'A03B-PENDING-SUCCESS-RECONCILE'
    for _ in range(2):
        restart(w)
        row = retained(w)
        assert row['pending_publication_json'] == pending
        assert w['service'].store.custody.public(row)['hold_reason'] == 'custody_pending_success'
    assert supervisor.invoked == 1
    assert w['service'].store.conn.execute("SELECT COUNT(*) FROM events WHERE kind='task.custody_released'").fetchone()[0] == 0


def test_coordinator_retries_intact_u33_with_the_same_verified_recovery_set(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from astrid_runtime import operator_upgrade
    from test_operator_upgrade import _fixture, _Boundary
    from test_timeline_commit_provider import Provider
    paths, profile, root = _fixture(tmp_path, version=33)
    boundary = _Boundary(paths)
    config = BootstrapConfig(source_profile=profile)
    with sqlite3.connect(root / 'realm.sqlite3') as db:
        db.execute("INSERT INTO user_preferences VALUES ('owner','kept','before migration',1,'t','t')")

    def fail_before_ddl(*args, **kwargs):
        raise OSError('coordinator interrupted before custody DDL')

    with monkeypatch.context() as fault:
        fault.setattr(operator_upgrade, 'migrate_canonical_to_current', fail_before_ddl)
        with pytest.raises(operator_upgrade.OperatorUpgradeError, match='interrupted before custody DDL'):
            operator_upgrade.upgrade_workspace(paths, boundary, config)
    archive, record = life.activation(root)
    original = record['operation_id'], record['recovery_digest']
    coordinator = json.loads((paths.runtime_support / 'upgrade-journal.json').read_text())
    assert coordinator['recovery_set'] == str(archive)
    assert record['state'] == 'backup_verified'
    started = []

    def start(target, *_args):
        service = RuntimeService(root)
        try:
            with pytest.raises(ConflictError):
                service._assert_mutation_admitted()
            service.register_timeline_commit_provider(Provider())
            assert service.store.conn.execute('SELECT content FROM user_preferences').fetchone()[0] == 'before migration'
        finally:
            service.close()
        started.append(1)
        discovery = {'pid': 1235, 'active_realm': 'realm-1', 'endpoint': 'http://127.0.0.1:17540',
                     'runtime_instance_id': 'resumed', 'process_birth_id': 'resumed-birth', 'realm_root': str(root)}
        target.discovery_path.write_text(json.dumps(discovery))
        target.instance_lock_path.write_text(json.dumps(discovery | {'realm_id': 'realm-1'}))
        return SimpleNamespace(endpoint=discovery['endpoint'], pid=1235, runtime_instance_id='resumed')

    monkeypatch.setattr(operator_upgrade, '_bootstrap_locked', start)
    result = operator_upgrade.recover_workspace(paths, boundary, config)
    assert result['state'] == 'complete' and result['operation_id'] == coordinator['operation_id']
    assert started == [1]
    resumed_archive, resumed = life.activation(root)
    assert resumed_archive == archive and (resumed['operation_id'], resumed['recovery_digest']) == original
    assert resumed['state'] == 'ready'
    assert json.loads((paths.runtime_support / 'upgrade-journal.json').read_text())['operation_id'] == coordinator['operation_id']
    life.verify_recovery(resumed_archive, resumed)
    with RealmStore(root) as store:
        assert store.conn.execute('SELECT version FROM runtime_schema').fetchone()[0] == 34
