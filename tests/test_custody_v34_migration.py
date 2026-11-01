"""Pinned schema, full-set activation, backup and conservative rollback tests."""
import sqlite3

import pytest

from runtime_protocol import v34_lifecycle as life
from runtime_protocol.canonical_schema import CURRENT_SCHEMA_SQL
from runtime_protocol.custody_schema import CUSTODY_TABLES
from runtime_protocol.errors import ConflictError, ValidationError
from runtime_protocol.store import RealmStore
from runtime_protocol.upgrade import inspect_realm_schema, migrate_canonical_to_current
from runtime_protocol.v33_manifest import canonical_manifest

from test_attempt_custody_v34 import arm, world, retained, restart


def u33(root):
    RealmStore.initialize(root).close()
    db=sqlite3.connect(root/'realm.sqlite3')
    db.execute('PRAGMA foreign_keys=OFF')
    for table in CUSTODY_TABLES:db.execute('DROP TABLE '+table)
    db.execute('UPDATE runtime_schema SET version=33');db.commit()
    assert canonical_manifest(db)['kind']=='U33'
    realm=db.execute('SELECT id FROM realm').fetchone()[0]
    db.close()
    return realm


def tree(root):
    return {p.relative_to(root).as_posix():p.read_bytes() for p in root.rglob('*') if p.is_file()}


def test_populated_u33_to_v34_pinned_fingerprint_and_fresh_parity(tmp_path):
    root=tmp_path/'realm';realm=u33(root)
    db=sqlite3.connect(root/'realm.sqlite3')
    db.execute("INSERT INTO user_preferences VALUES ('owner','note','retained note',1,'t','t')");db.commit();db.close()
    result=migrate_canonical_to_current(root,confirmation=f'MIGRATE CANONICAL {realm}')
    assert result['target_schema_version']==34 and result['admission_closed']
    with pytest.raises(ConflictError):RealmStore(root)
    pending=life.activation(root)
    life.verify_recovery(*pending)
    assert pending[1]['recovery_digest']==life.old.digest(pending[1]['inventory'])
    life.activate(root)
    with RealmStore(root) as store:
        assert store.conn.execute('SELECT content FROM user_preferences').fetchone()[0]=='retained note'
        current=canonical_manifest(store.conn)
        assert current['kind']=='V34'
        db=sqlite3.connect(':memory:');db.executescript(CURRENT_SCHEMA_SQL)
        db.execute("INSERT INTO runtime_schema VALUES (1,'astrid-runtime-sqlite-v1',34,'t')")
        db.execute("INSERT INTO realm VALUES ('fresh','fresh','t','t')")
        assert canonical_manifest(db)['fingerprint']==current['fingerprint']
        assert store.integrity_report()['ok']


@pytest.mark.parametrize('boundary',['before_schema_commit','schema_committed'])
def test_migration_interruption_intact_retries_committed_resumes_closed(tmp_path,monkeypatch,boundary):
    root=tmp_path/'realm';realm=u33(root)
    def crash(name):
        if name==boundary:raise OSError('power loss')
    with monkeypatch.context() as patch:
        patch.setattr(life,'boundary',crash)
        with pytest.raises(OSError):migrate_canonical_to_current(root,confirmation=f'MIGRATE CANONICAL {realm}')
    # Two successive process-level offline recovery invocations.
    for _ in range(2):
        result=migrate_canonical_to_current(root,confirmation=f'MIGRATE CANONICAL {realm}')
        assert result['admission_closed']
        with pytest.raises(ConflictError):RealmStore(root)
    life.activate(root)
    with RealmStore(root) as store:assert canonical_manifest(store.conn)['kind']=='V34'


def test_hybrid_refusal_zero_writes_and_backup_failure(tmp_path,monkeypatch):
    root=tmp_path/'realm';realm=u33(root)
    db=sqlite3.connect(root/'realm.sqlite3');db.execute('CREATE TABLE attempt_custody(x)');db.commit();db.close()
    before=tree(root)
    with pytest.raises(ValidationError):migrate_canonical_to_current(root,confirmation=f'MIGRATE CANONICAL {realm}')
    assert tree(root)==before and not (tmp_path/'.v34-recovery').exists()
    root2=tmp_path/'realm2';realm2=u33(root2)
    def fail(*args,**kwargs):raise OSError('backup failure')
    monkeypatch.setattr(life.old,'snapshot_tree',fail)
    with pytest.raises(OSError):migrate_canonical_to_current(root2,confirmation=f'MIGRATE CANONICAL {realm2}')
    assert inspect_realm_schema(root2)['kind']=='U33'
    assert not (root2/life.MARKER).exists()


def test_rollback_after_admitted_writes_refuses_without_erasing(tmp_path):
    root=tmp_path/'realm';realm=u33(root)
    migrate_canonical_to_current(root,confirmation=f'MIGRATE CANONICAL {realm}');life.activate(root)
    archive=life.activation(root)[0]
    with RealmStore(root) as store:
        store.conn.execute("INSERT INTO user_preferences VALUES ('owner','new-write','admitted after migration',1,'t','t')")
    before=tree(root)
    with pytest.raises(ConflictError):life.rollback(root,archive)
    assert tree(root)==before
    with RealmStore(root) as store:
        assert store.conn.execute('SELECT content FROM user_preferences').fetchone()[0]=='admitted after migration'


def test_custody_bearing_backup_restore_preserves_evidence_receipts_and_epoch(world,tmp_path):
    from runtime_protocol.backup import create_backup,restore_backup
    from runtime_protocol.service import RuntimeService
    w=world;r=arm(w);s=w['service']
    s.store.custody.stage_evidence(r['custody_id'],b'exact pending journal',expected_version=1,custody_seq=2,ref='journal')
    retained(w)
    archive=tmp_path/'backup'
    key=b'fixture-backup-key-for-custody-v34'
    create_backup(s.store,archive,key=key)
    s.close()
    target=tmp_path/'restored'
    restore_backup(archive,target,key=key)
    restored=RuntimeService(target)
    try:
        w['service']=restored;w['root']=target
        r=retained(w)
        assert r['custody_state']=='unresolved'
        assert restored.health()['runtime_epoch']>r['runtime_epoch']
        assert restored.store.custody.create(w['request'],idempotency_key='arm')['custody_id']==r['custody_id']
        assert restored.cas.read(__import__('hashlib').sha256(b'exact pending journal').hexdigest())==b'exact pending journal'
    finally:restored.close()


def test_legacy_inflight_is_quarantined_without_historical_stop_evidence(world):
    w=world;root=w['root'];s=w['service'];a=w['attempt'];realm=s.realm['id']
    s.close()
    db=sqlite3.connect(root/'realm.sqlite3');db.execute('PRAGMA foreign_keys=OFF')
    for table in CUSTODY_TABLES:db.execute('DROP TABLE '+table)
    db.execute('UPDATE runtime_schema SET version=33');db.commit();db.close()
    migrate_canonical_to_current(root,confirmation=f'MIGRATE CANONICAL {realm}');life.activate(root)
    from runtime_protocol.service import RuntimeService
    w['service']=RuntimeService(root)
    for _ in range(2):
        s=w['service'];task=s.store.get_task(a['task_id'])['task']
        assert task['attempt_id']==a['attempt_id'] and task['waiting_reason']=='legacy_install_custody_unknown'
        assert s.store.conn.execute('SELECT settled FROM attempts WHERE id=?',(a['attempt_id'],)).fetchone()[0]==0
        assert s.store.conn.execute('SELECT COUNT(*) FROM reservations WHERE released_at IS NULL').fetchone()[0]==1
        assert s.store.conn.execute('SELECT COUNT(*) FROM attempt_custody').fetchone()[0]==0
        with pytest.raises(ConflictError):s.store._release_reservations(a['task_id'])
        restart(w)


def test_pending_round1b_activation_is_not_overwritten(tmp_path):
    root=tmp_path/'realm';realm=u33(root)
    # An unknown/incomplete round-1b marker must fail before creating any v34
    # journal or replacing its recovery evidence.
    (root/life.old.MARKER).write_text('{"unreadable":"unfinished round1b"}')
    before=tree(root)
    with pytest.raises(ConflictError):migrate_canonical_to_current(root,confirmation=f'MIGRATE CANONICAL {realm}')
    assert tree(root)==before and not (root/life.MARKER).exists()
