"""Pinned schema, full-set activation, backup and conservative rollback tests."""
import sqlite3
import json

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


def test_old_binary_refuses_v34_without_mutating(tmp_path):
    import os,subprocess,sys
    from pathlib import Path
    root=tmp_path/'realm';RealmStore.initialize(root).close();before=tree(root)
    import io,tarfile
    old=tmp_path/'old-runtime';old.mkdir()
    project=Path(__file__).resolve().parents[1]
    archive=subprocess.check_output(['git','archive','1a275bb339ae897e52a5be5e1da99e846e402037','runtime_protocol','astrid_runtime'],cwd=project)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:tar.extractall(old,filter='data')
    program="from runtime_protocol.store import RealmStore; from runtime_protocol.errors import RealmAdmissionError; import sys\ntry: RealmStore(sys.argv[1])\nexcept RealmAdmissionError: sys.exit(0)\nelse: sys.exit(2)"
    environment={'PYTHONPATH':str(old),'PATH':os.defpath}
    result=subprocess.run([sys.executable,'-c',program,str(root)],cwd=old,env=environment,capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert tree(root)==before


def test_replacement_refuses_lost_custody_and_preserves_identical_snapshot(world,tmp_path):
    from runtime_protocol.backup import create_backup,restore_backup
    w=world;s=w['service'];key=b'custody-replacement-fixture-key-32'
    old=tmp_path/'old-backup';create_backup(s.store,old,key=key)
    stale=tmp_path/'stale';restore_backup(old,stale,key=key)
    r=arm(w)
    before=tree(w['root'])
    with pytest.raises(ConflictError):life.assert_replacement_preserves_custody(w['root'],stale)
    assert tree(w['root'])==before
    current=tmp_path/'current-backup';create_backup(s.store,current,key=key)
    preserved=tmp_path/'preserved';restore_backup(current,preserved,key=key)
    life.assert_replacement_preserves_custody(w['root'],preserved)
    retained(w)


def test_operator_activation_keeps_requests_closed_until_verified(tmp_path,monkeypatch):
    root=tmp_path/'realm';realm=u33(root)
    migrate_canonical_to_current(root,confirmation=f'MIGRATE CANONICAL {realm}')
    archive,record=life.activation(root)
    record['operator_owned']=True;life.phase(root,archive,record,record['state'])
    life.activate(root,admit=False)
    with pytest.raises(ConflictError):life.check_startup(root)
    monkeypatch.setenv('ASTRID_V33_ACTIVATION',record['operation_id'])
    life.check_startup(root)
    with pytest.raises(ConflictError):life.require_ready(root)
    record=life.activation(root)[1];life.phase(root,archive,record,'ready')
    life.require_ready(root)


def test_real_checkpoint_custody_pins_bytes_and_refuses_resume(world):
    w=world;r=arm(w);s=w['service']
    identity={k:r[k] for k in ('attempt_id','lease_id','fence','runtime_epoch')}
    authorization=s.prepare_reboot(identity)
    b={k:r[k] for k in ('lease_id','fence','runtime_epoch')}
    b.update(nonce=authorization['nonce'],authorization=authorization['nonce'],checkpoint={'pending_journal':'exact bytes'})
    checkpoint=s.checkpoint_attempt(r['attempt_id'],b)
    retained(w)
    row=s.store.custody.row(r['custody_id'])
    refs=json.loads(row['evidence_refs_json'])
    assert any(x['digest']==checkpoint['digest'].removeprefix('sha256:') for x in refs)
    restart(w);restart(w)
    with pytest.raises(ConflictError):w['service'].resume_attempt({'checkpoint_id':checkpoint['checkpoint_id'],'nonce':authorization['nonce'],'authorization':authorization['nonce'],'runtime_epoch':w['service'].health()['runtime_epoch']})
    retained(w)


def test_v34_upgrade_coordinator_preserves_archives_and_provider_gate(tmp_path,monkeypatch):
    from types import SimpleNamespace
    from astrid_runtime.paths import RuntimePaths
    from astrid_runtime.bootstrap import SourceProfile,BootstrapConfig
    from astrid_runtime.operator_upgrade import upgrade_workspace
    from test_operator_upgrade import _Boundary
    from test_timeline_commit_provider import Provider
    from runtime_protocol.service import RuntimeService
    home=tmp_path/'home';home.mkdir()
    paths=RuntimePaths.current(home=home,data_root=tmp_path/'support');paths.ensure_support_dirs()
    root=paths.realms_dir/'realm-1';u33(root)
    # Use a local, isolated prior executable fixture; no machine selection or
    # installed credentials participate in this protocol test.
    checkout=tmp_path/'prior';(checkout/'runtime_protocol').mkdir(parents=True)
    (checkout/'runtime_protocol/__init__.py').write_text('# local fixture executable\n')
    profile=SourceProfile(profile='astrid',runtime_checkout=str(checkout),source_checkout=str(checkout))
    realm=sqlite3.connect(root/'realm.sqlite3').execute('SELECT id FROM realm').fetchone()[0]
    catalog={'version':1,'selected_realm_id':realm,'realms':[{'realm_id':realm,'display_name':'Fixture','data_root':str(root)}],'source_profiles':{'astrid':profile.as_dict()}}
    paths.catalog_path.write_text(json.dumps(catalog));(paths.source_profiles_dir/'astrid.json').write_text(json.dumps(profile.as_dict()))
    (paths.runtime_support/'credentials').mkdir(exist_ok=True)
    (paths.runtime_support/'credentials/owner.token').write_text('fixture-owner-token')
    boundary=_Boundary(paths,live=False)
    def start(target_paths,_boundary,_config):
        service=RuntimeService(root)
        try:
            with pytest.raises(ConflictError):service._assert_mutation_admitted()
            service.register_timeline_commit_provider(Provider())
            assert life.activation(root)[1]['provider_verified']
        finally:service.close()
        discovery={'pid':2345,'active_realm':realm,'endpoint':'http://127.0.0.1:1235','runtime_instance_id':'fixture-2','process_birth_id':'birth-2','realm_root':str(root)}
        target_paths.discovery_path.write_text(json.dumps(discovery));target_paths.instance_lock_path.write_text(json.dumps(discovery|{'realm_id':realm}))
        return SimpleNamespace(endpoint=discovery['endpoint'],pid=2345,runtime_instance_id='fixture-2')
    monkeypatch.setattr('astrid_runtime.operator_upgrade._bootstrap_locked',start)
    result=upgrade_workspace(paths,boundary,BootstrapConfig(source_profile=profile))
    assert result['ok'] and life.activation(root)[1]['state']=='ready'
    assert inspect_realm_schema(root)['kind']=='V34'
    assert life.activation(root)[1]['source']['kind']=='U33'


def test_rollback_preserves_potentially_live_supervisor_and_post_backup_writes(world):
    from runtime_protocol.service import RuntimeService
    from test_attempt_custody_v34 import SupervisorDouble
    w=world;r=arm(w);supervisor=SupervisorDouble()
    w['service'].store.custody.dispatch(r['custody_id'],supervisor)
    assert supervisor.invoked==1
    w['service'].close()
    identity=inspect_realm_schema(w['root'])
    with life.old.sqlite_observation(w['root']) as observation:
        archive,record=life.begin(w['root'],identity,observation)
    life.phase(w['root'],archive,record,'ready')
    w['service']=RuntimeService(w['root'])
    w['service'].store.conn.execute("INSERT INTO user_preferences VALUES ('owner','post-backup','must survive',1,'t','t')")
    before=tree(w['root'])
    with pytest.raises(ConflictError):life.rollback(w['root'],archive)
    assert tree(w['root'])==before
    restart(w);restart(w);retained(w)
    assert supervisor.invoked==1
    assert w['service'].store.conn.execute('SELECT content FROM user_preferences').fetchone()[0]=='must survive'
