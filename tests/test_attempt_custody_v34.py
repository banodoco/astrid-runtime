"""Custody acceptance with real keys and a protocol-only supervisor double.

The double demonstrates Runtime's command protocol, not deployed supervisor
behaviour. No target, installer, external installation, or manifest is used.
"""
import base64
import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from runtime_protocol import custody as module
from runtime_protocol.custody import IDENTITY, Custody, digest, signed_bytes
from runtime_protocol.errors import AuthorizationError, ConflictError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore

OWNER = {'actor': 'owner', 'scopes': ['admin']}
D = hashlib.sha256(b'custody-capability').hexdigest()
S = hashlib.sha256(b'custody-source').hexdigest()


def public(key):
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


@pytest.fixture
def world(tmp_path):
    root = tmp_path / 'realm'
    RealmStore.initialize(root).close()
    s = RuntimeService(root)
    s.register_capability({'capability_id': 'custody.test', 'definition_digest': 'sha256:' + D,
                           'required_resource_keys': ['installer']})
    s.register_executor({'executor_id': 'installer-worker', 'capabilities': ['custody.test'],
                         'source_digest': 'sha256:' + S, 'resource_keys': ['installer']}, idempotency_key='register')
    key, controller = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    s.store.custody.enroll_key('install-old', 'h2-1', public(key), identity=OWNER)
    s.store.custody.enroll_key('install-old', 'controller-1', public(controller), identity=OWNER, role='controller')
    binding = {'realm_id': s.realm['id'], 'installation_id': 'install-old', 'capability_digest': D,
               'source_digest': S, 'definition_digest': D, 'executor_incarnation': 'birth-1'}
    created = s.create_task({'capability_id': 'custody.test', 'capability_digest': 'sha256:' + D,
                'idempotency_key': 'task', 'spec': {'install_binding': binding}})
    a = s.claim_next({'executor_id': 'installer-worker', 'capability_ids': ['custody.test'],
                      'runtime_epoch': s.health()['runtime_epoch']}, idempotency_key='claim')
    assert a and a['task_id'] == created['task']['id']
    request = {k: a[k] for k in ('task_id','attempt_id','lease_id','fence','runtime_epoch')}
    request.update(binding, install_binding=binding, executor_id='installer-worker',
                supervisor_identity={'boot_id':'supervisor-boot','pid_start_time':'123','launch_token_digest':D},
                launch_permit_expires_at=(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat())
    w = {'service': s, 'root': root, 'request': request, 'key': key, 'controller': controller, 'attempt': a}
    yield w
    w['service'].close()


def arm(w):
    c = w['service'].store.custody
    result = c.create(w['request'], idempotency_key='arm')
    w['custody_id'] = result['custody_id']
    return c.row(result['custody_id'])


def body(w, *, mode='reconcile', key=None, fencing='external_absence'):
    c = w['service'].store.custody
    r = c.row(w['custody_id'])
    repair = mode != 'reconcile'
    fence_bytes = b'independent owner controller fencing confirmation'
    if repair and not any(x['digest'] == hashlib.sha256(fence_bytes).hexdigest() for x in json.loads(r['evidence_refs_json'])):
        c.stage_evidence(r['custody_id'],fence_bytes,expected_version=r['custody_version'],custody_seq=r['custody_seq']+1,ref='independent-fence')
        r = c.row(w['custody_id'])
    e = {k: r[k] for k in IDENTITY}
    e.update({'repair_version' if repair else 'proof_version': 1,
              'key_id': 'controller-1' if repair else 'h2-1', 'dispatch_intent_id': r['dispatch_intent_id'],
              'launch_permit_id': r['launch_permit_id'], 'expected_custody_version': r['custody_version'],
              'target_recovery_generation': r['recovery_generation']+1, 'nonce': 'nonce-'+str(r['custody_version']),
              'evidence_digests': sorted({x['digest'] for x in json.loads(r['evidence_refs_json'])}),
              'supervisor_identity': json.loads(r['supervisor_identity_json']),
              'launch_permit_revocation': {'permit_id':r['launch_permit_id'], 'revoked':True,'durable_fence_digest':D},
              'callback_fence': {'fenced':True,'durable_fence_digest':D}, 'timestamp': datetime.now(timezone.utc).isoformat(),
              'mode': mode})
    if repair:
        e['fencing_evidence'] = {'kind':fencing, 'evidence_digest':hashlib.sha256(fence_bytes).hexdigest()}
        if fencing == 'isolated_replacement':
            e['fencing_evidence']['replacement_installation_id'] = 'install-replacement'
    else:
        e.update(child_births=[{'boot_id':'boot-1','pid':1234,'pid_start_time':'birth-1234'}],
                 pending_callbacks=['callback-1'], callbacks_revoked=['callback-1'],
                 observed_stops=[{'boot_id':'boot-1','pid':1234,'pid_start_time':'birth-1234'}],
                 complete_child_inventory=True, complete_callback_inventory=True)
    signer = key or (w['controller'] if repair else w['key'])
    proof = {'envelope':e, 'signature':base64.b64encode(signer.sign(signed_bytes(e, repair=repair))).decode()}
    return {'custody_id':r['custody_id'], 'mode':mode, 'expected_custody_version':r['custody_version'],
            'old_identity_digest':digest({k:r[k] for k in IDENTITY}), 'target_recovery_generation':r['recovery_generation']+1,
            'proof':proof}


def reconcile(w, b=None, *, replay='recover'):
    return w['service'].reconcile_task_custody(w['request']['task_id'], b or body(w), identity=OWNER, idempotency_key=replay)


def retained(w):
    db = w['service'].store.conn
    r = w['service'].store.custody.row(w['custody_id'])
    assert r['custody_state'] != 'released'
    assert r['stop_confirmed'] == 0
    assert db.execute('SELECT COUNT(*) FROM reservations WHERE task_id=? AND released_at IS NULL', (r['task_id'],)).fetchone()[0] == 1
    a = db.execute('SELECT * FROM attempts WHERE id=?', (r['attempt_id'],)).fetchone()
    assert a['settled'] == 0
    for k in ('lease_id','fence','runtime_epoch','executor_id'):
        assert a[k] == r[k]
    assert r['attempt_id'] == w['attempt']['attempt_id']
    assert r['runtime_epoch'] == w['attempt']['runtime_epoch']
    return r


def restart(w):
    w['service'].close()
    w['service'] = RuntimeService(w['root'])


class SupervisorDouble:
    """Test-only model of durable intent dedup and revoked permit enforcement."""
    def __init__(self):
        self.commands = {}; self.revoked = set(); self.invoked = 0; self.lose_ack = False

    def dispatch(self, command):
        if command['launch_permit_id'] in self.revoked or datetime.fromisoformat(command['launch_permit_expires_at']) <= datetime.now(timezone.utc):
            raise ConflictError('revoked or expired launch permit')
        intent = command['dispatch_intent_id']
        if intent not in self.commands:
            self.commands[intent] = command; self.invoked += 1
        if self.lose_ack:
            raise OSError('lost ACK')
        return {'dispatch_intent_id':intent}

    def query(self, intent):
        return self.commands.get(intent)


def test_real_signature_verification_and_key_rotation(world):
    w=world; arm(w); b=body(w)
    b['proof']['signature'] = base64.b64encode(b'x'*64).decode()
    with pytest.raises(AuthorizationError): reconcile(w,b)
    retained(w)
    new = Ed25519PrivateKey.generate()
    c=w['service'].store.custody
    c.enroll_key('install-old','h2-2',public(new),identity=OWNER,revoke_key_id='h2-1')
    with pytest.raises(AuthorizationError): reconcile(w,body(w))
    w['key']=new
    b=body(w); b['proof']['envelope']['key_id']='h2-2'
    b['proof']['signature']=base64.b64encode(new.sign(signed_bytes(b['proof']['envelope']))).decode()
    result=reconcile(w,b)
    assert result['disposition']=='released_observed_stop' and result['stop_confirmed']==1
    assert c.row(w['custody_id'])['released_seq']==result['custody_seq']


def test_repair_after_key_loss_and_replacement_never_reopens_old_installation(world):
    w=world; arm(w); c=w['service'].store.custody
    c.revoke_key('install-old','h2-1',identity=OWNER)
    with pytest.raises(AuthorizationError): reconcile(w,body(w))
    result=reconcile(w,body(w,mode='repair',fencing='isolated_replacement'))
    assert result['custody_state']=='released' and result['stop_confirmed']==0
    r=c.db.execute('SELECT * FROM custody_installations WHERE installation_id=?',('install-old',)).fetchone()
    assert r['permanent']==r['quarantined']==1
    restart(w); restart(w)
    c=w['service'].store.custody
    with pytest.raises(ConflictError): c.assert_clear(installation_id='install-old')
    c.enroll_key('install-old','new-supervisor',public(Ed25519PrivateKey.generate()),identity=OWNER)
    with pytest.raises(ConflictError): c.assert_clear(installation_id='install-old')
    c.enroll_key('install-replacement','replacement',public(Ed25519PrivateKey.generate()),identity=OWNER)
    c.assert_clear(installation_id='install-replacement')


def test_delayed_launch_rejection_lost_then_authenticated_repair(world):
    w=world; r=arm(w); supervisor=SupervisorDouble()
    c=w['service'].store.custody
    c.update(r['custody_id'],expected_version=1,custody_seq=2,state='dispatching',binding_digest=r['install_binding_digest'],dispatch_intent_id='exact-intent')
    command=c.dispatch_command(c.row(r['custody_id']))
    # The supervisor's durable revocation is a premise represented by the
    # double. The signed controller evidence authorizes Runtime's disposition.
    supervisor.revoked.add(command['launch_permit_id'])
    result=reconcile(w,body(w,mode='lost'))
    assert result['custody_state']=='lost_fenced' and result['stop_confirmed']==0
    retained(w)
    with pytest.raises(ConflictError): supervisor.dispatch(command)
    assert supervisor.invoked==0
    restart(w); restart(w)
    assert reconcile(w,body(w,mode='repair'),replay='repair')['custody_state']=='released'


def test_replay_after_lost_ack_and_compaction(world, monkeypatch):
    w=world; arm(w); b=body(w)
    def crash(self,name):
        if name=='release_committed': raise OSError('lost release ACK')
    with monkeypatch.context() as patch:
        patch.setattr(Custody,'_boundary',crash)
        with pytest.raises(OSError): reconcile(w,b)
    restart(w); restart(w)
    db=w['service'].store.conn
    events=db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
    replay=reconcile(w,b)
    db.execute("UPDATE attempt_custody SET released_at=?",((datetime.now(timezone.utc)-timedelta(days=40)).isoformat(),))
    assert w['service'].store.custody.compact()==1
    assert reconcile(w,b)==replay
    assert w['service'].store.custody.create(w['request'],idempotency_key='arm')['custody_id']==w['custody_id']
    assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0]==events
    assert db.execute('SELECT COUNT(*) FROM custody_receipts').fetchone()[0]>=3
    assert db.execute('SELECT COUNT(*) FROM reservations WHERE released_at IS NULL').fetchone()[0]==0


@pytest.mark.parametrize('field,value',[('realm_id','foreign'),('installation_id','foreign'),('executor_incarnation','foreign'),('runtime_epoch',999),('attempt_id','foreign')])
def test_wrong_identity_proofs_refuse_with_zero_writes(world,field,value):
    w=world; arm(w); b=body(w)
    e=b['proof']['envelope'];e[field]=value
    b['proof']['signature']=base64.b64encode(w['key'].sign(signed_bytes(e))).decode()
    before=tuple(w['service'].store.conn.iterdump())
    with pytest.raises(ConflictError): reconcile(w,b)
    assert tuple(w['service'].store.conn.iterdump())==before
    retained(w)


def test_duplicate_conflicting_creates_and_callback_cas(world):
    w=world; r=arm(w); c=w['service'].store.custody
    assert c.create(w['request'],idempotency_key='arm')['custody_id']==r['custody_id']
    changed=copy.deepcopy(w['request']);changed['launch_permit_expires_at']=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()
    with pytest.raises(ConflictError): c.create(changed,idempotency_key='arm')
    with pytest.raises(ConflictError): c.create(w['request'],idempotency_key='different-key')
    update=dict(expected_version=1,custody_seq=2,state='dispatching',binding_digest=r['install_binding_digest'],dispatch_intent_id='intent')
    once=c.update(r['custody_id'],**update)
    assert c.update(r['custody_id'],**update)==once
    with pytest.raises(ConflictError): c.update(r['custody_id'],**(update|{'dispatch_intent_id':'other'}))
    with pytest.raises(ConflictError): c.update(r['custody_id'],**(update|{'custody_seq':3}))
    retained(w)


@pytest.mark.parametrize('path',['claim','task_retry','run_retry','reset','reservation_release','new_task','reconcile_attempt','bare_stop','resume'])
def test_every_b1_bypass_path(world,path):
    w=world;r=arm(w);s=w['service'];db=s.store.conn
    if path=='claim':
        db.execute("UPDATE tasks SET status='queued' WHERE id=?",(r['task_id'],))
        call=lambda:s.store._claim_task(r['task_id'],'installer-worker','new-lease',runtime_epoch=r['runtime_epoch'],allow_provider_recovery=True)
    elif path=='task_retry':
        db.execute("UPDATE tasks SET status='failed' WHERE id=?",(r['task_id'],))
        call=lambda:s.retry_task(r['task_id'],idempotency_key='retry')
    elif path=='run_retry':
        db.execute("UPDATE tasks SET status='failed' WHERE id=?",(r['task_id'],))
        run=db.execute('SELECT run_id FROM tasks WHERE id=?',(r['task_id'],)).fetchone()[0]
        db.execute("UPDATE runs SET status='failed' WHERE id=?",(run,))
        call=lambda:s.store.retry_run(run)
    elif path=='reset': call=lambda:s.store.reset_execution_attempt(r['task_id'])
    elif path=='reservation_release': call=lambda:s.store._release_reservations(r['task_id'])
    elif path=='reconcile_attempt': call=lambda:s.store._reconcile_runtime_attempt(r['task_id'],r['attempt_id'])
    elif path=='new_task': call=lambda:s.store.create_task('custody.test',{'install_binding':w['request']['install_binding']})
    elif path=='bare_stop': call=lambda:s.store.cancel_task(r['task_id'],stop_observed=True)
    else:
        # A valid checkpoint lookup is supplied without involving reboot/host.
        s._checkpoint_row=lambda *args:{'task_id':r['task_id']}
        call=lambda:s.resume_attempt({'nonce':'n','authorization':'a','runtime_epoch':r['runtime_epoch'],'attempt_id':r['attempt_id']})
    with pytest.raises(ConflictError): call()
    retained(w)


@pytest.mark.parametrize('path',['cancel','run_cancel','failure','deadline','restart','completion'])
def test_terminal_paths_hold_without_proof(world,path):
    w=world;r=arm(w);s=w['service'];db=s.store.conn
    if path=='cancel':s.store.cancel_task(r['task_id'])
    elif path=='run_cancel':s.store.cancel_run(db.execute('SELECT run_id FROM tasks WHERE id=?',(r['task_id'],)).fetchone()[0])
    elif path=='failure':s.store.fail_task(r['task_id'],r['lease_id'],{'code':'installer_failed'},attempt_id=r['attempt_id'])
    elif path=='deadline':
        db.execute("UPDATE tasks SET lease_expires_at='2000-01-01T00:00:00+00:00' WHERE id=?",(r['task_id'],));s.store.reap_overdue_leases()
    elif path=='completion':s.store._settle_attempt(r['task_id'],r['lease_id'],{'actual':'success','publication':'exact-pending'},attempt_id=r['attempt_id'])
    else:restart(w)
    assert retained(w)['custody_state']=='unresolved'
    restart(w);restart(w);retained(w)
    assert reconcile(w)['stop_confirmed']==1


def test_concurrent_recovery_commits_one_event_and_generation(world):
    w=world;arm(w);b=body(w)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _:reconcile(w,b),range(2)))
    assert results[0]==results[1]
    c=w['service'].store.custody
    assert c.row(w['custody_id'])['recovery_generation']==1
    assert c.db.execute("SELECT COUNT(*) FROM events WHERE kind='task.custody_released'").fetchone()[0]==1


def test_quota_full_recovery_uses_reserved_budget(world,monkeypatch):
    w=world;arm(w);c=w['service'].store.custody
    monkeypatch.setattr(module,'MAX_EVIDENCE',module.RECOVERY_BUDGET)
    monkeypatch.setattr(module,'MAX_ROWS',1)
    with pytest.raises(ConflictError): c.create(w['request'],idempotency_key='quota-other')
    c.stage_evidence(w['custody_id'],b'pending journal bytes',expected_version=1,custody_seq=2,ref='journal')
    retained(w)
    assert reconcile(w)['custody_state']=='released'


def test_evidence_bounds_and_exhausted_retry_timeout(world,monkeypatch):
    w=world;r=arm(w);c=w['service'].store.custody
    for data,ref in [(b'x'*(module.MAX_OBJECT+1),'ref'),(b'x','x'*129)]:
        with pytest.raises(ValidationError):c.stage_evidence(r['custody_id'],data,expected_version=1,custody_seq=2,ref=ref)
    with pytest.raises(ValidationError):c.update(r['custody_id'],expected_version=1,custody_seq=2,state='unresolved',binding_digest=r['install_binding_digest'],metadata={'large':'x'*65536})
    c.update(r['custody_id'],expected_version=1,custody_seq=2,state='dispatching',binding_digest=r['install_binding_digest'],dispatch_intent_id='intent')
    class Missing:
        invoked=0
        def query(self,intent):self.invoked+=1;raise OSError('supervisor lost')
    supervisor=Missing()
    with pytest.raises(module.UnresolvedTimeout):c.query_dispatch(r['custody_id'],supervisor,sleep=lambda _:None,uniform=lambda a,b:1)
    assert supervisor.invoked==6
    retained(w)


@pytest.mark.parametrize('boundary',['before_create_commit','create_committed','before_dispatch_intent','dispatch_intent_committed','dispatch_returned','work','actual_stop','proof_staged','before_release_commit','release_committed'])
def test_v34_crash_points_two_successive_restarts(world,monkeypatch,boundary):
    w=world; supervisor=SupervisorDouble();b=None
    def crash(self,name):
        if name==boundary:raise OSError('injected crash '+name)
    with monkeypatch.context() as patch:
        patch.setattr(Custody,'_boundary',crash)
        try:
            arm(w)
            if boundary in {'before_dispatch_intent','dispatch_intent_committed','dispatch_returned'}:
                w['service'].store.custody.dispatch(w['custody_id'],supervisor)
            elif boundary in {'proof_staged','before_release_commit','release_committed'}:
                b=body(w);reconcile(w,b)
            elif boundary=='work':w['service'].store.custody.dispatch(w['custody_id'],supervisor)
            elif boundary=='actual_stop':w['service'].store.custody.dispatch(w['custody_id'],supervisor)
        except OSError:pass
    # A lost create ACK is discovered by the exact idempotency identity.
    rows=w['service'].store.conn.execute('SELECT custody_id FROM attempt_custody').fetchall()
    if not rows:
        assert boundary=='before_create_commit' and supervisor.invoked==0
        restart(w);restart(w)
        assert w['service'].store.conn.execute('SELECT COUNT(*) FROM attempt_custody').fetchone()[0]==0
        with pytest.raises(ConflictError): arm(w)
        task=w['service'].store.get_task(w['request']['task_id'])['task']
        assert task['status']=='queued'
        assert w['service'].store.conn.execute('SELECT settled FROM attempts WHERE id=?',(w['attempt']['attempt_id'],)).fetchone()[0]==1
        assert supervisor.invoked==0
        return
    else:
        w['custody_id']=rows[0][0]
        restart(w);restart(w)
    c=w['service'].store.custody;r=c.row(w['custody_id'])
    if boundary=='release_committed':
        events=c.db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        assert reconcile(w,b)['custody_state']=='released'
        assert c.db.execute('SELECT COUNT(*) FROM events').fetchone()[0]==events
    else:
        retained(w)
        if b is not None:
            assert reconcile(w,b)['custody_state']=='released'
        else:assert reconcile(w)['custody_state']=='released'
    assert supervisor.invoked==(1 if boundary in {'dispatch_returned','work','actual_stop'} else 0)
    assert c.db.execute("SELECT COUNT(*) FROM events WHERE kind='task.custody_released'").fetchone()[0]==1


def test_exact_pending_publication_bytes_survive_restart_and_no_late_overwrite(world):
    w=world;r=arm(w);s=w['service'];payload=b'installer output before any manifest'
    b={'lease_id':r['lease_id'],'fence':r['fence'],'runtime_epoch':r['runtime_epoch'],
       'outputs':[{'name':'output','kind':'object','digest':'sha256:'+hashlib.sha256(payload).hexdigest(),
                   'size':len(payload),'media_type':'application/octet-stream','data_base64':base64.b64encode(payload).decode()}],
       'result':{'actual_install_outcome':'success','pending_journal_identity':'exact-job-and-journal'}}
    result=s.settle_attempt(r['attempt_id'],b,idempotency_key='exact-publication')
    assert result is not None
    c=s.store.custody;row=retained(w)
    publication=[x for x in json.loads(row['evidence_refs_json']) if x['ref'].startswith('publication:')]
    assert len(publication)==1
    exact=s.cas.read(publication[0]['digest'])
    assert json.loads(exact)['body']==b
    pending=row['pending_publication_json']
    s.store.cancel_task(r['task_id'])
    assert c.row(r['custody_id'])['pending_publication_json']==pending
    restart(w);restart(w)
    assert w['service'].cas.read(publication[0]['digest'])==exact
    assert retained(w)['pending_publication_json']==pending
    reconcile(w)
    with pytest.raises(ConflictError):
        w['service'].store.custody.update(r['custody_id'],expected_version=1,custody_seq=999,state='active',binding_digest=r['install_binding_digest'],dispatch_intent_id='late')


def test_no_external_supervisor_call_inside_transaction_lost_launch_ack_queries_exact_intent(world):
    w=world;arm(w);s=w['service'];supervisor=SupervisorDouble();supervisor.lose_ack=True
    original=supervisor.dispatch
    def dispatch(command):
        assert not s.store.conn.in_transaction
        return original(command)
    supervisor.dispatch=dispatch
    with pytest.raises(OSError):s.store.custody.dispatch(w['custody_id'],supervisor)
    r=retained(w);intent=r['dispatch_intent_id']
    restart(w);restart(w)
    assert w['service'].store.custody.query_dispatch(r['custody_id'],supervisor)['dispatch_intent_id']==intent
    assert supervisor.invoked==1
    with pytest.raises(ConflictError):w['service'].store.custody.dispatch(r['custody_id'],supervisor)
    assert supervisor.invoked==1


def test_separate_repair_signer_and_owner_authorization(world):
    w=world;arm(w);c=w['service'].store.custody
    with pytest.raises(ConflictError):c.enroll_key('install-old','same-signer',public(w['key']),identity=OWNER,role='controller')
    with pytest.raises(AuthorizationError):c.enroll_key('install-old','worker-key',public(w['key']),identity={'actor':'worker','scopes':['worker:execute']})
    with pytest.raises(AuthorizationError):c.reconcile(w['request']['task_id'],body(w),idempotency_key='unauthorized',identity={'actor':'worker','scopes':[]})
    retained(w)


def test_reconcile_timeout_and_reference_bound_never_prove_stop(world,monkeypatch):
    w=world;r=arm(w);c=w['service'].store.custody
    monkeypatch.setattr(module,'MAX_REFS',2)
    c.stage_evidence(r['custody_id'],b'one',expected_version=1,custody_seq=2,ref='one')
    with pytest.raises(ConflictError):c.stage_evidence(r['custody_id'],b'two',expected_version=2,custody_seq=3,ref='two')
    b=body(w)
    monotonic=module.time.monotonic
    start=monotonic();ticks=iter([start,start,start+31])
    with monkeypatch.context() as patch:
        patch.setattr(module.time,'monotonic',lambda:next(ticks,start+31))
        with pytest.raises(module.UnresolvedTimeout):reconcile(w,b)
    retained(w)
    assert c.compact()==0
    assert reconcile(w,b)['custody_state']=='released'


def test_full_realm_refuses_new_installation_before_dispatch_then_recovers(world,monkeypatch):
    w=world;r=arm(w);s=w['service'];c=s.store.custody
    key=Ed25519PrivateKey.generate()
    c.enroll_key('other-installation','other-supervisor',public(key),identity=OWNER)
    s.register_executor({'executor_id':'other-worker','capabilities':['custody.test'],'source_digest':'sha256:'+S,'resource_keys':['installer']},idempotency_key='other-worker')
    binding=w['request']['install_binding'] | {'installation_id':'other-installation','executor_incarnation':'other-birth'}
    task=s.create_task({'capability_id':'custody.test','capability_digest':'sha256:'+D,'spec':{'install_binding':binding},'idempotency_key':'other-task'})
    attempt=s.claim_next({'executor_id':'other-worker','capability_ids':['custody.test'],'runtime_epoch':s.health()['runtime_epoch']},idempotency_key='other-claim')
    request=w['request'] | binding | {k:attempt[k] for k in ('task_id','attempt_id','lease_id','fence','runtime_epoch')} | {'executor_id':'other-worker','install_binding':binding}
    supervisor=SupervisorDouble()
    with monkeypatch.context() as patch:
        patch.setattr(module,'MAX_ROWS',1)
        with pytest.raises(ConflictError,match='quota'):c.create(request,idempotency_key='quota-new')
        assert supervisor.invoked==0
        retained(w)
        assert reconcile(w)['custody_state']=='released'
        other=c.create(request,idempotency_key='quota-new')
        assert other['custody_state']=='armed'
    assert c.db.execute("SELECT COUNT(*) FROM attempt_custody WHERE custody_state<>'released'").fetchone()[0]==1


def test_released_tombstone_refuses_different_recovery_and_stale_evidence(world):
    w=world;r=arm(w);b=body(w);reconcile(w,b)
    with pytest.raises(ConflictError):reconcile(w,b|{'mode':'lost'},replay='different')
    with pytest.raises(ConflictError):w['service'].store.custody.stage_evidence(r['custody_id'],b'late',expected_version=1,custody_seq=2,ref='late')
    assert w['service'].store.custody.row(r['custody_id'])['stop_confirmed']==1


def test_actual_wall_timeout_returns_without_stuck_transport(world,monkeypatch):
    import threading,time
    w=world;r=arm(w);gate=threading.Event()
    class Stuck:
        def dispatch(self,command):gate.wait();return {'dispatch_intent_id':command['dispatch_intent_id']}
    monkeypatch.setattr(module,'INVOCATION_SECONDS',0.02)
    start=time.monotonic()
    try:
        with pytest.raises(module.UnresolvedTimeout):w['service'].store.custody.dispatch(r['custody_id'],Stuck())
        assert time.monotonic()-start<1
        retained(w)
    finally:gate.set()


def test_cancellation_racing_staged_recovery_keeps_exact_lineage(world,monkeypatch):
    w=world;r=arm(w);b=body(w)
    def cancel(self,name):
        if name=='proof_staged':
            self.store.cancel_task(r['task_id'])
            retained(w)
    with monkeypatch.context() as patch:
        patch.setattr(Custody,'_boundary',cancel)
        result=reconcile(w,b)
    assert result['custody_state']=='released'
    assert result['recovery_generation']==1
    assert w['service'].store.conn.execute("SELECT COUNT(*) FROM events WHERE kind='task.custody_released'").fetchone()[0]==1


def test_conflicting_concurrent_recovery_only_one_commits(world):
    w=world;arm(w);first=body(w);second=copy.deepcopy(first)
    e=second['proof']['envelope'];e['nonce']='competing-recovery'
    second['proof']['signature']=base64.b64encode(w['key'].sign(signed_bytes(e))).decode()
    def recover(item):
        b,key=item
        try:return reconcile(w,b,replay=key)
        except ConflictError:return 'conflict'
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(recover,[(first,'first'),(second,'second')]))
    assert sum(isinstance(result,dict) for result in results)==1
    assert results.count('conflict')==1
    assert w['service'].store.custody.row(w['custody_id'])['recovery_generation']==1
    assert w['service'].store.conn.execute("SELECT COUNT(*) FROM events WHERE kind='task.custody_released'").fetchone()[0]==1
