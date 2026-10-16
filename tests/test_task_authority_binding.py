"""Synthetic canonical task/credential/claim lifecycle; no live stores."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import time

import pytest

# Run against this exact Runtime checkout with the caller's admitted Astrid source.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from runtime_protocol.auth import CredentialStore
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import AuthorizationError, ConflictError, ForbiddenError, LeaseError, ValidationError
from runtime_protocol.paired_session import PairedSessionAuthority
from runtime_protocol.store import RealmStore
from runtime_protocol.task_authority import TaskAuthorityBinding
from runtime_protocol.upgrade import migrate_canonical_to_current

SCOPES = ['handshake', 'projects:read', 'projects:write', 'tasks:read', 'tasks:write']
CAP = 'rendering.render'
DIGEST = 'sha256:' + hashlib.sha256(CAP.encode()).hexdigest()


@pytest.fixture
def pair(tmp_path):
    RealmStore.initialize(tmp_path / 'realm').close()
    d = RuntimeDaemon(tmp_path / 'realm', support_root=tmp_path / 'support').start()
    s = d.service
    p = s.create_project({'slug': 'one', 'name': 'Synthetic one'}, idempotency_key='p')['id']
    q = s.create_project({'slug': 'two', 'name': 'Synthetic two'}, idempotency_key='q')['id']
    s.select_project('connector', p)
    token, _ = d.credentials.provision_connector('connector', SCOPES, connector_id='c',
        realm_id=s.realm['id'], expires_at=time.time()+120)
    context = dict(pair_id='pair', connector_id='c', generation=1, realm_id=s.realm['id'], expires_at=int((time.time()+90)*1000))
    owner = d.httpd.paired_sessions
    identity = d.credentials.require(token, 'tasks:write')
    grant = owner.authenticate(identity, json.dumps(context), s)
    binding = owner.task_binding(grant, project_id=p, operation=CAP)
    s.register_capability({'capability_id': CAP, 'definition_digest': DIGEST})
    s.register_executor({'executor_id': 'worker', 'max_concurrency': 2, 'capabilities': [CAP]})
    try:
        yield d, p, q, token, context, grant, binding
    finally:
        d.stop()


def admit(pair, key='task', binding=None):
    d,p,_,_,_,_,original = pair
    return d.service.create_task(dict(capability_id=CAP, capability_digest=DIGEST, spec={}, project=p,
        idempotency_key=key), authority_binding=binding or original)


def claim(pair, key='claim'):
    s=pair[0].service
    return s.claim_next(dict(executor_id='worker', capability_ids=[CAP], runtime_epoch=s.health()['runtime_epoch']), idempotency_key=key)


def lease(c):
    return {k:c[k] for k in ('lease_id','fence','runtime_epoch')}


def test_private_binding_admission_receipt_replay_and_nonbearer_claim(pair):
    d,p,q,token,ctx,g,b=pair
    value=admit(pair)
    task_id=value['task']['id']
    raw=d.service.store.conn.execute('SELECT authority_binding_json FROM tasks WHERE id=?',(task_id,)).fetchone()[0]
    stored=json.loads(raw)
    assert stored == b.record()
    assert token not in raw and g.handle not in raw
    assert 'authority_binding_json' not in json.dumps(value)
    assert 'credential_binding' not in json.dumps(d.service._task_resource(value))
    assert admit(pair)['task']['id']==task_id
    other = d.httpd.paired_sessions.authenticate(d.credentials.load(token), json.dumps({**ctx, 'pair_id':'different'}), d.service)
    other_binding = d.httpd.paired_sessions.task_binding(other, project_id=p, operation=CAP)
    with pytest.raises(ConflictError):
        admit(pair,binding=other_binding)
    c=claim(pair)
    assert c['claim_authority']['task_id']==task_id
    assert c['claim_authority']['executor_id']=='worker'
    assert c['claim_authority']['project_id']==p
    assert 'claim_authority' not in c['spec']
    assert 'credential_binding' not in json.dumps(c) and g.handle not in json.dumps(c)
    assert c['lease_expires_at'] <= __import__('datetime').datetime.fromtimestamp(b.expiry,__import__('datetime').timezone.utc).isoformat(timespec='milliseconds')
    h=d.service.heartbeat_attempt(c['attempt_id'],lease(c),idempotency_key='renew')
    assert h['data']['claim_authority']['admission_digest']==c['claim_authority']['admission_digest']
    assert claim(pair)['attempt_id']==c['attempt_id']


@pytest.mark.parametrize('mutation', ['rotation','disabled','scope','expiry','generation','issuer','connector','realm'])
def test_exact_authority_rechecked_on_claim_and_renewal(pair,mutation):
    d,p,q,token,ctx,g,b=pair
    admit(pair)
    c=claim(pair)
    if mutation=='rotation':
        d.credentials.provision_connector('connector',SCOPES,connector_id='c',realm_id=d.service.realm['id'],expires_at=time.time()+120,rotate=True)
    elif mutation=='disabled': d.credentials.disable_actor('connector')
    elif mutation=='scope':
        meta=d.credentials.actor_metadata('connector'); meta['scopes']=['handshake']; d.credentials._publish('connector',token,meta)
    elif mutation=='expiry':
        meta=d.credentials.actor_metadata('connector'); meta['expires_at']=time.time()-1; d.credentials._publish('connector',token,meta)
    elif mutation in ('connector','realm'):
        meta=d.credentials.actor_metadata('connector')
        meta['connector_assertion']['connector_id' if mutation=='connector' else 'realm_id']='foreign'
        d.credentials._publish('connector',token,meta)
    elif mutation=='generation':
        d.httpd.paired_sessions.authenticate(d.credentials.load(token),json.dumps({**ctx,'pair_id':'new','generation':2}),d.service)
    else: d.httpd.paired_sessions.instance_id='replacement-instance'
    for invoke in (lambda:claim(pair),lambda:d.service.heartbeat_attempt(c['attempt_id'],lease(c),idempotency_key='late-renew'),
                   lambda:d.service.settle_attempt(c['attempt_id'],{**lease(c),'outputs':[]},idempotency_key='late-effect')):
        with pytest.raises((AuthorizationError,ForbiddenError)):
            invoke()
    # Failure reporting remains possible after authority loss.
    result=d.service.fail_attempt(c['attempt_id'],{**lease(c),'error':{'message':'authority ended','retryable':False}},idempotency_key='cleanup-report')
    assert result


@pytest.mark.parametrize('field,value', [('project_id','wrong'),('operation','timeline.update'),('realm_id','wrong'),('credential_binding','wrong'),('actor_id','wrong'),('generation',2)])
def test_trusted_binding_cannot_be_retargeted(pair,field,value):
    with pytest.raises((AuthorizationError,ForbiddenError,ValidationError)):
        admit(pair,binding=replace(pair[-1],**{field:value}))


@pytest.mark.parametrize('location', ['top','spec','nested','execution_request'])
def test_caller_authority_spoof_is_rejected(pair,location):
    d,p,*_=pair
    body=dict(capability_id=CAP,project=p,spec={},idempotency_key='spoof')
    if location=='top': body['authority_binding_json']=pair[-1].record()
    elif location=='spec':body['spec']['claim_authority']={'allowed':True}
    elif location=='nested':body['spec']['params']={'authority_instance_id':'spoof'}
    else:body['execution_request']={'authority_binding':pair[-1].record()}
    with pytest.raises(ValidationError):d.service.create_task(body,authority_binding=pair[-1])


def test_legacy_readability_is_not_implicit_host_ownership(pair):
    d,p,*_=pair
    task=d.service.create_task(dict(capability_id=CAP,project=p,spec={},idempotency_key='legacy'))
    assert d.service.task(task['task']['id'])
    assert claim(pair) is None
    assert d.service.task(task['task']['id'])['task']['waiting_reason']=='task_authority_missing'


def test_revoke_fences_replays_cancels_owned_task_and_is_durable(pair):
    d,p,q,token,ctx,g,b=pair
    value=admit(pair);c=claim(pair)
    d.httpd.paired_sessions.revoke(g)
    assert d.service.task(value['task']['id'])['task']['status']=='cancelled'
    with pytest.raises((ForbiddenError,LeaseError)):claim(pair)
    with pytest.raises((ForbiddenError,LeaseError)):
        d.service.heartbeat_attempt(c['attempt_id'],lease(c),idempotency_key='revoked-heartbeat')
    fresh=PairedSessionAuthority()
    identity=d.credentials.load(token)
    with pytest.raises(ForbiddenError) as e:fresh.authenticate(identity,json.dumps(ctx),d.service)
    assert e.value.details['decision']['code']=='project_grant_revoked'
    # A new CredentialStore lifetime observes the durable exact pair marker.
    reopened=CredentialStore(d.credentials.root)
    with pytest.raises(ForbiddenError):fresh.authenticate(reopened.load(token),json.dumps(ctx),d.service)
    d.credentials.provision_connector('connector',SCOPES,connector_id='c',realm_id=d.service.realm['id'],expires_at=time.time()+120,rotate=True)
    assert d.credentials.actor_metadata('connector')['paired_revocations']


def test_offline_v28_adds_only_nullable_private_column(tmp_path):
    root=tmp_path/'realm';store=RealmStore.initialize(root);realm=store.ensure_realm('Synthetic')['id'];store.close()
    conn=sqlite3.connect(root/'realm.sqlite3')
    conn.execute('ALTER TABLE tasks DROP COLUMN authority_binding_json')
    conn.execute('UPDATE runtime_schema SET version=28');conn.commit();conn.close()
    result=migrate_canonical_to_current(root,confirmation='MIGRATE CANONICAL '+realm)
    assert result['source_schema_version']==28 and result['target_schema_version']==29
    assert result['steps'][0]['added_columns']==['tasks.authority_binding_json']
    assert not migrate_canonical_to_current(root,confirmation='MIGRATE CANONICAL '+realm)['changed']


def test_revoked_pair_marker_survives_actor_revoke_and_explicit_reprovision(pair):
    d,p,q,token,ctx,g,b=pair
    d.httpd.paired_sessions.revoke(g)
    d.credentials.revoke('connector')
    assert not d.credentials.path_for('connector').exists()
    token,_=d.credentials.provision_connector('connector',SCOPES,connector_id='c',realm_id=d.service.realm['id'],expires_at=time.time()+120)
    with pytest.raises(ForbiddenError):
        PairedSessionAuthority().authenticate(d.credentials.load(token),json.dumps(ctx),d.service)


def test_denied_legacy_task_does_not_starve_an_authenticated_task(pair):
    d,p,*_=pair
    legacy=d.service.create_task(dict(capability_id=CAP,project=p,spec={},idempotency_key='legacy'))
    valid=admit(pair)
    assert claim(pair)['task_id']==valid['task']['id']
    assert d.service.task(legacy['task']['id'])['task']['waiting_reason']=='task_authority_missing'


@pytest.mark.parametrize('field,wrong',[('lease_id','foreign'),('fence',999),('runtime_epoch',999)])
def test_exact_lease_tuple_rejects_heartbeat_and_settlement(pair,field,wrong):
    d=pair[0];admit(pair);c=claim(pair);bad={**lease(c),field:wrong}
    with pytest.raises(LeaseError):d.service.heartbeat_attempt(c['attempt_id'],bad,idempotency_key='bad-heartbeat')
    with pytest.raises(LeaseError):d.service.settle_attempt(c['attempt_id'],bad,idempotency_key='bad-effect')


def test_original_issuer_lifetime_is_not_replaced_after_runtime_restart(pair):
    d,p,q,token,ctx,g,b=pair
    task=admit(pair)['task']['id']
    root,support=d.root,d.support_root
    d.stop()
    fresh=RuntimeDaemon(root,support_root=support).start()
    try:
        fresh.credentials.require(token,'tasks:write')
        fresh.service.select_project('connector',p)
        fresh.httpd.paired_sessions.authenticate(fresh.credentials.load(token),json.dumps(ctx),fresh.service)
        with pytest.raises(ForbiddenError) as e:fresh.service._assert_task_authority(task)
        assert e.value.details['decision']['code']=='paired_issuer_unresolved'
    finally:fresh.stop()


def test_delegated_child_retains_exact_parent_authority_and_cannot_widen(pair):
    d,p,q,token,ctx,g,b=pair;s=d.service
    body=dict(capability_id=CAP,capability_digest=DIGEST,spec={},project=p,idempotency_key='parent',
        child_delegation=dict(capabilities=[dict(capability_id=CAP,capability_digest=DIGEST)],targets=[dict(kind='default')],input_object_ids=[]))
    s.create_task(body,authority_binding=b)
    parent=claim(pair)
    identity=dict(actor='worker',scopes=['worker:execute'])
    issued=s.issue_child_authority(parent['attempt_id'],lease(parent),identity=identity)
    child=s.admit_delegated_child(dict(authority=issued['authority'],task=dict(capability_id=CAP,capability_digest=DIGEST,spec={})),idempotency_key='child',identity=identity)
    binding=s._task_authority(child['task']['id'])
    assert binding.parent_task_id==parent['task_id'] and binding.parent_attempt_id==parent['attempt_id']
    assert (binding.authority_instance_id,binding.pair_id,binding.credential_binding,binding.expiry)==(b.authority_instance_id,b.pair_id,b.credential_binding,b.expiry)
    d.httpd.paired_sessions.revoke(g)
    with pytest.raises((ForbiddenError,LeaseError,AuthorizationError)):
        s.admit_delegated_child(dict(authority=issued['authority'],task=dict(capability_id=CAP,capability_digest=DIGEST,spec={})),idempotency_key='child',identity=identity)


def test_typed_unpaired_and_explicit_host_owned_are_real_authority(pair):
    d,p,*_=pair;s=d.service
    identity=d.credentials.require(d.token,'tasks:write')
    identity={**identity,'_credential_binding':d.credentials._sha256(d.token.encode())}
    binding=s.task_authority_for_identity(identity,project_id=p,operation=CAP)
    assert binding.kind=='credential' and binding.actor_id=='owner'
    task=s.create_task(dict(capability_id=CAP,capability_digest=DIGEST,project=p,spec={},idempotency_key='owner'),authority_binding=binding)
    assert claim(pair)['task_id']==task['task']['id']
    task=s.create_task(dict(capability_id=CAP,capability_digest=DIGEST,project=p,spec={},idempotency_key='internal'),_host_owned=True)
    assert s._task_authority(task['task']['id']).kind=='host_owned'
    assert claim(pair,'second-claim')['task_id']==task['task']['id']
    worker_identity=d.credentials.load(d.worker_credential_path.read_text().strip())
    with pytest.raises((AuthorizationError,ForbiddenError)):
        s.task_authority_for_identity(worker_identity,project_id=p,operation=CAP)


def test_private_authority_cannot_be_swapped_after_canonical_admission(pair):
    d,p,q,token,ctx,g,b=pair
    task=admit(pair)['task']['id']
    other=d.httpd.paired_sessions.authenticate(d.credentials.load(token),json.dumps({**ctx,'pair_id':'other-pair'}),d.service)
    foreign=d.httpd.paired_sessions.task_binding(other,project_id=p,operation=CAP)
    d.service.store.conn.execute('UPDATE tasks SET authority_binding_json=? WHERE id=?',(json.dumps(foreign.record()),task))
    assert claim(pair) is None
    assert d.service.task(task)['task']['waiting_reason']=='task_admission_binding_mismatch'


def test_lease_is_capped_by_current_shortened_credential_expiry(pair):
    d,p,q,token,ctx,g,b=pair
    admit(pair)
    metadata=d.credentials.actor_metadata('connector')
    metadata['expires_at']=time.time()+5
    d.credentials._publish('connector',token,metadata)
    c=claim(pair)
    from datetime import datetime,timezone
    assert datetime.fromisoformat(c['lease_expires_at']).timestamp() <= metadata['expires_at']
    renewed=d.service.heartbeat_attempt(c['attempt_id'],{**lease(c),'lease_seconds':60},idempotency_key='short-renew')['data']
    assert datetime.fromisoformat(renewed['lease_expires_at']).timestamp() <= metadata['expires_at']


def test_claim_client_decode_and_metadata_use_the_actual_contract_inputs(pair):
    import runpy
    import astrid
    from banodoco_workspace_client.generated import AttemptFence,SCHEMA_DIGEST as CLIENT_DIGEST
    from runtime_protocol.contract_metadata import SCHEMA_DIGEST
    root=Path(__file__).resolve().parents[1]
    gen=runpy.run_path(str(root/'generators/generate.py'))
    gen['contract_digest'].__globals__['OPCALL_SCHEMA']=Path(astrid.__file__).resolve().parents[1]/'schemas/change-contract/opcall.schema.json'
    assert gen['contract_digest']()==SCHEMA_DIGEST==CLIENT_DIGEST
    admit(pair);c=claim(pair)
    decoded=AttemptFence.from_json(c)
    assert decoded.claim_authority==c['claim_authority']
    assert decoded.executor_id==c['executor_id']


def test_child_renewal_cannot_outlive_parent_lease_before_reaping(pair):
    from datetime import datetime,timedelta,timezone
    d,p,q,token,ctx,g,b=pair;s=d.service
    body=dict(capability_id=CAP,capability_digest=DIGEST,spec={},project=p,idempotency_key='parent-renewal',
        child_delegation=dict(capabilities=[dict(capability_id=CAP,capability_digest=DIGEST)],targets=[dict(kind='default')],input_object_ids=[]))
    s.create_task(body,authority_binding=b);parent=claim(pair)
    identity=dict(actor='worker',scopes=['worker:execute'])
    issued=s.issue_child_authority(parent['attempt_id'],lease(parent),identity=identity)
    s.admit_delegated_child(dict(authority=issued['authority'],task=dict(capability_id=CAP,capability_digest=DIGEST,spec={})),idempotency_key='child-renewal',identity=identity)
    child=claim(pair,'child-claim')
    assert datetime.fromisoformat(child['lease_expires_at']) <= datetime.fromisoformat(parent['lease_expires_at'])
    renewed=s.heartbeat_attempt(child['attempt_id'],lease(child),idempotency_key='bounded-child-renewal',identity=identity)['data']
    assert datetime.fromisoformat(renewed['lease_expires_at']) <= datetime.fromisoformat(parent['lease_expires_at'])
    expired=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
    s.store.conn.execute('UPDATE tasks SET lease_expires_at=? WHERE id=?',(expired,parent['task_id']))
    s.store.conn.execute('UPDATE attempts SET lease_expires_at=? WHERE id=?',(expired,parent['attempt_id']))
    # No claim/reaper has run. A still-live child must not renew its expired parent.
    with pytest.raises(LeaseError):
        s.heartbeat_attempt(child['attempt_id'],lease(child),idempotency_key='late-child-renewal',identity=identity)
