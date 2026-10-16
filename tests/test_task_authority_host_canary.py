"""Real paired HTTP admission through ordinary Astrid host; synthetic command only."""
import json
import errno
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys
import time
from urllib.request import Request, urlopen

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore
from astrid.core.execution import generic_host as gh

SCOPES=['handshake','projects:read','projects:write','tasks:read','tasks:write','objects:read']


def request(d, token, context, body, key):
    req=Request(d.endpoint+'/v1/tasks',data=json.dumps(body).encode(),headers={
        'Authorization':'Bearer '+token,'X-Reigh-Paired-Session':json.dumps(context),
        'Content-Type':'application/json','Idempotency-Key':key})
    with urlopen(req,timeout=10) as r:return json.load(r)


@pytest.fixture
def flow(tmp_path, request):
    RealmStore.initialize(tmp_path/'realm').close()
    d=RuntimeDaemon(tmp_path/'realm',support_root=tmp_path/'support').start()
    try:
        pack=tmp_path/'pack';pack.mkdir()
        outside=tmp_path/'synthetic-credential.txt';outside.write_text('synthetic-outside')
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(0.1)
        configuration=getattr(request, 'param', 0.35)
        delegated=isinstance(configuration,dict) and configuration.get('delegation') is True
        module=isinstance(configuration,dict) and configuration.get('module') is True
        delay=configuration.get('delay', 0.35) if isinstance(configuration,dict) else configuration
        probe = """
import errno,json,os,socket,subprocess,sys,time
from pathlib import Path
def check(operation):
    try:
        operation()
        return 0
    except OSError as e:
        return e.errno
outside,port=__OUTSIDE__,__PORT__
r={'read':check(lambda:Path(outside).read_text()),'write':check(lambda:Path(outside).write_text('forbidden')),
   'egress':check(lambda:socket.create_connection(('127.0.0.1',port),timeout=1)),
   'env_spoof': 'HOSTILE_AUTHORITY' in os.environ, 'pid':os.getpid(), 'started':time.monotonic()}
if len(sys.argv)==1:
    child=subprocess.run([sys.executable,'-I','-S','-c',__CHILD__,'descendant'],capture_output=True,text=True,check=True)
    r['descendant']=json.loads(child.stdout)
    __INFLIGHT__
    time.sleep(__DELAY__)
    r['finished']=time.monotonic()
    r['attempt']=str(Path('__OUTPUT__').parent.parent.name)
    Path('__OUTPUT__').write_text(json.dumps(r))
else:
    print(json.dumps(r))
"""
        if delegated:
            probe=probe.replace("if len(sys.argv)==1:\n", """if len(sys.argv)==1:
    from astrid.sdk import _child_bridge
    from astrid.sdk.exceptions import CapabilityInvocationError
    assert _child_bridge._bridge is not None
    try:
        _child_bridge._bridge.status('unowned','unowned')
    except CapabilityInvocationError:
        r['bridge_roundtrip_denied']=True
    else:
        raise AssertionError('foreign child status was accepted')
""")
        marker = "Path('__OUTPUT__').with_name('inflight.json').write_text(json.dumps(r))"
        probe=probe.replace('__INFLIGHT__', marker if isinstance(configuration,dict) and configuration.get('inflight') else 'pass')
        child=probe.replace('__OUTSIDE__' ,repr(str(outside))).replace('__PORT__',str(listener.getsockname()[1]))
        child=child.replace('__CHILD__', "''").replace('__DELAY__','0').replace('__OUTPUT__','unused')
        probe=probe.replace('__OUTSIDE__',repr(str(outside))).replace('__PORT__',str(listener.getsockname()[1]))
        probe=probe.replace('__CHILD__',repr(child)).replace('__DELAY__',str(delay)).replace('__OUTPUT__','{out}/answer.txt')
        argv=['{python_exec}','-c',probe]
        if module:
            package=pack/'executors';package.mkdir();(package/'__init__.py').write_text('')
            module_probe=probe.replace('if len(sys.argv)==1:', 'if len(sys.argv)==2:', 1)
            module_probe=module_probe.replace("'{out}/answer.txt'", 'sys.argv[1]')
            module_probe=module_probe.replace("r['finished']=time.monotonic()", "import astrid; r['admitted_module']=astrid.__file__; r['finished']=time.monotonic()")
            (package/'run.py').write_text(module_probe)
            argv=['{python_exec}','-m','executors.run','{out}/answer.txt']
        # External synthetic command uses the real production command spawn path.
        definition=dict(schema_version=1,id='rendering.render',name='Synthetic paired canary',kind='external',version='1.0',
            command={'argv':argv},
            outputs=[dict(name='answer',type='file',path_template='{out}/answer.txt',artifact_type='text/plain')],
            metadata=dict(resource_keys=[],estimated_scratch_bytes=1))
        (pack/'executor.yaml').write_text(json.dumps(definition))
        client=gh.RuntimeProtocolClient(d.endpoint,d.worker_credential_path.read_text().strip())
        host=gh.GenericPackHost(pack_roots=[pack],client=client,executor_id='astrid-pack-host',attempt_base=tmp_path/'attempts',max_concurrency=2)
        host._fixture_delegation=delegated
        host.discover();host.register()
        projects=[];sessions=[]
        for i in range(2):
            project=d.service.create_project(dict(slug='synthetic-'+str(i),name='Synthetic'),idempotency_key='project-'+str(i))['id']
            actor='connector-'+str(i);d.service.select_project(actor,project)
            token,_=d.credentials.provision_connector(actor,SCOPES,connector_id='connector-'+str(i),realm_id=d.service.realm['id'],expires_at=time.time()+240)
            context=dict(pair_id='pair-'+str(i),connector_id='connector-'+str(i),realm_id=d.service.realm['id'],generation=1,expires_at=int((time.time()+180)*1000))
            projects.append(project);sessions.append((token,context))
        yield d,host,projects,sessions
    finally:
        if 'host' in locals():host.shutdown()
        if 'listener' in locals():listener.close()
        d.stop()


def submit(flow,i,key):
    d,h,projects,sessions=flow
    token,context=sessions[i]
    body=dict(capability_id='rendering.render',capability_digest=h.capabilities['rendering.render'].capability_digest,project=projects[i],spec={})
    if h._fixture_delegation:
        body['child_delegation']=dict(capabilities=[dict(capability_id='rendering.render',capability_digest=h.capabilities['rendering.render'].capability_digest)],targets=[dict(kind='default')],input_object_ids=[])
    return request(d,token,context,body,key)


def test_real_paired_admission_durable_claim_and_ordinary_host_launch(flow):
    d,h,projects,sessions=flow
    first=submit(flow,0,'first')
    assert 'authority_binding_json' not in json.dumps(first)
    one=h.claim_once()
    assert one
    assert d.service.task(first['data']['task_id'])['task']['status']=='completed'
    policy_one=h._confinement_policy
    assert policy_one.claim_binding and policy_one.project.project_root.name=='inputs'
    second=submit(flow,1,'second')
    two=h.claim_once()
    assert two
    assert d.service.task(second['data']['task_id'])['task']['status']=='completed'
    policy_two=h._confinement_policy
    assert policy_one is not policy_two and policy_one.attempt_root != policy_two.attempt_root
    assert dict(policy_one.claim_binding)['project_id']==projects[0]
    assert dict(policy_two.claim_binding)['project_id']==projects[1]
    assert h.last_cleanup_receipt['status']=='deleted'
    assert not policy_one.attempt_root.exists() and not policy_two.attempt_root.exists()
    assert_probe(d,first['data']['task_id'])
    assert_probe(d,second['data']['task_id'])
    (policy_two.attempt_root.parent/'sequential-canary.json').write_text(json.dumps(dict(first=dict(policy_one.claim_binding),second=dict(policy_two.claim_binding),cleanup=h.last_cleanup_receipt)))


def assert_probe(d,task_id):
    outputs=d.service.store.list_managed_outputs(task_id)
    assert len(outputs)==1
    digest=outputs[0]['object_id'].removeprefix('sha256:')
    data=json.loads((d.service.store.cas_root/digest[:2]/digest[2:]).read_text())
    for observed in (data,data['descendant']):
        assert observed['read'] in (errno.EPERM,errno.EACCES)
        assert observed['write'] in (errno.EPERM,errno.EACCES)
        assert observed['egress'] in (errno.EPERM,errno.EACCES)
        assert observed['env_spoof'] is False
    return data


def test_simultaneous_project_isolated_slots_share_factory_not_policy(flow,monkeypatch):
    d,h,projects,sessions=flow
    monkeypatch.setenv('HOSTILE_AUTHORITY','synthetic-caller-claim')
    tasks=[submit(flow,i,'parallel-'+str(i)) for i in range(2)]
    # The canonical rendering resource is exclusive per executor. Use two
    # authenticated reusable executors to observe genuinely simultaneous work.
    from runtime_protocol.daemon import WORKER_SCOPES
    token,_=d.credentials.provision('synthetic-worker-two',list(WORKER_SCOPES))
    second_host=gh.GenericPackHost(pack_roots=list(h.pack_roots),
        client=gh.RuntimeProtocolClient(d.endpoint,token),executor_id='synthetic-worker-two',
        attempt_base=h.attempt_base,max_concurrency=2)
    second_host.discover();second_host.register()
    slots=[h._new_claim_slot(),second_host._new_claim_slot()]
    assert all(slot._confinement_policy is None for slot in slots)
    assert slots[0]._attempt_policy_factory is h._attempt_policy_factory
    assert slots[1]._attempt_policy_factory is second_host._attempt_policy_factory
    assert type(slots[0]._attempt_policy_factory) is type(slots[1]._attempt_policy_factory)
    with ThreadPoolExecutor(2) as pool:
        results=list(pool.map(lambda slot:slot.claim_once(),slots))
    assert all(results)
    policies=[slot._confinement_policy for slot in slots]
    assert policies[0] is not policies[1]
    assert set(dict(p.claim_binding)['project_id'] for p in policies)==set(projects)
    observed=[assert_probe(d,t['data']['task_id']) for t in tasks]
    assert max(o['started'] for o in observed) < min(o['finished'] for o in observed)
    assert all(slot.last_cleanup_receipt['status']=='deleted' for slot in slots)
    (policies[0].attempt_root.parent/'parallel-canary.json').write_text(json.dumps(dict(
        claims=[dict(p.claim_binding) for p in policies],probes=observed,
        cleanups=[slot.last_cleanup_receipt for slot in slots])))


@pytest.mark.parametrize('flow',[30],indirect=True)
def test_revoke_during_work_fences_effects_and_host_performs_owned_cleanup(flow):
    d,h,projects,sessions=flow
    task=submit(flow,0,'revoke-mid-work')['data']['task_id']
    result=[]
    def run():
        try:result.append(h.claim_once())
        except BaseException as exc:result.append(type(exc).__name__)
    thread=threading.Thread(target=run);thread.start()
    deadline=time.monotonic()+15
    while not h._active_processes and thread.is_alive() and time.monotonic()<deadline:time.sleep(.02)
    assert h._active_processes
    owned=list(h._active_processes)
    grant=d.httpd.paired_sessions._sessions[sessions[0][1]['pair_id']]
    d.httpd.paired_sessions.revoke(grant)
    thread.join(12)
    assert not thread.is_alive()
    assert d.service.task(task)['task']['status']=='cancelled'
    assert d.service.store.list_managed_outputs(task)==[]
    assert not h._active_processes and all(p.poll() is not None for p in owned)
    assert h.last_cleanup_receipt['status']=='deleted'
    fields=dict(h._confinement_policy.claim_binding)
    from runtime_protocol.errors import ForbiddenError,LeaseError
    with pytest.raises((ForbiddenError,LeaseError)):
        d.service.settle_attempt(fields['attempt_id'],{k:fields[k] for k in ('lease_id','fence','runtime_epoch')},idempotency_key='late-publication')
    (h.attempt_base/'revoke-canary.json').write_text(json.dumps(dict(claim=fields,
        cleanup=h.last_cleanup_receipt,pids=[p.pid for p in owned],exits=[p.poll() for p in owned],outcomes=result)))


@pytest.mark.parametrize('field,wrong',[('task_id','wrong'),('attempt_id','wrong'),('lease_id','wrong'),
    ('fence',999),('executor_id','wrong'),('runtime_epoch',999),('project_id','wrong')])
def test_authenticated_runtime_projection_rejects_wrong_attempt_tuple_before_policy(flow,field,wrong):
    d,h,projects,sessions=flow
    task=submit(flow,0,'wrong-tuple')['data']['task_id']
    c=h.client.claim_next(executor_id=h.executor_id,capability_ids=['rendering.render'],idempotency_key='tuple-claim')
    values={k:dict(c.claim_authority)[k] for k in ('task_id','attempt_id','lease_id','fence','runtime_epoch','project_id','operation','executor_id')}
    values[field]=wrong
    with pytest.raises(gh.HostError,match='provenance|binding mismatch'):
        h.client.confirm_claim_authority(**values)
    assert h._confinement_policy is None and not h._active_processes
    d.service.cancel(task)


@pytest.mark.parametrize('flow',[{'delegation':True}],indirect=True)
def test_unadmitted_delegation_descriptor_refuses_launch_with_owned_cleanup(flow):
    d,h,projects,sessions=flow
    task=submit(flow,0,'delegation-channel')['data']['task_id']
    # The existing macOS retained-custody launcher has no admitted consumer
    # for HostChildBridge's inherited AF_UNIX socket. Never bypass that guard.
    with pytest.raises(gh.HostError,match='descriptors differ'):
        h.claim_once()
    assert not h._active_processes
    assert d.service.task(task)['task']['status']=='failed'
    assert h.last_cleanup_receipt['status']=='deleted'


@pytest.mark.parametrize('flow',[{'module':True}],indirect=True)
def test_ordinary_module_launch_uses_verified_code_and_sanitized_environment(flow):
    d,h,projects,sessions=flow
    task=submit(flow,0,'module-launch')['data']['task_id']
    assert h.claim_once()
    observed=assert_probe(d,task)
    assert Path(observed['admitted_module']).parent==Path(gh.__file__).resolve().parents[2]
