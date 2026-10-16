"""Canonical commit acceptance revalidates after semantic preparation."""
import json
import threading
import time

import pytest

from http_helpers import Api
from runtime_protocol.contract_metadata import SCHEMA_DIGEST
from test_timeline_accept import acceptance, count, fixture, http_server, wire


@pytest.mark.parametrize('mutation',['revoke','rotation','scope','expiry'])
def test_paired_canonical_accept_rechecks_current_authority_after_preparation(fixture,tmp_path,mutation):
    s,p=fixture
    server,thread,unused=http_server(s,tmp_path)
    s.select_project('connector',p)
    token,_=server.credentials.provision_connector('connector',
        ['handshake','projects:read','projects:write'],connector_id='c',realm_id=s.realm['id'],expires_at=time.time()+120)
    context=dict(pair_id='pair',connector_id='c',realm_id=s.realm['id'],generation=1,expires_at=int((time.time()+90)*1000))
    headers={'X-Reigh-Paired-Session':json.dumps(context)}
    api=Api(unused.endpoint,token)
    prepared=threading.Event();resume=threading.Event()
    calls=[]
    class Provider:
        interface_version=1
        contract_digest=SCHEMA_DIGEST
        def commit(self,request,port):
            template=acceptance(s,p,request=request)
            calls.append(port.head()['revision_id'])
            prepared.set()
            assert resume.wait(5)
            return port.accept(template)['stored_result']
    s.register_timeline_commit_provider(Provider())
    request=wire(p);request['asserted_actor']['id']='connector'
    outcome=[]
    def save():
        try:
            outcome.append(api.request('POST',f'/astrid/v1/projects/{p}/timelines/main/commit',request,
                headers={**headers,'Idempotency-Key':request['request_id'],'X-Astrid-Session':request['session_id']}))
        except RuntimeError as exc:outcome.append(exc)
    try:
        api.request('GET','/v1/handshake',headers=headers)
        baseline=s.store.conn.total_changes
        worker=threading.Thread(target=save);worker.start();assert prepared.wait(5)
        grant=server.paired_sessions._sessions['pair']
        if mutation=='revoke':server.paired_sessions.revoke(grant)
        elif mutation=='rotation':server.credentials.provision_connector('connector',
            ['handshake','projects:read','projects:write'],connector_id='c',realm_id=s.realm['id'],expires_at=time.time()+120,rotate=True)
        else:
            meta=server.credentials.actor_metadata('connector')
            if mutation=='scope':meta['scopes']=['handshake','projects:read']
            else:meta['expires_at']=time.time()-1
            server.credentials._publish('connector',token,meta)
        resume.set();worker.join(5);assert not worker.is_alive()
        assert len(outcome)==1 and isinstance(outcome[0],RuntimeError)
        assert outcome[0].status in (401,403)
        assert calls==['parent-1']
        assert s.store.conn.total_changes==baseline
        assert count(s,'parent_composition_revisions')==1
        assert s.lookup_request(p,'main',request['request_id']) is None
    finally:
        resume.set();server.shutdown();server.server_close();thread.join()
