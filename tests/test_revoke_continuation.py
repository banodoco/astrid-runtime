"""Focused REVOKE evidence on disposable durable Runtime fixtures.

The commit provider is the existing synthetic acceptance adapter, not a semantic
renderer. Reconnect uses real HTTP connections; close-reason headers are hostile
transport hints, never an authorization input or WebSocket relay attestation.
"""
import hashlib
import http.client
import json
from urllib.parse import urlsplit

import pytest

from http_helpers import Api
from runtime_protocol.contract_metadata import SCHEMA_DIGEST
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ForbiddenError
from test_selected_media_commit import snapshot
from test_shot_composition_runtime import _publication
from test_task_authority_binding import CAP, DIGEST, pair
from test_timeline_accept import acceptance, wire


def paired_headers(context):
    return {'X-Reigh-Paired-Session': json.dumps(context)}


def task_body(project, key):
    return dict(capability_id=CAP, capability_digest=DIGEST, project=project,
                spec={}, idempotency_key=key)


def outputs(root):
    # Both CAS bytes and managed-output rows (in snapshot) must remain unchanged.
    cas = root / 'cas' / 'sha256'
    assert cas.is_dir()
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in cas.rglob('*') if p.is_file()}


def assert_revoked(invoke):
    with pytest.raises(RuntimeError) as caught:
        invoke()
    assert caught.value.status == 403
    assert caught.value.detail['details']['decision']['code'] == 'project_grant_revoked'


def test_revoked_new_operation_and_commit_have_no_effects(pair):
    d, project, _, token, context, grant, binding = pair
    s = d.service
    s.create_timeline(project, 'main', idempotency_key='timeline')
    s.publish_parent_composition(project, 'main', _publication(project), idempotency_key='initial')
    calls = []
    ports = []
    preparations = []

    class Provider:
        interface_version = 1
        contract_digest = SCHEMA_DIGEST

        def commit(self, request, port):
            calls.append(request['request_id'])
            ports.append(port)
            prepared = acceptance(s, project, request=request)
            preparations.append(prepared)
            return port.accept(prepared)['stored_result']

    s.register_timeline_commit_provider(Provider())
    api = Api(d.endpoint, token)
    headers = paired_headers(context)
    path = f'/astrid/v1/projects/{project}/timelines/main/commit'

    def commit(request):
        return api.request('POST', path, request, headers={**headers,
            'Idempotency-Key': request['request_id'], 'X-Astrid-Session': request['session_id']})

    first = wire(project, key='authorized-commit')
    first['asserted_actor']['id'] = 'connector'
    assert commit(first)['status'] == 'accepted'
    assert s.lookup_request(project, 'main', first['request_id']) is not None
    created = api.request('POST', '/v1/tasks', task_body(project, 'authorized-task'),
                          headers={**headers, 'Idempotency-Key': 'authorized-task'})
    task_id = created['data']['task_id']
    assert s.task(task_id)['task']['status'] == 'queued'
    assert calls == ['authorized-commit']
    # Keep the actual authorized request/port for a late acceptance replay.
    late = wire(project, key='late-commit')
    late['asserted_actor']['id'] = 'connector'
    late['base_revision_id'] = late['base_publication_id'] = s.head(project, 'main')['revision_id']
    # Retain the actual authenticated port; its final accept rechecks authority.
    d.httpd.paired_sessions.revoke(grant)
    assert s.task(task_id)['task']['status'] == 'cancelled'
    before = snapshot(s), s.store.conn.total_changes, s.head(project, 'main'), outputs(d.root)
    refusals = [
        lambda: api.request('POST', '/v1/tasks', task_body(project, 'new-after-revoke'),
                            headers={**headers, 'Idempotency-Key': 'new-after-revoke'}),
        lambda: commit(late),
        lambda: commit(first),  # accepted replay is fenced too
    ]
    for invoke in refusals:
        assert_revoked(invoke)
        assert (snapshot(s), s.store.conn.total_changes, s.head(project, 'main'), outputs(d.root)) == before
    # The retained authenticated pre-revoke port cannot accept prepared work late.
    with pytest.raises(ForbiddenError) as caught:
        ports[0].accept(preparations[0])
    assert caught.value.details['decision']['code'] == 'project_grant_revoked'
    assert (snapshot(s), s.store.conn.total_changes, s.head(project, 'main'), outputs(d.root)) == before
    assert s.lookup_request(project, 'main', late['request_id']) is None
    assert calls == ['authorized-commit']


def exchange(daemon, token, context, close_reason):
    endpoint = urlsplit(daemon.endpoint)
    conn = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=5)
    headers = {**paired_headers(context), 'Authorization': 'Bearer ' + token,
               'Connection': 'close'}
    if close_reason is not None:
        headers['X-Reigh-Close-Reason'] = close_reason
    try:
        conn.request('GET', '/v1/handshake', headers=headers)
        response = conn.getresponse()
        return response.status, json.loads(response.read())
    finally:
        conn.close()  # real transport close, independent of explicit grant revoke


@pytest.mark.parametrize('close_reason', [None, 'ordinary-disconnect', 'grant-revoked'])
def test_revoked_grant_stays_revoked_after_reconnect_and_daemon_restart(pair, close_reason):
    d, project, _, token, context, grant, binding = pair
    assert exchange(d, token, context, close_reason)[0] == 200
    # An ordinary disconnect/reconnect while authorized does not revoke the grant.
    assert exchange(d, token, context, close_reason)[0] == 200
    d.httpd.paired_sessions.revoke(grant)

    def denied(daemon):
        assert daemon.credentials.require(token, 'tasks:write')['actor'] == 'connector'
        before = snapshot(daemon.service), daemon.service.store.conn.total_changes, outputs(daemon.root)
        status, body = exchange(daemon, token, context, close_reason)
        assert status == 403
        assert body['details']['decision']['code'] == 'project_grant_revoked'
        assert (snapshot(daemon.service), daemon.service.store.conn.total_changes, outputs(daemon.root)) == before
        assert not daemon.httpd.paired_sessions._sessions or daemon is d

    denied(d)
    root, support = d.root, d.support_root
    old_instance = d.httpd.paired_sessions.instance_id
    d.stop()
    fresh = RuntimeDaemon(root, support_root=support).start()
    try:
        assert fresh.httpd.paired_sessions.instance_id != old_instance
        assert fresh.httpd.paired_sessions._sessions == {}
        assert fresh.credentials.actor_metadata('connector')['paired_revocations'] == [
            dict(pair_id=context['pair_id'], connector_id=context['connector_id'], generation=context['generation'])]
        denied(fresh)
        with pytest.raises(ForbiddenError) as caught:
            fresh.httpd.paired_sessions.authenticate(fresh.credentials.load(token), json.dumps(context), fresh.service)
        assert caught.value.details['decision']['code'] == 'project_grant_revoked'
        assert fresh.httpd.paired_sessions._sessions == {}
    finally:
        fresh.stop()
