from __future__ import annotations

import json
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ForbiddenError, ValidationError
from runtime_protocol.store import RealmStore

SCOPES = ['handshake', 'projects:read', 'projects:write', 'tasks:read', 'tasks:write', 'objects:read', 'objects:write']


def call(d, token, path='/v1/handshake', *, context=None, body=None, method=None):
    headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'Idempotency-Key': 'paired-fixture'}
    if context is not None:
        headers['X-Reigh-Paired-Session'] = json.dumps(context)
    req = Request(d.endpoint + path, headers=headers,
        data=json.dumps(body).encode() if body is not None else None, method=method)
    try:
        with urlopen(req, timeout=5) as r:
            return r.status, json.load(r)
    except HTTPError as e:
        return e.code, json.load(e)


def code(result):
    return result[1]['details']['decision']['code']


@pytest.fixture
def paired(tmp_path):
    root = tmp_path / 'realm'
    RealmStore.initialize(root).close()
    d = RuntimeDaemon(root, support_root=tmp_path / 'support').start()
    try:
        p = d.service.create_project({'slug': 'one', 'name': 'One'}, idempotency_key='p1')['id']
        q = d.service.create_project({'slug': 'two', 'name': 'Two'}, idempotency_key='p2')['id']
        d.service.select_project('connector-a', p)
        expiry = time.time() + 120
        token, _ = d.credentials.provision_connector('connector-a', SCOPES, connector_id='c', realm_id=d.service.realm['id'], expires_at=expiry)
        context = dict(pair_id='s1', connector_id='c', realm_id=d.service.realm['id'], generation=1, expires_at=int((time.time() + 60) * 1000))
        yield d, token, context, p, q, expiry
    finally:
        d.stop()


def test_http_authenticated_pair_mints_runtime_snapshot_and_bounds_expiry(paired):
    d, token, context, p, q, expiry = paired
    status, result = call(d, token, context=context)
    assert status == 200
    grant = result['project_grant']
    assert (grant['actor_id'], grant['realm_id'], grant['project_id']) == ('connector-a', d.service.realm['id'], p)
    assert grant['decision']['code'] == 'project_grant_allowed'
    assert grant['expiry'] <= min(context['expires_at'] / 1000, expiry)
    credential_limited = call(d, token, context={**context, 'pair_id': 'credential-limited',
        'expires_at': int((time.time()+600)*1000)})
    assert credential_limited[0] == 200
    assert credential_limited[1]['project_grant']['expiry'] == expiry
    d.service.select_project('connector-a', q)
    assert call(d, token, context=context)[1]['project_grant']['project_id'] == p
    assert code(call(d, token, '/v1/projects/' + q, context=context)) == 'project_grant_project_denied'


def test_http_ordinary_credential_and_browser_context_cannot_assert(paired):
    d, token, context, p, q, _ = paired
    ordinary, _ = d.credentials.provision('ordinary', SCOPES)
    assert call(d, ordinary)[0] == 200  # unrelated authorized CLI handshake
    assert code(call(d, ordinary, context=context)) == 'paired_connector_assertion_required'
    assert code(call(d, token, context=context, body={'paired_session': context})) == 'paired_browser_context_forbidden'
    assert code(call(d, ordinary, body={'project_grant': {'actor': 'owner'}})) == 'paired_browser_context_forbidden'
    assert code(call(d, token, '/v1/realm')) == 'paired_session_required'
    with pytest.raises(ValidationError, match='ordinary'):
        d.credentials.provision_connector('ordinary', SCOPES, connector_id='c', realm_id=d.service.realm['id'], expires_at=time.time()+60)


@pytest.mark.parametrize('field,value,expected', [
    ('realm_id', 'foreign', 'paired_realm_mismatch'),
    ('connector_id', 'foreign', 'paired_connector_mismatch'),
    ('expires_at', 1, 'paired_session_expired'),
    ('generation', 0, 'paired_session_invalid'),
])
def test_http_wrong_binding_is_named_denial(paired, field, value, expected):
    d, token, context, *_ = paired
    assert code(call(d, token, context={**context, field: value})) == expected


def test_http_actor_generation_and_session_exchange(paired):
    d, token, context, p, q, expiry = paired
    assert call(d, token, context=context)[0] == 200
    other, _ = d.credentials.provision_connector('connector-b', SCOPES, connector_id='c', realm_id=d.service.realm['id'], expires_at=expiry)
    d.service.select_project('connector-b', p)
    assert code(call(d, other, context=context)) == 'project_grant_actor_mismatch'
    second = {**context, 'pair_id': 's2'}
    assert call(d, token, context=second)[0] == 200
    # These handles never leave the host. Exercise the exact issued authorities,
    # not a fabricated policy or a browser-created session.
    authority = d.httpd.paired_sessions
    first_grant, second_grant = authority._sessions['s1'], authority._sessions['s2']
    with pytest.raises(ForbiddenError) as exc:
        authority.decision(second_grant, presented_grant=first_grant.handle, project_id=p, operation='rendering.render')
    assert exc.value.details['decision']['code'] == 'project_grant_unknown'
    assert code(call(d, token, context={**context, 'generation': 2})) == 'paired_session_binding_changed'
    assert call(d, token, context={**second, 'pair_id': 's3', 'generation': 2})[0] == 200
    assert code(call(d, token, context=context)) == 'paired_generation_stale'
    assert first_grant.generation == 1  # reconnect never mutates or revives it


def test_http_expired_grant_never_renews_and_credential_expiry_is_enforced(paired):
    d, token, context, p, q, _ = paired
    token, _ = d.credentials.provision_connector('connector-a', SCOPES, connector_id='c', realm_id=d.service.realm['id'], expires_at=time.time()+1000)
    context = {**context, 'expires_at': int((time.time()+600)*1000)}
    assert call(d, token, context=context)[0] == 200
    authority = d.httpd.paired_sessions
    authority.clock = lambda: time.time() + 301
    assert code(call(d, token, context=context)) == 'project_grant_expired'
    authority.clock = time.time
    metadata = d.credentials.actor_metadata('connector-a')
    metadata['expires_at'] = time.time() - 1
    d.credentials._publish('connector-a', token, metadata)  # synthetic host expiry canary
    status, error = call(d, token, context=context)
    assert status == 401
    assert error['details']['decision']['code'] == 'paired_credential_expired'


def test_http_real_task_path_checks_project_and_operation_before_admission(paired):
    d, token, context, p, q, _ = paired
    for project, capability, expected in [
        (q, 'rendering.render', 'project_grant_project_denied'),
        (p, 'provider.anything', 'project_grant_operation_denied'),
        (p, 'timeline.update', 'project_capability_unavailable'),
    ]:
        assert code(call(d, token, '/v1/tasks', context=context, body={'project': project, 'capability_id': capability})) == expected
    assert code(call(d, token, '/v1/timelines/fixture', context=context, body={}, method='PATCH')) == 'project_grant_operation_unavailable'
    assert d.service.store.conn.execute('SELECT COUNT(*) FROM tasks').fetchone()[0] == 0


def test_rotating_connector_credential_cannot_rebind_old_session(paired):
    d, token, context, p, q, expiry = paired
    assert call(d, token, context=context)[0] == 200
    replacement, _ = d.credentials.provision_connector('connector-a', SCOPES, connector_id='c',
        realm_id=d.service.realm['id'], expires_at=expiry, rotate=True)
    assert code(call(d, replacement, context=context)) == 'paired_credential_mismatch'
    assert call(d, token, context=context)[0] == 401
    assert call(d, replacement, context={**context, 'pair_id': 'fresh-session'})[0] == 200
