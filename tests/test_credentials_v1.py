"""Disposable credential/loopback canaries; no relay or semantic-provider proof."""
from __future__ import annotations

import json
import time

import pytest

from http_helpers import Api
from runtime_protocol.auth import CredentialStore
from runtime_protocol.errors import AuthorizationError, ValidationError
from runtime_protocol.server import RuntimeHandler
from test_timeline_accept import (
    IDENTITY, count, fixture, fixture_provider, http_server, wire,
)


def decision(error):
    return error.details['decision']['code']


def test_v1_provision_parse_exact_host_identity_and_static_handoff(tmp_path):
    store = CredentialStore(tmp_path / 'credentials')
    expiry = time.time() + 600
    token, path = store.provision('writer', ['projects:write', 'projects:read'],
                                  metadata={'expires_at': expiry})
    expected = {'credential_format': store.FORMAT, 'actor': 'writer',
                'scopes': ['projects:read', 'projects:write'], 'expires_at': expiry}
    assert json.loads(path.with_suffix('.json').read_text()) == expected
    assert store.load(token) == expected
    assert store.require(token, 'projects:write') == expected
    assert store.provision('writer', ['projects:write', 'projects:read'],
                           metadata={'expires_at': expiry})[0] == token
    store.provision_static('handoff', 'synthetic-handoff-token', ['projects:read'])
    assert store.load('synthetic-handoff-token') == {
        'credential_format': store.FORMAT, 'actor': 'handoff', 'scopes': ['projects:read']}


def test_connector_assertion_is_host_owned_and_bearer_bound(tmp_path):
    store = CredentialStore(tmp_path / 'credentials')
    expiry = time.time() + 600
    token, _ = store.provision_connector('connector', ['projects:write'],
        connector_id='connector-a', realm_id='realm-a', expires_at=expiry)
    identity = store.load(token)
    assert identity == {'credential_format': store.FORMAT, 'actor': 'connector',
        'scopes': ['projects:write'], 'expires_at': expiry,
        'connector_assertion': {'connector_id': 'connector-a', 'realm_id': 'realm-a'},
        '_credential_binding': store._sha256(token.encode())}


def test_expired_v1_is_named_refusal(tmp_path):
    store = CredentialStore(tmp_path / 'credentials')
    token, _ = store.provision('writer', ['projects:write'])
    metadata = store.actor_metadata('writer')
    metadata['expires_at'] = time.time() - 1
    store._publish('writer', token, metadata)  # synthetic owner-side storage
    with pytest.raises(AuthorizationError) as error:
        store.load(token)
    assert decision(error.value) == 'paired_credential_expired'


@pytest.mark.parametrize('committed', [False, True], ids=['pre-commit-pair', 'unversioned-committed'])
def test_exact_legacy_bearer_refused_and_host_provision_rotates(tmp_path, committed):
    store = CredentialStore(tmp_path / 'credentials')
    old = 'synthetic-legacy-bearer'
    path = store._publish('writer', old, {'actor': 'writer', 'scopes': ['projects:write']})
    if not committed:
        path.with_suffix('.commit').unlink()
    before = {p.name: p.read_bytes() for p in store.root.iterdir()}
    with pytest.raises(AuthorizationError) as error:
        store.load(old)
    assert decision(error.value) == 'credential_format_unsupported'
    assert before == {p.name: p.read_bytes() for p in store.root.iterdir()}
    with pytest.raises(AuthorizationError, match='invalid bearer'):
        store.load('unrelated-invalid-token')
    replacement, _ = store.provision('writer', ['projects:write'])
    assert replacement != old
    assert store.load(replacement)['credential_format'] == store.FORMAT
    with pytest.raises(AuthorizationError, match='invalid bearer'):
        store.load(old)


@pytest.mark.parametrize('marker', [None, 1, '', 'astrid.runtime-credential/v2'])
def test_unsupported_format_is_named_for_exact_bearer(tmp_path, marker):
    store = CredentialStore(tmp_path / 'credentials')
    store._publish('writer', 'synthetic-token', {'credential_format': marker,
        'actor': 'writer', 'scopes': ['projects:write']})
    with pytest.raises(AuthorizationError) as error:
        store.load('synthetic-token')
    assert decision(error.value) == 'credential_format_unsupported'


@pytest.mark.parametrize('patch', [
    {'actor': 'other'}, {'actor': None}, {'scopes': 'projects:write'},
    {'scopes': [1]}, {'scopes': ['']}, {'scopes': [' projects:write']},
    {'expires_at': True}, {'expires_at': 'future'}, {'expires_at': float('nan')},
    {'expires_at': float('inf')}, {'expires_at': 10**400},
    {'connector_assertion': {'connector_id': 'c', 'realm_id': 'r'}},
    {'connector_assertion': {'connector_id': 'c'}, 'expires_at': 9999999999},
    {'connector_assertion': {'connector_id': 'c', 'realm_id': 'r'},
     'scopes': ['admin'], 'expires_at': 9999999999},
])
def test_malformed_v1_authority_never_authenticates(tmp_path, patch):
    store = CredentialStore(tmp_path / 'credentials')
    store._publish('writer', 'synthetic-token', {'credential_format': store.FORMAT,
        'actor': 'writer', 'scopes': ['projects:write'], **patch})
    with pytest.raises(AuthorizationError) as error:
        store.load('synthetic-token')
    assert decision(error.value) == 'credential_metadata_invalid'
    assert store.actor_metadata('writer') is None


@pytest.mark.parametrize('scopes', ['projects:write', [None], [''], [' projects:write']])
def test_provision_rejects_malformed_scope_input(tmp_path, scopes):
    with pytest.raises(ValidationError):
        CredentialStore(tmp_path / 'credentials').provision('writer', scopes)


@pytest.mark.parametrize('field', ['credential_format', 'actor', 'scopes', '_credential_binding'])
def test_provision_reserves_identity_fields(tmp_path, field):
    with pytest.raises(ValidationError):
        CredentialStore(tmp_path / 'credentials').provision('writer', [], metadata={field: 'forged'})


def test_loopback_real_commit_with_v1_and_exact_scope_denials(fixture, tmp_path):
    service, project = fixture
    calls = fixture_provider(service, project)
    server, thread, api = http_server(service, tmp_path)
    request = wire(project)
    path = f'/astrid/v1/projects/{project}/timelines/main/commit'
    headers = {'Idempotency-Key': request['request_id'], 'X-Astrid-Session': request['session_id']}
    try:
        with pytest.raises(RuntimeError) as missing:
            Api(api.endpoint, None).request('POST', path, request, headers=headers)
        assert missing.value.status == 401
        assert missing.value.detail['code'] == 'unauthorized'
        assert missing.value.detail['message'] == 'bearer credential required'
        for scopes in (['projects:read'], ['admin'], ['*'], ['projects:*']):
            token, _ = server.credentials.provision(IDENTITY['actor'], scopes, rotate=True)
            # Header fields cannot manufacture credential grants or a version.
            with pytest.raises(RuntimeError) as denied:
                Api(api.endpoint, token).request('POST', path, request, headers={
                    **headers, 'X-Credential-Format': CredentialStore.FORMAT, 'X-Scopes': 'projects:write'})
            assert denied.value.status == 401
            assert denied.value.detail['code'] == 'unauthorized'
            assert denied.value.detail['details']['scope'] == 'projects:write'
            if scopes == ['admin']:
                assert denied.value.detail['details']['decision']['code'] == 'credential_scope_denied'
                assert server.credentials.require(token, 'projects:read')['scopes'] == ['admin']
        assert calls == [] and count(service, 'parent_composition_revisions') == 1
        token, _ = server.credentials.provision(IDENTITY['actor'], ['projects:write'])
        result = Api(api.endpoint, token).request('POST', path, request, headers=headers)
        assert result['status'] == 'accepted'
        assert result == service.lookup_request(project, 'main', request['request_id'])['result']
        assert calls == ['parent-1']
        assert count(service, 'parent_composition_revisions') == 2
        assert service.head(project, 'main')['revision_id'] == result['accepted_revision_id']
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_real_pair_project_denial_and_commit_gate_remains_closed(fixture, tmp_path, monkeypatch):
    service, project = fixture
    other = service.create_project({'slug': 'other', 'name': 'Other'}, idempotency_key='other')['id']
    calls = fixture_provider(service, project)
    server, thread, api = http_server(service, tmp_path)
    expiry = time.time() + 120
    service.select_project('connector', project)
    token, _ = server.credentials.provision_connector('connector',
        ['handshake', 'projects:read', 'projects:write'], connector_id='c',
        realm_id=service.realm['id'], expires_at=expiry)
    api = Api(api.endpoint, token)
    context = {'pair_id': 'pair', 'connector_id': 'c', 'realm_id': service.realm['id'],
               'generation': 1, 'expires_at': int((time.time() + 60) * 1000)}
    headers = {'X-Reigh-Paired-Session': json.dumps(context)}
    try:
        handshake = api.request('GET', '/v1/handshake', headers=headers)
        assert handshake['project_grant']['project_id'] == project
        assert handshake['project_grant']['decision']['code'] == 'project_grant_allowed'
        body_reads = []
        original_body = RuntimeHandler._body

        def track_body(handler):
            body_reads.append(handler.path)
            return original_body(handler)

        monkeypatch.setattr(RuntimeHandler, '_body', track_body)
        changes_before = service.store.conn.total_changes
        with pytest.raises(RuntimeError) as wrong_project:
            api.request('GET', f'/v1/projects/{other}', headers=headers)
        assert wrong_project.value.status == 403
        assert wrong_project.value.detail['details']['decision']['code'] == 'project_grant_project_denied'
        request = wire(project)
        request['asserted_actor']['id'] = 'connector'
        commit_headers = {**headers, 'Idempotency-Key': request['request_id'],
                          'X-Astrid-Session': request['session_id']}
        with pytest.raises(RuntimeError) as wrong_project_commit:
            # The body names the bound project; only Runtime's route selector
            # may choose the project being authorized.
            api.request('POST', f'/astrid/v1/projects/{other}/timelines/main/commit', request,
                        headers=commit_headers)
        assert wrong_project_commit.value.status == 403
        assert wrong_project_commit.value.detail['details']['decision']['code'] == 'project_grant_project_denied'
        assert body_reads == [] and calls == []
        assert service.store.conn.total_changes == changes_before
        assert count(service, 'parent_composition_revisions') == 1
        assert service.lookup_request(other, 'main', request['request_id']) is None
        assert service.lookup_request(project, 'main', request['request_id']) is None
        with pytest.raises(RuntimeError) as unavailable:
            api.request('POST', f'/astrid/v1/projects/{project}/timelines/main/commit', request,
                        headers=commit_headers)
        assert unavailable.value.status == 403
        assert unavailable.value.detail['details']['decision']['code'] == 'project_grant_operation_unavailable'
        assert calls == [] and service.lookup_request(project, 'main', request['request_id']) is None
        assert body_reads == [] and service.store.conn.total_changes == changes_before
        assert count(service, 'parent_composition_revisions') == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
