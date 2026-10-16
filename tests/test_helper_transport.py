"""Synthetic real-listener helper transport proof; no outside-host witness."""
from __future__ import annotations

import http.client
import ipaddress
import json
import socket
from urllib.parse import urlsplit

import pytest

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError
from runtime_protocol.local_worker_handoff import _validate_authority_sockets
from runtime_protocol.store import RealmStore


@pytest.fixture(params=['127.0.0.1', 'localhost'])
def daemon(tmp_path, request):
    RealmStore.initialize(tmp_path / 'realm').close()
    instance = RuntimeDaemon(tmp_path / 'realm', support_root=tmp_path / 'support',
                             host=request.param).start()
    try:
        yield instance
    finally:
        thread = instance.thread
        listener = instance.httpd.socket
        instance.stop()
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert listener.fileno() == -1


def request(instance, *, headers=None, token=None, method='POST', path='/v1/projects'):
    endpoint = urlsplit(instance.endpoint)
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=5)
    body = json.dumps({'slug': 'transport', 'name': 'Transport'}).encode()
    try:
        connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for name, value in (headers if headers is not None else [('Host', endpoint.netloc)]):
            connection.putheader(name, value)
        if token is not None:
            connection.putheader('Authorization', 'Bearer ' + token)
        connection.putheader('Content-Type', 'application/json')
        connection.putheader('Content-Length', str(len(body)))
        connection.putheader('Idempotency-Key', 'transport-project')
        connection.endheaders(body)
        response = connection.getresponse()
        payload = json.loads(response.read())
        return response.status, payload
    finally:
        connection.close()


def test_bound_socket_and_exact_inherited_endpoint_identity(daemon):
    listener = daemon.httpd.socket
    bound = listener.getsockname()
    endpoint = urlsplit(daemon.endpoint)
    assert listener.family == socket.AF_INET
    assert ipaddress.ip_address(bound[0]).is_loopback
    assert bound == (endpoint.hostname, endpoint.port)
    assert daemon.httpd.server_address == bound
    print('OBSERVED_LISTENER', json.dumps({'configured_host': daemon.host,
          'family': int(listener.family), 'bound': bound, 'endpoint': daemon.endpoint}))
    # Exercise Runtime's real descriptor-identity validator, not a stubbed result.
    left, right = socket.socketpair()
    try:
        _validate_authority_sockets(left.fileno(), listener.fileno(), expected_listener=bound)
        for wrong in [('127.0.0.2', bound[1]), (bound[0], bound[1] % 65535 + 1)]:
            with pytest.raises(ConflictError, match='handoff listener does not match the expected loopback endpoint'):
                _validate_authority_sockets(left.fileno(), listener.fileno(), expected_listener=wrong)
        _validate_authority_sockets(left.fileno(), listener.fileno(), expected_listener=bound)
    finally:
        left.close()
        right.close()
    status, payload = request(daemon, token=daemon.token)
    assert status == 201 and payload['data']['slug'] == 'transport'


@pytest.mark.parametrize('host', ['0.0.0.0', '::', '192.0.2.1'])
def test_nonloopback_configuration_refused_before_files_or_bind(tmp_path, host):
    with pytest.raises(ValueError, match='runtime daemon only binds to loopback'):
        RuntimeDaemon(tmp_path / 'realm', host=host)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('case', [
    'hostile-host', 'wrong-port', 'other-loopback', 'duplicate-host', 'missing-host',
    'host-userinfo', 'host-path', 'hostile-origin', 'null-origin', 'wrong-origin-port',
    'duplicate-origin', 'https-origin', 'origin-path', 'absolute-target',
])
def test_hostile_authority_refused_before_handler_side_effects(daemon, case):
    authority = urlsplit(daemon.endpoint).netloc
    wrong_port = daemon.httpd.server_port % 65535 + 1
    headers = [('Host', authority)]
    path = '/v1/projects'
    if case == 'hostile-host':
        headers = [('Host', 'hostile.invalid:' + str(daemon.httpd.server_port))]
    elif case == 'wrong-port':
        headers = [('Host', '127.0.0.1:' + str(wrong_port))]
    elif case == 'other-loopback':
        headers = [('Host', '127.0.0.2:' + str(daemon.httpd.server_port))]
    elif case == 'duplicate-host':
        headers += headers
    elif case == 'missing-host':
        headers = []
    elif case == 'host-userinfo':
        headers = [('Host', 'attacker@' + authority)]
    elif case == 'host-path':
        headers = [('Host', authority + '/path')]
    elif case == 'hostile-origin':
        headers += [('Origin', 'https://hostile.invalid')]
    elif case == 'null-origin':
        headers += [('Origin', 'null')]
    elif case == 'wrong-origin-port':
        headers += [('Origin', 'http://127.0.0.1:' + str(wrong_port))]
    elif case == 'duplicate-origin':
        headers += [('Origin', daemon.endpoint)] * 2
    elif case == 'https-origin':
        headers += [('Origin', 'https://' + authority)]
    elif case == 'origin-path':
        headers += [('Origin', daemon.endpoint + '/path')]
    elif case == 'absolute-target':
        path = 'http://hostile.invalid/v1/projects'
    before = daemon.service.store.conn.total_changes
    status, payload = request(daemon, headers=headers, path=path, token=daemon.token)
    assert status == 403, (case, status, payload)
    assert payload['code'] == 'forbidden'
    message = ('runtime request target must use origin form' if case == 'absolute-target'
               else 'runtime Origin does not match the bound endpoint' if 'origin' in case
               else 'runtime Host does not match the bound endpoint')
    assert payload['message'] == message
    assert daemon.service.store.conn.total_changes == before
    assert daemon.service.store.conn.execute('SELECT COUNT(*) FROM projects').fetchone()[0] == 0
    # The genuine endpoint and bearer must still perform the same mutation.
    status, payload = request(daemon, token=daemon.token)
    assert status == 201 and payload['data']['slug'] == 'transport'


def test_same_endpoint_origin_and_localhost_alias_work(daemon):
    authority = 'localhost:' + str(daemon.httpd.server_port)
    status, payload = request(daemon, headers=[('Host', authority), ('Origin', 'http://' + authority)],
                              token=daemon.token)
    assert status == 201 and payload['data']['slug'] == 'transport'


@pytest.mark.parametrize('header', ['Host', 'Origin'])
@pytest.mark.parametrize('path', [
    '/v1/projects', '/v1/objects', '/v1/control/local-worker/start',
    '/astrid/v1/projects/synthetic/timelines/synthetic/commit',
])
def test_hostile_transport_refused_without_reading_body(daemon, header, path):
    endpoint = urlsplit(daemon.endpoint)
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=5)
    before = daemon.service.store.conn.total_changes
    try:
        connection.putrequest('POST', path, skip_host=True, skip_accept_encoding=True)
        connection.putheader('Host', 'hostile.invalid' if header == 'Host' else endpoint.netloc)
        if header == 'Origin':
            connection.putheader('Origin', 'https://hostile.invalid')
        connection.putheader('Authorization', 'Bearer ' + daemon.token)
        connection.putheader('Content-Length', '1024')
        # Intentionally no body: refusal must arrive without waiting to read it.
        connection.endheaders()
        response = connection.getresponse()
        assert response.status == 403
        assert json.loads(response.read())['code'] == 'forbidden'
        assert daemon.service.store.conn.total_changes == before
    finally:
        connection.close()


def test_real_authentication_bound_to_selected_runtime(daemon, tmp_path):
    # A second disposable loopback daemon proves cross-endpoint bearer refusal.
    RealmStore.initialize(tmp_path / 'other-realm').close()
    other = RuntimeDaemon(tmp_path / 'other-realm', support_root=tmp_path / 'other-support').start()
    try:
        assert other.endpoint != daemon.endpoint
        assert other.instance_id != daemon.instance_id
        assert other.service.realm['id'] != daemon.service.realm['id']
        for selected, wrong_token in [(daemon, other.token), (other, daemon.token)]:
            status, health = request(selected, method='GET', path='/v1/health')
            assert status == 200 and health['runtime_instance_id'] == selected.instance_id
            before = selected.service.store.conn.total_changes
            for token in [None, wrong_token]:
                status, payload = request(selected, token=token)
                assert status == 401 and payload['code'] == 'unauthorized'
                assert selected.service.store.conn.total_changes == before
            status, payload = request(selected, token=selected.token)
            assert status == 201 and payload['data']['slug'] == 'transport'
    finally:
        thread = other.thread
        listener = other.httpd.socket
        other.stop()
        thread.join(timeout=5)
        assert not thread.is_alive() and listener.fileno() == -1
