import json
from types import SimpleNamespace

import pytest

from astrid_runtime.bootstrap import BootstrapError, doctor
from astrid_runtime.paths import RuntimePaths


@pytest.fixture
def observed(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path)
    paths.ensure_support_dirs()
    root = paths.realms_dir / 'realm'
    root.mkdir()
    paths.catalog_path.write_text(json.dumps({
        'version': 1, 'selected_realm_id': 'realm',
        'realms': [{'realm_id': 'realm', 'data_root': str(root)}],
    }))
    paths.discovery_path.write_text(json.dumps({
        'pid': 98765, 'runtime_instance_id': 'instance', 'active_realm': 'realm',
        'endpoint': 'http://127.0.0.1:43100',
    }))
    metadata = {'status': 'ok', 'runtime_instance_id': 'instance', 'realm_id': 'realm'}
    def endpoint_metadata(**kwargs):
        assert kwargs['credential_file'] == paths.runtime_support / 'credentials' / 'owner.token'
        return metadata
    boundary = SimpleNamespace(is_pid_alive=lambda pid: False, endpoint_metadata=endpoint_metadata)
    return paths, boundary, metadata


def test_authenticated_matching_health_overrides_invisible_pid(observed):
    paths, boundary, _ = observed
    before = {p: p.read_bytes() for p in paths.runtime_support.rglob('*') if p.is_file()}
    report = doctor(paths, boundary)
    assert report['healthy'] is True
    assert report['pid_alive'] is False
    assert report['notes'] == ['pid_not_visible']
    assert report['issues'] == []
    assert before == {p: p.read_bytes() for p in paths.runtime_support.rglob('*') if p.is_file()}


@pytest.mark.parametrize('field,value', [
    ('runtime_instance_id', 'another-instance'), ('realm_id', 'another-realm'), ('status', 'degraded'),
])
def test_endpoint_identity_and_health_must_match_even_with_visible_pid(observed, field, value):
    paths, boundary, metadata = observed
    boundary.is_pid_alive = lambda pid: True
    metadata[field] = value
    report = doctor(paths, boundary)
    assert report['healthy'] is False
    assert report['issues']


def test_dead_pid_and_unreachable_or_unauthenticated_endpoint_are_stale(observed):
    paths, boundary, metadata = observed
    metadata.clear()
    report = doctor(paths, boundary)
    assert report['healthy'] is False
    assert 'stale_discovery' in report['issues']


def test_unknown_pid_visibility_does_not_block_authenticated_health(observed):
    paths, boundary, _ = observed
    def unknown(pid):
        raise BootstrapError('process observation unavailable')
    boundary.is_pid_alive = unknown
    assert doctor(paths, boundary)['healthy'] is True


def test_real_boundary_uses_owner_credential_without_requiring_pid_visibility(observed, monkeypatch, capsys):
    from io import BytesIO
    from astrid_runtime.runtime_boundary import LocalRuntimeBoundary

    paths, _, metadata = observed
    credential = paths.runtime_support / 'credentials' / 'owner.token'
    credential.parent.mkdir(mode=0o700)
    credential.write_text('fixture-owner-token')
    credential.chmod(0o600)
    boundary = LocalRuntimeBoundary()
    monkeypatch.setattr(boundary, 'is_pid_alive', lambda pid: False)
    monkeypatch.setattr(boundary, '_http_health_payload', lambda endpoint: {
        'status': 'ok', 'runtime_instance_id': 'instance',
    })
    calls = []
    def authenticated_realm(request, **kwargs):
        calls.append(request.full_url)
        assert request.get_header('Authorization') == 'Bearer fixture-owner-token'
        return BytesIO(json.dumps({'realm_id': 'realm'}).encode())
    monkeypatch.setattr('astrid_runtime.runtime_boundary.urlopen_loopback', authenticated_realm)
    assert doctor(paths, boundary)['healthy'] is True
    assert calls == ['http://127.0.0.1:43100/v1/realm']
    from astrid_runtime import cli
    monkeypatch.setattr(cli, 'LocalRuntimeBoundary', lambda: boundary)
    assert cli.main(['doctor', '--json', '--data-root', str(paths.app_support)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['healthy'] is True
    assert report['pid_alive'] is False
