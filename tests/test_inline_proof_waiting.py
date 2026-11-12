import base64
import hashlib

import pytest

from runtime_protocol.errors import ConflictError
from test_generic_output_publication import _new_service, _filmstrip_attempt, _descriptor, _settle_body
from test_runtime_control2 import _service, _task, _claim_attempt, _digest


@pytest.mark.parametrize('failure', [False, True])
def test_existing_unscoped_inline_output_proves_possession(tmp_path, failure):
    service = _new_service(tmp_path / 'realm')
    try:
        _, first = _filmstrip_attempt(service, None)
        output = _descriptor(b'', name='log', filename='log', output_port='log', primary=False, media_type='text/plain')
        output['data_base64'] = ''
        service.settle_attempt(first['attempt_id'], _settle_body(first, [output]), idempotency_key='unscoped')
        project = service.create_project({'slug': 'target', 'name': 'Target'})['id']
        _, second = _filmstrip_attempt(service, project)
        method = service.fail_attempt if failure else service.settle_attempt
        method(second['attempt_id'], _settle_body(second, [output]), idempotency_key='project')
        assert service.store.conn.execute('SELECT 1 FROM project_objects WHERE project_id=? AND digest=?', (project, hashlib.sha256(b'').hexdigest())).fetchone()
    finally:
        service.close()


def test_claim_reports_all_blockers_and_holder(tmp_path, monkeypatch):
    service = _service(tmp_path / 'realm')
    try:
        service.register_capability({'capability_id': 'render.gpu', 'definition_digest': _digest('render.gpu-v1'), 'required_resource_keys': ['gpu']})
        service.register_executor({'executor_id': 'worker', 'capabilities': ['render.gpu'], 'resource_keys': ['gpu'], 'max_concurrency': 1}, idempotency_key='register')
        _task(service, 'first')
        holder = _claim_attempt(service, idempotency_key='first-claim')
        queued = _task(service, 'second')['task']['id']
        service.store.conn.execute("UPDATE tasks SET lease_expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (holder['task_id'],))
        result = _claim_attempt(service, idempotency_key='second-claim')
        assert result['waiting_reason'] == 'waiting_for_worker'
        assert any(b.get('holder_task_id') == holder['task_id'] and b.get('lease_expired') is True and b.get('holder_state') == 'running' for b in result['waiting_details']['blockers'])
        events = service.store.conn.execute("SELECT count(*) FROM events WHERE task_id=? AND kind='task.waiting_reason_changed'", (queued,)).fetchone()[0]
        assert events == 1
        _claim_attempt(service, idempotency_key='repeat-claim')
        assert service.store.conn.execute("SELECT count(*) FROM events WHERE task_id=? AND kind='task.waiting_reason_changed'", (queued,)).fetchone()[0] == 1
        monkeypatch.setattr(service.store, 'storage_preflight', lambda *a, **kw: {'ok': False})
        result = _claim_attempt(service, idempotency_key='third-claim')
        assert {b['reason'] for b in result['waiting_details']['blockers']} >= {'insufficient_storage', 'waiting_for_worker', 'waiting_for_gpu'}
    finally:
        service.close()


def test_wrong_inline_hash_is_rejected(tmp_path):
    service = _new_service(tmp_path / 'realm')
    try:
        project = service.create_project({'slug': 'target', 'name': 'Target'})['id']
        _, attempt = _filmstrip_attempt(service, project)
        output = _descriptor(b'expected', name='log', filename='log', output_port='log', primary=False, media_type='text/plain')
        output['data_base64'] = base64.b64encode(b'wrong').decode()
        with pytest.raises(ConflictError, match='hash does not match'):
            service.settle_attempt(attempt['attempt_id'], _settle_body(attempt, [output]), idempotency_key='wrong')
    finally:
        service.close()
