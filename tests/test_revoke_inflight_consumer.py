"""Real HTTP/worker lifecycle with a synthetic command, never a renderer claim."""
import base64
import hashlib
import http.client
import json
from pathlib import Path
import threading
import time
from urllib.parse import urlsplit

import pytest

from runtime_protocol.errors import ForbiddenError, LeaseError
from test_task_authority_host_canary import flow as _flow, submit

flow = _flow


def _request(d, token, context, method, path, body=None, key=None):
    endpoint = urlsplit(d.endpoint)
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=10)
    headers = {'Authorization': 'Bearer ' + token}
    if context is not None:
        headers['X-Reigh-Paired-Session'] = json.dumps(context)
    if key:
        headers['Idempotency-Key'] = key
    try:
        connection.request(method, path, body=None if body is None else json.dumps(body),
                           headers={**headers, 'Content-Type': 'application/json'})
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        # Ordinary transport close has no grant-revocation semantics.
        connection.close()


def _snapshot(d):
    with d.service.store._mutex:
        return ('\n'.join(d.service.store.conn.iterdump()),
                d.service.store.conn.total_changes,
                {str(p.relative_to(d.service.store.cas_root)): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in d.service.store.cas_root.rglob('*') if p.is_file()})


def _start(flow):
    d, host, projects, sessions = flow
    task = submit(flow, 0, 'inflight')['data']['task_id']
    result = []

    def run():
        try:
            result.append({'returned': bool(host.claim_once())})
        except Exception as exc:
            result.append({'error': type(exc).__name__, 'message': str(exc)})

    thread = threading.Thread(target=run)
    thread.start()
    deadline = time.monotonic() + 15
    marker = None
    while thread.is_alive() and time.monotonic() < deadline:
        markers = list(host.attempt_base.rglob('inflight.json'))
        if markers:
            try:
                marker = json.loads(markers[0].read_text())
                break
            except json.JSONDecodeError:
                pass
        time.sleep(.02)
    assert marker is not None, result
    owned = list(host._active_processes)
    assert owned and marker['pid'] in [p.pid for p in owned]
    assert all(p.poll() is None for p in owned)
    assert d.service.task(task)['task']['status'] == 'running'
    fields = dict(host._confinement_policy.claim_binding)
    binding = d.service._task_authority(task)
    grant = d.httpd.paired_sessions._sessions[sessions[0][1]['pair_id']]
    assert (binding.pair_id, binding.generation, binding.authority_instance_id,
            binding.actor_id, binding.credential_binding, binding.project_id, binding.operation) == (
                grant.pair_id, grant.generation, d.httpd.paired_sessions.instance_id,
                grant.actor, grant.credential_binding, projects[0], 'rendering.render')
    assert fields['task_id'] == task and fields['project_id'] == projects[0]
    assert fields['operation'] == 'rendering.render'
    assert fields['authority_instance_id'] == binding.authority_instance_id
    return task, thread, owned, fields, marker, result


@pytest.mark.parametrize('flow', [{'delay': 1.5, 'inflight': True}], indirect=True)
def test_disconnect_preserves_inflight_work_and_exact_output(flow):
    d, host, projects, sessions = flow
    task, thread, owned, fields, marker, result = _start(flow)
    events = [{'event': 'producer-inflight', 'monotonic': time.monotonic()}]
    try:
        token, context = sessions[0]
        grant = d.httpd.paired_sessions._sessions[context['pair_id']]
        metadata = d.credentials.actor_metadata(grant.actor)
        for _ in range(2):
            status, _ = _request(d, token, context, 'GET', '/v1/projects/' + projects[0])
            assert status == 200
            assert d.httpd.paired_sessions._sessions[context['pair_id']] is grant
            assert d.credentials.actor_metadata(grant.actor) == metadata
            events.append({'event': 'http-read-and-disconnect', 'monotonic': time.monotonic(), 'status': status})
        assert thread.is_alive() and all(p.poll() is None for p in owned)
        thread.join(12)
        assert not thread.is_alive(), result
        events.append({'event': 'consumer-completed', 'monotonic': time.monotonic()})
        assert d.service.task(task)['task']['status'] == 'completed', result
        outputs = d.service.store.list_managed_outputs(task)
        assert len(outputs) == 1
        digest = outputs[0]['object_id'].removeprefix('sha256:')
        data = d.service.cas.path_for(digest).read_bytes()
        assert hashlib.sha256(data).hexdigest() == digest
        answer = json.loads(data)
        read_status, readback = _request(d, token, context, 'GET', '/v1/objects/' + digest)
        assert read_status == 200 and readback == answer
        assert answer['pid'] == marker['pid'] and answer['started'] == marker['started']
        assert answer['finished'] >= marker['started']
        assert not host._active_processes and all(p.poll() is not None for p in owned)
        assert host.last_cleanup_receipt['status'] == 'deleted'
        assert d.credentials.actor_metadata(grant.actor) == metadata
        (host.attempt_base / 'disconnect-evidence.json').write_text(json.dumps({
            'claim': fields, 'marker': marker, 'output': outputs[0], 'digest': digest,
            'events': events, 'http_output_readback_status': read_status,
            'pids': [p.pid for p in owned], 'exits': [p.poll() for p in owned],
            'cleanup': host.last_cleanup_receipt, 'result': result}))
    finally:
        if thread.is_alive():
            host.shutdown()
            thread.join(12)


@pytest.mark.parametrize('flow', [{'delay': 30, 'inflight': True}], indirect=True)
@pytest.mark.parametrize('action', ['task-stop', 'consumer-stop', 'revoke'])
def test_stop_and_revoke_have_distinct_grant_effects_and_fence_output(flow, action):
    d, host, projects, sessions = flow
    task, thread, owned, fields, marker, result = _start(flow)
    events = [{'event': 'producer-inflight', 'monotonic': time.monotonic()}]
    try:
        token, context = sessions[0]
        grant = d.httpd.paired_sessions._sessions[context['pair_id']]
        metadata = d.credentials.actor_metadata(grant.actor)
        unrelated = submit(flow, 1, 'other-authority')['data']['task_id']
        same_project_context = {**context, 'pair_id': 'other-pair-same-project'}
        new_body = {'project': projects[0], 'capability_id': 'rendering.render',
                    'capability_digest': host.capabilities['rendering.render'].capability_digest, 'spec': {}}
        status, admitted = _request(d, token, same_project_context, 'POST', '/v1/tasks', new_body, 'other-pair')
        assert status == 201
        same_project_task = admitted['data']['task_id']
        status, _ = _request(d, token, context, 'GET', '/v1/projects/' + projects[0])
        assert status == 200 and thread.is_alive()
        events.append({'event': 'http-read-and-disconnect', 'monotonic': time.monotonic(), 'status': status})
        assert d.credentials.actor_metadata(grant.actor) == metadata
        assert all(p.poll() is None for p in owned)

        # These producers have no paired admission under the current policy.
        # An unavailable upload/prompt must not become a synthetic PASS claim.
        unavailable = []
        for path, body, code in [
            ('/v1/projects/' + projects[0] + '/media-imports', {}, 'project_grant_operation_unavailable'),
            ('/v1/tasks', {'project': projects[0], 'capability_id': 'generation.generate_image', 'spec': {}},
             'project_grant_operation_denied')]:
            baseline = _snapshot(d)
            status, refusal = _request(d, token, context, 'POST', path, body, 'unavailable-producer')
            assert status == 403 and code in json.dumps(refusal)
            assert _snapshot(d) == baseline
            unavailable.append({'path': path, 'code': code})

        events.append({'event': action + '-requested', 'monotonic': time.monotonic()})
        if action == 'task-stop':
            # Paired callers cannot widen their grant via the owner stop route.
            baseline = _snapshot(d)
            status, refusal = _request(d, token, context, 'POST', '/v1/tasks/' + task + '/cancel', {}, 'paired-stop')
            assert status == 403
            assert 'project_grant_operation_unavailable' in json.dumps(refusal)
            assert _snapshot(d) == baseline
            status, _ = _request(d, d.token, None, 'POST', '/v1/tasks/' + task + '/cancel', {}, 'owner-stop')
            assert status == 200
        elif action == 'consumer-stop':
            host.shutdown()
        else:
            # Existing host-owned API; no new route or direct store mutation.
            d.httpd.paired_sessions.revoke(grant)

        thread.join(12)
        assert not thread.is_alive(), result
        events.append({'event': 'consumer-stopped', 'monotonic': time.monotonic()})
        status_before_owner_stop = d.service.task(task)['task']['status']
        if action == 'consumer-stop':
            # Local consumer shutdown does not cancel Runtime's still-live
            # lease. Explicit task stop is the publication fence in this case.
            assert status_before_owner_stop == 'running', result
            events.append({'event': 'explicit-runtime-task-stop-requested', 'monotonic': time.monotonic()})
            status, _ = _request(d, d.token, None, 'POST', '/v1/tasks/' + task + '/cancel', {}, 'stop-after-shutdown')
            assert status == 200
        assert d.service.task(task)['task']['status'] == 'cancelled', result
        assert not host._active_processes and all(p.poll() is not None for p in owned)
        assert host.last_cleanup_receipt['status'] == 'deleted'
        assert not Path(host.last_cleanup_receipt['path']).exists()
        assert d.service.store.list_managed_outputs(task) == []
        assert d.service.task(unrelated)['task']['status'] == 'queued'
        assert d.service.task(same_project_task)['task']['status'] == 'queued'

        # A well-formed late output on the original attempt cannot publish.
        payload = b'synthetic-output-withheld-by-stop'
        digest = 'sha256:' + hashlib.sha256(payload).hexdigest()
        baseline = _snapshot(d)
        with pytest.raises((ForbiddenError, LeaseError)):
            d.service.settle_attempt(fields['attempt_id'], {
                **{k: fields[k] for k in ('lease_id', 'fence', 'runtime_epoch')},
                'outputs': [{'digest': digest, 'data_base64': base64.b64encode(payload).decode(),
                             'size': len(payload), 'media_type': 'text/plain', 'kind': 'object', 'name': 'answer'}]},
                idempotency_key='late-output')
        assert _snapshot(d) == baseline
        assert not d.service.cas.path_for(digest.removeprefix('sha256:')).exists()
        assert not (d.service.store.staging_root / 'settlements' / fields['attempt_id']).exists()
        events.append({'event': 'late-output-refused-with-no-effects', 'monotonic': time.monotonic()})

        if action == 'revoke':
            for method, path, body, key in [
                ('GET', '/v1/projects/' + projects[0], None, None),
                ('POST', '/v1/tasks', new_body, 'after-revoke')]:
                status, refusal = _request(d, token, context, method, path, body, key)
                assert status == 403 and 'project_grant_revoked' in json.dumps(refusal)
                assert _snapshot(d) == baseline
        else:
            assert d.credentials.actor_metadata(grant.actor) == metadata
            assert _request(d, token, context, 'GET', '/v1/projects/' + projects[0])[0] == 200
            assert _request(d, token, context, 'POST', '/v1/tasks', new_body, 'after-stop')[0] == 201
        other_token, other_context = sessions[1]
        assert _request(d, other_token, other_context, 'GET', '/v1/projects/' + projects[1])[0] == 200
        assert _request(d, token, same_project_context, 'GET', '/v1/projects/' + projects[0])[0] == 200
        (host.attempt_base / (action + '-evidence.json')).write_text(json.dumps({
            'action': action, 'claim': fields, 'marker': marker, 'task_status': d.service.task(task)['task']['status'],
            'events': events,
            'status_before_owner_stop': status_before_owner_stop,
            'unavailable_producers': unavailable,
            'unrelated_task': unrelated, 'unrelated_status': d.service.task(unrelated)['task']['status'],
            'same_project_other_pair_task': same_project_task,
            'same_project_other_pair_status': d.service.task(same_project_task)['task']['status'],
            'late_output_digest': digest, 'no_effect_snapshot_sha256': hashlib.sha256(baseline[0].encode()).hexdigest(),
            'pids': [p.pid for p in owned], 'exits': [p.poll() for p in owned],
            'cleanup': host.last_cleanup_receipt, 'result': result}))
    finally:
        if thread.is_alive():
            host.shutdown()
            thread.join(12)
