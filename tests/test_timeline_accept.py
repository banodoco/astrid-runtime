"""Disposable acceptance fixtures; not film or COMMIT semantic evidence."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import jsonschema
import pytest

from runtime_protocol.auth import CredentialStore
from runtime_protocol.errors import AuthorizationError, ConflictError, ValidationError
from runtime_protocol.server import RuntimeHTTPServer, RuntimeHandler
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit import digest, result_template, validate_request
from test_shot_composition_runtime import _service, _publication
from http_helpers import Api

IDENTITY = {"actor": "fixture-writer", "scopes": ["projects:write"]}
SCHEMA = json.loads((Path(__file__).parents[1] / 'contract/schemas/timeline-commit.json').read_text())


def valid(value, name):
    jsonschema.Draft202012Validator({"$ref": "#/$defs/" + name, "$defs": SCHEMA["$defs"]}).validate(value)


@pytest.fixture
def fixture(tmp_path):
    service, project = _service(tmp_path)
    service.publish_parent_composition(project, 'main', _publication(project), idempotency_key='initial')
    try:
        yield service, project
    finally:
        service.close()


def wire(project, *, key='save-1', dry_run=False):
    return dict(api_version=1, project_id=project, timeline_id='main', request_id=key,
                session_id='fixture-session', session_sequence=1, base_revision_id='parent-1',
                base_publication_id='parent-1', scope=dict(target='parent', complete=[], projection_version=1),
                change={'commands': []}, source={'via': 'script'}, asserted_actor={'kind': 'script', 'id': IDENTITY['actor']}, dry_run=dry_run)


def acceptance(service, project, *, key='save-1', no_change=False, request=None):
    request = request or wire(project, key=key)
    head = service.head(project, 'main')
    before = service.get_project_parent_composition_revision(project, 'main', head['revision_id'])['payload']
    publication = {k: v for k, v in _publication(project).items() if k in ('parent_composition', 'shot_revisions', 'internal_timeline_revisions')}
    publication['parent_composition']['config'] = {'fixture-save': key}
    for occurrence in publication['parent_composition']['occurrences']:
        occurrence['muted'] = occurrence.pop('mute')
    after = before if no_change else service._complete_parent_payload(publication['parent_composition'])
    result = result_template(request, digest(request))
    result.update(status='no_change' if no_change else 'accepted', canonical_document=after,
                  document_digest=service._revision_digest(after), rebased_onto=head['revision_id'])
    evidence = dict(commands=[], direct_writes=[], digests={'before': service._revision_digest(before), 'after': service._revision_digest(after)},
                    toolchain={'astrid_sha': 'synthetic-fixture-not-a-toolchain-attestation', 'compiler_version': 'fixture'})
    value = dict(project_id=project, timeline_id='main', request_id=request['request_id'], request_hash=digest(request),
                 expected_head_revision_id=head['revision_id'], publication=None if no_change else publication,
                 result=result, evidence=evidence, source=request['source'], asserted_actor=request['asserted_actor'])
    valid(value, 'AcceptRequest')
    return value


def count(service, table):
    return service.store.conn.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0]


def test_replay_before_moved_head_and_changed_body_conflict(fixture):
    s, p = fixture
    request = acceptance(s, p)
    first = s.accept(request, identity=IDENTITY)
    valid(first, 'AcceptResponse')
    s.accept(acceptance(s, p, key='next-save'), identity=IDENTITY)
    retried = s.accept(request, identity=IDENTITY)
    assert retried['outcome'] == 'replayed'
    assert retried['stored_result'] == first['stored_result']
    assert s.lookup_request(p, 'main', 'save-1')['result'] == first['stored_result']
    changed = copy.deepcopy(request)
    changed['request_hash'] = digest({'changed': True})
    changed['result']['request_hash'] = changed['request_hash']
    with pytest.raises(ConflictError) as error:
        s.accept(changed, identity=IDENTITY)
    assert error.value.details == {'code': 'RequestIdConflict', 'stored_request_hash': request['request_hash']}
    assert count(s, 'parent_composition_revisions') == 3
    assert s.revisions(p, 'main', {'before': s.head(p, 'main')['revision_id']})[0]['revision_id'] == first['revision_id']


def test_no_change_evidence_and_corruption(fixture):
    s, p = fixture
    request = acceptance(s, p, no_change=True)
    before = s.head(p, 'main')
    result = s.accept(request, identity=IDENTITY)
    valid(result, 'AcceptResponse')
    assert result['revision_id'] is None and result['stored_result']['status'] == 'no_change'
    assert s.head(p, 'main') == before
    assert count(s, 'parent_composition_revisions') == 1
    assert s.evidence(result['receipt']['evidence_digest']) == request['evidence']
    assert result['receipt']['publisher'] == IDENTITY['actor']
    assert result['receipt']['asserted_actor'] == request['asserted_actor']
    row = s.store.conn.execute("SELECT rowid,result_json FROM command_idempotency WHERE command_kind='timeline.commit'").fetchone()
    corrupted = json.loads(row['result_json'])
    corrupted['evidence']['commands'] = [{'corrupted': True}]
    with s.store._transaction():
        s.store.conn.execute('UPDATE command_idempotency SET result_json=? WHERE rowid=?', (json.dumps(corrupted), row['rowid']))
    with pytest.raises(ConflictError, match='digest verification'):
        s.evidence(result['receipt']['evidence_digest'])


@pytest.mark.parametrize('identity,actor', [(None, None), ({'actor': 'reader', 'scopes': ['projects:read']}, None), (IDENTITY, {'kind': 'user', 'id': 'forged'})])
def test_publisher_and_asserted_actor(fixture, identity, actor):
    s, p = fixture
    request = acceptance(s, p)
    if actor:
        request['asserted_actor'] = actor
    with pytest.raises(AuthorizationError):
        s.accept(request, identity=identity)
    assert count(s, 'parent_composition_revisions') == 1
    assert s.lookup_request(p, 'main', 'save-1') is None


def test_transaction_rollback_after_publication(fixture, monkeypatch):
    s, p = fixture
    request = acceptance(s, p)
    original = s._command_record
    def fail(kind, *args, **kwargs):
        if kind == 'timeline.commit':
            raise RuntimeError('injected before ledger persistence')
        return original(kind, *args, **kwargs)
    before = s.store.conn.total_changes
    monkeypatch.setattr(s, '_command_record', fail)
    with pytest.raises(RuntimeError, match='injected'):
        s.accept(request, identity=IDENTITY)
    assert s.store.conn.total_changes > before  # Actual publication ran, then rolled back.
    assert count(s, 'parent_composition_revisions') == 1
    assert count(s, 'parent_composition_heads') == 1
    assert s.head(p, 'main')['revision_id'] == 'parent-1'
    assert s.lookup_request(p, 'main', 'save-1') is None
    assert count(s, 'command_idempotency') == 3  # Project, timeline, initial publication.


@pytest.mark.parametrize('load', [1, 8])
def test_process_exit_after_durable_commit_recovers_exactly_once(tmp_path, load):
    s, p = _service(tmp_path)
    s.publish_parent_composition(p, 'main', _publication(p), idempotency_key='initial')
    prepared = [acceptance(s, p, key=f'crash-{i}') for i in range(load)]
    root = str(tmp_path / 'realm')
    s.close()
    program = '''
import json,os,sys
from runtime_protocol.service import RuntimeService
s=RuntimeService(sys.argv[1])
request=json.loads(sys.stdin.read())
def crash(result):
    assert not s.store.conn.in_transaction
    os.write(1,json.dumps(result,sort_keys=True).encode())
    os._exit(73)
s._after_timeline_commit=crash
s.accept(request,identity={"actor":"fixture-writer","scopes":["projects:write"]})
'''
    started = time.monotonic()
    for i, request in enumerate(prepared):
        if i:
            s = RuntimeService(root)
            request = acceptance(s, p, key=f'crash-{i}')
            s.close()
        # No fixed wall-clock deadline: work/recovery budget scales with load.
        child = subprocess.run([sys.executable, '-c', program, root], input=json.dumps(request), capture_output=True, text=True)
        assert child.returncode == 73, child.stderr
        original = json.loads(child.stdout)
        s = RuntimeService(root)
        try:
            saved = s.lookup_request(p, 'main', request['request_id'])
            assert saved['result'] == original
            assert s.accept(request, identity=IDENTITY)['stored_result'] == original
            assert count(s, 'parent_composition_revisions') == i + 2
            assert s.evidence(original['runtime_receipt']['evidence_digest']) == request['evidence']
            changed = copy.deepcopy(request)
            changed['request_hash'] = changed['result']['request_hash'] = digest({'changed': i})
            with pytest.raises(ConflictError):
                s.accept(changed, identity=IDENTITY)
        finally:
            s.close()
    print(json.dumps({'fixture_crashes': load, 'elapsed_s': time.monotonic() - started, 'revision_count': load + 1, 'deadline': 'load-scaled work, no fixed timeout'}))


def test_permanent_result_survives_ledger_pruning(fixture):
    s, p = fixture
    request = acceptance(s, p)
    first = s.accept(request, identity=IDENTITY)
    with s.store._transaction():
        s.store.conn.execute("UPDATE command_idempotency SET created_at='2000-01-01T00:00:00+00:00' WHERE command_kind='timeline.commit'")
    s.store._last_idempotency_prune = 0
    s.create_project({'slug': 'prune-trigger', 'name': 'Prune'}, idempotency_key='prune')
    assert s.accept(request, identity=IDENTITY)['stored_result'] == first['stored_result']


def test_stale_head_invalid_digest_and_narration_rollback(fixture):
    s, p = fixture
    for mode in ('head', 'digest', 'narration', 'identity'):
        request = acceptance(s, p)
        if mode == 'head':
            request['expected_head_revision_id'] = 'wrong-head'
        elif mode == 'digest':
            request['evidence']['digests']['after'] = 'sha256:' + '0' * 64
        elif mode == 'narration':
            request['narration'] = {'binding_id': 'not-integrated', 'expected_hash': 'before', 'new_hash': 'after'}
        else:
            request['result']['request_id'] = 'forged'
        with pytest.raises((ConflictError, ValidationError)):
            s.accept(request, identity=IDENTITY)
        assert count(s, 'parent_composition_revisions') == 1
        assert s.lookup_request(p, 'main', 'save-1') is None


def fixture_provider(s, p):
    """Synthetic D provider; no claim of real semantic algorithm/installed origin."""
    from runtime_protocol.contract_metadata import SCHEMA_DIGEST
    calls = []
    class Provider:
        interface_version = 1
        contract_digest = SCHEMA_DIGEST
        def commit(self, request, port):
            head = port.head()
            calls.append(head['revision_id'])
            assert not hasattr(port, 'store') and not hasattr(port, 'service')
            assert port.revision(request['base_revision_id'])['revision_id'] == request['base_revision_id']
            if request['dry_run']:
                result = result_template(request, digest(request))
                result.update(status='preview', rebased_onto=head['revision_id'])
                with pytest.raises(AuthorizationError):
                    port.accept(acceptance(s, p, request=request))
                return result
            return port.accept(acceptance(s, p, key=request['request_id'], request=request))['stored_result']
    s.register_timeline_commit_provider(Provider())
    return calls


def test_dry_run_once_on_current_head_stores_and_reserves_nothing(fixture):
    s, p = fixture
    s.accept(acceptance(s, p, key='advance'), identity=IDENTITY)
    calls = fixture_provider(s, p)
    request = wire(p, dry_run=True)
    before = s.store.conn.iterdump()
    before = '\n'.join(before)
    preview = s.commit_timeline(p, 'main', request, idempotency_key=request['request_id'], identity=IDENTITY)
    valid(preview, 'CommitResult')
    assert preview['status'] == 'preview'
    assert calls == [s.head(p, 'main')['revision_id']]
    assert '\n'.join(s.store.conn.iterdump()) == before
    assert s.lookup_request(p, 'main', request['request_id']) is None
    request['dry_run'] = False
    assert s.commit_timeline(p, 'main', request, idempotency_key=request['request_id'], identity=IDENTITY)['status'] == 'accepted'


def http_server(service, tmp_path):
    credentials = CredentialStore(tmp_path / 'credentials')
    token, _ = credentials.provision(IDENTITY['actor'], IDENTITY['scopes'])
    server = RuntimeHTTPServer(('127.0.0.1', 0), RuntimeHandler)
    server.runtime, server.credentials = service, credentials
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, Api(f'http://127.0.0.1:{server.server_port}', token)


def test_runtime_http_contract_lost_response_retry_and_headers(fixture, tmp_path):
    s, p = fixture
    calls = fixture_provider(s, p)
    server, thread, api = http_server(s, tmp_path)
    path = f'/astrid/v1/projects/{p}/timelines/main/commit'
    request = wire(p)
    headers = {'Idempotency-Key': request['request_id'], 'X-Astrid-Session': request['session_id']}
    try:
        with pytest.raises(RuntimeError) as unauthorized:
            Api(api.endpoint, None).request('POST', path, request, headers=headers)
        assert unauthorized.value.status == 401
        with pytest.raises(RuntimeError) as wrong_project:
            api.request('POST', path.replace(p, 'foreign-project'), request, headers=headers)
        assert wrong_project.value.status == 400
        with pytest.raises(RuntimeError) as forged_actor:
            api.request('POST', path, {**request, 'asserted_actor': {'kind': 'user', 'id': 'forged'}}, headers=headers)
        assert forged_actor.value.status == 401
        assert s.lookup_request(p, 'main', request['request_id']) is None
        with pytest.raises(RuntimeError) as mismatch:
            api.request('POST', path, request, headers={**headers, 'X-Astrid-Session': 'wrong'})
        assert mismatch.value.status == 400
        valid(mismatch.value.detail, 'CommitHttpBadRequest')
        s._after_timeline_commit = lambda result: (_ for _ in ()).throw(ConnectionResetError('lost response after commit'))
        with pytest.raises(Exception):
            api.request('POST', path, request, headers=headers)
        del s._after_timeline_commit
        stored = s.lookup_request(p, 'main', request['request_id'])['result']
        first = api.request('POST', path, request, headers=headers)
        valid(first, 'CommitHttpSuccess')
        assert first == stored
        s.accept(acceptance(s, p, key='head-moved'), identity=IDENTITY)
        assert api.request('POST', path, request, headers=headers) == stored
        assert len(calls) == 1
        assert count(s, 'parent_composition_revisions') == 3
        changed = {**request, 'label': 'changed'}
        with pytest.raises(RuntimeError) as conflict:
            api.request('POST', path, changed, headers=headers)
        assert conflict.value.status == 400
        assert conflict.value.detail['error']['code'] == 'request_id_conflict'
        valid(conflict.value.detail, 'CommitHttpBadRequest')
    finally:
        server.shutdown(); server.server_close(); thread.join()


def test_http_without_commit_producer_is_explicitly_unavailable(fixture, tmp_path):
    s, p = fixture
    server, thread, api = http_server(s, tmp_path)
    request = wire(p)
    try:
        with pytest.raises(RuntimeError) as error:
            api.request('POST', f'/astrid/v1/projects/{p}/timelines/main/commit', request,
                        headers={'Idempotency-Key': request['request_id'], 'X-Astrid-Session': request['session_id']})
        assert error.value.status == 503
        valid(error.value.detail, 'CommitHttpUnavailable')
        assert s.lookup_request(p, 'main', request['request_id']) is None
    finally:
        server.shutdown(); server.server_close(); thread.join()


def test_concurrent_exact_retries_and_competing_heads(fixture):
    from concurrent.futures import ThreadPoolExecutor
    s, p = fixture
    request = acceptance(s, p)
    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(lambda _: s.accept(request, identity=IDENTITY), range(16)))
    assert len({json.dumps(r['stored_result'], sort_keys=True) for r in results}) == 1
    assert count(s, 'parent_composition_revisions') == 2
    requests = [acceptance(s, p, key='compete-' + str(i)) for i in range(4)]
    def attempt(request):
        try:
            return s.accept(request, identity=IDENTITY)['outcome']
        except ConflictError as exc:
            assert exc.details['code'] == 'StaleHead'
            return 'stale'
    with ThreadPoolExecutor(max_workers=4) as workers:
        outcomes = list(workers.map(attempt, requests))
    assert outcomes.count('accepted') == 1 and outcomes.count('stale') == 3
    assert count(s, 'parent_composition_revisions') == 3


def test_semantic_document_is_not_storage_envelope(fixture):
    s, p = fixture
    request = acceptance(s, p)
    semantic = {'clips': [], 'opaque-semantic-document': {'null': None, '_vendor': 'preserved'}}
    request['result']['canonical_document'] = semantic
    request['result']['document_digest'] = request['evidence']['digests']['after'] = digest(semantic)
    result = s.accept(request, identity=IDENTITY)['stored_result']
    assert result['canonical_document'] == semantic
    assert result['document_digest'] == digest(semantic)
    assert s.get_project_parent_composition_revision(p, 'main', result['accepted_revision_id'])['payload'] != semantic
    valid(result, 'CommitResult')


@pytest.mark.parametrize('field,value', [('asserted_actor', None), ('source', {'via': []}), ('session_sequence', True), ('dry_run', None), ('scope', {'target': 'parent', 'complete': [], 'projection_version': 1, 'content': 'shared-shot'})])
def test_invalid_requests_store_nothing(fixture, field, value):
    s, p = fixture
    request = wire(p)
    request[field] = value
    with pytest.raises((ValidationError, AuthorizationError)):
        s.commit_timeline(p, 'main', request, idempotency_key=request['request_id'], identity=IDENTITY)
    assert s.lookup_request(p, 'main', request['request_id']) is None
    assert count(s, 'parent_composition_revisions') == 1


def test_offline_compaction_preserves_commit_result_and_evidence(fixture):
    from runtime_protocol.upgrade import compact_idempotency_ledger
    s, p = fixture
    request = acceptance(s, p)
    first = s.accept(request, identity=IDENTITY)
    with s.store._transaction():
        s.store.conn.execute("UPDATE command_idempotency SET created_at='2000-01-01T00:00:00+00:00' WHERE command_kind='timeline.commit'")
    root = s.store.root
    realm_id = s.store.conn.execute('SELECT id FROM realm').fetchone()[0]
    s.close()
    compact_idempotency_ledger(root, confirmation='COMPACT IDEMPOTENCY ' + realm_id)
    recovered = RuntimeService(root)
    try:
        assert recovered.accept(request, identity=IDENTITY)['stored_result'] == first['stored_result']
        assert recovered.evidence(first['receipt']['evidence_digest']) == request['evidence']
    finally:
        recovered.close()


def test_provider_registration_scope_and_dry_run_authority(fixture):
    from runtime_protocol.contract_metadata import SCHEMA_DIGEST
    s, p = fixture
    class BadProvider:
        interface_version = 2
        contract_digest = SCHEMA_DIGEST
        def commit(self, request, port): raise AssertionError('not admitted')
    with pytest.raises(ValidationError):
        s.register_timeline_commit_provider(BadProvider())
    fixture_provider(s, p)
    with pytest.raises(ConflictError):
        s.register_timeline_commit_provider(BadProvider())
    request = wire(p)
    port = s._request_commit_port(request, IDENTITY)
    prepared = acceptance(s, p, request=request)
    for key, value in [('project_id', 'foreign'), ('request_id', 'foreign'), ('source', {'via': 'cli'}),
                       ('asserted_actor', {'kind': 'script', 'id': 'forged'})]:
        changed = copy.deepcopy(prepared)
        changed[key] = value
        with pytest.raises(AuthorizationError):
            port.accept(changed)
    with pytest.raises(TypeError):
        port.head('foreign-project')
    with pytest.raises(TypeError):
        port.lookup_request('foreign-request')
    original = port.revision('parent-1')
    original['payload']['config']['modified-snapshot'] = True
    assert 'modified-snapshot' not in port.revision('parent-1')['payload']['config']
    dry = s._request_commit_port(wire(p, dry_run=True), IDENTITY)
    with pytest.raises(AuthorizationError):
        dry.accept(prepared)
    assert s.lookup_request(p, 'main', request['request_id']) is None


def test_provider_cannot_report_unstored_success_and_failure_is_unavailable(fixture):
    from runtime_protocol.contract_metadata import SCHEMA_DIGEST
    s, p = fixture
    class Provider:
        interface_version = 1
        contract_digest = SCHEMA_DIGEST
        def commit(self, request, port):
            return acceptance(s, p, request=request)['result']
    s.register_timeline_commit_provider(Provider())
    with pytest.raises(ValidationError, match='without the stored'):
        s.commit_timeline(p, 'main', wire(p), idempotency_key='save-1', identity=IDENTITY)
    assert count(s, 'parent_composition_revisions') == 1


def test_previous_publication_identity_is_stored_and_replayed(fixture):
    s, p = fixture
    head = s.head(p, 'main')
    assert head['publication_id'] != head['revision_id']
    request = acceptance(s, p)
    first = s.accept(request, identity=IDENTITY)
    assert first['previous_publication_id'] == head['publication_id']
    assert first['publication_id'] != first['revision_id']
    s.accept(acceptance(s, p, key='later'), identity=IDENTITY)
    replay = s.accept(request, identity=IDENTITY)
    assert replay['previous_publication_id'] == first['previous_publication_id']
    assert replay['stored_result'] == first['stored_result']


def test_runtime_http_semantic_provider_runs_outside_storage_mutex(fixture, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from runtime_protocol.contract_metadata import SCHEMA_DIGEST
    s, p = fixture
    class Provider:
        interface_version = 1
        contract_digest = SCHEMA_DIGEST
        def commit(self, request, port):
            with ThreadPoolExecutor(max_workers=1) as workers:
                assert workers.submit(port.head).result(timeout=30)['revision_id'] == 'parent-1'
            assert not s.store.conn.in_transaction
            return port.accept(acceptance(s, p, request=request))['stored_result']
    s.register_timeline_commit_provider(Provider())
    server, thread, api = http_server(s, tmp_path)
    request = wire(p)
    try:
        result = api.request('POST', f'/astrid/v1/projects/{p}/timelines/main/commit', request,
                             headers={'Idempotency-Key': request['request_id'], 'X-Astrid-Session': request['session_id']})
        assert result['status'] == 'accepted'
    finally:
        server.shutdown(); server.server_close(); thread.join()


def test_provider_failure_and_replay_without_provider_after_restart(fixture):
    from runtime_protocol.contract_metadata import SCHEMA_DIGEST
    s, p = fixture
    request = wire(p)
    first = s.accept(acceptance(s, p, request=request), identity=IDENTITY)['stored_result']
    root = s.store.root
    s.close()
    recovered = RuntimeService(root)
    try:
        assert recovered.commit_timeline(p, 'main', request, idempotency_key=request['request_id'], identity=IDENTITY) == first
    finally:
        recovered.close()
    recovered = RuntimeService(root)
    closed = []
    class Provider:
        interface_version = 1
        contract_digest = SCHEMA_DIGEST
        def commit(self, request, port): raise RuntimeError('fixture provider failed')
        def close(self): closed.append(True)
    recovered.register_timeline_commit_provider(Provider())
    try:
        failed = wire(p, key='provider-failed')
        result = recovered.commit_timeline(p, 'main', failed, idempotency_key=failed['request_id'], identity=IDENTITY)
        valid(result, 'CommitHttpUnavailable')
        assert recovered.lookup_request(p, 'main', failed['request_id']) is None
    finally:
        recovered.close()
    assert closed == [True]
