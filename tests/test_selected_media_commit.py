"""Real Runtime selected-media port/acceptance; disposable synthetic rows only.

The provider below is a contract adapter, not Astrid apply/rebase or film proof.
"""
from __future__ import annotations

import copy
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from runtime_protocol.contract_metadata import SCHEMA_DIGEST
from runtime_protocol.errors import AuthorizationError, ConflictError, NotFoundError, ValidationError
from runtime_protocol.timeline_commit import digest, result_template
from runtime_protocol.util import canonical_json
from test_timeline_accept import IDENTITY, acceptance, fixture, wire


def media(s, p, *, generation='g1', variant='v1', object_digest='a' * 64):
    """Create no files, decoder work, tasks, imports or settlement claims."""
    with s.store._transaction():
        s.store.conn.execute('INSERT OR IGNORE INTO objects VALUES (?,4,?,?,?)',
                             (object_digest, 'audio/wav', 'tone.wav', 'synthetic'))
        s.store.conn.execute("INSERT OR IGNORE INTO project_objects VALUES (?,?,'managed',?)",
                             (p, object_digest, 'synthetic'))
        s.store.conn.execute("INSERT INTO generations VALUES (?,?,NULL,'audio','completed',?,1,?,?)",
                             (generation, p, canonical_json({'params': {'duration_seconds': 1.25}, 'prompt': 'keep me'}), 'synthetic', 'synthetic'))
        s.store.conn.execute("INSERT INTO generation_variants(id,generation_id,object_id,variant_type,metadata_json,created_at) VALUES (?,?,?,'original',?,?)",
                             (variant, generation, object_digest, canonical_json({'is_primary': True, 'authoring': {'opaque': [1, None]}}), 'synthetic'))
    selection = dict(asset='sound-1', generation_id=generation, variant_id=variant, object_id='sha256:' + object_digest)
    # This internal authority reconstruction models the catalog producer's
    # digest calculation, independently of the request-bound read under test.
    with s.store._mutex:
        selection['catalog_digest'] = s._selected_project_media(p, selection)['catalog_digest']
    return selection


def request_for(p, selection, *, key='save-1'):
    request = wire(p, key=key)
    request['change']['commands'] = [{
        'op': 'timeline.add', 'select': 'parent/track:A1',
        'args': {'media': copy.deepcopy(selection), 'at': 3.5, 'createdID': 'reserved-clip'},
        'expect': {'parent/clip:reserved-clip::': {'state': 'absent'}},
    }]
    return request


def prepare(s, p, request):
    value = acceptance(s, p, request=request)
    value['evidence']['commands'] = copy.deepcopy(request['change']['commands'])
    value['result']['change']['commands'] = copy.deepcopy(request['change']['commands'])
    value['result']['id_map'] = {'createdID': 'parent/clip:reserved-clip'}
    return value


def snapshot(s):
    # Covers revisions, heads, journal, command ledgers, project/media rows and
    # references, including values rather than merely row counts.
    return '\n'.join(s.store.conn.iterdump())


def mutate(s, sql, args=()):
    with s.store._mutex, s.store._transaction():
        s.store.conn.execute(sql, args)


def test_detached_record_canonical_digest_and_ui_stability(fixture):
    s, p = fixture
    selection = media(s, p)
    request = request_for(p, selection)
    port = s._request_commit_port(request, IDENTITY)
    value = port.selected_media(selection)
    assert set(value) == {'realm_id', 'project_id', *selection, 'generation', 'variant', 'entry'}
    assert value['entry'] == {'object_id': selection['object_id'], 'media_type': 'audio/wav',
                              'size': 4, 'filename': 'tone.wav', 'duration_seconds': 1.25}
    assert value['variant']['metadata'] == {'authoring': {'opaque': [1, None]}}
    assert value['catalog_digest'] == digest({k: v for k, v in value.items() if k != 'catalog_digest'})
    value['generation']['metadata']['prompt'] = 'detached edit'
    mutate(s, "UPDATE generation_variants SET viewed_at='now', metadata_json=? WHERE id='v1'",
           (json.dumps({'authoring': {'opaque': [1, None]}, 'is_primary': False}),))
    fresh = s._request_commit_port(request, IDENTITY).selected_media(selection)
    assert fresh == port.selected_media(selection)
    assert fresh['generation']['metadata']['prompt'] == 'keep me'
    assert not {'store', 'service', 'connection'} & set(dir(port))
    assert set(port.revision_closure('parent-1')) == {'parent_revision', 'shot_revisions', 'internal_timeline_revisions'}


@pytest.mark.parametrize('field,value', [
    ('generation_id', 'missing'), ('variant_id', 'missing'), ('object_id', 'sha256:' + 'b' * 64),
    ('catalog_digest', 'sha256:' + '0' * 64), ('object_id', 'not-canonical'),
    ('asset', ''), ('realm_id', 'foreign'),
])
def test_missing_stale_invalid_selection_refuses_without_writes(fixture, field, value):
    s, p = fixture
    selected = media(s, p)
    selected[field] = value
    before = snapshot(s)
    with pytest.raises((NotFoundError, ConflictError, ValidationError)):
        s._request_commit_port(request_for(p, selected), IDENTITY).selected_media(selected)
    assert snapshot(s) == before


@pytest.mark.parametrize('mutation', [
    "UPDATE generations SET status='failed' WHERE id='g1'",
    "UPDATE generation_variants SET generation_id='g2' WHERE id='v1'",
    "UPDATE generation_variants SET object_id=NULL WHERE id='v1'",
    "DELETE FROM project_objects WHERE digest='" + 'a' * 64 + "'",
    "UPDATE project_objects SET relation='external' WHERE digest='" + 'a' * 64 + "'",
    "UPDATE generations SET metadata_json='[]' WHERE id='g1'",
    "UPDATE generations SET metadata_json='not-json' WHERE id='g1'",
    "UPDATE generations SET metadata_json='{\"params\":{\"duration_seconds\":-1}}' WHERE id='g1'",
    "UPDATE generation_variants SET metadata_json='{\"media_type\":\"video/mp4\"}' WHERE id='v1'",
    "UPDATE objects SET original_name='/private/media.wav' WHERE digest='" + 'a' * 64 + "'",
])
def test_invalid_authority_rows_refuse_atomically(fixture, mutation):
    s, p = fixture
    selected = media(s, p)
    media(s, p, generation='g2', variant='v2', object_digest='b' * 64)
    mutate(s, mutation)
    before = snapshot(s)
    with pytest.raises((NotFoundError, ConflictError, ValidationError)):
        s._request_commit_port(request_for(p, selected), IDENTITY).selected_media(selected)
    assert snapshot(s) == before


def test_foreign_project_cross_generation_and_realm_refuse(fixture, monkeypatch):
    s, p = fixture
    other = s.create_project({'slug': 'other', 'name': 'Other'}, idempotency_key='other')['id']
    selected = media(s, other)
    before = snapshot(s)
    with pytest.raises(NotFoundError):
        s._request_commit_port(request_for(p, selected), IDENTITY).selected_media(selected)
    assert snapshot(s) == before
    selected = media(s, p, generation='g2', variant='v2', object_digest='b' * 64)
    selected['variant_id'] = 'v1'
    with pytest.raises(NotFoundError):
        s._request_commit_port(request_for(p, selected), IDENTITY).selected_media(selected)
    monkeypatch.setattr(s, 'realm', {**s.realm, 'id': 'foreign-realm'})
    before = snapshot(s)
    with pytest.raises(AuthorizationError, match='realm'):
        s._request_commit_port(request_for(p, selected), IDENTITY).selected_media(selected)
    assert snapshot(s) == before


@pytest.mark.parametrize('identity', [None, {'actor': 'reader', 'scopes': ['projects:read']},
    {**IDENTITY, 'connector_assertion': {'realm_id': 'foreign', 'connector_id': 'missing-grant'}}])
def test_missing_capability_or_grant_cannot_read_or_accept(fixture, identity):
    s, p = fixture
    selection = media(s, p)
    request = request_for(p, selection)
    before = snapshot(s)
    port = s._request_commit_port(request, identity)
    with pytest.raises(AuthorizationError):
        port.selected_media(selection)
    with pytest.raises((AuthorizationError, ValidationError)):
        port.accept(prepare(s, p, request))
    assert snapshot(s) == before


def test_read_is_bound_to_declared_selection_and_not_caller_objects(fixture):
    s, p = fixture
    selection = media(s, p)
    other = media(s, p, generation='g2', variant='v2', object_digest='b' * 64)
    request = request_for(p, selection)
    port = s._request_commit_port(request, IDENTITY)
    request['change']['commands'][0]['args']['media'] = other
    before = snapshot(s)
    with pytest.raises(AuthorizationError):
        port.selected_media(other)
    with pytest.raises(ValidationError, match='must be read'):
        port.accept(prepare(s, p, request_for(p, selection)))
    assert snapshot(s) == before
    assert port.selected_media(selection)['variant_id'] == 'v1'


@pytest.mark.parametrize('sql,args', [
    ("UPDATE generations SET metadata_json=? WHERE id='g1'", ('{"params":{"duration_seconds":2}}',)),
    ("UPDATE generation_variants SET metadata_json=? WHERE id='v1'", ('{"authoring":{"changed":true}}',)),
    ("UPDATE generation_variants SET object_id=? WHERE id='v1'", ('b' * 64,)),
    ("UPDATE generations SET project_id=? WHERE id='g1'", ('OTHER',)),
    ("DELETE FROM project_objects WHERE project_id=? AND digest=?", ('PROJECT', 'a' * 64)),
    ("UPDATE objects SET media_type='video/mp4' WHERE digest=?", ('a' * 64,)),
])
def test_selected_mutation_after_read_refuses_in_accept_transaction(fixture, monkeypatch, sql, args):
    s, p = fixture
    selection = media(s, p)
    other = s.create_project({'slug': 'other', 'name': 'Other'}, idempotency_key='other')['id']
    media(s, p, generation='g2', variant='v2', object_digest='b' * 64)
    request = request_for(p, selection)
    port = s._request_commit_port(request, IDENTITY)
    captured = port.selected_media(selection)
    prepared = prepare(s, p, request)
    mutate(s, sql, tuple(p if v == 'PROJECT' else other if v == 'OTHER' else v for v in args))
    assert port.selected_media(selection) == captured  # never refresh on retry
    original = s._selected_project_media
    calls = []
    def checked(*args):
        calls.append(s.store.conn.in_transaction)
        return original(*args)
    monkeypatch.setattr(s, '_selected_project_media', checked)
    before = snapshot(s)
    with pytest.raises((ConflictError, NotFoundError, ValidationError)):
        port.accept(prepared)
    assert calls == [True]
    assert snapshot(s) == before


def test_unrelated_catalog_mutation_accepts_and_exact_adapter_result(fixture):
    s, p = fixture
    selection = media(s, p)
    request = request_for(p, selection)
    port = s._request_commit_port(request, IDENTITY)
    port.selected_media(selection)
    media(s, p, generation='unrelated', variant='unrelated')
    mutate(s, "UPDATE generations SET metadata_json='{\"unrelated\":true}' WHERE id='unrelated'")
    result = port.accept(prepare(s, p, request))
    assert set(result['stored_result']) == set(result_template(request, digest(request)))
    assert result['stored_result'] == s.lookup_request(p, 'main', request['request_id'])['result']
    assert result['outcome'] == 'accepted'
    assert result['stored_result']['id_map'] == {'createdID': 'parent/clip:reserved-clip'}
    assert s.evidence(result['receipt']['evidence_digest'])['commands'] == request['change']['commands']


def test_head_race_rebase_keeps_input_and_reserved_id_and_replay(fixture):
    s, p = fixture
    selection = media(s, p)
    request = request_for(p, selection)
    port = s._request_commit_port(request, IDENTITY)
    captured = port.selected_media(selection)
    stale = prepare(s, p, request)
    s.accept(acceptance(s, p, key='concurrent'), identity=IDENTITY)
    before = snapshot(s)
    with pytest.raises(ConflictError) as exc:
        port.accept(stale)
    assert exc.value.details['code'] == 'StaleHead'
    assert snapshot(s) == before
    assert port.selected_media(selection) == captured
    rebased = prepare(s, p, request)
    assert rebased['result']['id_map'] == stale['result']['id_map']
    accepted = port.accept(rebased)
    mutate(s, "DELETE FROM generation_variants WHERE id='v1'")
    mutate(s, "DELETE FROM project_objects WHERE digest=?", ('a' * 64,))
    before = snapshot(s)
    assert port.accept(rebased)['stored_result'] == accepted['stored_result']
    # Lost-response retry is served before provider/read/capability invocation.
    assert s.commit_timeline(p, 'main', request, idempotency_key=request['request_id'], identity=IDENTITY) == accepted['stored_result']
    assert snapshot(s) == before


def test_commit_adapter_reads_real_producer_once_and_replays(fixture):
    s, p = fixture
    selection = media(s, p)
    request = request_for(p, selection)
    calls = []
    class Provider:
        interface_version = 1
        contract_digest = SCHEMA_DIGEST
        def commit(self, request, port):
            calls.append(port.selected_media(request['change']['commands'][0]['args']['media']))
            return port.accept(prepare(s, p, request))['stored_result']
    s.register_timeline_commit_provider(Provider())
    first = s.commit_timeline(p, 'main', request, idempotency_key=request['request_id'], identity=IDENTITY)
    assert first['status'] == 'accepted'
    mutate(s, "UPDATE generations SET metadata_json='{}' WHERE id='g1'")
    assert s.commit_timeline(p, 'main', request, idempotency_key=request['request_id'], identity=IDENTITY) == first
    assert len(calls) == 1


def test_concurrent_accepts_and_rollback_after_media_recheck(fixture, monkeypatch):
    s, p = fixture
    selection = media(s, p)
    ports, prepared = [], []
    for key in ('compete-1', 'compete-2'):
        request = request_for(p, selection, key=key)
        port = s._request_commit_port(request, IDENTITY)
        port.selected_media(selection)
        ports.append(port)
        prepared.append(prepare(s, p, request))
    def attempt(i):
        try:
            return ports[i].accept(prepared[i])['outcome']
        except ConflictError as exc:
            assert exc.details['code'] == 'StaleHead'
            return 'stale'
    with ThreadPoolExecutor(max_workers=2) as workers:
        assert sorted(workers.map(attempt, range(2))) == ['accepted', 'stale']
    request = request_for(p, selection, key='rollback')
    port = s._request_commit_port(request, IDENTITY)
    port.selected_media(selection)
    prepared = prepare(s, p, request)
    record = s._command_record
    def fail(kind, *args, **kwargs):
        if kind == 'timeline.commit':
            raise RuntimeError('rollback after media validation and publication')
        return record(kind, *args, **kwargs)
    monkeypatch.setattr(s, '_command_record', fail)
    before = snapshot(s)
    with pytest.raises(RuntimeError, match='rollback'):
        port.accept(prepared)
    assert snapshot(s) == before


def test_accept_holds_sqlite_write_fence_through_publication(fixture, monkeypatch):
    s, p = fixture
    selection = media(s, p)
    request = request_for(p, selection)
    port = s._request_commit_port(request, IDENTITY)
    port.selected_media(selection)
    original = s.publish_parent_composition
    fenced = []
    def publish(*args, **kwargs):
        assert s.store.conn.in_transaction
        # A second actual SQL writer cannot slip a selected-record mutation
        # between dependency verification and nested composition publication.
        with sqlite3.connect(s.store.db_path, timeout=0) as competitor:
            with pytest.raises(sqlite3.OperationalError, match='locked'):
                competitor.execute("UPDATE generations SET metadata_json='{}' WHERE id='g1'")
        fenced.append(True)
        return original(*args, **kwargs)
    monkeypatch.setattr(s, 'publish_parent_composition', publish)
    assert port.accept(prepare(s, p, request))['outcome'] == 'accepted'
    assert fenced == [True]


def test_digest_canonical_order_transport_projection_and_optional_duration(fixture):
    s, p = fixture
    selection = media(s, p)
    metadata = {'params': {'duration_seconds': 1.25}, 'prompt': 'keep me',
                'object_location': {'local_path': '/private/never-read'},
                'browser_url': 'https://invalid.example/never-open'}
    mutate(s, "UPDATE generations SET metadata_json=? WHERE id='g1'", (json.dumps(metadata),))
    result = s._request_commit_port(request_for(p, selection), IDENTITY).selected_media(selection)
    assert result['generation']['metadata'] == {'params': {'duration_seconds': 1.25}, 'prompt': 'keep me'}
    mutate(s, "UPDATE generations SET metadata_json=? WHERE id='g1'", (json.dumps(dict(reversed(list(metadata.items())))),))
    assert s._request_commit_port(request_for(p, selection), IDENTITY).selected_media(selection) == result
    mutate(s, "UPDATE generations SET metadata_json='{\"params\":{}}' WHERE id='g1'")
    without_duration = {k: v for k, v in selection.items() if k != 'catalog_digest'}
    with s.store._mutex:
        without_duration['catalog_digest'] = s._selected_project_media(p, without_duration)['catalog_digest']
    # Runtime does not invent timing: D must require SFX natural duration or
    # the explicit duration/range for other insertion forms.
    assert 'duration_seconds' not in s._request_commit_port(request_for(p, without_duration), IDENTITY).selected_media(without_duration)['entry']


@pytest.mark.parametrize('alter', ['omit', 'substitute', 'unbound'])
def test_selected_dependency_must_survive_in_command_evidence(fixture, alter):
    s, p = fixture
    selection = media(s, p)
    request = request_for(p, selection)
    port = s._request_commit_port(request, IDENTITY)
    port.selected_media(selection)
    prepared = prepare(s, p, request)
    if alter == 'omit':
        prepared['evidence']['commands'] = []
    elif alter == 'substitute':
        prepared['evidence']['commands'][0]['args']['media']['asset'] = 'different'
    before = snapshot(s)
    with pytest.raises(ValidationError, match='recorded command evidence'):
        if alter == 'unbound':
            s.accept(prepared, identity=IDENTITY)
        else:
            port.accept(prepared)
    assert snapshot(s) == before
