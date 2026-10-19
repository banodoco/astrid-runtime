"""Production COMMIT port/auth/transaction with an explicit synthetic relay.

No renderer/native source admission witness is claimed by this fixture.
"""
import copy
from types import SimpleNamespace

import pytest

from test_storage_preparation_relay import source_composition

from runtime_protocol import authoring_scene as scene
from runtime_protocol.auth import CredentialStore
from runtime_protocol.errors import (AuthoringInvocationRevocationReason as Reason,
                                     AuthorizationError, AuthorizationGuard as Guard)
from runtime_protocol.timeline_commit import digest
from test_timeline_accept import wire, acceptance, count
from test_selected_media_commit import snapshot


@pytest.fixture
def scene_native_boundary(monkeypatch):
    """Synthetic retained identities; real codec/listener/handler, no native probes."""
    from test_storage_preparation_relay import ACTOR
    from astrid.core.execution import authoring_scene_transport as transport
    from astrid.core.execution import custody_broker as custody
    from banodoco_local import custody_broker as runtime_custody
    class Actor:
        def verify(self): return copy.deepcopy(ACTOR)
    for api in (custody.AuthenticatedCleanupActor, runtime_custody.AuthenticatedCleanupActor):
        monkeypatch.setattr(api, "current", lambda: Actor())
        monkeypatch.setattr(api, "private_peer", lambda channel: Actor())
    monkeypatch.setattr(transport, "_actor", lambda identity: Actor())
    return ACTOR


@pytest.fixture
def fixture(tmp_path):
    from test_shot_composition_runtime import _service, _publication
    service, project = _service(tmp_path)
    publication = _publication(project)
    # Current shared SDK track semantics require the fixture's picture track.
    # Keep the clip/domain and all production validation unchanged.
    publication["parent_composition"]["config"]["tracks"] = [
        {"id": "video-1", "kind": "visual"}]
    service.publish_parent_composition(project, "main", publication, idempotency_key="initial")
    try:
        yield service, project
    finally:
        service.close()


def projection():
    return dict(timeline=dict(theme='banodoco-default', clips=[], tracks=[], theme_overrides={}),
                assets={'assets': {}}, fps=24, width=320, height=180, roles={})


@pytest.mark.parametrize('edge', [None, 'path', 'url', 'extra', 'type', 'divergent', 'identity'])
def test_checkout_display_registry_is_projected_to_strict_cas_without_location_authority(edge):
    from astrid.core.execution import authoring_scene_protocol as wire
    from astrid.core.execution.remotion_frame_owner import FrameOwnerError
    value = projection(); oid = 'sha256:' + 'a' * 64
    entry = dict(media_id=oid, file=oid, type='video', width=16, height=16)
    if edge == 'path': entry['file'] = '/unadmitted/location'
    elif edge == 'url': entry['file'] = 'https://unadmitted.invalid/media'
    elif edge == 'extra': entry['url'] = oid
    elif edge == 'type': entry['type'] = 'callback'
    elif edge == 'divergent': entry['object_id'] = 'sha256:' + 'b' * 64
    elif edge == 'identity': entry['media_id'] = 'not-cas'
    value['assets']['assets']['picture'] = entry
    original = copy.deepcopy(value)
    if edge is not None:
        with pytest.raises(FrameOwnerError): scene._scene_cas_projection(value)
    else:
        projected = scene._scene_cas_projection(value)
        assert wire.assets(projected) == {oid}
        assert projected['assets']['assets']['picture'] == dict(media_id=oid, width=16, height=16)
    assert value == original


@pytest.fixture
def bound(fixture, tmp_path, monkeypatch):
    from astrid.core.execution import authoring_scene_protocol as protocol
    s, p = fixture
    credentials = CredentialStore(tmp_path / 'credentials')
    token, _ = credentials.provision('fixture-writer', ['projects:write', 'projects:read', 'objects:read'])
    identity = dict(actor='fixture-writer', scopes=['projects:write', 'objects:read'],
                    _credential_binding=credentials._sha256(token.encode()))
    s._task_credentials = credentials
    calls = []
    class Relay:
        def __init__(self):
            self.config = SimpleNamespace(binding={k: (1 if k == 'owner_generation' else 'astrid-v1' if k == 'provider_id'
                else 'sha256:' + 'a' * 64 if k.endswith('digest') or k == 'renderer_closure' else k)
                for k in protocol.CONTEXT_FIELDS})
            self.on_reply = lambda: None
            self.closed = False
        def check_live(self):
            if self.closed: raise AuthorizationError('relay revoked')
        def exchange(self, request, *, guard, cancelled):
            guard()
            protocol.validate_request(request, self.config.binding)
            calls.append(copy.deepcopy(request))
            self.on_reply()
            return [dict(frame=f, layers=[], coverage='GAP', content=None, findings=[]) for f in request['frames']]
        def close(self): self.closed = True
    relay = s._authoring_scene_relay = Relay()
    # Narrow trusted admission/transport fixture; actual request port/session/
    # credential rechecks and the existing atomic acceptance boundary stay real.
    monkeypatch.setattr(scene, 'check_binding', lambda service, selected: selected.check_live())
    s._timeline_commit_provider = SimpleNamespace(requires_scene_evaluation=True)
    return SimpleNamespace(s=s, p=p, identity=identity, credentials=credentials, relay=relay, calls=calls)


def evaluate(w, port, candidate):
    from astrid.core.execution import authoring_scene_protocol as protocol
    client = port.scene_evaluator(candidate)
    value = projection()
    client.query_scene(revision_digest=protocol.digest(value)[7:], scene=value, frames=[0])
    client.complete()
    client.close()
    return client


def test_private_refusal_keeps_source_frames_without_exception_text(bound, monkeypatch, capsys):
    from astrid.core.execution import authoring_scene_protocol as protocol
    from astrid.core.execution.remotion_frame_owner import FrameOwnerError
    w = bound; port = scene.RequestSceneEvaluation(w.s, wire(w.p), w.identity)
    client = port.evaluator({'candidate': 'bound'})
    def failed(*args, **kwargs): raise TypeError('secret-credential /private/untrusted-path')
    monkeypatch.setattr(w.relay, 'exchange', failed)
    value = projection()
    with pytest.raises(FrameOwnerError, match='authoring_evaluation_refused'):
        client.query_scene(revision_digest=protocol.digest(value)[7:], scene=value, frames=[0])
    captured = capsys.readouterr().err
    assert 'TypeError' in captured and 'test_authoring_scene.py' in captured
    assert 'secret-credential' not in captured and '/private/untrusted-path' not in captured
    port.close()


def test_authenticated_port_binds_complete_candidate_at_atomic_accept(bound):
    w = bound
    body = wire(w.p)
    prepared = acceptance(w.s, w.p, request=body)
    port = w.s._request_commit_port(body, w.identity)
    evaluate(w, port, prepared['result']['canonical_document'])
    result = port.accept(prepared)
    assert result['stored_result']['status'] == 'accepted'
    binding = w.calls[0]['invocation']
    assert binding['request_hash'] == digest(body)
    assert binding['candidate_digest'] == digest(prepared['result']['canonical_document'])
    assert binding['actor'] == w.identity['actor'] and binding['actor_session'] != body['session_id']
    port.close()
    # Replay is durable and precedes owner evaluation, even after relay loss.
    w.s._authoring_scene_relay = None
    w.s._timeline_commit_provider = SimpleNamespace(commit=lambda *a: pytest.fail('replayed provider invoked'))
    assert w.s.commit_timeline(w.p, 'main', body, idempotency_key=body['request_id'], identity=w.identity) == result['stored_result']


@pytest.mark.parametrize('phase', ['before', 'after_reply', 'accept'])
def test_credential_loss_refuses_without_publication(bound, phase):
    from astrid.core.execution.remotion_frame_owner import FrameOwnerError
    w = bound
    body = wire(w.p)
    prepared = acceptance(w.s, w.p, request=body)
    port = w.s._request_commit_port(body, w.identity)
    before = count(w.s, 'parent_composition_publications')
    if phase == 'before': w.credentials.disable_actor(w.identity['actor'])
    elif phase == 'after_reply': w.relay.on_reply = lambda: w.credentials.disable_actor(w.identity['actor'])
    if phase == 'accept':
        evaluate(w, port, prepared['result']['canonical_document'])
        w.credentials.disable_actor(w.identity['actor'])
    with pytest.raises((AuthorizationError, FrameOwnerError)):
        if phase == 'accept': port.accept(prepared)
        else: evaluate(w, port, prepared['result']['canonical_document'])
    assert count(w.s, 'parent_composition_publications') == before
    assert w.s.lookup_request(w.p, 'main', body['request_id']) is None
    if phase == 'before': assert w.calls == []
    port.close()


@pytest.mark.parametrize('case', ['missing', 'candidate', 'request', 'revoked', 'source', 'new_retry'])
def test_atomic_candidate_and_lifecycle_fences(bound, case):
    w = bound
    body = wire(w.p)
    prepared = acceptance(w.s, w.p, request=body)
    port = w.s._request_commit_port(body, w.identity)
    if case != 'missing': evaluate(w, port, prepared['result']['canonical_document'])
    if case == 'candidate':
        prepared['result']['canonical_document']['foreign'] = True
        # Keep all ordinary digest validation coherent to reach scene fence.
        prepared['result']['document_digest'] = digest(prepared['result']['canonical_document'])
        prepared['evidence']['digests']['after'] = prepared['result']['document_digest']
    elif case == 'request': prepared['request_hash'] = digest({'foreign': True})
    elif case == 'revoked': port.close()
    elif case == 'source': w.relay.closed = True
    elif case == 'new_retry': port.scene_evaluator({'different post-rebase candidate': True})
    before = snapshot(w.s)
    before_publications = count(w.s, 'parent_composition_publications')
    if case == 'revoked':
        with pytest.raises(AuthorizationError) as error: port.accept(prepared)
        assert error.value._authorization_guard is Guard.AUTHORING_INVOCATION_REVOKED
        assert error.value._authoring_invocation_reason is Reason.EVALUATION_CANCELLED
    else:
        with pytest.raises(Exception): port.accept(prepared)
    assert snapshot(w.s) == before
    assert count(w.s, 'parent_composition_publications') == before_publications
    assert w.s.lookup_request(w.p, 'main', body['request_id']) is None
    port.close()


def test_dry_run_cannot_accept_or_reserve_even_with_scene_completion(bound):
    w = bound
    body = wire(w.p, dry_run=True)
    port = w.s._request_commit_port(body, w.identity)
    evaluate(w, port, {'candidate': True})
    with pytest.raises(AuthorizationError, match='dry-run'):
        port.accept({})
    assert w.s.lookup_request(w.p, 'main', body['request_id']) is None
    port.close()


def test_worker_credential_and_missing_session_never_reach_relay(bound):
    w = bound
    for identity in (dict(actor='fixture-writer', scopes=['projects:write']),
                     {**w.identity, 'execution_binding': {'worker': True}}):
        port = w.s._request_commit_port(wire(w.p), identity)
        with pytest.raises(AuthorizationError): port.scene_evaluator({'candidate': True})
        port.close()
    assert w.calls == []


_REAL_CHECK_BINDING = scene.check_binding


@pytest.mark.parametrize('change', [None, 'epoch', 'source', 'dependency', 'capability', 'session'])
def test_real_registered_source_binding_checks_exact_catalog_tuple(bound, change):
    from astrid.core.execution.authoring_scene_startup import provider_digest
    w = bound
    s, c = w.s, w.relay.config.binding
    s.runtime_instance_id = 'selected-instance'
    c.update(runtime_realm_id=s.realm['id'], runtime_instance_id=s.runtime_instance_id,
             runtime_session_id=s.runtime_session_id, provider_digest=provider_digest())
    descriptor = dict(capability_id='rendering.timeline_visualize', definition_digest=c['capability_digest'],
                      status='ready', required_resource_keys=[])
    s.store.upsert_executor(c['executor_id'], [descriptor], runtime_epoch=s.store._current_runtime_epoch(),
        source_epoch=c['source_epoch'], source_digest=c['executor_source_digest'][7:],
        dependency_digest=c['executor_dependency_digest'][7:])
    if change == 'epoch': c['source_epoch'] = 'foreign'
    elif change == 'source': c['executor_source_digest'] = 'sha256:' + '0' * 64
    elif change == 'dependency': c['executor_dependency_digest'] = 'sha256:' + '0' * 64
    elif change == 'capability': c['capability_digest'] = 'sha256:' + '0' * 64
    elif change == 'session': c['runtime_session_id'] = 'foreign'
    if change is None: _REAL_CHECK_BINDING(s, w.relay)
    else:
        with pytest.raises(Exception): _REAL_CHECK_BINDING(s, w.relay)


@pytest.mark.parametrize('phase', ['reply', 'accept'])
def test_project_dependency_custody_rechecked_before_reply_and_accept(bound, monkeypatch, phase):
    from astrid.core.execution import authoring_scene_protocol as protocol
    from astrid.core.execution.remotion_frame_owner import FrameOwnerError
    w = bound
    oid = w.s.ingest(w.p, b'synthetic media', media_type='image/png', idempotency_key='asset')['data']['object_id']
    body = wire(w.p)
    prepared = acceptance(w.s, w.p, request=body)
    port = w.s._request_commit_port(body, w.identity)
    client = port.scene_evaluator(prepared['result']['canonical_document'])
    value = projection()
    value['assets']['assets']['x'] = {'media_id': oid}
    def revoke():
        w.s.store.conn.execute('DELETE FROM project_objects WHERE project_id=? AND digest=?', (w.p, oid[7:]))
    if phase == 'reply': w.relay.on_reply = revoke
    if phase == 'reply':
        with pytest.raises(FrameOwnerError):
            client.query_scene(revision_digest=protocol.digest(value)[7:], scene=value, frames=[0])
    else:
        client.query_scene(revision_digest=protocol.digest(value)[7:], scene=value, frames=[0])
        client.complete()
        revoke()
        with pytest.raises(Exception): port.accept(prepared)
    assert w.s.lookup_request(w.p, 'main', body['request_id']) is None
    port.close()


@pytest.mark.parametrize('dry_run', [True, False])
def test_installed_provider_uses_request_port_without_global_scene_client(bound, monkeypatch, dry_run):
    from astrid.sdk.timeline.commit import create_runtime_commit_service
    from astrid.core.timeline import scene_answers
    w = bound
    # Prove the ordinary scene_answers implementation consumes the provider's
    # explicit request client; no caller installs a private thread-local client.
    assert getattr(scene_answers._local, 'client', None) is None
    w.s._timeline_commit_provider = create_runtime_commit_service()
    body = wire(w.p, dry_run=dry_run)
    before = count(w.s, 'parent_composition_publications')
    result = w.s.commit_timeline(w.p, 'main', body, idempotency_key=body['request_id'], identity=w.identity)
    assert result['status'] in ({'preview'} if dry_run else {'accepted', 'no_change'}), result.get('error', result)
    assert w.calls
    assert {v['invocation']['candidate_digest'] for v in w.calls} == {digest(result['canonical_document'])}
    assert getattr(scene_answers._local, 'client', None) is None
    if dry_run:
        assert count(w.s, 'parent_composition_publications') == before
        assert w.s.lookup_request(w.p, 'main', body['request_id']) is None
    else:
        assert w.s.lookup_request(w.p, 'main', body['request_id'])['result'] == result


@pytest.mark.parametrize('failure', ['unknown', 'malformed', 'oversize', 'revoked'])
def test_real_provider_refusals_never_preview_or_accept(bound, monkeypatch, failure):
    from astrid.sdk.timeline.commit import create_runtime_commit_service
    from astrid.core.timeline import scene_answers
    w = bound
    w.s._timeline_commit_provider = create_runtime_commit_service()
    original = w.relay.exchange
    def failed(request, **kw):
        value = original(request, **kw)
        if failure == 'unknown': value[0]['coverage'] = 'UNKNOWN'
        elif failure == 'malformed': value[0]['frame'] = True
        elif failure == 'oversize': value[0]['findings'] = ['x' * (1024 * 1024)]
        elif failure == 'revoked': w.credentials.disable_actor(w.identity['actor'])
        return value
    monkeypatch.setattr(w.relay, 'exchange', failed)
    before = count(w.s, 'parent_composition_publications')
    body = wire(w.p, dry_run=True)
    result = w.s.commit_timeline(w.p, 'main', body, idempotency_key=body['request_id'], identity=w.identity)
    assert result['status'] in {'refused', 'error'}, result
    assert count(w.s, 'parent_composition_publications') == before
    assert w.s.lookup_request(w.p, 'main', body['request_id']) is None
    assert getattr(scene_answers._local, 'client', None) is None


def test_superseded_candidate_cannot_complete_late(bound):
    from astrid.core.execution import authoring_scene_protocol as protocol
    from astrid.core.execution.remotion_frame_owner import FrameOwnerError
    w = bound
    port = w.s._request_commit_port(wire(w.p), w.identity)
    value = projection()
    client = port.scene_evaluator({'candidate': 'old'})
    client.query_scene(revision_digest=protocol.digest(value)[7:], scene=value, frames=[0])
    port.scene_evaluator({'candidate': 'new'})
    with pytest.raises(FrameOwnerError): client.complete()
    port.close()


@pytest.mark.parametrize('failure', ['credential', 'invocation'])
def test_authority_loss_after_staged_publication_rolls_back_atomic_accept(bound, monkeypatch, failure):
    w = bound
    body = wire(w.p)
    prepared = acceptance(w.s, w.p, request=body)
    port = w.s._request_commit_port(body, w.identity)
    evaluate(w, port, prepared['result']['canonical_document'])
    original = w.s.publish_parent_composition
    def lose_after_staging(*args, **kwargs):
        result = original(*args, **kwargs)
        if failure == 'credential':
            w.credentials.disable_actor(w.identity['actor'])
        else:
            # Cancellation after the nested publication reaches the final
            # request-scoped invocation check inside the outer transaction.
            port.close()
        return result
    monkeypatch.setattr(w.s, 'publish_parent_composition', lose_after_staging)
    before = count(w.s, 'parent_composition_publications')
    full_before = snapshot(w.s)
    with pytest.raises(AuthorizationError) as error: port.accept(prepared)
    if failure == 'invocation':
        assert error.value._authorization_guard is Guard.AUTHORING_INVOCATION_REVOKED
        assert error.value._authoring_invocation_reason is Reason.EVALUATION_CANCELLED
    assert snapshot(w.s) == full_before
    assert count(w.s, 'parent_composition_publications') == before
    assert w.s.lookup_request(w.p, 'main', body['request_id']) is None
    port.close()


def test_installed_astrid_provider_cannot_silently_omit_scene_port_contract():
    from runtime_protocol.timeline_commit import validate_timeline_commit_provider
    from runtime_protocol.contract_metadata import SCHEMA_DIGEST
    from runtime_protocol.errors import ValidationError
    provider = SimpleNamespace(provider_id='astrid-v1', interface_version=1, contract_digest=SCHEMA_DIGEST,
                               commit=lambda *args: None)
    for marker in (None, False, 1):
        provider.requires_scene_evaluation = marker
        with pytest.raises(ValidationError): validate_timeline_commit_provider(provider)
    provider.requires_scene_evaluation = True
    validate_timeline_commit_provider(provider)


@pytest.mark.parametrize('dry_run', [True, False])
def test_empty_timeline_preserves_existing_shared_completeness_semantics(bound, dry_run):
    from astrid.sdk.timeline.commit import create_runtime_commit_service
    from test_shot_composition_runtime import _publication
    w = bound
    head = w.s.head(w.p, 'main')
    publication = _publication(w.p, expected_head=head['revision_id'], parent_revision_id='empty-scene')
    publication['parent_composition']['occurrences'] = []
    publication['shot_revisions'] = []
    publication['internal_timeline_revisions'] = []
    w.s.publish_parent_composition(w.p, 'main', publication, idempotency_key='empty-scene')
    w.s._timeline_commit_provider = create_runtime_commit_service()
    body = wire(w.p, dry_run=dry_run)
    head = w.s.head(w.p, 'main')
    body.update(base_revision_id=head['revision_id'], base_publication_id=head['publication_id'])
    result = w.s.commit_timeline(w.p, 'main', body, idempotency_key=body['request_id'], identity=w.identity)
    assert result['status'] in ({'preview'} if dry_run else {'accepted', 'no_change'}), result.get('error', result)
    assert not w.calls  # zero sampled frames; no manufactured answer


@pytest.fixture
def empty_bound(bound, monkeypatch, scene_native_boundary):
    """Public service/credential path plus real private Host transport.

    Selected native activation/source inventory is explicit fixture authority;
    there is no installed Host/profile or C live COMMIT in this offline proof.
    """
    import tempfile
    import threading
    from pathlib import Path
    from astrid.core.execution import authoring_scene_protocol as protocol
    from astrid.core.execution import authoring_scene_transport as transport
    from astrid.core.execution import authoring_scene_startup as startup
    from astrid.core.execution.custody_broker import AuthenticatedCleanupActor
    from astrid.core.execution.storage_preparation_transport import ProcessIdentity
    from astrid.core.execution.generic_host import GenericPackHost
    w = bound
    binding = {**{k: v for k, v in w.relay.config.binding.items()
                  if k not in {"renderer_closure", "owner_generation"}}, "mode": protocol.EMPTY_MODE}
    with tempfile.TemporaryDirectory(prefix="rt171-", dir="/private/tmp") as temporary:
        identity = ProcessIdentity(**AuthenticatedCleanupActor.current().verify())
        config = transport.AuthoringSceneConfig(Path(temporary), identity, identity, binding, "a" * 64)
        host = SimpleNamespace(_shutdown=threading.Event(), _authoring_scene_lock=threading.Lock(),
            _authoring_scene_listener=None,
            _authoring_scene_session=lambda *a: pytest.fail("empty commit acquired renderer"))
        monkeypatch.setattr(startup, "validate_host", lambda *a: None)
        listener = GenericPackHost.start_authoring_scene(host, config, {})
        relay = transport.AuthoringSceneRelay(listener.config)
        w.s._authoring_scene_relay = w.relay = relay
        original = relay.exchange
        def exchange(request, **kwargs):
            w.calls.append(copy.deepcopy(request))
            return original(request, **kwargs)
        monkeypatch.setattr(relay, "exchange", exchange)
        try:
            yield w
        finally:
            relay.close()
            listener.close()


def publish_empty(w):
    from test_shot_composition_runtime import _publication
    head = w.s.head(w.p, "main")
    value = _publication(w.p, expected_head=head["revision_id"], parent_revision_id="empty-scene",
                         config={"tracks": [{"id": "V1", "kind": "visual", "opacity": 1}]})
    value["parent_composition"]["occurrences"] = []
    value["shot_revisions"] = []
    value["internal_timeline_revisions"] = []
    w.s.publish_parent_composition(w.p, "main", value, idempotency_key="empty-scene")
    from astrid.sdk.timeline.commit import create_runtime_commit_service
    w.s._timeline_commit_provider = create_runtime_commit_service()
    body = wire(w.p)
    head = w.s.head(w.p, "main")
    body.update(base_revision_id=head["revision_id"], base_publication_id=head["publication_id"])
    body["change"]["commands"] = [dict(op="timeline.set", select="parent/track:V1",
        args=dict(values={"opacity": .625}, clear=[]),
        expect={"parent/track:V1::opacity": {"state": "present", "value": 1}})]
    return body


@pytest.fixture
def source_empty(source_composition, scene_native_boundary, monkeypatch):
    """Real static discovery, daemon composition, lazy resolution and empty codec.

    Only retained native/process authority and its action-child readiness
    observation are synthetic. The registered refusal remains unchanged.
    """
    import json
    import threading
    from astrid.core.execution import generic_host as hosts
    from astrid.core.execution import authoring_scene_protocol as protocol, authoring_scene_transport as transport
    from astrid.core.execution import authoring_scene_startup as startup
    from astrid.core.pack import source_setup
    from astrid.core.execution.storage_preparation_transport import ProcessIdentity
    from runtime_protocol.daemon import WORKER_ACTOR
    from test_shot_composition_runtime import _publication
    w = source_composition
    # This fixture owns its two source packs. Do not consult the user's managed
    # source catalogue, or inherit the transport-only fixture's 10ms race budget
    # for the real authenticated file/registration checks used here.
    monkeypatch.setenv(source_setup.SOURCE_STATE_ENV, str(w.profile.support_root / "fixture-sources.json"))
    w.d.local_worker_preparer.timeout_seconds = 1
    monkeypatch.setattr(hosts, "GenericPackHost", w.real_host_type)
    declaration = {"kind": "generator", "description": "Offline source regression",
        "invocation": {"kind": "command", "command": {"argv": ["{python_exec}", "-c", "raise RuntimeError('must not execute')"]}},
        "inputs": {"type": "object", "additionalProperties": True},
        "outputs": [{"name": "answer", "type": "file", "path_template": "{out}/answer.txt", "artifact_type": "text/plain"}],
        "metadata": {"adapter_family": "cpu", "resource_keys": ["cpu"], "estimated_scratch_bytes": 0, "estimated_output_bytes": 0}}
    for pack_id, action in (("synthetic", "bytes"), ("rendering", "timeline_visualize")):
        root = w.profile.support_root / pack_id
        root.mkdir()
        action_value = copy.deepcopy(declaration)
        if pack_id == "synthetic":
            (root / "actions").mkdir()
            (root / "actions" / "estimate.py").write_text("raise RuntimeError('estimator must not import or run')\n")
            action_value["metadata"]["storage_estimator"] = dict(schema_version=1, id="synthetic.bytes", version=1,
                policy_version="fixture-v1", path="actions/estimate.py", function="estimate")
        (root / "pack.yaml").write_text(json.dumps(dict(schema_version=3, id=pack_id, name=pack_id, version="1.0.0",
                                                       actions={action: action_value})))
    inventory = w.real_host_type(pack_roots=[w.profile.support_root])
    try:
        records = inventory.discover()
    finally:
        inventory.shutdown()
    assert {r.id for r in records} == {"synthetic.bytes", "rendering.timeline_visualize"}
    source = hosts._canonical_digest({r.id: r.source_digest for r in records})
    dependency = hosts._canonical_digest({r.id: r.dependency_digest for r in records})
    storage_record = next(r for r in records if r.id == "synthetic.bytes")
    # The action-child admission observation is the native boundary. Preserve
    # the Host's actual stable reason projection; never run that child here.
    from dataclasses import replace
    refusal_record = replace(storage_record, preflight={"action_child": {"ok": False, "reason": "selected action child unavailable"}})
    reason = hosts._preflight_unavailable_reason(refusal_record)
    descriptors = []
    for r in records:
        value = dict(capability_id=r.id, definition_digest=r.capability_digest)
        if r.has_request_storage_estimator:
            value.update(storage_estimate_contract=r.request_storage_estimate_contract, status="unavailable", unavailable_reason=reason)
        descriptors.append(value)
    w.s.register_executor(dict(executor_id=WORKER_ACTOR, runtime_epoch=w.s.store._current_runtime_epoch(),
        source_digest=source, dependency_digest=dependency,
        source_epoch="actual-static-discovery", capabilities=descriptors), idempotency_key="actual-static-register")
    rendering = next(r for r in records if r.id == "rendering.timeline_visualize")
    binding = dict(runtime_realm_id=w.s.realm["id"], runtime_instance_id=w.s.runtime_instance_id,
        runtime_session_id=w.s.runtime_session_id, executor_id=WORKER_ACTOR, host_instance_id=w.receipt["executor_incarnation"],
        source_epoch="actual-static-discovery", provider_id="astrid-v1", provider_digest=startup.provider_digest(),
        source_digest="sha256:" + rendering.source_digest, dependency_digest="sha256:" + rendering.dependency_digest,
        capability_digest=rendering.capability_digest, executor_source_digest="sha256:" + source.removeprefix("sha256:"),
        executor_dependency_digest="sha256:" + dependency.removeprefix("sha256:"), mode=protocol.EMPTY_MODE)
    initial = _publication(w.p)
    initial["parent_composition"]["config"]["tracks"] = [{"id": "video-1", "kind": "visual"}]
    w.s.publish_parent_composition(w.p, "main", initial, idempotency_key="source-initial")
    w.identity, w.calls = w.principal, []
    peer = ProcessIdentity(**scene_native_boundary)
    config = transport.AuthoringSceneConfig(w.profile.support_root, peer, peer, binding,
        w.profile.host_launch["boot_manifest_hash"].removeprefix("sha256:"))
    host = SimpleNamespace(_shutdown=threading.Event(), _authoring_scene_lock=threading.Lock(),
        _authoring_scene_listener=None, _authoring_scene_session=lambda *a: pytest.fail("renderer acquired"))
    monkeypatch.setattr(startup, "validate_host", lambda *a: None)
    listener = w.real_host_type.start_authoring_scene(host, config, {})
    w.d.start_local_worker(w.profile.profile_id, w.s.realm["id"])
    # No storage relay, estimator import/action, or eager authoring relay.
    assert w.s._preparation_relay is None and w.s._authoring_scene_relay is None
    original = transport.AuthoringSceneRelay.exchange
    def exchange(relay, request, **kwargs):
        w.calls.append(copy.deepcopy(request))
        return original(relay, request, **kwargs)
    monkeypatch.setattr(transport.AuthoringSceneRelay, "exchange", exchange)
    w.config, w.listener, w.storage_reason = listener.config, listener, reason
    try:
        yield w
    finally:
        if w.s._authoring_scene_relay is not None: w.s._authoring_scene_relay.close()
        listener.close()


def test_source_daemon_empty_selection_accepts_with_unavailable_storage(source_empty):
    from astrid.core.execution import authoring_scene_protocol as protocol
    w = source_empty
    body = publish_empty(w)
    result = w.s.commit_timeline(w.p, "main", body, idempotency_key=body["request_id"], identity=w.identity)
    assert result["status"] == "accepted", result
    assert result["canonical_document"]["parent"]["config"]["tracks"][0]["opacity"] == .625
    assert len(w.calls) == 1 and w.calls[0]["operation"] == protocol.EMPTY_OPERATION
    assert w.s._preparation_relay is None
    rows = {v["capability_id"]: v for v in w.s.list_capabilities(catalog_version=2)["items"]}
    assert rows["synthetic.bytes"]["status"] == "unavailable"
    assert w.storage_reason in rows["synthetic.bytes"]["unavailable_reason"]
    selection, relay = w.s._authoring_scene_selection, w.s._authoring_scene_relay
    w.d.start_local_worker(w.profile.profile_id, w.s.realm["id"])
    assert w.s._authoring_scene_selection is selection and w.s._authoring_scene_relay is relay


@pytest.mark.parametrize("resolved_before_failure", [False, True])
def test_failed_retained_composition_refuses_absent_capture_until_guarded_recomposition(
        source_empty, monkeypatch, resolved_before_failure):
    from runtime_protocol import local_preparation_relay as storage
    from runtime_protocol.errors import ConflictError

    w = source_empty
    body = publish_empty(w)
    body.update(request_id="offline-after-composition-failure", dry_run=True)
    before = snapshot(w.s)
    selected = w.s._authoring_scene_selection
    assert selected is not None and w.s._authoring_scene_relay is None
    previous = None
    if resolved_before_failure:
        previous = scene.RequestSceneEvaluation(w.s, body, w.identity)
        previous.check()
        assert previous.relay is selected.relay is w.s._authoring_scene_relay

    original_bind = storage.bind_selected_host
    primary = ConflictError("offline first composition failure")

    def failed_bind(*args):
        raise primary

    monkeypatch.setattr(storage, "bind_selected_host", failed_bind)
    launcher, handle = w.d.local_worker_launcher, w.handle
    with pytest.raises(ConflictError) as caught:
        w.d.start_local_worker(w.profile.profile_id, w.s.realm["id"])
    assert caught.value is primary
    assert primary.details["local_worker_state"] == "activated_composition_failed"
    assert w.d.local_worker_launcher is launcher
    assert w.selected[0] is handle and handle.activated and not handle.closed
    assert w.s._preparation_relay is None
    assert w.s._authoring_scene_selection is None and w.s._authoring_scene_relay is None
    assert w.d._local_composition_handle is None
    if previous is not None:
        with pytest.raises(AuthorizationError) as revoked:
            previous.check()
        assert revoked.value._authoring_invocation_reason is Reason.CURRENT_RELAY_REPLACED

    absent = scene.RequestSceneEvaluation(w.s, body, w.identity)
    assert absent.selection is None and absent.relay is None
    with pytest.raises(AuthorizationError) as refused:
        absent.check()
    assert refused.value._authoring_invocation_reason is Reason.CAPTURED_RELAY_ABSENT
    with pytest.raises(AuthorizationError) as consumer_refusal:
        w.s.commit_timeline(w.p, "main", body, idempotency_key=body["request_id"], identity=w.identity)
    assert consumer_refusal.value._authoring_invocation_reason is Reason.CAPTURED_RELAY_ABSENT
    assert snapshot(w.s) == before
    assert w.s.lookup_request(w.p, "main", body["request_id"]) is None

    # Only a successful pass through the real composer can install a selection.
    # This fixture's retained launcher/Host authority is synthetic; no Host starts.
    monkeypatch.setattr(storage, "bind_selected_host", original_bind)
    w.d.start_local_worker(w.profile.profile_id, w.s.realm["id"])
    replacement = w.s._authoring_scene_selection
    assert replacement is not selected and replacement.handle is handle
    assert w.s._authoring_scene_relay is None and w.s._preparation_relay is None
    current = scene.RequestSceneEvaluation(w.s, body, w.identity)
    current.check()
    assert current.relay is replacement.relay is w.s._authoring_scene_relay
    with pytest.raises(AuthorizationError) as still_absent:
        absent.check()
    assert still_absent.value._authoring_invocation_reason is Reason.CAPTURED_RELAY_ABSENT
    body["request_id"] = "offline-fresh-after-recomposition"
    result = w.s.commit_timeline(w.p, "main", body, idempotency_key=body["request_id"], identity=w.identity)
    assert result["status"] == "preview", result
    assert snapshot(w.s) == before
    assert w.s.lookup_request(w.p, "main", body["request_id"]) is None
    current.close()
    absent.close()
    if previous is not None:
        previous.close()


def test_selected_scene_resolution_failure_preserves_selection_and_first_error(
        source_empty, monkeypatch):
    from runtime_protocol.errors import ConflictError
    from astrid.core.execution.authoring_scene_transport import AuthoringSceneRelay

    w = source_empty
    body = publish_empty(w)
    body.update(request_id="offline-resolve-failure", dry_run=True)
    before = snapshot(w.s)
    selected = w.s._authoring_scene_selection
    original_check, original_close = scene.check_binding, AuthoringSceneRelay.close
    primary, closed = ConflictError("offline first resolution failure"), []

    def failed_check(*args):
        raise primary

    def close(relay):
        closed.append(relay)
        original_close(relay)
        raise RuntimeError("offline secondary close failure")

    monkeypatch.setattr(scene, "check_binding", failed_check)
    monkeypatch.setattr(AuthoringSceneRelay, "close", close)
    with pytest.raises(ConflictError) as caught:
        scene.RequestSceneEvaluation(w.s, body, w.identity)
    assert caught.value is primary and len(closed) == 1
    assert w.s._authoring_scene_selection is selected
    assert selected.relay is None and w.s._authoring_scene_relay is None
    assert w.handle.activated and not w.handle.closed

    # Resolution failure is not an absent capture: the same authorized selection
    # remains eligible for a later fresh invocation, with all checks restored.
    monkeypatch.setattr(scene, "check_binding", original_check)
    monkeypatch.setattr(AuthoringSceneRelay, "close", original_close)
    current = scene.RequestSceneEvaluation(w.s, body, w.identity)
    current.check()
    assert current.selection is selected
    assert current.relay is selected.relay is w.s._authoring_scene_relay
    result = w.s.commit_timeline(w.p, "main", body, idempotency_key=body["request_id"], identity=w.identity)
    assert result["status"] == "preview", result
    assert snapshot(w.s) == before
    assert w.s.lookup_request(w.p, "main", body["request_id"]) is None
    current.close()


def test_source_daemon_empty_selection_refuses_frame_and_nonempty_candidate(source_empty):
    from astrid.core.execution import authoring_scene_protocol as protocol
    from astrid.core.execution.remotion_frame_owner import FrameOwnerError
    from astrid.sdk.timeline.commit import create_runtime_commit_service
    w = source_empty
    body = wire(w.p)
    port = scene.RequestSceneEvaluation(w.s, body, w.identity)
    client = port.evaluator({"nonempty": "candidate"})
    value = projection()
    with pytest.raises(FrameOwnerError, match="empty_only_frame_query"):
        client.query_scene(revision_digest=protocol.digest(value)[7:], scene=value, frames=[0])
    assert not w.calls
    port.close()
    w.s._timeline_commit_provider = create_runtime_commit_service()
    before = count(w.s, "parent_composition_publications")
    result = w.s.commit_timeline(w.p, "main", body, idempotency_key=body["request_id"], identity=w.identity)
    assert result["status"] in {"error", "refused"}, result
    assert count(w.s, "parent_composition_publications") == before
    assert w.s.lookup_request(w.p, "main", body["request_id"]) is None


def test_source_daemon_replacement_fences_inflight_authoring(source_empty):
    w = source_empty
    port = scene.RequestSceneEvaluation(w.s, wire(w.p), w.identity)
    port.check()
    w.d.start_local_worker(w.profile.profile_id, w.s.realm["id"])
    port.check()  # Unchanged start preserves the actual resolved relay.
    w.selected[0] = SimpleNamespace(**vars(w.handle))
    w.d.start_local_worker(w.profile.profile_id, w.s.realm["id"])
    with pytest.raises(AuthorizationError): port.check()
    assert w.s._authoring_scene_relay is None and w.s._preparation_relay is None
    port.close()


@pytest.mark.parametrize("failure", ["missing_capability", "unavailable_capability", "missing_readiness", "invalid_readiness", "replacement"])
def test_source_daemon_authoring_dependency_still_refuses_without_publication(source_empty, monkeypatch, failure):
    import json
    from astrid.core.execution import authoring_scene_transport as transport
    w = source_empty
    body = publish_empty(w)
    if failure in {"missing_capability", "unavailable_capability"}:
        row = w.s.store.conn.execute("SELECT id,capabilities_json FROM executors").fetchone()
        values = json.loads(row["capabilities_json"])
        if failure == "missing_capability": values = [v for v in values if v["capability_id"] != "rendering.timeline_visualize"]
        else:
            for v in values:
                if v["capability_id"] == "rendering.timeline_visualize": v.update(status="unavailable", unavailable_reason="fixture")
        w.s.store.conn.execute("UPDATE executors SET capabilities_json=? WHERE id=?", (json.dumps(values), row["id"]))
    elif failure == "missing_readiness": w.config.readiness_path.unlink()
    elif failure == "invalid_readiness": w.config.readiness_path.write_text('{}\n')
    else:
        original = transport.AuthoringSceneRelay.__init__
        def replaced(relay, config):
            original(relay, config)
            w.s._authoring_scene_selection = None
        monkeypatch.setattr(transport.AuthoringSceneRelay, "__init__", replaced)
    before = count(w.s, "parent_composition_publications")
    try:
        result = w.s.commit_timeline(w.p, "main", body, idempotency_key=body["request_id"], identity=w.identity)
    except Exception:
        # Resolution errors are fatal to this dependent COMMIT, before accept.
        pass
    else:
        assert result["status"] in {"error", "refused"}, result
    assert count(w.s, "parent_composition_publications") == before
    assert w.s.lookup_request(w.p, "main", body["request_id"]) is None
    assert w.s._authoring_scene_relay is None and not w.calls


@pytest.mark.parametrize("dry_run", [True, False])
def test_public_empty_commit_requires_typed_authenticated_completion(empty_bound, dry_run):
    from astrid.core.execution import authoring_scene_protocol as protocol
    w = empty_bound
    body = publish_empty(w)
    body["dry_run"] = dry_run
    before = count(w.s, "parent_composition_publications")
    result = w.s.commit_timeline(w.p, "main", body, idempotency_key=body["request_id"], identity=w.identity)
    assert result["status"] == ("preview" if dry_run else "accepted"), result
    assert result["canonical_document"]["parent"]["config"]["tracks"][0]["opacity"] == .625
    assert len(w.calls) == 1 and w.calls[0]["operation"] == protocol.EMPTY_OPERATION
    invocation = w.calls[0]["invocation"]
    assert invocation["request_hash"] == digest(body)
    assert invocation["candidate_digest"] == digest(result["canonical_document"])
    assert w.calls[0]["candidate"] == result["canonical_document"]
    assert invocation["actor"] == w.identity["actor"]
    assert count(w.s, "parent_composition_publications") == before + (not dry_run)
    if dry_run:
        assert w.s.lookup_request(w.p, "main", body["request_id"]) is None
    else:
        w.s._authoring_scene_relay = None
        assert w.s.commit_timeline(w.p, "main", body, idempotency_key=body["request_id"], identity=w.identity) == result


@pytest.mark.parametrize("change", ["missing", "forged", "candidate", "request", "actor", "fence", "mode",
    "realm", "session", "executor", "owner", "source", "channel", "credential", "selection", "superseded"])
def test_empty_public_commit_refuses_forgery_and_inflight_authority_change(empty_bound, monkeypatch, change):
    from astrid.core.execution import authoring_scene_protocol as protocol
    w = empty_bound
    body = publish_empty(w)
    original = w.relay.exchange
    def changed(request, **kwargs):
        result = original(request, **kwargs)
        if change == "forged": return {"empty": True}
        if change in {"candidate", "request", "actor", "fence"}:
            field = {"candidate": "candidate_digest", "request": "request_hash"}.get(change, change)
            result["invocation"][field] = "foreign"
        elif change == "mode": result["context"]["mode"] = "renderer"
        elif change in {"realm", "session", "executor", "owner", "source"}:
            field = {"realm": "runtime_realm_id", "session": "runtime_session_id", "executor": "executor_id",
                     "owner": "host_instance_id", "source": "source_digest"}[change]
            w.relay.config.binding[field] = "foreign"
        elif change == "channel": w.relay.close()
        elif change == "credential": w.credentials.disable_actor(w.identity["actor"])
        elif change == "selection": w.s._authoring_scene_relay = SimpleNamespace(close=lambda: None)
        elif change == "superseded": kwargs["cancelled"].set()
        return result
    if change == "missing": w.s._authoring_scene_relay = None
    else: monkeypatch.setattr(w.relay, "exchange", changed)
    before = count(w.s, "parent_composition_publications")
    try:
        result = w.s.commit_timeline(w.p, "main", body, idempotency_key=body["request_id"], identity=w.identity)
        assert result["status"] in {"error", "refused"}, result
    except AuthorizationError:
        pass
    assert count(w.s, "parent_composition_publications") == before
    assert w.s.lookup_request(w.p, "main", body["request_id"]) is None


def test_empty_mode_refuses_frame_queries_and_nonempty_public_candidate(empty_bound):
    from astrid.core.execution import authoring_scene_protocol as protocol
    from astrid.core.execution.remotion_frame_owner import FrameOwnerError
    from astrid.sdk.timeline.commit import create_runtime_commit_service
    w = empty_bound
    body = wire(w.p)
    port = scene.RequestSceneEvaluation(w.s, body, w.identity)
    client = port.evaluator({"candidate": "not-empty-proof"})
    value = projection()
    with pytest.raises(FrameOwnerError, match="empty_only_frame_query"):
        client.query_scene(revision_digest=protocol.digest(value)[7:], scene=value, frames=[0])
    assert not w.calls
    port.close()
    w.s._timeline_commit_provider = create_runtime_commit_service()
    before = count(w.s, "parent_composition_publications")
    result = w.s.commit_timeline(w.p, "main", body, idempotency_key=body["request_id"], identity=w.identity)
    assert result["status"] in {"error", "refused"}, result
    assert count(w.s, "parent_composition_publications") == before
    assert w.s.lookup_request(w.p, "main", body["request_id"]) is None


def test_empty_proof_cannot_survive_rebase_onto_nonempty_head(empty_bound):
    from astrid.sdk.timeline.commit import RuntimeCommitService
    from astrid.core.execution.remotion_frame_owner import FrameOwnerError
    from test_shot_composition_runtime import _publication
    w = empty_bound
    body = publish_empty(w)
    port = w.s._request_commit_port(body, w.identity)
    candidate = RuntimeCommitService._load_revision(port, body, body["base_revision_id"])
    first = port.scene_evaluator(candidate)
    first.complete(empty=True)
    head = w.s.head(w.p, "main")
    value = _publication(w.p, expected_head=head["revision_id"], parent_revision_id="nonempty-head",
                         config={"tracks": [{"id": "V1", "kind": "visual", "opacity": 1},
                                            {"id": "video-1", "kind": "visual"}]})
    w.s.publish_parent_composition(w.p, "main", value, idempotency_key="nonempty-head")
    # A fresh complete post-rebase candidate contains the current head's domain.
    assert port.head()["revision_id"] == "nonempty-head"
    rebased = RuntimeCommitService._load_revision(port, body, "nonempty-head")
    second = port.scene_evaluator(rebased)
    with pytest.raises(FrameOwnerError): second.complete(empty=True)
    with pytest.raises(FrameOwnerError): first.complete(empty=True)
    assert second.invocation.proof is None
    port.close()


def test_public_retry_rebases_empty_candidate_onto_nonempty_head_and_refuses(empty_bound, monkeypatch):
    from test_shot_composition_runtime import _publication
    w = empty_bound
    body = publish_empty(w)
    original = w.s.accept
    attempts = []
    def move_head(prepared, **kwargs):
        attempts.append(copy.deepcopy(prepared))
        assert len(attempts) == 1  # Rebased nonempty evaluation never reaches acceptance.
        head = w.s.head(w.p, "main")
        value = _publication(w.p, expected_head=head["revision_id"], parent_revision_id="concurrent-nonempty",
            config={"tracks": [{"id": "V1", "kind": "visual", "opacity": 1},
                               {"id": "video-1", "kind": "visual"}]})
        w.s.publish_parent_composition(w.p, "main", value, idempotency_key="concurrent-nonempty")
        return original(prepared, **kwargs)  # Real StaleHead drives the provider's ordinary rebase.
    monkeypatch.setattr(w.s, "accept", move_head)
    result = w.s.commit_timeline(w.p, "main", body, idempotency_key=body["request_id"], identity=w.identity)
    assert result["status"] in {"error", "refused"}, result
    assert result["rebased_onto"] == "concurrent-nonempty", result
    assert len(attempts) == 1 and len(w.calls) == 1
    assert w.calls[0]["candidate"]["placements"] == []
    assert w.s.head(w.p, "main")["revision_id"] == "concurrent-nonempty"
    assert w.s.lookup_request(w.p, "main", body["request_id"]) is None


@pytest.mark.parametrize("change", ["credential", "channel", "source"])
def test_empty_authority_rechecked_at_atomic_accept_after_valid_completion(empty_bound, monkeypatch, change):
    w = empty_bound
    body = publish_empty(w)
    original = w.s.accept
    def revoke(prepared, **kwargs):
        assert len(w.calls) == 1
        if change == "credential": w.credentials.disable_actor(w.identity["actor"])
        elif change == "channel": w.relay.close()
        elif change == "source": w.relay.config.binding["source_epoch"] = "foreign"
        return original(prepared, **kwargs)
    monkeypatch.setattr(w.s, "accept", revoke)
    before = count(w.s, "parent_composition_publications")
    from astrid.core.execution.remotion_frame_owner import FrameOwnerError
    try:
        result = w.s.commit_timeline(w.p, "main", body, idempotency_key=body["request_id"], identity=w.identity)
        assert result["status"] in {"error", "refused"}, result
    except (AuthorizationError, FrameOwnerError):
        pass
    assert count(w.s, "parent_composition_publications") == before
    assert w.s.lookup_request(w.p, "main", body["request_id"]) is None


@pytest.mark.parametrize('case, expected', [
    ('cancelled', Reason.EVALUATION_CANCELLED),
    ('absent', Reason.CAPTURED_RELAY_ABSENT),
    ('replaced', Reason.CURRENT_RELAY_REPLACED),
    ('removed', Reason.CURRENT_RELAY_REPLACED),
    ('cancelled_absent', Reason.EVALUATION_CANCELLED),
    ('cancelled_replaced', Reason.EVALUATION_CANCELLED),
])
def test_invocation_revocation_reports_first_failing_clause(bound, monkeypatch, case, expected):
    w = bound
    if case in {'absent', 'cancelled_absent'}:
        w.s._authoring_scene_relay = None
    invocation = scene.RequestSceneEvaluation(w.s, wire(w.p), w.identity)
    if case.startswith('cancelled'):
        invocation.close()
    if case in {'replaced', 'cancelled_replaced'}:
        w.s._authoring_scene_relay = object()
    elif case == 'removed':
        w.s._authoring_scene_relay = None
    # Revocation must still fail before authority or owner/source checks.
    monkeypatch.setattr(invocation, '_authority', lambda: pytest.fail('authority checked after revocation'))
    before = count(w.s, 'parent_composition_publications')
    try:
        with pytest.raises(AuthorizationError) as error:
            invocation.check()
        assert error.value._authorization_guard is Guard.AUTHORING_INVOCATION_REVOKED
        assert error.value._authoring_invocation_reason is expected
        assert error.value.status == 401
        assert error.value.as_dict() == dict(code='unauthorized',
            message='authoring invocation revoked or unavailable')
        assert count(w.s, 'parent_composition_publications') == before
        assert w.calls == []
    finally:
        w.s._authoring_scene_relay = w.relay
        invocation.close()


@pytest.mark.parametrize('field', ['host_instance_id', 'source_digest'])
def test_invocation_owner_source_change_keeps_adjacent_guard(bound, field):
    w = bound
    invocation = scene.RequestSceneEvaluation(w.s, wire(w.p), w.identity)
    w.relay.config.binding[field] = 'foreign'
    try:
        with pytest.raises(AuthorizationError, match='authoring source/owner changed') as error:
            invocation.check()
        assert error.value._authorization_guard is Guard.AUTHORING_INVOCATION_OWNER_CHANGED
        assert error.value._authoring_invocation_reason is None
        assert error.value.as_dict() == dict(code='unauthorized', message='authoring source/owner changed')
        assert w.calls == []
    finally:
        invocation.close()
