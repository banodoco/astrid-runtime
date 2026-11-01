import io
import json
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from runtime_protocol.door import classify
from runtime_protocol.errors import AuthorizationError, BodyTooLargeError, ConflictError, ProtocolError
from runtime_protocol.server import RuntimeHandler


PROJECT = "project-1"
TIMELINE = "timeline-1"


def request_body(*, project_id=PROJECT, timeline_id=TIMELINE, **overrides):
    body = {
        "api_version": 1,
        "project_id": project_id,
        "timeline_id": timeline_id,
        "base_revision_id": "revision-1",
        "base_publication_id": "publication-1",
        "commands": [{
            "schema_version": 1,
            "op": "clip.move",
            "version": "1",
            "select": "parent/clip:clip-1",
            "args": {"on": 1.0},
        }],
    }
    body.update(overrides)
    return body


def restore_body(**overrides):
    body = {"expected_head": "revision-1", "expected_publication_id": "publication-1"}
    body.update(overrides)
    return body


class RouteHandler(RuntimeHandler):
    def _identity(self, scope):
        self.scopes_seen.append(scope)
        return {"actor": self.identity_actor, "scopes": ["projects:write", "projects:read"]}

    def _send(self, status, payload=None, **kwargs):
        self.reply = status, payload


def make_handler(runtime, body, *, path=None, headers=None, command="POST", actor="publisher-1"):
    handler = object.__new__(RouteHandler)
    handler.server = SimpleNamespace(runtime=runtime)
    handler.command = command
    handler.path = path or f"/v1/projects/{PROJECT}/timelines/{TIMELINE}/commit"
    raw = body if isinstance(body, bytes) else json.dumps(body, separators=(",", ":")).encode()
    handler.rfile = io.BytesIO(raw)
    handler.headers = {"Content-Length": str(len(raw)), "Idempotency-Key": "commit-key-1", **(headers or {})}
    handler.scopes_seen = []
    handler.identity_actor = actor
    return handler


def test_commit_route_passes_exact_service_shape_and_rechecks_authority():
    calls = []

    def commit(project_id, timeline_id, body, *, idempotency_key, publisher, invocation_path, authorize):
        calls.append((project_id, timeline_id, body, idempotency_key, publisher, invocation_path))
        assert authorize()["actor"] == publisher
        return {"data": {"status": "accepted"}, "receipt": {"receipt_id": "r1"}}

    body = request_body()
    handler = make_handler(SimpleNamespace(commit_timeline=commit), body)
    handler._route()
    assert handler.reply == (200, {"data": {"status": "accepted"}, "receipt": {"receipt_id": "r1"}})
    assert calls == [(
        PROJECT, TIMELINE, body, "commit-key-1", "publisher-1",
        f"/v1/projects/{PROJECT}/timelines/{TIMELINE}/commit",
    )]
    assert handler.scopes_seen == ["projects:write", "projects:write"]


def test_commit_route_forwards_full_v2_envelope_and_reply_unchanged():
    calls = []
    reads = [{"kind": "scope", "ref": "parent", "path": []}]
    patch = {
        "op": "set",
        "ref": "parent",
        "path": ["config", "title"],
        "before": {"state": "absent"},
        "value": "Opening",
    }
    body = request_body(
        commands=[{
            "schema_version": 1,
            "op": "doc.patch",
            "version": "1",
            "select": None,
            "args": {"changes": [patch]},
        }],
        label="Opening title",
        steps=[{
            "id": "opening",
            "label": "Opening title",
            "intent": "Set the opening title",
            "tags": ["title"],
            "command_ordinals": [0],
            "patch": [patch],
            "reads": reads,
        }],
        merge="fields",
        reads=reads,
        source={"via": "app", "detail": "mounted-v2"},
    )
    reply = {
        "data": {
            "status": "merged",
            "label": body["label"],
            "merge_mode": body["merge"],
            "steps": body["steps"],
            "commands": body["commands"],
        },
        "receipt": {"receipt_id": "r-v2", "request_hash": "h-v2"},
    }

    def commit(project_id, timeline_id, received, **kwargs):
        calls.append((project_id, timeline_id, received, kwargs))
        return reply

    handler = make_handler(SimpleNamespace(commit_timeline=commit), body)
    handler._route()

    assert handler.reply == (200, reply)
    assert len(calls) == 1
    project, timeline, received, kwargs = calls[0]
    assert (project, timeline, received) == (PROJECT, TIMELINE, body)
    assert kwargs["idempotency_key"] == "commit-key-1"
    assert kwargs["publisher"] == "publisher-1"
    assert kwargs["invocation_path"] == f"/v1/projects/{PROJECT}/timelines/{TIMELINE}/commit"
    assert kwargs["authorize"]()["actor"] == "publisher-1"


def test_commit_route_leaves_semantic_schema_validation_to_service():
    calls = []

    def commit(project_id, timeline_id, body, *, idempotency_key, publisher, invocation_path, authorize):
        calls.append(body)
        return {"data": {"status": "refused"}, "receipt": None}

    body = request_body(commands=[])
    handler = make_handler(SimpleNamespace(commit_timeline=commit), body)
    handler._route()
    assert calls == [body]


def test_commit_route_rejects_path_mismatch_before_service():
    def commit(project_id, timeline_id, body, *, idempotency_key, publisher, invocation_path, authorize):
        pytest.fail("provider called")

    handler = make_handler(SimpleNamespace(commit_timeline=commit), request_body(project_id="other-project"))
    with pytest.raises(ConflictError):
        handler._route()


def test_commit_route_rejects_duplicate_fields_and_nonfinite_overflow():
    def commit(project_id, timeline_id, body, *, idempotency_key, publisher, invocation_path, authorize):
        pytest.fail("provider called")

    duplicate = b'{"api_version":1,"api_version":1,"project_id":"project-1","timeline_id":"timeline-1","base_revision_id":"r","base_publication_id":"p","commands":[]}'
    handler = make_handler(SimpleNamespace(commit_timeline=commit), duplicate)
    with pytest.raises(ProtocolError):
        handler._route()

    overflow = b'{"api_version":1,"project_id":"project-1","timeline_id":"timeline-1","base_revision_id":"r","base_publication_id":"p","commands":[{"schema_version":1,"op":"clip.move","version":"1","select":null,"args":{"opaque":{"number":1e999}}}]}'
    handler = make_handler(SimpleNamespace(commit_timeline=commit), overflow)
    with pytest.raises(ProtocolError):
        handler._route()


def test_commit_route_preserves_opaque_json_and_encoded_identity():
    project_id = "project/one"
    timeline_id = "timeline/one"
    body = request_body(
        project_id=project_id,
        timeline_id=timeline_id,
        commands=[{
            "schema_version": 1,
            "op": "opaque.extension",
            "version": "1",
            "select": None,
            "args": {"foreign_project_id": "another-project", "nested": [1.0, "opaque"]},
        }],
    )
    calls = []

    def commit(project, timeline, original, *, idempotency_key, publisher, invocation_path, authorize):
        calls.append((project, timeline, original, invocation_path))
        return {"data": {"status": "accepted"}, "receipt": {"receipt_id": "r1"}}

    path = f"/v1/projects/{quote(project_id, safe='')}/timelines/{quote(timeline_id, safe='')}/commit"
    handler = make_handler(SimpleNamespace(commit_timeline=commit), body, path=path)
    handler._route()
    assert calls == [(project_id, timeline_id, body, path)]


def test_history_route_passes_authorize_callback_and_exact_shape():
    calls = []

    def history(project_id, timeline_id, *, cursor=None, limit=50, authorize):
        calls.append((project_id, timeline_id, cursor, limit, authorize()["actor"]))
        return {"data": []}

    handler = make_handler(
        SimpleNamespace(list_timeline_commits=history), b"", command="GET",
        path=f"/v1/projects/{PROJECT}/timelines/{TIMELINE}/commits?cursor=c1&limit=7",
        headers={"Content-Length": "0"},
    )
    handler._route()
    assert calls == [(PROJECT, TIMELINE, "c1", "7", "publisher-1")]
    assert handler.scopes_seen == ["projects:read", "projects:read"]


def test_history_authorize_callback_rejects_actor_change():
    def history(project_id, timeline_id, *, cursor=None, limit=50, authorize):
        handler.identity_actor = "different-actor"
        with pytest.raises(AuthorizationError):
            authorize()
        return {"data": []}

    handler = make_handler(
        SimpleNamespace(list_timeline_commits=history), b"", command="GET",
        path=f"/v1/projects/{PROJECT}/timelines/{TIMELINE}/commits",
        headers={"Content-Length": "0"},
    )
    handler._route()
    assert handler.scopes_seen == ["projects:read", "projects:read"]


def test_media_selection_route_passes_selectors_mapping_and_authorize():
    calls = []

    def media(project_id, selectors, *, authorize):
        calls.append((project_id, selectors, authorize()["actor"]))
        return {"data": {"object_id": "object-1"}}

    handler = make_handler(
        SimpleNamespace(get_project_media_selection=media), b"", command="GET",
        path=f"/v1/projects/{PROJECT}/media-selection?association_id=a&object_id=o&version=2",
        headers={"Content-Length": "0"},
    )
    handler._route()
    assert calls == [(PROJECT, {"association_id": "a", "object_id": "o", "version": 2}, "publisher-1")]
    assert handler.scopes_seen == ["projects:read", "projects:read"]


def test_restore_route_passes_original_body_identity_and_canonical_path():
    project_id = "project/one"
    timeline_id = "timeline/one"
    revision = "revision/one"
    path = (
        f"/v1/projects/{quote(project_id, safe='')}/timelines/{quote(timeline_id, safe='')}"
        f"/composition-revisions/{quote(revision, safe='')}/restore"
    )
    body = restore_body()
    calls = []

    def restore(project, timeline, selected_revision, original, *, idempotency_key, publisher, invocation_path, authorize):
        calls.append((project, timeline, selected_revision, original, idempotency_key, publisher, invocation_path))
        assert authorize()["actor"] == publisher
        return {"data": {"status": "accepted"}, "receipt": {"receipt_id": "r1"}}

    handler = make_handler(
        SimpleNamespace(restore_project_parent_composition_revision=restore), body,
        path=path, headers={"Idempotency-Key": "restore-key-1"},
    )
    handler._route()
    assert calls == [(project_id, timeline_id, revision, body, "restore-key-1", "publisher-1", path)]


@pytest.mark.parametrize("raw", [
    b'{"expected_head":"r","expected_head":"r2","expected_publication_id":"p"}',
    b'{"expected_head":"r","expected_publication_id":"p","opaque":1e999}',
])
def test_restore_route_rejects_duplicate_or_nonfinite_original_body(raw):
    def restore(project, timeline, selected_revision, original, *, idempotency_key, publisher, invocation_path, authorize):
        pytest.fail("provider called")

    handler = make_handler(
        SimpleNamespace(restore_project_parent_composition_revision=restore), raw,
        path=f"/v1/projects/{PROJECT}/timelines/{TIMELINE}/composition-revisions/revision-1/restore",
    )
    with pytest.raises(ProtocolError):
        handler._route()


def test_restore_route_enforces_one_megabyte_limit_before_read():
    def restore(project, timeline, selected_revision, original, *, idempotency_key, publisher, invocation_path, authorize):
        pytest.fail("provider called")

    handler = make_handler(
        SimpleNamespace(restore_project_parent_composition_revision=restore), b"",
        path=f"/v1/projects/{PROJECT}/timelines/{TIMELINE}/composition-revisions/revision-1/restore",
        headers={"Content-Length": str(1024 * 1024 + 1)},
    )
    with pytest.raises(BodyTooLargeError):
        handler._route()


def test_restore_dispatch_runs_without_store_mutex_or_response_lock():
    class ExplodingMutex:
        def __enter__(self):
            raise AssertionError("restore acquired the store mutex")

        def __exit__(self, *args):
            return False

    calls = []

    def restore(project, timeline, selected_revision, original, *, idempotency_key, publisher, invocation_path, authorize):
        calls.append((original, invocation_path))
        return {"data": {"status": "accepted"}, "receipt": {"receipt_id": "r1"}}

    runtime = SimpleNamespace(
        restore_project_parent_composition_revision=restore,
        store=SimpleNamespace(_mutex=ExplodingMutex()),
    )
    handler = make_handler(
        runtime, restore_body(),
        path=f"/v1/projects/{PROJECT}/timelines/{TIMELINE}/composition-revisions/revision-1/restore",
        headers={"Idempotency-Key": "restore-key-1"},
    )
    handler._dispatch()
    assert calls == [(restore_body(), f"/v1/projects/{PROJECT}/timelines/{TIMELINE}/composition-revisions/revision-1/restore")]
    assert handler.reply[0] == 200


def test_commit_route_rejects_duplicate_idempotency_headers_and_neutral_runtime_is_503():
    def commit(project_id, timeline_id, body, *, idempotency_key, publisher, invocation_path, authorize):
        pytest.fail("provider called")

    class DuplicateHeaders(dict):
        def get_all(self, name, default=None):
            if name.lower() == "idempotency-key":
                return ["one", "two"]
            return [self.get(name)] if name in self else (default or [])

    handler = make_handler(SimpleNamespace(commit_timeline=commit), request_body())
    handler.headers = DuplicateHeaders(handler.headers)
    with pytest.raises(ProtocolError):
        handler._route()

    handler = make_handler(SimpleNamespace(), request_body())
    with pytest.raises(Exception) as caught:
        handler._route()
    assert caught.value.status == 503
    assert caught.value.as_dict()["details"]["reason"] == "runtime_unavailable"


def test_new_door_routes_are_exact():
    assert classify("/api/runtime/v1/projects/project-1/timelines/timeline-1/commit", "POST")
    assert classify("/api/runtime/v1/projects/project-1/timelines/timeline-1/commits", "GET")
    assert classify("/api/runtime/v1/projects/project-1/media-selection?asset=a&generation_id=g&variant_id=v", "GET")
    assert classify("/api/runtime/v1/projects/project-1/timelines/timeline-1/commit/extra", "POST") is None
