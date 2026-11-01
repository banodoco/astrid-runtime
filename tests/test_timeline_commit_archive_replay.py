"""Archived exact commit replay keeps authorization and rejects new writes."""
from __future__ import annotations

import copy
import hashlib
import io
import json
from types import SimpleNamespace
from typing import Any

import pytest
import test_timeline_commit_authentication as auth_tests
import test_timeline_commit_port as port_tests

from runtime_protocol.errors import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    RuntimeErrorBase,
)
from runtime_protocol.server import RuntimeHandler
from runtime_protocol.timeline_commit_port import route_path

service = port_tests.service


def _archive(service):
    with service.store._transaction():
        service.store.conn.execute(
            "UPDATE timelines SET archived_at=? WHERE id=? AND project_id=?",
            ("2026-10-23T00:00:00Z", "main", service.test_project),
        )


def _snapshot(service):
    return list(service.store.conn.iterdump())


def _render_state(service):
    return (
        _snapshot(service),
        {
            str(path.relative_to(service.store.root)): path.read_bytes()
            for directory in (service.store.cas_root, service.store.staging_root)
            for path in directory.rglob("*")
            if path.is_file()
        },
    )


def _commit(service, body, *, key, publisher="editor", authorize=lambda: None):
    return service.commit_timeline(
        service.test_project,
        "main",
        body,
        idempotency_key=key,
        publisher=publisher,
        invocation_path=route_path(service.test_project, "main"),
        authorize=authorize,
    )


def _render_request(service, accepted, *, key):
    digest = "sha256:" + hashlib.sha256(b"rendering.render").hexdigest()
    service.register_capability({"capability_id": "rendering.render", "definition_digest": digest})
    service.register_executor({"executor_id": "render-worker", "capabilities": ["rendering.render"]})
    parent = accepted["data"]["canonical_document"]["parent_revision"]
    return {
        "project": service.test_project,
        "capability_id": "rendering.render",
        "capability_digest": digest,
        "input_object_ids": [],
        "idempotency_key": key,
        "spec": {
            "family": "render",
            "params": {
                "timeline_ref": "main",
                "selector": "rendering.remotion",
                "canonical_revision": {
                    "project_id": service.test_project,
                    "timeline_id": "main",
                    "revision_id": accepted["data"]["accepted_revision_id"],
                    "publication_id": accepted["receipt"]["receipt_id"],
                    "content_digest": parent["content_digest"],
                },
            },
        },
    }


def test_exact_complete_replay_after_archive_is_immutable_and_provider_free(service):
    auth_tests.provider(service)
    submitted = auth_tests.body(service)
    first = _commit(service, submitted, key="archive-replay")
    assert first["receipt"]["result"] == first["data"]
    provider_calls = service.test_provider.calls

    _archive(service)
    before = _snapshot(service)
    callbacks = []

    replay = _commit(
        service,
        submitted,
        key="archive-replay",
        authorize=lambda: callbacks.append("authorized"),
    )

    assert replay == first
    assert replay["data"] == first["data"]
    assert replay["receipt"] == first["receipt"]
    assert callbacks and len(callbacks) >= 2
    assert service.test_provider.calls == provider_calls
    assert _snapshot(service) == before

    service._timeline_commit_provider = None
    replay_without_provider = _commit(
        service,
        submitted,
        key="archive-replay",
        authorize=lambda: callbacks.append("authorized-without-provider"),
    )
    assert replay_without_provider == first
    assert service.test_provider.calls == provider_calls
    assert _snapshot(service) == before


def test_archived_new_key_fails_before_provider_and_writes(service):
    submitted = port_tests.request(service)
    first = _commit(service, submitted, key="archive-existing")
    assert first["data"]["status"] == "accepted"
    _archive(service)
    before = _snapshot(service)
    provider_calls = service.test_provider.calls

    with pytest.raises(NotFoundError):
        _commit(service, submitted, key="archive-new")

    assert service.test_provider.calls == provider_calls
    assert _snapshot(service) == before


@pytest.mark.parametrize("change", ["body", "publisher"])
def test_archived_changed_identity_cannot_replay_or_write(service, change):
    submitted = port_tests.request(service)
    _commit(service, submitted, key="archive-identity")
    _archive(service)
    before = _snapshot(service)
    service._timeline_commit_provider = None

    changed = json.loads(json.dumps(submitted))
    publisher = "editor"
    if change == "body":
        changed["commands"][0]["args"]["on"] = 99
    else:
        publisher = "different-authorized-actor"

    with pytest.raises(RuntimeErrorBase) as error:
        _commit(service, changed, key="archive-identity", publisher=publisher)

    assert error.value.details is not None
    assert error.value.details["reason"] == "idempotency_mismatch"
    assert _snapshot(service) == before


def test_archived_historical_render_replay_returns_original_admission(service):
    accepted = _commit(service, port_tests.request(service), key="archive-render-commit")
    request = _render_request(service, accepted, key="archive-render")
    first = service.create_task(request)

    _archive(service)
    before = _render_state(service)
    replay = service.create_task(copy.deepcopy(request))

    assert replay == first
    assert _render_state(service) == before


@pytest.mark.parametrize("field", ["publication_id", "content_digest"])
def test_archived_historical_render_forgery_refuses_without_writes(service, field):
    accepted = _commit(service, port_tests.request(service), key="archive-forgery-commit")
    request = _render_request(service, accepted, key="archive-forgery")
    service.create_task(request)
    _archive(service)
    forged = copy.deepcopy(request)
    forged["spec"]["params"]["canonical_revision"][field] = (
        "unpublished" if field == "publication_id" else "sha256:" + "0" * 64
    )
    before = _render_state(service)

    with pytest.raises(ConflictError):
        service.create_task(forged)

    assert _render_state(service) == before


class AuthHandler(RuntimeHandler):
    actor: str
    allowed_scopes: set[str]
    identity_calls: list[str]

    def _identity(self, scope):
        self.identity_calls.append(scope)
        if scope not in self.allowed_scopes:
            raise ForbiddenError("scope is not granted")
        return {"actor": self.actor, "scopes": sorted(self.allowed_scopes)}

    def _send(self, status, payload=None, **kwargs):
        self.reply = status, payload


def _http_handler(service, body, *, actor="editor", scopes=("projects:write",)):
    handler: Any = object.__new__(AuthHandler)
    handler.server = SimpleNamespace(runtime=service)
    handler.command = "POST"
    handler.path = f"/v1/projects/{service.test_project}/timelines/main/commit"
    raw = json.dumps(body, separators=(",", ":")).encode()
    handler.rfile = io.BytesIO(raw)
    handler.headers = {"Content-Length": str(len(raw)), "Idempotency-Key": "http-archive-replay"}
    handler.actor = actor
    handler.allowed_scopes = set(scopes)
    handler.identity_calls = []
    return handler


def test_http_bearer_scope_and_actor_binding_survive_archived_replay(service):
    submitted = port_tests.request(service)
    first_handler = _http_handler(service, submitted)
    first_handler._route()
    assert first_handler.reply[0] == 200
    first = first_handler.reply[1]

    _archive(service)
    before = _snapshot(service)
    service._timeline_commit_provider = None
    replay_handler = _http_handler(service, submitted)
    replay_handler._route()

    assert replay_handler.reply == (200, first)
    assert replay_handler.identity_calls
    assert set(replay_handler.identity_calls) == {"projects:write"}
    assert _snapshot(service) == before

    changed_actor = _http_handler(service, submitted, actor="other-actor")
    with pytest.raises(RuntimeErrorBase) as error:
        changed_actor._route()
    assert error.value.details is not None
    assert error.value.details["reason"] == "idempotency_mismatch"
    assert _snapshot(service) == before

    missing_scope = _http_handler(service, submitted, scopes=("projects:read",))
    with pytest.raises(ForbiddenError):
        missing_scope._route()
    assert _snapshot(service) == before
