from __future__ import annotations

import hashlib
import io
import json
from http.server import BaseHTTPRequestHandler
from types import SimpleNamespace
from typing import Any, cast

import pytest
from test_timeline_commit_acceptance import context

import runtime_protocol.server as server_module
from runtime_protocol.server import RuntimeHandler
from runtime_protocol.timeline_commit_port import CommitUnavailable
from runtime_protocol.timeline_commit_provider import TimelineCommitUnavailable
from tests.door_helpers import PRODUCT_ACTOR, start_door_world, write_owner_only


def _diagnostic_lines(stderr):
    lines = stderr.splitlines()
    assert len(lines) == 1
    prefix, encoded = lines[0].split(" ", 1)
    assert prefix == "runtime.timeline_commit.error"
    return json.loads(encoded)


def test_provider_none_keeps_public_503_and_tags_the_actual_source(realm, capsys):
    service, _, project, head, _ = realm
    request = context(service, project, head, "provider-none")

    with pytest.raises(CommitUnavailable) as caught:
        service.commit_timeline(
            project,
            "main",
            request["request"],
            idempotency_key=request["idempotency_key"],
            publisher=request["publisher"],
            invocation_path=request["invocation"]["path"],
            authorize=lambda: None,
        )

    assert caught.value.status == 503
    assert caught.value.as_dict() == {
        "code": "not_ready",
        "message": "Timeline commit outcome unavailable; retry the exact request",
        "details": {"reason": "runtime_unavailable"},
    }
    diagnostic = _diagnostic_lines(capsys.readouterr().err)
    assert diagnostic["reason"] == "provider_none"
    assert diagnostic["exception_class_chain"] == []
    assert diagnostic["frames"] == []


def test_missing_server_commit_callable_keeps_public_503_and_tags_route(capsys):
    body = {
        "api_version": 1,
        "project_id": "project-1",
        "timeline_id": "timeline-1",
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
    handler: Any = object.__new__(RuntimeHandler)
    handler.server = SimpleNamespace(runtime=SimpleNamespace())
    handler.command = "POST"
    handler.path = "/v1/projects/project-1/timelines/timeline-1/commit"
    raw = json.dumps(body, separators=(",", ":")).encode()
    handler.rfile = io.BytesIO(raw)
    handler.headers = {"Content-Length": str(len(raw)), "Idempotency-Key": "missing-provider"}
    handler._identity = lambda _scope: {"actor": "publisher-1"}

    with pytest.raises(TimelineCommitUnavailable) as caught:
        handler._timeline_commit("project-1", "timeline-1", ["v1", "projects", "project-1"])

    assert caught.value.status == 503
    assert caught.value.as_dict() == {
        "code": "not_ready",
        "message": "timeline commit provider is unavailable",
        "details": {"reason": "runtime_unavailable"},
    }
    diagnostic = _diagnostic_lines(capsys.readouterr().err)
    assert diagnostic["reason"] == "timeline_commit_unavailable"
    assert diagnostic["exception_class_chain"] == []
    assert diagnostic["frames"] == []


def test_missing_server_commit_callable_redacts_public_id_with_private_correlation(capsys):
    body = {
        "api_version": 1,
        "project_id": "project-1",
        "timeline_id": "timeline-1",
        "base_revision_id": "revision-1",
        "base_publication_id": "publication-1",
        "commands": [],
    }
    public_request_id = "61c84a4e" * 4
    handler: Any = object.__new__(RuntimeHandler)
    handler.server = SimpleNamespace(runtime=SimpleNamespace())
    handler.command = "POST"
    handler.path = "/v1/projects/project-1/timelines/timeline-1/commit"
    raw = json.dumps(body, separators=(",", ":")).encode()
    handler.rfile = io.BytesIO(raw)
    handler.headers = {
        "Content-Length": str(len(raw)),
        "Idempotency-Key": "missing-provider-redaction",
        "X-Request-ID": public_request_id,
    }
    handler._identity = lambda _scope: {"actor": "publisher-1"}

    with pytest.raises(TimelineCommitUnavailable):
        handler._timeline_commit("project-1", "timeline-1", ["v1", "projects", "project-1"])

    diagnostic = _diagnostic_lines(capsys.readouterr().err)
    assert diagnostic["request_id"] != public_request_id
    assert diagnostic["public_request_id_hash"] == (
        "sha256:" + hashlib.sha256(public_request_id.encode()).hexdigest()
    )
    assert public_request_id not in json.dumps(diagnostic)


def test_request_id_is_stable_within_one_request_and_fresh_across_keepalive_requests(monkeypatch):
    observed = []
    generated = iter(("a" * 32, "b" * 32))

    def fake_handle_one_request(handler):
        observed.append((handler._request_id(), handler._request_id()))

    monkeypatch.setattr(BaseHTTPRequestHandler, "handle_one_request", fake_handle_one_request)
    monkeypatch.setattr(server_module.uuid, "uuid4", lambda: SimpleNamespace(hex=next(generated)))

    handler: Any = object.__new__(RuntimeHandler)
    handler.headers = {"X-Request-ID": "first-request"}
    RuntimeHandler.handle_one_request(handler)
    handler.headers = {"X-Request-ID": "second-request"}
    RuntimeHandler.handle_one_request(handler)
    handler.headers = {}
    RuntimeHandler.handle_one_request(handler)
    handler.headers = {}
    RuntimeHandler.handle_one_request(handler)

    assert observed == [
        ("first-request", "first-request"),
        ("second-request", "second-request"),
        ("a" * 32, "a" * 32),
        ("b" * 32, "b" * 32),
    ]


def test_door_runtime_unavailable_causes_are_distinct_and_public_reply_is_unchanged(tmp_path, capsys):
    world = start_door_world(tmp_path)
    try:
        door_httpd = cast(Any, world.daemon.door_httpd)
        service = cast(Any, world.daemon.service)
        door_httpd.accepting_authenticated_requests = False
        not_accepting = world.call("/api/runtime/v1/health")

        door_httpd.accepting_authenticated_requests = True
        service._verified = False
        not_verified = world.call("/api/runtime/v1/health")

        service._verified = True
        world.credential_file.unlink()
        credential_missing = world.call("/api/runtime/v1/health")

        world.provision()
        write_owner_only(
            world.credential_file,
            {"version": 1, "scope": "astrid", "actor_id": PRODUCT_ACTOR, "token": "rejected"},
        )
        auth_rejected = world.call("/api/runtime/v1/health")
    finally:
        world.stop()

    for reply in (not_accepting, not_verified, credential_missing, auth_rejected):
        assert reply.status == 503
        assert reply.json() == {"error": "runtime_unavailable"}
    diagnostics = capsys.readouterr().err.splitlines()
    assert len(diagnostics) == 4
    reasons = []
    for line in diagnostics:
        prefix, encoded = line.split(" ", 1)
        assert prefix == "runtime.timeline_commit.error"
        payload = json.loads(encoded)
        reasons.append(payload["reason"])
        assert payload["exception_class_chain"] == []
        assert payload["frames"] == []
    assert reasons == ["not_accepting", "not_verified", "credential_missing", "auth_rejected"]
