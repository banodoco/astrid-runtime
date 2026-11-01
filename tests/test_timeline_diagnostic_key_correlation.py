from __future__ import annotations

import hashlib
import io
import json
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Any

import pytest
from test_timeline_commit_acceptance import context

from runtime_protocol.server import RuntimeHandler
from runtime_protocol.timeline_commit_execution import (
    _emit_redacted_diagnostic,
    current_idempotency_key,
    idempotency_key_scope,
    public_request_id_scope,
)
from runtime_protocol.timeline_commit_port import CommitUnavailable
from runtime_protocol.timeline_commit_provider import TimelineCommitUnavailable


def _diagnostic_lines(stderr):
    lines = stderr.splitlines()
    assert lines
    result = []
    for line in lines:
        prefix, encoded = line.split(" ", 1)
        assert prefix == "runtime.timeline_commit.error"
        result.append(json.loads(encoded))
    return result


def _key_hash(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_diagnostic_key_hash_matches_helper_and_keeps_retry_hash_stable(capsys):
    key = "swap-retry.v1"
    with public_request_id_scope("public-request"), idempotency_key_scope(key):
        _emit_redacted_diagnostic("a" * 32, reason="provider_none")
        _emit_redacted_diagnostic("b" * 32, reason="provider_none")

    diagnostics = _diagnostic_lines(capsys.readouterr().err)
    assert [item["request_id"] for item in diagnostics] == ["a" * 32, "b" * 32]
    assert {item["idempotency_key_sha256"] for item in diagnostics} == {_key_hash(key)}
    assert {item["public_request_id_hash"] for item in diagnostics} == {
        "sha256:" + hashlib.sha256(b"public-request").hexdigest()
    }
    assert key not in json.dumps(diagnostics)


def test_diagnostic_key_scope_is_nested_and_thread_local(capsys):
    with idempotency_key_scope("outer-key"):
        assert current_idempotency_key() == "outer-key"
        _emit_redacted_diagnostic("1" * 32, reason="provider_none")
        with idempotency_key_scope("inner-key"):
            assert current_idempotency_key() == "inner-key"
            _emit_redacted_diagnostic("2" * 32, reason="provider_none")
        assert current_idempotency_key() == "outer-key"
        _emit_redacted_diagnostic("3" * 32, reason="provider_none")
    assert current_idempotency_key() is None

    def emit(ordinal):
        key = f"thread-{ordinal}"
        with idempotency_key_scope(key):
            _emit_redacted_diagnostic(f"{ordinal:032x}", reason="provider_none")
        return key

    keys = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        keys.extend(pool.map(emit, (4, 5)))

    diagnostics = _diagnostic_lines(capsys.readouterr().err)
    by_request = {item["request_id"]: item for item in diagnostics}
    assert by_request["1" * 32]["idempotency_key_sha256"] == _key_hash("outer-key")
    assert by_request["2" * 32]["idempotency_key_sha256"] == _key_hash("inner-key")
    assert by_request["3" * 32]["idempotency_key_sha256"] == _key_hash("outer-key")
    for ordinal, key in zip((4, 5), keys):
        assert by_request[f"{ordinal:032x}"]["idempotency_key_sha256"] == _key_hash(key)


@pytest.mark.parametrize("key", (None, "", "é", "a\nsecret", "a " , "a" * 257))
def test_diagnostic_omits_absent_rejected_or_oversized_keys(key, capsys):
    with idempotency_key_scope(key):
        _emit_redacted_diagnostic("c" * 32, reason="provider_none")
    diagnostic = _diagnostic_lines(capsys.readouterr().err)[0]
    assert "idempotency_key_sha256" not in diagnostic
    assert "secret" not in json.dumps(diagnostic)


def test_mounted_commit_unavailable_path_emits_private_key_hash_without_public_change(
        capsys):
    body = {
        "api_version": 1,
        "project_id": "project-1",
        "timeline_id": "timeline-1",
        "base_revision_id": "revision-1",
        "base_publication_id": "publication-1",
        "commands": [],
    }
    public_request_id = "61c84a4e" * 4
    key = "missing-provider-key"
    handler: Any = object.__new__(RuntimeHandler)
    handler.server = SimpleNamespace(runtime=SimpleNamespace())
    handler.command = "POST"
    handler.path = "/v1/projects/project-1/timelines/timeline-1/commit"
    raw = json.dumps(body, separators=(",", ":")).encode()
    handler.rfile = io.BytesIO(raw)
    handler.headers = {
        "Content-Length": str(len(raw)),
        "Idempotency-Key": key,
        "X-Request-ID": public_request_id,
    }
    handler._identity = lambda _scope: {"actor": "publisher-1"}

    with pytest.raises(TimelineCommitUnavailable) as caught:
        handler._timeline_commit("project-1", "timeline-1", ["v1", "projects", "project-1"])

    assert caught.value.as_dict() == {
        "code": "not_ready",
        "message": "timeline commit provider is unavailable",
        "details": {"reason": "runtime_unavailable"},
    }
    diagnostic = _diagnostic_lines(capsys.readouterr().err)[0]
    assert diagnostic["request_id"] != public_request_id
    assert diagnostic["public_request_id_hash"] == (
        "sha256:" + hashlib.sha256(public_request_id.encode("ascii")).hexdigest()
    )
    assert diagnostic["idempotency_key_sha256"] == _key_hash(key)
    assert public_request_id not in json.dumps(diagnostic)
    assert key not in json.dumps(diagnostic)


def test_service_commit_diagnostic_uses_exact_key_hash_and_public_reply_is_unchanged(
        realm, capsys):
    service, _, project, head, _ = realm
    request = context(service, project, head, "service-key-hash")
    public_request_id = "service-public-id"

    with pytest.raises(CommitUnavailable) as caught:
        service.commit_timeline(
            project,
            "main",
            request["request"],
            idempotency_key=request["idempotency_key"],
            publisher=request["publisher"],
            invocation_path=request["invocation"]["path"],
            authorize=lambda: None,
            public_request_id=public_request_id,
        )

    assert caught.value.as_dict() == {
        "code": "not_ready",
        "message": "Timeline commit outcome unavailable; retry the exact request",
        "details": {"reason": "runtime_unavailable"},
    }
    diagnostic = _diagnostic_lines(capsys.readouterr().err)[0]
    assert diagnostic["reason"] == "provider_none"
    assert diagnostic["idempotency_key_sha256"] == _key_hash(request["idempotency_key"])
    assert diagnostic["public_request_id_hash"] == (
        "sha256:" + hashlib.sha256(public_request_id.encode("ascii")).hexdigest()
    )
