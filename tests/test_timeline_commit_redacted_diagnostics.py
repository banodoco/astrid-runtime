from __future__ import annotations

import copy
import hashlib
import json
import re

import pytest

pytest_plugins = ["test_timeline_commit_acceptance"]

from test_timeline_commit_acceptance import context

from runtime_protocol.contract_metadata import SCHEMA_DIGEST
from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.timeline_commit_execution import CommitOutcomeUnknown

MAX_DIAGNOSTIC_BYTES = 4096


class Provider:
    provider_id = "astrid-v1"
    interface_version = 1
    contract_digest = SCHEMA_DIGEST

    def __init__(self, action):
        self.action = action

    def commit(self, context, port):
        return self.action(context, port)


def _commit(service, project, body, key):
    return service.commit_timeline(
        project,
        "main",
        copy.deepcopy(body),
        idempotency_key=key,
        publisher="diagnostic-editor",
        invocation_path=f"/v1/projects/{project}/timelines/main/commit",
        authorize=lambda: None,
    )


def _diagnostic(stderr):
    lines = stderr.splitlines()
    assert len(lines) == 1
    prefix, encoded = lines[0].split(" ", 1)
    assert prefix == "runtime.timeline_commit.error"
    return json.loads(encoded)


def test_provider_exception_keeps_public_503_and_emits_one_redacted_line(realm, capsys):
    service, _, project, head, _ = realm
    request = context(service, project, head, "redacted-provider")
    secret = "exception-secret-message-and-note"

    def fail(_, __):
        try:
            raise LookupError(secret)
        except LookupError as cause:
            error = RuntimeError("provider wrapper")
            error.__cause__ = cause
            error.add_note(secret)
            raise error

    service.register_timeline_commit_provider(Provider(fail))
    with pytest.raises(RuntimeErrorBase) as caught:
        _commit(service, project, request["request"], request["idempotency_key"])

    assert caught.value.status == 503
    assert caught.value.as_dict() == {
        "code": "not_ready",
        "message": "Timeline commit outcome unavailable; retry the exact request",
        "details": {"reason": "runtime_unavailable"},
    }
    stderr = capsys.readouterr().err
    diagnostic = _diagnostic(stderr)
    assert diagnostic["reason"] == "catchall:builtins.RuntimeError"
    assert re.fullmatch(r"[a-f0-9]{32}", diagnostic["request_id"])
    assert diagnostic["exception_class_chain"][:2] == [
        "builtins.RuntimeError",
        "builtins.LookupError",
    ]
    assert any(":fail" in frame for frame in diagnostic["frames"])
    assert secret not in stderr
    assert secret not in json.dumps(diagnostic)


def test_lookup_exception_maps_to_unknown_once_without_public_detail_change(realm, monkeypatch, capsys):
    service, _, project, head, _ = realm
    request = context(service, project, head, "redacted-lookup")
    secret = "lookup-secret-message"
    commits, _ = service._timeline_commits()
    original_lookup = commits.lookup
    calls = 0

    def fail_second_lookup(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError(secret)
        return original_lookup(*args, **kwargs)

    def refuse(_, __):
        return {
            "http_status": 409,
            "code": "conflict",
            "message": "provider refusal",
            "details": {
                "status": "conflict",
                "reason": "head_changed",
                "base": None,
                "current": None,
                "conflicts": [],
            },
        }

    monkeypatch.setattr(commits, "lookup", fail_second_lookup)
    service.register_timeline_commit_provider(Provider(refuse))
    with pytest.raises(CommitOutcomeUnknown) as caught:
        _commit(service, project, request["request"], request["idempotency_key"])

    assert caught.value.status == 503
    assert caught.value.as_dict() == {
        "code": "not_ready",
        "message": "Timeline commit outcome unavailable; retry the exact request",
        "details": {"reason": "runtime_unavailable"},
    }
    stderr = capsys.readouterr().err
    diagnostic = _diagnostic(stderr)
    assert diagnostic["reason"] == "catchall:builtins.OSError"
    assert diagnostic["exception_class_chain"] == ["builtins.OSError"]
    assert secret not in json.dumps(diagnostic)


def test_malicious_exception_metadata_is_bounded_and_public_reply_is_unchanged(realm, capsys):
    service, _, project, head, _ = realm
    request = context(service, project, head, "redacted-metadata")
    secret = "metadata-secret-sentinel"
    class_sentinel = "class-metadata-sentinel"
    filename_sentinel = "filename-metadata-sentinel"

    class MetadataError(Exception):
        pass

    MetadataError.__module__ = class_sentinel + ("x" * 20_000)
    MetadataError.__qualname__ = class_sentinel + ("y" * 20_000)
    errors = [MetadataError(secret) for _ in range(32)]
    for current, following in zip(errors, errors[1:] + errors[:1]):
        current.__cause__ = following
    namespace = {"MetadataError": MetadataError}
    filename = (
        "https://user:password@example.test/"
        + filename_sentinel
        + ("z" * 10_000)
        + ".py"
    )
    exec(compile("def invoke(error):\n    raise error\n", filename, "exec"), namespace)  # noqa: S102

    def fail(_, __):
        namespace["invoke"](errors[0])

    service.register_timeline_commit_provider(Provider(fail))
    with pytest.raises(RuntimeErrorBase) as caught:
        _commit(service, project, request["request"], request["idempotency_key"])

    assert caught.value.status == 503
    assert caught.value.code == "not_ready"
    assert caught.value.as_dict() == {
        "code": "not_ready",
        "message": "Timeline commit outcome unavailable; retry the exact request",
        "details": {"reason": "runtime_unavailable"},
    }
    stderr = capsys.readouterr().err
    assert len(stderr.encode("utf-8")) <= MAX_DIAGNOSTIC_BYTES
    diagnostic = _diagnostic(stderr)
    assert set(diagnostic) == {
        "event",
        "request_id",
        "reason",
        "exception_class_chain",
        "frames",
        "idempotency_key_sha256",
    }
    assert diagnostic["idempotency_key_sha256"] == hashlib.sha256(request["idempotency_key"].encode("utf-8")).hexdigest()
    assert request["idempotency_key"] not in stderr
    assert diagnostic["reason"].startswith("catchall:sha256:")
    assert re.fullmatch(r"[a-f0-9]{32}", diagnostic["request_id"])
    assert len(diagnostic["exception_class_chain"]) <= 8
    assert len(diagnostic["frames"]) <= 32
    assert any("sha256:" in value for value in diagnostic["exception_class_chain"])
    assert any("sha256:" in value for value in diagnostic["frames"])
    assert secret not in stderr
    assert class_sentinel not in stderr
    assert filename_sentinel not in stderr
    assert "user:password" not in stderr
