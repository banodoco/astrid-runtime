from __future__ import annotations

import ast
import copy
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

pytest_plugins = ["test_timeline_commit_acceptance"]

from test_timeline_commit_acceptance import context
from test_timeline_commit_port import prepared as port_prepared

from runtime_protocol.contract_metadata import SCHEMA_DIGEST
from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_execution import (
    _HISTORY_SOURCE_TAGS,
    _emit_redacted_diagnostic,
    _history_diagnostic_reason,
    current_public_request_id,
    public_request_id_scope,
)
from runtime_protocol.timeline_commit_port import digest
from runtime_protocol.timeline_commit_store import request_identity


class Provider:
    provider_id = "astrid-v1"
    interface_version = 1
    contract_digest = SCHEMA_DIGEST

    def __init__(self, action):
        self.action = action

    def commit(self, commit_context, port):
        return self.action(commit_context, port)


def _commit(service, project, request, *, public_request_id=None):
    return service.commit_timeline(
        project,
        "main",
        copy.deepcopy(request["request"]),
        idempotency_key=request["idempotency_key"],
        publisher=request["publisher"],
        invocation_path=request["invocation"]["path"],
        authorize=lambda: None,
        public_request_id=public_request_id,
    )


def _diagnostic(stderr):
    lines = stderr.splitlines()
    assert len(lines) == 1
    prefix, encoded = lines[0].split(" ", 1)
    assert prefix == "runtime.timeline_commit.error"
    return json.loads(encoded)


def _assert_history_refusal(caught, *, message="history_unavailable"):
    assert caught.value.status == 409
    assert caught.value.as_dict() == {
        "code": "conflict",
        "message": message,
        "details": {
            "status": "refused",
            "reason": "history_unavailable",
            "base": None,
            "current": None,
            "conflicts": [],
        },
    }


def test_store_history_emitters_have_distinct_static_tags():
    source = Path(__file__).parents[1] / "runtime_protocol/timeline_commit_store.py"
    tree = ast.parse(source.read_text())
    tags = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != "reject":
            continue
        if not node.args or not isinstance(node.args[0], ast.Constant) or node.args[0].value != "history_unavailable":
            continue
        values = [keyword.value for keyword in node.keywords
                  if keyword.arg == "diagnostic_reason" and isinstance(keyword.value, ast.Constant)]
        assert len(values) == 1, f"history emitter at line {node.lineno} lacks a static tag"
        tags.append(values[0].value)
    assert len(tags) == 31
    assert len(tags) == len(set(tags))
    assert set(tags) <= _HISTORY_SOURCE_TAGS


def test_port_history_emitters_have_distinct_static_tags():
    source = Path(__file__).parents[1] / "runtime_protocol/timeline_commit_port.py"
    tree = ast.parse(source.read_text())
    tags = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != "refused":
            continue
        if not node.args or not isinstance(node.args[0], ast.Constant) or node.args[0].value != "history_unavailable":
            continue
        values = [keyword.value for keyword in node.keywords
                  if keyword.arg == "diagnostic_reason" and isinstance(keyword.value, ast.Constant)]
        assert len(values) == 1, f"history emitter at line {node.lineno} lacks a static tag"
        tags.append(values[0].value)
    assert len(tags) == 6
    assert len(tags) == len(set(tags))
    assert set(tags) <= _HISTORY_SOURCE_TAGS


def test_real_store_history_refusal_emits_source_tag_without_public_change(realm, capsys):
    service, _, project, head, _ = realm
    request = context(service, project, head, "history-diagnostic-store")

    def refuse(_, port):
        port.history(port.head(), after_publication_id="missing-publication")

    service.register_timeline_commit_provider(Provider(refuse))
    with pytest.raises(RuntimeErrorBase) as caught:
        _commit(service, project, request)

    _assert_history_refusal(caught)
    diagnostic = _diagnostic(capsys.readouterr().err)
    assert diagnostic["reason"] == "store_history_entry_missing"
    assert diagnostic["exception_class_chain"] == []
    assert diagnostic["frames"] == []


def test_provider_history_refusal_has_distinct_tag_and_one_way_public_correlation(realm, capsys):
    service, _, project, head, _ = realm
    request = context(service, project, head, "history-diagnostic-provider")
    public_request_id = "61c84a4e"

    def refuse(_, __):
        raise CommitRejected({
            "http_status": 409,
            "code": "conflict",
            "message": "history_unavailable",
            "details": {
                "status": "refused",
                "reason": "history_unavailable",
                "base": None,
                "current": None,
                "conflicts": [],
            },
        })

    service.register_timeline_commit_provider(Provider(refuse))
    with pytest.raises(RuntimeErrorBase) as caught, public_request_id_scope(public_request_id):
        _commit(service, project, request)

    _assert_history_refusal(caught)
    diagnostic = _diagnostic(capsys.readouterr().err)
    assert diagnostic["reason"] == "provider_history_guard"
    assert diagnostic["request_id"] != public_request_id
    assert diagnostic["public_request_id_hash"] == "sha256:" + hashlib.sha256(public_request_id.encode()).hexdigest()
    assert public_request_id not in json.dumps(diagnostic)
    assert diagnostic["exception_class_chain"] == []
    assert diagnostic["frames"] == []


def test_real_port_history_refusal_emits_source_tag_without_public_change(realm, capsys):
    service, _, project, head, _ = realm
    request = context(service, project, head, "history-diagnostic-port")

    def refuse(_, port):
        port.revision_closure("undeclared-revision")

    service.register_timeline_commit_provider(Provider(refuse))
    with pytest.raises(RuntimeErrorBase) as caught:
        _commit(service, project, request)

    _assert_history_refusal(caught, message="revision is outside request ancestry or declared source")
    diagnostic = _diagnostic(capsys.readouterr().err)
    assert diagnostic["reason"] == "port_revision_outside_ancestry"
    assert diagnostic["exception_class_chain"] == []
    assert diagnostic["frames"] == []


def test_reference_projection_apply_history_refusal_keeps_public_conflict(realm, monkeypatch, capsys):
    service, _, project, head, _ = realm
    request = context(service, project, head, "history-diagnostic-reference-apply", op="fixture.inspect")
    media = service.ingest(project, b"reference-projection-media", idempotency_key="reference-media")["data"]["object_id"]
    pin = {"media_id": media, "content_digest": media}
    request["request"]["commands"][0]["args"] = {"media_pin": pin}
    request["invocation"]["body"] = copy.deepcopy(request["request"])
    request["request_hash"] = request_identity(request)

    def refuse(_, port):
        candidate = port_prepared(_, port)
        candidate["canonical_document"]["dependency_manifest"]["media"] = [pin]
        payload = candidate["canonical_document"]["parent_revision"]["payload"]
        payload["config"]["app"] = {"astrid": {"timeline_references": {
            "reference": {"version": 1, "reference_id": "reference", "role": "source", "media": pin}
        }}}
        candidate["canonical_document"]["parent_revision"]["content_digest"] = digest(payload)
        candidate["document_digest"] = digest(candidate["canonical_document"])
        port.raw_media_info(pin)
        return port.accept(candidate)

    import runtime_protocol.timeline_commit_reference_projection as projection

    original_prepare = projection.prepare_reference_projection

    def prepare_with_changed_version(*args, **kwargs):
        value = original_prepare(*args, **kwargs)
        service.store.conn.execute(
            "UPDATE timelines SET version=version+1 WHERE id=? AND project_id=?", ("main", project)
        )
        return value

    monkeypatch.setattr(projection, "prepare_reference_projection", prepare_with_changed_version)
    service.register_timeline_commit_provider(Provider(refuse))
    with pytest.raises(RuntimeErrorBase) as caught:
        _commit(service, project, request)

    assert caught.value.status == 503
    assert caught.value.as_dict() == {
        "code": "not_ready",
        "message": "Timeline commit outcome unavailable; retry the exact request",
        "details": {"reason": "runtime_unavailable"},
    }
    diagnostic = _diagnostic(capsys.readouterr().err)
    assert diagnostic["reason"] == "store_reference_projection_apply_history"
    assert diagnostic["exception_class_chain"] == []
    assert diagnostic["frames"] == []


def test_history_mapper_rejects_non_history_and_untrusted_source_tags():
    assert _history_diagnostic_reason({"details": {"reason": "head_changed"}}) is None
    assert _history_diagnostic_reason({
        "details": {"reason": "history_unavailable"},
    }, source_reason="not-a-static-tag") is None
    assert _history_diagnostic_reason({
        "message": "history bounds disagree",
        "details": {"reason": "history_unavailable"},
    }) == "port_history_bounds_mismatch"


def test_public_request_id_scope_is_nested_and_thread_local(capsys):
    assert current_public_request_id() is None
    with public_request_id_scope("outer-request"):
        assert current_public_request_id() == "outer-request"
        with public_request_id_scope("inner-request"):
            assert current_public_request_id() == "inner-request"
        assert current_public_request_id() == "outer-request"
    assert current_public_request_id() is None

    public_ids = [f"thread-{index}" for index in range(8)]

    def emit(public_request_id):
        with public_request_id_scope(public_request_id):
            _emit_redacted_diagnostic("f" * 32, reason="provider_none")

    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(emit, public_ids))

    diagnostics = [_diagnostic(line) for line in capsys.readouterr().err.splitlines()]
    assert {item["public_request_id_hash"] for item in diagnostics} == {
        "sha256:" + hashlib.sha256(value.encode()).hexdigest() for value in public_ids
    }
    assert all(item["request_id"] == "f" * 32 for item in diagnostics)
    assert all(value not in json.dumps(diagnostics) for value in public_ids)
