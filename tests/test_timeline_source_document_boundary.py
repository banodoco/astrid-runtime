"""Ordinary producer documents stay outside canonical timeline authority."""
from __future__ import annotations

import json
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest

from http_helpers import Api
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_port import digest, route_path
from test_timeline_commit_port import PreparedProvider, prepared


def _renderer_unavailable(*args, **kwargs):
    raise AssertionError("source capture/save reached the renderer")


@pytest.fixture
def http_case(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    project = service.create_project({"slug": "source-boundary", "name": "Source boundary"})["id"]
    service.register_timeline_commit_provider(PreparedProvider())
    service.create_timeline(project, "main", idempotency_key="main")
    service.close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
    token, _ = daemon.credentials.provision("source-boundary", ["projects:read", "projects:write"])
    try:
        yield SimpleNamespace(
            daemon=daemon, service=daemon.service, project=project,
            api=Api(daemon.endpoint, token),
        )
    finally:
        daemon.stop()


def _snapshot(service):
    with service.store._mutex:
        return (
            tuple(service.store.conn.iterdump()),
            {str(path.relative_to(service.store.cas_root)): path.read_bytes()
             for path in service.store.cas_root.rglob("*") if path.is_file()},
            service.store.conn.total_changes,
        )


def _head_and_history(case):
    head = case.service.get_project_timeline(case.project, "main")
    history = case.service.list_timeline_commits(
        case.project, "main", authorize=lambda: None,
    )
    return (head["head_revision_id"], head["head_publication_id"]), history["items"]


def test_nested_timeline_shape_is_ordinary_but_top_level_spoofs_are_zero_write(http_case):
    case = http_case
    content = {
        "schema": "producer.config/v1",
        "clips": [{"id": "timeline:clip-inside"}],
        "registry": {"timeline_id": "timeline:nested"},
        "unknown": {"document_id": "timeline:nested-doc", "kind": "timeline.composition"},
    }
    before = _head_and_history(case)
    created = case.api.request(
        "POST", f"/v1/projects/{case.project}/documents",
        {"document_id": "producer-source", "kind": "producer.config", "content": content},
        headers={"Idempotency-Key": "producer-v1"},
    )
    changed = {**content, "clips": [{"id": "timeline:clip-v2"}], "enabled": True}
    updated = case.api.request(
        "PATCH", f"/v1/projects/{case.project}/documents/producer-source",
        {"expected_version": created["data"]["version"], "content": changed},
        headers={"Idempotency-Key": "producer-v2"},
    )
    assert updated["data"]["kind"] == "producer.config"
    assert updated["data"]["content"] == changed
    assert _head_and_history(case) == before

    for document_id, kind in (("timeline:spoof", "producer.config"),
                              ("ordinary-spoof", "timeline.composition")):
        unchanged = _snapshot(case.service)
        with pytest.raises(RuntimeError) as error:
            case.api.request(
                "POST", f"/v1/projects/{case.project}/documents",
                {"document_id": document_id, "kind": kind, "content": content},
                headers={"Idempotency-Key": "spoof-" + document_id.replace(":", "-")},
            )
        assert error.value.status == 410
        assert _snapshot(case.service) == unchanged


def test_http_config_source_retains_v1_across_producer_update_and_retry(http_case, monkeypatch):
    case = http_case
    import runtime_protocol.service as service_module
    import runtime_protocol.visual_seam as visual_seam
    monkeypatch.setattr(service_module, "evaluate_closure", _renderer_unavailable)
    monkeypatch.setattr(visual_seam, "evaluate_closure", _renderer_unavailable)
    v1 = {"schema": "producer.config/v1", "clips": [], "registry": {"timeline_id": "timeline:opaque"}}
    source = case.api.request(
        "POST", f"/v1/projects/{case.project}/documents",
        {"document_id": "producer-config", "kind": "producer.config", "content": v1},
        headers={"Idempotency-Key": "config-v1"},
    )["data"]
    pin = {"document_id": source["document_id"], "version": source["version"],
           "content_digest": digest(source["content"])}
    seen = []

    def action(context, port):
        seen.append(port.config_source(pin))
        candidate = prepared(context, port)
        candidate["canonical_document"]["dependency_manifest"]["documents"] = [pin]
        candidate["document_digest"] = digest(candidate["canonical_document"])
        candidate["records"]["commands"][0]["dependencies"] = [
            {"key": "config:producer-config", "kind": "source", "pin": pin, "policy": "exact"},
        ]
        return port.accept(candidate)

    case.service.register_timeline_commit_provider(PreparedProvider(action))
    head = case.service.get_project_timeline(case.project, "main")
    body = {"api_version": 1, "project_id": case.project, "timeline_id": "main",
            "base_revision_id": head["head_revision_id"],
            "base_publication_id": head["head_publication_id"],
            "commands": [{"schema_version": 1, "op": "fixture.capture-source", "version": "1",
                          "select": None, "args": {"pin": pin}, "created": []}]}
    path = f"/v1/projects/{case.project}/timelines/main/commit"
    accepted = case.api.request("POST", path, body, headers={"Idempotency-Key": "capture-v1"})
    assert accepted["data"]["canonical_document"]["dependency_manifest"]["documents"] == [pin]
    assert accepted["data"]["accepted_revision_id"] == accepted["data"]["canonical_document"]["parent_revision"]["revision_id"]
    canonical_after_accept = _head_and_history(case)
    v2 = {"schema": "producer.config/v2", "clips": [], "registry": {"timeline_id": "timeline:opaque-v2"}}
    current = case.api.request(
        "PATCH", f"/v1/projects/{case.project}/documents/producer-config",
        {"expected_version": 1, "kind": "producer.v2.config", "content": v2},
        headers={"Idempotency-Key": "config-v2"},
    )
    assert current["data"]["version"] == 2
    assert current["data"]["kind"] == "producer.v2.config"
    assert case.api.request("POST", path, body, headers={"Idempotency-Key": "capture-v1"}) == accepted
    assert _head_and_history(case) == canonical_after_accept
    assert seen == [{"pin": pin, "document": source}]
    retained = case.service.store.conn.execute(
        "SELECT b.document_version, c.content_json "
        "FROM timeline_document_input_bindings b "
        "JOIN timeline_document_input_contents c ON c.content_digest=b.content_digest "
        "WHERE b.document_id=?", (source["document_id"],)
    ).fetchone()
    assert retained["document_version"] == 1
    assert json.loads(retained["content_json"]) == v1


def test_http_transcript_source_reads_retained_v1_without_pack_object(http_case):
    case = http_case
    media_id = case.service.ingest(
        case.project, b"transcript media", media_type="video/mp4", idempotency_key="transcript-media",
    )["data"]["object_id"]
    content = {
        "schema": "media.transcript/v1", "media_id": media_id, "source_id": "default",
        "segments": [{"id": "segment-1", "start": 0.0, "end": 1.0, "text": "v1",
                      "words": [{"id": "word-1", "start": 0.0, "end": 1.0, "text": "v1"}]}],
    }
    document_id = RuntimeService._transcript_document_id(case.project, media_id, "default")
    source = case.service.create_document(
        case.project, {"document_id": document_id, "kind": "media.transcript", "content": content},
        idempotency_key="transcript-v1",
    )["data"]
    pin = {"document_id": document_id, "version": 1, "content_digest": digest(content)}
    seen = []

    def action(context, port):
        candidate = prepared(context, port)
        seen.append(port.transcript_source(pin))
        candidate["canonical_document"]["dependency_manifest"]["documents"] = [pin]
        candidate["document_digest"] = digest(candidate["canonical_document"])
        candidate["records"]["commands"][0]["dependencies"] = [
            {"key": "transcript", "kind": "transcript", "pin": pin, "policy": "exact"},
        ]
        return port.accept(candidate)

    case.service.register_timeline_commit_provider(PreparedProvider(action))
    head = case.service.get_project_timeline(case.project, "main")
    body = {
        "api_version": 1, "project_id": case.project, "timeline_id": "main",
        "base_revision_id": head["head_revision_id"], "base_publication_id": head["head_publication_id"],
        "commands": [{"schema_version": 1, "op": "fixture.capture-transcript", "version": "1",
                       "select": None, "args": {"pin": pin}, "created": []}],
    }
    case.service.commit_timeline(
        case.project, "main", body, idempotency_key="capture-transcript",
        publisher="transcript-boundary", invocation_path=route_path(case.project, "main"),
        authorize=lambda: None,
    )
    assert seen == [{"pin": pin, "document": source}]

    changed = {**content, "segments": [{**content["segments"][0], "text": "v2",
                                          "words": [{"id": "word-1", "start": 0.0, "end": 1.0, "text": "v2"}]}]}
    case.service.update_document(
        case.project, document_id, {"expected_version": 1, "content": changed},
        idempotency_key="transcript-v2",
    )
    case.service.store.conn.execute("DELETE FROM project_documents WHERE id=?", (document_id,))
    expected = {"pin": pin, "document": source}
    query = urlencode(pin)
    assert case.api.request("GET", f"/v1/projects/{case.project}/document-inputs/verified?{query}") == expected
    case.daemon.stop()
    case.daemon.start()
    case.service = case.daemon.service
    case.api.endpoint = case.daemon.endpoint
    assert case.api.request("GET", f"/v1/projects/{case.project}/document-inputs/verified?{query}") == expected

    note = case.service.create_document(
        case.project, {"document_id": "ordinary-note", "kind": "demo.note", "content": {"text": "no"}},
        idempotency_key="ordinary-note",
    )["data"]
    foreign = case.service.create_project({"slug": "foreign-transcript", "name": "Foreign transcript"})["id"]
    before = _snapshot(case.service)
    with pytest.raises(RuntimeErrorBase):
        case.service.get_project_verified_document(case.project, {**pin, "document_id": note["document_id"]},
                                                   authorize=lambda: None)
    with pytest.raises(RuntimeErrorBase):
        case.service.get_project_verified_document(foreign, pin, authorize=lambda: None)
    assert _snapshot(case.service) == before
