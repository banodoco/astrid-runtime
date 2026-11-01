"""Authenticated HTTP boundaries for canonical timeline history and reads."""
from __future__ import annotations

import base64
import json

import pytest

from astrid_runtime_client import ApiError, WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_port import digest

from test_timeline_commit_port import PreparedProvider, _complete_v2_metadata, prepared
from tests.http_helpers import Api


def _commit_body(client, project_id, timeline_id, marker):
    head = client.get_project_timeline(project_id, timeline_id)
    return {
        "api_version": 1,
        "project_id": project_id,
        "timeline_id": timeline_id,
        "base_revision_id": head["head_revision_id"],
        "base_publication_id": head["head_publication_id"],
        "commands": [{
            "schema_version": 1,
            "op": "clip.move",
            "version": "1",
            "select": "parent/clip:clip-1",
            "args": {"on": 2},
        }],
        "label": str(marker),
    }


def _child_candidate(context, port, label):
    candidate = prepared(context, port)
    document = candidate["canonical_document"]
    internal_payload = {"clips": [], "tracks": [], "registry": {}, "audio": []}
    internal = {
        "timeline_id": "main",
        "revision_id": f"internal-{label}",
        "content_digest": digest(internal_payload),
        "payload": internal_payload,
    }
    shot_payload = {"internal_timeline_revision_id": internal["revision_id"],
                    "metadata": {"title": label}, "items": [], "pools": [],
                    "selected_variants": {}, "provenance": {},
                    "generation_inputs": {}, "audio_bindings": [], "text_bindings": []}
    shot = {
        "shot_id": "shot-1",
        "revision_id": f"shot-{label}",
        "internal_timeline_revision_id": internal["revision_id"],
        "content_digest": digest(shot_payload),
        "payload": shot_payload,
    }
    parent = document["parent_revision"]
    parent["payload"]["occurrences"] = [{
        "occurrence_id": f"occ-{label}", "shot_id": shot["shot_id"],
        "shot_revision_id": shot["revision_id"], "placement": {"start_ms": 0},
        "source_offset": 0, "duration_ms": 1000, "speed": 1,
        "track": "picture", "transform": {}, "gain": 1, "mute": False,
        "provenance": {},
    }]
    parent["revision_id"] = f"parent-{label}"
    parent["content_digest"] = digest(parent["payload"])
    document["shot_revisions"] = [shot]
    document["internal_timeline_revisions"] = [internal]
    document["dependency_manifest"] = {
        "shots": [{key: shot[key] for key in
                   ("shot_id", "revision_id", "internal_timeline_revision_id", "content_digest")}],
        "internal_timelines": [{key: internal[key] for key in
                                 ("timeline_id", "revision_id", "content_digest")}],
        "media": [], "documents": [],
    }
    candidate["document_digest"] = digest(document)
    _complete_v2_metadata(context, port, document, candidate["expected_head"], candidate["records"])
    return port.accept(candidate)


@pytest.fixture
def http_runtime(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
    provider = PreparedProvider()
    daemon.service.register_timeline_commit_provider(provider)
    client = WorkspaceClient(daemon.endpoint, daemon.token)
    project = client.create_project("History", slug="history", idempotency_key="project")
    project_id = project["project_id"]
    client.create_timeline(project_id, "main", idempotency_key="timeline")
    try:
        yield daemon, client, project_id, provider
    finally:
        daemon.stop()


def test_http_history_keeps_fixed_head_and_distinct_same_revision_edges(http_runtime):
    _, client, project_id, provider = http_runtime
    provider.action = lambda context, port: port.accept(prepared(context, port, same=True))
    for index in range(4):
        client.commit_timeline(
            project_id, "main", _commit_body(client, project_id, "main", index),
            idempotency_key=f"same-{index}",
        )
    expected = client.list_timeline_commits(project_id, "main", limit=50)
    first = client.list_timeline_commits(project_id, "main", limit=2)
    assert len(first["items"]) == 2
    bound_head = first["head"]
    cursor = first["next_cursor"]

    later = client.commit_timeline(
        project_id, "main", _commit_body(client, project_id, "main", "later"),
        idempotency_key="same-later",
    )
    client.rename_timeline(project_id, "main", "Renamed", idempotency_key="rename")

    pages = [first]
    while cursor:
        page = client.list_timeline_commits(project_id, "main", cursor=cursor, limit=2)
        pages.append(page)
        assert page["head"] == bound_head
        cursor = page["next_cursor"]
    items = [item for page in pages for item in page["items"]]
    assert [item["publication_id"] for item in items] == [
        item["publication_id"] for item in expected["items"]
    ]
    assert later["receipt"]["receipt_id"] not in {item["publication_id"] for item in items}
    assert len({item["revision_id"] for item in items[1:]}) == 1
    assert len({item["publication_id"] for item in items[1:]}) == len(items) - 1
    for item in items[1:]:
        assert item["receipt"]["result"]["accepted_revision_id"] == item["revision_id"]
        assert item["receipt"]["result"]["commands"] == [item["records"]["commands"][0]["command"]]
    decoded = json.loads(base64.urlsafe_b64decode(first["next_cursor"].encode()))
    assert decoded["scope"][2] == bound_head


def test_http_history_scope_auth_and_limits_refuse_without_leaking_data(http_runtime, tmp_path):
    daemon, client, project_id, _ = http_runtime
    client.commit_timeline(
        project_id, "main", _commit_body(client, project_id, "main", "scope"), idempotency_key="scope"
    )
    client.create_timeline(project_id, "other", idempotency_key="other-timeline")
    first = client.list_timeline_commits(project_id, "main", limit=1)
    reader_token, _ = daemon.credentials.provision("reader", ["projects:read"])
    reader = WorkspaceClient(daemon.endpoint, reader_token)
    assert reader.list_timeline_commits(project_id, "main")["items"]
    with pytest.raises(ApiError) as error:
        reader.commit_timeline(project_id, "main", _commit_body(client, project_id, "main", "read-only"), idempotency_key="read-only")
    assert error.value.status == 401

    api = Api(daemon.endpoint, daemon.token)
    for limit in ("0", "201", "not-a-number", ""):
        with pytest.raises(RuntimeError) as error:
            api.request("GET", f"/v1/projects/{project_id}/timelines/main/commits?limit={limit}")
        assert error.value.status == 400
        assert "items" not in error.value.detail
    with pytest.raises(RuntimeError) as error:
        api.request("GET", f"/v1/projects/missing/timelines/main/commits")
    assert error.value.status == 404 and "items" not in error.value.detail
    with pytest.raises(RuntimeError) as error:
        api.request("GET", f"/v1/projects/{project_id}/timelines/missing/commits")
    assert error.value.status == 404 and "items" not in error.value.detail
    with pytest.raises(ApiError) as error:
        reader.list_timeline_commits(project_id, "other", cursor=first["next_cursor"])
    assert error.value.status == 422
    with pytest.raises(RuntimeError) as error:
        Api(daemon.endpoint, None).request("GET", f"/v1/projects/{project_id}/timelines/main/commits")
    assert error.value.status == 401
    foreign_root = tmp_path / "foreign-realm"
    RealmStore.initialize(foreign_root).close()
    foreign = RuntimeDaemon(foreign_root, support_root=tmp_path / "foreign-support").start()
    try:
        with pytest.raises(RuntimeError) as error:
            Api(foreign.endpoint, daemon.token).request(
                "GET", "/v1/projects/missing/timelines/main/commits"
            )
        assert error.value.status == 401
    finally:
        foreign.stop()


def test_http_dry_run_needs_write_scope_and_reserves_nothing(http_runtime):
    daemon, client, project_id, _ = http_runtime
    reader_token, _ = daemon.credentials.provision("dry-reader", ["projects:read"])
    reader = WorkspaceClient(daemon.endpoint, reader_token)
    before = client.list_timeline_commits(project_id, "main", limit=50)
    body = {**_commit_body(client, project_id, "main", "dry"), "dry_run": True}
    with pytest.raises(ApiError) as error:
        reader.commit_timeline(project_id, "main", body, idempotency_key="dry-read-only")
    assert error.value.status == 401
    assert client.list_timeline_commits(project_id, "main", limit=50) == before
    preview = client.commit_timeline(project_id, "main", body, idempotency_key="dry-writer")
    assert preview["data"]["status"] == "preview"
    assert preview["receipt"] is None
    assert client.list_timeline_commits(project_id, "main", limit=50) == before
    assert client.get_project_timeline(project_id, "main")["head_publication_id"] == before["head"]["publication_id"]


def test_http_revision_reads_keep_manifest_pinned_children_after_new_head(http_runtime):
    daemon, client, project_id, provider = http_runtime
    provider.action = lambda context, port: _child_candidate(context, port, context["idempotency_key"])
    old = client.commit_timeline(
        project_id, "main", _commit_body(client, project_id, "main", "old"), idempotency_key="old"
    )
    old_document = old["data"]["canonical_document"]
    new = client.commit_timeline(
        project_id, "main", _commit_body(client, project_id, "main", "new"), idempotency_key="new"
    )
    old_parent = client.get_project_parent_composition_revision(project_id, "main", old["data"]["accepted_revision_id"])
    old_shot = old_document["shot_revisions"][0]
    old_internal = old_document["internal_timeline_revisions"][0]
    assert old_parent["payload"]["occurrences"][0]["shot_revision_id"] == old_shot["revision_id"]
    assert old_parent["dependency_manifest"]["shots"][0]["revision_id"] == old_shot["revision_id"]
    assert client.get_project_shot_revision(project_id, "shot-1", old_shot["revision_id"])["payload"] == old_shot["payload"]
    assert client.get_project_timeline_revision(project_id, "main", old_internal["revision_id"])["payload"] == old_internal["payload"]
    reader_token, _ = daemon.credentials.provision("revision-reader", ["projects:read"])
    reader = WorkspaceClient(daemon.endpoint, reader_token)
    assert reader.get_project_parent_composition_revision(project_id, "main", old["data"]["accepted_revision_id"])["payload"] == old_parent["payload"]
    with pytest.raises(RuntimeError) as error:
        Api(daemon.endpoint, None).request(
            "GET", f"/v1/projects/{project_id}/timelines/main/composition-revisions/{old['data']['accepted_revision_id']}"
        )
    assert error.value.status == 401
    assert new["data"]["accepted_revision_id"] != old["data"]["accepted_revision_id"]
    assert old_parent["payload"]["occurrences"][0]["shot_revision_id"] != new["data"]["canonical_document"]["shot_revisions"][0]["revision_id"]
