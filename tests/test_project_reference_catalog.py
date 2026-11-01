"""Main's project catalog is metadata, independent of timeline acceptance."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from astrid_runtime_client import ApiError, WorkspaceClient
from runtime_protocol.errors import ConflictError, NotFoundError
from runtime_protocol.service import RuntimeService

from test_runtime_e2e import daemon  # noqa: F401 (fixture)
from test_timeline_commit_integration import agent, editing, film  # noqa: F401 (fixtures)
from test_timeline_reference_authority import (
    CATALOG_FAMILIES, call_service, catalog_request, film_snapshot, snapshot,
    service_case, http_case, actual_provider,  # noqa: F401 (fixtures)
)


def test_catalog_before_any_timeline_is_scoped_ordered_and_restart_durable(daemon, tmp_path):
    owner = WorkspaceClient(daemon.endpoint, daemon.token)
    project = owner.create_project("Catalog", slug="catalog", idempotency_key="project").project_id
    other = owner.create_project("Other", slug="other", idempotency_key="other").project_id
    media = owner.ingest_project_object(project, b"source", media_type="application/octet-stream",
                                        idempotency_key="source").object_id
    output = owner.ingest_project_object(project, b"produced", media_type="application/octet-stream",
                                         idempotency_key="produced").object_id
    token, _ = daemon.credentials.provision("catalog-author", ["projects:read", "projects:write"])
    client = WorkspaceClient(daemon.endpoint, token)
    body = {"reference_id": "character", "kind": "character", "name": "Aria", "media_id": media,
            "description": "Lead", "metadata": {"costume": "red"}}
    created = client.create_project_reference(project, body, idempotency_key="create")
    assert created["version"] == 1 and created["kind"] == "character"
    assert created["description"] == "Lead" and created["metadata"] == {"costume": "red"}
    assert created["media_references"][0]["is_primary"] is True
    assert client.list_project_references(other)[0] == []
    updated = client.update_project_reference(project, "character", expected_version=1, name="Aria Prime",
                                               idempotency_key="update")
    archived = client.archive_project_reference(project, "character", expected_version=updated["version"],
                                                 idempotency_key="archive")
    assert archived["archived"] is True and client.list_project_references(project)[0] == []
    assert client.list_project_references(project, include_archived=True)[0] == [
        {key: value for key, value in archived.items() if key != "receipt"},
    ]
    recovered = client.recover_project_reference(project, "character", expected_version=archived["version"],
                                                   idempotency_key="recover")
    assert recovered["archived"] is False and recovered["name"] == "Aria Prime"
    for role, object_id in (("used_as_input", media), ("depicts", output)):
        associated = client.associate_reference(project, "character", {
            "association_id": role, "media_id": object_id, "role": role,
            "metadata": {"context_task": "producer-task", "context_run": "producer-run", "port": "image"},
        }, idempotency_key=role)
    associations = associated["media_references"]
    assert [item["ordinal"] for item in associations] == [0, 1, 2]
    assert [item["role"] for item in associations] == ["canonical", "used_as_input", "depicts"]
    assert [item["media_id"] for item in associations] == [media, media, output]
    assert associations[-1]["metadata"]["context_task"] == "producer-task"
    primary = client.set_primary_reference(project, "character", "depicts", expected_version=associated["version"],
                                             idempotency_key="primary")
    assert [item["association_id"] for item in primary["media_references"] if item["is_primary"]] == ["depicts"]
    target = client.create_project_reference(project, {
        "reference_id": "prop", "kind": "object", "name": "Prop", "media_id": media,
    }, idempotency_key="prop")
    link = client.link_references(project, {
        "from_reference_id": "character", "to_reference_id": target["reference_id"], "kind": "related_to",
    }, idempotency_key="link")
    assert link["kind"] == "related_to"
    final = client.get_project_reference(project, "character")
    assert {(item["from_reference_id"], item["to_reference_id"]) for item in final["links"]} == {
        ("character", "prop"), ("prop", "character"),
    }
    assert client.list_timelines(project)[0] == []
    assert daemon.service.store.conn.execute("SELECT COUNT(*) FROM timelines").fetchone()[0] == 0
    daemon.stop()
    service = RuntimeService(tmp_path / "realm")
    try:
        assert service.get_project_reference(project, "character") == final
        before = snapshot(service)
        replay = service.create_project_reference(project, body, idempotency_key="create")
        assert replay["data"] == {key: value for key, value in created.items() if key != "receipt"}
        assert replay["receipt"] == created.receipt
        assert snapshot(service) == before
        with pytest.raises(ConflictError):
            service.create_project_reference(project, {**body, "name": "Changed"}, idempotency_key="create")
        assert snapshot(service) == before
        with pytest.raises(ConflictError):
            service.create_project_reference(project, body, idempotency_key="duplicate-id")
        assert snapshot(service) == before
    finally:
        service.close()


@pytest.mark.parametrize("family", CATALOG_FAMILIES)
def test_catalog_scope_and_worker_renderer_authority_are_unchanged(http_case, family):
    case, method, path, body = catalog_request(http_case.service, http_case.cases["fresh"], family)
    if family == "create_project_reference":
        media = http_case.service.ingest(case.project, b"fresh project only", idempotency_key="fresh-only")
        body["media_id"] = media["data"]["object_id"]
    before = snapshot(http_case.service)
    for actor, scopes in (("producer-worker", ["worker:execute", "worker:register", "objects:write"]),
                          ("renderer", ["projects:read", "objects:read", "tasks:read", "tasks:write"])):
        token, _ = http_case.daemon.credentials.provision(actor, scopes)
        client = WorkspaceClient(http_case.daemon.endpoint, token)
        with pytest.raises(ApiError) as error:
            client._request(method, path, body=json.dumps(body).encode(), expected=(200, 201),
                            headers={"Content-Type": "application/json", "Idempotency-Key": "unauthorized"})
        assert error.value.status == 401
        assert snapshot(http_case.service) == before
    foreign = http_case.cases["unused"]
    foreign_case = SimpleNamespace(**{**vars(case), "project": foreign.project})
    if family == "create_project_reference":
        body = {**body, "reference_id": "foreign-media"}
    with pytest.raises(NotFoundError):
        call_service(http_case.service, foreign_case, family, body, "foreign")
    assert snapshot(http_case.service) == before


@pytest.mark.parametrize("family", ("create_project_reference", "associate_reference"))
def test_catalog_media_must_belong_to_reference_project(service_case, family):
    service = service_case.service
    case, _, _, body = catalog_request(service, service_case.cases["fresh"], family)
    # The same bytes are owned by both fresh projects; use a genuinely foreign
    # API-ingested object to distinguish ownership from global CAS presence.
    foreign = service.ingest(service_case.cases["unused"].project, b"foreign media", idempotency_key="foreign-media")
    body["media_id"] = foreign["data"]["object_id"]
    before = snapshot(service)
    with pytest.raises(NotFoundError):
        call_service(service, case, family, body, "foreign-media-catalog")
    assert snapshot(service) == before


@pytest.mark.parametrize("family", ("update_project_reference", "archive_project_reference",
                                    "recover_project_reference", "set_primary_reference"))
def test_catalog_stale_version_refuses_atomically(service_case, family):
    service = service_case.service
    case, _, _, body = catalog_request(service, service_case.cases["existing"], family)
    before = snapshot(service)
    with pytest.raises(ConflictError):
        call_service(service, case, family, {**body, "expected_version": case.version + 1}, "stale")
    assert snapshot(service) == before


@pytest.mark.parametrize("family", CATALOG_FAMILIES)
def test_catalog_mutation_and_receipt_roll_back_together(service_case, monkeypatch, family):
    service = service_case.service
    case, _, _, body = catalog_request(service, service_case.cases["existing"], family)
    before = snapshot(service)[:2]
    record = service._command_record

    def fail(*args, **kwargs):
        raise RuntimeError("receipt serialization failed")

    monkeypatch.setattr(service, "_command_record", fail)
    with pytest.raises(RuntimeError, match="receipt serialization failed"):
        call_service(service, case, family, body, "atomic-catalog")
    assert snapshot(service)[:2] == before
    monkeypatch.setattr(service, "_command_record", record)
    assert call_service(service, case, family, body, "atomic-catalog")["receipt"]


def test_catalog_changes_after_accepted_move_preserve_pinned_film_head_history_and_cas(editing):
    accepted = editing.commit(editing.body([editing.move("music-bed", 1)]), "catalog-film-move")
    service = editing.service
    media = service.ingest(editing.project, b"catalog media after move", idempotency_key="catalog-media")
    case = SimpleNamespace(project=editing.project, timeline=editing.timeline,
                           media=media["data"]["object_id"], reference="uncreated-reference",
                           association="association", version=1, retry="unused")
    before = film_snapshot(service, case)
    assert before[2] == accepted["data"]["canonical_document"]
    for family in CATALOG_FAMILIES:
        prepared, _, _, body = catalog_request(service, case, family)
        call_service(service, prepared, family, body, family)
        assert film_snapshot(service, case) == before
    editing.assert_readback(accepted)
