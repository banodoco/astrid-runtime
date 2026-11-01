"""Cross-family Runtime-door checks for the timeline cutover boundary."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from http_helpers import Api
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.door import DoorConfig
from precut_realm_fixture import load_precut_realm_fixture
from tests.door_helpers import DoorWorld, HOSTED


def _snapshot(service):
    with service.store._mutex:
        database = tuple(service.store.conn.iterdump())
        cas = {str(path.relative_to(service.store.cas_root)): path.read_bytes()
               for path in service.store.cas_root.rglob("*") if path.is_file()}
        staging = {str(path.relative_to(service.store.staging_root)): path.read_bytes()
                   for path in service.store.staging_root.rglob("*") if path.is_file()}
    return database, cas, staging, service.store.conn.total_changes


@pytest.fixture
def realm(tmp_path):
    captured = load_precut_realm_fixture(tmp_path)
    credential_file = tmp_path / "astrid.json"
    daemon = RuntimeDaemon(
        captured.copy_roots[1], support_root=tmp_path / "support",
        door=DoorConfig(origin=HOSTED, port=0, credential_file=credential_file),
    ).start()
    world = DoorWorld(tmp_path, daemon, credential_file)
    world.provision()
    try:
        yield SimpleNamespace(
            daemon=daemon, world=world, captured=captured,
            project=captured.pins["project_id"], timeline=captured.pins["timeline_id"],
            shot="shot-1", reference=captured.pins["reference_id"],
        )
    finally:
        daemon.stop()


def _cases(case, project=None):
    project = project or case.project
    timeline = case.timeline
    return {
        "timeline": ("POST", f"/v1/projects/{project}/timeline-documents",
                      {"timeline_id": timeline, "config": {}, "registry": {}}),
        "shot": ("PATCH", f"/v1/projects/{project}/shots/{case.shot}",
                  {"expected_version": 1, "name": "changed"}),
        "reference": ("PATCH", f"/v1/projects/{project}/references/{case.reference}",
                       {"expected_version": 1, "name": "changed"}),
        "render": ("POST", "/v1/attempts/not-an-attempt/publish-timeline-render", {}),
        "document": ("POST", f"/v1/projects/{project}/documents",
                      {"document_id": f"timeline:{timeline}", "kind": "timeline.composition", "content": {}}),
    }


def _request_error(api, method, path, body, key):
    with pytest.raises(RuntimeError) as caught:
        if isinstance(body, bytes):
            api.request(method, path, raw=body, headers={"Content-Type": "application/json", "Idempotency-Key": key})
        else:
            api.request(method, path, body, headers={"Idempotency-Key": key})
    return caught.value.status, caught.value.detail


@pytest.mark.parametrize("family", ["timeline", "shot", "reference", "render", "document"])
def test_credentials_are_checked_before_retired_body(family, realm):
    case = realm
    daemon, project = case.daemon, case.project
    reader, _ = daemon.credentials.provision("door-reader", ["projects:read"])
    api = Api(daemon.endpoint, None)
    method, path, body = _cases(case)[family]
    before = _snapshot(daemon.service)
    for index, credential in enumerate((None, "not-a-credential", reader)):
        api.credential = credential
        status, detail = _request_error(api, method, path, body, f"unauthorized-{family}-{index}")
        assert status == 401
        assert detail["code"] == "unauthorized"
        assert "retired_route" not in json.dumps(detail)
        assert project not in json.dumps(detail)
        assert _snapshot(daemon.service) == before


@pytest.mark.parametrize("family", ["timeline", "shot", "reference", "document"])
def test_authenticated_foreign_owned_resources_are_refused_without_writes_or_disclosure(family, realm):
    case = realm
    daemon = case.daemon
    foreign = daemon.service.create_project({"slug": "foreign-door", "name": "Foreign"})["id"]
    # CredentialStore scopes authorize operations globally; they do not bind an
    # actor to a project. This test therefore proves authenticated refusal for
    # a foreign-owned resource, not project-scoped credential authorization.
    token, _ = daemon.credentials.provision(
        "authenticated-actor", ["projects:read", "projects:write", "objects:read", "objects:write"]
    )
    api = Api(daemon.endpoint, token)
    method, path, body = _cases(case, foreign)[family]
    before = _snapshot(daemon.service)
    status, detail = _request_error(api, method, path, body, f"foreign-{family}")
    # Project-catalog shot/reference writers are live (KEEP): a foreign-project
    # resource is refused as the same non-disclosing not_found a missing row gets.
    expected_status, expected_code = (
        (404, "not_found") if family in {"reference", "shot"} else (410, "retired_route")
    )
    assert status == expected_status
    assert detail["code"] == expected_code
    assert foreign not in json.dumps(detail)
    assert case.reference not in json.dumps(detail)
    assert _snapshot(daemon.service) == before


def test_actual_runtime_and_astrid_aliases_refuse_before_old_receipt_replay(realm, monkeypatch):
    case = realm
    service = case.daemon.service
    body = _cases(case)["document"][2]

    def replay_must_not_run(*args, **kwargs):
        pytest.fail("alias dispatch consulted the retired receipt replay")

    monkeypatch.setattr(service, "_command_replay", replay_must_not_run)
    before = _snapshot(service)
    for alias in ("runtime", "astrid"):
        reply = case.world.call(
            f"/api/{alias}/v1/projects/{case.project}/documents", "POST",
            body=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "Idempotency-Key": f"alias-{alias}"},
        )
        assert reply.status == 410, reply.body
        detail = reply.json()
        assert detail["code"] == "retired_route"
        assert case.project not in json.dumps(detail)
        assert _snapshot(service) == before


def test_decoder_rejection_and_unknown_door_routes_keep_distinct_main_behavior(realm):
    case = realm
    service = case.daemon.service
    api = Api(case.daemon.endpoint, case.daemon.token)
    method, path, body = _cases(case)["document"]
    before = _snapshot(service)
    status, detail = _request_error(
        api, method, path, b"[", "malformed-document",
    )
    assert status == 400
    assert detail["code"] == "protocol_error"
    assert _snapshot(service) == before

    for path in (
        "/api/runtime/v1/unknown",
        "/api/astrid/v1/projects/%2e%2e/documents",
    ):
        reply = case.world.call(path, "POST", body=json.dumps(body).encode(),
                                headers={"Content-Type": "application/json"})
        assert reply.status == 404
        assert reply.json() == {"error": "route_not_allowed"}
        assert _snapshot(service) == before


def test_ordinary_project_media_and_source_document_controls_still_succeed(realm):
    case = realm
    token, _ = case.daemon.credentials.provision(
        "ordinary-project", ["projects:read", "projects:write", "objects:read", "objects:write"]
    )
    api = Api(case.daemon.endpoint, token)
    document = api.request(
        "POST", f"/v1/projects/{case.project}/documents",
        {"document_id": "door-notes", "kind": "example.notes", "content": {"draft": True}},
        headers={"Idempotency-Key": "door-notes-create"},
    )
    updated = api.request(
        "PATCH", f"/v1/projects/{case.project}/documents/door-notes",
        {"expected_version": document["data"]["version"], "content": {"draft": False}},
        headers={"Idempotency-Key": "door-notes-update"},
    )
    assert updated["data"]["content"] == {"draft": False}
    assert api.ingest(case.project, b"ordinary-door-media", idempotency_key="door-media")["data"]["object_id"]
    project = api.request(
        "PATCH", f"/v1/projects/{case.project}",
        {"expected_version": 1, "name": "Door metadata"},
        headers={"Idempotency-Key": "door-project-update"},
    )
    assert project["name"] == "Door metadata"
