"""Public authenticated metadata and browser door proof; run centrally only."""
from __future__ import annotations

import copy
import json
from urllib.parse import urlencode

import pytest
import test_timeline_verified_media as media_support
from astrid_runtime_client import ApiError, WorkspaceClient
from door_helpers import HOSTED, DoorWorld
from test_timeline_verified_media import selector, settle_media, snapshot

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.door import DoorConfig

settled_media_bytes = media_support.settled_media_bytes


@pytest.fixture
def world(tmp_path, settled_media_bytes):
    service, project, outputs = settle_media(tmp_path, settled_media_bytes)
    root = service.store.root
    service.close()
    credential_file = tmp_path / "astrid.json"
    config = DoorConfig(origin=HOSTED, port=0, credential_file=credential_file)
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support", door=config).start()
    world = DoorWorld(tmp_path, daemon, credential_file)
    world.provision()
    try:
        yield world, project, outputs
    finally:
        world.stop()


def test_public_verified_image_old_new_video_and_closed_query_without_writes(world, settled_media_bytes):
    world, project, outputs = world
    client = WorkspaceClient(world.daemon.endpoint, world.product_token)
    service = world.daemon.service
    foreign = service.create_project({"slug": "foreign", "name": "Foreign"})["id"]
    before = snapshot(service)
    selections = {}
    for name, output in outputs.items():
        selection = client.get_project_media_selection(project, selector(output))
        explicit = {key: selection[key] for key in ("asset", "generation_id", "variant_id")}
        explicit["asset"] = f"popup/{name} & original"
        selection = client.get_project_media_selection(project, explicit)
        selections[name] = copy.deepcopy(selection)
        verified = client.get_project_verified_media(project, selection)
        assert verified == {"selection": selection, "media_type": "image/png" if name == "image" else "video/mp4",
                            "size": len(settled_media_bytes[name]), "duration_seconds": 2.0, "width": 16, "height": 16}
        path = f"/api/runtime/v1/projects/{project}/media-selection/verified?{urlencode(selection)}"
        reply = world.call(path)
        assert reply.status == 200 and reply.json() == verified
        assert set(selection) == {"asset", "generation_id", "variant_id", "object_id", "catalog_digest"}
    assert selections["old"]["object_id"] != selections["new"]["object_id"]

    selected = selections["old"]
    query = urlencode(selected)
    for bad_query in (query + "&extra=x", query + "&asset=duplicate", query + "&bad",
                      query.replace("catalog_digest=", "missing="), "asset=%", "asset=%FF",
                      urlencode({**selected, "asset": ""})):
        status, _ = world.owner("GET", f"/v1/projects/{project}/media-selection/verified?{bad_query}")
        assert status == 400
    for changed, status in (({**selected, "object_id": selections["new"]["object_id"]}, 404),
                            ({**selected, "catalog_digest": "sha256:" + "0" * 64}, 409),
                            ({**selected, "object_id": "bad"}, 422),
                            ({**selected, "catalog_digest": "bad"}, 422)):
        with pytest.raises(ApiError) as caught:
            client.get_project_verified_media(project, changed)
        assert caught.value.status == status
    with pytest.raises(ApiError) as caught:
        client.get_project_verified_media(foreign, selected)
    assert caught.value.status == 404
    assert snapshot(service) == before

    service.update_managed_output_lifecycle(outputs["old"]["association_id"], {
        "operation": "pin", "expected_version": 1,
    }, idempotency_key="pin-between-public-reads")
    after_pin = snapshot(service)
    for read in (lambda: client.get_project_verified_media(project, selected),
                 lambda: client.get_project_media_selection(project, selector(outputs["old"]))):
        with pytest.raises(ApiError) as caught:
            read()
        assert caught.value.status == 409
    assert selected == selections["old"]
    assert snapshot(service) == after_pin


def test_verified_read_requires_credential_scope_and_door_origin(world):
    world, project, outputs = world
    service = world.daemon.service
    selection = service.get_project_media_selection(project, selector(outputs["image"]), authorize=lambda: None)
    readonly, _ = world.daemon.credentials.provision("metadata-reader", ["projects:read"])
    wrong_scope, _ = world.daemon.credentials.provision("metadata-writer", ["projects:write"])
    before = snapshot(service)
    assert WorkspaceClient(world.daemon.endpoint, readonly).get_project_verified_media(project, selection)["selection"] == selection
    for token in (None, "invalid", wrong_scope):
        with pytest.raises(ApiError) as caught:
            WorkspaceClient(world.daemon.endpoint, token).get_project_verified_media(project, selection)
        assert caught.value.status in {401, 403}
    path = f"/api/runtime/v1/projects/{project}/media-selection/verified?{urlencode(selection)}"
    for origin in (None, "https://evil.test"):
        reply = world.call(path, origin=origin)
        assert reply.status == 403 and reply.json()["error"] == "hosted_origin_required"
    assert world.call(path).status == 200
    assert world.call(path, headers={"Authorization": "Bearer browser"}).status == 403
    assert world.call(path, method="POST").status == 404
    assert snapshot(service) == before


@pytest.mark.parametrize("change", ["contradictory", "missing", "changed"])
def test_public_read_refuses_catalog_metadata_race_without_refresh(world, change):
    world, project, outputs = world
    client = WorkspaceClient(world.daemon.endpoint, world.product_token)
    selection = client.get_project_media_selection(project, selector(outputs["old"]))
    captured = copy.deepcopy(selection)
    service = world.daemon.service
    with service.store._mutex:
        # Negative race fixture: corrupt/change metadata only after successful settlement and selection.
        row = service.store.conn.execute("SELECT metadata_json FROM generations WHERE id=?", (selection["generation_id"],)).fetchone()
        metadata = json.loads(row[0])
        if change == "contradictory":
            metadata["params"]["size"] = 1
        elif change == "missing":
            del metadata["params"]["duration_seconds"]
        else:
            metadata["params"]["duration_seconds"] = 3
        service.store.conn.execute("UPDATE generations SET metadata_json=? WHERE id=?", (json.dumps(metadata), selection["generation_id"]))
    before = snapshot(service)
    with pytest.raises(ApiError) as caught:
        client.get_project_verified_media(project, selection)
    assert caught.value.status == (409 if change == "changed" else 422)
    assert selection == captured
    assert snapshot(service) == before
