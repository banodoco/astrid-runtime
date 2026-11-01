"""Public exact-pin read of retained project-pack objects (selected-pack PARAM declarations).

The read reuses the commit port's retained binding, closure and CAS custody checks,
so a V1 declaration survives a live V2, Document removal and restart without writes.
"""
from __future__ import annotations

import base64
import copy
import json
from urllib.parse import urlencode

import pytest
import test_timeline_commit_port as support
from astrid_runtime_client import ApiError, WorkspaceClient
from door_helpers import HOSTED, DoorWorld
from test_timeline_pack_inputs import (
    commit,
    create_pack,
    install_object_provider,
    pin,
    portable_object,
    snapshot,
    source_request,
)

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.door import DoorConfig
from runtime_protocol.errors import AuthorizationError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService

service = support.service


def declaration(maximum):
    return json.dumps({"params": {"count": {"min": 1, "max": maximum}}}, sort_keys=True, separators=(",", ":")).encode()


def read(runtime, source_pin, object_id, *, project=None, authorize=lambda: None):
    return runtime.get_project_verified_document_object(project or runtime.test_project, source_pin, object_id,
                                                        authorize=authorize)


def decoded(value):
    return json.loads(base64.b64decode(value["bytes_base64"]))


def accepts(value, element):
    return 1 <= element <= decoded(value)["params"]["count"]["max"]


def retained_v1(service):
    """V1 pack with a portable max-10 declaration, captured by an accepted commit."""
    descriptor, data = portable_object(service, data=declaration(10))
    source = create_pack(service, snapshot_object=descriptor)
    source_pin = pin(source)
    install_object_provider(service, source_pin, descriptor["object_id"])
    commit(service, source_request(service, source_pin))
    return source, source_pin, descriptor, data


def publish_v2(service, source, maximum=20):
    newer, _ = portable_object(service, data=declaration(maximum), key="portable-v2")
    content = copy.deepcopy(source["content"])
    content["admissions"] = [{**content["admissions"][0], "revision": "sha256:" + "3" * 64,
                              "snapshot_digest": "4" * 64, "snapshot_object": newer}]
    service.update_document(service.test_project, source["document_id"],
                            {"expected_version": 1, "content": content}, idempotency_key="v2")
    return newer


def test_v1_declaration_is_read_live_and_survives_v2_removal_and_restart(service):
    source, source_pin, descriptor, data = retained_v1(service)
    expected = {**descriptor, "bytes_base64": base64.b64encode(data).decode("ascii")}
    before = snapshot(service)
    assert read(service, source_pin, descriptor["object_id"]) == expected
    assert snapshot(service) == before

    newer = publish_v2(service, source)
    service.store.conn.execute("DELETE FROM project_documents WHERE id=?", (source["document_id"],))
    project, root = service.test_project, service.store.root
    service.close()
    restarted = RuntimeService(root)
    try:
        restarted.test_project = project
        before = snapshot(restarted)
        value = read(restarted, source_pin, descriptor["object_id"])
        assert value == expected
        assert accepts(value, 4) and accepts(value, 8) and not accepts(value, 16)
        # V2's object belongs to V2's pin, never to the retained V1 pin.
        with pytest.raises(RuntimeErrorBase):
            read(restarted, source_pin, newer["object_id"])
        assert snapshot(restarted) == before
    finally:
        restarted.close()


def test_v2_declaration_is_a_distinct_exact_pin(service):
    source, source_pin, descriptor, _ = retained_v1(service)
    newer = publish_v2(service, source)
    current = service.get_document(service.test_project, source["document_id"])
    value = read(service, pin(current), newer["object_id"])
    assert accepts(value, 16) and not accepts(value, 21)
    with pytest.raises(RuntimeErrorBase):
        read(service, pin(current), descriptor["object_id"])


@pytest.mark.parametrize("damage", ["stale-live", "wrong-digest", "foreign-project", "unreachable", "wrong-object",
                                    "not-a-pack", "bad-pin", "bad-object-id"])
def test_pin_scope_and_object_refusals_without_writes(service, damage):
    descriptor, _ = portable_object(service, data=declaration(10))
    source = create_pack(service, snapshot_object=descriptor)
    source_pin = pin(source)
    object_id = descriptor["object_id"]
    project = None
    if damage == "stale-live":
        publish_v2(service, source)
    elif damage == "wrong-digest":
        source_pin = {**source_pin, "content_digest": "sha256:" + "0" * 64}
    elif damage == "foreign-project":
        project = service.create_project({"slug": "foreign", "name": "Foreign"})["id"]
    elif damage == "unreachable":
        install_object_provider(service, source_pin, object_id)
        commit(service, source_request(service, source_pin))
        service.store.conn.execute("DELETE FROM timeline_document_input_links")
    elif damage == "wrong-object":
        object_id = "sha256:" + "0" * 64
    elif damage == "not-a-pack":
        config = service.create_document(service.test_project, {"document_id": "config-1", "kind": "demo.config",
                                                                  "content": {"a": 1}}, idempotency_key="config")["data"]
        source_pin = pin(config)
    elif damage == "bad-pin":
        source_pin = {**source_pin, "version": 0}
    else:
        object_id = "../../outside"
    before = snapshot(service)
    with pytest.raises(RuntimeErrorBase):
        read(service, source_pin, object_id, project=project)
    assert snapshot(service) == before


def test_read_authorization_runs_before_any_read(service):
    _, source_pin, descriptor, _ = retained_v1(service)
    calls = []

    def revoked():
        calls.append(1)
        raise AuthorizationError("authority revoked")
    before = snapshot(service)
    with pytest.raises(AuthorizationError):
        read(service, source_pin, descriptor["object_id"], authorize=revoked)
    assert calls and snapshot(service) == before


@pytest.mark.parametrize("damage", ["association", "metadata", "missing-blob", "corrupt-blob"])
def test_retained_object_custody_damage_is_refused(service, damage):
    _, source_pin, descriptor, data = retained_v1(service)
    raw_hash = descriptor["object_id"].removeprefix("sha256:")
    if damage == "association":
        service.store.conn.execute("DELETE FROM project_objects WHERE digest=?", (raw_hash,))
    elif damage == "metadata":
        service.store.conn.execute("UPDATE objects SET size=size+1 WHERE digest=?", (raw_hash,))
    elif damage == "missing-blob":
        service.cas.path_for(raw_hash).unlink()
    else:
        service.cas.path_for(raw_hash).write_bytes(b"x" * len(data))
    before = snapshot(service)
    with pytest.raises(RuntimeErrorBase):
        read(service, source_pin, descriptor["object_id"])
    assert snapshot(service) == before


@pytest.fixture
def world(service, tmp_path):
    source, source_pin, descriptor, data = retained_v1(service)
    publish_v2(service, source)
    service.store.conn.execute("DELETE FROM project_documents WHERE id=?", (source["document_id"],))
    project, root = service.test_project, service.store.root
    service.close()
    config = DoorConfig(origin=HOSTED, port=0, credential_file=tmp_path / "astrid.json")
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support", door=config).start()
    world = DoorWorld(tmp_path, daemon, tmp_path / "astrid.json")
    world.provision()
    try:
        yield world, project, source_pin, descriptor, data
    finally:
        world.stop()


def test_public_read_returns_retained_v1_after_v2_removal_and_restart(world):
    world, project, source_pin, descriptor, data = world
    client = WorkspaceClient(world.daemon.endpoint, world.product_token)
    runtime = world.daemon.service
    foreign = runtime.create_project({"slug": "foreign", "name": "Foreign"})["id"]
    before = snapshot(runtime)
    expected = {**descriptor, "bytes_base64": base64.b64encode(data).decode("ascii")}
    value = client.get_project_verified_document_object(project, source_pin, descriptor["object_id"])
    assert value == expected
    assert accepts(value, 4) and accepts(value, 8) and not accepts(value, 16)
    query = urlencode({**source_pin, "object_id": descriptor["object_id"]})
    reply = world.call(f"/api/runtime/v1/projects/{project}/document-objects/verified?{query}")
    assert reply.status == 200 and reply.json() == expected

    for bad_query in (query + "&extra=x", query + "&version=2", query.replace("object_id=", "missing="), "document_id=%",
                      urlencode({**source_pin, "object_id": ""}), urlencode({**source_pin, "version": "0",
                                                                             "object_id": descriptor["object_id"]})):
        status, _ = world.owner("GET", f"/v1/projects/{project}/document-objects/verified?{bad_query}")
        assert status == 400
    for bad_pin, bad_object, status in (({**source_pin, "content_digest": "bad"}, descriptor["object_id"], 422),
                                        (source_pin, "bad", 422)):
        with pytest.raises(ApiError) as caught:
            client.get_project_verified_document_object(project, bad_pin, bad_object)
        assert caught.value.status == status
    with pytest.raises(ApiError) as caught:
        client.get_project_verified_document_object(project, source_pin, "sha256:" + "0" * 64)
    assert caught.value.status == 409
    with pytest.raises(ApiError) as caught:
        client.get_project_verified_document_object(foreign, source_pin, descriptor["object_id"])
    assert caught.value.status == 404
    assert snapshot(runtime) == before
