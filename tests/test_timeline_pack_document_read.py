"""Public exact-pin read of the retained config/pack Document, beside the object read.

Native selected-PARAM capture needs the VerifiedDocument (exact V1 declaration) and
the selected object map. The flow test commits through the real port: capture both,
then accept or refuse a value against the retained V1 max, after V2, Document
removal and restart, with no canonical write on refusal.
"""
from __future__ import annotations

import base64
import json
from urllib.parse import urlencode

import pytest
import test_timeline_commit_port as support
from astrid_runtime_client import ApiError, WorkspaceClient
from door_helpers import HOSTED, DoorWorld
from test_timeline_commit_port import PreparedProvider, commit, prepared, request
from test_timeline_pack_inputs import create_pack, pin, portable_object, snapshot
from test_timeline_pack_param_retained_read import declaration, publish_v2, retained_v1

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.door import DoorConfig
from runtime_protocol.errors import AuthorizationError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_port import digest, refused

service = support.service


def read(runtime, source_pin, *, project=None, authorize=lambda: None):
    return runtime.get_project_verified_document(project or runtime.test_project, source_pin, authorize=authorize)


def install_param_provider(service, history_pin=None, seen=None):
    """The Agent's side of selected-PARAM capture: VerifiedDocument, then the selected object.

    A pin the request does not declare is only readable through accepted history.
    """
    def action(context, port):
        candidate = prepared(context, port)
        args = context["request"]["commands"][0]["args"]
        source_pin, value = args.get("source", history_pin), args["value"]
        verified = port.config_source(source_pin)
        selected = verified["document"]["content"]["admissions"][0]["snapshot_object"]
        declared = json.loads(base64.b64decode(port.document_object(verified["pin"], selected["object_id"])["bytes_base64"]))
        maximum = declared["params"]["count"]["max"]
        if seen is not None:
            seen.append((verified["pin"], maximum))
        if not 1 <= value <= maximum:
            raise refused("param_out_of_range", f"count {value} is outside the declared range")
        candidate["canonical_document"]["dependency_manifest"]["documents"] = [source_pin]
        candidate["records"]["commands"][0]["dependencies"] = [
            {"key": "selected-pack", "kind": "source", "pin": source_pin, "policy": "exact"},
        ]
        candidate["document_digest"] = digest(candidate["canonical_document"])
        return port.accept(candidate)
    provider = PreparedProvider(action)
    service.test_provider.__dict__.update(provider.__dict__)
    return service.test_provider


def try_value(service, source_pin, value, key, *, declare=False):
    before = snapshot(service)
    body = request(service)
    body["commands"][0].update(op="fixture.pack-param",
                               args={"source": source_pin, "value": value} if declare else {"value": value})
    try:
        commit(service, body, key=key)
    except RuntimeErrorBase:
        assert snapshot(service) == before
        return False
    assert snapshot(service) != before
    return True


def test_native_capture_commits_against_retained_v1_after_v2_removal_and_restart(service):
    source, source_pin, descriptor, data = retained_v1(service)
    install_param_provider(service, source_pin)
    assert try_value(service, source_pin, 8, "live-8", declare=True)
    assert not try_value(service, source_pin, 16, "live-16", declare=True)

    # V2 (max 20) is live now; the head still depends on V1, so V1's declaration decides.
    newer = publish_v2(service, source)
    seen = []
    install_param_provider(service, source_pin, seen)
    assert try_value(service, source_pin, 8, "v1-8") and not try_value(service, source_pin, 16, "v1-16")
    assert seen == [(source_pin, 10)] * 2

    service.store.conn.execute("DELETE FROM project_documents WHERE id=?", (source["document_id"],))
    assert try_value(service, source_pin, 8, "removed-8") and not try_value(service, source_pin, 16, "removed-16")

    project, root = service.test_project, service.store.root
    service.close()
    restarted = RuntimeService(root)
    try:
        restarted.test_project = project
        restarted.test_provider = PreparedProvider()
        restarted.register_timeline_commit_provider(restarted.test_provider)
        install_param_provider(restarted, source_pin)
        assert try_value(restarted, source_pin, 8, "restart-8") and not try_value(restarted, source_pin, 16, "restart-16")
        assert read(restarted, source_pin)["pin"] == source_pin
        assert newer["object_id"] != descriptor["object_id"]
    finally:
        restarted.close()


def test_public_read_equals_the_commit_port_capture_and_survives_v2_removal_and_restart(service):
    seen = []
    source, source_pin, descriptor, _ = retained_v1(service)
    before = snapshot(service)
    expected = {"pin": source_pin, "document": source}
    assert read(service, source_pin) == expected
    assert snapshot(service) == before

    publish_v2(service, source)
    service.store.conn.execute("DELETE FROM project_documents WHERE id=?", (source["document_id"],))
    project, root = service.test_project, service.store.root
    service.close()
    restarted = RuntimeService(root)
    try:
        restarted.test_project = project
        before = snapshot(restarted)
        value = read(restarted, source_pin)
        assert value == expected
        assert value["document"]["content"]["admissions"][0]["snapshot_object"] == descriptor
        assert snapshot(restarted) == before
        # The port's own capture of the same pin is byte-identical.
        restarted.test_provider = PreparedProvider()
        restarted.register_timeline_commit_provider(restarted.test_provider)
        install_param_provider(restarted, source_pin, seen)
        assert try_value(restarted, source_pin, 4, "port")
        assert seen == [(source_pin, 10)]
    finally:
        restarted.close()


def test_config_document_pin_is_read_from_the_retained_binding(service):
    config = service.create_document(service.test_project, {"document_id": "config-1", "kind": "demo.config",
                                                            "content": {"a": 1}}, idempotency_key="config")["data"]
    config_pin = pin(config)
    seen = []

    def action(context, port):
        candidate = prepared(context, port)
        seen.append(port.config_source(config_pin))
        candidate["canonical_document"]["dependency_manifest"]["documents"] = [config_pin]
        candidate["records"]["commands"][0]["dependencies"] = [
            {"key": "config", "kind": "source", "pin": config_pin, "policy": "exact"}]
        candidate["document_digest"] = digest(candidate["canonical_document"])
        return port.accept(candidate)
    service.test_provider.__dict__.update(PreparedProvider(action).__dict__)
    body = request(service)
    body["commands"][0].update(op="fixture.config-input", args={"source": config_pin})
    commit(service, body)
    service.update_document(service.test_project, "config-1", {"expected_version": 1, "content": {"a": 2}},
                            idempotency_key="config-v2")
    service.store.conn.execute("DELETE FROM project_documents WHERE id='config-1'")
    assert read(service, config_pin) == seen[0] == {"pin": config_pin, "document": config}


@pytest.mark.parametrize("damage", ["stale-live", "wrong-digest", "foreign-project", "unreachable", "unknown-document",
                                    "bad-pin", "wrong-kind", "tampered-content", "removed-without-binding"])
def test_pin_scope_and_custody_refusals_without_writes(service, damage):
    source, source_pin, _, _ = retained_v1(service)
    project = None
    if damage == "stale-live":
        # A V2 pin that was never accepted is only readable while it is the live version.
        publish_v2(service, source)
        source_pin = {**source_pin, "version": 2}
    elif damage == "wrong-digest":
        source_pin = {**source_pin, "content_digest": "sha256:" + "0" * 64}
    elif damage == "foreign-project":
        project = service.create_project({"slug": "foreign", "name": "Foreign"})["id"]
    elif damage == "unreachable":
        service.store.conn.execute("DELETE FROM timeline_document_input_links")
        service.store.conn.execute("DELETE FROM project_documents WHERE id=?", (source["document_id"],))
    elif damage == "unknown-document":
        source_pin = {**source_pin, "document_id": "document:missing"}
    elif damage == "bad-pin":
        source_pin = {**source_pin, "version": 0}
    elif damage == "wrong-kind":
        note = service.create_document(service.test_project, {"document_id": "note-1", "kind": "demo.note",
                                                                "content": {"a": 1}}, idempotency_key="note")["data"]
        source_pin = pin(note)
    elif damage == "tampered-content":
        publish_v2(service, source)
        service.store.conn.execute("UPDATE timeline_document_input_contents SET content_json='{}' WHERE content_digest=?",
                                   (source_pin["content_digest"],))
    else:
        service.store.conn.execute("DELETE FROM timeline_document_input_links")
        service.store.conn.execute("DELETE FROM timeline_document_input_bindings")
        service.store.conn.execute("DELETE FROM project_documents WHERE id=?", (source["document_id"],))
    before = snapshot(service)
    with pytest.raises(RuntimeErrorBase):
        read(service, source_pin, project=project)
    assert snapshot(service) == before


def test_read_authorization_runs_before_any_read(service):
    _, source_pin, _, _ = retained_v1(service)
    calls = []

    def revoked():
        calls.append(1)
        raise AuthorizationError("authority revoked")
    before = snapshot(service)
    with pytest.raises(AuthorizationError):
        read(service, source_pin, authorize=revoked)
    assert calls and snapshot(service) == before


@pytest.fixture
def world(service, tmp_path):
    source, source_pin, descriptor, _ = retained_v1(service)
    publish_v2(service, source)
    service.store.conn.execute("DELETE FROM project_documents WHERE id=?", (source["document_id"],))
    project, root = service.test_project, service.store.root
    service.close()
    config = DoorConfig(origin=HOSTED, port=0, credential_file=tmp_path / "astrid.json")
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support", door=config).start()
    world = DoorWorld(tmp_path, daemon, tmp_path / "astrid.json")
    world.provision()
    try:
        yield world, project, source, source_pin, descriptor
    finally:
        world.stop()


def test_public_read_returns_retained_v1_document_after_v2_removal_and_restart(world):
    world, project, source, source_pin, descriptor = world
    client = WorkspaceClient(world.daemon.endpoint, world.product_token)
    runtime = world.daemon.service
    foreign = runtime.create_project({"slug": "foreign", "name": "Foreign"})["id"]
    before = snapshot(runtime)
    expected = {"pin": source_pin, "document": source}
    value = client.get_project_verified_document(project, source_pin)
    assert value == expected
    # Exact V1 declaration and the selected object map, both from the public reads.
    selected = value["document"]["content"]["admissions"][0]["snapshot_object"]
    declared = client.get_project_verified_document_object(project, value["pin"], selected["object_id"])
    assert declared["object_id"] == descriptor["object_id"]
    assert json.loads(base64.b64decode(declared["bytes_base64"])) == json.loads(declaration(10))
    query = urlencode(source_pin)
    reply = world.call(f"/api/runtime/v1/projects/{project}/document-inputs/verified?{query}")
    assert reply.status == 200 and reply.json() == expected

    for bad_query in (query + "&extra=x", query + "&version=2", query.replace("version=", "missing="), "document_id=%",
                      query + "&object_id=" + descriptor["object_id"],
                      urlencode({**source_pin, "version": "0"}), urlencode({**source_pin, "content_digest": ""})):
        status, _ = world.owner("GET", f"/v1/projects/{project}/document-inputs/verified?{bad_query}")
        assert status == 400
    with pytest.raises(ApiError) as caught:
        client.get_project_verified_document(project, {**source_pin, "content_digest": "bad"})
    assert caught.value.status == 422
    with pytest.raises(ApiError) as caught:
        client.get_project_verified_document(project, {**source_pin, "content_digest": "sha256:" + "0" * 64})
    assert caught.value.status in (404, 409)
    with pytest.raises(ApiError) as caught:
        client.get_project_verified_document(foreign, source_pin)
    assert caught.value.status == 404
    assert snapshot(runtime) == before
