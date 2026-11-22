"""Project-pack element bundles served by the door from the Runtime's own CAS.

The Agent ingests a portable snapshot object per admission and names one
compiled file of it (`compiled`), with the element's `descriptor` and
`authoring`. The Runtime lists the current admissions and serves those bytes,
re-verified on every request: no restart after admit, no agent disk.
"""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import threading
import urllib.error
import urllib.request
import uuid

import pytest

from runtime_protocol import timeline_commit_inputs
from runtime_protocol.errors import ConflictError, NotFoundError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.util import canonical_json
from runtime_protocol.server import pack_http_route
from runtime_protocol.timeline_commit_inputs import PROJECT_PACK_KIND, PROJECT_PACK_SCHEMA
from tests.door_helpers import HOSTED, create_realm, start_door_world

TSX = "elements/reveal/component.tsx"
COMPILED = "compiled/" + TSX + ".mjs"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def compiled_bytes(tag: str) -> bytes:
    return f"export default function Reveal_{tag}() {{ return null; }}\n".encode()


def owner_id(service, project: str) -> str:
    return "project_" + hashlib.sha256(f"{service.realm['id']}:{project}:default".encode()).hexdigest()[:20]


def _fixture_resources(compiled: bytes, path: str = COMPILED) -> dict:
    return {"pack.yaml": b"id: fixture\n", "elements/reveal/element.yaml": b"id: reveal\n",
            TSX: b"export default function Reveal() { return null; }\n", path: compiled}


def _fixture_closure(compiled: bytes, path: str = COMPILED) -> str:
    files = [{"path": name, "sha256": sha(raw)} for name, raw in sorted(_fixture_resources(compiled, path).items())]
    # Agent _closure_digest, including ASCII escaping.
    return sha(json.dumps(files, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode())


def ingest_snapshot(service, project: str, compiled: bytes, *, path: str = COMPILED,
                    pack_id: str | None = None, revision: str = "1", ref_id: str = "reveal",
                    include_binding: bool = True) -> dict:
    """Vendor Agent's _portable_snapshot and _build_receipt output shapes."""
    ref = {"projectId": project, "packId": pack_id or owner_id(service, project),
           "id": ref_id, "kind": "effect", "revision": "sha256:" + revision * 64}
    selection = {"elements": [{"projectId": project, "descriptor": {key: ref[key] for key in ("packId", "id", "kind", "revision")}}]}
    selection_bytes = (json.dumps(selection, indent=2, sort_keys=True) + "\n").encode()
    receipt = {"schema": "astrid.element-build/v1", "selectionDigest": "sha256:" + sha(selection_bytes),
               "elements": [ref], "compiledBindings": [{**ref, "componentPath": TSX,
                                                          "compiled": {"path": path, "sha256": sha(compiled)}}]}
    if not include_binding:
        del receipt["compiledBindings"]
    receipt_bytes = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    files = _fixture_resources(compiled, path)
    value = {"files": [{"path": name, "sha256": sha(raw), "bytes_base64": b64(raw)}
                       for name, raw in sorted(files.items())], "build_receipt_base64": b64(receipt_bytes)}
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    actual = service.ingest(project, data, media_type="application/json",
                            idempotency_key="snapshot-" + sha(data))["data"]
    return {name: actual[name] for name in ("object_id", "digest", "size", "media_type")}


def admission(service, project: str, descriptor_object: dict, compiled: bytes, *, revision: str = "1") -> dict:
    """One admitted effect in the Agent's stored shape."""
    ref_id, kind = "reveal", "effect"
    revision_text = "sha256:" + revision * 64
    closure = _fixture_closure(compiled)
    return {
        "id": ref_id, "kind": kind, "revision": revision_text, "snapshot_digest": closure,
        "snapshot_object": descriptor_object,
        "compiled": {"path": COMPILED, "sha256": sha(compiled)},
        "descriptor": {"packId": owner_id(service, project), "id": ref_id, "kind": kind,
                       "revision": revision_text, "label": "Reveal", "description": "", "componentPath": f"external/{owner_id(service, project)}/{closure}/{TSX}",
                       "defaults": {}, "parameters": [],
                       "renderability": {"preview": "supported", "browserExport": "supported", "workerExport": "unknown"}},
        "authoring": {"packRoot": "/work/packs/reveal", "descriptorPath": "/work/packs/reveal/descriptor.yaml",
                      "componentPath": "/work/packs/reveal/component.tsx", "status": "admitted"},
    }


def legacy_admission(service, project: str) -> dict:
    """An admission recorded before compiled bytes existed: identity and snapshot only."""
    value = admission(service, project, ingest_snapshot(service, project, compiled_bytes("legacy")),
                      compiled_bytes("legacy"), revision="3")
    value["id"], value["kind"] = "wipe", "transition"
    del value["compiled"], value["descriptor"], value["authoring"]
    return value


def direct(world, path: str, token: str):
    """A request straight to the Runtime listener with a chosen bearer: (status, body bytes)."""
    request = urllib.request.Request(world.daemon.endpoint + path, method="GET")
    request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def pack_document(service, project: str, admissions: list[dict]) -> tuple[str, dict]:
    realm = service.realm["id"]
    owner = owner_id(service, project)
    document_id = "document:" + str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps([project, PROJECT_PACK_KIND, "default"])))
    content = {"schema": PROJECT_PACK_SCHEMA, "pack_id": owner, "source_binding_key": "project-packs",
               "relative_manifest": f"{realm}/{project}/packs/{owner}/pack.yaml", "admissions": admissions}
    return document_id, content


def publish(service, project: str, admissions: list[dict], key: str) -> dict:
    document_id, content = pack_document(service, project, admissions)
    return service.create_document(project, {"document_id": document_id, "kind": PROJECT_PACK_KIND,
                                             "content": content}, idempotency_key=key)["data"]


def replace_admissions(service, project: str, admissions: list[dict], key: str) -> None:
    row = service.store.conn.execute(
        "SELECT id, version, content_json FROM project_documents WHERE project_id=? AND kind=?",
        (project, PROJECT_PACK_KIND)).fetchone()
    content = json.loads(row["content_json"])
    content["admissions"] = admissions
    service.update_document(project, row["id"], {"expected_version": row["version"], "content": content},
                            idempotency_key=key)


FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "project-elements-list.json"
FIXTURE_PROJECT, FIXTURE_REALM, FIXTURE_PACK = "fixture-project", "fixture-realm", "project_0123456789abcdef0123"


def list_path(project: str) -> str:
    return f"/api/runtime/packs/project-elements?project={project}"


def element_path(project: str, digest: str) -> str:
    return f"/api/runtime/packs/project-elements/{project}/{digest}.js"


@pytest.fixture
def world(tmp_path):
    current = start_door_world(tmp_path)
    try:
        yield current
    finally:
        current.daemon.stop()


@pytest.fixture
def project(world):
    return world.daemon.service.create_project({"slug": "elements", "name": "Elements"})["id"]


@pytest.fixture
def service_project(tmp_path):
    root = tmp_path / "realm"
    create_realm(root)
    service = RuntimeService(root)
    try:
        yield service, service.create_project({"slug": "elements", "name": "Elements"})["id"]
    finally:
        service.close()


def test_list_and_element_bytes_are_served_through_the_door(world, project):
    service = world.daemon.service
    compiled = compiled_bytes("a")
    publish(service, project, [admission(service, project, ingest_snapshot(service, project, compiled), compiled),
                               legacy_admission(service, project)], "pack-a")
    digest = sha(compiled)

    listed = world.call(list_path(project))
    assert listed.status == 200
    assert listed.headers["content-type"] == "application/json"
    assert listed.headers["cache-control"] == "no-store"
    # The committed fixture is the list response with the install's identities named by placeholders; the editor's
    # parser test reads the same file.
    expected = json.loads(FIXTURE.read_text().replace(FIXTURE_PROJECT, project)
                          .replace(FIXTURE_REALM, service.realm["id"]).replace(FIXTURE_PACK, owner_id(service, project)))
    assert expected["elements"][0]["digest"] == digest
    expected["elements"][0]["descriptor"]["componentPath"] = f"external/{owner_id(service, project)}/{_fixture_closure(compiled)}/{TSX}"
    refs = [[element["ref"], element["digest"]] for element in expected["elements"]]
    expected["selectionDigest"] = sha(canonical_json({"projectId": project, "realmId": service.realm["id"], "refs": refs}).encode())
    assert listed.json() == expected

    served = world.call(element_path(project, digest))
    assert served.status == 200
    assert served.body == compiled
    assert served.headers["content-type"] == "text/javascript"
    assert served.headers["etag"] == f'"sha256:{digest}"'
    assert served.headers["cache-control"] == "no-store"

    partial = world.call(element_path(project, digest), headers={"Range": "bytes=0-6", "If-Range": f'"sha256:{digest}"'})
    assert partial.status == 206 and partial.body == compiled[:7]

    head = world.call(element_path(project, digest), "HEAD")
    assert head.status == 200 and head.body == b""
    assert head.headers["content-length"] == str(len(compiled))


def test_http_projection_authoring_commands_scope_named_collection(world, project):
    service = world.daemon.service
    default_bytes = compiled_bytes("default")
    named_bytes = compiled_bytes("named")
    publish(service, project, [admission(service, project,
        ingest_snapshot(service, project, default_bytes), default_bytes)], "commands-default")

    collection = "special_effects"
    named = admission(service, project, ingest_snapshot(service, project, named_bytes, pack_id=collection), named_bytes)
    named["descriptor"]["packId"] = collection
    named["descriptor"]["componentPath"] = f"external/{collection}/{named['snapshot_digest']}/{TSX}"
    document_id = "document:" + str(uuid.uuid5(
        uuid.NAMESPACE_URL, json.dumps([project, PROJECT_PACK_KIND, collection])))
    content = {"schema": PROJECT_PACK_SCHEMA, "pack_id": collection, "source_binding_key": "project-packs",
               "relative_manifest": f"{service.realm['id']}/{project}/packs/{collection}/pack.yaml",
               "admissions": [named]}
    service.create_document(project, {"document_id": document_id, "kind": PROJECT_PACK_KIND, "content": content},
                            idempotency_key="commands-named")

    response = world.call(list_path(project))
    assert response.status == 200
    projected = {item["packId"]: item for item in response.json()["projects"]}
    default = projected[owner_id(service, project)]
    expected_prefix = "python3 -m astrid.core.element.cli project-pack"
    for verb, key in (("init", "initCommand"), ("admit", "admitCommand"), ("inspect", "inspectCommand")):
        assert default[key] == f"{expected_prefix} {verb} --realm {service.realm['id']} --project {project}"
        assert projected[collection][key] == (
            f"{expected_prefix} {verb} --realm {service.realm['id']} --project {project} --collection {collection}")


def test_door_refuses_foreign_origins_and_non_exact_routes(world, project):
    service = world.daemon.service
    compiled = compiled_bytes("b")
    publish(service, project, [admission(service, project, ingest_snapshot(service, project, compiled), compiled)],
            "pack-b")
    digest = sha(compiled)

    assert world.call(list_path(project), origin="https://foreign.example").status == 403
    assert world.call(element_path(project, digest), origin="https://foreign.example").status == 403
    assert world.call(element_path(project, digest), "POST").status == 404
    for path in (
        "/api/runtime/packs/project-elements",
        f"/api/runtime/packs/project-elements?project={project}&extra=1",
        "/api/runtime/packs/project-elements?project=",
        f"/api/runtime/packs/project-elements/{project}/{digest.upper()}.js",
        f"/api/runtime/packs/project-elements/{project}/{digest}",
        f"/api/runtime/packs/project-elements/{project}/{digest}.js?x=1",
    ):
        assert world.call(path).status == 404, path


def test_list_reads_only_admission_metadata_without_cas_reads(service_project, monkeypatch):
    service, project = service_project
    compiled = compiled_bytes("a")
    publish(service, project, [admission(service, project, ingest_snapshot(service, project, compiled), compiled),
                               legacy_admission(service, project)], "pack-metadata")
    reads = []

    def unexpected_read(*args, **kwargs):
        reads.append((args, kwargs))
        raise AssertionError("listing must not read snapshot bytes")

    monkeypatch.setattr(timeline_commit_inputs, "read_pack_snapshot_object", unexpected_read)
    monkeypatch.setattr(timeline_commit_inputs, "read_pack_snapshot_bytes", unexpected_read)
    monkeypatch.setattr(service.cas, "open", unexpected_read)
    listed = service.project_pack_elements(project)
    assert reads == []
    expected = json.loads(FIXTURE.read_text().replace(FIXTURE_PROJECT, project)
                          .replace(FIXTURE_REALM, service.realm["id"]).replace(FIXTURE_PACK, owner_id(service, project)))
    expected["elements"][0]["descriptor"]["componentPath"] = f"external/{owner_id(service, project)}/{_fixture_closure(compiled)}/{TSX}"
    refs = [[element["ref"], element["digest"]] for element in expected["elements"]]
    expected["selectionDigest"] = sha(canonical_json({"projectId": project, "realmId": service.realm["id"], "refs": refs}).encode())
    assert canonical_json(listed) == canonical_json(expected)


@pytest.mark.parametrize("selected_first", [True, False])
def test_bytes_read_only_selected_snapshot_without_holding_store_mutex(service_project, monkeypatch, selected_first):
    service, project = service_project
    compiled = compiled_bytes("selected")
    snapshot = ingest_snapshot(service, project, compiled)
    selected = admission(service, project, snapshot, compiled)
    other_bytes = compiled_bytes("unrelated")
    other = admission(service, project, ingest_snapshot(service, project, other_bytes, ref_id="other"), other_bytes)
    other["id"] = other["descriptor"]["id"] = "other"
    # An unrelated corrupt compiled file must not prevent serving the selected one.
    other["compiled"]["sha256"] = "0" * 64
    publish(service, project, [selected, other] if selected_first else [other, selected], "pack-selected")
    reads, probes = [], []
    validate_snapshot = timeline_commit_inputs.validate_pack_snapshot_objects
    read_snapshot = timeline_commit_inputs.read_pack_snapshot_bytes
    decode = base64.b64decode
    encoded = b64(compiled)

    def probe(stage):
        """Record whether another thread can take the store mutex right now."""
        acquired = []

        def try_lock():
            held = service.store._mutex.acquire(blocking=False)
            acquired.append(held)
            if held:
                service.store._mutex.release()

        thread = threading.Thread(target=try_lock)
        thread.start()
        thread.join(timeout=2)
        probes.append((stage, acquired))

    def validate_under_mutex(connection, project_id, content):
        probe("validate")
        return validate_snapshot(connection, project_id, content)

    def read_without_mutex(cas, descriptor, **kwargs):
        reads.append(descriptor["object_id"])
        probe("read")
        return read_snapshot(cas, descriptor, **kwargs)

    def decode_without_mutex(data, *args, **kwargs):
        if data == encoded:
            probe("decode")
        return decode(data, *args, **kwargs)

    monkeypatch.setattr(timeline_commit_inputs, "validate_pack_snapshot_objects", validate_under_mutex)
    monkeypatch.setattr(timeline_commit_inputs, "read_pack_snapshot_bytes", read_without_mutex)
    monkeypatch.setattr(base64, "b64decode", decode_without_mutex)
    with pytest.raises(NotFoundError):
        service.open_project_pack_element(project, "3" * 64)
    assert reads == []
    metadata, stream = service.open_project_pack_element(project, sha(compiled))
    with stream:
        assert stream.read() == compiled
    assert metadata == {"digest": sha(compiled), "size": len(compiled), "media_type": "text/javascript"}
    assert reads == [snapshot["object_id"]]
    # Validation runs while the mutex is held (no other thread can take it);
    # the CAS read and the decode run after it is released.
    assert probes[-2:] == [("read", [True]), ("decode", [True])]
    assert probes and all(held == [False] for stage, held in probes if stage == "validate")
    with pytest.raises(ConflictError, match="compiled element bytes are missing or corrupt"):
        service.open_project_pack_element(project, other["compiled"]["sha256"])


def test_unknown_digest_and_other_projects_are_not_found(world, project):
    service = world.daemon.service
    compiled = compiled_bytes("c")
    publish(service, project, [admission(service, project, ingest_snapshot(service, project, compiled), compiled)],
            "pack-c")
    other = service.create_project({"slug": "other", "name": "Other"})["id"]

    assert world.call(element_path(project, "3" * 64)).status == 404
    assert world.call(element_path(other, sha(compiled))).status == 404
    assert json.loads(world.call(list_path(other)).body)["elements"] == []
    assert world.call(element_path(project, sha(compiled))).status == 200


def test_current_admissions_are_reread_on_every_request(world, project):
    service = world.daemon.service
    first = compiled_bytes("first")
    publish(service, project, [admission(service, project, ingest_snapshot(service, project, first), first)],
            "pack-first")
    assert json.loads(world.call(list_path(project)).body)["elements"][0]["digest"] == sha(first)

    second = compiled_bytes("second")
    replace_admissions(service, project,
                       [admission(service, project, ingest_snapshot(service, project, second, revision="2"), second, revision="2")],
                       "pack-second")

    listed = json.loads(world.call(list_path(project)).body)
    assert [item["digest"] for item in listed["elements"]] == [sha(second)]
    assert world.call(element_path(project, sha(first))).status == 404
    assert world.call(element_path(project, sha(second))).body == second


def test_admissions_without_compiled_bytes_are_reported_not_listed(world, project):
    service = world.daemon.service
    publish(service, project, [legacy_admission(service, project)], "pack-legacy")
    listed = json.loads(world.call(list_path(project)).body)
    assert listed["elements"] == []
    assert listed["projects"] == []
    assert listed["legacy"] == [{"packId": owner_id(service, project), "kind": "transition", "id": "wipe"}]


def test_list_has_an_empty_legacy_report_when_every_admission_is_current(world, project):
    assert json.loads(world.call(list_path(project)).body)["legacy"] == []


def test_project_elements_need_the_project_document_read_scope(world, project):
    service = world.daemon.service
    compiled = compiled_bytes("auth")
    publish(service, project, [admission(service, project, ingest_snapshot(service, project, compiled), compiled)],
            "pack-auth")
    digest = sha(compiled)
    # The broad pre-change scope no longer reads project elements; neither do write-only or unrelated scopes.
    for actor, scopes in (("objects-only", ["objects:read"]), ("writer-only", ["projects:write", "tasks:read"])):
        token, _ = world.daemon.credentials.provision(actor, scopes)
        for path in (list_path(project), element_path(project, digest)):
            status, body = direct(world, path, token)
            assert status == 401 and b"lacks required scope" in body, (path, status, body)
    token, _ = world.daemon.credentials.provision("reader", ["projects:read"])
    status, body = direct(world, list_path(project), token)
    assert status == 200 and json.loads(body)["elements"][0]["digest"] == digest
    status, body = direct(world, element_path(project, digest), token)
    assert status == 200 and body == compiled
    # Like the project document read, an unknown project is not found.
    assert direct(world, list_path("no-such-project"), token)[0] == 404


@pytest.mark.parametrize("damage", [
    "no-renderability", "renderability-other-value", "renderability-extra-key", "renderability-missing-key",
    "no-label", "empty-label", "no-description", "no-component-path", "defaults-list", "no-parameters",
    "parameter-not-object", "parameter-no-name",
])
def test_document_refuses_descriptors_the_editor_cannot_read(world, project, damage):
    service = world.daemon.service
    compiled = compiled_bytes("shape")
    value = admission(service, project, ingest_snapshot(service, project, compiled), compiled)
    descriptor = value["descriptor"]
    if damage == "no-renderability":
        del descriptor["renderability"]
    elif damage == "renderability-other-value":
        descriptor["renderability"]["preview"] = "maybe"
    elif damage == "renderability-extra-key":
        descriptor["renderability"]["extra"] = "supported"
    elif damage == "renderability-missing-key":
        del descriptor["renderability"]["workerExport"]
    elif damage == "no-label":
        del descriptor["label"]
    elif damage == "empty-label":
        descriptor["label"] = ""
    elif damage == "no-description":
        del descriptor["description"]
    elif damage == "no-component-path":
        del descriptor["componentPath"]
    elif damage == "defaults-list":
        descriptor["defaults"] = []
    elif damage == "no-parameters":
        del descriptor["parameters"]
    elif damage == "parameter-not-object":
        descriptor["parameters"] = ["size"]
    else:
        descriptor["parameters"] = [{"type": "number"}]
    with pytest.raises(RuntimeErrorBase):
        publish(service, project, [value], "pack-shape-" + damage)


def test_compiled_bytes_that_disagree_with_their_snapshot_fail_closed(world, project):
    service = world.daemon.service
    compiled = compiled_bytes("drift")
    drifted = admission(service, project, ingest_snapshot(service, project, compiled), compiled)
    drifted["compiled"] = {"path": COMPILED, "sha256": sha(b"not the bytes in the snapshot")}
    publish(service, project, [drifted], "pack-drift")

    listed = world.call(list_path(project))
    assert listed.status == 200
    assert listed.json()["elements"][0]["digest"] == drifted["compiled"]["sha256"]
    assert world.call(element_path(project, sha(b"not the bytes in the snapshot"))).status == 409


@pytest.mark.parametrize("damage", [
    "path-escape", "absolute-path", "extra-compiled-key", "short-digest", "no-snapshot",
    "descriptor-other-ref", "descriptor-no-pack", "authoring-missing-key", "authoring-empty-value",
])
def test_document_refuses_malformed_compiled_metadata(world, project, damage):
    service = world.daemon.service
    compiled = compiled_bytes("bad")
    value = admission(service, project, ingest_snapshot(service, project, compiled), compiled)
    if damage == "path-escape":
        value["compiled"]["path"] = "../component.js"
    elif damage == "absolute-path":
        value["compiled"]["path"] = "/elements/component.js"
    elif damage == "extra-compiled-key":
        value["compiled"]["media_type"] = "text/javascript"
    elif damage == "short-digest":
        value["compiled"]["sha256"] = "ab"
    elif damage == "no-snapshot":
        del value["snapshot_object"]
    elif damage == "descriptor-other-ref":
        value["descriptor"]["id"] = "other"
    elif damage == "descriptor-no-pack":
        del value["descriptor"]["packId"]
    elif damage == "authoring-missing-key":
        del value["authoring"]["componentPath"]
    else:
        value["authoring"]["status"] = ""
    with pytest.raises(RuntimeErrorBase):
        publish(service, project, [value], "pack-bad-" + damage)


def test_route_parser_accepts_only_the_exact_shapes():
    digest = "a" * 64
    assert pack_http_route("/api/runtime/packs/project-elements?project=proj_1") == ("project-elements", "proj_1")
    assert pack_http_route(f"/api/runtime/packs/project-elements/proj_1/{digest}.js") == (
        "project-element", "proj_1", digest)
    for target in (
        "/api/runtime/packs/project-elements",
        "/api/runtime/packs/project-elements/",
        "/api/runtime/packs/project-elements?project=",
        "/api/runtime/packs/project-elements?project=%2e%2e",
        f"/api/runtime/packs/project-elements/proj_1/{digest}",
        "/api/runtime/packs/project-elementsx?project=a",
        f"/api/runtime/packs/project-elements/proj_1/{digest[:-1]}G.js",
    ):
        assert pack_http_route(target) is None, target


@pytest.mark.parametrize("damage", ["document_id", "source_binding_key", "relative_manifest"])
def test_preview_excludes_noncanonical_pack_and_preserves_healthy_pack(service_project, damage):
    service, project = service_project
    good_bytes, bad_bytes = compiled_bytes("good"), compiled_bytes("bad")
    good = admission(service, project, ingest_snapshot(service, project, good_bytes), good_bytes)
    publish(service, project, [good], "canonical-good")
    bad = admission(service, project, ingest_snapshot(service, project, bad_bytes), bad_bytes, revision="4")
    bad["descriptor"]["packId"] = "other_pack"
    document_id, content = pack_document(service, project, [bad])
    content["pack_id"] = "other_pack"
    content["relative_manifest"] = f"{service.realm['id']}/{project}/packs/other_pack/pack.yaml"
    document_id = "document:" + str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps([project, PROJECT_PACK_KIND, "other_pack"])))
    if damage == "document_id":
        document_id = "document:" + str(uuid.uuid4())
    else:
        content[damage] = "wrong"
    service.create_document(project, {"document_id": document_id, "kind": PROJECT_PACK_KIND,
                                      "content": content}, idempotency_key="noncanonical")
    listed = service.project_pack_elements(project)
    assert [item["digest"] for item in listed["elements"]] == [sha(good_bytes)]
    with pytest.raises(NotFoundError):
        service.open_project_pack_element(project, sha(bad_bytes))
    assert service.open_project_pack_element(project, sha(good_bytes))[1].read() == good_bytes


def test_preview_isolates_wrong_descriptor_owner_in_same_pack(service_project):
    service, project = service_project
    good_bytes, bad_bytes = compiled_bytes("good"), compiled_bytes("wrong_owner")
    good = admission(service, project, ingest_snapshot(service, project, good_bytes), good_bytes)
    bad = admission(service, project, ingest_snapshot(service, project, bad_bytes), bad_bytes, revision="4")
    bad["descriptor"]["packId"] = "other_pack"
    publish(service, project, [bad, good, legacy_admission(service, project)], "mixed-owner")
    listed = service.project_pack_elements(project)
    assert [item["digest"] for item in listed["elements"]] == [sha(good_bytes)]
    assert listed["legacy"] == [{"packId": owner_id(service, project), "kind": "transition", "id": "wipe"}]
    with pytest.raises(NotFoundError):
        service.open_project_pack_element(project, sha(bad_bytes))
    assert service.open_project_pack_element(project, sha(good_bytes))[1].read() == good_bytes


def test_preview_excludes_default_owner_alias_and_ambiguous_refs(service_project):
    service, project = service_project
    good_bytes, duplicate_bytes, alias_bytes = (compiled_bytes(tag) for tag in ("healthy", "duplicate", "alias"))
    good = admission(service, project, ingest_snapshot(service, project, good_bytes, ref_id="healthy"), good_bytes)
    good["id"] = good["descriptor"]["id"] = "healthy"
    duplicate = admission(service, project, ingest_snapshot(service, project, duplicate_bytes), duplicate_bytes)
    publish(service, project, [duplicate, dict(duplicate), good], "duplicates")
    alias = admission(service, project, ingest_snapshot(service, project, alias_bytes), alias_bytes, revision="4")
    alias_id = "document:" + str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps([project, PROJECT_PACK_KIND, owner_id(service, project)])))
    _, content = pack_document(service, project, [alias])
    service.create_document(project, {"document_id": alias_id, "kind": PROJECT_PACK_KIND,
                                      "content": content}, idempotency_key="owner-alias")
    assert [item["digest"] for item in service.project_pack_elements(project)["elements"]] == [sha(good_bytes)]
    for data in (duplicate_bytes, alias_bytes):
        with pytest.raises(NotFoundError):
            service.open_project_pack_element(project, sha(data))
    assert service.open_project_pack_element(project, sha(good_bytes))[1].read() == good_bytes


def test_commit_pack_source_rejects_compiled_descriptor_owner_mismatch(service_project):
    service, project = service_project
    data = compiled_bytes("wrong_owner_commit")
    value = admission(service, project, ingest_snapshot(service, project, data), data)
    value["descriptor"]["packId"] = "other_pack"
    document_id, content = pack_document(service, project, [value])
    with pytest.raises(ConflictError, match="owner does not match"):
        timeline_commit_inputs._project_pack_source(service.store.conn, project, document_id, content)


def test_same_digest_wrong_compiled_member_is_refused(service_project):
    service, project = service_project
    selected = compiled_bytes("selected")
    wrong = selected  # Identical bytes cannot authorize the wrong member.
    component = "elements/reveal/component.tsx"
    other_component = "elements/other/component.tsx"
    selected_path = "compiled/" + component + ".mjs"
    wrong_path = "compiled/" + other_component + ".mjs"
    resources = {"pack.yaml": b"fixture manifest", component: b"selected source", other_component: b"other source",
                 selected_path: selected, wrong_path: wrong}
    closure = [{"path": path, "sha256": sha(raw)} for path, raw in sorted(resources.items())]
    closure_digest = sha(json.dumps(closure, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False).encode())
    ref = {"projectId": project, "packId": owner_id(service, project), "id": "reveal",
           "kind": "effect", "revision": "sha256:" + "1" * 64}
    binding = {**ref, "componentPath": component,
               "compiled": {"path": selected_path, "sha256": sha(selected)}}
    receipt = json.dumps({"schema": "astrid.element-build/v1", "selectionDigest": "sha256:" + "0" * 64,
                          "elements": [ref], "compiledBindings": [binding]}).encode()
    # Exact Agent _portable_snapshot serializer.
    envelope = {"files": [{"path": path, "sha256": sha(raw), "bytes_base64": b64(raw)}
                          for path, raw in sorted(resources.items())],
                "build_receipt_base64": b64(receipt)}
    data = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode()
    stored = service.ingest(project, data, media_type="application/json",
                            idempotency_key="wrong-member-" + sha(data))["data"]
    snapshot = {key: stored[key] for key in ("object_id", "digest", "size", "media_type")}
    value = admission(service, project, snapshot, wrong)
    value["snapshot_digest"] = closure_digest
    value["descriptor"]["componentPath"] = f"external/{ref['packId']}/{closure_digest}/{component}"
    value["compiled"] = {"path": selected_path, "sha256": sha(selected)}
    publish(service, project, [value], "right-member")
    assert service.open_project_pack_element(project, sha(selected))[1].read() == selected
    value["compiled"] = {"path": wrong_path, "sha256": sha(wrong)}
    replace_admissions(service, project, [value], "wrong-member")
    assert service.project_pack_elements(project)["elements"][0]["digest"] == sha(wrong)
    with pytest.raises(ConflictError, match="compiled element bytes are missing or corrupt"):
        service.open_project_pack_element(project, sha(wrong))
    value["compiled"] = {"path": selected_path, "sha256": sha(selected)}
    alias = json.loads(json.dumps(value))
    alias["id"] = alias["descriptor"]["id"] = "other"
    replace_admissions(service, project, [value, alias], "same-digest-alias")
    with pytest.raises(ConflictError, match="compiled element bytes are missing or corrupt"):
        service.open_project_pack_element(project, sha(selected))


def test_pre_release_receipt_refuses_with_recovery_reason(service_project):
    service, project = service_project
    compiled = compiled_bytes("old_receipt")
    snapshot = ingest_snapshot(service, project, compiled, include_binding=False)
    value = admission(service, project, snapshot, compiled)
    publish(service, project, [value], "old-receipt")
    with pytest.raises(ConflictError) as refused:
        service.open_project_pack_element(project, sha(compiled))
    assert str(refused.value) == ("This project element was admitted by a pre-release build. "
                                  "Change its component source, admit the element again, "
                                  "then place the new revision on the clip.")
    assert refused.value.details["reason"] == "project_element_binding_missing"
