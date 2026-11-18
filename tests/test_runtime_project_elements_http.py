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
import re
import uuid

import pytest

from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.server import pack_http_route
from runtime_protocol.timeline_commit_inputs import PROJECT_PACK_KIND, PROJECT_PACK_SCHEMA
from tests.door_helpers import HOSTED, start_door_world

TSX = "elements/reveal/component.tsx"
COMPILED = "elements/reveal/component.js"
SHA_RE = re.compile(r"[0-9a-f]{64}")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def compiled_bytes(tag: str) -> bytes:
    return f"export default function Reveal_{tag}() {{ return null; }}\n".encode()


def owner_id(service, project: str) -> str:
    return "project_" + hashlib.sha256(f"{service.realm['id']}:{project}:default".encode()).hexdigest()[:20]


def ingest_snapshot(service, project: str, compiled: bytes, *, path: str = COMPILED) -> dict:
    """The portable snapshot the Agent builds: the source file, the compiled file and a build receipt."""
    source = b"export default function Reveal() { return null; }\n"
    files = [
        {"path": TSX, "sha256": sha(source), "bytes_base64": b64(source)},
        {"path": path, "sha256": sha(compiled), "bytes_base64": b64(compiled)},
    ]
    data = json.dumps({"files": files, "build_receipt_base64": b64(b"receipt")},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    actual = service.ingest(project, data, media_type="application/json",
                            idempotency_key="snapshot-" + sha(data))["data"]
    return {name: actual[name] for name in ("object_id", "digest", "size", "media_type")}


def admission(service, project: str, descriptor_object: dict, compiled: bytes, *, revision: str = "1") -> dict:
    """One admitted effect as the Agent records it: identity, closure digest, snapshot, compiled file, metadata."""
    ref_id, kind = "reveal", "effect"
    revision_text = "sha256:" + revision * 64
    return {
        "id": ref_id, "kind": kind, "revision": revision_text, "snapshot_digest": "2" * 64,
        "snapshot_object": descriptor_object,
        "compiled": {"path": COMPILED, "sha256": sha(compiled)},
        "descriptor": {"packId": owner_id(service, project), "id": ref_id, "kind": kind,
                       "revision": revision_text, "label": "Reveal", "componentPath": TSX},
        "authoring": {"packRoot": "/work/packs/reveal", "descriptorPath": "/work/packs/reveal/descriptor.yaml",
                      "componentPath": "/work/packs/reveal/component.tsx", "status": "admitted"},
    }


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


def test_list_and_element_bytes_are_served_through_the_door(world, project):
    service = world.daemon.service
    compiled = compiled_bytes("a")
    publish(service, project, [admission(service, project, ingest_snapshot(service, project, compiled), compiled)],
            "pack-a")
    digest = sha(compiled)

    listed = world.call(list_path(project))
    assert listed.status == 200
    assert listed.headers["content-type"] == "application/json"
    assert listed.headers["cache-control"] == "no-store"
    body = listed.json()
    assert set(body) == {"version", "projectId", "realmId", "selectionDigest", "projects", "elements"}
    assert body["version"] == 1
    assert body["projectId"] == project
    assert body["realmId"] == service.realm["id"]
    assert SHA_RE.fullmatch(body["selectionDigest"])

    owner = owner_id(service, project)
    revision = "sha256:" + "1" * 64
    assert body["elements"] == [{
        "ref": {"packId": owner, "kind": "effect", "id": "reveal", "revision": revision},
        "digest": digest,
        "descriptor": {"packId": owner, "id": "reveal", "kind": "effect", "revision": revision,
                       "label": "Reveal", "componentPath": TSX},
        "authoring": {"packRoot": "/work/packs/reveal", "descriptorPath": "/work/packs/reveal/descriptor.yaml",
                      "componentPath": "/work/packs/reveal/component.tsx", "status": "admitted"},
        "url": element_path(project, digest),
    }]
    assert body["projects"] == [{
        "projectId": project, "packId": owner, "packRoot": "/work/packs/reveal", "status": "admitted",
        "initCommand": f"python3 -m astrid.core.element.cli project-pack init --realm {service.realm['id']} --project {project}",
        "admitCommand": f"python3 -m astrid.core.element.cli project-pack admit --realm {service.realm['id']} --project {project}",
        "inspectCommand": f"python3 -m astrid.core.element.cli project-pack inspect --realm {service.realm['id']} --project {project}",
    }]

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
                       [admission(service, project, ingest_snapshot(service, project, second), second, revision="2")],
                       "pack-second")

    listed = json.loads(world.call(list_path(project)).body)
    assert [item["digest"] for item in listed["elements"]] == [sha(second)]
    assert world.call(element_path(project, sha(first))).status == 404
    assert world.call(element_path(project, sha(second))).body == second


def test_admissions_without_compiled_bytes_are_not_listed(world, project):
    service = world.daemon.service
    legacy = admission(service, project, ingest_snapshot(service, project, compiled_bytes("legacy")),
                       compiled_bytes("legacy"))
    del legacy["compiled"], legacy["descriptor"], legacy["authoring"]
    publish(service, project, [legacy], "pack-legacy")
    listed = json.loads(world.call(list_path(project)).body)
    assert listed["elements"] == []
    assert listed["projects"] == []


def test_compiled_bytes_that_disagree_with_their_snapshot_fail_closed(world, project):
    service = world.daemon.service
    compiled = compiled_bytes("drift")
    drifted = admission(service, project, ingest_snapshot(service, project, compiled), compiled)
    drifted["compiled"] = {"path": COMPILED, "sha256": sha(b"not the bytes in the snapshot")}
    publish(service, project, [drifted], "pack-drift")

    assert world.call(list_path(project)).status == 409
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
