"""Exact project-pack Documents at the Runtime host boundary.

The portable CAS tests prove byte custody independently of Agent's declaration
validation. The older real-admission tests qualify only the Document boundary.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_timeline_commit_port as support
from test_timeline_commit_port import PreparedProvider, commit, prepared, request

from runtime_protocol.errors import NotFoundError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_inputs import (
    PROJECT_PACK_KIND,
    PROJECT_PACK_SCHEMA,
    capture_document_input,
)
from runtime_protocol.timeline_commit_port import digest

service = support.service


def pin(document):
    return {"document_id": document["document_id"], "version": document["version"],
            "content_digest": digest(document["content"])}


def create_pack(service, *, collection="default", snapshot_object=None, **changes):
    project = service.test_project
    realm = service.realm["id"]
    owner = "project_" + hashlib.sha256(f"{realm}:{project}:default".encode()).hexdigest()[:20]
    if collection != "default":
        owner = collection
    content = {"schema": PROJECT_PACK_SCHEMA, "pack_id": owner, "source_binding_key": "project-packs",
               "relative_manifest": f"{realm}/{project}/packs/{owner}/pack.yaml",
               "admissions": [{"id": "reveal", "kind": "effect", "revision": "sha256:" + "1" * 64,
                               "snapshot_digest": "2" * 64}]}
    if snapshot_object is not None:
        content["admissions"][0]["snapshot_object"] = snapshot_object
    document_id = "document:" + str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps([project, PROJECT_PACK_KIND, collection])))
    body = {"document_id": document_id, "kind": PROJECT_PACK_KIND, "content": content}
    body.update(changes)
    return service.create_document(project, body, idempotency_key="pack-" + collection)["data"]


def install_source_provider(service, source_pin, *, before_accept=None, seen=None):
    def action(context, port):
        candidate = prepared(context, port)
        value = port.config_source(source_pin)
        if seen is not None:
            seen.append(value)
        candidate["canonical_document"]["dependency_manifest"]["documents"] = [source_pin]
        candidate["records"]["commands"][0]["dependencies"] = [
            {"key": "selected-pack", "kind": "source", "pin": source_pin, "policy": "exact"},
        ]
        candidate["document_digest"] = digest(candidate["canonical_document"])
        if before_accept:
            before_accept(value, candidate)
        return port.accept(candidate)
    provider = PreparedProvider(action)
    if hasattr(service, "test_provider"):
        service.test_provider.__dict__.update(provider.__dict__)
        provider = service.test_provider
    else:
        service.register_timeline_commit_provider(provider)
        service.test_provider = provider
    return provider


def source_request(service, source_pin, *, declare=True):
    body = request(service)
    body["commands"][0].update(op="fixture.pack-input", args={"source": source_pin} if declare else {})
    return body


def snapshot(service):
    return tuple(service.store.conn.iterdump())


@pytest.mark.parametrize("collection", ["default", "special_effects"])
def test_exact_pack_inventory_retained_after_update_restart_and_retry(service, collection):
    source = create_pack(service, collection=collection)
    source_pin = pin(source)
    seen = []
    install_source_provider(service, source_pin, seen=seen)
    body = source_request(service, source_pin)
    accepted = commit(service, body)
    assert seen == [{"pin": source_pin, "document": source}]
    assert seen[0]["document"]["kind"] == PROJECT_PACK_KIND
    original_bytes = service.store.conn.execute(
        "SELECT content_json FROM timeline_document_input_contents WHERE content_digest=?",
        (source_pin["content_digest"],),
    ).fetchone()[0]
    changed = copy.deepcopy(source["content"])
    changed["admissions"].append({**changed["admissions"][0], "revision": "sha256:" + "3" * 64,
                                  "snapshot_digest": "4" * 64})
    updated = service.update_document(service.test_project, source["document_id"],
                                      {"expected_version": 1, "content": changed}, idempotency_key="pack-v2")["data"]
    assert updated["version"] == 2
    project, root = service.test_project, service.store.root
    service.close()
    restarted = RuntimeService(root)
    try:
        restarted.test_project = project
        provider = install_source_provider(restarted, source_pin, seen=seen)
        before = snapshot(restarted)
        assert commit(restarted, body) == accepted
        assert snapshot(restarted) == before
        assert provider.calls == 0  # Ledger retry needs no provider/source reads.
        next_body = source_request(restarted, source_pin, declare=False)
        commit(restarted, next_body, key="historical-input")
        assert seen == [{"pin": source_pin, "document": source}] * 2
        assert restarted.get_document(project, source["document_id"]) == updated
        assert restarted.store.conn.execute(
            "SELECT content_json FROM timeline_document_input_contents WHERE content_digest=?",
            (source_pin["content_digest"],),
        ).fetchone()[0] == original_bytes
    finally:
        restarted.close()


@pytest.mark.parametrize("damage", ["kind", "schema", "binding", "owner", "project", "id", "revision", "digest", "duplicate"])
def test_invalid_pack_identity_refuses_without_writes(service, damage):
    source = create_pack(service)
    content = copy.deepcopy(source["content"])
    if damage == "kind":
        service.store.conn.execute("UPDATE project_documents SET kind=? WHERE id=?", (PROJECT_PACK_SCHEMA, source["document_id"]))
    elif damage in {"schema", "binding", "owner", "project"}:
        field = {"schema": "schema", "binding": "source_binding_key", "owner": "pack_id", "project": "relative_manifest"}[damage]
        content[field] = "wrong"
    elif damage == "id":
        content["admissions"][0]["id"] = ""
    elif damage == "revision":
        content["admissions"][0]["revision"] = "not-a-revision"
    elif damage == "digest":
        content["admissions"][0]["snapshot_digest"] = "not-a-digest"
    else:
        content["admissions"].append(copy.deepcopy(content["admissions"][0]))
    if damage != "kind":
        source = service.update_document(service.test_project, source["document_id"],
                                          {"expected_version": 1, "content": content}, idempotency_key="invalid-pack")["data"]
    source_pin = pin(source)
    install_source_provider(service, source_pin)
    before = snapshot(service)
    with pytest.raises(RuntimeErrorBase):
        commit(service, source_request(service, source_pin))
    assert snapshot(service) == before


@pytest.mark.parametrize("damage", ["undeclared", "foreign", "stale-version", "wrong-digest", "arbitrary-document"])
def test_source_port_does_not_broaden_document_authority(service, damage):
    source = create_pack(service)
    source_pin = pin(source)
    if damage == "foreign":
        foreign = service.create_project({"name": "Foreign pack", "slug": "foreign-pack"})["id"]
        service.store.conn.execute("UPDATE project_documents SET project_id=? WHERE id=?", (foreign, source["document_id"]))
    elif damage == "stale-version":
        source_pin["version"] += 1
    elif damage == "wrong-digest":
        source_pin["content_digest"] = "sha256:" + "0" * 64
    elif damage == "arbitrary-document":
        service.store.conn.execute("UPDATE project_documents SET kind='notes' WHERE id=?", (source["document_id"],))
    install_source_provider(service, source_pin)
    before = snapshot(service)
    with pytest.raises(RuntimeErrorBase):
        commit(service, source_request(service, source_pin, declare=damage != "undeclared"))
    assert snapshot(service) == before


def test_guessed_retained_pack_pin_is_not_authority_in_another_timeline(service):
    source = create_pack(service)
    source_pin = pin(source)
    install_source_provider(service, source_pin)
    commit(service, source_request(service, source_pin))
    service.create_timeline(service.test_project, "other", idempotency_key="other-timeline")
    body = source_request(service, source_pin)
    other = service.get_project_timeline(service.test_project, "other")
    body.update(timeline_id="other", base_revision_id=other["head_revision_id"],
                base_publication_id=other["head_publication_id"])
    before = snapshot(service)
    with pytest.raises(RuntimeErrorBase, match="authorized closure"):
        service.commit_timeline(service.test_project, "other", body, idempotency_key="guess-pack",
                                publisher="editor", invocation_path=f"/v1/projects/{service.test_project}/timelines/other/commit",
                                authorize=lambda: None)
    assert snapshot(service) == before


@pytest.mark.parametrize("damage", ["stale-capture", "detached-mutation", "corrupt-retention"])
def test_acceptance_revalidates_pack_bytes_before_writes(service, damage):
    source = create_pack(service)
    source_pin = pin(source)
    if damage == "corrupt-retention":
        install_source_provider(service, source_pin)
        commit(service, source_request(service, source_pin))
        service.store.conn.execute("UPDATE timeline_document_input_contents SET content_json='{}'")

    def before_accept(value, candidate):
        if damage == "stale-capture":
            content = copy.deepcopy(source["content"])
            content["admissions"] = []
            service.update_document(service.test_project, source["document_id"],
                                    {"expected_version": 1, "content": content}, idempotency_key="racing-pack")
        else:
            value["document"]["content"]["admissions"] = []  # Detached return cannot mutate private capture.

    install_source_provider(service, source_pin, before_accept=before_accept)
    before = snapshot(service)
    if damage == "detached-mutation":
        commit(service, source_request(service, source_pin))
        captured = capture_document_input(service.store.conn, service.test_project, source_pin,
                                          reachable_pins=[source_pin], expected_kind=PROJECT_PACK_KIND,
                                          expected_schema=PROJECT_PACK_SCHEMA)
        assert captured.document == source
    else:
        with pytest.raises(RuntimeErrorBase):
            commit(service, source_request(service, source_pin), key="invalid-capture")
        if damage == "corrupt-retention":
            assert snapshot(service) == before
        assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_document_input_links").fetchone()[0] == (
            1 if damage == "corrupt-retention" else 0)


@pytest.fixture
def admitted_pack(service, tmp_path, astrid_importable, monkeypatch):
    import yaml
    from astrid.core.element import project_packs as packs
    from astrid.sdk.contracts import DomainResult, ErrorObject

    monkeypatch.setenv(packs.ROOT_ENV, str(tmp_path / "authoring"))
    monkeypatch.setenv(packs.ARTIFACT_ENV, str(tmp_path / "artifacts"))
    verifier = tmp_path / "verify-build.py"
    verifier.write_text(
        "import hashlib,json,sys\nfrom pathlib import Path\n"
        "p=Path(sys.argv[1]);v=json.loads(p.read_bytes())\n"
        "print(json.dumps({'schema':'astrid.element-build/v1',"
        "'selectionDigest':'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest(),"
        "'elements':[{'projectId':e['projectId'],**{k:e['descriptor'][k] "
        "for k in ('packId','id','kind','revision')}} for e in v['elements']]}))\n"
    )
    monkeypatch.setenv(packs.BUILD_ENV, json.dumps([sys.executable, str(verifier)]))

    class Documents:
        def _identity(self):
            return {"realm_id": service.realm["id"]}

        def show(self, document, *, project):
            try:
                return DomainResult.success(service.get_document(project, document))
            except NotFoundError:
                return DomainResult.failure(ErrorObject("not_found", "missing", {}))

        def create(self, *, project, kind, document_id, content, idempotency_key):
            return DomainResult.success(service.create_document(
                project, {"kind": kind, "document_id": document_id, "content": content},
                idempotency_key=idempotency_key,
            )["data"])

        def update(self, document, *, project, content, expected_version, idempotency_key):
            return DomainResult.success(service.update_document(
                project, document, {"content": content, "expected_version": expected_version},
                idempotency_key=idempotency_key,
            )["data"])

    class Media:
        def import_bytes(self, *, project, data, filename, media_type, idempotency_key):
            return DomainResult.success(service.ingest(
                project, data, media_type=media_type, original_name=filename,
                idempotency_key=idempotency_key,
            )["data"])

    client = SimpleNamespace(documents=Documents(), media=Media())
    realm, project = service.realm["id"], service.test_project
    context = packs.init_project_pack(realm, project, client=client)
    root = Path(context["packRoot"])
    directory = root / "rendering/elements/effects/reveal"
    directory.mkdir(parents=True)
    component = directory / "component.tsx"
    component.write_text("import React from 'react';export default function Reveal(){return <div/>;}\n")
    declaration = {"schema_version": 1, "id": "reveal", "kind": "effect", "pack_id": context["packId"],
                   "short_description": "Selected schema test.", "defaults": {"seed": 4},
                   "schema": {"type": "object", "properties": {"seed": {"type": "number", "maximum": 10}}},
                   "runtime": {"adapter": "remotion"}}
    descriptor_path = directory / "element.yaml"
    descriptor_path.write_text(yaml.safe_dump(declaration))
    manifest = yaml.safe_load((root / "pack.yaml").read_text())
    manifest["rendering"] = {"effects/reveal": {"type": "element",
        "path": "rendering/elements/effects/reveal/element.yaml", "resources": [
            {"kind": "implementation", "path": "rendering/elements/effects/reveal/component.tsx"},
        ]}}
    (root / "pack.yaml").write_text(yaml.safe_dump(manifest))
    admission = packs.admit_project_pack(realm, project, client=client)
    source = service.get_document(project, admission["documentId"])
    record = admission["elements"][0]
    reference = {key: record["descriptor"][key] for key in ("packId", "id", "kind", "revision")}

    def resolve(verified, reference=reference):
        class VerifiedDocuments:
            def _identity(self):
                return {"realm_id": realm}

            def show(self, document, *, project):
                if document == verified["pin"]["document_id"] and project == service.test_project:
                    return DomainResult.success(copy.deepcopy(verified["document"]))
                return DomainResult.failure(ErrorObject("not_found", "missing", {}))
        # Host-boundary proof: the existing resolver still reads its local
        # immutable artifact cache. Runtime CAS custody is not claimed here.
        return packs.resolve_admitted_element(realm, project, reference,
                                              client=SimpleNamespace(documents=VerifiedDocuments()))

    def update_source():
        declaration["schema"]["properties"]["seed"]["maximum"] = 20
        descriptor_path.write_text(yaml.safe_dump(declaration))
        component.write_text(component.read_text() + "// source v2\n")
        return packs.admit_project_pack(realm, project, client=client)

    def no_renderer(*args, **kwargs):
        raise AssertionError("save called renderer or launcher")

    import runtime_protocol.service as service_module
    from runtime_protocol import visual_seam
    monkeypatch.setattr(service_module, "evaluate_closure", no_renderer)
    monkeypatch.setattr(visual_seam, "evaluate_closure", no_renderer)
    monkeypatch.setattr(packs, "_open_client", no_renderer)
    return SimpleNamespace(source=source, record=record, reference=reference, resolve=resolve,
                           update_source=update_source, packs=packs)


@pytest.mark.integration
def test_real_admission_inventory_retention_keeps_exact_selected_revision(service, admitted_pack):
    case = admitted_pack
    source_pin = pin(case.source)
    selected = []

    def select(verified, candidate):
        descriptor = case.resolve(verified)["descriptor"]
        assert descriptor == case.record["descriptor"]
        selected.append(descriptor)

    install_source_provider(service, source_pin, before_accept=select)
    body = source_request(service, source_pin)
    accepted = commit(service, body)
    original_files = {item["path"]: (Path(case.record["snapshot"]["root"]) / item["path"]).read_bytes()
                      for item in case.record["snapshot"]["files"]}
    new_admission = case.update_source()
    assert new_admission["elements"][0]["descriptor"]["revision"] != case.reference["revision"]
    assert new_admission["elements"][0]["descriptor"]["schema"]["properties"]["seed"]["maximum"] == 20
    project, root = service.test_project, service.store.root
    service.close()
    restarted = RuntimeService(root)
    try:
        restarted.test_project = project
        provider = install_source_provider(restarted, source_pin, before_accept=select)
        before = snapshot(restarted)
        assert commit(restarted, body) == accepted
        assert snapshot(restarted) == before and provider.calls == 0
        commit(restarted, source_request(restarted, source_pin, declare=False), key="exact-old-admission")
        assert len(selected) == 2
        assert selected[-1]["schema"]["properties"]["seed"]["maximum"] == 10
        assert {item["path"]: (Path(case.record["snapshot"]["root"]) / item["path"]).read_bytes()
                for item in case.record["snapshot"]["files"]} == original_files
    finally:
        restarted.close()


@pytest.mark.integration
@pytest.mark.parametrize("damage", ["owner", "id", "kind", "revision", "snapshot", "build-receipt"])
def test_real_exact_selection_refuses_without_acceptance_writes(service, admitted_pack, damage):
    from runtime_protocol.timeline_commit_port import refused

    case = admitted_pack
    reference = copy.deepcopy(case.reference)
    if damage in {"owner", "id", "kind", "revision"}:
        reference[{"owner": "packId"}.get(damage, damage)] = "wrong"
    else:
        root = Path(case.record["snapshot"]["root"])
        path = root / (case.record["snapshot"]["componentPath"] if damage == "snapshot" else ".build-receipt.json")
        path.write_text("{}")

    def select(verified, candidate):
        try:
            case.resolve(verified, reference)
        except (ValueError, OSError) as exc:
            raise refused("dependency_unavailable", "exact admitted declaration is unavailable") from exc
        raise AssertionError("damaged selection unexpectedly resolved")

    source_pin = pin(case.source)
    install_source_provider(service, source_pin, before_accept=select)
    before = snapshot(service)
    with pytest.raises(RuntimeErrorBase, match="exact admitted declaration"):
        commit(service, source_request(service, source_pin))
    assert snapshot(service) == before


def portable_object(service, *, data=None, project=None, media_type="application/json", key="portable"):
    if data is None:
        resource = b"original pack resource\n"
        data = json.dumps({"files": [{"path": "pack.yaml", "sha256": hashlib.sha256(resource).hexdigest(),
                                     "bytes_base64": base64.b64encode(resource).decode("ascii")}],
                           "build_receipt_base64": base64.b64encode(b"original receipt").decode("ascii")},
                          sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    actual = service.ingest(project or service.test_project, data, media_type=media_type, idempotency_key=key)["data"]
    descriptor = {name: actual[name] for name in ("object_id", "digest", "size", "media_type")}
    return descriptor, data


def install_object_provider(service, source_pin, object_id, *, seen=None, before_accept=None):
    def read_object(verified, candidate):
        port = service.test_provider.ports[-1]
        value = port.document_object(source_pin, object_id)
        if seen is not None:
            seen.append(value)
        if before_accept is not None:
            before_accept(value, candidate)
    return install_source_provider(service, source_pin, before_accept=read_object)


@pytest.mark.parametrize("damage", ["null", "extra", "bool-size", "zero-size", "float-size", "negative-size",
                                    "hash", "object-id", "uppercase", "mime", "missing-key"])
@pytest.mark.parametrize("boundary", ["create", "update"])
def test_snapshot_descriptor_validation_at_document_admission(service, damage, boundary):
    descriptor, _ = portable_object(service)
    source = create_pack(service)
    value = copy.deepcopy(descriptor)
    if damage == "null":
        value = None
    elif damage == "extra":
        value["path"] = "/tmp/forged"
    elif damage.endswith("size"):
        value["size"] = {"bool-size": True, "zero-size": 0, "float-size": 1.0, "negative-size": -1}[damage]
    elif damage == "hash":
        value["digest"] = "sha256:" + "0" * 64
    elif damage == "object-id":
        value["object_id"] = "../../outside"
    elif damage == "uppercase":
        value["object_id"] = value["digest"] = descriptor["digest"].upper()
    elif damage == "mime":
        value["media_type"] = "application/octet-stream"
    else:
        del value["digest"]
    content = copy.deepcopy(source["content"])
    content["admissions"][0]["snapshot_object"] = value
    before = snapshot(service)
    with pytest.raises(RuntimeErrorBase, match="snapshot"):
        if boundary == "create":
            service.create_document(service.test_project, {"document_id": "bad-pack", "kind": PROJECT_PACK_KIND,
                                                           "content": content}, idempotency_key="bad-create")
        else:
            service.update_document(service.test_project, source["document_id"],
                                    {"expected_version": 1, "content": content}, idempotency_key="bad-update")
    assert snapshot(service) == before


@pytest.mark.parametrize("damage", ["foreign", "unmanaged", "missing-object", "size", "mime", "dedup-mime"])
def test_snapshot_admission_requires_actual_managed_project_metadata(service, damage):
    project = service.test_project
    if damage == "foreign":
        project = service.create_project({"slug": "foreign", "name": "Foreign"})["id"]
    descriptor, data = portable_object(service, project=project,
                                       media_type="text/plain" if damage == "dedup-mime" else "application/json")
    raw_hash = descriptor["object_id"].removeprefix("sha256:")
    if damage == "unmanaged":
        service.store.conn.execute("UPDATE project_objects SET relation='referenced' WHERE digest=?", (raw_hash,))
    elif damage == "missing-object":
        service.store.conn.execute("PRAGMA foreign_keys=OFF")
        service.store.conn.execute("DELETE FROM objects WHERE digest=?", (raw_hash,))
        service.store.conn.execute("PRAGMA foreign_keys=ON")
    elif damage == "size":
        descriptor["size"] += 1
    elif damage == "mime":
        service.store.conn.execute("UPDATE objects SET media_type='text/plain' WHERE digest=?", (raw_hash,))
    elif damage == "dedup-mime":
        actual, _ = portable_object(service, data=data, key="dedup")
        assert actual["media_type"] == "text/plain"  # Requested MIME never replaces stored metadata.
        descriptor["media_type"] = "application/json"
    before = snapshot(service)
    with pytest.raises(RuntimeErrorBase, match="snapshot"):
        create_pack(service, snapshot_object=descriptor)
    assert snapshot(service) == before


@pytest.mark.parametrize("damage", ["not-captured", "forged-config", "wrong-object", "foreign", "unmanaged", "missing-object",
                                    "size", "mime", "missing-blob", "corrupt-blob", "symlink"])
def test_document_object_refuses_unauthorized_or_damaged_cas(service, tmp_path, damage):
    descriptor, data = portable_object(service)
    source = create_pack(service, snapshot_object=descriptor)
    source_pin = pin(source)
    raw_hash = descriptor["object_id"].removeprefix("sha256:")
    path = service.cas.path_for(raw_hash)
    if damage == "forged-config":
        service.store.conn.execute("UPDATE project_documents SET kind='forged.config' WHERE id=?", (source["document_id"],))
    elif damage in {"foreign", "unmanaged"}:
        if damage == "foreign":
            foreign = service.create_project({"slug": "foreign", "name": "Foreign"})["id"]
            service.store.conn.execute("UPDATE project_objects SET project_id=? WHERE digest=?", (foreign, raw_hash))
        else:
            service.store.conn.execute("DELETE FROM project_objects WHERE digest=?", (raw_hash,))
    elif damage == "missing-object":
        service.store.conn.execute("PRAGMA foreign_keys=OFF")
        service.store.conn.execute("DELETE FROM objects WHERE digest=?", (raw_hash,))
        service.store.conn.execute("PRAGMA foreign_keys=ON")
    elif damage in {"size", "mime"}:
        service.store.conn.execute("UPDATE objects SET " + ("size=size+1" if damage == "size" else "media_type='text/plain'") +
                                   " WHERE digest=?", (raw_hash,))
    elif damage == "missing-blob":
        path.unlink()
    elif damage == "corrupt-blob":
        path.write_bytes(b"x" * len(data))
    elif damage == "symlink":
        target = tmp_path / "outside-cas"
        target.write_bytes(data)
        path.unlink()
        path.symlink_to(target)

    def action(context, port):
        candidate = prepared(context, port)
        if damage != "not-captured":
            port.config_source(source_pin)
        port.document_object(source_pin, "sha256:" + "0" * 64 if damage == "wrong-object" else descriptor["object_id"])
        raise AssertionError("unavailable object was read")
    service.test_provider.action = action
    before = snapshot(service)
    with pytest.raises(RuntimeErrorBase):
        commit(service, source_request(service, source_pin))
    assert snapshot(service) == before


@pytest.mark.parametrize("damage", ["association", "metadata", "bytes", "replacement", "live-v2", "authority"])
def test_object_capture_rechecks_races_atomically(service, damage):
    descriptor, data = portable_object(service)
    source = create_pack(service, snapshot_object=descriptor)
    source_pin = pin(source)
    raw_hash = descriptor["object_id"].removeprefix("sha256:")
    after_race = []

    def race(value, candidate):
        if damage == "association":
            service.store.conn.execute("DELETE FROM project_objects WHERE digest=?", (raw_hash,))
        elif damage == "metadata":
            service.store.conn.execute("UPDATE objects SET size=size+1 WHERE digest=?", (raw_hash,))
        elif damage in {"bytes", "replacement"}:
            path = service.cas.path_for(raw_hash)
            if damage == "bytes":
                path.write_bytes(b"x" * len(data))
            else:
                replacement = path.with_suffix(".replacement")
                replacement.write_bytes(data)
                replacement.replace(path)
        elif damage == "live-v2":
            content = copy.deepcopy(source["content"])
            content["admissions"] = []
            service.update_document(service.test_project, source["document_id"],
                                    {"expected_version": 1, "content": content}, idempotency_key="race-v2")
        after_race.append(snapshot(service))

    install_object_provider(service, source_pin, descriptor["object_id"], before_accept=race)
    from runtime_protocol.errors import AuthorizationError
    def authorize():
        if damage == "authority" and after_race:
            raise AuthorizationError("authority revoked")
    with pytest.raises(RuntimeErrorBase):
        commit(service, source_request(service, source_pin), authorize=authorize)
    assert after_race and snapshot(service) == after_race[0]
    assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_document_input_links").fetchone()[0] == 0


def test_portable_snapshot_v1_survives_v2_document_removal_restart_and_compaction(service):
    from runtime_protocol.upgrade import compact_idempotency_ledger
    descriptor, data = portable_object(service)
    source = create_pack(service, snapshot_object=descriptor)
    source_pin = pin(source)
    seen = []
    provider = install_object_provider(service, source_pin, descriptor["object_id"], seen=seen)
    body = source_request(service, source_pin)
    accepted = commit(service, body)
    assert seen == [{**descriptor, "bytes_base64": base64.b64encode(data).decode("ascii")}]
    with pytest.raises(RuntimeErrorBase):
        provider.ports[-1].document_object(source_pin, descriptor["object_id"])
    newer, _ = portable_object(service, data=b'{"v":2}', key="portable-v2")
    content = copy.deepcopy(source["content"])
    content["admissions"].append({**content["admissions"][0], "revision": "sha256:" + "3" * 64,
                                  "snapshot_digest": "4" * 64, "snapshot_object": newer})
    service.update_document(service.test_project, source["document_id"],
                            {"expected_version": 1, "content": content}, idempotency_key="v2")
    service.store.conn.execute("DELETE FROM project_documents WHERE id=?", (source["document_id"],))
    tables = ("objects", "project_objects", "timeline_document_input_contents",
              "timeline_document_input_bindings", "timeline_document_input_links")
    retained = {table: list(map(tuple, service.store.conn.execute(f"SELECT * FROM {table}"))) for table in tables}
    project, root, realm = service.test_project, service.store.root, service.realm["id"]
    assert service.store.integrity_report()["ok"]
    service.close()
    compact_idempotency_ledger(root, confirmation=f"COMPACT IDEMPOTENCY {realm}")
    restarted = RuntimeService(root)
    try:
        restarted.test_project = project
        provider = install_object_provider(restarted, source_pin, descriptor["object_id"], seen=seen)
        assert {table: list(map(tuple, restarted.store.conn.execute(f"SELECT * FROM {table}"))) for table in tables} == retained
        before = snapshot(restarted)
        assert commit(restarted, body) == accepted
        assert snapshot(restarted) == before and provider.calls == 0
        commit(restarted, source_request(restarted, source_pin, declare=False), key="retained-cas-v1")
        assert seen == [{**descriptor, "bytes_base64": base64.b64encode(data).decode("ascii")}] * 2
        assert restarted.store.integrity_report()["ok"]
    finally:
        restarted.close()


@pytest.mark.parametrize("damage", ["association", "object", "size", "mime", "blob", "corruption"])
def test_doctor_detects_retained_snapshot_damage_after_current_document_removal(service, damage):
    descriptor, data = portable_object(service)
    source = create_pack(service, snapshot_object=descriptor)
    source_pin = pin(source)
    install_object_provider(service, source_pin, descriptor["object_id"])
    commit(service, source_request(service, source_pin))
    service.store.conn.execute("DELETE FROM project_documents WHERE id=?", (source["document_id"],))
    assert service.store.integrity_report()["ok"]
    raw_hash = descriptor["object_id"].removeprefix("sha256:")
    if damage == "association":
        service.store.conn.execute("DELETE FROM project_objects WHERE digest=?", (raw_hash,))
    elif damage == "object":
        service.store.conn.execute("PRAGMA foreign_keys=OFF")
        service.store.conn.execute("DELETE FROM objects WHERE digest=?", (raw_hash,))
        service.store.conn.execute("PRAGMA foreign_keys=ON")
    elif damage in {"size", "mime"}:
        service.store.conn.execute("UPDATE objects SET " + ("size=size+1" if damage == "size" else "media_type='text/plain'") +
                                   " WHERE digest=?", (raw_hash,))
    elif damage == "blob":
        service.cas.path_for(raw_hash).unlink()
    else:
        service.cas.path_for(raw_hash).write_bytes(b"x" * len(data))
    report = service.store.integrity_report()
    assert not report["ok"]
    if damage in {"association", "object", "size", "mime"}:
        assert not report["checks"]["revisions"]["ok"]
    before = snapshot(service)
    with pytest.raises(RuntimeErrorBase):
        commit(service, source_request(service, source_pin, declare=False), key="damaged-retained-v1")
    assert snapshot(service) == before
