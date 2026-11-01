"""Real Agent admission/decoder paired with Runtime retained-input custody.

The build receipt is fixture setup, and PreparedProvider only drives host
acceptance. These tests do not qualify native PARAM edits or a pack-host build.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_timeline_commit_port as support
from test_timeline_commit_port import PreparedProvider, commit, prepared
from test_timeline_pack_inputs import pin, snapshot, source_request

from runtime_protocol.errors import NotFoundError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_port import digest, refused

pytestmark = pytest.mark.integration
service = support.service


@pytest.fixture
def portable_pack(service, tmp_path, astrid_importable, monkeypatch):
    import yaml
    from astrid.core.element import project_packs as packs
    from astrid.sdk.contracts import DomainResult, ErrorObject

    packs_path = Path(packs.__file__).resolve()
    assert packs_path.is_relative_to(astrid_importable), (
        f"project_packs imported outside configured Astrid checkout: {packs_path}"
    )
    snapshot_descriptor = getattr(packs, "admitted_element_snapshot_descriptor", None)
    assert callable(snapshot_descriptor), (
        f"configured Astrid checkout lacks required project_packs API: "
        "admitted_element_snapshot_descriptor"
    )
    authoring, artifacts = tmp_path / "authoring", tmp_path / "artifacts"
    monkeypatch.setenv(packs.ROOT_ENV, str(authoring))
    monkeypatch.setenv(packs.ARTIFACT_ENV, str(artifacts))
    # Existing project-pack test build seam: setup emits a matching receipt,
    # without asserting any real renderer or pack-host compilation succeeded.
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
        def __init__(self):
            self.imports = []

        def import_bytes(self, *, project, data, filename, media_type, idempotency_key):
            result = service.ingest(project, data, original_name=filename,
                                    media_type=media_type, idempotency_key=idempotency_key)
            self.imports.append((data, copy.deepcopy(result["data"])))
            return DomainResult.success(result["data"])

        def read_bytes(self, object_id):
            return service.cas.read(object_id.removeprefix("sha256:"))

    client = SimpleNamespace(documents=Documents(), media=Media())
    realm, project = service.realm["id"], service.test_project
    context = packs.init_project_pack(realm, project, client=client)
    root = Path(context["packRoot"])
    directory = root / "rendering/elements/effects/reveal"
    directory.mkdir(parents=True)
    component = directory / "component.tsx"
    component.write_text("import React from 'react';export default function Reveal(){return <div/>;}\n")
    declaration = {"schema_version": 1, "id": "reveal", "kind": "effect", "pack_id": context["packId"],
                   "short_description": "Portable selected schema test.", "defaults": {"seed": 4},
                   "schema": {"type": "object", "properties": {"seed": {"type": "number", "maximum": 10}}},
                   "runtime": {"adapter": "remotion"}}
    declaration_path = directory / "element.yaml"
    declaration_path.write_text(yaml.safe_dump(declaration))
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
    descriptor = source["content"]["admissions"][0]["snapshot_object"]
    files = {item["path"]: (root / item["path"]).read_bytes() for item in record["snapshot"]["files"]}
    receipt = (Path(record["snapshot"]["root"]) / ".build-receipt.json").read_bytes()
    data, actual = client.media.imports[0]
    assert descriptor == {key: actual[key] for key in descriptor}
    assert descriptor["digest"] == descriptor["object_id"] == "sha256:" + hashlib.sha256(data).hexdigest()
    assert descriptor["size"] == len(data) and descriptor["media_type"] == "application/json"
    assert service.cas.read(descriptor["digest"].removeprefix("sha256:")) == data
    association = service.store.conn.execute(
        "SELECT relation FROM project_objects WHERE project_id=? AND digest=?",
        (project, descriptor["digest"].removeprefix("sha256:")),
    ).fetchone()
    assert association["relation"] == "managed"
    envelope = json.loads(data)
    assert json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8") == data
    assert [item["path"] for item in envelope["files"]] == sorted(files)
    assert {item["path"]: base64.b64decode(item["bytes_base64"], validate=True)
            for item in envelope["files"]} == files
    assert base64.b64decode(envelope["build_receipt_base64"], validate=True) == receipt

    def update_source():
        declaration["schema"]["properties"]["seed"]["maximum"] = 20
        declaration_path.write_text(yaml.safe_dump(declaration))
        component.write_text(component.read_text() + "// source v2\n")
        return packs.admit_project_pack(realm, project, client=client)

    def forbidden(*args, **kwargs):
        raise AssertionError("save/replay attempted source/cache, renderer, or launcher access")

    @contextmanager
    def save_boundary():
        import runtime_protocol.service as service_module
        from runtime_protocol import visual_seam

        with monkeypatch.context() as guard:
            guard.setattr(service_module, "evaluate_closure", forbidden)
            guard.setattr(visual_seam, "evaluate_closure", forbidden)
            guard.setattr(subprocess, "run", forbidden)
            guard.setattr(subprocess, "Popen", forbidden)
            for name in ("_open_client", "_verify_build", "authoring_root", "artifact_root",
                         "resolve_admitted_element", "_resources"):
                guard.setattr(packs, name, forbidden)
            yield

    def decode(verified, value, selected):
        # Runtime reads its CAS before this guard; the Agent decoder itself
        # must be pure, even while source/cache still exist on first use.
        with monkeypatch.context() as guard:
            for name in ("read_bytes", "read_text", "open", "resolve", "is_file", "is_dir", "rglob"):
                guard.setattr(Path, name, forbidden)
            return snapshot_descriptor(realm, project, selected, verified, value)

    return SimpleNamespace(packs=packs, realm=realm, project=project, client=client,
                           source=source, record=record, reference=reference, descriptor=descriptor,
                           data=data, files=files, receipt=receipt, authoring=authoring, artifacts=artifacts,
                           update_source=update_source, save_boundary=save_boundary, decode=decode)


def install_decoder(service, case, *, selected=None, object_id=None, capture=True, before_accept=None):
    source_pin = pin(case.source)
    seen = []

    def action(context, port):
        candidate = prepared(context, port)
        verified = port.config_source(source_pin) if capture else None
        value = port.document_object(source_pin, object_id or case.descriptor["object_id"])
        try:
            descriptor = case.decode(verified, value, selected or case.reference)
        except ValueError as exc:
            raise refused("dependency_unavailable", str(exc)) from exc
        seen.append((verified, value, descriptor))
        candidate["canonical_document"]["dependency_manifest"]["documents"] = [source_pin]
        candidate["records"]["commands"][0]["dependencies"] = [
            {"key": "selected-pack", "kind": "source", "pin": source_pin, "policy": "exact"},
        ]
        candidate["document_digest"] = digest(candidate["canonical_document"])
        if before_accept:
            before_accept()
        return port.accept(candidate)

    provider = PreparedProvider(action)
    if hasattr(service, "test_provider"):
        service.test_provider.__dict__.update(provider.__dict__)
        provider = service.test_provider
    else:
        service.register_timeline_commit_provider(provider)
        service.test_provider = provider
    return provider, seen


def assert_original(case, seen):
    verified, value, descriptor = seen
    assert verified == {"pin": pin(case.source), "document": case.source}
    assert descriptor == case.record["descriptor"]
    assert descriptor["schema"]["properties"]["seed"]["maximum"] == 10
    assert value == {**case.descriptor, "bytes_base64": base64.b64encode(case.data).decode("ascii")}
    envelope = json.loads(base64.b64decode(value["bytes_base64"], validate=True))
    assert {item["path"]: base64.b64decode(item["bytes_base64"], validate=True)
            for item in envelope["files"]} == case.files
    assert base64.b64decode(envelope["build_receipt_base64"], validate=True) == case.receipt


def test_real_portable_v1_retained_after_v2_disk_removal_restart_retry_and_replay(service, portable_pack):
    case = portable_pack
    provider, seen = install_decoder(service, case)
    body = source_request(service, pin(case.source))
    with case.save_boundary():
        accepted = commit(service, body)
    assert len(seen) == 1
    assert_original(case, seen[0])
    with pytest.raises(RuntimeErrorBase):
        provider.ports[-1].document_object(pin(case.source), case.descriptor["object_id"])

    newer = case.update_source()
    assert newer["elements"][0]["descriptor"]["revision"] != case.reference["revision"]
    assert newer["elements"][0]["descriptor"]["schema"]["properties"]["seed"]["maximum"] == 20
    current = service.get_document(case.project, case.source["document_id"])
    assert current["version"] > case.source["version"]
    assert len(current["content"]["admissions"]) == 2
    assert current["content"]["admissions"][1]["snapshot_object"] != case.descriptor
    shutil.rmtree(case.authoring)
    shutil.rmtree(case.artifacts)
    assert not case.authoring.exists() and not case.artifacts.exists()
    # Intentional fixture removal, never manufacturing retained history.
    service.store.conn.execute("DELETE FROM project_documents WHERE id=?", (case.source["document_id"],))
    with pytest.raises(NotFoundError):
        service.get_document(case.project, case.source["document_id"])
    retained = service.store.conn.execute(
        "SELECT content_json FROM timeline_document_input_contents WHERE content_digest=?",
        (pin(case.source)["content_digest"],),
    ).fetchone()[0]
    assert json.loads(retained) == case.source["content"]
    root = service.store.root
    assert service.store.integrity_report()["ok"]
    service.close()
    restarted = RuntimeService(root)
    try:
        restarted.test_project = case.project
        provider, replayed = install_decoder(restarted, case)
        before = snapshot(restarted)
        with case.save_boundary():
            assert commit(restarted, body) == accepted
        assert snapshot(restarted) == before and provider.calls == 0 and replayed == []
        with case.save_boundary():
            commit(restarted, source_request(restarted, pin(case.source), declare=False), key="retained-v1-replay")
        assert provider.calls == 1 and len(replayed) == 1
        assert_original(case, replayed[0])
        assert restarted.store.conn.execute(
            "SELECT content_json FROM timeline_document_input_contents WHERE content_digest=?",
            (pin(case.source)["content_digest"],),
        ).fetchone()[0] == retained
        assert restarted.store.integrity_report()["ok"]
    finally:
        restarted.close()


@pytest.mark.parametrize("damage", ["revision", "owner", "objecthash", "association", "corrupt-blob", "uncaptured"])
def test_real_portable_selection_refuses_without_writes(service, portable_pack, damage):
    case = portable_pack
    selected = copy.deepcopy(case.reference)
    object_id = case.descriptor["object_id"]
    raw_hash = object_id.removeprefix("sha256:")
    if damage == "revision":
        selected["revision"] = "sha256:" + "0" * 64
    elif damage == "owner":
        selected["packId"] = "wrong_owner"
    elif damage == "objecthash":
        object_id = "sha256:" + "0" * 64
    elif damage == "association":
        service.store.conn.execute("DELETE FROM project_objects WHERE digest=?", (raw_hash,))
    elif damage == "corrupt-blob":
        service.cas.path_for(raw_hash).write_bytes(b"x" * len(case.data))
    install_decoder(service, case, selected=selected, object_id=object_id, capture=damage != "uncaptured")
    before = snapshot(service)
    with case.save_boundary(), pytest.raises(RuntimeErrorBase):
        commit(service, source_request(service, pin(case.source)))
    assert snapshot(service) == before


def test_real_portable_association_rechecked_at_acceptance(service, portable_pack):
    case = portable_pack
    after_race = []

    def remove_association():
        service.store.conn.execute("DELETE FROM project_objects WHERE digest=?",
                                   (case.descriptor["digest"].removeprefix("sha256:"),))
        after_race.append(snapshot(service))

    _, seen = install_decoder(service, case, before_accept=remove_association)
    with case.save_boundary(), pytest.raises(RuntimeErrorBase):
        commit(service, source_request(service, pin(case.source)))
    assert len(seen) == 1 and len(after_race) == 1
    assert_original(case, seen[0])
    assert snapshot(service) == after_race[0]


def test_real_legacy_readmission_backfills_and_noop_keeps_descriptor(service, portable_pack):
    case = portable_pack
    content = copy.deepcopy(case.source["content"])
    del content["admissions"][0]["snapshot_object"]
    legacy = service.update_document(case.project, case.source["document_id"],
                                    {"content": content, "expected_version": case.source["version"]},
                                    idempotency_key="legacy-fixture")["data"]
    case.packs.materialize_project_pack(case.realm, case.project, client=case.client)
    result = case.packs.admit_project_pack(case.realm, case.project, client=case.client)
    updated = service.get_document(case.project, case.source["document_id"])
    assert result["documentVersion"] == legacy["version"] + 1
    assert updated["content"] == case.source["content"]
    assert len(updated["content"]["admissions"]) == 1
    assert case.client.media.imports[-1][0] == case.data
    before, uploads = snapshot(service), len(case.client.media.imports)
    shutil.rmtree(Path(case.record["snapshot"]["root"]))
    again = case.packs.admit_project_pack(case.realm, case.project, client=case.client)
    assert again["documentVersion"] == updated["version"]
    assert snapshot(service) == before and len(case.client.media.imports) == uploads
    assert (Path(case.record["snapshot"]["root"]) / ".build-receipt.json").read_bytes() == case.receipt
