"""Public capture admission must verify source content before it writes anything.

The compact frozen projection was produced by Agent 321cef4b's real capture
probe. Tests need only Runtime: setup publishes the actual immutable closure,
and restores its graph from public revision reads, never from SQL seed rows.
"""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from runtime_protocol.errors import ConflictError, NotFoundError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.snapshot_refs import snapshot_bytes, snapshot_digest
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_store import TimelineCommitStore
from runtime_protocol.util import canonical_json
from test_timeline_commit_acceptance import validate_prepared
from test_timeline_native_inspection import _publish

CAPABILITY = "rendering.timeline_visualize"
CAPABILITY_DIGEST = "sha256:" + hashlib.sha256(CAPABILITY.encode()).hexdigest()
REFUSALS = (ConflictError, NotFoundError, ValidationError)


def _digest(value):
    return "sha256:" + hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _refresh_identity(snapshot):
    snapshot["metadata"]["capture_identity"] = _digest({
        "authority": snapshot["metadata"]["capture_authority"],
        "config": snapshot["config"], "registry": snapshot["registry"],
    })
    snapshot["video_digest"] = snapshot["metadata"]["capture_identity"]


@pytest.fixture
def capture(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "source-probe", "name": "Source probe"})["id"]
        service.create_timeline(project, "main", idempotency_key="timeline")
        TimelineCommitStore(service.store, validate_prepared=validate_prepared).bootstrap(
            project, "main", authorize=lambda: None)
        service.register_capability({"capability_id": CAPABILITY, "definition_digest": CAPABILITY_DIGEST})
        service.register_executor({"executor_id": "probe", "capabilities": [CAPABILITY]})
        template = Path(__file__).with_name("fixtures") / "capture_authority.json"
        fixture = json.loads(template.read_text().replace("PROJECT_ID", project))
        media = service.ingest(project, fixture["media_bytes"].encode(), media_type="video/mp4",
                               idempotency_key="media")["data"]["object_id"]
        publication = fixture["publication"]
        assert publication["shot_revisions"][0]["payload"]["items"][0]["media_id"] == media
        # Runtime-only seam tests use the frozen real Agent projection as the
        # trusted provider output. The live Agent golden/pair is a separate gate.
        from runtime_protocol.contract_metadata import SCHEMA_DIGEST
        from runtime_protocol.timeline_commit_provider import PROVIDER_ID

        class FrozenProjectionProvider:
            provider_id = PROVIDER_ID
            interface_version = 1
            contract_digest = SCHEMA_DIGEST

            def commit(self, request, port):
                raise AssertionError("capture admission must not invoke commit")

            def project_capture(self, document, *, authoring_preview=None):
                assert document["project_id"] == project
                assert document["timeline_id"] == "main"
                assert document["parent_revision"]["revision_id"] == "parent-1"
                assert authoring_preview is None
                return deepcopy(projection)

        service.register_timeline_commit_provider(FrozenProjectionProvider())
        _publish(service, project, publication, idempotency_key="source")
        parent = service.get_project_parent_composition_revision(project, "main", "parent-1")
        shot = service.get_project_shot_revision(project, "shot-shared", "shot-rev-1")
        internal = service.get_project_timeline_revision(project, "main", "internal-1")
        for row in (parent, shot, internal):
            assert _digest(row["payload"]) == row["content_digest"]
        snapshot = fixture["saved"]
        authority = snapshot["metadata"]["capture_authority"]
        assert authority["parent_content_digest"] == parent["content_digest"]
        assert authority["expansion"]["shots"][0]["content_digest"] == shot["content_digest"]
        assert authority["expansion"]["children"][0]["config_hash"] == internal["content_digest"]
        authority["expansion"]["graph"] = {
            "parent_revision": parent, "shot_revisions": [shot], "internal_timeline_revisions": [internal],
        }
        snapshot["metadata"]["canonical_timeline"] = deepcopy(authority)
        _refresh_identity(snapshot)
        projection = {"config": deepcopy(snapshot["config"]), "registry": deepcopy(snapshot["registry"]),
                      "expansion": deepcopy(authority["expansion"])}
        yield service, project, publication, snapshot, media
    finally:
        service.close()


def _ref(service, project, snapshot):
    payload = snapshot_bytes(snapshot)
    digest = snapshot_digest(snapshot)
    result = service.ingest(project, payload, media_type="application/json",
                            idempotency_key="capture-" + digest.removeprefix("sha256:"))
    assert result["data"]["object_id"] == digest
    assert service.object(digest)[1] == payload
    authority = snapshot["metadata"].get("capture_authority", {})
    ref = {"digest": digest, "project_id": project, "timeline_id": "main",
           "revision_id": authority.get("parent_revision_id"),
           "revision_digest": authority.get("parent_content_digest"),
           "source_kind": "revision" if authority else "cas"}
    return ref


def _request(capture, *, snapshot=None, inline=False):
    service, project, _, saved, media = capture
    snapshot = deepcopy(saved if snapshot is None else snapshot)
    context = {"mode": "composed_capture", "project_id": project, "timeline_id": "main"}
    authority = snapshot.get("metadata", {}).get("capture_authority")
    if authority:
        context["revision_id"] = authority["parent_revision_id"]
    if inline:
        context["capture_snapshot"] = snapshot
    else:
        context["capture_snapshot_ref"] = _ref(service, project, snapshot)
    return {"project": project, "capability_id": CAPABILITY, "capability_digest": CAPABILITY_DIGEST,
            "input_object_ids": [media], "idempotency_key": "capture-admission",
            "spec": {"authority_context": context,
                     "inputs": {"filmstrip_authority": canonical_json(context)}}}


def _sql(service):
    tables = [row[0] for row in service.store.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
    )]
    return {name: tuple(sorted((tuple(row) for row in service.store.conn.execute(
        'SELECT * FROM "' + name.replace('"', '""') + '"',
    )), key=repr)) for name in tables}


def _files(root):
    return {str(path.relative_to(root)): path.read_bytes() if path.is_file() else None
            for path in root.rglob("*")}


def _state(service):
    return {"SQL": _sql(service), "CAS": _files(service.store.cas_root),
            "staging": _files(service.store.staging_root)}


def _assert_refused_without_writes(service, request):
    # All setup, especially pre-ingested ref objects/managed relations, is baseline.
    before = _state(service)
    refused = None
    try:
        service.create_task(request)
    except REFUSALS as exc:
        refused = exc
    after = _state(service)
    changed = {kind: sorted(name for name in before[kind].keys() | after[kind].keys()
                            if before[kind].get(name) != after[kind].get(name))
               for kind in before if after[kind] != before[kind]}
    assert refused is not None and not changed, (
        f"admission refusal={type(refused).__name__ if refused else 'NONE'}; "
        f"changed={changed}"
    )
    return refused


@pytest.mark.parametrize("field", ["config", "registry", "shot_digest"])
@pytest.mark.parametrize("inline", [True, False], ids=["inline", "ref"])
def test_forged_capture_is_refused_without_writes(capture, field, inline):
    snapshot = deepcopy(capture[3])
    if field == "config":
        snapshot["config"]["clips"][0]["hold"] = 123
    elif field == "registry":
        next(iter(snapshot["registry"]["assets"].values()))["opaque_asset"] = "forged meaning"
    else:
        for key in ("capture_authority", "canonical_timeline"):
            snapshot["metadata"][key]["expansion"]["shots"][0]["content_digest"] = "sha256:" + "0" * 64
    # Both the capture's own identity and any pre-ingested CAS hash are valid.
    # They cannot establish that its content came from the claimed revision.
    _refresh_identity(snapshot)
    request = _request(capture, snapshot=snapshot, inline=inline)
    _assert_refused_without_writes(capture[0], request)


@pytest.mark.parametrize("inline", [True, False], ids=["inline", "ref"])
def test_mismatched_duplicate_authority_is_refused_without_writes(capture, inline):
    request = _request(capture, inline=inline)
    duplicate = json.loads(request["spec"]["inputs"]["filmstrip_authority"])
    if inline:
        duplicate["capture_snapshot"]["config"]["clips"][0]["hold"] = 123
    else:
        replacement = deepcopy(capture[3])
        replacement["config"]["clips"][0]["hold"] = 123
        duplicate["capture_snapshot_ref"] = _ref(capture[0], capture[1], replacement)
    request["spec"]["inputs"]["filmstrip_authority"] = canonical_json(duplicate)
    _assert_refused_without_writes(capture[0], request)


@pytest.mark.parametrize("scope", ["project", "timeline", "revision_digest", "managed_relation"])
def test_capture_ref_scope_is_refused_without_writes(capture, scope):
    service, _, _, snapshot, _ = capture
    request = _request(capture)
    ref = request["spec"]["authority_context"]["capture_snapshot_ref"]
    if scope in {"project", "managed_relation"}:
        other = service.create_project({"slug": "other", "name": "Other"})["id"]
        if scope == "project":
            ref["project_id"] = other
        else:
            # Real CAS object, but only the other project owns its managed relation.
            replacement = deepcopy(snapshot)
            replacement["metadata"]["scope_probe"] = True
            ref["digest"] = _ref(service, other, replacement)["digest"]
    elif scope == "timeline":
        ref["timeline_id"] = "other-timeline"
    else:
        ref["revision_digest"] = "sha256:" + "0" * 64
    request["spec"]["inputs"]["filmstrip_authority"] = canonical_json(request["spec"]["authority_context"])
    _assert_refused_without_writes(service, request)


@pytest.mark.parametrize("inline", [True, False], ids=["inline", "ref"])
def test_embedded_cross_project_authority_is_refused_without_writes(capture, inline):
    service = capture[0]
    other = service.create_project({"slug": "other", "name": "Other"})["id"]
    snapshot = deepcopy(capture[3])
    for key in ("capture_authority", "canonical_timeline"):
        snapshot["metadata"][key]["project_id"] = other
    _refresh_identity(snapshot)
    # Outer task/context/ref all name the legitimate project. The claimed
    # source inside those bytes must independently agree with that scope.
    request = _request(capture, snapshot=snapshot, inline=inline)
    _assert_refused_without_writes(service, request)


@pytest.mark.parametrize("payload", [b"not JSON", b"{}"], ids=["malformed", "missing-closure"])
def test_non_snapshot_cas_ref_is_refused_without_writes(capture, payload):
    service, project, _, _, _ = capture
    request = _request(capture)
    obj = service.ingest(project, payload, media_type="application/json",
                         idempotency_key="not-a-capture")["data"]["object_id"]
    request["spec"]["authority_context"]["capture_snapshot_ref"]["digest"] = obj
    request["spec"]["inputs"]["filmstrip_authority"] = canonical_json(request["spec"]["authority_context"])
    _assert_refused_without_writes(service, request)


@pytest.mark.parametrize("binding", ["base", "candidate"])
@pytest.mark.parametrize("inline", [True, False], ids=["inline", "ref"])
def test_wrong_working_copy_binding_is_refused_without_writes(capture, binding, inline):
    service, _, _, snapshot, _ = capture
    snapshot = deepcopy(snapshot)
    authority = snapshot["metadata"]["capture_authority"]
    # Deliberately caller-asserted marker, not authoritative candidate setup.
    # A saved base row plus a self-consistent marker cannot certify a candidate.
    marker = {"candidate_parent_revision_id": "candidate", "candidate_digest": "sha256:" + "a" * 64,
              "publication_digest": "sha256:" + "b" * 64,
              "base_parent": {"revision_id": "parent-1", "content_digest": authority["parent_content_digest"]}}
    if binding == "base":
        marker["base_parent"]["content_digest"] = "sha256:" + "0" * 64
    authority["parent_revision_id"] = "candidate"
    snapshot["metadata"]["canonical_timeline"] = deepcopy(authority)
    snapshot["metadata"]["working_copy"] = marker
    _refresh_identity(snapshot)
    request = _request(capture, snapshot=snapshot, inline=inline)
    if not inline:
        ref = request["spec"]["authority_context"]["capture_snapshot_ref"]
        ref.update(source_kind="working_copy", revision_digest=marker["candidate_digest"], working_copy={
            "candidate_digest": marker["candidate_digest"], "publication_digest": marker["publication_digest"],
            "base_revision_id": "parent-1", "base_revision_digest": marker["base_parent"]["content_digest"],
        })
        request["spec"]["inputs"]["filmstrip_authority"] = canonical_json(request["spec"]["authority_context"])
    _assert_refused_without_writes(service, request)


def _admit_and_claim(capture, request):
    service = capture[0]
    task = service.create_task(request)["task"]
    claim = service.claim_next({"executor_id": "probe", "capability_ids": [CAPABILITY],
                                "runtime_epoch": service.health()["runtime_epoch"]})
    assert claim["task_id"] == task["id"]
    return task["spec"]["spec"]["authority_context"]["capture_snapshot_ref"]


@pytest.mark.parametrize("advance_head", [False, True], ids=["saved", "retained-after-new-head"])
@pytest.mark.parametrize("inline", [True, False], ids=["inline", "ref"])
def test_exact_saved_capture_passes_without_canonical_writes(capture, inline, advance_head):
    service, project, publication, snapshot, _ = capture
    request = _request(capture, inline=inline)
    if advance_head:
        newer = deepcopy(publication)
        newer.update(expected_head="parent-1", parent_revision_id="parent-2")
        newer["parent_composition"]["config"]["opaque_parent_config"] = {"new_head": True}
        newer["parent_composition"]["occurrences"][0]["shot_revision_id"] = "shot-rev-2"
        shot = newer["shot_revisions"][0]
        shot.update(revision_id="shot-rev-2", internal_timeline_revision_id="internal-2")
        shot["payload"]["internal_timeline_revision_id"] = "internal-2"
        child = newer["internal_timeline_revisions"][0]
        child["revision_id"] = "internal-2"
        child["payload"]["opaque_new_head"] = True
        _publish(service, project, newer, idempotency_key="new-head")
        assert service.get_project_timeline(project, "main")["head_revision_id"] == "parent-2"
    before = _state(service)
    ref = _admit_and_claim(capture, request)
    assert ref["source_kind"] == "revision"
    assert ref["revision_id"] == "parent-1"
    assert ref["revision_digest"] == snapshot["metadata"]["capture_authority"]["parent_content_digest"]
    assert ref["digest"] == snapshot_digest(snapshot)
    assert service.object(ref["digest"])[1] == snapshot_bytes(snapshot)
    after = _state(service)
    ordinary = {"objects", "project_objects", "tasks", "runs", "task_specs", "command_idempotency",
                "attempts", "executors", "events", "project_sequences", "sqlite_sequence"}
    changed = {name for name in before["SQL"] if before["SQL"][name] != after["SQL"][name]}
    assert changed <= ordinary, f"unexpected canonical writes: {changed - ordinary}"
    assert all(after["CAS"][name] == payload for name, payload in before["CAS"].items())
    new_files = {name for name in after["CAS"] if name not in before["CAS"] and after["CAS"][name] is not None}
    assert new_files == ({ref["digest"].removeprefix("sha256:")[:2] + "/" +
                          ref["digest"].removeprefix("sha256:")[2:]} if inline else set())


def test_native_unclaimed_cas_capture_does_not_acquire_revision_authority(capture):
    snapshot = deepcopy(capture[3])
    snapshot["metadata"].pop("capture_authority")
    snapshot["metadata"].pop("canonical_timeline")
    request = _request(capture, snapshot=snapshot)
    ref = _admit_and_claim(capture, request)
    assert ref["source_kind"] == "cas"
    assert ref["revision_id"] is None
    assert ref["revision_digest"] is None
    assert capture[0].object(ref["digest"])[1] == snapshot_bytes(snapshot)
