"""Real Agent candidate projection -> Runtime admission -> claim -> Agent host.

The saved full expansion golden remains blocked by CanonicalDocument's missing
outer read metadata. These tests qualify the unpublished candidate path only.
"""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_timeline_commit_acceptance import validate_prepared
from test_timeline_native_inspection import _publish

from runtime_protocol.service import RuntimeService
from runtime_protocol.snapshot_refs import snapshot_bytes, snapshot_digest
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_provider import load_timeline_commit_provider
from runtime_protocol.timeline_commit_store import TimelineCommitStore
from runtime_protocol.util import canonical_json
from tests.test_snapshot_authority_refusal import (
    CAPABILITY,
    CAPABILITY_DIGEST,
    _assert_refused_without_writes,
    _digest,
    _state,
)

pytestmark = pytest.mark.integration


class CaptureClient:
    """Adapt only SDK read shapes; all reads and writes use the real Runtime."""

    def __init__(self, service, project):
        self.service, self.project_id = service, project
        self.media = SimpleNamespace(list=self.media_list)
        self._remote = SimpleNamespace(_transport=self)

    def get_project(self, project):
        row = self.service.store.get_project(project)
        return {**row, "project_id": row["id"]}

    def list_timelines(self, project, **_kwargs):
        return [[self.service.get_project_timeline(project, "main")], None]

    def media_list(self, project, **kwargs):
        page = self.service.list_project_objects(project, **kwargs)
        return [page["items"], page["next_cursor"]]

    def get_project_parent_composition_revision(self, *args):
        return self.service.get_project_parent_composition_revision(*args)

    def get_project_shot_revision(self, *args):
        return self.service.get_project_shot_revision(*args)

    def get_project_timeline_revision(self, *args):
        return self.service.get_project_timeline_revision(*args)

    def get_object(self, digest):
        return self.service.object(digest)[1]


@pytest.fixture
def candidate(tmp_path, astrid_importable):
    from astrid.core.timeline.authoring_bundle import open_authoring_bundle
    from astrid.sdk.timeline import commit as agent

    assert Path(agent.__file__).resolve().is_relative_to(astrid_importable)
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "actual-candidate", "name": "Actual candidate"})["id"]
        service.create_timeline(project, "main", idempotency_key="timeline")
        TimelineCommitStore(service.store, validate_prepared=validate_prepared).bootstrap(
            project, "main", authorize=lambda: None)
        service.register_capability({"capability_id": CAPABILITY, "definition_digest": CAPABILITY_DIGEST})
        service.register_executor({"executor_id": "probe", "capabilities": [CAPABILITY]})
        # Borrow only publication data, never the frozen projection/provider.
        fixture = json.loads((Path(__file__).with_name("fixtures") / "capture_authority.json")
                             .read_text().replace("PROJECT_ID", project))
        media = service.ingest(project, fixture["media_bytes"].encode(), media_type="video/mp4",
                               idempotency_key="media")["data"]["object_id"]
        publication = fixture["publication"]
        assert publication["shot_revisions"][0]["payload"]["items"][0]["media_id"] == media
        # Use a fully pinned authored registry; the SDK's media admission must
        # not have to enrich an incomplete registry after pure projection.
        asset = publication["internal_timeline_revisions"][0]["payload"]["registry"]["assets"]["picture"]
        asset["content_sha256"] = media.removeprefix("sha256:")
        _publish(service, project, publication, idempotency_key="source")
        provider = load_timeline_commit_provider("astrid")
        assert type(provider) is agent.RuntimeCommitService
        assert callable(provider.project_capture)
        service.register_timeline_commit_provider(provider)
        client = CaptureClient(service, project)
        parent = client.get_project_parent_composition_revision(project, "main", "parent-1")
        shot = client.get_project_shot_revision(project, "shot-shared", "shot-rev-1")
        internal = client.get_project_timeline_revision(project, "main", "internal-1")
        for row in (parent, shot, internal):
            assert _digest(row["payload"]) == row["content_digest"]
        document = service._timeline_commits()[0].revision_closure(project, "main", "parent-1")
        assert document["dependency_manifest"]["media"] == [{"media_id": media, "content_digest": media}]
        assert document["dependency_manifest"]["documents"] == []
        bundle = open_authoring_bundle(parent, shot_revisions=[shot], internal_timeline_revisions=[internal])
        yield SimpleNamespace(service=service, client=client, project=project, media=media,
                              document=document, bundle=bundle)
    finally:
        service.close()


def _candidate_snapshot(case, change="parent"):
    from astrid.core.timeline.authoring_bundle import preview_authoring_candidate
    from astrid.sdk.timeline_filmstrip import prepare_filmstrip

    bundle = deepcopy(case.bundle)
    if change == "parent":
        bundle["parent"]["config"]["opaque_parent_config"] = {"unsaved": [False, None, 0]}
    else:
        bundle["shots"]["shot-shared"]["internal_timeline"]["clips"][0]["hold"] = 0.5
    preview = preview_authoring_candidate(bundle)
    snapshot = prepare_filmstrip({"composed_capture": True, "timeline_ref": "main",
                                  "authoring_preview": preview},
                                 project=case.project, client=case.client)["capture_snapshot"]
    # Require entire SDK expansion parity, including any graph it supplies.
    projection = case.service._timeline_commit_provider.project_capture(case.document, authoring_preview=preview)
    assert projection == {"config": snapshot["config"], "registry": snapshot["registry"],
                          "expansion": snapshot["metadata"]["capture_authority"]["expansion"]}
    if change == "parent":
        assert snapshot["config"]["opaque_parent_config"] == {"unsaved": [False, None, 0]}
    else:
        assert snapshot["config"]["clips"][0]["hold"] == 0.5
    return snapshot, preview


def _request(case, snapshot, preview, *, inline, native=False):
    context = {"mode": "composed_capture", "project_id": case.project, "timeline_id": "main"}
    authority = snapshot["metadata"]["capture_authority"]
    if not native:
        context["revision_id"] = authority["parent_revision_id"]
    if inline:
        context["capture_snapshot"] = snapshot
    else:
        digest = snapshot_digest(snapshot)
        result = case.service.ingest(case.project, snapshot_bytes(snapshot), media_type="application/json",
                                     idempotency_key="capture-" + digest.removeprefix("sha256:"))
        assert result["data"]["object_id"] == digest
        ref = {"digest": digest, "project_id": case.project, "timeline_id": "main", "source_kind": "cas"}
        if not native:
            marker = snapshot["metadata"]["working_copy"]
            ref.update(source_kind="working_copy", revision_id=authority["parent_revision_id"],
                       revision_digest=marker["candidate_digest"], working_copy={
                           "candidate_digest": marker["candidate_digest"],
                           "publication_digest": marker["publication_digest"],
                           "base_revision_id": marker["base_parent"]["revision_id"],
                           "base_revision_digest": marker["base_parent"]["content_digest"]})
        context["capture_snapshot_ref"] = ref
    inputs = {"filmstrip_authority": canonical_json(context)}
    if preview is not None:
        # The WHOLE existing SDK artifact is plain task input, never a marker.
        inputs["authoring_preview"] = deepcopy(preview)
    return {"project": case.project, "capability_id": CAPABILITY, "capability_digest": CAPABILITY_DIGEST,
            "input_object_ids": [case.media], "idempotency_key": "actual-candidate",
            "spec": {"authority_context": context, "inputs": inputs}}


def _alias_request(case, snapshots, *, inline):
    context = {"mode": "composed_capture", "project_id": case.project, "timeline_id": "main",
               "revision_id": next(iter(snapshots.values()))["metadata"]["capture_authority"]["parent_revision_id"]}
    if inline:
        for key, snapshot in snapshots.items():
            context[key] = deepcopy(snapshot)
    else:
        for key, snapshot in snapshots.items():
            digest = snapshot_digest(snapshot)
            result = case.service.ingest(
                case.project, snapshot_bytes(snapshot), media_type="application/json",
                idempotency_key="alias-capture-" + digest.removeprefix("sha256:"),
            )
            assert result["data"]["object_id"] == digest
            authority = snapshot["metadata"]["capture_authority"]
            marker = snapshot["metadata"]["working_copy"]
            context[key + "_ref"] = {
                "digest": digest, "project_id": case.project, "timeline_id": "main",
                "revision_id": authority["parent_revision_id"],
                "revision_digest": marker["candidate_digest"], "source_kind": "working_copy",
                "working_copy": {
                    "candidate_digest": marker["candidate_digest"],
                    "publication_digest": marker["publication_digest"],
                    "base_revision_id": marker["base_parent"]["revision_id"],
                    "base_revision_digest": marker["base_parent"]["content_digest"],
                },
            }
    return {"project": case.project, "capability_id": CAPABILITY,
            "capability_digest": CAPABILITY_DIGEST, "input_object_ids": [case.media],
            "idempotency_key": "capture-aliases", "spec": {
                "authority_context": context,
                "inputs": {"filmstrip_authority": canonical_json(context)},
            }}


def _outer_legacy_spec(case, snapshots, *, inline):
    request = _alias_request(case, snapshots, inline=inline)
    nested = request["spec"]
    return {
        "input_object_ids": request["input_object_ids"],
        "schema_version": "1",
        "capability_digest": CAPABILITY_DIGEST,
        "authority_context": nested["authority_context"],
        "spec": {"inputs": nested["inputs"]},
    }


def _claim_and_materialize(case, request, attempt):
    from astrid.core.execution.generic_host import GenericPackHost

    task = case.service.create_task(request)["task"]
    claim = case.service.claim_next({"executor_id": "probe", "capability_ids": [CAPABILITY],
                                     "runtime_epoch": case.service.health()["runtime_epoch"]})
    assert claim["task_id"] == task["id"]
    values = GenericPackHost(pack_roots=[], client=case.client)._materialize_inputs(task["spec"], attempt)
    return task, values


@pytest.mark.parametrize("change", ["parent", "child"])
@pytest.mark.parametrize("inline", [True, False], ids=["inline", "ref"])
def test_actual_candidate_reaches_claim_and_host(candidate, tmp_path, monkeypatch, change, inline):
    from astrid.core.rendering.contracts import RenderRequest
    from astrid.core.rendering.verified_source import SOURCE_ENV

    snapshot, preview = _candidate_snapshot(candidate, change)
    request = _request(candidate, snapshot, preview, inline=inline)
    before = _state(candidate.service)
    task, values = _claim_and_materialize(candidate, request, tmp_path / "attempt")
    binding = values.timeline_source.read()
    ref = binding["ref"]
    assert binding["snapshot"] == snapshot
    assert binding["authority"] == snapshot["metadata"]["capture_authority"]
    assert ref["source_kind"] == "working_copy"
    assert ref["revision_digest"] == preview["candidate_digest"]
    assert ref["working_copy"] == {
        "candidate_digest": preview["candidate_digest"], "publication_digest": preview["publication_digest"],
        "base_revision_id": preview["head"]["revision_id"],
        "base_revision_digest": preview["head"]["content_digest"]}
    assert candidate.service.object(ref["digest"])[1] == snapshot_bytes(snapshot)
    assert task["spec"]["spec"]["inputs"]["authoring_preview"] == preview
    expansion = binding["authority"]["expansion"]
    manifest = preview["publication"]["dependency_manifest"]
    assert [(row["shot_id"], row["revision_id"], row["content_digest"]) for row in expansion["shots"]] == [
        (pin["shot_id"], pin["revision_id"], pin["content_digest"]) for pin in manifest["shots"]]
    assert [(row["timeline_id"], row["revision_id"], row["config_hash"]) for row in expansion["children"]] == [
        (pin["timeline_id"], pin["revision_id"], pin["content_digest"]) for pin in manifest["internal_timelines"]]
    assert json.loads(Path(values["timeline"]).read_text()) == snapshot["config"]
    for path in set(values["materialized_objects"].values()):
        assert Path(path).read_bytes() == b"source video"
    assert candidate.media in values["materialized_objects"]
    monkeypatch.setenv(SOURCE_ENV, values.timeline_source._anchor)
    parsed = RenderRequest(schema_version=1, timeline_path=values["timeline"],
                           assets_registry_path=values["assets_registry"], output_name="probe.mp4")
    assert parsed.verified_source.read() == binding
    assert candidate.service.create_task(request)["task"]["id"] == task["id"]
    assert candidate.service._timeline_commits()[0].revision_closure(candidate.project, "main", "parent-1") == candidate.document
    after = _state(candidate.service)
    ordinary = {"objects", "project_objects", "tasks", "runs", "task_specs", "command_idempotency",
                "attempts", "executors", "events", "project_sequences", "sqlite_sequence"}
    assert {name for name in before["SQL"] if before["SQL"][name] != after["SQL"][name]} <= ordinary
    assert after["staging"] == before["staging"]
    assert all(after["CAS"][name] == payload for name, payload in before["CAS"].items())
    new_files = {name for name in after["CAS"] if name not in before["CAS"] and after["CAS"][name] is not None}
    digest_hex = ref["digest"].removeprefix("sha256:")
    assert new_files == ({digest_hex[:2] + "/" + digest_hex[2:]} if inline else set())


@pytest.mark.parametrize("field", ["config", "registry", "shot_digest"])
@pytest.mark.parametrize("inline", [False, True], ids=["ref", "inline"])
def test_original_working_copy_forgeries_refuse_before_writes(candidate, field, inline):
    snapshot, preview = _candidate_snapshot(candidate)
    # Exact mutations from Agent 321cef4b test_arbitrary_capture_cannot_acquire_canonical_source.
    if field == "config":
        snapshot["config"]["clips"][0]["hold"] = 123
    elif field == "registry":
        entry = next(iter(snapshot["registry"]["assets"].values()))
        entry["opaque_asset"] = "not from the immutable source"
    else:
        snapshot["metadata"]["capture_authority"]["expansion"]["shots"][0]["content_digest"] = "sha256:" + "0" * 64
    request = _request(candidate, snapshot, preview, inline=inline)
    _assert_refused_without_writes(candidate.service, request)


@pytest.mark.parametrize("inline", [True, False], ids=["inline", "ref"])
def test_working_copy_without_candidate_is_admitted_uncertified(candidate, tmp_path, inline):
    snapshot, _ = _candidate_snapshot(candidate)
    request = _request(candidate, snapshot, None, inline=inline)
    task = candidate.service.create_task(request)["task"]
    claim = candidate.service.claim_next({"executor_id": "probe", "capability_ids": [CAPABILITY],
                                          "runtime_epoch": candidate.service.health()["runtime_epoch"]})
    assert claim["task_id"] == task["id"]
    ref = claim["spec"]["spec"]["authority_context"]["capture_snapshot_ref"]
    assert ref == {"digest": snapshot_digest(snapshot), "project_id": candidate.project,
                   "timeline_id": "main", "source_kind": "cas"}
    assert "authoring_preview" not in claim["spec"]["spec"]["inputs"]


@pytest.mark.parametrize("alias", ["capture_snapshot", "input_snapshot", "filmstrip_snapshot"])
@pytest.mark.parametrize("inline", [True, False], ids=["inline", "ref"])
@pytest.mark.parametrize("multicarrier", [False, True], ids=["single", "multi"])
def test_all_capture_aliases_label_each_uncertified_carrier_without_rewriting(
    candidate, alias, inline, multicarrier
):
    first, _ = _candidate_snapshot(candidate, "parent")
    second = deepcopy(first)
    second["config"]["alias_probe"] = "input"
    snapshots = {alias: first}
    if multicarrier:
        snapshots = {
            "capture_snapshot": first,
            "input_snapshot": second,
            "filmstrip_snapshot": first,
        }
    request = _alias_request(candidate, snapshots, inline=inline)
    admitted = candidate.service.create_task(request)["task"]
    stored_before_claim = deepcopy(admitted["spec"])
    claim = candidate.service.claim_next({
        "executor_id": "probe", "capability_ids": [CAPABILITY],
        "runtime_epoch": candidate.service.health()["runtime_epoch"],
    })
    claimed = claim["spec"]["spec"]
    for key, snapshot in snapshots.items():
        ref = claimed["authority_context"][key + "_ref"]
        assert ref == {
            "digest": snapshot_digest(snapshot), "project_id": candidate.project,
            "timeline_id": "main", "source_kind": "cas",
        }
        duplicate_ref = json.loads(claimed["inputs"]["filmstrip_authority"])[key + "_ref"]
        assert duplicate_ref == ref

    # Claim-time relabeling is a worker view only: reads and exact retries keep
    # the admitted working-copy bytes and authority claims unchanged.
    assert candidate.service.store.get_task(admitted["id"])["task"]["spec"] == stored_before_claim
    retry = candidate.service.create_task(request)["task"]
    assert retry["id"] == admitted["id"]
    assert retry["spec"] == stored_before_claim


@pytest.mark.parametrize("alias", ["capture_snapshot", "input_snapshot", "filmstrip_snapshot"])
@pytest.mark.parametrize("inline", [True, False], ids=["inline", "ref"])
def test_outer_legacy_aliases_are_labelled_without_rewriting_admission(
    candidate, alias, inline
):
    snapshot, _ = _candidate_snapshot(candidate, "parent")
    request = _outer_legacy_spec(candidate, {alias: snapshot}, inline=inline)
    key = f"outer-legacy-{alias}-{inline}"
    admitted = candidate.service.store.create_task(
        CAPABILITY,
        request,
        candidate.project,
        idempotency_key=key,
        capability_digest=CAPABILITY_DIGEST,
    )["task"]
    stored_before_claim = deepcopy(admitted["spec"])
    state_before_claim = _state(candidate.service)

    claim = candidate.service.claim_next({
        "executor_id": "probe", "capability_ids": [CAPABILITY],
        "runtime_epoch": candidate.service.health()["runtime_epoch"],
    })
    assert claim["task_id"] == admitted["id"]
    claimed = claim["spec"]
    ref = claimed["authority_context"][alias + "_ref"]
    expected = {
        "digest": snapshot_digest(snapshot), "project_id": candidate.project,
        "timeline_id": "main", "source_kind": "cas",
    }
    assert ref == expected
    duplicate = json.loads(claimed["spec"]["inputs"]["filmstrip_authority"])
    assert duplicate[alias + "_ref"] == expected

    # Claim relabeling is only a public worker view. The admitted task
    # history/spec and immutable snapshot objects remain byte-for-byte intact.
    persisted = candidate.service.store.get_task(admitted["id"])["task"]
    assert persisted["spec"] == stored_before_claim
    spec_digest = candidate.service.store.conn.execute(
        "SELECT spec_digest FROM tasks WHERE id=?", (admitted["id"],)
    ).fetchone()["spec_digest"]
    assert candidate.service.store._load_spec(spec_digest) == stored_before_claim
    state_after_claim = _state(candidate.service)
    assert state_after_claim["CAS"] == state_before_claim["CAS"]

    retry = candidate.service.store.create_task(
        CAPABILITY,
        request,
        candidate.project,
        idempotency_key=key,
        capability_digest=CAPABILITY_DIGEST,
    )["task"]
    assert retry["id"] == admitted["id"]
    assert retry["spec"] == stored_before_claim


def test_claim_checks_nested_and_outer_aliases_with_mixed_results(monkeypatch):
    from runtime_protocol import capture_validation

    refs = {
        key: {
            "digest": "sha256:" + str(index) * 64,
            "project_id": "p",
            "timeline_id": "main",
            "revision_id": "r",
            "revision_digest": "sha256:" + "a" * 64,
            "source_kind": "revision",
        }
        for index, key in enumerate((
            "filmstrip_snapshot_ref", "input_snapshot_ref", "capture_snapshot_ref",
        ), 1)
    }
    duplicate = json.dumps(refs)
    spec = {
        "authority_context": deepcopy(refs),
        "spec": {
            "authority_context": deepcopy(refs),
            "inputs": {"filmstrip_authority": duplicate,
                        "argv": ["--authority", json.dumps({"nested": [refs]})]},
        },
    }
    monkeypatch.setattr(
        capture_validation,
        "validate_capture",
        lambda _service, _snapshot, ref, _inputs: ref["digest"] == refs["input_snapshot_ref"]["digest"],
    )
    service = SimpleNamespace(object=lambda _digest: ({}, b"{}"))
    result = capture_validation.claim_capture_view(service, spec)

    for context in (result["authority_context"], result["spec"]["authority_context"]):
        assert context["input_snapshot_ref"] == refs["input_snapshot_ref"]
        for key in ("filmstrip_snapshot_ref", "capture_snapshot_ref"):
            assert context[key] == {
                "digest": refs[key]["digest"], "project_id": "p", "timeline_id": "main",
                "source_kind": "cas",
            }
    parsed = json.loads(result["spec"]["inputs"]["filmstrip_authority"])
    assert parsed["input_snapshot_ref"] == refs["input_snapshot_ref"]
    assert parsed["filmstrip_snapshot_ref"]["source_kind"] == "cas"
    listed = json.loads(result["spec"]["inputs"]["argv"][1])["nested"][0]
    assert listed["capture_snapshot_ref"]["source_kind"] == "cas"


@pytest.mark.parametrize("candidate_given", [True, False], ids=["with-candidate", "without-candidate"])
@pytest.mark.parametrize("inline", [True, False], ids=["inline", "ref"])
def test_forged_working_copy_certificate_refuses_before_writes(candidate, inline, candidate_given):
    snapshot, preview = _candidate_snapshot(candidate)
    snapshot["metadata"]["working_copy"]["candidate_digest"] = "sha256:" + "a" * 64
    request = _request(candidate, snapshot, preview if candidate_given else None, inline=inline)
    _assert_refused_without_writes(candidate.service, request)


def test_explicit_cas_candidate_is_native_without_binding(candidate, tmp_path):
    snapshot, _ = _candidate_snapshot(candidate)
    # Existing labels/working-copy metadata do not certify an explicit CAS ref.
    request = _request(candidate, snapshot, None, inline=False, native=True)
    task, values = _claim_and_materialize(candidate, request, tmp_path / "attempt")
    ref = task["spec"]["spec"]["authority_context"]["capture_snapshot_ref"]
    assert ref["source_kind"] == "cas"
    assert not ref.get("revision_id") and not ref.get("revision_digest")
    assert values.timeline_source is None
