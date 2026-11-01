from __future__ import annotations

import copy
import hashlib
import json
import math
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from runtime_protocol.errors import ConflictError, NotFoundError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_store import TimelineCommitStore, digest, request_identity
from runtime_protocol.timeline_commit_validation import validate_commit_value
from runtime_protocol.util import canonical_json
from runtime_protocol.visual_seam import evaluate_closure
from test_timeline_commit_port import PreparedProvider
from test_visual_seam_admission import _accept_visual_publication


def _digest(data):
    return "sha256:" + hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


@pytest.fixture
def canonical_scene(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "scene-render", "name": "Scene"}, idempotency_key="project")
        service.register_timeline_commit_provider(PreparedProvider())
        service.create_timeline(project["id"], "main", idempotency_key="timeline")
        service.register_capability({"capability_id": "rendering.render", "definition_digest": _digest("rendering.render")})
        service.register_executor({"executor_id": "worker", "capabilities": ["rendering.render"]})
        html = "<!doctype html><html><body>immutable scene</body></html>"
        entry = service.ingest(project["id"], html.encode(), media_type="text/html", original_name="scene.html", idempotency_key="entry")["data"]
        audio = service.ingest(project["id"], b"ordinary-audio", media_type="audio/wav", idempotency_key="audio")["data"]
        package_body = {
            "manifest": {"formatVersion": 1, "entry": "scene.html", "duration": 100, "authoredFps": 30},
            "entry": {"object_id": entry["object_id"], "digest": entry["digest"], "media_type": "text/html", "size": len(html.encode()), "filename": "scene.html"},
            "assets": [],
        }
        fixture = {"service": service, "project": project["id"], "html": html, "entry": entry, "audio": audio, "package_body": package_body}
        _set_package(fixture, package_body)
        yield fixture
    finally:
        service.close()


def _set_package(fixture, body):
    encoded = canonical_json(body)
    package = fixture["service"].ingest(fixture["project"], encoded.encode(), media_type="application/json", original_name="scene.json", idempotency_key="package-" + _digest(encoded).removeprefix("sha256:"))["data"]
    fixture["package"] = package
    fixture["envelope"] = {"revision": package["digest"], "source": {"objectId": package["object_id"], "revision": package["digest"]}, "packageBody": encoded, "html": fixture["html"]}


def _publication(fixture, *, revision="parent-1", expected_head=None):
    clips = [
        {"id": "scene-a", "clipType": "haus.astrid.liveScene", "at": 0, "from": 55, "to": 65, "speed": 2, "track": "visual", "app": {"liveScene": copy.deepcopy(fixture["envelope"]), "opaque": {"keep": True}}},
        {"id": "scene-b", "clipType": "haus.astrid.liveScene", "at": 5, "from": 65, "to": 75, "speed": 1, "track": "visual", "app": {"liveScene": copy.deepcopy(fixture["envelope"])}},
        {"id": "music", "clipType": "media", "at": 0, "from": 0, "to": 15, "track": "audio", "asset": "music"},
    ]
    return {
        "project_id": fixture["project"], "timeline_id": "main", "expected_head": expected_head, "parent_revision_id": revision,
        "dependency_manifest": {"media": [{"media_id": fixture["audio"]["object_id"], "content_digest": fixture["audio"]["digest"]}]},
        "parent_composition": {
            "config": {"tracks": [{"id": "visual", "kind": "visual"}, {"id": "audio", "kind": "audio"}], "effects": [], "app": {"sentinel": "canonical"}},
            "registry": {"assets": {"music": {"media_id": "music-media", "content_sha256": fixture["audio"]["object_id"], "type": "audio"}}},
            "clips": clips, "occurrences": [],
        },
    }


def _publish(fixture, **kwargs):
    publication = _publication(fixture, **kwargs)
    return _accept_publication(fixture, publication, idempotency_key="publish-" + publication["parent_revision_id"])


def _accept_publication(fixture, publication, *, idempotency_key, dry_run=False):
    """Install exact render inputs at the host acceptance boundary, not Agent semantics.

    Like PreparedProvider, this fixture supplies prepared data to real persistence.
    Scene packages and registry metadata stay opaque until actual Task admission.
    """
    service = fixture["service"]
    commits = TimelineCommitStore(
        service.store, validate_prepared=lambda value: validate_commit_value(value, "PreparedCommit"),
    )
    head = commits.head(fixture["project"], "main")
    if publication["expected_head"] is not None:
        assert head["revision_id"] == publication["expected_head"]
    document = commits.revision_closure(fixture["project"], "main", head["revision_id"])
    before = document["parent_revision"]["payload"]
    payload = copy.deepcopy(publication["parent_composition"])
    document["parent_revision"] = {
        "revision_id": publication["parent_revision_id"], "payload": payload, "content_digest": digest(payload),
    }
    document["dependency_manifest"] = {
        "shots": [], "internal_timelines": [], "documents": [],
        **copy.deepcopy(publication["dependency_manifest"]),
    }
    command = {"schema_version": 1, "op": "fixture.install-render-parent", "version": "1",
               "select": None, "args": {"canonical_document": copy.deepcopy(document)}}
    request = {"api_version": 1, "project_id": fixture["project"], "timeline_id": "main",
               "base_revision_id": head["revision_id"], "base_publication_id": head["publication_id"],
               "commands": [command]}
    if dry_run:
        request["dry_run"] = True
    context = {"request": request, "invocation": {"operation": "commitTimeline",
               "path": f"/v1/projects/{fixture['project']}/timelines/main/commit", "body": copy.deepcopy(request)},
               "idempotency_key": idempotency_key, "realm_id": service.realm["id"], "publisher": "render-fixture"}
    context["request_hash"] = request_identity(context)
    record = {"ordinal": 0, "command": command,
              "writes": [{"ref": "parent", "path": [key],
                          "before": {"state": "present", "value": before[key]} if key in before else {"state": "absent"},
                          "after": {"state": "present", "value": value}} for key, value in payload.items()],
              "reads": [], "selections": [], "bindings": [], "created": [], "dependencies": [], "derived_writes": []}
    prepared = {"expected_head": head, "canonical_document": document, "document_digest": digest(document),
                "records": {"schema_version": 1, "commands": [record], "undo_of": [], "restored_from": None},
                "id_map": {}, "semantic_events": [], "provider_version": "prepared-fixture-1", "compiler_version": "fixture-1"}
    if dry_run:
        return commits.preview(context, prepared, authorize=service._assert_mutation_admitted)
    accepted = commits.accept(context, prepared, authorize=service._assert_mutation_admitted)
    return _fixture_image_view(accepted)


def _fixture_image_view(accepted):
    """Read-only image view for existing assertions; never a legacy publish response."""
    parent = accepted["data"]["canonical_document"]["parent_revision"]
    return {"accepted": accepted, "data": {
        "payload": copy.deepcopy(parent["payload"]), "content_digest": parent["content_digest"],
        "new_head": accepted["data"]["accepted_revision_id"],
    }}


def _request(fixture, *, head="parent-1", key="render"):
    version = fixture["service"].get_project_timeline(fixture["project"], "main")["version"]
    return {
        "project": fixture["project"], "capability_id": "rendering.render", "capability_digest": _digest("rendering.render"), "input_object_ids": [], "idempotency_key": key,
        "spec": {"family": "render", "params": {"timeline_ref": "main", "expected_version": version, "canonical_project_id": fixture["project"], "canonical_parent_document_id": "main", "canonical_head_revision_id": head, "canonical_occurrence_ids": [], "selector": "rendering.remotion"}},
    }


def _snapshot(service, spec):
    """Resolve the admitted spec's CAS snapshot ref and check the bytes match its digest."""
    ref = spec["spec"]["timeline_snapshot_ref"]
    assert "timeline_snapshot" not in spec["spec"]
    payload = service.object(ref["digest"])[1]
    assert _digest(payload) == ref["digest"]
    return json.loads(payload)


def _assert_rejected(fixture, body, errors=(ConflictError, ValidationError, NotFoundError), match=None):
    service = fixture["service"]
    before = {table: service.store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in ("tasks", "runs")}
    with pytest.raises(errors, match=match):
        service.create_task(body)
    assert {table: service.store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in before} == before


def _stored_state(service):
    return (tuple(service.store.conn.iterdump()),
            {str(path.relative_to(service.store.cas_root)): path.read_bytes()
             for path in service.store.cas_root.rglob("*") if path.is_file()})


def test_canonical_parent_freezes_both_placements_ordinary_audio_and_exact_objects(canonical_scene):
    f = canonical_scene
    publication = _publish(f)
    admitted = f["service"].create_task(_request(f))
    spec = admitted["task"]["spec"]
    ref = spec["spec"]["timeline_snapshot_ref"]
    snapshot = _snapshot(f["service"], spec)
    expected_config = copy.deepcopy(publication["data"]["payload"]["config"])
    expected_config["clips"] = publication["data"]["payload"]["clips"]
    expected_registry = copy.deepcopy(publication["data"]["payload"]["registry"])
    expected_registry["assets"]["music"]["content_sha256"] = f["audio"]["object_id"].removeprefix("sha256:")
    assert snapshot == {"config": expected_config, "registry": expected_registry}
    assert [clip["id"] for clip in snapshot["config"]["clips"]] == ["scene-a", "scene-b", "music"]
    canonical = [oid for oid in spec["input_object_ids"] if oid != ref["digest"]]
    assert len(spec["input_object_ids"]) == 4
    assert set(canonical) == {f["package"]["object_id"], f["entry"]["object_id"], f["audio"]["object_id"]}
    assert spec["input_object_ids"] == canonical + [ref["digest"]]
    authority = spec["spec"]["inputs"]["timeline_authority"]
    assert authority["parent_revision_id"] == "parent-1"
    assert authority["parent_content_digest"] == publication["data"]["content_digest"]
    assert authority["snapshot_digest"] == _digest(canonical_json(snapshot))
    assert authority["snapshot_digest"] == ref["digest"]
    assert authority["input_object_ids"] == canonical
    assert authority["dependency_digests"] == [{"dependency_kind": "media", "dependency_id": f["audio"]["object_id"], "content_digest": f["audio"]["digest"]}]
    # An exact assertion is accepted and idempotent; it cannot create extra authority.
    request = _request(f, key="exact-inputs")
    request["input_object_ids"] = canonical
    assert f["service"].create_task(request) == f["service"].create_task(request)


@pytest.mark.parametrize(
    "picture_tracks,issue_code",
    [(None, "boundary/child-picture-gap"), (["plate"], "boundary/child-picture-gap")],
    ids=["visual-track-inferred", "declared-picture-track-gap"],
)
def test_unsafe_occurrence_seam_is_advisory_and_materialized_for_render(canonical_scene, picture_tracks, issue_code):
    f = canonical_scene
    publication = {
        "project_id": f["project"], "timeline_id": "main", "expected_head": None,
        "parent_revision_id": "unsafe-occurrence-parent",
        "internal_timeline_revisions": [{
            "timeline_id": "main", "revision_id": "unsafe-occurrence-child",
            "payload": {
                "tracks": [{"id": "plate", "kind": "visual"}],
                "clips": [
                    {"id": "custom-a", "clipType": "am-footage", "at": 0, "hold": 0.5, "track": "plate"},
                    {"id": "custom-b", "clipType": "am-snap-plate", "at": 0.8, "hold": 0.5, "track": "plate"},
                ],
                "effects": [], "audio": [], "layout": {}, "registry": {}, "assets": [],
            },
        }],
        "shot_revisions": [{
            "shot_id": "unsafe-shot", "revision_id": "unsafe-shot-revision",
            "internal_timeline_revision_id": "unsafe-occurrence-child",
            "payload": {"metadata": {}, "items": [], "pools": [], "selected_variants": {},
                        "provenance": {}, "generation_inputs": {}, "audio_bindings": [], "text_bindings": []},
        }],
        "parent_composition": {
            "config": {"output": {"fps": 30}, "tracks": [{"id": "visual", "kind": "visual"}]},
            "registry": {}, "clips": [],
            "occurrences": [{
                "occurrence_id": "unsafe-occurrence", "shot_id": "unsafe-shot",
                "shot_revision_id": "unsafe-shot-revision", "placement": {"start_ms": 0},
                "source_offset": 0, "duration_ms": 2000, "speed": 1, "track": "visual",
                "transform": {}, "gain": 1, "mute": False, "provenance": {},
            }],
        },
    }
    if picture_tracks is not None:
        publication["parent_composition"]["config"]["app"] = {
            "visualSeamContract": {"pictureTracks": picture_tracks},
        }
    saved = _accept_visual_publication(
        f["service"], publication, idempotency_key="save-unsafe-occurrence"
    )
    document = saved["data"]["canonical_document"]
    report, _ = evaluate_closure(
        document["parent_revision"]["payload"],
        {(image["shot_id"], image["revision_id"]): image for image in document["shot_revisions"]},
        {image["revision_id"]: image for image in document["internal_timeline_revisions"]},
        timeline_id="main",
    )
    assert report["blocked"] is True

    request = _request(f, head="unsafe-occurrence-parent", key="render-unsafe-occurrence")
    request["spec"]["params"]["canonical_occurrence_ids"] = ["unsafe-occurrence"]
    admitted = f["service"].create_task(request)
    spec = admitted["task"]["spec"]
    authority = spec["spec"]["inputs"]["timeline_authority"]
    snapshot = _snapshot(f["service"], spec)

    assert authority["visual_seam_report"] == report
    assert authority["visual_seam_report"]["blocked"] is True
    assert any(issue["code"] == issue_code
               for issue in authority["visual_seam_report"]["structuralIssues"])
    assert [clip["clipType"] for clip in snapshot["config"]["clips"]] == ["am-footage", "am-snap-plate"]
    assert [clip["track"] for clip in snapshot["config"]["clips"]] == ["plate", "plate"]
    assert [(clip["at"], clip["hold"]) for clip in snapshot["config"]["clips"]] == [(0, 0.5), (0.8, 0.5)]
    assert snapshot["config"].get("app", {}).get("visualSeamContract", {}).get("pictureTracks") == picture_tracks


@pytest.mark.parametrize("alpha", [False, True], ids=["opaque", "alpha-stamp"])
def test_canonical_long_media_and_hold_admission_covers_selected_fallback(canonical_scene, monkeypatch, alpha):
    f = canonical_scene
    publication = _publication(f)
    publication["parent_composition"]["clips"].append({
        "id": "bridge", "clipType": "hold", "at": 15, "hold": 25,
        "track": "visual",
    })
    publication["parent_composition"]["clips"].append({
        "id": "long-hold", "clipType": "hold", "at": 40, "hold": 256, "speed": 2,
        "track": "visual",
    })
    if alpha:
        publication["parent_composition"]["config"]["metadata"] = {
            "astrid_layer": {"alpha": True},
        }
    _accept_publication(
        f, publication, idempotency_key="publish-long-fallback",
    )
    monkeypatch.setattr(f["service"].store, "storage_preflight", lambda *_args, **_kwargs: {"ok": True})
    admitted = f["service"].create_task(_request(f, key="long-fallback"))
    estimate = admitted["task"]["spec"]["storage_estimate"]
    # At 30 fps, the held still reaches frame 5040. Opaque output uses the
    # JPEG95 fallback estimate; an Astrid alpha stamp retains PNG budgeting.
    png_raw_frame_bytes = (4 * 1920 + 1) * 1080
    png_frame_bytes = (png_raw_frame_bytes * 101 + 99) // 100
    png_sequence_bytes = png_frame_bytes * 5040
    jpeg_sequence_bytes = ((1920 * 1080) // 4) * 5040
    if alpha:
        assert estimate["scratch_bytes"] >= math.ceil(png_sequence_bytes * 1.10)
    else:
        assert estimate["scratch_bytes"] >= math.ceil(jpeg_sequence_bytes * 1.10)
        assert estimate["scratch_bytes"] < png_sequence_bytes


@pytest.mark.parametrize("route", ["/api/runtime/v1/objects/{encoded}", "/v1/objects/{encoded}",
                                   "/api/runtime/v1/objects/{plain}", "/v1/objects/{bare}"])
def test_frozen_managed_asset_canonicalizes_the_runtime_object_locator(canonical_scene, route):
    f = canonical_scene
    publication = _publication(f)
    object_id = f["audio"]["object_id"]
    asset_id = "cb9c765b-e54b-4727-9093-f47abf81a6c7"
    asset = {"media_id": f["audio"]["object_id"], "type": "audio/wav",
             "file": route.format(encoded=object_id.replace(":", "%3A"), plain=object_id, bare=object_id.removeprefix("sha256:")),
             "thumbnailUrl": "/api/runtime/v1/objects/thumbnail", "generationId": "film-generation"}
    publication["parent_composition"]["registry"]["assets"] = {asset_id: asset}
    publication["parent_composition"]["clips"][-1]["asset"] = asset_id
    _accept_publication(f, publication, idempotency_key="publish")
    authored = f["service"].get_project_parent_composition_revision(f["project"], "main", "parent-1")
    admitted = f["service"].create_task(_request(f))
    spec = admitted["task"]["spec"]
    assert f["audio"]["object_id"] in spec["input_object_ids"]
    assert _snapshot(f["service"], spec)["registry"]["assets"][asset_id] == {
        "media_id": object_id, "content_sha256": object_id.removeprefix("sha256:"), "type": "audio/wav"}
    assert f["service"].get_project_parent_composition_revision(f["project"], "main", "parent-1") == authored
    assert authored["payload"]["registry"]["assets"][asset_id] == asset
    assert spec["spec"]["inputs"]["timeline_authority"]["managed_media_admissions"] == {
        f["audio"]["object_id"]: f["audio"]["object_id"]}


def test_frozen_asset_retains_render_characteristics_without_editor_metadata(canonical_scene):
    f = canonical_scene
    publication = _publication(f)
    asset = {
        "media_id": f["audio"]["object_id"], "type": "audio/wav",
        "content_sha256": f["audio"]["object_id"],
        "duration": 3, "fps": 30, "resolution": "1920x1080",
        "thumbnailUrl": "/api/runtime/v1/objects/sha256%3A" + "1" * 64,
        "generationId": "film-generation", "variantId": "film-variant",
        "filename": "source.wav", "handle": "run:film/audio#0",
        # This is retired editor provenance, never the managed byte source.
        "source": "/retired/authoring/source.wav", "pixel_provenance": {"drawn_block": 13},
    }
    publication["parent_composition"]["registry"]["assets"]["music"] = asset
    _accept_publication(f, publication, idempotency_key="publish")
    authored = f["service"].get_project_parent_composition_revision(f["project"], "main", "parent-1")
    spec = f["service"].create_task(_request(f))["task"]["spec"]
    assert _snapshot(f["service"], spec)["registry"]["assets"]["music"] == {
        "media_id": f["audio"]["object_id"],
        "content_sha256": f["audio"]["object_id"].removeprefix("sha256:"),
        "type": "audio/wav", "duration": 3, "fps": 30, "resolution": "1920x1080",
    }
    assert authored["payload"]["registry"]["assets"]["music"] == asset
    assert f["service"].get_project_parent_composition_revision(f["project"], "main", "parent-1") == authored


def test_opaque_media_identity_without_a_digest_still_fails_admission(canonical_scene):
    f = canonical_scene
    publication = _publication(f)
    publication["parent_composition"]["registry"]["assets"]["music"] = {
        "media_id": "opaque-media-id", "file": "/api/runtime/v1/objects/" + f["audio"]["object_id"], "type": "audio/wav"}
    _accept_publication(f, publication, idempotency_key="publish")
    _assert_rejected(f, _request(f), ValidationError, "no runtime content digest")


@pytest.mark.parametrize("locator", [
    "https://example.com/api/runtime/v1/objects/{id}", "http://127.0.0.1:1234/v1/objects/{id}",
    "//example.com/v1/objects/{id}", "/api/runtime/v1/objects/{id}?token=x", "/v1/objects/{id}#fragment",
    "/v1/objects/{id}/../other", "/api/runtime/v1/objects/sha256:" + "0" * 64,
    "file:///tmp/source.wav", "/tmp/source.wav", "", None,
])
def test_managed_asset_real_or_mismatched_locators_are_refused(canonical_scene, locator):
    f = canonical_scene
    publication = _publication(f)
    publication["parent_composition"]["registry"]["assets"]["music"] = {
        "media_id": f["audio"]["object_id"], "file": locator.format(id=f["audio"]["object_id"]) if locator else locator}
    _accept_publication(f, publication, idempotency_key="publish")
    _assert_rejected(f, _request(f), ValidationError, "unmanaged locator")


@pytest.mark.parametrize("field", ["url", "uri", "sourceUrl", "remoteUrl", "path", "source_path", "locator", "realm"])
def test_matching_runtime_file_url_never_exempts_an_additional_locator(canonical_scene, field):
    f = canonical_scene
    publication = _publication(f)
    publication["parent_composition"]["registry"]["assets"]["music"] = {
        "media_id": f["audio"]["object_id"], "file": "/v1/objects/" + f["audio"]["object_id"], field: "/unmanaged/source.wav"}
    _accept_publication(f, publication, idempotency_key="publish")
    _assert_rejected(f, _request(f), ValidationError, "unmanaged locator")


def test_saved_source_tracks_remain_authored_but_are_removed_from_render_projection(canonical_scene):
    f = canonical_scene
    service = f["service"]
    source = service.ingest(
        f["project"], b"source-only-image", media_type="image/png",
        original_name="source.png", idempotency_key="source-image",
    )["data"]
    publication = _publication(f)
    authored_tracks = copy.deepcopy(publication["parent_composition"]["config"]["tracks"])
    authored_tracks[0]["role"] = "output"
    authored_tracks.append({"id": "source", "kind": "visual", "label": "References", "role": "source"})
    publication["parent_composition"]["config"]["tracks"] = authored_tracks
    source_clip = {
        "id": "reference-image", "clipType": "media", "at": 0, "from": 0,
        "to": 1, "track": "source", "asset": "source-image",
    }
    unknown_track_clip = {
        "id": "legacy-untracked", "clipType": "media", "at": 20, "from": 0,
        "to": 1, "track": "legacy-track", "asset": "music",
    }
    publication["parent_composition"]["clips"].extend([source_clip, unknown_track_clip])
    publication["parent_composition"]["registry"]["assets"]["source-image"] = {
        "media_id": source["object_id"],
        "content_sha256": source["object_id"],
        "type": "image",
    }
    publication["dependency_manifest"]["media"].append({
        "media_id": source["object_id"], "content_digest": source["digest"],
    })

    saved = _accept_publication(
        f, publication, idempotency_key="publish-source-role"
    )
    authored = service.get_project_parent_composition_revision(
        f["project"], "main", saved["data"]["new_head"]
    )["payload"]
    assert authored["config"]["tracks"] == authored_tracks
    assert source_clip in authored["clips"]
    assert "source-image" in authored["registry"]["assets"]
    inspection = service.inspect_timeline(f["project"], "main", {"track": "source"})
    assert [clip["clip_id"] for clip in inspection["selected_parent_clips"]] == ["reference-image"]

    admitted = service.create_task(_request(f))
    render_spec = admitted["task"]["spec"]
    snapshot = _snapshot(service, render_spec)
    assert render_spec["spec"]["timeline_snapshot_ref"]["digest"] in render_spec["input_object_ids"]
    assert snapshot["config"]["tracks"] == [track for track in authored_tracks if track.get("role") != "source"]
    assert [clip["id"] for clip in snapshot["config"]["clips"]] == [
        "scene-a", "scene-b", "music", "legacy-untracked",
    ]
    assert "source-image" not in snapshot["registry"]["assets"]
    assert source["object_id"] not in render_spec["input_object_ids"]
    assert render_spec["spec"]["inputs"]["timeline_authority"]["parent_content_digest"] == saved["data"]["content_digest"]


def test_nonempty_source_only_timeline_cannot_be_admitted_for_render(canonical_scene):
    f = canonical_scene
    body = _publication(f)
    body["internal_timeline_revisions"] = []
    body["shot_revisions"] = []
    body["parent_composition"]["occurrences"] = []
    body["dependency_manifest"] = {"media": []}
    body["parent_composition"]["config"] = {
        "tracks": [{"id": "source", "kind": "visual", "label": "Source", "role": "source"}],
    }
    body["parent_composition"]["registry"] = {"assets": {}}
    body["parent_composition"]["clips"] = [{
        "id": "source-clip", "clipType": "text", "at": 0, "hold": 1, "track": "source",
    }]
    _accept_publication(
        f, body, idempotency_key="publish-source-only"
    )

    _assert_rejected(f, _request(f), ValidationError, "source-only")


def test_canonical_stale_head_rejected_with_current_metadata_version(canonical_scene):
    f = canonical_scene
    service = f["service"]
    initial_version = service.get_project_timeline(f["project"], "main")["version"]
    _publish(f)
    version_before = service.get_project_timeline(f["project"], "main")["version"]
    assert version_before == initial_version + 1
    _publish(f, revision="parent-2", expected_head="parent-1")
    current = service.get_project_timeline(f["project"], "main")
    assert current["version"] == version_before + 1
    request = _request(f)
    assert request["spec"]["params"]["expected_version"] == current["version"]
    assert request["spec"]["params"]["canonical_head_revision_id"] == "parent-1" != current["head_revision_id"]
    before = _stored_state(service)
    _assert_rejected(f, request, ConflictError, "head")
    assert _stored_state(service) == before


@pytest.mark.parametrize("field,value", [
    ("canonical_project_id", "other-project"),
    ("canonical_parent_document_id", "other-timeline"),
    ("canonical_occurrence_ids", ["injected-occurrence"]),
])
def test_canonical_scope_assertions_are_checked(canonical_scene, field, value):
    f = canonical_scene
    _publish(f)
    request = _request(f)
    request["spec"]["params"][field] = value
    _assert_rejected(f, request)


def test_canonical_timeline_reference_cannot_cross_projects(canonical_scene):
    f = canonical_scene
    _publish(f)
    other = f["service"].create_project({"slug": "other", "name": "Other"}, idempotency_key="other")
    request = _request(f)
    request["project"] = other["id"]
    request["spec"]["params"]["canonical_project_id"] = other["id"]
    _assert_rejected(f, request)


@pytest.mark.parametrize("where,field,value", [
    ("spec", "timeline_snapshot", {"config": {"clips": []}, "registry": {}}),
    ("inputs", "timeline_snapshot", {"config": {}, "registry": {}}),
    ("inputs", "timeline_authority", {"project_id": "injected"}),
    ("inputs", "materialized_objects", {"injected": "/caller/file"}),
    ("inputs", "materialized_root", "/caller/root"),
    ("inputs", "timeline", "/caller/timeline.json"),
    ("inputs", "assets_registry", "/caller/assets.json"),
])
def test_canonical_snapshot_authority_and_materialization_injection_rejected(canonical_scene, where, field, value):
    f = canonical_scene
    _publish(f)
    request = _request(f)
    target = request["spec"] if where == "spec" else request["spec"].setdefault("inputs", {})
    target[field] = value
    _assert_rejected(f, request, ValidationError)


@pytest.mark.parametrize("ids", ["extra", "partial", "reversed"])
def test_canonical_nonempty_input_ids_are_only_exact_assertions(canonical_scene, ids):
    f = canonical_scene
    _publish(f)
    accepted = f["service"].create_task(_request(f, key="reference"))
    admitted_spec = accepted["task"]["spec"]
    snapshot_digest = admitted_spec["spec"]["timeline_snapshot_ref"]["digest"]
    assert snapshot_digest in admitted_spec["input_object_ids"]
    # The admitted list also carries the snapshot ref; the exact assertion is the canonical objects only.
    derived = [oid for oid in admitted_spec["input_object_ids"] if oid != snapshot_digest]
    assert len(derived) == 3
    extra = f["service"].ingest(f["project"], b"unreachable-object", idempotency_key="extra")["data"]["object_id"]
    request = _request(f, key="injected")
    request["input_object_ids"] = {"extra": derived + [extra], "partial": derived[:-1], "reversed": list(reversed(derived))}[ids]
    _assert_rejected(f, request, ConflictError, "input_object_ids")


@pytest.mark.parametrize("object_name", ["package", "entry"])
@pytest.mark.parametrize("damage", ["unowned", "missing", "digest", "size", "media_type"])
def test_canonical_scene_objects_require_project_association_and_verified_bytes(canonical_scene, object_name, damage):
    f = canonical_scene
    _publish(f)
    digest = f[object_name]["object_id"].removeprefix("sha256:")
    conn = f["service"].store.conn
    path = f["service"].cas.path_for(digest)
    if damage == "unowned":
        other = f["service"].create_project({"slug": "other", "name": "Other"}, idempotency_key="other")
        f["service"].ingest(other["id"], path.read_bytes(), idempotency_key="other-object")
        conn.execute("DELETE FROM project_objects WHERE project_id=? AND digest=?", (f["project"], digest))
    elif damage == "missing":
        path.unlink()
    elif damage == "digest":
        data = path.read_bytes()
        path.write_bytes(bytes([data[0] ^ 1]) + data[1:])
    elif damage == "size":
        conn.execute("UPDATE objects SET size=size+1 WHERE digest=?", (digest,))
    elif damage == "media_type":
        conn.execute("UPDATE objects SET media_type='application/octet-stream' WHERE digest=?", (digest,))
    _assert_rejected(f, _request(f))


@pytest.mark.parametrize("mutation", ["assets_missing", "assets_nonempty", "format", "entry_path", "duration", "fps", "entry_digest", "entry_size", "entry_id", "entry_filename"])
def test_canonical_scene_package_contract_rejected(canonical_scene, mutation):
    f = canonical_scene
    body = copy.deepcopy(f["package_body"])
    if mutation == "assets_missing":
        body.pop("assets")
    elif mutation == "assets_nonempty":
        body["assets"] = [body["entry"]]
    elif mutation == "format":
        body["manifest"]["formatVersion"] = 2
    elif mutation == "entry_path":
        body["manifest"]["entry"] = "../escape.html"
    elif mutation == "duration":
        body["manifest"]["duration"] = 0
    elif mutation == "fps":
        body["manifest"]["authoredFps"] = False
    elif mutation == "entry_digest":
        body["entry"]["digest"] = _digest("other")
    elif mutation == "entry_size":
        body["entry"]["size"] += 1
    elif mutation == "entry_id":
        body["entry"]["object_id"] = f["audio"]["object_id"]
    elif mutation == "entry_filename":
        body["entry"]["filename"] = []
    _set_package(f, body)
    _publish(f)
    _assert_rejected(f, _request(f))


@pytest.mark.parametrize("field,value", [
    ("packageBody", "{}"), ("html", "<html>caller replacement</html>"),
    ("revision", _digest("different-revision")),
    ("source", {"objectId": _digest("unreachable"), "revision": _digest("unreachable")}),
])
def test_canonical_scene_envelope_must_match_immutable_objects(canonical_scene, field, value):
    f = canonical_scene
    f["envelope"][field] = value
    _publish(f)
    _assert_rejected(f, _request(f))


def test_canonical_conflicting_populated_clip_lists_fail_closed(canonical_scene):
    f = canonical_scene
    publication = _publication(f)
    publication["parent_composition"]["config"]["clips"] = [{"id": "different", "clipType": "text", "at": 0, "hold": 1}]
    before = _stored_state(f["service"])
    for dry_run in (False, True):
        with pytest.raises(CommitRejected) as error:
            _accept_publication(f, publication, idempotency_key="conflicting-clips", dry_run=dry_run)
        assert error.value.failure == {
            "http_status": 422, "code": "validation_error",
            "message": "canonical parent clips and config.clips disagree",
            "details": {"status": "refused", "reason": "invalid_closure",
                        "base": None, "current": None, "conflicts": []},
        }
        assert _stored_state(f["service"]) == before


def test_canonical_admission_holds_sqlite_write_fence_during_snapshot_freeze(canonical_scene, monkeypatch):
    f = canonical_scene
    _publish(f)
    store = f["service"].store
    original = store._freeze_managed_render_inputs
    resolved = threading.Event()
    release = threading.Event()
    publishing = threading.Event()

    def pause_after_freeze(*args):
        result = original(*args)
        resolved.set()
        assert release.wait(5), "test did not release admission"
        return result

    monkeypatch.setattr(store, "_freeze_managed_render_inputs", pause_after_freeze)
    # Reuse the admitted service state with a separate DB connection/mutex.
    # No new Runtime session or owner is created by this competing writer.
    publisher = copy.copy(f["service"])
    publisher.store = copy.copy(store)
    publisher.store._mutex = threading.RLock()
    publisher.store.conn = sqlite3.connect(store.db_path, timeout=5, isolation_level=None, check_same_thread=False)
    publisher.store.conn.row_factory = sqlite3.Row
    publisher.store.conn.execute("PRAGMA foreign_keys=ON")
    publisher.store.conn.set_trace_callback(lambda sql: publishing.set() if sql == "BEGIN IMMEDIATE" else None)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            future = pool.submit(f["service"].create_task, _request(f))
            try:
                assert resolved.wait(5), "admission did not freeze canonical parent"
                writer = sqlite3.connect(store.db_path, timeout=0, isolation_level=None)
                try:
                    # A different DB writer cannot publish a new head during freeze.
                    # This checks SQLite fencing independently of the local mutex.
                    with pytest.raises(sqlite3.OperationalError, match="locked"):
                        writer.execute("BEGIN IMMEDIATE")
                finally:
                    writer.close()
                later = {**f, "service": publisher}
                published = pool.submit(_publish, later, revision="parent-2", expected_head="parent-1")
                assert publishing.wait(5), "concurrent publication did not reach its DB fence"
                assert not published.done(), "publication crossed the active admission fence"
            finally:
                release.set()
            admitted = future.result(timeout=5)
            assert published.result(timeout=5)["data"]["new_head"] == "parent-2"
    finally:
        publisher.store.conn.close()
    monkeypatch.setattr(store, "_freeze_managed_render_inputs", original)
    assert admitted["task"]["spec"]["spec"]["inputs"]["timeline_authority"]["parent_revision_id"] == "parent-1"
    _assert_rejected(f, _request(f, key="stale-after-publication"), ConflictError, "head")


def test_canonical_claim_and_retry_keep_snapshot_and_objects_after_later_publication(canonical_scene):
    f = canonical_scene
    service = f["service"]
    _publish(f)
    admitted = service.create_task(_request(f))
    immutable_spec = copy.deepcopy(admitted["task"]["spec"])
    # Later publication points to different real package and entry objects.
    new_html = "<html><body>later scene</body></html>"
    new_entry = service.ingest(f["project"], new_html.encode(), media_type="text/html", idempotency_key="later-entry")["data"]
    later = copy.copy(f)
    later["html"] = new_html
    later["entry"] = new_entry
    body = copy.deepcopy(f["package_body"])
    body["entry"].update(object_id=new_entry["object_id"], digest=new_entry["digest"], size=len(new_html.encode()))
    _set_package(later, body)
    _publish(later, revision="parent-2", expected_head="parent-1")
    epoch = service.health()["runtime_epoch"]
    claim_body = {"executor_id": "worker", "capability_ids": ["rendering.render"], "runtime_epoch": epoch}
    first = service.claim_next(claim_body)
    assert first["task_id"] == admitted["task"]["id"]
    assert first["spec"] == immutable_spec
    assert first["input_object_ids"] == immutable_spec["input_object_ids"]
    assert later["package"]["object_id"] not in first["input_object_ids"]
    service.fail_attempt(first["attempt_id"], {"lease_id": first["lease_id"], "fence": first["fence"], "runtime_epoch": epoch, "error": {"code": "test_retry"}}, idempotency_key="fail")
    service.retry_task(first["task_id"], idempotency_key="retry")
    retried = service.claim_next(claim_body)
    assert retried["task_id"] == first["task_id"]
    assert retried["attempt_id"] != first["attempt_id"]
    assert retried["spec"] == immutable_spec
    assert retried["input_object_ids"] == first["input_object_ids"]
