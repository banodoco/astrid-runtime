"""D101: real native asset captures retain both mirrors through merge and undo."""
from __future__ import annotations

import copy
import os
from pathlib import Path

import pytest
import test_timeline_clip_replacement as native

from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_auth import native_asset_reads


def body(editing, commands, *, reads=None, merge="fields", step_reads=None):
    request = native._native_body(editing.service, editing.project, commands)
    changes = [change for command in commands if command["op"] == "doc.patch"
               for change in command["args"]["changes"]]
    request.update(label="D101 asset union", merge=merge, reads=reads or [], steps=[{
        "id": "asset", "label": "D101 asset union", "intent": "Edit parent media", "tags": [],
        "command_ordinals": list(range(len(commands))), "patch": changes, "reads": step_reads or [],
    }])
    return request


def commit(editing, request, key):
    return native._native_commit(editing.service, editing.project, request, key)


def current(editing):
    return native._native_empty_document(editing.service, editing.project)


def patch(editing, path, value=None, *, remove=False):
    from astrid.sdk.timeline._doc_patch import value_at

    payload = current(editing)["parent_revision"]["payload"]
    change = {"op": "remove" if remove else "set", "ref": "parent", "path": path,
              "before": copy.deepcopy(value_at(payload, "parent", path))}
    if not remove:
        change["value"] = copy.deepcopy(value)
    return {"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
            "args": {"changes": [change]}}


@pytest.fixture(params=["raw", "both"])
def editing(tmp_path, request):
    from types import SimpleNamespace

    api = native._native_imports()
    import astrid.sdk.timeline._commit_patch as producer

    assert Path(producer.__file__).resolve().is_relative_to(Path(os.environ["ASTRID_CHECKOUT"]).resolve())
    RealmStore.initialize(tmp_path / "realm").close()
    service = RuntimeService(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "asset-union", "name": "Asset union"})["id"]
        service.register_timeline_commit_provider(api.load_timeline_commit_provider("astrid"))
        service.create_timeline(project, "film", idempotency_key="create")
        pin, verified = native._native_import_media(service, project, alias="source", kind="image")
        editing = SimpleNamespace(service=service, project=project, api=api, pin=pin, verified=verified)
        track = api.capture_track_create(api.bundle_from_document(current(editing)), "parent", {
            "id": "visual", "kind": "visual"})
        commit(editing, body(editing, [track]), "track")
        commit(editing, body(editing, [patch(editing, ["registry", "opaque"], ["A", "B"])]), "ordered")
        commit(editing, body(editing, [birth(editing, "anchor")]), "anchor")
        if request.param == "both":
            payload = copy.deepcopy(current(editing)["parent_revision"]["payload"])
            payload["config"]["registry"] = copy.deepcopy(payload["registry"])
            commit(editing, body(editing, [patch(editing, [], payload)]), "storage")
        yield editing
    finally:
        service.close()


def birth(editing, identity):
    return editing.api.capture_clip_add_media(
        editing.api.bundle_from_document(current(editing)), {
            "id": identity, "clipType": "image", "asset": editing.pin["asset"],
            "track": "visual", "at": 0, "hold": 1,
        }, editing.pin, verified_media=[editing.verified])


def inverse(editing, result):
    command = {"schema_version": 1, "op": "timeline.inverse", "version": "1", "select": None,
               "args": {"publications": [result["receipt"]["receipt_id"]]}}
    return body(editing, [command])


def clip_note(editing, value):
    from astrid.sdk.timeline._scalar_commands import capture_clip_set_params

    return capture_clip_set_params(editing.api.bundle_from_document(current(editing)),
                                   "parent/clip:anchor", values={"later": [value, None, False]})


@pytest.mark.parametrize("scope", [None, "parent", "timeline", "step-parent", "atomic", "fallback"])
def test_disjoint_clip_merge_and_guarded_undo_preserve_explicit_scopes(editing, scope):
    read = {"kind": "scope", "ref": "parent" if scope == "step-parent" else scope, "path": []}
    request = body(editing, [birth(editing, "new")],
                   reads=[read] if scope in {"parent", "timeline"} else [],
                   step_reads=[read] if scope == "step-parent" else [],
                   merge="atomic" if scope == "atomic" else "fields")
    if scope == "fallback":
        request = body(editing, [patch(editing, ["config", "clips", "id:anchor", "hold"], 2)])
        request.pop("reads")
    commit(editing, body(editing, [clip_note(editing, "later")]), "later")
    before = native._native_rows(editing.service)
    if scope is not None:
        with pytest.raises(RuntimeErrorBase):
            commit(editing, request, "stale")
        assert native._native_rows(editing.service) == before
        return
    result = commit(editing, request, "stale")
    assert result["data"]["status"] == "merged"
    dependencies = result["data"]["steps"][0]["dependencies"]
    assert not any(item["kind"] == "scope" and item["ref"] in {"parent", "timeline"}
                   for item in dependencies)
    commit(editing, body(editing, [clip_note(editing, "after")]), "after")
    undone = commit(editing, inverse(editing, result), "undo")
    rows = undone["data"]["canonical_document"]["parent_revision"]["payload"]["clips"]
    assert [row["id"] for row in rows] == ["anchor"]
    assert rows[0]["params"]["later"] == ["after", None, False]


@pytest.mark.parametrize("mirror", ["raw", "config"])
@pytest.mark.parametrize("mutation", ["value", "null", "type", "add", "remove", "reorder", "registry-null", "registry-type", "registry-remove"])
@pytest.mark.parametrize("phase", ["merge", "undo-aba"])
def test_every_asset_read_mutation_conflicts_or_refuses(editing, mirror, mutation, phase, record_property):
    request = body(editing, [birth(editing, "new")])
    result = commit(editing, request, "source") if phase == "undo-aba" else None
    document = current(editing)
    prefix = ["registry"] if mirror == "raw" else ["config", "registry"]
    payload = document["parent_revision"]["payload"]
    registry = payload.get("registry", payload["config"].get("registry"))
    original = copy.deepcopy(registry)
    changed = copy.deepcopy(registry)
    if mutation == "value":
        changed["assets"][editing.pin["asset"]]["opaque"] = [None, False]
    elif mutation == "null":
        changed["assets"] = None
    elif mutation == "type":
        changed["assets"] = []
    elif mutation == "add":
        changed["assets"]["other"] = copy.deepcopy(changed["assets"][editing.pin["asset"]])
    elif mutation == "remove":
        changed.pop("assets")
    elif mutation == "reorder":
        changed["opaque"] = ["B", "A"]
    elif mutation == "registry-null":
        changed = None
    elif mutation == "registry-type":
        changed = []
    before = native._native_rows(editing.service)
    command = patch(editing, prefix, changed, remove=mutation == "registry-remove")
    if mutation == "add":
        command["created"] = ["parent/asset:other"]
    try:
        commit(editing, body(editing, [command]), "mutation")
    except RuntimeErrorBase as error:
        record_property("protection", "mutation-refused")
        record_property("reason", str(error))
        assert native._native_rows(editing.service) == before
        return  # Contradictory/malformed mirror states are refused by production.
    if phase == "undo-aba":
        commit(editing, body(editing, [patch(editing, prefix, original)]), "restore")
        request = inverse(editing, result)
    before = native._native_rows(editing.service)
    with pytest.raises(RuntimeErrorBase) as guarded_error:
        commit(editing, request, "guard")
    record_property("protection", "history-conflict")
    record_property("reason", str(guarded_error.value))
    assert native._native_rows(editing.service) == before


@pytest.mark.parametrize("mutation", ["absent", "null", "type"])
def test_config_container_mutation_refuses_or_conflicts(editing, mutation, record_property):
    request = body(editing, [birth(editing, "new")])
    before = native._native_rows(editing.service)
    try:
        commit(editing, body(editing, [patch(editing, ["config"],
                                          None if mutation == "null" else [],
                                          remove=mutation == "absent")]), "config-mutation")
    except RuntimeErrorBase as error:
        record_property("protection", "mutation-refused")
        record_property("reason", str(error))
        assert native._native_rows(editing.service) == before
        return
    before = native._native_rows(editing.service)
    with pytest.raises(RuntimeErrorBase):
        commit(editing, request, "stale-config")
    record_property("protection", "history-conflict")
    assert native._native_rows(editing.service) == before


def test_genuine_native_capture_is_retained_with_lossless_union(editing, record_property):
    from astrid.sdk.timeline._command_state import State

    document = current(editing)
    expected = State(editing.api.bundle_from_document(document)).get("parent/collection:asset", [])
    result = commit(editing, body(editing, [birth(editing, "new")]), "capture")
    history = editing.service.list_timeline_commits(editing.project, "film", authorize=lambda: None)
    entry = next(item for item in history["items"] if item["publication_id"] == result["receipt"]["receipt_id"])
    captures = [read for command in entry["records"]["commands"] for read in command["reads"]
                if read["ref"] == "parent/collection:asset"]
    assert captures == [{"ref": "parent/collection:asset", "path": [], "state": expected}]
    dependencies = entry["records"]["steps"][0]["dependencies"]
    for read in native_asset_reads(document["parent_revision"]["payload"]):
        assert read in dependencies
    record_property("native_capture", repr(captures))
    record_property("dependency_union", repr(dependencies))


@pytest.mark.parametrize("config", ["absent", None, False, [], {}, {"registry": None},
                                    {"registry": {"assets": ["B", "A"]}}])
def test_physical_projection_preserves_container_tags_and_both_mirrors(config):
    from astrid.sdk.timeline._commit_patch import native_asset_reads as agent_reads

    payload = {"registry": {"assets": {"a": None}, "opaque": [False, None]}}
    if config != "absent":
        payload["config"] = config
    reads = native_asset_reads(payload)
    assert reads == agent_reads(payload)
    assert reads[0]["path"] == ["registry"]
    assert reads[0]["state"]["value"] == payload["registry"]
    assert reads[1]["path"] == (["config", "registry"] if isinstance(config, dict) else ["config"])
