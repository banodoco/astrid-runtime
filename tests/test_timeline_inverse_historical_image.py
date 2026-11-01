"""Reopening a retired foreign closure uses the exact accepted inverse image."""
from __future__ import annotations

import copy
import functools
import inspect

import pytest

from runtime_protocol import timeline_commit_auth as auth
from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_provider import load_timeline_commit_provider
from runtime_protocol.timeline_commit_validation import digest

pytestmark = pytest.mark.integration


@pytest.fixture
def historical_image(tmp_path, astrid_importable, monkeypatch):
    from astrid.sdk.timeline.capture import capture_track_create
    from astrid.sdk.timeline.commit import bundle_from_document
    from astrid.sdk.timeline.native_occurrence_create import capture_occurrence_create
    from astrid.sdk.timeline.native_occurrence_shared import foreign_shared_command

    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    runtime = RuntimeService(root)
    assert runtime.store.conn is not None
    runtime.register_timeline_commit_provider(load_timeline_commit_provider("astrid"))
    project = runtime.create_project({"slug": "historical-image", "name": "Historical image"})["id"]
    for timeline in ("origin", "target"):
        runtime.create_timeline(project, timeline, idempotency_key="bootstrap-" + timeline)

    def document(timeline):
        head = runtime.get_project_timeline(project, timeline)
        value = runtime._timeline_commits()[0].revision_closure(project, timeline, head["head_revision_id"])
        assert value is not None
        return value

    def request(call):
        head = runtime.get_project_timeline(project, "target")
        return {"api_version": 1, "project_id": project, "timeline_id": "target",
                "base_revision_id": head["head_revision_id"], "base_publication_id": head["head_publication_id"],
                "commands": [call], "label": "Historical image", "merge": "atomic", "reads": [],
                "steps": [{"id": "owner-boundary", "label": "Historical image", "intent": "Reopen",
                           "tags": [], "command_ordinals": [0], "patch": []}]}

    def commit(timeline, body, key):
        return runtime.commit_timeline(project, timeline, body, idempotency_key=key, publisher="editor",
            invocation_path=f"/v1/projects/{project}/timelines/{timeline}/commit", authorize=lambda: None)

    def inverse(result):
        return {"schema_version": 1, "op": "timeline.inverse", "version": "1", "select": None,
                "args": {"publications": [result["receipt"]["receipt_id"]]}}

    try:
        for timeline in ("origin", "target"):
            body = request(capture_track_create(bundle_from_document(document(timeline)), "parent",
                                               {"id": "visual", "kind": "visual"}))
            head = runtime.get_project_timeline(project, timeline)
            body.update(timeline_id=timeline, base_revision_id=head["head_revision_id"],
                        base_publication_id=head["head_publication_id"])
            commit(timeline, body, "track-" + timeline)
        body = request(capture_occurrence_create(bundle_from_document(document("origin")),
            "source-owner", "physical-shot", name="Bounded", track="visual", on=0, duration=7))
        head = runtime.get_project_timeline(project, "origin")
        body.update(timeline_id="origin", base_revision_id=head["head_revision_id"],
                    base_publication_id=head["head_publication_id"])
        born = commit("origin", body, "birth")
        source = document("origin")
        parent = source["parent_revision"]
        source_ref = {"project_id": project, "timeline_id": "origin", "revision_id": parent["revision_id"],
                      "publication_id": born["receipt"]["receipt_id"], "content_digest": parent["content_digest"]}
        before = document("target")
        placed = commit("target", request(foreign_shared_command(source_ref, "source-owner", "return-owner", on=9)),
                        "place")
        after = document("target")
        undone = commit("target", request(inverse(placed)), "undo")
        assert document("target") == before
        body = request(inverse(undone))
        packets = []
        original = auth.validate

        @functools.wraps(original)
        def capture(*args, **kwargs):
            bound = inspect.signature(original).bind(*args, **kwargs)
            bound.apply_defaults()
            if bound.arguments["request"] == body:
                packets.append(copy.deepcopy(bound.arguments))
            return original(*args, **kwargs)

        monkeypatch.setattr(auth, "validate", capture)
        yield runtime, document, commit, body, source, after, packets
    finally:
        runtime.close()


def _stored(runtime):
    files = {str(path): path.read_bytes() for root in (runtime.store.cas_root, runtime.store.staging_root)
             for path in root.rglob("*") if path.is_file()}
    return tuple(runtime.store.conn.iterdump()), files


def test_redo_reopens_exact_retired_images_with_one_native_write(historical_image):
    runtime, document, commit, body, source, after, packets = historical_image
    before = _stored(runtime)
    preview = commit("target", {**body, "dry_run": True}, "preview")
    assert preview["receipt"] is None
    assert _stored(runtime) == before
    restored = commit("target", body, "restore")
    assert document("target") == after == restored["data"]["canonical_document"]
    assert document("origin") == source
    stored = _stored(runtime)
    assert commit("target", body, "restore") == restored
    assert _stored(runtime) == stored
    packet = packets[-1]
    record = packet["prepared"]["records"]["commands"][0]
    assert len(record["writes"]) == 1
    stage = next(binding["boundary"] for binding in record["bindings"] if binding["key"] == "inverse.stage")
    assert stage["native_write_range"] == [0, 1]
    assert stage["effect_range"] == [0, 3]
    original = copy.deepcopy(packet)
    auth.validate(**packet)
    assert packet == original


@pytest.mark.parametrize("damage", ["native-count", "native-value", "range", "effect-count", "effect-payload",
                                     "physical-pin", "owners", "source-payload", "source-pin", "source-owners",
                                     "source-range", "coherent-image"])
def test_redo_rejects_changed_native_effect_and_source_images(historical_image, monkeypatch, damage):
    runtime, _, commit, body, _, _, packets = historical_image
    before = _stored(runtime)
    original = auth.validate

    def attack(*args, **kwargs):
        bound = inspect.signature(original).bind(*args, **kwargs)
        bound.apply_defaults()
        packet = copy.deepcopy(bound.arguments)
        if packet["request"] != body:
            return original(*args, **kwargs)
        prepared = packet["prepared"]
        record = prepared["records"]["commands"][0]
        stage = next(binding["boundary"] for binding in record["bindings"] if binding["key"] == "inverse.stage")
        source = next(iter(packet["history"].values()))["records"]
        if damage == "native-count":
            record["writes"].append(copy.deepcopy(record["writes"][0]))
            stage["native_write_range"] = [0, 2]
        elif damage == "native-value":
            record["writes"][0]["after"]["value"]["duration_ms"] += 1
        elif damage == "range":
            stage["effect_range"] = [0, 2]
        elif damage == "effect-count":
            prepared["records"]["steps"][0]["patch"].pop(0)
            stage["effect_range"] = [0, 2]
        elif damage == "effect-payload":
            prepared["records"]["steps"][0]["patch"][0]["value"]["opaque"] = "forged"
        elif damage == "coherent-image":
            effect = prepared["records"]["steps"][0]["patch"][0]
            effect["value"]["opaque"] = "forged"
            image = prepared["canonical_document"]["internal_timeline_revisions"][0]
            image["payload"] = copy.deepcopy(effect["value"])
            image["content_digest"] = digest(image["payload"])
            for binding in record["bindings"]:
                if binding.get("physical_ref") == effect["ref"]:
                    binding["content_digest"] = image["content_digest"]
        elif damage in {"physical-pin", "owners"}:
            binding = next(item for item in record["bindings"] if "owners" in item)
            binding["revision_id" if damage == "physical-pin" else "owners"] = (
                "foreign" if damage == "physical-pin" else ["occurrence:foreign/shot"])
        elif damage == "source-payload":
            source["steps"][0]["patch"][-1]["before"]["value"]["opaque"] = "forged"
        elif damage == "source-pin":
            next(item for item in source["commands"][0]["bindings"]
                 if item.get("owners"))["content_digest"] = "sha256:" + "0" * 64
        elif damage == "source-owners":
            next(item for item in source["commands"][0]["bindings"]
                 if item.get("owners"))["owners"] = ["occurrence:foreign/shot"]
        elif damage == "source-range":
            source["commands"][0]["bindings"][0]["boundary"]["native_write_range"] = [0, 2]
        prepared["document_digest"] = digest(prepared["canonical_document"])
        untouched = copy.deepcopy(packet)
        try:
            original(**packet)
        except CommitRejected:
            assert packet == untouched
            raise
        raise AssertionError("changed inverse was accepted")

    monkeypatch.setattr(auth, "validate", attack)
    with pytest.raises(RuntimeErrorBase):
        commit("target", body, "attack")
    assert packets
    assert _stored(runtime) == before
