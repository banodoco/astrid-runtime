"""Grouped inverses retain sequential physical sites after removing their owners."""
from __future__ import annotations

import copy

import pytest
import test_timeline_forward_created_authority as forward_tests
from test_timeline_commit_port import commit

from runtime_protocol import timeline_commit_auth as auth
from runtime_protocol.timeline_commit import CommitRejected

runtime = forward_tests.runtime
pytestmark = pytest.mark.integration


@pytest.fixture
def grouped_inverse(runtime, monkeypatch):
    from astrid.sdk.timeline.capture import capture_track_create
    from astrid.sdk.timeline.commands import execute
    from astrid.sdk.timeline.commit import bundle_from_document
    from astrid.sdk.timeline.native_occurrence_create import capture_occurrence_create

    commit(runtime, forward_tests.body(runtime, forward_tests.command()), key="parent-track")
    head = runtime.get_project_timeline(runtime.test_project, "main")
    initial = runtime._timeline_commits()[0].revision_closure(
        runtime.test_project, "main", head["head_revision_id"])
    bundle = bundle_from_document(initial)
    birth = capture_occurrence_create(bundle, "child", "child-shot", name="Child",
                                      track="stable-track", on=0, duration=10)
    child = capture_track_create(execute(bundle, [birth]).bundle, "occurrence:child",
                                 {"id": "one", "kind": "visual"})
    request = forward_tests.body(runtime, birth)
    request["commands"] = [birth, child]
    request["steps"][0]["command_ordinals"] = [0, 1]
    created = commit(runtime, request, key="grouped-birth")
    packet = {}
    validate = auth.validate

    def capture(request, prepared, source, base=None, continuations=None, history=None, sequential=None):
        packet.update(copy.deepcopy({"request": request, "prepared": prepared, "source": source,
                                     "base": base, "continuations": continuations, "history": history,
                                     "sequential": sequential}))
        return validate(request, prepared, source, base, continuations, history, sequential)

    monkeypatch.setattr(auth, "validate", capture)
    inverse = {"schema_version": 1, "op": "timeline.inverse", "version": "1", "select": None,
               "args": {"publications": [created["receipt"]["receipt_id"]]}}
    restored = commit(runtime, forward_tests.body(runtime, inverse), key="grouped-undo")
    assert restored["data"]["canonical_document"] == initial
    monkeypatch.setattr(auth, "validate", validate)
    return packet


def test_grouped_inverse_removes_alias_only_after_its_child_write(grouped_inverse):
    packet = grouped_inverse
    before = copy.deepcopy(packet)
    record = packet["prepared"]["records"]["commands"][0]
    assert [(write["ref"], write["path"]) for write in record["writes"]] == [
        ("occurrence:child/track:one", []), ("occurrence:child", []), ("shot:child-shot", [])]
    assert record["writes"][0]["before"] == {
        "state": "present", "value": {"id": "one", "kind": "visual"}}
    assert record["writes"][0]["after"] == {"state": "absent"}
    output = packet["prepared"]["canonical_document"]
    assert output["parent_revision"]["payload"]["occurrences"] == []
    assert output["shot_revisions"] == output["internal_timeline_revisions"] == []
    auth.validate(**packet)
    assert packet == before


@pytest.mark.parametrize("damage", [
    "before", "after", "ref", "path", "order", "missing-write", "range", "publication", "step",
    "ordinal", "effect-pin", "owners", "digest", "physical-source", "source-edge", "ghost-owner",
    "effect-coverage", "source-membership",
])
def test_removed_alias_still_requires_exact_sequential_authority(grouped_inverse, runtime, damage):
    packet = copy.deepcopy(grouped_inverse)
    prepared = packet["prepared"]
    records = prepared["records"]
    record = records["commands"][0]
    stage = next(binding for binding in record["bindings"] if binding["key"] == "inverse.stage")
    pins = [binding for binding in record["bindings"]
            if binding["key"] == "commit.effect" and binding["physical_ref"].startswith("internal-revision:")]
    if damage == "before":
        record["writes"][0]["before"]["value"]["kind"] = "audio"
    elif damage == "after":
        record["writes"][0]["after"] = copy.deepcopy(record["writes"][0]["before"])
    elif damage in {"ref", "path"}:
        record["writes"][0][damage] = "occurrence:foreign/track:one" if damage == "ref" else ["kind"]
    elif damage == "order":
        record["writes"][0], record["writes"][1] = record["writes"][1], record["writes"][0]
    elif damage == "missing-write":
        record["writes"].pop(0)
        stage["boundary"]["native_write_range"][1] -= 1
    elif damage in {"range", "publication", "step", "ordinal"}:
        key, value = {"range": ("native_write_range", [1, 3]),
                      "publication": ("publication_id", "foreign"), "step": ("step_id", "foreign"),
                      "ordinal": ("command_ordinals", [1])}[damage]
        stage["boundary"][key] = value
    elif damage == "effect-pin":
        record["bindings"].remove(pins[0])
    elif damage == "owners":
        pins[0]["owners"] = ["occurrence:foreign/shot"]
    elif damage == "digest":
        pins[0]["content_digest"] = "sha256:" + "0" * 64
    elif damage == "physical-source":
        pins[0]["physical_ref"] = pins[0]["ref"] = "internal-revision:foreign"
    elif damage == "source-edge":
        packet["source"]["shot_revisions"][0]["internal_timeline_revision_id"] = "foreign"
    elif damage == "ghost-owner":
        prepared["canonical_document"]["parent_revision"]["payload"]["occurrences"] = copy.deepcopy(
            packet["source"]["parent_revision"]["payload"]["occurrences"])
    elif damage == "effect-coverage":
        records["steps"][0]["patch"].pop()
    else:
        entry = packet["history"][stage["boundary"]["publication_id"]]
        entry["records"]["commands"][1]["writes"][0]["ref"] = "occurrence:foreign/track:one"
    before = copy.deepcopy(packet)
    durable = tuple(runtime.store.conn.iterdump())
    with pytest.raises(CommitRejected):
        auth.validate(**packet)
    assert packet == before
    assert tuple(runtime.store.conn.iterdump()) == durable
