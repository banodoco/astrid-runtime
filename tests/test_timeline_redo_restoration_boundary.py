"""Redo reads guard absent owners before authenticated sequential restoration."""
from __future__ import annotations

import copy

import pytest
import test_timeline_forward_created_authority as forward_tests
import test_timeline_inverse_removed_alias_boundary as inverse_tests
from test_timeline_commit_port import commit

from runtime_protocol import timeline_commit_auth as auth
from runtime_protocol.timeline_commit import CommitRejected

runtime = forward_tests.runtime
grouped_inverse = inverse_tests.grouped_inverse
pytestmark = pytest.mark.integration


@pytest.fixture
def grouped_redo(runtime, grouped_inverse, monkeypatch):
    head = runtime.get_project_timeline(runtime.test_project, "main")
    inverse = {"schema_version": 1, "op": "timeline.inverse", "version": "1", "select": None,
               "args": {"publications": [head["head_publication_id"]]}}
    packet = {}
    validate = auth.validate

    def capture(request, prepared, source, base=None, continuations=None, history=None, sequential=None):
        packet.update(copy.deepcopy({"request": request, "prepared": prepared, "source": source,
                                     "base": base, "continuations": continuations, "history": history,
                                     "sequential": sequential}))
        return validate(request, prepared, source, base, continuations, history, sequential)

    monkeypatch.setattr(auth, "validate", capture)
    request = forward_tests.body(runtime, inverse)
    durable = tuple(runtime.store.conn.iterdump())
    preview = commit(runtime, {**request, "dry_run": True}, key="grouped-redo-preview")
    assert preview["receipt"] is None and preview["data"]["status"] == "preview"
    assert preview["data"]["canonical_document"] == grouped_inverse["source"]
    assert tuple(runtime.store.conn.iterdump()) == durable
    restored = commit(runtime, request, key="grouped-redo")
    assert restored["data"]["canonical_document"] == grouped_inverse["source"]
    durable = tuple(runtime.store.conn.iterdump())
    assert commit(runtime, request, key="grouped-redo") == restored
    assert tuple(runtime.store.conn.iterdump()) == durable
    monkeypatch.setattr(auth, "validate", validate)
    return packet


def test_redo_restores_aggregate_before_child_while_reads_keep_input_absence(grouped_redo):
    packet = grouped_redo
    before = copy.deepcopy(packet)
    record = packet["prepared"]["records"]["commands"][0]
    read = next(read for read in record["reads"] if read["ref"] == "occurrence:child/collection:track")
    assert read == {"ref": "occurrence:child/collection:track", "path": [], "state": {"state": "absent"}}
    assert packet["source"]["parent_revision"]["payload"]["occurrences"] == []
    assert [write["ref"] for write in record["writes"]] == [
        "shot:child-shot", "occurrence:child", "occurrence:child/track:one"]
    assert record["writes"][0]["after"]["value"]["internal_timeline"]["tracks"] == []
    assert record["writes"][2]["before"] == {"state": "absent"}
    assert packet["prepared"]["canonical_document"]["internal_timeline_revisions"][0]["payload"]["tracks"] == [
        {"id": "one", "kind": "visual"}]
    auth.validate(**packet)
    assert packet == before


@pytest.mark.parametrize("damage", [
    "read-present", "read-owner", "read-physical", "read-family", "read-path",
    "owner-claim", "owner-guard", "root-before",
    "root-after", "child-before", "child-after", "child-ref", "child-path", "order", "member",
    "aba", "range", "effect-range", "publication", "step", "ordinal", "pair", "base-pair",
    "source-member", "source-root", "source-effect", "source-range", "effect-pin", "pin-owner",
    "pin-digest", "pin-physical", "pin-edge", "final-closure",
])
def test_redo_requires_exact_source_restoration_and_absent_owner_guard(grouped_redo, runtime, damage):
    packet = copy.deepcopy(grouped_redo)
    prepared = packet["prepared"]
    records = prepared["records"]
    record = records["commands"][0]
    stage = next(binding for binding in record["bindings"] if binding["key"] == "inverse.stage")
    source = packet["history"][stage["boundary"]["publication_id"]]["records"]
    read = next(read for read in record["reads"] if read["ref"] == "occurrence:child/collection:track")
    pin = next(binding for binding in record["bindings"] if binding["key"] == "commit.effect"
               and binding["physical_ref"].startswith("internal-revision:"))
    if damage == "read-present":
        read["state"] = {"state": "present", "value": []}
    elif damage in {"read-owner", "read-physical"}:
        read["ref"] = ("occurrence:foreign/collection:track" if damage == "read-owner"
                       else "internal-revision:foreign")
    elif damage == "read-family":
        read["ref"] = "occurrence:child/collection:foreign"
    elif damage == "read-path":
        read["path"] = ["foreign"]
    elif damage == "owner-claim":
        record["created"] = [item for item in record["created"] if item["ref"] != "occurrence:child"]
    elif damage == "owner-guard":
        records["steps"][0]["dependencies"] = [
            dependency for dependency in records["steps"][0]["dependencies"]
            if dependency["ref"] != "parent" or dependency["path"] not in (
                [], ["occurrences", "occurrence_id:child"])]
    elif damage == "root-before":
        record["writes"][0]["before"] = copy.deepcopy(record["writes"][0]["after"])
    elif damage == "root-after":
        record["writes"][0]["after"]["value"]["internal_timeline"]["tracks"] = [
            {"id": "one", "kind": "visual"}]
    elif damage in {"child-before", "child-after"}:
        record["writes"][2][damage.removeprefix("child-")] = {"state": "absent"} if (
            damage == "child-after") else copy.deepcopy(record["writes"][2]["after"])
    elif damage in {"child-ref", "child-path"}:
        record["writes"][2][damage.removeprefix("child-")] = (
            "occurrence:foreign/track:one" if damage == "child-ref" else ["kind"])
    elif damage == "order":
        record["writes"][0], record["writes"][2] = record["writes"][2], record["writes"][0]
    elif damage == "member":
        record["writes"].pop()
        stage["boundary"]["native_write_range"][1] -= 1
    elif damage == "aba":
        write = copy.deepcopy(record["writes"][2])
        record["writes"].extend([{**write, "before": write["after"], "after": write["before"]}, write])
        stage["boundary"]["native_write_range"][1] += 2
    elif damage in {"range", "effect-range", "publication", "step", "ordinal"}:
        key, value = {"range": ("native_write_range", [1, 3]), "effect-range": ("effect_range", [1, 3]),
                      "publication": ("publication_id", "foreign"), "step": ("step_id", "foreign"),
                      "ordinal": ("command_ordinals", [1])}[damage]
        stage["boundary"][key] = value
    elif damage == "pair":
        prepared["expected_head"]["publication_id"] = "foreign"
    elif damage == "base-pair":
        packet["request"]["base_publication_id"] = "foreign"
    elif damage == "source-member":
        source["commands"][0]["writes"][0]["ref"] = "occurrence:foreign/track:one"
    elif damage == "source-root":
        source["commands"][0]["writes"][2]["before"]["value"]["internal_timeline"]["tracks"] = [
            {"id": "one", "kind": "visual"}]
    elif damage == "source-effect":
        source["steps"][0]["patch"][0]["before"] = {"state": "absent"}
    elif damage == "source-range":
        next(binding for binding in source["commands"][0]["bindings"]
             if binding["key"] == "inverse.stage")["boundary"]["native_write_range"] = [1, 3]
    elif damage == "effect-pin":
        record["bindings"].remove(pin)
    elif damage == "pin-owner":
        pin["owners"] = ["occurrence:foreign/shot"]
    elif damage == "pin-digest":
        pin["content_digest"] = "sha256:" + "0" * 64
    elif damage == "pin-physical":
        pin["physical_ref"] = pin["ref"] = "internal-revision:foreign"
    elif damage == "pin-edge":
        prepared["canonical_document"]["shot_revisions"][0]["internal_timeline_revision_id"] = "foreign"
    else:
        prepared["canonical_document"]["parent_revision"]["payload"]["occurrences"] = []
    before = copy.deepcopy(packet)
    durable = tuple(runtime.store.conn.iterdump())
    with pytest.raises(CommitRejected):
        auth.validate(**packet)
    assert packet == before
    assert tuple(runtime.store.conn.iterdump()) == durable
