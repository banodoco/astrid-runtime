"""Whole-closure inverse captures through the supported production provider."""
from __future__ import annotations

import copy

import pytest
import test_timeline_forward_created_authority as forward_tests
from test_timeline_commit_port import commit

from runtime_protocol import timeline_commit_auth as auth
from runtime_protocol.timeline_commit import CommitRejected

body = forward_tests.body
command = forward_tests.command
runtime = forward_tests.runtime


@pytest.mark.parametrize("restore", [False, True], ids=["native-delete", "whole-restore"])
@pytest.mark.parametrize("v2", [False, True], ids=["legacy", "v2"])
def test_inverse_sequential_scope_round_trip(runtime, restore, v2):
    revision = runtime.get_project_timeline(runtime.test_project, "main")["head_revision_id"]
    initial = runtime._timeline_commits()[0].revision_closure(runtime.test_project, "main", revision)
    created = commit(runtime, body(runtime, command(), v2=v2), key="create")
    inverse = {"schema_version": 1, "op": "timeline.inverse", "version": "1", "select": None,
               "args": {"publications": [created["receipt"]["receipt_id"]]}}
    call = ({"schema_version": 1, "op": "timeline.restore", "version": "1", "select": None,
             "args": {key: initial["parent_revision"][key] for key in ("revision_id", "content_digest")}}
            if restore else inverse)
    emptied = commit(runtime, body(runtime, call, v2=v2), key="empty")
    assert emptied["data"]["canonical_document"]["parent_revision"]["payload"]["config"]["tracks"] == []
    inverse["args"]["publications"] = [emptied["receipt"]["receipt_id"]]
    request = body(runtime, inverse, v2=v2)
    if restore:
        before = tuple(runtime.store.conn.iterdump())
        preview = commit(runtime, {**copy.deepcopy(request), "dry_run": True}, key="preview")
        assert preview["data"]["status"] == "preview" and preview["data"]["would_status"] == "accepted"
        assert preview["receipt"] is None and tuple(runtime.store.conn.iterdump()) == before
    restored = commit(runtime, request, key="undo-empty")
    assert restored["data"]["canonical_document"] == created["data"]["canonical_document"]
    assert commit(runtime, copy.deepcopy(request), key="undo-empty") == restored
    if restore:
        inverse["args"]["publications"] = [restored["receipt"]["receipt_id"]]
        redone = commit(runtime, body(runtime, inverse, v2=v2), key="redo-empty")
        assert redone["data"]["canonical_document"] == emptied["data"]["canonical_document"]


@pytest.fixture
def restore_inverse(runtime, monkeypatch):
    captured = []
    boundaries = auth._inverse_stage_boundaries

    def capture(*args, **kwargs):
        if any(record["command"]["op"] == "timeline.inverse" and write["ref"] == "timeline"
               for record in args[3]["commands"] for write in record["writes"]):
            captured.append(copy.deepcopy(args))
        return boundaries(*args, **kwargs)

    monkeypatch.setattr(auth, "_inverse_stage_boundaries", capture)
    test_inverse_sequential_scope_round_trip(runtime, restore=True, v2=True)
    assert captured
    # First inverse of the restore, before the inherited redo stage.
    return captured[0]


@pytest.mark.parametrize("mutation", [
    "before-revision", "before-digest", "before-state", "after-revision", "after-digest", "after-state",
    "path", "extra-write", "source-before", "source-after", "source-ref", "source-path", "source-extra",
    "missing-history", "publication", "step", "command-range", "native-range", "effect-range",
    "effect-value", "missing-effect-pin", "source-effect-value", "source-effect-op", "transient-root",
])
def test_restore_inverse_refuses_inexact_sequential_authority(restore_inverse, mutation):
    boundary, output, step, records, accepted, original, history = copy.deepcopy(restore_inverse)
    record = records["commands"][0]
    write = record["writes"][0]
    stage = next(binding for binding in record["bindings"] if binding["key"] == "inverse.stage")
    source = history[stage["boundary"]["publication_id"]]["records"]["commands"][0]
    if mutation.startswith(("before-", "after-")):
        side, field = mutation.split("-")
        if field == "state":
            write[side] = {"state": "absent"}
        else:
            write[side]["value"]["revision_id" if field == "revision" else "content_digest"] = "foreign"
    elif mutation == "path":
        write["path"] = ["config"]
    elif mutation == "extra-write":
        record["writes"].append(copy.deepcopy(write))
        stage["boundary"]["native_write_range"][1] += 1
    elif mutation.startswith("source-"):
        field = mutation.removeprefix("source-")
        if field == "effect-value":
            source_step = next(item for item in next(iter(history.values()))["records"]["steps"]
                               if item["id"] == stage["boundary"]["step_id"])
            source_step["patch"][0]["before"]["value"][0]["opaque"] = [None, True]
        elif field == "effect-op":
            next(iter(history.values()))["records"]["steps"][0]["patch"][0]["op"] = "list.move"
        elif field == "extra":
            source["writes"].append(copy.deepcopy(source["writes"][0]))
        elif field in {"before", "after"}:
            source["writes"][0][field]["value"]["revision_id"] = "foreign"
        else:
            source["writes"][0][field] = "parent" if field == "ref" else ["config"]
    elif mutation == "missing-history":
        history.clear()
    elif mutation in {"publication", "step"}:
        stage["boundary"][mutation + "_id"] = "foreign"
    elif mutation.endswith("-range"):
        field = {"command-range": "command_ordinals", "native-range": "native_write_range",
                 "effect-range": "effect_range"}[mutation]
        stage["boundary"][field] = [1, 2]
    elif mutation == "effect-value":
        step["patch"][0]["value"][0]["opaque"] = [None, True]
    elif mutation == "transient-root":
        step["patch"].extend([
            {"op": "set", "ref": "internal-revision:forged", "path": [],
             "before": {"state": "absent"}, "value": {"forged": True}},
            {"op": "remove", "ref": "internal-revision:forged", "path": [],
             "before": {"state": "present", "value": {"forged": True}}},
        ])
        stage["boundary"]["effect_range"][1] += 2
    else:
        record["bindings"] = [binding for binding in record["bindings"] if binding["key"] != "commit.effect"]
    args = (boundary, output, step, records, accepted, original, history)
    before = copy.deepcopy(args)
    with pytest.raises(CommitRejected) as error:
        auth._inverse_stage_boundaries(*args)
    if mutation == "transient-root":
        assert str(error.value) == "inverse stage timeline effects differ from authenticated source history"
    assert args == before
