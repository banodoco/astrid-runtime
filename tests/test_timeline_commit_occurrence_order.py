"""Occurrence order observations cannot replace authenticated physical rows."""
from __future__ import annotations

import copy

import pytest

from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_auth import command_output, step_output
from runtime_protocol.timeline_commit_validation import digest


def _order_case():
    rows = [{"occurrence_id": identity, "shot_id": "shot-" + identity,
             "shot_revision_id": "revision-" + identity, "placement": {"start_ms": index * 1000},
             "extension": {"opaque": [None, False, {"keep": identity}]}}
            for index, identity in enumerate(["first", "middle", "last"])]
    parent = {"occurrences": rows, "extension": {"keep": True}}
    boundary = {"parent": {"revision_id": "before", "content_digest": digest(parent), "payload": parent}}
    for row in rows:
        internal = "internal-" + row["occurrence_id"]
        payload = {"internal_timeline_revision_id": internal}
        boundary["shot-revision:" + row["shot_revision_id"]] = {
            "revision_id": row["shot_revision_id"], "shot_id": row["shot_id"],
            "internal_timeline_revision_id": internal, "content_digest": digest(payload), "payload": payload}
        boundary["internal-revision:" + internal] = {
            "revision_id": internal, "timeline_id": row["shot_id"], "payload": {}, "content_digest": digest({})}
    change = {"op": "list.move", "ref": "parent", "path": ["occurrences"],
              "id": "last", "after_id": None, "order_before": [row["occurrence_id"] for row in rows],
              "before": {"state": "present", "value": copy.deepcopy(rows[-1])}}
    authored = [{key: copy.deepcopy(value) for key, value in row.items() if key != "shot_revision_id"}
                for row in rows]
    capture = {"ref": "parent", "path": ["occurrences"],
               "before": {"state": "present", "value": authored},
               "after": {"state": "present", "value": copy.deepcopy([authored[2], authored[0], authored[1]])}}
    binding = {"key": "doc.patch:0", "physical_ref": "parent", "path": ["occurrences"],
               "change": copy.deepcopy(change), "write_range": [0, 1],
               "boundary": {"change_ordinal": 0}}
    record = {"command": {"op": "doc.patch", "args": {"changes": [copy.deepcopy(change)]}},
              "writes": [capture], "derived_writes": [], "bindings": [binding]}
    accepted = copy.deepcopy(boundary)
    accepted["parent"]["payload"]["occurrences"] = copy.deepcopy([rows[2], rows[0], rows[1]])
    accepted["parent"]["content_digest"] = digest(accepted["parent"]["payload"])
    accepted["parent"]["revision_id"] = "after"
    following = {"bindings": [{"physical_ref": "parent", "revision_id": "after",
                               "content_digest": accepted["parent"]["content_digest"],
                               "boundary": {"phase": "input"}}]}
    step = {"command_ordinals": [0], "patch": [change]}
    return boundary, step, record, accepted, following


@pytest.mark.parametrize("projection", ["step", "command"])
def test_occurrence_order_projects_exact_physical_rows(projection):
    boundary, step, record, accepted, following = _order_case()
    original = copy.deepcopy(boundary)
    if projection == "step":
        result = step_output(boundary, step, {"commands": [record]}, accepted)
    else:
        result = command_output(boundary, record, following)
    assert result == accepted
    assert boundary == original


@pytest.mark.parametrize("projection", ["step", "command"])
@pytest.mark.parametrize("damage", [
    "missing", "duplicate", "foreign", "owner", "value", "pin", "input-pin", "stale-order",
    "unbound-order", "unbound-move", "wrong-range", "wrong-change", "wrong-physical-owner",
    "sealed-order", "sealed-pin", "sealed-value", "sealed-anchor",
    "added", "forged-pin", "physical-pin", "opaque", "wrong-landing", "bound-order", "sealed-id",
])
def test_occurrence_order_rejects_forged_collection_observations(projection, damage):
    boundary, step, record, accepted, following = _order_case()
    capture = record["writes"][0]
    rows = capture["after"]["value"]
    if damage == "missing":
        rows.pop()
    elif damage == "duplicate":
        rows[1] = copy.deepcopy(rows[0])
    elif damage == "foreign":
        rows[0]["occurrence_id"] = "foreign"
    elif damage == "owner":
        rows[0]["shot_id"] = "shot-first"
    elif damage == "value":
        rows[0]["placement"]["start_ms"] = 9000
    elif damage in {"pin", "input-pin"}:
        target = rows if damage == "pin" else capture["before"]["value"]
        target[0]["shot_revision_id"] = "revision-first"
    elif damage == "stale-order":
        capture["before"]["value"].reverse()
    elif damage == "unbound-order":
        rows.reverse()
    elif damage == "unbound-move":
        record["bindings"][0]["change"]["after_id"] = "first"
    elif damage == "wrong-range":
        record["bindings"][0]["write_range"] = [0, 0]
    elif damage == "wrong-change":
        record["bindings"][0]["boundary"]["change_ordinal"] = 1
    elif damage == "wrong-physical-owner":
        boundary["shot-revision:revision-last"]["shot_id"] = "shot-first"
    elif damage == "physical-pin":
        boundary["parent"]["payload"]["occurrences"][0]["shot_revision_id"] = "revision-forged"
    elif damage == "forged-pin":
        rows[0]["shot_revision_id"] = "revision-forged"
    elif damage == "added":
        rows.append({"occurrence_id": "extra", "shot_id": "shot-extra", "shot_revision_id": "revision-extra",
                     "placement": {"start_ms": 9000}, "extension": {"opaque": []}})
    elif damage == "opaque":
        rows[0]["extension"]["opaque"][2]["keep"] = "changed"
    elif damage == "wrong-landing":
        rows[0], rows[1] = rows[1], rows[0]
    elif damage == "bound-order":
        record["bindings"][0]["change"]["order_before"].reverse()
    else:
        for change in (step["patch"][0], record["command"]["args"]["changes"][0],
                       record["bindings"][0]["change"]):
            if damage == "sealed-order":
                change["order_before"].reverse()
            elif damage == "sealed-pin":
                change["before"]["value"]["shot_revision_id"] = "revision-first"
            elif damage == "sealed-value":
                change["before"]["value"]["placement"]["start_ms"] = 9000
            elif damage == "sealed-id":
                change["id"] = "first"
            else:
                change["after_id"] = "first"
    original = copy.deepcopy(boundary)
    with pytest.raises(CommitRejected):
        if projection == "step":
            step_output(boundary, step, {"commands": [record]}, accepted)
        else:
            command_output(boundary, record, following)
    assert boundary == original


@pytest.mark.parametrize("projection", ["step", "command"])
def test_occurrence_order_observes_an_earlier_timing_edit(projection):
    boundary, step, record, accepted, following = _order_case()
    path = ["occurrences", "occurrence_id:last", "placement", "start_ms"]
    timing = {"op": "set", "ref": "parent", "path": path,
              "before": {"state": "present", "value": 2000}, "value": 9000}
    for state in (record["writes"][0]["before"], record["writes"][0]["after"]):
        next(row for row in state["value"] if row["occurrence_id"] == "last")["placement"]["start_ms"] = 9000
    for change in (step["patch"][0], record["command"]["args"]["changes"][0],
                   record["bindings"][0]["change"]):
        change["before"]["value"]["placement"]["start_ms"] = 9000
    record["writes"].insert(0, {"ref": "parent", "path": path, "before": timing["before"],
                                "after": {"state": "present", "value": 9000}})
    record["bindings"][0].update(key="doc.patch:1", write_range=[1, 2], boundary={"change_ordinal": 1})
    record["command"]["args"]["changes"].insert(0, timing)
    step["patch"].insert(0, timing)
    accepted["parent"]["payload"]["occurrences"][0]["placement"]["start_ms"] = 9000
    accepted["parent"]["content_digest"] = digest(accepted["parent"]["payload"])
    following["bindings"][0]["content_digest"] = accepted["parent"]["content_digest"]
    if projection == "step":
        result = step_output(boundary, step, {"commands": [record]}, accepted)
    else:
        result = command_output(boundary, record, following)
    assert result == accepted


@pytest.mark.parametrize("projection", ["step", "command"])
@pytest.mark.parametrize("forged_alias", [False, True])
def test_shared_occurrence_order_authenticates_each_local_alias(astrid_importable, projection, forged_alias):
    from astrid.core.timeline.authoring_bundle import _authoring_shot_id

    boundary, step, record, accepted, following = _order_case()
    for image in (boundary, accepted):
        rows = image["parent"]["payload"]["occurrences"]
        last = next(row for row in rows if row["occurrence_id"] == "last")
        last.update(shot_id="shot-first", shot_revision_id="revision-first")
        image.pop("shot-revision:revision-last")
        image.pop("internal-revision:internal-last")
        image["parent"]["content_digest"] = digest(image["parent"]["payload"])
    for change in (step["patch"][0], record["command"]["args"]["changes"][0],
                   record["bindings"][0]["change"]):
        change["before"]["value"].update(shot_id="shot-first", shot_revision_id="revision-first")
    for state in (record["writes"][0]["before"], record["writes"][0]["after"]):
        for row in state["value"]:
            if row["occurrence_id"] in {"first", "last"}:
                row["shot_id"] = _authoring_shot_id("project", "main", row["occurrence_id"],
                                                     "shot-first", shared=True)
    if forged_alias:
        rows = record["writes"][0]["after"]["value"]
        rows[0]["shot_id"] = rows[1]["shot_id"]
    following["bindings"][0]["content_digest"] = accepted["parent"]["content_digest"]

    def project():
        if projection == "step":
            return step_output(boundary, step, {"commands": [record]}, accepted, identity_scope=("project", "main"))
        return command_output(boundary, record, following, identity_scope=("project", "main"))

    if forged_alias:
        with pytest.raises(CommitRejected):
            project()
    else:
        assert project() == accepted


@pytest.fixture
def occurrence_film(tmp_path, astrid_importable):
    from types import SimpleNamespace

    from astrid.sdk.timeline.capture import capture_track_create
    from astrid.sdk.timeline.commands import execute
    from astrid.sdk.timeline.commit import bundle_from_document
    from astrid.sdk.timeline.native_occurrence_create import capture_occurrence_create

    from runtime_protocol.service import RuntimeService
    from runtime_protocol.store import RealmStore
    from runtime_protocol.timeline_commit_port import route_path
    from runtime_protocol.timeline_commit_provider import load_timeline_commit_provider

    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    runtime = RuntimeService(root)
    runtime.register_timeline_commit_provider(load_timeline_commit_provider("astrid"))
    project = runtime.create_project({"slug": "order", "name": "Occurrence order"})["id"]
    runtime.create_timeline(project, "main", idempotency_key="bootstrap")

    def document():
        head = runtime.get_project_timeline(project, "main")
        return runtime._timeline_commits()[0].revision_closure(project, "main", head["head_revision_id"])

    def body(commands):
        head = runtime.get_project_timeline(project, "main")
        patch = ([copy.deepcopy(change) for command in commands for change in command["args"]["changes"]]
                 if all(command["op"] == "doc.patch" for command in commands) else [])
        return {"api_version": 1, "project_id": project, "timeline_id": "main",
                "base_revision_id": head["head_revision_id"], "base_publication_id": head["head_publication_id"],
                "commands": commands, "label": "Arrange occurrences", "merge": "fields", "reads": [],
                "steps": [{"id": "arrange", "label": "Arrange occurrences", "intent": "", "tags": [],
                           "command_ordinals": list(range(len(commands))), "patch": patch, "reads": []}],
                "source": {"via": "python"}}

    def publish(submitted, key):
        return runtime.commit_timeline(project, "main", submitted, idempotency_key=key, publisher="editor",
                                       invocation_path=route_path(project, "main"), authorize=lambda: None)

    try:
        bundle = bundle_from_document(document())
        publish(body([capture_track_create(bundle, "parent", {"id": "picture", "kind": "visual"})]), "track")
        bundle = bundle_from_document(document())
        births = []
        for index in range(20):
            command = capture_occurrence_create(bundle, f"occ-{index:02d}", f"shot-{index:02d}",
                                                name=f"Shot {index:02d}", track="picture",
                                                on=index * 3, duration=2)
            births.append(command)
            bundle = execute(bundle, [command]).bundle
        setup = body(births)
        setup["steps"] = [{"id": f"birth-{index}", "label": "Create occurrence", "intent": "", "tags": [],
                           "command_ordinals": [index], "patch": [], "reads": []}
                          for index in range(len(births))]
        publish(setup, "births")
        yield SimpleNamespace(runtime=runtime, project=project, document=document, body=body, publish=publish)
    finally:
        runtime.close()


@pytest.mark.parametrize("multiple_commands", [False, True])
def test_real_twenty_occurrences_reorder_with_sequential_timing_and_exact_undo(occurrence_film, multiple_commands):
    film = occurrence_film
    before = film.document()
    rows = copy.deepcopy(before["parent_revision"]["payload"]["occurrences"])
    commands, changes, timings = [], [], []
    for index, row in enumerate(list(reversed(rows))):
        identity = row["occurrence_id"]
        change = {"op": "list.move", "ref": "parent", "path": ["occurrences"], "id": identity,
                  "order_before": [item["occurrence_id"] for item in rows],
                  "before": {"state": "present", "value": copy.deepcopy(row)},
                  "after_id": None if index == 0 else rows[index - 1]["occurrence_id"]}
        changes.append(change)
        rows.remove(row)
        rows.insert(index, row)
        timings.append({"op": "set", "ref": "parent",
                        "path": ["occurrences", "occurrence_id:" + identity, "placement", "start_ms"],
                        "before": {"state": "present", "value": row["placement"]["start_ms"]},
                        "value": 100000 + index * 2000})
        if multiple_commands:
            commands.append({"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
                             "args": {"changes": changes}})
            changes = []
    changes.extend(timings)
    if changes:
        commands.append({"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
                         "args": {"changes": changes}})
    for index, row in enumerate(rows):
        row["placement"]["start_ms"] = 100000 + index * 2000
    history = film.runtime.list_timeline_commits(film.project, "main", authorize=lambda: None)
    submitted = film.body(commands)
    arranged = film.publish(submitted, "arrange")
    assert arranged["data"]["status"] == "accepted"
    assert arranged["data"]["canonical_document"]["parent_revision"]["payload"]["occurrences"] == rows
    for family in ("shot_revisions", "internal_timeline_revisions"):
        assert arranged["data"]["canonical_document"][family] == before[family]
    assert film.publish(submitted, "arrange") == arranged
    after_history = film.runtime.list_timeline_commits(film.project, "main", authorize=lambda: None)
    assert len(after_history["items"]) == len(history["items"]) + 1
    inverse = {"schema_version": 1, "op": "timeline.inverse", "version": "1", "select": None,
               "args": {"publications": [arranged["receipt"]["receipt_id"]]}}
    undone = film.publish(film.body([inverse]), "undo")
    assert undone["data"]["canonical_document"] == before


def test_real_shared_occurrence_order_retains_physical_images(occurrence_film):
    from astrid.sdk.timeline.commit import bundle_from_document
    from astrid.sdk.timeline.native_occurrence_shared import (
        capture_occurrence_place_shared,
    )

    film = occurrence_film
    shared = capture_occurrence_place_shared(bundle_from_document(film.document()),
                                             "occurrence:occ-00", "shared", on=70)
    film.publish(film.body([shared]), "share")
    before = film.document()
    rows = before["parent_revision"]["payload"]["occurrences"]
    change = {"op": "list.move", "ref": "parent", "path": ["occurrences"], "id": "shared",
              "order_before": [row["occurrence_id"] for row in rows],
              "before": {"state": "present", "value": copy.deepcopy(rows[-1])}, "after_id": None}
    command = {"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
               "args": {"changes": [change]}}
    arranged = film.publish(film.body([command]), "shared-order")["data"]["canonical_document"]
    assert arranged["parent_revision"]["payload"]["occurrences"] == [rows[-1], *rows[:-1]]
    assert arranged["shot_revisions"] == before["shot_revisions"]
    assert arranged["internal_timeline_revisions"] == before["internal_timeline_revisions"]
