"""Authenticated Runtime boundaries for grouped inverse stages."""
from __future__ import annotations

import copy

import pytest
import test_timeline_commit_integration as real_tests
import test_timeline_commit_port as port_tests

from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.timeline_commit_port import digest, route_path
from runtime_protocol.timeline_commit_validation import validate_commit_value

service = port_tests.service


def _request(runtime, publication):
    head = runtime.get_project_timeline(runtime.test_project, "main")
    return {
        "api_version": 1,
        "project_id": runtime.test_project,
        "timeline_id": "main",
        "base_revision_id": head["head_revision_id"],
        "base_publication_id": head["head_publication_id"],
        "commands": [{
            "schema_version": 1,
            "op": "timeline.inverse",
            "version": "1",
            "select": None,
            "args": {"publications": [publication]},
        }],
        "label": "Grouped inverse",
        "merge": "fields",
        "reads": [],
        "steps": [{
            "id": "undo",
            "label": "Grouped inverse",
            "intent": "Undo",
            "tags": [],
            "command_ordinals": [0],
            "patch": [],
        }],
    }


def _seed_request(runtime):
    head = runtime.get_project_timeline(runtime.test_project, "main")
    changes = [
        {"op": "set", "ref": "parent", "path": ["unknown"],
         "before": {"state": "absent"}, "value": {"stage": {"one": True, "two": True}}},
        {"op": "set", "ref": "parent", "path": ["unknown", "stage", "two"],
         "before": {"state": "present", "value": True}, "value": True},
    ]
    return {"api_version": 1, "project_id": runtime.test_project, "timeline_id": "main",
            "base_revision_id": head["head_revision_id"], "base_publication_id": head["head_publication_id"],
            "commands": [{"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
                          "args": {"changes": [changes[0]]}},
                         {"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
                          "args": {"changes": [changes[1]]}}],
            "label": "Seed grouped source", "merge": "fields", "reads": [],
            "steps": [{"id": "original-one", "label": "One", "intent": "Seed", "tags": [],
                       "command_ordinals": [0], "patch": [changes[0]]},
                      {"id": "original-two", "label": "Two", "intent": "Seed", "tags": [],
                       "command_ordinals": [1], "patch": [changes[1]]}]}


def _seed(context, port):
    request = context["request"]
    head = port.head()
    source = port.revision_closure(head["revision_id"])
    document = copy.deepcopy(source)
    parent = document["parent_revision"]
    first = request["commands"][0]["args"]["changes"][0]
    second = request["commands"][1]["args"]["changes"][0]
    parent["payload"]["unknown"] = copy.deepcopy(first["value"])
    parent["payload"]["unknown"]["stage"]["two"] = second["value"]
    parent["revision_id"] = "seed-parent"
    parent["content_digest"] = digest(parent["payload"])

    def record(ordinal, command, change, step_id, before, after):
        boundary = {"base_revision_id": request["base_revision_id"],
                    "base_publication_id": request["base_publication_id"],
                    "evaluated_head": copy.deepcopy(head), "command_ordinal": ordinal,
                    "step_id": step_id, "phase": "input", "change_ordinal": 0}
        binding = {"key": "doc.patch:0", "ref": "parent", "physical_ref": "parent",
                   "revision_id": before["revision_id"], "content_digest": before["content_digest"],
                   "policy": "fixed", "dependencies": [], "path": change["path"],
                   "change": copy.deepcopy(change), "write_range": [0, 1], "boundary": boundary}
        effect_boundary = {**boundary, "phase": "effect"}
        effect_bindings = []
        for side, image in (("before", before), ("after", after)):
            effect_bindings.append({"key": "commit.effect", "ref": "parent", "physical_ref": "parent",
                                    "revision_id": image["revision_id"], "content_digest": image["content_digest"],
                                    "policy": "fixed", "dependencies": [], "path": change["path"],
                                    "boundary": {**effect_boundary, "side": side}, "effect_ordinal": 0})
        return {"ordinal": ordinal, "command": copy.deepcopy(command),
                "writes": [{"ref": "parent", "path": change["path"], "before": change["before"],
                            "after": {"state": "present", "value": copy.deepcopy(after["payload"])}}],
                "reads": [], "selections": [], "bindings": [binding, *effect_bindings], "created": [],
                "dependencies": [], "derived_writes": []}

    before = copy.deepcopy(source["parent_revision"])
    first_parent = copy.deepcopy(before)
    first_parent["payload"]["unknown"] = copy.deepcopy(first["value"])
    first_parent["content_digest"] = digest(first_parent["payload"])
    second_parent = copy.deepcopy(first_parent)
    second_parent["payload"]["unknown"]["stage"]["two"] = second["value"]
    records = {"schema_version": 1,
               "commands": [record(0, request["commands"][0], first, "original-one", before,
                                    first_parent),
                            record(1, request["commands"][1], second, "original-two", first_parent,
                                    second_parent)],
               "undo_of": [], "restored_from": None, "label": request["label"], "merge_mode": "fields",
               "steps": [{**request["steps"][0], "dependencies": []},
                         {**request["steps"][1], "dependencies": []}]}
    value = {"expected_head": head, "canonical_document": document,
             "document_digest": digest(document), "records": records, "id_map": {},
             "semantic_events": [], "provider_version": "inverse-stage-seed",
             "compiler_version": "fixture-1"}
    validate_commit_value(value, "PreparedCommit")
    return port.accept(value)


def _prepared(context, port, mutation=None):
    request = context["request"]
    head = port.head()
    source = port.revision_closure(head["revision_id"])
    before_parent = copy.deepcopy(source["parent_revision"])
    first_payload = copy.deepcopy(before_parent["payload"])
    first_payload["meta"] = {"org.example.stage": {"one": True}}
    final_payload = copy.deepcopy(first_payload)
    final_payload["meta"]["org.example.stage"]["two"] = True

    effects = [
        {"op": "set", "ref": "parent", "path": ["meta"],
         "before": {"state": "absent"}, "value": first_payload["meta"]},
        {"op": "set", "ref": "parent", "path": ["meta", "org.example.stage", "two"],
         "before": {"state": "absent"}, "value": True},
    ]
    writes = [
        {"ref": "parent", "path": ["meta"], "before": effects[0]["before"],
         "after": {"state": "present", "value": first_payload["meta"]}},
        {"ref": "parent", "path": ["meta", "org.example.stage", "two"],
         "before": effects[1]["before"], "after": {"state": "present", "value": True}},
    ]

    def image(payload, revision_id):
        return {**copy.deepcopy(before_parent), "revision_id": revision_id,
                "content_digest": digest(payload), "payload": copy.deepcopy(payload)}

    first = image(first_payload, "inverse-stage-one")
    final = image(final_payload, "inverse-stage-two")
    document = copy.deepcopy(source)
    document["parent_revision"] = final
    common = {"base_revision_id": request["base_revision_id"],
              "base_publication_id": request["base_publication_id"],
              "evaluated_head": copy.deepcopy(head), "command_ordinal": 0,
              "step_id": "undo", "phase": "effect"}

    def effect_binding(index, side, boundary_image):
        boundary = {**common, "side": side}
        return {"key": "commit.effect", "ref": "parent", "physical_ref": "parent",
                "revision_id": boundary_image["revision_id"],
                "content_digest": boundary_image["content_digest"], "policy": "fixed",
                "dependencies": [], "path": effects[index]["path"],
                "boundary": boundary, "step_id": "undo", "effect_ordinal": index}

    if mutation == "missing-history":
        request["commands"][0]["args"]["publications"] = ["missing-publication"]
    publication = request["commands"][0]["args"]["publications"][0]
    stage_one = {"key": "inverse.stage", "ref": "parent", "policy": "fixed",
                 "dependencies": [], "boundary": {"publication_id": publication,
                 "step_id": "original-two", "command_ordinals": [1],
                 "native_write_range": [0, 1], "effect_range": [0, 1]}}
    stage_two = {"key": "inverse.stage", "ref": "parent", "policy": "fixed",
                 "dependencies": [], "boundary": {"publication_id": publication,
                 "step_id": "original-one", "command_ordinals": [0],
                 "native_write_range": [1, 2], "effect_range": [1, 2]}}
    bindings = [stage_one, stage_two,
                effect_binding(0, "before", before_parent), effect_binding(0, "after", first),
                effect_binding(1, "before", first), effect_binding(1, "after", final)]
    if mutation == "digest":
        bindings[-1]["content_digest"] = "sha256:" + "0" * 64
    elif mutation == "unrelated":
        unrelated = image({"unrelated": True}, "unrelated-image")
        bindings[-1].update(revision_id=unrelated["revision_id"], content_digest=unrelated["content_digest"])
    elif mutation == "overlap":
        stage_two["boundary"]["effect_range"] = [0, 2]
    elif mutation == "missing":
        stage_two["boundary"]["effect_range"] = [2, 2]
    elif mutation == "reordered":
        stage_two["boundary"]["effect_range"] = [0, 1]
    elif mutation == "missing-binding":
        bindings.pop()
    elif mutation == "publication":
        stage_one["boundary"]["publication_id"] = "foreign-publication"
    elif mutation == "step":
        stage_one["boundary"]["step_id"] = "foreign-step"
    elif mutation == "command-ordinal":
        stage_one["boundary"]["command_ordinals"] = [0]
    elif mutation == "native-range":
        stage_one["boundary"]["native_write_range"] = [0, 2]
    elif mutation == "ref":
        stage_one["ref"] = "foreign-stage-ref"
    elif mutation == "policy":
        stage_one["policy"] = "follow"
    elif mutation == "dependency":
        stage_one["dependencies"] = ["forged-dependency"]

    record = {"ordinal": 0, "command": copy.deepcopy(request["commands"][0]),
              "writes": writes, "reads": [], "selections": [], "bindings": bindings,
              "created": [], "dependencies": [], "derived_writes": []}
    step = {**copy.deepcopy(request["steps"][0]), "patch": effects, "dependencies": []}
    value = {"expected_head": head, "canonical_document": document,
             "document_digest": digest(document),
             "records": {"schema_version": 1, "commands": [record], "undo_of": [publication],
                         "restored_from": None, "label": request["label"], "merge_mode": "fields",
                         "steps": [step]},
             "id_map": {}, "semantic_events": [],
             "provider_version": "inverse-stage-test", "compiler_version": "fixture-1"}
    validate_commit_value(value, "PreparedCommit")
    return value


@pytest.mark.parametrize("mutation", [None, "digest", "unrelated", "overlap", "missing", "reordered",
                                       "missing-binding", "publication", "step", "command-ordinal",
                                       "native-range", "ref", "policy", "dependency", "missing-history"])
def test_grouped_inverse_effects_use_authenticated_stage_images(service, mutation):
    service.test_provider.action = _seed
    seed_request = _seed_request(service)
    port_tests.commit(service, seed_request, key="inverse-stage-seed")
    history = service.list_timeline_commits(service.test_project, "main", authorize=lambda: None)
    publication = history["items"][-1]["publication_id"]
    request = _request(service, publication)

    def execute(context, port):
        return port.accept(_prepared(context, port, mutation))

    service.test_provider.action = execute
    if mutation is None:
        result = service.commit_timeline(service.test_project, "main", request,
                                         idempotency_key="inverse-stage-valid",
                                         publisher="editor", invocation_path=route_path(service.test_project, "main"),
                                         authorize=lambda: None)
        assert result["data"]["status"] == "accepted"
        replay = service.list_timeline_commits(service.test_project, "main", authorize=lambda: None)
        assert replay["items"][-1]["records"]["undo_of"] == [publication]
    else:
        with pytest.raises(RuntimeErrorBase) as error:
            service.commit_timeline(service.test_project, "main", request,
                                    idempotency_key="inverse-stage-" + mutation,
                                    publisher="editor", invocation_path=route_path(service.test_project, "main"),
                                    authorize=lambda: None)
        assert error.value.details is not None
        assert error.value.details["reason"] == ("history_unavailable" if mutation == "missing-history"
                                                   else "invalid_records")


# Use the captured film and installed production provider, including its native
# recorder aliases and canonical effect images, in the normal Runtime suite.
film = real_tests.film
agent = real_tests.agent
editing = real_tests.editing


@pytest.mark.integration
@pytest.mark.parametrize("recipe", ["move", "track", "multistage"])
def test_current_agent_inverse_stage_round_trip(editing, monkeypatch, recipe):
    original = editing.document()
    if recipe == "move":
        body = editing.body([editing.move("music-bed", 1)])
    elif recipe == "track":
        track = {"id": "stage-audio", "kind": "audio", "extension": {"opaque": [None, "kept"]}}
        body = editing.body([editing.agent.track(editing.agent.bundle(original), "parent", track)])
    else:
        changes = [
            {"op": "set", "ref": "parent", "path": ["meta"], "before": {"state": "absent"},
             "value": {"org.example.stage": {"one": True}}},
            {"op": "set", "ref": "parent", "path": ["meta", "org.example.stage", "two"],
             "before": {"state": "absent"}, "value": True},
        ]
        body = editing.body([{"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
                              "args": {"changes": [change]}} for change in changes])
        body["steps"] = [{"id": "source-" + str(index), "label": "Stage " + str(index),
                          "intent": "Sequential patch", "tags": [], "command_ordinals": [index],
                          "patch": [change], "reads": []} for index, change in enumerate(changes)]
    first = editing.commit(body, "stage-source")
    expected = copy.deepcopy(original)
    if recipe == "move":
        newer = editing.commit(editing.body([editing.move("music-other", 2)]), "stage-disjoint")
        expected = copy.deepcopy(newer["data"]["canonical_document"])
        for container in ([], ["config"]):
            target = expected["parent_revision"]["payload"]
            baseline = original["parent_revision"]["payload"]
            for key in container:
                target, baseline = target[key], baseline[key]
            target["clips"] = [copy.deepcopy(next(row for row in baseline["clips"] if row["id"] == clip["id"]))
                               if clip["id"] == "music-bed" else clip for clip in target["clips"]]
    history = copy.deepcopy(editing.history())
    undo = editing.body([real_tests.inverse(first["receipt"]["receipt_id"])])
    before = real_tests.rows(editing.service)
    preview = editing.commit({**copy.deepcopy(undo), "dry_run": True}, "stage-preview")
    assert preview["data"]["status"] == "preview" and preview["receipt"] is None
    assert real_tests.rows(editing.service) == before
    result = editing.commit(undo, "stage-undo")
    actual = result["data"]["canonical_document"]
    # Generated parent revision names may change; every document byte they
    # authenticate, including all closure families, must be restored exactly.
    expected["parent_revision"]["revision_id"] = actual["parent_revision"]["revision_id"]
    expected["parent_revision"]["content_digest"] = digest(expected["parent_revision"]["payload"])
    real_tests.assert_json_equal(actual, expected)
    real_tests.assert_json_equal(preview["data"]["canonical_document"]["parent_revision"]["payload"],
                                 actual["parent_revision"]["payload"])
    assert editing.history()[:-1] == history
    record = editing.history()[-1]["records"]["commands"][0]
    stages = [binding["boundary"] for binding in record["bindings"] if binding["key"] == "inverse.stage"]
    assert [stage["publication_id"] for stage in stages] == [first["receipt"]["receipt_id"]] * len(stages)
    assert [stage["step_id"] for stage in stages] == (["source-1", "source-0"] if recipe == "multistage" else ["edit"])
    after = real_tests.rows(editing.service)

    def forbidden(self, context, port):
        raise AssertionError("exact retry executed Agent")

    monkeypatch.setattr(type(editing.service._timeline_commit_provider), "commit", forbidden)
    assert editing.commit(copy.deepcopy(undo), "stage-undo") == result
    assert real_tests.rows(editing.service) == after
    editing.assert_readback(first)
    editing.assert_readback(result)


@pytest.mark.integration
@pytest.mark.parametrize("mutation", ["sequential-before", "sequential-after", "publication", "step",
                                      "command-ordinal", "ref"])
def test_current_agent_inverse_rejects_forged_stage(editing, monkeypatch, mutation):
    from runtime_protocol.timeline_commit_port import RequestCommitPort

    first = editing.commit(editing.body([editing.move("music-bed", 1)]), "forgery-source")
    before, history = real_tests.rows(editing.service), copy.deepcopy(editing.history())
    accept = RequestCommitPort.accept
    reached = []

    def forged_accept(port, prepared):
        value = copy.deepcopy(prepared)
        record = value["records"]["commands"][0]
        if mutation.startswith("sequential-"):
            write = next(write for write in record["writes"] if write["path"] == ["app", "astrid"])
            assert write["before"] == {"state": "present", "value": {}}
            write[mutation.removeprefix("sequential-")] = {"state": "present", "value": {"forged": True}}
        else:
            stage = next(binding for binding in record["bindings"] if binding["key"] == "inverse.stage")
            if mutation == "ref":
                stage["ref"] = "forged-stage-ref"
            else:
                key, replacement = {"publication": ("publication_id", "foreign-publication"),
                                    "step": ("step_id", "foreign-step"),
                                    "command-ordinal": ("command_ordinals", [1])}[mutation]
                stage["boundary"][key] = replacement
        reached.append(True)
        return accept(port, value)

    monkeypatch.setattr(RequestCommitPort, "accept", forged_accept)
    with pytest.raises(RuntimeErrorBase) as error:
        editing.commit(editing.body([real_tests.inverse(first["receipt"]["receipt_id"])]), "forged-stage")
    assert reached == [True]
    assert error.value.details["reason"] == "invalid_records"
    assert real_tests.rows(editing.service) == before
    assert editing.history() == history


@pytest.mark.integration
@pytest.mark.parametrize("mutation", ["replace", "add", "remove", "changed-path", "duplicate", "reorder"])
def test_current_agent_inverse_native_membership_is_authenticated(editing, monkeypatch, mutation):
    from runtime_protocol.timeline_commit_port import RequestCommitPort

    first = editing.commit(editing.body([editing.move("music-bed", 1)]), "native-forgery-source")
    before, history = real_tests.rows(editing.service), copy.deepcopy(editing.history())
    accept = RequestCommitPort.accept
    reached = []

    def forged_accept(port, prepared):
        value = copy.deepcopy(prepared)
        record = value["records"]["commands"][0]
        forged = {"ref": "parent", "path": ["config", "forged-native-write"],
                  "before": {"state": "absent"}, "after": {"state": "absent"}}
        if mutation == "replace":
            record["writes"][0] = forged
        elif mutation == "add":
            record["writes"].append(forged)
            stage = next(binding for binding in record["bindings"] if binding["key"] == "inverse.stage")
            stage["boundary"]["native_write_range"][1] += 1
        elif mutation == "remove":
            # Removing an absent-to-absent observation cannot change output.
            index = next(index for index, write in enumerate(record["writes"])
                         if write["before"] == write["after"] == {"state": "absent"})
            record["writes"].pop(index)
            stage = next(binding for binding in record["bindings"] if binding["key"] == "inverse.stage")
            stage["boundary"]["native_write_range"][1] -= 1
        else:
            index = next(index for index, write in enumerate(record["writes"])
                         if write["before"] == write["after"] == {"state": "absent"})
            if mutation == "changed-path":
                # Remain inside the canonical removed app container. Footprint
                # overlap alone must not authorize a different native fact.
                record["writes"][index]["path"] = ["app", "astrid", "forged-native-write"]
            elif mutation == "duplicate":
                record["writes"][index] = copy.deepcopy(record["writes"][index + 1])
            else:
                record["writes"][index], record["writes"][index + 1] = (
                    record["writes"][index + 1], record["writes"][index])
        reached.append(True)
        return accept(port, value)

    monkeypatch.setattr(RequestCommitPort, "accept", forged_accept)
    with pytest.raises(RuntimeErrorBase) as error:
        editing.commit(editing.body([real_tests.inverse(first["receipt"]["receipt_id"])]), "native-forgery")
    assert reached == [True]
    assert error.value.details["reason"] == "invalid_records"
    assert real_tests.rows(editing.service) == before
    assert editing.history() == history


@pytest.mark.parametrize("mutation", ["reviewer", "source-sites-without-effects"])
def test_reviewer_replaced_native_write_is_refused_before_persistence(service, mutation):
    service.test_provider.action = _seed
    port_tests.commit(service, _seed_request(service), key="reviewer-seed")
    publication = service.list_timeline_commits(
        service.test_project, "main", authorize=lambda: None)["items"][-1]["publication_id"]
    request = _request(service, publication)
    before = real_tests.rows(service)
    history = copy.deepcopy(service.list_timeline_commits(service.test_project, "main", authorize=lambda: None))

    def execute(context, port):
        value = _prepared(context, port)
        writes = value["records"]["commands"][0]["writes"]
        if mutation == "reviewer":
            writes[0]["path"] = ["config", "forged-native-write"]
            writes[0]["before"] = {"state": "absent"}
            writes[0]["after"] = {"state": "absent"}
        else:
            # Exact source membership alone cannot prove that native captures
            # cover the independently authenticated canonical stage image.
            payload = port.revision_closure(port.head()["revision_id"])["parent_revision"]["payload"]
            for write, path, observed in ((writes[0], ["unknown", "stage", "two"], True),
                                          (writes[1], ["unknown"], payload["unknown"])):
                write["path"] = path
                write["before"] = {"state": "present", "value": copy.deepcopy(observed)}
                write["after"] = copy.deepcopy(write["before"])
        return port.accept(value)

    service.test_provider.action = execute
    with pytest.raises(RuntimeErrorBase) as error:
        service.commit_timeline(service.test_project, "main", request,
                                idempotency_key="reviewer-forged-write", publisher="editor",
                                invocation_path=route_path(service.test_project, "main"), authorize=lambda: None)
    assert error.value.details["reason"] == "invalid_records"
    assert real_tests.rows(service) == before
    assert service.list_timeline_commits(service.test_project, "main", authorize=lambda: None) == history


def test_grouped_canonical_stage_observations_retry_exactly(service):
    service.test_provider.action = _seed
    port_tests.commit(service, _seed_request(service), key="canonical-stage-seed")
    publication = service.list_timeline_commits(
        service.test_project, "main", authorize=lambda: None)["items"][-1]["publication_id"]
    request = _request(service, publication)
    service.test_provider.action = lambda context, port: port.accept(_prepared(context, port))

    def commit():
        return service.commit_timeline(service.test_project, "main", copy.deepcopy(request),
                                       idempotency_key="canonical-stage-retry", publisher="editor",
                                       invocation_path=route_path(service.test_project, "main"), authorize=lambda: None)

    result = commit()
    before = real_tests.rows(service)

    def forbidden(context, port):
        raise AssertionError("exact canonical-stage retry executed the provider")

    service.test_provider.action = forbidden
    assert commit() == result
    assert real_tests.rows(service) == before


def _split_and_note_body(editing):
    source = editing.document()["parent_revision"]["payload"]["clips"][0]
    right = {**copy.deepcopy(source), "id": "music-right", "at": 2, "hold": 1}
    absent = {"state": "absent"}

    def change(path, before, value=None, *, op="set", **extra):
        result = {"op": op, "ref": "parent", "path": path, "before": copy.deepcopy(before), **extra}
        if op in ("set", "list.insert"):
            result["value"] = copy.deepcopy(value)
        return result

    changes = [
        change(["config", "output", "file"], absent, "output.mp4"),
        change(["clips"], absent, right, op="list.insert", id="music-right",
               order_before=[clip["id"] for clip in editing.document()["parent_revision"]["payload"]["clips"]],
               after_id=source["id"]),
        change(["clips", "id:" + source["id"], "hold"], {"state": "present", "value": source["hold"]}, 1),
        change(["clips", "id:" + source["id"], "label"], absent, None),
        change(["config", "output", "note"], absent, "kept"),
        change(["clips", "id:" + source["id"], "hold"], {"state": "present", "value": 1}, 1.5),
        change(["clips", "id:" + source["id"], "label"], {"state": "present", "value": None}, op="remove"),
    ]
    body = editing.body([{"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
                          "args": {"changes": changes}, "created": ["parent/clip:music-right"]}])
    body.update(label="Split and output", group_id="split-group",
                rationale="Retained split and unrelated note history probe")
    body["steps"] = [{"id": "split", "label": body["label"], "intent": body["label"],
                      "tags": ["retained-probe"], "command_ordinals": [0], "patch": changes, "reads": []}]
    return body


@pytest.mark.integration
def test_store_authenticated_split_and_note_inverse_restores_both_native_mirrors(editing, monkeypatch):
    from runtime_protocol.timeline_commit_auth import validate
    from runtime_protocol.timeline_commit_port import RequestCommitPort

    original = editing.document()
    captured = []
    accept = RequestCommitPort.accept

    def capture(port, prepared):
        captured.append(copy.deepcopy(prepared))
        return accept(port, prepared)

    monkeypatch.setattr(RequestCommitPort, "accept", capture)
    forward_body = _split_and_note_body(editing)
    forward = editing.commit(forward_body, "split-note-forward")
    store = editing.service._timeline_commits()[0]
    publication = forward["receipt"]["receipt_id"]
    history = {publication: store.history_entry(editing.project, editing.timeline, publication)}
    assert history[publication]["records"] == captured[0]["records"]
    inverse_body = editing.body([real_tests.inverse(publication)])
    inverse_body.update(label="Undo split and output", group_id="split-group",
                        rationale=forward_body["rationale"])
    inverse_body["steps"] = [{"id": "undo", "label": inverse_body["label"], "intent": inverse_body["label"],
                              "tags": ["retained-probe"], "command_ordinals": [0], "patch": [], "reads": []}]
    inverse = editing.commit(inverse_body, "split-note-inverse")
    assert forward["data"]["status"] == inverse["data"]["status"] == "accepted"
    assert store._inverse_stage_history(editing.project, editing.timeline, captured[1]["records"]) == history
    for request, prepared in zip((forward_body, inverse_body), captured):
        source = store.revision_closure(editing.project, editing.timeline, prepared["expected_head"]["revision_id"])
        base = store.revision_closure(editing.project, editing.timeline, request["base_revision_id"])
        continuations = store._binding_continuations(
            editing.project, editing.timeline, request["base_publication_id"], prepared["expected_head"])
        validate(request, prepared, source, base, continuations, history)
    writes = captured[1]["records"]["commands"][0]["writes"]
    mirrors = [write for write in writes if write["ref"] == "parent"
               and write["path"] in (["config", "clips"], ["clips"])]
    assert [write["path"] for write in mirrors] == [["config", "clips"], ["clips"]]
    assert mirrors[0]["before"] == mirrors[1]["before"]
    assert mirrors[0]["after"] == mirrors[1]["after"]
    assert mirrors[0]["before"] != mirrors[0]["after"]
    restored = inverse["data"]["canonical_document"]
    original["parent_revision"]["revision_id"] = restored["parent_revision"]["revision_id"]
    real_tests.assert_json_equal(restored, original)
    before = real_tests.rows(editing.service)
    assert editing.commit(copy.deepcopy(inverse_body), "split-note-inverse") == inverse
    assert real_tests.rows(editing.service) == before
    editing.assert_readback(forward)
    editing.assert_readback(inverse)


@pytest.mark.integration
@pytest.mark.parametrize("path", [["config", "clips"], ["clips"]])
@pytest.mark.parametrize("side", ["before", "after"])
def test_store_split_and_note_native_mirror_forgery_refuses_without_writes(editing, monkeypatch, path, side):
    from runtime_protocol.timeline_commit_port import RequestCommitPort

    forward = editing.commit(_split_and_note_body(editing), "split-note-forgery-source")
    before, history = real_tests.rows(editing.service), copy.deepcopy(editing.history())
    accept = RequestCommitPort.accept
    reached = []

    def forged_accept(port, prepared):
        value = copy.deepcopy(prepared)
        write = next(write for write in value["records"]["commands"][0]["writes"]
                     if write["ref"] == "parent" and write["path"] == path)
        write[side]["value"][0]["hold"] = 99
        reached.append(True)
        return accept(port, value)

    monkeypatch.setattr(RequestCommitPort, "accept", forged_accept)
    with pytest.raises(RuntimeErrorBase) as error:
        editing.commit(editing.body([real_tests.inverse(forward["receipt"]["receipt_id"])]), "split-note-forged")
    assert reached == [True]
    assert error.value.details["reason"] == "invalid_records"
    assert real_tests.rows(editing.service) == before
    assert editing.history() == history


@pytest.mark.integration
@pytest.mark.parametrize("mutation", ["missing", "forged-step", "future"])
def test_store_split_and_note_requires_exact_forward_history(editing, monkeypatch, mutation):
    from runtime_protocol.timeline_commit import CommitRejected
    from runtime_protocol.timeline_commit_auth import validate
    from runtime_protocol.timeline_commit_port import RequestCommitPort

    forward = editing.commit(_split_and_note_body(editing), "split-note-history-source")
    request = editing.body([real_tests.inverse(forward["receipt"]["receipt_id"])])
    captured = []
    accept = RequestCommitPort.accept

    def capture(port, prepared):
        captured.append(copy.deepcopy(prepared))
        return accept(port, prepared)

    monkeypatch.setattr(RequestCommitPort, "accept", capture)
    inverse = editing.commit(request, "split-note-history-inverse")
    prepared = captured[0]
    store = editing.service._timeline_commits()[0]
    history = store._inverse_stage_history(editing.project, editing.timeline, prepared["records"])
    assert set(history) == {forward["receipt"]["receipt_id"]}
    if mutation == "missing":
        history = None
    elif mutation == "forged-step":
        history[forward["receipt"]["receipt_id"]]["records"]["steps"][0]["id"] = "caller-invented-step"
    else:
        publication = inverse["receipt"]["receipt_id"]
        history[publication] = store.history_entry(editing.project, editing.timeline, publication)
    source = store.revision_closure(editing.project, editing.timeline, prepared["expected_head"]["revision_id"])
    base = store.revision_closure(editing.project, editing.timeline, request["base_revision_id"])
    continuations = store._binding_continuations(
        editing.project, editing.timeline, request["base_publication_id"], prepared["expected_head"])
    before = real_tests.rows(editing.service)
    with pytest.raises(CommitRejected) as error:
        validate(request, prepared, source, base, continuations, history)
    assert error.value.failure["details"]["reason"] == "invalid_records"
    assert real_tests.rows(editing.service) == before


@pytest.fixture
def source_copy_stage(tmp_path, astrid_importable):
    from astrid.sdk.timeline.capture import capture_track_create
    from astrid.sdk.timeline.commit import bundle_from_document
    from astrid.sdk.timeline.native_occurrence_create import capture_occurrence_create

    from runtime_protocol.service import RuntimeService
    from runtime_protocol.store import RealmStore
    from runtime_protocol.timeline_commit_provider import load_timeline_commit_provider

    root = tmp_path / "copy-realm"
    RealmStore.initialize(root).close()
    runtime = RuntimeService(root)
    project = runtime.create_project({"slug": "copy", "name": "Copy"})["id"]
    runtime.register_timeline_commit_provider(load_timeline_commit_provider("astrid"))
    for timeline in ("source", "destination"):
        runtime.create_timeline(project, timeline, idempotency_key="create-" + timeline)
    store = runtime._timeline_commits()[0]

    def document(timeline):
        return store.revision_closure(project, timeline, store.head(project, timeline)["revision_id"])

    def commit(timeline, commands, key):
        head = store.head(project, timeline)
        request = {"api_version": 1, "project_id": project, "timeline_id": timeline,
                   "base_revision_id": head["revision_id"], "base_publication_id": head["publication_id"],
                   "commands": commands, "label": "Copy stage", "merge": "atomic", "reads": [],
                   "steps": [{"id": "copy", "label": "Copy stage", "intent": "Keep source",
                              "tags": [], "command_ordinals": list(range(len(commands))), "patch": [], "reads": []}]}
        return runtime.commit_timeline(project, timeline, request, idempotency_key=key, publisher="editor",
                                       invocation_path=route_path(project, timeline), authorize=lambda: None)

    try:
        bundle = bundle_from_document(document("source"))
        commit("source", [capture_track_create(bundle, "parent", {"id": "picture", "kind": "visual"})], "track")
        bundle = bundle_from_document(document("source"))
        commit("source", [capture_occurrence_create(bundle, "one", "shared", name="Shared",
                                                   track="picture", on=0, duration=10)], "shot")
        source = document("source")
        head = store.head(project, "source")
        command = {"schema_version": 1, "op": "timeline.duplicate", "version": "1", "select": "parent",
                   "args": {"source_ref": {"project_id": project, "timeline_id": "source",
                            "revision_id": head["revision_id"], "publication_id": head["publication_id"],
                            "content_digest": source["parent_revision"]["content_digest"]},
                            "shots": {"shared": "copied"}, "occurrences": {"one": "copy-one"}},
                   "created": ["shot:copied", "occurrence:copy-one"]}
        yield runtime, document, commit, command
    finally:
        runtime.close()


@pytest.mark.integration
def test_source_copy_native_roots_authenticate_and_round_trip(source_copy_stage):
    runtime, document, commit, command = source_copy_stage
    original = document("destination")
    forward = commit("destination", [command], "copy")
    copied = document("destination")
    publication = forward["receipt"]["receipt_id"]
    store = runtime._timeline_commits()[0]
    history = store.history_entry(original["project_id"], "destination", publication)
    inverse = commit("destination", [real_tests.inverse(publication)], "undo-copy")
    assert document("destination") == original
    commit("destination", [real_tests.inverse(inverse["receipt"]["receipt_id"])], "redo-copy")
    assert document("destination") == copied
    assert store.history_entry(original["project_id"], "destination", publication) == history


@pytest.mark.integration
@pytest.mark.parametrize("mutation", ["occurrence-before", "shot-before", "shot-edge", "shot-after",
                                     "path", "ref", "omitted", "extra", "missing-effect", "effect-digest"])
def test_source_copy_native_root_forgeries_refuse_without_durable_writes(source_copy_stage, monkeypatch, mutation):
    from runtime_protocol.timeline_commit_port import RequestCommitPort

    runtime, document, commit, command = source_copy_stage
    forward = commit("destination", [command], "copy")
    before = real_tests.rows(runtime)
    stored = tuple(runtime.store.conn.iterdump())
    project = document("destination")["project_id"]
    history = runtime.list_timeline_commits(project, "destination", authorize=lambda: None)
    accept = RequestCommitPort.accept
    reached = []

    def forged_accept(port, prepared):
        value = copy.deepcopy(prepared)
        record = value["records"]["commands"][0]
        occurrence = next(write for write in record["writes"] if write["ref"] == "occurrence:copy-one")
        shot = next(write for write in record["writes"] if write["ref"] == "shot:copied")
        if mutation == "occurrence-before":
            occurrence["before"]["value"]["muted"] = True
        elif mutation == "shot-before":
            shot["before"]["value"]["payload"]["name"] = "forged"
        elif mutation == "shot-edge":
            shot["before"]["value"]["payload"]["internal_timeline_revision_id"] = "forged"
        elif mutation == "shot-after":
            shot["after"] = copy.deepcopy(shot["before"])
        elif mutation == "path":
            occurrence["path"] = ["muted"]
        elif mutation == "ref":
            occurrence["ref"] = "occurrence:foreign"
        elif mutation == "omitted":
            record["writes"].remove(shot)
        elif mutation == "extra":
            record["writes"].append(copy.deepcopy(shot))
        elif mutation == "missing-effect":
            record["bindings"] = [binding for binding in record["bindings"] if binding["key"] != "commit.effect"]
        else:
            next(binding for binding in record["bindings"] if binding["key"] == "commit.effect")["content_digest"] = (
                "sha256:" + "0" * 64)
        reached.append(True)
        return accept(port, value)

    monkeypatch.setattr(RequestCommitPort, "accept", forged_accept)
    with pytest.raises(RuntimeErrorBase) as error:
        commit("destination", [real_tests.inverse(forward["receipt"]["receipt_id"])], "forged-undo")
    assert reached == [True]
    assert error.value.details["reason"] == "invalid_records"
    assert real_tests.rows(runtime) == before
    assert tuple(runtime.store.conn.iterdump()) == stored
    assert runtime.list_timeline_commits(project, "destination", authorize=lambda: None) == history


@pytest.fixture
def retained_leaf_inverse():
    import hashlib
    import json
    from pathlib import Path

    raw = (Path(__file__).parent / "fixtures" / "timeline_leaf_inverse_1246.json").read_bytes()
    # Byte-for-byte custody of the credential-scanned Agent 1246 package.
    assert hashlib.sha256(raw).hexdigest() == "1123978b7b18c59d280f73c9ad9155b5ba18d0c64b24e45b8bdd02af30a887b0"
    package = json.loads(raw)
    for name in ("auth-input-35.json", "stage-comparison-01.json"):
        artifact = package["artifacts"][name]
        compact = json.dumps(artifact["data"], sort_keys=True, separators=(",", ":")).encode()
        assert hashlib.sha256(compact).hexdigest() == artifact["compact_sha256"]
    return package


def test_actual_leaf_and_fork_inverse_stages_authenticate_losslessly(retained_leaf_inverse):
    from runtime_protocol.timeline_commit_auth import (
        _inverse_stage_boundaries,
        images,
        validate,
    )

    artifacts = retained_leaf_inverse["artifacts"]
    captured = artifacts["stage-comparison-01.json"]["data"]
    inputs = artifacts["auth-input-35.json"]["data"]
    original = copy.deepcopy(inputs)
    prepared = inputs["prepared"]
    records = prepared["records"]
    boundaries = _inverse_stage_boundaries(
        images(inputs["source"]), images(prepared["canonical_document"]), records["steps"][0],
        records, images(prepared["canonical_document"]), images(inputs["base"]), inputs["history"])
    assert boundaries[0] == (captured["stage_before"], captured["stage_after"])
    assert len(boundaries[0][0]) == len(boundaries[0][1]) == 5
    assert boundaries[5][0] == captured["stage_after"]
    assert boundaries[8][1] == images(prepared["canonical_document"])
    stages = [binding["boundary"] for binding in records["commands"][0]["bindings"]
              if binding["key"] == "inverse.stage"]
    assert [(stage["native_write_range"], stage["effect_range"]) for stage in stages] == [
        ([0, 1], [0, 5]), ([1, 3], [5, 9])]
    validate(**inputs)
    assert inputs == original


@pytest.mark.parametrize("mutation", [
    "owner", "mixed-owner", "edge", "digest", "history-step", "history-ordinal", "history-base",
    "history-head", "aggregate-pin", "native-before", "native-after", "aggregate-payload",
    "native-order", "range", "stage-order", "extra-effect", "unrelated-payload",
    "effect-and-binding", "equal-payload-foreign-owner", "equal-payload-foreign-roots",
])
def test_actual_leaf_inverse_forgery_is_refused(retained_leaf_inverse, mutation):
    from runtime_protocol.timeline_commit import CommitRejected
    from runtime_protocol.timeline_commit_auth import validate

    inputs = retained_leaf_inverse["artifacts"]["auth-input-35.json"]["data"]
    prepared = inputs["prepared"]
    record = prepared["records"]["commands"][0]
    patch = prepared["records"]["steps"][0]["patch"]
    history = next(iter(inputs["history"].values()))
    bindings = [binding for binding in history["records"]["commands"][1]["bindings"]
                if binding["key"] == "commit.materialization"]
    stages = [binding for binding in record["bindings"] if binding["key"] == "inverse.stage"]
    if mutation in {"owner", "mixed-owner"}:
        for binding in bindings[:1 if mutation == "mixed-owner" else 2]:
            binding.update(owner="occurrence:f2-sibling/shot", owners=["occurrence:f2-sibling/shot"])
    elif mutation == "edge":
        bindings[0]["edge_before"] = bindings[0]["edge_after"]
    elif mutation == "digest":
        bindings[0]["content_digest"] = "sha256:" + "0" * 64
    elif mutation.startswith("history-"):
        key, value = {"history-step": ("step_id", "fork-edit-0"), "history-ordinal": ("command_ordinal", 0),
                      "history-base": ("base_revision_id", "foreign"),
                      "history-head": ("evaluated_head", prepared["expected_head"])}[mutation]
        bindings[0]["boundary"][key] = value
    elif mutation == "aggregate-pin":
        record["writes"][2]["before"]["value"]["payload"]["internal_timeline_revision_id"] = "foreign"
    elif mutation in {"native-before", "native-after"}:
        record["writes"][0][mutation.removeprefix("native-")] = {"state": "present", "value": "forged"}
    elif mutation == "aggregate-payload":
        record["writes"][2]["before"]["value"]["payload"]["opaque_shot"] = None
    elif mutation == "native-order":
        record["writes"][1:] = reversed(record["writes"][1:])
    elif mutation == "range":
        stages[0]["boundary"]["native_write_range"] = [0, 2]
    elif mutation == "stage-order":
        first, second = stages
        first["boundary"], second["boundary"] = second["boundary"], first["boundary"]
    elif mutation == "extra-effect":
        patch.append({"op": "set", "ref": "parent", "path": ["forged"],
                      "before": {"state": "absent"}, "value": True})
        stages[1]["boundary"]["effect_range"][1] += 1
    elif mutation == "unrelated-payload":
        prepared["canonical_document"]["shot_revisions"][0]["payload"]["opaque_shot"] = None
    elif mutation == "effect-and-binding":
        patch[0]["value"]["opaque_timeline"] = {"future_schema": "forged"}
        for binding in record["bindings"]:
            if binding.get("effect_ordinal") == 0 and binding.get("boundary", {}).get("side") == "after":
                binding["content_digest"] = digest(patch[0]["value"])
    elif mutation == "equal-payload-foreign-owner":
        shot = next(row for row in inputs["source"]["shot_revisions"] if row["shot_id"] == "selected-shot")
        payload = copy.deepcopy(shot["payload"])
        shot["shot_id"] = "foreign-owner"
        assert shot["payload"] == payload
    else:
        # Keep the exact complete payloads while replacing both restored root
        # identities and their pins; source history grants neither identity.
        import json

        for index in (0, 1):
            identity = patch[index]["ref"].partition(":")[2]
            prepared = json.loads(json.dumps(prepared).replace(identity, "foreign-" + identity))
        inputs["prepared"] = prepared
    before = copy.deepcopy(inputs)
    with pytest.raises(CommitRejected) as error:
        validate(**inputs)
    assert error.value.failure["details"]["reason"] == "invalid_records"
    assert inputs == before


@pytest.fixture
def retained_occurrence_order_inverse():
    import hashlib
    import json
    from pathlib import Path

    # Lossless projection of a8dcf1d1 packet run/cases/060-port-prepared.json:
    # exact request/prepared, expected-head closure, and undo_of-only history.
    raw = (Path(__file__).parent / "fixtures" / "timeline_occurrence_order_inverse_060.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == "50d9e08be8efa3e9f4d1d789ab99fd2c76d7e92bbeacfba543f65d2a331145c0"
    return json.loads(raw)


def test_retained_occurrence_order_inverse_preserves_authenticated_physical_pins(retained_occurrence_order_inverse):
    from runtime_protocol.timeline_commit_auth import validate

    inputs = retained_occurrence_order_inverse
    before = copy.deepcopy(inputs)
    assert set(inputs["history"]) == set(inputs["prepared"]["records"]["undo_of"])
    write = inputs["prepared"]["records"]["commands"][0]["writes"][6]
    assert write["ref"] == "parent" and write["path"] == ["occurrences"]
    assert all("shot_revision_id" not in row for side in ("before", "after") for row in write[side]["value"])
    validate(**inputs)
    assert inputs == before


@pytest.mark.parametrize("mutation", [
    "duplicate", "missing", "foreign", "shot", "pin", "payload", "unknown", "malformed", "absent",
    "before", "wrong-order", "physical-pin", "physical-pin-swap", "internal-pin", "owner",
    "effect-before", "effect-after", "effect-coverage",
    "native-range", "effect-range", "history-missing", "history-foreign", "history-source",
])
def test_retained_occurrence_order_forgeries_refuse_losslessly(retained_occurrence_order_inverse, mutation):
    from runtime_protocol.timeline_commit import CommitRejected
    from runtime_protocol.timeline_commit_auth import validate

    inputs = retained_occurrence_order_inverse
    prepared = inputs["prepared"]
    record = prepared["records"]["commands"][0]
    write = record["writes"][6]
    rows = write["after"]["value"]
    if mutation == "duplicate":
        rows[1] = copy.deepcopy(rows[0])
    elif mutation == "missing":
        rows.pop()
    elif mutation == "foreign":
        rows[0]["occurrence_id"] = "foreign"
    elif mutation == "shot":
        rows[0]["shot_id"] = rows[1]["shot_id"]
    elif mutation == "pin":
        rows[0]["shot_revision_id"] = "forged-pin"
    elif mutation == "payload":
        rows[0]["placement"]["start_ms"] = 99
    elif mutation == "unknown":
        rows[0]["unknown"] = {"opaque": None}
    elif mutation == "malformed":
        rows[0] = None
    elif mutation == "absent":
        write["after"] = {"state": "absent"}
    elif mutation == "before":
        write["before"]["value"][0]["gain"] = 99
    elif mutation == "wrong-order":
        rows.reverse()
    elif mutation == "physical-pin":
        prepared["canonical_document"]["parent_revision"]["payload"]["occurrences"][0][
            "shot_revision_id"] = "forged-pin"
    elif mutation == "physical-pin-swap":
        physical = prepared["canonical_document"]["parent_revision"]["payload"]["occurrences"]
        physical[0]["shot_revision_id"] = physical[1]["shot_revision_id"]
    elif mutation == "internal-pin":
        prepared["canonical_document"]["shot_revisions"][0]["payload"][
            "internal_timeline_revision_id"] = "forged-pin"
    elif mutation == "owner":
        prepared["canonical_document"]["shot_revisions"][0]["shot_id"] = "foreign"
    elif mutation in {"effect-before", "effect-after", "effect-coverage"}:
        effect = prepared["records"]["steps"][0]["patch"][0]
        if mutation == "effect-before":
            effect["before"] = {"state": "present", "value": None}
        elif mutation == "effect-after":
            effect["value"] = None
        else:
            prepared["records"]["steps"][0]["patch"].pop()
    elif mutation in {"native-range", "effect-range"}:
        binding = next(binding for binding in record["bindings"] if binding["key"] == "inverse.stage")
        binding["boundary"]["native_write_range" if mutation == "native-range" else "effect_range"][0] = 1
    elif mutation == "history-missing":
        inputs["history"] = {}
    elif mutation == "history-foreign":
        inputs["history"]["foreign"] = copy.deepcopy(next(iter(inputs["history"].values())))
    else:
        next(iter(inputs["history"].values()))["records"]["commands"][0]["writes"].pop()
    before = copy.deepcopy(inputs)
    with pytest.raises(CommitRejected) as error:
        validate(**inputs)
    assert error.value.failure["details"]["reason"] == "invalid_records"
    if mutation in {"duplicate", "missing", "foreign", "shot", "pin", "payload", "unknown", "malformed", "absent"}:
        # The source of this undo is itself an inverse whose shot removals make it an
        # inherited stage (a5fc9ddf), so its exact reversed source captures are compared
        # before the per-write permutation check can run. The forgery is refused earlier.
        assert str(error.value) == (
            "inherited inverse native captures or effects differ from authenticated history")
    assert inputs == before


@pytest.fixture
def retained_native_order_packet():
    import json
    from pathlib import Path

    return json.loads((Path(__file__).parent / "fixtures" / "timeline_inverse_native_order_1416.json").read_bytes())


def test_retained_native_order_packet_authenticates_against_physical_closure(retained_native_order_packet):
    from runtime_protocol.timeline_commit_auth import validate

    inputs = retained_native_order_packet["actual_input"]
    validate(request=inputs["context"]["request"], prepared=copy.deepcopy(inputs["prepared"]),
             source=copy.deepcopy(inputs["source"]), base=copy.deepcopy(inputs["previous"]),
             history=copy.deepcopy(inputs["history"]))


@pytest.mark.parametrize("mutation", [
    "wrong-pin", "effect", "history", "owner", "payload", "order", "membership",
    "ordinal", "source", "digest",
])
def test_retained_native_order_packet_rejects_coordinated_forgery(retained_native_order_packet, mutation):
    from runtime_protocol.timeline_commit import CommitRejected
    from runtime_protocol.timeline_commit_auth import validate

    inputs = copy.deepcopy(retained_native_order_packet["actual_input"])
    prepared = inputs["prepared"]
    record = prepared["records"]["commands"][0]
    stage = next(binding for binding in record["bindings"] if binding["key"] == "inverse.stage")
    effect_binding = next(binding for binding in record["bindings"]
                          if binding.get("key") == "commit.effect" and binding.get("effect_ordinal") == 0)
    if mutation == "wrong-pin":
        prepared["records"]["steps"][0]["patch"][2]["value"]["occurrences"][0]["shot_revision_id"] = "foreign-pin"
    elif mutation == "effect":
        prepared["records"]["steps"][0]["patch"][2]["value"]["opaque"] = {"forged": True}
    elif mutation == "history":
        prepared["records"]["undo_of"] = ["foreign-publication"]
    elif mutation == "owner":
        effect_binding["owners"] = ["occurrence:foreign/shot"]
    elif mutation == "payload":
        record["writes"][3]["before"]["value"][0]["shot_id"] = "foreign-shot"
    elif mutation == "order":
        record["writes"][3], record["writes"][4] = record["writes"][4], record["writes"][3]
    elif mutation == "membership":
        record["writes"].pop(0)
    elif mutation == "ordinal":
        stage["boundary"]["command_ordinals"] = [1]
    elif mutation == "source":
        stage["boundary"]["publication_id"] = "foreign-publication"
    else:
        effect_binding["content_digest"] = "sha256:" + "0" * 64

    with pytest.raises(CommitRejected) as error:
        validate(request=inputs["context"]["request"], prepared=prepared,
                 source=inputs["source"], base=inputs["previous"], history=inputs["history"])
    assert error.value.failure["details"]["reason"] == "invalid_records"


@pytest.fixture
def retained_nested_inverse():
    import hashlib
    import json
    from pathlib import Path

    raw = (Path(__file__).parent / "fixtures" / "timeline_nested_inverse_1543.json").read_bytes()
    inputs = json.loads(raw)
    # Immediate accepted entry and auth-only inverse projection extracted from the credential-scanned
    # 1404 packet (SHA-256 9a47bb934b879efa0f6147d673038cee76299ba4e30ab22b6d5bcb1377ade589).
    assert hashlib.sha256(raw).hexdigest() == "8798a4b3a66b6922367add8cae44183a112dea54e4ec15b4e67a47ae7e8b6a13"
    return next(iter(inputs["history"].values()))


def _nested_projection(entry):
    source = entry["records"]["commands"][0]
    source_step = entry["records"]["steps"][0]
    writes = [{**copy.deepcopy(write), "before": copy.deepcopy(write["after"]),
               "after": copy.deepcopy(write["before"])} for write in reversed(source["writes"])]
    patch = []
    for effect in reversed(source_step["patch"]):
        inverse = {"op": "set" if effect["before"]["state"] == "present" else "remove",
                   "ref": effect["ref"], "path": effect["path"],
                   "before": {"state": "present", "value": effect["value"]}
                   if effect["op"] == "set" else {"state": "absent"}}
        if inverse["op"] == "set":
            inverse["value"] = effect["before"]["value"]
        patch.append(inverse)
    bindings = []
    for binding in reversed(source["bindings"]):
        if binding["key"] != "inverse.stage":
            continue
        boundary = binding["boundary"]
        start, end = boundary["native_write_range"]
        first, last = boundary["effect_range"]
        bindings.append({**copy.deepcopy(binding), "boundary": {
            "publication_id": entry["publication_id"], "step_id": source_step["id"],
            "command_ordinals": source_step["command_ordinals"],
            "native_write_range": [len(writes) - end, len(writes) - start],
            "effect_range": [len(patch) - last, len(patch) - first]}})
    command = {"schema_version": 1, "op": "timeline.inverse", "version": "1", "select": None,
               "args": {"publications": [entry["publication_id"]]}}
    record = {"ordinal": 0, "command": command, "writes": writes, "bindings": bindings,
              "reads": [], "selections": [], "created": [], "dependencies": [], "derived_writes": []}
    return {"id": "undo", "command_ordinals": [0], "patch": patch}, {
        "commands": [record], "undo_of": [entry["publication_id"]], "undo_steps": None}


def test_retained_nested_ranges_bind_immediate_identity_and_exact_captures(retained_nested_inverse):
    from runtime_protocol.timeline_commit_auth import _inverse_stage_ranges

    entry = retained_nested_inverse
    step, records = _nested_projection(entry)
    original = copy.deepcopy((entry, step, records))
    stages = _inverse_stage_ranges(step, records, {entry["publication_id"]: entry})
    assert [(stage["native_range"], stage["effect_range"]) for stage in stages] == [
        ([0, 2], [0, 4]), ([2, 3], [4, 9])]
    assert [(write["ref"], write["path"]) for write in records["commands"][0]["writes"]] == [
        ("shot:selected-shot", []), ("occurrence:f2-occurrence", ["shot_id"]),
        ("occurrence:f2-occurrence/clip:f2-agent-clip", ["params", "text"])]
    assert (entry, step, records) == original


def test_inverse_stage_rejects_empty_native_range_for_effectful_source(retained_nested_inverse):
    from runtime_protocol.timeline_commit import CommitRejected
    from runtime_protocol.timeline_commit_auth import _inverse_stage_ranges

    entry = retained_nested_inverse
    step, records = _nested_projection(entry)
    stage = next(binding for binding in records["commands"][0]["bindings"]
                 if binding["key"] == "inverse.stage")
    stage["boundary"]["native_write_range"] = [0, 0]

    with pytest.raises(CommitRejected, match="inverse stage native ranges"):
        _inverse_stage_ranges(step, records, {entry["publication_id"]: entry})


@pytest.mark.parametrize("mutation", [None, "publication", "step", "ordinal", "order", "omitted",
                                      "overlap", "effect", "native-before", "native-after", "digest"])
def test_nested_inverse_authenticates_boundaries_without_durable_forgery(service, mutation):
    service.test_provider.action = _seed
    port_tests.commit(service, _seed_request(service), key="nested-seed")
    store = service._timeline_commits()[0]
    publication = store.head(service.test_project, "main")["publication_id"]
    service.test_provider.action = lambda context, port: port.accept(_prepared(context, port))
    port_tests.commit(service, _request(service, publication), key="nested-source")
    publication = store.head(service.test_project, "main")["publication_id"]
    entry = store.history_entry(service.test_project, "main", publication)
    before = tuple(service.store.conn.iterdump())

    def execute(context, port):
        request = context["request"]
        source = port.revision_closure(port.head()["revision_id"])
        step, records = _nested_projection(entry)
        step = {**request["steps"][0], "patch": step["patch"], "dependencies": []}
        records.update(schema_version=1, restored_from=None, label=request["label"], merge_mode="fields",
                       steps=[step])
        first = copy.deepcopy(source["parent_revision"])
        first["payload"]["meta"]["org.example.stage"].pop("two")
        first.update(revision_id="nested-intermediate", content_digest=digest(first["payload"]))
        final = copy.deepcopy(first)
        final["payload"].pop("meta")
        final.update(revision_id="nested-final", content_digest=digest(final["payload"]))
        record = records["commands"][0]
        for index, pair in enumerate(((source["parent_revision"], first), (first, final))):
            for side, image in zip(("before", "after"), pair):
                record["bindings"].append({
                    "key": "commit.effect", "ref": "parent", "physical_ref": "parent", "policy": "fixed",
                    "dependencies": [], "path": step["patch"][index]["path"],
                    "revision_id": image["revision_id"], "content_digest": image["content_digest"],
                    "step_id": "undo", "effect_ordinal": index,
                    "boundary": {"base_revision_id": request["base_revision_id"],
                                 "base_publication_id": request["base_publication_id"],
                                 "evaluated_head": port.head(), "command_ordinal": 0,
                                 "step_id": "undo", "phase": "effect", "side": side}})
        stages = record["bindings"][:2]
        if mutation in {"publication", "step", "ordinal"}:
            key, value = {"publication": ("publication_id", "foreign"), "step": ("step_id", "foreign"),
                          "ordinal": ("command_ordinals", [1])}[mutation]
            stages[0]["boundary"][key] = value
        elif mutation == "order":
            record["bindings"][:2] = reversed(stages)
        elif mutation == "omitted":
            record["bindings"].pop(0)
        elif mutation == "overlap":
            stages[1]["boundary"]["native_write_range"] = [0, 2]
        elif mutation == "effect":
            step["patch"][0]["path"] = ["forged"]
        elif mutation in {"native-before", "native-after"}:
            record["writes"][0][mutation.removeprefix("native-")] = {"state": "present", "value": "forged"}
        elif mutation == "digest":
            record["bindings"][-1]["content_digest"] = "sha256:" + "0" * 64
        document = {**copy.deepcopy(source), "parent_revision": final}
        value = {"expected_head": port.head(), "canonical_document": document, "document_digest": digest(document),
                 "records": records, "id_map": {}, "semantic_events": [], "provider_version": "nested-test",
                 "compiler_version": "fixture-1"}
        return port.accept(value)

    service.test_provider.action = execute
    request = _request(service, publication)
    if mutation is None:
        result = port_tests.commit(service, request, key="nested-valid")
        assert result["data"]["status"] == "accepted"
        assert "meta" not in result["data"]["canonical_document"]["parent_revision"]["payload"]
        assert store.history_entry(service.test_project, "main", result["receipt"]["receipt_id"])[
            "records"]["undo_of"] == [publication]
    else:
        with pytest.raises(RuntimeErrorBase) as error:
            port_tests.commit(service, request, key="nested-forged")
        assert error.value.details is not None
        assert error.value.details["reason"] == "invalid_records"
        assert tuple(service.store.conn.iterdump()) == before


@pytest.fixture
def retained_nested_auth_input(retained_nested_inverse):
    import json
    from pathlib import Path

    return json.loads((Path(__file__).parent / "fixtures" / "timeline_nested_inverse_1543.json").read_bytes())


def test_actual_nested_inverse_authenticates_complete_retained_boundaries(retained_nested_auth_input):
    from runtime_protocol.timeline_commit_auth import validate

    inputs = retained_nested_auth_input
    before = copy.deepcopy(inputs)
    validate(**inputs)
    assert inputs == before


@pytest.mark.parametrize("mutation", [
    "owner", "pin", "digest", "read", "foreign", "future", "self", "omitted", "flattened", "overlap",
    "order", "native-before", "native-after", "effect-before", "effect-after", "effect-binding",
    "history-overlap", "history-gap", "history-self", "history-foreign",
])
def test_actual_nested_inverse_forgeries_refuse_losslessly(retained_nested_auth_input, mutation):
    from runtime_protocol.timeline_commit import CommitRejected
    from runtime_protocol.timeline_commit_auth import validate

    inputs = retained_nested_auth_input
    prepared = inputs["prepared"]
    record = prepared["records"]["commands"][0]
    stages = [binding for binding in record["bindings"] if binding["key"] == "inverse.stage"]
    source = next(iter(inputs["history"].values()))
    if mutation == "owner":
        prepared["canonical_document"]["shot_revisions"][0]["shot_id"] = "foreign-owner"
    elif mutation == "pin":
        prepared["canonical_document"]["shot_revisions"][0]["payload"]["internal_timeline_revision_id"] = "foreign-pin"
    elif mutation == "digest":
        next(binding for binding in record["bindings"] if binding["key"] == "commit.effect")[
            "content_digest"] = "sha256:" + "0" * 64
    elif mutation == "read":
        record["reads"].append({"ref": "parent", "path": ["forged"], "state": {"state": "present", "value": True}})
    elif mutation in {"foreign", "future", "self"}:
        stages[0]["boundary"]["publication_id"] = (
            prepared["canonical_document"]["parent_revision"]["revision_id"] if mutation == "future"
            else "foreign-publication" if mutation == "foreign" else "self")
    elif mutation == "omitted":
        record["bindings"].remove(stages[0])
    elif mutation == "flattened":
        record["bindings"] = [binding for binding in record["bindings"] if binding["key"] != "inverse.stage"]
    elif mutation == "overlap":
        stages[1]["boundary"]["effect_range"] = [0, 9]
    elif mutation == "order":
        stages[0]["boundary"], stages[1]["boundary"] = stages[1]["boundary"], stages[0]["boundary"]
    elif mutation in {"native-before", "native-after"}:
        record["writes"][0][mutation.removeprefix("native-")] = {"state": "present", "value": "forged"}
    elif mutation in {"effect-before", "effect-after"}:
        effect = prepared["records"]["steps"][0]["patch"][0]
        if mutation == "effect-before":
            effect["before"] = {"state": "present", "value": None}
        else:
            effect["op"] = "remove"
            effect.pop("value", None)
    elif mutation == "effect-binding":
        record["bindings"] = [binding for binding in record["bindings"] if binding["key"] != "commit.effect"]
    else:
        binding = next(binding for binding in source["records"]["commands"][0]["bindings"]
                       if binding["key"] == "inverse.stage")
        if mutation == "history-overlap":
            binding["boundary"]["native_write_range"] = [0, 3]
        elif mutation == "history-gap":
            binding["boundary"]["effect_range"] = [1, 5]
        else:
            binding["boundary"]["publication_id"] = (source["publication_id"] if mutation == "history-self"
                                                       else "foreign")
    before = copy.deepcopy(inputs)
    with pytest.raises(CommitRejected) as error:
        validate(**inputs)
    assert error.value.failure["details"]["reason"] == "invalid_records"
    assert inputs == before
