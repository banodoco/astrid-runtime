"""Occurrence inverses retire only their authenticated, unreferenced closure."""
from __future__ import annotations

import copy

import pytest
import test_timeline_commit_port as port_tests

from runtime_protocol import timeline_commit_auth as auth
from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_validation import digest

service = port_tests.service


def _image(revision, payload, **identity):
    return {"revision_id": revision, "content_digest": digest(payload),
            "payload": copy.deepcopy(payload), **identity}


def _document(project="project", timeline="destination", owners=1, shared_internal=False):
    internal = _image("foreign-internal", {"clips": [], "tracks": [], "registry": {"assets": {}},
                                           "output": {}}, timeline_id="source")
    shot = _image("foreign-shot", {"name": "Shared", "items": [],
                                   "internal_timeline_revision_id": internal["revision_id"]},
                  shot_id="shared", internal_timeline_revision_id=internal["revision_id"])
    row = {"occurrence_id": "copy", "shot_id": "shared", "shot_revision_id": shot["revision_id"],
           "placement": {"start_ms": 12000, "track": "picture"}, "duration_ms": 10000,
           "source_offset": 0, "speed": 1, "gain": 1, "track": "picture"}
    rows = [row]
    shots = [shot]
    if owners > 1:
        rows.append({**copy.deepcopy(row), "occurrence_id": "retained"})
    if shared_internal:
        shots.append(_image("other-shot", shot["payload"], shot_id="other",
                            internal_timeline_revision_id=internal["revision_id"]))
        rows.append({**copy.deepcopy(row), "occurrence_id": "other", "shot_id": "other",
                     "shot_revision_id": "other-shot"})
    parent = _image("before-parent", {"config": {"clips": [], "tracks": []}, "clips": [],
                                       "registry": {}, "occurrences": rows})
    return {"schema_version": 1, "project_id": project, "timeline_id": timeline,
            "parent_revision": parent, "shot_revisions": shots,
            "internal_timeline_revisions": [internal],
            "dependency_manifest": {"media": [], "documents": [], "shots": [
                {key: image[key] for key in ("shot_id", "revision_id", "content_digest",
                                             "internal_timeline_revision_id")} for image in shots],
                "internal_timelines": [{key: internal[key] for key in (
                    "timeline_id", "revision_id", "content_digest")}]}}


def _request(document, publication="forward"):
    return {"api_version": 1, "project_id": document["project_id"], "timeline_id": document["timeline_id"],
            "base_revision_id": document["parent_revision"]["revision_id"],
            "base_publication_id": publication, "label": "Undo foreign occurrence", "reads": [],
            "merge": "fields", "commands": [{"schema_version": 1, "op": "timeline.inverse",
                "version": "1", "select": None, "args": {"publications": [publication]}}],
            "steps": [{"id": "undo", "label": "Undo foreign occurrence", "intent": "Undo",
                       "tags": [], "command_ordinals": [0], "patch": []}]}


def _packet(document=None, publication="forward", request=None, retire=True):
    source = copy.deepcopy(document or _document())
    request = copy.deepcopy(request or _request(source, publication))
    row = source["parent_revision"]["payload"]["occurrences"][0]
    native_row = {key: value for key, value in row.items() if key != "shot_revision_id"}
    capture = {"ref": "occurrence:copy", "path": [], "before": {"state": "absent"},
               "after": {"state": "present", "value": native_row}}
    output = copy.deepcopy(source)
    output["parent_revision"]["payload"]["occurrences"].pop(0)
    remaining = output["parent_revision"]["payload"]["occurrences"]
    if retire and not any(item["shot_revision_id"] == row["shot_revision_id"] for item in remaining):
        output["shot_revisions"] = [shot for shot in output["shot_revisions"]
                                    if shot["revision_id"] != row["shot_revision_id"]]
        if not output["shot_revisions"]:
            output["internal_timeline_revisions"] = []
    output["parent_revision"].update(revision_id="after-parent",
                                     content_digest=digest(output["parent_revision"]["payload"]))
    output["dependency_manifest"]["shots"] = [pin for pin in output["dependency_manifest"]["shots"]
        if any(shot["revision_id"] == pin["revision_id"] for shot in output["shot_revisions"])]
    if not output["internal_timeline_revisions"]:
        output["dependency_manifest"]["internal_timelines"] = []
    effects = port_tests._step_patches(source, output)
    head = {"revision_id": request["base_revision_id"], "publication_id": publication}
    stage = {"key": "inverse.stage", "ref": "parent", "policy": "fixed", "dependencies": [],
             "boundary": {"publication_id": publication, "step_id": "copy", "command_ordinals": [0],
                          "native_write_range": [0, 1], "effect_range": [0, len(effects)]}}
    bindings = [stage]
    for index, effect in enumerate(effects):
        for side, document_image in (("before", source), ("after", output)):
            image = auth.images(document_image).get(effect["ref"])
            if image is None:
                continue
            binding = {"key": "commit.effect", "ref": effect["ref"], "physical_ref": effect["ref"],
                       "revision_id": image["revision_id"], "content_digest": image["content_digest"],
                       "policy": "fixed", "dependencies": [], "path": effect["path"], "effect_ordinal": index,
                       "boundary": {"base_revision_id": request["base_revision_id"],
                           "base_publication_id": publication, "evaluated_head": head,
                           "command_ordinal": 0, "step_id": "undo", "phase": "effect", "side": side}}
            if effect["ref"] != "parent":
                binding["owners"] = auth._capture_owners(document_image, effect["ref"])
            bindings.append(binding)
    record = {"ordinal": 0, "command": copy.deepcopy(request["commands"][0]),
              "writes": [{**copy.deepcopy(capture), "before": capture["after"], "after": capture["before"]}],
              "reads": [], "selections": [], "bindings": bindings, "created": [],
              "dependencies": [], "derived_writes": []}
    step = {**copy.deepcopy(request["steps"][0]), "dependencies": [], "patch": effects}
    records = {"schema_version": 1, "commands": [record], "steps": [step], "undo_of": [publication],
               "restored_from": None, "label": request["label"], "merge_mode": "fields"}
    history = {publication: {"publication_id": publication, "intent": "recorded",
        "receipt": {"receipt_id": publication, "result": {"canonical_document": copy.deepcopy(source)}},
        "records": {"commands": [{"ordinal": 0, "writes": [capture], "derived_writes": [],
                                   "bindings": [], "command": {"op": "occurrence.place-shared"}}],
                    "steps": [{"id": "copy", "command_ordinals": [0], "patch": []}]}}}
    return {"request": request, "source": source, "base": copy.deepcopy(source), "history": history,
            "prepared": {"expected_head": head, "canonical_document": output, "document_digest": digest(output),
                         "records": records, "id_map": {}, "semantic_events": [],
                         "provider_version": "retirement-test", "compiler_version": "fixture-1"}}


@pytest.mark.parametrize("owners,shared_internal", [(1, False), (2, False), (1, True)])
def test_occurrence_retirement_preserves_every_surviving_physical_reference(owners, shared_internal):
    packet = _packet(_document(owners=owners, shared_internal=shared_internal))
    original = copy.deepcopy(packet)
    auth.validate(**packet)
    assert packet == original
    output = packet["prepared"]["canonical_document"]
    assert len(output["shot_revisions"]) == (1 if owners > 1 or shared_internal else 0)
    assert len(output["internal_timeline_revisions"]) == (1 if owners > 1 or shared_internal else 0)
    for image in [*output["shot_revisions"], *output["internal_timeline_revisions"]]:
        assert image == auth.images(packet["source"])[
            ("shot-revision:" if "shot_id" in image else "internal-revision:") + image["revision_id"]]
    stage = packet["prepared"]["records"]["commands"][0]["bindings"][0]["boundary"]
    assert stage["native_write_range"] == [0, 1]


def _damage(packet, mutation):
    prepared = packet["prepared"]
    records = prepared["records"]
    record = records["commands"][0]
    stage = record["bindings"][0]["boundary"]
    entry = next(iter(packet["history"].values()))
    if mutation in {"publication", "step", "ordinal", "range"}:
        key, value = {"publication": ("publication_id", "foreign"), "step": ("step_id", "foreign"),
                      "ordinal": ("command_ordinals", [1]), "range": ("native_write_range", [0, 2])}[mutation]
        stage[key] = value
    elif mutation == "extra-native":
        record["writes"].append(copy.deepcopy(record["writes"][0]))
        stage["native_write_range"] = [0, 2]
    elif mutation == "canonical-native":
        record["writes"] = [{"ref": effect["ref"], "path": effect["path"], "before": effect["before"],
                             "after": {"state": "present", "value": effect["value"]}
                             if effect["op"] == "set" else {"state": "absent"}}
                            for effect in records["steps"][0]["patch"]]
        stage["native_write_range"] = [0, len(record["writes"])]
    elif mutation == "effect-range":
        stage["effect_range"] = [0, 1]
    elif mutation == "effect-order":
        records["steps"][0]["patch"].reverse()
    elif mutation == "missing-history":
        packet["history"] = {}
    elif mutation == "source-native":
        entry["records"]["commands"][0]["writes"][0]["after"]["value"]["gain"] = 9
    elif mutation == "reused-source":
        entry["records"]["commands"][0]["writes"][0]["before"] = copy.deepcopy(
            entry["records"]["commands"][0]["writes"][0]["after"])
    elif mutation in {"source-image", "source-pin"}:
        image = entry["receipt"]["result"]["canonical_document"]["shot_revisions"][0]
        if mutation == "source-image":
            image["payload"]["name"] = "Foreign"
        else:
            image["revision_id"] = "equal-payload-foreign-pin"
    elif mutation == "source-target":
        entry["records"]["commands"][0]["writes"][0]["ref"] = "occurrence:foreign"
    elif mutation in {"native-before", "native-after"}:
        record["writes"][0][mutation.removeprefix("native-")] = {"state": "present", "value": {}}
    elif mutation == "effect-only":
        record["writes"] = []
        stage["native_write_range"] = [0, 0]
    elif mutation == "owners":
        next(binding for binding in record["bindings"] if "owners" in binding)["owners"] = []
    elif mutation == "digest":
        record["bindings"][-1]["content_digest"] = "sha256:" + "0" * 64
    elif mutation == "foreign-scope":
        prepared["canonical_document"]["project_id"] = "foreign-project"
        prepared["document_digest"] = digest(prepared["canonical_document"])
    else:
        raise AssertionError(mutation)


MUTATIONS = ["publication", "step", "ordinal", "range", "extra-native", "canonical-native", "effect-range",
             "effect-order", "missing-history",
             "source-native", "reused-source", "source-image", "source-pin", "source-target", "native-before",
             "native-after", "effect-only", "owners", "digest"]


@pytest.mark.parametrize("mutation", MUTATIONS)
def test_retirement_requires_exact_source_and_native_authority_without_mutating_inputs(mutation):
    packet = _packet()
    _damage(packet, mutation)
    original = copy.deepcopy(packet)
    with pytest.raises(CommitRejected):
        auth.validate(**packet)
    assert packet == original


def test_unclaimed_orphan_and_equal_payload_foreign_images_cannot_be_retired():
    packet = _packet()
    for document in (packet["source"], packet["base"]):
        other = copy.deepcopy(document["shot_revisions"][0])
        other.update(revision_id="unrelated-shot", shot_id="unrelated")
        document["shot_revisions"].append(other)
    # The extra shot still references the internal image. Neither image may
    # disappear just because the submitted effects remove the copied owner.
    original = copy.deepcopy(packet)
    with pytest.raises(CommitRejected):
        auth.validate(**packet)
    assert packet == original


def test_sole_owner_retirement_is_required_even_if_provider_keeps_orphans():
    with pytest.raises(CommitRejected, match="do not cover"):
        auth.validate(**_packet(retire=False))


@pytest.fixture
def accepted_occurrence(service):
    service.create_timeline(service.test_project, "source", idempotency_key="source-timeline")

    def seed(context, port):
        value = port_tests.prepared(context, port, same=True)
        document = _document(service.test_project, "main")
        source = value["canonical_document"]
        document["parent_revision"]["payload"] = {**source["parent_revision"]["payload"],
            "occurrences": document["parent_revision"]["payload"]["occurrences"]}
        document["parent_revision"]["content_digest"] = digest(document["parent_revision"]["payload"])
        packet = _packet(document)
        records = value["records"]
        records["commands"][0]["writes"] = copy.deepcopy(
            packet["history"]["forward"]["records"]["commands"][0]["writes"])
        value.update(canonical_document=document, document_digest=digest(document))
        port_tests._complete_v2_metadata(context, port, document, value["expected_head"], records)
        records["steps"][0]["id"] = "copy"
        return port.accept(value)

    service.test_provider.action = seed
    body = port_tests.request(service, commands=[{"schema_version": 1, "op": "fixture.foreign",
        "version": "1", "select": None, "args": {}}], label="Copy", merge="fields", reads=[],
        steps=[{"id": "copy", "label": "Copy", "intent": "Copy", "tags": [],
                "command_ordinals": [0], "patch": []}])
    forward = port_tests.commit(service, body, key="foreign-source")
    publication = forward["receipt"]["receipt_id"]
    store = service._timeline_commits()[0]

    def inverse(context, port):
        head = port.head()
        document = port.revision_closure(head["revision_id"])
        packet = _packet(document, publication, context["request"])
        packet["prepared"]["expected_head"] = head
        for binding in packet["prepared"]["records"]["commands"][0]["bindings"]:
            if binding.get("key") == "commit.effect":
                binding["boundary"]["evaluated_head"] = head
        return packet["prepared"]

    return service, store, publication, inverse


def _stored(runtime):
    files = {str(path): path.read_bytes() for root in (runtime.store.cas_root, runtime.store.staging_root)
             for path in root.rglob("*") if path.is_file()}
    return tuple(runtime.store.conn.iterdump()), files


@pytest.mark.parametrize("mutation", [None, "extra-native", "canonical-native", "effect-range", "effect-only",
                                      "owners", "digest", "native-before", "foreign-scope"])
def test_production_retirement_acceptance_retry_preview_and_tamper_no_write(accepted_occurrence, mutation):
    runtime, store, publication, inverse = accepted_occurrence
    document = store.revision_closure(runtime.test_project, "main", store.head(runtime.test_project, "main")["revision_id"])
    body = _request(document, publication)

    def execute(context, port):
        value = inverse(context, port)
        if mutation:
            _damage({"prepared": value, "history": {"unused": {}}}, mutation)
        return port.preview(value) if context["request"].get("dry_run") else port.accept(value)

    runtime.test_provider.action = execute
    before = _stored(runtime)
    if mutation:
        with pytest.raises(RuntimeErrorBase):
            port_tests.commit(runtime, body, key="retire")
        assert _stored(runtime) == before
    else:
        preview = port_tests.commit(runtime, {**body, "dry_run": True}, key="preview")
        assert preview["receipt"] is None
        assert _stored(runtime) == before
        reply = port_tests.commit(runtime, body, key="retire")
        assert reply["data"]["status"] == "accepted"
        assert reply["data"]["canonical_document"]["shot_revisions"] == []
        after = _stored(runtime)
        assert port_tests.commit(runtime, body, key="retire") == reply
        assert _stored(runtime) == after
        entry = store.history_entry(runtime.test_project, "main", reply["receipt"]["receipt_id"])
        assert entry["records"]["undo_of"] == [publication]
        assert entry["receipt"] == reply["receipt"]


def test_retirement_merges_over_unrelated_parent_edit(accepted_occurrence):
    runtime, store, publication, inverse = accepted_occurrence
    source = store.revision_closure(runtime.test_project, "main", store.head(runtime.test_project, "main")["revision_id"])
    body = _request(source, publication)
    original_history = store.history_entry(runtime.test_project, "main", publication)
    runtime.test_provider.action = lambda context, port: port.accept(port_tests.prepared(context, port))
    port_tests.commit(runtime, port_tests.request(runtime, label="Other", merge="fields", reads=[]), key="other")
    runtime.test_provider.action = lambda context, port: port.accept(inverse(context, port))
    reply = port_tests.commit(runtime, body, key="merged-retirement")
    assert reply["data"]["status"] == "merged"
    document = reply["data"]["canonical_document"]
    assert document["parent_revision"]["payload"]["fixture_label"] == "other"
    assert document["shot_revisions"] == document["internal_timeline_revisions"] == []
    assert store.history_entry(runtime.test_project, "main", publication) == original_history
