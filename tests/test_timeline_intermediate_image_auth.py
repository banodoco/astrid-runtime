"""Authenticate unchanged sequential images at their own command boundary."""
from __future__ import annotations

import copy
import json
import runpy

import pytest

from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_auth import _observation_site, command_output, images

pytest_plugins = ("test_timeline_commit_authentication",)


def _sdk_flat_reflow_plan(astrid_importable):
    from astrid.sdk.timeline.checkout import Checkout
    from astrid.sdk.timeline.commit import _digest, _manifest, bundle_from_document
    from astrid.sdk.timeline.commands import execute
    from astrid.sdk.timeline.emitter import emit_document_commands

    fixture_path = astrid_importable / "tests/sdk/test_timeline_commit_provider_document.py"
    document_fixture = runpy.run_path(str(fixture_path))["document_fixture"]
    document = document_fixture(shared=False)
    parent = document["parent_revision"]["payload"]
    clips = [
        {"id": "before", "clipType": "media", "track": "picture", "asset": "picture",
         "at": 0.0, "from": 0.0, "to": 0.5,
         "extension": {"opaque": [None, False, 0]}},
        {"id": "inside", "clipType": "media", "track": "picture2", "asset": "picture",
         "at": 4.5, "from": 10.0, "to": 10.5},
        {"id": "across", "clipType": "media", "track": "picture", "asset": "picture",
         "at": 3.0, "from": 20.0, "to": 24.0},
        {"id": "after", "clipType": "media", "track": "picture", "asset": "long",
         "at": 8.0, "from": 30.0, "to": 31.0},
        {"id": "voice", "clipType": "media", "track": "audio", "asset": "voice",
         "at": 0.0, "from": 0.0, "to": 10.0,
         "app": {"astrid": {"segment": "voice", "text": "before after",
                              "words": [[0.1, 1.2, "before"], [6.1, 6.4, "after"]]}}},
        {"id": "sfx-before", "clipType": "media", "track": "sfx", "asset": "voice",
         "at": 0.5, "from": 11.0, "to": 11.5},
        {"id": "sfx-inside", "clipType": "media", "track": "sfx", "asset": "voice",
         "at": 4.5, "from": 12.0, "to": 12.5},
        {"id": "sfx-edge-start", "clipType": "media", "track": "sfx", "asset": "voice",
         "at": 4.0, "from": 13.0, "to": 13.5},
        {"id": "sfx-edge-end", "clipType": "media", "track": "sfx", "asset": "voice",
         "at": 6.0, "from": 14.0, "to": 14.5},
        {"id": "sfx-after", "clipType": "media", "track": "sfx", "asset": "voice",
         "at": 8.0, "from": 15.0, "to": 15.5},
    ]
    parent["clips"] = copy.deepcopy(clips)
    parent["config"]["clips"] = copy.deepcopy(clips)
    parent["config"]["tracks"] = [
        {"id": "picture", "kind": "visual"}, {"id": "picture2", "kind": "visual"},
        {"id": "audio", "kind": "audio"}, {"id": "sfx", "kind": "audio"},
    ]
    parent["config"]["output"]["fps"] = {"numerator": 30, "denominator": 1}
    parent["registry"]["assets"]["picture"].update(type="video", duration=100.0)
    parent["registry"]["assets"]["long"] = copy.deepcopy(parent["registry"]["assets"]["picture"])
    parent["registry"]["assets"]["voice"] = {
        "media_id": parent["registry"]["assets"]["picture"]["media_id"],
        "type": "audio", "duration": 20.0,
    }
    parent["config"]["registry"] = copy.deepcopy(parent["registry"])
    parent["occurrences"] = []
    document["parent_revision"]["content_digest"] = _digest(parent)
    document["shot_revisions"] = []
    document["internal_timeline_revisions"] = []
    document["dependency_manifest"] = _manifest(
        [], [], document["dependency_manifest"]["media"], [],
    )

    bundle = bundle_from_document(document)
    bundle["base_parent"]["publication_id"] = "bootstrap"
    checkout = Checkout(copy.deepcopy(bundle))
    checkout.insert_time(4, 2)
    calls = emit_document_commands(bundle, checkout.bundle)
    request = {
        "api_version": 1, "project_id": bundle["project_id"],
        "timeline_id": bundle["timeline_id"],
        "base_revision_id": bundle["base_parent"]["revision_id"],
        "base_publication_id": "bootstrap", "commands": calls,
        "label": "diagnostic", "steps": [{
            "id": "edit", "label": "diagnostic", "intent": "", "tags": [],
            "command_ordinals": list(range(len(calls))),
            "patch": [change for call in calls for change in call["args"]["changes"]],
        }],
    }
    plan = execute(bundle, calls, commit_request=request, evaluated_head={
        "revision_id": request["base_revision_id"], "publication_id": "bootstrap",
    })
    return plan


def test_real_sdk_reflow_preserves_raw_parent_mirror_observations(astrid_importable):
    plan = _sdk_flat_reflow_plan(astrid_importable)
    first = plan.records[0]
    assert [(write["ref"], write["path"]) for write in first["writes"]] == [
        ("parent", ["clips"]), ("parent", ["config", "clips"]),
        ("parent/clip:inside", ["at"]),
    ]
    assert [(write["ref"], write["path"]) for write in first["derived_writes"]] == [
        ("parent", ["config", "clips"]),
    ]

    # The recorder's actual ordered physical observations must project to the
    # next command's input without merging the two source mirror captures.
    for ordinal, record in enumerate(plan.records[:-1]):
        command_output(images(plan._sequential_execution[ordinal]["input"]), record,
                       plan.records[ordinal + 1])

    boundary = images(plan._sequential_execution[0]["input"])
    for target, damage in ((first["writes"][0], "identity"),
                           (first["writes"][0], "order"),
                           (first["writes"][0], "extension"),
                           (first["writes"][1], "mirror")):
        forged = copy.deepcopy(first)
        capture = forged["writes"][0 if target is first["writes"][0] else 1]
        rows = capture["before"]["value"]
        if damage == "identity":
            rows[0]["id"] = "forged"
        elif damage == "order":
            rows.reverse()
        elif damage == "extension":
            rows[0]["extension"]["opaque"][2] = 99
        else:
            rows[0]["at"] = 99
        with pytest.raises(CommitRejected, match="input observation"):
            command_output(boundary, forged, plan.records[1])


def test_native_parent_clip_observation_keeps_supported_storage_shapes():
    both = {"parent": {"payload": {"clips": [], "config": {"clips": []}}}}
    config_only = {"parent": {"payload": {"config": {"clips": []}}}}
    payload_only = {"parent": {"payload": {"clips": []}}}
    null_mirrors = {"parent": {"payload": {"clips": None, "config": {"clips": None}}}}

    assert _observation_site(both, "parent/clip:one", ["at"]) == (
        "parent", ["clips", "id:one", "at"])
    assert _observation_site(config_only, "parent/clip:one", ["at"]) == (
        "parent", ["config", "clips", "id:one", "at"])
    assert _observation_site(payload_only, "parent/clip:one", ["at"]) == (
        "parent", ["clips", "id:one", "at"])
    assert _observation_site(null_mirrors, "parent/clip:one", ["at"]) == (
        "parent", ["config", "clips", "id:one", "at"])
    assert _observation_site(both, "parent", ["config", "clips"]) == (
        "parent", ["config", "clips"])


def _request_with_admission(submitted, source, runtime=None, project=None):
    def find_pin(value):
        if isinstance(value, dict):
            if set(value) == {"media_id", "content_digest"}:
                return value
            if isinstance(value.get("object_id"), str):
                return {"media_id": value["object_id"], "content_digest": value["object_id"]}
            for child in value.values():
                found = find_pin(child)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = find_pin(child)
                if found is not None:
                    return found
        return None

    pin = source["dependency_manifest"]["media"][0] if source["dependency_manifest"]["media"] else None
    if pin is None and runtime is not None:
        media = next(command["args"]["media"] for command in submitted["commands"]
                     if "media" in command.get("args", {}))
        selection = runtime.get_project_media_selection(
            project, {key: media[key] for key in ("asset", "generation_id", "variant_id")},
            authorize=lambda: None,
        )
        pin = {"media_id": selection["object_id"], "content_digest": selection["object_id"]}
    if pin is None:
        pin = find_pin(submitted)
    assert pin is not None, json.dumps(submitted["commands"], indent=2)
    media_selection = next(command["args"]["media"] for command in submitted["commands"]
                           if "media" in command.get("args", {}))
    admission = {
        "schema_version": 1,
        "op": "media.admit",
        "version": "1",
        "select": None,
        "args": {"inputs": [{"pin": copy.deepcopy(pin), "selection": copy.deepcopy(media_selection)}]},
    }
    commands = [admission, *copy.deepcopy(submitted["commands"])]
    child_step = copy.deepcopy(submitted["steps"][0])
    child_step["id"] = "child"
    child_step["command_ordinals"] = list(range(1, len(commands)))
    return {
        **copy.deepcopy(submitted),
        "commands": commands,
        "steps": [
            {"id": "media", "label": "Capture media", "intent": "", "tags": [],
             "command_ordinals": [0], "patch": [], "reads": []},
            child_step,
        ],
    }


@pytest.mark.parametrize("created_child_public", [True], indirect=True)
def test_admission_step_uses_its_unchanged_parent_boundary(created_child_public):
    runtime, project, source, submitted, held, document, publish = created_child_public
    parent_media = next(command["args"]["row"] for command in submitted["commands"]
                        if command["op"] == "clip.add-media")
    submitted = _request_with_admission(submitted, source, runtime, project)

    result = publish(submitted, "intermediate-image")
    canonical = result["data"]["canonical_document"]

    assert result["data"]["status"] == "accepted"
    assert canonical == document()
    assert canonical["parent_revision"]["payload"]["clips"] == [parent_media]
    assert canonical["parent_revision"]["payload"]["config"]["clips"] == [parent_media]
    assert canonical["internal_timeline_revisions"][0]["payload"]["clips"] == [held]


@pytest.mark.parametrize("created_child_public", [True], indirect=True)
@pytest.mark.parametrize("damage", ["intermediate_image", "effect_ordinal", "changed_pin", "wrong_owner"])
def test_admission_step_rejects_forged_intermediate_authority(created_child_public, monkeypatch, damage):
    from runtime_protocol.timeline_commit_port import RequestCommitPort

    runtime, project, source, submitted, _held, document, publish = created_child_public
    submitted = _request_with_admission(submitted, source, runtime, project)
    original_accept = RequestCommitPort.accept
    original_capture = RequestCommitPort.capture_sequential_execution

    def forge_capture(port, capture):
        capture = copy.deepcopy(capture)
        if damage == "intermediate_image":
            output = capture["landing"]["commands"][0]["output"]
            output["parent_revision"]["payload"]["forged"] = True
            output["parent_revision"]["content_digest"] = "sha256:" + "0" * 64
        return original_capture(port, capture)

    def forge_accept(port, prepared):
        prepared = copy.deepcopy(prepared)
        bindings = [binding for record in prepared["records"]["commands"]
                    for binding in record["bindings"]]
        if damage == "effect_ordinal":
            next(binding for binding in bindings if binding.get("key") == "commit.effect")["effect_ordinal"] = 99
        elif damage == "changed_pin":
            next(binding for binding in bindings if binding.get("key") == "commit.effect")["revision_id"] = "foreign"
        elif damage == "wrong_owner":
            binding = next(binding for binding in bindings if "owners" in binding)
            binding["owner"] = "occurrence:foreign/shot"
            binding["owners"] = ["occurrence:foreign/shot"]
        return original_accept(port, prepared)

    monkeypatch.setattr(RequestCommitPort, "capture_sequential_execution", forge_capture)
    monkeypatch.setattr(RequestCommitPort, "accept", forge_accept)
    before = document()
    with pytest.raises(RuntimeErrorBase) as error:
        publish(submitted, "intermediate-image-" + damage)

    assert error.value.details is not None
    assert error.value.details["reason"] == "invalid_records"
    assert document() == before == source
