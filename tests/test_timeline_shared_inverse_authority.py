"""A shared inverse restores one accepted consumer without retargeting its sibling."""
from __future__ import annotations

import copy

import pytest

from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_auth import (
    _authoring_identity,
    _inverse_stage_boundaries,
    _inverse_stage_ranges,
    images,
)
from runtime_protocol.timeline_commit_validation import digest


def _packet(native_items):
    owner = "occurrence:a/shot"
    copied = _authoring_identity("shot-placement", "project", "main", "a", "shared")
    item = _authoring_identity("shot-item-placement", "project", "main", "a", copied, "item")

    def image(revision, payload, **fields):
        return {"revision_id": revision, "payload": payload, "content_digest": digest(payload), **fields}

    rows = [{"occurrence_id": identity, "shot_id": "shared", "shot_revision_id": "shot"}
            for identity in ("a", "b")]
    baseline = {"project_id": "project", "timeline_id": "main",
                "parent_revision": image("parent", {"occurrences": rows}),
                "shot_revisions": [image("shot", {"internal_timeline_revision_id": "internal",
                    "items": ([{"item_id": "item", "media_id": "old"}] if native_items else [])},
                    shot_id="shared", internal_timeline_revision_id="internal")],
                "internal_timeline_revisions": [image("internal", {
                    "registry": {"assets": {"asset": {"media_id": "old", "type": "image"}}},
                    "clips": [{"id": "clip", "asset": "asset"}]})]}
    source = copy.deepcopy(baseline)
    source["parent_revision"]["payload"]["occurrences"][0].update(
        shot_id=copied, shot_revision_id="copy-shot")
    source["parent_revision"] = image("copy-parent", source["parent_revision"]["payload"])
    internal = copy.deepcopy(baseline["internal_timeline_revisions"][0]["payload"])
    internal["registry"]["assets"]["asset"].update(media_id="new", generationId="generation", variantId="variant")
    shot = copy.deepcopy(baseline["shot_revisions"][0]["payload"])
    shot["internal_timeline_revision_id"] = "copy-internal"
    if native_items:
        shot["items"][0].update(item_id=item, media_id="new")
    source["shot_revisions"].append(image("copy-shot", shot, shot_id=copied,
                                         internal_timeline_revision_id="copy-internal"))
    source["internal_timeline_revisions"].append(image("copy-internal", internal))
    present = lambda value: {"state": "present", "value": value}
    writes = [{"ref": "occurrence:a/asset:asset", "path": [field], "before": before, "after": present(after)}
              for field, before, after in (("media_id", present("old"), "new"),
                  ("type", present("image"), "image"), ("generationId", {"state": "absent"}, "generation"),
                  ("variantId", {"state": "absent"}, "variant"))]
    if native_items:
        writes.append({"ref": owner, "path": ["payload", "items", "item_id:item", "media_id"],
                       "before": present("old"), "after": present("new")})
    writes.append({"ref": "occurrence:a/clip:clip", "path": ["asset"],
                   "before": present("asset"), "after": present("asset")})
    before, after = images(baseline), images(source)
    edges = [{"op": "set", "ref": "parent", "path": ["occurrences", "occurrence_id:a", field],
              "before": present(old), "value": new}
             for field, old, new in (("shot_id", "shared", copied), ("shot_revision_id", "shot", "copy-shot"))]
    roots = [{"op": "set", "ref": ref, "path": [], "before": {"state": "absent"},
              "value": after[ref]["payload"]} for ref in ("internal-revision:copy-internal", "shot-revision:copy-shot")]
    effects = roots + edges
    attribution = {"base_revision_id": "parent", "base_publication_id": "bootstrap",
                   "evaluated_head": {"revision_id": "parent", "publication_id": "bootstrap"},
                   "step_id": "edit", "command_ordinal": 0, "phase": "input"}
    bindings = []
    for old, new, sibling_old, sibling_new in (
            ("shot-revision:shot", "shot-revision:copy-shot", "internal-revision:internal", "internal-revision:copy-internal"),
            ("internal-revision:internal", "internal-revision:copy-internal", "shot-revision:shot", "shot-revision:copy-shot")):
        bindings.append({"key": "commit.materialization", "ref": old, "physical_ref": old,
            "revision_id": before[old]["revision_id"], "content_digest": before[old]["content_digest"],
            "successor": new, "owner": owner, "owners": [owner, "occurrence:b/shot"],
            "edge_before": sibling_old, "edge_after": sibling_new, "step_id": "edit",
            "policy": "fixed", "dependencies": [], "boundary": attribution})

    def pins(patches, input_images, output_images):
        return [{"key": "commit.effect", "physical_ref": effect["ref"], "ref": effect["ref"],
                 "revision_id": boundary[effect["ref"]]["revision_id"],
                 "content_digest": boundary[effect["ref"]]["content_digest"],
                 "owners": ([owner] if effect["ref"] != "parent" else []),
                 "boundary": {"side": side}, "effect_ordinal": index,
                 "policy": "fixed", "dependencies": [], "path": effect["path"]}
                for index, effect in enumerate(patches)
                for side, boundary in (("before", input_images), ("after", output_images))
                if effect["ref"] in boundary]

    step = {"id": "edit", "command_ordinals": [0], "patch": effects}
    entry = {"publication_id": "publication", "intent": "recorded", "previous": attribution["evaluated_head"],
             "receipt": {"receipt_id": "publication", "result": {"canonical_document": source,
                 "document_digest": digest(source), "base_revision_id": "parent", "base_publication_id": "bootstrap"}},
             "records": {"steps": [step], "commands": [{"ordinal": 0,
                 "command": {"op": "occurrence.swap-media"}, "writes": writes,
                 "bindings": bindings + pins(effects, before, after), "derived_writes": []}]}}
    inverse_writes = [{**copy.deepcopy(write), "before": write["after"], "after": write["before"]}
                      for write in reversed(writes)]
    if native_items:
        inverse_writes[1]["path"][2] = "item_id:" + item
    inverse_effects = [{**copy.deepcopy(effect), "before": present(effect["value"]),
                        "value": effect["before"]["value"]} for effect in edges]
    inverse_effects += [{"op": "remove", "ref": effect["ref"], "path": [],
                         "before": present(effect["value"])} for effect in reversed(roots)]
    inverse_step = {"id": "undo", "command_ordinals": [0], "patch": inverse_effects}
    stage = {"key": "inverse.stage", "ref": "parent", "policy": "fixed", "dependencies": [],
             "boundary": {"publication_id": "publication", "step_id": "edit", "command_ordinals": [0],
                          "native_write_range": [0, len(writes)], "effect_range": [0, 4]}}
    records = {"undo_of": ["publication"], "steps": [inverse_step], "commands": [{"ordinal": 0,
        "command": {"op": "timeline.inverse"}, "writes": inverse_writes,
        "bindings": [stage, *pins(inverse_effects, after, before)]}]}
    return inverse_step, records, {"publication": entry}, after, before


@pytest.mark.parametrize("native_items", [False, True])
@pytest.mark.parametrize("damage", [None, "mapping", "owner", "revision", "digest", "source-command",
    "native-order", "native-count", "native-omitted", "native-range", "effect-range", "effect-order",
    "effect-count", "effect-value", "foreign-write", "history", "equal-byte-retarget", "sibling"])
def test_shared_inverse_authority_requires_the_exact_accepted_copy(native_items, damage):
    step, records, history, before, after = _packet(native_items)
    command = records["commands"][0]
    original = history["publication"]["records"]["commands"][0]
    if damage == "mapping":
        command["writes"][1 if native_items else 0]["path"][2 if native_items else -1] = "item_id:foreign"
    elif damage == "owner":
        original["bindings"][0]["owners"] = ["occurrence:a/shot", "occurrence:foreign/shot"]
    elif damage in {"revision", "digest"}:
        original["bindings"][0]["revision_id" if damage == "revision" else "content_digest"] = "foreign"
    elif damage == "source-command":
        command["bindings"][0]["boundary"]["command_ordinals"] = [1]
    elif damage == "native-order":
        command["writes"].reverse()
    elif damage == "native-count":
        command["writes"].append(copy.deepcopy(command["writes"][-1]))
    elif damage == "native-omitted":
        command["writes"].pop()
    elif damage == "native-range":
        command["bindings"][0]["boundary"]["native_write_range"][1] -= 1
    elif damage == "effect-range":
        command["bindings"][0]["boundary"]["effect_range"][1] -= 1
    elif damage == "effect-order":
        step["patch"].reverse()
    elif damage == "effect-count":
        step["patch"].append(copy.deepcopy(step["patch"][-1]))
        command["bindings"][0]["boundary"]["effect_range"][1] += 1
    elif damage == "effect-value":
        step["patch"][0]["value"] = "foreign"
    elif damage == "foreign-write":
        command["writes"][0]["ref"] = "occurrence:b/clip:clip"
    elif damage == "history":
        history["publication"]["receipt"]["receipt_id"] = "foreign"
    elif damage == "equal-byte-retarget":
        before["shot-revision:copy-shot"]["revision_id"] = "unproven"
    elif damage == "sibling":
        after["parent"]["payload"]["occurrences"][1]["shot_id"] = "foreign"

    def verify():
        assert _inverse_stage_ranges(step, records, history)
        return _inverse_stage_boundaries(before, after, step, records, after, before, history)

    if damage is None:
        assert len(verify()) == 4
    else:
        with pytest.raises(CommitRejected):
            verify()
