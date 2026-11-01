"""Authenticated same-step fork/add-media projection controls."""
from __future__ import annotations

import copy

import pytest

from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_auth import command_output
from runtime_protocol.timeline_commit_validation import digest


def _case():
    old_internal = {"output": {"fps": 24}, "tracks": [], "clips": [], "registry": {"assets": {}}}
    new_internal = copy.deepcopy(old_internal)
    new_internal["registry"]["assets"]["added"] = {"media_id": "sha256:" + "4" * 64, "type": "image"}
    added = {"id": "added", "clipType": "hold", "track": "picture", "at": 0, "hold": 5,
             "asset": "added"}
    new_internal["clips"].append(added)
    old_occurrence = {"occurrence_id": "occ-new", "shot_id": "old-shot", "shot_revision_id": "old-r1",
                      "track": "picture", "placement": {"start_ms": 0}, "duration_ms": 1000}
    new_occurrence = {**old_occurrence, "shot_id": "fork-shot", "shot_revision_id": "fork-r1"}
    parent = {"config": {"output": {"fps": 24}}, "occurrences": [old_occurrence]}
    parent_after = {**parent, "occurrences": [new_occurrence]}
    initial_shot = {"name": "Opening", "internal_timeline_revision_id": "fork-internal"}
    boundary = {
        "parent": {"revision_id": "base-parent", "content_digest": digest(parent), "payload": parent},
        "shot-revision:old-r1": {"shot_id": "old-shot", "revision_id": "old-r1",
                                  "internal_timeline_revision_id": "old-internal",
                                  "payload": {"name": "Old", "internal_timeline_revision_id": "old-internal"},
                                  "content_digest": digest({"name": "Old", "internal_timeline_revision_id": "old-internal"})},
        "internal-revision:old-internal": {"timeline_id": "old-shot", "revision_id": "old-internal",
                                            "payload": old_internal, "content_digest": digest(old_internal)},
    }
    accepted = copy.deepcopy(boundary)
    accepted["parent"] = {"revision_id": "after-parent", "content_digest": digest(parent_after),
                           "payload": parent_after}
    accepted["shot-revision:fork-r1"] = {
        "shot_id": "fork-shot", "revision_id": "fork-r1", "internal_timeline_revision_id": "fork-internal",
        "payload": initial_shot, "content_digest": digest(initial_shot),
    }
    accepted["internal-revision:fork-internal"] = {
        "timeline_id": "fork-shot", "revision_id": "fork-internal", "payload": new_internal,
        "content_digest": digest(new_internal),
    }
    record = {
        "writes": [
            {"ref": "shot:fork-shot", "path": [], "before": {"state": "absent"},
             "after": {"state": "present", "value": {"payload": initial_shot,
                                                           "internal_timeline": old_internal}}},
            {"ref": "occurrence:occ-new", "path": ["shot_id"],
             "before": {"state": "present", "value": "old-shot"},
             "after": {"state": "present", "value": "fork-shot"}},
        ],
        "derived_writes": [],
        "created": [{"ref": "shot:fork-shot", "kind": "shot", "owner": None}],
    }
    following = {
        "reads": [{"ref": "occurrence:occ-new/source", "path": ["output", "fps"],
                   "state": {"state": "present", "value": 24}}],
        "bindings": [
            {"ref": "parent", "physical_ref": "parent", "revision_id": "after-parent",
             "content_digest": digest(parent_after), "boundary": {"phase": "input"}},
            {"ref": "occurrence:occ-new/source", "physical_ref": "internal-revision:fork-internal",
             "revision_id": "fork-internal", "content_digest": digest(old_internal),
             "boundary": {"phase": "input"}},
        ],
        "writes": [
            {"ref": "occurrence:occ-new/asset:added", "path": [], "before": {"state": "absent"},
             "after": {"state": "present", "value": accepted["internal-revision:fork-internal"]["payload"]["registry"]["assets"]["added"]}},
            {"ref": "occurrence:occ-new/clip:added", "path": [], "before": {"state": "absent"},
             "after": {"state": "present", "value": added}},
        ],
        "derived_writes": [],
    }
    return boundary, record, following, accepted


def test_fork_created_shot_projects_to_authenticated_add_media_boundary():
    boundary, record, following, accepted = _case()

    result = command_output(boundary, record, following, accepted=accepted)

    assert result["parent"]["payload"]["occurrences"] == [
        {"occurrence_id": "occ-new", "shot_id": "fork-shot", "shot_revision_id": "fork-r1",
         "track": "picture", "placement": {"start_ms": 0}, "duration_ms": 1000}
    ]
    assert result["shot-revision:fork-r1"]["payload"] == accepted["shot-revision:fork-r1"]["payload"]
    assert result["internal-revision:fork-internal"]["payload"] == {
        "output": {"fps": 24}, "tracks": [], "clips": [], "registry": {"assets": {}}
    }


@pytest.mark.parametrize("mutation", ["owner", "sibling", "source"])
def test_fork_created_shot_projection_rejects_unauthenticated_physical_claims(mutation):
    boundary, record, following, accepted = _case()
    if mutation == "owner":
        following["writes"][1]["after"]["value"] = {**following["writes"][1]["after"]["value"], "id": "forged"}
        record["writes"][1]["after"]["value"] = "foreign-shot"
    elif mutation == "sibling":
        accepted["shot-revision:other-r1"] = copy.deepcopy(accepted["shot-revision:fork-r1"])
        accepted["shot-revision:other-r1"]["revision_id"] = "other-r1"
    else:
        following["bindings"][1]["physical_ref"] = "internal-revision:foreign"

    with pytest.raises(CommitRejected):
        command_output(boundary, record, following, accepted=accepted)
