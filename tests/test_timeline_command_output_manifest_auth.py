"""Command-boundary authentication for manifest-only parent turnover."""
from __future__ import annotations

import copy

import pytest

from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_auth import (
    _authoring_parent_identity,
    command_output,
)
from runtime_protocol.timeline_commit_validation import digest


def _case():
    payload = {"config": {"clips": [{"id": "hold", "hold": 2}]}, "occurrences": []}
    boundary = {"parent": {"revision_id": "source-parent", "content_digest": digest(payload),
                            "payload": payload}}
    p1 = {"document_id": "pack", "version": 1, "content_digest": "sha256:" + "1" * 64}
    p2 = {"document_id": "pack", "version": 2, "content_digest": "sha256:" + "2" * 64}
    previous = {"shots": [], "internal_timelines": [], "media": [], "documents": [p1]}
    consumed = {**copy.deepcopy(previous), "documents": [p1, p2]}
    record = {"dependencies": [{"kind": "source", "pin": p2}], "writes": [],
              "derived_writes": [], "created": []}
    expected = _authoring_parent_identity(boundary, ("project", "timeline"), consumed)
    following = {"bindings": [{"physical_ref": "parent", "revision_id": expected,
                                "content_digest": digest(payload),
                                "boundary": {"phase": "input"}}]}
    return boundary, record, following, previous, consumed, p1, p2, expected


def test_consumed_manifest_turnover_projects_authenticated_parent_revision():
    boundary, record, following, previous, consumed, _p1, _p2, expected = _case()

    result = command_output(boundary, record, following, identity_scope=("project", "timeline"),
                            manifest=consumed, previous_manifest=previous)

    assert result["parent"]["payload"] == boundary["parent"]["payload"]
    assert result["parent"]["content_digest"] == boundary["parent"]["content_digest"]
    assert result["parent"]["revision_id"] == expected


@pytest.mark.parametrize("mutation", ["missing", "foreign", "stale", "retargeted"])
def test_manifest_only_turnover_requires_the_following_authenticated_parent_pin(mutation):
    boundary, record, following, previous, consumed, _p1, p2, _expected = _case()
    if mutation == "missing":
        following["bindings"] = []
    elif mutation == "foreign":
        following["bindings"][0]["revision_id"] = "foreign-parent"
    elif mutation == "stale":
        following["bindings"][0]["revision_id"] = _authoring_parent_identity(
            boundary, ("project", "timeline"), previous)
    else:
        record["dependencies"][0]["pin"] = {**p2, "document_id": "other-pack"}

    with pytest.raises(CommitRejected):
        command_output(boundary, record, following, identity_scope=("project", "timeline"),
                       manifest=consumed, previous_manifest=previous)


def test_equal_payload_alone_does_not_project_a_manifest_revision():
    boundary, record, following, _previous, consumed, _p1, _p2, expected = _case()
    result = command_output(boundary, record, following, identity_scope=("project", "timeline"),
                            manifest=consumed)

    assert result["parent"]["revision_id"] == "source-parent"
    assert result["parent"]["revision_id"] != expected


def test_unconsumed_manifest_claim_is_rejected_at_the_command_boundary():
    boundary, record, following, previous, consumed, _p1, p2, _expected = _case()
    record["dependencies"] = []
    consumed["documents"] = [previous["documents"][0], p2]

    with pytest.raises(CommitRejected):
        command_output(boundary, record, following, identity_scope=("project", "timeline"),
                       manifest=consumed, previous_manifest=previous)


def test_ordered_derived_clip_mirrors_chain_within_one_command():
    initial = [{"id": "old-intro"}, {"id": "scene"}]
    first = [{"id": "scene"}]
    second = [{"id": "scene", "at": 2}]
    payload = {"config": {"clips": initial}, "occurrences": []}
    boundary = {"parent": {"revision_id": "source-parent", "content_digest": digest(payload),
                            "payload": payload}}
    def capture(before, after):
        return {"ref": "parent", "path": ["config", "clips"], "cause": 4,
                "before": {"state": "present", "value": before},
                "after": {"state": "present", "value": after}}

    record = {"ordinal": 4, "writes": [], "derived_writes": [capture(initial, first), capture(first, second)],
              "created": [], "dependencies": []}
    final_payload = {"config": {"clips": second}, "occurrences": []}
    following = {"bindings": [{"physical_ref": "parent", "revision_id": "final-parent",
                                "content_digest": digest(final_payload),
                                "boundary": {"phase": "input"}}]}

    result = command_output(boundary, record, following)

    assert result["parent"]["payload"]["config"]["clips"] == second
    assert result["parent"]["content_digest"] == digest(result["parent"]["payload"])

    forged = copy.deepcopy(record)
    forged["derived_writes"][1]["before"] = {"state": "present", "value": initial}
    with pytest.raises(CommitRejected, match="different input observation"):
        command_output(boundary, forged, following)

    forged = copy.deepcopy(record)
    forged["derived_writes"][1]["cause"] = 3
    with pytest.raises(CommitRejected, match="different input observation"):
        command_output(boundary, forged, following)
