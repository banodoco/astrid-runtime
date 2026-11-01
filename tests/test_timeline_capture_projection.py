"""Projection comparisons retain every authoritative image field."""
from __future__ import annotations

import copy

import pytest
from test_timeline_validation_cost import _packet

from runtime_protocol.timeline_commit_auth import _capture_projection_equal, images


def _boundary():
    return images(_packet()["capture"]["original"]["commands"][0]["input"])


def test_projection_omits_only_internal_transport_annotation_without_mutation():
    left = _boundary()
    right = copy.deepcopy(left)
    for ref, image in right.items():
        if ref.startswith("internal-revision:"):
            image["timeline_id"] = "another-transport"
    before = copy.deepcopy((left, right))

    assert _capture_projection_equal(left, right)
    assert _capture_projection_equal(right, left)
    assert (left, right) == before


@pytest.mark.parametrize("family", ["parent", "shot-revision:", "internal-revision:"])
@pytest.mark.parametrize("damage", [
    "revision", "digest", "payload", "nested_annotation", "boolean", "absent_null",
    "extra_field", "missing_image", "extra_image",
])
def test_projection_rechecks_authoritative_fields_after_equal_comparison(family, damage):
    left = _boundary()
    ref = next(ref for ref in left if ref.startswith(family))
    left[ref]["payload"]["projection_probe"] = {"value": 1, "timeline_id": "authored"}
    right = copy.deepcopy(left)
    assert _capture_projection_equal(left, right)

    image = right[ref]
    if damage == "revision":
        image["revision_id"] = "foreign"
    elif damage == "digest":
        image["content_digest"] = "sha256:" + "0" * 64
    elif damage == "payload":
        image["payload"]["projection_probe"]["value"] = 2
    elif damage == "nested_annotation":
        image["payload"]["projection_probe"]["timeline_id"] = "foreign"
    elif damage == "boolean":
        image["payload"]["projection_probe"]["value"] = True
    elif damage == "absent_null":
        image["payload"]["projection_probe"]["absent"] = None
    elif damage == "extra_field":
        image["unexpected"] = None
    elif damage == "missing_image":
        del right[ref]
    else:
        right[ref + "-foreign"] = copy.deepcopy(image)
    before = copy.deepcopy((left, right))

    assert not _capture_projection_equal(left, right)
    assert not _capture_projection_equal(right, left)
    assert (left, right) == before


@pytest.mark.parametrize("family", ["parent", "shot-revision:"])
def test_projection_preserves_non_internal_transport_named_fields(family):
    left = _boundary()
    right = copy.deepcopy(left)
    ref = next(ref for ref in right if ref.startswith(family))
    right[ref]["timeline_id"] = "foreign"
    assert not _capture_projection_equal(left, right)


def test_projection_recursively_compares_shared_payloads():
    left = _boundary()
    right = dict(left)
    left["parent"]["payload"]["nonfinite_probe"] = float("nan")
    assert not _capture_projection_equal(left, right)
