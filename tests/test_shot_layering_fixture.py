from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "conformance/fixtures/shot-layering-v1.json"
FIXTURE_SHA256 = "4900be369f31bd03736b7eadaf2f8595a7ce48df5218296d405162cb13cfc16c"
REQUIRED_CASES = {
    "child-audio-parent-visual",
    "child-visual-parent-audio",
    "film-picture-over-type",
    "loose-above-shot",
    "loose-below-shot",
    "loose-same-row",
    "shot-only-suffix-tracks",
    "two-shots-one-row",
    "shot-row-missing",
}
REQUIRED_OCCURRENCE_FIELDS = {
    "occurrence_id",
    "shot_id",
    "revision_id",
    "at_ms",
    "duration_ms",
}


def load_shot_layering_fixture() -> dict[str, Any]:
    """Read the checked-in conformance data; Runtime has no production fixture loader."""
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _assert_no_unknown(value: Any, path: str = "fixture") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            assert key != "UNKNOWN", f"unresolved UNKNOWN key at {path}"
            _assert_no_unknown(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _assert_no_unknown(child, f"{path}[{index}]")
    else:
        assert value != "UNKNOWN", f"unresolved UNKNOWN value at {path}"


def _assert_canonical_input(case: dict[str, Any]) -> None:
    input_data = case["input"]
    assert set(input_data) == {
        "schema_version",
        "project",
        "primary_timeline",
        "parent_composition",
        "shot_revisions",
        "cases",
        "occurrences",
    }
    assert input_data["schema_version"] == 1
    assert "shots" not in input_data
    assert "loose_clips" not in input_data
    assert "main_tracks" not in input_data
    assert input_data["cases"]["stale_write_rejection"]["expected_status"] == 409

    parent_config = input_data["parent_composition"]["config"]
    assert isinstance(parent_config["tracks"], list)
    assert isinstance(parent_config["clips"], list)
    revisions = {
        (revision["shot_id"], revision["revision_id"]): revision
        for revision in input_data["shot_revisions"]
    }
    assert revisions
    for revision in revisions.values():
        internal = revision["internal_timeline_revision"]
        timeline = internal["timeline"]
        assert internal["revision_id"]
        assert isinstance(timeline["tracks"], list)
        assert isinstance(timeline["clips"], list)
        assert all("at_ms" in clip and "duration_ms" in clip for clip in timeline["clips"])

    occurrences = input_data["occurrences"]
    assert occurrences
    for occurrence in occurrences:
        assert REQUIRED_OCCURRENCE_FIELDS <= set(occurrence)
        assert occurrence["parent_document_id"] == input_data["primary_timeline"]["document_id"]
        assert (occurrence["shot_id"], occurrence["revision_id"]) in revisions
        assert isinstance(occurrence["at_ms"], int) and occurrence["at_ms"] >= 0
        assert isinstance(occurrence["duration_ms"], int) and occurrence["duration_ms"] >= 0


def test_shared_shot_layering_fixture_is_valid_and_complete() -> None:
    fixture = load_shot_layering_fixture()

    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == FIXTURE_SHA256
    assert fixture["$schema"] == "timeline.shot-layering/v1"
    assert fixture["schema_version"] == 1
    _assert_no_unknown(fixture)

    cases = fixture["cases"]
    assert {case["id"] for case in cases} == REQUIRED_CASES
    assert fixture["representation"]["group_tag"]["path"] == "track.app.group"
    assert fixture["representation"]["empty_area"] == {
        "mode": "transparent",
        "parent_content_visible": True,
        "opaque_background": False,
    }

    for case in cases:
        _assert_canonical_input(case)
        expected = case["expected"]
        assert expected["track_order"]
        group_ids = [group["id"] for group in expected["group_tracks"]]
        assert all(group_id in expected["track_order"] for group_id in group_ids)
        for group in expected["group_tracks"]:
            tag = group["app"]["group"]
            assert group["id"] == f"{tag['id']}~{tag['sourceTrack']}"


def test_shared_fixture_preserves_settled_layering_semantics() -> None:
    fixture = load_shot_layering_fixture()
    cases = {case["id"]: case for case in fixture["cases"]}

    film = cases["film-picture-over-type"]
    assert film["expected"]["transparent_windows_ms"] == [[21100, 28700]]
    assert film["expected"]["clip_tracks"]["clip-0"] == "type"
    assert film["expected"]["clip_tracks"]["vision-audio"] == "audio"
    assert film["input"]["occurrences"][0]["track"] == "picture"

    assert cases["loose-above-shot"]["expected"]["track_order"][:2] == ["overlay", "occ-above~plate"]
    assert cases["loose-below-shot"]["expected"]["track_order"][:2] == ["occ-below~plate", "picture"]
    assert cases["loose-same-row"]["expected"]["same_row_warning"] is False
    assert cases["shot-only-suffix-tracks"]["expected"]["track_order"][:2] == ["occ-suffix~plate", "occ-suffix~title"]

    two_shots = cases["two-shots-one-row"]
    assert [item["occurrence_id"] for item in two_shots["input"]["occurrences"]] == ["occ-first", "occ-second"]
    assert two_shots["expected"]["track_order"][:3] == ["occ-first~plate", "occ-second~plate", "occ-second~type"]

    missing = cases["shot-row-missing"]["expected"]["warnings"]
    assert missing == [{
        "severity": "warning",
        "code": "timeline-patch/target-not-found",
        "message": "shot-layering: track \"picture\" not found — placing occurrence \"occ-missing\" at top of stack",
    }]

    audio_child = cases["child-audio-parent-visual"]["expected"]
    assert "clip_timing" not in audio_child
    assert audio_child["track_order"] == ["picture", "shared", "music", "occ-collision~shared"]
    assert audio_child["group_tracks"] == []
    assert audio_child["clip_tracks"] == {
        "parent-clip": "shared",
        "trim-inherited": "occ-collision~shared",
        "hold-inherited": "occ-collision~shared",
        "trim-child-speed": "occ-collision~shared",
        "hold-child-speed": "occ-collision~shared",
        "compatible-audio": "music",
    }

    visual_child = cases["child-visual-parent-audio"]["expected"]
    assert "clip_timing" not in visual_child
    assert visual_child["track_order"] == ["occ-collision~shared", "picture", "shared", "music"]
    assert visual_child["group_tracks"] == [{
        "id": "occ-collision~shared",
        "app": {"group": {"id": "occ-collision", "sourceTrack": "shared"}},
    }]
    assert visual_child["clip_tracks"] == {
        "parent-clip": "shared",
        "trim-inherited": "occ-collision~shared",
        "hold-inherited": "occ-collision~shared",
        "trim-child-speed": "occ-collision~shared",
        "hold-child-speed": "occ-collision~shared",
        "compatible-audio": "music",
    }


def test_shared_fixture_groups_source_role_visual_track() -> None:
    fixture = load_shot_layering_fixture()
    film = next(case for case in fixture["cases"] if case["id"] == "film-picture-over-type")
    timeline = film["input"]["shot_revisions"][0]["internal_timeline_revision"]["timeline"]

    assert {"id": "source-plate", "kind": "visual", "role": "source"} in timeline["tracks"]
    source_clip = next(clip for clip in timeline["clips"] if clip["id"] == "vision-source-plate")
    assert source_clip["track"] == "source-plate"
    assert source_clip["duration_ms"] > 0
    assert film["input"]["occurrences"][0]["occurrence_id"] == "occ-vision"

    expected = film["expected"]
    assert "occ-vision~source-plate" in expected["track_order"]
    assert {
        "id": "occ-vision~source-plate",
        "role": "output",
        "app": {"group": {"id": "occ-vision", "sourceTrack": "source-plate"}},
    } in expected["group_tracks"]
    assert expected["clip_tracks"][source_clip["id"]] == "occ-vision~source-plate"


def test_shared_fixture_rejects_unknown_values_at_any_depth() -> None:
    fixture = load_shot_layering_fixture()
    fixture["cases"][0]["input"]["shot_revisions"][0]["internal_timeline_revision"]["timeline"]["clips"][0]["asset_id"] = "UNKNOWN"

    with pytest.raises(AssertionError, match="unresolved UNKNOWN value"):
        _assert_no_unknown(fixture)
