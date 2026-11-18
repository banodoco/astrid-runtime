"""source_offset is the window origin into the shot's timeline (shared fixture, same bytes as the Agent and App)."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from runtime_protocol.errors import ValidationError
from runtime_protocol.managed_render_snapshot import expand_shot_clips
from runtime_protocol.visual_seam import admit_closure

FIXTURE = json.loads((Path(__file__).parent / "fixtures/occurrence-window/start-trimmed-multi-clip.json").read_text())
ASSETS = {"a": {"object_id": "object-a", "content_sha256": "digest-a", "type": "video/mp4"}}


def closure(occurrence):
    child = {"tracks": [{"id": "picture", "kind": "visual"}], "clips": copy.deepcopy(FIXTURE["clips"]),
             "registry": {"assets": copy.deepcopy(ASSETS)}}
    parent = {"config": {"output": {"resolution": "1280x720", "fps": 30}, "tracks": [{"id": "picture", "kind": "visual"}],
                         "clips": []},
              "registry": {"assets": {}}, "clips": [],
              "occurrences": [{**copy.deepcopy(occurrence), "shot_id": "shot-1", "shot_revision_id": "rev-1",
                               "track": "picture", "gain": 1, "muted": False}]}
    return parent, {("shot-1", "rev-1"): {"internal_timeline_revision_id": "internal"}}, {"internal": {"payload": child}}


def rendered(occurrence):
    parent, shots, internals = closure(occurrence)
    _, projection = admit_closure(parent, shots, internals, timeline_id="main", materialize=True)
    return {c["id"].removeprefix("occ-1:"): c for c in projection["render_config"]["clips"]}


def test_runtime_seam_follows_the_window_origin():
    clips = rendered(FIXTURE["occurrence"])
    assert sorted(clips) == sorted(row["id"] for row in FIXTURE["expected"])
    for row in FIXTURE["expected"]:
        clip = clips[row["id"]]
        assert clip["at"] == pytest.approx(row["at"], abs=1 / 30), row["id"]
        assert clip["from"] == pytest.approx(row["from"], abs=1 / 30), row["id"]
        assert (clip["hold"] if "hold" in clip else clip["to"] - clip["from"]) == pytest.approx(row["hold"], abs=1 / 30)


def test_managed_shot_expansion_follows_the_window_origin():
    occ = FIXTURE["occurrence"]
    parent = {"clips": [{"id": "shot", "clipType": "shot", "at": occ["placement"]["start_ms"] / 1000,
                         "hold": occ["duration_ms"] / 1000, "track": "picture",
                         "params": {"shot_id": "shot-1", "timeline_document_id": "pinned",
                                    "source_offset": occ["source_offset"]["start"] / 1000}}]}
    child = {"clips": [dict(c, asset="a", to=c["from"] + c["hold"]) for c in copy.deepcopy(FIXTURE["clips"])]}
    expanded, _ = expand_shot_clips(parent, {"assets": {}}, load_timeline=lambda _: (child, {"assets": copy.deepcopy(ASSETS)}))
    by_source = {c["app"]["astrid_shot_composition"]["source_clip_id"]: c for c in expanded["clips"]}
    assert sorted(by_source) == sorted(row["id"] for row in FIXTURE["expected"])
    for row in FIXTURE["expected"]:
        clip = by_source[row["id"]]
        assert clip["at"] == pytest.approx(row["at"]) and clip["hold"] == pytest.approx(row["hold"])
        assert clip.get("from", 0) == pytest.approx(row["from"])


def test_a_negative_source_offset_is_refused_by_the_service():
    from runtime_protocol.service import RuntimeService

    with pytest.raises(ValidationError, match="must not be negative"):
        RuntimeService._normalize_occurrence(
            object.__new__(RuntimeService),
            {"occurrence_id": "o", "shot_id": "s", "shot_revision_id": "r", "placement": {"start_ms": 0},
             "source_offset": -1, "duration_ms": 1000}, shot_lookup={("s", "r"): {}})
