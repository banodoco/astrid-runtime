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


def _end_card_closure(offset_ms=0, duration_ms=4000):
    """The last shot of a film: its window ends at 14 s but its end card (a picture) runs to 19 s (5 s past)."""
    occurrence = {"occurrence_id": "occ-1", "placement": {"start_ms": 10000, "track": "picture"}, "duration_ms": duration_ms,
                  "source_offset": offset_ms, "speed": 1}
    child = {"tracks": [{"id": "picture", "kind": "visual"}],
             "clips": [{"id": "end-card", "track": "picture", "clipType": "media", "asset": "a", "at": 0, "from": 0, "hold": 9}],
             "registry": {"assets": copy.deepcopy(ASSETS)}}
    return occurrence, child


def _seam_and_render(offset_ms, duration_ms=4000):
    """(seam clip, render clip) of one 9 s child on a last shot whose window is [10 s, 14 s]: what the preview path
    (visual_seam) and the render path (expand_shot_clips) each do with the 5 s that run past it."""
    occurrence, child = _end_card_closure(offset_ms, duration_ms)
    parent = {"config": {"output": {"resolution": "1280x720", "fps": 30}, "tracks": [{"id": "picture", "kind": "visual"}], "clips": []},
              "registry": {"assets": {}}, "clips": [],
              "occurrences": [{**occurrence, "shot_id": "shot-1", "shot_revision_id": "rev-1", "track": "picture", "gain": 1, "muted": False}]}
    shots = {("shot-1", "rev-1"): {"internal_timeline_revision_id": "internal"}}
    _, projection = admit_closure(parent, shots, {"internal": {"payload": child}}, timeline_id="main", materialize=True)
    seam = projection["render_config"]["clips"]
    par = {"clips": [{"id": "shot", "clipType": "shot", "at": 10, "hold": duration_ms / 1000, "track": "picture",
                      "params": {"shot_id": "shot-1", "timeline_document_id": "pinned", "source_offset": offset_ms / 1000}}]}
    ch = {"clips": [dict(c, to=c["from"] + c["hold"]) for c in child["clips"]]}
    expanded, _ = expand_shot_clips(par, {"assets": {}}, load_timeline=lambda _: (ch, {"assets": copy.deepcopy(ASSETS)}))
    return seam, expanded["clips"]


def test_a_clip_past_a_trimmed_window_is_cropped_identically_by_preview_and_render():
    seam, render = _seam_and_render(offset_ms=2000)       # window shows [2 s, 6 s] of the shot
    assert len(seam) == len(render) == 1
    assert (seam[0]["at"], seam[0]["hold"]) == pytest.approx((10.0, 4.0))
    assert (render[0]["at"], render[0]["hold"]) == pytest.approx((10.0, 4.0))


def test_an_untrimmed_window_is_soft_in_the_seam_but_cut_by_the_render():
    """The one known preview/render difference: an untrimmed shot's window stretches to its content in the seam, but
    the render cuts a child off at the stored length. The Agent's check() blocks it (a child past an untrimmed window);
    a start/end trim makes the window explicit, and then both paths agree (test above)."""
    seam, render = _seam_and_render(offset_ms=0)
    assert seam[0]["hold"] == pytest.approx(9.0)          # preview would show 19 s of it
    assert render[0]["hold"] == pytest.approx(4.0)        # the render stops at 14 s


def test_the_window_helpers_read_every_stored_form():
    from runtime_protocol.occurrence_window import source_offset, visible_span

    assert source_offset(None) == source_offset({}) == source_offset(0) == 0
    assert source_offset(2000) == source_offset({"start": 2000, "end": 99999}) == 2000   # `end` is legacy, never read
    for bad in (-1, {"start": -1}, float("nan"), "2", True):
        with pytest.raises(ValidationError):
            source_offset(bad)
    assert visible_span(1000, 5000, 2000, 4000) == (2000, 5000)   # the same vectors as the Agent and App helpers
    assert visible_span(0, 2000, 2000, 4000) is None
    assert visible_span(1000, 10000, 2000, 4000) == (2000, 6000)
