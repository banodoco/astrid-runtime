"""R13 built-in visual timing remains disclosed by Runtime's closed boundary."""

import pytest

from runtime_protocol.visual_boundary import boundary_report, transition_frames
from runtime_protocol.visual_seam import evaluate_closure


def _report(clip, *, fps=30, start=0, end=120, origin=0):
    return boundary_report({
        "clip": {"clipType": "media", **clip},
        "fps": fps,
        "startFrame": start,
        "endFrame": end,
        "originFrame": origin,
        "path": ["clip"],
        "params": {},
    })


@pytest.mark.parametrize("identity", ["crossfade", "cross-fade", "fade", "wipe", "slide-push", "zoom-through"])
def test_r13_transition_renderers_have_trusted_timing(identity):
    assert transition_frames({"type": identity}, 30) == 8
    assert transition_frames({"id": identity, "durationFrames": 17}, 30) == 17
    assert transition_frames({"type": identity, "duration": 0.5}, 30) == 15
    assert "unsupported transition timing" not in _report({"transition": {"type": identity}})["opaque"]


@pytest.mark.parametrize("identity", ["crossfade", "wipe", "slide-push", "zoom-through"])
def test_r13_incoming_transition_is_accepted_at_picture_join(identity):
    track = {"id": "v", "kind": "visual", "label": "Picture"}
    clip = {"clipType": "media", "track": "v", "asset": "picture", "hold": 1}
    parent = {
        "config": {"tracks": [track], "output": {"fps": 30, "resolution": "128x72"}},
        "registry": {"assets": {"picture": {"type": "image", "file": "picture.png"}}},
        "clips": [
            {**clip, "id": "outgoing", "at": 0},
            {**clip, "id": "incoming", "at": 0.8, "transition": {"type": identity, "duration": 0.2}},
        ],
        "occurrences": [],
    }
    report, _ = evaluate_closure(parent, {}, {}, timeline_id="r13")
    assert report["structuralIssues"] == []
    assert report["opaqueElements"] == []


def test_unknown_transition_remains_opaque():
    assert transition_frames({"type": "crossfadee"}, 30) is None
    assert transition_frames({"type": ["crossfade"]}, 30) is None
    assert "unsupported transition timing" in _report({"transition": {"type": "crossfadee"}})["opaque"]


@pytest.mark.parametrize("phase,identity", [
    *[("entrance", identity) for identity in (
        "slide-down", "slide-right", "zoom-in", "zoom-spin", "pulse", "flip", "bounce", "meteorite",
    )],
    *[("exit", identity) for identity in ("slide-down", "zoom-out", "flip", "fade-out", "shrink", "dissolve")],
])
def test_r13_phase_effects_use_wrapper_duration_fallback(phase, identity):
    report = _report({phase: {"type": identity}}, fps=30)
    assert report["opaque"] == []
    assert report["cues"] == [{"frame": 1 if phase == "entrance" else 109,
                              "kind": "motion-start", "id": phase, "path": ["clip"]}]


@pytest.mark.parametrize("phase", ["entrance", "exit"])
def test_r13_phase_effect_duration_overrides_are_used(phase):
    identity = "meteorite" if phase == "entrance" else "dissolve"
    explicit_frames = _report({phase: {"type": identity, "durationFrames": 20}})
    assert explicit_frames["cues"][0]["frame"] == (1 if phase == "entrance" else 101)
    seconds = _report({phase: {"type": identity, "duration": 0.5}})
    assert seconds["cues"][0]["frame"] == (1 if phase == "entrance" else 106)


@pytest.mark.parametrize("identity", ["ken-burns", "float", "glitch", "slow-zoom", "drift"])
def test_r13_continuous_effects_have_trusted_timing(identity):
    report = _report({"continuous": {"type": identity}})
    assert report["opaque"] == []
    expected_frame = 0 if identity == "glitch" else 1
    assert report["cues"] == [{"frame": expected_frame, "kind": "motion-start", "id": "continuous", "path": ["clip"]}]


def test_unknown_phase_and_continuous_ids_remain_opaque():
    for phase in ("entrance", "exit"):
        report = _report({phase: {"type": "unregistered-effect"}})
        assert report["opaque"] == [f"unsupported {phase} timing"]
    report = _report({"continuous": {"type": "unregistered-effect"}})
    assert report["opaque"] == ["unsupported continuous timing"]
