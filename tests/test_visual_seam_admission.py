from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path

import pytest

from runtime_protocol.errors import ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_store import (
    TimelineCommitStore,
    digest,
    request_identity,
)
from runtime_protocol.timeline_commit_validation import validate_commit_value
from runtime_protocol.util import canonical_json
from runtime_protocol.visual_boundary import boundary_report
from runtime_protocol.visual_seam import admit_closure, evaluate_closure
from tests.astrid_checkout import astrid_checkout

ROOT = Path(__file__).resolve().parents[1]


def _fixture(path):
    return json.loads(path.read_text())


def test_boundary_vectors_match_runtime_byte_for_byte():
    vectors = _fixture(ROOT / "conformance/fixtures/visual-boundary-v1.json")
    assert len(vectors["vectors"]) >= 10
    for vector in vectors["vectors"]:
        assert boundary_report(vector["context"]) == vector["expected"], vector["name"]


def test_materialized_occurrence_timing_is_visual_only_and_matches_shared_vectors():
    vectors = _fixture(ROOT / "conformance/fixtures/occurrence-media-projection.json")
    child_assets = {
        row["asset_id"]: {
            "object_id": row["object_id"], "content_sha256": row["digest"],
            "type": row["media_type"],
        }
        for row in vectors["assets"]
    }
    child = {
        "tracks": copy.deepcopy(vectors["tracks"]),
        "clips": copy.deepcopy(vectors["clips"]),
        "registry": {"assets": child_assets},
    }
    original_child = copy.deepcopy(child)
    parent_clip = copy.deepcopy(vectors["parent_clip"])
    parent = {
        "config": {
            "output": {"resolution": "1280x720", "fps": 30},
            "tracks": [{"id": "parent-visual-lane", "kind": "visual"}],
            "clips": [parent_clip],
        },
        "registry": {"assets": {"standalone-source": {"object_id": "object-standalone-source", "type": "image/png"}}},
        "clips": [copy.deepcopy(parent_clip)],
        "occurrences": [
            {
                "occurrence_id": "occ-1", "shot_id": "shot-alpha", "shot_revision_id": "rev-a",
                "placement": {"start_ms": vectors["occurrence"]["at_ms"]},
                "source_offset": vectors["occurrence"]["source_offset"],
                "duration_ms": vectors["occurrence"]["duration_ms"],
                "speed": vectors["occurrence"]["speed"], "track": vectors["occurrence"]["track"],
                "gain": 1, "muted": False,
            },
            {
                "occurrence_id": "occ-2", "shot_id": "shot-alpha", "shot_revision_id": "rev-a",
                "placement": {"start_ms": vectors["next_occurrence"]["at_ms"]},
                "source_offset": 0, "duration_ms": vectors["next_occurrence"]["duration_ms"],
                "speed": 1, "track": vectors["next_occurrence"]["track"], "gain": 1, "muted": False,
            },
        ],
    }
    shots = {("shot-alpha", "rev-a"): {"internal_timeline_revision_id": "projection-internal"}}
    internals = {"projection-internal": {"payload": child}}

    _, projection = admit_closure(parent, shots, internals, timeline_id="main", materialize=True)
    clips = {clip["id"].removeprefix("occ-1:"): clip for clip in projection["render_config"]["clips"] if clip["id"].startswith("occ-1:")}
    for clip_id, expected in vectors["expected"].items():
        clip = clips[clip_id]
        assert clip["at"] == pytest.approx(expected["at"]), clip_id
        assert clip["from"] == pytest.approx(expected["from"]), clip_id
        if "to" in expected:
            assert clip["to"] == pytest.approx(expected["to"]), clip_id
        if "hold" in expected:
            assert clip["hold"] == pytest.approx(expected["hold"]), clip_id
        assert clip.get("speed") == expected.get("speed"), clip_id
        source_duration = clip["hold"] if "hold" in clip else clip["to"] - clip["from"]
        assert source_duration / clip.get("speed", 1) == pytest.approx(expected["timeline_duration"]), clip_id
    rendered_standalone = projection["render_config"]["clips"][0]
    assert {key: rendered_standalone.get(key) for key in parent_clip} == parent_clip
    assert projection["render_registry"]["assets"]["occ-1:lane-audio-source"]["object_id"] == "object-lane-audio-source"
    assert clips["audio-track-inherited"]["app"]["canonicalTiming"]["sourceOffsetMs"] == 350
    assert clips["audio-track-inherited"]["app"]["canonicalTiming"]["occurrenceSpeed"] == 1.5
    assert projection["render_config"]["clips"][1]["id"] == "occ-1:visual-trim-inherited"
    assert child == original_child
    assert parent["clips"] == [parent_clip]


@pytest.mark.integration  # compares against a sibling Astrid checkout's copy of the vectors
def test_shared_astrid_boundary_vectors_match_runtime_byte_for_byte():
    fixture = Path(os.environ.get("ASTRID_VISUAL_BOUNDARY_FIXTURE") or astrid_checkout() / "tests/fixtures/visual-boundary-v1.json")
    assert fixture.is_file(), f"Astrid's visual-boundary-v1.json is unavailable: {fixture}"
    vectors = _fixture(ROOT / "conformance/fixtures/visual-boundary-v1.json")
    assert vectors == _fixture(fixture)


def test_historical_pinned_closure_metadata_is_labeled_and_digest_verified():
    encoded = (ROOT / "conformance/fixtures/visual-seam-old-closure.json.gz.base64").read_bytes()
    fixture = json.loads(gzip.decompress(base64.b64decode(encoded)))
    assert fixture["provenance"]["source"] == "read-only Runtime immutable revision rows"
    assert fixture["provenance"]["mediaLoaded"] is False
    parent = fixture["parent"]
    digest = "sha256:" + hashlib.sha256(canonical_json(parent).encode()).hexdigest()
    assert digest == fixture["provenance"]["parent_digest"]
    assert fixture["provenance"]["parent_revision_id"].startswith("authoring-parent-revision-")
    # This verifies recovered historical metadata closure only; no media/pixel
    # evidence is inferred from the synthetic cross-runtime vectors.
    report, _ = evaluate_closure(
        parent,
        {(s["shot_id"], s["revision_id"]): s for s in fixture["shots"]},
        {x["revision_id"]: x for x in fixture["internal"]},
        timeline_id=fixture["provenance"]["timeline_id"],
    )
    assert report["version"] == 1
    assert report["spans"]


def _normalized(clips, policy=None, *, tracks=None, effects=None, assets=None):
    parent = {
        "config": {"output": {"fps": 30}, "tracks": tracks or [{"id": "v", "kind": "visual"}], "effects": effects or [],
                   "app": {"visualSeamContract": policy or {}}},
        "registry": {"assets": assets or {}}, "clips": clips, "occurrences": [],
    }
    return evaluate_closure(parent, {}, {}, timeline_id="t")[0]


def _portable_policy(report, frame, kind="synchronized"):
    boundary = next(b for b in report["boundaries"] if b["frame"] == frame)
    return {"intents": {str(frame): {"contextVersion": "visual-seam/v1", "frame": frame, "kind": kind,
                                    "context": boundary["canonicalContext"],
                                    "participants": boundary["canonicalCueIds"] if kind == "synchronized" else []}}}


def _motion_keys():
    return [{"at": 0, "x": 0, "y": 0, "width": 100, "height": 100, "opacity": 1},
            {"at": 0.5, "x": 10, "y": 0, "width": 100, "height": 100, "opacity": 1}]


@pytest.mark.parametrize("empty", [[], {}])
def test_optional_empty_effects_match_absence_without_erasing_real_effects(empty):
    clips = [{"id": "a", "clipType": "media", "asset": "picture", "track": "v", "at": 0, "hold": 1},
             {"id": "b", "clipType": "media", "asset": "picture", "track": "v", "at": 1, "hold": 1, "entrance": "fade"}]
    absent = _normalized(clips)
    policy = _portable_policy(absent, 30)
    clips[1]["effects"] = empty
    current = _normalized(clips, policy)
    assert current["boundaries"][0]["canonicalContext"] == absent["boundaries"][0]["canonicalContext"]
    assert not current["blocked"]
    real = [{"id": "real", "type": "animated-media-transform", "params": {"keyframes": _motion_keys()}}]
    clips[1]["effects"] = real
    changed = _normalized(clips, policy)
    owner = next(o for o in changed["boundaries"][0]["canonicalContext"]["owners"] if o["path"] == ["clip", "b"])
    assert owner["clip"]["effects"] == real
    assert changed["boundaries"][0]["canonicalContext"] != absent["boundaries"][0]["canonicalContext"]
    assert changed["blocked"]


def test_historical_phase_and_motion_require_named_portable_acknowledgement():
    vector = next(v for v in _fixture(ROOT / "conformance/fixtures/visual-boundary-v1.json")["vectors"]
                  if v["name"] == "old EndSpanning phase 1259 then geometry 1260")
    effect = vector["context"]["clip"]
    clips = [{"id": "a", "clipType": "media", "asset": "picture", "track": "v", "at": 0, "hold": 1259 / 30},
             {"id": "b", "clipType": "media", "asset": "picture", "track": "v", "at": 1259 / 30, "hold": 20}, effect]
    assets = {effect["asset"]: {"file": vector["context"]["source"], "type": "video"}}
    baseline = _normalized(clips, assets=assets)
    assert baseline["blocked"]
    boundary = baseline["boundaries"][0]
    assert (1259, "phase-change", "iteration") in [(c["frame"], c["kind"], c["id"]) for c in boundary["cues"]]
    assert (1260, "motion-start", "move-up") in [(c["frame"], c["kind"], c["id"]) for c in boundary["cues"]]
    assert all(c["path"] == ["parent", "t", "clip", effect["id"]] for c in boundary["cues"])
    assert not baseline["opaqueElements"]
    policy = _portable_policy(baseline, 1259)
    assert not _normalized(clips, policy, assets=assets)["blocked"]
    policy["intents"]["1259"]["participants"].pop()
    assert _normalized(clips, policy, assets=assets)["blocked"]


def test_continuous_and_deeper_nested_effects_retain_known_motion_and_opaque_reasons():
    clips = [{"id": "a", "clipType": "media", "asset": "picture", "track": "v", "at": 0, "hold": 1},
             {"id": "b", "clipType": "media", "asset": "picture", "track": "v", "at": 1, "hold": 1,
              "effects": [{"id": "nested", "type": "animated-media-transform", "entrance": "fade",
                           "continuous": "drift", "effects": [{"id": "deeper", "type": "submitted"}],
                           "params": {"keyframes": _motion_keys()}}]}]
    report = _normalized(clips)
    assert report["blocked"]
    path = ["parent", "t", "clip", "b", "effect", "nested"]
    opaque = next(o for o in report["opaqueElements"] if o["span"]["path"] == path)
    assert opaque["opaque"] == ["unsupported continuous timing", "unsupported nested effect timing"]
    assert any(c["path"] == path and c["id"] == "key-0" for c in report["cues"])
    assert any(c["path"] == path and c["id"] == "entrance" for c in report["cues"])


@pytest.mark.parametrize("kind", ["hard-cut", "transition", "synchronized"])
def test_incoming_crossfade_never_grants_an_unrelated_parent_effect(kind):
    clips = [{"id": "a", "clipType": "media", "asset": "picture", "track": "v", "at": 0, "hold": 1},
             {"id": "b", "clipType": "media", "asset": "picture", "track": "v", "at": 0.8, "hold": 1,
              "transition": {"type": "crossfade", "duration": 0.2}}]
    assert not _normalized(clips)["blocked"]
    effects = [{"id": "unrelated", "type": "animated-media-transform", "at": 0.8, "hold": 1,
                "params": {"keyframes": _motion_keys()}}]
    baseline = _normalized(clips, effects=effects)
    assert not baseline["structuralIssues"]
    assert baseline["boundaries"][0]["requiresIntent"]
    assert all(c["path"] == ["parent", "t", "effect", "unrelated"] for c in baseline["boundaries"][0]["cues"])
    assert _normalized(clips, _portable_policy(baseline, 24, kind), effects=effects)["blocked"] is (kind != "synchronized")


def test_opaque_overlay_activation_is_not_a_picture_warning():
    clips = [{"id": "a", "clipType": "media", "asset": "picture", "track": "v", "at": 0, "hold": 1},
             {"id": "b", "clipType": "media", "asset": "picture", "track": "v", "at": 1, "hold": 1},
             {"id": "fx", "clipType": "submitted", "track": "fx", "at": 1, "hold": 1}]
    baseline = _normalized(clips)
    assert not baseline["blocked"]
    assert baseline["boundaries"][0]["cues"] == []
    assert baseline["boundaries"][0]["opaquePaths"] == []
    assert baseline["opaqueElements"] == []


def test_opaque_primary_picture_owner_is_represented_by_the_cut_not_auxiliary_activation():
    clips = [{"id": "a", "clipType": "haus.astrid.liveScene", "track": "v", "at": 0, "hold": 1},
             {"id": "b", "clipType": "haus.astrid.liveScene", "track": "v", "at": 1, "hold": 1}]
    report = _normalized(clips, {"pictureTracks": ["v"]})
    assert not report["blocked"]
    assert report["boundaries"][0]["opaquePaths"] == [["parent", "t", "clip", "b"]]
    assert not report["cues"]


def test_spanning_cue_free_secondary_picture_is_not_an_intent_owner():
    tracks = [{"id": "v", "kind": "visual"}, {"id": "secondary", "kind": "visual"}]
    clips = [{"id": "a", "clipType": "media", "asset": "picture", "track": "v", "at": 0, "hold": 1},
             {"id": "b", "clipType": "media", "asset": "picture", "track": "v", "at": 1, "hold": 1, "entrance": "fade"},
             {"id": "spanning", "clipType": "media", "asset": "picture", "track": "secondary", "at": 0, "hold": 4}]
    baseline = _normalized(clips, tracks=tracks)
    owners = baseline["boundaries"][0]["canonicalContext"]["owners"]
    assert [o["path"] for o in owners] == [["clip", "a"], ["clip", "b"]]
    policy = _portable_policy(baseline, 30)
    assert not _normalized(clips, policy, tracks=tracks)["blocked"]
    clips[2]["opacity"] = 0.5
    assert not _normalized(clips, policy, tracks=tracks)["blocked"]
    clips[1]["entrance"] = {"type": "fade", "duration": 0.7}
    assert _normalized(clips, policy, tracks=tracks)["blocked"]


def test_two_occurrence_portable_context_ignores_spanning_secondary_child():
    tracks = [{"id": "v", "kind": "visual"}, {"id": "secondary", "kind": "visual"}]
    parent = {
        "config": {"output": {"fps": 30}, "tracks": tracks}, "registry": {}, "clips": [],
        "occurrences": [
            {"occurrence_id": "outgoing", "shot_id": "s1", "shot_revision_id": "r1",
             "placement": {"start_ms": 0}, "source_offset": 0, "duration_ms": 1000,
             "speed": 1, "track": "v", "transform": {}, "gain": 1, "mute": False},
            {"occurrence_id": "incoming", "shot_id": "s2", "shot_revision_id": "r2",
             "placement": {"start_ms": 1000}, "source_offset": 0, "duration_ms": 1000,
             "speed": 1, "track": "v", "transform": {}, "gain": 1, "mute": False},
        ],
    }
    shots = {
        ("s1", "r1"): {"internal_timeline_revision_id": "i1"},
        ("s2", "r2"): {"internal_timeline_revision_id": "i2"},
    }
    internals = {
        "i1": {"payload": {"tracks": tracks, "clips": [
            {"id": "a", "clipType": "media", "asset": "picture", "track": "v", "at": 0, "hold": 1},
            {"id": "spanning", "clipType": "media", "asset": "picture", "track": "secondary", "at": 0, "hold": 1},
        ], "registry": {}}},
        "i2": {"payload": {"tracks": tracks, "clips": [
            {"id": "b", "clipType": "media", "asset": "picture", "track": "v", "at": 0, "hold": 1, "entrance": "fade"},
        ], "registry": {}}},
    }
    baseline, _ = evaluate_closure(parent, shots, internals, timeline_id="main")
    boundary = next(b for b in baseline["boundaries"] if b["frame"] == 30)
    assert [owner["path"] for owner in boundary["canonicalContext"]["owners"]] == [
        ["occurrence", "incoming", "clip", "b"], ["occurrence", "outgoing", "clip", "a"]]
    policy = {"intents": {"30": {"contextVersion": "visual-seam/v1", "frame": 30,
                                  "kind": "synchronized", "context": boundary["canonicalContext"],
                                  "participants": boundary["canonicalCueIds"]}}}
    parent["config"]["app"] = {"visualSeamContract": policy}
    acknowledged, _ = evaluate_closure(parent, shots, internals, timeline_id="main")
    assert not acknowledged["blocked"]

    internals["i1"]["payload"]["clips"][1]["opacity"] = 0.5
    unchanged_secondary, _ = evaluate_closure(parent, shots, internals, timeline_id="main")
    assert not unchanged_secondary["blocked"]
    internals["i2"]["payload"]["clips"][0]["entrance"] = {"type": "fade", "duration": 0.7}
    changed_picture, _ = evaluate_closure(parent, shots, internals, timeline_id="main")
    assert changed_picture["blocked"]


@pytest.mark.parametrize("mode", ["cue-free", "cue-contributor", "lane-boundary"])
def test_occurrence_context_binds_lane_boundary_children_and_independent_cues(mode):
    tracks = [{"id": "v", "kind": "visual"}, {"id": "secondary", "kind": "visual"}]
    outgoing = [{"id": "a", "clipType": "media", "asset": "picture", "track": "v", "at": 0, "hold": 1},
                {"id": "spanning", "clipType": "media", "asset": "picture", "track": "secondary", "at": 0, "hold": 1}]
    incoming = [{"id": "b", "clipType": "media", "asset": "picture", "track": "v", "at": 0, "hold": 1,
                 "entrance": {"type": "fade", "duration": 0.5}}]
    if mode == "cue-contributor":
        outgoing[1]["exit"] = {"type": "fade", "durationFrames": 2}
    if mode == "lane-boundary":
        incoming.append({"id": "secondary-in", "clipType": "media", "asset": "picture", "track": "secondary", "at": 0, "hold": 1})
    parent = {"config": {"output": {"fps": 30}, "tracks": tracks}, "clips": [], "registry": {},
              "occurrences": [{"occurrence_id": f"o-{i}", "shot_id": f"s-{i}", "shot_revision_id": f"sr-{i}",
                               "placement": {"start_ms": i * 1000}, "track": "v", "duration_ms": 1000}
                              for i in range(2)]}
    shots = {(f"s-{i}", f"sr-{i}"): {"internal_timeline_revision_id": f"ir-{i}"} for i in range(2)}
    internal = {f"ir-{i}": {"payload": {"clips": clips}} for i, clips in enumerate([outgoing, incoming])}
    baseline, _ = evaluate_closure(parent, shots, internal, timeline_id="main")
    assert baseline["blocked"]
    boundary = next(b for b in baseline["boundaries"] if b["frame"] == 30)
    expected_paths = [["occurrence", "o-0", "clip", "a"]]
    if mode != "cue-free":
        expected_paths.append(["occurrence", "o-0", "clip", "spanning"])
    expected_paths.append(["occurrence", "o-1", "clip", "b"])
    if mode == "lane-boundary":
        expected_paths.append(["occurrence", "o-1", "clip", "secondary-in"])
    assert [o["path"] for o in boundary["canonicalContext"]["owners"]] == expected_paths
    # Owner selection must leave full child geometry/coverage available.
    assert len(baseline["spans"]) == len(outgoing) + len(incoming)
    assert not baseline["structuralIssues"]
    parent["config"]["app"] = {"visualSeamContract": _portable_policy(baseline, 30)}
    admitted, _ = admit_closure(parent, shots, internal, timeline_id="main")
    assert not admitted["blocked"]
    if mode == "cue-free":
        outgoing[1]["opacity"] = 0.5
        unrelated, _ = admit_closure(parent, shots, internal, timeline_id="main")
        assert unrelated["boundaries"][0]["canonicalContext"] == boundary["canonicalContext"]
    # Every selected picture or cue contributor remains bound, including the
    # secondary lane when it contributes a cue or its own adjacent pair.
    for path in expected_paths:
        clips = outgoing if path[1] == "o-0" else incoming
        clip = next(c for c in clips if c["id"] == path[-1])
        original = copy.deepcopy(clip)
        clip["rotation"] = 15
        changed, _ = evaluate_closure(parent, shots, internal, timeline_id="main")
        assert changed["boundaries"][0]["canonicalContext"] != boundary["canonicalContext"]
        assert changed["blocked"]
        diagnostic, materialized = admit_closure(parent, shots, internal, timeline_id="main", materialize=True)
        assert diagnostic["blocked"]
        assert materialized["render_config"]["clips"]
        clip.clear()
        clip.update(original)
    incoming[0]["entrance"] = {"type": "fade", "duration": 0.7}
    assert evaluate_closure(parent, shots, internal, timeline_id="main")[0]["blocked"]


@pytest.mark.parametrize("mode", ["cue-free", "cue-contributor", "secondary-cut", "independent-effect"])
def test_occurrence_seam_binds_lane_boundary_owners_and_independent_cue_contributors(mode):
    tracks = [{"id": "v", "kind": "visual"}, {"id": "secondary", "kind": "visual"}]
    outgoing = [{"id": "a", "clipType": "media", "asset": "picture", "track": "v", "at": 0, "hold": 1},
                {"id": "spanning", "clipType": "media", "asset": "picture", "track": "secondary", "at": 0, "hold": 1}]
    incoming = [{"id": "b", "clipType": "media", "asset": "picture", "track": "v", "at": 0, "hold": 1,
                 "entrance": {"type": "fade", "duration": 0.5}}]
    if mode == "cue-contributor":
        outgoing[1]["exit"] = {"type": "fade", "durationFrames": 2}
    if mode == "secondary-cut":
        incoming.append({"id": "secondary-in", "clipType": "media", "asset": "picture", "track": "secondary", "at": 0, "hold": 1})
    if mode == "independent-effect":
        outgoing[1]["effects"] = [{"id": "nested", "type": "animated-media-transform",
                                    "params": {"keyframes": [
                                        {**_motion_keys()[0], "at": 28 / 30},
                                        {**_motion_keys()[1], "at": 29 / 30}]}}]
    parent = {"config": {"output": {"fps": 30}, "tracks": tracks}, "clips": [], "registry": {},
              "occurrences": [{"occurrence_id": f"o-{i}", "shot_id": f"s-{i}", "shot_revision_id": f"sr-{i}",
                               "placement": {"start_ms": i * 1000}, "track": "v", "duration_ms": 1000}
                              for i in range(2)]}
    shots = {(f"s-{i}", f"sr-{i}"): {"internal_timeline_revision_id": f"ir-{i}"} for i in range(2)}
    internal = {f"ir-{i}": {"payload": {"tracks": tracks, "clips": clips}}
                for i, clips in enumerate((outgoing, incoming))}
    baseline, metadata = evaluate_closure(parent, shots, internal, timeline_id="main")
    boundary = next(b for b in baseline["boundaries"] if b["frame"] == 30)
    expected_paths = [["occurrence", "o-0", "clip", "a"]]
    if mode in ("cue-contributor", "secondary-cut"):
        expected_paths.append(["occurrence", "o-0", "clip", "spanning"])
    if mode == "independent-effect":
        expected_paths.append(["occurrence", "o-0", "clip", "spanning", "effect", "nested"])
    expected_paths.append(["occurrence", "o-1", "clip", "b"])
    if mode == "secondary-cut":
        expected_paths.append(["occurrence", "o-1", "clip", "secondary-in"])
    assert [o["path"] for o in boundary["canonicalContext"]["owners"]] == expected_paths
    # Omission from the portable witness never removes child disclosure or coverage.
    assert any(s["path"][-1] == "spanning" for s in metadata["spans"])
    assert not baseline["structuralIssues"]
    assert baseline["blocked"]
    parent["config"]["app"] = {"visualSeamContract": _portable_policy(baseline, 30)}
    assert not admit_closure(parent, shots, internal, timeline_id="main")[0]["blocked"]
    if mode == "cue-free":
        outgoing[1]["opacity"] = 0.5
        assert not admit_closure(parent, shots, internal, timeline_id="main")[0]["blocked"]
        outgoing[1]["exit"] = {"type": "fade", "durationFrames": 2}
    elif mode == "independent-effect":
        outgoing[1]["effects"][0]["params"]["keyframes"][1]["x"] = 20
    else:
        outgoing[1]["opacity"] = 0.5
    diagnostic, materialized = admit_closure(parent, shots, internal, timeline_id="main", materialize=True)
    assert diagnostic["blocked"]
    assert materialized["render_config"]["clips"]
    # Reauthor, then a relevant incoming fade edit must independently invalidate.
    current = evaluate_closure(parent, shots, internal, timeline_id="main")[0]
    parent["config"]["app"] = {"visualSeamContract": _portable_policy(current, 30)}
    assert not admit_closure(parent, shots, internal, timeline_id="main")[0]["blocked"]
    incoming[0]["entrance"]["duration"] = 0.7
    diagnostic, materialized = admit_closure(parent, shots, internal, timeline_id="main", materialize=True)
    assert diagnostic["blocked"]
    assert materialized["render_config"]["clips"]


@pytest.mark.parametrize("pause", [
    {"kind": "pause", "track": "v", "startFrame": 29, "endFrame": 60},
    {"kind": "pause", "track": "v", "startFrame": 30, "endFrame": 61},
    {"kind": "pause", "track": "secondary", "startFrame": 30, "endFrame": 60},
    {"kind": "pause", "track": "v", "startFrame": True, "endFrame": 60},
])
def test_pause_grants_only_its_exact_picture_interval(pause):
    clips = [{"id": "a", "clipType": "media", "asset": "picture", "track": "v", "at": 0, "hold": 1},
             {"id": "b", "clipType": "media", "asset": "picture", "track": "v", "at": 2, "hold": 1,
              "app": {"visualBoundary": {"intentionalPause": True}}}]
    assert _normalized(clips)["blocked"]
    assert _normalized(clips, {"gaps": [pause]})["blocked"]
    policy = {"gaps": [{"kind": "pause", "track": "v", "startFrame": 30, "endFrame": 60}]}
    assert not _normalized(clips, policy)["blocked"]
    clips.append({"id": "c", "clipType": "media", "asset": "picture", "track": "v", "at": 4, "hold": 1})
    assert [i["frame"] for i in _normalized(clips, policy)["structuralIssues"]] == [120]


@pytest.mark.parametrize("shape", [
    {"entrance": "fade", "exit": ["fade", {"id": "slide-up", "durationFrames": 6}], "transition": "crossfade"},
    {"entrance": ["fade", {"id": "slide-up", "durationFrames": 6}], "exit": "fade", "transition": ["crossfade"]},
])
def test_materialization_retains_effect_shapes_and_child_parent_scope(shape):
    parent = _unsafe_publication("p")["parent_composition"]
    parent["occurrences"][0]["placement"]["start_ms"] = 1000
    local = {"id": "local", "type": "animated-media-transform", "params": {"keyframes": _motion_keys()}}
    child_effect = {"id": "child", "type": "animated-media-transform", "at": 1, "hold": 1, "params": {"keyframes": _motion_keys()}}
    parent_effect = {"id": "parent", "type": "animated-media-transform", "at": 2, "hold": 1, "params": {"keyframes": _motion_keys()}}
    parent["config"]["effects"] = [parent_effect]
    child = {"tracks": [{"id": "v", "kind": "visual"}], "clips": [
        {"id": "a", "clipType": "media", "asset": "picture", "track": "v", "at": 0, "hold": 1, **shape, "effects": [local]},
        {"id": "b", "clipType": "media", "asset": "picture", "track": "v", "at": 1, "hold": 1}], "effects": [child_effect]}
    original = copy.deepcopy(child)
    report, metadata = evaluate_closure(parent, {("s", "unsafe-shot"): {"internal_timeline_revision_id": "unsafe-child"}},
                                       {"unsafe-child": {"payload": child}}, timeline_id="main", materialize=True)
    rendered = metadata["render_config"]["clips"][0]
    assert all(rendered[k] == v for k, v in shape.items())
    assert rendered["effects"] == [local, child_effect]
    assert rendered["app"]["canonicalEffects"] == {"localCount": 1, "timeline": [child_effect]}
    assert metadata["render_config"]["effects"] == [parent_effect]
    assert child == original
    boundary = next(b for b in report["boundaries"] if b["frame"] == 60)
    assert any(c["path"] == ["parent", "main", "occurrence", "o", "effect", "child"] for c in boundary["cues"])
    assert any(c["path"] == ["parent", "main", "effect", "parent"] for c in boundary["cues"])
    assert report["blocked"]
    parent["config"]["app"] = {"visualSeamContract": _portable_policy(report, 60)}
    assert not evaluate_closure(parent, {("s", "unsafe-shot"): {"internal_timeline_revision_id": "unsafe-child"}},
                                {"unsafe-child": {"payload": child}}, timeline_id="main")[0]["blocked"]


def test_disclosure_is_opaque_for_unknown_effect_and_caller_report_is_ignored():
    clip = {"id": "unknown", "clipType": "submitted-plugin", "at": 0, "hold": 4, "track": "v",
            "report": {"cues": [], "opaque": []}, "visual_seam_report": {"blocked": False},
            "params": {"code": "raise RuntimeError('must not execute')"}}
    report = _normalized([clip], {"pictureTracks": ["v"]})
    assert report["opaqueElements"]
    assert report["opaqueElements"][0]["opaque"] == ["unknown effect timing"]
    assert not report["cues"]


def test_gap_overlap_and_context_bound_intent_are_evaluated_from_authored_clips():
    clips = [
        {"id": "a", "clipType": "media", "asset": "picture", "at": 0, "hold": 1, "track": "v"},
        {"id": "b", "clipType": "media", "asset": "picture", "at": 1.2, "hold": 1, "track": "v"},
    ]
    report = _normalized(clips)
    assert any(row["code"] == "boundary/gap" and row["frames"] == 6 for row in report["structuralIssues"])
    overlapping = copy.deepcopy(clips)
    overlapping[1]["at"] = 0.8
    report = _normalized(overlapping)
    assert any(row["code"] == "boundary/overlap" and row["frames"] == 6 for row in report["structuralIssues"])
    transitioned = copy.deepcopy(overlapping)
    transitioned[1]["transition"] = {"type": "crossfade", "duration": 0.2}
    assert not any(row["code"] == "boundary/overlap" for row in _normalized(transitioned)["structuralIssues"])

    moving = [
        {"id": "a", "clipType": "media", "asset": "picture", "at": 0, "hold": 1, "track": "v"},
        {"id": "b", "clipType": "media", "asset": "picture", "at": 1, "hold": 1, "track": "v",
         "keyframes": {"x": [{"time": 0, "value": 0}, {"time": 0.5, "value": 8}]}},
    ]
    baseline = _normalized(moving)
    assert baseline["boundaries"] and baseline["boundaries"][0]["requiresIntent"]
    boundary = baseline["boundaries"][0]
    cue_ids = ["/".join(cue["path"]) + ":" + cue["kind"] + ":" + cue["id"] + ":" + str(cue["frame"])
               for cue in boundary["cues"]]
    policy = {"intents": {str(boundary["frame"]): {"frame": boundary["frame"], "kind": "synchronized",
                                                        "context": boundary["context"], "participants": cue_ids}}}
    acknowledged = _normalized(moving, policy)
    assert not acknowledged["boundaries"][0]["requiresIntent"]
    policy["intents"][str(boundary["frame"])]["context"] = "forged"
    assert _normalized(moving, policy)["boundaries"][0]["requiresIntent"]


def _unsafe_publication(project_id):
    body = {
        "project_id": project_id, "timeline_id": "main", "expected_head": None, "parent_revision_id": "unsafe-parent",
        "internal_timeline_revisions": [{"timeline_id": "main", "revision_id": "unsafe-child",
            "payload": {"tracks": [], "clips": [
                {"id": "first", "clipType": "media", "asset": "picture", "at": 0, "hold": 1, "track": "v"},
                {"id": "second", "clipType": "media", "asset": "picture", "at": 1.2, "hold": 1, "track": "v"},
            ], "effects": [], "audio": [], "layout": {}, "registry": {}, "assets": []}}],
        "shot_revisions": [{"shot_id": "s", "revision_id": "unsafe-shot", "internal_timeline_revision_id": "unsafe-child",
            "payload": {"metadata": {}, "items": [], "pools": [], "selected_variants": {}, "provenance": {},
                        "generation_inputs": {}, "audio_bindings": [], "text_bindings": []}}],
        "parent_composition": {"config": {"output": {"fps": 30}, "tracks": [{"id": "v", "kind": "visual"}]},
            "registry": {}, "clips": [], "occurrences": [{"occurrence_id": "o", "shot_id": "s", "shot_revision_id": "unsafe-shot",
                "placement": {"start_ms": 0}, "source_offset": 0, "duration_ms": 3000, "speed": 1,
                "track": "v", "transform": {}, "gain": 1, "mute": False, "provenance": {}}]},
    }
    return body


def _accept_visual_publication(service, publication, *, idempotency_key):
    """Install a visual fixture through the renderer-free host acceptance seam."""
    project_id = publication["project_id"]
    timeline_id = publication["timeline_id"]
    commits = TimelineCommitStore(
        service.store, validate_prepared=lambda value: validate_commit_value(value, "PreparedCommit"),
    )
    head = commits.bootstrap(project_id, timeline_id, authorize=lambda: None)
    document = commits.revision_closure(project_id, timeline_id, head["revision_id"])
    parent = copy.deepcopy(publication["parent_composition"])
    document["parent_revision"] = {
        "revision_id": publication["parent_revision_id"],
        "payload": parent,
        "content_digest": digest(parent),
    }
    internals = []
    for image in publication["internal_timeline_revisions"]:
        payload = copy.deepcopy(image["payload"])
        internals.append({
            "timeline_id": image["timeline_id"],
            "revision_id": image["revision_id"],
            "payload": payload,
            "content_digest": digest(payload),
        })
    shots = []
    for image in publication["shot_revisions"]:
        payload = copy.deepcopy(image["payload"])
        payload.setdefault("internal_timeline_revision_id", image["internal_timeline_revision_id"])
        shots.append({
            "shot_id": image["shot_id"],
            "revision_id": image["revision_id"],
            "internal_timeline_revision_id": image["internal_timeline_revision_id"],
            "payload": payload,
            "content_digest": digest(payload),
        })
    media_ids = set()

    def collect_media(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"media_id", "object_id"} and isinstance(child, str) and child.startswith("sha256:"):
                    media_ids.add(child)
                collect_media(child)
        elif isinstance(value, list):
            for child in value:
                collect_media(child)

    for image in [document["parent_revision"], *shots, *internals]:
        collect_media(image["payload"])
    document.update({
        "shot_revisions": sorted(shots, key=lambda image: (image["shot_id"], image["revision_id"])),
        "internal_timeline_revisions": sorted(internals, key=lambda image: (image["timeline_id"], image["revision_id"])),
        "dependency_manifest": {
            "shots": [{key: image[key] for key in ("shot_id", "revision_id", "internal_timeline_revision_id", "content_digest")}
                      for image in sorted(shots, key=lambda image: (image["shot_id"], image["revision_id"]))],
            "internal_timelines": [{key: image[key] for key in ("timeline_id", "revision_id", "content_digest")}
                                   for image in sorted(internals, key=lambda image: (image["timeline_id"], image["revision_id"]))],
            "media": [{"media_id": media_id, "content_digest": media_id} for media_id in sorted(media_ids)],
            "documents": [],
        },
    })
    command = {"schema_version": 1, "op": "fixture.install-visual-publication", "version": "1",
               "select": None, "args": {}}
    request = {
        "api_version": 1, "project_id": project_id, "timeline_id": timeline_id,
        "base_revision_id": head["revision_id"], "base_publication_id": head["publication_id"],
        "commands": [command],
    }
    context = {
        "request": request,
        "invocation": {"operation": "commitTimeline",
                        "path": f"/v1/projects/{project_id}/timelines/{timeline_id}/commit",
                        "body": copy.deepcopy(request)},
        "idempotency_key": idempotency_key,
        "realm_id": service.realm["id"],
        "publisher": "visual-host-fixture",
    }
    context["request_hash"] = request_identity(context)
    before = commits.revision_closure(project_id, timeline_id, head["revision_id"])["parent_revision"]["payload"]
    record = {"ordinal": 0, "command": command,
              "writes": [{"ref": "parent", "path": [key],
                          "before": {"state": "present", "value": before[key]} if key in before else {"state": "absent"},
                          "after": {"state": "present", "value": value}} for key, value in parent.items()],
              "reads": [], "selections": [], "bindings": [], "created": [], "dependencies": [],
              "derived_writes": []}
    prepared = {
        "expected_head": head,
        "canonical_document": document,
        "document_digest": digest(document),
        "records": {"schema_version": 1, "commands": [record], "undo_of": [], "restored_from": None},
        "id_map": {}, "semantic_events": [], "provider_version": "visual-host-fixture", "compiler_version": "visual-host-fixture",
    }
    accepted = commits.accept(context, prepared, authorize=lambda: None)
    assert accepted["data"]["status"] == "accepted"
    return accepted


def test_publication_rejects_unsafe_resolved_child_without_partial_rows(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "seam", "name": "Seam"}, idempotency_key="project")
        service.create_timeline(project["id"], "main", idempotency_key="timeline")
        tables = ("timelines", "internal_timeline_revisions", "shot_revisions", "parent_composition_revisions",
                  "shot_revision_heads", "parent_composition_heads", "composition_revision_occurrences",
                  "composition_revision_dependencies", "timeline_events", "command_idempotency")
        before = {name: service.store.conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in tables}
        accepted = _accept_visual_publication(service, _unsafe_publication(project["id"]), idempotency_key="unsafe")
        assert accepted["data"]["accepted_revision_id"] == "unsafe-parent"
        document = accepted["data"]["canonical_document"]
        report, _ = evaluate_closure(
            document["parent_revision"]["payload"],
            {(image["shot_id"], image["revision_id"]): image for image in document["shot_revisions"]},
            {image["revision_id"]: image for image in document["internal_timeline_revisions"]},
            timeline_id="main",
        )
        assert report["blocked"] is True
        assert sorted((issue["code"], issue.get("frames")) for issue in report["structuralIssues"]) == [
            ("boundary/child-picture-gap", None), ("boundary/gap", 6),
        ]
        after = {name: service.store.conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in tables}
        assert {name: after[name] - before[name] for name in tables} == {
            "timelines": 0, "internal_timeline_revisions": 1, "shot_revisions": 1, "parent_composition_revisions": 2,
            "shot_revision_heads": 1, "parent_composition_heads": 1, "composition_revision_occurrences": 1,
            "composition_revision_dependencies": after["composition_revision_dependencies"] - before["composition_revision_dependencies"],
            "timeline_events": 2, "command_idempotency": 2,
        }
        assert after["composition_revision_dependencies"] > before["composition_revision_dependencies"]
        assert service.store.conn.execute(
            "SELECT revision_id FROM parent_composition_heads WHERE timeline_id='main'").fetchone()[0] == "unsafe-parent"
    finally:
        service.close()


def test_unknown_transition_does_not_excuse_overlap():
    report = _normalized([
        {"id": "a", "clipType": "media", "asset": "picture", "at": 0, "hold": 1, "track": "v"},
        {"id": "b", "clipType": "media", "asset": "picture", "at": 0.8, "hold": 1, "track": "v",
         "transition": {"type": "not-real", "duration": 0.2}},
    ])
    assert report["blocked"]
    assert any(i["code"] == "boundary/overlap" for i in report["structuralIssues"])
    assert report["opaqueElements"]


def test_incoming_fade_is_risky_but_custom_overlay_is_not_opaque():
    report = _normalized([
        {"id": "a", "clipType": "media", "asset": "picture", "at": 0, "hold": 1, "track": "v"},
        {"id": "b", "clipType": "media", "asset": "picture", "at": 1, "hold": 1, "track": "v", "entrance": {"type": "fade", "duration": 0.5}},
        {"id": "fx", "clipType": "media", "at": 0, "hold": 2, "track": "fx", "elementRef": {"id": "custom", "kind": "effect"}},
    ])
    assert report["blocked"]
    assert any(c["id"] == "entrance" and c["frame"] == 31 for c in report["cues"])
    assert report["boundaries"][0]["opaquePaths"] == []


@pytest.mark.parametrize("clips,code", [
    ([], "boundary/empty-child-picture"),
    ([{"id": "picture", "clipType": "media", "asset": "picture", "at": 0.2, "hold": 1, "track": "v"}], "boundary/child-picture-gap"),
    ([{"id": "picture", "clipType": "media", "asset": "picture", "at": 0, "hold": 0.5, "track": "v"},
      {"id": "tail-fx", "clipType": "end-spanning-layer", "at": 0, "hold": 1, "track": "fx"}], "boundary/child-picture-gap"),
])
def test_occurrence_picture_coverage_findings_are_advisory(clips, code):
    body = _unsafe_publication("p")
    parent = body["parent_composition"]
    shots = {("s", "unsafe-shot"): {"internal_timeline_revision_id": "unsafe-child", "payload": {}}}
    internals = {"unsafe-child": {"payload": {"clips": clips}}}
    report, metadata = admit_closure(parent, shots, internals, timeline_id="main", materialize=True)
    assert any(i["code"] == code for i in report["structuralIssues"])
    assert [clip["app"]["canonical"]["sourceClipId"] for clip in metadata["render_config"]["clips"]] == [clip["id"] for clip in clips]


@pytest.mark.parametrize("start_ms,hold,rendered_count", [(0, 0, 0), (-1000, 1, 1)])
def test_invalid_occurrence_diagnostic_still_returns_materialized_closure(start_ms, hold, rendered_count):
    parent = _unsafe_publication("p")["parent_composition"]
    parent["occurrences"][0]["placement"]["start_ms"] = start_ms
    shots = {("s", "unsafe-shot"): {"internal_timeline_revision_id": "unsafe-child"}}
    internal = {"unsafe-child": {"payload": {"clips": [
        {"id": "picture", "clipType": "media", "asset": "picture", "track": "v", "at": 0, "hold": hold},
    ]}}}

    report, metadata = admit_closure(parent, shots, internal, timeline_id="main", materialize=True)

    assert report["blocked"]
    assert any(issue["code"] == "boundary/invalid-occurrence" for issue in report["structuralIssues"])
    assert len(metadata["render_config"]["clips"]) == rendered_count


@pytest.mark.parametrize("change,message", [
    ({"speed": 0}, "visual timing speed must be positive"),
    ({"hold": -1}, "visual timing duration must be finite and non-negative"),
    ({"at": float("inf")}, "visual timing start must be finite"),
])
def test_render_materialization_still_rejects_invalid_timing(change, message):
    parent = {"config": {"output": {"fps": 30}}, "occurrences": [], "clips": [
        {"id": "picture", "clipType": "media", "asset": "picture", "at": 0, "hold": 1, **change},
    ]}
    with pytest.raises(ValidationError, match=message):
        admit_closure(parent, {}, {}, timeline_id="main", materialize=True)


@pytest.mark.parametrize("fps", [{"numerator": 30000, "denominator": 1001}, [30000, 1001]])
def test_render_materialization_accepts_raw_rational_fps(fps):
    parent = {"config": {"output": {"fps": fps}}, "occurrences": [], "clips": []}

    report, metadata = admit_closure(parent, {}, {}, timeline_id="main", materialize=True)

    assert report["fps"] == pytest.approx(30000 / 1001)
    assert metadata["render_config"]["output"]["fps"] == fps


@pytest.mark.parametrize("fps", [True, 0, -1, float("inf"), {"numerator": 1, "denominator": 0}, [1, 0]])
def test_render_materialization_rejects_invalid_fps(fps):
    parent = {"config": {"output": {"fps": fps}}, "occurrences": [], "clips": []}

    with pytest.raises(ValidationError, match="visual timing fps must be finite and positive"):
        admit_closure(parent, {}, {}, timeline_id="main", materialize=True)


def _custom_picture_closure():
    parent = {"config": {"output": {"fps": 30}, "tracks": [{"id": "v", "kind": "visual"}]},
              "clips": [], "registry": {}, "occurrences": [
                  {"occurrence_id": f"o-{i}", "shot_id": f"s-{i}", "shot_revision_id": f"sr-{i}",
                   "placement": {"start_ms": i * 1000}, "track": "v", "duration_ms": 1000}
                  for i in range(2)]}
    shots = {(f"s-{i}", f"sr-{i}"): {"internal_timeline_revision_id": f"ir-{i}"} for i in range(2)}
    internal = {f"ir-{i}": {"payload": {
        "tracks": [{"id": "plate", "kind": "visual"}, {"id": "fx", "kind": "visual"}],
        "clips": [{"id": f"picture-{i}", "clipType": "custom-picture", "track": "plate", "at": 0, "hold": 1}],
    }} for i in range(2)}
    return parent, shots, internal


def test_custom_picture_presence_is_independent_of_declared_full_frame_coverage():
    parent, shots, internal = _custom_picture_closure()
    original = copy.deepcopy(internal)
    undeclared, _ = evaluate_closure(parent, shots, internal, timeline_id="main")
    assert not any(issue["code"] == "boundary/empty-child-picture" for issue in undeclared["structuralIssues"])
    assert all(span["primary"] for span in undeclared["spans"])
    assert not undeclared["boundaries"]
    assert not undeclared["opaqueElements"]
    assert not any(s["coversFrame"] for s in undeclared["spans"])
    parent["config"]["app"] = {"visualSeamContract": {"continuityTracks": ["v"], "pictureTracks": ["plate"]}}
    declared, _ = evaluate_closure(parent, shots, internal, timeline_id="main")
    assert all(s["coversFrame"] for s in declared["spans"])
    report, metadata = admit_closure(parent, shots, internal, timeline_id="main", materialize=True)
    assert not report["blocked"]
    assert not report["structuralIssues"]
    assert [b["frame"] for b in report["boundaries"]] == [30]
    assert not report["cues"]  # Primary opaque picture is represented by its cut.
    assert len(report["opaqueElements"]) == 2
    assert all(s["primary"] for s in report["spans"])
    assert [c["clipType"] for c in metadata["render_config"]["clips"]] == ["custom-picture"] * 2
    assert internal == original


@pytest.mark.parametrize("clip_type", ["am-footage", "am-snap-plate", "am-type"])
def test_film_shape_custom_picture_on_visual_plate_is_advisory_and_materialized(clip_type):
    parent, shots, internal = _custom_picture_closure()
    parent["config"]["app"] = {"someOtherAuthoringSetting": True}
    for child in internal.values():
        child["payload"]["clips"][0]["clipType"] = clip_type

    original = copy.deepcopy(internal)
    report, metadata = admit_closure(parent, shots, internal, timeline_id="main", materialize=True)

    assert not any(issue["code"] == "boundary/empty-child-picture" for issue in report["structuralIssues"])
    assert [span["primary"] for span in report["spans"]] == [True, True]
    assert not report["opaqueElements"]
    assert [clip["clipType"] for clip in metadata["render_config"]["clips"]] == [clip_type, clip_type]
    assert [clip["track"] for clip in metadata["render_config"]["clips"]] == ["plate", "plate"]
    assert internal == original


def test_empty_visual_plate_still_reports_empty_child_picture():
    parent, shots, internal = _custom_picture_closure()
    for child in internal.values():
        child["payload"]["clips"] = []

    report, _ = evaluate_closure(parent, shots, internal, timeline_id="main")

    assert [issue["code"] for issue in report["structuralIssues"]] == [
        "boundary/empty-child-picture", "boundary/empty-child-picture"]


def test_layered_picture_coverage_is_independent_of_strict_continuity_lanes():
    parent, shots, internal = _custom_picture_closure()
    parent["config"]["app"] = {"visualSeamContract": {"continuityTracks": ["v"], "pictureTracks": ["plate"]}}
    internal["ir-0"]["payload"]["clips"].append(
        {"id": "layer", "clipType": "custom-picture", "track": "plate", "at": 0.2, "hold": 0.8})
    report, _ = admit_closure(parent, shots, internal, timeline_id="main")
    assert not report["structuralIssues"]
    assert [b["frame"] for b in report["boundaries"]] == [30]
    # Requiring strict continuity on that same lane still detects the overlap.
    parent["config"]["app"]["visualSeamContract"]["continuityTracks"].append("plate")
    report, _ = evaluate_closure(parent, shots, internal, timeline_id="main")
    assert report["blocked"]
    assert any(i["code"] == "boundary/overlap" for i in report["structuralIssues"])


@pytest.mark.parametrize("change", [
    {"clipType": "end-spanning-layer"}, {"clipType": "effect-layer"}, {"clipType": "frame-overlay"},
    {"clipType": "text"}, {"clipType": "audio"}, {"elementRef": {"id": "custom", "kind": "effect"}},
    {"elementRef": {"id": "custom", "kind": "animation"}},
    {"elementRef": {"id": "custom", "kind": "transition"}},
    {"active": False}, {"enabled": False}, {"disabled": True}, {"hidden": True}, {"deleted": True},
])
def test_visual_picture_lane_never_counts_auxiliary_or_inactive_content(change):
    parent, shots, internal = _custom_picture_closure()
    for child in internal.values():
        child["payload"]["clips"][0].update(change)
    report, _ = evaluate_closure(parent, shots, internal, timeline_id="main")
    assert [i["code"] for i in report["structuralIssues"]] == [
        "boundary/empty-child-picture", "boundary/empty-child-picture"]


@pytest.mark.parametrize("track", [{"id": "plate", "kind": "audio"},
                                   {"id": "plate", "kind": "visual", "role": "source"}])
def test_declared_custom_picture_requires_a_visual_output_lane(track):
    parent, shots, internal = _custom_picture_closure()
    parent["config"]["app"] = {"visualSeamContract": {"continuityTracks": ["v"]}}
    internal["ir-0"]["payload"]["tracks"][0] = track
    report, _ = evaluate_closure(parent, shots, internal, timeline_id="main")
    assert report["blocked"]
    assert report["structuralIssues"][0]["code"] == "boundary/empty-child-picture"


@pytest.mark.parametrize("parent_kind,child_kind,picture", [("audio", "visual", False), ("visual", "audio", True)])
def test_picture_classification_matches_parent_first_materialized_track_definitions(parent_kind, child_kind, picture):
    parent, shots, internal = _custom_picture_closure()
    parent["config"]["tracks"].append({"id": "plate", "kind": parent_kind})
    parent["config"]["app"] = {"visualSeamContract": {"continuityTracks": ["v"]}}
    for child in internal.values():
        child["payload"]["tracks"][0]["kind"] = child_kind
    report, metadata = evaluate_closure(parent, shots, internal, timeline_id="main", materialize=True)
    assert next(t for t in metadata["render_config"]["tracks"] if t["id"] == "plate")["kind"] == parent_kind
    assert all(s["primary"] is picture for s in metadata["spans"])
    assert report["blocked"] is not picture


def test_source_only_child_tail_does_not_extend_rendered_picture_coverage():
    parent, shots, internal = _custom_picture_closure()
    parent["config"]["app"] = {"visualSeamContract": {"continuityTracks": ["v"]}}
    child = internal["ir-1"]["payload"]
    child["tracks"].append({"id": "reference", "kind": "visual", "role": "source"})
    child["clips"].append({"id": "unused-reference", "clipType": "media", "asset": "picture", "track": "reference", "at": 10, "hold": 5})
    report, metadata = admit_closure(parent, shots, internal, timeline_id="main")
    assert not report["blocked"]
    assert metadata["occurrences"][-1]["endFrame"] == 60
    # Authored source metadata is retained; it does not create output time.
    assert child["clips"][-1]["hold"] == 5


def test_custom_picture_does_not_warn_about_auxiliary_overlay_activation():
    parent, shots, internal = _custom_picture_closure()
    policy = {"continuityTracks": ["v"], "pictureTracks": ["plate"]}
    parent["config"]["app"] = {"visualSeamContract": policy}
    for child in internal.values():
        next(track for track in child["payload"]["tracks"] if track["id"] == "fx")["kind"] = "audio"
    internal["ir-1"]["payload"]["clips"].append(
        {"id": "custom-overlay", "clipType": "custom-overlay", "track": "fx", "at": 0, "hold": 1})
    report, _ = evaluate_closure(parent, shots, internal, timeline_id="main")
    assert not report["structuralIssues"]
    assert not report["blocked"]
    assert not report["boundaries"][0]["requiresIntent"]
    assert not report["cues"]
    internal["ir-1"]["payload"]["clips"][-1]["params"] = {"message": "changed"}
    assert not evaluate_closure(parent, shots, internal, timeline_id="main")[0]["blocked"]


@pytest.mark.parametrize("width,overhang", [(200, False), (1920, True)])
def test_owner_clipping_warns_only_for_full_frame_picture(width, overhang):
    parent, shots, internal = _custom_picture_closure()
    parent["config"]["output"]["resolution"] = "1920x1080"
    for child in internal.values():
        child["payload"]["clips"][0].update(clipType="media", asset="picture")
    internal["ir-0"]["payload"]["clips"].append({
        "id": "layer", "clipType": "media", "asset": "sprite", "track": "plate",
        "at": 0.5, "hold": 1, "width": width, "height": 1080,
    })
    report, metadata = evaluate_closure(parent, shots, internal, timeline_id="main", materialize=True)
    layer = next(s for s in metadata["spans"] if s["path"][-1] == "layer")
    assert (layer["rawEndFrame"], layer["endFrame"]) == (45, 30)
    assert any(i["code"] == "boundary/owner-overhang" for i in report["structuralIssues"]) is overhang
    assert any(i["code"] == "boundary/overlap" for i in report["structuralIssues"]) is overhang


def test_negative_overlay_start_remains_a_timing_diagnostic():
    report = _normalized([{"id": "overlay", "clipType": "am-sprite", "track": "v", "at": -0.5, "hold": 1}])
    assert report["structuralIssues"] == [{"code": "boundary/negative-start", "path": ["parent", "t", "clip", "overlay"], "frame": -15}]
    assert report["opaqueElements"] == []


def test_declared_picture_lane_keeps_timeline_scoped_effects_auxiliary():
    parent, shots, internal = _custom_picture_closure()
    parent["config"]["app"] = {"visualSeamContract": {"continuityTracks": ["v"]}}
    internal["ir-1"]["payload"]["effects"] = [
        {"id": "timeline-effect", "type": "opacity", "track": "plate", "hold": 1, "params": {"opacity": 0.5}}]
    report, metadata = evaluate_closure(parent, shots, internal, timeline_id="main")
    effect = next(s for s in metadata["spans"] if s["path"][-2:] == ["effect", "timeline-effect"])
    assert not effect["primary"]
    assert not report["structuralIssues"]
    assert not report["blocked"]
    assert not any(c["kind"] == "activation" and c["path"][-1] == "timeline-effect" for c in report["cues"])


@pytest.mark.parametrize("duration,fps", [(7.366667, 30), (1.000001, 30), (2.041667, 24)])
@pytest.mark.parametrize("gap_frames", [0, 1])
def test_fractional_occurrence_bounds_match_render_frames_and_preserve_real_gaps(duration, fps, gap_frames):
    parent, shots, internal = _custom_picture_closure()
    parent["config"]["output"]["fps"] = fps
    parent["config"]["app"] = {"visualSeamContract": {"continuityTracks": ["v"]}}
    parent["occurrences"][1]["placement"]["start_ms"] = duration * 1000
    internal["ir-0"]["payload"]["clips"][0]["hold"] = duration - gap_frames / fps
    internal["ir-0"]["payload"]["clips"].append(
        {"id": "audio-tail", "clipType": "media", "asset": "picture", "track": "audio", "at": 0, "hold": duration})
    internal["ir-0"]["payload"]["tracks"].append({"id": "audio", "kind": "audio"})
    report, metadata = evaluate_closure(parent, shots, internal, timeline_id="main", materialize=True)
    first, second = metadata["occurrences"]
    assert first["endFrame"] == second["startFrame"] == round(duration * fps)
    assert report["blocked"] is bool(gap_frames)
    if gap_frames:
        assert [(i["code"], i["endFrame"] - i["startFrame"]) for i in report["structuralIssues"]] == [
            ("boundary/child-picture-gap", 1)]
    else:
        assert not report["structuralIssues"]
        rendered = metadata["render_config"]["clips"][0]
        assert round(rendered["at"] * fps) + round(rendered["hold"] * fps) == second["startFrame"]


def test_managed_materialization_preserves_child_effects_and_offset_without_trim():
    body = _unsafe_publication("p")
    parent = body["parent_composition"]
    parent["occurrences"][0]["source_offset"] = 1500
    child_effect = {"id": "child-fade", "type": "opacity", "params": {"opacity": 0.5}}
    local_effect = {"id": "local", "type": "crop", "params": {"left": 4}}
    child = {"clips": [{"id": "picture", "clipType": "media", "asset": "picture", "at": 0, "hold": 1, "track": "v", "effects": [local_effect]}],
             "effects": [child_effect]}
    _, metadata = admit_closure(parent, {("s", "unsafe-shot"): {"internal_timeline_revision_id": "unsafe-child", "payload": {}}},
                               {"unsafe-child": {"payload": child}}, timeline_id="main", materialize=True)
    clip = metadata["render_config"]["clips"][0]
    assert clip["from"] == 1.5
    assert clip["hold"] == 1
    assert clip["effects"] == [local_effect, child_effect]
    assert "from" not in child["clips"][0]
    assert child["clips"][0]["effects"] == [local_effect]


def test_managed_render_freezes_child_effects_and_offset_from_pinned_closure(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "child-render", "name": "Child Render"}, idempotency_key="project")
        service.create_timeline(project["id"], "main", idempotency_key="timeline")
        capability = "sha256:" + hashlib.sha256(b"rendering.render").hexdigest()
        service.register_capability({"capability_id": "rendering.render", "definition_digest": capability})
        service.register_executor({"executor_id": "worker", "capabilities": ["rendering.render"]})
        media = service.ingest(project["id"], b"frozen-media", media_type="video/mp4", idempotency_key="media")["data"]["object_id"]
        publication = _unsafe_publication(project["id"])
        publication["parent_composition"]["occurrences"][0]["source_offset"] = 1500
        child_effect = {"id": "child", "type": "opacity", "params": {"opacity": 0.5}}
        local_effect = {"id": "local", "type": "crop", "params": {"left": 4}}
        child = publication["internal_timeline_revisions"][0]["payload"]
        child.update({"clips": [{"id": "picture", "clipType": "media", "at": 0, "hold": 1, "track": "v", "asset": "source", "effects": [local_effect]}],
                      "effects": [child_effect], "registry": {"assets": {"source": {"object_id": media, "type": "video/mp4"}}}})
        _accept_visual_publication(service, publication, idempotency_key="publish")
        task = service.create_task({"project": project["id"], "capability_id": "rendering.render", "capability_digest": capability,
                                    "input_object_ids": [], "idempotency_key": "render", "spec": {"family": "render", "params": {"timeline_ref": "main"}}})
        frozen = task["task"]["spec"]["spec"]
        ref = frozen["timeline_snapshot_ref"]
        assert "timeline_snapshot" not in frozen
        assert ref["digest"] in task["task"]["spec"]["input_object_ids"]
        assert ref["revision_id"] == "unsafe-parent"
        clip = json.loads(service.object(ref["digest"])[1])["config"]["clips"][0]
        assert clip["from"] == 1.5
        assert clip["effects"] == [local_effect, child_effect]
        assert frozen["inputs"]["timeline_authority"]["parent_revision_id"] == "unsafe-parent"
        assert not frozen["inputs"]["timeline_authority"]["visual_seam_report"]["blocked"]
    finally:
        service.close()


@pytest.mark.parametrize("scope", ["parent", "parent-media-id", "shot", "internal"])
def test_managed_render_preserves_asset_identity_from_the_pinned_asset_scope(tmp_path, scope):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "scoped-assets", "name": "Scoped Assets"}, idempotency_key="project")
        service.create_timeline(project["id"], "main", idempotency_key="timeline")
        capability = "sha256:" + hashlib.sha256(b"rendering.render").hexdigest()
        service.register_capability({"capability_id": "rendering.render", "definition_digest": capability})
        service.register_executor({"executor_id": "worker", "capabilities": ["rendering.render"]})
        media = service.ingest(project["id"], b"pinned-picture", media_type="image/png", idempotency_key="media")["data"]["object_id"]
        asset = {"media_id": media, "content_sha256": media, "type": "image/png", "file": "/api/runtime/v1/objects/" + media}
        if scope == "parent-media-id":
            del asset["content_sha256"]
        publication = _unsafe_publication(project["id"])
        child = publication["internal_timeline_revisions"][0]["payload"]
        child["clips"] = [{"id": "picture", "clipType": "media", "at": 0, "hold": 1, "track": "v", "asset": "shared"}]
        if scope in ("parent", "parent-media-id"):
            publication["parent_composition"]["registry"] = {"assets": {"shared": asset}}
        elif scope == "shot":
            publication["shot_revisions"][0]["payload"]["assets"] = [
                {"asset_id": "shared", "object_id": media, "digest": media, "media_type": "image/png"}]
        else:
            child["registry"] = {"assets": {"shared": asset}}
        _accept_visual_publication(service, publication, idempotency_key="publish")
        authored = service.get_project_parent_composition_revision(project["id"], "main", "unsafe-parent")
        task = service.create_task({"project": project["id"], "capability_id": "rendering.render", "capability_digest": capability,
                                    "input_object_ids": [], "idempotency_key": "render", "spec": {"family": "render", "params": {"timeline_ref": "main"}}})
        spec = task["task"]["spec"]
        snapshot = json.loads(service.object(spec["spec"]["timeline_snapshot_ref"]["digest"])[1])
        rendered_asset = snapshot["registry"]["assets"][snapshot["config"]["clips"][0]["asset"]]
        assert rendered_asset["media_id"] == media
        if scope == "shot":
            assert rendered_asset["content_sha256"] == media.removeprefix("sha256:")
        else:
            # Frozen worker inputs carry explicit digest identity, while the
            # redundant browser URL remains only in authored revision bytes.
            assert rendered_asset == {**{k: v for k, v in asset.items() if k != "file"}, "content_sha256": media.removeprefix("sha256:")}
        assert media in spec["input_object_ids"]
        assert service.get_project_parent_composition_revision(project["id"], "main", "unsafe-parent") == authored
    finally:
        service.close()


@pytest.mark.parametrize("local", [None, {"object_id": "sha256:" + "c" * 64, "type": "image/png"},
                                   {"file": "/display-only-child.png"}])
def test_pinned_asset_resolution_preserves_nearest_scope_without_mixing_metadata(local):
    parent = _unsafe_publication("p")["parent_composition"]
    parent["registry"] = {"assets": {"shared": {"media_id": "sha256:" + "a" * 64, "parentOnly": True}}}
    shot_asset = {"asset_id": "shared", "object_id": "sha256:" + "b" * 64,
                  "digest": "sha256:" + "b" * 64, "media_type": "image/png"}
    shot = {"internal_timeline_revision_id": "unsafe-child", "payload": {"assets": [shot_asset]}}
    child = {"clips": [{"id": "picture", "clipType": "media", "track": "v", "at": 0, "hold": 1, "asset": "shared"}],
             "registry": {"assets": {"shared": local} if local is not None else {}}}
    original = copy.deepcopy((parent, shot, child))
    _, metadata = admit_closure(parent, {("s", "unsafe-shot"): shot}, {"unsafe-child": {"payload": child}},
                               timeline_id="main", materialize=True)
    rendered = metadata["render_registry"]["assets"]["o:shared"]
    if local is not None:
        assert rendered == local
    else:
        assert rendered["media_id"] == shot_asset["object_id"]
        assert rendered["content_sha256"] == shot_asset["digest"]
    assert "parentOnly" not in rendered
    assert (parent, shot, child) == original


@pytest.mark.parametrize("clips,code", [
    pytest.param([], "boundary/empty-child-picture", id="clips0"),
    pytest.param([{"id": "picture", "clipType": "media", "at": 0.2, "hold": 1, "track": "v"}], "boundary/child-picture-gap", id="clips1"),
])
def test_publication_and_render_preserve_uncovered_child_with_advisory_report(tmp_path, clips, code):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "coverage", "name": "Coverage"}, idempotency_key="project")
        service.create_timeline(project["id"], "main", idempotency_key="timeline")
        capability = "sha256:" + hashlib.sha256(b"rendering.render").hexdigest()
        service.register_capability({"capability_id": "rendering.render", "definition_digest": capability})
        service.register_executor({"executor_id": "worker", "capabilities": ["rendering.render"]})
        publication = _unsafe_publication(project["id"])
        publication["internal_timeline_revisions"][0]["payload"]["clips"] = clips
        accepted = _accept_visual_publication(service, publication, idempotency_key="unsafe")
        assert accepted["data"]["accepted_revision_id"] == "unsafe-parent"
        document = accepted["data"]["canonical_document"]
        report, _ = evaluate_closure(
            document["parent_revision"]["payload"],
            {(image["shot_id"], image["revision_id"]): image for image in document["shot_revisions"]},
            {image["revision_id"]: image for image in document["internal_timeline_revisions"]},
            timeline_id="main",
        )
        assert report["blocked"] is True
        assert [issue["code"] for issue in report["structuralIssues"]] == [code]
        rendered = service.create_task({"project": project["id"], "capability_id": "rendering.render", "capability_digest": capability,
                                        "input_object_ids": [], "idempotency_key": "render", "spec": {"family": "render", "params": {"timeline_ref": "main"}}})
        frozen = rendered["task"]["spec"]["spec"]
        authority = frozen["inputs"]["timeline_authority"]
        assert authority["visual_seam_report"]["blocked"] is True
        assert [issue["code"] for issue in authority["visual_seam_report"]["structuralIssues"]] == [code]
        frozen_clips = json.loads(service.object(frozen["timeline_snapshot_ref"]["digest"])[1])["config"]["clips"]
        assert [clip["app"]["canonical"]["sourceClipId"] for clip in frozen_clips] == [clip["id"] for clip in clips]
        assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
        assert service.store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 1
    finally:
        service.close()
