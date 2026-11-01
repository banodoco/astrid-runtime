"""Visual-field semantics are owned by Agent's completed-candidate provider."""
from __future__ import annotations

import copy

import pytest

pytest_plugins = ("test_timeline_commit_integration",)
pytestmark = pytest.mark.integration

from runtime_protocol.errors import RuntimeErrorBase
from test_timeline_commit_integration import _commit_visual_field, _visual_stand_in, rows


def test_visual_field_provider_acceptance_and_refusal_regressions(editing):
    _visual_stand_in(editing)
    accepted = [
        ("entrance", {"id": "fade", "durationFrames": 12,
                      "params": {"easing": " EASE-OUT "}}, False),
        ("entrance", {"id": "fade-up", "durationFrames": 18}, True),
        ("entrance", {"id": "scale-in", "durationFrames": 18}, True),
        ("entrance", {"id": "slide-left", "durationFrames": 18}, True),
        ("exit", {"id": "fade", "durationFrames": 12}, True),
        ("exit", {"id": "slide-up", "durationFrames": 12}, True),
        ("transition", {"id": "cross-fade", "durationFrames": 12}, True),
        ("transition", {"id": "fade", "durationFrames": 12}, True),
        ("transition", {"type": "crossfade", "duration": 0.2}, False),
        ("entrance", {"type": "fade", "duration": 0.4}, False),
    ]
    for index, (field, value, use_agent_setter) in enumerate(accepted):
        result = _commit_visual_field(editing, field, value, f"visual-regression-accept-{index}",
                                      use_agent_setter=use_agent_setter)
        revision = result["data"]["accepted_revision_id"]
        payload = editing.service.get_project_parent_composition_revision(
            editing.project, editing.timeline, revision,
        )["payload"]
        clip = next(row for row in payload["clips"] if row["id"] == "music-bed")
        assert clip[field] == next(row[field] for row in result["data"]["canonical_document"]
                                   ["parent_revision"]["payload"]["clips"] if row["id"] == "music-bed")

    refused = [
        ("entrance", {"id": "slide-up", "durationFrames": 12}),
        ("exit", {"id": "fade-up", "durationFrames": 12}),
        ("entrance", {"id": "not-installed", "durationFrames": 12}),
        ("entrance", {"id": "fade", "durationFrames": 12, "duration": 0.4}),
        ("entrance", {"id": "fade", "durationFrames": 12, "params": {"easing": "bounce"}}),
        ("entrance", {"id": "fade", "durationFrames": 12, "params": {"amplitude": 2}}),
        ("entrance", {"id": "type-on", "durationFrames": 60, "params": {"showCaret": "yes"}}),
        ("entrance", {"id": "type-on", "durationFrames": 60, "params": {"startFrame": "soon"}}),
        ("entrance", {"id": "fade", "durationFrames": 0}),
        ("transition", {"type": "wipe", "duration": 0.4}),
        ("transition", {"id": "wipe", "durationFrames": 12}),
        ("transition", {"id": "fade", "durationFrames": 12, "duration": 0.4}),
        ("transition", {"id": "fade", "durationFrames": 12, "params": {"easing": "out"}}),
    ]
    for index, (field, value) in enumerate(refused):
        before_rows, before_head, before_history = rows(editing.service), editing.head(), editing.history()
        with pytest.raises(RuntimeErrorBase):
            _commit_visual_field(editing, field, value, f"visual-regression-refuse-{index}",
                                 use_agent_setter=False)
        assert editing.head() == before_head
        assert editing.history() == before_history
        assert rows(editing.service) == before_rows


def test_visual_field_provider_preserves_opaque_custom_data(editing):
    _visual_stand_in(editing)
    before = editing.document()
    original = copy.deepcopy(next(row["params"] for row in before["parent_revision"]["payload"]["clips"]
                                  if row["id"] == "music-bed"))
    _commit_visual_field(editing, "entrance", {"id": "fade", "durationFrames": 12,
                                                "params": {"easing": "out"}},
                         "visual-opaque-preserved")
    after = editing.document()
    assert next(row["params"] for row in after["parent_revision"]["payload"]["clips"]
                if row["id"] == "music-bed") == original


@pytest.mark.xfail(
    strict=True,
    raises=RuntimeErrorBase,
    reason="[declared-xfail:p1-top-level-text-hook] P1 top-level text-hook restoration requirement",
)
def test_supported_top_level_type_on_retains_original_roundtrip_expectations(editing):
    # P1 must restore the top-level text hook before this original acceptance
    # case can publish; keep its stored, read, and human-description checks.
    from astrid.core.timeline import clip_fields as cf

    _visual_stand_in(editing)
    ref = {"id": "type-on", "durationFrames": 60,
           "params": {"durationFraction": 0.55, "showCaret": True, "startFrame": 18}}
    accepted = _commit_visual_field(editing, "entrance", ref,
                                    "original-top-level-type-on-acceptance", use_agent_setter=False)
    clip = next(row for row in accepted["data"]["canonical_document"]["parent_revision"]["payload"]["clips"]
                if row["id"] == "music-bed")
    assert clip["entrance"] == ref
    assert cf.read(clip, "entrance", fps=24) == ref
    assert cf.describe(clip, fps=24)["entrance"] == "type-on 60f"


@pytest.mark.parametrize("field,value", [
    ("entrance", {"id": "fade", "durationFrames": 12}),
    ("exit", {"id": "fade", "durationFrames": 12}),
    ("transition", {"id": "fade", "durationFrames": 12}),
])
def test_visual_fields_on_audio_track_are_refused_before_publication(editing, field, value):
    document = editing.document()
    clip = next(row for row in document["parent_revision"]["payload"]["clips"]
                if row["id"] == "music-bed")
    track = next(row for row in document["parent_revision"]["payload"]["config"]["tracks"]
                 if row["id"] == clip["track"])
    assert track["kind"] == "audio"
    before_rows, before_head, before_history = rows(editing.service), editing.head(), editing.history()
    with pytest.raises(RuntimeErrorBase):
        _commit_visual_field(editing, field, value, "audio-track-visual-" + field,
                             use_agent_setter=False)
    assert editing.head() == before_head
    assert editing.history() == before_history
    assert rows(editing.service) == before_rows
