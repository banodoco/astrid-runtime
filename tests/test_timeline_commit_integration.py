"""Real Agent recipes through Runtime acceptance, independently of rendering.

Run explicitly with the integration lane and an Agent checkout/dependency stack.
Default neutral Runtime collection never imports Agent.
"""
from __future__ import annotations

import copy
import io
import json
import os
import subprocess
import sys
import wave
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, Lock
from types import SimpleNamespace

import pytest

from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_baseline import verify_baseline
from precut_realm_fixture import load_precut_realm_fixture
from timeline_commit_film_fixture import FilmFixture

pytestmark = pytest.mark.integration


@pytest.fixture
def film(tmp_path, monkeypatch):
    captured = load_precut_realm_fixture(tmp_path, variant="music-documents")
    pins = captured.pins
    fixture = FilmFixture(
        source_root=captured.copy_roots[0],
        duplicate_root=captured.copy_roots[1],
        project_id=pins["project_id"],
        timeline_id=pins["timeline_id"],
        parent_revision_id=pins["parent_revision_id"],
        media_ids=pins["media_ids"],
        transcript_document_id=pins["transcript_document_id"],
        text_binding_id=pins["text_binding_id"],
    )
    # The capture contains the original two clips, opaque data and config mirror.
    # Read its verified publication without replaying the retired writer.
    service = RuntimeService(fixture.duplicate_root)
    try:
        baseline = verify_baseline(
            service.store.conn, fixture.project_id, fixture.timeline_id,
            read_object=service.cas.read,
        )
        receipt = baseline["entries"][-1]["receipt"]
        publication = {"data": receipt["result"], "receipt": receipt}
        original_events = [tuple(row) for row in service.store.conn.execute(
            "SELECT * FROM timeline_events ORDER BY id",
        )]
        assert service.store.conn is not None
        timestamps = [datetime.fromisoformat(row[0]) for row in service.store.conn.execute(
            "SELECT created_at FROM command_idempotency",
        )]
    finally:
        service.close()
    # Continue just after the capture, inside the real receipt replay window.
    # Keep normal pruning enabled and leave the captured bytes untouched.
    captured_now = max(timestamps) + timedelta(seconds=1)
    from runtime_protocol import idempotency, store, util

    assert captured_now.tzinfo == UTC
    assert min(timestamps) > captured_now - timedelta(seconds=store.IDEMPOTENCY_RESULT_WINDOW_SECONDS)

    class CaptureClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return captured_now.astimezone(tz) if tz else captured_now.replace(tzinfo=None)

    for module in (store, idempotency, util):
        monkeypatch.setattr(module, "datetime", CaptureClock)
    return SimpleNamespace(fixture=fixture, publication=publication, original_events=original_events)


@pytest.fixture
def agent(film, astrid_importable, monkeypatch):
    class RendererUnavailable:
        def find_spec(self, fullname, path=None, target=None):
            if (fullname.startswith(("astrid.packs.rendering", "astrid.core.rendering",
                                     "astrid.sdk.authoring_render_preview",
                                     "astrid.core.timeline.compatibility", "composition",
                                     "remotion", "node")) or "scene" in fullname):
                raise AssertionError("save imported renderer: " + fullname)

    blocker = RendererUnavailable()
    monkeypatch.setattr(sys, "meta_path", [blocker, *sys.meta_path])

    def unavailable(*args, **kwargs):
        raise AssertionError("save evaluated a scene")

    # The seed publication happened before rendering became unavailable.
    import runtime_protocol.service as service_module
    import runtime_protocol.visual_seam as visual_seam
    monkeypatch.setattr(service_module, "evaluate_closure", unavailable)
    monkeypatch.setattr(visual_seam, "evaluate_closure", unavailable)

    from astrid.sdk.timeline.capture import capture_move, capture_track_create
    from astrid.sdk.timeline.commit import bundle_from_document
    from runtime_protocol.timeline_commit_provider import load_timeline_commit_provider

    return SimpleNamespace(move=capture_move, track=capture_track_create,
                           bundle=bundle_from_document,
                           provider=lambda: load_timeline_commit_provider("astrid"))


class Editing:
    def __init__(self, service, film, agent):
        self.service, self.film, self.agent = service, film, agent
        self.project = film.fixture.project_id
        self.timeline = film.fixture.timeline_id
        self.path = f"/v1/projects/{self.project}/timelines/{self.timeline}/commit"

    def head(self):
        head = self.service.get_project_timeline(self.project, self.timeline)
        return {"revision_id": head["head_revision_id"],
                "publication_id": head["head_publication_id"]}

    def document(self, revision=None):
        return self.service._timeline_commits()[0].revision_closure(
            self.project, self.timeline, revision or self.head()["revision_id"],
        )

    def body(self, commands, base=None):
        base = base or self.head()
        label = "Real renderer-free integration"
        return {"api_version": 1, "project_id": self.project, "timeline_id": self.timeline,
                "base_revision_id": base["revision_id"], "base_publication_id": base["publication_id"],
                "commands": copy.deepcopy(commands), "source": {"via": "python"},
                "label": label, "merge": "fields", "reads": [], "dry_run": False,
                "steps": [{"id": "edit", "label": label, "intent": "Exercise native editing",
                           "tags": ["integration"], "command_ordinals": list(range(len(commands))),
                           "patch": [], "reads": []}],
                "rationale": "real renderer-free integration"}

    def move(self, clip, on, *, document=None):
        return self.agent.move(self.agent.bundle(document or self.document()), "parent/clip:" + clip, on)

    def commit(self, body, key):
        return self.service.commit_timeline(
            self.project, self.timeline, body, idempotency_key=key, publisher="integration-editor",
            invocation_path=self.path, authorize=lambda: None,
        )

    def history(self):
        return self.service.list_timeline_commits(self.project, self.timeline, authorize=lambda: None)["items"]

    def assert_baseline(self):
        baselines = [entry for entry in self.history() if entry["intent"] == "legacy_unknown"]
        assert len(baselines) == 2
        baseline = baselines[-1]
        assert baseline["intent"] == "legacy_unknown"
        assert baseline["records"] is None
        assert baseline["publication_id"] == self.film.publication["receipt"]["receipt_id"]
        assert baseline["receipt"] == self.film.publication["receipt"]
        events = [tuple(row) for row in self.service.store.conn.execute(
            "SELECT * FROM timeline_events ORDER BY id",
        )]
        assert events[:len(self.film.original_events)] == self.film.original_events

    def assert_readback(self, accepted):
        data = accepted["data"]
        document = data["canonical_document"]
        revision = document["parent_revision"]["revision_id"]
        assert data["accepted_revision_id"] == revision
        assert accepted["receipt"]["result"] == data
        entry = next(row for row in self.history()
                     if row["publication_id"] == accepted["receipt"]["receipt_id"])
        assert entry["receipt"] == accepted["receipt"]
        assert entry["label"] == data["label"]
        assert entry["steps"] == entry["records"]["steps"] == data["steps"]
        assert entry["publisher"] == data["publisher"]
        assert entry["merge_mode"] == data["merge_mode"]
        assert all(isinstance(step["patch"], list) for step in data["steps"])
        assert self.document(revision) == document
        parent = self.service.get_project_parent_composition_revision(self.project, self.timeline, revision)
        assert parent["revision_id"] == revision
        assert parent["payload"] == document["parent_revision"]["payload"]
        assert parent["content_digest"] == document["parent_revision"]["content_digest"]
        for image in document["shot_revisions"]:
            row = self.service.store.conn.execute("SELECT payload_json FROM shot_revisions WHERE id=?",
                                                  (image["revision_id"],)).fetchone()
            assert json.loads(row[0]) == image["payload"]
        for image in document["internal_timeline_revisions"]:
            row = self.service.store.conn.execute("SELECT payload_json FROM internal_timeline_revisions WHERE id=?",
                                                  (image["revision_id"],)).fetchone()
            assert json.loads(row[0]) == image["payload"]


@pytest.fixture
def editing(film, agent):
    service = RuntimeService(film.fixture.duplicate_root)
    try:
        service.register_timeline_commit_provider(agent.provider())
        result = Editing(service, film, agent)
        result.assert_baseline()
        yield result
    finally:
        service.close()


def inverse(publication):
    return {"schema_version": 1, "op": "timeline.inverse", "version": "1", "select": None,
            "args": {"publications": [publication]}}


def positions(document):
    return {row["id"]: row["at"] for row in document["parent_revision"]["payload"]["clips"]}


def assert_json_equal(actual, expected):
    if type(actual) in (int, float) and type(expected) in (int, float):
        assert actual == expected
        return
    assert type(actual) is type(expected)
    if isinstance(expected, dict):
        assert actual.keys() == expected.keys()
        for key in expected:
            assert_json_equal(actual[key], expected[key])
    elif isinstance(expected, list):
        assert len(actual) == len(expected)
        for actual_item, expected_item in zip(actual, expected):
            assert_json_equal(actual_item, expected_item)
    else:
        assert actual == expected


def rows(service):
    # Rejection/retry must leave the entire durable store unchanged, including
    # projections, sequence allocation, receipts, retained inputs and history.
    return tuple(service.store.conn.iterdump())


def _commit_visual_field(editing, field, value, key, *, use_agent_setter=True):
    from astrid.core.timeline.clip_fields import write
    from astrid.sdk.timeline._command_state import present

    document = editing.document()
    before_clips = copy.deepcopy(document["parent_revision"]["payload"]["clips"])
    after_clips = copy.deepcopy(before_clips)
    target = next(clip for clip in after_clips if clip["id"] == "music-bed")
    if field in ("entrance", "exit", "transition") and use_agent_setter:
        write(target, field, copy.deepcopy(value), fps=24)
        expected = copy.deepcopy(target[field])
    else:
        target[field] = copy.deepcopy(value)
        expected = copy.deepcopy(value)
    change = {"op": "set", "ref": "parent", "path": ["clips"],
              "before": present(before_clips), "value": after_clips}
    command = {"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
               "args": {"changes": [change]}}
    body = editing.body([command])
    body["steps"][0]["patch"] = [change]
    accepted = editing.commit(body, key)
    editing.assert_readback(accepted)
    stored = next(clip for clip in accepted["data"]["canonical_document"]["parent_revision"]["payload"]["clips"]
                  if clip["id"] == "music-bed")
    assert stored[field] == expected
    return accepted


def _visual_stand_in(editing):
    """Turn the fixture clip into deterministic text on its visual track."""
    from astrid.sdk.timeline._command_state import present

    document = editing.document()
    clips = copy.deepcopy(document["parent_revision"]["payload"]["clips"])
    music = next(clip for clip in clips if clip["id"] == "music-bed")
    music["track"] = "picture"
    music["clipType"] = "text"
    music.pop("asset", None)
    music.pop("volume", None)
    music["text"] = {"content": "Visual field publication proof"}
    music["params"] = {
        "entrance": "custom-element-setting",
        "custom": {
            "opaque": [None, False, {"easing": "package-owned"}],
            "entrance": {"future": [None, "nested entrance"]},
            "exit": {"future": [False, "nested exit"]},
            "transition": {"future": [0, "nested transition"]},
        },
    }
    change = {"op": "set", "ref": "parent", "path": ["clips"],
              "before": present(document["parent_revision"]["payload"]["clips"]), "value": clips}
    command = {"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
               "args": {"changes": [change]}}
    request = editing.body([command])
    request["steps"][0]["patch"] = [change]
    accepted = editing.commit(request, "visual-stand-in")
    editing.assert_readback(accepted)
    clip = next(clip for clip in accepted["data"]["canonical_document"]["parent_revision"]["payload"]["clips"]
                if clip["id"] == "music-bed")
    assert clip["track"] == "picture" and clip["clipType"] == "text"
    assert clip["params"] == music["params"]
    return clip


def test_agent_written_visual_fields_validate_and_read_back_from_published_revision(editing):
    _visual_stand_in(editing)
    cases = [
        ("entrance.fade", "entrance", {"id": "fade", "durationFrames": 12,
                                         "params": {"easing": "step"}}, True),
        ("entrance.fade.linear", "entrance", {"id": "fade", "durationFrames": 12,
                                                "params": {"easing": "linear"}}, True),
        ("entrance.fade-up", "entrance", {"id": "fade-up", "durationFrames": 18}, True),
        ("entrance.scale-in", "entrance", {"id": "scale-in", "durationFrames": 18}, True),
        ("exit.fade", "exit", {"id": "fade", "durationFrames": 12}, True),
        ("exit.slide-up", "exit", {"id": "slide-up", "durationFrames": 12}, True),
        ("transition.fade.default", "transition", {"id": "fade"}, True),
        ("transition.cross-fade.default", "transition", {"id": "cross-fade"}, True),
        ("transition.fade.explicit-frames", "transition", {"id": "fade", "durationFrames": 8}, True),
        ("transition.cross-fade.legacy-seconds", "transition", {"type": "crossfade", "duration": 0.5}, False),
        ("effects.array", "effects", [{"fade_in": 0.25}, {"fade_out": 0.5}], False),
        ("effects.object", "effects", {"fade_in": 0.25, "fade_out": 0.5}, False),
    ]
    handoff = []
    for case_key, field, value, use_agent_setter in cases:
        before = editing.document()
        clip_before = next(clip for clip in before["parent_revision"]["payload"]["clips"]
                           if clip["id"] == "music-bed")
        opaque_params = copy.deepcopy(clip_before["params"])
        accepted = _commit_visual_field(editing, field, value, "visual-field-" + case_key,
                                        use_agent_setter=use_agent_setter)
        document = accepted["data"]["canonical_document"]
        revision = document["parent_revision"]["revision_id"]
        readback = editing.service.get_project_parent_composition_revision(
            editing.project, editing.timeline, revision,
        )
        clip = next(clip for clip in readback["payload"]["clips"] if clip["id"] == "music-bed")
        authored = next(authored for authored in document["parent_revision"]["payload"]["clips"]
                        if authored["id"] == "music-bed")
        assert clip[field] == authored[field]
        assert clip["params"] == opaque_params
        config = readback["payload"]["config"]
        visual_overrides = (config.get("theme_overrides") or {}).get("visual") or {}
        handoff.append({
            "case_key": case_key,
            "accepted_revision": {"project_id": editing.project, "timeline_id": editing.timeline,
                                  "revision_id": revision,
                                  "publication_id": accepted["receipt"]["receipt_id"]},
            "authored_visual_fields": {field: copy.deepcopy(value)},
            "frame_basis": {
                "setter_fps": 24,
                "published_output": copy.deepcopy(config.get("output")),
                "published_canvas": copy.deepcopy(visual_overrides.get("canvas")),
            },
            "published_readback_config": copy.deepcopy(config),
        })
    output_dir = os.environ.get("D66_OUTPUT_DIR")
    if output_dir:
        path = Path(output_dir) / "runtime-visual-fields-readback.json"
        from astrid.sdk.timeline import commit as agent_commit

        checkout = os.environ.get("ASTRID_CHECKOUT")
        pin = subprocess.check_output(
            ["git", "-C", checkout, "rev-parse", "HEAD"], text=True,
        ).strip() if checkout else None
        expected_pin = (Path(__file__).with_name("astrid-agent.pin").read_text().strip()
                        if checkout else None)
        assert pin == expected_pin
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"agent_pin": pin, "agent_pin_source": "tests/astrid-agent.pin",
                                   "agent_checkout": checkout, "output_path": str(path),
                                   "agent_provider_import": agent_commit.__file__,
                                   "expected_agent_pin": expected_pin, "cases": handoff},
                                  indent=2, sort_keys=True) + "\n")
        print(f"Agent pin={pin} imported={agent_commit.__file__} readback={path}")


@pytest.mark.parametrize("field,value", [
    ("entrance", {"type": "fade", "duration": 0.5}),
    ("exit", {"type": "fade", "duration": 0.25}),
    ("transition", {"type": "crossfade", "duration": 0.4}),
])
def test_drawable_legacy_visual_fields_survive_publication_readback(editing, field, value):
    _visual_stand_in(editing)
    _commit_visual_field(editing, field, value, "legacy-visual-field-" + field, use_agent_setter=False)


def test_agent_provider_refuses_top_level_type_on_without_publication(editing):
    _visual_stand_in(editing)
    before_rows, before_head, before_history = rows(editing.service), editing.head(), editing.history()
    with pytest.raises(RuntimeErrorBase, match="type-on cannot draw as a top-level clip animation"):
        _commit_visual_field(editing, "entrance", {"id": "type-on", "durationFrames": 48},
                             "unsupported-top-level-type-on", use_agent_setter=False)
    assert editing.head() == before_head
    assert editing.history() == before_history
    assert rows(editing.service) == before_rows


def test_agent_provider_refuses_animation_in_unsupported_phase_without_publication(editing):
    _visual_stand_in(editing)
    before_rows, before_head, before_history = rows(editing.service), editing.head(), editing.history()
    with pytest.raises(RuntimeErrorBase, match="animation 'slide-up'.*expected 'entrance'"):
        _commit_visual_field(editing, "entrance", {"id": "slide-up", "durationFrames": 12},
                             "unsupported-animation-phase", use_agent_setter=False)
    assert editing.head() == before_head
    assert editing.history() == before_history
    assert rows(editing.service) == before_rows


@pytest.mark.parametrize("field,value", [
    ("entrance", {"id": "not-installed", "durationFrames": 12}),
    ("entrance", {"id": "fade", "durationFrames": 12, "params": {"easing": "bounce"}}),
    ("entrance", {"id": "fade", "durationFrames": 12, "params": {"amplitude": 2}}),
    ("transition", {"type": "wipe", "duration": 0.4}),
])
def test_unsupported_visual_fields_refuse_before_publication(editing, field, value):
    _visual_stand_in(editing)
    before_rows, before_head, before_history = rows(editing.service), editing.head(), editing.history()
    with pytest.raises(RuntimeErrorBase):
        _commit_visual_field(editing, field, value, "unsupported-visual-" + field, use_agent_setter=False)
    assert editing.head() == before_head
    assert editing.history() == before_history
    assert rows(editing.service) == before_rows


def test_visual_candidate_is_refused_before_publication_when_builtin_phase_is_unsupported(editing, monkeypatch):
    from astrid.sdk.timeline import validation as agent_validation

    _visual_stand_in(editing)
    before_rows, before_head, before_history = rows(editing.service), editing.head(), editing.history()
    validate = agent_validation.validate_final_candidate

    def inject_before_agent_validation(bundle, *args, **kwargs):
        candidate = copy.deepcopy(bundle)
        target = next(clip for clip in candidate["parent"]["clips"] if clip["id"] == "music-bed")
        target["entrance"] = {"id": "slide-up", "durationFrames": 12}
        mirror = next(clip for clip in candidate["parent"]["config"]["clips"]
                      if clip["id"] == "music-bed")
        mirror["entrance"] = {"id": "slide-up", "durationFrames": 12}
        return validate(candidate, *args, **kwargs)

    monkeypatch.setattr(agent_validation, "validate_final_candidate", inject_before_agent_validation)
    with pytest.raises(RuntimeErrorBase, match="animation 'slide-up'.*expected 'entrance'"):
        editing.commit(editing.body([editing.move("music-bed", 1)]), "unsupported-visual-ref")

    assert editing.head() == before_head
    assert editing.history() == before_history
    assert rows(editing.service) == before_rows


def test_real_move_rebases_disjoint_clip_and_conflicts_on_same_clip(editing):
    base, document = editing.head(), editing.document()
    first_body = editing.body([editing.move("music-bed", 1, document=document)], base)
    disjoint = editing.body([editing.move("music-other", 2, document=document)], base)
    conflicting = editing.body([editing.move("music-bed", 3, document=document)], base)
    first = editing.commit(first_body, "move-first")
    assert editing.service.store._last_idempotency_prune > 0
    second = editing.commit(disjoint, "move-disjoint")
    assert first["data"]["status"] == "accepted"
    assert second["data"]["status"] == "merged"
    assert second["data"]["rebased_onto"] == {
        "revision_id": first["data"]["accepted_revision_id"],
        "publication_id": first["receipt"]["receipt_id"],
    }
    assert positions(second["data"]["canonical_document"]) == {"music-bed": 1, "music-other": 2}
    editing.assert_readback(first)  # Exact old accepted closure after a newer head.
    editing.assert_readback(second)
    before = rows(editing.service)
    with pytest.raises(RuntimeErrorBase) as error:
        editing.commit(conflicting, "move-conflict")
    assert error.value.status == 409
    assert error.value.details["status"] == "conflict"
    assert rows(editing.service) == before
    history = editing.history()
    assert len(history) == 4
    assert [entry["publication_id"] for entry in history[-2:]] == [
        first["receipt"]["receipt_id"], second["receipt"]["receipt_id"],
    ]
    original = history[-2]["records"]["commands"][0]
    assert original["command"] == first["data"]["commands"][0]
    assert original["writes"] and original["reads"] and original["bindings"]
    assert original["selections"] and original["dependencies"]
    editing.assert_baseline()


@pytest.mark.parametrize("deleted_index", [0, -1])
def test_real_reordered_clip_delete_undo_restores_exact_order(editing, deleted_index):
    from astrid.sdk.timeline.capture import capture_clip_delete
    from astrid.sdk.timeline.commands import execute

    original = editing.document()
    clips = original["parent_revision"]["payload"]["clips"]
    target = clips[deleted_index]["id"]
    change = {"op": "list.move", "ref": "parent", "path": ["clips"],
              "before": {"state": "present", "value": copy.deepcopy(clips[-1])},
              "id": clips[-1]["id"], "order_before": [row["id"] for row in clips], "after_id": None}
    reorder = {"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
               "args": {"changes": [change]}}
    staged = execute(editing.agent.bundle(original), [reorder])
    deletion = capture_clip_delete(staged.bundle, "parent/clip:" + target)
    body = editing.body([reorder, deletion])
    body["steps"] = [
        {"id": "order", "label": "Order", "intent": "", "tags": [],
         "command_ordinals": [0], "patch": [change], "reads": []},
        {"id": "delete", "label": "Delete", "intent": "", "tags": [],
         "command_ordinals": [1], "patch": [], "reads": []},
    ]

    forward = editing.commit(body, "ordered-delete-forward-" + str(deleted_index))
    inverse_body = editing.body([inverse(forward["receipt"]["receipt_id"])])
    restored = editing.commit(inverse_body, "ordered-delete-undo-" + str(deleted_index))

    assert restored["data"]["canonical_document"] == original


def test_real_same_step_multi_delete_undo_restores_each_command_order(editing):
    from astrid.sdk.timeline.capture import capture_clip_delete
    from astrid.sdk.timeline.commands import execute

    original = editing.document()
    clips = original["parent_revision"]["payload"]["clips"]
    staged = editing.agent.bundle(original)
    commands = []
    for target in (clips[0]["id"], clips[-1]["id"]):
        deletion = capture_clip_delete(staged, "parent/clip:" + target)
        commands.append(deletion)
        staged = execute(staged, [deletion]).bundle
    body = editing.body(commands)
    body["steps"] = [{"id": "delete-both", "label": "Delete both", "intent": "", "tags": [],
                       "command_ordinals": [0, 1], "patch": [], "reads": []}]

    forward = editing.commit(body, "same-step-multi-delete-forward")
    inverse_body = editing.body([inverse(forward["receipt"]["receipt_id"])])
    restored = editing.commit(inverse_body, "same-step-multi-delete-undo")

    assert restored["data"]["canonical_document"] == original


def test_real_delete_then_reorder_undo_restores_exact_order(editing):
    from astrid.sdk.timeline.capture import capture_clip_delete
    from astrid.sdk.timeline.commands import execute

    clips = editing.document()["parent_revision"]["payload"]["clips"]
    extra = copy.deepcopy(clips[-1])
    extra.update(id="parent-order-extra", at=max(row["at"] + row["hold"] for row in clips) + 1)
    insert = {"op": "list.insert", "ref": "parent", "path": ["clips"],
              "before": {"state": "absent"}, "id": extra["id"], "value": extra,
              "order_before": [row["id"] for row in clips], "after_id": clips[-1]["id"]}
    seed = {"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
            "args": {"changes": [insert]}, "created": ["parent/clip:" + extra["id"]]}
    setup = editing.body([seed])
    setup["steps"][0]["patch"] = [insert]
    editing.commit(setup, "parent-after-order-setup")
    original = editing.document()
    baseline = editing.agent.bundle(original)
    delete = capture_clip_delete(baseline, "parent/clip:" + clips[0]["id"])
    staged = execute(baseline, [delete])
    remaining = staged.bundle["parent"]["clips"]
    change = {"op": "list.move", "ref": "parent", "path": ["clips"],
              "before": {"state": "present", "value": copy.deepcopy(remaining[-1])},
              "id": remaining[-1]["id"],
              "order_before": [row["id"] for row in remaining], "after_id": None}
    reorder = {"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
               "args": {"changes": [change]}}
    body = editing.body([delete, reorder])
    body["steps"] = [
        {"id": "delete", "label": "Mixed delete order", "intent": "", "tags": [],
         "command_ordinals": [0], "patch": [], "reads": []},
        {"id": "order", "label": "Mixed delete order", "intent": "", "tags": [],
         "command_ordinals": [1], "patch": [change], "reads": []},
    ]
    forward = editing.commit(body, "parent-after-order-forward")
    restored = editing.commit(
        editing.body([inverse(forward["receipt"]["receipt_id"])]),
        "parent-after-order-undo",
    )

    assert restored["data"]["canonical_document"] == original


@pytest.mark.parametrize("overlap", [False, True], ids=["immediate", "later-overlap"])
def test_real_mixed_helper_commit_undo_is_exact_or_refuses_overlap(editing, overlap):
    from astrid.sdk.timeline.api import Timeline
    from astrid.sdk.timeline.commands import execute

    def evaluate(base, document, edit):
        bundle = editing.agent.bundle(document)
        timeline = Timeline(None, bundle, base, evaluating=True)
        edit(timeline)
        timeline._capture_free_edits()
        assert timeline._commands
        commands = execute(bundle, timeline._commands).commands
        return copy.deepcopy(commands), copy.deepcopy(timeline._steps)

    def seed(timeline):
        timeline.add_text("Old title", at=6, hold=7, track="picture", id="old-title")
        timeline.add_text("Old intro", at=0, hold=1, track="picture", id="old-intro")

    seed_base = editing.head()
    seed_commands, seed_steps = evaluate(seed_base, editing.document(), seed)
    seed_body = editing.body(seed_commands, seed_base)
    seed_body["steps"] = seed_steps
    editing.commit(seed_body, "mixed-helper-seed")

    before = copy.deepcopy(editing.document())
    history_before = copy.deepcopy(editing.history())
    base = editing.head()

    def recut(timeline):
        timeline.track("titles", above="picture").rename("Opening")
        timeline.add_text("Chapter one", at=12, hold=3, track="titles", id="chapter-one")
        timeline.clip("old-title").set_track("titles").hold_for(2.5).on(5)
        timeline.clip("old-intro").remove()

    commands, steps = evaluate(base, before, recut)
    body = editing.body(commands, base)
    body["steps"] = steps
    accepted = editing.commit(body, "mixed-helper-recut")

    assert accepted["data"]["status"] == "accepted"
    authored = editing.history()
    assert authored[:-1] == history_before
    assert authored[-1]["publication_id"] == accepted["receipt"]["receipt_id"]
    parent = editing.document()["parent_revision"]["payload"]
    tracks = parent["config"]["tracks"]
    assert [row["id"] for row in tracks].index("titles") < [row["id"] for row in tracks].index("picture")
    assert next(row for row in tracks if row["id"] == "titles")["label"] == "Opening"
    clips = parent["clips"]
    assert "old-intro" not in [row["id"] for row in clips]
    title = next(row for row in clips if row["id"] == "old-title")
    assert (title["track"], title["hold"], title["at"]) == ("titles", 2.5, 5)
    assert next(row for row in clips if row["id"] == "chapter-one")["params"]["text"] == "Chapter one"

    if overlap:
        peer = editing.body([editing.move("old-title", 6)], editing.head())
        editing.commit(peer, "mixed-helper-peer-move")
        current = copy.deepcopy(editing.document())
        current_history = copy.deepcopy(editing.history())
        current_rows = rows(editing.service)
        with pytest.raises(RuntimeErrorBase) as error:
            editing.commit(editing.body([inverse(accepted["receipt"]["receipt_id"])]),
                           "mixed-helper-undo-overlap")
        assert error.value.status == 409
        assert editing.document() == current
        assert editing.history() == current_history
        assert rows(editing.service) == current_rows
    else:
        undone = editing.commit(editing.body([inverse(accepted["receipt"]["receipt_id"])]),
                                "mixed-helper-undo")
        assert undone["data"]["canonical_document"] == before


def test_real_inverse_refuses_well_hashed_wrong_clip_order(editing, monkeypatch):
    from astrid.sdk.timeline.capture import capture_clip_delete
    from runtime_protocol.timeline_commit_auth import _authoring_parent_identity, images
    from runtime_protocol.timeline_commit_port import RequestCommitPort
    from runtime_protocol.timeline_commit_validation import digest

    original = editing.document()
    clips = original["parent_revision"]["payload"]["clips"]
    deletion = capture_clip_delete(editing.agent.bundle(original), "parent/clip:" + clips[0]["id"])
    forward = editing.commit(editing.body([deletion]), "wrong-order-source-delete")
    before_rows = rows(editing.service)
    before_history = editing.history()
    accept = RequestCommitPort.accept
    reached = []

    def reverse_prepared(port, prepared):
        value = copy.deepcopy(prepared)
        document = value["canonical_document"]
        payload = document["parent_revision"]["payload"]
        payload["clips"].reverse()
        payload["config"]["clips"].reverse()
        document["parent_revision"]["content_digest"] = digest(payload)
        document["parent_revision"]["revision_id"] = _authoring_parent_identity(
            images(document), (document["project_id"], document["timeline_id"]),
            document["dependency_manifest"],
        )
        value["document_digest"] = digest(document)
        reached.append(value)
        return accept(port, value)

    monkeypatch.setattr(RequestCommitPort, "accept", reverse_prepared)
    with pytest.raises(RuntimeErrorBase) as error:
        editing.commit(editing.body([inverse(forward["receipt"]["receipt_id"])]),
                       "wrong-order-undo")

    assert error.value.details is not None
    assert error.value.details["reason"] == "invalid_records"
    assert reached
    assert rows(editing.service) == before_rows
    assert editing.history() == before_history


def test_real_door_concurrent_disjoint_moves_accept_and_rebase(film, agent, tmp_path, monkeypatch):
    world = _start_door(film, tmp_path)
    try:
        editing = Editing(world.daemon.service, film, agent)
        editing.assert_baseline()
        base, document = editing.head(), editing.document()
        requests = [
            (editing.body([editing.move("music-bed", 1, document=document)], base), "door-concurrent-bed"),
            (editing.body([editing.move("music-other", 2, document=document)], base), "door-concurrent-other"),
        ]

        provider_type = type(world.daemon.service._timeline_commit_provider)
        provider_commit = provider_type.commit
        preparation_barrier = Barrier(2)
        provider_keys, provider_lock = [], Lock()

        def overlap_provider(provider, context, port):
            with provider_lock:
                provider_keys.append(context["idempotency_key"])
            preparation_barrier.wait(timeout=10)
            return provider_commit(provider, context, port)

        monkeypatch.setattr(provider_type, "commit", overlap_provider)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(_post_door, world, editing.path, body, key)
                       for body, key in requests]
            results = [future.result(timeout=30) for future in futures]

        assert sorted(provider_keys) == sorted(key for _, key in requests)
        assert sorted(result["data"]["status"] for result in results) == ["accepted", "merged"]
        assert len({result["receipt"]["receipt_id"] for result in results}) == 2
        for result in results:
            editing.assert_readback(result)

        final = editing.document()
        assert positions(final) == {"music-bed": 1, "music-other": 2}
        history = editing.history()
        assert len(history) == 4
        concurrent_history = history[-2:]
        assert {entry["publication_id"] for entry in concurrent_history} == {
            result["receipt"]["receipt_id"] for result in results
        }
        assert len({entry["revision_id"] for entry in concurrent_history}) == 2
        ledger = world.daemon.service.store.conn.execute(
            "SELECT idempotency_key, txn_id FROM command_idempotency "
            "WHERE command_kind='timeline.commit' AND idempotency_key IN (?, ?) "
            "ORDER BY idempotency_key",
            tuple(key for _, key in requests),
        ).fetchall()
        assert [(row["idempotency_key"], row["txn_id"]) for row in ledger] == sorted(
            (key, next(result["receipt"]["receipt_id"] for result in results
                       if result["receipt"]["idempotency_key"] == key))
            for _, key in requests
        )
    finally:
        world.stop()


def test_real_inverse_preserves_newer_disjoint_work_and_original_recorders(editing):
    original = editing.document()
    first = editing.commit(editing.body([editing.move("music-bed", 1)]), "undo-target")
    second = editing.commit(editing.body([editing.move("music-other", 2)]), "undo-disjoint")
    stored = copy.deepcopy(editing.history())
    undone = editing.commit(editing.body([inverse(first["receipt"]["receipt_id"])]), "undo-target-publication")
    assert positions(undone["data"]["canonical_document"]) == {"music-bed": 0, "music-other": 2}
    parent = undone["data"]["canonical_document"]["parent_revision"]["payload"]
    original_parent = original["parent_revision"]["payload"]
    second_parent = second["data"]["canonical_document"]["parent_revision"]["payload"]
    # Baseline plus B.at omitted B's intentional app.astrid fixed_start/for writes.
    expected = copy.deepcopy(second_parent)
    for container, baseline in ((expected, original_parent),
                                (expected["config"], original_parent["config"])):
        target = next(row for row in baseline["clips"] if row["id"] == "music-bed")
        for index, row in enumerate(container["clips"]):
            if row["id"] == "music-bed":
                container["clips"][index] = copy.deepcopy(target)
    assert_json_equal(parent, expected)
    for container, accepted in ((parent, second_parent),
                                (parent["config"], second_parent["config"])):
        assert_json_equal(next(row for row in container["clips"] if row["id"] == "music-other"),
                          next(row for row in accepted["clips"] if row["id"] == "music-other"))
    assert undone["data"]["canonical_document"]["shot_revisions"] == original["shot_revisions"]
    assert undone["data"]["canonical_document"]["internal_timeline_revisions"] == original["internal_timeline_revisions"]
    assert editing.history()[:-1] == stored
    assert editing.history()[-1]["records"]["undo_of"] == [first["receipt"]["receipt_id"]]
    editing.assert_readback(first)
    editing.assert_readback(second)
    editing.assert_readback(undone)


def test_real_same_value_publication_is_recorded_and_blocks_older_undo(editing):
    first = editing.commit(editing.body([editing.move("music-bed", 1)]), "same-target")
    same = editing.commit(editing.body([editing.move("music-bed", 1)]), "same-value")
    assert same["data"]["accepted_revision_id"] == first["data"]["accepted_revision_id"]
    assert same["receipt"]["receipt_id"] != first["receipt"]["receipt_id"]
    records = editing.history()[-1]["records"]["commands"]
    assert any(write["ref"] == "parent/clip:music-bed" and write["path"] == ["at"]
               and write["before"] == write["after"] for write in records[0]["writes"])
    before = rows(editing.service)
    with pytest.raises(RuntimeErrorBase) as error:
        editing.commit(editing.body([inverse(first["receipt"]["receipt_id"])]), "same-value-undo-conflict")
    assert error.value.status == 409
    assert error.value.details["status"] == "conflict"
    assert rows(editing.service) == before
    assert len(editing.history()) == 4
    editing.assert_readback(same)


@pytest.mark.parametrize("later", ["overwritten", "returned"])
def test_real_inverse_refuses_when_target_was_overwritten_or_returned(editing, later):
    first = editing.commit(editing.body([editing.move("music-bed", 1)]), "undo-stale-target")
    editing.commit(editing.body([editing.move("music-bed", 2)]), "undo-overwrite")
    if later == "returned":
        editing.commit(editing.body([editing.move("music-bed", 1)]), "undo-return")
    before, length = rows(editing.service), len(editing.history())
    with pytest.raises(RuntimeErrorBase) as error:
        editing.commit(editing.body([inverse(first["receipt"]["receipt_id"])]), "undo-stale-conflict")
    assert error.value.status == 409
    assert error.value.details["status"] == "conflict"
    assert rows(editing.service) == before
    assert len(editing.history()) == length


def test_real_inverse_dry_run_and_exact_retry_write_only_the_undo_once(editing, monkeypatch):
    first = editing.commit(editing.body([editing.move("music-bed", 1)]), "undo-dry-target")
    undo = editing.body([inverse(first["receipt"]["receipt_id"])])
    before = rows(editing.service)
    preview = editing.commit({**copy.deepcopy(undo), "dry_run": True}, "undo-dry-run")
    assert preview["data"]["status"] == "preview"
    assert preview["receipt"] is None
    assert rows(editing.service) == before
    undone = editing.commit(copy.deepcopy(undo), "undo-real")
    after = rows(editing.service)

    def forbidden(self, context, port):
        raise AssertionError("exact retry executed the semantic provider")

    with monkeypatch.context() as retry:
        retry.setattr(type(editing.service._timeline_commit_provider), "commit", forbidden)
        assert editing.commit(copy.deepcopy(undo), "undo-real") == undone
    assert rows(editing.service) == after
    assert editing.history()[-1]["records"]["undo_of"] == [first["receipt"]["receipt_id"]]


def test_real_track_create_and_inverse_keep_complete_film_closure(editing):
    original = editing.document()
    track = {"id": "new-audio", "kind": "audio", "extension": {"opaque": [None, "kept"]}}
    command = editing.agent.track(editing.agent.bundle(original), "parent", track)
    accepted = editing.commit(editing.body([command]), "track-create")
    assert accepted["data"]["canonical_document"]["parent_revision"]["payload"]["config"]["tracks"][-1] == track
    assert editing.history()[-1]["records"]["commands"][0]["created"]
    undone = editing.commit(editing.body([inverse(accepted["receipt"]["receipt_id"])]), "track-undo")
    restored = undone["data"]["canonical_document"]
    assert restored["parent_revision"]["payload"] == original["parent_revision"]["payload"]
    assert restored["parent_revision"]["content_digest"] == original["parent_revision"]["content_digest"]
    for family in ("shot_revisions", "internal_timeline_revisions", "dependency_manifest"):
        assert restored[family] == original[family]
    editing.assert_readback(accepted)
    editing.assert_readback(undone)


def test_real_picture_audio_tracks_and_overlay_wav_undo_exactly(editing):
    from astrid.sdk.timeline._command_state import ABSENT, present
    from test_timeline_clip_replacement import _media_bytes

    original = editing.document()
    image = editing.service.ingest(
        editing.project, _media_bytes(kind="image"), media_type="image/png", idempotency_key="e2-picture",
    )["data"]["object_id"]
    audio = io.BytesIO()
    with wave.open(audio, "wb") as output:
        output.setparams((1, 2, 8000, 0, "NONE", "not compressed"))
        output.writeframes(b"\x00\x00" * 8000)
    wav = editing.service.ingest(
        editing.project, audio.getvalue(), media_type="audio/wav", idempotency_key="e2-wav",
    )["data"]["object_id"]

    def command(op, select, args):
        return {"schema_version": 1, "op": op, "version": "1", "select": select, "args": args}

    clips = original["parent_revision"]["payload"]["clips"]
    added = [
        {"id": "e2-picture", "track": "V2", "asset": "e2-picture", "clipType": "image", "at": 0, "hold": 1},
        {"id": "e2-wav", "track": "A2", "asset": "e2-wav", "clipType": "audio", "at": 0, "hold": 1},
    ]
    changes = [{"op": "set", "ref": "parent", "path": ["clips"], "before": present(clips),
                "value": [*clips, *added]}]
    for identity, media, kind in (("e2-picture", image, "image/png"), ("e2-wav", wav, "audio/wav")):
        changes.append({"op": "set", "ref": "parent", "path": ["registry", "assets", identity],
                        "before": ABSENT, "value": {"media_id": media, "type": kind}})
    patch = command("doc.patch", None, {"changes": changes})
    patch["created"] = ["parent/clip:e2-picture", "parent/clip:e2-wav",
                        "parent/asset:e2-picture", "parent/asset:e2-wav"]
    admission = command("media.admit", None, {"inputs": [
        {"pin": {"media_id": media, "content_digest": media}} for media in (image, wav)
    ]})
    commands = [admission, command("track.create", "parent", {"row": {"id": "V2", "kind": "visual"}}),
                command("track.create", "parent", {"row": {"id": "A2", "kind": "audio"}}), patch]
    request = editing.body(commands)
    request["steps"] = [
        {"id": "admit", "label": "Admit", "intent": "", "tags": [],
         "command_ordinals": [0], "patch": []},
        {"id": "edit", "label": "Edit", "intent": "", "tags": [],
         "command_ordinals": [1, 2, 3], "patch": copy.deepcopy(changes)},
    ]

    prior_count = len(editing.history())
    accepted = editing.commit(request, "picture-audio-overlay-wav")
    assert len(editing.history()) == prior_count + 1
    edited = accepted["data"]["canonical_document"]["parent_revision"]["payload"]
    assert [row["id"] for row in edited["config"]["tracks"]][-2:] == ["V2", "A2"]
    assert [row["id"] for row in edited["clips"][-2:]] == ["e2-picture", "e2-wav"]

    undone = editing.commit(editing.body([inverse(accepted["receipt"]["receipt_id"])]), "picture-audio-undo")
    assert len(editing.history()) == prior_count + 2
    assert undone["data"]["canonical_document"] == original


def _start_door(film, tmp_path):
    from runtime_protocol.daemon import RuntimeDaemon
    from runtime_protocol.door import DoorConfig
    from tests.door_helpers import HOSTED, DoorWorld

    credential = tmp_path / "product.json"
    daemon = RuntimeDaemon(
        film.fixture.duplicate_root, support_root=tmp_path / "support", authoring_profile="astrid",
        door=DoorConfig(origin=HOSTED, port=0, credential_file=credential),
    ).start()
    assert daemon.service is not None
    world = DoorWorld(tmp_path, daemon, credential)
    world.provision()
    handshake = world.call("/api/runtime/v1/handshake", "POST", body=b"{}",
                           headers={"Content-Type": "application/json"})
    assert handshake.status == 200, handshake.body
    return world


def _post_door(world, path, body, key):
    response = world.call("/api/runtime" + path, "POST", body=json.dumps(body).encode(),
                          headers={"Content-Type": "application/json", "Idempotency-Key": key})
    assert response.status == 200, response.body
    return response.json()


def _full_v2_auth_body(edit):
    change = {
        "op": "set",
        "ref": "parent",
        "path": ["meta", "org.example.auth-probe"],
        "before": {"state": "absent"},
        "value": "must-not-write",
    }
    reads = [{"kind": "field", "ref": "parent", "path": change["path"],
              "state": {"state": "absent"}}]
    command = {
        "schema_version": 1,
        "op": "doc.patch",
        "version": "1",
        "select": None,
        "args": {"changes": [copy.deepcopy(change)]},
    }
    body = edit.body([command])
    body.update({
        "label": "Door authorization probe",
        "steps": [{
            "id": "auth-probe",
            "label": "Door authorization probe",
            "intent": "Verify commit admission",
            "tags": ["authorization"],
            "command_ordinals": [0],
            "patch": [change],
            "reads": reads,
        }],
        "merge": "fields",
        "reads": reads,
    })
    return body


def _assert_door_refusal_unchanged(edit, response, expected_status, expected_body,
                                   before_rows, before_head, before_history):
    assert response.status == expected_status, response.body
    assert response.json() == expected_body
    assert rows(edit.service) == before_rows
    assert edit.head() == before_head
    assert edit.history() == before_history


@pytest.mark.parametrize("merge", ["fields", "atomic"])
def test_real_door_v2_native_and_patch_preview_accept_retry_and_stale_head(
        film, agent, tmp_path, monkeypatch, merge):
    world = _start_door(film, tmp_path)
    try:
        edit = Editing(world.daemon.service, film, agent)
        assert edit.service is not None
        base, document = edit.head(), edit.document()
        body = _full_v2_auth_body(edit)
        body["merge"] = merge
        change = body["commands"][0]["args"]["changes"][0]
        # This capture has no meta container; create it as one guarded value.
        assert "meta" not in document["parent_revision"]["payload"]
        change["path"] = ["meta"]
        change["value"] = {"org.example.auth-probe": {"note": "Preserve alongside the native move"}}
        body["reads"][0]["path"] = ["meta"]
        body["steps"][0]["reads"][0]["path"] = ["meta"]
        body["steps"][0]["patch"] = [copy.deepcopy(change)]
        body["commands"].insert(0, edit.move("music-bed", 1, document=document))
        body["steps"][0]["command_ordinals"] = [1]
        body["steps"].insert(0, {
            "id": "native-move", "label": "Move the music bed", "intent": "Retain native semantics",
            "tags": ["integration"], "command_ordinals": [0], "patch": [], "reads": [],
        })
        frozen = copy.deepcopy(body)
        before = rows(edit.service)
        preview = _post_door(world, edit.path, {**body, "dry_run": True}, "v2-preview")
        assert preview["data"]["status"] == "preview"
        assert preview["data"]["would_status"] == "accepted"
        assert preview["data"]["evaluated_head"] == base
        assert preview["data"]["merge_mode"] == merge
        assert preview["receipt"] is None
        assert rows(edit.service) == before

        accepted = _post_door(world, edit.path, body, "v2-mixed")
        assert accepted["data"]["status"] == "accepted"
        assert accepted["data"]["label"] == body["label"]
        assert accepted["data"]["merge_mode"] == merge
        assert next(row for row in edit.history()
                    if row["publication_id"] == accepted["receipt"]["receipt_id"])["reads"] == body["reads"]
        assert [step["id"] for step in accepted["data"]["steps"]] == ["native-move", "auth-probe"]
        assert accepted["data"]["steps"][1]["patch"] == [change]
        assert accepted["data"]["steps"][1]["reads"] == body["steps"][1]["reads"]
        canonical = accepted["data"]["canonical_document"]
        assert positions(canonical) == {"music-bed": 1, "music-other": 0}
        assert canonical["parent_revision"]["payload"]["meta"] == change["value"]
        edit.assert_readback(accepted)
        after = rows(edit.service)

        def forbidden(self, context, port):
            raise AssertionError("exact v2 retry executed the semantic provider")

        with monkeypatch.context() as retry:
            retry.setattr(type(edit.service._timeline_commit_provider), "commit", forbidden)
            assert _post_door(world, edit.path, body, "v2-mixed") == accepted
        assert body == frozen
        assert rows(edit.service) == after

        stale = edit.body([edit.move("music-other", 2, document=document)], base)
        stale["merge"] = merge
        response = world.call("/api/runtime" + edit.path, "POST", body=json.dumps(stale).encode(),
                              headers={"Content-Type": "application/json", "Idempotency-Key": "v2-stale"})
        if merge == "fields":
            assert response.status == 200, response.body
            merged = response.json()
            assert merged["data"]["status"] == "merged"
            assert merged["data"]["rebased_onto"] == {
                "revision_id": accepted["data"]["accepted_revision_id"],
                "publication_id": accepted["receipt"]["receipt_id"],
            }
            assert positions(merged["data"]["canonical_document"]) == {"music-bed": 1, "music-other": 2}
            assert merged["data"]["canonical_document"]["parent_revision"]["payload"]["meta"] == canonical["parent_revision"]["payload"]["meta"]
            edit.assert_readback(merged)
        else:
            assert response.status == 409, response.body
            details = response.json()["details"]
            assert details["status"] == "conflict"
            assert details["code"] == "atomic_scope_changed"
            assert details["current"] == edit.head()
            assert isinstance(details["path"], list)
            assert details["hint"] and details["suggested_command"]
            assert rows(edit.service) == after
        edit.assert_baseline()
    finally:
        world.stop()


def test_real_door_v2_invalid_patch_has_structured_failure_without_writes(film, agent, tmp_path):
    world = _start_door(film, tmp_path)
    try:
        edit = Editing(world.daemon.service, film, agent)
        body = _full_v2_auth_body(edit)
        change = body["commands"][0]["args"]["changes"][0]
        change["path"] = ["meta"]
        change["before"] = {"state": "present", "value": {"org.example.auth-probe": {"note": "never existed"}}}
        change["value"] = {"org.example.auth-probe": {"note": "must not be accepted"}}
        body["reads"][0]["path"] = ["meta"]
        body["steps"][0]["reads"][0]["path"] = ["meta"]
        body["steps"][0]["patch"] = [copy.deepcopy(change)]
        before, head, history = rows(edit.service), edit.head(), copy.deepcopy(edit.history())
        response = world.call("/api/runtime" + edit.path, "POST", body=json.dumps(body).encode(),
                              headers={"Content-Type": "application/json", "Idempotency-Key": "v2-invalid"})
        assert response.status == 422, response.body
        failure = response.json()
        assert failure["code"] == "validation_error"
        details = failure["details"]
        assert details["status"] == "invalid"
        assert details["code"] == "previous_value_mismatch"
        assert details["path"] == change["path"]
        assert details["current"] == head
        assert details["hint"] and details["suggested_command"]
        assert "receipt" not in failure
        assert rows(edit.service) == before
        assert edit.head() == head
        assert edit.history() == history
        edit.assert_baseline()
    finally:
        world.stop()


def _assert_route_scope_refusal_unchanged(edit, response, before_rows, before_head,
                                          before_history):
    assert response.status == 409, response.body
    payload = response.json()
    assert payload["code"] == "conflict"
    assert payload["message"] == "commit project/timeline identity does not match the route"
    assert isinstance(payload["request_id"], str) and payload["request_id"]
    assert rows(edit.service) == before_rows
    assert edit.head() == before_head
    assert edit.history() == before_history


def test_real_door_commit_admission_checks_origin_auth_and_project_scope(film, agent, tmp_path, monkeypatch):
    from runtime_protocol import door as door_module
    from tests.door_helpers import PRODUCT_ACTOR, write_owner_only

    world = _start_door(film, tmp_path)
    try:
        evil_origin = "https://evil.test"
        edit = Editing(world.daemon.service, film, agent)
        edit.assert_baseline()
        body = edit.body([edit.move("music-bed", 1)])
        negative_body = _full_v2_auth_body(edit)
        encoded = json.dumps(negative_body).encode()
        path = "/api/runtime" + edit.path
        headers = {"Content-Type": "application/json", "Idempotency-Key": "door-admission"}
        before = rows(edit.service)
        before_head = edit.head()
        before_history = copy.deepcopy(edit.history())

        service = edit.service
        assert service is not None
        provider_type = type(service._timeline_commit_provider)

        def forbidden_provider(*args, **kwargs):
            raise AssertionError("refused door request reached the commit provider")

        with monkeypatch.context() as guard:
            guard.setattr(provider_type, "commit", forbidden_provider)

            refused = world.call(path, "POST", origin=evil_origin, body=encoded, headers=headers)
            _assert_door_refusal_unchanged(
                edit, refused, 403, {"error": "hosted_origin_required"},
                before, before_head, before_history,
            )

            refused = world.call(path, "POST", body=encoded,
                                 headers={**headers, "Authorization": "Bearer browser"})
            _assert_door_refusal_unchanged(
                edit, refused, 403, {"error": "browser_credentials_forbidden"},
                before, before_head, before_history,
            )

            world.credential_file.unlink()
            refused = world.call(path, "POST", body=encoded,
                                 headers={**headers, "Idempotency-Key": "door-missing-credential"})
            _assert_door_refusal_unchanged(
                edit, refused, 503, {"error": "runtime_unavailable"},
                before, before_head, before_history,
            )

            write_owner_only(world.credential_file, {
                "version": 1, "scope": "astrid", "actor_id": PRODUCT_ACTOR,
                "token": "not-a-token-the-runtime-knows",
            })
            refused = world.call(path, "POST", body=encoded,
                                 headers={**headers, "Idempotency-Key": "door-invalid-credential"})
            _assert_door_refusal_unchanged(
                edit, refused, 503, {"error": "runtime_unavailable"},
                before, before_head, before_history,
            )

            assert world.daemon.credentials is not None
            credential_store = world.daemon.credentials
            reduced_scopes = [scope for scope in door_module.PRODUCT_SCOPES if scope != "projects:write"]
            readonly_token, _ = credential_store.provision(
                PRODUCT_ACTOR, reduced_scopes, rotate=True,
            )
            identity = credential_store.require(readonly_token, "handshake")
            assert identity["actor"] == PRODUCT_ACTOR
            assert identity["scopes"] == reduced_scopes
            # The unchanged door requires the exact product scope set before
            # dispatch, so missing write authority fails profile admission.
            write_owner_only(world.credential_file, {
                "version": 1, "scope": "astrid", "actor_id": PRODUCT_ACTOR,
                "token": readonly_token,
            })
            refused = world.call(path, "POST", body=encoded,
                                 headers={**headers, "Idempotency-Key": "door-read-only-credential"})
            _assert_door_refusal_unchanged(
                edit, refused, 503, {"error": "runtime_identity_mismatch"},
                before, before_head, before_history,
            )

            world.provision()

            foreign = copy.deepcopy(negative_body)
            foreign["project_id"] = "foreign-project"
            refused = world.call(path, "POST", body=json.dumps(foreign).encode(),
                                 headers={**headers, "Idempotency-Key": "door-foreign-project"})
            _assert_route_scope_refusal_unchanged(edit, refused, before, before_head, before_history)

            foreign_path = "/api/runtime/v1/projects/{}/timelines/{}/commit".format(
                edit.project, "foreign-timeline",
            )
            refused = world.call(foreign_path, "POST", body=encoded,
                                 headers={**headers, "Idempotency-Key": "door-foreign-route"})
            _assert_route_scope_refusal_unchanged(edit, refused, before, before_head, before_history)

        accepted = _post_door(world, edit.path, body, "door-admission")
        assert accepted["data"]["status"] == "accepted"
        assert accepted["data"]["publisher"] == PRODUCT_ACTOR
        assert edit.history()[-1]["publisher"] == PRODUCT_ACTOR
        edit.assert_readback(accepted)
        edit.assert_baseline()
    finally:
        world.stop()


def test_real_door_lost_ack_restart_exact_retry_never_executes_provider(film, agent, tmp_path, monkeypatch):
    def start():
        return _start_door(film, tmp_path)

    post = _post_door

    world = start()
    try:
        edit = Editing(world.daemon.service, film, agent)
        edit.assert_baseline()
        body = edit.body([edit.move("music-bed", 1)])
        frozen = json.dumps(body, sort_keys=True)
        accepted = post(world, edit.path, body, "door-lost-ack")
        # No acknowledgement is applied to a client session. Its exact flight
        # survives while a different author advances the head before shutdown.
        newer = edit.commit(edit.body([edit.move("music-other", 2)]), "door-newer-disjoint")
        original_history = copy.deepcopy(edit.history())
        old_instance = world.daemon.instance_id
        provider_type = type(world.daemon.service._timeline_commit_provider)
    finally:
        world.stop()

    world = start()
    try:
        assert world.daemon.instance_id != old_instance
        edit = Editing(world.daemon.service, film, agent)
        assert edit.head()["revision_id"] == newer["data"]["accepted_revision_id"]
        before = rows(edit.service)

        def forbidden(self, context, port):
            raise AssertionError("exact retry executed the semantic provider")

        with monkeypatch.context() as retry:
            retry.setattr(provider_type, "commit", forbidden)
            replayed = post(world, edit.path, json.loads(frozen), "door-lost-ack")
        assert replayed == accepted
        assert json.dumps(body, sort_keys=True) == frozen
        assert rows(edit.service) == before
        assert edit.history() == original_history
        edit.assert_readback(replayed)
        edit.assert_readback(newer)
        # A changed request under the same identity is refused without writes.
        changed = copy.deepcopy(body)
        changed["rationale"] = "changed identity"
        refused = world.call("/api/runtime" + edit.path, "POST", body=json.dumps(changed).encode(),
                             headers={"Content-Type": "application/json", "Idempotency-Key": "door-lost-ack"})
        assert refused.status == 409, refused.body
        assert refused.json()["details"]["reason"] == "idempotency_mismatch"
        assert rows(edit.service) == before
        undone = post(world, edit.path, edit.body([inverse(accepted["receipt"]["receipt_id"])]), "door-undo")
        assert positions(undone["data"]["canonical_document"]) == {"music-bed": 0, "music-other": 2}
        assert edit.history()[:-1] == original_history
        edit.assert_readback(undone)
        edit.assert_baseline()
    finally:
        world.stop()


def test_real_restart_undo_then_recorder_tamper_fails_closed(film, agent, tmp_path):
    from runtime_protocol.errors import RealmAdmissionError
    from runtime_protocol.util import canonical_json

    world = _start_door(film, tmp_path)
    try:
        edit = Editing(world.daemon.service, film, agent)
        edit.assert_baseline()
        accepted = _post_door(world, edit.path, edit.body([edit.move("music-bed", 1)]), "restart-undo-target")
    finally:
        world.stop()

    world = _start_door(film, tmp_path)
    try:
        edit = Editing(world.daemon.service, film, agent)
        publication = accepted["receipt"]["receipt_id"]
        undone = _post_door(world, edit.path, edit.body([inverse(accepted["receipt"]["receipt_id"])]), "restart-undo")
        edit.assert_readback(undone)
        assert edit.history()[-1]["records"]["undo_of"] == [publication]
        # Tamper the durable recorder of the pre-restart edit; the live store must refuse it.
        conn = world.daemon.service.store.conn
        records = json.loads(conn.execute(
            "SELECT records_json FROM timeline_commit_history WHERE publication_id=?", (publication,),
        ).fetchone()[0])
        records["undo_of"] = ["other-publication"]
        conn.execute("UPDATE timeline_commit_history SET records_json=? WHERE publication_id=?",
                     (canonical_json(records), publication))
        commits = world.daemon.service._timeline_commits()[0]
        assert any(error["id"] == publication for error in commits.integrity_errors())
    finally:
        world.stop()

    with pytest.raises(RealmAdmissionError) as error:
        RuntimeService(film.fixture.duplicate_root)
    assert not error.value.details["ok"]
    assert any(item["table"] == "timeline_commit_history" for item in error.value.details["checks"]["revisions"]["errors"])
