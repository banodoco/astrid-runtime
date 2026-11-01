"""Public CLI trim versus independent SDK label, on two separate films.

Run in the explicit integration lane with the current Astrid checkout. Keep
unsupported frontend capture as a failing acceptance assertion, rather than
rewriting the historical film or relaxing the native command's guards.
"""
from __future__ import annotations

import copy
import io
import json
import sys
import wave
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Event
from time import monotonic
from types import SimpleNamespace

import pytest

from test_timeline_commit_integration import (
    Editing,
    _start_door,
    assert_json_equal,
    film,  # noqa: F401 (verified historical music-film duplicate)
    rows,
)
from test_shot_composition_runtime import _publication
from historical_audio_fixture import prepare_pcm_historical_audio_film

pytestmark = pytest.mark.integration


class HistoricalAudioCaptureGap(AssertionError):
    """Only the original audio row's exact known pre-POST capture refusal."""


@pytest.fixture
def journey_film(request, film, astrid_importable, tmp_path):
    if request.param == "historical-audio":
        prepared = prepare_pcm_historical_audio_film(film, tmp_path)
        # Exercise the normal door and SDK read path after the fixture's
        # read-only startup-admission control. This is not a second setup
        # path: open_bundle only reads the immutable prepared closure.
        world = _start_door(prepared, tmp_path)
        try:
            opened = _client(world.daemon).timelines.open_bundle(
                prepared.fixture.project_id,
                prepared.fixture.timeline_id,
                revision_id=prepared.fixture.parent_revision_id,
            )
            assert opened.ok, opened.as_dict()
            assert opened.data["revision_id"] == prepared.fixture.parent_revision_id
        finally:
            world.stop()
        return prepared

    # Reuse the approved first-import builder on a NEW film with its own
    # child identities. The historical audio film remains entirely untouched.
    world = _start_door(film, tmp_path)
    try:
        client = _client(world.daemon)
        edit = Editing(world.daemon.service, film, None)
        original, history = edit.document(), edit.history()
        audio = io.BytesIO()
        with wave.open(audio, "wb") as output:
            output.setparams((1, 2, 8000, 0, "NONE", "not compressed"))
            output.writeframes(b"\x00\x00" * 48000)
        with wave.open(io.BytesIO(audio.getvalue()), "rb") as source:
            duration = source.getnframes() / source.getframerate()
        imported = client.media.import_bytes(
            project=edit.project, data=audio.getvalue(), filename="literal-control.wav",
            media_type="audio/wav", idempotency_key="literal-control-source",
        )
        assert imported.ok, imported.as_dict()
        media = imported.data["object_id"]
        body = _publication(edit.project, parent_revision_id="literal-baseline",
                            shot_revision_id="literal-shot-revision", config={
                                "output": {"fps": 30},
                                "tracks": [{"id": "music", "kind": "audio"}],
                                "extension": {"opaque": [None, False]},
                            })
        body["timeline_id"] = "literal-film"
        internal, = body["internal_timeline_revisions"]
        internal.update(timeline_id="literal-film", revision_id="literal-internal")
        internal["payload"].update(
            output={"fps": 30}, tracks=[{"id": "video-1", "kind": "visual"}],
            clips=[{"id": "title", "track": "video-1", "clipType": "text", "at": 0,
                    "hold": 1, "params": {"text": "Literal control"}, "extension": [None, False]}],
        )
        shot, = body["shot_revisions"]
        shot.update(shot_id="literal-shot", internal_timeline_revision_id="literal-internal")
        shot["payload"]["metadata"]["opaque"] = [None, {"kept": False}]
        parent = body["parent_composition"]
        parent["occurrences"][0]["shot_id"] = "literal-shot"
        parent["registry"]["assets"] = {"literal-source": {
            "media_id": media, "type": "audio", "duration": duration,
        }}
        parent["clips"].append({
            "id": "literal-media", "track": "music", "clipType": "media",
            "asset": "literal-source", "at": 0, "from": 0, "to": duration,
            "hold": duration, "extension": {"opaque": [None, False, {"kept": True}]},
        })
        parent["config"]["clips"] = copy.deepcopy(parent["clips"])
        publication = client._remote._transport.publish_parent_composition(
            edit.project, "literal-film", body, idempotency_key="literal-baseline",
        )
        assert edit.document() == original and edit.history() == history
        location = edit.service.object_location(edit.project, media)
        assert location["verified"]
        assert edit.service.cas.read(media.removeprefix("sha256:")) == audio.getvalue()
        return SimpleNamespace(
            fixture=replace(film.fixture, timeline_id="literal-film",
                            parent_revision_id="literal-baseline",
                            media_ids=(media,)),
            publication=publication, original_events=film.original_events,
            clip_id="literal-media",
        )
    finally:
        world.stop()


@pytest.fixture
def renderer_off(journey_film, astrid_importable, monkeypatch):
    class NoSceneImports:
        def find_spec(self, fullname, path=None, target=None):
            if (fullname.startswith(("composition", "remotion", "node",
                                     "astrid.sdk.authoring_render_preview",
                                     "astrid.core.timeline.compatibility"))
                    or ".scene" in fullname):
                raise AssertionError("journey imported scene evaluation: " + fullname)

    # As in the public M1 journey, permit the pure readable timing helper
    # under packs.rendering; scene evaluation remains unavailable throughout.
    monkeypatch.setattr(sys, "meta_path", [NoSceneImports(), *sys.meta_path])

    def unavailable(*args, **kwargs):
        raise AssertionError("journey evaluated a scene with renderer unavailable")

    monkeypatch.setattr("runtime_protocol.service.evaluate_closure", unavailable)
    monkeypatch.setattr("runtime_protocol.visual_seam.evaluate_closure", unavailable)


def _client(daemon, *, actor="owner", credential=None):
    from astrid.sdk.client import AstridClient

    return AstridClient.open(
        endpoint=daemon.endpoint, credential=credential or daemon.credential_path,
        realm_id=daemon.service.realm["id"], actor_id=actor,
        client_name="public-s2-mixed-journey", client_version="1",
        protocol_version="workspace.v1",
    )


def _cli(client, fixture, capsys, *args):
    from astrid.packs.timeline.cli import build_parser

    parsed = build_parser(client).parse_args([
        *args, "--project", fixture.project_id, "--json",
    ])
    code = parsed.handler(parsed)
    output = capsys.readouterr()
    return code, json.loads(output.out)


def _ok_cli(client, fixture, capsys, *args):
    code, result = _cli(client, fixture, capsys, *args)
    assert code == 0 and result["ok"], (code, result)
    return result


def _readback(edit, accepted):
    # TimelineSession decorates the public result; the durable receipt keeps
    # the exact Runtime result. Check both before reusing the raw-store helper.
    data, receipt = accepted["data"], accepted["receipt"]
    if "accepted_publication_id" in data:
        assert data["accepted_publication_id"] == receipt["receipt_id"]
        assert data["show_command"] == (
            f"astrid timelines show {edit.timeline} --project {edit.project} --published "
            f"--revision-id {data['accepted_revision_id']}"
        )
    assert receipt["result"] == {key: value for key, value in data.items()
                                 if key not in {"accepted_publication_id", "show_command"}}
    edit.assert_readback({"data": receipt["result"], "receipt": receipt})


def _views(client, fixture, capsys, document, clip_id):
    revision = document["parent_revision"]["revision_id"]
    parent = document["parent_revision"]["payload"]
    expected_clip = next(row for row in parent["clips"] if row["id"] == clip_id)
    expected_track = next(row for row in parent["config"]["tracks"] if row["id"] == "music")
    shown = _ok_cli(client, fixture, capsys, "show", fixture.timeline_id,
                    "--published", "--revision-id", revision)
    assert shown["data"]["revision_id"] == revision
    assert shown["data"]["working_copy"] is None
    assert shown["data"]["complete"]
    layers = _ok_cli(client, fixture, capsys, "show", fixture.timeline_id,
                     "--published", "--revision-id", revision,
                     "--layers", "--clip", clip_id)
    inspection = layers["data"]["native_inspection"]
    assert inspection["revision_id"] == revision
    assert [row["clip_id"] for row in inspection["selected_parent_clips"]] == [clip_id]
    projected, = inspection["selected_parent_clips"]
    assert_json_equal(projected["authored_fields"], expected_clip)
    assert_json_equal(projected["track"], expected_track)
    assert projected["source_from"] == expected_clip.get("from")
    assert projected["source_to"] == expected_clip.get("to")
    asset = parent["registry"]["assets"][expected_clip["asset"]]
    # The old assertion assumed every registered asset exposed media_id.
    expected_source = asset["media_id"] if "media_id" in asset else asset["object_id"]
    assert expected_source is not None
    expected_pin, = [
        pin["media_id"] for pin in document["dependency_manifest"]["media"]
        if pin["media_id"] == expected_source
    ]
    assert projected["source_object_id"] == expected_pin
    inputs = _ok_cli(client, fixture, capsys, "visualize", fixture.timeline_id,
                     "--published", "--revision-id", revision,
                     "--mode", "inputs", "--format", "md")
    inspection = inputs["data"]["outputs"]["inspection"]
    assert inspection["revision_id"] == revision
    assert inspection["evidence_kind"] == "declared_inputs"
    projected = next(row for row in inspection["selected_parent_clips"] if row["clip_id"] == clip_id)
    assert_json_equal(projected["authored_fields"], expected_clip)
    assert_json_equal(projected["track"], expected_track)


@pytest.mark.parametrize("journey_film", [
    pytest.param("historical-audio", marks=pytest.mark.xfail(
        strict=True, raises=HistoricalAudioCaptureGap,
        reason="[declared-xfail:timeline-public-s2-historical-audio] M2 historical audio capture: /tmp/claude-0/-home-user-repo/"
               "7dc61be1-7066-52e0-a5d0-94f90e61430a/scratchpad/orch/design/"
               "runtime-public-s2-literal-journey.md#original-audio-requirement",
    )),
    "literal-media",
], indirect=True)
def test_public_cli_stale_trim_rebases_label_lost_ack_restart_retry_and_undo(
    journey_film, renderer_off, tmp_path, monkeypatch, capsys,
):
    from astrid.sdk.timeline._scalar_commands import capture_track_set
    from astrid.sdk.timeline.commit import bundle_from_document
    from astrid.sdk.timeline.sync import TimelineSession
    from runtime_protocol.server import RuntimeHandler

    monkeypatch.setenv("ASTRID_RUNTIME_DATA_ROOT", str(tmp_path / "client-data"))
    film = journey_film
    fixture = film.fixture
    clip_id = getattr(film, "clip_id", "music-bed")
    key = "public-s2-cli-trim"
    args = ("edit", fixture.timeline_id, "--clip", "parent/clip:" + clip_id,
            "--trim-out", "4", "--idempotency-key", key)
    paused, release = Event(), Event()
    observed = []
    lose = {key}
    original_route, original_send = RuntimeHandler._route, RuntimeHandler._send

    def route(handler):
        if (handler._is_timeline_commit() and handler.headers.get("Idempotency-Key") == key
                and not paused.is_set()):
            # _dispatch has prefetched the real POST bytes, outside the SQLite
            # mutex. Nothing has reached acceptance, so another author can win.
            paused.set()
            if not release.wait(30):
                raise TimeoutError("mixed journey did not release CLI trim")
        return original_route(handler)

    def send(handler, status, payload=None, **kwargs):
        if (handler._is_timeline_commit()
                and not getattr(handler, "_defer_response", False)):
            request_key = handler.headers["Idempotency-Key"]
            error = kwargs.get("error")
            observed.append({"path": handler.path, "key": request_key,
                             "body": handler._prefetched_body,
                             "status": status,
                             "response": copy.deepcopy(payload if error is None else error)})
            if status == 200 and request_key in lose:
                lose.remove(request_key)
                # Existing M1 seam: acceptance is durable; no response bytes
                # reach the real SDK transport or acknowledge its disk outbox.
                raise ConnectionError("mixed journey lost durable trim ACK")
        return original_send(handler, status, payload, **kwargs)

    monkeypatch.setattr(RuntimeHandler, "_route", route)
    monkeypatch.setattr(RuntimeHandler, "_send", send)
    world = _start_door(film, tmp_path)
    try:
        client = _client(world.daemon)
        edit = Editing(world.daemon.service, film, None)
        baseline = copy.deepcopy(edit.history())
        if clip_id == "music-bed":
            edit.assert_baseline()
        else:
            assert len(baseline) == 1 and baseline[0]["intent"] == "legacy_unknown"
            assert baseline[0]["records"] is None
        h0, original = edit.head(), edit.document()
        assert original["shot_revisions"] and original["internal_timeline_revisions"]
        assert original["dependency_manifest"]["media"]
        cli_session = TimelineSession.open(fixture.project_id, fixture.timeline_id, client=client)
        _, credential = world.daemon.credentials.provision("python-label-editor", [
            "handshake", "projects:read", "projects:write", "objects:read", "objects:write",
            "tasks:read", "tasks:write",
        ])
        peer = TimelineSession.open(
            fixture.project_id, fixture.timeline_id,
            client=_client(world.daemon, actor="python-label-editor", credential=credential),
            outbox_path=tmp_path / "peer.json",
        )
        label = capture_track_set(bundle_from_document(original), "parent/track:music",
                                  values={"label": "Independent Python label"})
        before = rows(edit.service)
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(_cli, client, fixture, capsys, *args)
            try:
                deadline = monotonic() + 15
                while not paused.wait(0.01) and not pending.done() and monotonic() < deadline:
                    pass
                if not paused.is_set():
                    result = pending.result(timeout=5)
                    assert rows(edit.service) == before
                    assert cli_session.outbox.read()["flight"] is None
                    if clip_id == "music-bed" and result == (1, {
                        "data": None, "error": {"code": "timeline_edit_error", "details": {},
                                                "message": "clip.trim applies to media clips"},
                        "idempotency_key": "", "ok": False, "receipt": None,
                    }):
                        raise HistoricalAudioCaptureGap(
                            "public_s2_cli_trim_must_capture_original_music_film_before_POST: "
                            f"{result!r}"
                        )
                    pytest.fail(
                        "public_s2_cli_trim_must_capture_original_music_film_before_POST: "
                        f"CLI exited without submitting native trim: {result!r}"
                    )
                assert edit.head() == h0
                flight = copy.deepcopy(cli_session.outbox.read()["flight"])
                body = json.loads(flight["body"])
                assert flight["key"] == key and flight["path"] == edit.path
                assert body["source"] == {"via": "cli"}
                assert (body["base_revision_id"], body["base_publication_id"]) == (
                    h0["revision_id"], h0["publication_id"],
                )
                command, = body["commands"]
                assert command["op"] == "clip.trim" and command["select"] == "parent/clip:" + clip_id
                assert command["reads"] and command["bindings"] and command["expect"]
                labelled = peer.commit(label, idempotency_key="public-s2-python-label")
                assert labelled["data"]["status"] == "accepted"
                assert labelled["data"]["publisher"] == "python-label-editor"
                accepted_wires = [row for row in observed
                                  if row["key"] == "public-s2-python-label"]
                assert len(accepted_wires) == 1
                assert accepted_wires[0]["path"] == edit.path
                assert accepted_wires[0]["status"] == 200
                assert accepted_wires[0]["response"]["data"] == {
                    key: value for key, value in labelled["data"].items()
                    if key not in {"accepted_publication_id", "show_command"}
                }
                assert accepted_wires[0]["response"]["receipt"] == labelled["receipt"]
                after_label = rows(edit.service)
                refusal_body = edit.body([label], base=h0)
                refusal_raw = json.dumps(refusal_body).encode()
                refusal_response = world.call(
                    "/api/runtime" + edit.path, "POST", body=refusal_raw,
                    headers={"Content-Type": "application/json",
                             "Idempotency-Key": "public-s2-observer-refusal"},
                )
                assert refusal_response.status == 409
                refusal_wires = [row for row in observed
                                 if row["key"] == "public-s2-observer-refusal"]
                assert len(refusal_wires) == 1
                assert (refusal_wires[0]["path"], refusal_wires[0]["body"],
                        refusal_wires[0]["key"], refusal_wires[0]["status"]) == (
                    edit.path, refusal_raw, "public-s2-observer-refusal", 409,
                )
                assert refusal_wires[0]["response"]["code"] == "conflict"
                assert refusal_wires[0]["response"]["details"]["reason"] == "dependency_changed"
                assert rows(edit.service) == after_label
                release.set()
                code, ambiguous = pending.result(timeout=30)
                assert code == 1 and not ambiguous["ok"], (code, ambiguous)
            finally:
                release.set()

        trim_wire = next(row for row in observed if row["key"] == key)
        # On the current Agent checkout this is the real refusal that the
        # previous deferred-only observer hid. Keep the proof bounded to the
        # actual final HTTP send; the original acceptance assertion below
        # remains unchanged and reports the Agent-owned guard conflict.
        if trim_wire["status"] == 409:
            assert trim_wire["path"] == flight["path"]
            assert trim_wire["body"] == flight["body"].encode()
            assert trim_wire["response"]["code"] == "conflict"
            assert trim_wire["response"]["details"]["reason"] == "dependency_changed"
        assert trim_wire["status"] == 200
        assert (trim_wire["path"], trim_wire["body"], trim_wire["key"]) == (
            flight["path"], flight["body"].encode(), flight["key"],
        )
        accepted = trim_wire["response"]
        assert accepted["data"]["status"] == "rebased"
        assert accepted["data"]["publisher"] == "owner"
        assert accepted["data"]["commands"] == [command]
        assert accepted["data"]["rebased_onto"] == {
            "revision_id": labelled["data"]["accepted_revision_id"],
            "publication_id": labelled["receipt"]["receipt_id"],
        }
        expected_trim = copy.deepcopy(labelled["data"]["canonical_document"]["parent_revision"]["payload"])
        target = next(row for row in expected_trim["clips"] if row["id"] == clip_id)
        target.update({"from": 0, "to": 4, "hold": 4})
        expected_trim["config"]["clips"] = copy.deepcopy(expected_trim["clips"])
        assert_json_equal(accepted["data"]["canonical_document"]["parent_revision"]["payload"], expected_trim)
        assert cli_session.outbox.read()["flight"] == flight
        saved_history = copy.deepcopy(edit.history())
        assert len(saved_history) == len(baseline) + 2
        assert saved_history[:len(baseline)] == baseline
        instance = world.daemon.instance_id
        _readback(edit, accepted)
        _readback(edit, labelled)
    finally:
        release.set()
        world.stop()

    world = _start_door(film, tmp_path)
    try:
        assert world.daemon.instance_id != instance
        client = _client(world.daemon)
        edit = Editing(world.daemon.service, film, None)
        session = TimelineSession.open(fixture.project_id, fixture.timeline_id, client=client)
        assert session.outbox.read()["flight"] == flight
        before = rows(edit.service)

        def forbidden(*args, **kwargs):
            raise AssertionError("exact outbox retry executed the semantic provider")

        with monkeypatch.context() as retry:
            retry.setattr(type(edit.service._timeline_commit_provider), "commit", forbidden)
            retried = _ok_cli(client, fixture, capsys, *args)
        assert retried["receipt"] == accepted["receipt"]
        assert observed[-1] == trim_wire
        assert rows(edit.service) == before
        assert edit.history() == saved_history
        state = session.outbox.read()
        assert state["flight"] is None and state["pending"] == []
        assert state["base"] == {
            "revision_id": accepted["data"]["accepted_revision_id"],
            "publication_id": accepted["receipt"]["receipt_id"],
        }
        _views(client, fixture, capsys, accepted["data"]["canonical_document"], clip_id)
        undone = _ok_cli(client, fixture, capsys, "undo", fixture.timeline_id,
                         "--publication", accepted["receipt"]["receipt_id"])
        restored = undone["data"]["canonical_document"]
        labelled_document = labelled["data"]["canonical_document"]
        assert_json_equal(restored, labelled_document)
        expected_parent = copy.deepcopy(original["parent_revision"]["payload"])
        next(row for row in expected_parent["config"]["tracks"] if row["id"] == "music")["label"] = (
            "Independent Python label"
        )
        assert_json_equal(restored["parent_revision"]["payload"], expected_parent)
        for family in ("shot_revisions", "internal_timeline_revisions", "dependency_manifest"):
            assert restored[family] == original[family]
            assert accepted["data"]["canonical_document"][family] == original[family]
        for media in restored["dependency_manifest"]["media"]:
            assert edit.service.object_location(fixture.project_id, media["media_id"])["verified"]
        _readback(edit, accepted)
        _readback(edit, undone)
        if clip_id == "music-bed":
            edit.assert_baseline()
        assert edit.history()[:len(baseline)] == baseline
        _views(client, fixture, capsys, restored, clip_id)
        # The old accepted film remains inspectable after undo advances HEAD.
        _views(client, fixture, capsys, accepted["data"]["canonical_document"], clip_id)
        final = edit.history()
        assert len(final) == len(saved_history) + 1
        assert final[:-1] == saved_history
        assert final[-1]["records"]["undo_of"] == [accepted["receipt"]["receipt_id"]]
    finally:
        world.stop()
