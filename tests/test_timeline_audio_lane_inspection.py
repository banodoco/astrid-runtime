"""Runtime's read-only port; integration uses the exact admitted Astrid source.

Set RUNTIME_AUDIO_LANE_ASTRID_SOURCE to the verified producer checkout for the
optional cross-repo cohort, including the daemon's fixed installed SDK binding.
No production data is used.
The JSON fixture is I AUDIO-LANE-011's actual adopted fixture/document and lane.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import threading
import urllib.error
import urllib.request

import pytest

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import CapabilityUnavailableError, ConflictError, ValidationError
from runtime_protocol.timeline_inspection import normalize_options
from runtime_protocol.util import canonical_json
from test_timeline_native_inspection import _publication, _service

OPTIONS = {"presentation": {"audio_lane": True}, "supported_capabilities": ["adopted-music-bed"]}
FIXTURE = Path(__file__).parent / "fixtures/audio_lane_adopted.json"


@pytest.fixture
def astrid(monkeypatch):
    source = os.environ.get("RUNTIME_AUDIO_LANE_ASTRID_SOURCE")
    if not source:
        pytest.skip("cross-repo proof requires the explicitly admitted Astrid producer checkout")
    monkeypatch.syspath_prepend(source)
    from astrid.core.timeline.authoring_bundle import open_authoring_bundle
    from astrid.sdk.timeline.music_lane import project
    from astrid.sdk.timeline.checkout import Checkout

    def provider(closure, *, capabilities):
        bundle = open_authoring_bundle(
            closure["parent_revision"], shot_revisions=closure["shot_revisions"],
            internal_timeline_revisions=closure["internal_timeline_revisions"],
        )
        return project(Checkout(bundle), capabilities=capabilities)

    return provider, project, Checkout


def publication(project, *, adopted=True, revision="lane-1", expected_head=None):
    bundle = json.loads(FIXTURE.read_text())["bundle"]
    parent = copy.deepcopy(bundle["parent"])
    if not adopted:
        parent["config"]["app"]["astrid"].pop("bed")
    occurrences, shots, internals = [], [], []
    for i, placement in enumerate(bundle["placements"]):
        sid = placement["shot_id"]
        internal_id, shot_id = f"internal-{sid}", f"shot-{sid}"
        occurrence = {**placement, "shot_revision_id": shot_id, "track": "picture", "name": f"s{i+1}"}
        occurrences.append(occurrence)
        shot_payload = copy.deepcopy(bundle["shots"][sid]["payload"])
        shot_payload["metadata"] = {"name": f"s{i+1}"}
        shots.append({"shot_id": sid, "revision_id": shot_id, "internal_timeline_revision_id": internal_id, "payload": shot_payload})
        internals.append({"timeline_id": "main", "revision_id": internal_id,
                          "payload": copy.deepcopy(bundle["shots"][sid]["internal_timeline"])})
    parent["occurrences"] = occurrences
    return {"project_id": project, "timeline_id": "main", "parent_revision_id": revision,
            "expected_head": expected_head, "parent_composition": parent,
            "shot_revisions": shots, "internal_timeline_revisions": internals}


def expected_lane(astrid, project):
    _, project_lane, Checkout = astrid
    bundle = json.loads(FIXTURE.read_text())["bundle"]
    bundle.update(project_id=project, timeline_id="main")
    return project_lane(Checkout(bundle), capabilities=OPTIONS["supported_capabilities"])


def database_state(service):
    # Every SQL table, including revisions, journal, OpCalls, tasks, materialized
    # documents and idempotency records. Inspect must not write any of them.
    return list(service.store.conn.iterdump())


@pytest.mark.parametrize("options", [
    {"presentation": None}, {"presentation": {}}, {"presentation": {"audio_lane": False}},
    {"presentation": {"audio_lane": 1}}, {"presentation": {"audio_lane": True, "other": True}},
    {"supported_capabilities": "adopted-music-bed"}, {"supported_capabilities": [None]},
    {"supported_capabilities": [""]}, {"supported_capabilities": ["a\n"]},
])
def test_request_shape_rejected(options):
    with pytest.raises(ValidationError):
        normalize_options(options)


def test_off_missing_provider_and_explicit_caller_capabilities(tmp_path):
    service, project, _ = _service(tmp_path)
    try:
        service.publish_parent_composition(project, "main", _publication(project), idempotency_key="publish")
        plain = service.inspect_timeline(project, "main")
        assert "presentation" not in plain
        assert "presentation" not in plain["selectors"]
        for capabilities in (None, [], ["projects:read"], ["unknown"]):
            options = {"presentation": {"audio_lane": True}}
            if capabilities is not None:
                options["supported_capabilities"] = capabilities
            with pytest.raises(CapabilityUnavailableError, match="caller support"):
                service.inspect_timeline(project, "main", options)
        with pytest.raises(CapabilityUnavailableError, match="not installed"):
            service.inspect_timeline(project, "main", OPTIONS)
        with pytest.raises(ConflictError, match="fixed"):
            service.register_timeline_audio_lane_provider(lambda *_args, **_kwargs: None)
    finally:
        service.close()


def test_provider_registration_is_single_trusted_callable(tmp_path):
    service, _, _ = _service(tmp_path)
    try:
        with pytest.raises(ValidationError, match="callable"):
            service.register_timeline_audio_lane_provider(None)
        service.register_timeline_audio_lane_provider(lambda *_args, **_kwargs: None)
        with pytest.raises(ConflictError):
            service.register_timeline_audio_lane_provider(lambda *_args, **_kwargs: None)
    finally:
        service.close()


@pytest.mark.parametrize("adopted", [False, True])
def test_real_producer_complete_pinned_closure_and_no_state_changes(tmp_path, astrid, adopted):
    service, project, _ = _service(tmp_path)
    real, _, _ = astrid
    seen = []
    def provider(closure, *, capabilities):
        seen.append(copy.deepcopy((closure, capabilities)))
        lane = real(closure, capabilities=capabilities)
        closure["parent_revision"]["payload"].clear()
        closure["internal_timeline_revisions"][0]["payload"].clear()
        capabilities.clear()
        return lane
    try:
        service.register_timeline_audio_lane_provider(provider)
        service.publish_parent_composition(project, "main", publication(project, adopted=adopted), idempotency_key="publish")
        before = database_state(service)
        caps = ["other", "adopted-music-bed", "adopted-music-bed"]
        options = {**OPTIONS, "limit": 1, "supported_capabilities": caps}
        result = service.inspect_timeline(project, "main", options)
        assert result["presentation"]["audio_lane"] == (expected_lane(astrid, project) if adopted else None)
        assert caps == ["other", "adopted-music-bed", "adopted-music-bed"]
        closure, forwarded = seen[0]
        assert forwarded == caps
        assert closure["snapshot_digest"] == result["snapshot_digest"]
        assert closure["revision_id"] == result["revision_id"] == "lane-1"
        assert closure["project_id"] == project and closure["timeline_id"] == "main"
        parent = service.get_project_parent_composition_revision(project, "main", "lane-1")
        assert closure["parent_revision"]["payload"] == parent["payload"]
        assert len(closure["parent_revision"]["payload"]["occurrences"]) == 2
        for row in closure["shot_revisions"]:
            assert row["payload"] == service.get_project_shot_revision(project, row["shot_id"], row["revision_id"])["payload"]
        for row in closure["internal_timeline_revisions"]:
            assert row["payload"] == service.get_project_timeline_revision(project, row["timeline_id"], row["revision_id"])["payload"]
        assert database_state(service) == before
        assert result["page"]["returned_clips"] == 1
        assert result["next_cursor"]
        second = service.inspect_timeline(project, "main", {**options, "cursor": result["next_cursor"]})
        selected = service.inspect_timeline(project, "main", {**OPTIONS, "occurrence": "absent"})
        assert selected["selected"] == []
        assert selected["presentation"] == result["presentation"] == second["presentation"]
        assert database_state(service) == before
    finally:
        service.close()


def test_history_head_advancement_and_cursor_binding(tmp_path, astrid):
    service, project, _ = _service(tmp_path)
    try:
        service.register_timeline_audio_lane_provider(astrid[0])
        service.publish_parent_composition(project, "main", publication(project), idempotency_key="one")
        first = service.inspect_timeline(project, "main", {**OPTIONS, "limit": 1})
        service.publish_parent_composition(project, "main", publication(project, adopted=False, revision="lane-2", expected_head="lane-1"), idempotency_key="two")
        before = database_state(service)
        history = service.inspect_timeline(project, "main", {**OPTIONS, "revision_id": "lane-1"})
        current = service.inspect_timeline(project, "main", OPTIONS)
        assert history["presentation"] == first["presentation"]
        assert history["snapshot_digest"] == first["snapshot_digest"]
        assert history["head_revision_id"] == current["revision_id"] == "lane-2"
        assert history["is_current_head"] is False
        assert current["presentation"]["audio_lane"] is None
        with pytest.raises(ValidationError, match="cursor"):
            service.inspect_timeline(project, "main", {**OPTIONS, "limit": 1, "cursor": first["next_cursor"]})
        assert database_state(service) == before
    finally:
        service.close()


@pytest.mark.parametrize("damage", ["missing-output", "ambiguous-anchor", "source-provenance", "digest", "internal-pin"])
def test_real_producer_or_closure_refuses_malformed_input(tmp_path, astrid, damage):
    service, project, _ = _service(tmp_path)
    try:
        service.register_timeline_audio_lane_provider(astrid[0])
        body = publication(project)
        bed = body["parent_composition"]["config"]["app"]["astrid"]["bed"]
        if damage == "missing-output":
            bed["outputs"][next(iter(bed["outputs"]))] = ["missing"]
        elif damage == "ambiguous-anchor":
            bed["switches"][0]["on"] = '"missing-word" in s1 #1'
        elif damage == "source-provenance":
            bed["arrangements"][0]["owner"] = "occurrence:missing/clip:a-music"
        service.publish_parent_composition(project, "main", body, idempotency_key="publish")
        if damage == "digest":
            service.store.conn.execute("UPDATE parent_composition_revisions SET content_digest=? WHERE id=?", ("sha256:" + "0"*64, "lane-1"))
        elif damage == "internal-pin":
            row = service.store.conn.execute("SELECT payload_json FROM shot_revisions WHERE id='shot-A'").fetchone()
            payload = json.loads(row[0]); payload["internal_timeline_revision_id"] = "wrong"
            service.store.conn.execute("UPDATE shot_revisions SET payload_json=? WHERE id='shot-A'", (canonical_json(payload),))
        before = database_state(service)
        with pytest.raises((ValidationError, ConflictError)):
            service.inspect_timeline(project, "main", OPTIONS)
        assert database_state(service) == before
    finally:
        service.close()


@pytest.mark.parametrize("result", [None, {}, {"schema": "wrong"}, {"schema": "astrid.audio-lane.v1"},
                                    {**json.loads(FIXTURE.read_text())["expected_lane"], "fps": float("nan")}])
def test_invalid_provider_output_is_explicit(tmp_path, result):
    service, project, _ = _service(tmp_path)
    try:
        service.register_timeline_audio_lane_provider(lambda *_args, **_kwargs: result)
        service.publish_parent_composition(project, "main", publication(project), idempotency_key="publish")
        with pytest.raises(ValidationError):
            service.inspect_timeline(project, "main", OPTIONS)
    finally:
        service.close()


def test_complete_lane_size_refusal_never_truncates(tmp_path, astrid, monkeypatch):
    import runtime_protocol.timeline_inspection as inspection
    service, project, _ = _service(tmp_path)
    try:
        service.register_timeline_audio_lane_provider(astrid[0])
        service.publish_parent_composition(project, "main", publication(project), idempotency_key="publish")
        result = service.inspect_timeline(project, "main", {**OPTIONS, "limit": 1})
        assert result["presentation"]["audio_lane"] == expected_lane(astrid, project)
        assert len(canonical_json(result).encode()) == result["page"]["response_bytes"]
        monkeypatch.setattr(inspection, "MAX_RESPONSE_BYTES", result["page"]["response_bytes"] - 100)
        with pytest.raises(ValidationError, match="complete audio lane"):
            service.inspect_timeline(project, "main", {**OPTIONS, "limit": 1})
    finally:
        service.close()


def test_http_post_auth_and_real_producer(tmp_path, astrid):
    service, project, root = _service(tmp_path)
    service.publish_parent_composition(project, "main", publication(project), idempotency_key="publish")
    service.close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support")
    # Normal startup binds the installed SDK adapter before serving HTTP.
    daemon.start()
    try:
        read, _ = daemon.credentials.provision("reader", ["projects:read"])
        denied, _ = daemon.credentials.provision("denied", ["tasks:read"])
        url = f"{daemon.endpoint}/v1/projects/{project}/timelines/main/inspect"
        def request(token, options=OPTIONS):
            headers = {"Content-Type": "application/json"}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            req = urllib.request.Request(url, data=json.dumps(options).encode(), headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req) as response:
                    return response.status, json.load(response)
            except urllib.error.HTTPError as exc:
                return exc.code, json.load(exc)
        assert request(None)[0] == 401
        assert request(denied)[0] == 401
        code, result = request(read)
        assert code == 200
        assert result["presentation"]["audio_lane"] == expected_lane(astrid, project)
        assert request(read, {"presentation": {"audio_lane": True}})[0] == 409
        assert request(read, {"presentation": {"audio_lane": False}})[0] == 422
        assert "presentation" not in request(read, {})[1]
        # Scoped timeline GET now exposes head metadata (C 0533069); it is
        # not the inspection surface. Presentation requires canonical POST.
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {read}"})
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(req)
        assert error.value.code == 404
    finally:
        daemon.stop()


def fixture_snapshot(tl):
    """I011 test_timeline_music_lane._render_snapshot's lossless fixture shape.

    Test adapter only: all bytes come from the received pinned authoring bundle.
    Production composition should use I's authoring-bundle adapter directly.
    """
    config = copy.deepcopy(tl.bundle["parent"]["config"])
    config["tracks"] = copy.deepcopy(tl._internal("A")["tracks"])
    config.setdefault("theme_overrides", {}).setdefault("visual", {}).setdefault("canvas", {})["fps"] = tl.fps
    clips, occurrences, assets = copy.deepcopy(config.get("clips") or []), [], {}
    for placement in tl.bundle["placements"]:
        oid, sid = placement["occurrence_id"], placement["shot_id"]
        at_ms = placement.get("at_ms", placement.get("placement", {}).get("start_ms"))
        occurrences.append({**copy.deepcopy(placement), "at_ms": at_ms})
        for key, value in tl._registry(sid).items():
            assets[f"{oid}:{key}"] = copy.deepcopy(value)
        for raw in tl._internal(sid)["clips"]:
            clip = copy.deepcopy(raw)
            original_id = clip["id"]
            clip["id"] = f"{oid}:{original_id}"
            clip["at"] = round(float(clip.get("at") or 0) + at_ms / 1000, 6)
            if isinstance(clip.get("asset"), str):
                clip["asset"] = f"{oid}:{clip['asset']}"
            clip.setdefault("app", {})["astrid_shot_composition"] = {
                "occurrence_id": oid, "source_clip_id": original_id,
            }
            clip.update(shot_id=sid, shot_occurrence_id=oid)
            clips.append(clip)
    config["clips"] = clips
    config.setdefault("app", {}).setdefault("astrid_shot_composition", {})["occurrences"] = occurrences
    return {"config": config, "registry": {"assets": assets}, "fps": tl.fps,
            "project_id": tl.bundle["project_id"], "timeline_id": tl.bundle["timeline_id"]}


def test_actual_project_snapshot_producer_through_runtime_port(tmp_path, astrid):
    # I's existing fixture snapshot builder preserves all authored child bytes
    # rather than applying render clipping/defaults. The lane itself is returned
    # by the actual project_snapshot producer; this is no fake lane callback.
    from astrid.core.timeline.authoring_bundle import open_authoring_bundle
    from astrid.sdk.timeline.music_lane import project_snapshot
    _, _, Checkout = astrid
    service, project, _ = _service(tmp_path)
    snapshots = []
    def provider(closure, *, capabilities):
        bundle = open_authoring_bundle(
            closure["parent_revision"], shot_revisions=closure["shot_revisions"],
            internal_timeline_revisions=closure["internal_timeline_revisions"],
        )
        snapshot = fixture_snapshot(Checkout(bundle))
        snapshot.update(revision_id=closure["revision_id"], snapshot_digest=closure["snapshot_digest"])
        snapshots.append(copy.deepcopy(snapshot))
        return project_snapshot(snapshot, capabilities=capabilities)
    try:
        service.register_timeline_audio_lane_provider(provider)
        service.publish_parent_composition(project, "main", publication(project), idempotency_key="publish")
        before = database_state(service)
        result = service.inspect_timeline(project, "main", {**OPTIONS, "limit": 1})
        assert result["presentation"]["audio_lane"] == expected_lane(astrid, project)
        snapshot = snapshots[0]
        assert snapshot["revision_id"] == result["revision_id"]
        assert snapshot["snapshot_digest"] == result["snapshot_digest"]
        assert snapshot["fps"] == 30
        assert len(snapshot["config"]["app"]["astrid_shot_composition"]["occurrences"]) == 2
        assert "occ-A:Q" in snapshot["registry"]["assets"]
        words = next(c for c in snapshot["config"]["clips"] if c["id"] == "occ-A:a-vo")
        assert words["app"]["astrid"]["words"]
        assert words["app"]["astrid_shot_composition"]["source_clip_id"] == "a-vo"
        assert database_state(service) == before
    finally:
        service.close()


def test_render_flattening_mismatch_remains_explicit(tmp_path, astrid):
    # An important preserved producer limitation: render projection adds volume
    # defaults and clips source windows. It is not lossless authoring input.
    from astrid.core.timeline.shot_composition_projection import project_runtime_parent_composition
    from astrid.sdk.timeline.music_lane import project_snapshot
    service, project, _ = _service(tmp_path)
    def provider(closure, *, capabilities):
        flat = project_runtime_parent_composition(
            closure["parent_revision"], shot_revisions=closure["shot_revisions"],
            internal_timeline_revisions=closure["internal_timeline_revisions"],
        )
        return project_snapshot({"config": flat.config, "registry": flat.registry,
                                 "project_id": project, "timeline_id": "main"}, capabilities=capabilities)
    try:
        service.register_timeline_audio_lane_provider(provider)
        service.publish_parent_composition(project, "main", publication(project), idempotency_key="publish")
        before = database_state(service)
        with pytest.raises(ValidationError) as error:
            service.inspect_timeline(project, "main", OPTIONS)
        assert error.value.details["producer_error"] == "MusicBedError"
        assert "inconsistent supplied music output" in error.value.details["reason"]
        assert database_state(service) == before
    finally:
        service.close()


def test_head_cannot_advance_during_projection(tmp_path, astrid):
    service, project, _ = _service(tmp_path)
    entered, attempted, advanced = threading.Event(), threading.Event(), threading.Event()
    results, errors = [], []
    def provider(closure, *, capabilities):
        entered.set()
        assert attempted.wait(5)
        assert not advanced.is_set()
        return astrid[0](closure, capabilities=capabilities)
    def inspect():
        try:
            results.append(service.inspect_timeline(project, "main", OPTIONS))
        except BaseException as exc:
            errors.append(exc)
    def publish():
        try:
            assert entered.wait(5)
            attempted.set()
            service.publish_parent_composition(project, "main", publication(project, adopted=False, revision="lane-2", expected_head="lane-1"), idempotency_key="two")
            advanced.set()
        except BaseException as exc:
            errors.append(exc)
    try:
        service.register_timeline_audio_lane_provider(provider)
        service.publish_parent_composition(project, "main", publication(project), idempotency_key="one")
        reader, writer = threading.Thread(target=inspect), threading.Thread(target=publish)
        reader.start(); writer.start()
        reader.join(10); writer.join(10)
        assert not reader.is_alive() and not writer.is_alive()
        assert not errors
        assert advanced.is_set()
        assert results[0]["revision_id"] == results[0]["head_revision_id"] == "lane-1"
        assert results[0]["presentation"]["audio_lane"] == expected_lane(astrid, project)
    finally:
        service.close()


@pytest.mark.parametrize("exception,expected", [(ValueError("bad provenance"), ValidationError), (RuntimeError("broken provider"), CapabilityUnavailableError)])
def test_producer_exceptions_use_existing_error_envelopes(tmp_path, exception, expected):
    service, project, _ = _service(tmp_path)
    def provider(*_args, **_kwargs):
        raise exception
    try:
        service.register_timeline_audio_lane_provider(provider)
        service.publish_parent_composition(project, "main", publication(project), idempotency_key="publish")
        before = database_state(service)
        with pytest.raises(expected):
            service.inspect_timeline(project, "main", OPTIONS)
        assert database_state(service) == before
    finally:
        service.close()


def test_presentation_is_inspect_only_and_schema_is_additive(tmp_path):
    from jsonschema import Draft202012Validator
    schemas = Path(__file__).resolve().parents[1] / "contract/schemas"
    request = json.loads((schemas / "timeline-inspection.json").read_text())
    response = json.loads((schemas / "timeline-inspection-result.json").read_text())
    Draft202012Validator(request).validate(OPTIONS)
    Draft202012Validator(response["properties"]["presentation"]).validate({"audio_lane": None})
    assert list(Draft202012Validator(request).iter_errors({"presentation": {"audio_lane": False}}))
    service, project, _ = _service(tmp_path)
    try:
        service.publish_parent_composition(project, "main", publication(project), idempotency_key="publish")
        before = database_state(service)
        with pytest.raises(ValidationError, match="only through inspect"):
            service.create_timeline_view(project, "main", OPTIONS)
        assert database_state(service) == before
    finally:
        service.close()


def test_closure_limit_refuses_before_projecting(tmp_path, monkeypatch):
    import runtime_protocol.timeline_inspection as inspection
    service, project, _ = _service(tmp_path)
    calls = []
    try:
        service.register_timeline_audio_lane_provider(lambda *args, **kwargs: calls.append(args))
        service.publish_parent_composition(project, "main", publication(project), idempotency_key="publish")
        monkeypatch.setattr(inspection, "MAX_CLOSURE_CLIPS", 1)
        with pytest.raises(ValidationError, match="closure exceeds"):
            service.inspect_timeline(project, "main", OPTIONS)
        assert calls == []
    finally:
        service.close()
