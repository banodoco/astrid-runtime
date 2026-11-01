"""Exact catalog metadata reads reuse acceptance's selected-media verifier."""
from __future__ import annotations

import copy
import json
import math
import subprocess
from urllib.parse import urlencode

import pytest
from test_generation_publish_v1_settlement import _effect, _fixture, _output, _settle
from test_timeline_commit_routes import PROJECT, make_handler

from runtime_protocol.errors import (
    AuthorizationError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from runtime_protocol.timeline_commit_port import MediaReads


@pytest.fixture(scope="session")
def settled_media_bytes():
    result = {}
    for name, color in (("image", "green"), ("old", "blue"), ("new", "red")):
        codec = (["-frames:v", "1", "-threads", "1", "-c:v", "png", "-f", "image2pipe"]
                 if name == "image" else
                 ["-t", "2", "-an", "-c:v", "libx264", "-pix_fmt", "yuv420p",
                  "-movflags", "+frag_keyframe+empty_moov", "-f", "mp4"])
        result[name] = subprocess.run(
            ["ffmpeg", "-v", "error", "-f", "lavfi", "-i", f"color=c={color}:s=16x16:r=10",
             *codec, "pipe:1"], check=True, stdout=subprocess.PIPE,
        ).stdout
    assert result["image"].startswith(b"\x89PNG\r\n\x1a\n")
    return result


def settle_media(tmp_path, media_bytes, *, provider=None):
    def effect_factory(project_id):
        effect = _effect(project_id, groups=[{"group_key": "main", "selectors": [
            {"selector": name, "ordinal": ordinal, "variant_key": name,
             "output_port": "image" if name == "image" else "video"}
            for ordinal, name in enumerate(media_bytes)
        ]}])
        effect["payload"]["metadata"] = {"params": {"duration_seconds": 2.0, "width": 16, "height": 16}}
        return effect

    service, project, task, attempt, effect = _fixture(tmp_path, effect_factory=effect_factory, slug="verified")
    try:
        if provider is not None:
            service.register_timeline_commit_provider(provider)
        _settle(service, attempt, [
            _output(data, output_port="image" if name == "image" else "video", group_key="main",
                    variant_key=name, ordinal=ordinal, filename=name + (".png" if name == "image" else ".mp4"),
                    media_type="image/png" if name == "image" else "video/mp4")
            for ordinal, (name, data) in enumerate(media_bytes.items())
        ], effect=effect)
        service.create_timeline(project["id"], "main", idempotency_key="canonical-timeline")
        outputs = {output["variant_key"]: output for output in service.managed_outputs(task["task"]["id"])}
        return service, project["id"], outputs
    except BaseException:
        service.close()
        raise


@pytest.fixture
def media(tmp_path, settled_media_bytes):
    service, project, outputs = settle_media(tmp_path, settled_media_bytes)
    try:
        yield service, project, outputs
    finally:
        service.close()


def selector(output):
    return {"association_id": output["association_id"], "object_id": output["object_id"],
            "version": output["lifecycle"]["version"]}


def snapshot(service):
    return tuple(service.store.conn.iterdump()), {
        path.relative_to(service.store.cas_root).as_posix(): path.read_bytes()
        for path in service.store.cas_root.rglob("*") if path.is_file()
    }


def test_verified_image_and_both_swap_inputs_preserve_exact_selection_without_writes(media, settled_media_bytes, monkeypatch):
    service, project, outputs = media
    before = snapshot(service)
    calls = []

    def authorize():
        assert service.store._mutex._is_owned()
        calls.append(True)

    def mutation():
        pytest.fail("a metadata read must not request mutation admission")

    monkeypatch.setattr(service, "_assert_mutation_admitted", mutation)
    for name, output in outputs.items():
        selection = service.get_project_media_selection(project, selector(output), authorize=authorize)
        # The explicit alias is independent of the registered variant identity.
        explicit = {key: selection[key] for key in ("asset", "generation_id", "variant_id")}
        explicit["asset"] = f"popup/{name} & original"
        selection = service.get_project_media_selection(project, explicit, authorize=authorize)
        captured = copy.deepcopy(selection)
        verified = service.get_project_verified_media(project, selection, authorize=authorize)
        assert verified == MediaReads(service).selected(project, captured)
        assert verified == {"selection": captured, "media_type": "image/png" if name == "image" else "video/mp4",
                            "size": len(settled_media_bytes[name]), "duration_seconds": 2.0, "width": 16, "height": 16}
        assert set(selection) == {"asset", "generation_id", "variant_id", "object_id", "catalog_digest"}
        assert type(verified["size"]) is int and verified["size"] > 0
        assert math.isfinite(verified["duration_seconds"]) and verified["duration_seconds"] > 0
        assert selection == captured
    assert len(calls) == 18
    assert snapshot(service) == before


@pytest.mark.parametrize("change,error", [
    ("object", NotFoundError), ("scope", NotFoundError), ("digest", ConflictError),
    ("malformed_object", ValidationError), ("malformed_digest", ValidationError),
    ("missing", ValidationError), ("extra", ValidationError), ("blank", ValidationError),
])
def test_verified_media_refuses_changed_or_malformed_exact_identity_without_writes(media, change, error):
    service, project, outputs = media
    selection = service.get_project_media_selection(project, selector(outputs["old"]), authorize=lambda: None)
    if change == "scope":
        project = service.create_project({"slug": "foreign", "name": "Foreign"})["id"]
    elif change in {"object", "digest"}:
        selection["object_id" if change == "object" else "catalog_digest"] = "sha256:" + "0" * 64
    elif change in {"malformed_object", "malformed_digest"}:
        selection["object_id" if change == "malformed_object" else "catalog_digest"] = "not-a-digest"
    elif change == "missing":
        del selection["asset"]
    elif change == "extra":
        selection["duration_seconds"] = 999
    else:
        selection["asset"] = ""
    before = snapshot(service)
    with pytest.raises(error):
        service.get_project_verified_media(project, selection, authorize=lambda: None)
    assert snapshot(service) == before


@pytest.mark.parametrize("change", ["wrong_metadata", "removed_duration", "changed_duration", "removed_variant", "pin", "promote", "expired"])
def test_catalog_changes_refuse_original_pin_without_refresh_or_writes(media, change):
    service, project, outputs = media
    output = outputs["old"]
    selection = service.get_project_media_selection(project, selector(output), authorize=lambda: None)
    original = copy.deepcopy(selection)
    if change in {"pin", "promote"}:
        service.update_managed_output_lifecycle(output["association_id"], {
            "operation": change, "expected_version": 1,
        }, idempotency_key="catalog-race")
    elif change == "expired":
        # A durable output cannot normally expire; emulate an ineligible catalog race.
        service.store.conn.execute("UPDATE managed_output_lifecycle SET state='expired', version=version+1 WHERE association_id=?",
                                   (output["association_id"],))
    elif change == "removed_variant":
        service.store.conn.execute("DELETE FROM generation_variants WHERE id=?", (selection["variant_id"],))
    else:
        # Deliberate catalog corruption/race, never a positive publication seed.
        row = service.store.conn.execute("SELECT metadata_json FROM generations WHERE id=?", (selection["generation_id"],)).fetchone()
        metadata = json.loads(row[0])
        if change == "wrong_metadata":
            metadata["params"]["media_type"] = "image/png"
        elif change == "removed_duration":
            del metadata["params"]["duration_seconds"]
        else:
            metadata["params"]["duration_seconds"] = 3
        service.store.conn.execute("UPDATE generations SET metadata_json=? WHERE id=?", (json.dumps(metadata), selection["generation_id"]))
    before = snapshot(service)
    with pytest.raises((ConflictError, NotFoundError, ValidationError)):
        service.get_project_verified_media(project, selection, authorize=lambda: None)
    if change in {"pin", "promote", "expired"}:
        with pytest.raises(ConflictError):
            service.get_project_media_selection(project, selector(output), authorize=lambda: None)
    assert selection == original
    assert snapshot(service) == before


def test_verified_read_rechecks_authority_under_mutex(media):
    service, project, outputs = media
    selection = service.get_project_media_selection(project, selector(outputs["image"]), authorize=lambda: None)
    before = snapshot(service)
    calls = []

    def revoked():
        assert service.store._mutex._is_owned()
        calls.append(True)
        if len(calls) == 2:
            raise AuthorizationError("credential revoked")

    for authorize in (None, revoked):
        with pytest.raises(AuthorizationError):
            service.get_project_verified_media(project, selection, authorize=authorize)
    assert len(calls) == 2
    assert snapshot(service) == before


def test_verified_route_passes_exact_selection_and_rechecks_actor():
    from types import SimpleNamespace

    selection = {"asset": "alias/ &", "generation_id": "g", "variant_id": "v",
                 "object_id": "sha256:" + "a" * 64, "catalog_digest": "sha256:" + "b" * 64}
    response = {"selection": selection, "media_type": "video/mp4", "size": 5, "duration_seconds": 2}

    def read(project, value, *, authorize):
        assert project == PROJECT and value == selection
        assert authorize()["actor"] == "publisher-1"
        handler.identity_actor = "revoked"
        with pytest.raises(AuthorizationError):
            authorize()
        return response

    handler = make_handler(SimpleNamespace(get_project_verified_media=read), b"", command="GET",
                           path=f"/v1/projects/{PROJECT}/media-selection/verified?{urlencode(selection)}")
    handler._route()
    assert handler.reply == (200, response)
    assert handler.scopes_seen == ["projects:read"] * 3


@pytest.mark.parametrize("query", [
    "", "asset=a&generation_id=g&variant_id=v", "asset=a&asset=b&generation_id=g&variant_id=v&object_id=o&catalog_digest=d",
    "asset=a&generation_id=g&variant_id=v&object_id=o&catalog_digest=d&unknown=x",
    "asset=a&generation_id=g&variant_id=v&object_id=o&catalog_digest=", "asset=%20&generation_id=g&variant_id=v&object_id=o&catalog_digest=d",
    "asset=a&generation_id=g&variant_id=v&object_id=o&catalog_digest=%", "asset=%FF&generation_id=g&variant_id=v&object_id=o&catalog_digest=d",
    "asset=a&generation_id=g&variant_id=v&object_id=o&catalog_digest=d&bad", "association_id=a&object_id=o&version=1",
])
def test_verified_route_refuses_nonexact_or_bad_query_before_service(query):
    from types import SimpleNamespace

    from runtime_protocol.errors import ProtocolError

    handler = make_handler(SimpleNamespace(), b"", command="GET",
                           path=f"/v1/projects/{PROJECT}/media-selection/verified?{query}")
    with pytest.raises(ProtocolError):
        handler._route()
