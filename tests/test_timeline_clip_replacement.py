from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).parents[1] / "packages" / "python"))
from astrid_runtime_client import WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore
from runtime_protocol.errors import ConflictError, NotFoundError, RetiredRouteError, RuntimeErrorBase, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_port import CommitUnavailable


# Direct replace_timeline_clip is retired (ledger D04; refusal asserted in
# test_timeline_legacy_authority.py). These keep the original expectations until
# the commit path covers clip media replacement (Agent popup swap / occurrence
# media swap bundle).
retired_writer = pytest.mark.xfail(
    strict=True, raises=RetiredRouteError,
    reason="[declared-xfail:timeline-clip-replacement] ledger D04: direct clip replacement retired; awaiting commit-path replacement",
)


def _media_bytes(duration: float = 5, *, kind: str = "video") -> bytes:
    missing = [tool for tool in ("ffmpeg", "ffprobe") if shutil.which(tool) is None]
    assert not missing, f"required media tools are unavailable: {', '.join(missing)}"
    if kind == "image":
        inputs = ["-f", "lavfi", "-i", "color=c=red:s=16x16:r=1"]
        codec = ["-frames:v", "1", "-threads", "1", "-c:v", "png", "-f", "image2pipe"]
    elif kind == "video":
        inputs = ["-f", "lavfi", "-i", "color=c=blue:s=16x16:r=10"]
        codec = ["-an", "-c:v", "libx264", "-pix_fmt", "yuv420p"]
    else:
        inputs = ["-f", "lavfi", "-i", "sine=frequency=440:sample_rate=8000"]
        codec = ["-vn", "-c:a", "aac"]
    if kind == "image":
        return subprocess.run(
            ["ffmpeg", "-v", "error", *inputs, *codec, "pipe:1"],
            check=True, stdout=subprocess.PIPE,
        ).stdout
    result = subprocess.run(
        ["ffmpeg", "-v", "error", *inputs, "-t", str(duration), *codec,
         "-movflags", "+frag_keyframe+empty_moov", "-f", "mp4", "pipe:1"],
        check=True,
        stdout=subprocess.PIPE,
    )
    return result.stdout


def _composition(asset_id: str = "old") -> tuple[dict, dict]:
    return (
        {
            "tracks": [{"id": "visual", "kind": "visual"}],
            "clips": [
                {"id": "target", "track": "visual", "clipType": "video", "asset": asset_id, "at": 2, "from": 1, "to": 4, "effects": [{"id": "grade"}]},
                {"id": "untouched", "track": "visual", "clipType": "text", "at": 8, "text": "keep me"},
            ],
            "metadata": {"keep": True},
        },
        {"assets": {asset_id: {"media_id": "sha256:" + "0" * 64, "type": "video/mp4"}}, "metadata": {"keep": True}},
    )


def _service_fixture(tmp_path, *, clip_type: str | None = None):
    RealmStore.initialize(tmp_path / "realm").close()
    service = RuntimeService(tmp_path / "realm")
    project = service.create_project({"slug": "replace", "name": "Replace"})
    config, registry = _composition()
    if clip_type is not None:
        config["clips"][0]["clipType"] = clip_type
    service.create_timeline_document(
        project["id"],
        {"timeline_id": "main", "slug": "main", "name": "Main", "config": config, "registry": registry},
        idempotency_key="timeline-create",
    )
    source = service.ingest(project["id"], _media_bytes(), media_type="video/mp4", idempotency_key="source")
    return service, project, config, registry, source["data"]["object_id"]


NATIVE_OWNER = "occurrence:native-occurrence"
NATIVE_TARGET = NATIVE_OWNER + "/clip:native-clip"
NATIVE_PARENT_TARGET = "parent/clip:native-parent-clip"
_PREPARED_AGENT = Path(
    "/tmp/claude-0/-home-user-repo/7dc61be1-7066-52e0-a5d0-94f90e61430a/"
    "scratchpad/orch/workers/rt-m2-next-ordinary-official-prep/agent-final-source"
)


def _native_agent_source():
    """Use the frozen ordinary Agent source when the integration runner lacks it."""
    configured = Path(os.environ.get("ASTRID_CHECKOUT", ""))
    source = configured if (configured / "astrid/sdk/timeline/native_occurrence_create.py").exists() else _PREPARED_AGENT
    if not (source / "astrid/sdk/timeline/native_occurrence_create.py").exists():
        pytest.fail("frozen ordinary Agent source is unavailable")
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))
    return source


def _native_imports():
    _native_agent_source()
    from astrid.sdk.timeline.capture import capture_track_create
    from astrid.sdk.timeline._command_state import CommandError
    from astrid.sdk.timeline._clip_scalar_commands import capture_clip_set
    from astrid.sdk.timeline.commands import execute
    from astrid.sdk.timeline.commit import bundle_from_document
    from astrid.sdk.timeline.commit import _digest
    from astrid.sdk.timeline.native_occurrence_create import capture_occurrence_create
    from astrid.sdk.timeline.native_occurrence_media_commands import (
        capture_occurrence_add_media,
        capture_parent_swap_media,
        capture_occurrence_swap_media,
    )
    from astrid.sdk.timeline.native_parent_media_commands import capture_clip_add_media
    from runtime_protocol.timeline_commit_provider import load_timeline_commit_provider
    return SimpleNamespace(
        CommandError=CommandError,
        capture_clip_set=capture_clip_set,
        capture_occurrence_add_media=capture_occurrence_add_media,
        capture_clip_add_media=capture_clip_add_media,
        capture_occurrence_create=capture_occurrence_create,
        capture_occurrence_swap_media=capture_occurrence_swap_media,
        capture_parent_swap_media=capture_parent_swap_media,
        capture_track_create=capture_track_create,
        bundle_from_document=bundle_from_document,
        digest=_digest,
        execute=execute,
        load_timeline_commit_provider=load_timeline_commit_provider,
    )


def _native_import_media(service, project, *, alias, duration=5, kind="video", key=None):
    media_type = {"video": "video/mp4", "audio": "audio/mp4", "image": "image/png"}[kind]
    result = service.import_media(
        project,
        _media_bytes(duration=duration, kind=kind),
        media_type=media_type,
        original_name=f"{alias}.mp4",
        actor_id="native-clip-replacement-test",
        duration_seconds=None if kind == "image" else duration,
        idempotency_key=key or f"import-{alias}",
    )
    result = result["data"]
    pin = service.get_project_media_selection(project, {
        "asset": result["variant_id"],
        "generation_id": result["generation_id"],
        "variant_id": result["variant_id"],
    }, authorize=lambda: None)
    verified = service.get_project_verified_media(project, pin, authorize=lambda: None)
    return pin, verified


def _native_empty_document(service, project, timeline="film"):
    head = service.get_project_timeline(project, timeline)
    bootstrap = service.get_project_parent_composition_revision(project, timeline, head["head_revision_id"])
    return {
        "schema_version": 1,
        "project_id": project,
        "timeline_id": timeline,
        "parent_revision": {key: bootstrap[key] for key in ("revision_id", "content_digest", "payload")},
        "shot_revisions": [],
        "internal_timeline_revisions": [],
        "dependency_manifest": bootstrap["dependency_manifest"],
    }


def _native_bootstrap_commands(native, document, old, old_verified):
    kind = "image" if old_verified["media_type"].startswith("image/") else "video"
    bundle = native.bundle_from_document(document)
    parent_track = native.capture_track_create(bundle, "parent", {"id": "picture", "kind": "visual"})
    tracked = native.execute(bundle, [parent_track]).bundle
    parent_media_track = native.capture_track_create(tracked, "parent", {"id": "overlay", "kind": "visual"})
    tracked = native.execute(tracked, [parent_media_track]).bundle
    parent_row = {
        "id": "native-parent-clip", "clipType": kind, "asset": old["asset"],
        "track": "overlay", "at": 0, "hold": 3, "opaque": [None, False],
    }
    if kind == "video":
        parent_row.update({"from": 1, "to": 4})
    parent_add = native.capture_clip_add_media(
        tracked, parent_row, old, verified_media=[old_verified],
    )
    tracked = native.execute(tracked, [parent_add], verified_media=[old_verified]).bundle
    birth = native.capture_occurrence_create(
        tracked, NATIVE_OWNER.removeprefix("occurrence:"), "native-shot",
        name="Native chapter", track="picture", on=0, duration=5,
    )
    born = native.execute(tracked, [birth]).bundle
    child_track = native.capture_track_create(born, NATIVE_OWNER, {"id": "picture", "kind": "visual"})
    child_bundle = native.execute(born, [child_track]).bundle
    row = {
        "id": "native-clip", "clipType": "media" if kind == "image" else kind,
        "asset": old["asset"], "track": "picture", "at": 2, "hold": 3,
        "opaque": [None, False],
    }
    if kind == "video":
        row.update({"from": 1, "to": 4})
    add = native.capture_occurrence_add_media(
        child_bundle, NATIVE_OWNER, row, old, verified_media=[old_verified],
    )
    return [parent_track, parent_media_track, parent_add, birth, child_track, add]


def _native_body(service, project, commands, *, timeline="film", base=None):
    head = service.get_project_timeline(project, timeline) if base is None else base
    return {
        "api_version": 1, "project_id": project, "timeline_id": timeline,
        "base_revision_id": head["head_revision_id"],
        "base_publication_id": head["head_publication_id"],
        "commands": copy.deepcopy(commands), "source": {"via": "python"},
    }


def _native_commit(service, project, body, key, *, timeline="film"):
    return service.commit_timeline(
        project, timeline, body, idempotency_key=key,
        publisher="native-clip-replacement-test",
        invocation_path=f"/v1/projects/{project}/timelines/{timeline}/commit",
        authorize=lambda: None,
    )


def _native_rows(service):
    return tuple(service.store.conn.iterdump())


def _native_editing(tmp_path, *, kind="video"):
    native = _native_imports()
    RealmStore.initialize(tmp_path / "realm").close()
    service = RuntimeService(tmp_path / "realm")
    project = service.create_project({"slug": "native-replace", "name": "Native replace"})["id"]
    service.register_timeline_commit_provider(native.load_timeline_commit_provider("astrid"))
    service.create_timeline(project, "film", idempotency_key="native-bootstrap")
    old, old_verified = _native_import_media(service, project, alias="old", kind=kind)
    new, new_verified = _native_import_media(service, project, alias="new", kind=kind)
    document = _native_empty_document(service, project)
    bootstrap = _native_bootstrap_commands(native, document, old, old_verified)
    created = _native_commit(service, project, _native_body(service, project, bootstrap), "native-birth")
    return SimpleNamespace(
        native=native, service=service, project=project, root=tmp_path / "realm",
        old=old, old_verified=old_verified, new=new, new_verified=new_verified,
        document=created["data"]["canonical_document"],
    )


@pytest.fixture
def native_editing(tmp_path):
    editing = _native_editing(tmp_path)
    try:
        yield editing
    finally:
        editing.service.close()


@pytest.fixture
def native_image_editing(tmp_path):
    editing = _native_editing(tmp_path, kind="image")
    try:
        yield editing
    finally:
        editing.service.close()


def _native_swap(editing, *, media=None, verified=None, old_media=None, document=None):
    native = editing.native
    bundle = native.bundle_from_document(document or editing.document)
    return native.capture_occurrence_swap_media(
        bundle, NATIVE_TARGET, old_media or editing.old, media or editing.new,
        verified_media=verified or [editing.old_verified, editing.new_verified],
    )


def _unsealed_native_swap(editing, media):
    """Build an ordinary public command with no client-forged capture claims."""
    command = _native_swap(editing)
    command["args"]["media"] = copy.deepcopy(media)
    for key in ("resolved", "expect", "authorship", "reads", "selections", "bindings", "created"):
        command.pop(key, None)
    return command


def _native_payload(document, scope):
    if scope == "parent":
        return document["parent_revision"]["payload"]
    return document["internal_timeline_revisions"][0]["payload"]


def _assert_native_swap_result(editing, before_document, accepted, *, parent_unchanged=True):
    data = accepted["data"]
    assert data["status"] in {"accepted", "rebased"}
    before_internal = _native_payload(before_document, "internal")
    after_internal = _native_payload(data["canonical_document"], "internal")
    expected_internal = copy.deepcopy(before_internal)
    expected_internal["clips"][0]["asset"] = editing.new["asset"]
    expected_internal["registry"]["assets"][editing.new["asset"]] = {
        "generationId": editing.new["generation_id"],
        "media_id": editing.new["object_id"],
        "type": "video" if editing.new_verified["media_type"].startswith("video/") else "image",
        "variantId": editing.new["variant_id"],
    }
    assert after_internal == expected_internal
    if parent_unchanged:
        before_parent = _native_payload(before_document, "parent")
        after_parent = _native_payload(data["canonical_document"], "parent")
        for key in ("clips", "config", "registry"):
            assert after_parent[key] == before_parent[key]
    before_shot = copy.deepcopy(before_document["shot_revisions"][0]["payload"])
    after_shot = copy.deepcopy(data["canonical_document"]["shot_revisions"][0]["payload"])
    before_shot.pop("internal_timeline_revision_id", None)
    after_shot.pop("internal_timeline_revision_id", None)
    assert after_shot == before_shot
    assert accepted["receipt"]["command_kind"] == "timeline.commit"
    assert accepted["receipt"]["result"] == data
    assert len(accepted["receipt"]["event_ids"]) == 1
    event = editing.service.store.conn.execute(
        "SELECT kind, payload_json FROM timeline_events WHERE id=?",
        (accepted["receipt"]["event_ids"][0],),
    ).fetchone()
    assert event["kind"] == "timeline.commit.accepted"
    assert json.loads(event["payload_json"])["revision_id"] == data["accepted_revision_id"]


@pytest.mark.integration
def test_native_clip_swap_is_atomic_cas_and_exactly_replayable(native_editing):
    command = _native_swap(native_editing)
    body = _native_body(native_editing.service, native_editing.project, [command])
    before_document = copy.deepcopy(native_editing.document)
    before_receipts = native_editing.service.store.conn.execute(
        "SELECT COUNT(*) FROM command_idempotency WHERE command_kind='timeline.commit'",
    ).fetchone()[0]
    before_events = native_editing.service.store.conn.execute(
        "SELECT COUNT(*) FROM timeline_events WHERE timeline_id='film'",
    ).fetchone()[0]
    first = _native_commit(native_editing.service, native_editing.project, body, "native-swap")
    _assert_native_swap_result(native_editing, before_document, first)
    assert native_editing.service.store.conn.execute(
        "SELECT COUNT(*) FROM command_idempotency WHERE command_kind='timeline.commit'",
    ).fetchone()[0] == before_receipts + 1
    assert native_editing.service.store.conn.execute(
        "SELECT COUNT(*) FROM timeline_events WHERE timeline_id='film'",
    ).fetchone()[0] == before_events + 1
    old_path = native_editing.service.cas.path_for(native_editing.old["object_id"].removeprefix("sha256:"))
    old_bytes = old_path.read_bytes()
    old_path.write_bytes(bytes([old_bytes[0] ^ 1]) + old_bytes[1:])
    assert _native_commit(native_editing.service, native_editing.project, body, "native-swap") == first
    assert native_editing.service.store.conn.execute(
        "SELECT COUNT(*) FROM command_idempotency WHERE command_kind='timeline.commit'",
    ).fetchone()[0] == before_receipts + 1
    assert native_editing.service.store.conn.execute(
        "SELECT COUNT(*) FROM timeline_events WHERE timeline_id='film'",
    ).fetchone()[0] == before_events + 1
    old_path.write_bytes(old_bytes)
    changed = copy.deepcopy(body)
    changed["commands"][0]["select"] = NATIVE_OWNER + "/clip:missing"
    with pytest.raises(RuntimeErrorBase) as error:
        _native_commit(native_editing.service, native_editing.project, changed, "native-swap")
    assert error.value.status == 409
    assert error.value.details["reason"] == "idempotency_mismatch"

    stale_body = copy.deepcopy(body)
    edit = native_editing.native.capture_clip_set(
        native_editing.native.bundle_from_document(first["data"]["canonical_document"]), NATIVE_TARGET,
        values={"hold": 2},
    )
    _native_commit(native_editing.service, native_editing.project,
                   _native_body(native_editing.service, native_editing.project, [edit]), "native-intervening")
    with pytest.raises(RuntimeErrorBase) as error:
        _native_commit(native_editing.service, native_editing.project, stale_body, "native-stale")
    assert error.value.status == 409


@pytest.mark.integration
def test_native_clip_swap_rebases_after_disjoint_intervening_edit(native_editing):
    before_document = copy.deepcopy(native_editing.document)
    body = _native_body(
        native_editing.service, native_editing.project, [_native_swap(native_editing)],
    )
    disjoint = native_editing.native.capture_clip_set(
        native_editing.native.bundle_from_document(before_document), NATIVE_PARENT_TARGET,
        values={"hold": 2},
    )
    intervening = _native_commit(
        native_editing.service, native_editing.project,
        _native_body(native_editing.service, native_editing.project, [disjoint]),
        "native-disjoint-intervening",
    )
    accepted = _native_commit(
        native_editing.service, native_editing.project, body, "native-disjoint-stale",
    )
    assert accepted["data"]["status"] == "rebased"
    assert accepted["data"]["rebased_onto"] == {
        "revision_id": intervening["data"]["accepted_revision_id"],
        "publication_id": intervening["receipt"]["receipt_id"],
    }
    _assert_native_swap_result(native_editing, before_document, accepted, parent_unchanged=False)
    assert _native_payload(accepted["data"]["canonical_document"], "parent")["clips"][0]["hold"] == 2


@pytest.mark.integration
def test_native_parent_clip_swap_route_refuses_parent_ownership_on_public013_schema(native_editing):
    command = native_editing.native.capture_parent_swap_media(
        native_editing.native.bundle_from_document(native_editing.document),
        NATIVE_PARENT_TARGET, native_editing.old, native_editing.new,
        verified_media=[native_editing.old_verified, native_editing.new_verified],
    )
    public_schema = json.loads(
        (Path(__file__).parent / "fixtures/published-command-schemas/agent-26ef2bbb.json").read_bytes()
    )
    errors = [
        error for error in Draft202012Validator(public_schema).iter_errors(command)
        if tuple(error.path) == ("intent", "ownership")
    ]
    assert len(errors) == 1
    assert errors[0].validator == "enum"
    assert errors[0].validator_value == ["shared", "occurrence"]
    assert errors[0].instance == "parent"


@pytest.mark.integration
def test_native_parent_clip_swap_route_replaces_parent_media(native_editing):
    command = native_editing.native.capture_parent_swap_media(
        native_editing.native.bundle_from_document(native_editing.document),
        NATIVE_PARENT_TARGET, native_editing.old, native_editing.new,
        verified_media=[native_editing.old_verified, native_editing.new_verified],
    )
    body = _native_body(native_editing.service, native_editing.project, [command])
    accepted = _native_commit(native_editing.service, native_editing.project, body, "native-parent-swap")
    assert accepted["data"]["status"] in {"accepted", "rebased"}
    assert accepted["data"]["canonical_document"]["parent_revision"]["payload"]["clips"][0]["asset"] == native_editing.new["asset"]


@pytest.mark.integration
def test_native_clip_swap_rejects_cross_project_source_without_mutation(native_editing):
    service, project = native_editing.service, native_editing.project
    foreign_project = service.create_project({"slug": "foreign", "name": "Foreign"})["id"]
    foreign, foreign_verified = _native_import_media(service, foreign_project, alias="foreign")
    command = _native_swap(native_editing, media=foreign, verified=[native_editing.old_verified, foreign_verified])
    before = _native_rows(service)
    with pytest.raises(RuntimeErrorBase):
        _native_commit(service, project, _native_body(service, project, [command]), "native-cross-project")
    assert _native_rows(service) == before


@pytest.mark.integration
def test_native_clip_swap_rejects_malformed_source_before_native_commit(native_editing):
    malformed = copy.deepcopy(native_editing.new)
    malformed.pop("catalog_digest")
    command = _unsealed_native_swap(native_editing, malformed)
    service = native_editing.service
    before = (_native_rows(service), service.get_project_timeline(native_editing.project, "film"))
    with pytest.raises(RuntimeErrorBase, match="media|selection|catalog"):
        _native_commit(service, native_editing.project,
                       _native_body(service, native_editing.project, [command]), "native-malformed")
    assert _native_rows(service) == before[0]
    assert service.get_project_timeline(native_editing.project, "film") == before[1]


@pytest.mark.integration
def test_native_clip_swap_rejects_tampered_cas_without_mutation(native_editing):
    digest = native_editing.old["object_id"].removeprefix("sha256:")
    path = native_editing.service.cas.path_for(digest)
    original = path.read_bytes()
    path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    command = _native_swap(native_editing)
    before = _native_rows(native_editing.service)
    with pytest.raises(RuntimeErrorBase, match="immutable|changed|integrity|size"):
        _native_commit(native_editing.service, native_editing.project,
                       _native_body(native_editing.service, native_editing.project, [command]), "native-tampered")
    assert _native_rows(native_editing.service) == before


@pytest.mark.integration
def test_native_clip_swap_rejects_selected_source_corruption_between_capture_and_accept(native_editing, monkeypatch):
    service = native_editing.service
    digest = native_editing.new["object_id"].removeprefix("sha256:")
    path = service.cas.path_for(digest)
    before_rows = _native_rows(service)
    before_head = service.get_project_timeline(native_editing.project, "film")
    before_receipts = [tuple(row) for row in service.store.conn.execute(
        "SELECT * FROM command_idempotency ORDER BY txn_id",
    )]
    original_verify = service._verify_child_object_bytes
    corruption = {}

    def verify_then_corrupt(object_digest, size, *, label):
        result = original_verify(object_digest, size, label=label)
        if object_digest == digest and not corruption:
            data = path.read_bytes()
            corruption["bytes"] = bytes([data[0] ^ 1]) + data[1:]
            path.write_bytes(corruption["bytes"])
        return result

    monkeypatch.setattr(service, "_verify_child_object_bytes", verify_then_corrupt)
    command = _native_swap(native_editing)
    with pytest.raises(RuntimeErrorBase, match="immutable|changed|integrity|size"):
        _native_commit(native_editing.service, native_editing.project,
                       _native_body(service, native_editing.project, [command]), "native-capture-race")
    assert corruption
    assert _native_rows(service) == before_rows
    assert service.get_project_timeline(native_editing.project, "film") == before_head
    assert [tuple(row) for row in service.store.conn.execute(
        "SELECT * FROM command_idempotency ORDER BY txn_id",
    )] == before_receipts
    assert path.read_bytes() == corruption["bytes"]


@pytest.mark.integration
def test_native_clip_swap_rejects_wrong_stream_without_mutation(native_editing):
    audio, audio_verified = _native_import_media(native_editing.service, native_editing.project, alias="audio", kind="audio")
    service = native_editing.service
    before = (_native_rows(service), service.get_project_timeline(native_editing.project, "film"))
    with pytest.raises(RuntimeErrorBase, match="media|stream|kind"):
        _native_commit(service, native_editing.project,
                       _native_body(service, native_editing.project, [_unsealed_native_swap(native_editing, audio)]),
                       "native-wrong-stream")
    assert _native_rows(service) == before[0]
    assert service.get_project_timeline(native_editing.project, "film") == before[1]


@pytest.mark.integration
@pytest.mark.parametrize("duration", [1, 3.5])
def test_native_clip_swap_rejects_too_short_or_end_short_source(native_editing, duration):
    short, short_verified = _native_import_media(
        native_editing.service, native_editing.project, alias=f"short-{duration}", duration=duration,
    )
    service = native_editing.service
    before = (_native_rows(service), service.get_project_timeline(native_editing.project, "film"))
    with pytest.raises(RuntimeErrorBase, match="short|duration|window|extent|source"):
        _native_commit(service, native_editing.project,
                       _native_body(service, native_editing.project, [_unsealed_native_swap(native_editing, short)]),
                       f"native-short-{duration}")
    assert _native_rows(service) == before[0]
    assert service.get_project_timeline(native_editing.project, "film") == before[1]


@pytest.mark.integration
def test_native_generic_visual_media_requires_video_stream(native_editing):
    audio, audio_verified = _native_import_media(native_editing.service, native_editing.project, alias="generic-audio", kind="audio")
    document = copy.deepcopy(native_editing.document)
    internal = document["internal_timeline_revisions"][0]
    internal["payload"]["clips"][0]["clipType"] = "media"
    internal["content_digest"] = native_editing.native.digest(internal["payload"])
    manifest = document["dependency_manifest"]["internal_timelines"][0]
    manifest["content_digest"] = internal["content_digest"]
    bundle = native_editing.native.bundle_from_document(document)
    with pytest.raises(native_editing.native.CommandError, match="image/video"):
        native_editing.native.capture_occurrence_swap_media(
            bundle, NATIVE_TARGET, native_editing.old, audio,
            verified_media=[native_editing.old_verified, audio_verified],
        )


@pytest.mark.integration
def test_native_generic_visual_media_accepts_verified_image_swap(native_image_editing):
    assert native_image_editing.old_verified["media_type"] == "image/png"
    assert native_image_editing.new_verified["media_type"] == "image/png"
    before_document = copy.deepcopy(native_image_editing.document)
    body = _native_body(
        native_image_editing.service, native_image_editing.project,
        [_native_swap(native_image_editing)],
    )
    accepted = _native_commit(
        native_image_editing.service, native_image_editing.project, body, "native-image-swap",
    )
    _assert_native_swap_result(native_image_editing, before_document, accepted)
    target = accepted["data"]["canonical_document"]["internal_timeline_revisions"][0]["payload"]["clips"][0]
    assert target["clipType"] == "media"
    assert set(target) == {"id", "clipType", "asset", "track", "at", "hold", "opaque"}


@pytest.mark.integration
def test_native_clip_swap_replays_after_intervening_edit_and_reopen(native_editing):
    command = _native_swap(native_editing)
    body = _native_body(native_editing.service, native_editing.project, [command])
    first = _native_commit(native_editing.service, native_editing.project, body, "native-replay")
    current = first["data"]["canonical_document"]
    edit = native_editing.native.capture_clip_set(
        native_editing.native.bundle_from_document(current), NATIVE_TARGET, values={"hold": 3},
    )
    _native_commit(native_editing.service, native_editing.project,
                   _native_body(native_editing.service, native_editing.project, [edit]), "native-intervening-replay")
    native_editing.service.close()
    reopened = RuntimeService(native_editing.root)
    try:
        reopened.register_timeline_commit_provider(native_editing.native.load_timeline_commit_provider("astrid"))
        assert _native_commit(reopened, native_editing.project, body, "native-replay") == first
        assert reopened.get_project_timeline(native_editing.project, "film")["head_publication_id"] != first["receipt"]["receipt_id"]
        assert reopened.store.conn.execute(
            "SELECT COUNT(*) FROM command_idempotency WHERE command_kind='timeline.commit'",
        ).fetchone()[0] == 3
        assert reopened.store.conn.execute(
            "SELECT COUNT(*) FROM timeline_events WHERE timeline_id='film'",
        ).fetchone()[0] == 5
    finally:
        reopened.close()


@pytest.mark.integration
def test_rt02_project_shot_crud_native_replacement_retries_after_restart(native_editing):
    """Replace one slice of ``test_project_shot_crud_isolated_idempotent_and_restart_durable``.

    The normal provider bootstrap creates the occurrence-owned shot and clip;
    this test keeps the original workflow's modify, exact-retry, and restart
    assertions while routing the film mutation through an EditCommand.
    """
    created = copy.deepcopy(native_editing.document)
    created_clip = _native_payload(created, "internal")["clips"][0]
    assert created["shot_revisions"][0]["shot_id"] == "native-shot"
    assert created_clip["asset"] == native_editing.old["asset"]

    body = _native_body(
        native_editing.service, native_editing.project, [_native_swap(native_editing)],
    )
    before_receipts = native_editing.service.store.conn.execute(
        "SELECT COUNT(*) FROM command_idempotency WHERE command_kind='timeline.commit'",
    ).fetchone()[0]
    accepted = _native_commit(
        native_editing.service, native_editing.project, body, "rt02-native-shot-modify",
    )
    assert accepted["data"]["status"] == "accepted"
    assert _native_payload(accepted["data"]["canonical_document"], "internal")["clips"][0]["asset"] == native_editing.new["asset"]

    native_editing.service.close()
    reopened = RuntimeService(native_editing.root)
    try:
        reopened.register_timeline_commit_provider(native_editing.native.load_timeline_commit_provider("astrid"))
        assert _native_commit(
            reopened, native_editing.project, body, "rt02-native-shot-modify",
        ) == accepted
        assert reopened.store.conn.execute(
            "SELECT COUNT(*) FROM command_idempotency WHERE command_kind='timeline.commit'",
        ).fetchone()[0] == before_receipts + 1
    finally:
        reopened.close()


@pytest.mark.integration
def test_rt02_native_occurrence_swap_rolls_back_before_restart_retry(native_editing, monkeypatch):
    """A persistence failure leaves the occurrence-owned shot untouched before retry."""
    service = native_editing.service
    commits, _ = service._timeline_commits()
    body = _native_body(service, native_editing.project, [_native_swap(native_editing)])
    before_rows = _native_rows(service)
    before_head = service.get_project_timeline(native_editing.project, "film")
    original_persist = commits._persist_closure

    def fail_after_persist(document):
        original_persist(document)
        raise RuntimeError("injected native persistence failure")

    monkeypatch.setattr(commits, "_persist_closure", fail_after_persist)
    with pytest.raises(CommitUnavailable, match="exact request"):
        _native_commit(service, native_editing.project, body, "rt02-native-rollback")
    assert _native_rows(service) == before_rows
    assert service.get_project_timeline(native_editing.project, "film") == before_head

    monkeypatch.undo()
    service.close()
    reopened = RuntimeService(native_editing.root)
    try:
        reopened.register_timeline_commit_provider(native_editing.native.load_timeline_commit_provider("astrid"))
        accepted = _native_commit(
            reopened, native_editing.project, body, "rt02-native-rollback",
        )
        assert accepted["data"]["status"] == "accepted"
        assert _native_payload(accepted["data"]["canonical_document"], "internal")["clips"][0]["asset"] == native_editing.new["asset"]
        after_accept = _native_rows(reopened)
        assert _native_commit(
            reopened, native_editing.project, body, "rt02-native-rollback",
        ) == accepted
        assert _native_rows(reopened) == after_accept
    finally:
        reopened.close()


@pytest.mark.integration
def test_native_clip_swap_public_http_route(tmp_path):
    """The public commit route accepts the same native occurrence swap bundle."""
    native = _native_imports()
    RealmStore.initialize(tmp_path / "realm").close()
    daemon = RuntimeDaemon(
        tmp_path / "realm", support_root=tmp_path / "support", authoring_profile="astrid",
    ).start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = client.create_project("Native HTTP", slug="native-http", idempotency_key="http-project")
        project_id = project.project_id
        client.create_timeline(project_id, "film", idempotency_key="http-bootstrap")

        imported = client.import_project_media(
            project_id, _media_bytes(), media_type="video/mp4", filename="old.mp4",
            duration_seconds=5, idempotency_key="http-old-media",
        )
        old = client.get_project_media_selection(project_id, {
            "asset": imported["variant_id"], "generation_id": imported["generation_id"],
            "variant_id": imported["variant_id"],
        })
        old_verified = client.get_project_verified_media(project_id, old)
        imported_new = client.import_project_media(
            project_id, _media_bytes(), media_type="video/mp4", filename="new.mp4",
            duration_seconds=5, idempotency_key="http-new-media",
        )
        new = client.get_project_media_selection(project_id, {
            "asset": imported_new["variant_id"], "generation_id": imported_new["generation_id"],
            "variant_id": imported_new["variant_id"],
        })
        new_verified = client.get_project_verified_media(project_id, new)
        empty = _native_empty_document(daemon.service, project_id)
        bootstrap = _native_bootstrap_commands(native, empty, old, old_verified)
        created = client.commit_timeline(
            project_id, "film", _native_body(daemon.service, project_id, bootstrap),
            idempotency_key="http-birth",
        )
        swap = native.capture_occurrence_swap_media(
            native.bundle_from_document(created["data"]["canonical_document"]),
            NATIVE_TARGET, old, new, verified_media=[old_verified, new_verified],
        )
        request = _native_body(daemon.service, project_id, [swap])
        before_receipts = daemon.service.store.conn.execute(
            "SELECT COUNT(*) FROM command_idempotency WHERE command_kind='timeline.commit'",
        ).fetchone()[0]
        before_events = daemon.service.store.conn.execute(
            "SELECT COUNT(*) FROM timeline_events WHERE timeline_id='film'",
        ).fetchone()[0]
        accepted = client.commit_timeline(project_id, "film", request, idempotency_key="http-swap")
        _assert_native_swap_result(
            SimpleNamespace(service=daemon.service, new=new, new_verified=new_verified),
            created["data"]["canonical_document"], accepted,
        )
        assert accepted["receipt"]["idempotency_key"] == "http-swap"
        assert accepted["receipt"]["project_id"] == project_id
        assert accepted["receipt"]["request_hash"]
        assert daemon.service.store.conn.execute(
            "SELECT COUNT(*) FROM command_idempotency WHERE command_kind='timeline.commit'",
        ).fetchone()[0] == before_receipts + 1
        assert daemon.service.store.conn.execute(
            "SELECT COUNT(*) FROM timeline_events WHERE timeline_id='film'",
        ).fetchone()[0] == before_events + 1
        assert client.commit_timeline(project_id, "film", request, idempotency_key="http-swap") == accepted
    finally:
        daemon.stop()


@retired_writer
def test_replace_timeline_clip_is_atomic_cas_and_exactly_replayable(tmp_path):
    service, project, before_config, before_registry, source_id = _service_fixture(tmp_path)
    try:
        body = {"clip_id": "target", "source_object_id": source_id, "expected_version": 1, "timing": "preserve-duration"}
        replaced = service.replace_timeline_clip("main", body, idempotency_key="replace")
        assert replaced["receipt"]["command_kind"] == "timeline.clip.replace"
        assert replaced["receipt"]["event_ids"]
        assert replaced["data"]["config_version"] == 2
        assert replaced["data"]["config"]["clips"][0] == {**before_config["clips"][0], "asset": source_id}
        assert replaced["data"]["config"]["clips"][1] == before_config["clips"][1]
        assert replaced["data"]["registry"]["metadata"] == before_registry["metadata"]
        assert replaced["data"]["registry"]["assets"]["old"] == before_registry["assets"]["old"]
        assert service.replace_timeline_clip("main", body, idempotency_key="replace") == replaced

        with pytest.raises(ConflictError, match="different input"):
            service.replace_timeline_clip("main", {**body, "clip_id": "untouched"}, idempotency_key="replace")
        with pytest.raises(ConflictError, match="version conflict"):
            service.replace_timeline_clip("main", {**body, "expected_version": 1}, idempotency_key="stale")

        assert service._timeline_resource("main")["config_version"] == 2
        receipt_rows = service.store.conn.execute("SELECT * FROM command_idempotency WHERE command_kind='timeline.clip.replace'").fetchall()
        event_rows = service.store.conn.execute("SELECT * FROM timeline_events WHERE timeline_id='main' AND kind='timeline.clip.replaced'").fetchall()
        assert len(receipt_rows) == len(event_rows) == 1
    finally:
        service.close()


@retired_writer
def test_replace_timeline_clip_rejects_cross_project_source(tmp_path):
    service, _, _, _, _ = _service_fixture(tmp_path)
    try:
        other = service.create_project({"slug": "other", "name": "Other"})
        foreign = service.ingest(other["id"], _media_bytes(duration=6), media_type="video/mp4", idempotency_key="foreign")["data"]["object_id"]
        with pytest.raises(NotFoundError, match="timeline project"):
            service.replace_timeline_clip("main", {"clip_id": "target", "source_object_id": foreign, "expected_version": 1}, idempotency_key="cross-project")
        assert service._timeline_resource("main")["config_version"] == 1
    finally:
        service.close()


@retired_writer
def test_replace_timeline_clip_rejects_malformed_source_without_mutation(tmp_path):
    service, project, _, _, _ = _service_fixture(tmp_path)
    try:
        malformed = service.ingest(project["id"], b"not a media container", media_type="video/mp4", idempotency_key="malformed")
        before = service._timeline_resource("main")
        with pytest.raises(ValidationError, match="malformed"):
            service.replace_timeline_clip("main", {"clip_id": "target", "source_object_id": malformed["data"]["object_id"], "expected_version": 1}, idempotency_key="malformed-replace")
        assert service._timeline_resource("main") == before
        assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE timeline_id='main'").fetchone()[0] == 1
        assert service.store.conn.execute("SELECT COUNT(*) FROM command_idempotency WHERE command_kind='timeline.clip.replace'").fetchone()[0] == 0
    finally:
        service.close()


@retired_writer
def test_replace_timeline_clip_rejects_tampered_cas_without_mutation(tmp_path):
    service, _, _, _, source_id = _service_fixture(tmp_path)
    try:
        digest = source_id.removeprefix("sha256:")
        service.cas.path_for(digest).write_bytes(b"tampered")
        before = service._timeline_resource("main")
        with pytest.raises(ConflictError, match="immutable"):
            service.replace_timeline_clip("main", {"clip_id": "target", "source_object_id": source_id, "expected_version": 1}, idempotency_key="tampered-replace")
        assert service._timeline_resource("main") == before
        assert service.store.conn.execute("SELECT COUNT(*) FROM command_idempotency WHERE command_kind='timeline.clip.replace'").fetchone()[0] == 0
    finally:
        service.close()


@retired_writer
def test_replace_timeline_clip_rejects_wrong_stream_without_mutation(tmp_path):
    service, project, _, _, _ = _service_fixture(tmp_path)
    try:
        audio = service.ingest(project["id"], _media_bytes(kind="audio"), media_type="audio/mp4", idempotency_key="audio")
        before = service._timeline_resource("main")
        with pytest.raises(ValidationError, match="stream"):
            service.replace_timeline_clip("main", {"clip_id": "target", "source_object_id": audio["data"]["object_id"], "expected_version": 1}, idempotency_key="wrong-stream")
        assert service._timeline_resource("main") == before
    finally:
        service.close()


@retired_writer
def test_replace_timeline_clip_rejects_too_short_source_without_mutation(tmp_path):
    service, project, _, _, _ = _service_fixture(tmp_path)
    try:
        short = service.ingest(project["id"], _media_bytes(duration=1), media_type="video/mp4", idempotency_key="short")
        before = service._timeline_resource("main")
        with pytest.raises(ValidationError, match="too short"):
            service.replace_timeline_clip("main", {"clip_id": "target", "source_object_id": short["data"]["object_id"], "expected_version": 1}, idempotency_key="too-short")
        assert service._timeline_resource("main") == before
    finally:
        service.close()


@retired_writer
def test_replace_timeline_clip_requires_source_to_reach_authored_end(tmp_path):
    service, project, _, _, _ = _service_fixture(tmp_path)
    try:
        source = service.ingest(project["id"], _media_bytes(duration=3.5), media_type="video/mp4", idempotency_key="end-short")
        before = service._timeline_resource("main")
        with pytest.raises(ValidationError, match="too short"):
            service.replace_timeline_clip("main", {"clip_id": "target", "source_object_id": source["data"]["object_id"], "expected_version": 1}, idempotency_key="end-short-replace")
        assert service._timeline_resource("main") == before
    finally:
        service.close()


@retired_writer
def test_replace_timeline_clip_generic_visual_media_requires_video_stream(tmp_path):
    service, project, _, _, _ = _service_fixture(tmp_path, clip_type="media")
    try:
        source = service.ingest(project["id"], _media_bytes(kind="audio"), media_type="audio/mp4", idempotency_key="generic-audio")
        before = service._timeline_resource("main")
        with pytest.raises(ValidationError, match="stream"):
            service.replace_timeline_clip("main", {"clip_id": "target", "source_object_id": source["data"]["object_id"], "expected_version": 1}, idempotency_key="generic-audio-replace")
        assert service._timeline_resource("main") == before
    finally:
        service.close()


@retired_writer
def test_replace_timeline_clip_replays_after_intervening_edit_and_reopen(tmp_path):
    service, project, _, _, source_id = _service_fixture(tmp_path)
    root = tmp_path / "realm"
    body = {"clip_id": "target", "source_object_id": source_id, "expected_version": 1}
    first = service.replace_timeline_clip("main", body, idempotency_key="replay")
    current = service.get_document(project["id"], "timeline:main")
    edited = json.loads(json.dumps(current["content"]))
    edited["metadata"] = {"intervening": True}
    service.update_document(project["id"], "timeline:main", {"expected_version": current["version"], "content": edited}, idempotency_key="intervening-edit")
    service.close()
    reopened = RuntimeService(root)
    try:
        assert reopened.replace_timeline_clip("main", body, idempotency_key="replay") == first
        assert reopened._timeline_resource("main")["config_version"] == 3
        assert reopened.store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE kind='timeline.clip.replaced'").fetchone()[0] == 1
    finally:
        reopened.close()


@retired_writer
def test_replace_timeline_clip_public_http_route(tmp_path):
    RealmStore.initialize(tmp_path / "realm").close()
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = client.create_project("HTTP", slug="http", idempotency_key="project")
        config, registry = _composition()
        # Public timeline-document creation is retired (HTTP 410); seed the
        # timeline through the running daemon's service, as the other fixtures do.
        daemon.service.create_timeline_document(
            project.project_id,
            {"timeline_id": "main", "slug": "main", "name": "Main", "config": config, "registry": registry},
            idempotency_key="timeline",
        )
        source = client.ingest_project_object(project.project_id, _media_bytes(), media_type="video/mp4", idempotency_key="source")
        request = urllib.request.Request(
            f"{daemon.endpoint}/v1/timelines/main/replace-clip",
            data=json.dumps({"clip_id": "target", "source_object_id": source.object_id, "expected_version": 1}).encode(),
            method="POST",
            headers={"Authorization": f"Bearer {daemon.token}", "Content-Type": "application/json", "Idempotency-Key": "replace"},
        )
        with urllib.request.urlopen(request) as response:
            value = json.loads(response.read())
        assert value["data"]["config"]["clips"][0]["asset"] == source.object_id
        assert value["receipt"]["command_kind"] == "timeline.clip.replace"
    finally:
        daemon.stop()
