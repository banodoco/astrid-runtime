from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from precut_realm_fixture import FIXTURE_BACKUP_KEY, _extract_archive
from runtime_protocol.backup import restore_backup, verify_backup
from runtime_protocol.errors import ConflictError, NotFoundError, ValidationError
from runtime_protocol.managed_render_snapshot import ShotExpansionError, expand_shot_clips
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_store import TimelineCommitStore, digest, request_identity
from runtime_protocol.timeline_commit_validation import validate_commit_value
from runtime_protocol.util import canonical_json


def _digest(value: bytes | str) -> str:
    raw = value.encode() if isinstance(value, str) else value
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _admit_timeline(service, project_id, timeline, *, idempotency_key):
    """Host acceptance fixture, without claiming Agent command/compiler semantics.

    Keep the original raw config/registry, including incomplete editor shapes.
    Runtime's real acceptance store checks the closure, media custody and schema,
    and writes the publication/history/receipt; no legacy writer installs rows.
    """
    timeline_id = timeline["timeline_id"]
    service.create_timeline(project_id, timeline_id, name=timeline.get("name"), idempotency_key=idempotency_key)
    commits = TimelineCommitStore(service.store, validate_prepared=lambda value: validate_commit_value(value, "PreparedCommit"))
    head = commits.bootstrap(project_id, timeline_id, authorize=lambda: None)
    document = commits.revision_closure(project_id, timeline_id, head["revision_id"])
    parent = document["parent_revision"]
    before = copy.deepcopy(parent["payload"])
    parent["payload"] = {
        "config": copy.deepcopy(timeline["config"]),
        "registry": copy.deepcopy(timeline["registry"]),
        "clips": copy.deepcopy(timeline["config"].get("clips", [])),
        "occurrences": [],
    }
    parent["revision_id"] = "direct-render-" + timeline_id
    parent["content_digest"] = digest(parent["payload"])
    # Only the long-render case uses a CAS media_id. Opaque IDs in the other
    # registries retain their separate content_sha256 binding exactly as authored.
    media_ids = sorted({asset["media_id"] for asset in timeline["registry"].get("assets", {}).values()
                        if asset.get("media_id", "").startswith("sha256:")})
    document["dependency_manifest"]["media"] = [{"media_id": value, "content_digest": value} for value in media_ids]
    command = {"schema_version": 1, "op": "fixture.direct-render-source", "version": "1", "select": None, "args": {}}
    request = {"api_version": 1, "project_id": project_id, "timeline_id": timeline_id,
               "base_revision_id": head["revision_id"], "base_publication_id": head["publication_id"], "commands": [command]}
    context = {"request": request, "invocation": {"operation": "commitTimeline",
               "path": f"/v1/projects/{project_id}/timelines/{timeline_id}/commit", "body": copy.deepcopy(request)},
               "idempotency_key": idempotency_key + "-source", "realm_id": service.realm["id"], "publisher": "host-render-fixture"}
    context["request_hash"] = request_identity(context)
    record = {"ordinal": 0, "command": command, "writes": [
        {"ref": "parent", "path": [key], "before": {"state": "present", "value": before[key]},
         "after": {"state": "present", "value": value}} for key, value in parent["payload"].items()
    ], "reads": [], "selections": [], "bindings": [], "created": [], "dependencies": [], "derived_writes": []}
    accepted = commits.accept(context, {
        "expected_head": head, "canonical_document": document, "document_digest": digest(document),
        "records": {"schema_version": 1, "commands": [record], "undo_of": [], "restored_from": None},
        "id_map": {}, "semantic_events": [], "provider_version": "host-render-fixture", "compiler_version": "host-render-fixture",
    }, authorize=lambda: None)
    assert accepted["data"]["status"] == "accepted"
    pinned = service.get_project_parent_composition_revision(project_id, timeline_id, accepted["data"]["accepted_revision_id"])
    assert pinned["payload"] == parent["payload"]
    return service.get_project_timeline(project_id, timeline_id)["version"]


def _legacy_shot_service(tmp_path, label):
    """Restore authenticated M1 API bytes; M2 never saves these invalid shapes."""
    archive = Path(__file__).with_name("fixtures") / f"precut-direct-render-{label}-v31.tar.gz"
    backup = _extract_archive(tmp_path / "legacy-archive", archive)
    assert verify_backup(backup, key=FIXTURE_BACKUP_KEY)["manifest"]["schema"]["version"] == 31
    root = tmp_path / "realm"
    restore_backup(backup, root, key=FIXTURE_BACKUP_KEY)
    service = RuntimeService(root)
    return service, service.list_projects()["items"][0]["project_id"]


def test_direct_managed_render_admission_freezes_snapshot_before_claim(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        capability_digest = _digest("rendering.render")
        service.register_capability({
            "capability_id": "rendering.render",
            "definition_digest": capability_digest,
        })
        service.register_executor({
            "executor_id": "worker",
            "capabilities": ["rendering.render"],
        })
        project = service.create_project({"slug": "managed-render", "name": "Managed Render"}, idempotency_key="project")
        source = service.ingest(project["id"], b"source-media", media_type="video/mp4", idempotency_key="source")
        source_id = source["data"]["object_id"]
        timeline = {
            "timeline_id": "main",
            "slug": "main",
            "name": "Main",
            "config": {"clips": [{"id": "source", "type": "video"}]},
            "registry": {"assets": {"source": {"media_id": "media-source", "content_sha256": source_id}}},
        }
        config_version = _admit_timeline(service, project["id"], timeline, idempotency_key="timeline")

        admitted = service.create_task({
            "project": project["id"],
            "capability_id": "rendering.render",
            "capability_digest": capability_digest,
            "input_object_ids": [source_id],
            "idempotency_key": "render",
            "storage_estimate": {"scratch_bytes": 0, "output_bytes": 0},
            "spec": {
                "family": "render",
                "params": {
                    "timeline_ref": "main",
                    "expected_version": config_version,
                    "selector": "rendering.remotion",
                },
            },
        })
        task = admitted["task"]
        admitted_spec = task["spec"]["spec"]
        assert admitted_spec["params"]["timeline_ref"] == "main"
        assert "timeline_snapshot" not in admitted_spec
        snapshot_ref = admitted_spec["timeline_snapshot_ref"]
        # The render projection (_project_output_timeline) always materializes the output track list.
        assert json.loads(service.object(snapshot_ref["digest"])[1]) == {
            "config": {**timeline["config"], "tracks": []},
            "registry": {"assets": {"source": {**timeline["registry"]["assets"]["source"], "content_sha256": source_id.removeprefix("sha256:")}}},
        }
        assert snapshot_ref["project_id"] == project["id"]
        assert snapshot_ref["timeline_id"] == "main"
        assert admitted_spec["inputs"]["timeline_ref"] == "main"
        assert admitted_spec["inputs"]["selector"] == "rendering.remotion"
        assert admitted_spec["inputs"]["timeline_authority"]["project_id"] == project["id"]
        assert admitted_spec["inputs"]["timeline_authority"]["project_slug"] == "managed-render"
        assert admitted_spec["inputs"]["timeline_authority"]["config_version"] == config_version
        assert admitted_spec["inputs"]["timeline_authority"]["managed_media_admissions"] == {"media-source": source_id}
        assert task["spec"]["input_object_ids"] == [source_id, snapshot_ref["digest"]]
        assert task["spec"]["storage_estimate"]["scratch_bytes"] >= 128 * 1024 * 1024
        assert task["spec"]["storage_estimate"]["output_bytes"] >= 1024 * 1024

        epoch = service.health()["runtime_epoch"]
        claimed = service.claim_next({
            "executor_id": "worker",
            "capability_ids": ["rendering.render"],
            "runtime_epoch": epoch,
        })
        assert re.fullmatch(r"[0-9a-f]{32}", claimed["run_id"])
        assert claimed["run_id"] == task["run_id"]
        assert "timeline_snapshot" not in claimed["spec"]["spec"]
        assert claimed["spec"]["spec"]["timeline_snapshot_ref"] == snapshot_ref
        assert claimed["spec"]["spec"]["inputs"]["timeline_authority"] == admitted_spec["inputs"]["timeline_authority"]
        assert claimed["input_object_ids"] == [source_id, snapshot_ref["digest"]]
        assert claimed["storage_estimate"] == task["spec"]["storage_estimate"]
    finally:
        service.close()


@pytest.mark.parametrize("alpha_mode", ["opaque", "stamp", "profile"])
def test_direct_long_render_admission_budgets_current_fallback(tmp_path, monkeypatch, alpha_mode):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        capability_digest = _digest("rendering.render")
        service.register_capability({
            "capability_id": "rendering.render",
            "definition_digest": capability_digest,
        })
        project = service.create_project({"slug": "long-render", "name": "Long Render"}, idempotency_key="project")
        source = service.ingest(project["id"], b"long-video", media_type="video/mp4", idempotency_key="source")["data"]
        timeline_config = {"clips": [
                {"id": "late-media", "clipType": "media", "at": 140, "from": 0, "to": 40,
                 "speed": 2, "track": "visual", "asset": "source"},
                {"id": "long-hold", "clipType": "hold", "at": 160, "hold": 16,
                 "speed": 2, "track": "visual"},
            ]}
        if alpha_mode == "stamp":
            timeline_config["metadata"] = {"astrid_layer": {"alpha": True}}
        _admit_timeline(service, project["id"], {
            "timeline_id": "main", "slug": "main",
            "config": timeline_config,
            "registry": {"assets": {"source": {
                "media_id": source["object_id"], "content_sha256": source["object_id"],
            }}},
        }, idempotency_key="timeline")
        # This isolates budget derivation from the test machine's physical
        # free-space floor; the admission code still derives the full estimate.
        monkeypatch.setattr(service.store, "storage_preflight", lambda *_args, **_kwargs: {"ok": True})
        admitted = service.create_task({
            "project": project["id"], "capability_id": "rendering.render",
            "capability_digest": capability_digest, "idempotency_key": "long-render",
            "spec": {"family": "render", "params": {
                "timeline_ref": "main",
                **({"profile": {
                    "width": 1920, "height": 1080, "fps_rational": [30, 1],
                    "time_base": [1, 30], "container": "mov", "video_codec": "prores",
                    "video_profile": "4444", "video_level": "unknown",
                    "pixel_format": "yuva444p12le", "duration_tolerance": 0,
                }} if alpha_mode == "profile" else {}),
            }},
        })
        estimate = admitted["task"]["spec"]["storage_estimate"]
        png_raw_frame_bytes = (4 * 1920 + 1) * 1080
        png_frame_bytes = (png_raw_frame_bytes * 101 + 99) // 100
        png_sequence_bytes = png_frame_bytes * 5040
        jpeg_sequence_bytes = ((1920 * 1080) // 4) * 5040
        if alpha_mode == "opaque":
            assert estimate["scratch_bytes"] >= math.ceil(jpeg_sequence_bytes * 1.10)
            assert estimate["scratch_bytes"] < png_sequence_bytes
            # Eight timeline seconds of held media at 160 seconds keeps the
            # opaque output clock at exactly 168 seconds / 5040 frames.
            assert estimate["output_bytes"] == 344_359_936
        else:
            assert estimate["scratch_bytes"] >= math.ceil(png_sequence_bytes * 1.10)
    finally:
        service.close()


def test_managed_render_storage_estimate_right_sizes_opaque_and_keeps_alpha_png(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        registry = {"assets": {}}

        def estimate_for(frames, *, alpha=False):
            config = {"clips": [{"id": "picture", "at": 0, "duration": frames / 30}]}
            if alpha:
                config["metadata"] = {"astrid_layer": {"alpha": True}}
            return config, service.store._derive_managed_render_storage_estimate(
                config, registry, [],
            )

        _, opaque = estimate_for(4889)
        total_163s = opaque["scratch_bytes"] + opaque["output_bytes"]
        assert total_163s < 8 * 1024**3

        # The transparent path still budgets PNG frames with the existing raw-frame formula.
        alpha_config, alpha = estimate_for(4889, alpha=True)
        png_frame_bytes = (((4 * 1920 + 1) * 1080 * 101 + 99) // 100)
        png_sequence_bytes = png_frame_bytes * 4889
        alpha_snapshot_bytes = len(canonical_json(alpha_config).encode()) + len(canonical_json(registry).encode())
        alpha_raw_scratch = alpha_snapshot_bytes + png_sequence_bytes + 2 * 1024 * 1024 + 128 * 1024 * 1024
        assert alpha["scratch_bytes"] == math.ceil(alpha_raw_scratch * 1.10)

        _, ten_minutes = estimate_for(600 * 30)
        ten_minute_total = ten_minutes["scratch_bytes"] + ten_minutes["output_bytes"]
        assert ten_minute_total < 15 * 1024**3
        monkeypatch.setenv("ASTRID_RUNTIME_FREE_DISK_FLOOR_BYTES", "0")
        monkeypatch.setattr(
            "runtime_protocol.store.shutil.disk_usage",
            lambda _path: SimpleNamespace(free=ten_minute_total - 1),
        )
        preflight = service.store.storage_preflight(
            "rendering.render", storage_estimate=ten_minutes,
        )
        assert preflight["ok"] is False
        assert preflight["required_bytes"] == ten_minute_total
    finally:
        service.close()


def test_direct_managed_render_rejects_stale_scope_and_path_injection(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "managed-render", "name": "Managed Render"}, idempotency_key="project")
        config_version = _admit_timeline(
            service,
            project["id"],
            {"timeline_id": "main", "slug": "main", "config": {}, "registry": {}},
            idempotency_key="timeline",
        )
        capability_digest = _digest("rendering.render")
        body = {
            "project": project["id"],
            "capability_id": "rendering.render",
            "capability_digest": capability_digest,
            "spec": {"params": {"timeline_ref": "main", "expected_version": config_version + 1}},
        }
        with pytest.raises(ConflictError, match="expected_version"):
            service.create_task(body)

        understated = {
            **body,
            "spec": {"params": {"timeline_ref": "main"}},
            "storage_estimate": {"scratch_bytes": 1, "output_bytes": 1},
        }
        with pytest.raises(ConflictError, match="understates"):
            service.create_task(understated)

        for field, message in (
            ("timeline", "caller-supplied timeline path"),
            ("assets_registry", "assets registry path"),
            ("materialized_root", "materialization is host-owned"),
        ):
            injected = {
                **body,
                "spec": {
                    "params": {"timeline_ref": "main"},
                    "inputs": {field: "/caller/project/input"},
                },
            }
            with pytest.raises(ValidationError, match=message):
                service.create_task(injected)

        other_project = service.create_project({"slug": "other", "name": "Other"}, idempotency_key="other-project")
        wrong_scope = {**body, "project": other_project["id"], "spec": {"params": {"timeline_ref": "main"}}}
        with pytest.raises(NotFoundError, match="selected project"):
            service.create_task(wrong_scope)
    finally:
        service.close()


def test_direct_managed_render_rejects_legacy_shot_before_claim(tmp_path):
    service, project_id = _legacy_shot_service(tmp_path, "legacy-shot")
    project = {"id": project_id}
    try:
        capability_digest = _digest("rendering.render")

        with pytest.raises(ConflictError, match="legacy clipType 'shot'"):
            service.create_task({
                "project": project["id"],
                "capability_id": "rendering.render",
                "capability_digest": capability_digest,
                "input_object_ids": [],
                "idempotency_key": "shot-render",
                "spec": {
                    "family": "rendering.render",
                    "params": {
                        "timeline_ref": "main",
                        "selector": "rendering.remotion",
                        "output_name": "shot-render.mp4",
                        "profile": {},
                    },
                },
            })
        assert service.list_project_tasks(project["id"])["items"] == []
    finally:
        service.close()


def test_direct_managed_render_accepts_root_static_image_hold(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        capability_digest = _digest("rendering.render")
        service.register_capability({
            "capability_id": "rendering.render",
            "definition_digest": capability_digest,
        })
        project = service.create_project({"slug": "overlay-render", "name": "Overlay Render"}, idempotency_key="project")
        overlay = service.ingest(project["id"], b"overlay-png", media_type="image/png", idempotency_key="overlay")
        overlay_id = overlay["data"]["object_id"]
        _admit_timeline(
            service,
            project["id"],
            {
                "timeline_id": "main",
                "slug": "main",
                "config": {
                    "tracks": [{"id": "frame", "kind": "visual"}],
                    "clips": [{
                        "id": "frame-overlay",
                        "at": 0,
                        "hold": 5,
                        "track": "frame",
                        "clipType": "media",
                        "asset": "frame-overlay",
                    }],
                },
                "registry": {
                    "assets": {
                        "frame-overlay": {
                            "type": "image",
                            "media_id": "media-overlay",
                            "content_sha256": overlay_id,
                        },
                    },
                },
            },
            idempotency_key="timeline",
        )

        admitted = service.create_task({
            "project": project["id"],
            "capability_id": "rendering.render",
            "capability_digest": capability_digest,
            "input_object_ids": [],
            "idempotency_key": "overlay-render",
            "spec": {
                "family": "rendering.render",
                "params": {"timeline_ref": "main", "selector": "rendering.remotion"},
            },
        })

        admitted_spec = admitted["task"]["spec"]
        snapshot_ref = admitted_spec["spec"]["timeline_snapshot_ref"]
        assert snapshot_ref["digest"] in admitted_spec["input_object_ids"]
        snapshot = json.loads(service.object(snapshot_ref["digest"])[1])
        clip = snapshot["config"]["clips"][0]
        assert clip["id"] == "frame-overlay"
        assert clip["hold"] == 5
    finally:
        service.close()


def test_direct_managed_render_rejects_nested_shot_before_queueing(tmp_path):
    service, project_id = _legacy_shot_service(tmp_path, "nested-shot")
    project = {"id": project_id}
    try:
        capability_digest = _digest("rendering.render")

        with pytest.raises(ConflictError, match="legacy clipType 'shot'"):
            service.create_task({
                "project": project["id"],
                "capability_id": "rendering.render",
                "capability_digest": capability_digest,
                "input_object_ids": [],
                "idempotency_key": "nested-render",
                "spec": {"params": {"timeline_ref": "main"}},
            })
        assert service.list_project_tasks(project["id"])["items"] == []
    finally:
        service.close()


def test_shot_expansion_rejects_conflicting_asset_keys():
    config = {
        "clips": [{
            "id": "shot",
            "clipType": "shot",
            "at": 0,
            "hold": 1,
            "params": {"shot_id": "shot-1", "timeline_document_id": "child"},
        }],
    }
    registry = {"assets": {"shared": {"media_id": "parent-media"}}}

    with pytest.raises(ShotExpansionError, match="asset key collision"):
        expand_shot_clips(
            config,
            registry,
            load_timeline=lambda _ref: (
                {"clips": [{"id": "child-clip", "at": 0, "hold": 1, "asset": "shared"}]},
                {"assets": {"shared": {"media_id": "child-media"}}},
            ),
        )


def test_shot_expansion_namespaces_repeated_child_clip_ids_and_trims_left_window():
    config = {
        "clips": [
            {
                "id": "shot-a",
                "clipType": "shot",
                "at": 1,
                "hold": 2,
                "params": {"shot_id": "shot-1", "timeline_document_id": "child"},
            },
            {
                "id": "shot-b",
                "clipType": "shot",
                "at": 4,
                "hold": 2,
                "params": {"shot_id": "shot-1", "timeline_document_id": "child"},
            },
        ],
    }
    child_config = {
        "clips": [{
            "id": "shared-child-id",
            "clipType": "media",
            "at": -0.5,
            "hold": 2,
            "from": 0,
            "to": 2,
            "asset": "shared",
        }],
    }
    expanded, _registry = expand_shot_clips(
        config,
        {"assets": {}},
        load_timeline=lambda _ref: (child_config, {"assets": {"shared": {"media_id": "media"}}}),
    )

    clips = expanded["clips"]
    assert [clip["id"] for clip in clips] == [
        "shot-occ-0000-shot-1--shared-child-id",
        "shot-occ-0001-shot-1--shared-child-id",
    ]
    assert [clip["shot_occurrence_id"] for clip in clips] == [
        "shot-occ-0000-shot-1",
        "shot-occ-0001-shot-1",
    ]
    assert clips[0]["at"] == 1.0
    assert clips[0]["hold"] == 1.5
    assert clips[0]["from"] == 0.5
    assert clips[0]["to"] == 2.0
    assert "source_clip_id" not in clips[0]
    assert clips[0]["app"]["astrid_shot_composition"]["source_clip_id"] == "shared-child-id"


def test_shot_expansion_visible_time_vectors_apply_speed_once_and_preserve_source_geometry():
    parent = {
        "clips": [{
            "id": "shot",
            "clipType": "shot",
            "at": 0,
            "hold": 3,
            "params": {"shot_id": "shot-1", "timeline_document_id": "child"},
        }],
    }
    child = {
        "clips": [
            {"id": "hold-slow", "at": 0, "hold": 1, "speed": 0.5, "asset": "shared"},
            {"id": "hold-fast", "at": 0, "hold": 4, "speed": 2, "asset": "shared"},
            {"id": "duration-ms-fast", "at": 0, "duration_ms": 17, "speed": 2, "asset": "shared"},
            {"id": "trim-slow", "at": 0, "from": 2, "to": 3, "speed": 0.5, "asset": "shared"},
            {"id": "trim-fast", "at": 0, "from": 2, "to": 6, "speed": 2, "asset": "shared"},
        ],
    }
    original = copy.deepcopy(child)
    expanded, _ = expand_shot_clips(
        parent,
        {"assets": {}},
        load_timeline=lambda _ref: (child, {"assets": {"shared": {"media_id": "media"}}}),
    )
    clips = {clip["app"]["astrid_shot_composition"]["source_clip_id"]: clip for clip in expanded["clips"]}

    assert clips["hold-slow"]["hold"] / clips["hold-slow"]["speed"] == 2
    assert clips["hold-fast"]["hold"] / clips["hold-fast"]["speed"] == 2
    assert clips["duration-ms-fast"]["hold"] / clips["duration-ms-fast"]["speed"] == pytest.approx(0.0085)
    assert "duration_ms" not in clips["duration-ms-fast"]
    assert (clips["trim-slow"]["from"], clips["trim-slow"]["to"]) == (2, 3)
    assert (clips["trim-fast"]["from"], clips["trim-fast"]["to"]) == (2, 6)
    assert child == original

    clipped, _ = expand_shot_clips(
        {"clips": [{**parent["clips"][0], "hold": 0.75}]},
        {"assets": {}},
        load_timeline=lambda _ref: (
            {"clips": [{"id": "hold-fast", "at": 0, "hold": 4, "speed": 2, "asset": "shared"}]},
            {"assets": {"shared": {"media_id": "media"}}},
        ),
    )
    assert clipped["clips"][0]["hold"] == 1.5
    assert clipped["clips"][0]["hold"] / clipped["clips"][0]["speed"] == 0.75


def test_shot_expansion_rejects_non_finite_or_non_positive_timing():
    with pytest.raises(ShotExpansionError, match="finite"):
        expand_shot_clips(
            {"clips": [{"id": "shot", "clipType": "shot", "at": float("nan"), "hold": 1, "params": {"shot_id": "s", "timeline_document_id": "child"}}]},
            {"assets": {}},
            load_timeline=lambda _ref: ({"clips": []}, {"assets": {}}),
        )
    with pytest.raises(ShotExpansionError, match="positive hold"):
        expand_shot_clips(
            {"clips": [{"id": "shot", "clipType": "shot", "at": 0, "hold": 0, "params": {"shot_id": "s", "timeline_document_id": "child"}}]},
            {"assets": {}},
            load_timeline=lambda _ref: ({"clips": []}, {"assets": {}}),
        )
