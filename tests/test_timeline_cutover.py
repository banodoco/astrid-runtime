from __future__ import annotations

import pytest

from baseline_fixture import load_baseline_fixture
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.timeline_cutover import audit_active_timeline_heads
from tests.http_helpers import Api


def _publication(project: str) -> dict:
    return {
        "project_id": project,
        "timeline_id": "main",
        "expected_head": None,
        "parent_revision_id": "parent-1",
        "internal_timeline_revisions": [{
            "timeline_id": "main",
            "revision_id": "internal-1",
            "payload": {
                "clips": [{"id": "media-1", "clip_type": "media", "track": "picture", "at_ms": 0, "duration_ms": 1000}],
                "tracks": [{"id": "picture"}], "registry": {}, "audio": [],
            },
        }],
        "shot_revisions": [{
            "shot_id": "shot-1", "revision_id": "shot-rev-1",
            "internal_timeline_revision_id": "internal-1",
            "payload": {"name": "Canonical opening", "assets": [], "audio_bindings": [], "text_bindings": []},
        }],
        "parent_composition": {
            "config": {},
            "registry": {},
            "clips": [{"id": "effect-code", "clip_type": "effect", "track": "effects", "at_ms": 0, "duration_ms": 1000, "parameters": {"opacity": 0.5}}],
            "occurrences": [{
                "occurrence_id": "occ-1", "shot_id": "shot-1", "shot_revision_id": "shot-rev-1",
                "placement": {"start_ms": 0}, "duration_ms": 1000, "source_offset": 0,
                "speed": 1, "track": "picture", "transform": {}, "gain": 1,
                "mute": False, "provenance": {},
            }],
        },
    }


def _service(tmp_path):
    return load_baseline_fixture(tmp_path, "cutover")


def test_active_head_audit_reports_canonical_closure_and_legacy_shell(tmp_path):
    service, project_id, _ = _service(tmp_path)
    try:
        report = audit_active_timeline_heads(service.store.conn, project_id=project_id)
        assert report["schema"] == "runtime.timeline.active-head-audit/v1"
        assert report["status"] == "ok"
        assert report["migration_required_count"] == 1
        item = report["items"][0]
        assert item["status"] == "migration_required"
        assert item["canonical_head"]["revision_id"] == "parent-1"
        assert item["closure"]["occurrences"][0]["name"] == "Canonical opening"
        assert item["closure"]["parent_clip_count"] == 1
        assert item["legacy"]["clip_type_shot_count"] == 1
        assert item["legacy"]["pinned_group_count"] == 1
    finally:
        service.close()


def test_active_head_audit_accepts_canonical_cutover_tombstone(tmp_path):
    service, project_id, _ = load_baseline_fixture(tmp_path, "legacy-document")
    try:
        service.store.conn.execute(
            "UPDATE project_documents SET content_json=?, version=? WHERE id=? AND project_id=?",
            ('{"canonical_cutover":{"head_revision_id":"parent-1","replacement":"inspectTimeline"}}',
             2, "timeline:main", project_id),
        )
        report = audit_active_timeline_heads(service.store.conn, project_id=project_id)
        assert report["status"] == "ok"
        assert report["migration_required_count"] == 0
        item = report["items"][0]
        assert item["status"] == "available"
        assert item["legacy"]["cutover"] == "canonical_head_tombstone"
        assert item["legacy"]["canonical_head_revision_id"] == "parent-1"
    finally:
        service.close()


def test_public_timeline_document_routes_are_retired(tmp_path):
    service, project_id, _ = load_baseline_fixture(tmp_path)
    root = service.store.root
    service.rename_timeline(project_id, "main", {"name": "Main"}, idempotency_key="timeline-name")
    service.close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
    try:
        api = Api(daemon.endpoint, daemon.token)
        # GET /v1/projects/{project_id}/timelines/{timeline_id} is deliberately live again (5a4087c: get returns
        # the timeline name).  Only the identity/head metadata is served, never the retired document bytes.
        timeline = api.request("GET", f"/v1/projects/{project_id}/timelines/main", None)
        assert timeline["timeline_id"] == "main"
        assert timeline["name"] == "Main"
        assert timeline["head_revision_id"] == "parent-1"
        assert not {"config", "registry", "config_version"} & set(timeline)
        for method, route, body in (
            ("POST", f"/v1/projects/{project_id}/timeline-documents", {"timeline_id": "other", "config": {}, "registry": {}}),
            ("GET", f"/v1/projects/{project_id}/documents/timeline:main", None),
            ("PATCH", f"/v1/projects/{project_id}/documents/timeline:main", {"expected_version": 1, "content": {}}),
        ):
            with pytest.raises(RuntimeError) as error:
                api.request(method, route, body)
            assert error.value.status == 410
    finally:
        daemon.stop()
