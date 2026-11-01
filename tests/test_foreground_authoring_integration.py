"""Installed authoring provider works through the foreground boundary."""
from pathlib import Path

import pytest

from astrid_runtime.bootstrap import SourceProfile


@pytest.mark.integration
def test_foreground_boundary_creates_timeline_and_commits(tmp_path, astrid_importable):
    from astrid_runtime.runtime_boundary import ForegroundRuntimeBoundary
    from runtime_protocol.store import RealmStore
    from runtime_protocol.timeline_commit_port import route_path

    root = tmp_path / "realm"
    support = tmp_path / "support"
    RealmStore.initialize(root, realm_id="foreground-authoring").close()
    source = SourceProfile(profile="astrid", runtime_checkout=str(Path(__file__).resolve().parents[1]),
                           source_checkout=str(astrid_importable))
    boundary = ForegroundRuntimeBoundary()
    try:
        boundary.start(realm_id="foreground-authoring", realm_root=root,
                       owner_lock=support / "instance.lock", source_profile=source)
        service = boundary.daemon.service
        project = service.create_project({"slug": "foreground", "name": "Foreground"})["id"]
        created = service.create_timeline(project, "main", idempotency_key="create")["data"]
        history = service.list_timeline_commits(project, "main", authorize=lambda: None)
        assert [entry["intent"] for entry in history["items"]] == ["bootstrap"]
        assert created["head_revision_id"] == history["head"]["revision_id"]
        service.commit_timeline(project, "main", {
            "api_version": 1, "project_id": project, "timeline_id": "main",
            "base_revision_id": created["head_revision_id"],
            "base_publication_id": created["head_publication_id"],
            "commands": [{"schema_version": 1, "op": "track.create", "version": "1", "select": "parent",
                          "args": {"row": {"id": "V2", "kind": "visual"}}}],
            "source": {"via": "python"},
        }, idempotency_key="edit", publisher="editor", invocation_path=route_path(project, "main"),
           authorize=lambda: None)
        history = service.list_timeline_commits(project, "main", authorize=lambda: None)
        assert len(history["items"]) == 2
        assert history["head"]["revision_id"] != created["head_revision_id"]
        boundary.check_running()
    finally:
        boundary.stop()
