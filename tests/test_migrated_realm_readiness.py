"""RT1/RT2: preserve the fence, then verify/save/reopen the same migrated realm."""
from __future__ import annotations

import pytest

from astrid_runtime_client import WorkspaceClient
from migrated_realm import MigratedRealmDaemon, register_migrated_provider
from precut_realm_fixture import load_precut_realm_fixture, readonly_tree_digest
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError
from runtime_protocol.service import RuntimeService
from runtime_protocol.v33_lifecycle import activation


def test_migrated_realm_refuses_mutation_before_provider_verification(tmp_path, astrid_importable):
    captured = load_precut_realm_fixture(tmp_path)
    root = captured.copy_roots[1]
    service = RuntimeService(root)
    try:
        assert activation(root)[1]["state"] == "backfill_complete"
        before = tuple(service.store.conn.iterdump()), service.store.conn.total_changes
        body = {"document_id": "readiness-notes", "kind": "example.notes", "content": {"saved": True}}
        with pytest.raises(ConflictError, match=(
            "^v33 provider/baseline verification is pending; requests and fresh pins are fenced$"
        )):
            service.create_document(captured.pins["project_id"], body, idempotency_key="readiness-notes")
        assert (tuple(service.store.conn.iterdump()), service.store.conn.total_changes) == before
        register_migrated_provider(service)
        assert activation(root)[1]["state"] == "ready"
        saved = service.create_document(captured.pins["project_id"], body, idempotency_key="readiness-notes")
        assert saved["data"]["content"] == {"saved": True}
    finally:
        service.close()


@pytest.mark.parametrize("profile", [None, "neutral"])
def test_neutral_migrated_profile_still_refuses_startup(tmp_path, profile):
    captured = load_precut_realm_fixture(tmp_path)
    root = captured.copy_roots[1]
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support", authoring_profile=profile)
    try:
        with pytest.raises(ConflictError, match=(
            "^migrated realm requires fresh Timeline provider registration before readiness$"
        )):
            daemon.start()
        assert daemon.service is None
        assert activation(root)[1]["state"] == "backfill_complete"
    finally:
        daemon.stop()


@pytest.mark.integration
def test_migrated_authoring_realm_registers_verifies_saves_and_reopens(tmp_path, astrid_importable):
    captured = load_precut_realm_fixture(tmp_path)
    root = captured.copy_roots[1]
    original = readonly_tree_digest(captured.backup_root)
    project, timeline = captured.pins["project_id"], captured.pins["timeline_id"]
    realm_id = activation(root)[1]["realm_id"]
    daemon = MigratedRealmDaemon(root, support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        state = activation(root)[1]
        assert state["state"] == "ready" and state["realm_id"] == realm_id
        assert daemon.service._v33_provider_registered is True
        assert any(row["project_id"] == project and row["timeline_id"] == timeline
                   and row["access"] == "verified" for row in state["baseline_inventory"])
        initial = client.get_project_timeline(project, timeline)
        request = {
            "api_version": 1, "project_id": project, "timeline_id": timeline,
            "base_revision_id": initial["head_revision_id"],
            "base_publication_id": initial["head_publication_id"],
            "commands": [{"schema_version": 1, "op": "track.create", "version": "1", "select": "parent",
                          "args": {"row": {"id": "verified-track", "kind": "visual"}}}],
            "source": {"via": "python"},
        }
        saved = client.commit_timeline(project, timeline, request, idempotency_key="verified-save")
        head = client.get_project_timeline(project, timeline)
        assert head["head_revision_id"] == saved["data"]["accepted_revision_id"]
        assert head["head_revision_id"] != initial["head_revision_id"]
        assert head["head_publication_id"] == saved["receipt"]["receipt_id"]
        revision = client.get_project_parent_composition_revision(project, timeline, head["head_revision_id"])
        assert any(track["id"] == "verified-track" for track in revision["payload"]["config"]["tracks"])
        first_owner = daemon.service
    finally:
        daemon.stop()

    # A durable ready marker does not authorize a new neutral owner.
    neutral = RuntimeDaemon(root, support_root=tmp_path / "neutral", authoring_profile="neutral")
    try:
        with pytest.raises(ConflictError, match="migrated realm requires fresh Timeline provider registration"):
            neutral.start()
    finally:
        neutral.stop()

    reopened = MigratedRealmDaemon(root, support_root=tmp_path / "support").start()
    try:
        assert reopened.service is not first_owner
        assert reopened.service._v33_provider_registered is True
        assert reopened.service.realm_resource()["realm_id"] == realm_id
        client = WorkspaceClient(reopened.endpoint, reopened.token)
        assert client.get_project_timeline(project, timeline)["head_revision_id"] == head["head_revision_id"]
        assert client.get_project_parent_composition_revision(project, timeline, head["head_revision_id"]) == revision
        assert client.commit_timeline(project, timeline, request, idempotency_key="verified-save") == saved
        assert readonly_tree_digest(captured.backup_root) == original
    finally:
        reopened.stop()
