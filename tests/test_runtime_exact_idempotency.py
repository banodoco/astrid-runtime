from __future__ import annotations

import json

import pytest
from astrid_runtime_client import ApiError, WorkspaceClient
from http_helpers import Api

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore


def test_executor_registration_requires_key_and_fences_stale_replay_after_restart(tmp_path):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=support).start()
    try:
        api = Api(daemon.endpoint, daemon.token)
        executor = {
            "executor_id": "exact-executor",
            "max_concurrency": 2,
            "resource_keys": ["gpu"],
            "capabilities": ["render.basic"],
            "protocol": "workspace.v1",
        }
        with pytest.raises(RuntimeError) as missing:
            api.request("POST", "/v1/executors", executor)
        assert missing.value.status == 400
        first = api.request("POST", "/v1/executors", executor, headers={"Idempotency-Key": "executor-exact"})
        assert first["executor_id"] == "exact-executor"
    finally:
        daemon.stop()

    restarted = RuntimeDaemon(root, support_root=support).start()
    try:
        api = Api(restarted.endpoint, restarted.token)
        with pytest.raises(RuntimeError) as stale:
            api.request("POST", "/v1/executors", executor, headers={"Idempotency-Key": "executor-exact"})
        assert stale.value.status == 409
        with pytest.raises(RuntimeError) as changed:
            api.request("POST", "/v1/executors", {**executor, "max_concurrency": 3}, headers={"Idempotency-Key": "executor-exact"})
        assert changed.value.status == 409
        assert restarted.service.store.conn.execute("SELECT COUNT(*) FROM executors WHERE id=?", ("exact-executor",)).fetchone()[0] == 1
    finally:
        restarted.stop()

def test_project_reference_creation_is_keyed_durable_and_non_overwriting(tmp_path):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=support).start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = client.create_project("Exact Reference", idempotency_key="exact-project")
        media = client.ingest_project_object(project.project_id, b"exact-reference", media_type="application/octet-stream", idempotency_key="exact-media")
        reference = {"reference_id": "exact-reference", "kind": "character", "name": "Exact", "media_id": media.object_id}
        with pytest.raises(ApiError) as missing_reference:
            client._request("POST", f"/v1/projects/{project.project_id}/references", body=json.dumps(reference).encode(), headers={"Content-Type": "application/json"})
        assert missing_reference.value.status == 400
        first_reference = client.create_project_reference(project.project_id, reference, idempotency_key="exact-reference-key")
    finally:
        daemon.stop()

    restarted = RuntimeDaemon(root, support_root=support).start()
    try:
        client = WorkspaceClient(restarted.endpoint, restarted.token)
        assert client.create_project_reference(project.project_id, reference, idempotency_key="exact-reference-key") == first_reference
        with pytest.raises(ApiError) as changed_reference:
            client.create_project_reference(project.project_id, {**reference, "name": "Changed"}, idempotency_key="exact-reference-key")
        assert changed_reference.value.status == 409
        with pytest.raises(ApiError) as overwrite_reference:
            client.create_project_reference(project.project_id, {**reference, "name": "Overwrite"}, idempotency_key="different-reference-key")
        assert overwrite_reference.value.status == 409
        assert restarted.service.store.conn.execute("SELECT name FROM project_references WHERE id='exact-reference'").fetchone()[0] == "Exact"
    finally:
        restarted.stop()
