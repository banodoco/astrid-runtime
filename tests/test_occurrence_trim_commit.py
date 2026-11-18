"""occurrence.trim end to end: a real commit through the door against the Agent's executor.

The Runtime holds only the schema for this op (no per-op handler): the Agent SDK executes it.
Run with ASTRID_CHECKOUT naming an Agent checkout whose astrid_runtime_client matches this Runtime.
"""
from __future__ import annotations

import pytest

from astrid_runtime_client import WorkspaceClient
from runtime_protocol.contract_metadata import SCHEMA_DIGEST
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.door import DoorConfig
from runtime_protocol.store import RealmStore
from tests.door_helpers import HOSTED, DoorWorld

pytestmark = pytest.mark.integration


def test_occurrence_trim_commits_through_the_door(tmp_path, astrid_importable):
    from astrid.sdk.timeline import commit as agent

    credential = tmp_path / "product.json"
    RealmStore.initialize(tmp_path / "realm").close()
    daemon = RuntimeDaemon(
        tmp_path / "realm", support_root=tmp_path / "support", authoring_profile="astrid",
        door=DoorConfig(origin=HOSTED, port=0, credential_file=credential),
    ).start()
    world = DoorWorld(tmp_path, daemon, credential)
    try:
        world.provision()

        def transport(method, path, headers, body):
            response = world.call("/api/runtime" + path, method, headers=headers, body=body)
            return response.status, response.headers, response.body

        client = WorkspaceClient(daemon.door_endpoint, transport=transport)
        client.handshake("occurrence-trim", "1", ["projects:read", "projects:write"])
        assert daemon.service._timeline_commit_provider.contract_digest == SCHEMA_DIGEST
        project = client.create_project("Trim", slug="trim", idempotency_key="project")["project_id"]
        client.create_timeline(project, "film", idempotency_key="timeline")
        page = client.list_timeline_commits(project, "film", limit=100)

        from astrid.core.timeline.authoring_bundle import open_authoring_bundle
        from astrid.sdk.timeline.capture import capture_track_create
        from astrid.sdk.timeline.native_occurrence_create import capture_occurrence_create
        from astrid.sdk.timeline.native_occurrence_trim import capture_occurrence_trim

        parent = client.get_project_parent_composition_revision(project, "film", page["head"]["revision_id"])
        bundle = open_authoring_bundle(parent, shot_revisions=[], internal_timeline_revisions=[])

        def commit(command, key):
            head = client.list_timeline_commits(project, "film", limit=100)["head"]
            accepted = client.commit_timeline(project, "film", {
                "api_version": 1, "project_id": project, "timeline_id": "film",
                "base_revision_id": head["revision_id"],
                "base_publication_id": head["publication_id"], "commands": [command],
            }, idempotency_key=key)
            return accepted["data"]["canonical_document"]

        def occurrence(document):
            rows = document["parent_revision"]["payload"]["occurrences"]
            assert len(rows) == 1
            return rows[0]

        track = {"id": "picture", "kind": "visual", "role": "output"}
        document = commit(capture_track_create(bundle, "parent", track), "track")
        document = commit(capture_occurrence_create(
            agent.bundle_from_document(document), "occ-1", "shot-1", name="One", track="picture",
            on=10, duration=6), "birth")
        row = occurrence(document)
        assert (row["placement"]["start_ms"], row["duration_ms"], row["source_offset"]) == (10000, 6000, 0)

        document = commit(capture_occurrence_trim(
            agent.bundle_from_document(document), "occ-1", edge="start", to_ms=12000), "trim-start")
        row = occurrence(document)
        assert (row["placement"]["start_ms"], row["source_offset"], row["duration_ms"]) == (12000, 2000, 4000)

        document = commit(capture_occurrence_trim(
            agent.bundle_from_document(document), "occ-1", edge="end", to_ms=14000), "trim-end")
        row = occurrence(document)
        assert (row["placement"]["start_ms"], row["source_offset"], row["duration_ms"]) == (12000, 2000, 2000)
    finally:
        world.stop()
