"""Ordinary parent recipes through the real door and normal Astrid startup.

Keep the first unsupported wire operation as a failing acceptance assertion;
do not seed media through a legacy publisher to make this sequence pass.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from astrid_runtime_client import ApiError, CONTRACT_VERSION, WorkspaceClient
from astrid_runtime_client.contract_metadata import SCHEMA_DIGEST as CLIENT_SCHEMA_DIGEST
from runtime_protocol.contract_metadata import SCHEMA_DIGEST
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.door import DoorConfig
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from tests.door_helpers import HOSTED, PRODUCT_ACTOR, DoorWorld, write_owner_only

pytestmark = pytest.mark.integration


def test_ordinary_http_empty_bootstrap_must_be_reachable(
    tmp_path, monkeypatch, astrid_importable,
):
    def forbidden(*args, **kwargs):
        raise AssertionError("ordinary editing called a legacy writer or renderer")

    class RendererStopped:
        def find_spec(self, fullname, path=None, target=None):
            if fullname.startswith(("astrid.packs.rendering", "astrid.core.rendering",
                                    "astrid.sdk.authoring_render_preview",
                                    "astrid.core.timeline.compatibility",
                                    "composition", "remotion")) or "scene" in fullname:
                raise AssertionError("ordinary editing imported renderer: " + fullname)

    # Install before startup and empty bootstrap, including already-imported
    # evaluator aliases. Persistence primitives used by commit remain real.
    import runtime_protocol.service as service_module
    import runtime_protocol.visual_seam as visual_seam

    monkeypatch.setattr(sys, "meta_path", [RendererStopped(), *sys.meta_path])
    monkeypatch.setattr(service_module, "evaluate_closure", forbidden)
    monkeypatch.setattr(visual_seam, "evaluate_closure", forbidden)
    for name in (
        "publish_parent_composition", "replace_parent_composition_media",
        "replace_timeline_clip", "update_timeline", "create_timeline_document",
        "create_document", "update_document", "create_project_shot",
        "update_project_shot", "create_shot", "update_shot",
        "publish_timeline_render", "_publication_replay_result",
    ):
        monkeypatch.setattr(RuntimeService, name, forbidden)

    from astrid.sdk.timeline import commit as agent

    assert Path(agent.__file__).resolve().is_relative_to(astrid_importable)
    assert CONTRACT_VERSION == "0.2.15"
    assert CLIENT_SCHEMA_DIGEST == SCHEMA_DIGEST
    agent_metadata = (astrid_importable / "astrid_runtime_client" / "contract_metadata.py").read_text()
    assert f"CONTRACT_VERSION = {CONTRACT_VERSION!r}" in agent_metadata
    assert f"SCHEMA_DIGEST = {SCHEMA_DIGEST!r}" in agent_metadata

    credential = tmp_path / "product.json"
    RealmStore.initialize(tmp_path / "realm").close()
    daemon = RuntimeDaemon(
        tmp_path / "realm", support_root=tmp_path / "support", authoring_profile="astrid",
        door=DoorConfig(origin=HOSTED, port=0, credential_file=credential),
    ).start()
    world = DoorWorld(tmp_path, daemon, credential)
    try:
        world.provision()

        responses = []

        def transport(method, path, headers, body):
            response = world.call("/api/runtime" + path, method, headers=headers, body=body)
            responses.append(response)
            return response.status, response.headers, response.body

        # The generated client serializes real requests; this adapter only adds
        # the browser door prefix/Origin and opens a real HTTP connection.
        client = WorkspaceClient(daemon.door_endpoint, transport=transport)
        health = client.health()
        assert health.status == "ok" and health.schema_digest == SCHEMA_DIGEST
        identity = client.handshake("ordinary-http", "1", ["projects:read", "projects:write"])
        assert identity.actor_id == PRODUCT_ACTOR and identity.schema_digest == SCHEMA_DIGEST
        assert daemon.service._timeline_commit_provider.__class__ is agent.RuntimeCommitService
        assert daemon.service._timeline_commit_provider.contract_digest == SCHEMA_DIGEST
        project = client.create_project("Ordinary HTTP", slug="ordinary-http", idempotency_key="project")["project_id"]
        bootstrap_error = None
        try:
            client.create_timeline(project, "film", idempotency_key="empty-bootstrap")
        except ApiError as error:
            bootstrap_error = error
        assert bootstrap_error is None, (
            "ordinary_http_empty_bootstrap_must_be_reachable: normal create_timeline must reach "
            "the Astrid-profile bootstrap before track.create/clip.add; "
            f"HTTP {responses[-1].status}: {responses[-1].body!r}"
        )
        page = client.list_timeline_commits(project, "film", limit=100)
        assert page["head"]["revision_id"] and page["head"]["publication_id"]
        assert len(page["items"]) == 1 and page["items"][0]["records"] is None

        for field, value in (
            ("config", {"clips": []}), ("canonical_document", {}),
            ("project_id", "foreign-project"), ("unknown", None),
        ):
            before = tuple(daemon.service.store.conn.iterdump())
            response = world.call(
                f"/api/runtime/v1/projects/{project}/timelines", "POST",
                headers={"Content-Type": "application/json", "Idempotency-Key": "reject-" + field},
                body=json.dumps({"timeline_id": "refused-" + field, field: value}).encode(),
            )
            assert response.status == 400, (
                "ordinary_http_create_timeline_body_is_closed: " + field, response.body,
            )
            assert tuple(daemon.service.store.conn.iterdump()) == before

        create_path = f"/api/runtime/v1/projects/{project}/timelines"
        create_body = b'{"timeline_id":"refused"}'
        create_headers = {"Content-Type": "application/json", "Idempotency-Key": "refused"}
        before = tuple(daemon.service.store.conn.iterdump())
        for origin in (None, "https://foreign.test"):
            response = world.call(create_path, "POST", origin=origin,
                                  headers=create_headers, body=create_body)
            assert response.status == 403, response.body
        response = world.call(create_path, "POST", body=create_body,
                              headers={"Content-Type": "application/json"})
        assert response.status == 400, response.body
        response = world.call(create_path, "POST", body=create_body,
                              headers={**create_headers, "Authorization": "Bearer browser"})
        assert response.status == 403, response.body
        assert tuple(daemon.service.store.conn.iterdump()) == before

        product_credential = json.loads(credential.read_text())
        readonly_token, _ = daemon.credentials.provision(
            "ordinary-readonly", ["handshake", "projects:read"],
        )
        try:
            write_owner_only(credential, {**product_credential, "actor_id": "ordinary-readonly",
                                          "token": readonly_token})
            response = world.call(create_path, "POST", headers=create_headers, body=create_body)
            assert response.status == 503, response.body
            assert response.json() == {"error": "runtime_identity_mismatch"}
            credential.unlink()
            response = world.call(create_path, "POST", headers=create_headers, body=create_body)
            assert response.status == 503, response.body
        finally:
            write_owner_only(credential, product_credential)
        assert tuple(daemon.service.store.conn.iterdump()) == before

        from astrid.core.timeline.authoring_bundle import open_authoring_bundle
        from astrid.sdk.timeline._clip_commands import capture_clip_add
        from astrid.sdk.timeline._clip_scalar_commands import capture_clip_set
        from astrid.sdk.timeline._command_state import CommandError
        from astrid.sdk.timeline.capture import capture_track_create

        parent = client.get_project_parent_composition_revision(
            project, "film", page["head"]["revision_id"],
        )
        bundle = open_authoring_bundle(parent, shot_revisions=[], internal_timeline_revisions=[])
        assert bundle["parent"]["clips"] == []

        def commit(command, key):
            assert {"reads", "selections", "bindings", "created", "expect", "authorship"} <= command.keys()
            head = client.list_timeline_commits(project, "film", limit=100)["head"]
            accepted = client.commit_timeline(project, "film", {
                "api_version": 1, "project_id": project, "timeline_id": "film",
                "base_revision_id": head["revision_id"],
                "base_publication_id": head["publication_id"], "commands": [command],
            }, idempotency_key=key)
            document = accepted["data"]["canonical_document"]
            assert accepted["receipt"]["result"] == accepted["data"]
            assert document["project_id"] == project and document["timeline_id"] == "film"
            assert document["shot_revisions"] == document["internal_timeline_revisions"] == []
            assert document["dependency_manifest"] == parent["dependency_manifest"]
            stored = client.get_project_parent_composition_revision(
                project, "film", accepted["data"]["accepted_revision_id"],
            )
            assert {key: stored[key] for key in document["parent_revision"]} == document["parent_revision"]
            assert stored["dependency_manifest"] == document["dependency_manifest"]
            history = client.list_timeline_commits(project, "film", limit=100)
            assert history["items"][-1]["records"]["commands"][0]["command"] == command
            return document

        track = {"id": "picture", "kind": "visual", "role": "output", "opaque": [None, False]}
        tracked = commit(capture_track_create(bundle, "parent", track), "track-create")
        assert tracked["parent_revision"]["payload"]["config"]["tracks"] == [track]
        row = {"id": "title", "clipType": "text", "track": "picture", "at": 0, "hold": 4,
               "params": {"text": "Ordinary HTTP"}, "opaque": [None, False, 0, {}, []]}
        created = commit(capture_clip_add(agent.bundle_from_document(tracked), "parent", row), "clip-add")
        assert created["parent_revision"]["payload"]["clips"] == [row]
        assert created["parent_revision"]["payload"]["config"]["clips"] == [row]
        held = commit(capture_clip_set(agent.bundle_from_document(created), "parent/clip:title",
                                       values={"hold": 3}), "hold-set")
        assert held["parent_revision"]["payload"]["clips"] == [{**row, "hold": 3}]

        # Continue on the film created through the public API. A source or
        # registry seeded through a legacy writer would hide this boundary.
        before = tuple(daemon.service.store.conn.iterdump())
        clear_error = None
        try:
            cleared = capture_clip_set(agent.bundle_from_document(held), "parent/clip:title", clear=["hold"])
        except CommandError as error:
            clear_error = error
        assert tuple(daemon.service.store.conn.iterdump()) == before
        assert clear_error is None, (
            "ordinary_http_hold_clear_after_native_creation_must_be_capturable: "
            f"public empty timeline -> track.create -> clip.add -> hold set -> hold clear: {clear_error}"
        )
        commit(cleared, "hold-clear")
    finally:
        world.stop()
