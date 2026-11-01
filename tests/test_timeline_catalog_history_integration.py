"""Catalog visibility preserves real accepted history on the normal HTTP path.

Port of Agent's test_catalog_recover_uses_real_http_and_preserves_closure_before_revision_restore;
reuse Runtime's precut film and actual startup provider, never manufacture acceptance.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from runtime_protocol.contract_metadata import SCHEMA_DIGEST
from test_timeline_commit_integration import film, _start_door, rows  # noqa: F401 (fixture)

pytestmark = pytest.mark.integration


def open_client(world):
    from astrid.sdk.client import AstridClient
    from astrid.sdk.timeline.commit import RuntimeCommitService
    from astrid_runtime_client import contract_metadata

    assert contract_metadata.CONTRACT_VERSION == "0.2.14"
    assert contract_metadata.SCHEMA_DIGEST == SCHEMA_DIGEST
    assert type(world.daemon.service._timeline_commit_provider) is RuntimeCommitService
    assert world.daemon.service._timeline_commit_provider.contract_digest == SCHEMA_DIGEST
    # Match Agent's original probe: one ordinary authenticated /v1 connection.
    return AstridClient.open(
        endpoint=world.daemon.endpoint, credential=world.daemon.credential_path,
        realm_id=world.daemon.service.realm["id"], actor_id="owner",
        client_name="catalog-history", client_version="1", protocol_version="workspace.v1",
    )


def film_state(service):
    tables = (
        "parent_composition_heads", "parent_composition_revisions", "shot_revisions",
        "shot_revision_heads", "internal_timeline_revisions", "timeline_commit_history",
        "project_documents", "timeline_shots", "timeline_references", "project_shots",
        "shot_items", "shot_text_bindings", "shot_text_binding_events",
        "timeline_document_input_links",
    )
    with service.store._mutex:
        return {
            "rows": {table: [tuple(row) for row in service.store.conn.execute(f"SELECT * FROM {table}")]
                     for table in tables},
            "cas": {str(path.relative_to(service.store.cas_root)): path.read_bytes()
                    for path in service.store.cas_root.rglob("*") if path.is_file()},
        }


def cycle(client, fixture):
    archived = client.timelines.archive(fixture.project_id, fixture.timeline_id,
                                        idempotency_key="catalog-archive")
    assert archived.ok, archived.as_dict()
    version = archived.data["version"]
    recovered = client.timelines.recover(
        fixture.project_id, fixture.timeline_id, expected_version=version, version=version,
        idempotency_key="catalog-recover",
    )
    assert recovered.ok, recovered.as_dict()
    return archived, recovered


def test_catalog_visibility_preserves_exact_history_and_new_session_restore(
    film, astrid_importable, tmp_path, monkeypatch,
):
    from astrid.sdk.timeline.sync import TimelineSession

    fixture = film.fixture
    monkeypatch.setenv("ASTRID_RUNTIME_DATA_ROOT", str(tmp_path / "client-data"))
    assert Path(__import__("astrid").__file__).resolve().is_relative_to(astrid_importable)
    world = _start_door(film, tmp_path)
    try:
        with open_client(world) as client:
            session = TimelineSession.open(fixture.project_id, fixture.timeline_id, client=client,
                                           outbox_path=tmp_path / "move-outbox.json")
            service = world.daemon.service
            original_head = client.timelines.history(fixture.project_id, fixture.timeline_id, limit=1).data["head"]
            before = service._timeline_commits()[0].revision_closure(
                fixture.project_id, fixture.timeline_id, original_head["revision_id"],
            )
            accepted = session.move("parent/clip:music-bed", 1, idempotency_key="catalog-basis")
            preserved = film_state(world.daemon.service)
            history = client.timelines.history(fixture.project_id, fixture.timeline_id, limit=100)
            assert history.ok, history.as_dict()
            archived, recovered = cycle(client, fixture)
            assert film_state(world.daemon.service) == preserved
            assert client.timelines.history(fixture.project_id, fixture.timeline_id, limit=100).data == history.data
            old_instance = world.daemon.instance_id
    finally:
        world.stop()

    world = _start_door(film, tmp_path)
    try:
        assert world.daemon.instance_id != old_instance
        with open_client(world) as client:
            assert film_state(world.daemon.service) == preserved
            assert client.timelines.history(fixture.project_id, fixture.timeline_id, limit=100).data == history.data
            original_version = archived.data["version"]
            before_retry = rows(world.daemon.service)
            assert client.timelines.archive(
                fixture.project_id, fixture.timeline_id, expected_version=original_version - 1,
                idempotency_key="catalog-archive",
            ).data == archived.data
            assert client._remote._transport.recover_timeline(
                fixture.timeline_id, expected_version=original_version,
                version=original_version, idempotency_key="catalog-recover",
            )["data"] == recovered.data
            assert rows(world.daemon.service) == before_retry
            fresh = TimelineSession.open(fixture.project_id, fixture.timeline_id, client=client,
                                         outbox_path=tmp_path / "restore-outbox.json")
            restored = fresh.restore(before["parent_revision"]["revision_id"],
                                     before["parent_revision"]["content_digest"],
                                     idempotency_key="catalog-restore")
            assert restored["data"]["canonical_document"] == before
            assert restored["receipt"]["receipt_id"] != accepted["receipt"]["receipt_id"]
            final = client.timelines.history(fixture.project_id, fixture.timeline_id, limit=100)
            assert final.ok, final.as_dict()
            assert final.data["items"][:-1] == history.data["items"]
            assert final.data["items"][-1]["records"]["restored_from"] == {
                key: before["parent_revision"][key] for key in ("revision_id", "content_digest")
            }
    finally:
        world.stop()


def test_catalog_receipts_do_not_authorize_untracked_shot_projection_mutation(
    film, astrid_importable, tmp_path, monkeypatch,
):
    from astrid.sdk.timeline.sync import TimelineSession

    fixture = film.fixture
    monkeypatch.setenv("ASTRID_RUNTIME_DATA_ROOT", str(tmp_path / "client-data"))
    world = _start_door(film, tmp_path)
    try:
        with open_client(world) as client:
            session = TimelineSession.open(fixture.project_id, fixture.timeline_id, client=client,
                                           outbox_path=tmp_path / "move-outbox.json")
            session.move("parent/clip:music-bed", 1, idempotency_key="catalog-basis")
            service = world.daemon.service
            with service.store._mutex:
                head = service.get_project_timeline(fixture.project_id, fixture.timeline_id)
                document = service._timeline_commits()[0].revision_closure(
                    fixture.project_id, fixture.timeline_id, head["head_revision_id"],
                )
                assert document["shot_revisions"]
                shot = document["shot_revisions"][0]["shot_id"]
                previous_name = service.store.conn.execute(
                    "SELECT name FROM project_shots WHERE id=?", (shot,),
                ).fetchone()["name"]
                service.store.conn.execute(
                    "UPDATE project_shots SET name=? WHERE id=?", (previous_name + " untracked", shot),
                )
                assert service.store.conn.execute(
                    "SELECT name FROM project_shots WHERE id=?", (shot,),
                ).fetchone()["name"] != previous_name
            # Genuine visibility receipts must not launder an earlier raw write.
            cycle(client, fixture)
            before = rows(service)
            refused = client.timelines.history(fixture.project_id, fixture.timeline_id, limit=100)
            assert not refused.ok
            assert refused.error.code == "conflict"
            assert refused.error.details["reason"] == "history_unavailable"
            assert refused.error.details["integrity_reason"] == "unaccounted_shot_projection"
            assert rows(service) == before
    finally:
        world.stop()
