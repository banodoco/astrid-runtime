from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from astrid_runtime_client import ApiError, WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore
from runtime_protocol.util import now
from test_timeline_commit_integration import agent, editing, film, rows  # noqa: F401


def catalog_shot(service, project, items, *, shot_id="shot-1"):
    # Approved private storage bootstrap in this ephemeral realm; createShot
    # and addItem remain retired. Promotion below uses the normal public route.
    with service.store._mutex, service.store._transaction():
        service._apply_published_shot_projection(project, {"shot_id": shot_id, "payload": {
            "name": "Shot 1", "items": items, "metadata": {},
        }}, now())
    return SimpleNamespace(**service.get_project_shot(project, shot_id))


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def test_candidate_promotion_is_atomic_fixed_point_and_byte_stable_on_replay(tmp_path):
    RealmStore.initialize(tmp_path / "realm").close()
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = client.create_project("Promotion", slug="promotion", idempotency_key="promotion-project")
        old = client.ingest_project_object(project.project_id, b"old", media_type="image/png", idempotency_key="promotion-old")
        new = client.ingest_project_object(project.project_id, b"new", media_type="image/png", idempotency_key="promotion-new")
        plate = client.ingest_project_object(project.project_id, b"plate", media_type="image/png", idempotency_key="promotion-plate")
        proxy = client.ingest_project_object(project.project_id, b"proxy", media_type="image/png", idempotency_key="promotion-proxy")
        old_id, new_id = old.digest, new.digest
        old_hash, plate_hash = old.digest, plate.digest
        shot = catalog_shot(daemon.service, project.project_id, [
            {"item_id": "old", "media_id": old_id, "metadata": {"role": "primary_visual", "status": "primary"}},
            {"item_id": "plate", "media_id": plate.digest, "metadata": {"kind": "plate", "source_item_id": "old", "source_media_id": old_id, "source_content_sha256": old_hash}},
            {"item_id": "proxy", "media_id": proxy.digest, "metadata": {"kind": "proxy", "source_item_id": "plate", "source_media_id": plate.digest, "source_content_sha256": plate_hash}},
            {"item_id": "new", "media_id": new_id, "metadata": {"role": "primary_visual", "status": "candidate", "recipe": {"project_id": project.project_id, "shot_id": "shot-1", "target_role": "primary_visual"}}},
        ])
        candidate = shot
        expected_head = int(candidate.version)
        timeline = [{"id": "timeline-1", "metadata": {"source_item_id": "old", "source_media_id": old_id, "source_content_sha256": old_hash}}]
        promoted = client.promote_project_shot_candidate(project.project_id, shot.shot_id, "new", expected_head_seq=expected_head, timeline_assets=timeline, idempotency_key="promotion-command")
        assert promoted["promotion"]["superseded_item_id"] == "old"
        assert {entry["item_id"] for entry in promoted["invalidation"]["stale"]} >= {"plate", "proxy"}
        assert "timeline-1" in {entry.get("asset_id") for entry in promoted["invalidation"]["stale"]}
        assert promoted.receipt["result"] == {
            "promotion": promoted["promotion"],
            "invalidation": promoted["invalidation"],
            "revision_id": promoted["revision_id"],
            "internal_timeline_revision_id": promoted["internal_timeline_revision_id"],
            "content_digest": promoted["content_digest"],
        }
        replay = client.promote_project_shot_candidate(project.project_id, shot.shot_id, "new", expected_head_seq=expected_head, timeline_assets=timeline, idempotency_key="promotion-command")
        assert replay == promoted
        shown = client.get_project_shot(project.project_id, shot.shot_id)
        statuses = [item["metadata"].get("status") for item in shown["items"] if item["metadata"].get("role") == "primary_visual"]
        assert statuses.count("primary") == 1 and "superseded" in statuses
        with pytest.raises(ApiError) as stale:
            client.promote_project_shot_candidate(project.project_id, shot.shot_id, "new", expected_head_seq=expected_head, idempotency_key="promotion-stale")
        assert stale.value.status == 409
    finally:
        daemon.stop()


def test_candidate_provenance_is_verified_before_promotion(tmp_path):
    RealmStore.initialize(tmp_path / "realm").close()
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = client.create_project("Provenance", slug="provenance", idempotency_key="provenance-project")
        obj = client.ingest_project_object(project.project_id, b"candidate", media_type="image/png", idempotency_key="provenance-object")
        shot = catalog_shot(daemon.service, project.project_id, [
            {"item_id": "candidate", "media_id": obj.digest, "metadata": {"role": "primary_visual", "status": "candidate", "provenance": {"project_id": "foreign-project", "shot_id": "shot-1"}}},
        ])
        candidate = shot
        with pytest.raises(ApiError) as failed:
            client.promote_project_shot_candidate(project.project_id, shot.shot_id, "candidate", expected_head_seq=candidate.version, idempotency_key="provenance-promote")
        assert failed.value.status == 422
        assert client.get_project_shot(project.project_id, shot.shot_id)["version"] == candidate.version
    finally:
        daemon.stop()


def test_catalog_promotion_checks_bytes_and_rolls_back_before_receipt(tmp_path, monkeypatch):
    from runtime_protocol.errors import ValidationError
    from runtime_protocol.service import RuntimeService

    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"name": "Bytes", "slug": "bytes"}, idempotency_key="project")["id"]
        media = service.ingest(project, b"candidate", media_type="image/png", idempotency_key="media")["data"]["object_id"]
        shot = catalog_shot(service, project, [
            {"item_id": "old", "media_id": media, "metadata": {"role": "primary_visual", "status": "primary"}},
            {"item_id": "candidate", "media_id": media, "metadata": {"role": "primary_visual", "status": "candidate"}},
        ])
        body = {"candidate_item_id": "candidate", "expected_head_seq": shot.version}
        before = rows(service)
        path = service.cas.path_for(media.removeprefix("sha256:"))
        path.write_bytes(b"corrupted")
        with pytest.raises(ValidationError, match="candidate media is unavailable"):
            service.promote_project_shot_candidate(project, shot.shot_id, body, idempotency_key="promote")
        assert rows(service) == before
        path.write_bytes(b"candidate")
        with monkeypatch.context() as patch:
            def fail_receipt(*args, **kwargs):
                raise RuntimeError("receipt unavailable")
            patch.setattr(service, "_command_record", fail_receipt)
            with pytest.raises(RuntimeError, match="receipt unavailable"):
                service.promote_project_shot_candidate(project, shot.shot_id, body, idempotency_key="promote")
        assert rows(service) == before
        promoted = service.promote_project_shot_candidate(project, shot.shot_id, body, idempotency_key="promote")
        assert promoted["data"]["promotion"]["superseded_item_id"] == "old"
        with pytest.raises(ValidationError, match="status='candidate'"):
            service.promote_project_shot_candidate(project, shot.shot_id,
                {**body, "expected_head_seq": shot.version + 1}, idempotency_key="already-primary")
    finally:
        service.close()


@pytest.mark.integration
def test_catalog_promotion_preserves_accepted_film_and_retries_before_live_guards(editing, monkeypatch):  # noqa: F811 (fixture)
    service, project = editing.service, editing.project
    media = editing.film.fixture.media_ids[0]
    shot = catalog_shot(service, project, [
        {"item_id": "library-old", "media_id": media, "metadata": {"role": "primary_visual", "status": "primary"}},
        {"item_id": "library-new", "media_id": media, "metadata": {"role": "primary_visual", "status": "candidate"}},
    ], shot_id="library")
    # Library identity is explicit; it is not any occurrence-owned destination.
    assert shot.shot_id not in {s["shot_id"] for s in editing.document()["shot_revisions"]}
    before = editing.head(), editing.document(), editing.history()
    body = {"candidate_item_id": "library-new", "expected_head_seq": shot.version}
    result = service.promote_project_shot_candidate(project, shot.shot_id, body, idempotency_key="library-promotion")
    assert (editing.head(), editing.document(), editing.history()) == before
    assert service.get_project_shot(project, shot.shot_id)["version"] == shot.version + 1
    assert result["receipt"]["result"] == result["data"]
    from runtime_protocol.errors import ConflictError
    from runtime_protocol.service import RuntimeService
    service.close()
    restarted = RuntimeService(editing.film.fixture.duplicate_root)
    try:
        before_retry = rows(restarted)
        monkeypatch.setattr(restarted.store, "get_project", lambda *_: pytest.fail("retry read current project"))
        monkeypatch.setattr(restarted.cas, "read", lambda *_: pytest.fail("retry read current media"))
        assert restarted.promote_project_shot_candidate(project, shot.shot_id, body, idempotency_key="library-promotion") == result
        with pytest.raises(ConflictError):
            restarted.promote_project_shot_candidate(project, shot.shot_id, {**body, "expected_head_seq": shot.version + 1}, idempotency_key="library-promotion")
        assert rows(restarted) == before_retry
    finally:
        restarted.close()


@pytest.mark.integration
def test_catalog_promotion_prevents_native_overwrite_after_historical_reuse(editing):  # noqa: F811 (fixture)
    from runtime_protocol.errors import RuntimeErrorBase

    original = editing.document()
    owner = "occurrence:occurrence-3/clip:clip-3"
    move = editing.agent.move(editing.agent.bundle(original), owner, 3.5)
    first_body = editing.body([move])
    first = editing.commit(first_body, "slot-move")
    pin = {k: original["parent_revision"][k] for k in ("revision_id", "content_digest")}
    restore = {"schema_version": 1, "op": "timeline.restore", "version": "1", "select": None, "args": pin}
    editing.commit(editing.body([restore]), "slot-restore-before-catalog")
    move = editing.agent.move(editing.agent.bundle(editing.document()), owner, 3.6)
    second = editing.commit(editing.body([move]), "slot-rematerialize-before-catalog")
    document = second["data"]["canonical_document"]
    occurrence = next(o for o in document["parent_revision"]["payload"]["occurrences"] if o["occurrence_id"] == "occurrence-3")
    slot_id = occurrence["shot_id"]
    source_id = next(o["shot_id"] for o in original["parent_revision"]["payload"]["occurrences"] if o["occurrence_id"] == "occurrence-3")
    assert slot_id == source_id  # This normal film has an exclusive occurrence owner.
    media = editing.film.fixture.media_ids[0]
    slot = catalog_shot(editing.service, editing.project, [
        {"item_id": "slot-candidate", "media_id": media, "metadata": {"role": "primary_visual", "status": "candidate"}},
    ], shot_id=slot_id)
    promoted = editing.service.promote_project_shot_candidate(editing.project, slot_id,
        {"candidate_item_id": "slot-candidate", "expected_head_seq": slot.version}, idempotency_key="slot-promotion")
    catalog = editing.service.get_project_shot(editing.project, slot_id)
    assert editing.document() == document
    assert editing.commit(first_body, "slot-move") == first
    # A direct update of a currently pinned slot also cannot erase newer catalog intent.
    move = editing.agent.move(editing.agent.bundle(editing.document()), owner, 3.7)
    before = rows(editing.service)
    with pytest.raises(RuntimeErrorBase) as error:
        editing.commit(editing.body([move]), "slot-overwrite-current")
    assert error.value.details["reason"] == "destination_occupied"
    assert rows(editing.service) == before
    editing.commit(editing.body([restore]), "slot-restore")
    # Exact historical reuse preserves both source and newer global slot head (C4).
    assert editing.document()["shot_revisions"] == original["shot_revisions"]
    assert editing.service.get_project_shot(editing.project, slot_id) == catalog
    assert editing.service.store.conn.execute("SELECT revision_id FROM shot_revision_heads WHERE shot_id=?", (slot_id,)).fetchone()[0] == promoted["data"]["revision_id"]
    move = editing.agent.move(editing.agent.bundle(editing.document()), owner, 3.8)
    before = rows(editing.service)
    with pytest.raises(RuntimeErrorBase) as error:
        editing.commit(editing.body([move]), "slot-overwrite-historical")
    assert error.value.details["reason"] == "destination_occupied"
    assert rows(editing.service) == before
