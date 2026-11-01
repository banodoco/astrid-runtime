"""Permanent custody regressions for the project-shot catalog boundary."""
from __future__ import annotations

import copy
import json

import pytest

from runtime_protocol.errors import ConflictError, RetiredRouteError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_store import TimelineCommitStore, digest

from test_timeline_commit_acceptance import context, prepared, validate_prepared


def _snapshot(service):
    with service.store._mutex:
        database = tuple(service.store.conn.iterdump())
        cas = {
            str(path.relative_to(service.store.cas_root)): path.read_bytes()
            for path in service.store.cas_root.rglob("*")
            if path.is_file()
        }
        staging = {
            str(path.relative_to(service.store.staging_root)): path.read_bytes()
            for path in service.store.staging_root.rglob("*")
            if path.is_file()
        }
        return database, cas, staging, service.store.conn.total_changes


def _canonical_shot_candidate(service, commits, project_id, shot_id, head, *, name, metadata):
    request = context(service, project_id, head, key="place-" + shot_id, op="fixture.place-shot")
    candidate = prepared(commits, request, revision="placed-" + shot_id)
    document = candidate["canonical_document"]
    internal = {
        "timeline_id": f"shot:{shot_id}",
        "revision_id": f"internal-{shot_id}",
        "payload": {"clips": [], "tracks": [], "opaque": {"fixture": True}},
    }
    internal["content_digest"] = digest(internal["payload"])
    shot = {
        "shot_id": shot_id,
        "revision_id": f"shot-{shot_id}",
        "payload": {
            "name": name,
            "metadata": copy.deepcopy(metadata),
            "internal_timeline_revision_id": internal["revision_id"],
            "items": [],
        },
        "internal_timeline_revision_id": internal["revision_id"],
    }
    shot["content_digest"] = digest(shot["payload"])
    document["shot_revisions"].append(shot)
    document["internal_timeline_revisions"].append(internal)
    document["parent_revision"]["payload"]["occurrences"].append({
        "occurrence_id": "occ-" + shot_id,
        "shot_id": shot_id,
        "shot_revision_id": shot["revision_id"],
        "placement": {"start_ms": 0, "track": "picture"},
        "duration_ms": 1000,
        "source_offset": 0,
        "speed": {"numerator": 1, "denominator": 1},
        "track": "picture",
        "transform": {},
        "gain": 1,
        "muted": False,
        "provenance": {},
    })
    document["dependency_manifest"]["shots"] = [
        {key: value[key] for key in ("shot_id", "revision_id", "internal_timeline_revision_id", "content_digest")}
        for value in document["shot_revisions"]
    ]
    document["dependency_manifest"]["internal_timelines"] = [
        {key: value[key] for key in ("timeline_id", "revision_id", "content_digest")}
        for value in document["internal_timeline_revisions"]
    ]
    document["parent_revision"]["content_digest"] = digest(document["parent_revision"]["payload"])
    candidate["document_digest"] = digest(document)
    return candidate


def test_same_project_archived_legacy_film_membership_refuses_without_writes(tmp_path):
    RealmStore.initialize(tmp_path / "realm").close()
    service = RuntimeService(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "legacy", "name": "Legacy"})["id"]
        service.create_project_shot(
            project, {"shot_id": "legacy-shot", "name": "Shot"}, idempotency_key="legacy-shot"
        )
        service.create_timeline(project, "legacy-film", idempotency_key="legacy-film")
        # These are the two persisted legacy film projections named by the
        # review. They are fixture state in an ephemeral realm, not accepted
        # command history or a fabricated receipt.
        with service.store._transaction():
            service.store.conn.execute(
                "INSERT INTO timeline_shots(id, timeline_id, start_ms, duration_ms, reference_ids_json) "
                "VALUES (?, ?, 0, 1000, '[]')",
                ("legacy-shot", "legacy-film"),
            )
            service.store.conn.execute(
                "INSERT INTO timeline_revisions(timeline_id, version, shots_json, references_json, created_at) "
                "VALUES (?, 2, ?, '[]', ?)",
                ("legacy-film", json.dumps([{"shot_id": "legacy-shot"}]), "2026-01-01T00:00:00Z"),
            )
        service.archive_timeline("legacy-film", {"expected_version": 1}, idempotency_key="archive-legacy-film")
        assert service.store.conn.execute(
            "SELECT project_id, archived_at FROM timelines WHERE id=?", ("legacy-film",)
        ).fetchone()["project_id"] == project
        assert service.store.conn.execute(
            "SELECT archived_at FROM timelines WHERE id=?", ("legacy-film",)
        ).fetchone()["archived_at"] is not None
        before = _snapshot(service)

        with pytest.raises(RetiredRouteError) as error:
            service.update_project_shot(
                project,
                "legacy-shot",
                {"expected_version": 1, "name": "must-refuse"},
                idempotency_key="legacy-update",
            )
        assert error.value.details["reason"] == "shot_in_film_history"
        assert _snapshot(service) == before
    finally:
        service.close()


def test_catalog_receipt_replays_after_canonical_film_placement_without_writes(tmp_path):
    RealmStore.initialize(tmp_path / "realm").close()
    service = RuntimeService(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "replay", "name": "Replay"})["id"]
        service.create_timeline(project, "main", idempotency_key="main")
        commits = TimelineCommitStore(service.store, validate_prepared=validate_prepared)
        head = commits.bootstrap(project, "main", authorize=lambda: None)
        service.create_project_shot(
            project,
            {"shot_id": "replay-shot", "name": "Shot", "metadata": {"source": "catalog"}},
            idempotency_key="replay-shot",
        )
        body = {"expected_version": 1, "name": "Catalog name", "metadata": {"source": "catalog"}}
        first = service.update_project_shot(project, "replay-shot", body, idempotency_key="catalog-update")
        assert first["receipt"]["command_kind"] == "shot.update"

        candidate = _canonical_shot_candidate(
            service,
            commits,
            project,
            "replay-shot",
            head,
            name=first["data"]["name"],
            metadata=first["data"]["metadata"],
        )
        # The existing closure persistence helper is the supported test setup
        # for an accepted canonical film projection; keep it inside this
        # ephemeral realm and do not manufacture a receipt or event history.
        with service.store._transaction():
            commits._persist_closure(candidate["canonical_document"])
        history = commits.revision_closure(
            project, "main", candidate["canonical_document"]["parent_revision"]["revision_id"]
        )
        assert any(item["shot_id"] == "replay-shot" for item in history["shot_revisions"])
        assert any(item["shot_id"] == "replay-shot" for item in history["parent_revision"]["payload"]["occurrences"])

        before_retry = _snapshot(service)
        assert service.update_project_shot(
            project, "replay-shot", body, idempotency_key="catalog-update"
        ) == first
        assert _snapshot(service) == before_retry

        with pytest.raises(ConflictError):
            service.update_project_shot(
                project,
                "replay-shot",
                {**body, "name": "changed-under-same-key"},
                idempotency_key="catalog-update",
            )
        assert _snapshot(service) == before_retry
    finally:
        service.close()
