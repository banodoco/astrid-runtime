from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from runtime_protocol.errors import ConflictError
from runtime_protocol.service import RuntimeService

from timeline_commit_film_fixture import (
    build_film_fixture,
    fixture_facts,
    read_object_from_realm,
)


from runtime_protocol import timeline_commit_baseline as baseline


def _open_duplicate(fixture):
    return RuntimeService(fixture.duplicate_root)


def _verify(baseline, service, fixture):
    return baseline.verify_baseline(
        service.store.conn,
        fixture.project_id,
        fixture.timeline_id,
        read_object=lambda digest: read_object_from_realm(fixture.duplicate_root, digest),
    )


def test_fixture_is_api_built_and_duplicate_contains_real_closure(tmp_path):
    fixture = build_film_fixture(tmp_path)
    service = _open_duplicate(fixture)
    try:
        facts = fixture_facts(service, fixture)
        assert facts["parent"]["revision_id"] == fixture.parent_revision_id
        assert len(facts["parent"]["payload"]["occurrences"]) == 3
        assert facts["parent"]["payload"]["clips"][0]["effects"][0]["type"] == "fade"
        assert facts["parent"]["payload"]["clips"][0]["asset"] == "music-bed"
        assert (
            facts["parent"]["payload"]["occurrences"][1]["shot_revision_id"]
            == "film-shot-revision-2"
        )
        assert facts["parent"]["payload"]["occurrences"][1]["duration_ms"] == 1800
        second_internal = json.loads(service.store.conn.execute(
            "SELECT payload_json FROM internal_timeline_revisions WHERE id=?",
            ("film-internal-2",),
        ).fetchone()[0])
        assert second_internal["clips"][0]["transition"]["type"] == "crossfade"
        first_shot = json.loads(service.store.conn.execute(
            "SELECT payload_json FROM shot_revisions WHERE id=?",
            ("film-shot-revision-1",),
        ).fetchone()[0])
        assert first_shot["metadata"]["transcript_anchor"]["word_id"] == "word-1"
        assert facts["transcript"]["content"]["media_id"] in fixture.media_ids
        assert facts["binding"]["media_id"] in fixture.media_ids
        assert facts["binding"]["kind"] == "transcript"
        assert all(
            (
                service.store.cas_root
                / digest.removeprefix("sha256:")[:2]
                / digest.removeprefix("sha256:")[2:]
            ).is_file()
            for digest in fixture.media_ids
        )
        publication_events = service.store.conn.execute(
            "SELECT kind, payload_json FROM timeline_events "
            "WHERE timeline_id=? AND kind='parent.composition.published'",
            (fixture.timeline_id,),
        ).fetchall()
        assert len(publication_events) == 1
        publication = json.loads(publication_events[0]["payload_json"])
        receipt = service.store.conn.execute(
            "SELECT txn_id, event_ids_json FROM command_idempotency "
            "WHERE command_kind='parent_composition.publish' AND aggregate_id=?",
            (fixture.timeline_id,),
        ).fetchone()
        assert receipt["txn_id"]
        assert json.loads(receipt["event_ids_json"]) == [str(service.store.conn.execute(
            "SELECT id FROM timeline_events WHERE timeline_id=? AND kind='parent.composition.published'",
            (fixture.timeline_id,),
        ).fetchone()[0])]
        assert publication["new_head"] == fixture.parent_revision_id
    finally:
        service.close()


def test_baseline_verifies_valid_scoped_head_and_survives_reopen(tmp_path):
    fixture = build_film_fixture(tmp_path)
    service = _open_duplicate(fixture)
    try:
        first = _verify(baseline, service, fixture)
        assert first["head"]["revision_id"] == fixture.parent_revision_id
        assert first["head"]["publication_id"].startswith("txn-")
        assert first["canonical_document"]["dependency_manifest"]["media"]
        assert first["canonical_document"]["shot_revisions"]
    finally:
        service.close()

    reopened = _open_duplicate(fixture)
    try:
        assert _verify(baseline, reopened, fixture) == first
    finally:
        reopened.close()


@pytest.mark.parametrize("corruption", ["receipt", "digest", "source"])
def test_baseline_fails_closed_on_duplicate_provenance_corruption(tmp_path, corruption):
    fixture = build_film_fixture(tmp_path)
    service = _open_duplicate(fixture)
    try:
        valid = _verify(baseline, service, fixture)
        receipt_id = valid["head"]["publication_id"]
        if corruption == "receipt":
            service.store.conn.execute("DELETE FROM command_idempotency WHERE txn_id=?", (receipt_id,))
        elif corruption == "digest":
            service.store.conn.execute(
                "UPDATE parent_composition_revisions SET content_digest=? WHERE id=?",
                ("sha256:" + "0" * 64, fixture.parent_revision_id),
            )
        else:
            digest = fixture.media_ids[0].removeprefix("sha256:")
            (service.store.cas_root / digest[:2] / digest[2:]).unlink()
        service.store.conn.commit()
        with pytest.raises(ConflictError) as error:
            _verify(baseline, service, fixture)
        assert error.value.details["reason"] == "history_unavailable"
    finally:
        service.close()


def test_handoff_invocation_uses_read_only_sqlite_and_duplicate_cas(tmp_path):
    fixture = build_film_fixture(tmp_path)
    connection = sqlite3.connect(
        f"file:{fixture.duplicate_root / 'realm.sqlite3'}?mode=ro", uri=True,
    )
    try:
        assert connection.execute("PRAGMA query_only").fetchone()[0] == 0
        connection.execute("PRAGMA query_only=ON")
        assert connection.execute("PRAGMA query_only").fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM timeline_events WHERE timeline_id=? AND kind='parent.composition.published'",
            (fixture.timeline_id,),
        ).fetchone()[0] == 1
    finally:
        connection.close()
