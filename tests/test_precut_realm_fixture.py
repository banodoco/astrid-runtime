from __future__ import annotations

import hashlib
import json
import sqlite3

from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_baseline import verify_baseline

from precut_realm_fixture import (
    ARCHIVE,
    FIXTURE_LABEL,
    SCHEMA_VERSION,
    load_precut_realm_fixture,
    readonly_tree_digest,
)


def _read_facts(root, pins):
    service = RuntimeService(root)
    try:
        baseline = verify_baseline(
            service.store.conn,
            pins["project_id"],
            pins["timeline_id"],
            read_object=lambda digest: service.object(digest)[1],
        )
        return {
            "project": service.get_project(pins["project_id"]),
            "parent": service.get_project_parent_composition_revision(
                pins["project_id"], pins["timeline_id"], pins["parent_revision_id"]
            ),
            "document": service.get_document(pins["project_id"], pins["transcript_document_id"]),
            "binding": service.get_project_shot_text_binding(
                pins["project_id"], pins["text_binding_id"]
            ),
            "reference": service.get_project_reference(
                pins["project_id"], pins["reference_id"]
            ),
            "baseline": baseline,
        }
    finally:
        service.close()


def test_archive_is_schema31_labeled_and_backup_verified(tmp_path):
    fixture = load_precut_realm_fixture(tmp_path)

    assert ARCHIVE.stat().st_size < 200_000
    assert FIXTURE_LABEL == "schema31/pre-cut80973d3"
    assert fixture.manifest["format_version"] == 2
    assert fixture.manifest["schema"]["version"] == SCHEMA_VERSION
    assert fixture.manifest["realm"]["id"] == "synthetic-film-realm"
    assert fixture.manifest["database_sha256"]
    assert fixture.manifest["cas_manifest_sha256"]

    for root in fixture.copy_roots:
        assert (root / "activation-handoff.json").is_file()
        assert (root / "realm.sqlite3").is_file()
        assert (root / "cas" / "sha256").is_dir()
        handoff = json.loads((root / "activation-handoff.json").read_text())
        assert handoff["source_manifest_sha256"] == hashlib.sha256(
            (fixture.backup_root / "manifest.json").read_bytes()
        ).hexdigest()
        assert handoff["candidate_database_sha256"] == fixture.manifest["database_sha256"]


def test_restored_copies_preserve_publication_closure_media_and_legacy_reference(tmp_path):
    fixture = load_precut_realm_fixture(tmp_path)
    facts = [_read_facts(root, fixture.pins) for root in fixture.copy_roots]

    assert [item["parent"]["revision_id"] for item in facts] == [fixture.pins["parent_revision_id"]] * 2
    assert all(item["parent"]["payload"]["occurrences"] for item in facts)
    assert all(item["parent"]["payload"]["clips"][0]["effects"] for item in facts)
    assert all(item["parent"]["payload"]["clips"][0]["asset"] == "music-bed" for item in facts)
    assert all(item["document"]["content"]["media_id"] in fixture.pins["media_ids"] for item in facts)
    assert all(item["binding"]["media_id"] == fixture.pins["text_binding_media_id"] for item in facts)
    assert all(item["binding"]["kind"] == "transcript" for item in facts)
    assert all(item["reference"]["reference_id"] == fixture.pins["reference_id"] for item in facts)
    assert all(
        any(
            association["association_id"] == fixture.pins["association_id"]
            and association["media_id"] == fixture.pins["association_media_id"]
            for association in item["reference"]["media_references"]
        )
        for item in facts
    )
    assert all(
        item["baseline"]["head"]["publication_id"] == fixture.pins["publication_receipt_id"]
        for item in facts
    )


def test_two_restored_copies_have_independent_owner_locks_and_readonly_stable_bytes(tmp_path):
    fixture = load_precut_realm_fixture(tmp_path)
    before = [readonly_tree_digest(root) for root in fixture.copy_roots]
    assert before[0] == before[1] == readonly_tree_digest(fixture.backup_root)
    first = RuntimeService(fixture.copy_roots[0])
    second = RuntimeService(fixture.copy_roots[1])
    try:
        assert first.store.realm["id"] == second.store.realm["id"] == "synthetic-film-realm"
        assert first.store._lock_file is not second.store._lock_file
        assert first.get_project(fixture.pins["project_id"])["id"] == fixture.pins["project_id"]
        assert second.get_project(fixture.pins["project_id"])["id"] == fixture.pins["project_id"]
        for service in (first, second):
            changes = service.store.conn.total_changes
            verify_baseline(
                service.store.conn,
                fixture.pins["project_id"],
                fixture.pins["timeline_id"],
                read_object=lambda digest: service.object(digest)[1],
            )
            assert service.store.conn.total_changes == changes
    finally:
        first.close()
        second.close()


def test_archive_retains_event_receipt_and_closure_provenance_bytes(tmp_path):
    fixture = load_precut_realm_fixture(tmp_path)
    database = fixture.copy_roots[0] / "realm.sqlite3"
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        event = connection.execute(
            "SELECT payload_json FROM timeline_events WHERE id=?",
            (fixture.pins["publication_event_id"],),
        ).fetchone()
        receipt = connection.execute(
            "SELECT txn_id, event_ids_json FROM command_idempotency WHERE txn_id=?",
            (fixture.pins["publication_receipt_id"],),
        ).fetchone()
        assert event is not None and receipt is not None
        assert json.loads(receipt["event_ids_json"]) == list(fixture.pins["publication_event_ids"])
        assert fixture.pins["publication_event_id"] == fixture.pins["publication_event_ids"][0]
        assert json.loads(event["payload_json"]) == fixture.pins["publication_payload"]
    finally:
        connection.close()
