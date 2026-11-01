from __future__ import annotations

import copy
import hashlib
import sqlite3
from dataclasses import replace

import pytest

from runtime_protocol.errors import ConflictError, NotFoundError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_inputs import (
    CapturedDocument,
    DocumentInputLink,
    capture_document_input,
    content_digest,
    initialize_document_input_schema,
    persist_document_input_links,
    reachable_document_input_pins,
    validate_captured_document_inputs,
)


@pytest.fixture
def service(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    value = RuntimeService(root)
    initialize_document_input_schema(value.store.conn)
    yield value
    value.close()


def _project(service, name):
    return service.create_project({"name": name, "slug": name.lower()})


def _media(service, project_id, payload=b"source media"):
    return service.ingest(
        project_id,
        payload,
        media_type="video/mp4",
        idempotency_key=f"media-{project_id}-{hashlib.sha256(payload).hexdigest()[:12]}",
    )["data"]["object_id"]


def _transcript(service, project_id, media_id, text="hello"):
    content = {
        "schema": "media.transcript/v1",
        "media_id": media_id,
        "source_id": "default",
        "segments": [{
            "id": "segment-1",
            "start": 0.0,
            "end": 1.0,
            "text": text,
            "words": [{"id": "word-1", "start": 0.0, "end": 1.0, "text": text}],
        }],
    }
    document_id = RuntimeService._transcript_document_id(project_id, media_id, "default")
    resource = service.create_document(
        project_id,
        {"document_id": document_id, "kind": "media.transcript", "content": content},
        idempotency_key="create-transcript",
    )["data"]
    return resource, content


def _pin(resource):
    return {
        "document_id": resource["document_id"],
        "version": resource["version"],
        "content_digest": content_digest(resource["content"]),
    }


def _retain(service, project_id, resource, *, publication, revision, kind="transcript", timeline="timeline-1"):
    capture = capture_document_input(
        service.store.conn,
        project_id,
        _pin(resource),
        expected_kind=resource["kind"],
        expected_schema="media.transcript/v1" if resource["kind"] == "media.transcript" else "pack.config/v1",
    )
    persist_document_input_links(
        service.store.conn,
        project_id=project_id,
        timeline_id=timeline,
        publication_id=publication,
        revision_id=revision,
        links=[(capture, kind)],
    )
    return capture


def _counts(connection):
    return tuple(
        connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        for table in (
            "timeline_document_input_contents",
            "timeline_document_input_bindings",
            "timeline_document_input_links",
        )
    )


def test_transcript_v1_is_retained_after_v2_and_database_reopen(service):
    project = _project(service, "Transcript")
    media_id = _media(service, project["id"])
    first, first_content = _transcript(service, project["id"], media_id, "v1")
    first_pin = _pin(first)
    _retain(service, project["id"], first, publication="pub-1", revision="rev-1")

    second_content = copy.deepcopy(first_content)
    second_content["segments"][0]["text"] = "v2"
    service.update_document(
        project["id"],
        first["document_id"],
        {"expected_version": 1, "content": second_content},
        idempotency_key="transcript-v2",
    )
    db_path = service.store.db_path
    service.close()

    reopened = sqlite3.connect(db_path)
    reopened.row_factory = sqlite3.Row
    try:
        initialize_document_input_schema(reopened)
        reachable = reachable_document_input_pins(
            reopened, project["id"], "timeline-1", revision_ids=["rev-1"]
        )
        restored = capture_document_input(
            reopened, project["id"], first_pin,
            reachable_pins=reachable,
            expected_kind="media.transcript",
            expected_schema="media.transcript/v1",
        )
        assert restored.retained is True
        assert restored.document["version"] == 1
        assert restored.document["content"] == first_content
        assert restored.document["created_at"] == first["created_at"]
        assert restored.document["updated_at"] == first["updated_at"]
    finally:
        reopened.close()


def test_config_input_retention_reuses_identical_content_bytes(service):
    owner = _project(service, "Config owner")
    other = _project(service, "Config other")
    content = {"schema": "pack.config/v1", "enabled": True, "threshold": 3}
    owner_doc = service.create_document(
        owner["id"], {"document_id": "pack.config-owner", "kind": "pack.config", "content": content},
        idempotency_key="config-owner",
    )["data"]
    other_doc = service.create_document(
        other["id"], {"document_id": "pack.config-other", "kind": "pack.config", "content": content},
        idempotency_key="config-other",
    )["data"]

    _retain(service, owner["id"], owner_doc, publication="pub-config-1", revision="rev-config-1", kind="source")
    _retain(service, other["id"], other_doc, publication="pub-config-2", revision="rev-config-2", kind="source")
    assert service.store.conn.execute(
        "SELECT COUNT(*) FROM timeline_document_input_contents"
    ).fetchone()[0] == 1
    assert service.store.conn.execute(
        "SELECT COUNT(*) FROM timeline_document_input_bindings"
    ).fetchone()[0] == 2

    changed = {**content, "threshold": 4}
    service.update_document(
        owner["id"], owner_doc["document_id"],
        {"expected_version": 1, "content": changed}, idempotency_key="config-v2",
    )
    retained = capture_document_input(
        service.store.conn, owner["id"], _pin(owner_doc),
        reachable_pins=reachable_document_input_pins(
            service.store.conn, owner["id"], "timeline-1", revision_ids=["rev-config-1"]
        ),
        expected_kind="pack.config", expected_schema="pack.config/v1",
    )
    assert retained.document["content"] == content


def test_first_use_capture_rejects_update_race_without_snapshots(service):
    project = _project(service, "Race")
    media_id = _media(service, project["id"])
    resource, content = _transcript(service, project["id"], media_id, "before")
    capture = capture_document_input(
        service.store.conn, project["id"], _pin(resource),
        expected_kind="media.transcript", expected_schema="media.transcript/v1",
    )
    changed = copy.deepcopy(content)
    changed["segments"][0]["text"] = "after"
    service.update_document(
        project["id"], resource["document_id"],
        {"expected_version": 1, "content": changed}, idempotency_key="race-update",
    )
    with pytest.raises(ConflictError, match="changed"):
        persist_document_input_links(
            service.store.conn,
            project_id=project["id"], timeline_id="timeline-race",
            publication_id="pub-race", revision_id="rev-race",
            links=[(capture, "transcript")],
        )
    assert _counts(service.store.conn) == (0, 0, 0)


def test_rejected_batch_rolls_back_all_content_bindings_and_links(service):
    project = _project(service, "Rollback")
    media_id = _media(service, project["id"])
    resource, _ = _transcript(service, project["id"], media_id)
    valid = capture_document_input(
        service.store.conn, project["id"], _pin(resource),
        expected_kind="media.transcript", expected_schema="media.transcript/v1",
    )
    invalid = replace(valid, pin={**valid.pin, "content_digest": "sha256:" + "0" * 64})
    with pytest.raises(ConflictError):
        persist_document_input_links(
            service.store.conn,
            project_id=project["id"], timeline_id="timeline-rollback",
            publication_id="pub-rollback", revision_id="rev-rollback",
            links=[(valid, "transcript"), (invalid, "transcript")],
        )
    assert _counts(service.store.conn) == (0, 0, 0)


def test_foreign_guessed_and_revoked_source_pins_are_denied(service):
    owner = _project(service, "Owner")
    foreign = _project(service, "Foreign")
    media_id = _media(service, owner["id"])
    resource, _ = _transcript(service, owner["id"], media_id)
    pin = _pin(resource)

    with pytest.raises(NotFoundError):
        capture_document_input(
            service.store.conn, foreign["id"], pin,
            expected_kind="media.transcript", expected_schema="media.transcript/v1",
        )
    with pytest.raises(NotFoundError):
        capture_document_input(
            service.store.conn, owner["id"], {**pin, "content_digest": "sha256:" + "f" * 64},
            expected_kind="media.transcript", expected_schema="media.transcript/v1",
        )
    service.store.conn.execute(
        "DELETE FROM project_objects WHERE project_id=? AND digest=? AND relation='managed'",
        (owner["id"], media_id.removeprefix("sha256:")),
    )
    with pytest.raises(ConflictError, match="managed"):
        capture_document_input(
            service.store.conn, owner["id"], pin,
            expected_kind="media.transcript", expected_schema="media.transcript/v1",
        )


def test_retained_lookup_requires_reachability_and_rejects_missing_or_corrupt_bytes(service):
    project = _project(service, "Integrity")
    media_id = _media(service, project["id"])
    resource, _ = _transcript(service, project["id"], media_id)
    _retain(service, project["id"], resource, publication="pub-integrity", revision="rev-integrity")
    pin = _pin(resource)
    with pytest.raises(ConflictError, match="outside"):
        capture_document_input(
            service.store.conn, project["id"], pin,
            expected_kind="media.transcript", expected_schema="media.transcript/v1",
        )

    service.store.conn.execute(
        "UPDATE timeline_document_input_contents SET content_json=? WHERE content_digest=?",
        ("{\"corrupt\":true}", pin["content_digest"]),
    )
    reachable = reachable_document_input_pins(
        service.store.conn, project["id"], "timeline-1", revision_ids=["rev-integrity"]
    )
    with pytest.raises(ConflictError, match="corrupt|digest"):
        capture_document_input(
            service.store.conn, project["id"], pin, reachable_pins=reachable,
            expected_kind="media.transcript", expected_schema="media.transcript/v1",
        )


@pytest.mark.parametrize("corruption, message", [("missing", "missing"), ("corrupt", "digest|corrupt")])
def test_retained_capture_does_not_heal_missing_or_corrupt_content(service, corruption, message):
    project = _project(service, "No healing")
    media_id = _media(service, project["id"])
    resource, _ = _transcript(service, project["id"], media_id)
    _retain(service, project["id"], resource, publication="pub-existing", revision="rev-existing")
    pin = _pin(resource)
    reachable = reachable_document_input_pins(
        service.store.conn, project["id"], "timeline-1", revision_ids=["rev-existing"]
    )
    capture = capture_document_input(
        service.store.conn, project["id"], pin, reachable_pins=reachable,
        expected_kind="media.transcript", expected_schema="media.transcript/v1",
    )

    if corruption == "missing":
        service.store.conn.execute("PRAGMA foreign_keys=OFF")
        service.store.conn.execute(
            "DELETE FROM timeline_document_input_contents WHERE content_digest=?", (pin["content_digest"],)
        )
        service.store.conn.commit()
        service.store.conn.execute("PRAGMA foreign_keys=ON")
    else:
        service.store.conn.execute(
            "UPDATE timeline_document_input_contents SET content_json=? WHERE content_digest=?",
            ('{"schema":"media.transcript/v1","media_id":"sha256:' + "0" * 64 + '","source_id":"default"}',
             pin["content_digest"]),
        )
    service.store.conn.commit()

    with pytest.raises(ConflictError, match=message):
        validate_captured_document_inputs(service.store.conn, [capture])
    with pytest.raises(ConflictError, match=message):
        persist_document_input_links(
            service.store.conn,
            project_id=project["id"], timeline_id="timeline-1",
            publication_id="pub-new", revision_id="rev-new",
            links=[DocumentInputLink(capture, "transcript", 0)],
        )
    assert service.store.conn.execute(
        "SELECT COUNT(*) FROM timeline_document_input_links WHERE publication_id='pub-new'"
    ).fetchone()[0] == 0
    stored = service.store.conn.execute(
        "SELECT content_json FROM timeline_document_input_contents WHERE content_digest=?", (pin["content_digest"],)
    ).fetchone()
    if corruption == "missing":
        assert stored is None
    else:
        assert stored is not None
        assert '"media_id":"sha256:' + "0" * 64 + '"' in stored[0]


def test_stored_source_header_mismatch_is_refused_at_accept(service):
    project = _project(service, "Source header")
    media_id = _media(service, project["id"])
    resource, _ = _transcript(service, project["id"], media_id)
    _retain(service, project["id"], resource, publication="pub-existing", revision="rev-existing")
    pin = _pin(resource)
    capture = capture_document_input(
        service.store.conn, project["id"], pin,
        reachable_pins=reachable_document_input_pins(
            service.store.conn, project["id"], "timeline-1", revision_ids=["rev-existing"]
        ),
        expected_kind="media.transcript", expected_schema="media.transcript/v1",
    )
    service.store.conn.execute(
        "UPDATE timeline_document_input_bindings SET source_media_id=? "
        "WHERE project_id=? AND document_id=? AND document_version=? AND content_digest=?",
        ("sha256:" + "f" * 64, project["id"], pin["document_id"], pin["version"], pin["content_digest"]),
    )
    service.store.conn.commit()

    with pytest.raises(ConflictError, match="source identity"):
        validate_captured_document_inputs(service.store.conn, [capture])
    with pytest.raises(ConflictError, match="source identity"):
        persist_document_input_links(
            service.store.conn,
            project_id=project["id"], timeline_id="timeline-1",
            publication_id="pub-new", revision_id="rev-new",
            links=[DocumentInputLink(capture, "transcript", 0)],
        )


@pytest.mark.parametrize("column, value", [("updated_at", "race-updated"), ("kind", "media.other")])
def test_first_use_capture_rechecks_exact_header(service, column, value):
    project = _project(service, "Header race")
    media_id = _media(service, project["id"])
    resource, _ = _transcript(service, project["id"], media_id)
    capture = capture_document_input(
        service.store.conn, project["id"], _pin(resource),
        expected_kind="media.transcript", expected_schema="media.transcript/v1",
    )
    service.store.conn.execute(
        f"UPDATE project_documents SET {column}=? WHERE project_id=? AND id=?",
        (value, project["id"], resource["document_id"]),
    )
    service.store.conn.commit()

    with pytest.raises(ConflictError, match="header|kind"):
        validate_captured_document_inputs(service.store.conn, [capture])
    with pytest.raises(ConflictError, match="header|kind"):
        persist_document_input_links(
            service.store.conn,
            project_id=project["id"], timeline_id="timeline-race",
            publication_id="pub-race", revision_id="rev-race",
            links=[DocumentInputLink(capture, "transcript", 0)],
        )
    assert _counts(service.store.conn) == (0, 0, 0)


def test_document_input_link_instance_is_strictly_validated(service):
    project = _project(service, "Link validation")
    media_id = _media(service, project["id"])
    resource, _ = _transcript(service, project["id"], media_id)
    capture = capture_document_input(
        service.store.conn, project["id"], _pin(resource),
        expected_kind="media.transcript", expected_schema="media.transcript/v1",
    )

    for link in (DocumentInputLink(capture, "other", 0), DocumentInputLink(capture, "transcript", True)):
        with pytest.raises(ValidationError):
            persist_document_input_links(
                service.store.conn,
                project_id=project["id"], timeline_id="timeline-link",
                publication_id="pub-link", revision_id="rev-link", links=[link],
            )
