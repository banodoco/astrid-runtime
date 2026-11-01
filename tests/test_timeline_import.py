from __future__ import annotations

import copy
import hashlib
import io
import json
import sys
from types import SimpleNamespace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "packages" / "python"))
from runtime_protocol.errors import ConflictError, NotFoundError, ValidationError
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.util import canonical_json


def _service(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    project = service.create_project({"slug": "import", "name": "Import"}, idempotency_key="project")
    return service, project["id"]


def _managed(service, project, data, media_type, name, key):
    return service.ingest(project, data, media_type=media_type, original_name=name, idempotency_key=key)["data"]["object_id"]


def _prepared(service, project, timeline="imported", *, text=False, transcript=False):
    shot_id, occurrence_id = timeline + "-shot", timeline + "-occ"
    internal_id = timeline + "-internal-rev"
    shot_revision_id = timeline + "-shot-rev"
    text_bindings = []
    media = []
    shot_pins = []
    if text:
        text_bytes = b"A copied narration line.\n"
        text_id = _managed(service, project, text_bytes, "text/plain", "narration.txt", "media-" + timeline)
        binding_id = service._text_binding_id(project, shot_id, "voiceover_script", None)
        shot_pins.append({
            "binding_id": binding_id, "project_id": project, "shot_id": shot_id,
            "kind": "voiceover_script", "slot": None, "media_id": text_id,
            "event_stream_id": binding_id + ":shot.text_binding", "head": 1,
            "content_hash": text_id, "mime_type": "text/plain", "byte_size": len(text_bytes),
        })
        text_bindings.append({"shot_id": shot_id, "kind": "voiceover_script", "slot": None, "media_id": text_id})
        media.append({"media_id": text_id, "content_digest": text_id})

    transcript_rows = []
    config = {}
    if transcript:
        source_media_id = _managed(service, project, b"audio", "audio/wav", "audio.wav", "audio-" + timeline)
        content = {"schema": "media.transcript/v1", "media_id": source_media_id, "source_id": "whisper", "segments": []}
        document_id = service._transcript_document_id(project, source_media_id, "whisper")
        transcript_rows.append({"document_id": document_id, "kind": "media.transcript", "content": content})
        config = {"bundle": {"transcriptReferences": {"associations": [{"documentId": document_id}]}}}

    internal_payload = {"tracks": [], "clips": [], "effects": [], "audio": [], "layout": {}, "registry": {}, "assets": []}
    internal_digest = service._revision_digest(internal_payload)
    shot_payload = {
        "metadata": {"title": "copied"}, "items": [], "pools": [], "selected_variants": {},
        "provenance": {}, "generation_inputs": {}, "audio_bindings": [], "text_bindings": shot_pins,
        "internal_timeline_revision_id": internal_id,
    }
    shot_digest = service._revision_digest(shot_payload)
    parent = {
        "config": config, "registry": {}, "clips": [],
        "occurrences": [{
            "occurrence_id": occurrence_id, "shot_id": shot_id,
            "shot_revision_id": shot_revision_id, "placement": {"start_ms": 0},
            "source_offset": 0, "duration_ms": 1000, "speed": 1, "track": "video-1",
            "transform": {}, "gain": 1, "muted": False, "provenance": {},
        }],
    }
    parent_digest = service._revision_digest(parent)
    publication = {
        "project_id": project, "timeline_id": timeline, "expected_head": None,
        "parent_revision_id": timeline + "-parent-rev", "content_digest": parent_digest,
        "parent_composition": parent,
        "internal_timeline_revisions": [{"timeline_id": timeline, "revision_id": internal_id, "payload": internal_payload, "content_digest": internal_digest}],
        "shot_revisions": [{"shot_id": shot_id, "revision_id": shot_revision_id, "internal_timeline_revision_id": internal_id, "payload": shot_payload, "content_digest": shot_digest}],
        "dependency_manifest": {
            "shots": [{"shot_id": shot_id, "revision_id": shot_revision_id, "internal_timeline_revision_id": internal_id, "content_digest": shot_digest}],
            "internal_timelines": [{"timeline_id": timeline, "revision_id": internal_id, "content_digest": internal_digest}],
            "media": media,
        },
    }
    return {
        "timeline_id": timeline, "name": "Imported timeline", "publication": publication,
        "transcripts": transcript_rows, "text_bindings": text_bindings,
        "differences": {"missing_effects": [], "different_effects": []},
    }


def test_import_pins_fresh_shot_text_and_is_idempotent(tmp_path):
    service, project = _service(tmp_path)
    prepared = _prepared(service, project, text=True)
    result = service.import_timeline(project, prepared, idempotency_key="import-one")
    assert result["data"]["timeline_id"] == "imported"
    replay = service.import_timeline(project, copy.deepcopy(prepared), idempotency_key="import-one")
    assert replay["data"] == result["data"]
    payload = json.loads(service.store.conn.execute("SELECT payload_json FROM shot_revisions WHERE shot_id=?", ("imported-shot",)).fetchone()[0])
    pin = payload["text_bindings"][0]
    assert pin["shot_id"] == "imported-shot" and pin["project_id"] == project and pin["head"] == 1
    row = service.store.conn.execute("SELECT shot_id, head_seq, media_digest FROM shot_text_bindings WHERE id=?", (pin["binding_id"],)).fetchone()
    assert row["shot_id"] == "imported-shot" and row["head_seq"] == 1 and pin["media_id"] == "sha256:" + row["media_digest"]
    changed = copy.deepcopy(prepared)
    changed["name"] = "Changed body"
    with pytest.raises(ConflictError, match="idempotency key"):
        service.import_timeline(project, changed, idempotency_key="import-one")


def test_import_retries_receipt_accepted_on_main_without_provenance(tmp_path):
    service, project = _service(tmp_path)
    prepared = _prepared(service, project, timeline="legacy-import")
    # Main accepted this request before provenance was added to the contract.
    original_hash = hashlib.sha256(canonical_json({
        "project_id": project, "prepared": prepared,
    }).encode()).hexdigest()
    with service.store._mutex, service.store._transaction():
        original = service._command_record(
            "timeline.import", project, "legacy-key", original_hash,
            {"timeline_id": "legacy-import", "new_head": "legacy-head"}, project_id=project,
        )

    assert service.import_timeline(project, prepared, idempotency_key="legacy-key") == original
    assert service.store.conn.execute("SELECT COUNT(*) FROM timelines").fetchone()[0] == 0
    with pytest.raises(ConflictError, match="idempotency key"):
        service.import_timeline(project, {**prepared, "source": {"via": "app"}},
                                idempotency_key="legacy-key")


def test_import_accepts_minimal_prepare_binding_descriptor(tmp_path):
    service, project = _service(tmp_path)
    prepared = _prepared(service, project, text=True, timeline="minimal-pin")
    pin = prepared["publication"]["shot_revisions"][0]["payload"]["text_bindings"][0]
    for optional in ("project_id", "shot_id", "event_stream_id"):
        pin.pop(optional)
    shot = prepared["publication"]["shot_revisions"][0]
    shot["content_digest"] = service._revision_digest(shot["payload"])
    prepared["publication"]["dependency_manifest"]["shots"][0]["content_digest"] = shot["content_digest"]

    result = service.import_timeline(project, prepared, idempotency_key="minimal-pin-import")

    assert result["data"]["timeline_id"] == "minimal-pin"
    stored = json.loads(service.store.conn.execute("SELECT payload_json FROM shot_revisions WHERE id=?", (shot["revision_id"],)).fetchone()[0])
    assert stored["text_bindings"][0]["binding_id"] == pin["binding_id"]


def test_import_commits_unresolved_unpinned_effect_warning_and_returns_receipt(tmp_path):
    service, project = _service(tmp_path)
    prepared = _prepared(service, project, timeline="missing-effect-warning")
    unresolved = {"packId": "", "kind": "effect", "id": "not-installed", "revision": "", "pinned": False}
    prepared["differences"]["missing_effects"] = [unresolved]

    result = service.import_timeline(project, prepared, idempotency_key="missing-effect-warning")

    assert result["data"]["missing_effects"] == [unresolved]
    assert result["data"]["different_effects"] == []
    assert service.store.conn.execute("SELECT 1 FROM timelines WHERE id=?", (prepared["timeline_id"],)).fetchone()


@pytest.mark.parametrize("via,prepared_object", [("cli", True), ("app", False)])
def test_import_source_and_publication_are_preserved_in_commit_history(tmp_path, via, prepared_object):
    service, project = _service(tmp_path)
    prepared = _prepared(service, project, timeline="source-" + via)
    if prepared_object:
        encoded = canonical_json(prepared).encode("utf-8")
        object_id = _managed(service, project, encoded, "application/json", "prepared.json", "prepared-" + via)
        body = {"prepared_object_id": object_id, "source": {"via": via}}
    else:
        body = {**prepared, "source": {"via": via}}

    imported = service.import_timeline(project, body, idempotency_key="source-" + via)
    history = service.list_timeline_commits(
        project, prepared["timeline_id"], authorize=lambda: None,
    )

    assert len(history["items"]) == 1
    entry = history["items"][0]
    assert entry["publication_id"] == imported["data"]["new_publication_id"]
    assert entry["revision_id"] == imported["data"]["accepted_revision_id"]
    assert entry["source"] == {"via": via}
    assert imported["data"]["source"] == {"via": via}


@pytest.mark.parametrize("field,descriptor", [
    ("missing_effects", {"packId": "", "kind": "effect", "id": "not-installed", "pinned": True}),
    ("missing_effects", {"packId": "", "kind": "effect", "id": "not-installed"}),
    ("missing_effects", {"packId": None, "kind": "effect", "id": "not-installed", "pinned": False}),
    ("missing_effects", {"kind": "effect", "id": "not-installed", "pinned": False}),
    ("missing_effects", {"packId": "", "kind": "", "id": "not-installed", "pinned": False}),
    ("different_effects", {"packId": "", "kind": "effect", "id": "not-installed", "pinned": False}),
])
def test_import_rejects_malformed_or_misplaced_unresolved_warning_without_metadata(tmp_path, field, descriptor):
    service, project = _service(tmp_path)
    prepared = _prepared(service, project, timeline="invalid-warning")
    prepared["differences"][field] = [descriptor]

    with pytest.raises(ValidationError, match="differences"):
        service.import_timeline(project, prepared, idempotency_key="invalid-warning")

    assert service.store.conn.execute("SELECT 1 FROM timelines WHERE id=?", (prepared["timeline_id"],)).fetchone() is None
    assert service.store.conn.execute("SELECT 1 FROM project_shots WHERE id=?", (prepared["timeline_id"] + "-shot",)).fetchone() is None
    assert service.store.conn.execute(
        "SELECT 1 FROM command_idempotency WHERE command_kind='timeline.import' AND idempotency_key='invalid-warning'"
    ).fetchone() is None


def test_import_transcript_reuse_and_conflict_are_reported_without_overwrite(tmp_path):
    service, project = _service(tmp_path)
    prepared = _prepared(service, project, timeline="transcript-import", transcript=True)
    transcript = prepared["transcripts"][0]
    service.create_document(project, transcript, idempotency_key="existing-transcript")
    result = service.import_timeline(project, prepared, idempotency_key="transcript-same")
    assert result["data"]["transcript_conflicts"] == []

    prepared = _prepared(service, project, timeline="transcript-conflict", transcript=True)
    transcript = prepared["transcripts"][0]
    changed = copy.deepcopy(transcript["content"])
    changed["segments"] = [{"id": "segment-1", "start": 0, "end": 1, "text": "different words"}]
    # Keep the same deterministic target document identity to exercise conflict preservation.
    service.store.conn.execute("UPDATE project_documents SET content_json=? WHERE project_id=? AND id=?", (canonical_json(changed), project, transcript["document_id"]))
    result = service.import_timeline(project, prepared, idempotency_key="transcript-different")
    assert result["data"]["transcript_conflicts"][0]["document_id"] == transcript["document_id"]
    stored = json.loads(service.store.conn.execute("SELECT content_json FROM project_documents WHERE id=?", (transcript["document_id"],)).fetchone()[0])
    assert stored == changed


@pytest.mark.parametrize("failure_stage", ["create", "binding", "document"])
def test_import_failure_rolls_back_shell_projections_bindings_documents_and_receipts(tmp_path, monkeypatch, failure_stage):
    service, project = _service(tmp_path)
    prepared = _prepared(service, project, text=True, transcript=True)
    if failure_stage == "create":
        original = service.create_timeline
        def fail_after_create(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("fault after shell creation")
        monkeypatch.setattr(service, "create_timeline", fail_after_create)
    elif failure_stage == "binding":
        commits, _ = service._timeline_commits()
        original = commits._project_text_binding
        def fail_after_binding(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("fault after binding")
        monkeypatch.setattr(commits, "_project_text_binding", fail_after_binding)
    else:
        original = service.create_document
        def fail_after_document(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("fault after document")
        monkeypatch.setattr(service, "create_document", fail_after_document)
    with pytest.raises(RuntimeError, match="fault after"):
        service.import_timeline(project, prepared, idempotency_key="fault-import")
    assert service.store.conn.execute("SELECT 1 FROM timelines WHERE id=?", (prepared["timeline_id"],)).fetchone() is None
    assert service.store.conn.execute("SELECT 1 FROM project_shots WHERE id=?", (prepared["timeline_id"] + "-shot",)).fetchone() is None
    assert service.store.conn.execute("SELECT 1 FROM shot_text_bindings WHERE shot_id=?", (prepared["timeline_id"] + "-shot",)).fetchone() is None
    assert service.store.conn.execute("SELECT 1 FROM project_documents WHERE id=?", (prepared["transcripts"][0]["document_id"],)).fetchone() is None
    assert service.store.conn.execute("SELECT 1 FROM command_idempotency WHERE command_kind='timeline.import' AND idempotency_key='fault-import'").fetchone() is None


def test_import_requires_complete_managed_media_and_transcript_references(tmp_path):
    service, project = _service(tmp_path)
    prepared = _prepared(service, project)
    prepared["publication"]["dependency_manifest"]["media"] = [{"media_id": "sha256:" + "f" * 64, "content_digest": "sha256:" + "f" * 64}]
    with pytest.raises(NotFoundError, match="media dependency is missing"):
        service.import_timeline(project, prepared, idempotency_key="missing-media")

    prepared = _prepared(service, project)
    prepared["publication"]["parent_composition"]["config"] = {"transcriptReferences": {"associations": [{"documentId": "transcript:missing"}]}}
    with pytest.raises(ValidationError, match="transcript references"):
        service.import_timeline(project, prepared, idempotency_key="missing-transcript")


def test_import_prepared_object_success_and_project_ownership(tmp_path):
    service, project = _service(tmp_path)
    prepared = _prepared(service, project, timeline="object-backed")
    prepared_bytes = canonical_json(prepared).encode("utf-8")
    object_id = _managed(service, project, prepared_bytes, "application/json", "prepared.json", "prepared-object")
    body = {"prepared_object_id": object_id}

    result = service.import_timeline(project, body, idempotency_key="object-backed-import")
    assert result["data"]["timeline_id"] == "object-backed"

    other = service.create_project({"slug": "other", "name": "Other"}, idempotency_key="other-project")["id"]
    refused = _prepared(service, project, timeline="foreign-object")
    foreign_bytes = canonical_json(refused).encode("utf-8")
    foreign_id = _managed(service, project, foreign_bytes, "application/json", "foreign-prepared.json", "foreign-prepared")
    with pytest.raises(NotFoundError, match="not managed by the target project"):
        service.import_timeline(other, {"prepared_object_id": foreign_id}, idempotency_key="foreign-object-import")
    assert service.store.conn.execute("SELECT 1 FROM timelines WHERE id='foreign-object'").fetchone() is None


def test_import_tampered_parent_digest_reaches_commit_store_unchanged(tmp_path, monkeypatch):
    service, project = _service(tmp_path)
    prepared = _prepared(service, project, timeline="tampered-digest")
    publication = prepared["publication"]
    tampered = "sha256:" + "f" * 64
    publication["content_digest"] = tampered
    commits, _ = service._timeline_commits()
    original = commits.bootstrap
    seen = {}

    def observe_and_publish(project_id, timeline_id, **kwargs):
        seen["digest"] = kwargs["document"]["parent_revision"]["content_digest"]
        return original(project_id, timeline_id, **kwargs)

    monkeypatch.setattr(commits, "bootstrap", observe_and_publish)
    with pytest.raises((CommitRejected, ConflictError, ValidationError)):
        service.import_timeline(project, prepared, idempotency_key="tampered-digest-import")

    assert seen["digest"] == tampered
    assert publication["content_digest"] == tampered
    assert service.store.conn.execute("SELECT 1 FROM timelines WHERE id=?", (prepared["timeline_id"],)).fetchone() is None


def test_import_rejects_reused_shot_and_incomplete_internal_closure(tmp_path):
    service, project = _service(tmp_path)
    first = _prepared(service, project, timeline="first")
    service.import_timeline(project, first, idempotency_key="first-import")
    reused = _prepared(service, project, timeline="second")
    reused["publication"]["shot_revisions"][0]["shot_id"] = "first-shot"
    reused["publication"]["parent_composition"]["occurrences"][0]["shot_id"] = "first-shot"
    with pytest.raises(ConflictError, match="shot identity is already in use"):
        service.import_timeline(project, reused, idempotency_key="reused-shot")

    incomplete = _prepared(service, project, timeline="incomplete")
    incomplete["publication"]["internal_timeline_revisions"] = []
    incomplete["publication"]["dependency_manifest"]["internal_timelines"] = []
    with pytest.raises(ValidationError, match="copied internal timeline"):
        service.import_timeline(project, incomplete, idempotency_key="incomplete-children")


@pytest.mark.parametrize("case", [
    "internal_revision_id", "occurrence_shot_id", "shot_internal_revision_id",
    "binding_shot_id", "binding_kind", "empty_shot_id",
    "manifest_shot_id", "manifest_shot_revision_id", "manifest_shot_internal_id",
    "manifest_shot_digest", "manifest_internal_timeline_id", "manifest_internal_revision_id",
    "manifest_internal_digest", "duplicate_media",
])
def test_import_rejects_malformed_hashable_identities_without_mutation(tmp_path, case):
    service, project = _service(tmp_path)
    prepared = _prepared(service, project, text=case in {"binding_shot_id", "binding_kind", "duplicate_media"},
                         timeline="invalid-" + case)
    publication = prepared["publication"]
    if case == "internal_revision_id":
        publication["internal_timeline_revisions"][0]["revision_id"] = []
    elif case == "occurrence_shot_id":
        publication["parent_composition"]["occurrences"][0]["shot_id"] = {}
    elif case == "shot_internal_revision_id":
        publication["shot_revisions"][0]["internal_timeline_revision_id"] = []
    elif case == "binding_shot_id":
        prepared["text_bindings"][0]["shot_id"] = []
    elif case == "binding_kind":
        prepared["text_bindings"][0]["kind"] = {}
    elif case == "empty_shot_id":
        publication["shot_revisions"][0]["shot_id"] = ""
    elif case.startswith("manifest_shot_"):
        field = {
            "manifest_shot_id": "shot_id",
            "manifest_shot_revision_id": "revision_id",
            "manifest_shot_internal_id": "internal_timeline_revision_id",
            "manifest_shot_digest": "content_digest",
        }[case]
        publication["dependency_manifest"]["shots"][0][field] = []
    elif case.startswith("manifest_internal_"):
        field = {
            "manifest_internal_timeline_id": "timeline_id",
            "manifest_internal_revision_id": "revision_id",
            "manifest_internal_digest": "content_digest",
        }[case]
        publication["dependency_manifest"]["internal_timelines"][0][field] = {}
    elif case == "duplicate_media":
        media = publication["dependency_manifest"]["media"]
        media.append(copy.deepcopy(media[0]))

    original = copy.deepcopy(prepared)
    with pytest.raises(ValidationError):
        service.import_timeline(project, prepared, idempotency_key="invalid-" + case)

    assert prepared == original
    assert service.store.conn.execute("SELECT 1 FROM timelines WHERE id=?", (prepared["timeline_id"],)).fetchone() is None
    assert service.store.conn.execute("SELECT 1 FROM project_shots WHERE id=?", (prepared["timeline_id"] + "-shot",)).fetchone() is None
    assert service.store.conn.execute(
        "SELECT 1 FROM command_idempotency WHERE command_kind='timeline.import' AND idempotency_key=?",
        ("invalid-" + case,),
    ).fetchone() is None


def test_import_fault_after_commit_store_publication_rolls_back_all_import_metadata(tmp_path, monkeypatch):
    service, project = _service(tmp_path)
    prepared = _prepared(service, project, text=True, transcript=True, timeline="publish-rollback")
    commits, _ = service._timeline_commits()
    publish = commits.bootstrap
    def fail_after_publish(*args, **kwargs):
        publish(*args, **kwargs)
        raise RuntimeError("fault after completed publication")
    monkeypatch.setattr(commits, "bootstrap", fail_after_publish)
    key = "publish-rollback-key"

    with pytest.raises(RuntimeError, match="completed publication"):
        service.import_timeline(project, prepared, idempotency_key=key)

    timeline_id = prepared["timeline_id"]
    shot_id = timeline_id + "-shot"
    shot_revision_id = timeline_id + "-shot-rev"
    internal_revision_id = timeline_id + "-internal-rev"
    parent_revision_id = timeline_id + "-parent-rev"
    transcript_id = prepared["transcripts"][0]["document_id"]
    for table, identity_column, identity in (
        ("timelines", "id", timeline_id),
        ("timeline_revisions", "timeline_id", timeline_id),
        ("project_shots", "id", shot_id),
        ("shot_revisions", "id", shot_revision_id),
        ("shot_revision_heads", "shot_id", shot_id),
        ("internal_timeline_revisions", "id", internal_revision_id),
        ("parent_composition_revisions", "id", parent_revision_id),
        ("parent_composition_heads", "timeline_id", timeline_id),
        ("composition_revision_occurrences", "parent_revision_id", parent_revision_id),
        ("composition_revision_dependencies", "parent_revision_id", parent_revision_id),
        ("shot_text_bindings", "shot_id", shot_id),
        ("shot_text_binding_events", "binding_id", service._text_binding_id(project, shot_id, "voiceover_script", None)),
        ("project_documents", "id", transcript_id),
        ("timeline_events", "timeline_id", timeline_id),
    ):
        assert service.store.conn.execute(f"SELECT 1 FROM {table} WHERE {identity_column}=?", (identity,)).fetchone() is None, table
    child_keys = {
        service._import_key(project + ":" + key, operation, identity)
        for operation, identity in (
            ("create", timeline_id), ("binding", shot_id + ":voiceover_script:None"),
            ("transcript", transcript_id), ("publish", timeline_id),
        )
    }
    assert service.store.conn.execute("SELECT 1 FROM command_idempotency WHERE idempotency_key=?", (key,)).fetchone() is None
    assert not any(service.store.conn.execute("SELECT 1 FROM command_idempotency WHERE idempotency_key=?", (child_key,)).fetchone() for child_key in child_keys)


def test_import_http_route_requires_write_scope_and_forwards_body_and_key():
    from runtime_protocol.server import RuntimeHandler

    calls = []
    identity_calls = []
    response = {}

    class Runtime:
        def import_timeline(self, project_id, body, *, idempotency_key):
            calls.append((project_id, body, idempotency_key))
            return {"data": {"timeline_id": body["timeline_id"]}, "receipt": {}}

    class Credentials:
        def require(self, token, scope):
            identity_calls.append((token, scope))
            if token != "writer" or scope != "projects:write":
                raise AssertionError("import route must require projects:write")
            return {"actor": "writer"}

    body = json.dumps({"timeline_id": "new-timeline"}).encode()
    handler = object.__new__(RuntimeHandler)
    handler.server = SimpleNamespace(runtime=Runtime(), credentials=Credentials())
    handler.path = "/v1/projects/project-1/timelines/import"
    handler.command = "POST"
    handler.headers = {"Authorization": "Bearer writer", "Idempotency-Key": "import-key", "Content-Length": str(len(body))}
    handler.rfile = io.BytesIO(body)
    handler._send = lambda status, payload, **_kwargs: response.update(status=status, payload=payload)

    handler._route()

    assert identity_calls == [("writer", "projects:write")]
    assert calls == [("project-1", {"timeline_id": "new-timeline"}, "import-key")]
    assert response["status"] == 201
    assert response["payload"]["data"]["timeline_id"] == "new-timeline"
