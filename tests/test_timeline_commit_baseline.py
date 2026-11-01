from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sqlite3
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, ValidationError

from test_shot_composition_contract import _composition_validator, _schema
from baseline_fixture import film_inputs, load_baseline_fixture

from runtime_protocol.errors import ConflictError
from runtime_protocol.store import expired_command_result, expired_publication_result
from runtime_protocol.timeline_commit_baseline import (
    baseline_install_plan,
    bootstrap_install_plan,
    default_bootstrap_document,
    empty_bootstrap_document,
    verify_baseline,
)
from runtime_protocol.util import canonical_json
from test_shot_composition_runtime import (
    _rehash_timeline_events,
    _service,
)


def _renderer_unavailable(*args, **kwargs):
    raise AssertionError("baseline verification must not evaluate or replay scenes")


def _disable_renderer(monkeypatch, service):
    monkeypatch.setattr("runtime_protocol.service.evaluate_closure", _renderer_unavailable)
    monkeypatch.setattr("runtime_protocol.visual_seam.evaluate_closure", _renderer_unavailable)
    monkeypatch.setattr(service, "_publication_replay_result", _renderer_unavailable)
    receipt_payload = service._receipt_payload

    def receipt_without_publication_replay(row, *, project_id):
        if row["command_kind"] == "parent_composition.publish":
            _renderer_unavailable()
        return receipt_payload(row, project_id=project_id)

    monkeypatch.setattr(service, "_receipt_payload", receipt_without_publication_replay)


def _verify(service, project_id):
    return verify_baseline(service.store.conn, project_id, "main", read_object=service.cas.read)


def _refused(call):
    with pytest.raises(ConflictError) as error:
        call()
    assert error.value.status == 409
    assert error.value.details["reason"] == "history_unavailable"
    return error.value.details["integrity_reason"]


@pytest.fixture
def published(tmp_path, monkeypatch):
    service, project_id, (accepted,) = load_baseline_fixture(tmp_path)
    _disable_renderer(monkeypatch, service)
    try:
        yield service, project_id, accepted
    finally:
        service.close()


def test_main_publication_is_verified_read_only_and_detached(published):
    service, project_id, accepted = published
    connection = service.store.conn
    before = connection.total_changes
    facts = _verify(service, project_id)
    assert connection.total_changes == before
    assert facts["head"] == {"revision_id": "parent-1", "publication_id": accepted["receipt"]["receipt_id"]}
    assert facts["entries"] == [{
        "publication_id": accepted["receipt"]["receipt_id"], "revision_id": "parent-1", "previous": None,
        "receipt": accepted["receipt"], "intent": "legacy_unknown", "records": None,
        "provider_version": None, "compiler_version": None, "publisher": None,
    }]
    document = facts["canonical_document"]
    assert document["parent_revision"]["payload"] == accepted["data"]["payload"]
    assert document["shot_revisions"][0]["revision_id"] == "shot-rev-1"
    assert document["internal_timeline_revisions"][0]["revision_id"] == "timeline-rev-1"
    assert document["dependency_manifest"] == {**accepted["data"]["dependency_manifest"], "documents": []}
    document["parent_revision"]["payload"]["config"]["changed"] = True
    assert _verify(service, project_id)["canonical_document"]["parent_revision"]["payload"]["config"] == {}


def test_latest_same_content_publication_keeps_its_own_receipt(tmp_path, monkeypatch):
    # Even the exact same revision can be selected twice; row/content order
    # cannot identify the accepted head publication.
    service, project_id, (first, second) = load_baseline_fixture(tmp_path, "same-content")
    try:
        _disable_renderer(monkeypatch, service)
        facts = _verify(service, project_id)
        assert facts["head"]["publication_id"] == second["receipt"]["receipt_id"]
        assert facts["entries"][1]["previous"] == {"revision_id": "parent-1", "publication_id": first["receipt"]["receipt_id"]}
        connection = service.store.conn
        connection.execute("UPDATE command_idempotency SET event_ids_json=? WHERE idempotency_key='second'", (canonical_json(first["receipt"]["event_ids"]),))
        _refused(lambda: _verify(service, project_id))
    finally:
        service.close()


def test_old_missing_receipt_becomes_an_explicit_baseline_boundary(tmp_path, monkeypatch):
    service, project_id, (first, second) = load_baseline_fixture(tmp_path, "history")
    try:
        service.store.conn.execute("DELETE FROM command_idempotency WHERE txn_id=?", (first["receipt"]["receipt_id"],))
        _disable_renderer(monkeypatch, service)
        facts = _verify(service, project_id)
        assert len(facts["entries"]) == 1
        assert facts["entries"][0]["previous"] is None
        assert facts["head"]["publication_id"] == second["receipt"]["receipt_id"]
    finally:
        service.close()


@pytest.mark.parametrize("sql", [
    "UPDATE command_idempotency SET txn_id=NULL WHERE command_kind='parent_composition.publish'",
    "DELETE FROM command_idempotency WHERE command_kind='parent_composition.publish'",
    "UPDATE command_idempotency SET event_ids_json='[]' WHERE command_kind='parent_composition.publish'",
    "UPDATE command_idempotency SET resulting_stream_seq=999 WHERE command_kind='parent_composition.publish'",
    "UPDATE command_idempotency SET primary_stream_id='foreign' WHERE command_kind='parent_composition.publish'",
    "UPDATE command_idempotency SET first_project_seq=999, last_project_seq=999 WHERE command_kind='parent_composition.publish'",
    "UPDATE command_idempotency SET last_project_seq=first_project_seq+1 WHERE command_kind='parent_composition.publish'",
    "UPDATE parent_composition_heads SET revision_id=NULL",
    "UPDATE parent_composition_revisions SET content_digest='sha256:bad'",
    "UPDATE shot_revisions SET payload_json='{}' WHERE id='shot-rev-1'",
    "UPDATE internal_timeline_revisions SET payload_json='{}' WHERE id='timeline-rev-1'",
    "DELETE FROM composition_revision_dependencies WHERE dependency_kind='shot_revision'",
    "UPDATE composition_revision_dependencies SET ordinal=9 WHERE dependency_kind='internal_timeline_revision'",
    "UPDATE composition_revision_dependencies SET content_digest='wrong' WHERE dependency_kind='internal_timeline_revision'",
    "DELETE FROM composition_revision_occurrences",
    "UPDATE composition_revision_occurrences SET duration_ms=2222",
    "UPDATE shot_revisions SET internal_timeline_revision_id=(SELECT id FROM internal_timeline_revisions LIMIT 1), payload_json=json_set(payload_json, '$.internal_timeline_revision_id', 'wrong') WHERE id='shot-rev-1'",
    "UPDATE timeline_events SET event_hash='bad' WHERE kind='parent.composition.published'",
    "DELETE FROM timeline_events WHERE kind='timeline.created'",
    "UPDATE command_idempotency SET result_json=json_remove(result_json, '$.dependency_manifest') WHERE command_kind='parent_composition.publish'",
    "UPDATE command_idempotency SET result_json=json_set(result_json, '$.event_id', '0') WHERE command_kind='parent_composition.publish'",
    "UPDATE command_idempotency SET result_json=json_set(result_json, '$.project_id', 'foreign') WHERE command_kind='parent_composition.publish'",
])
def test_corrupt_or_missing_current_proof_fails_closed(published, sql):
    service, project_id, _ = published
    service.store.conn.execute(sql)
    before = service.store.conn.total_changes
    _refused(lambda: _verify(service, project_id))
    assert service.store.conn.total_changes == before


def test_manifest_mismatch_even_with_valid_event_hash_and_matching_receipt(published):
    service, project_id, accepted = published
    payload = json.loads(service.store.conn.execute("SELECT payload_json FROM timeline_events WHERE id=?", accepted["receipt"]["event_ids"]).fetchone()[0])
    payload["dependency_manifest"]["shots"] = []
    result = copy.deepcopy(accepted["data"])
    result["dependency_manifest"] = payload["dependency_manifest"]
    service.store.conn.execute("UPDATE command_idempotency SET result_json=? WHERE txn_id=?", (canonical_json(result), accepted["receipt"]["receipt_id"]))
    _rehash_timeline_events(service, "main", replacements={int(accepted["data"]["event_id"]): payload})
    assert _refused(lambda: _verify(service, project_id)) == "manifest_closure_mismatch"


def test_later_same_value_write_invalidates_head(published):
    service, project_id, _ = published
    with service.store._transaction():
        service.store._append_timeline_event("main", "timeline.document.saved", {"project_id": project_id})
    assert _refused(lambda: _verify(service, project_id)) == "later_unaccounted_timeline_write"


def test_later_document_write_without_parent_event_invalidates_head(tmp_path, monkeypatch):
    service, project_id, _ = load_baseline_fixture(tmp_path, "legacy-document")
    try:
        _disable_renderer(monkeypatch, service)
        assert _refused(lambda: _verify(service, project_id)) == "later_unaccounted_ledger_write"
    finally:
        service.close()


def test_later_display_rename_is_not_an_authored_write(published):
    service, project_id, accepted = published
    from test_timeline_commit_provider import Provider
    service.register_timeline_commit_provider(Provider())
    service.rename_timeline(project_id, "main", {"name": "Renamed"}, idempotency_key="rename")
    assert _verify(service, project_id)["head"]["publication_id"] == accepted["receipt"]["receipt_id"]


@pytest.mark.parametrize("damage", [None, "generic", "manifest_hash", "event_id", "no_event"])
def test_compacted_publication_requires_complete_paired_proof(published, damage):
    service, project_id, accepted = published
    connection = service.store.conn
    encoded = connection.execute("SELECT result_json FROM command_idempotency WHERE txn_id=?", (accepted["receipt"]["receipt_id"],)).fetchone()[0]
    marker = json.loads(expired_publication_result(encoded))
    if damage == "generic":
        marker = json.loads(expired_command_result(encoded))
    elif damage == "manifest_hash":
        marker["dependency_manifest_sha256"] = "0" * 64
    elif damage == "event_id":
        marker["event_id"] = "0"
    elif damage == "no_event":
        connection.execute("DELETE FROM timeline_events WHERE kind='parent.composition.published'")
    connection.execute("UPDATE command_idempotency SET result_json=? WHERE txn_id=?", (canonical_json(marker), accepted["receipt"]["receipt_id"]))
    if damage:
        _refused(lambda: _verify(service, project_id))
    else:
        facts = _verify(service, project_id)
        assert facts["entries"][0]["receipt"]["result"] == marker
        assert facts["head"]["publication_id"] == accepted["receipt"]["receipt_id"]


def test_install_plan_rechecks_facts_and_is_idempotent(published):
    service, project_id, _ = published
    connection = service.store.conn
    facts = _verify(service, project_id)
    _refused(lambda: baseline_install_plan(connection, facts, read_object=service.cas.read))
    with service.store._transaction():
        before = connection.total_changes
        plan = baseline_install_plan(connection, facts, read_object=service.cas.read)
        assert plan["install"] is True
        replay = baseline_install_plan(connection, facts, read_object=service.cas.read, existing_head=plan["head"])
        assert replay == {**plan, "install": False}
        assert connection.total_changes == before
        _refused(lambda: baseline_install_plan(connection, facts, read_object=service.cas.read, existing_head={"revision_id": "parent-1", "publication_id": "other"}))
        plan["entries"][0]["receipt"]["request_hash"] = "altered"
        assert facts["entries"][0]["receipt"]["request_hash"] != "altered"
    with service.store._transaction():
        service.store._append_timeline_event("main", "timeline.document.saved", {"project_id": project_id})
        _refused(lambda: baseline_install_plan(connection, facts, read_object=service.cas.read))


def test_install_plan_refuses_replacement_same_revision_publication(tmp_path):
    service, project_id, _ = load_baseline_fixture(tmp_path)
    try:
        facts = _verify(service, project_id)
        service.close()
        service, project_id, _ = load_baseline_fixture(tmp_path, "same-content")
        with service.store._transaction():
            assert _refused(lambda: baseline_install_plan(service.store.conn, facts, read_object=service.cas.read)) == "baseline_compare_failed"
    finally:
        service.close()


def test_foreign_scope_and_foreign_child_are_refused(published):
    service, project_id, _ = published
    from test_timeline_commit_provider import Provider
    service.register_timeline_commit_provider(Provider())
    other = service.create_project({"slug": "other", "name": "Other"}, idempotency_key="other")
    _refused(lambda: _verify(service, other["id"]))
    service.store.conn.execute("UPDATE internal_timeline_revisions SET project_id=? WHERE id='timeline-rev-1'", (other["id"],))
    _refused(lambda: _verify(service, project_id))


def test_explicit_media_uses_duplicate_database_and_cas_read_only(tmp_path, monkeypatch):
    service, project_id, (accepted,) = load_baseline_fixture(tmp_path, "explicit-media")
    duplicate = tmp_path / "duplicate"
    duplicate.mkdir()
    try:
        _disable_renderer(monkeypatch, service)
        with sqlite3.connect(duplicate / "realm.sqlite3") as destination:
            service.store.conn.backup(destination)
        shutil.copytree(service.store.cas_root, duplicate / "cas")
        with sqlite3.connect(f"file:{duplicate / 'realm.sqlite3'}?mode=ro", uri=True) as connection:
            connection.row_factory = sqlite3.Row
            def read_object(digest):
                return (duplicate / "cas" / service.cas.path_for(digest).relative_to(service.store.cas_root)).read_bytes()
            before = connection.total_changes
            facts = verify_baseline(connection, project_id, "main", read_object=read_object)
            assert facts["head"]["publication_id"] == accepted["receipt"]["receipt_id"]
            assert len(facts["canonical_document"]["dependency_manifest"]["media"]) == 2
            assert connection.total_changes == before
            pin = facts["canonical_document"]["dependency_manifest"]["media"][0]["media_id"][7:]
            copied_object = duplicate / "cas" / service.cas.path_for(pin).relative_to(service.store.cas_root)
            copied_object.write_bytes(b"corrupt")
            _refused(lambda: verify_baseline(connection, project_id, "main", read_object=read_object))
            copied_object.unlink()
            _refused(lambda: verify_baseline(connection, project_id, "main", read_object=read_object))
            assert service.cas.read(pin) != b"corrupt"
    finally:
        service.close()


def test_empty_bootstrap_candidate_requires_real_parent_receipt(tmp_path, monkeypatch):
    service, project_id = _service(tmp_path)
    try:
        connection = service.store.conn
        with service.store._transaction():
            _refused(lambda: bootstrap_install_plan(connection, project_id, "main", read_object=service.cas.read))
        service.close()
        service, project_id, (accepted,) = load_baseline_fixture(tmp_path, "empty")
        connection = service.store.conn
        document = empty_bootstrap_document(project_id, "main", "empty-parent")
        _disable_renderer(monkeypatch, service)
        with service.store._transaction():
            plan = bootstrap_install_plan(connection, project_id, "main", read_object=service.cas.read)
        assert plan["head"]["publication_id"] == accepted["receipt"]["receipt_id"]
        assert plan["entries"][0]["intent"] == "bootstrap"
        assert plan["entries"][0]["records"] is None
        assert plan["entries"][0]["previous"] is None
        assert plan["entries"][0]["receipt"] == accepted["receipt"]
        assert _verify(service, project_id)["canonical_document"] == document
    finally:
        service.close()


def test_empty_bootstrap_uses_authoritative_timeline_config_schema():
    document = empty_bootstrap_document("project", "main", "empty-parent")
    payload = document["parent_revision"]["payload"]
    assert payload["config"] == {"clips": [], "tracks": []}
    # The wire ParentComposition references this pinned artifact; do not copy
    # TimelineConfig's definition into the bootstrap tests or implementation.
    schema_path = Path(__file__).resolve().parents[1] / "contract" / "schemas" / "timeline-config.schema.json"
    validator = Draft7Validator(json.loads(schema_path.read_text()))
    validator.validate(payload["config"])
    with pytest.raises(ValidationError):
        validator.validate({})
    _composition_validator(_schema()).validate({
        "project_id": document["project_id"], "timeline_id": document["timeline_id"],
        "expected_head": None, "parent_revision_id": document["parent_revision"]["revision_id"],
        "parent_composition": payload,
    })


def test_default_bootstrap_tracks_are_valid_and_detached():
    document = default_bootstrap_document("project", "main", "initial-parent")
    payload = document["parent_revision"]["payload"]
    assert [(track["id"], track["label"], track["kind"]) for track in payload["config"]["tracks"]] == [
        ("V1", "V1", "visual"), ("A1", "A1", "audio"),
    ]
    schema_path = Path(__file__).resolve().parents[1] / "contract" / "schemas" / "timeline-config.schema.json"
    Draft7Validator(json.loads(schema_path.read_text())).validate(payload["config"])
    from runtime_protocol.timeline_commit_port import digest
    assert document["parent_revision"]["content_digest"] == digest(payload)
    payload["config"]["tracks"][0]["label"] = "Changed"
    assert default_bootstrap_document("project", "other", "other-parent")["parent_revision"]["payload"]["config"]["tracks"][0]["label"] == "V1"


@pytest.mark.parametrize("field,value", [
    ("config", {}),
    ("config", {"clips": [], "tracks": [], "app": {}}),
    ("registry", {"assets": {}}),
    ("extension", {"innocent": True}),
])
def test_bootstrap_requires_exact_canonical_empty_payload(tmp_path, monkeypatch, field, value):
    variant = {
        ("config", canonical_json({})): "empty-config",
        ("config", canonical_json({"clips": [], "tracks": [], "app": {}})): "empty-config-app",
        ("registry", canonical_json({"assets": {}})): "empty-registry",
        ("extension", canonical_json({"innocent": True})): "empty-extension",
    }[(field, canonical_json(value))]
    service, project_id, _ = load_baseline_fixture(tmp_path, variant)
    try:
        _disable_renderer(monkeypatch, service)
        with service.store._transaction():
            before = service.store.conn.total_changes
            assert _refused(lambda: bootstrap_install_plan(service.store.conn, project_id, "main", read_object=service.cas.read)) == "bootstrap_requires_empty_initial_publication"
            assert service.store.conn.total_changes == before
    finally:
        service.close()


def test_nonempty_head_cannot_be_relabelled_bootstrap(published):
    service, project_id, _ = published
    with service.store._transaction():
        assert _refused(lambda: bootstrap_install_plan(service.store.conn, project_id, "main", read_object=service.cas.read)) == "bootstrap_requires_empty_initial_publication"


def test_synthetic_film_duplicate_preserves_shared_shots_music_transition_and_transcript(tmp_path, monkeypatch):
    service, project_id, (accepted,) = load_baseline_fixture(tmp_path, "film")
    inputs = film_inputs(tmp_path)
    body, audio, binding = (inputs[key] for key in ("body", "audio", "binding"))
    try:
        _disable_renderer(monkeypatch, service)
        duplicate = tmp_path / "film-duplicate"
        duplicate.mkdir()
        with sqlite3.connect(duplicate / "realm.sqlite3") as destination:
            service.store.conn.backup(destination)
        shutil.copytree(service.store.cas_root, duplicate / "cas")
        def read_object(digest):
            return (duplicate / "cas" / digest[:2] / digest[2:]).read_bytes()
        with sqlite3.connect(f"file:{duplicate / 'realm.sqlite3'}?mode=ro", uri=True) as connection:
            connection.row_factory = sqlite3.Row
            facts = verify_baseline(connection, project_id, "main", read_object=read_object)
        document = facts["canonical_document"]
        assert facts["head"]["publication_id"] == accepted["receipt"]["receipt_id"]
        assert len(document["shot_revisions"]) == len(document["internal_timeline_revisions"]) == 3
        assert len(document["parent_revision"]["payload"]["occurrences"]) == 4
        assert document["parent_revision"]["payload"]["config"]["transitions"] == body["parent_composition"]["config"]["transitions"]
        assert document["internal_timeline_revisions"][0]["payload"]["clips"][0]["transcript_anchor"]["word_id"] == "word-1"
        assert {pin["media_id"] for pin in document["dependency_manifest"]["media"]} == {audio, binding["media_id"]}
        # Acceptance owns the real edge schema; exercise re-verification/CAS on
        # the duplicate DB with a tiny caller-owned table, never the source.
        with sqlite3.connect(duplicate / "realm.sqlite3", isolation_level=None) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("CREATE TABLE installed_baseline (timeline_id TEXT PRIMARY KEY, head_json TEXT NOT NULL)")
            connection.execute("BEGIN IMMEDIATE")
            plan = baseline_install_plan(connection, facts, read_object=read_object)
            connection.execute("INSERT INTO installed_baseline VALUES (?, ?)", ("main", canonical_json(plan["head"])))
            connection.commit()
            connection.execute("BEGIN IMMEDIATE")
            head = json.loads(connection.execute("SELECT head_json FROM installed_baseline WHERE timeline_id='main'").fetchone()[0])
            assert baseline_install_plan(connection, facts, read_object=read_object, existing_head=head)["install"] is False
            assert connection.execute("SELECT COUNT(*) FROM installed_baseline").fetchone()[0] == 1
            connection.rollback()
        assert not service.store.conn.execute("SELECT name FROM sqlite_master WHERE name='installed_baseline'").fetchone()
    finally:
        service.close()


def test_latest_event_must_select_current_head_even_when_content_matches(tmp_path, monkeypatch):
    service, project_id, _ = load_baseline_fixture(tmp_path, "history")
    try:
        service.store.conn.execute("UPDATE parent_composition_heads SET revision_id='parent-1'")
        _disable_renderer(monkeypatch, service)
        assert _refused(lambda: _verify(service, project_id)) == "latest_publication_does_not_select_head"
    finally:
        service.close()


def test_extra_dependency_and_raw_projection_write_fail_closed(published):
    service, project_id, _ = published
    with service.store._transaction():
        service.store.conn.execute("INSERT INTO composition_revision_dependencies SELECT parent_revision_id, dependency_kind, dependency_id, content_digest, 99 FROM composition_revision_dependencies LIMIT 1")
        assert _refused(lambda: _verify(service, project_id)) == "dependency_rows_mismatch"
        service.store.conn.execute("DELETE FROM composition_revision_dependencies WHERE ordinal=99")
        service.store.conn.execute("UPDATE project_shots SET name='untracked writer' WHERE id='shot-1'")
        assert _refused(lambda: _verify(service, project_id)) == "unaccounted_shot_projection"


def test_plausible_but_wrong_project_sequence_is_refused(published):
    service, project_id, _ = published
    service.store.conn.execute("UPDATE command_idempotency SET first_project_seq=1, last_project_seq=1 WHERE command_kind='parent_composition.publish'")
    assert _refused(lambda: _verify(service, project_id)) == "receipt_project_sequence_mismatch"


def test_corrupt_old_head_is_not_guessed_from_equal_content(tmp_path, monkeypatch):
    service, project_id, (_, second) = load_baseline_fixture(tmp_path, "history")
    try:
        result = copy.deepcopy(second["data"])
        result["old_head"] = "unproven-other-parent"
        service.store.conn.execute("UPDATE command_idempotency SET result_json=? WHERE txn_id=?", (canonical_json(result), second["receipt"]["receipt_id"]))
        event_id = int(result["event_id"])
        payload = json.loads(service.store.conn.execute("SELECT payload_json FROM timeline_events WHERE id=?", (event_id,)).fetchone()[0])
        payload["old_head"] = result["old_head"]
        _rehash_timeline_events(service, "main", replacements={event_id: payload})
        _disable_renderer(monkeypatch, service)
        assert _refused(lambda: _verify(service, project_id)) == "publication_ancestry_mismatch"
    finally:
        service.close()


def test_unrelated_project_and_timeline_writes_do_not_invalidate_baseline(published):
    service, project_id, accepted = published
    from test_timeline_commit_provider import Provider
    service.register_timeline_commit_provider(Provider())
    other = service.create_project({"slug": "unrelated", "name": "Unrelated"}, idempotency_key="unrelated")
    service.create_timeline(other["id"], "elsewhere", idempotency_key="elsewhere")
    service.create_document(other["id"], {"document_id": "notes", "kind": "notes", "content": {}}, idempotency_key="notes")
    assert _verify(service, project_id)["head"]["publication_id"] == accepted["receipt"]["receipt_id"]


def test_declared_document_pin_is_not_silently_labelled_an_empty_dependency_closure(published):
    service, project_id, accepted = published
    connection = service.store.conn
    event_id = int(accepted["data"]["event_id"])
    payload = json.loads(connection.execute("SELECT payload_json FROM timeline_events WHERE id=?", (event_id,)).fetchone()[0])
    payload["dependency_manifest"]["documents"] = [{
        "document_id": "source-config", "version": 1, "content_digest": "sha256:" + "1" * 64,
    }]
    result = copy.deepcopy(accepted["data"])
    result["dependency_manifest"] = payload["dependency_manifest"]
    connection.execute("UPDATE command_idempotency SET result_json=? WHERE txn_id=?", (canonical_json(result), accepted["receipt"]["receipt_id"]))
    _rehash_timeline_events(service, "main", replacements={event_id: payload})
    before = connection.total_changes
    assert _refused(lambda: _verify(service, project_id)) == "unretained_document_dependency"
    assert connection.total_changes == before


@pytest.mark.parametrize("location", ["config", "parent", "shot", "internal"])
def test_pin_shaped_opaque_values_are_preserved(tmp_path, monkeypatch, location):
    service, project_id, (accepted,) = load_baseline_fixture(tmp_path, f"opaque-{location}")
    try:
        opaque = {
            "project_id": "unrelated-project", "document_id": "notes", "object_id": "external-record",
            "version": 1, "content_digest": "sha256:" + "1" * 64,
            "example.org/extension": {"source": {"document_id": "other-notes", "version": 2},
                                      "ref": {"document_id": "third-notes", "content_digest": "unrelated"}},
        }
        _disable_renderer(monkeypatch, service)
        facts = _verify(service, project_id)
        document = facts["canonical_document"]
        assert facts["entries"][0]["receipt"] == accepted["receipt"]
        assert document["dependency_manifest"]["documents"] == []
        if location == "config":
            restored = document["parent_revision"]["payload"]["config"]
        elif location == "parent":
            restored = document["parent_revision"]["payload"]["metadata"]
        elif location == "shot":
            restored = document["shot_revisions"][0]["payload"]["metadata"]
        else:
            restored = document["internal_timeline_revisions"][0]["payload"]["app"]
        assert restored["source"] == opaque
    finally:
        service.close()


@pytest.mark.parametrize("relation", ["reference", "promoted"])
def test_reference_only_media_is_not_current_managed_ownership(tmp_path, monkeypatch, relation):
    service, project_id, (accepted,) = load_baseline_fixture(tmp_path, "explicit-media")
    scene = "sha256:" + hashlib.sha256(b'{"schema":"live-scene-package/v1"}').hexdigest()
    try:
        _disable_renderer(monkeypatch, service)
        original = _verify(service, project_id)
        assert original["entries"][0]["receipt"] == accepted["receipt"]
        digest = scene.removeprefix("sha256:")
        connection = service.store.conn
        connection.execute("UPDATE project_objects SET relation=? WHERE project_id=? AND digest=?", (relation, project_id, digest))
        before = connection.total_changes
        assert _refused(lambda: _verify(service, project_id)) == "missing_scoped_row"
        assert connection.total_changes == before
        connection.execute("INSERT INTO project_objects(project_id, digest, relation, created_at) SELECT project_id, digest, 'managed', created_at FROM project_objects WHERE project_id=? AND digest=?", (project_id, digest))
        assert _verify(service, project_id) == original
    finally:
        service.close()
