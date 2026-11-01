from __future__ import annotations

import hashlib
import json
import sqlite3

import pytest

from runtime_protocol import cli, upgrade
from runtime_protocol.canonical_schema import GENERATION_TAG_INDEX_SQL, generation_tag_index_is_current
from runtime_protocol.errors import OwnerBusyError, ValidationError
from runtime_protocol.store import RealmStore
from runtime_protocol.upgrade import inspect_canonical_schema, migrate_canonical_to_current, migrate_generation_tags


STAMP = "2026-10-01T00:00:00Z"
CONFIRMATION = "MIGRATE GENERATION TAGS realm-tags"


def _realm(root, *, old=False):
    store = RealmStore.initialize(root, realm_id="realm-tags")
    store.close()
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        connection.execute(
            "INSERT INTO projects(id, realm_id, slug, name, metadata_json, created_at, updated_at) VALUES ('project-tags', 'realm-tags', 'fixture', 'Fixture', '{}', ?, ?)",
            (STAMP, STAMP),
        )
        if old:
            # A C31 source has app state but neither the Timeline v32 bundle
            # nor M's generation index.  Merely relabeling a U33 database as
            # v31 would create a forbidden v33-manifest hybrid.
            connection.execute("DROP INDEX idx_generations_gen")
            for table in ("timeline_document_input_links", "timeline_document_input_bindings",
                          "timeline_document_input_contents", "timeline_commit_history"):
                connection.execute(f"DROP TABLE {table}")
            connection.execute("ALTER TABLE parent_composition_heads DROP COLUMN publication_id")
            connection.execute("ALTER TABLE parent_composition_revisions DROP COLUMN commit_manifest_json")
            connection.execute("UPDATE runtime_schema SET version=31 WHERE id=1")
        connection.execute(
            "INSERT INTO command_idempotency(command_kind, aggregate_id, idempotency_key, request_hash, result_json, created_at) "
            "VALUES ('media.import', 'unrelated', 'receipt', 'hash', ?, ?)",
            (json.dumps({"metadata": {"gen": {"model": "ledger-only"}}}), STAMP),
        )
    return root / "realm.sqlite3"


def _generation(connection, identity, metadata, *, task_id=None, intent=None, effect=None, spec=None):
    if task_id:
        body = json.dumps(spec if spec is not None else {"__runtime_generation_intent": {"metadata": {"gen": intent or {}}}})
        digest = hashlib.sha256(body.encode()).hexdigest()
        connection.execute("INSERT OR IGNORE INTO task_specs VALUES (?, ?, ?)", (digest, body, STAMP))
        connection.execute(
            "INSERT INTO runs(id, project_id, capability, spec_digest, status, created_at, updated_at) VALUES (?, 'project-tags', 'test.generate', ?, 'completed', ?, ?)",
            ("run-" + task_id, digest, STAMP, STAMP),
        )
        connection.execute(
            "INSERT INTO tasks(id, run_id, capability, spec_digest, expected_effect_json, status, created_at, updated_at) VALUES (?, ?, 'test.generate', ?, ?, 'completed', ?, ?)",
            (task_id, "run-" + task_id, digest, json.dumps(effect) if effect is not None else None, STAMP, STAMP),
        )
    connection.execute(
        "INSERT INTO generations(id, project_id, source_task_id, metadata_json, created_at, updated_at) VALUES (?, 'project-tags', ?, ?, ?, ?)",
        (identity, task_id, json.dumps(metadata) if not isinstance(metadata, str) else metadata, STAMP, STAMP),
    )


def test_v31_upgrade_adds_guarded_index_and_preserves_generation_metadata(tmp_path):
    root = tmp_path / "old"
    database = _realm(root, old=True)
    with sqlite3.connect(database) as connection:
        for identity, metadata in (("known", {"gen": {"model": "x", "target": "runpod"}, "other": [1]}),
                                   ("malformed", "not-json"), ("scalar", {"gen": 7})):
            _generation(connection, identity, metadata)
        before = connection.execute("SELECT * FROM generations ORDER BY id").fetchall()
    result = migrate_canonical_to_current(root, confirmation="MIGRATE CANONICAL realm-tags")
    assert result["steps"] == [
        {"source_schema_version": 31, "target_schema_version": 32, "baseline_required": True},
        {"source_schema_version": 32, "target_schema_version": 33, "source_family": "TL32"},
    ]
    with sqlite3.connect(database) as connection:
        assert generation_tag_index_is_current(connection)
        assert connection.execute("SELECT sql FROM sqlite_master WHERE name='idx_generations_gen'").fetchone()[0] == GENERATION_TAG_INDEX_SQL
        assert connection.execute("SELECT * FROM generations ORDER BY id").fetchall() == before
    assert inspect_canonical_schema(root)["version"] == 33


@pytest.mark.parametrize("replacement", [None, "CREATE INDEX idx_generations_gen ON generations(id)"])
def test_v32_index_inspection_rejects_missing_or_alternate_index(tmp_path, replacement):
    root = tmp_path / "realm"
    database = _realm(root)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP INDEX idx_generations_gen")
        if replacement:
            connection.execute(replacement)
    before = database.read_bytes()
    contents = sorted(path.name for path in root.iterdir())
    with pytest.raises(ValidationError, match="unsupported canonical v33 manifest"):
        inspect_canonical_schema(root)
    assert database.read_bytes() == before
    assert sorted(path.name for path in root.iterdir()) == contents


def test_old_project_dry_run_is_read_only_and_reports_unresolved_rows(tmp_path, monkeypatch):
    root = tmp_path / "old"
    database = _realm(root, old=True)
    with sqlite3.connect(database) as connection:
        _generation(connection, "evidence", {"untouched": True}, task_id="task-a", intent={"model": "wan", "target": "runpod", "tags": ["fixture"]})
        _generation(connection, "imported", {"provenance": {"origin": "imported"}, "params": {"content_type": "image"}})
        _generation(connection, "opaque", {}, task_id="task-b")
        _generation(connection, "bad-json", "not-json")
        _generation(connection, "bad-gen", {"gen": []})
        _generation(connection, "bad-spec", {}, task_id="task-c", spec={"generation_intent": []})
    before = database.read_bytes()
    original_connect = sqlite3.connect
    connections = []

    def read_only_connect(path, *args, **kwargs):
        assert kwargs.get("uri") is True
        assert str(path).endswith("?mode=ro")
        connection = original_connect(path, *args, **kwargs)
        connections.append(connection)
        connection.set_authorizer(lambda action, first, second, db, trigger:
                                  sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_READ and first == "command_idempotency" else sqlite3.SQLITE_OK)
        return connection

    monkeypatch.setattr(sqlite3, "connect", read_only_connect)
    result = migrate_generation_tags(root, dry_run=True)
    assert connections
    assert result["candidate_count"] == 2 and result["migrated"] == 0
    assert result["dry_run"] is True and result["skip_ledger"] is True
    assert {item["generation_id"]: item["reason"] for item in result["skipped"]} == {
        "opaque": "insufficient_evidence", "bad-json": "malformed_metadata",
        "bad-gen": "malformed_gen", "bad-spec": "malformed_generation_intent",
    }
    assert database.read_bytes() == before
    assert not (root / "realm.sqlite3-journal").exists()


def test_apply_preserves_metadata_and_existing_gen_values_is_idempotent_and_skips_ledger(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    database = _realm(root)
    with sqlite3.connect(database) as connection:
        _generation(connection, "evidence", {"other": {"kept": 1}, "gen": {"model": "authoritative"}},
                    task_id="task-a", intent={"kind": "video", "model": "historical", "target": "runpod", "tags": ["a"]})
        ledger = connection.execute("SELECT * FROM command_idempotency").fetchall()
    original_connect = sqlite3.connect

    def deny_ledger_connect(*args, **kwargs):
        connection = original_connect(*args, **kwargs)
        connection.set_authorizer(lambda action, first, second, db, trigger:
                                  sqlite3.SQLITE_DENY if first == "command_idempotency" else sqlite3.SQLITE_OK)
        return connection

    monkeypatch.setattr(sqlite3, "connect", deny_ledger_connect)
    result = migrate_generation_tags(root, dry_run=False, confirmation=CONFIRMATION)
    assert result["migrated"] == 1 and result["skip_ledger"] is True
    repeated = migrate_generation_tags(root, dry_run=False, confirmation=CONFIRMATION)
    assert repeated["migrated"] == 0
    assert repeated["skipped"] == [{"generation_id": "evidence", "reason": "already_current"}]
    with original_connect(database) as connection:
        metadata, version = connection.execute("SELECT metadata_json, version FROM generations").fetchone()
        assert json.loads(metadata) == {"other": {"kept": 1}, "gen": {
            "kind": "video", "model": "authoritative", "target": "runpod", "tags": ["a"],
            "task_id": "task-a", "run_id": "run-task-a",
        }}
        assert version == 2
        assert connection.execute("SELECT * FROM command_idempotency").fetchall() == ledger


@pytest.mark.parametrize("dry_run", [True, False])
def test_backfill_requires_stopped_runtime(tmp_path, dry_run):
    root = tmp_path / "realm"
    _realm(root)
    owner = RealmStore(root)
    try:
        with pytest.raises(OwnerBusyError):
            migrate_generation_tags(root, dry_run=dry_run, confirmation=CONFIRMATION)
    finally:
        owner.close()


def test_apply_requires_exact_confirmation_before_mutation(tmp_path):
    root = tmp_path / "realm"
    database = _realm(root)
    before = database.read_bytes()
    with pytest.raises(ValidationError, match="confirmation exactly"):
        migrate_generation_tags(root, dry_run=False, confirmation="MIGRATE GENERATION TAGS wrong-realm")
    assert database.read_bytes() == before


def test_runtime_admin_cli_exposes_dry_run_and_skip_ledger(tmp_path, capsys):
    root = tmp_path / "realm"
    _realm(root, old=True)
    assert cli.main(["migrate-generation-tags", "--root", str(root), "--dry-run", "--skip-ledger"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["dry_run"] is True and result["skip_ledger"] is True
    assert result["schema_version"] == 31


def test_backfill_uses_effect_evidence_and_honors_project_scope(tmp_path):
    root = tmp_path / "realm"
    database = _realm(root)
    with sqlite3.connect(database) as connection:
        _generation(connection, "effect", {"legacy": "kept"}, task_id="task-a", effect={
            "effect_type": "generation.create_with_variant", "payload": {"metadata": {"gen": {"origin": "generated", "model": "explicit"}}},
        })
        connection.execute(
            "INSERT INTO projects(id, realm_id, slug, name, metadata_json, created_at, updated_at) VALUES ('other-project', 'realm-tags', 'other', 'Other', '{}', ?, ?)",
            (STAMP, STAMP),
        )
        _generation(connection, "other", {"provenance": {"origin": "imported"}})
        connection.execute("UPDATE generations SET project_id='other-project' WHERE id='other'")
    result = migrate_generation_tags(root, project_id="project-tags", dry_run=False, confirmation=CONFIRMATION)
    assert result["migrated"] == 1 and result["skipped_count"] == 0
    with sqlite3.connect(database) as connection:
        metadata = {identity: json.loads(body) for identity, body in connection.execute("SELECT id, metadata_json FROM generations")}
    assert metadata["effect"]["gen"]["model"] == "explicit"
    assert "gen" not in metadata["other"]


def test_backfill_reports_conflicting_evidence_without_guessing(tmp_path):
    root = tmp_path / "realm"
    database = _realm(root)
    with sqlite3.connect(database) as connection:
        _generation(connection, "conflict", {}, task_id="task-a", intent={"model": "intent"}, effect={
            "effect_type": "generation.create_with_variant", "payload": {"metadata": {"gen": {"model": "effect"}}},
        })
    result = migrate_generation_tags(root, dry_run=False, confirmation=CONFIRMATION)
    assert result["migrated"] == 0
    assert result["skipped"] == [{"generation_id": "conflict", "reason": "conflicting_evidence"}]


def test_backfill_rejects_source_project_mismatch(tmp_path):
    root = tmp_path / "realm"
    database = _realm(root)
    with sqlite3.connect(database) as connection:
        _generation(connection, "mismatch", {}, task_id="task-a", intent={"model": "explicit"})
        connection.execute(
            "INSERT INTO projects(id, realm_id, slug, name, metadata_json, created_at, updated_at) VALUES ('other-project', 'realm-tags', 'other', 'Other', '{}', ?, ?)",
            (STAMP, STAMP),
        )
        connection.execute("UPDATE runs SET project_id='other-project' WHERE id='run-task-a'")
    result = migrate_generation_tags(root, dry_run=False, confirmation=CONFIRMATION)
    assert result["migrated"] == 0
    assert result["skipped"] == [{"generation_id": "mismatch", "reason": "source_project_mismatch"}]


def test_imported_kind_uses_only_explicit_runtime_content_type(tmp_path):
    root = tmp_path / "realm"
    database = _realm(root)
    with sqlite3.connect(database) as connection:
        _generation(connection, "imported", {"provenance": {"origin": "imported"}, "params": {"content_type": "image"}})
        _generation(connection, "other", {"provenance": {"origin": "imported"}, "params": {"content_type": "unknown"}})
    assert migrate_generation_tags(root, dry_run=False, confirmation=CONFIRMATION)["migrated"] == 2
    with sqlite3.connect(database) as connection:
        values = {identity: json.loads(body)["gen"] for identity, body in connection.execute("SELECT id, metadata_json FROM generations")}
    assert values["imported"] == {"kind": "image", "origin": "imported"}
    assert values["other"] == {"origin": "imported"}


def test_backfill_timeout_rolls_back_earlier_rows(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    database = _realm(root)
    with sqlite3.connect(database) as connection:
        for identity in ("a", "b", "c"):
            _generation(connection, identity, {"provenance": {"origin": "imported"}})
        before = connection.execute("SELECT * FROM generations ORDER BY id").fetchall()
    clock = [1.0]
    original = upgrade._generation_tag_evidence

    def evidence_and_advance(connection, generation, *, version):
        result = original(connection, generation, version=version)
        if generation["id"] == "b":
            clock[0] = 1000.0
        return result

    monkeypatch.setattr(upgrade.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(upgrade, "_generation_tag_evidence", evidence_and_advance)
    with pytest.raises(TimeoutError, match="timed out"):
        migrate_generation_tags(root, dry_run=False, confirmation=CONFIRMATION, timeout_seconds=1)
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT * FROM generations ORDER BY id").fetchall() == before
