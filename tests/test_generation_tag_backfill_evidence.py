from __future__ import annotations

import json
import shutil
import sqlite3

import pytest

from runtime_protocol import cli
from runtime_protocol.errors import ValidationError
from runtime_protocol.upgrade import migrate_generation_tags
from test_generation_tag_migration import CONFIRMATION, _generation, _realm


def _json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_copied_legacy_backfill_recovers_sql_h3_import_manifest_and_receipt_without_ledger(tmp_path):
    original = tmp_path / "original"
    database = _realm(original, old=True)
    workflow = "a" * 64
    with sqlite3.connect(database) as connection:
        _generation(connection, "managed", {"params": {
            "content_type": "image", "model": "X", "target": "managed", "tags": ["hero"],
        }})
        _generation(connection, "runpod", {"h3_av": {
            "graph": {"profile": "h3-template", "workflow": {"sha256": workflow}},
        }}, task_id="h3-task")
        _generation(connection, "fal", {"other": {"preserved": True}})
        _generation(connection, "imported", {"provenance": {"origin": "imported"},
                                              "params": {"content_type": "image"}})
        _generation(connection, "unrecoverable", {})
        ledger = connection.execute("SELECT * FROM command_idempotency").fetchall()
    copied = tmp_path / "copied"
    shutil.copytree(original, copied)
    copied_db = copied / "realm.sqlite3"
    manifests = tmp_path / "manifests"
    receipts = tmp_path / "receipts"
    manifests.mkdir()
    receipts.mkdir()
    _json(manifests / "generations.json", {"generations": [
        {"generation_id": "fal", "project_id": "project-tags", "modality": "video",
         "template_id": "fal-template", "target": "fal", "mode_used": "t2v", "tags": ["hero"]},
        {"generation_id": "imported", "metadata": {"gen": {"origin": "generated", "tags": ["import"]}}},
    ]})
    _json(receipts / "invocation.json", {"realm_id": "realm-tags", "locator": {
        "task_id": "h3-task", "run_id": "run-h3-task",
    }, "metadata": {"gen": {"target": "runpod", "seed": 0, "cost_usd": 0.25, "duration_ms": 12,
                              "tags": ["hero"]}}})
    mapping = _json(tmp_path / "models.json", {"h3-template": "X", "fal-template": "Y"})
    # Neither this sibling nor any path named inside a manifest is traversed.
    _json(tmp_path / "unselected.json", {"generation_id": "unrecoverable", "gen": {"model": "guessed"}})
    before = copied_db.read_bytes()
    arguments = dict(manifest_roots=[manifests], receipt_roots=[receipts], template_model_map=mapping)
    report = migrate_generation_tags(copied, **arguments)
    assert report["dry_run"] is True and report["migrated"] == 0
    assert report["candidate_count"] == 4 and report["skip_ledger"] is True
    assert report["skipped"] == [{"generation_id": "unrecoverable", "reason": "insufficient_evidence"}]
    assert report["source_skipped"] == []
    candidates = {item["generation_id"]: item["gen"] for item in report["candidates"]}
    assert candidates["runpod"] == {
        "generator": "h3_av.transform", "model": "X", "workflow_digest": "sha256:" + workflow,
        "target": "runpod", "task_id": "h3-task", "run_id": "run-h3-task",
        "seed": 0, "cost_usd": 0.25, "duration_ms": 12, "tags": ["hero"],
    }
    assert candidates["imported"]["origin"] == "imported"
    assert candidates["fal"]["model"] == "Y" and candidates["fal"]["kind"] == "video"
    assert copied_db.read_bytes() == before
    applied = migrate_generation_tags(copied, dry_run=False, confirmation=CONFIRMATION, **arguments)
    assert applied["migrated"] == 4
    repeated = migrate_generation_tags(copied, dry_run=False, confirmation=CONFIRMATION, **arguments)
    assert repeated["candidate_count"] == 0 and repeated["migrated"] == 0
    with sqlite3.connect(copied_db) as connection:
        values = {identity: json.loads(body) for identity, body in connection.execute("SELECT id, metadata_json FROM generations")}
        assert values["fal"]["other"] == {"preserved": True}
        assert values["imported"]["provenance"]["origin"] == "imported"
        assert connection.execute("SELECT * FROM command_idempotency").fetchall() == ledger
        assert connection.execute("SELECT version FROM runtime_schema").fetchone()[0] == 31
    assert database.read_bytes() == before


def test_external_conflict_and_identity_mismatch_are_row_skips(tmp_path):
    root = tmp_path / "realm"
    database = _realm(root)
    with sqlite3.connect(database) as connection:
        for name in ("conflict", "foreign", "known"):
            _generation(connection, name, {"gen": {"model": "authoritative"}} if name == "known" else {})
    manifests = _json(tmp_path / "manifest.json", {"generations": [
        {"generation_id": "conflict", "model": "one"},
        {"generation_id": "conflict", "model": "two"},
        {"generation_id": "foreign", "project_id": "another-project", "model": "wrong"},
        {"generation_id": "known", "model": "historical", "tags": ["kept"]},
    ]})
    report = migrate_generation_tags(root, manifest_roots=[manifests])
    assert report["skipped"] == [
        {"generation_id": "conflict", "reason": "conflicting_evidence"},
        {"generation_id": "foreign", "reason": "external_source_identity_mismatch"},
    ]
    assert report["candidates"][0]["gen"] == {"model": "authoritative", "tags": ["kept"]}


def test_explicit_evidence_roots_report_malformed_unbound_and_symlink_files(tmp_path):
    root = tmp_path / "realm"
    _realm(root)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "broken.json").write_text("not json")
    _json(evidence / "unbound.json", {"model": "no identity"})
    target = _json(tmp_path / "outside.json", {"generation_id": "anything", "model": "outside"})
    (evidence / "link.json").symlink_to(target)
    report = migrate_generation_tags(root, manifest_roots=[evidence])
    assert {item["reason"] for item in report["source_skipped"]} == {
        "malformed_evidence_file", "missing_generation_or_task_identity", "unsafe_or_oversized_evidence_file",
    }
    with pytest.raises(ValidationError, match="existing absolute"):
        migrate_generation_tags(root, manifest_roots=["relative"])
    with pytest.raises(ValidationError, match="existing absolute"):
        migrate_generation_tags(root, receipt_roots=[evidence / "link.json"])


def test_sql_intent_modality_and_historical_inputs_supply_missing_fields(tmp_path):
    root = tmp_path / "realm"
    database = _realm(root)
    with sqlite3.connect(database) as connection:
        _generation(connection, "sql", {"preserve": True}, task_id="task", spec={
            "generation_intent": {"modality": "audio", "metadata": {}},
            "inputs": {"template_id": "audio-template", "seed": 0, "execution": "cloud", "mode": "t2a"},
        })
    mapping = _json(tmp_path / "map.json", {"audio-template": "audio-model"})
    report = migrate_generation_tags(root, template_model_map=mapping)
    assert report["candidates"][0]["gen"] == {
        "kind": "audio", "model": "audio-model", "seed": 0, "backend": "cloud", "mode": "t2a",
        "task_id": "task", "run_id": "run-task",
    }


def test_cli_defaults_to_preview_and_apply_is_explicit(tmp_path, capsys):
    root = tmp_path / "realm"
    database = _realm(root)
    with sqlite3.connect(database) as connection:
        _generation(connection, "fixture", {})
    manifest = _json(tmp_path / "manifest.json", {"generation_id": "fixture", "template_id": "template"})
    mapping = _json(tmp_path / "map.json", {"template": "model"})
    args = ["migrate-generation-tags", "--root", str(root), "--manifest-root", str(manifest),
            "--template-model-map", str(mapping), "--skip-ledger"]
    assert cli.main(args) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["dry_run"] is True and preview["candidate_count"] == 1 and preview["migrated"] == 0
    assert cli.main([*args, "--apply"]) == 1
    assert "confirmation exactly" in json.loads(capsys.readouterr().out)["error"]["message"]
    assert cli.main([*args, "--apply", "--confirm", CONFIRMATION]) == 0
    assert json.loads(capsys.readouterr().out)["migrated"] == 1
