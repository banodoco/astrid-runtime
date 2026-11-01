from __future__ import annotations

import copy
import hashlib
import json
import tarfile

import pytest

from precut_realm_fixture import (
    ARCHIVE,
    VARIANT_ARCHIVES,
    load_precut_realm_fixture,
    readonly_tree_digest,
)
from runtime_protocol.errors import RetiredRouteError
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_baseline import verify_baseline
from runtime_protocol.timeline_commit_validation import validate_commit_value
from runtime_protocol.util import canonical_json
from test_timeline_commit_validation import prepared


VARIANTS = [
    ("music-documents", "film-move-baseline", "film-two-clip-publication"),
    ("anchor", "input-anchor-baseline", "input-anchor-baseline"),
    ("raw", "raw-parent", "raw-publication"),
]


def _baseline(root, pins):
    service = RuntimeService(root)
    try:
        changes = service.store.conn.total_changes
        result = verify_baseline(
            service.store.conn, pins["project_id"], pins["timeline_id"],
            read_object=service.cas.read,
        )
        assert service.store.conn.total_changes == changes
        return result
    finally:
        service.close()


def _expected_payloads(original, variant):
    parent = copy.deepcopy(original["parent_revision"]["payload"])
    internals = copy.deepcopy(original["internal_timeline_revisions"])
    shots = copy.deepcopy(original["shot_revisions"])
    if variant == "music-documents":
        parent["config"]["tracks"].append({"id": "music-2", "kind": "audio"})
        parent["clips"].append({
            "id": "music-other", "clipType": "audio", "asset": "music-bed",
            "track": "music-2", "at": 0, "hold": 5.5,
            "extension": {"opaque": [None, {"keep": True}]},
        })
        parent["config"]["clips"] = copy.deepcopy(parent["clips"])
    elif variant == "anchor":
        parent["clips"][0]["at"] = 0.25
        parent["clips"][0]["app"] = {
            "on": "word:word-1", "astrid": {"on": "word:word-1", "fixed_start": False, "for": 5.5},
        }
        parent["config"]["clips"] = copy.deepcopy(parent["clips"])
    else:
        parent["config"]["output"] = {
            "fps": 24, "background": None, "future_output": {"clear": None},
        }
        parent["config"]["future_config"] = None
        parent["future_parent"] = {"opaque": [None, False]}
        internal = internals[0]
        shot = next(image for image in shots
                    if image["internal_timeline_revision_id"] == internal["revision_id"])
        raw = internal["payload"]
        raw["output"] = copy.deepcopy(parent["config"]["output"])
        raw["output"]["fps"] = {"numerator": 30000, "denominator": 1001}
        raw["playback"] = {"future_playback": None}
        raw["future_internal"] = {"opaque": [None, False]}
        raw["tracks"][0]["future_track"] = None
        raw["clips"][0].update(volume=None, future_clip={"clear": None})
        old_shot_revision = shot["revision_id"]
        internal["revision_id"] = "raw-internal"
        shot["revision_id"] = "raw-shot"
        shot["internal_timeline_revision_id"] = "raw-internal"
        shot["payload"]["internal_timeline_revision_id"] = "raw-internal"
        for occurrence in parent["occurrences"]:
            if occurrence["shot_revision_id"] == old_shot_revision:
                occurrence["shot_revision_id"] = "raw-shot"
        for image in (internal, shot):
            image["content_digest"] = RuntimeService._revision_digest(image["payload"])
    return parent, internals, shots


@pytest.mark.parametrize("variant, revision, key", VARIANTS)
def test_variants_restore_exact_historical_images_and_publication_identity(tmp_path, variant, revision, key):
    original = load_precut_realm_fixture(tmp_path)
    original_baseline = _baseline(original.copy_roots[0], original.pins)
    captured = load_precut_realm_fixture(tmp_path, variant=variant)
    archive = VARIANT_ARCHIVES[variant]
    assert archive.stat().st_size < 40_000
    with tarfile.open(archive) as contents:
        assert all(member.name == "backup" or member.name.startswith("backup/")
                   for member in contents.getmembers())
        assert {member.name for member in contents.getmembers() if member.isfile()} == {
            "backup/manifest.json", "backup/cas-manifest.json", "backup/realm.sqlite3",
            *("backup/" + path.relative_to(captured.backup_root).as_posix()
              for path in (captured.backup_root / "cas").rglob("*") if path.is_file()),
        }
    assert captured.manifest["schema"]["version"] == 31
    assert captured.manifest["realm"] == original.manifest["realm"]
    assert captured.pins["parent_revision_id"] == revision
    assert captured.pins["publication_id"] is None
    for name, value in original.pins.items():
        if name not in {"parent_revision_id", "publication_event_id", "publication_event_ids",
                        "publication_receipt_id", "publication_payload"}:
            assert captured.pins[name] == value

    before = readonly_tree_digest(captured.backup_root)
    assert all(readonly_tree_digest(root) == before for root in captured.copy_roots)
    expected_parent, expected_internals, expected_shots = _expected_payloads(
        original_baseline["canonical_document"], variant,
    )
    baselines = [_baseline(root, captured.pins) for root in captured.copy_roots]
    assert baselines[0] == baselines[1]
    for baseline in baselines:
        assert len(baseline["entries"]) == 2
        assert baseline["entries"][0] == original_baseline["entries"][0]
        receipt = baseline["entries"][-1]["receipt"]
        assert receipt["idempotency_key"] == key
        assert receipt["receipt_id"] == captured.pins["publication_receipt_id"]
        assert receipt["event_ids"] == list(captured.pins["publication_event_ids"])
        assert receipt["result"]["new_head"] == revision
        assert baseline["head"] == {
            "revision_id": revision, "publication_id": receipt["receipt_id"],
        }
        assert captured.pins["publication_payload"]["new_head"] == revision
        document = baseline["canonical_document"]
        assert document["parent_revision"]["payload"] == expected_parent
        for kind, expected in (("internal_timeline_revisions", expected_internals),
                               ("shot_revisions", expected_shots)):
            assert {image["revision_id"]: image for image in document[kind]} == {
                image["revision_id"]: image for image in expected
            }
        value = prepared()
        value["canonical_document"] = document
        value["document_digest"] = baseline["document_digest"]
        before_validation = canonical_json(value)
        validate_commit_value(value, "PreparedCommit")
        assert canonical_json(value) == before_validation
        for image in [document["parent_revision"], *document["internal_timeline_revisions"],
                      *document["shot_revisions"]]:
            assert image["content_digest"] == RuntimeService._revision_digest(image["payload"])
    for root in captured.copy_roots:
        handoff = json.loads((root / "activation-handoff.json").read_text())
        assert handoff["candidate_database_sha256"] == captured.manifest["database_sha256"]
    assert readonly_tree_digest(captured.backup_root) == before
    assert hashlib.sha256(ARCHIVE.read_bytes()).hexdigest() == (
        "e304773208ff96cea0dca545c69cfa3fcb7ef605c01c306017ed8bcfc654a6b5"
    )


def test_canonical_documents_have_genuine_create_receipts_and_refuse_bypass(tmp_path):
    captured = load_precut_realm_fixture(tmp_path, variant="music-documents")
    service = RuntimeService(captured.copy_roots[0])
    project = captured.pins["project_id"]
    try:
        parent = service.get_project_parent_composition_revision(project, "film", "film-parent-v1")["payload"]
        internal = service.get_project_timeline_revision(project, "film", "film-internal-1")["payload"]
        for document_id, content in (("timeline:film", parent), ("legacy-projection", parent),
                                     ("timeline:shot:shot-1", internal)):
            document = service.get_document(project, document_id)
            assert document["kind"] == "timeline.composition"
            assert document["version"] == 1
            assert document["content"] == content
            request = {"project_id": project, "document_id": document_id,
                       "kind": document["kind"], "content": content}
            row = service.store.conn.execute(
                "SELECT * FROM command_idempotency WHERE command_kind='document.create' AND aggregate_id=?",
                (document_id,),
            ).fetchone()
            assert row is not None and row["txn_id"]
            assert row["request_hash"] == hashlib.sha256(canonical_json(request).encode()).hexdigest()
            assert json.loads(row["result_json"]) == document
            before = (service.store.conn.total_changes, tuple(service.store.conn.iterdump()))
            for kind in ("timeline.composition", "example.notes"):
                with pytest.raises(RetiredRouteError):
                    service.create_document(project, {
                        "document_id": document_id, "kind": kind, "content": content,
                    }, idempotency_key=row["idempotency_key"])
            with pytest.raises(RetiredRouteError):
                service.update_document(project, document_id, {
                    "expected_version": 1, "kind": "example.notes", "content": content,
                }, idempotency_key="forbidden-update")
            assert (service.store.conn.total_changes, tuple(service.store.conn.iterdump())) == before
    finally:
        service.close()


def test_anchor_capture_stops_before_input_acceptance_and_preserves_source_config(tmp_path):
    captured = load_precut_realm_fixture(tmp_path, variant="anchor")
    service = RuntimeService(captured.copy_roots[0])
    try:
        project = captured.pins["project_id"]
        transcript = service.get_document(project, captured.pins["transcript_document_id"])
        config = service.get_document(project, "film.config")
        assert config["version"] == transcript["version"] == 1
        assert config["content"] == {
            "schema": "film.config/v1", "enabled": True, "opaque": [None, {"keep": True}],
            "source": {"media_id": transcript["content"]["media_id"],
                       "source_id": transcript["content"]["source_id"], "word_id": "word-1"},
            "time_map": {"source_offset": 0, "speed": 1},
        }
        baseline = verify_baseline(service.store.conn, project, "film", read_object=service.cas.read)
        assert baseline["canonical_document"]["dependency_manifest"]["documents"] == []
        assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_commit_history").fetchone()[0] == 0
    finally:
        service.close()


@pytest.mark.parametrize("variant", ["../precut-v31", "precut-v31.tar.gz", "unknown"])
def test_archive_selection_is_bounded(tmp_path, variant):
    with pytest.raises(ValueError, match="unknown pre-cut fixture variant"):
        load_precut_realm_fixture(tmp_path, variant=variant)
    assert list(tmp_path.iterdir()) == []
