from __future__ import annotations

import hashlib
import json
import sqlite3

import pytest

from precut_realm_fixture import FIXTURE_BACKUP_KEY, _extract_archive, readonly_tree_digest
from restore_history_fixture import ARCHIVE, load_restore_history_fixture
from runtime_protocol.backup import verify_backup
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_baseline import baseline_install_plan, verify_baseline
from runtime_protocol.util import canonical_json
from test_shot_composition_runtime import (
    _restore,
    _select_restore_provider,
    restore_provider,  # noqa: F401 (real Agent fixture)
)
from test_timeline_commit_baseline import _disable_renderer


DIGESTS = {
    "parent": "sha256:89c0b9129bbda1ab783ff843d4fa0ce82a90f814793d0e57e5ad252d3259d574",
    "shot-rev-1": "sha256:0deb93fbdd9338a5ea8c1e439b709152ddc3713cd1b5237a95f54d48fdcd5c16",
    "timeline-rev-1": "sha256:5c6bc59f300d4c065a6c9c09c09b0c756e2c773f2479ec32a42bfc2ecdb7877c",
}


def _reads(service, project_id):
    return {
        "parent": service.get_project_parent_composition_revision(project_id, "main", "parent-1"),
        "shot-rev-1": service.get_project_shot_revision(project_id, "shot-1", "shot-rev-1"),
        "timeline-rev-1": service.get_project_timeline_revision(project_id, "main", "timeline-rev-1"),
    }


def test_authenticated_capture_has_only_two_parent_images_and_original_counters(tmp_path):
    backup = _extract_archive(tmp_path / "archive", ARCHIVE)
    before = readonly_tree_digest(backup)
    manifest = verify_backup(backup, key=FIXTURE_BACKUP_KEY)["manifest"]
    assert manifest["format_version"] == 2
    assert manifest["schema"]["version"] == 31
    assert manifest["database_sha256"] == "65ccceca86a0ff09bb091ab780fb3ec0b05c2e0bc2f1f9384222b2411d2beb14"
    connection = sqlite3.connect(f"file:{backup / 'realm.sqlite3'}?mode=ro", uri=True)
    try:
        assert connection.execute("SELECT id FROM parent_composition_revisions ORDER BY id").fetchall() == [
            ("parent-1",), ("parent-2",),
        ]
        assert connection.execute("SELECT id FROM shot_revisions").fetchall() == [("shot-rev-1",)]
        # create_timeline's genuine initial internal image is retained too.
        assert connection.execute("SELECT id FROM internal_timeline_revisions ORDER BY id").fetchall() == [
            ("e6c27ea1caaf4bb782724e4b0a45626b",), ("timeline-rev-1",),
        ]
        assert connection.execute("SELECT next_seq FROM project_sequences").fetchall() == [(5,)]
        assert connection.execute("SELECT COUNT(*) FROM timeline_commit_history").fetchone()[0] == 0
        publications = connection.execute(
            "SELECT idempotency_key, first_project_seq, last_project_seq, resulting_stream_seq, result_json "
            "FROM command_idempotency WHERE command_kind='parent_composition.publish' ORDER BY first_project_seq",
        ).fetchall()
        assert [row[:4] for row in publications] == [
            ("history-publish-1", 3, 3, 2), ("history-publish-2", 4, 4, 3),
        ]
        results = [json.loads(row[4]) for row in publications]
        assert [(result["old_head"], result["new_head"]) for result in results] == [
            (None, "parent-1"), ("parent-1", "parent-2"),
        ]
        assert all(result["content_digests"] == DIGESTS for result in results)
        assert results[0]["payload"] == results[1]["payload"]
    finally:
        connection.close()
    assert readonly_tree_digest(backup) == before


def test_loader_reads_and_baseline_install_reopen_preserve_two_publications(tmp_path, monkeypatch):
    fixture = load_restore_history_fixture(tmp_path)
    service = RuntimeService(fixture.root)
    try:
        _disable_renderer(monkeypatch, service)
        before = _reads(service, fixture.project_id)
        for key, image in before.items():
            assert image["content_digest"] == DIGESTS[key]
            assert "sha256:" + hashlib.sha256(canonical_json(image["payload"]).encode()).hexdigest() == DIGESTS[key]
        occurrence = before["parent"]["payload"]["occurrences"][0]
        assert occurrence["muted"] is False and "mute" not in occurrence
        assert before["shot-rev-1"]["payload"]["internal_timeline_revision_id"] == "timeline-rev-1"
        assert fixture.first["data"] == fixture.first["receipt"]["result"]
        assert fixture.first["data"]["payload"] == before["parent"]["payload"]
        assert fixture.first["data"]["content_digests"] == DIGESTS
        assert fixture.first["receipt"]["receipt_id"] == "txn-4a2c3d0712df498cb26fc90c6b793836"
        assert fixture.head == {"revision_id": "parent-2", "publication_id": "txn-4e2af9fa95724c4e8725d60c35f60015"}
        changes = service.store.conn.total_changes
        facts = verify_baseline(service.store.conn, fixture.project_id, "main", read_object=service.cas.read)
        assert service.store.conn.total_changes == changes
        assert facts["entries"][0]["receipt"] == fixture.first["receipt"]
        assert [entry["revision_id"] for entry in facts["entries"]] == ["parent-1", "parent-2"]
        with service.store._transaction():
            plan = baseline_install_plan(service.store.conn, facts, read_object=service.cas.read)
            assert plan == {"head": fixture.head, "entries": facts["entries"], "install": True}
        commits, _ = service._timeline_commits()
        assert commits.install_verified_baseline(fixture.project_id, "main", authorize=lambda: None) == fixture.head
        assert commits.history(fixture.project_id, "main", fixture.head)["items"] == facts["entries"]
        # Installation adds the verified manifest to parent GETs; payloads,
        # digests, timestamps and all child GET fields retain their source values.
        installed_reads = _reads(service, fixture.project_id)
        assert installed_reads["parent"].pop("dependency_manifest") == facts["canonical_document"]["dependency_manifest"]
        assert installed_reads == before
    finally:
        service.close()
    reopened = RuntimeService(fixture.root)
    try:
        commits, _ = reopened._timeline_commits()
        assert commits.head(fixture.project_id, "main") == fixture.head
        assert commits.history(fixture.project_id, "main", fixture.head)["items"] == facts["entries"]
        page_one = reopened.list_project_parent_composition_revisions(fixture.project_id, "main", limit=1)
        page_two = reopened.list_project_parent_composition_revisions(
            fixture.project_id, "main", cursor=page_one["next_cursor"], limit=1,
        )
        assert page_one["next_cursor"] and page_two["next_cursor"] is None
        assert [page_one["items"][0]["revision_id"], page_two["items"][0]["revision_id"]] == ["parent-2", "parent-1"]
        assert _reads(reopened, fixture.project_id)["shot-rev-1"] == before["shot-rev-1"]
        assert _reads(reopened, fixture.project_id)["timeline-rev-1"] == before["timeline-rev-1"]
    finally:
        reopened.close()


@pytest.mark.integration
def test_captured_history_guarded_restore_with_real_agent(tmp_path, monkeypatch, restore_provider):
    fixture = load_restore_history_fixture(tmp_path)
    service = RuntimeService(fixture.root)
    try:
        _disable_renderer(monkeypatch, service)
        children = _reads(service, fixture.project_id)
        guards = _select_restore_provider(service, fixture.project_id, restore_provider)
        assert guards == {"expected_head": fixture.head["revision_id"],
                          "expected_publication_id": fixture.head["publication_id"]}
        commits, _ = service._timeline_commits()
        assert len(commits.history(fixture.project_id, "main", fixture.head)["items"]) == 2
        source = commits.revision_closure(fixture.project_id, "main", "parent-1")
        restored = _restore(service, fixture.project_id, "parent-1", guards, idempotency_key="captured-history-restore")
        accepted = restored["data"]["canonical_document"]
        assert accepted["parent_revision"]["payload"] == fixture.first["data"]["payload"]
        for field in ("shot_revisions", "internal_timeline_revisions", "dependency_manifest"):
            assert accepted[field] == source[field]
        assert restored["receipt"]["result"] == restored["data"]
        assert restored["receipt"]["receipt_id"] not in (
            fixture.head["publication_id"], fixture.first["receipt"]["receipt_id"],
        )
        after = _reads(service, fixture.project_id)
        for key in ("shot-rev-1", "timeline-rev-1"):
            assert after[key] == children[key]
        assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_commit_history").fetchone()[0] == 3
        assert _restore(service, fixture.project_id, "parent-1", guards, idempotency_key="captured-history-restore") == restored
    finally:
        service.close()
