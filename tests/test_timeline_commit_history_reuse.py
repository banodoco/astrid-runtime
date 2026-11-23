"""Proof reuse must remain bounded by real SQLite writes."""
from contextlib import closing
import sqlite3

from runtime_protocol.timeline_commit_store import TimelineCommitStore
from test_timeline_commit_authentication import body, provider
from test_timeline_commit_port import commit, service
from test_timeline_verified_reads import next_request


def test_verified_head_reuses_proof_through_first_save_without_intervening_write(service, monkeypatch):
    provider(service)
    first = commit(service, body(service))
    commits, _ = service._timeline_commits()
    commits.clear_replay_memo()
    service.get_timeline_verified_head(service.test_project, "main", authorize=lambda: None)
    generation = commits._replay_generation
    replay = TimelineCommitStore._verify_accepted_replay
    replayed = []

    def observe(self, row, edge, *args, **kwargs):
        replayed.append(edge["publication_id"])
        return replay(self, row, edge, *args, **kwargs)

    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted_replay", observe)
    second = commit(service, next_request(service), key="second")
    assert second["data"]["accepted_revision_id"] != first["data"]["accepted_revision_id"]
    assert first["receipt"]["receipt_id"] not in replayed
    assert commits._replay_generation == generation


def test_external_committed_write_forces_verified_head_reverification(service, monkeypatch):
    provider(service)
    first = commit(service, body(service))
    commits, _ = service._timeline_commits()
    commits.clear_replay_memo()
    head = service.get_timeline_verified_head(service.test_project, "main", authorize=lambda: None)
    initial_version = service.store.conn.execute("PRAGMA data_version").fetchone()[0]
    initial_changes = service.store.conn.total_changes
    replay = TimelineCommitStore._verify_accepted_replay
    replayed = []

    def observe(self, row, edge, *args, **kwargs):
        replayed.append(edge["publication_id"])
        return replay(self, row, edge, *args, **kwargs)

    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted_replay", observe)
    with closing(sqlite3.connect(service.store.db_path, isolation_level=None)) as writer:
        changed = writer.execute("UPDATE timelines SET name=COALESCE(name, '') || ' external' WHERE project_id=?",
                                 (service.test_project,))
        assert changed.rowcount == 1
    assert service.store.conn.total_changes == initial_changes
    assert service.store.conn.execute("PRAGMA data_version").fetchone()[0] != initial_version
    assert service.get_timeline_verified_head(service.test_project, "main", authorize=lambda: None) == head
    assert first["receipt"]["receipt_id"] in replayed
