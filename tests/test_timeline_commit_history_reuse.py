"""Proof reuse must remain bounded by real SQLite writes."""
from contextlib import closing
import sqlite3

from runtime_protocol.timeline_commit_store import TimelineCommitStore
from runtime_protocol.service import RuntimeService
from test_timeline_commit_authentication import body, provider
from test_timeline_commit_port import commit, service
from test_timeline_producer_guards import (
    _execute as execute_producer,
    _settle as settle_producer,
    producer as producer_fixture,
)
from test_timeline_verified_reads import next_request
from test_timeline_verified_reads import handler


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


def test_reopened_service_reverifies_persisted_verified_head(service, monkeypatch):
    provider(service)
    first = commit(service, body(service))
    project = service.test_project
    root = service.store.root
    expected = service.get_timeline_verified_head(project, "main", authorize=lambda: None)
    service.close()

    reopened = RuntimeService(root)
    replayed = []
    replay = TimelineCommitStore._verify_accepted_replay

    def observe(self, row, edge, *args, **kwargs):
        replayed.append(edge["publication_id"])
        return replay(self, row, edge, *args, **kwargs)

    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted_replay", observe)
    try:
        actual = reopened.get_timeline_verified_head(project, "main", authorize=lambda: None)
        assert actual == expected
        assert first["receipt"]["receipt_id"] in replayed
    finally:
        reopened.close()


# Plan 78 Runtime follow-up probe; this fixture is generation-backed synthetic
# producer coverage, not evidence of the exact Plan 78 writer path.
def test_public_history_reuses_producer_commit_verification_for_next_commit(producer_fixture):
    service = producer_fixture.service
    settle_producer(producer_fixture)
    producer_commit = execute_producer(producer_fixture)

    assert producer_commit["data"]["status"] == "accepted"
    assert producer_commit["data"]["commands"][-1]["op"] == "clip.move"
    producer_publication = producer_commit["receipt"]["receipt_id"]

    first_history = handler(service, "commits?limit=1")
    first_history._dispatch()
    assert first_history.reply[0] == 200, first_history.error
    assert first_history.reply[1]["items"]
    assert first_history.reply[1]["head"]["publication_id"] == producer_publication

    # The producer fixture already registered this same prepared-provider type.
    service.test_provider = service._timeline_commit_provider
    provider(service)
    annotation = commit(service, body(service), key="annotation-after-producer")
    assert annotation["data"]["status"] == "accepted"

    second_history = handler(service, "commits?limit=1")
    second_history._dispatch()
    assert second_history.reply[0] == 200, second_history.error
    assert second_history.reply[1]["items"]
    assert second_history.reply[1]["head"]["publication_id"] == annotation["receipt"]["receipt_id"]
