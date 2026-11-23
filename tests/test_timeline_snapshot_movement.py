"""An isolated result can be served without retaining a stale proof."""
import json
from contextlib import closing
import sqlite3

import pytest

from runtime_protocol.errors import ProtocolError
from runtime_protocol.timeline_commit_store import TimelineCommitStore
from runtime_protocol.util import canonical_json
from test_timeline_commit_authentication import body, provider
from test_timeline_commit_port import commit, service
from test_timeline_verified_reads import next_request


def test_external_unrelated_write_serves_snapshot_but_next_read_reverifies(service, monkeypatch):
    provider(service)
    accepted = commit(service, body(service))
    commits, _ = service._timeline_commits()
    commits.clear_replay_memo()
    original = TimelineCommitStore._verify_accepted_replay
    reads = []

    def replay(reader, *args, **kwargs):
        result = original(reader, *args, **kwargs)
        reads.append(reader)
        if len(reads) == 1:
            with closing(sqlite3.connect(service.store.db_path, isolation_level=None)) as writer:
                writer.execute("UPDATE timelines SET name=COALESCE(name, '') || ' changed' WHERE id='main'")
        return result

    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted_replay", replay)
    result = service.get_timeline_verified_head(service.test_project, "main", authorize=lambda: None)
    assert result["head"]["publication_id"] == accepted["receipt"]["receipt_id"]
    assert len(reads) == 1
    assert not commits._replay_memo
    assert service.get_timeline_verified_head(service.test_project, "main", authorize=lambda: None) == result
    assert len(reads) == 2


def test_fixed_head_history_tamper_serves_snapshot_and_save_matches_base(service, monkeypatch):
    provider(service)
    first = commit(service, body(service))
    second = commit(service, next_request(service), key="second")
    save_request = next_request(service)
    change = save_request["commands"][0]["args"]["changes"][0]
    change["before"] = {"state": "present", "value": {"org.example.timeline": {"note": "second"}}}
    change["value"] = {"org.example.timeline": {"note": "third"}}
    save_request["steps"][0]["patch"] = [dict(change)]
    commits, _ = service._timeline_commits()
    commits.clear_replay_memo()
    original = TimelineCommitStore.verified_head
    calls = []

    def tamper(reader, *args, **kwargs):
        result = original(reader, *args, **kwargs)
        calls.append(True)
        if len(calls) == 1:
            with closing(sqlite3.connect(service.store.db_path, isolation_level=None)) as writer:
                publication = first["receipt"]["receipt_id"]
                value = writer.execute("SELECT records_json FROM timeline_commit_history WHERE publication_id=?",
                                       (publication,)).fetchone()[0]
                records = json.loads(value)
                records["steps"][0]["patch"] = []
                writer.execute("UPDATE timeline_commit_history SET records_json=? WHERE publication_id=?",
                               (canonical_json(records), publication))
        return result

    monkeypatch.setattr(TimelineCommitStore, "verified_head", tamper)
    result = service.get_timeline_verified_head(service.test_project, "main", authorize=lambda: None)
    assert result["head"]["publication_id"] == second["receipt"]["receipt_id"]
    assert calls == [True]
    assert not commits._replay_memo
    assert not any(commits._history_state.values())
    replay = TimelineCommitStore._verify_accepted_replay
    replayed = []

    def observe_replay(reader, row, edge, *args, **kwargs):
        if reader is commits:
            replayed.append(edge["publication_id"])
        return replay(reader, row, edge, *args, **kwargs)

    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted_replay", observe_replay)
    outcome = commit(service, save_request, key="after-tamper")
    assert second["receipt"]["receipt_id"] in replayed
    assert outcome["data"]["status"] == "accepted"
    assert outcome["receipt"]["receipt_id"] != second["receipt"]["receipt_id"]
    head = commits._public_head(service.store.conn, service.test_project, "main")
    assert head["publication_id"] == outcome["receipt"]["receipt_id"]
    with pytest.raises(ProtocolError):
        commits.history_entry(service.test_project, "main", first["receipt"]["receipt_id"])


def test_other_timeline_commit_serves_snapshot_without_retaining_proof(service, monkeypatch):
    from runtime_protocol.timeline_commit_port import route_path

    provider(service)
    accepted = commit(service, body(service))
    service.create_timeline(service.test_project, "other", idempotency_key="create-other")
    other_head = service.get_project_timeline(service.test_project, "other")
    other_request = body(service)
    other_request.update(timeline_id="other", base_revision_id=other_head["head_revision_id"],
                         base_publication_id=other_head["head_publication_id"])
    commits, _ = service._timeline_commits()
    commits.clear_replay_memo()
    original = TimelineCommitStore.verified_head
    replay = TimelineCommitStore._verify_accepted_replay
    reads = []
    replayed = []

    def count_replays(reader, row, edge, *args, **kwargs):
        if edge["timeline_id"] == "main":
            replayed.append(edge["publication_id"])
        return replay(reader, row, edge, *args, **kwargs)

    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted_replay", count_replays)

    def commit_other(reader, *args, **kwargs):
        result = original(reader, *args, **kwargs)
        reads.append(True)
        if len(reads) == 1:
            written = service.commit_timeline(
                service.test_project, "other", other_request, idempotency_key="other-edit",
                publisher="editor", invocation_path=route_path(service.test_project, "other"),
                authorize=lambda: None,
            )
            assert written["data"]["status"] == "accepted"
        return result

    monkeypatch.setattr(TimelineCommitStore, "verified_head", commit_other)
    result = service.get_timeline_verified_head(service.test_project, "main", authorize=lambda: None)
    assert result["head"]["publication_id"] == accepted["receipt"]["receipt_id"]
    assert reads == [True]
    assert replayed == [accepted["receipt"]["receipt_id"]]
    assert not commits._replay_memo
    assert service.get_timeline_verified_head(service.test_project, "main", authorize=lambda: None) == result
    assert reads == [True, True]
    assert replayed == [accepted["receipt"]["receipt_id"]] * 2
