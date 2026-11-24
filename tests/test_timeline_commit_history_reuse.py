"""Proof reuse must remain bounded by real SQLite writes."""
from contextlib import closing
import sqlite3

import pytest

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


def _record_idle_claim(service, key):
    # The production command recorder runs inside the RealmStore mutex.
    with service.store._mutex:
        service._command_record("task.claim", "idle", key, "request", {"task": None})


def test_idle_claims_during_verified_read_preserve_memo_and_expire_old_rows(service, monkeypatch):
    provider(service)
    accepted = commit(service, body(service))
    commits, _ = service._timeline_commits()
    _record_idle_claim(service, "old-claim")
    with service.store._mutex:
        service.store.conn.execute(
            "UPDATE temp.session_command_replay SET created_at='2000-01-01T00:00:00+00:00' "
            "WHERE idempotency_key='old-claim'"
        )
    commits.clear_replay_memo()
    original = TimelineCommitStore.verified_head
    calls = []

    def poll_during_read(reader, *args, **kwargs):
        result = original(reader, *args, **kwargs)
        # Simulates several idle polls while one slow history replay is in flight.
        for index in range(6):
            _record_idle_claim(service, f"during-{len(calls)}-{index}")
        calls.append(True)
        return result

    monkeypatch.setattr(TimelineCommitStore, "verified_head", poll_during_read)
    result = service.get_timeline_verified_head(service.test_project, "main", authorize=lambda: None)
    assert result["head"]["publication_id"] == accepted["receipt"]["receipt_id"]
    assert calls == [True]
    assert service.store.conn.execute(
        "SELECT is_expired FROM temp.session_command_replay WHERE idempotency_key='old-claim'"
    ).fetchone()[0] == 1
    generation = commits._replay_generation
    assert commits._replay_memo
    monkeypatch.setattr(TimelineCommitStore, "verified_head", original)
    service.get_timeline_verified_head(service.test_project, "main", authorize=lambda: None)
    assert commits._replay_generation == generation
    assert commits._replay_memo


def test_rolled_back_replay_write_remains_attributed(service):
    provider(service)
    commit(service, body(service))
    commits, _ = service._timeline_commits()
    calls = []

    def read(reader):
        calls.append(True)
        with service.store._mutex:
            service.store.conn.execute("BEGIN IMMEDIATE")
            try:
                _record_idle_claim(service, f"rollback-{len(calls)}")
            finally:
                service.store.conn.rollback()
        return "ok"

    assert commits.read_isolated(service.test_project, "main", prepare=lambda: None,
                                 authorize=lambda: None, read=read) == "ok"
    assert calls == [True]


def test_replay_trigger_main_write_still_forces_retry(service):
    provider(service)
    commit(service, body(service))
    commits, _ = service._timeline_commits()
    with service.store._mutex:
        service.store.conn.execute(
            "CREATE TEMP TRIGGER replay_main_write AFTER INSERT ON session_command_replay "
            "BEGIN UPDATE timelines SET name=COALESCE(name, '') || ' trigger'; END"
        )
    calls = []

    def read(reader):
        calls.append(True)
        if len(calls) == 1:
            _record_idle_claim(service, "trigger-claim")
        return "ok"

    assert commits.read_isolated(service.test_project, "main", prepare=lambda: None,
                                 authorize=lambda: None, read=read) == "ok"
    assert len(calls) == 2


def test_unaccounted_temp_write_still_forces_retry(service):
    provider(service)
    commit(service, body(service))
    commits, _ = service._timeline_commits()
    service.store.conn.execute("CREATE TEMP TABLE unaccounted (n INTEGER)")
    calls = []

    def read(reader):
        calls.append(True)
        if len(calls) == 1:
            with service.store._mutex:
                service.store.conn.execute("INSERT INTO temp.unaccounted VALUES (1)")
        return "ok"

    assert commits.read_isolated(service.test_project, "main", prepare=lambda: None,
                                 authorize=lambda: None, read=read) == "ok"
    assert len(calls) == 2


def test_history_then_verified_head_survives_idle_claims(service, monkeypatch):
    provider(service)
    accepted = commit(service, body(service))
    service.register_executor({"executor_id": "worker", "capabilities": []})
    epoch = service.health()["runtime_epoch"]
    commits, _ = service._timeline_commits()
    commits.clear_replay_memo()
    original = TimelineCommitStore._verify_accepted_replay
    calls = []

    def poll_during_history(reader, *args, **kwargs):
        result = original(reader, *args, **kwargs)
        calls.append(True)
        for index in range(6):
            assert service.claim_next(
                {"executor_id": "worker", "capability_ids": [], "runtime_epoch": epoch},
                idempotency_key=f"history-{len(calls)}-{index}",
            ) is None
        return result

    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted_replay", poll_during_history)
    request = handler(service, "commits?limit=1")
    request._dispatch()
    assert request.reply[0] == 200, request.error
    assert request.reply[1]["head"]["publication_id"] == accepted["receipt"]["receipt_id"]
    assert len(calls) == 1
    generation = commits._replay_generation
    head = service.get_timeline_verified_head(service.test_project, "main", authorize=lambda: None)
    assert head["head"]["publication_id"] == accepted["receipt"]["receipt_id"]
    assert len(calls) == 1
    assert commits._replay_generation == generation


def test_same_connection_durable_write_with_replay_still_forces_retry(service):
    provider(service)
    commit(service, body(service))
    commits, _ = service._timeline_commits()
    calls = []

    def read(reader):
        calls.append(True)
        if len(calls) == 1:
            with service.store._mutex:
                _record_idle_claim(service, "mixed-claim")
                service.store.conn.execute(
                    "UPDATE timelines SET name=COALESCE(name, '') || ' changed' WHERE project_id=?",
                    (service.test_project,),
                )
        return "ok"

    assert commits.read_isolated(service.test_project, "main", prepare=lambda: None,
                                 authorize=lambda: None, read=read) == "ok"
    assert len(calls) == 2


def test_external_write_during_isolated_read_forces_retry(service):
    provider(service)
    commit(service, body(service))
    commits, _ = service._timeline_commits()
    calls = []

    def read(reader):
        calls.append(True)
        if len(calls) == 1:
            with closing(sqlite3.connect(service.store.db_path, isolation_level=None)) as writer:
                writer.execute("UPDATE timelines SET name=COALESCE(name, '') || ' external' WHERE project_id=?",
                               (service.test_project,))
        return "ok"

    assert commits.read_isolated(service.test_project, "main", prepare=lambda: None,
                                 authorize=lambda: None, read=read) == "ok"
    assert len(calls) == 2


def test_replay_credit_is_not_transferred_between_connections(service):
    provider(service)
    commit(service, body(service))
    commits, _ = service._timeline_commits()
    original = service.store.conn
    _record_idle_claim(service, "original-credit")
    with service.store._mutex:
        before = commits._store_version()
        assert before[1] < original.total_changes
        other = sqlite3.connect(":memory:", isolation_level=None)
        try:
            other.execute(
                "CREATE TEMP TABLE session_command_replay ("
                "command_kind TEXT NOT NULL, aggregate_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, "
                "request_hash TEXT NOT NULL, result_json TEXT NOT NULL, created_at TEXT NOT NULL, "
                "is_expired INTEGER NOT NULL DEFAULT 0, "
                "PRIMARY KEY(command_kind, aggregate_id, idempotency_key))"
            )
            service.store.conn = other
            _record_idle_claim(service, "replacement-credit")
            # A credit established on a different connection must not reduce
            # the fence when the original connection returns.
            service.store.conn = original
            after = commits._store_version()
            assert after[1] == original.total_changes
            assert after[1] > before[1]
        finally:
            service.store.conn = original
            other.close()


def test_failed_replay_trigger_with_main_side_effect_forces_retry(service):
    provider(service)
    commit(service, body(service))
    commits, _ = service._timeline_commits()
    with service.store._mutex:
        service.store.conn.execute(
            "CREATE TEMP TRIGGER failed_replay AFTER INSERT ON session_command_replay "
            "BEGIN UPDATE timelines SET name=COALESCE(name, '') || ' failed trigger'; "
            "SELECT RAISE(FAIL, 'replay failure'); END"
        )
    calls = []

    def read(reader):
        calls.append(True)
        if len(calls) == 1:
            with pytest.raises(sqlite3.IntegrityError, match="replay failure"):
                _record_idle_claim(service, "failing-claim")
        return "ok"

    assert commits.read_isolated(service.test_project, "main", prepare=lambda: None,
                                 authorize=lambda: None, read=read) == "ok"
    assert len(calls) == 2
    assert service.store.conn.execute(
        "SELECT name FROM timelines WHERE project_id=?", (service.test_project,)
    ).fetchone()[0].endswith(" failed trigger")


def test_history_row_mutation_during_both_verifications_refuses_result(service, monkeypatch):
    from runtime_protocol.errors import HeadBusyError

    provider(service)
    accepted = commit(service, body(service))
    publication = accepted["receipt"]["receipt_id"]
    commits, _ = service._timeline_commits()
    commits.clear_replay_memo()
    original = TimelineCommitStore.verified_head
    calls = []

    def mutate_after_verification(reader, *args, **kwargs):
        result = original(reader, *args, **kwargs)
        calls.append(True)
        with service.store._mutex:
            _record_idle_claim(service, f"mutation-claim-{len(calls)}")
            from tests.history_forgery import forge_history_row
            changed = forge_history_row(service.store.conn,
                "UPDATE timeline_commit_history SET metadata_json=metadata_json || ' ' WHERE publication_id=?",
                (publication,),
            )
            assert changed.rowcount == 1
        return result

    monkeypatch.setattr(TimelineCommitStore, "verified_head", mutate_after_verification)
    with pytest.raises(HeadBusyError):
        service.get_timeline_verified_head(service.test_project, "main", authorize=lambda: None)
    assert len(calls) == 2


def test_replay_write_helper_rejects_arbitrary_main_sql(service):
    before = service.store.conn.total_changes
    with pytest.raises(ValueError):
        service._session_replay_write("UPDATE main.timelines SET name='tampered'", ())
    assert service.store.conn.total_changes == before
