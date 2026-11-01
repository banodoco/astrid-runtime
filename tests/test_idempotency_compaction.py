from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta, timezone

import pytest

from runtime_protocol.errors import ConflictError
from runtime_protocol.cli import main as runtime_cli
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import IdempotencyWindowExpired, RealmStore
from runtime_protocol.upgrade import compact_idempotency_ledger
from runtime_protocol.util import canonical_json
from test_timeline_commit_integration import agent, film  # noqa: F401 (shared fixtures)


def _service(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    return root, RuntimeService(root)


def test_large_result_window_refuses_reexecution_and_preserves_receipt(tmp_path):
    _, service = _service(tmp_path)
    try:
        payload = {"data": "x" * 20000}
        request_hash = hashlib.sha256(b"request").hexdigest()
        first = service._command_record(
            "test.large", "one", "key", request_hash, payload,
            project_id="unscoped",
        )
        assert service._command_replay("test.large", "one", "key", request_hash, project_id="unscoped") == first
        with pytest.raises(ConflictError):
            service._command_replay("test.large", "one", "key", "different", project_id="unscoped")
        old = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(timespec="milliseconds")
        service.store.conn.execute(
            "UPDATE command_idempotency SET created_at=? WHERE command_kind='test.large'", (old,)
        )
        with pytest.raises(IdempotencyWindowExpired):
            service._command_replay("test.large", "one", "key", request_hash, project_id="unscoped")
        service.store._last_idempotency_prune = 0
        service._command_record("test.small", "two", "key2", request_hash, {"ok": True}, project_id="unscoped")
        with pytest.raises(IdempotencyWindowExpired) as expired:
            service._command_replay("test.large", "one", "key", request_hash, project_id="unscoped")
        assert expired.value.code == "idempotency_window_expired"
        with pytest.raises(ConflictError) as changed:
            service._command_replay("test.large", "one", "key", "different", project_id="unscoped")
        assert changed.value.code == "conflict"
        assert service.store.conn.execute("SELECT COUNT(*) FROM command_idempotency").fetchone()[0] == 2
    finally:
        service.close()


def test_timeline_receipt_sweep_expires_only_owned_stale_bodies(tmp_path, monkeypatch):
    _, service = _service(tmp_path)
    try:
        conn = service.store.conn
        assert conn is not None
        own = service.create_project({"slug": "own", "name": "Own"}, idempotency_key="own-project")["id"]
        foreign = service.create_project({"slug": "foreign", "name": "Foreign"}, idempotency_key="foreign-project")["id"]
        request_hash = hashlib.sha256(b"request").hexdigest()
        service._command_record(
            "test.owned", "own", "owned-key", request_hash,
            {"project_id": own, "body": "x" * 20000}, project_id=own,
        )
        service._command_record(
            "test.foreign", "foreign", "foreign-key", request_hash,
            {"project_id": foreign, "body": "y" * 20000}, project_id=foreign,
        )
        old = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(timespec="milliseconds")
        conn.execute("UPDATE command_idempotency SET created_at=?", (old,))
        owned_before = conn.execute(
            "SELECT result_json FROM command_idempotency WHERE command_kind='test.owned'"
        ).fetchone()[0]
        foreign_before = conn.execute(
            "SELECT result_json FROM command_idempotency WHERE command_kind='test.foreign'"
        ).fetchone()[0]

        clocks = iter((1000.0, 1901.0))
        monkeypatch.setattr("runtime_protocol.store.time.monotonic", lambda: next(clocks))
        service.store._last_idempotency_prune = 0
        service._command_record(
            "timeline.commit", "[own,main]", "timeline-key", request_hash,
            {"project_id": own, "accepted": True}, project_id=own,
        )
        owned = conn.execute(
            "SELECT result_json FROM command_idempotency WHERE command_kind='test.owned'"
        ).fetchone()[0]
        assert owned == canonical_json({
            "__runtime_idempotency_result_expired_v1": hashlib.sha256(owned_before.encode()).hexdigest(),
        })
        with pytest.raises(IdempotencyWindowExpired):
            service._command_replay("test.owned", "own", "owned-key", request_hash, project_id=own)
        assert conn.execute(
            "SELECT result_json FROM command_idempotency WHERE command_kind='test.foreign'"
        ).fetchone()[0] == foreign_before
        assert service.store._last_idempotency_prune == 1000.0

        service._command_record(
            "timeline.commit", "[own,main]", "timeline-key-2", request_hash,
            {"project_id": own, "accepted": True}, project_id=own,
        )
        assert service.store._last_idempotency_prune == 1901.0
    finally:
        service.close()


def _elapsed_clock(monkeypatch):
    from runtime_protocol import idempotency, store, util

    wall = store.datetime.now(UTC)
    tick = 1000.0

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return wall.astimezone(tz) if tz else wall.replace(tzinfo=None)

    def advance(seconds):
        nonlocal wall, tick
        wall += timedelta(seconds=seconds)
        tick += seconds
        return tick

    for module in (idempotency, store, util):
        monkeypatch.setattr(module, "datetime", Clock)
    monkeypatch.setattr(store.time, "monotonic", lambda: tick)
    return advance


@pytest.mark.parametrize("failure", ["outer", "released-savepoint", "caught-savepoint", "commit", "interrupt"])
def test_receipt_sweep_rollback_retries_without_advancing_clock(tmp_path, monkeypatch, failure):
    advance = _elapsed_clock(monkeypatch)
    root, service = _service(tmp_path)
    try:
        store = service.store
        conn = store.conn
        assert conn is not None
        own = service.create_project({"slug": "own", "name": "Own"}, idempotency_key="own")["id"]
        foreign = service.create_project({"slug": "foreign", "name": "Foreign"}, idempotency_key="foreign")["id"]
        for project in (own, foreign):
            service._command_record("test.large", project, "large", "request-hash",
                                    {"project_id": project, "body": "x" * 20000}, project_id=project)
        original = conn.execute(
            "SELECT result_json FROM command_idempotency WHERE command_kind='test.large' AND aggregate_id=?", (own,),
        ).fetchone()[0]
        foreign_before = conn.execute(
            "SELECT * FROM command_idempotency WHERE command_kind='test.large' AND aggregate_id=?", (foreign,),
        ).fetchone()
        tombstone = canonical_json({
            "__runtime_idempotency_result_expired_v1": hashlib.sha256(original.encode()).hexdigest(),
        })
        last_prune = store._last_idempotency_prune
        clocks = getattr(store, "_idempotency_prune_clocks", {None: last_prune}).copy()
        before = list(conn.iterdump())
        due = advance(24 * 60 * 60 + 1)

        def record():
            service._command_record("timeline.commit", own, "timeline-key", "timeline-hash",
                                    {"project_id": own, "accepted": True}, project_id=own)
            assert conn.execute(
                "SELECT result_json FROM command_idempotency WHERE command_kind='test.large' AND aggregate_id=?", (own,),
            ).fetchone()[0] == tombstone
            assert store._last_idempotency_prune == last_prune
            assert store._idempotency_prune_clocks == clocks

        def deny_commit(action, operation, *_):
            return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_TRANSACTION and operation == "COMMIT" else sqlite3.SQLITE_OK

        error = sqlite3.DatabaseError if failure == "commit" else KeyboardInterrupt if failure == "interrupt" else RuntimeError
        try:
            with pytest.raises(error), store._transaction():
                if failure in {"released-savepoint", "caught-savepoint"}:
                    try:
                        with store._transaction():
                            record()
                            if failure == "caught-savepoint":
                                raise RuntimeError("inner failure")
                    except RuntimeError:
                        assert list(conn.iterdump()) == before
                        assert store._idempotency_prune_pending == {}
                        # The outer mutation can retry immediately after a savepoint rollback.
                        record()
                else:
                    record()
                if failure == "commit":
                    conn.set_authorizer(deny_commit)
                else:
                    raise error("failure after sweep")
        finally:
            conn.set_authorizer(None)
        assert not conn.in_transaction
        assert list(conn.iterdump()) == before
        assert store._last_idempotency_prune == last_prune
        assert store._idempotency_prune_clocks == clocks

        with store._transaction():
            record()
        assert store._last_idempotency_prune == due
        assert store._idempotency_prune_clocks == {**clocks, own: due}
        service.close()
        service = RuntimeService(root)
        reopened = service.store.conn
        assert reopened is not None
        row = reopened.execute(
            "SELECT request_hash,result_json FROM command_idempotency WHERE command_kind='test.large' AND aggregate_id=?", (own,),
        ).fetchone()
        assert tuple(row) == ("request-hash", tombstone)
        assert tuple(reopened.execute(
            "SELECT * FROM command_idempotency WHERE command_kind='test.large' AND aggregate_id=?", (foreign,),
        ).fetchone()) == tuple(foreign_before)
        with pytest.raises(IdempotencyWindowExpired):
            service._command_replay("test.large", own, "large", "request-hash", project_id=own)
        with pytest.raises(ConflictError):
            service._command_replay("test.large", own, "large", "changed-hash", project_id=own)
    finally:
        service.close()


def test_elapsed_timeline_sweeps_bound_work_without_starving_other_owners(tmp_path, monkeypatch):
    advance = _elapsed_clock(monkeypatch)
    _, service = _service(tmp_path)
    try:
        store = service.store
        conn = store.conn
        assert conn is not None
        projects = [service.create_project({"slug": slug, "name": slug}, idempotency_key=slug)["id"]
                    for slug in ("a", "b", "inactive")]
        for project, count in zip(projects, (101, 1, 1)):
            for index in range(count):
                service._command_record("test.large", project, str(index), "hash",
                                        {"project_id": project, "body": "x" * 20000}, project_id=project)
        before = [tuple(row) for row in conn.execute(
            "SELECT aggregate_id,idempotency_key,result_json FROM command_idempotency WHERE command_kind='test.large'",
        )]
        all_before = dict(conn.execute("SELECT rowid,result_json FROM command_idempotency"))
        original_clock = store._last_idempotency_prune
        advance(24 * 60 * 60 + 1)

        def sweep(project, key, kind="timeline.commit"):
            with store._transaction():
                service._command_record(kind, project, key, "hash", {"project_id": project}, project_id=project)

        sweep(projects[0], "a-first")
        assert store._last_idempotency_prune == original_clock  # The 100-row budget was exhausted.
        after = dict(conn.execute("SELECT rowid,result_json FROM command_idempotency"))
        assert sum(after[rowid] != body for rowid, body in all_before.items()) == 100
        advance(1)
        sweep(projects[0], "a-second")
        a_clock = store._last_idempotency_prune
        advance(1)
        sweep(projects[1], "b-first")  # A's completed sweep must not postpone B.
        assert store._idempotency_prune_clocks[projects[1]] > a_clock
        for project, key, body in before:
            actual = conn.execute(
                "SELECT result_json FROM command_idempotency WHERE command_kind='test.large' AND aggregate_id=? AND idempotency_key=?",
                (project, key),
            ).fetchone()[0]
            assert actual == (body if project == projects[2] else canonical_json({
                "__runtime_idempotency_result_expired_v1": hashlib.sha256(body.encode()).hexdigest(),
            }))
        # Ordinary mutations still perform global maintenance, including inactive owners.
        sweep(projects[0], "global", kind="test.trigger")
        assert len(conn.execute(
            "SELECT result_json FROM command_idempotency WHERE command_kind='test.large' AND aggregate_id=?", (projects[2],),
        ).fetchone()[0]) < 200
    finally:
        service.close()


@pytest.mark.integration
def test_real_timeline_only_commits_retry_failed_expiry_sweep(request, monkeypatch):
    from test_timeline_commit_integration import Editing

    from runtime_protocol.timeline_commit_port import CommitUnavailable

    captured_film = request.getfixturevalue("film")
    actual_agent = request.getfixturevalue("agent")
    advance = _elapsed_clock(monkeypatch)
    service = RuntimeService(captured_film.fixture.duplicate_root)
    try:
        service.register_timeline_commit_provider(actual_agent.provider())
        edit = Editing(service, captured_film, actual_agent)
        store = service.store
        conn = store.conn
        assert conn is not None
        service._command_record("test.large", edit.project, "large", "hash",
                                {"project_id": edit.project, "body": "x" * 20000}, project_id=edit.project)
        original = conn.execute(
            "SELECT * FROM command_idempotency WHERE command_kind='test.large'",
        ).fetchone()
        history = edit.history()
        advance(24 * 60 * 60 - 1)
        first_body = edit.body([edit.move("music-bed", 1)])
        first = edit.commit(first_body, "before-expiry")
        assert tuple(conn.execute(
            "SELECT * FROM command_idempotency WHERE command_kind='test.large'",
        ).fetchone()) == tuple(original)
        advance(901)
        body = edit.body([edit.move("music-bed", 2)])
        before = list(conn.iterdump())
        clocks, last_prune = store._idempotency_prune_clocks.copy(), store._last_idempotency_prune
        record = store._record_command_receipt

        def fail_after_receipt(*args, **kwargs):
            record(*args, **kwargs)
            raise RuntimeError("failure after timeline receipt sweep")

        with monkeypatch.context() as patch:
            patch.setattr(store, "_record_command_receipt", fail_after_receipt)
            with pytest.raises(CommitUnavailable) as error:
                edit.commit(body, "failed-expiry")
            assert isinstance(error.value.__cause__, RuntimeError)
            assert str(error.value.__cause__) == "failure after timeline receipt sweep"
        assert list(conn.iterdump()) == before
        assert store._last_idempotency_prune == last_prune
        assert store._idempotency_prune_clocks == clocks
        accepted = edit.commit(body, "failed-expiry")
        edit.assert_readback(accepted)
        assert store._last_idempotency_prune > last_prune
        row = conn.execute("SELECT * FROM command_idempotency WHERE command_kind='test.large'").fetchone()
        assert row["request_hash"] == original["request_hash"]
        assert row["created_at"] == original["created_at"]
        assert row["result_json"] == canonical_json({
            "__runtime_idempotency_result_expired_v1": hashlib.sha256(original["result_json"].encode()).hexdigest(),
        })
        advance(901)
        latest = edit.commit(edit.body([edit.move("music-bed", 3)]), "after-expiry")
        edit.assert_readback(latest)
        assert len(edit.history()) == len(history) + 3
        assert edit.commit(first_body, "before-expiry") == first
        with pytest.raises(IdempotencyWindowExpired):
            service._command_replay("test.large", edit.project, "large", "hash", project_id=edit.project)
        with pytest.raises(ConflictError):
            service._command_replay("test.large", edit.project, "large", "changed", project_id=edit.project)
        assert store.integrity_report()["ok"]
    finally:
        service.close()


def test_session_claim_replay_keeps_permanent_ledger_empty(tmp_path):
    _, service = _service(tmp_path)
    try:
        response = {"task_id": "one", "spec": {"input": "x" * 20000}}
        assert service._command_record("task.claim", "claim", "claim-key", "hash", response, project_id="unscoped", with_receipt=False) == response
        assert service._command_replay("task.claim", "claim", "claim-key", "hash", with_receipt=False) == response
        assert service.store.conn.execute("SELECT COUNT(*) FROM command_idempotency WHERE command_kind='task.claim'").fetchone()[0] == 0
        with pytest.raises(ConflictError):
            service._command_replay("task.claim", "claim", "claim-key", "changed", with_receipt=False)
        old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(timespec="milliseconds")
        service.store.conn.execute(
            "UPDATE session_command_replay SET created_at=? WHERE idempotency_key='claim-key'", (old,)
        )
        with pytest.raises(IdempotencyWindowExpired):
            service._command_replay("task.claim", "claim", "claim-key", "hash", with_receipt=False)
        service._command_record("task.claim", "claim", "next-key", "hash", None, project_id="unscoped", with_receipt=False)
        with pytest.raises(IdempotencyWindowExpired):
            service._command_replay("task.claim", "claim", "claim-key", "hash", with_receipt=False)
        assert service.store.conn.execute("SELECT COUNT(*) FROM command_idempotency WHERE command_kind='task.claim'").fetchone()[0] == 0
    finally:
        service.close()


def test_offline_compaction_rewrites_only_expired_bulk_and_session_rows(tmp_path, capsys):
    root, service = _service(tmp_path)
    old = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(timespec="milliseconds")
    large = canonical_json({"data": "z" * 200000})
    try:
        for kind in ("task.create", "task.claim", "executor.register", "object.ingest", "media.import", "parent_composition.publish"):
            service.store.conn.execute(
                "INSERT INTO command_idempotency(command_kind,aggregate_id,idempotency_key,request_hash,result_json,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (kind, "one", kind, "hash", large, old),
            )
        realm_id = service.realm["id"]
    finally:
        service.close()
    result = compact_idempotency_ledger(root, confirmation=f"COMPACT IDEMPOTENCY {realm_id}")
    assert result["removed_session_rows"] == 0
    assert result["expired_results"] == 3
    assert result["after_bytes"] < result["before_bytes"]
    with sqlite3.connect(f"file:{root / 'realm.sqlite3'}?mode=ro", uri=True) as connection:
        rows = dict(connection.execute("SELECT command_kind, result_json FROM command_idempotency"))
    assert set(rows) == {"task.create", "task.claim", "executor.register", "object.ingest", "media.import", "parent_composition.publish"}
    assert all(len(rows[kind]) < 200 for kind in ("task.create", "task.claim", "executor.register"))
    assert all(rows[kind] == large for kind in ("object.ingest", "media.import", "parent_composition.publish"))
    assert runtime_cli(["compact", "--root", str(root), "--confirm", f"COMPACT IDEMPOTENCY {realm_id}"]) == 0
    second = json.loads(capsys.readouterr().out)
    assert second["removed_session_rows"] == second["expired_results"] == 0
    reopened = RuntimeService(root)
    try:
        assert reopened.store.integrity_report()["ok"] is True
    finally:
        reopened.close()
