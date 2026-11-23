from datetime import datetime, timedelta, timezone

import pytest

import runtime_protocol.store as store_module
from runtime_protocol.store import RealmStore


@pytest.fixture
def store(tmp_path):
    root = tmp_path / 'realm'
    RealmStore.initialize(root).close()
    value = RealmStore(root)
    yield value
    value.close()


def test_idle_refresh_expiry_restart_and_changed_capability(store, monkeypatch):
    clock = [datetime(2026, 1, 1, tzinfo=timezone.utc)]

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock[0] if tz else clock[0].replace(tzinfo=None)

    monkeypatch.setattr(store_module, 'datetime', Clock)
    monkeypatch.setattr(store_module, 'now', lambda: clock[0].isoformat())
    descriptor = {'capability_id': 'render', 'definition_digest': 'sha256:' + 'a' * 64}
    store.upsert_executor('worker', [descriptor])
    before = store.conn.total_changes
    wal = store.db_path.with_name(store.db_path.name + '-wal')
    size = wal.stat().st_size if wal.exists() else 0
    for _ in range(3):
        clock[0] += timedelta(seconds=45)
        store.upsert_executor('worker', [descriptor])
        assert store.matching_live_executor('render', include_storage=False)
    assert store.conn.total_changes == before
    assert (wal.stat().st_size if wal.exists() else 0) == size
    row = store.conn.execute("SELECT * FROM executors WHERE id='worker'").fetchone()
    assert store._executor_result(row)['last_seen_at'] == clock[0].isoformat()
    clock[0] += timedelta(seconds=90)
    assert not store._executor_live(row)
    store.upsert_executor('worker', [descriptor])
    assert store._executor_live(row)
    store._executor_seen.clear()  # a new Runtime process has no liveness history
    assert not store._executor_live(row)
    assert store._executor_result(row)['last_seen_at'] == row['last_seen_at']
    store.upsert_executor('worker', [descriptor])
    row = store.conn.execute("SELECT * FROM executors WHERE id='worker'").fetchone()
    assert store._executor_live(row)
    store.upsert_executor('worker', [{**descriptor, 'status': 'unavailable'}])
    assert store.conn.total_changes > before


def test_registration_rollback_does_not_grant_liveness(store):
    with pytest.raises(RuntimeError):
        with store._mutex, store._transaction():
            store.upsert_executor('worker', ['render'])
            raise RuntimeError('rollback')
    assert 'worker' not in store._executor_seen
    assert store.conn.execute("SELECT 1 FROM executors WHERE id='worker'").fetchone() is None


def test_pending_registration_visible_inside_transaction_only(store):
    with pytest.raises(RuntimeError):
        with store._mutex, store._transaction():
            store.upsert_executor('worker', ['render'])
            row = store.conn.execute("SELECT * FROM executors WHERE id='worker'").fetchone()
            assert store._executor_live(row)
            with pytest.raises(ValueError):
                with store._transaction():
                    store.upsert_executor('other', ['render'])
                    raise ValueError('nested rollback')
            assert 'other' not in store._executor_seen_pending
            raise RuntimeError('outer rollback')
    assert not store._executor_seen


def test_restart_and_public_observation(tmp_path):
    from runtime_protocol.service import RuntimeService

    root = tmp_path / 'realm'
    RealmStore.initialize(root).close()
    owner = {'actor': 'owner', 'scopes': ['admin']}
    runtime = RuntimeService(root)
    epoch = runtime.health()['runtime_epoch']
    runtime.register_executor({'executor_id': 'worker', 'capabilities': ['render'], 'runtime_epoch': epoch})
    assert runtime.executor_observation('worker', identity=owner)['last_seen_at'] is not None
    runtime.close()
    runtime = RuntimeService(root)
    try:
        epoch = runtime.health()['runtime_epoch']
        assert runtime.executor_observation('worker', identity=owner)['last_seen_at'] is not None
        runtime.store.heartbeat_executor('worker', runtime_epoch=epoch)
        runtime.store.set_executor_readiness('worker', ready=True, runtime_epoch=epoch)
        assert runtime.executor_observation('worker', identity=owner)['last_seen_at'] is not None
        assert runtime.store.matching_live_executor('render', include_storage=False)
        runtime.register_executor({'executor_id': 'worker', 'capabilities': ['render'], 'runtime_epoch': epoch})
        assert runtime.executor_observation('worker', identity=owner)['last_seen_at'] is not None
        assert runtime.store.matching_live_executor('render', include_storage=False)
        runtime.store.begin_runtime_session('another-boot')
        assert runtime.executor_observation('worker', identity=owner)['last_seen_at'] is not None
    finally:
        runtime.close()


def test_changed_durable_timestamp_invalidates_overlay(store):
    store.upsert_executor('worker', ['render'])
    store.upsert_executor('worker', ['render'])
    old = '2000-01-01T00:00:00+00:00'
    store.conn.execute("UPDATE executors SET last_seen_at=? WHERE id='worker'", (old,))
    row = store.conn.execute("SELECT * FROM executors WHERE id='worker'").fetchone()
    assert not store._executor_live(row)
    assert store._executor_result(row)['last_seen_at'] == old
    before = store.conn.total_changes
    store.upsert_executor('worker', ['render'])
    assert store.conn.total_changes > before
    row = store.conn.execute("SELECT * FROM executors WHERE id='worker'").fetchone()
    assert store._executor_live(row)
