from datetime import datetime, timedelta, timezone

import runtime_protocol.store as store_module
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def test_idle_registration_and_empty_claim_poll_leave_durable_state_unchanged(tmp_path, monkeypatch):
    root = tmp_path / 'realm'
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        clock = [datetime.now(timezone.utc).replace(microsecond=0)]

        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return clock[0] if tz else clock[0].replace(tzinfo=None)

        monkeypatch.setattr(store_module, 'datetime', Clock)
        monkeypatch.setattr(store_module, 'now', lambda: clock[0].isoformat())
        epoch = service.health()['runtime_epoch']
        descriptor = {'capability_id': 'render', 'definition_digest': 'sha256:' + 'a' * 64}
        body = {'executor_id': 'worker', 'runtime_epoch': epoch, 'capabilities': [descriptor]}
        claim = {'executor_id': 'worker', 'runtime_epoch': epoch, 'capability_ids': ['render']}
        service.register_executor(body, idempotency_key='initial')
        conn = service.store.conn
        assert conn.execute('SELECT COUNT(*) FROM tasks').fetchone()[0] == 0
        wal = service.store.db_path.with_name(service.store.db_path.name + '-wal')
        wal_size = wal.stat().st_size if wal.exists() else 0
        owner, credit = service.store._session_replay_changes
        assert owner is conn
        raw = conn.total_changes
        temp_rows = conn.execute('SELECT COUNT(*) FROM temp.session_command_replay').fetchone()[0]
        for i in range(3):
            clock[0] += timedelta(seconds=45)
            service.register_executor(body, idempotency_key=f'refresh-{i}')
            before_poll = conn.total_changes
            _, before_credit = service.store._session_replay_changes
            assert service.claim_next(claim, idempotency_key=f'poll-{i}') is None
            assert conn.total_changes - before_poll == 1
            assert service.store._session_replay_changes[1] - before_credit == 1
            service.store.reap_overdue_leases()
            assert service.store.matching_live_executor('render', include_storage=False)
            assert service.executor_observation('worker', identity={'actor': 'owner', 'scopes': ['admin']})['last_seen_at'] == clock[0].isoformat()
        owner, after_credit = service.store._session_replay_changes
        assert owner is conn
        assert conn.total_changes - raw == after_credit - credit == 6
        assert conn.execute('SELECT COUNT(*) FROM temp.session_command_replay').fetchone()[0] - temp_rows == 6
        assert (wal.stat().st_size if wal.exists() else 0) == wal_size
        assert conn.execute('SELECT COUNT(*) FROM tasks').fetchone()[0] == 0
        durable_before = conn.total_changes - after_credit
        changed = {**body, 'capabilities': [{**descriptor, 'status': 'unavailable'}]}
        service.register_executor(changed, idempotency_key='changed')
        assert conn.total_changes - service.store._session_replay_changes[1] > durable_before
    finally:
        service.close()
