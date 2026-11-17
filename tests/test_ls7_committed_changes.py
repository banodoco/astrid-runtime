"""LS-7: notifications are tied to the existing durable outer commit."""
from __future__ import annotations

import threading

import pytest

from runtime_protocol.committed_changes import CommittedChanges
from runtime_protocol.store import RealmStore


def test_only_outer_commit_notifies(tmp_path, monkeypatch):
    store = RealmStore.initialize(tmp_path / "realm")
    store._committed_changes = CommittedChanges(store._mutex)
    notifications = []
    monkeypatch.setattr(store._committed_changes, "committed", lambda: notifications.append(store.conn.in_transaction))
    try:
        with store._mutex, store._transaction():
            with store._transaction():
                assert notifications == []
            assert notifications == []
        assert notifications == [False]
        with pytest.raises(RuntimeError), store._mutex, store._transaction():
            with store._transaction():
                pass
            raise RuntimeError("rollback")
        assert notifications == [False]
    finally:
        store.close()


def test_registration_and_predicate_share_commit_lock(tmp_path):
    store = RealmStore.initialize(tmp_path / "realm")
    changes = store._committed_changes = CommittedChanges(store._mutex)
    registered = threading.Event()
    finished = threading.Event()
    observed = []

    def waiter():
        # The outer acquisition models the HTTP dispatch's recursive lock.
        with store._mutex, changes.condition:
            registered.set()
            while store.conn.execute("SELECT display_name FROM realm").fetchone()[0] != "Committed":
                assert changes.condition.wait(2), "commit notification was lost"
            observed.append(store.conn.in_transaction)
        finished.set()

    thread = threading.Thread(target=waiter)
    thread.start()
    try:
        assert registered.wait(2)
        with store._mutex, store._transaction():
            store.conn.execute("UPDATE realm SET display_name='Committed'")
        assert finished.wait(2)
        assert observed == [False]
    finally:
        store.close()
        thread.join(2)
    assert not thread.is_alive()
