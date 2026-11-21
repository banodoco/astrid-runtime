"""Focused physical identity and SQLite write guards for TimelineCommitStore."""
from __future__ import annotations

import os
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from runtime_protocol.errors import HeadBusyError, ProtocolError
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_store import TimelineCommitStore, _same_store_version


def _commit_store(root):
    RealmStore.initialize(root).close()
    store = RealmStore(root)
    commits = TimelineCommitStore(store, validate_prepared=lambda _value: None)
    return store, commits


def test_external_committed_sqlite_write_changes_data_version(tmp_path):
    store, commits = _commit_store(tmp_path / "realm")
    try:
        before = commits._store_version()
        writer = sqlite3.connect(store.db_path, timeout=5)
        try:
            writer.execute("CREATE TABLE external_write (value TEXT)")
            writer.execute("INSERT INTO external_write VALUES ('committed')")
            writer.commit()
        finally:
            writer.close()

        after = commits._store_version()
        assert after[2] != before[2]
    finally:
        store.close()


def test_database_shrink_during_checkpoint_allowance_is_refused(tmp_path):
    store, commits = _commit_store(tmp_path / "realm")
    try:
        before = commits._store_version()
        files = list(before[3])
        database = list(files[0])
        database[2] -= 1
        files[0] = tuple(database)
        after = (*before[:3], tuple(files), *before[4:])

        assert files[0][:2] == before[3][0][:2]
        assert not _same_store_version(before, after, allow_checkpoint=True)
    finally:
        store.close()


def test_database_inode_swap_is_reopened_or_refused(tmp_path):
    store, commits = _commit_store(tmp_path / "realm")
    try:
        before = commits._store_version()
        original_connection = commits._connection
        db_path = store.db_path
        replacement = tmp_path / "replacement.sqlite3"
        other = sqlite3.connect(replacement)
        try:
            other.execute("PRAGMA journal_mode=WAL")
            other.execute("CREATE TABLE replacement_marker (value TEXT)")
            other.commit()
        finally:
            other.close()
        for suffix in ("-wal", "-shm"):
            candidate = str(replacement) + suffix
            if os.path.exists(candidate):
                os.unlink(candidate)
        os.replace(replacement, db_path)

        try:
            after = commits._store_version()
        except ProtocolError:
            # A replacement with an incompatible realm schema may be rejected;
            # the important guard is that the old live handle is never accepted.
            assert commits._connection is not original_connection
        else:
            assert commits._connection is not original_connection
            assert after[0] == id(commits._connection)
            assert after[0] != before[0]
    finally:
        store.close()


def test_external_commit_during_established_read_snapshot_is_refused(tmp_path):
    store, commits = _commit_store(tmp_path / "realm")
    try:
        connection = commits._connection
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        with pytest.raises(HeadBusyError):
            with commits.verification_scope(), commits._read_transaction():
                # This SELECT establishes the outer SQLite read snapshot.
                connection.execute("SELECT name FROM sqlite_master ORDER BY name LIMIT 1").fetchone()
                with closing(sqlite3.connect(store.db_path, timeout=5, isolation_level=None)) as writer:
                    writer.execute("CREATE TABLE external_snapshot_write (value TEXT)")
        assert not any(commits._history_state.values())
        assert not connection.in_transaction
    finally:
        store.close()


@pytest.mark.parametrize("suffix", ["", "-wal"], ids=["database", "wal"])
def test_sqlite_file_replacement_during_snapshot_is_refused(tmp_path, suffix):
    store, commits = _commit_store(tmp_path / "realm")
    try:
        connection = commits._connection
        target = Path(str(store.db_path) + suffix)
        replacement = tmp_path / "replacement"
        with pytest.raises(ProtocolError, match="identity changed during a transaction"):
            with commits.verification_scope(), commits._read_transaction():
                connection.execute("SELECT name FROM sqlite_master ORDER BY name LIMIT 1").fetchone()
                shutil.copyfile(target, replacement)
                try:
                    replacement.replace(target)
                except PermissionError as exc:
                    pytest.skip(f"platform does not permit replacing an open SQLite database: {exc}")
        assert not any(commits._history_state.values())
        assert not connection.in_transaction
    finally:
        store.close()
