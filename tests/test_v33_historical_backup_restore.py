from __future__ import annotations

import os

import pytest

from precut_realm_fixture import FIXTURE_BACKUP_KEY, _extract_archive, readonly_tree_digest
from runtime_protocol import backup as backup_module
from runtime_protocol.backup import restore_backup, verify_backup
from runtime_protocol.errors import ConflictError


def test_historical_backup_restores_only_as_explicit_migration_input(tmp_path):
    backup = _extract_archive(tmp_path / "archive")
    with pytest.raises(ConflictError, match="integrity checks"):
        verify_backup(backup, key=FIXTURE_BACKUP_KEY)
    with pytest.raises(ConflictError, match="integrity checks"):
        restore_backup(backup, tmp_path / "strict", key=FIXTURE_BACKUP_KEY)
    assert not (tmp_path / "strict").exists()

    verified = verify_backup(backup, key=FIXTURE_BACKUP_KEY, older_schema=True)
    assert verified["manifest"]["schema"]["version"] == 31
    assert verified["doctor"]["issues"] == ["schema"]
    restored = tmp_path / "migration-input"
    restore_backup(backup, restored, key=FIXTURE_BACKUP_KEY, older_schema=True)
    assert readonly_tree_digest(restored) == readonly_tree_digest(backup)


def test_historical_restore_rejects_changed_backup_before_publishing(tmp_path):
    backup = _extract_archive(tmp_path / "archive")
    database = backup / "realm.sqlite3"
    with database.open("r+b") as stream:
        stream.seek(-1, 2)
        last = stream.read(1)
        stream.seek(-1, 2)
        stream.write(bytes([last[0] ^ 1]))
    destination = tmp_path / "migration-input"
    with pytest.raises(ConflictError, match="digest mismatch"):
        restore_backup(backup, destination, key=FIXTURE_BACKUP_KEY, older_schema=True)
    assert not destination.exists()


def test_historical_restore_checks_copied_bytes_before_publishing(tmp_path, monkeypatch):
    backup = _extract_archive(tmp_path / "archive")
    original_copy = backup_module.copy_file_at

    def corrupt_copy(source_fd, source_name, destination_fd, destination_name):
        original_copy(source_fd, source_name, destination_fd, destination_name)
        fd = os.open(destination_name, os.O_RDWR, dir_fd=destination_fd)
        try:
            os.lseek(fd, -1, os.SEEK_END)
            last = os.read(fd, 1)
            os.lseek(fd, -1, os.SEEK_END)
            os.write(fd, bytes([last[0] ^ 1]))
        finally:
            os.close(fd)

    monkeypatch.setattr(backup_module, "copy_file_at", corrupt_copy)
    destination = tmp_path / "migration-input"
    with pytest.raises(ConflictError, match="SQLite bytes differ"):
        restore_backup(backup, destination, key=FIXTURE_BACKUP_KEY, older_schema=True)
    assert not destination.exists()
