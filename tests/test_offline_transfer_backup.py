"""Offline database unit; fixture is a captured v31 predecessor backup."""
from contextlib import closing
import fcntl
import hashlib
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from astrid_runtime._realm_fence import FenceUnavailable, ProvisionalRealmFence
from precut_realm_fixture import _extract_archive
from runtime_protocol import offline_transfer_backup as offline
from runtime_protocol.errors import ConflictError, ValidationError
from runtime_protocol.v33_manifest import canonical_manifest
from test_provisional_realm_fence import contender

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux O_NOATIME required")


@pytest.fixture
def predecessor(tmp_path):
    root = _extract_archive(tmp_path / "archive", Path(__file__).parent / "fixtures/precut-restore-history-v31.tar.gz")
    root.chmod(0o700)
    database = root / "realm.sqlite3"
    database.chmod(0o600)
    (root / "owner.lock").touch(mode=0o600)
    with closing(sqlite3.connect(f"file:{database}?mode=ro", uri=True)) as conn:
        manifest = canonical_manifest(conn)
    assert manifest["version"] == 31
    return root, manifest


def _snapshot(fence, dest, manifest):
    return offline.create_offline_snapshot(fence, dest, expected_realm_id=manifest["realm_id"], expected_schema_kind=manifest["kind"])


def _source_state(root):
    return {p.name: (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns, p.stat().st_ctime_ns, p.stat().st_ino)
            for p in root.iterdir() if p.name.startswith("realm.sqlite3")}


def test_wal_aware_consistency_and_read_only_source_preservation(tmp_path, predecessor):
    root, manifest = predecessor
    # Commit to WAL and simulate process death so WAL remains without any writer.
    script = """import os, sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute('PRAGMA journal_mode=WAL')
c.execute('PRAGMA wal_autocheckpoint=0')
c.execute('PRAGMA user_version=723')
c.commit()
os._exit(0)
"""
    subprocess.run([sys.executable, "-c", script, str(root / "realm.sqlite3")], check=True)
    assert (root / "realm.sqlite3-wal").stat().st_size > 0
    before = _source_state(root)
    atimes = {name: (root / name).stat().st_atime_ns for name in before}
    with ProvisionalRealmFence(root) as fence:
        result = _snapshot(fence, tmp_path / "snapshot", manifest)
        fence.revalidate()
        assert contender(root / "owner.lock") == 17
        assert {name: (root / name).stat().st_atime_ns for name in before} == atimes
        assert _source_state(root) == before
    with closing(sqlite3.connect(f"file:{tmp_path / 'snapshot/realm.sqlite3'}?mode=ro", uri=True)) as conn:
        assert conn.execute("PRAGMA user_version").fetchone() == (723,)
        assert canonical_manifest(conn) == manifest
    assert result["sha256"] == hashlib.sha256((tmp_path / "snapshot/realm.sqlite3").read_bytes()).hexdigest()
    assert set(p.name for p in (tmp_path / "snapshot").iterdir()) == {"realm.sqlite3"}


def test_predecessor_schema_mismatch_and_invalid_manifest_refused(tmp_path, predecessor):
    root, manifest = predecessor
    before = _source_state(root)
    with ProvisionalRealmFence(root) as fence:
        with pytest.raises(ValidationError, match="schema mismatch"):
            offline.create_offline_snapshot(fence, tmp_path / "bad", expected_realm_id=manifest["realm_id"], expected_schema_kind="U33")
        with pytest.raises(ValidationError, match="realm identity mismatch"):
            offline.create_offline_snapshot(fence, tmp_path / "bad", expected_realm_id="wrong", expected_schema_kind=manifest["kind"])
        assert _source_state(root) == before
    with sqlite3.connect(root / "realm.sqlite3") as conn:
        conn.execute("CREATE TABLE fabricated_evidence (id INTEGER)")
    before = _source_state(root)
    with ProvisionalRealmFence(root) as fence, pytest.raises(ValidationError, match="unsupported canonical"):
        _snapshot(fence, tmp_path / "bad", manifest)
    assert _source_state(root) == before
    assert not (tmp_path / "bad").exists()


def test_path_replacement_and_symlink_refusal(tmp_path, predecessor, monkeypatch):
    root, manifest = predecessor
    with ProvisionalRealmFence(root) as fence:
        real_copy = offline._copy_component
        def replace_after_copy(*args):
            real_copy(*args)
            if args[1] == "realm.sqlite3":
                (root / "realm.sqlite3").rename(root / "original.sqlite3")
                (root / "realm.sqlite3").symlink_to(root / "original.sqlite3")
        monkeypatch.setattr(offline, "_copy_component", replace_after_copy)
        with pytest.raises(ConflictError, match="invalid SQLite component"):
            _snapshot(fence, tmp_path / "bad", manifest)
        assert (root / "realm.sqlite3").is_symlink()
        assert (root / "original.sqlite3").exists()
    assert not (tmp_path / "bad").exists()
    (root / "realm.sqlite3").unlink()
    (root / "original.sqlite3").rename(root / "realm.sqlite3")
    with ProvisionalRealmFence(root) as fence:
        root.rename(tmp_path / "old-root")
        root.symlink_to(tmp_path / "old-root", target_is_directory=True)
        with pytest.raises(FenceUnavailable):
            _snapshot(fence, tmp_path / "bad", manifest)
        assert root.is_symlink()


def test_backup_verification_and_publication_failure(tmp_path, predecessor, monkeypatch):
    root, manifest = predecessor
    with ProvisionalRealmFence(root) as fence:
        real_inspect = offline._inspect
        calls = []
        def fail_verification(conn, expected):
            calls.append(1)
            if len(calls) == 2:
                raise ConflictError("verification failed")
            return real_inspect(conn, expected)
        monkeypatch.setattr(offline, "_inspect", fail_verification)
        with pytest.raises(ConflictError, match="verification failed"):
            _snapshot(fence, tmp_path / "bad", manifest)
        assert not (tmp_path / "bad").exists()
        monkeypatch.setattr(offline, "_inspect", real_inspect)
        publish = offline._publish_new_directory
        def race(parent_fd, source, target):
            os.mkdir(target, dir_fd=parent_fd)
            fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent_fd)
            try:
                marker = os.open("other", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
                os.close(marker)
            finally:
                os.close(fd)
            publish(parent_fd, source, target)
        monkeypatch.setattr(offline, "_publish_new_directory", race)
        with pytest.raises(ConflictError, match="destination appeared"):
            _snapshot(fence, tmp_path / "bad", manifest)
        assert (tmp_path / "bad/other").is_file()
        assert not list(tmp_path.glob(".offline-snapshot-*"))


def test_requires_live_authority_and_destination_outside_realm(tmp_path, predecessor):
    root, manifest = predecessor
    with pytest.raises(ConflictError, match="fence"):
        _snapshot(None, tmp_path / "bad", manifest)
    fence = ProvisionalRealmFence(root)
    with pytest.raises(ConflictError, match="inside"):
        _snapshot(fence, root / "bad", manifest)
    fence.close()
    with pytest.raises(FenceUnavailable):
        _snapshot(fence, tmp_path / "bad", manifest)


def test_lost_lock_authority_refused(tmp_path, predecessor):
    root, manifest = predecessor
    fence = ProvisionalRealmFence(root)
    try:
        fcntl.flock(fence._owner_fd, fcntl.LOCK_UN)
        with pytest.raises(ConflictError, match="authority is not held"):
            _snapshot(fence, tmp_path / "bad", manifest)
        assert not (tmp_path / "bad").exists()
    finally:
        fence.close()


def test_replaced_staging_directory_preserved(tmp_path, predecessor, monkeypatch):
    root, manifest = predecessor
    inspect = offline._inspect
    calls = []
    def replace_stage(conn, expected):
        result = inspect(conn, expected)
        calls.append(1)
        if len(calls) == 2:
            stage = next(tmp_path.glob(".offline-snapshot-*"))
            stage.rename(tmp_path / "original-stage")
            stage.mkdir()
            (stage / "replacement").touch()
        return result
    monkeypatch.setattr(offline, "_inspect", replace_stage)
    with ProvisionalRealmFence(root) as fence, pytest.raises(ConflictError, match="staging directory changed"):
        _snapshot(fence, tmp_path / "bad", manifest)
    assert next(tmp_path.glob(".offline-snapshot-*/replacement")).is_file()
    assert not (tmp_path / "bad").exists()
