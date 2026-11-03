"""Kernel-backed characterization of the existing private upgrade fences.

These do not expose or qualify an installer API; they pin the integration seam.
"""
import os
from pathlib import Path
import subprocess
import sys

import pytest

from runtime_protocol import platform, v33_lifecycle as lifecycle
from runtime_protocol.errors import OwnerBusyError
from runtime_protocol.store import realm_admission_fence
from runtime_protocol.upgrade import _owner_fence, inspect_realm_schema, migrate_canonical_to_current
from test_v33_manifest import database
from test_v33_upgrade_dispatch import write_realm


def _contender(root, target):
    code = '''import os, sys
from runtime_protocol import platform
fd = os.open(sys.argv[1], os.O_RDONLY if sys.argv[2] == "directory" else os.O_RDWR)
try:
    platform.lock_file(fd, blocking=False)
except BlockingIOError:
    sys.exit(42)
sys.exit(0)
'''
    path = root if target == "directory" else root / "owner.lock"
    return subprocess.run([sys.executable, "-c", code, str(path), target],
                          env=os.environ.copy(), check=False).returncode


def test_external_fence_refuses_nested_migration_without_mutation(tmp_path):
    root = tmp_path / "realm"
    write_realm(root, database("C31"))
    before = (root / "realm.sqlite3").read_bytes()
    with realm_admission_fence(root, blocking=False):
        with pytest.raises(OwnerBusyError):
            migrate_canonical_to_current(root, confirmation="MIGRATE CANONICAL r")
    assert (root / "realm.sqlite3").read_bytes() == before
    assert sorted(p.name for p in root.iterdir()) == ["realm.sqlite3"]


def test_private_fence_preserves_both_kernel_locks_through_interrupted_restore(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    write_realm(root, database("C31"))
    (root / "payload").write_bytes(b"original")
    with _owner_fence(root):
        ids = ((root.stat().st_dev, root.stat().st_ino),
               ((root / "owner.lock").stat().st_dev, (root / "owner.lock").stat().st_ino))
        assert (_contender(root, "directory"), _contender(root, "owner")) == (42, 42)
        identity = inspect_realm_schema(root)
        with lifecycle.sqlite_observation(root) as observed:
            archive, record = lifecycle.begin(root, identity, sqlite_image=observed)
        lifecycle.phase(archive, record, "backup_verified", operator_owned=True)
        result = migrate_canonical_to_current(root, confirmation="MIGRATE CANONICAL r")
        assert result["target_schema_version"] == 33
        assert (_contender(root, "directory"), _contender(root, "owner")) == (42, 42)
        (root / "payload").write_bytes(b"candidate")
        snapshot = lifecycle.snapshot_tree
        def interrupt(source, destination, **kwargs):
            if Path(source) == archive / "realm" and Path(destination) == root:
                (root / "partial").write_bytes(b"interrupted")
                raise RuntimeError("interrupted restore")
            return snapshot(source, destination, **kwargs)
        monkeypatch.setattr(lifecycle, "snapshot_tree", interrupt)
        with pytest.raises(RuntimeError, match="interrupted restore"):
            lifecycle.restore(root, archive)
        assert lifecycle.activation(root)[1]["state"] == "restoring"
        assert (_contender(root, "directory"), _contender(root, "owner")) == (42, 42)
        monkeypatch.setattr(lifecycle, "snapshot_tree", snapshot)
        lifecycle.restore(root, archive)
        assert (root / "payload").read_bytes() == b"original"
        assert not (root / "partial").exists()
        assert inspect_realm_schema(root)["kind"] == "C31"
        assert ids == ((root.stat().st_dev, root.stat().st_ino),
                       ((root / "owner.lock").stat().st_dev, (root / "owner.lock").stat().st_ino))
        assert (_contender(root, "directory"), _contender(root, "owner")) == (42, 42)
    assert (_contender(root, "directory"), _contender(root, "owner")) == (0, 0)


def test_restore_refuses_corrupt_archive_before_modifying_realm(tmp_path):
    from runtime_protocol.errors import ConflictError
    root = tmp_path / "realm"
    write_realm(root, database("C31"))
    (root / "payload").write_bytes(b"original")
    with _owner_fence(root):
        identity = inspect_realm_schema(root)
        with lifecycle.sqlite_observation(root) as observed:
            archive, _ = lifecycle.begin(root, identity, sqlite_image=observed)
        (root / "payload").write_bytes(b"candidate")
        (archive / "realm" / "payload").write_bytes(b"corrupt")
        before = {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()}
        with pytest.raises(ConflictError, match="inventory/hash mismatch"):
            lifecycle.restore(root, archive)
        assert {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()} == before


def test_restore_rejects_ready_recovery_set(tmp_path):
    from runtime_protocol.errors import ConflictError
    root = tmp_path / "realm"
    write_realm(root, database("C31"))
    with _owner_fence(root):
        identity = inspect_realm_schema(root)
        with lifecycle.sqlite_observation(root) as observed:
            archive, record = lifecycle.begin(root, identity, sqlite_image=observed)
        lifecycle.phase(archive, record, "ready")
        before = (root / "realm.sqlite3").read_bytes()
        with pytest.raises(ConflictError, match="pre-admission window"):
            lifecycle.restore(root, archive)
        assert (root / "realm.sqlite3").read_bytes() == before
