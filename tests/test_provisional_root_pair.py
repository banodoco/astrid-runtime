"""Overlapping root custody is provisional; it does not admit a restore."""
import os
import stat
import sys

import pytest

from astrid_runtime import _realm_fence
from astrid_runtime._realm_fence import FenceUnavailable, ProvisionalRootPair
from test_provisional_realm_fence import contender

pytestmark = pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="POSIX flock only")


def roots(tmp_path):
    result = []
    for name in ("old", "replacement"):
        root = tmp_path / name
        root.mkdir(mode=0o700)
        (root / "owner.lock").touch(mode=0o600)
        result.append(root)
    return result


def test_pair_acquires_directories_before_owners_in_file_id_order(tmp_path, monkeypatch):
    old, replacement = roots(tmp_path)
    locks = []
    real_lock = _realm_fence.platform.lock_file

    def record(fd, *, blocking=True):
        info = os.fstat(fd)
        locks.append((stat.S_IFMT(info.st_mode), (info.st_dev, info.st_ino), blocking))
        return real_lock(fd, blocking=blocking)

    monkeypatch.setattr(_realm_fence.platform, "lock_file", record)
    with ProvisionalRootPair(replacement, old) as pair:
        pair.revalidate()
        assert [item[0] for item in locks] == [stat.S_IFDIR, stat.S_IFDIR, stat.S_IFREG, stat.S_IFREG]
        assert [item[1] for item in locks[:2]] == sorted(item[1] for item in locks[:2])
        assert all(item[2] is False for item in locks)
        assert contender(old / "owner.lock") == 17
        assert contender(replacement / "owner.lock") == 17
    assert contender(old / "owner.lock") == 0
    assert contender(replacement / "owner.lock") == 0


def test_contended_replacement_does_not_disturb_existing_owner(tmp_path):
    import fcntl

    old, replacement = roots(tmp_path)
    held = os.open(replacement / "owner.lock", os.O_RDWR)
    try:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(FenceUnavailable):
            ProvisionalRootPair(old, replacement)
        assert contender(replacement / "owner.lock") == 17
        assert contender(old / "owner.lock") == 0
    finally:
        os.close(held)


def test_pair_detects_replacement_and_keeps_original_descriptions(tmp_path):
    old, replacement = roots(tmp_path)
    pair = ProvisionalRootPair(old, replacement)
    try:
        (replacement / "owner.lock").rename(replacement / "previous.lock")
        (replacement / "owner.lock").touch(mode=0o600)
        with pytest.raises(FenceUnavailable):
            pair.revalidate()
        assert contender(old / "owner.lock") == 17
        assert contender(replacement / "previous.lock") == 17
        (replacement / "owner.lock").unlink()
        (replacement / "previous.lock").rename(replacement / "owner.lock")
        with pytest.raises(FenceUnavailable):
            pair.revalidate()
    finally:
        pair.close()


def test_duplicate_root_refused_and_close_only_keeps_alias_locked(tmp_path):
    old, replacement = roots(tmp_path)
    with pytest.raises(FenceUnavailable):
        ProvisionalRootPair(old, old)
    pair = ProvisionalRootPair(old, replacement)
    entry = next(item for item in pair._roots if item["path"] == old)
    alias = os.dup(entry["owner"])
    try:
        pair.close()
        pair.close()
        assert contender(old / "owner.lock") == 17
        assert contender(replacement / "owner.lock") == 0
    finally:
        os.close(alias)
    assert contender(old / "owner.lock") == 0
