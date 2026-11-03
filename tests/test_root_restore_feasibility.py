"""Kernel feasibility checks; these do not implement or authorize restore."""

import ctypes
import errno
import os
import sys

import pytest

from astrid_runtime._realm_fence import ProvisionalRootPair


pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux renameat2")


def _renameat2(parent_fd, source, destination, flags):
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        rename = libc.renameat2
    except AttributeError:
        pytest.skip("renameat2 unavailable")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent_fd, os.fsencode(source), parent_fd, os.fsencode(destination), flags):
        error = ctypes.get_errno()
        if error in (errno.ENOSYS, errno.EOPNOTSUPP, errno.EINVAL):
            pytest.skip("renameat2 operation unavailable on this filesystem")
        raise OSError(error, os.strerror(error))


def _roots(tmp_path):
    for name in ("old", "candidate"):
        root = tmp_path / name
        root.mkdir()
        (root / "owner.lock").touch(mode=0o600)
    return tmp_path / "old", tmp_path / "candidate"


def test_locked_roots_do_not_prevent_parent_entry_replacement(tmp_path):
    old, candidate = _roots(tmp_path)
    with ProvisionalRootPair(old, candidate):
        old_id = os.stat(old).st_ino
        old.rename(tmp_path / "retained")
        old.mkdir()
        assert os.stat(tmp_path / "retained").st_ino == old_id
        assert os.stat(old).st_ino != old_id


def test_exchange_after_identity_check_swaps_replacement_not_locked_old(tmp_path):
    old, candidate = _roots(tmp_path)
    with ProvisionalRootPair(old, candidate) as pair:
        parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            pair.revalidate()
            old_id = os.stat("old", dir_fd=parent, follow_symlinks=False).st_ino
            candidate_id = os.stat("candidate", dir_fd=parent, follow_symlinks=False).st_ino
            # A change between the identity check and the exchange is not
            # conditioned on either of those observed file IDs by renameat2.
            old.rename(tmp_path / "retained")
            old.mkdir()
            intruder_id = os.stat(old).st_ino
            _renameat2(parent, "candidate", "old", 2)  # RENAME_EXCHANGE
            assert os.stat("old", dir_fd=parent).st_ino == candidate_id
            assert os.stat("candidate", dir_fd=parent).st_ino == intruder_id
            assert os.stat("retained", dir_fd=parent).st_ino == old_id
        finally:
            os.close(parent)
