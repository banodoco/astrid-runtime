"""Kernel-level checks for the provisional lock primitive, not admission."""
import os
import subprocess
import sys

import pytest

from astrid_runtime._realm_fence import FenceUnavailable, ProvisionalRealmFence


pytestmark = pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="POSIX flock only")


def realm(tmp_path):
    root = tmp_path / "realm"
    root.mkdir(mode=0o700)
    (root / "owner.lock").touch(mode=0o600)
    return root


def contender(path):
    script = """import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit(17)
"""
    return subprocess.run([sys.executable, "-c", script, str(path)], check=False).returncode


def test_retains_original_nonblocking_lock_and_releases_on_close(tmp_path):
    root = realm(tmp_path)
    fence = ProvisionalRealmFence(root)
    assert contender(root / "owner.lock") == 17
    with pytest.raises(FenceUnavailable):
        ProvisionalRealmFence(root)
    assert contender(root / "owner.lock") == 17
    fence.close()
    fence.close()
    assert contender(root / "owner.lock") == 0


def test_owner_alias_survives_broker_close_and_child_death_preserves_broker(tmp_path):
    root = realm(tmp_path)
    fence = ProvisionalRealmFence(root)
    script = "import sys; print('ready', flush=True); sys.stdin.read()"
    child = subprocess.Popen([sys.executable, "-c", script], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, pass_fds=(fence._owner_fd,))
    try:
        assert child.stdout.readline() == b"ready\n"
        assert contender(root / "owner.lock") == 17
        fence.close()
        assert contender(root / "owner.lock") == 17
    finally:
        child.stdin.close()
        assert child.wait(timeout=10) == 0
        child.stdout.close()
        fence.close()
    assert contender(root / "owner.lock") == 0
    with ProvisionalRealmFence(root) as fence:
        child = subprocess.Popen([sys.executable, "-c", "pass"], pass_fds=(fence._owner_fd,))
        assert child.wait(timeout=10) == 0
        assert contender(root / "owner.lock") == 17
    assert contender(root / "owner.lock") == 0


def test_replacement_is_detected_without_removing_replacement(tmp_path):
    root = realm(tmp_path)
    with ProvisionalRealmFence(root) as fence:
        (root / "owner.lock").rename(root / "old.lock")
        (root / "owner.lock").write_text("replacement")
        with pytest.raises(FenceUnavailable):
            fence.revalidate()
        assert (root / "owner.lock").read_text() == "replacement"


def test_missing_linked_or_symlinked_owner_refused_without_creation(tmp_path):
    root = realm(tmp_path)
    owner = root / "owner.lock"
    owner.unlink()
    with pytest.raises(FenceUnavailable):
        ProvisionalRealmFence(root)
    assert not owner.exists()
    external = tmp_path / "external"
    external.touch(mode=0o600)
    owner.symlink_to(external)
    with pytest.raises(FenceUnavailable):
        ProvisionalRealmFence(root)
    owner.unlink()
    os.link(external, owner)
    with pytest.raises(FenceUnavailable):
        ProvisionalRealmFence(root)
    assert owner.stat().st_ino == external.stat().st_ino


def test_replaced_root_and_symlinked_ancestor_refused(tmp_path):
    root = realm(tmp_path)
    with ProvisionalRealmFence(root) as fence:
        root.rename(tmp_path / "original")
        root.mkdir()
        with pytest.raises(FenceUnavailable):
            fence.revalidate()
    root.rmdir()
    root.symlink_to(tmp_path / "original", target_is_directory=True)
    with pytest.raises(FenceUnavailable):
        ProvisionalRealmFence(root)
    assert root.is_symlink()
