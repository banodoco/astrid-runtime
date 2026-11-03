"""Provisional exclusion only; these tests do not establish R18 admission."""
import os
import select
import subprocess
import sys
from types import SimpleNamespace

import pytest

from astrid_runtime._realm_fence import FenceUnavailable
from astrid_runtime._transfer_session import ProvisionalTransferSession
from test_provisional_realm_fence import contender, realm


def paths(tmp_path):
    support = tmp_path / "support"
    support.mkdir(mode=0o700)
    lock = support / "bootstrap.lock"
    lock.touch(mode=0o600)
    return SimpleNamespace(runtime_support=support, bootstrap_lock_path=lock)


def test_session_holds_bootstrap_and_original_realm_until_close(tmp_path):
    config = paths(tmp_path)
    root = realm(tmp_path)
    with ProvisionalTransferSession(config, root) as session:
        session.revalidate()
        assert contender(config.bootstrap_lock_path) == 17
        assert contender(root / "owner.lock") == 17
        with pytest.raises(FenceUnavailable):
            ProvisionalTransferSession(config, root)
        assert contender(root / "owner.lock") == 17
    assert contender(config.bootstrap_lock_path) == 0
    assert contender(root / "owner.lock") == 0


def test_existing_bootstrap_mutex_waits_for_session(tmp_path):
    config = paths(tmp_path)
    root = realm(tmp_path)
    script = """from pathlib import Path
from types import SimpleNamespace
from astrid_runtime.bootstrap import _bootstrap_mutex
import sys
p = Path(sys.argv[1])
paths = SimpleNamespace(runtime_support=p, bootstrap_lock_path=p / 'bootstrap.lock')
print('waiting', flush=True)
with _bootstrap_mutex(paths):
    print('acquired', flush=True)
"""
    child = None
    try:
        with ProvisionalTransferSession(config, root):
            child = subprocess.Popen([sys.executable, "-u", "-c", script, str(config.runtime_support)],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert select.select([child.stdout], [], [], 10)[0]
            assert child.stdout.readline() == b"waiting\n"
            assert not select.select([child.stdout], [], [], 0.2)[0]
            assert contender(root / "owner.lock") == 17
        stdout, stderr = child.communicate(timeout=10)
        assert child.returncode == 0, stderr.decode()
        assert stdout == b"acquired\n"
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.communicate()


@pytest.mark.parametrize("replace", ["bootstrap", "owner", "root", "support"])
def test_replacement_poison_retains_original_locks_and_preserves_replacement(tmp_path, replace):
    config = paths(tmp_path)
    root = realm(tmp_path)
    with ProvisionalTransferSession(config, root) as session:
        if replace == "bootstrap":
            old = config.bootstrap_lock_path.with_name("old.lock")
            config.bootstrap_lock_path.rename(old)
            config.bootstrap_lock_path.write_text("replacement")
        elif replace == "owner":
            old = root / "old.lock"
            (root / "owner.lock").rename(old)
            (root / "owner.lock").write_text("replacement")
        elif replace == "root":
            old_root = tmp_path / "old-realm"
            root.rename(old_root)
            root.mkdir()
            old = old_root / "owner.lock"
        else:
            old_support = tmp_path / "old-support"
            config.runtime_support.rename(old_support)
            config.runtime_support.mkdir()
            old = old_support / "bootstrap.lock"
        with pytest.raises(FenceUnavailable):
            session.revalidate()
        assert contender(old) == 17
        with pytest.raises(FenceUnavailable):
            session.revalidate()
        if replace in ("bootstrap", "owner"):
            replacement = config.bootstrap_lock_path if replace == "bootstrap" else root / "owner.lock"
            assert replacement.read_text() == "replacement"
    assert contender(old) == 0


def test_failed_realm_acquisition_releases_bootstrap_without_creating_owner(tmp_path):
    config = paths(tmp_path)
    root = realm(tmp_path)
    (root / "owner.lock").unlink()
    with pytest.raises(FenceUnavailable):
        ProvisionalTransferSession(config, root)
    assert not (root / "owner.lock").exists()
    assert contender(config.bootstrap_lock_path) == 0


def test_bootstrap_symlink_and_hardlink_refused(tmp_path):
    config = paths(tmp_path)
    root = realm(tmp_path)
    config.bootstrap_lock_path.unlink()
    target = tmp_path / "target"
    target.touch(mode=0o600)
    config.bootstrap_lock_path.symlink_to(target)
    with pytest.raises(FenceUnavailable):
        ProvisionalTransferSession(config, root)
    config.bootstrap_lock_path.unlink()
    os.link(target, config.bootstrap_lock_path)
    with pytest.raises(FenceUnavailable):
        ProvisionalTransferSession(config, root)
    assert contender(root / "owner.lock") == 0


def test_unsupported_platform_refuses_before_opening_paths(tmp_path, monkeypatch):
    config = paths(tmp_path)
    root = realm(tmp_path)
    monkeypatch.setattr("astrid_runtime._transfer_session.sys.platform", "win32")
    with pytest.raises(FenceUnavailable, match="unsupported"):
        ProvisionalTransferSession(config, root)
