"""Focused provisional facade tests; no test here establishes admission."""
import copy
import hashlib
import os
import subprocess
import sys
import threading

import pytest

from astrid_runtime._transfer_session import FenceUnavailable
from astrid_runtime.lifecycle_transfer import begin_transfer
from test_lifecycle_transfer_helpers import contender, realm, paths


def identity(path):
    info = path.stat()
    return [info.st_dev, info.st_ino]


def directory(path):
    return {"path": str(path), "file_id": identity(path)}


def fixture(tmp_path):
    config = paths(tmp_path)
    root = realm(tmp_path)
    source = tmp_path / "module.py"
    source.write_bytes(b"installed source\n")
    digest = "a" * 64
    src = {"repository_sha": "b" * 40, "version_document_digest": digest,
           "profile_digest": digest, "manifest_digest": digest,
           "module": {"path": str(source), "file_id": identity(source),
                      "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}}
    binding = {
        "version": "astrid.lifecycle-transfer/v1", "operation_id": "op", "attempt_id": "attempt",
        "transfer_id": "transfer", "generation": "generation",
        "controller": {"pid": os.getpid(), "uid": os.geteuid(), "birth": "native-birth"},
        "installation": directory(tmp_path), "program": directory(tmp_path), "data": directory(tmp_path),
        "support": directory(config.runtime_support),
        "realm": {"uuid": "realm", "root": directory(root), "owner_file_id": identity(root / "owner.lock")},
        "old_source": src, "candidate_source": copy.deepcopy(src),
        "prior_selection_digest": digest, "journal_digest": digest,
        "manager": {"kind": "systemd-user", "namespace": "user", "target": "unit", "definition_digest": digest},
        "publications": {"instance": {"status": "absent", "digest": None},
                         "discovery": {"status": "absent", "digest": None}, "incarnation": None},
        "origin": "stopped-r0", "prior_state": {"running": False, "loaded": True, "enabled": True},
        "root_lineage": [identity(root)], "role": "candidate",
    }
    return config, root, source, binding


def directory_contender(root):
    script = """import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit(17)
"""
    return subprocess.run([sys.executable, "-c", script, str(root)], check=False).returncode


def test_retains_both_original_locks_and_repeated_acquisition_is_same_fence(tmp_path):
    config, root, _, binding = fixture(tmp_path)
    session = begin_transfer(config, binding=binding)
    assert contender(root / "owner.lock") == 0
    assert directory_contender(root) == 0
    with session:
        fence = session.pin_and_acquire_original()
        assert session.pin_and_acquire_original() is fence
        fence.revalidate()
        assert directory_contender(root) == 17
        assert contender(root / "owner.lock") == 17
        with begin_transfer(config, binding=binding) as other:
            with pytest.raises(FenceUnavailable):
                other.pin_and_acquire_original()
        assert contender(root / "owner.lock") == 17
    assert directory_contender(root) == 0
    assert contender(root / "owner.lock") == 0
    with pytest.raises(FenceUnavailable):
        fence.revalidate()


def test_concurrent_calls_return_single_fence(tmp_path):
    config, root, _, binding = fixture(tmp_path)
    with begin_transfer(config, binding=binding) as session:
        results = []
        threads = [threading.Thread(target=lambda: results.append(session.pin_and_acquire_original())) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        assert len(results) == 4 and all(result is results[0] for result in results)
        assert contender(root / "owner.lock") == 17


def test_close_never_unlocks_shared_descriptions(tmp_path):
    config, root, _, binding = fixture(tmp_path)
    session = begin_transfer(config, binding=binding)
    session.pin_and_acquire_original()
    held = session._custody._realm
    owner_alias, directory_alias = os.dup(held._owner_fd), os.dup(held._directory_fd)
    try:
        session.close()
        assert contender(root / "owner.lock") == 17
        assert directory_contender(root) == 17
    finally:
        os.close(owner_alias)
        os.close(directory_alias)
    assert contender(root / "owner.lock") == 0
    assert directory_contender(root) == 0


@pytest.mark.parametrize("changed", ["owner", "root", "source", "support"])
def test_replacement_poison_preserves_held_originals(tmp_path, changed):
    config, root, source, binding = fixture(tmp_path)
    with begin_transfer(config, binding=binding) as session:
        fence = session.pin_and_acquire_original()
        old_root = root
        if changed == "owner":
            (root / "owner.lock").rename(root / "old.lock")
            (root / "owner.lock").write_text("replacement")
        elif changed == "root":
            old_root = tmp_path / "old-realm"
            root.rename(old_root)
            root.mkdir()
        elif changed == "source":
            source.write_text("changed source")
        else:
            config.runtime_support.rename(tmp_path / "old-support")
            config.runtime_support.mkdir()
        with pytest.raises(FenceUnavailable):
            fence.revalidate()
        with pytest.raises(FenceUnavailable):
            session.pin_and_acquire_original()
        original_owner = old_root / ("old.lock" if changed == "owner" else "owner.lock")
        assert contender(original_owner) == 17
        assert directory_contender(old_root) == 17
        if changed == "owner":
            assert (root / "owner.lock").read_text() == "replacement"
    assert contender(original_owner) == 0


@pytest.mark.parametrize("change", ["owner_id", "root_id", "source_hash", "source_id", "support"])
def test_binding_mismatch_refuses_and_unwinds(tmp_path, change):
    config, root, _, binding = fixture(tmp_path)
    if change == "owner_id":
        binding["realm"]["owner_file_id"][1] += 1
    elif change == "root_id":
        binding["realm"]["root"]["file_id"][1] += 1
    elif change == "source_hash":
        binding["old_source"]["module"]["sha256"] = "0" * 64
    elif change == "source_id":
        binding["candidate_source"]["module"]["file_id"][1] += 1
    else:
        binding["support"] = directory(tmp_path)
    with pytest.raises(FenceUnavailable):
        with begin_transfer(config, binding=binding) as session:
            session.pin_and_acquire_original()
    assert contender(root / "owner.lock") == 0
    assert directory_contender(root) == 0
    assert contender(config.bootstrap_lock_path) == 0


@pytest.mark.parametrize("change", ["extra", "missing", "nested_extra", "digest", "relative", "bool_id", "state", "role"])
def test_malformed_closed_binding_refused(tmp_path, change):
    config, _, _, binding = fixture(tmp_path)
    if change == "extra":
        binding["extra"] = "value"
    elif change == "missing":
        del binding["generation"]
    elif change == "nested_extra":
        binding["manager"]["extra"] = "value"
    elif change == "digest":
        binding["old_source"]["module"]["sha256"] = "wrong"
    elif change == "relative":
        binding["realm"]["root"]["path"] = "relative"
    elif change == "bool_id":
        binding["realm"]["owner_file_id"] = [True, 1]
    elif change == "state":
        binding["prior_state"]["running"] = "unknown"
    else:
        binding["role"] = "rollback-r0"
    with pytest.raises(FenceUnavailable):
        begin_transfer(config, binding=binding)


def test_unsupported_platform_refused_before_acquisition(tmp_path, monkeypatch):
    config, root, _, binding = fixture(tmp_path)
    monkeypatch.setattr("astrid_runtime.lifecycle_transfer.sys.platform", "win32")
    with pytest.raises(FenceUnavailable, match="unsupported"):
        begin_transfer(config, binding=binding)
    assert contender(root / "owner.lock") == 0


@pytest.mark.parametrize("blocked", ["directory", "owner"])
def test_independent_kernel_lock_contention_refuses_and_unwinds(tmp_path, blocked):
    import fcntl

    config, root, _, binding = fixture(tmp_path)
    target = root if blocked == "directory" else root / "owner.lock"
    fd = os.open(target, os.O_RDONLY if blocked == "directory" else os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with begin_transfer(config, binding=binding) as session:
            with pytest.raises(FenceUnavailable):
                session.pin_and_acquire_original()
            with pytest.raises(FenceUnavailable):
                session.pin_and_acquire_original()
        assert contender(config.bootstrap_lock_path) == 0
        if blocked == "owner":
            assert directory_contender(root) == 0
    finally:
        os.close(fd)
    assert contender(root / "owner.lock") == 0
    assert directory_contender(root) == 0


def test_binding_snapshot_is_immutable_after_begin(tmp_path):
    config, root, _, binding = fixture(tmp_path)
    with begin_transfer(config, binding=binding) as session:
        digest = session._binding_digest
        binding["operation_id"] = "other"
        binding["realm"]["owner_file_id"][1] += 1
        session.pin_and_acquire_original().revalidate()
        assert session._binding_digest == digest
        assert contender(root / "owner.lock") == 17
