"""Ledger facts never grant custody, native-state knowledge or admission."""
import copy
import json
import os
import stat
import subprocess
import sys

import pytest

from astrid_runtime._realm_fence import FenceUnavailable
from astrid_runtime.lifecycle_transfer import begin_transfer
from test_lifecycle_transfer_session import fixture


def request(session, binding, request_id="one", **changes):
    envelope = {"operation_id": binding["operation_id"], "generation": binding["generation"],
                "request_id": request_id, "expected_phase": "observed",
                "binding_digest": session.binding_digest}
    envelope.update(changes)
    return session.record_request(**envelope)


def test_replay_reopen_and_query_are_ledger_only(tmp_path):
    config, _, _, binding = fixture(tmp_path)
    path = config.runtime_support / "lifecycle-transfer-ledger.json"
    with begin_transfer(config, binding=binding) as session:
        before = set(config.runtime_support.iterdir())
        assert session.query() == {"phase": "observed", "requests": []}
        assert set(config.runtime_support.iterdir()) == before
        result = request(session, binding)
        assert result == {"code": "recorded", "stage": "ledger_only",
                          "lifecycle_side_effect": False, "sequence": 1}
        assert request(session, binding) == result
        assert request(session, binding, "two")["sequence"] == 2
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with begin_transfer(config, binding=binding) as reopened:
        assert request(reopened, binding) == result
        entries = reopened.query()["requests"]
        assert [e["result"]["sequence"] for e in entries] == [1, 2]
        assert entries[0]["request"]["binding_digest"] == reopened.binding_digest
        assert reopened._custody is None
        assert not hasattr(reopened, "admit_stopped_r0")
        assert not hasattr(reopened, "arm_writer")
        assert not hasattr(reopened, "commit_decision")
        assert not hasattr(reopened, "finalize_release")
    # A separate interpreter reads the same persisted record without acquiring custody.
    script = '''import json, sys
from pathlib import Path
from types import SimpleNamespace
from astrid_runtime.lifecycle_transfer import begin_transfer
b = json.loads(sys.argv[2]); p = Path(sys.argv[1])
s = begin_transfer(SimpleNamespace(runtime_support=p, bootstrap_lock_path=p / "bootstrap.lock"), binding=b)
result = s.record_request(operation_id=b["operation_id"], generation=b["generation"],
                          request_id="one", expected_phase="observed", binding_digest=s.binding_digest)
print(json.dumps({"query": s.query(), "replay": result, "custody": s._custody is not None}, sort_keys=True))
'''
    process = subprocess.run([sys.executable, "-c", script, str(config.runtime_support), json.dumps(binding)],
                             text=True, capture_output=True, check=True)
    child = json.loads(process.stdout)
    assert child["query"]["requests"][0]["result"] == result
    assert child["replay"] == result and child["custody"] is False


def test_changed_ids_binding_and_stale_phase_refuse(tmp_path):
    config, _, _, binding = fixture(tmp_path)
    with begin_transfer(config, binding=binding) as session:
        result = request(session, binding)
        for changes in ({"expected_phase": "other"}, {"generation": "other"},
                        {"operation_id": "other"}, {"binding_digest": "0" * 64}):
            with pytest.raises(FenceUnavailable, match="binding_changed"):
                request(session, binding, **changes)
        with pytest.raises(FenceUnavailable, match="stale_phase"):
            request(session, binding, "new", expected_phase="other")
        with pytest.raises(FenceUnavailable, match="binding_changed"):
            request(session, binding, "new", generation="other")
        assert request(session, binding) == result
    other = copy.deepcopy(binding)
    other["generation"] = "other"
    with begin_transfer(config, binding=other) as session:
        with pytest.raises(FenceUnavailable, match="binding_changed"):
            session.query()
        with pytest.raises(FenceUnavailable, match="binding_changed"):
            request(session, other)


def test_failure_before_commit_and_after_replace_never_returns_success(tmp_path, monkeypatch):
    import astrid_runtime.lifecycle_transfer as module

    config, _, _, binding = fixture(tmp_path)
    path = config.runtime_support / "lifecycle-transfer-ledger.json"
    real_fsync = os.fsync
    with begin_transfer(config, binding=binding) as session:
        def fail_file(fd):
            raise OSError("injected fsync failure")
        with monkeypatch.context() as patch:
            patch.setattr(module.os, "fsync", fail_file)
            with pytest.raises(FenceUnavailable, match="durability_failed"):
                request(session, binding)
        assert not path.exists()
        assert session.query()["requests"] == []
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("injected directory fsync failure")
            return real_fsync(fd)
        with monkeypatch.context() as patch:
            patch.setattr(module.os, "fsync", fail_directory)
            with pytest.raises(FenceUnavailable, match="durability_failed"):
                request(session, binding)
            with pytest.raises(FenceUnavailable, match="durability_failed"):
                request(session, binding)
        # A query may observe the rename; only a later successful fsync acknowledges it.
        assert len(session.query()["requests"]) == 1
        assert request(session, binding)["sequence"] == 1


@pytest.mark.parametrize("damage", ["symlink", "mode", "corrupt", "hardlink", "oversized", "temp"])
def test_unsafe_or_interrupted_storage_refuses(tmp_path, damage):
    config, _, _, binding = fixture(tmp_path)
    path = config.runtime_support / "lifecycle-transfer-ledger.json"
    target = tmp_path / "target"
    if damage == "symlink":
        target.write_text("keep")
        path.symlink_to(target)
    elif damage == "temp":
        (config.runtime_support / ".lifecycle-transfer-ledger.tmp").write_text("interrupted")
    else:
        path.write_bytes(b"x" * (128 * 1024 + 1) if damage == "oversized" else b"{}")
        path.chmod(0o644 if damage == "mode" else 0o600)
        if damage == "hardlink":
            os.link(path, target)
    with begin_transfer(config, binding=binding) as session:
        with pytest.raises(FenceUnavailable):
            request(session, binding)
        with pytest.raises(FenceUnavailable):
            session.query()
    if damage == "symlink":
        assert target.read_text() == "keep"
    if damage == "temp":
        assert (config.runtime_support / ".lifecycle-transfer-ledger.tmp").read_text() == "interrupted"


def test_bounded_requests_and_support_permissions(tmp_path):
    config, _, _, binding = fixture(tmp_path)
    with begin_transfer(config, binding=binding) as session:
        with pytest.raises(FenceUnavailable):
            request(session, binding, "x" * 257)
        for i in range(128):
            assert request(session, binding, str(i))["sequence"] == i + 1
        with pytest.raises(FenceUnavailable, match="ledger full"):
            request(session, binding, "overflow")
        assert request(session, binding, "0")["sequence"] == 1
        config.runtime_support.chmod(0o755)
        with pytest.raises(FenceUnavailable):
            session.query()
        with pytest.raises(FenceUnavailable):
            request(session, binding, "new")


def test_cross_session_serialization_and_observational_query(tmp_path):
    import fcntl

    config, _, _, binding = fixture(tmp_path)
    with begin_transfer(config, binding=binding) as first, begin_transfer(config, binding=binding) as second:
        request(first, binding)
        path = config.runtime_support / "lifecycle-transfer-ledger.json"
        contents = path.read_bytes()
        before = path.stat()
        assert second.query()["requests"][0]["result"]["sequence"] == 1
        after = path.stat()
        assert path.read_bytes() == contents
        assert (before.st_ino, before.st_mtime_ns, before.st_ctime_ns) == (after.st_ino, after.st_mtime_ns, after.st_ctime_ns)
        directory = os.open(config.runtime_support, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with pytest.raises(FenceUnavailable):
                second.query()
            with pytest.raises(FenceUnavailable):
                request(second, binding, "blocked")
        finally:
            os.close(directory)
        assert request(second, binding, "next")["sequence"] == 2


def test_fifo_ledger_refuses_without_blocking(tmp_path):
    config, _, _, binding = fixture(tmp_path)
    os.mkfifo(config.runtime_support / "lifecycle-transfer-ledger.json", 0o600)
    with begin_transfer(config, binding=binding) as session:
        with pytest.raises(FenceUnavailable):
            session.query()
        with pytest.raises(FenceUnavailable):
            request(session, binding)
