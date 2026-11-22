from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from runtime_protocol import source_identity
from tests.test_source_startup_identity import _git, _repo
from tests.lanes import requires_posix_private_modes


@requires_posix_private_modes
def test_process_budget_preserves_independent_observations_and_edits(tmp_path, monkeypatch):
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    for root in (runtime, agent):
        for i in range(150):
            (root / f"tracked-{i}").write_text(f"tracked {i}")
            (root / f"untracked-{i}").write_text(f"untracked {i}")
        (root / "line\nbreak").write_bytes(b"unusual")
        for i in range(12):
            (root / f"link-{i}").symlink_to(f"target-{i}")
        _git(root, "add", "tracked-*")
        _git(root, "commit", "-qm", "many files")

    calls = []
    observations = []
    original_run = subprocess.run
    original_capture = source_identity._capture_repo

    def counted_run(argv, **kwargs):
        calls.append(argv)
        return original_run(argv, **kwargs)

    def observed(root):
        observations.append(root)
        return original_capture(root)

    with monkeypatch.context() as patch:
        patch.setattr(subprocess, "run", counted_run)
        patch.setattr(source_identity, "_capture_repo", observed)
        first = source_identity.capture_source_identity(runtime, agent)
    assert observations == [runtime, agent, runtime, agent]
    assert len(calls) <= 36
    assert all(call[0] == "git" for call in calls)

    for path, content in ((runtime / "tracked-149", "edited tracked"),
                          (agent / "untracked-149", "edited untracked"),
                          (runtime / "line\nbreak", "edited unusual")):
        path.write_text(content)
        changed = source_identity.capture_source_identity(runtime, agent)
        assert changed["dirty_hash"] != first["dirty_hash"]
        first = changed
    link = agent / "link-11"
    link.unlink()
    link.symlink_to("different target")
    assert source_identity.capture_source_identity(runtime, agent)["dirty_hash"] != first["dirty_hash"]


def test_edit_after_raw_batch_is_detected(tmp_path: Path, monkeypatch):
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    for i in range(150):
        (runtime / f"file-{i:03}").write_text(str(i))
    original = source_identity._blob_ids
    changed = False

    def race(root, paths):
        nonlocal changed
        hashes = original(root, paths)
        if root == runtime and b"file-149" in paths and not changed:
            changed = True
            (runtime / "file-149").write_text("edited during capture")
        return hashes

    monkeypatch.setattr(source_identity, "_blob_ids", race)
    with pytest.raises(source_identity.SourceIdentityError, match="changed during identity capture"):
        source_identity.capture_source_identity(runtime, agent)
    assert changed
