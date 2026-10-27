from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from runtime_protocol.source_identity import SourceIdentityError, capture_source_identity
from tests.lanes import requires_posix_private_modes


def _git(path: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(path), *args], check=True, text=True, capture_output=True)
    return result.stdout.strip()


def _repo(path: Path) -> Path:
    path.mkdir()
    _git(path, "init", "-q")
    _git(path, "config", "user.email", "test@example.invalid")
    _git(path, "config", "user.name", "Test")
    (path / "tracked.txt").write_text("initial\n")
    _git(path, "add", "tracked.txt")
    _git(path, "commit", "-qm", "initial")
    return path


def _capture(runtime: Path, agent: Path) -> dict:
    return capture_source_identity(runtime, agent)


def test_clean_identity_is_stable_and_ignores_mtime(tmp_path: Path) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    first = _capture(runtime, agent)
    os.utime(runtime / "tracked.txt", (1234567890, 1234567890))
    assert _capture(runtime, agent) == first
    assert first["dirty"] is False
    assert first["release"] == 0 and first["managed_by"] == "source"
    assert len(first["runtime_head"]) >= 40 and len(first["agent_head"]) >= 40
    assert len(first["dirty_hash"]) == 64


def test_diff_configuration_does_not_change_identity(tmp_path: Path) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    before = _capture(runtime, agent)
    _git(runtime, "config", "diff.algorithm", "patience")
    _git(runtime, "config", "diff.context", "99")
    _git(runtime, "config", "core.quotepath", "true")
    _git(agent, "config", "diff.algorithm", "histogram")
    _git(agent, "config", "diff.context", "3")
    _git(agent, "config", "core.quotepath", "false")
    _git(runtime, "config", "status.showUntrackedFiles", "no")
    _git(agent, "config", "status.renames", "false")
    assert _capture(runtime, agent) == before


def test_capture_is_bound_to_requested_git_root_and_ignores_redirect_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    other = _repo(tmp_path / "other")
    expected = _capture(runtime, agent)
    nested = runtime / "nested"
    nested.mkdir()
    with pytest.raises(SourceIdentityError, match="not the root"):
        _capture(nested, agent)

    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(other))
    assert _capture(runtime, agent) == expected


def test_each_checkout_head_is_part_of_identity(tmp_path: Path) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    initial = _capture(runtime, agent)
    for repo, key in ((runtime, "runtime_head"), (agent, "agent_head")):
        (repo / "next.txt").write_text("committed\n")
        _git(repo, "add", "next.txt")
        _git(repo, "commit", "-qm", "second")
        changed = _capture(runtime, agent)
        assert changed[key] != initial[key]
        assert changed["dirty_hash"] != initial["dirty_hash"]
        initial = changed


def test_index_worktree_untracked_and_path_metadata_are_captured(tmp_path: Path) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    clean = _capture(runtime, agent)
    (runtime / "tracked.txt").write_text("staged\n")
    _git(runtime, "add", "tracked.txt")
    staged = _capture(runtime, agent)
    assert staged["dirty"] and staged["dirty_hash"] != clean["dirty_hash"]
    (runtime / "tracked.txt").write_text("staged and unstaged\n")
    unstaged = _capture(runtime, agent)
    assert unstaged["dirty_hash"] != staged["dirty_hash"]

    (agent / "new.txt").write_text("untracked one\n")
    added = _capture(runtime, agent)
    assert added["dirty_hash"] != unstaged["dirty_hash"]
    (agent / "new.txt").write_text("untracked two\n")
    edited = _capture(runtime, agent)
    assert edited["dirty_hash"] != added["dirty_hash"]
    (agent / "new.txt").rename(agent / "renamed.txt")
    renamed = _capture(runtime, agent)
    assert renamed["dirty_hash"] != edited["dirty_hash"]
    (agent / "renamed.txt").unlink()
    assert _capture(runtime, agent)["dirty_hash"] != renamed["dirty_hash"]


@requires_posix_private_modes
def test_tracked_delete_rename_and_executable_mode_are_captured(tmp_path: Path) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    baseline = _capture(runtime, agent)
    (runtime / "tracked.txt").unlink()
    deleted = _capture(runtime, agent)
    assert deleted["dirty_hash"] != baseline["dirty_hash"]

    _git(runtime, "checkout", "--", "tracked.txt")
    baseline = _capture(runtime, agent)
    (runtime / "tracked.txt").rename(runtime / "renamed.txt")
    _git(runtime, "add", "-A")
    renamed = _capture(runtime, agent)
    assert renamed["dirty_hash"] != baseline["dirty_hash"]

    (runtime / "renamed.txt").chmod(0o755)
    executable = _capture(runtime, agent)
    assert executable["dirty_hash"] != renamed["dirty_hash"]


def test_tracked_file_replaced_by_directory_with_untracked_child(tmp_path: Path) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    baseline = _capture(runtime, agent)
    tracked = runtime / "tracked.txt"
    tracked.unlink()
    tracked.mkdir()
    child = tracked / "child.txt"
    child.write_text("first\n")
    first = _capture(runtime, agent)
    assert first["dirty"] is True
    assert first["dirty_hash"] != baseline["dirty_hash"]

    child.write_text("second\n")
    second = _capture(runtime, agent)
    assert second["dirty_hash"] != first["dirty_hash"]
    child.unlink()
    removed = _capture(runtime, agent)
    assert removed["dirty_hash"] != second["dirty_hash"]


@requires_posix_private_modes
def test_filemode_disabled_does_not_hide_tracked_executable_change(tmp_path: Path) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    _git(runtime, "config", "core.filemode", "false")
    baseline = _capture(runtime, agent)
    (runtime / "tracked.txt").chmod(0o755)
    changed = _capture(runtime, agent)
    assert changed["dirty"] is True
    assert changed["dirty_hash"] != baseline["dirty_hash"]


@requires_posix_private_modes
def test_tracked_symlink_target_is_captured(tmp_path: Path) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    (runtime / "tracked.txt").unlink()
    (runtime / "tracked.txt").symlink_to("target-a")
    _git(runtime, "add", "tracked.txt")
    _git(runtime, "commit", "-qm", "symlink")
    first = _capture(runtime, agent)
    assert first["dirty"] is False
    (runtime / "tracked.txt").unlink()
    (runtime / "tracked.txt").symlink_to("target-b")
    second = _capture(runtime, agent)
    assert second["dirty"] is True
    assert second["dirty_hash"] != first["dirty_hash"]


def test_clean_filter_cannot_hide_tracked_raw_byte_edits(tmp_path: Path) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    (runtime / ".gitattributes").write_text("tracked.txt filter=canonical\n")
    (runtime / "tracked.txt").write_text("a\n")
    _git(runtime, "config", "filter.canonical.clean", "tr ab x")
    _git(runtime, "config", "filter.canonical.smudge", "cat")
    _git(runtime, "add", ".gitattributes", "tracked.txt")
    _git(runtime, "commit", "-qm", "configure clean filter")
    baseline = _capture(runtime, agent)
    (runtime / "tracked.txt").write_text("b\n")
    assert _git(runtime, "status", "--porcelain").strip() == ""
    changed = _capture(runtime, agent)
    assert changed["dirty"] is True
    assert changed["dirty_hash"] != baseline["dirty_hash"]


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_hidden_index_flags_fail_closed(tmp_path: Path, flag: str) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    _git(runtime, "update-index", flag, "tracked.txt")
    (runtime / "tracked.txt").write_text("hidden edit\n")
    with pytest.raises(SourceIdentityError, match="assume-unchanged/skip-worktree"):
        _capture(runtime, agent)


def test_same_heads_and_dirty_flag_do_not_hide_different_contents(tmp_path: Path) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    (runtime / "tracked.txt").write_text("dirty A\n")
    first = _capture(runtime, agent)
    (runtime / "tracked.txt").write_text("dirty B\n")
    second = _capture(runtime, agent)
    assert first["runtime_head"] == second["runtime_head"]
    assert first["dirty"] is second["dirty"] is True
    assert first["dirty_hash"] != second["dirty_hash"]


@requires_posix_private_modes
def test_untracked_symlink_and_executable_mode_are_captured(tmp_path: Path) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    (agent / "tool").write_text("#!/bin/sh\n")
    before = _capture(runtime, agent)
    (agent / "tool").chmod(0o755)
    executable = _capture(runtime, agent)
    assert executable["dirty_hash"] != before["dirty_hash"]
    (agent / "link").symlink_to("tool")
    linked = _capture(runtime, agent)
    assert linked["dirty_hash"] != executable["dirty_hash"]
    (agent / "link").unlink()
    (agent / "link").symlink_to("missing")
    assert _capture(runtime, agent)["dirty_hash"] != linked["dirty_hash"]


def test_ignored_files_are_excluded_and_submodules_fail_closed(tmp_path: Path) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    _git(runtime, "config", "core.excludesfile", str(tmp_path / "global-ignore"))
    (tmp_path / "global-ignore").write_text("cache.bin\n")
    before = _capture(runtime, agent)
    (runtime / "cache.bin").write_bytes(b"ignored")
    assert _capture(runtime, agent) == before

    sub = _repo(tmp_path / "submodule")
    _git(runtime, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub), "vendor/sub")
    with pytest.raises(SourceIdentityError, match="submodules are not supported"):
        _capture(runtime, agent)


def test_submodule_staged_removal_from_index_fails_closed(tmp_path: Path) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    sub = _repo(tmp_path / "submodule")
    _git(runtime, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub), "vendor/sub")
    _git(runtime, "commit", "-qam", "add submodule")
    _git(runtime, "rm", "-q", "--cached", "-r", "vendor/sub")
    with pytest.raises(SourceIdentityError, match="submodules or unsupported tree entries"):
        _capture(runtime, agent)


def test_untracked_enumeration_order_does_not_change_hash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    for name in ("zeta", "alpha", "mu"):
        (agent / name).write_text(name)
    normal = _capture(runtime, agent)
    from runtime_protocol import source_identity

    original = source_identity._untracked

    def reverse(root: Path):
        return list(reversed(original(root)))

    monkeypatch.setattr(source_identity, "_untracked", reverse)
    assert _capture(runtime, agent) == normal


def test_invalid_checkout_and_git_failure_raise_source_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    with pytest.raises(SourceIdentityError):
        _capture(runtime, tmp_path / "missing")

    def fail(*args, **kwargs):
        raise OSError("git unavailable")

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(SourceIdentityError, match="cannot inspect Git checkout"):
        _capture(runtime, agent)


def test_tracked_read_error_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    original = Path.read_bytes

    def unreadable(path: Path) -> bytes:
        if path == runtime / "tracked.txt":
            raise PermissionError("denied")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", unreadable)
    with pytest.raises(SourceIdentityError, match="cannot read tracked source entry"):
        _capture(runtime, agent)


def test_file_changed_during_raw_read_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    original = Path.read_bytes
    changed = False

    def racing_read(path: Path) -> bytes:
        nonlocal changed
        data = original(path)
        if path == runtime / "tracked.txt" and not changed:
            changed = True
            path.write_text("changed while being captured\n")
        return data

    monkeypatch.setattr(Path, "read_bytes", racing_read)
    with pytest.raises(SourceIdentityError, match="changed during identity capture"):
        _capture(runtime, agent)


def test_same_status_content_race_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    source_identity = __import__("runtime_protocol.source_identity", fromlist=["_tracked_inventory"])
    original = source_identity._tracked_inventory
    calls = 0

    def racing(root: Path):
        nonlocal calls
        inventory = original(root)
        calls += 1
        if root == runtime and calls == 1:
            (runtime / "tracked.txt").write_text("changed during capture\n")
        return inventory

    monkeypatch.setattr(source_identity, "_tracked_inventory", racing)
    with pytest.raises(SourceIdentityError, match="changed during identity capture"):
        _capture(runtime, agent)


def test_head_race_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime, agent = _repo(tmp_path / "runtime"), _repo(tmp_path / "agent")
    source_identity = __import__("runtime_protocol.source_identity", fromlist=["_head"])
    original = source_identity._head
    changed = False

    def racing(root: Path) -> str:
        nonlocal changed
        head = original(root)
        if root == runtime and not changed:
            changed = True
            (runtime / "new.txt").write_text("commit\n")
            _git(runtime, "add", "new.txt")
            _git(runtime, "commit", "-qm", "race")
        return head

    monkeypatch.setattr(source_identity, "_head", racing)
    with pytest.raises(SourceIdentityError, match="changed during identity capture"):
        _capture(runtime, agent)


def test_git_worktree_dot_git_file_is_supported(tmp_path: Path) -> None:
    source, agent = _repo(tmp_path / "source"), _repo(tmp_path / "agent")
    linked = tmp_path / "linked-worktree"
    _git(source, "worktree", "add", "-qb", "linked", str(linked), "HEAD")
    assert (linked / ".git").is_file()
    identity = _capture(linked, agent)
    assert identity["dirty"] is False


def test_checkout_root_admission_is_absolute_and_does_not_capture_contents(tmp_path, monkeypatch):
    from runtime_protocol import source_identity

    root = _repo(tmp_path / "source")
    assert source_identity.validate_checkout_root(root) == root.resolve()
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SourceIdentityError, match="absolute"):
        source_identity.validate_checkout_root(Path("source"))
    nested = root / "nested"
    nested.mkdir()
    with pytest.raises(SourceIdentityError, match="not the root"):
        source_identity.validate_checkout_root(nested)
    monkeypatch.setattr(source_identity, "_head", lambda *_: pytest.fail("admission must not capture HEAD"))
    assert source_identity.validate_checkout_root(root) == root.resolve()
